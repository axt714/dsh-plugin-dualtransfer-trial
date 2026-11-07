// Cooperative private-UID ownership protocol. This is not a repair/admin Tool.
// A stable bootstrap id and one kernel guard cover the WHOLE runtime set.
// Legacy, incomplete, uncertain and failed-drain states require maintenance;
// no PID-only inference, pathname deletion, rename/CAS claim, or weak fallback.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as native from './agent-owner-platform.mjs';
import { createOwnerJournal } from './agent-owner-journal.mjs';
import { createOwnerRoot } from './agent-owner-root.mjs';

const PROTOCOL = 'dsh-owner-set-v2';
const LIMIT = 4 * 1024 * 1024;
const MEMBER_LIMIT = 128;
const ROOT_FILE = '.runtime-root-v2.json';
const CONTROL = '.runtime-ownership-v2';
const JOURNAL = 'journal.jsonl';
const BROKER = fileURLToPath(new URL('./agent-owner-file-op.mjs', import.meta.url));
const REGISTRY = Symbol.for('dsh.dualtransfer.runtime-owner-set.v2');
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const FIXED = ['owner.lock', 'peer/identity/peer-identity.owner.lock',
  'provider/agent-node-provider.owner.lock', 'provider/messages/agent-message-store.owner.lock',
  'host/agent-host-owner.lock', 'provider/client.json'];
const DIRECTORIES = ['', 'peer', 'peer/identity', 'provider', 'provider/messages', 'host', CONTROL];
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const bytesOf = value => Buffer.from(JSON.stringify(value) + '\n');
const triple = stat => ({ dev: String(stat.dev), ino: String(stat.ino), birth: String(stat.birthtimeNs) });
const same = (a, b) => !!a && !!b && ['dev', 'ino', 'birth'].every(key => a[key] === b[key]);
function refusal(code) { return Object.assign(new Error(code), { code }); }
function safeCode(error) {
  return typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{1,95}$/.test(error.code)
    ? error.code : 'OWNER_OPERATION_FAILED';
}
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function roleFor(relative) {
  if (FIXED.includes(relative)) return relative;
  if (/^host\/binding-[0-9a-f-]{36}\/(?:core\/)?owner\.lock$/.test(relative)) return 'binding-core';
  throw refusal('OWNER_ROLE_UNSUPPORTED');
}
function registry() {
  if (!(globalThis[REGISTRY] instanceof Map)) Object.defineProperty(globalThis, REGISTRY, { value: new Map() });
  return globalThis[REGISTRY];
}

export function createRuntimeOwnership({ directory, legacyOrigin }, seams = {}) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || directory.includes('\0')) throw refusal('OWNER_DIRECTORY_INVALID');
  const root = path.resolve(directory);
  const platform = seams.platform ?? native;
  const directories = new Map();
  const heldFiles = new Map();
  const nativeAnchors = [];
  const barriers = new Set();
  const leases = new Map();
  const mine = {};
  let server = null;
  let kernelGuard = null;
  let directoryQuerySession = null;
  let ioGuardKey = null;
  let ioGuardPort = null;
  let guardHeld = false;
  let registered = false;
  let opened = false;
  let revoked = false;
  let closed = false;
  let poisoned = false;
  let childUncertain = false;
  let effects = false;
  let diagnostic = null;
  let identity = null;
  let bootstrap = null;
  let journal = null;
  let journalStore = null;
  let state = null;
  let rootEvidence = null, rootStore = null;
  let rootInitializing = false, rootTransition = false, rootFirstEvent = null;

  const historicalSame = (a, b) => rootStore ? rootStore.sameIdentity(a, b) : same(a, b);
  function verifyPersistentDirectory(file) {
    if (!rootEvidence || (file !== root && !file.startsWith(root + path.sep))) return;
    const observed = platform.persistentDirectoryIdentity(file);
    if (observed.protocol !== 'dsh-owner-root-evidence-v1' || observed.platform !== identity.platform
      || observed.persistentFileIds !== true || observed.boot !== identity.boot
      || observed.machineId !== rootEvidence.machineId || observed.volumeId !== rootEvidence.volumeId
      || !same(observed.identity, directories.get(file)?.identity)) throw refusal('OWNER_ROOT_IDENTITY');
    assertDirectoryPaths();
  }

  const relative = file => {
    const absolute = path.resolve(file);
    const name = path.relative(root, absolute).split(path.sep).join('/');
    if (!name || name === '..' || name.startsWith('../') || path.isAbsolute(name)) throw refusal('OWNER_PATH_OUTSIDE');
    return name;
  };
  function mark(error) {
    diagnostic ??= safeCode(error);
    poisoned = true;
    if (state) state.phase = 'blocked';
    return error instanceof Error ? error : refusal(diagnostic);
  }
  function checkPrivate(stat, isDirectory = false) {
    if (isDirectory ? !stat.isDirectory() : !stat.isFile()) throw refusal('OWNER_FILE_TYPE');
    if (process.platform === 'darwin' && (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n))) throw refusal('OWNER_PRIVATE_REQUIRED');
    if (!isDirectory && stat.nlink !== 1n) throw refusal('OWNER_FILE_LINKED');
  }
  function assertDirectoryPaths() {
    const reader = directoryQuerySession ?? platform;
    if (process.platform === 'win32' && typeof reader.directoryIdentities === 'function') {
      // Each original check point obtains fresh evidence; never cache across
      // a seam, IO operation, await, lease or run. Parents may exceed one batch.
      const entries = [...directories];
      for (let offset = 0; offset < entries.length; offset += 128) {
        const batch = entries.slice(offset, offset + 128);
        const observed = reader.directoryIdentities(batch.map(([file, entry]) => ({
          path: file, expected: entry.identity,
        })));
        if (!Array.isArray(observed) || observed.length < 1 || observed.length > batch.length) throw refusal('OWNER_NATIVE_OUTPUT');
        for (let index = 0; index < batch.length; index += 1) {
          if (index >= observed.length) throw refusal('OWNER_NATIVE_OUTPUT');
          if (!same(observed[index], batch[index][1].identity)) throw refusal('OWNER_ANCESTOR_CHANGED');
        }
      }
    } else {
      for (const [file, entry] of directories) {
        if (process.platform === 'darwin') {
          const named = fs.lstatSync(file, { bigint: true });
          const pinned = fs.fstatSync(entry.fd, { bigint: true });
          if (!named.isDirectory() || named.isSymbolicLink() || !same(triple(named), entry.identity)
            || !same(triple(pinned), entry.identity)) throw refusal('OWNER_ANCESTOR_CHANGED');
        } else if (!same(platform.directoryIdentity(file), entry.identity)) throw refusal('OWNER_ANCESTOR_CHANGED');
      }
    }
    for (const anchor of nativeAnchors) if (!anchor.isAlive()) throw refusal('OWNER_ANCHOR_LOST');
  }
  function assertCapability(allowBlocked = false) {
    if (closed || revoked || !guardHeld || !registered || registry().get(bootstrap?.rootId) !== mine) throw refusal('OWNER_CAPABILITY_REVOKED');
    if (childUncertain) throw refusal('OWNER_CHILD_UNCERTAIN');
    if (kernelGuard && !kernelGuard.isAlive()) throw mark(refusal('OWNER_GUARD_LOST'));
    if (poisoned && !allowBlocked) throw refusal(diagnostic ?? 'OWNER_RUNTIME_BLOCKED');
    assertDirectoryPaths();
  }
  function pinDirectory(file, privateRequired = true) {
    if (directories.has(file)) return directories.get(file).identity;
    if (process.platform === 'darwin') {
      const named = fs.lstatSync(file, { bigint: true });
      if (!named.isDirectory() || named.isSymbolicLink()) throw refusal('OWNER_ANCESTOR_REPARSE');
      if (privateRequired) checkPrivate(named, true);
      const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const current = fs.fstatSync(fd, { bigint: true });
      if (!same(triple(current), triple(named))) { fs.closeSync(fd); throw refusal('OWNER_ANCESTOR_CHANGED'); }
      directories.set(file, { fd, identity: triple(current) });
    } else directories.set(file, { fd: null, identity: platform.directoryIdentity(file) });
    verifyPersistentDirectory(file);
    return directories.get(file).identity;
  }
  function pinAncestors() {
    // The Windows adapter opens/holds its complete system ancestor chain. Only
    // our actual private target must satisfy the private-root ACL contract;
    // C:\\ and other system ancestors are not current-user private directories.
    if (process.platform === 'win32') { pinDirectory(root); return; }
    const parsed = path.parse(root);
    let current = parsed.root;
    pinDirectory(current, false);
    for (const part of root.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, part);
      pinDirectory(current, current === root);
    }
  }
  function holdFile(file, expected) {
    if (heldFiles.has(file)) {
      const held = heldFiles.get(file);
      if (!same(held.identity, expected)) throw refusal('OWNER_FILE_REPLACED');
      return;
    }
    const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    try {
      const stat = fs.fstatSync(fd, { bigint: true });
      checkPrivate(stat);
      const bridge = process.platform === 'win32'
        ? { dev: expected.nodeDev, ino: expected.nodeIno, birth: expected.nodeBirth } : expected;
      if (!same(triple(stat), bridge)) throw refusal('OWNER_FD_IDENTITY_MISMATCH');
      heldFiles.set(file, { fd, identity: expected });
    } catch (error) { fs.closeSync(fd); throw error; }
  }
  function fileOperation(file, options, beforeGuard = false, { retainHandle = true } = {}) {
    if (!beforeGuard) assertCapability(true);
    else assertDirectoryPaths();
    const parent = path.dirname(file);
    const anchor = directories.get(parent);
    if (!anchor) throw refusal('OWNER_PARENT_NOT_ANCHORED');
    seams.beforeOperation?.({ action: options.action, relative: path.relative(root, file) });
    assertDirectoryPaths();
    const input = { ...options, parent, name: path.basename(file), expectedParent: anchor.identity,
      ioGuardKey, ioGuardPort, ownerProcess: identity };
    let result;
    try {
      if (process.platform === 'win32') {
        const reply = platform.nativeFileOperation(input);
        result = options.action === 'mkdir' ? { identity: reply } : reply;
      } else {
        const child = spawnSync(process.execPath, [BROKER], {
          cwd: parent, input: JSON.stringify(input), encoding: 'utf8',
          timeout: 15_000, killSignal: 'SIGKILL', maxBuffer: 12 * 1024 * 1024,
          env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', ELECTRON_RUN_AS_NODE: '1' },
        });
        if (child.error || child.status === null || child.signal) {
          childUncertain = true;
          throw refusal('OWNER_CHILD_UNCERTAIN');
        }
        let reply;
        try { reply = JSON.parse(child.stdout); } catch { throw refusal('OWNER_BROKER_OUTPUT'); }
        if (child.status !== 0 || reply.ok !== true) throw refusal(reply.error?.code ?? 'OWNER_BROKER_FAILED');
        result = reply.result;
      }
      if (!object(result) || !object(result.identity)) throw refusal('OWNER_FILE_EVIDENCE_INVALID');
      if (options.action !== 'mkdir') {
        if (!/^[0-9a-f]{64}$/.test(result.sha256 ?? '') || !Number.isInteger(result.bytes)) throw refusal('OWNER_FILE_EVIDENCE_INVALID');
        if (retainHandle) holdFile(file, result.identity);
      }
      assertDirectoryPaths();
      return result;
    } catch (error) {
      if (/TIMEOUT|IO_UNCERTAIN|UNAVAILABLE|ANCHOR_UNKNOWN/.test(safeCode(error))) childUncertain = true;
      throw mark(error);
    }
  }
  function inspect(file, expected, expectedHash, beforeGuard = false, { retainHandle = true } = {}) {
    const checkedExpected = expected && rootStore ? rootStore.physicalIdentity(expected) : expected;
    const result = fileOperation(file, { action: 'inspect', ...(checkedExpected && { expected: checkedExpected }), ...(expectedHash && { expectedHash }) }, beforeGuard, { retainHandle });
    if (typeof result.data !== 'string') throw refusal('OWNER_FILE_DATA_INVALID');
    const data = Buffer.from(result.data, 'base64');
    if (data.toString('base64') !== result.data || data.length !== result.bytes || sha(data) !== result.sha256) throw refusal('OWNER_FILE_DATA_INVALID');
    return { ...result, raw: data };
  }
  function exists(file) {
    try { fs.lstatSync(file); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  }
  function scanMembers() {
    const found = new Set(FIXED.filter(name => exists(path.join(root, name))));
    const host = path.join(root, 'host');
    if (!exists(host)) return found;
    for (const entry of fs.readdirSync(host, { withFileTypes: true })) {
      if (!entry.name.startsWith('binding-')) continue;
      if (!/^binding-[0-9a-f-]{36}$/.test(entry.name) || !entry.isDirectory() || entry.isSymbolicLink()) throw refusal('OWNER_BINDING_LAYOUT');
      for (const leaf of ['owner.lock', 'core/owner.lock']) {
        const name = `host/${entry.name}/${leaf}`;
        if (exists(path.join(root, name))) found.add(name);
      }
    }
    return found;
  }
  async function prepareDirectory(file) {
    const absolute = path.resolve(file);
    if (absolute !== root) relative(absolute);
    if (opened) assertCapability();
    const parent = path.dirname(absolute);
    if (absolute !== root && !directories.has(parent)) await prepareDirectory(parent);
    if (!exists(absolute)) {
      if (!guardHeld) throw refusal('OWNER_INITIAL_DIRECTORY_MISSING');
      fileOperation(absolute, { action: 'mkdir' });
    }
    const wasPresent = directories.has(absolute);
    pinDirectory(absolute);
    if (process.platform === 'win32' && !wasPresent) {
      try { nativeAnchors.push(await platform.holdDirectoryAnchors([{ path: absolute, identity: directories.get(absolute).identity }])); }
      catch (error) { childUncertain = true; throw mark(error); }
    }
    if (state && !state.parents[path.relative(root, absolute).split(path.sep).join('/')]) {
      state.parents[path.relative(root, absolute).split(path.sep).join('/')] = directories.get(absolute).identity;
      persist('directory-prepared');
    }
  }
  async function pinRecordedDirectory(file, expected) {
    // Read/hold-only for a pre-existing ownership set. In particular there is
    // no exists-then-mkdir path if a recorded ancestor disappears mid-proof.
    const wasPresent = directories.has(file);
    try { pinDirectory(file); }
    catch (error) {
      if (error?.code === 'ENOENT') throw refusal('OWNER_RECORDED_DIRECTORY_MISSING');
      throw error;
    }
    const actual = directories.get(file).identity;
    if (expected && !historicalSame(actual, expected)) throw refusal('OWNER_PARENT_CHANGED');
    if (process.platform === 'win32' && !wasPresent) {
      try { nativeAnchors.push(await platform.holdDirectoryAnchors([{ path: file, identity: actual }])); }
      catch (error) { childUncertain = true; throw mark(error); }
    }
    assertDirectoryPaths();
  }
  function persist(event) {
    assertCapability(true);
    if (!journalStore || childUncertain) throw refusal('OWNER_JOURNAL_UNAVAILABLE');
    if (rootTransition && event !== rootFirstEvent) throw refusal('OWNER_ROOT_TRANSITION_UNCERTAIN');
    try {
      if (rootStore && !rootInitializing) rootStore.assertWritable(state);
      journal = journalStore.persist(event, state);
      if (rootStore && !rootInitializing) rootStore.assertWritable(state);
      if (rootTransition) { rootTransition = false; rootFirstEvent = null; }
    } catch (error) { throw mark(error); }
    finally { journal = journalStore.current(); }
  }
  function validateState(value) {
    if (!object(value) || value.protocol !== PROTOCOL || value.rootId !== bootstrap.rootId
      || !object(value.parents) || !object(value.entries) || Object.keys(value.entries).length > MEMBER_LIMIT
      || !['initializing', 'starting', 'running', 'quiescing', 'blocked', 'recovering', 'stopped'].includes(value.phase)
      || !historicalSame(value.bootstrapIdentity, bootstrap.identity)
      || !historicalSame(value.rootIdentity, directories.get(root).identity)) throw refusal('OWNER_JOURNAL_STATE');
    for (const [name, entry] of Object.entries(value.entries)) {
      if (roleFor(name) !== entry.role || entry.path !== name || !UUID.test(entry.leaseId)
        || !UUID.test(entry.runId) || !object(entry.owner) || !object(entry.identity)
        || !/^[0-9a-f]{64}$/.test(entry.sha256 ?? '') || !Number.isInteger(entry.bytes)
        || typeof entry.released !== 'boolean' || !object(entry.parent)) throw refusal('OWNER_JOURNAL_MEMBER');
    }
  }
  async function loadJournal({ initialize = false } = {}) {
    const control = path.join(root, CONTROL);
    journalStore = createOwnerJournal({
      rootId: bootstrap.rootId, parentIdentity: directories.get(control).identity, validateState,
      physicalIdentity: expected => rootStore ? rootStore.physicalIdentity(expected) : expected,
      rootMarkerName: () => rootStore?.markerName() ?? null,
      validateRecord: (record, checkpoint, prefix) => rootStore?.record(record, checkpoint, prefix),
      effect() { effects = true; },
      listNames() { assertCapability(true); return fs.readdirSync(control); },
      inspectFile(name, expected, expectedHash, retainHandle) {
        return inspect(path.join(control, name), expected, expectedHash, false, { retainHandle });
      },
      createFile(name, data, retainHandle) {
        return fileOperation(path.join(control, name), { action: 'create', data: data.toString('base64'), length: data.length }, false, { retainHandle });
      },
      appendFile(name, expected, expectedHash, data) {
        return fileOperation(path.join(control, name), { action: 'append', expected, expectedHash,
          data: data.toString('base64'), length: data.length });
      },
      closeFile(name, expected) {
        const file = path.join(control, name), held = heldFiles.get(file);
        if (!held || !same(held.identity, expected)) throw refusal('OWNER_FD_IDENTITY_MISMATCH');
        const stat = fs.fstatSync(held.fd, { bigint: true });
        checkPrivate(stat);
        const bridge = process.platform === 'win32'
          ? { dev: expected.nodeDev, ino: expected.nodeIno, birth: expected.nodeBirth } : expected;
        if (!same(triple(stat), bridge)) throw refusal('OWNER_FD_IDENTITY_MISMATCH');
        fs.closeSync(held.fd); heldFiles.delete(file);
      },
    });
    if (initialize) {
      // Only this invocation's O_EXCL-created bootstrap may initialize. The
      // journal engine likewise refuses an unexpected pre-existing journal.
      state = { schema: 2, protocol: PROTOCOL, rootId: bootstrap.rootId, phase: 'initializing',
        rootIdentity: directories.get(root).identity, bootstrapIdentity: bootstrap.identity,
        journalIdentity: null, parents: Object.fromEntries([...directories].filter(([p]) => p === root || p.startsWith(root + path.sep))
          .map(([p, v]) => [path.relative(root, p).split(path.sep).join('/'), v.identity])),
        entries: {}, runId: null, owner: null, pending: null, barriers: [] };
      journal = journalStore.initialize(state);
      state.journalIdentity = journal.identity; state.phase = 'stopped';
      persist('initialized');
      return;
    }
    const loaded = journalStore.load();
    journal = loaded.journal; state = loaded.state;
    // Eligibility applies only to the complete committed chain's FINAL tip.
    // Interior checkpoints may contain pending/barriers resolved downstream.
    if (state.pending || state.barriers.length || !['stopped', 'running'].includes(state.phase)) throw refusal('OWNER_RECOVERY_INCOMPLETE');
  }
  async function validateMembers() {
    for (const [name, expected] of Object.entries(state.parents)) {
      const file = name ? path.join(root, name) : root;
      if (path.resolve(file) !== root && !path.resolve(file).startsWith(root + path.sep)) throw refusal('OWNER_PARENT_OUTSIDE');
      await pinRecordedDirectory(file, expected);
    }
    const found = scanMembers();
    const names = Object.keys(state.entries);
    if (found.size !== names.length || names.some(name => !found.has(name))) throw refusal('OWNER_SET_MISMATCH');
    const active = names.filter(name => !state.entries[name].released);
    if (state.phase === 'stopped' && active.length) throw refusal('OWNER_STOPPED_WITH_OWNERS');
    if (state.phase === 'running' && FIXED.filter(name => name !== 'host/agent-host-owner.lock')
      .some(name => !active.includes(name))) throw refusal('OWNER_RUNNING_SET_INCOMPLETE');
    for (const name of names) {
      const entry = state.entries[name];
      if (!historicalSame(directories.get(path.dirname(path.join(root, name)))?.identity, entry.parent)) throw refusal('OWNER_MEMBER_PARENT_CHANGED');
      inspect(path.join(root, name), entry.identity, entry.sha256);
      if (!entry.released && (entry.runId !== state.runId || JSON.stringify(entry.owner) !== JSON.stringify(state.owner))) throw refusal('OWNER_MEMBER_INSTANCE_MISMATCH');
    }
    const client = state.entries['provider/client.json'];
    const provider = state.entries['provider/agent-node-provider.owner.lock'];
    if (client && !client.released && (!provider || provider.released || client.providerLeaseId !== provider.leaseId)) throw refusal('OWNER_CLIENT_ASSOCIATION');
    const bookFile = path.join(root, 'host', 'agent-host-bindings.json');
    if (exists(bookFile)) {
      let book;
      // This mutable business file is replaced atomically by Host persistence.
      // Retaining its read handle prevents rename on Windows; leases and journal
      // still retain their handles. Native path/ACL/content checks remain intact.
      try { book = JSON.parse(inspect(bookFile, undefined, undefined, false, { retainHandle: false }).raw.toString('utf8')); } catch { throw refusal('OWNER_BINDING_STATE_UNKNOWN'); }
      if (!object(book) || !Array.isArray(book.records) || book.blocked !== false
        || book.records.some(record => record.state === 'preparing')) throw refusal('OWNER_BINDING_STATE_UNCERTAIN');
    }
    return active;
  }
  async function acquireGuard() {
    const key = bootstrap.rootId;
    if (registry().has(key)) throw refusal('OWNER_SET_ACTIVE');
    registry().set(key, mine); registered = true;
    const hash = sha(Buffer.from(identity.guardScope + ':' + key));
    if (process.platform === 'win32') {
      try { kernelGuard = await platform.acquireKernelGuard({ key: hash }); }
      catch (error) { if (!/GUARD_BUSY/.test(safeCode(error))) childUncertain = true; throw error; }
      guardHeld = true;
      return;
    }
    const port = 20000 + (parseInt(hash.slice(0, 8), 16) % 20000);
    server = net.createServer(socket => socket.destroy());
    server.on('error', () => { if (guardHeld) { poisoned = true; diagnostic ??= 'OWNER_GUARD_ERROR'; } });
    await new Promise((resolve, reject) => {
      const error = () => reject(refusal('OWNER_SET_GUARD_BUSY'));
      server.once('error', error);
      server.listen({ host: '127.0.0.1', port, exclusive: true, ipv6Only: false }, () => {
        server.removeListener('error', error); guardHeld = true; resolve();
      });
    });
    server.on('close', () => { if (!revoked && !closed) { poisoned = true; diagnostic ??= 'OWNER_GUARD_LOST'; } });
  }
  async function probeIoGuard(key = ioGuardKey) {
    if (process.platform === 'win32') {
      const probe = await platform.acquireKernelGuard({ key });
      try { await probe.close(); } catch (error) { childUncertain = true; throw error; }
      return;
    }
    const port = 40000 + (parseInt(key.slice(0, 8), 16) % 20000);
    const probe = net.createServer(socket => socket.destroy());
    await new Promise((resolve, reject) => {
      probe.once('error', () => reject(refusal('OWNER_IO_GUARD_BUSY')));
      probe.listen({ host: '127.0.0.1', port, exclusive: true }, resolve);
    });
    try { await new Promise((resolve, reject) => probe.close(error => error ? reject(error) : resolve())); }
    catch (error) { childUncertain = true; throw error; }
  }
  async function open() {
    if (opened || closed || revoked) throw refusal('OWNER_OPEN_STATE');
    try {
      identity = platform.currentProcessIdentity();
      if (!['darwin', 'win32'].includes(process.platform) || identity.pid !== process.pid) throw refusal('OWNER_PLATFORM_UNSUPPORTED');
      if (process.platform !== 'darwin' && legacyOrigin !== undefined) throw refusal('OWNER_NATIVE_UNSUPPORTED');
      if (process.platform === 'win32' && !['privateFileOperations', 'ancestorReparseChecks', 'privateAclEvidence', 'anchoredDirectories']
        .every(key => identity.capabilities[key] === true)) throw refusal('OWNER_PLATFORM_UNSUPPORTED');
      pinAncestors();
      if (process.platform === 'win32') {
        const initialDirectories = [...directories].map(([p, v]) => ({ path: p, identity: v.identity }));
        if (typeof platform.createDirectoryQuerySession === 'function') {
          directoryQuerySession = platform.createDirectoryQuerySession(initialDirectories);
          // Register before the first await: not-ready never means child-free.
          nativeAnchors.push(directoryQuerySession);
          try { await directoryQuerySession.ready; }
          catch (error) { childUncertain = true; throw error; }
        } else nativeAnchors.push(await platform.holdDirectoryAnchors(initialDirectories));
      }
      ioGuardKey = sha(Buffer.from(identity.guardScope + ':io:' + JSON.stringify(directories.get(root).identity)));
      ioGuardPort = 40000 + (parseInt(ioGuardKey.slice(0, 8), 16) % 20000);
      const rootFile = path.join(root, ROOT_FILE);
      let createdBootstrap = false;
      if (!exists(rootFile)) {
        if (exists(path.join(root, CONTROL))) throw refusal('OWNER_BOOTSTRAP_INCOMPLETE');
        if (scanMembers().size) throw refusal('OWNER_LEGACY_MAINTENANCE_REQUIRED');
        const data = bytesOf({ schema: 2, protocol: PROTOCOL, rootId: randomUUID(),
          rootIdentity: directories.get(root).identity, guardScope: identity.guardScope });
        fileOperation(rootFile, { action: 'create', data: data.toString('base64') }, true);
        createdBootstrap = true;
      }
      const rootRecord = inspect(rootFile, undefined, undefined, true);
      let value;
      try { value = JSON.parse(rootRecord.raw.toString('utf8')); } catch { throw refusal('OWNER_BOOTSTRAP_INVALID'); }
      if (!object(value) || value.schema !== 2 || value.protocol !== PROTOCOL || !UUID.test(value.rootId)
        || !object(value.rootIdentity) || typeof value.guardScope !== 'string') throw refusal('OWNER_BOOTSTRAP_SCOPE');
      if (!createdBootstrap && !exists(path.join(root, CONTROL, JOURNAL))) throw refusal('OWNER_BOOTSTRAP_INCOMPLETE');
      bootstrap = { ...value, identity: rootRecord.identity };
      await acquireGuard();
      await probeIoGuard();
      // Never trust a bootstrap cached before this invocation acquired Whole.
      inspect(rootFile, rootRecord.identity, rootRecord.sha256);
      rootEvidence = platform.persistentDirectoryIdentity(root);
      if (rootEvidence.platform !== identity.platform || !same(rootEvidence.identity, directories.get(root).identity)
        || rootEvidence.boot !== identity.boot) throw refusal('OWNER_ROOT_IDENTITY');
      verifyPersistentDirectory(root);
      // Freshness is latched from this invocation's O_EXCL bootstrap, not names.
      for (const name of DIRECTORIES.slice(1)) {
        const file = path.join(root, name);
        if (createdBootstrap) await prepareDirectory(file);
        else await pinRecordedDirectory(file);
      }
      const control = path.join(root, CONTROL);
      rootStore = createOwnerRoot({ rootId: bootstrap.rootId,
        bootstrap: { value, ...rootRecord }, evidence: rootEvidence,
        controlIdentity: directories.get(control).identity, guardScope: identity.guardScope, legacyOrigin,
        listNames() { assertCapability(true); return fs.readdirSync(control); },
        inspectFile(name, expected, expectedHash) {
          return inspect(path.join(control, name), expected, expectedHash, false, { retainHandle: false });
        },
        createFile(name, data) {
          return fileOperation(path.join(control, name), { action: 'create', data: data.toString('base64'), length: data.length }, false, { retainHandle: false });
        },
        effect() { effects = true; },
      });
      rootStore.load();
      rootInitializing = createdBootstrap;
      try { await loadJournal({ initialize: createdBootstrap }); }
      finally { rootInitializing = false; }
      rootStore?.finish(journalStore.boundary());
      const active = await validateMembers();
      // A same-boot old broker can still own the old dev-derived namespace.
      // Check it before converting RAM state; never replace the current IO key.
      const oldScope = state.owner?.guardScope ?? bootstrap.guardScope;
      if (oldScope === identity.guardScope) {
        const oldRoot = process.platform === 'darwin' ? { dev: state.rootIdentity.dev,
          ino: state.rootIdentity.ino, birth: state.rootIdentity.birth } : state.rootIdentity;
        const oldKey = sha(Buffer.from(oldScope + ':io:' + JSON.stringify(oldRoot)));
        if (oldKey !== ioGuardKey) await probeIoGuard(oldKey);
      }
      if (active.length || (process.platform === 'win32' && state.owner && state.owner.boot !== identity.boot)) {
        const evidence = platform.probeProcessIdentity(state.owner);
        if (evidence.state !== 'dead') {
          const stable = rootStore?.stableRoot();
          if (!stable || state.owner.boot === identity.boot || evidence.state === 'active'
            || /REUSED/.test(evidence.code ?? '') || (process.platform === 'win32'
              && (evidence.state !== 'unknown' || evidence.code !== 'OWNER_NATIVE_BOOT_MISMATCH'))) throw refusal(evidence.code ?? 'OWNER_PROCESS_UNKNOWN');
          const prior = platform.previousBootEvidence(state.owner, root, stable);
          if (prior.state !== 'prior-boot' || prior.code !== 'OWNER_PROCESS_PRIOR_BOOT') throw refusal(prior.code ?? 'OWNER_PROCESS_UNKNOWN');
        }
      }
      // All old bytes/parents/members and the FINAL owner are proven first.
      const recovery = active.length ? randomUUID() : null;
      const nextRunId = randomUUID();
      if (rootStore) {
        state = rootStore.liveState(state);
        const publication = rootStore.prepare(journalStore.boundary(), createdBootstrap);
        const first = structuredClone(state);
        if (publication) first.rootAnchor = publication.hash;
        const event = active.length ? 'recovery-intent' : 'run-begin';
        if (active.length) {
          first.phase = 'recovering'; first.pending = { kind: 'recover', recovery, members: active };
        } else {
          first.runId = nextRunId; first.owner = identity; first.phase = 'starting';
          first.pending = null; first.barriers = [];
        }
        journalStore.preflight(event, first);
        if (publication) {
          rootTransition = true; rootFirstEvent = event;
          rootStore.publish();
          state.rootAnchor = publication.hash;
        }
      }
      if (active.length) {
        state.phase = 'recovering'; state.pending = { kind: 'recover', recovery, members: active };
        persist('recovery-intent');
        const backupDirectory = path.join(root, CONTROL, 'backup-' + recovery);
        await prepareDirectory(backupDirectory);
        for (const [index, name] of active.entries()) {
          const entry = state.entries[name];
          const original = inspect(path.join(root, name), entry.identity, entry.sha256);
          fileOperation(path.join(backupDirectory, String(index).padStart(3, '0') + '.bin'), {
            action: 'create', data: original.raw.toString('base64') });
          seams.afterBackup?.({ index, role: entry.role });
        }
        // Revalidate the complete old set after backup and before any retirement.
        for (const name of active) {
          const entry = state.entries[name];
          inspect(path.join(root, name), entry.identity, entry.sha256);
        }
        for (const name of active) releaseEntry(name);
        state.pending = null; state.phase = 'stopped'; persist('recovery-committed');
      }
      state.runId = nextRunId; state.owner = identity; state.phase = 'starting';
      state.pending = null; state.barriers = []; persist('run-begin');
      opened = true;
      return snapshot();
    } catch (error) {
      // A failed acquire with no business/journal effect can be safely unwound.
      if (!effects && !childUncertain && !state?.pending && !guardHeld) diagnostic = safeCode(error);
      else mark(error);
      throw error;
    }
  }
  function memberSlotAvailable(name) {
    return Object.hasOwn(state.entries, name) || Object.keys(state.entries).length < MEMBER_LIMIT;
  }
  function acquire(file, value) {
    assertCapability();
    const name = relative(file), role = roleFor(name);
    if (leases.has(name)) throw refusal('OWNER_LEASE_ACTIVE');
    const old = state.entries[name];
    // Normal admission refusal, before serialization, claim-intent or any effect.
    // Released paths still consume slots; legal same-path reuse is unchanged.
    if (!memberSlotAvailable(name)) throw refusal('OWNER_MEMBER_LIMIT');
    if (exists(file)) {
      if (!old?.released) throw refusal('OWNER_LEASE_UNKNOWN');
      inspect(file, old.identity, old.sha256);
    } else if (old) throw refusal('OWNER_LEASE_MISSING');
    const provider = state.entries['provider/agent-node-provider.owner.lock'];
    if (name === 'provider/client.json' && (!provider || provider.released || provider.runId !== state.runId)) throw refusal('OWNER_CLIENT_ASSOCIATION');
    const data = bytesOf(value);
    if (data.length > 65536) throw refusal('OWNER_LEASE_SIZE');
    // JSON serialization may run caller code; recheck before mutating state.
    if (!memberSlotAvailable(name)) throw refusal('OWNER_MEMBER_LIMIT');
    const leaseId = randomUUID();
    state.pending = { kind: 'claim', path: name, leaseId, sha256: sha(data) };
    persist('claim-intent'); effects = true;
    try {
      const result = fileOperation(file, { action: old ? 'replace' : 'create',
        ...(old && { expected: old.identity, expectedHash: old.sha256 }), data: data.toString('base64') });
      state.entries[name] = { path: name, role, leaseId, runId: state.runId, owner: identity,
        parent: directories.get(path.dirname(file)).identity, identity: result.identity,
        sha256: result.sha256, bytes: result.bytes, released: false,
        ...(name === 'provider/client.json' && { providerLeaseId: provider.leaseId }) };
      state.pending = null; persist('claim-committed');
      const token = {};
      leases.set(name, token);
      let released = false;
      return () => {
        if (released) return;
        assertCapability(true);
        if (leases.get(name) !== token) throw refusal('OWNER_LEASE_REPLACED');
        state.pending = { kind: 'release', path: name, leaseId };
        persist('release-intent');
        releaseEntry(name);
        state.pending = null; persist('release-committed');
        leases.delete(name); released = true;
      };
    } catch (error) { throw mark(error); }
  }
  function releaseEntry(name) {
    const entry = state.entries[name];
    if (!entry || entry.released) throw refusal('OWNER_RELEASE_STATE');
    const data = bytesOf({ schema: 2, protocol: PROTOCOL, kind: 'released', rootId: bootstrap.rootId,
      runId: entry.runId, leaseId: entry.leaseId, role: entry.role, previousHash: entry.sha256 });
    const result = fileOperation(path.join(root, name), { action: 'replace', expected: entry.identity,
      expectedHash: entry.sha256, data: data.toString('base64') });
    entry.sha256 = result.sha256; entry.bytes = result.bytes; entry.released = true;
  }
  function canAcquire(file) {
    try {
      assertCapability();
      const name = relative(file), entry = state.entries[name];
      if (!entry) {
        if (!memberSlotAvailable(name)) return false; // No poison for full capacity.
        try { roleFor(name); } catch { return false; }
        const provider = state.entries['provider/agent-node-provider.owner.lock'];
        if (name === 'provider/client.json' && (!provider || provider.released || provider.runId !== state.runId)) return false;
        return !exists(file);
      }
      if (!entry.released) return false;
      inspect(file, entry.identity, entry.sha256);
      return true;
    } catch (error) { mark(error); return false; }
  }
  function beginBarrier(stage) {
    assertCapability(true);
    if (typeof stage !== 'string' || !/^[A-Za-z][A-Za-z0-9._:-]{0,95}$/.test(stage)) throw refusal('OWNER_STAGE_INVALID');
    const token = randomUUID();
    barriers.add(token); state.barriers.push({ token, stage });
    if (!poisoned) state.phase = 'quiescing';
    persist('barrier-begin');
    let done = false;
    return Object.freeze({
      complete() {
        assertCapability(true);
        if (done) return;
        state.barriers = state.barriers.filter(entry => entry.token !== token);
        barriers.delete(token); done = true;
        if (!poisoned && !barriers.size) state.phase = leases.size ? 'running' : 'starting';
        persist('barrier-complete');
      },
      fail(code = 'OWNER_DRAIN_FAILED') { if (done) return; fail(code, stage); },
    });
  }
  function fail(code, stage = 'runtime') {
    diagnostic ??= /^[A-Z][A-Z0-9_]{1,95}$/.test(code ?? '') ? code : 'OWNER_RUNTIME_FAILED';
    poisoned = true;
    if (state) {
      state.phase = 'blocked';
      state.failure = { code: diagnostic, stage: /^[A-Za-z][A-Za-z0-9._:-]{0,95}$/.test(stage) ? stage : 'runtime' };
      try { if (journal && !childUncertain) persist('runtime-blocked'); } catch { /* Keep guard and all evidence. */ }
    }
  }
  function started() {
    assertCapability();
    if (state.pending || barriers.size || !leases.has('owner.lock') || !leases.has('provider/client.json')) throw refusal('OWNER_START_INCOMPLETE');
    state.phase = 'running'; persist('run-started');
  }
  function snapshot() {
    return Object.freeze({ protocol: PROTOCOL, phase: closed ? 'closed' : state?.phase ?? 'unopened',
      errorCode: diagnostic, guardHeld, leases: leases.size, childUncertain,
      recoverySupported: !!identity && !poisoned, maintenanceRequired: poisoned || childUncertain });
  }
  function capacity() {
    const entries = state ? Object.keys(state.entries).length : 0;
    // Last verified journal operation, not a fresh external-file/health proof.
    // A free member slot does not reserve claim/release/barrier/stop bytes.
    return Object.freeze({ entries, maxEntries: MEMBER_LIMIT, memberSlotAvailable: !!state && entries < MEMBER_LIMIT,
      journalBytes: journal?.bytes ?? null, maxJournalBytes: LIMIT, stopBudgetGuaranteed: false });
  }
  async function close() {
    if (closed) return;
    const noOwnedEffects = !opened && !effects && !leases.size && !barriers.size;
    if (leases.size || barriers.size || childUncertain || rootTransition || (!noOwnedEffects && (poisoned || state?.pending))) throw refusal(diagnostic ?? 'OWNER_CLOSE_UNCERTAIN');
    // A failed read/acquire can release only THIS instance's guard and handles;
    // it must never mark a previously recorded owner's journal stopped.
    if (!noOwnedEffects && guardHeld && journal) { state.phase = 'stopped'; persist('run-stopped'); }
    revoked = true;
    // Revoke first; close confirmation is required for every owned child and FD.
    try {
      for (const anchor of nativeAnchors) await anchor.close();
      for (const { fd } of heldFiles.values()) fs.closeSync(fd);
      heldFiles.clear();
      for (const { fd } of [...directories.values()].reverse()) if (fd !== null) fs.closeSync(fd);
      directories.clear();
      if (guardHeld) {
        if (kernelGuard) await kernelGuard.close();
        else await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      }
      guardHeld = false;
      if (registered && registry().get(bootstrap?.rootId) === mine) registry().delete(bootstrap.rootId);
      registered = false; closed = true;
    } catch (error) { childUncertain = true; throw mark(error); }
  }
  return Object.freeze({ open, prepareDirectory, acquire, canAcquire, beginBarrier, fail, started, close, snapshot, capacity });
}

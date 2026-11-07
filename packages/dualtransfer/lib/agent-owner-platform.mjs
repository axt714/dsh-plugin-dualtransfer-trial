// Internal ownership adapter, not a public Tool/Service. No weak OS fallbacks.
import { spawn, spawnSync } from 'node:child_process';
import { Worker } from 'node:worker_threads';
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const darwinBinary = path.join(here, 'native', 'owner-process-darwin-universal');
const windowsScript = path.join(here, 'native', 'owner-windows.ps1');
const windowsExecutable = path.join(here, 'native', 'owner-windows.exe');
const windowsProvenance = path.join(here, 'native', 'NATIVE-CONSOLE-BUILD-PROVENANCE.json');
const MAX_ASSEMBLY_BYTES = 512 * 1024;
const NATIVE_SOURCE_SHA256 = 'c6f53faf118f468f4030b5b6a91e74c85371c64beec4a11d38a92bf32ac88293';
const PROTOCOL = 'dsh-owner-native-v1';
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_TRANSPORT = 12 * 1024 * 1024;
const TIMEOUT = 30_000;
const SAFE_CODES = new Set([
  'OWNER_NATIVE_INPUT', 'OWNER_NATIVE_UNSUPPORTED', 'OWNER_NATIVE_UNAVAILABLE',
  'OWNER_NATIVE_TIMEOUT', 'OWNER_NATIVE_OUTPUT', 'OWNER_NATIVE_PROCESS_UNKNOWN',
  'OWNER_NATIVE_BOOT_UNKNOWN', 'OWNER_NATIVE_BOOT_MISMATCH',
  'OWNER_NATIVE_NAMESPACE_UNKNOWN', 'OWNER_NATIVE_ACL_UNKNOWN',
  'OWNER_NATIVE_IDENTITY_MISMATCH', 'OWNER_NATIVE_HASH_MISMATCH',
  'OWNER_NATIVE_IO_UNKNOWN', 'OWNER_NATIVE_IO_UNCERTAIN', 'OWNER_NATIVE_LIMIT',
  'OWNER_NATIVE_ANCHOR_UNKNOWN', 'OWNER_NATIVE_GUARD_BUSY',
  'OWNER_NATIVE_GUARD_UNKNOWN', 'OWNER_NATIVE_PARENT_UNKNOWN',
]);

function failure(code) {
  const safe = SAFE_CODES.has(code) ? code : 'OWNER_NATIVE_UNAVAILABLE';
  const error = new Error(safe);
  error.code = safe;
  return error;
}
function refuse(code) { throw failure(code); }
function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function triple(value) {
  return object(value) && ['dev', 'ino', 'birth'].every(key =>
    typeof value[key] === 'string' && /^[A-Za-z0-9:.-]{1,128}$/.test(value[key]));
}
function checkedTriple(value) {
  if (!triple(value)) refuse('OWNER_NATIVE_OUTPUT');
  const result = { dev: value.dev, ino: value.ino, birth: value.birth };
  if (process.platform === 'win32') {
    for (const key of ['nodeDev', 'nodeIno', 'nodeBirth']) {
      if (typeof value[key] !== 'string' || !/^\d{1,32}$/.test(value[key])) {
        refuse('OWNER_NATIVE_OUTPUT');
      }
      result[key] = value[key];
    }
    if (typeof value.nativeFileId !== 'string' || !/^[0-9a-f]{32}$/.test(value.nativeFileId)) {
      refuse('OWNER_NATIVE_OUTPUT');
    }
    result.nativeFileId = value.nativeFileId;
  }
  return Object.freeze(result);
}
function checkedProcess(value, expectedPid) {
  const prefix = process.platform === 'darwin' ? 'darwin-kernel:' : 'windows-kernel:';
  if (!object(value) || value.protocol !== PROTOCOL || value.platform !== process.platform ||
      !Number.isInteger(value.pid) || value.pid < 1 || value.pid > 0x7fffffff ||
      (expectedPid !== undefined && value.pid !== expectedPid) ||
      typeof value.birth !== 'string' || !/^\d{1,24}(?::\d{6})?$/.test(value.birth) ||
      typeof value.boot !== 'string' ||
      !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value.boot) ||
      typeof value.guardScope !== 'string' || value.guardScope !== prefix + value.boot +
        (process.platform === 'win32' ? ':global-mutex:host-silo:0' : '') ||
      !/^[a-z0-9:-]{1,160}$/.test(value.guardScope) || !object(value.capabilities) ||
      value.capabilities.nativeProcessIdentity !== true) refuse('OWNER_NATIVE_OUTPUT');
  const capabilities = {};
  for (const key of ['nativeProcessIdentity', 'privateFileOperations',
    'ancestorReparseChecks', 'privateAclEvidence', 'anchoredDirectories']) {
    if (typeof value.capabilities[key] !== 'boolean') refuse('OWNER_NATIVE_OUTPUT');
    capabilities[key] = value.capabilities[key];
  }
  return Object.freeze({ protocol: PROTOCOL, platform: value.platform, pid: value.pid,
    birth: value.birth, boot: value.boot, guardScope: value.guardScope,
    capabilities: Object.freeze(capabilities) });
}
function decodeReply(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_TRANSPORT) {
    refuse('OWNER_NATIVE_OUTPUT');
  }
  let result;
  try { result = JSON.parse(text.replace(/^\uFEFF/, '')); }
  catch { refuse('OWNER_NATIVE_OUTPUT'); }
  if (!object(result) || typeof result.ok !== 'boolean') refuse('OWNER_NATIVE_OUTPUT');
  if (!result.ok) refuse(SAFE_CODES.has(result.code) ? result.code : 'OWNER_NATIVE_UNAVAILABLE');
  return result;
}
function readPackageArtifact(file, limit, minimum = 1) {
  // Package provenance is a consistency check, NOT a signature or an ACL proof.
  // The enclosing installed/staged package must already be trusted. A bounded
  // same-FD read plus before/after identities detects ordinary replacement;
  // the EXE host independently compares its image bytes with stdin evidence.
  // Neither check authenticates code that has already crossed package trust.
  // pnpm may share trusted package artifacts through hard links. Require a
  // positive, stable link count during this read; private runtime files stay single-link.
  let fd;
  let result;
  try {
    const before = lstatSync(file, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink < 1n ||
        before.size < BigInt(minimum) || before.size > BigInt(limit)) refuse('OWNER_NATIVE_UNAVAILABLE');
    fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const same = (a, b) => a.dev === b.dev && a.ino === b.ino && a.nlink === b.nlink &&
      a.birthtimeNs === b.birthtimeNs && a.size === b.size &&
      a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile() || opened.nlink < 1n || !same(before, opened)) refuse('OWNER_NATIVE_UNAVAILABLE');
    const bytes = Buffer.alloc(Number(opened.size) + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(fd, { bigint: true });
    const named = lstatSync(file, { bigint: true });
    if (length !== Number(opened.size) || !after.isFile() || after.nlink < 1n ||
        !same(opened, after) || !named.isFile() || named.isSymbolicLink() ||
        named.nlink < 1n || !same(opened, named)) refuse('OWNER_NATIVE_UNAVAILABLE');
    result = bytes.subarray(0, length);
  } catch { refuse('OWNER_NATIVE_UNAVAILABLE'); }
  finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { refuse('OWNER_NATIVE_UNAVAILABLE'); }
    }
  }
  return result;
}
function packageSourceDigests(bytes) {
  const text = bytes.toString('utf8');
  const endMarker = "\n'@\n";
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.includes('\r') ||
      text.split(endMarker).length !== 3) refuse('OWNER_NATIVE_UNAVAILABLE');
  const extract = name => {
    const marker = `$${name} = @'\n`;
    const start = text.indexOf(marker);
    if (start < 0 || text.lastIndexOf(marker) !== start ||
        start > 0 && text[start - 1] !== '\n') refuse('OWNER_NATIVE_UNAVAILABLE');
    const first = start + marker.length;
    const end = text.indexOf(endMarker, first);
    if (end <= first) refuse('OWNER_NATIVE_UNAVAILABLE');
    return { start, end, sha256: createHash('sha256').update(text.slice(first, end), 'utf8').digest('hex') };
  };
  const native = extract('nativeSource');
  const consoleHost = extract('consoleHostSource');
  if (native.end >= consoleHost.start || native.sha256 !== NATIVE_SOURCE_SHA256) {
    refuse('OWNER_NATIVE_UNAVAILABLE');
  }
  return { native: native.sha256, consoleHost: consoleHost.sha256 };
}
function windowsArtifactEvidence() {
  const exe = readPackageArtifact(windowsExecutable, MAX_ASSEMBLY_BYTES, 512);
  const source = readPackageArtifact(windowsScript, 256 * 1024);
  const evidence = readPackageArtifact(windowsProvenance, 64 * 1024);
  const sources = packageSourceDigests(source);
  let manifest;
  try { manifest = JSON.parse(evidence.toString('utf8')); }
  catch { refuse('OWNER_NATIVE_UNAVAILABLE'); }
  const digest = value => createHash('sha256').update(value).digest('hex');
  if (!object(manifest) || manifest.protocol !== 'dsh-owner-native-build-v1' ||
      !object(manifest.source) || manifest.source.path !== 'lib/native/owner-windows.ps1' ||
      manifest.source.sha256 !== digest(source) ||
      manifest.source.canonicalCSharpSha256 !== sources.native ||
      manifest.source.consoleHostCSharpSha256 !== sources.consoleHost ||
      manifest.source.extraction !== 'two-exact-named-powershell-single-quoted-here-strings' ||
      !object(manifest.windows) || manifest.windows.file !== 'lib/native/owner-windows.exe' ||
      manifest.windows.kind !== 'console-executable' ||
      manifest.windows.entryPoint !== 'DSHOwnerNative.ConsoleHost' ||
      manifest.windows.framework !== 'net48' || manifest.windows.architecture !== 'x64' ||
      manifest.windows.bytes !== exe.length || manifest.windows.sha256 !== digest(exe)) {
    refuse('OWNER_NATIVE_UNAVAILABLE');
  }
  return { nativeAssemblySha256: manifest.windows.sha256, nativeAssemblyBytes: exe.length };
}
function windowsCommand() {
  // Fixed net48/x64 image, no PATH lookup or PowerShell/cmd/DLL fallback.
  // Never inherit NODE_OPTIONS, debugger switches, COMPLUS/DOTNET hooks/tokens.
  if (process.platform !== 'win32' || process.arch !== 'x64' ||
      !/^c:\\windows$/i.test(process.env.SystemRoot ?? '')) refuse('OWNER_NATIVE_UNSUPPORTED');
  return { evidence: windowsArtifactEvidence(), command: windowsExecutable, args: [],
    env: { SystemRoot: 'C:\\Windows', WINDIR: 'C:\\Windows',
      PATH: 'C:\\Windows\\System32;C:\\Windows' } };
}
function requestWindows(request) {
  const { command, args, env, evidence } = windowsCommand();
  const input = `${JSON.stringify({ ...request, ...evidence })}\n`;
  if (Buffer.byteLength(input) > MAX_TRANSPORT) refuse('OWNER_NATIVE_LIMIT');
  let child;
  try {
    child = spawnSync(command, args, { shell: false, windowsHide: true,
      cwd: here, env, input, encoding: 'utf8', timeout: TIMEOUT,
      killSignal: 'SIGKILL', maxBuffer: MAX_TRANSPORT });
  } catch { refuse('OWNER_NATIVE_UNAVAILABLE'); }
  if (child.error?.code === 'ETIMEDOUT') refuse('OWNER_NATIVE_TIMEOUT');
  if (child.error || child.signal || child.status !== 0 || child.stderr?.length) {
    refuse('OWNER_NATIVE_UNAVAILABLE');
  }
  return decodeReply(child.stdout);
}
function requestDarwin(operation, identity, directoryFd) {
  if (process.platform !== 'darwin') refuse('OWNER_NATIVE_UNSUPPORTED');
  if (operation === 'directory' && (!Number.isInteger(directoryFd) || directoryFd < 0)) {
    refuse('OWNER_NATIVE_INPUT');
  }
  let child;
  const input = operation === 'directory' ? 'directory\n'
    : operation === 'identity' ? `identity ${process.pid}\n`
      : `probe ${identity.pid} ${identity.birth} ${identity.boot}\n`;
  try {
    const stat = lstatSync(darwinBinary);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
        (stat.mode & 0o022) !== 0 || stat.uid !== process.getuid()) {
      refuse('OWNER_NATIVE_UNAVAILABLE');
    }
    child = spawnSync(darwinBinary, [], { shell: false, cwd: here,
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' },
      ...(operation === 'directory' ? { stdio: ['pipe', 'pipe', 'pipe', directoryFd] } : {}),
      input, encoding: 'utf8', timeout: TIMEOUT, killSignal: 'SIGKILL', maxBuffer: 64 * 1024 });
  } catch { refuse('OWNER_NATIVE_UNAVAILABLE'); }
  if (child.error?.code === 'ETIMEDOUT') refuse('OWNER_NATIVE_TIMEOUT');
  if (child.error || child.signal || child.status !== 0 || child.stderr?.length) {
    refuse('OWNER_NATIVE_UNAVAILABLE');
  }
  return decodeReply(child.stdout);
}

export function currentProcessIdentity() {
  if (process.platform === 'darwin') return checkedProcess(requestDarwin('identity'), process.pid);
  if (process.platform === 'win32') {
    return checkedProcess(requestWindows({ operation: 'identity', pid: process.pid }), process.pid);
  }
  refuse('OWNER_NATIVE_UNSUPPORTED');
}

export function probeProcessIdentity(identity) {
  try {
    const checked = checkedProcess(identity);
    const reply = process.platform === 'darwin' ? requestDarwin('probe', checked)
      : process.platform === 'win32' ? requestWindows({ operation: 'probe', ...checked })
        : refuse('OWNER_NATIVE_UNSUPPORTED');
    const codes = { dead: 'OWNER_PROCESS_ABSENT', active: 'OWNER_PROCESS_ACTIVE',
      reused: 'OWNER_PROCESS_REUSED' };
    if (!Object.hasOwn(codes, reply.state) || reply.code !== codes[reply.state]) {
      refuse('OWNER_NATIVE_PROCESS_UNKNOWN');
    }
    return Object.freeze({ state: reply.state, code: reply.code });
  } catch (error) {
    return Object.freeze({ state: 'unknown', code: SAFE_CODES.has(error?.code)
      ? error.code : 'OWNER_NATIVE_PROCESS_UNKNOWN' });
  }
}

function posixDirectoryIdentity(directory) {
  // Darwin stat/fstat expose kernel dev/inode/birth nanoseconds. This is an
  // identity query, not namespace CAS. The Lead's broker supplies write anchoring.
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || directory.includes('\0') ||
      typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_DIRECTORY !== 'number') {
    refuse('OWNER_NATIVE_INPUT');
  }
  const absolute = path.resolve(directory);
  const parts = absolute.split('/').filter(Boolean);
  if (parts.length > 128) refuse('OWNER_NATIVE_LIMIT');
  const held = [];
  const same = (a, b) => a.dev === b.dev && a.ino === b.ino && a.birthtimeNs === b.birthtimeNs;
  let fd;
  try {
    let current = '/';
    for (let index = 0; index <= parts.length; index += 1) {
      if (index) current = path.join(current, parts[index - 1]);
      const stat = lstatSync(current, { bigint: true });
      if (!stat.isDirectory() || stat.isSymbolicLink() || stat.birthtimeNs <= 0n) {
        refuse('OWNER_NATIVE_NAMESPACE_UNKNOWN');
      }
      held.push({ path: current, stat });
    }
    fd = openSync(absolute, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const stat = fstatSync(fd, { bigint: true });
    if (!stat.isDirectory() || !same(stat, held.at(-1).stat)) {
      refuse('OWNER_NATIVE_IDENTITY_MISMATCH');
    }
    for (const entry of held) {
      const now = lstatSync(entry.path, { bigint: true });
      if (!now.isDirectory() || now.isSymbolicLink() || !same(now, entry.stat)) {
        refuse('OWNER_NATIVE_NAMESPACE_UNKNOWN');
      }
    }
    return Object.freeze({ dev: stat.dev.toString(), ino: stat.ino.toString(),
      birth: stat.birthtimeNs.toString() });
  } catch (error) {
    throw failure(SAFE_CODES.has(error?.code) ? error.code : 'OWNER_NATIVE_NAMESPACE_UNKNOWN');
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* Identity only: no file data was changed. */ }
    }
  }
}

export function directoryIdentity(directory) {
  if (process.platform === 'darwin') return posixDirectoryIdentity(directory);
  if (process.platform === 'win32') {
    if (typeof directory !== 'string' || directory.length > 24_000 || directory.includes('\0')) {
      refuse('OWNER_NATIVE_INPUT');
    }
    return checkedTriple(requestWindows({ operation: 'directory', directory }).identity);
  }
  refuse('OWNER_NATIVE_UNSUPPORTED');
}

function rootUuid(value) {
  return typeof value === 'string' &&
    /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value) &&
    value !== '00000000-0000-0000-0000-000000000000';
}
function checkedRootEvidence(value, code = 'OWNER_NATIVE_OUTPUT') {
  const keys = ['protocol', 'platform', 'machineId', 'volumeId', 'boot', 'identity', 'persistentFileIds'];
  const decimal64 = field => typeof field === 'string' && /^(?:0|[1-9]\d{0,19})$/.test(field) &&
    BigInt(field) <= 0xffffffffffffffffn;
  if (!object(value) || Object.keys(value).length !== keys.length ||
      !keys.every(key => Object.hasOwn(value, key)) ||
      value.protocol !== 'dsh-owner-root-evidence-v1' ||
      !['darwin', 'win32'].includes(value.platform) || value.platform !== process.platform ||
      !rootUuid(value.machineId) || !rootUuid(value.volumeId) || !rootUuid(value.boot) ||
      value.persistentFileIds !== true || !object(value.identity) ||
      Object.keys(value.identity).length !== 3 ||
      !['dev', 'ino', 'birth'].every(key => Object.hasOwn(value.identity, key)) ||
      !decimal64(value.identity.dev) || !decimal64(value.identity.birth) || value.identity.birth === '0' ||
      (value.platform === 'win32'
        ? typeof value.identity.ino !== 'string' || !/^[0-9a-f]{32}$/.test(value.identity.ino) ||
          value.identity.ino === '00000000000000000000000000000000'
        : !decimal64(value.identity.ino) || value.identity.ino === '0')) refuse(code);
  return Object.freeze({ protocol: 'dsh-owner-root-evidence-v1', platform: value.platform,
    machineId: value.machineId, volumeId: value.volumeId, boot: value.boot,
    identity: Object.freeze({ dev: value.identity.dev, ino: value.identity.ino, birth: value.identity.birth }),
    persistentFileIds: true });
}

export function persistentDirectoryIdentity(directory) {
  if (process.platform === 'win32') {
    if (typeof directory !== 'string' || directory.length > 24_000 || directory.includes('\0')) {
      refuse('OWNER_NATIVE_INPUT');
    }
    // Native owns the read-only, held-FD NTFS/no-reparse/ACL/silo proof. Only
    // this root query projects three fields; checkedTriple/full IO bridges stay unchanged.
    const { ok, ...wireEvidence } = requestWindows({ operation: 'persistentDirectory', directory });
    if (ok !== true) refuse('OWNER_NATIVE_OUTPUT');
    return checkedRootEvidence(wireEvidence);
  }
  if (process.platform !== 'darwin') refuse('OWNER_NATIVE_UNSUPPORTED');
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || directory.length > 24_000 ||
      directory.includes('\0') || path.resolve(directory) !== directory ||
      typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_DIRECTORY !== 'number') {
    refuse('OWNER_NATIVE_INPUT');
  }
  const parts = directory.split('/').filter(Boolean);
  if (parts.length > 128) refuse('OWNER_NATIVE_LIMIT');
  const held = [];
  const same = (a, b) => a.dev === b.dev && a.ino === b.ino && a.birthtimeNs === b.birthtimeNs &&
    a.uid === b.uid && a.gid === b.gid && a.mode === b.mode;
  try {
    let current = '/';
    for (let index = 0; index <= parts.length; index += 1) {
      if (index) current = path.join(current, parts[index - 1]);
      const before = lstatSync(current, { bigint: true });
      if (!before.isDirectory() || before.isSymbolicLink() || before.birthtimeNs <= 0n) {
        refuse('OWNER_NATIVE_NAMESPACE_UNKNOWN');
      }
      const entry = { path: current,
        fd: openSync(current, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW) };
      held.push(entry);
      entry.stat = fstatSync(entry.fd, { bigint: true });
      if (!entry.stat.isDirectory() || !same(before, entry.stat)) refuse('OWNER_NATIVE_IDENTITY_MISMATCH');
    }
    const target = held.at(-1);
    if (target.stat.uid !== BigInt(process.getuid()) || (target.stat.mode & 0o777n) !== 0o700n) {
      refuse('OWNER_NATIVE_ACL_UNKNOWN');
    }
    // The helper receives only this read-only target FD as FD 3, not a pathname.
    // It checks native private mode/extended ACL, mount-root UUID and FS capabilities.
    const { ok, ...wireEvidence } = requestDarwin('directory', null, target.fd);
    if (ok !== true) refuse('OWNER_NATIVE_OUTPUT');
    const evidence = checkedRootEvidence(wireEvidence);
    if (evidence.identity.dev !== target.stat.dev.toString() ||
        evidence.identity.ino !== target.stat.ino.toString() ||
        evidence.identity.birth !== target.stat.birthtimeNs.toString()) refuse('OWNER_NATIVE_IDENTITY_MISMATCH');
    for (const entry of held) {
      const named = lstatSync(entry.path, { bigint: true });
      const opened = fstatSync(entry.fd, { bigint: true });
      if (!named.isDirectory() || named.isSymbolicLink() || !opened.isDirectory() ||
          !same(entry.stat, named) || !same(entry.stat, opened)) refuse('OWNER_NATIVE_NAMESPACE_UNKNOWN');
      if (entry === target && [named, opened].some(stat => stat.nlink !== target.stat.nlink ||
          stat.ctimeNs !== target.stat.ctimeNs)) refuse('OWNER_NATIVE_ACL_UNKNOWN');
    }
    return evidence;
  } catch (error) {
    throw failure(SAFE_CODES.has(error?.code) ? error.code : 'OWNER_NATIVE_NAMESPACE_UNKNOWN');
  } finally {
    let failed = false;
    for (let index = held.length - 1; index >= 0; index -= 1) {
      try { closeSync(held[index].fd); } catch { failed = true; }
    }
    if (failed) refuse('OWNER_NATIVE_ANCHOR_UNKNOWN');
  }
}

export function previousBootEvidence(owner, directory, expectedStableRoot) {
  // Runtime MUST first associate owner and the trusted full native anchor with
  // the same root and validated durable chain. Field validation cannot establish
  // that history, and an arbitrary old boot string is never a death proof.
  // Same-boot process decisions stay with Runtime's existing native probe.
  if (process.platform === 'win32') {
    try {
      const checkedOwner = checkedProcess(owner);
      if (!rootUuid(checkedOwner.boot)) refuse('OWNER_NATIVE_INPUT');
      const expected = checkedRootEvidence(expectedStableRoot, 'OWNER_NATIVE_INPUT');
      const current = persistentDirectoryIdentity(directory); // Fresh, never cached.
      if (current.platform === checkedOwner.platform && current.platform === expected.platform &&
          current.machineId === expected.machineId && current.volumeId === expected.volumeId &&
          current.identity.dev === expected.identity.dev && current.identity.ino === expected.identity.ino &&
          current.identity.birth === expected.identity.birth && current.boot !== checkedOwner.boot) {
        return Object.freeze({ state: 'prior-boot', code: 'OWNER_PROCESS_PRIOR_BOOT' });
      }
    } catch (error) {
      if (error?.code === 'OWNER_NATIVE_UNSUPPORTED') {
        return Object.freeze({ state: 'unknown', code: 'OWNER_NATIVE_UNSUPPORTED' });
      }
    }
    return Object.freeze({ state: 'unknown', code: 'OWNER_NATIVE_PROCESS_UNKNOWN' });
  }
  if (process.platform !== 'darwin') {
    return Object.freeze({ state: 'unknown', code: 'OWNER_NATIVE_UNSUPPORTED' });
  }
  try {
    const checkedOwner = checkedProcess(owner);
    if (!rootUuid(checkedOwner.boot)) refuse('OWNER_NATIVE_INPUT');
    const expected = checkedRootEvidence(expectedStableRoot, 'OWNER_NATIVE_INPUT');
    const current = persistentDirectoryIdentity(directory);
    if (current.machineId === expected.machineId && current.volumeId === expected.volumeId &&
        current.identity.ino === expected.identity.ino && current.identity.birth === expected.identity.birth &&
        current.boot !== checkedOwner.boot) {
      // Independent reboot evidence, NOT dead and NOT cleanup authorization.
      return Object.freeze({ state: 'prior-boot', code: 'OWNER_PROCESS_PRIOR_BOOT' });
    }
  } catch (error) {
    if (error?.code === 'OWNER_NATIVE_UNSUPPORTED') {
      return Object.freeze({ state: 'unknown', code: 'OWNER_NATIVE_UNSUPPORTED' });
    }
  }
  return Object.freeze({ state: 'unknown', code: 'OWNER_NATIVE_PROCESS_UNKNOWN' });
}

// One fresh, ordered directory proof per original manager check point. The
// expected identities let the helper stop before a later path masks an earlier
// mismatch. Only that checked prefix is returned; it is never cached.
export function directoryIdentities(entries) {
  return checkedDirectoryBatch(entries, requestWindows);
}
function checkedDirectoryBatch(entries, execute) {
  if (process.platform !== 'win32') refuse('OWNER_NATIVE_UNSUPPORTED');
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > 128) refuse('OWNER_NATIVE_INPUT');
  const directories = [];
  for (const entry of entries) {
    if (!object(entry) || typeof entry.path !== 'string' || entry.path.length > 24_000 ||
        entry.path.includes('\0') || !triple(entry.expected)) refuse('OWNER_NATIVE_INPUT');
    directories.push({ path: entry.path, expected: {
      dev: entry.expected.dev, ino: entry.expected.ino, birth: entry.expected.birth,
    } });
  }
  const reply = execute({ operation: 'directoryBatch', directories });
  const mismatch = reply.mismatchIndex;
  if (!Number.isInteger(mismatch) || mismatch < -1 || mismatch >= entries.length ||
      !Array.isArray(reply.identities) ||
      reply.identities.length !== (mismatch === -1 ? entries.length : mismatch + 1)) refuse('OWNER_NATIVE_OUTPUT');
  const identities = reply.identities.map(checkedTriple);
  for (let index = 0; index < identities.length; index += 1) {
    const actual = identities[index], expected = directories[index].expected;
    const equal = ['dev', 'ino', 'birth'].every(key => actual[key] === expected[key]);
    if (equal !== (index !== mismatch)) refuse('OWNER_NATIVE_OUTPUT');
  }
  return Object.freeze(identities);
}

export function nativeFileOperation(options) {
  if (process.platform !== 'win32') refuse('OWNER_NATIVE_UNSUPPORTED');
  if (!object(options) || !triple(options.expectedParent) ||
      typeof options.parent !== 'string' || options.parent.length > 24_000 ||
      options.parent.includes('\0') || typeof options.name !== 'string' ||
      !/^[^\\/:*?"<>|\x00-\x1f]{1,240}$/.test(options.name) ||
      !['inspect', 'create', 'replace', 'append', 'mkdir'].includes(options.action)) {
    refuse('OWNER_NATIVE_INPUT');
  }
  if (options.expected != null && !triple(options.expected)) refuse('OWNER_NATIVE_INPUT');
  if (options.expectedHash != null && !/^[0-9a-f]{64}$/.test(options.expectedHash)) {
    refuse('OWNER_NATIVE_INPUT');
  }
  let payload;
  if (['create', 'replace', 'append'].includes(options.action)) {
    if (typeof options.data !== 'string' || options.data.length > Math.ceil(MAX_BYTES / 3) * 4 ||
        !/^[A-Za-z0-9+/]*={0,2}$/.test(options.data)) {
      refuse('OWNER_NATIVE_INPUT');
    }
    payload = Buffer.from(options.data, 'base64');
    if (payload.length > MAX_BYTES || payload.toString('base64') !== options.data ||
        (options.length !== undefined && options.length !== payload.length)) refuse('OWNER_NATIVE_LIMIT');
  } else if (options.data !== undefined || options.length !== undefined) {
    refuse('OWNER_NATIVE_INPUT');
  }
  if (['replace', 'append'].includes(options.action) &&
      (!triple(options.expected) || !/^[0-9a-f]{64}$/.test(options.expectedHash ?? ''))) {
    refuse('OWNER_NATIVE_INPUT');
  }
  // All mutations enter the native IO gate before proving the real creator's
  // active birth. No Node pathname reopen is ever a substitute for that check.
  let ownerProcess = null;
  let ioGuardKey = null;
  if (options.action !== 'inspect') {
    if (typeof options.ioGuardKey !== 'string' || !/^[0-9a-f]{64}$/.test(options.ioGuardKey)) {
      refuse('OWNER_NATIVE_INPUT');
    }
    ownerProcess = checkedProcess(options.ownerProcess, process.pid);
    ioGuardKey = options.ioGuardKey;
  }
  const request = { operation: 'file', parent: options.parent, ownerProcess, ioGuardKey,
    expectedParent: { dev: options.expectedParent.dev, ino: options.expectedParent.ino,
      birth: options.expectedParent.birth }, name: options.name, action: options.action,
    expected: options.expected == null ? null : { dev: options.expected.dev,
      ino: options.expected.ino, birth: options.expected.birth },
    expectedHash: options.expectedHash ?? null, data: options.data ?? null,
    length: payload?.length ?? null };
  const reply = requestWindows(request);
  const identity = checkedTriple(reply.identity);
  if (options.action === 'mkdir') return identity;
  if (!Number.isInteger(reply.bytes) || reply.bytes < 0 || reply.bytes > MAX_BYTES ||
      !/^[0-9a-f]{64}$/.test(reply.sha256 ?? '') || typeof reply.data !== 'string' ||
      reply.data.length > Math.ceil(MAX_BYTES / 3) * 4) refuse('OWNER_NATIVE_OUTPUT');
  const bytes = Buffer.from(reply.data, 'base64');
  if (bytes.toString('base64') !== reply.data || bytes.length !== reply.bytes ||
      createHash('sha256').update(bytes).digest('hex') !== reply.sha256) refuse('OWNER_NATIVE_OUTPUT');
  return Object.freeze({ identity, sha256: reply.sha256, bytes: reply.bytes, data: reply.data });
}

export async function holdDirectoryAnchors(directories) {
  // POSIX anchoring is deliberately owned by the separate Lead broker; a normal
  // POSIX FD does not have Windows' no-delete-share namespace guarantee.
  if (process.platform !== 'win32') refuse('OWNER_NATIVE_UNSUPPORTED');
  if (!Array.isArray(directories) || directories.length < 1 || directories.length > 128 ||
      !directories.every(entry => object(entry) && typeof entry.path === 'string' &&
        entry.path.length <= 24_000 && !entry.path.includes('\0') && triple(entry.identity))) {
    refuse('OWNER_NATIVE_INPUT');
  }
  return keepWindows({ operation: 'hold', directories: directories.map(entry => ({
    path: entry.path, identity: { dev: entry.identity.dev, ino: entry.identity.ino,
      birth: entry.identity.birth },
  })) });
}

// One runtime-owned, read-only extension of its initial directory anchor.
// The token exists before ready is awaited, so startup failure is accountable.
export function createDirectoryQuerySession(directories) {
  if (process.platform !== 'win32') refuse('OWNER_NATIVE_UNSUPPORTED');
  if (!Array.isArray(directories) || directories.length < 1 || directories.length > 128 ||
      !directories.every(entry => object(entry) && typeof entry.path === 'string' &&
        entry.path.length <= 24_000 && !entry.path.includes('\0') && triple(entry.identity))) refuse('OWNER_NATIVE_INPUT');
  const { command, env, evidence } = windowsCommand();
  const initialRequest = { operation: 'holdQueries', ...evidence,
    directories: directories.map(entry => ({ path: entry.path, identity: {
      dev: entry.identity.dev, ino: entry.identity.ino, birth: entry.identity.birth,
    } })) };
  if (Buffer.byteLength(JSON.stringify(initialRequest)) + 1 > MAX_TRANSPORT) refuse('OWNER_NATIVE_LIMIT');
  const buffer = new SharedArrayBuffer(MAX_TRANSPORT + 16);
  const header = new Int32Array(buffer, 0, 4), payload = new Uint8Array(buffer, 16);
  let ready = false, failed = false, closing = false, sequence = 0, nativeIdentity = null;
  let childClose = null, closeTimer, resolveReady, rejectReady, resolveClose, rejectClose;
  const readiness = new Promise((ok, no) => { resolveReady = ok; rejectReady = no; });
  const completion = new Promise((ok, no) => { resolveClose = ok; rejectClose = no; });
  readiness.catch(() => {}); completion.catch(() => {});
  const worker = new Worker(new URL('./agent-owner-directory-worker.mjs', import.meta.url), {
    execArgv: [], workerData: { command, cwd: here, env, initialRequest, buffer,
      timeout: TIMEOUT, maxBytes: MAX_TRANSPORT },
  });
  const fail = code => {
    failed = true;
    Atomics.store(header, 2, 0);
    if (!ready) rejectReady(failure(code));
    if (closing) rejectClose(failure(code));
  };
  const abort = code => {
    failed = true;
    Atomics.store(header, 2, 0);
    Atomics.store(header, 0, 3);
    try { worker.postMessage({ type: 'abort' }); } catch { /* Unknown child close remains failed. */ }
    if (!ready) rejectReady(failure(code));
    if (closing) rejectClose(failure(code));
  };
  const startupTimer = setTimeout(() => abort('OWNER_NATIVE_TIMEOUT'), TIMEOUT);
  worker.on('message', message => {
    if (message?.type === 'ready') {
      try {
        if (ready || failed || closing) refuse('OWNER_NATIVE_ANCHOR_UNKNOWN');
        const reply = decodeReply(JSON.stringify(message.reply));
        if (reply.ready !== true) refuse('OWNER_NATIVE_OUTPUT');
        nativeIdentity = checkedProcess(reply.processIdentity, message.pid);
        if (Atomics.load(header, 2) !== 1) refuse('OWNER_NATIVE_ANCHOR_UNKNOWN');
        ready = true; clearTimeout(startupTimer); resolveReady();
      } catch (error) { abort(SAFE_CODES.has(error?.code) ? error.code : 'OWNER_NATIVE_OUTPUT'); }
    } else if (message?.type === 'failed') {
      fail(SAFE_CODES.has(message.code) ? message.code : 'OWNER_NATIVE_ANCHOR_UNKNOWN');
    } else if (message?.type === 'closed') {
      childClose = message;
      if (!message.graceful) fail('OWNER_NATIVE_ANCHOR_UNKNOWN');
    } else abort('OWNER_NATIVE_OUTPUT');
  });
  worker.on('error', () => fail('OWNER_NATIVE_ANCHOR_UNKNOWN'));
  worker.on('exit', code => {
    clearTimeout(startupTimer); clearTimeout(closeTimer);
    Atomics.store(header, 2, 0);
    if (code === 0 && ready && closing && !failed && childClose?.graceful === true &&
        childClose.code === 0 && childClose.signal === null && childClose.stdoutEnded && childClose.stderrEnded) resolveClose();
    else { fail('OWNER_NATIVE_ANCHOR_UNKNOWN'); rejectClose(failure('OWNER_NATIVE_ANCHOR_UNKNOWN')); }
  });
  function execute(request) {
    if (!ready || failed || closing || Atomics.load(header, 2) !== 1 || ++sequence > 0x7fffffff) refuse('OWNER_NATIVE_ANCHOR_UNKNOWN');
    // Recheck the exact package/EXE evidence on every request. No proof cache.
    const current = windowsCommand();
    const frame = { ...request, ...current.evidence };
    if (Buffer.byteLength(JSON.stringify({ ...frame, queryId: sequence })) + 1 > MAX_TRANSPORT) refuse('OWNER_NATIVE_LIMIT');
    const previous = Atomics.load(header, 0);
    if ((previous !== 0 && previous !== 2) || Atomics.compareExchange(header, 0, previous, 1) !== previous) {
      abort('OWNER_NATIVE_ANCHOR_UNKNOWN'); refuse('OWNER_NATIVE_ANCHOR_UNKNOWN');
    }
    Atomics.store(header, 3, sequence);
    Atomics.store(header, 1, 0);
    if (Atomics.load(header, 2) !== 1) { abort('OWNER_NATIVE_ANCHOR_UNKNOWN'); refuse('OWNER_NATIVE_ANCHOR_UNKNOWN'); }
    const deadline = performance.now() + TIMEOUT;
    try { worker.postMessage({ type: 'query', id: sequence, request: frame }); }
    catch { abort('OWNER_NATIVE_ANCHOR_UNKNOWN'); refuse('OWNER_NATIVE_ANCHOR_UNKNOWN'); }
    while (Atomics.load(header, 0) === 1) {
      const remaining = deadline - performance.now();
      if (remaining <= 0) {
        if (Atomics.compareExchange(header, 0, 1, 3) === 1) { abort('OWNER_NATIVE_TIMEOUT'); refuse('OWNER_NATIVE_TIMEOUT'); }
        break;
      }
      Atomics.wait(header, 0, 1, remaining);
    }
    if (Atomics.load(header, 0) === 3 && Atomics.load(header, 3) === sequence) {
      const length = Atomics.load(header, 1);
      if (length > 0 && length <= MAX_TRANSPORT) {
        try { decodeReply(Buffer.from(payload.slice(0, length)).toString('utf8')); }
        catch (error) { abort(SAFE_CODES.has(error?.code) ? error.code : 'OWNER_NATIVE_OUTPUT'); throw error; }
      }
    }
    if (Atomics.load(header, 0) !== 2 || Atomics.load(header, 3) !== sequence) {
      abort('OWNER_NATIVE_ANCHOR_UNKNOWN'); refuse('OWNER_NATIVE_ANCHOR_UNKNOWN');
    }
    const length = Atomics.load(header, 1);
    if (!Number.isInteger(length) || length < 1 || length > MAX_TRANSPORT) { abort('OWNER_NATIVE_OUTPUT'); refuse('OWNER_NATIVE_OUTPUT'); }
    try { return decodeReply(Buffer.from(payload.slice(0, length)).toString('utf8')); }
    catch (error) { abort(SAFE_CODES.has(error?.code) ? error.code : 'OWNER_NATIVE_OUTPUT'); throw error; }
  }
  return Object.freeze({ ready: readiness, get processIdentity() { return nativeIdentity; },
    isAlive: () => ready && !failed && !closing && Atomics.load(header, 2) === 1,
    directoryIdentities: entries => {
      try { return checkedDirectoryBatch(entries, execute); }
      catch (error) {
        // Any uncertain protocol or native failure poisons this session forever.
        if (error?.code !== 'OWNER_NATIVE_INPUT') abort(SAFE_CODES.has(error?.code) ? error.code : 'OWNER_NATIVE_OUTPUT');
        throw error;
      }
    },
    close: () => {
      if (closing) return completion;
      closing = true;
      if (failed || !ready || Atomics.load(header, 2) !== 1) { rejectClose(failure('OWNER_NATIVE_ANCHOR_UNKNOWN')); return completion; }
      closeTimer = setTimeout(() => abort('OWNER_NATIVE_TIMEOUT'), TIMEOUT);
      try { worker.postMessage({ type: 'close' }); }
      catch { abort('OWNER_NATIVE_ANCHOR_UNKNOWN'); }
      return completion;
    },
  });
}

export async function acquireKernelGuard(options) {
  if (process.platform !== 'win32') refuse('OWNER_NATIVE_UNSUPPORTED');
  if (!object(options) || typeof options.key !== 'string' || !/^[0-9a-f]{64}$/.test(options.key)) {
    refuse('OWNER_NATIVE_INPUT');
  }
  return keepWindows({ operation: 'kernelGuard', key: options.key });
}

function keepWindows(request) {
  const { command, args, env, evidence } = windowsCommand();
  const input = `${JSON.stringify({ ...request, ...evidence })}\n`;
  if (Buffer.byteLength(input) > MAX_TRANSPORT) refuse('OWNER_NATIVE_LIMIT');
  return new Promise((resolve, reject) => {
    let child;
    try { child = spawn(command, args, { shell: false, windowsHide: true, cwd: here, env,
      stdio: ['pipe', 'pipe', 'pipe'] }); }
    catch { reject(failure('OWNER_NATIVE_ANCHOR_UNKNOWN')); return; }
    let ready = false;
    let failed = false;
    let closed = false;
    let exitCode;
    let total = 0;
    let output = '';
    let closePromise;
    let closeResolve;
    let closeReject;
    let closeTimer;
    const abort = code => {
      if (failed) return;
      failed = true;
      try { child.kill('SIGKILL'); } catch { /* Never report a confirmed close. */ }
      if (!ready) reject(failure(code));
      if (closeReject) closeReject(failure(code));
    };
    const timer = setTimeout(() => abort('OWNER_NATIVE_TIMEOUT'), TIMEOUT);
    child.on('error', () => abort('OWNER_NATIVE_ANCHOR_UNKNOWN'));
    child.stdin.on('error', () => abort('OWNER_NATIVE_ANCHOR_UNKNOWN'));
    child.stderr.on('data', () => abort('OWNER_NATIVE_ANCHOR_UNKNOWN'));
    child.stdout.on('data', chunk => {
      total += chunk.length;
      if (total > 64 * 1024 || ready) { abort('OWNER_NATIVE_OUTPUT'); return; }
      output += chunk.toString('utf8');
      const newline = output.indexOf('\n');
      if (newline === -1) return;
      try {
        if (output.slice(newline + 1).trim()) refuse('OWNER_NATIVE_OUTPUT');
        const response = decodeReply(output.slice(0, newline));
        if (response.ready !== true) refuse('OWNER_NATIVE_OUTPUT');
        const processIdentity = checkedProcess(response.processIdentity, child.pid);
        if (failed || closed) refuse('OWNER_NATIVE_ANCHOR_UNKNOWN');
        ready = true;
        clearTimeout(timer);
        resolve(Object.freeze({ processIdentity,
          isAlive: () => ready && !failed && !closed && child.exitCode === null && !child.killed,
          close: () => {
            if (closePromise) return closePromise;
            if (closed) return exitCode === 0 && !failed
              ? Promise.resolve() : Promise.reject(failure('OWNER_NATIVE_ANCHOR_UNKNOWN'));
            closePromise = new Promise((ok, no) => { closeResolve = ok; closeReject = no; });
            if (failed) closeReject(failure('OWNER_NATIVE_ANCHOR_UNKNOWN'));
            else {
              closeTimer = setTimeout(() => abort('OWNER_NATIVE_TIMEOUT'), TIMEOUT);
              child.stdin.end();
            }
            return closePromise;
          },
        }));
      } catch (error) { abort(SAFE_CODES.has(error?.code) ? error.code : 'OWNER_NATIVE_OUTPUT'); }
    });
    child.on('close', (code, signal) => {
      closed = true;
      exitCode = signal ? null : code;
      clearTimeout(timer);
      clearTimeout(closeTimer);
      if (!ready) { reject(failure('OWNER_NATIVE_ANCHOR_UNKNOWN')); return; }
      // Merely requesting termination or EOF is not proof that handles closed.
      if (closeResolve) {
        if (code === 0 && !signal && !failed) closeResolve();
        else closeReject(failure('OWNER_NATIVE_ANCHOR_UNKNOWN'));
      }
    });
    child.stdin.write(input);
  });
}

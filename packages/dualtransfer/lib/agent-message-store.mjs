import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { exclusiveFile, failure, safeDirectory, syncDir } from './private-fs.mjs';
import { assertRuntimeCapability, beginRuntimeBarrier, failRuntimeBarrier, createFailureLatch, brandAgentFailure } from './agent-failure.mjs';

const MAX_ITEMS = 10000;
const MAX_BYTES = 32 * 1024 * 1024;
const MAX_TEXT_BYTES = 16 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/i;
const TRANSPORT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const EPOCH = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const TOKEN = /^[0-9a-f]{64}$(?![\s\S])/;
const SCOPE_KEYS = ['pairingId', 'generation', 'localDeviceId', 'peerDeviceId', 'localTargetToken', 'peerTargetToken'];
const MESSAGE_KEYS = ['id', 'channel', 'text', 'conversation', 'sender', 'created', 'replyTo'];
const FILE = 'agent-messages.snapshot.json';
const LOCK = 'agent-message-store.owner.lock';
const integer = n => Number.isSafeInteger(n) && n >= 0;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const copy = value => JSON.parse(JSON.stringify(value));
const assert = (condition, code) => { if (!condition) throw failure(code); };

function record(value, keys, code) {
  try {
    assert(value !== null && typeof value === 'object' && !Array.isArray(value), code);
    const prototype = Object.getPrototypeOf(value);
    assert(prototype === Object.prototype || prototype === null, code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const own = Reflect.ownKeys(descriptors);
    assert(own.length === keys.length && keys.every(key => Object.hasOwn(descriptors, key)), code);
    const result = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      assert(Object.hasOwn(descriptor, 'value') && descriptor.enumerable, code);
      result[key] = descriptor.value;
    }
    return result;
  } catch { throw failure(code); }
}

/** Exact, immutable identity tuple. UUID case is legal and remains significant. */
export function validateAgentMessageScope(value) {
  const result = record(value, SCOPE_KEYS, 'AGENT_SCOPE_INVALID');
  for (const key of SCOPE_KEYS.slice(0, 4)) assert(typeof result[key] === 'string' && UUID.test(result[key]), 'AGENT_SCOPE_INVALID');
  for (const key of SCOPE_KEYS.slice(4)) assert(typeof result[key] === 'string' && TOKEN.test(result[key]), 'AGENT_SCOPE_INVALID');
  return Object.freeze(result);
}

function message(value) {
  const result = record(value, MESSAGE_KEYS, 'AGENT_MESSAGE_INVALID');
  assert(typeof result.id === 'string' && TRANSPORT_ID.test(result.id), 'INVALID_TRANSPORT_ID');
  assert(result.replyTo === null || (typeof result.replyTo === 'string' && TRANSPORT_ID.test(result.replyTo)), 'INVALID_TRANSPORT_ID');
  assert(result.channel === 'agent' && typeof result.text === 'string' && result.text.trim().length > 0
    && Buffer.byteLength(result.text, 'utf8') <= MAX_TEXT_BYTES, 'AGENT_MESSAGE_INVALID');
  assert(typeof result.conversation === 'string' && result.conversation.length <= 100
    && typeof result.sender === 'string' && result.sender.length <= 80 && integer(result.created), 'AGENT_MESSAGE_INVALID');
  return Object.freeze(result);
}
const sameScope = (a, b) => SCOPE_KEYS.every(key => a[key] === b[key]);
const sameMessage = (a, b) => MESSAGE_KEYS.every(key => a[key] === b[key]);
const payload = row => Object.fromEntries(MESSAGE_KEYS.map(key => [key, row[key]]));
const GATE_KEYS = ['state', 'revision', 'sessionId', 'policyRevision', 'approvedAt', 'approvalExpiresAt', 'firstDispatchAt', 'firstDispatchOrder', 'legacy'];
const GATE_STATES = ['awaiting-approval', 'approved', 'trusted', 'denied', 'legacy-unapproved'];
const SESSION = /^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
function replyGate(value) {
  const gate = record(value, GATE_KEYS, 'AGENT_REPLY_GATE_INVALID');
  assert(GATE_STATES.includes(gate.state) && integer(gate.revision) && integer(gate.policyRevision)
    && (gate.sessionId === null || typeof gate.sessionId === 'string' && SESSION.test(gate.sessionId)), 'AGENT_REPLY_GATE_INVALID');
  assert(typeof gate.legacy === 'boolean' && (gate.state !== 'legacy-unapproved' || gate.legacy), 'AGENT_REPLY_GATE_INVALID');
  for (const key of ['approvedAt', 'approvalExpiresAt', 'firstDispatchAt', 'firstDispatchOrder']) assert(gate[key] === null || integer(gate[key]), 'AGENT_REPLY_GATE_INVALID');
  if (gate.state === 'approved' || gate.state === 'trusted') assert(gate.sessionId !== null && gate.approvedAt !== null
    && gate.approvalExpiresAt !== null && gate.approvalExpiresAt > gate.approvedAt, 'AGENT_REPLY_GATE_INVALID');
  return Object.freeze(gate);
}
function legacyGate(row) {
  return replyGate({ state: 'legacy-unapproved', revision: 0, sessionId: null, policyRevision: 0,
    approvedAt: null, approvalExpiresAt: null, firstDispatchAt: null, firstDispatchOrder: null, legacy: true });
}
function publicRow(row) { const { scope, admissionOrder, ...result } = row; return copy(result); }
function protocolTail(items) { return items.reduce((tail, row) => Math.max(tail, row.admissionOrder, row.replyGate?.firstDispatchOrder ?? 0), 0); }
function nextProtocolOrder(items) {
  const tail = protocolTail(items); assert(tail < Number.MAX_SAFE_INTEGER, 'AGENT_STORE_SEQUENCE_EXHAUSTED'); return tail + 1;
}
function deviceName(value) {
  assert(typeof value === 'string' && value.length > 0 && value.length <= 80 && !/[\x00-\x1f\x7f]/.test(value), 'AGENT_DEVICE_INVALID');
  return value;
}
function checkedLimit(value, maximum) {
  assert(Number.isSafeInteger(value) && value >= 1 && value <= maximum, 'AGENT_PAGE_INVALID');
  return value;
}
function fixedError(error) {
  const code = typeof error?.code === 'string' && /^(?:AGENT_[A-Z_]+|PRIVATE_[A-Z_]+|PRODUCT_OWNER_[A-Z_]+|INVALID_TRANSPORT_ID|MESSAGE_ID_CONFLICT)$/.test(error.code)
    ? error.code : 'AGENT_STORE_IO';
  return failure(code); // Never expose native paths, causes, contents or credentials.
}

function decodeState(value) {
  const header = record(value, ['schema', 'epoch', 'globalTail', 'revision', 'items'], 'AGENT_STORE_CORRUPT');
  assert((header.schema === 1 || header.schema === 2) && typeof header.epoch === 'string' && EPOCH.test(header.epoch)
    && integer(header.globalTail) && integer(header.revision) && Array.isArray(header.items) && header.items.length <= MAX_ITEMS, 'AGENT_STORE_CORRUPT');
  let previous = 0, previousAdmission = 0;
  const ids = new Set(), orders = new Set();
  const items = header.items.map(raw => {
    assert(raw && (raw.direction === 'in' || raw.direction === 'out'), 'AGENT_STORE_CORRUPT');
    const extra = raw.direction === 'in' ? ['received'] : raw.delivered === true ? ['delivered', 'deliveredAt'] : ['delivered'];
    if (header.schema === 2) extra.push('admissionOrder', ...(raw.direction === 'out' ? ['replyGate'] : []));
    const row = record(raw, [...MESSAGE_KEYS, 'seq', 'direction', 'device', 'scope', ...extra], 'AGENT_STORE_CORRUPT');
    const clean = message(payload(row)), scope = validateAgentMessageScope(row.scope);
    assert(Number.isSafeInteger(row.seq) && row.seq > previous && row.seq <= header.globalTail && !ids.has(row.id), 'AGENT_STORE_CORRUPT');
    previous = row.seq; ids.add(row.id); deviceName(row.device);
    if (row.direction === 'in') assert(integer(row.received), 'AGENT_STORE_CORRUPT');
    else assert(typeof row.delivered === 'boolean' && (!row.delivered || integer(row.deliveredAt)), 'AGENT_STORE_CORRUPT');
    const gate = row.direction === 'out' ? header.schema === 1 ? legacyGate(row) : replyGate(row.replyGate) : null;
    const admissionOrder = header.schema === 1 ? row.seq : row.admissionOrder;
    assert(integer(admissionOrder) && admissionOrder > previousAdmission && !orders.has(admissionOrder), 'AGENT_STORE_CORRUPT');
    previousAdmission = admissionOrder; orders.add(admissionOrder);
    if (gate) {
      assert((gate.firstDispatchAt === null) === (gate.firstDispatchOrder === null), 'AGENT_STORE_CORRUPT');
      if (gate.firstDispatchOrder !== null) {
        assert(gate.firstDispatchOrder >= admissionOrder && (!orders.has(gate.firstDispatchOrder) || gate.firstDispatchOrder === admissionOrder), 'AGENT_STORE_CORRUPT');
        orders.add(gate.firstDispatchOrder);
      }
    }
    return Object.freeze({ ...clean, ...Object.fromEntries(['seq', 'direction', 'device', ...extra].map(key => [key, row[key]])),
      ...(gate ? { replyGate: gate } : {}), admissionOrder, scope });
  });
  return Object.freeze({ ...header, items: Object.freeze(items) });
}

const statFields = ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs'];
const sameStat = (a, b) => statFields.every(key => a[key] === b[key]);
const sameDirectory = (a, b) => a.dev === b.dev && a.ino === b.ino;
function privateStat(st, directory = false) {
  assert((directory ? st.isDirectory() : st.isFile()) && !st.isSymbolicLink(), 'PRIVATE_FILE_UNSAFE');
  if (!directory) assert(st.nlink === 1n, 'PRIVATE_FILE_UNSAFE');
  if (process.platform !== 'win32') {
    assert((st.mode & 0o777n) === (directory ? 0o700n : 0o600n), directory ? 'PRIVATE_DIRECTORY_MODE' : 'PRIVATE_FILE_UNSAFE');
    assert(st.uid === BigInt(process.getuid()), 'PRIVATE_FILE_UNSAFE');
  }
}

/** Provider transport ledger only: no Core, dispatch, networking, pairing or old-App imports. */
export function createAgentMessageStore({ directory, now = Date.now, runtime } = {}) {
  assert(typeof directory === 'string' && path.isAbsolute(directory) && !directory.includes('\0')
    && path.resolve(directory) !== path.parse(directory).root && typeof now === 'function', 'AGENT_STORE_OPTIONS_INVALID');
  // Construction and metadata observation are deliberately filesystem-free.
  directory = path.resolve(directory);
  assertRuntimeCapability(runtime);
  const filename = path.join(directory, FILE), lockname = path.join(directory, LOCK);
  const failures = createFailureLatch();
  let phase = 'new', state = null, directoryStat = null, fileRecord = null;
  let release = null, fault = null, gateClosed = false, opening = null, closing = null;
  let queue = Promise.resolve(), directoryDurability = 'not-checked';

  function metadata() {
    return Object.freeze({ phase, epoch: state?.epoch ?? null, globalTail: state?.globalTail ?? 0,
      revision: state?.revision ?? 0, total: state?.items.length ?? 0,
      pending: state?.items.filter(row => row.direction === 'out' && !row.delivered).length ?? 0,
      errorCode: fault?.code ?? null, directoryDurability,
      permissionModel: process.platform === 'win32' ? 'windows-acl-unverified' : 'posix-owner-modes' });
  }
  function fail(error) { fault ??= fixedError(error); phase = 'failed'; directoryDurability = 'uncertain'; return fault; }
  function accepting() {
    if (gateClosed) throw failure('AGENT_STORE_CLOSED');
    if (fault) throw fixedError(fault);
    assert(phase === 'open' && state, 'AGENT_STORE_NOT_OPEN');
  }
  function verifyDirectory() {
    assert(safeDirectory(directory), 'PRIVATE_PATH_UNSAFE');
    const current = fs.lstatSync(directory, { bigint: true }); privateStat(current, true);
    assert(!directoryStat || sameDirectory(directoryStat, current), 'AGENT_STORE_CHANGED');
    return current;
  }
  // private-fs.readPrivate has a 16MiB cap. Keep its no-follow/private-file rules,
  // but bound this ledger's FD reads to the separately agreed 32MiB maximum.
  function readFile() {
    verifyDirectory();
    let before;
    try { before = fs.lstatSync(filename, { bigint: true }); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    privateStat(before); assert(before.size <= BigInt(MAX_BYTES), 'AGENT_STORE_TOO_LARGE');
    let fd, primary, result;
    try {
      fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      const opened = fs.fstatSync(fd, { bigint: true }); privateStat(opened);
      assert(sameStat(before, opened), 'AGENT_STORE_CHANGED');
      const buffer = Buffer.alloc(Number(opened.size) + 1);
      let length = 0;
      while (length < buffer.length) {
        const count = fs.readSync(fd, buffer, length, buffer.length - length, length);
        if (!count) break;
        length += count;
      }
      const after = fs.fstatSync(fd, { bigint: true });
      assert(length === Number(opened.size) && sameStat(opened, after), 'AGENT_STORE_CHANGED');
      const bytes = buffer.subarray(0, length);
      assert(Buffer.from(bytes.toString('utf8')).equals(bytes), 'AGENT_STORE_CORRUPT');
      result = { stat: after, hash: digest(bytes), bytes };
    } catch (error) { primary = error; }
    if (fd !== undefined) { try { fs.closeSync(fd); } catch (error) { primary ??= error; } }
    if (primary) throw primary;
    verifyDirectory();
    assert(sameStat(result.stat, fs.lstatSync(filename, { bigint: true })), 'AGENT_STORE_CHANGED');
    return result;
  }
  function unchanged() {
    const current = readFile();
    assert(current === null ? fileRecord === null
      : fileRecord !== null && sameStat(current.stat, fileRecord.stat) && current.hash === fileRecord.hash, 'AGENT_STORE_CHANGED');
    return current;
  }
  function durableUnchanged() {
    try { return unchanged(); } catch (error) { throw fail(error); }
  }
  function save(next) {
    assert(next.items.length <= MAX_ITEMS, 'AGENT_STORE_FULL');
    // Size the bounded rows individually before allocating a whole snapshot.
    let size = Buffer.byteLength(JSON.stringify({ ...next, items: [] }) + '\n');
    for (let index = 0; index < next.items.length; index++) {
      size += Buffer.byteLength(JSON.stringify(next.items[index])) + Number(index > 0);
      assert(size <= MAX_BYTES, 'AGENT_STORE_TOO_LARGE');
    }
    const bytes = Buffer.from(JSON.stringify(next) + '\n');
    assert(bytes.length === size && bytes.length <= MAX_BYTES, 'AGENT_STORE_TOO_LARGE');
    const temporary = filename + '.tmp-' + randomUUID();
    let fd;
    try {
      verifyDirectory(); unchanged();
      fd = fs.openSync(temporary, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
      fs.fchmodSync(fd, 0o600); fs.writeFileSync(fd, bytes); fs.fsyncSync(fd);
      const owned = fs.fstatSync(fd, { bigint: true }); privateStat(owned);
      assert(owned.size === BigInt(bytes.length), 'AGENT_STORE_CHANGED');
      const closingFd = fd; fd = undefined; fs.closeSync(closingFd); // Never retry an uncertain close.
      verifyDirectory(); unchanged();
      assert(sameStat(owned, fs.lstatSync(temporary, { bigint: true })), 'AGENT_STORE_CHANGED');
      // This is cooperative-owner checking, NOT an atomic pathname CAS or a
      // guarantee against a malicious same-uid rename/check scheduling window.
      fs.renameSync(temporary, filename);
      const durability = syncDir(directory); // Preserve the audited Windows rule verbatim.
      const committed = readFile();
      assert(committed && committed.stat.dev === owned.dev && committed.stat.ino === owned.ino
        && committed.bytes.equals(bytes), 'AGENT_STORE_CHANGED');
      fileRecord = { stat: committed.stat, hash: committed.hash };
      state = Object.freeze({ ...next, items: Object.freeze(next.items) });
      directoryDurability = durability.directoryDurability;
    } catch (error) { throw fail(error); }
    finally {
      // Failed/partial temporary files are deliberately retained, never repaired
      // or removed by an uncertain pathname. The owner lease also stays on fault.
      if (fd !== undefined) {
        const closingFd = fd; fd = undefined;
        try { fs.closeSync(closingFd); } catch (error) { throw fail(error); }
      }
    }
  }
  function flushFile() {
    let fd;
    try {
      const before = unchanged(); assert(before, 'AGENT_STORE_CHANGED');
      // Windows file fsync is not covered by the directory-EPERM exception;
      // obtain a writable handle without truncation before flushing the file.
      fd = fs.openSync(filename, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      assert(sameStat(before.stat, fs.fstatSync(fd, { bigint: true })), 'AGENT_STORE_CHANGED');
      fs.fsyncSync(fd);
      const closingFd = fd; fd = undefined; fs.closeSync(closingFd);
      unchanged(); directoryDurability = syncDir(directory).directoryDurability;
    } catch (error) { throw fail(error); }
    finally {
      if (fd !== undefined) { const closingFd = fd; fd = undefined; try { fs.closeSync(closingFd); } catch (error) { throw fail(error); } }
    }
  }
  function enqueue(work) {
    accepting();
    const job = queue.then(() => { if (fault) throw fixedError(fault); return work(); });
    queue = job.then(() => undefined, () => undefined);
    return job;
  }
  function tick() { let value; try { value = now(); } catch { throw failure('AGENT_STORE_CLOCK_INVALID'); } assert(integer(value), 'AGENT_STORE_CLOCK_INVALID'); return value; }
  function changed(items, globalTail = state.globalTail) {
    assert(state.revision < Number.MAX_SAFE_INTEGER, 'AGENT_STORE_REVISION_EXHAUSTED');
    save({ ...state, schema: 2, items, globalTail, revision: state.revision + 1 });
  }
  function exactExisting(row, clean, scope, direction) {
    assert(row.direction === direction && sameScope(row.scope, scope) && sameMessage(row, clean), 'MESSAGE_ID_CONFLICT');
  }

  const api = {
    async open() {
      if (gateClosed) throw failure('AGENT_STORE_CLOSED');
      if (fault) throw fixedError(fault);
      if (phase === 'open') return metadata();
      if (!opening) {
        phase = 'opening';
        opening = Promise.resolve().then(() => {
          if (gateClosed) throw failure('AGENT_STORE_CLOSED');
          safeDirectory(directory, { create: true }); directoryStat = verifyDirectory();
          assert(fs.readdirSync(directory).every(name => name === FILE || name === LOCK), 'AGENT_STORE_DIRECTORY_CONFLICT');
          const value = { schema: 1, pid: process.pid, nonce: randomUUID() };
          release = runtime === undefined ? exclusiveFile(lockname, value) : runtime.acquire(lockname, value);
          const existing = readFile();
          if (existing) {
            let decoded; try { decoded = JSON.parse(existing.bytes.toString('utf8')); } catch { throw failure('AGENT_STORE_CORRUPT'); }
            state = decodeState(decoded); fileRecord = { stat: existing.stat, hash: existing.hash };
          } else {
            save({ schema: 2, epoch: randomUUID(), globalTail: 0, revision: 0, items: [] });
          }
          phase = 'open'; return metadata();
        }).catch(error => {
          if (error.code === 'AGENT_STORE_CLOSED' && !release && !state) throw error;
          const rootCause = failures.capture(error, { stage: 'store-open', origin: 'store', lifecycle: 'start' });
          throw brandAgentFailure(fail(error), { rootCause });
        });
      }
      return opening;
    },
    async close() {
      if (!closing) {
        let barrier;
        try { barrier = beginRuntimeBarrier(runtime, 'store-close'); }
        catch (error) {
          const rootCause = failures.capture(error, { stage: 'store-close', origin: 'store', lifecycle: 'stop' });
          failRuntimeBarrier(runtime, barrier, error, 'store-close');
          closing = Promise.reject(brandAgentFailure(error, { rootCause })); closing.catch(() => {}); return closing;
        }
        gateClosed = true; phase = 'closing'; // Durable ownership barrier precedes admission retirement.
        closing = (async () => {
          if (opening) { try { await opening; } catch (error) { if (error.code !== 'AGENT_STORE_CLOSED' || release || state) throw error; } }
          await queue;
          if (fault) throw fixedError(fault);
          if (state) flushFile();
          if (release) { release(); release = null; }
          barrier?.complete(); phase = 'closed'; return metadata();
        })().catch(error => {
          const rootCause = failures.capture(error, { stage: 'store-close', origin: 'store', lifecycle: 'stop' });
          failRuntimeBarrier(runtime, barrier, error, 'store-close'); throw brandAgentFailure(fail(error), { rootCause });
        });
      }
      return closing;
    },
    async flush() { return enqueue(() => { flushFile(); return metadata(); }); },
    async drain() {
      if (closing) await closing;
      else { if (opening) await opening; const accepted = queue; await accepted; }
      if (fault) throw fixedError(fault);
      return metadata();
    },
    async appendOutgoing(value, valueScope, valueGate) {
      accepting(); const clean = message(value), scope = validateAgentMessageScope(valueScope);
      const gate = replyGate(valueGate === undefined ? { state: 'awaiting-approval', revision: 0, sessionId: null, policyRevision: 0,
        approvedAt: null, approvalExpiresAt: null, firstDispatchAt: null, firstDispatchOrder: null, legacy: false } : valueGate);
      return enqueue(() => {
        const existing = state.items.find(row => row.id === clean.id);
        if (existing) { exactExisting(existing, clean, scope, 'out'); durableUnchanged(); return publicRow(existing); }
        assert(state.items.length < MAX_ITEMS, 'AGENT_STORE_FULL');
        assert(state.globalTail < Number.MAX_SAFE_INTEGER, 'AGENT_STORE_SEQUENCE_EXHAUSTED');
        const admissionOrder = nextProtocolOrder(state.items);
        assert(gate.firstDispatchOrder === null, 'AGENT_REPLY_GATE_INVALID');
        const storedGate = Object.freeze({ ...gate, firstDispatchOrder: gate.firstDispatchAt === null ? null : admissionOrder });
        const row = Object.freeze({ ...clean, seq: state.globalTail + 1, direction: 'out', device: deviceName(process.platform), delivered: false,
          replyGate: storedGate, admissionOrder, scope });
        changed([...state.items, row], row.seq); return publicRow(row);
      });
    },
    async ingestIncoming(values, valueScope, { device = 'unknown' } = {}) {
      accepting(); const scope = validateAgentMessageScope(valueScope), source = deviceName(device);
      assert(Array.isArray(values) && values.length <= MAX_ITEMS, 'AGENT_MESSAGE_BATCH_INVALID');
      const clean = values.map(message);
      return enqueue(() => {
        const items = state.items.slice(), index = new Map(items.map(row => [row.id, row]));
        let globalTail = state.globalTail, order = protocolTail(items), received;
        for (const value of clean) {
          const existing = index.get(value.id);
          if (existing) { exactExisting(existing, value, scope, 'in'); continue; }
          assert(items.length < MAX_ITEMS, 'AGENT_STORE_FULL');
          assert(globalTail < Number.MAX_SAFE_INTEGER, 'AGENT_STORE_SEQUENCE_EXHAUSTED');
          received ??= tick();
          assert(order < Number.MAX_SAFE_INTEGER, 'AGENT_STORE_SEQUENCE_EXHAUSTED');
          const row = Object.freeze({ ...value, seq: ++globalTail, direction: 'in', device: source, received, admissionOrder: ++order, scope });
          items.push(row); index.set(row.id, row);
        }
        if (items.length !== state.items.length) changed(items, globalTail);
        else durableUnchanged();
        // No ACK escapes until the entire message+scope+epoch+tail commit succeeds.
        return clean.map(value => value.id);
      });
    },
    async acknowledge(values, valueScope) {
      accepting(); const scope = validateAgentMessageScope(valueScope);
      assert(Array.isArray(values) && values.length <= MAX_ITEMS
        && values.every(id => typeof id === 'string' && TRANSPORT_ID.test(id)), 'INVALID_TRANSPORT_ID');
      const ids = values.slice();
      return enqueue(() => {
        const index = new Map(state.items.map(row => [row.id, row]));
        for (const id of ids) {
          const row = index.get(id);
          assert(row && row.direction === 'out' && sameScope(row.scope, scope), 'AGENT_ACK_SCOPE_MISMATCH');
        }
        const selected = new Set(ids);
        if (state.items.some(row => selected.has(row.id) && !row.delivered)) {
          const deliveredAt = tick();
          changed(state.items.map(row => selected.has(row.id) && !row.delivered ? Object.freeze({ ...row, delivered: true, deliveredAt }) : row));
        } else durableUnchanged();
        return ids;
      });
    },
    list({ since = 0, limit = 100, direction, channel, scope: valueScope } = {}) {
      accepting(); const scope = validateAgentMessageScope(valueScope);
      assert(integer(since) && since <= state.globalTail, 'AGENT_PAGE_INVALID'); checkedLimit(limit, 1000);
      assert(direction === undefined || direction === 'in' || direction === 'out', 'AGENT_PAGE_INVALID');
      assert(channel === undefined || channel === 'agent', 'AGENT_PAGE_INVALID');
      const matches = state.items.filter(row => row.seq > since && sameScope(row.scope, scope)
        && (direction === undefined || row.direction === direction) && (channel === undefined || row.channel === channel));
      const selected = matches.slice(0, limit);
      return { messages: selected.map(publicRow), next: selected.length ? selected.at(-1).seq : since,
        more: matches.length > selected.length, revision: state.revision, epoch: state.epoch, globalTail: state.globalTail };
    },
    async setReplyGate(input, valueScope) {
      accepting(); const scope = validateAgentMessageScope(valueScope);
      const clean = record(input, ['messageId', 'expectedRevision', 'gate'], 'AGENT_REPLY_GATE_INVALID');
      const gate = replyGate(clean.gate);
      assert(typeof clean.messageId === 'string' && TRANSPORT_ID.test(clean.messageId) && integer(clean.expectedRevision), 'AGENT_REPLY_GATE_INVALID');
      return enqueue(() => {
        const row = state.items.find(item => item.id === clean.messageId);
        assert(row && row.direction === 'out' && sameScope(row.scope, scope), 'AGENT_REPLY_NOT_FOUND');
        assert(row.replyGate.revision === clean.expectedRevision && gate.revision === clean.expectedRevision + 1, 'AGENT_REPLY_STALE');
        assert(row.replyGate.sessionId === null || gate.sessionId === row.replyGate.sessionId, 'AGENT_REPLY_CONTEXT_RETIRED');
        assert(gate.legacy === row.replyGate.legacy && gate.firstDispatchOrder === row.replyGate.firstDispatchOrder, 'AGENT_REPLY_GATE_INVALID');
        assert(row.replyGate.firstDispatchAt === null || gate.firstDispatchAt === row.replyGate.firstDispatchAt, 'AGENT_REPLY_GATE_INVALID');
        const storedGate = Object.freeze({ ...gate, firstDispatchOrder: row.replyGate.firstDispatchOrder
          ?? (gate.firstDispatchAt === null ? null : nextProtocolOrder(state.items)) });
        const next = Object.freeze({ ...row, replyGate: storedGate });
        changed(state.items.map(item => item === row ? next : item)); return publicRow(next);
      });
    },
    pending(valueScope, { limit = 8, authorize = () => false } = {}) {
      accepting(); const scope = validateAgentMessageScope(valueScope); checkedLimit(limit, 8);
      assert(typeof authorize === 'function', 'AGENT_REPLY_GATE_INVALID');
      const time = tick();
      // A store cannot establish live Session/policy authority. Callers must supply
      // that check; the legacy no-argument enumerator is deliberately fail closed.
      return state.items.filter(row => row.direction === 'out' && !row.delivered && sameScope(row.scope, scope)
        && ['approved', 'trusted'].includes(row.replyGate.state) && row.replyGate.firstDispatchAt !== null
        && row.replyGate.approvalExpiresAt > time && authorize(publicRow(row)) === true).slice(0, limit).map(payload);
    },
    messagesForScope(valueScope) {
      accepting(); const scope = validateAgentMessageScope(valueScope);
      return state.items.filter(row => sameScope(row.scope, scope)).map(row => ({ ...publicRow(row), admissionOrder: row.admissionOrder }));
    },
    capacity() {
      // Pure observation of committed state and last verified file size. No
      // queue/IO, snapshot mutation, archive, or reserved ACK/gate byte budget.
      let serializedBytes = state ? Buffer.byteLength(JSON.stringify({ ...state, items: [] }) + '\n') : null;
      if (state) for (const [index, row] of state.items.entries()) serializedBytes += Buffer.byteLength(JSON.stringify(row)) + Number(index > 0);
      return Object.freeze({ items: state?.items.length ?? 0, maxItems: MAX_ITEMS, serializedBytes,
        persistedBytes: fileRecord ? Number(fileRecord.stat.size) : null, maxBytes: MAX_BYTES, ackBudgetGuaranteed: false });
    },
    snapshot() { return metadata(); },
  };
  return Object.freeze(api);
}

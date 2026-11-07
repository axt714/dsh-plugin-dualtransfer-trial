import * as nativeFs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { record, keysOnly, validRequest, validBinding, validCursor, validUsed } from './wire.mjs';
export class StorageError extends Error {
  constructor(code) { super(code); this.name = 'StorageError'; this.code = code; }
}
const fail = code => { throw new StorageError(code); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const FILES = Object.freeze({ binding: 'binding.json', cursor: 'cursor.json', journal: 'journal.json',
  used: 'setup-used.json', request: 'bind-request.json', control: 'control.json', status: 'public-status.json' });
const PUBLIC_KEYS = ['schema', 'adapterContract', 'writtenAt', 'hostPid', 'coreSha256', 'coreSchema',
  'stateEpoch', 'storeEpoch', 'globalTail', 'binding', 'enabled', 'effectiveEnabled', 'sourceContract',
  'canEnable', 'dispatchReady', 'pending', 'cooldownUntil', 'lastPollAt', 'error'];
export function createStorage({ directory, fs = nativeFs, uuid = randomUUID } = {}) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) fail('INVALID_DIRECTORY');
  const root = path.resolve(directory);
  let owner = false, closed = false;
  const target = name => {
    if (!Object.values(FILES).includes(name)) fail('INVALID_STORAGE_TARGET');
    const result = path.resolve(root, name);
    if (path.dirname(result) !== root) fail('INVALID_STORAGE_TARGET');
    return result;
  };
  const writable = () => { if (!owner || closed) fail('STORAGE_NOT_OWNED'); };
  async function directoryExists() {
    try { const stat = await fs.lstat(root); if (!stat.isDirectory() || stat.isSymbolicLink()) fail('INVALID_DIRECTORY'); return true; }
    catch (error) { if (error?.code === 'ENOENT') return false; if (error instanceof StorageError) throw error; fail('PRIVATE_STATE_IO'); }
  }
  async function json(name, maximum = 8192) {
    const filename = target(name);
    try {
      const stat = await fs.lstat(filename);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maximum) fail('PRIVATE_STATE_CONFLICT');
      const text = await fs.readFile(filename, 'utf8');
      if (Buffer.byteLength(text, 'utf8') > maximum) fail('PRIVATE_STATE_CONFLICT');
      const value = JSON.parse(text);
      if (!record(value)) fail('PRIVATE_STATE_CONFLICT');
      return value;
    } catch (error) {
      if (error?.code === 'ENOENT') return null;
      if (error instanceof StorageError) throw error;
      fail('PRIVATE_STATE_CONFLICT');
    }
  }
  async function tuple() {
    const [binding, cursor, journal, used, request] = await Promise.all([
      json(FILES.binding), json(FILES.cursor), json(FILES.journal, 32 * 1024 * 1024),
      json(FILES.used), json(FILES.request),
    ]);
    return { binding, cursor, journal, used, request };
  }
  function journalMatches(value, expected) {
    // The frozen Core remains the ONLY full journal validator. Never use its
    // private generation as an epoch, a mount id or a replacement message ledger.
    return record(value) && value.schema === 1 && value.binding?.sessionId === expected.sessionId
      && value.binding?.revision === expected.revision && Array.isArray(value.records)
      && Array.isArray(value.attempts) && (value.batch === null || record(value.batch));
  }
  async function preflight(expected, now) {
    if (!await directoryExists()) return { kind: 'unbound', code: 'BIND_REQUEST_REQUIRED' };
    const value = await tuple();
    const empty = !value.binding && !value.cursor && !value.journal && !value.used;
    if (empty) {
      if (!value.request) return { kind: 'unbound', code: 'BIND_REQUEST_REQUIRED' };
      if (!validRequest(value.request, expected, now)) fail('BIND_REQUEST_INVALID');
      return { kind: 'fresh', request: value.request };
    }
    if (!validBinding(value.binding, expected) || !validCursor(value.cursor, value.binding)
        || !validUsed(value.used, value.binding) || !journalMatches(value.journal, expected)
        || value.request !== null) fail('PRIVATE_STATE_CONFLICT');
    return { kind: 'resume', binding: value.binding, cursor: value.cursor, used: value.used };
  }
  async function verifyOwned(before, expected, now) {
    writable();
    const value = await tuple();
    if (!journalMatches(value.journal, expected)) fail('PRIVATE_STATE_CONFLICT');
    if (before.kind === 'fresh') {
      if (value.binding || value.cursor || value.used || !same(value.request, before.request)
          || !validRequest(value.request, expected, now)) fail('PRIVATE_STATE_CONFLICT');
    } else if (before.kind === 'resume') {
      if (!same(value.binding, before.binding) || !same(value.cursor, before.cursor)
          || !same(value.used, before.used) || value.request !== null
          || !validBinding(value.binding, expected) || !validCursor(value.cursor, value.binding)) fail('PRIVATE_STATE_CONFLICT');
    } else fail('PRIVATE_STATE_CONFLICT');
  }
  async function atomic(name, value) {
    writable();
    const final = target(name), temporary = path.resolve(root, '.runtime-' + uuid() + '.tmp');
    if (path.dirname(temporary) !== root) fail('INVALID_STORAGE_TARGET');
    let handle;
    try {
      handle = await fs.open(temporary, 'wx', 0o600);
      writable();
      await handle.writeFile(JSON.stringify(value) + '\n', 'utf8');
      await handle.sync(); await handle.close(); handle = null;
      writable();
      await fs.rename(temporary, final);
      let directory;
      try { directory = await fs.open(root, 'r'); await directory.sync(); }
      catch { /* Windows directory fsync is not universally supported. */ }
      finally { if (directory) try { await directory.close(); } catch { /* fixed errors only */ } }
    } catch {
      if (handle) try { await handle.close(); } catch { /* release best effort */ }
      // temporary is a verified fixed-root path generated by this operation only.
      try { await fs.unlink(temporary); } catch { /* do not touch any other file */ }
      fail('STATE_WRITE_FAILED');
    }
  }
  async function prepare(before, expected, now) {
    await verifyOwned(before, expected, now);
    if (before.kind !== 'fresh') fail('PRIVATE_STATE_CONFLICT');
    const binding = Object.freeze({ schema: 1, id: uuid(), ...expected, state: 'preparing',
      setupNonce: before.request.nonce, createdAt: now });
    if (!validBinding(binding, expected, 'preparing')) fail('BIND_REQUEST_INVALID');
    const used = { schema: 1, nonce: binding.setupNonce, bindingId: binding.id,
      ...expected, consumedAt: now };
    // Only after the Core owner was acquired. Any partial artifact blocks later
    // bootstrap: never reuse the request or automatically take another barrier.
    await atomic(FILES.used, used);
    await atomic(FILES.binding, binding);
    if (!same(await json(FILES.request), before.request)) fail('PRIVATE_STATE_CONFLICT');
    writable();
    try { await fs.unlink(target(FILES.request)); } catch { fail('STATE_WRITE_FAILED'); }
    return binding;
  }
  async function commitBinding(binding) {
    writable();
    const present = await json(FILES.binding), cursor = await json(FILES.cursor), used = await json(FILES.used);
    if (!same(present, binding) || !validCursor(cursor, binding) || !validUsed(used, binding)) fail('PRIVATE_STATE_CONFLICT');
    const committed = Object.freeze({ ...binding, state: 'committed' });
    await atomic(FILES.binding, committed);
    return committed;
  }
  async function persistCursor(value, binding) {
    if (!validCursor(value, binding)) fail('PRIVATE_STATE_CONFLICT');
    await atomic(FILES.cursor, value);
  }
  async function readControl() {
    try { return await json(FILES.control); }
    catch { fail('CONTROL_INVALID'); }
  }
  async function writePublic(value) {
    if (!keysOnly(value, PUBLIC_KEYS) || value.schema !== 1 || value.adapterContract !== 2
        || typeof value.canEnable !== 'boolean' || typeof value.effectiveEnabled !== 'boolean'
        || value.dispatchReady !== (value.canEnable && value.effectiveEnabled)
        || !keysOnly(value.binding, ['bound', 'id', 'revision', 'label'])
        || !keysOnly(value.pending, ['queued', 'phase', 'uncertain'])
        || !(value.error === null || keysOnly(value.error, ['code', 'at']))
        || Buffer.byteLength(JSON.stringify(value)) > 16384) fail('INVALID_PUBLIC_STATUS');
    await atomic(FILES.status, value);
  }
  return Object.freeze({ preflight, verifyOwned, prepare, commitBinding, persistCursor, readControl, writePublic,
    setOwner(value) { if (closed || typeof value !== 'boolean') fail('STORAGE_NOT_OWNED'); owner = value; },
    close() { closed = true; owner = false; } });
}

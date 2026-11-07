'use strict';
// Shared local control plane. No defaults to a user's HOME, profile or installed app.
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const YAML = require('./vendor/yaml/dist/index.js');
const { isLocalAbsolutePath, sameLocalPath } = require('./path-policy.cjs');
const CONTROL_API_VERSION = 2;
const SCHEMA = 1;
const CONTRACT = Object.freeze({ min: 2, max: 2 });
const CONNECT_WINDOW_MS = 15000;
const BIND_TTL_MS = 300000;
const ID36 = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ROOT_NAME = new RegExp('^agent-wake-runtime-r([1-9][0-9]*)$', process.platform === 'win32' ? 'i' : '');
const PRIVATE_STATE_NAMES = Object.freeze(['journal.json', 'owner.lock', 'binding.json', 'cursor.json', 'setup-used.json', 'bind-request.json', 'control.json', 'public-status.json']);
const PHASES = new Set(['idle', 'pending', 'submitting', 'accepted', 'uncertain']);
const SOURCE_CONTRACTS = new Set(['unknown', 'pending', 'verified', 'refused']);
const RUNTIME_PKG = 'dsh-plugin-dualtransfer';
const RUNTIME_ROW_ID = 'dsh-plugin-dualtransfer';
const fail = (code, field) => Object.assign(new Error(field ? code + ': ' + field : code), { code });
const isInt = (v, min) => Number.isSafeInteger(v) && v >= min;
const isTime = (v) => isInt(v, 0);
const contractOk = (c) => !!c && typeof c === 'object' && !Array.isArray(c) && Object.keys(c).every((key) => ['min', 'max'].includes(key)) && isInt(c.min, 1) && isInt(c.max, 1) && c.min <= CONTRACT.max && c.max >= CONTRACT.min;
// Snapshot capabilities stay private; returned records keep their legacy enumerable shape.
const controlSnapshots = new WeakMap();
function increment(value, code) {
  if (!isInt(value, 0) || value >= Number.MAX_SAFE_INTEGER) throw fail(code);
  return value + 1;
}
function absolute(value, code) {
  if (!isLocalAbsolutePath(value)) throw fail(code);
  return path.resolve(value);
}
function forbiddenDirectory(dir) {
  // Check the unnormalised spelling too: legacy-root/../runtime is not a bypass.
  return dir.split(/[\\/]+/).some((part) => part.normalize('NFKC').toLowerCase().replace(/[. ]+$/, '') === 'agent-wake');
}
function noSymlinks(dir, code) {
  let current = path.parse(dir).root;
  for (const part of dir.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    let st;
    try { st = fs.lstatSync(current); } catch (e) {
      if (e.code === 'ENOENT') return;
      throw fail(code);
    }
    if (st.isSymbolicLink() || !st.isDirectory()) throw fail(code);
  }
}
function assertRuntimeDirectory(dir) {
  const resolved = absolute(dir, 'RUNTIME_DIRECTORY_REQUIRED');
  if (resolved === path.parse(resolved).root || forbiddenDirectory(dir) || forbiddenDirectory(resolved)) throw fail('RUNTIME_DIRECTORY_FORBIDDEN');
  const name = ROOT_NAME.exec(path.basename(resolved));
  if (!name || !isInt(Number(name[1]), 1)) throw fail('RUNTIME_DIRECTORY_INVALID');
  noSymlinks(resolved, 'RUNTIME_DIRECTORY_UNSAFE');
  return resolved;
}
function assertProfilesRoot(root) {
  const resolved = absolute(root, 'PROFILES_ROOT_REQUIRED');
  if (resolved === path.parse(resolved).root) throw fail('PROFILES_ROOT_INVALID');
  noSymlinks(resolved, 'PROFILE_PATH_UNSAFE');
  return resolved;
}
function runtimeFile(dir, name) { return path.join(assertRuntimeDirectory(dir), name); }
function controlPath(dir) { return runtimeFile(dir, 'control.json'); }
function statusPath(dir) { return runtimeFile(dir, 'public-status.json'); }
function readJson(file) {
  let fd;
  try {
    const entry = fs.lstatSync(file, { bigint: true });
    if (!entry.isFile() || entry.isSymbolicLink()) return { exists: true, unreadable: true };
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(fd, { bigint: true });
    if (!stat.isFile() || stat.dev !== entry.dev || stat.ino !== entry.ino) return { exists: true, unreadable: true };
    return { exists: true, value: JSON.parse(fs.readFileSync(fd, 'utf8')) };
  } catch (e) {
    return e.code === 'ENOENT' ? { exists: false } : { exists: true, unreadable: true };
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function syncDirectory(dir) {
  let fd;
  try { fd = fs.openSync(dir, 'r'); fs.fsyncSync(fd); } catch { /* atomic rename has completed */ }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function writeTextAtomic(file, text, mode = 0o600, beforeRename) {
  const tmp = file + '.tmp-' + randomUUID();
  let fd;
  let created = false;
  try {
    fd = fs.openSync(tmp, 'wx', mode);
    created = true;
    fs.fchmodSync(fd, mode);
    fs.writeFileSync(fd, text, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd); fd = undefined;
    if (beforeRename) beforeRename();
    fs.renameSync(tmp, file);
    created = false;
    syncDirectory(path.dirname(file));
  } catch (e) { throw fail(e.code && /^[A-Z_]+$/.test(e.code) ? e.code : 'CONTROL_WRITE_FAILED'); }
  finally {
    if (fd !== undefined) fs.closeSync(fd);
    // tmp is an exact, locally-created sibling; never remove state roots or candidates.
    if (created) { try { fs.unlinkSync(tmp); } catch { /* preserve primary error */ } }
  }
}
function atomicSnapshot(file) {
  let fd;
  try {
    const entry = fs.lstatSync(file, { bigint: true });
    if (!entry.isFile() || entry.isSymbolicLink()) throw fail('CONTROL_FILE_UNSAFE');
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(fd, { bigint: true });
    if (!stat.isFile() || stat.dev !== entry.dev || stat.ino !== entry.ino) throw fail('CONTROL_FILE_UNSAFE');
    const bytes = fs.readFileSync(fd);
    return { stat, bytes, hash: createHash('sha256').update(bytes).digest('hex') };
  } catch (e) { if (e.code === 'ENOENT') return null; throw fail('CONTROL_FILE_UNSAFE'); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function backupBytes(file, bytes, code) {
  const backup = file + '.bak-' + randomUUID();
  let fd;
  try {
    fd = fs.openSync(backup, 'wx', 0o600);
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
  } catch { throw fail(code); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
  syncDirectory(path.dirname(backup));
}
function snapshotsEqual(a, b) {
  return (!a && !b) || !!(a && b && a.hash === b.hash && a.stat.dev === b.stat.dev && a.stat.ino === b.stat.ino && a.stat.mode === b.stat.mode && a.stat.mtimeNs === b.stat.mtimeNs && a.stat.ctimeNs === b.stat.ctimeNs);
}
function writeJsonAtomic(file, value, expectedSnapshot = undefined) {
  return writeJsonAtomicChecked(file, value, expectedSnapshot);
}
// The verifier is an internal closure, never accepted from public options or RPC.
function writeJsonAtomicChecked(file, value, expectedSnapshot, verifyActive) {
  absolute(file, 'CONTROL_FILE_REQUIRED');
  assertRuntimeDirectory(path.dirname(file));
  const absoluteFile = path.resolve(file);
  const snapshot = atomicSnapshot(absoluteFile);
  if (expectedSnapshot !== undefined && !snapshotsEqual(snapshot, expectedSnapshot)) throw fail('CONTROL_CONFIG_CHANGED');
  const text = JSON.stringify(value) + '\n';
  if (snapshot) backupBytes(absoluteFile, snapshot.bytes, 'CONTROL_BACKUP_FAILED');
  writeTextAtomic(absoluteFile, text, 0o600, () => {
    if (verifyActive) verifyActive();
    const latest = atomicSnapshot(absoluteFile);
    if (!snapshotsEqual(snapshot, latest)) throw fail('CONTROL_CONFIG_CHANGED');
  });
}
function defaultControl() {
  // Internal construction template only: empty binding identity is never persisted.
  return { schema: SCHEMA, toggleRevision: 0, enabled: false, forBindingId: '', forBindingRevision: 0, leaseExpiresAt: null, requestedBy: 'local-ui', updatedAt: 0, adapterContract: { ...CONTRACT } };
}
function validateControl(value) {
  const fields = ['schema', 'toggleRevision', 'enabled', 'forBindingId', 'forBindingRevision', 'leaseExpiresAt', 'requestedBy', 'updatedAt', 'adapterContract'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some((key) => !fields.includes(key))) throw fail('CONTROL_CORRUPT', 'object');
  if (value.schema !== SCHEMA) throw fail('CONTROL_CORRUPT', 'schema');
  if (!isInt(value.toggleRevision, 0)) throw fail('CONTROL_CORRUPT', 'toggleRevision');
  if (typeof value.enabled !== 'boolean') throw fail('CONTROL_CORRUPT', 'enabled');
  if (typeof value.forBindingId !== 'string' || !UUID_V4.test(value.forBindingId)) throw fail('CONTROL_CORRUPT', 'forBindingId');
  if (!isInt(value.forBindingRevision, 1)) throw fail('CONTROL_CORRUPT', 'forBindingRevision');
  if (!(value.leaseExpiresAt === null || isTime(value.leaseExpiresAt))) throw fail('CONTROL_CORRUPT', 'leaseExpiresAt');
  if (value.requestedBy !== 'local-ui') throw fail('CONTROL_CORRUPT', 'requestedBy');
  if (!isTime(value.updatedAt)) throw fail('CONTROL_CORRUPT', 'updatedAt');
  if (!contractOk(value.adapterContract)) throw fail('CONTROL_CONTRACT', 'adapterContract');
  return value;
}
function controlFromSnapshot(file, snapshot) {
  const remember = (record) => {
    controlSnapshots.set(record, { file, snapshot });
    return record;
  };
  if (!snapshot) return remember({ exists: false, value: null, valid: false, code: 'CONTROL_ABSENT' });
  let value;
  try { value = JSON.parse(snapshot.bytes.toString('utf8')); }
  catch { return remember({ exists: true, value: null, valid: false, code: 'CONTROL_UNREADABLE' }); }
  try { validateControl(value); return remember({ exists: true, value, valid: true, code: '' }); }
  catch (e) { return remember({ exists: true, value: null, valid: false, code: e.code || 'CONTROL_CORRUPT' }); }
}
function readControl(dir) {
  const file = controlPath(dir);
  let snapshot;
  try { snapshot = atomicSnapshot(file); }
  catch { return { exists: true, value: null, valid: false, code: 'CONTROL_UNREADABLE' }; }
  return controlFromSnapshot(file, snapshot);
}
function assertExpectedControl(file, snapshot, expectedControl) {
  if (expectedControl === undefined) return; // Legacy direct callers have no prior probe.
  const expected = controlSnapshots.get(expectedControl);
  if (!expected || !sameLocalPath(expected.file, file) || !snapshotsEqual(expected.snapshot, snapshot)) throw fail('CONTROL_CONFIG_CHANGED');
}
function withControlLock(dir, fn) {
  const lock = runtimeFile(dir, '.control-write.lock');
  try { fs.mkdirSync(lock, { mode: 0o700 }); }
  catch (e) { throw fail(e.code === 'EEXIST' ? 'CONTROL_LOCKED' : 'CONTROL_LOCK_FAILED'); }
  try { return fn(); }
  finally { try { fs.rmdirSync(lock); } catch { /* never break an unknown lock */ } }
}
function saveControlUnlocked(dir, next, { allowCorrupt = false, expectedControl } = {}, verifyActive) {
  const file = controlPath(dir);
  // This exact snapshot authorises the write too; never rebase onto a newer toggle.
  const expected = atomicSnapshot(file);
  assertExpectedControl(file, expected, expectedControl);
  const current = controlFromSnapshot(file, expected);
  if (current.exists && !current.valid && !allowCorrupt) throw fail(current.code);
  validateControl(next);
  const prev = current.value || defaultControl();
  if (next.toggleRevision !== prev.toggleRevision) throw fail('CONTROL_CONFIG_CHANGED');
  // The frozen WIRE accepts only local-ui, independent of the caller's audit label.
  const value = { ...next, schema: SCHEMA, toggleRevision: increment(prev.toggleRevision, 'CONTROL_REVISION_EXHAUSTED'), requestedBy: 'local-ui', updatedAt: Date.now(), adapterContract: { ...CONTRACT } };
  validateControl(value);
  writeJsonAtomicChecked(file, value, expected, verifyActive);
  return value;
}
function saveControl(dir, next, _options = {}) {
  return withControlLock(dir, () => saveControlUnlocked(dir, next));
}
function enableForBinding(dir, options = {}) {
  return enableForBindingChecked(dir, options);
}
function enableForBindingChecked(dir, { bindingId, bindingRevision, requestedBy = 'local-ui', leaseExpiresAt = null, expectedControl } = {}, verifyActive) {
  assertRuntimeDirectory(dir);
  if (typeof bindingId !== 'string' || !UUID_V4.test(bindingId)) throw fail('ENABLE_INVALID_BINDING_ID');
  if (!isInt(bindingRevision, 1)) throw fail('ENABLE_INVALID_BINDING_REVISION');
  if (!(leaseExpiresAt === null || isTime(leaseExpiresAt))) throw fail('ENABLE_INVALID_LEASE');
  return withControlLock(dir, () => {
    if (verifyActive) verifyActive();
    const current = readControl(dir);
    return saveControlUnlocked(dir, { ...(current.value || defaultControl()), enabled: true, forBindingId: bindingId, forBindingRevision: bindingRevision, leaseExpiresAt }, { expectedControl: expectedControl === undefined ? current : expectedControl }, verifyActive);
  });
}
function disable(dir, _options = {}) {
  return withControlLock(dir, () => {
    const current = readControl(dir);
    let prev = current.value;
    if (!current.valid) {
      const binding = readBinding(dir);
      if (!binding.valid) throw fail('DISABLE_BINDING_REQUIRED');
      prev = { ...defaultControl(), forBindingId: binding.value.id, forBindingRevision: binding.value.revision };
    }
    // A recoverable corrupt file is retained byte-for-byte in a private backup.
    return saveControlUnlocked(dir, { ...prev, enabled: false, leaseExpiresAt: null }, { allowCorrupt: true, expectedControl: current });
  });
}
function effectiveEnabled(control, { now = Date.now() } = {}) {
  if (!control || control.enabled !== true) return false;
  return control.leaseExpiresAt === null || control.leaseExpiresAt === undefined || (isTime(control.leaseExpiresAt) && control.leaseExpiresAt > now);
}
function validateStatus(value) {
  if (!value || typeof value !== 'object') throw fail('STATUS_CORRUPT', 'object');
  if (value.schema !== SCHEMA) throw fail('STATUS_CORRUPT', 'schema');
  if (value.adapterContract !== CONTRACT.max) throw fail('STATUS_PROTOCOL', 'adapterContract');
  if (!isTime(value.writtenAt)) throw fail('STATUS_CORRUPT', 'writtenAt');
  if (!isInt(value.hostPid, 1)) throw fail('STATUS_CORRUPT', 'hostPid');
  if (typeof value.coreSha256 !== 'string' || !SHA256.test(value.coreSha256)) throw fail('STATUS_CORRUPT', 'coreSha256');
  if (value.coreSchema !== 1) throw fail('STATUS_CORRUPT', 'coreSchema');
  if (typeof value.stateEpoch !== 'string' || !ID36.test(value.stateEpoch)) throw fail('STATUS_CORRUPT', 'stateEpoch');
  if (!(value.storeEpoch === null || (typeof value.storeEpoch === 'string' && ID36.test(value.storeEpoch)))) throw fail('STATUS_CORRUPT', 'storeEpoch');
  if (!(value.globalTail === null || isInt(value.globalTail, 0))) throw fail('STATUS_CORRUPT', 'globalTail');
  const b = value.binding;
  const known = b && typeof b.id === 'string' && ID36.test(b.id) && isInt(b.revision, 1);
  const unknown = b && b.bound === false && b.id === null && b.revision === null;
  if (!b || typeof b.bound !== 'boolean' || (!known && !unknown) || typeof b.label !== 'string' || b.label.length > 80) throw fail('STATUS_CORRUPT', 'binding');
  if (typeof value.enabled !== 'boolean' || typeof value.canEnable !== 'boolean' || typeof value.dispatchReady !== 'boolean') throw fail('STATUS_CORRUPT', 'flags');
  if (typeof value.effectiveEnabled !== 'boolean') throw fail('STATUS_PROTOCOL', 'effectiveEnabled');
  if (value.dispatchReady !== (value.canEnable && value.effectiveEnabled)) throw fail('STATUS_PROTOCOL', 'dispatchReady equation');
  if (value.globalTail === null && (value.canEnable || value.dispatchReady)) throw fail('STATUS_CORRUPT', 'unknown transport readiness');
  if (!b.bound && (value.canEnable || value.effectiveEnabled || value.dispatchReady)) throw fail('STATUS_CORRUPT', 'unbound readiness');
  if (!SOURCE_CONTRACTS.has(value.sourceContract)) throw fail('STATUS_CORRUPT', 'sourceContract');
  const p = value.pending;
  if (!p || !isInt(p.queued, 0) || !PHASES.has(p.phase) || typeof p.uncertain !== 'boolean' || p.uncertain !== (p.phase === 'uncertain')) throw fail('STATUS_CORRUPT', 'pending');
  if (!(value.cooldownUntil === null || isTime(value.cooldownUntil))) throw fail('STATUS_CORRUPT', 'cooldownUntil');
  if (!(value.lastPollAt === null || isTime(value.lastPollAt))) throw fail('STATUS_CORRUPT', 'lastPollAt');
  if (!(value.error === null || (typeof value.error === 'object' && typeof value.error.code === 'string' && value.error.code.length > 0 && value.error.code.length <= 64 && isTime(value.error.at)))) throw fail('STATUS_CORRUPT', 'error');
  return value;
}
function pidAlive(pid) { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } }
function readStatus(dir, { now = Date.now(), alive = pidAlive } = {}) {
  const r = readJson(statusPath(dir));
  if (!r.exists) return { exists: false, connected: false, ready: false, value: null, code: 'STATUS_ABSENT' };
  if (r.unreadable) return { exists: true, connected: false, ready: false, value: null, code: 'STATUS_UNREADABLE' };
  let value;
  try { value = validateStatus(r.value); } catch (e) { return { exists: true, connected: false, ready: false, value: null, code: e.code || 'STATUS_CORRUPT' }; }
  const age = now - value.writtenAt;
  const connected = age >= 0 && age <= CONNECT_WINDOW_MS && !!alive(value.hostPid);
  return { exists: true, connected, ready: connected && value.dispatchReady === true, value, code: '' };
}
function summarize(status) {
  if (!status || !status.exists || !status.value) return { connected: false, ready: false, code: status ? status.code : 'STATUS_ABSENT', text: '未连接', canEnable: false, enabled: false, effectiveEnabled: false, dispatchReady: false };
  const v = status.value;
  const label = !status.connected ? '未连接' : v.dispatchReady ? '已开启' : !v.enabled ? (v.canEnable ? '可开启（当前关闭）' : '不可开启') : (v.canEnable ? '已开启（未生效：租约或运行态）' : '已开启（未生效：能力不足）');
  return { connected: status.connected, ready: status.ready, code: '', text: label, canEnable: v.canEnable, enabled: v.enabled, effectiveEnabled: v.effectiveEnabled, dispatchReady: v.dispatchReady === true, pending: v.pending, binding: v.binding, sourceContract: v.sourceContract, stateEpoch: v.stateEpoch, error: v.error };
}
function normalizeSessionId(raw) {
  if (typeof raw !== 'string') throw fail('SESSION_ID_INVALID');
  const text = raw.trim();
  const bare = text.startsWith('session-') ? text.slice(8) : text;
  if (!ID36.test(bare)) throw fail('SESSION_ID_INVALID');
  return 'session-' + bare;
}
function readBinding(dir) {
  const root = assertRuntimeDirectory(dir);
  const r = readJson(path.join(root, 'binding.json'));
  const invalid = (code) => ({ exists: true, valid: false, committed: false, value: null, code });
  if (!r.exists) return { exists: false, valid: false, committed: false, value: null, code: 'BINDING_ABSENT' };
  if (r.unreadable) return invalid('BINDING_UNREADABLE');
  const b = r.value;
  const fields = ['schema', 'id', 'sessionId', 'revision', 'state', 'setupNonce', 'createdAt'];
  if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).some((key) => !fields.includes(key)) || b.schema !== 1 || !UUID_V4.test(b.id || '') || !UUID_V4.test(b.setupNonce || '') || !isInt(b.revision, 1) || b.revision !== Number(ROOT_NAME.exec(path.basename(root))[1]) || !['preparing', 'committed'].includes(b.state) || !isTime(b.createdAt)) return invalid('BINDING_CORRUPT');
  try { if (normalizeSessionId(b.sessionId) !== b.sessionId) return invalid('BINDING_CORRUPT'); }
  catch { return invalid('BINDING_CORRUPT'); }
  return { exists: true, valid: true, committed: b.state === 'committed', value: b, code: '' };
}
function readProfile(file) {
  noSymlinks(path.dirname(file), 'PROFILE_PATH_UNSAFE');
  let fd;
  try {
    const entry = fs.lstatSync(file, { bigint: true });
    if (!entry.isFile() || entry.isSymbolicLink()) throw fail('PROFILE_PATH_UNSAFE');
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(fd, { bigint: true });
    if (!stat.isFile() || stat.dev !== entry.dev || stat.ino !== entry.ino) throw fail('PROFILE_PATH_UNSAFE');
    const bytes = fs.readFileSync(fd);
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes)) throw fail('PROFILE_YAML_INVALID');
    return { text, bytes, stat, hash: createHash('sha256').update(bytes).digest('hex') };
  } catch (e) { throw fail(e.code === 'ENOENT' ? 'PROFILE_ABSENT' : ['ELOOP', 'PROFILE_PATH_UNSAFE'].includes(e.code) ? 'PROFILE_PATH_UNSAFE' : e.code === 'PROFILE_YAML_INVALID' ? e.code : 'PROFILE_UNREADABLE'); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function parsePatch(text) {
  let docs;
  try { docs = YAML.parseAllDocuments(text, { version: '1.2', schema: 'core', strict: true, uniqueKeys: true, keepSourceTokens: true, prettyErrors: false }); }
  catch { throw fail('PROFILE_YAML_INVALID'); }
  if (docs.length !== 1 || docs[0].errors.length || docs[0].warnings.length) throw fail('PROFILE_YAML_INVALID');
  const doc = docs[0];
  YAML.visit(doc, (_key, node) => {
    if (YAML.isAlias(node) || (YAML.isNode(node) && (node.anchor || node.tag))) throw fail('PROFILE_YAML_AMBIGUOUS');
    if (YAML.isMap(node)) for (const pair of node.items) {
      if (!YAML.isScalar(pair.key) || typeof pair.key.value !== 'string' || pair.key.value === '<<') throw fail('PROFILE_YAML_AMBIGUOUS');
    }
  });
  if (!YAML.isSeq(doc.contents)) throw fail('PROFILE_YAML_INVALID');
  const rows = [];
  for (const row of doc.contents.items) {
    if (!YAML.isMap(row)) throw fail('PROFILE_YAML_INVALID');
    if (row.get('id') === RUNTIME_ROW_ID || row.get('name') === RUNTIME_PKG) rows.push(row);
  }
  if (rows.length > 1) throw fail('PROFILE_AMBIGUOUS');
  if (rows.length === 0) return { doc, row: null };
  const row = rows[0];
  if (row.get('id') !== RUNTIME_ROW_ID || (row.has('name') && row.get('name') !== RUNTIME_PKG)) throw fail('PROFILE_ROW_INVALID');
  const config = row.get('config', true);
  if (!YAML.isMap(config)) throw fail('PROFILE_CONFIG_MISSING');
  return { doc, row, config };
}
function runtimePatch(profilesRoot) {
  const root = assertProfilesRoot(profilesRoot);
  let names;
  try { names = fs.readdirSync(root, { withFileTypes: true }); } catch { throw fail('PROFILE_UNREADABLE'); }
  const found = [];
  for (const entry of names.sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.isSymbolicLink()) throw fail('PROFILE_PATH_UNSAFE');
    if (!entry.isDirectory()) continue;
    const file = path.join(root, entry.name, 'cordis.patch.yml');
    let snapshot;
    try { snapshot = readProfile(file); } catch (e) { if (e.code === 'PROFILE_ABSENT') continue; throw e; }
    // Parse every patch, rather than missing a block/quoted scalar package name.
    const parsed = parsePatch(snapshot.text);
    if (parsed.row) found.push({ profile: entry.name, file, text: snapshot.text, snapshot, ...parsed });
  }
  if (found.length !== 1) throw fail('PROFILE_AMBIGUOUS');
  return found[0];
}
function configValues(patch) {
  const read = (key) => {
    const node = patch.config.get(key, true);
    if (node === undefined || node === null) return null;
    if (!YAML.isScalar(node)) throw fail('PROFILE_CONFIG_INVALID', key);
    return node.value;
  };
  const cfg = { enabled: read('enabled'), sessionId: read('sessionId'), revision: read('revision'), dataDirectory: read('dataDirectory'), agentClientConfigPath: read('agentClientConfigPath') };
  if (typeof cfg.enabled !== 'boolean' || !isInt(cfg.revision, 1)) throw fail('PROFILE_CONFIG_INVALID', 'revision or enabled');
  // A configured, disabled shell may have no first binding yet. That is not a bind success.
  if (cfg.sessionId !== '' && normalizeSessionId(cfg.sessionId) !== cfg.sessionId) throw fail('PROFILE_CONFIG_INVALID', 'sessionId');
  // These are pure checks: never open credentials or touch an invalid configured root.
  const directory = absolute(cfg.dataDirectory, 'RUNTIME_DIRECTORY_REQUIRED');
  if (cfg.agentClientConfigPath !== null && (!isLocalAbsolutePath(cfg.agentClientConfigPath) || PRIVATE_STATE_NAMES.some((name) => sameLocalPath(cfg.agentClientConfigPath, path.join(directory, name))))) throw fail('PROFILE_CONFIG_INVALID', 'agentClientConfigPath');
  cfg.dataDirectory = assertRuntimeDirectory(cfg.dataDirectory);
  if (Number(ROOT_NAME.exec(path.basename(cfg.dataDirectory))[1]) !== cfg.revision) throw fail('PROFILE_CONFIG_INVALID', 'root revision');
  return cfg;
}
function readActiveConfig(profilesRoot) {
  const patch = runtimePatch(profilesRoot);
  return { profile: patch.profile, file: patch.file, config: configValues(patch) };
}
function assertExpectedActive(patch, cfg, expectedActive) {
  if (expectedActive === undefined) return; // Legacy direct UI callers have no captured snapshot.
  const fields = ['enabled', 'sessionId', 'revision', 'dataDirectory', 'agentClientConfigPath'];
  if (!expectedActive || typeof expectedActive !== 'object' || Array.isArray(expectedActive) || !expectedActive.config || typeof expectedActive.config !== 'object' || Array.isArray(expectedActive.config) || expectedActive.profile !== patch.profile || expectedActive.file !== patch.file || fields.some((key) => expectedActive.config[key] !== cfg[key])) throw fail('PROFILE_CONFIG_CHANGED');
}
function unchanged(patch) {
  const latest = readProfile(patch.file);
  if (latest.hash !== patch.snapshot.hash || latest.stat.dev !== patch.snapshot.stat.dev || latest.stat.ino !== patch.snapshot.stat.ino || latest.stat.mode !== patch.snapshot.stat.mode || latest.stat.mtimeNs !== patch.snapshot.stat.mtimeNs || latest.stat.ctimeNs !== patch.snapshot.stat.ctimeNs) throw fail('PROFILE_CONFIG_CHANGED');
}
function backupProfile(patch) {
  const file = patch.file + '.backup-' + randomUUID();
  let fd;
  try {
    fd = fs.openSync(file, 'wx', 0o600);
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, patch.snapshot.bytes);
    fs.fsyncSync(fd);
  } catch { throw fail('PROFILE_BACKUP_FAILED'); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
  syncDirectory(path.dirname(file));
}
function validRequest(request, cfg, now) {
  const fields = ['schema', 'nonce', 'sessionId', 'revision', 'createdAt', 'expiresAt'];
  return request && typeof request === 'object' && !Array.isArray(request) && Object.keys(request).every((key) => fields.includes(key)) && request.schema === 1 && UUID_V4.test(request.nonce || '') && request.sessionId === cfg.sessionId && request.revision === cfg.revision && isTime(request.createdAt) && request.createdAt <= now && isTime(request.expiresAt) && request.expiresAt > request.createdAt && request.expiresAt - request.createdAt <= BIND_TTL_MS;
}
function withProfileLock(patch, profilesRoot, fn) {
  const lock = patch.file + '.dualtransfer-bind.lock';
  try { fs.mkdirSync(lock, { mode: 0o700 }); }
  catch (e) { throw fail(e.code === 'EEXIST' ? 'PROFILE_LOCKED' : 'PROFILE_LOCK_FAILED'); }
  try {
    // Re-discover the unique active row under the lock, not merely the old file.
    // Another profile may have appeared or taken over while this lock was acquired.
    const fresh = runtimePatch(profilesRoot);
    if (fresh.profile !== patch.profile || fresh.file !== patch.file || fresh.snapshot.hash !== patch.snapshot.hash) throw fail('PROFILE_CONFIG_CHANGED');
    unchanged(patch);
    return fn(fresh);
  } finally {
    // This is the exact lock successfully created by this operation only.
    try { fs.rmdirSync(lock); } catch { /* leave a fail-closed lock */ }
  }
}
function renewRequest(dir, cfg, now, create, verifyProfile) {
  // Share the frozen Core's owner barrier. Never reclaim even a stale owner here.
  const lock = runtimeFile(dir, 'owner.lock');
  const contents = JSON.stringify({ pid: process.pid, nonce: randomUUID() });
  let fd;
  try { fd = fs.openSync(lock, 'wx', 0o600); }
  catch (e) { throw fail(e.code === 'EEXIST' ? 'PENDING_HOST_BUSY' : 'BIND_REQUEST_INVALID'); }
  try {
    fs.writeFileSync(fd, contents, 'utf8'); fs.fsyncSync(fd);
    if (readBinding(dir).exists) return null;
    // Partial/consumed first binding is never a fresh request, even without binding.json.
    for (const name of ['setup-used.json', 'cursor.json', 'journal.json', 'owner-recovery.lock']) {
      if (readJson(runtimeFile(dir, name)).exists) throw fail('BIND_REQUEST_CONSUMED');
    }
    const requestPath = runtimeFile(dir, 'bind-request.json');
    const expected = atomicSnapshot(requestPath);
    const existing = readJson(requestPath);
    if (!existing.exists) return null;
    if (existing.unreadable || !validRequest(existing.value, cfg, now)) throw fail('BIND_REQUEST_INVALID');
    verifyProfile();
    const renewed = create(cfg.revision);
    writeJsonAtomic(requestPath, renewed, expected);
    return renewed;
  } catch (e) { throw fail(e.code && /^[A-Z_]+$/.test(e.code) ? e.code : 'BIND_REQUEST_INVALID'); }
  finally {
    const owned = fs.fstatSync(fd, { bigint: true });
    fs.closeSync(fd);
    // Never follow a replaced symlink or remove a different owner's lock.
    try {
      const present = atomicSnapshot(lock);
      if (present && present.stat.dev === owned.dev && present.stat.ino === owned.ino && present.bytes.toString('utf8') === contents) fs.unlinkSync(lock);
    } catch { /* fail closed */ }
  }
}
function enableForActiveBinding(dir, { profilesRoot, sessionId, revision, bindingId, bindingRevision, requestedBy = 'local-ui', expectedActive, expectedControl, verifyHost } = {}) {
  // Both caller-supplied roots must pass pure syntax checks before either is touched.
  absolute(dir, 'RUNTIME_DIRECTORY_REQUIRED');
  absolute(profilesRoot, 'PROFILES_ROOT_REQUIRED');
  const root = assertRuntimeDirectory(dir);
  assertProfilesRoot(profilesRoot);
  const sid = normalizeSessionId(sessionId);
  const initial = runtimePatch(profilesRoot);
  configValues(initial); // Reject invalid configured paths before creating the profile lock.
  return withProfileLock(initial, profilesRoot, (patch) => {
    const cfg = configValues(patch);
    assertExpectedActive(patch, cfg, expectedActive);
    if (cfg.enabled !== true) throw fail('PROFILE_CONFIG_CHANGED');
    const binding = readBinding(root);
    if (!sameLocalPath(cfg.dataDirectory, root) || cfg.sessionId !== sid || cfg.revision !== revision || !binding.valid || !binding.committed || binding.value.sessionId !== sid || binding.value.revision !== revision || binding.value.revision !== bindingRevision || binding.value.id !== bindingId) throw fail('PROFILE_CONFIG_CHANGED');
    const verifyActive = () => {
      if (verifyHost) verifyHost();
      // Re-scan uniqueness as well as the original bytes/stat; a new profile is drift too.
      const fresh = runtimePatch(profilesRoot);
      if (fresh.profile !== patch.profile || fresh.file !== patch.file || fresh.snapshot.hash !== patch.snapshot.hash) throw fail('PROFILE_CONFIG_CHANGED');
      unchanged(patch);
      const current = readBinding(root);
      const identity = ['schema', 'id', 'sessionId', 'revision', 'state', 'setupNonce', 'createdAt'];
      if (!current.valid || !current.committed || identity.some((key) => current.value[key] !== binding.value[key])) throw fail('PROFILE_CONFIG_CHANGED');
    };
    unchanged(patch);
    return enableForBindingChecked(root, { bindingId, bindingRevision, requestedBy, expectedControl }, verifyActive);
  });
}
function rebindSession(dir, { sessionId, now = Date.now(), ttlMs = BIND_TTL_MS, operator = 'local-ui', profilesRoot, expectedActive } = {}) {
  absolute(dir, 'RUNTIME_DIRECTORY_REQUIRED');
  absolute(profilesRoot, 'PROFILES_ROOT_REQUIRED');
  const currentDir = assertRuntimeDirectory(dir);
  assertProfilesRoot(profilesRoot);
  const sid = normalizeSessionId(sessionId);
  if (!isTime(now) || !isInt(ttlMs, 60000) || ttlMs > BIND_TTL_MS || !Number.isSafeInteger(now + ttlMs)) throw fail('BIND_TTL_INVALID');
  const initial = runtimePatch(profilesRoot);
  configValues(initial);
  return withProfileLock(initial, profilesRoot, (patch) => {
    const cfg = configValues(patch);
    assertExpectedActive(patch, cfg, expectedActive);
    if (!sameLocalPath(cfg.dataDirectory, currentDir)) throw fail('PROFILE_CONFIG_CHANGED');
    const result = (extra) => ({ changed: false, renewed: false, profile: patch.profile, sessionId: sid, revision: cfg.revision, dataDirectory: cfg.dataDirectory, expiresAt: null, operator, ...extra });
    const request = (revision) => ({ schema: 1, nonce: randomUUID(), sessionId: sid, revision, createdAt: now, expiresAt: now + ttlMs });
    if (cfg.sessionId === sid) {
      // Existence alone is the commit barrier, including corrupt/unreadable bindings.
      if (readBinding(currentDir).exists) return result({});
      if (!readJson(runtimeFile(currentDir, 'bind-request.json')).exists) return result({});
      const renewed = renewRequest(currentDir, cfg, now, request, () => unchanged(patch));
      return renewed ? result({ renewed: true, expiresAt: renewed.expiresAt }) : result({});
    }
    let revision = cfg.revision;
    let names;
    try { names = fs.readdirSync(path.dirname(currentDir)); }
    catch { throw fail('RUNTIME_DIRECTORY_UNREADABLE'); }
    // Basenames alone establish history: never inspect any old root or symlink target.
    for (const name of names) {
      const match = ROOT_NAME.exec(name);
      if (!match) continue;
      const historical = Number(match[1]);
      if (!isInt(historical, 1)) throw fail('PROFILE_REVISION_EXHAUSTED');
      revision = Math.max(revision, historical);
    }
    let target;
    for (let guard = 0; guard < 50; guard++) {
      revision = increment(revision, 'PROFILE_REVISION_EXHAUSTED');
      target = path.join(path.dirname(currentDir), 'agent-wake-runtime-r' + revision);
      // Exclusive mkdir: files, empty/dirty directories and symlinks are all occupied.
      try { fs.mkdirSync(target, { mode: 0o700 }); break; }
      catch (e) { if (e.code !== 'EEXIST') throw fail('RUNTIME_CREATE_FAILED'); target = null; }
    }
    if (!target) throw fail('REBIND_EXHAUSTED');
    const fresh = request(revision);
    writeJsonAtomic(runtimeFile(target, 'bind-request.json'), fresh);
    for (const [key, value] of Object.entries({ sessionId: sid, revision, dataDirectory: target })) {
      // Replace the complete scalar node (not a line); block scalar content cannot leak.
      patch.config.set(key, patch.doc.createNode(value));
    }
    const rendered = String(patch.doc);
    const check = parsePatch(rendered);
    if (!check.row || configValues(check).sessionId !== sid || configValues(check).revision !== revision) throw fail('PROFILE_RENDER_INVALID');
    unchanged(patch);
    backupProfile(patch);
    writeTextAtomic(patch.file, rendered, Number(patch.snapshot.stat.mode & 0o777n), () => unchanged(patch));
    return result({ changed: true, revision, dataDirectory: target, expiresAt: fresh.expiresAt });
  });
}
// operation-v1: serialisable, private, exact plans. Never accept plans or paths via RPC.
const OPERATION_TTL_MS = 120000;
const CORE_SHA256 = '9fc17b19d0f62d0391de7105b8269368288c9f67c8f6c27bf6337b98b41ad036';
function cas(snapshot) {
  if (!snapshot) return null;
  return { hash: snapshot.hash, dev: String(snapshot.stat.dev), ino: String(snapshot.stat.ino),
    mode: String(snapshot.stat.mode), mtimeNs: String(snapshot.stat.mtimeNs), ctimeNs: String(snapshot.stat.ctimeNs) };
}
function casEqual(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function validateClock(now, preparedAt, expiresAt) {
  if (!isTime(now) || !isTime(preparedAt) || !isTime(expiresAt)
    || expiresAt !== preparedAt + OPERATION_TTL_MS || now < preparedAt || now >= expiresAt) throw fail('OPERATION_EXPIRED');
}
function checkConfiguration(profilesRoot) {
  // No runtime/control/status/credential reads. Incomplete first-install configuration is explicit.
  try {
    const { config } = readActiveConfig(profilesRoot);
    if (!config.agentClientConfigPath || !isLocalAbsolutePath(config.agentClientConfigPath)) return { configurationRequired: true };
    return { configurationRequired: false };
  } catch (error) {
    if (['PROFILES_ROOT_REQUIRED', 'PROFILE_AMBIGUOUS', 'PROFILE_UNREADABLE', 'PROFILE_CONFIG_MISSING',
      'PROFILE_CONFIG_INVALID', 'RUNTIME_DIRECTORY_REQUIRED', 'RUNTIME_DIRECTORY_INVALID', 'SESSION_ID_INVALID'].includes(error.code)) return { configurationRequired: true };
    throw error;
  }
}
function assertPlan(plan) {
  if (!plan || plan.schema !== 1 || plan.protocol !== 'operation-v1' || !UUID_V4.test(plan.operationId || '')
    || !['fresh', 'existing'].includes(plan.kind) || !isTime(plan.preparedAt)
    || plan.expiresAt !== plan.preparedAt + OPERATION_TTL_MS) throw fail('OPERATION_PLAN_INVALID');
  assertProfilesRoot(plan.profilesRoot); assertRuntimeDirectory(plan.target.dataDirectory);
  if (normalizeSessionId(plan.target.sessionId) !== plan.target.sessionId || plan.target.enabled !== true
    || Number(ROOT_NAME.exec(path.basename(plan.target.dataDirectory))[1]) !== plan.target.revision
    || !isLocalAbsolutePath(plan.target.agentClientConfigPath)) throw fail('OPERATION_PLAN_INVALID');
  return plan;
}
function targetMatches(a, b) {
  return ['enabled', 'sessionId', 'revision', 'dataDirectory', 'agentClientConfigPath'].every(key => a[key] === b[key]);
}
function assertSource(plan, patch) {
  if (patch.file !== plan.source.file || patch.profile !== plan.source.profile || !casEqual(cas(patch.snapshot), plan.source.cas)
    || !targetMatches(configValues(patch), plan.source.config)) throw fail('PROFILE_CONFIG_CHANGED');
}
function prepareBinding({ profilesRoot, sessionId, operationId, now = Date.now(), expiresAt = now + OPERATION_TTL_MS } = {}) {
  const root = assertProfilesRoot(profilesRoot), sid = normalizeSessionId(sessionId);
  if (!UUID_V4.test(operationId || '')) throw fail('OPERATION_ID_INVALID');
  validateClock(now, now, expiresAt);
  const patch = runtimePatch(root), config = configValues(patch);
  if (!config.agentClientConfigPath || !isLocalAbsolutePath(config.agentClientConfigPath)) throw fail('CONFIGURATION_REQUIRED');
  const binding = readBinding(config.dataDirectory);
  if (binding.exists && !binding.valid) throw fail(binding.code);
  let kind = 'fresh', targetRoot = config.dataDirectory, revision = config.revision;
  const priorStatus = readStatus(config.dataDirectory, { now });
  if (config.sessionId === sid && binding.committed && binding.value.sessionId === sid) kind = 'existing';
  else {
    // Never adopt a partial request or inspect old reliable data to make it look like first bind.
    let occupied = true;
    try { fs.lstatSync(targetRoot); } catch (e) { if (e.code === 'ENOENT') occupied = false; else throw fail('RUNTIME_DIRECTORY_UNSAFE'); }
    if (occupied || (config.sessionId && config.sessionId !== sid)) {
      let entries; try { entries = fs.readdirSync(path.dirname(targetRoot)); } catch { throw fail('RUNTIME_DIRECTORY_UNREADABLE'); }
      for (const name of entries) { const m = ROOT_NAME.exec(name); if (m) {
        if (!isInt(Number(m[1]), 1)) throw fail('PROFILE_REVISION_EXHAUSTED');
        revision = Math.max(revision, Number(m[1]));
      } }
      revision = increment(revision, 'PROFILE_REVISION_EXHAUSTED');
      targetRoot = path.join(path.dirname(targetRoot), 'agent-wake-runtime-r' + revision);
    }
  }
  const target = { ...config, enabled: true, sessionId: sid, revision, dataDirectory: targetRoot };
  return { schema: 1, protocol: 'operation-v1', operationId, profilesRoot: root, kind, preparedAt: now, expiresAt,
    source: { file: patch.file, profile: patch.profile, cas: cas(patch.snapshot), config }, target,
    request: kind === 'fresh' ? { schema: 1, nonce: randomUUID(), sessionId: sid, revision, createdAt: now, expiresAt } : null,
    binding: kind === 'existing' ? binding.value : null,
    previousStateEpoch: priorStatus.value?.stateEpoch ?? null };
}
function commitBinding(plan, { now = Date.now() } = {}) {
  assertPlan(plan); validateClock(now, plan.preparedAt, plan.expiresAt);
  const initial = runtimePatch(plan.profilesRoot); assertSource(plan, initial);
  return withProfileLock(initial, plan.profilesRoot, patch => {
    assertSource(plan, patch);
    if (plan.kind === 'fresh') {
      // Exclusive creation of exactly the durable target. No alternate rN and no nonce regeneration.
      try { fs.mkdirSync(plan.target.dataDirectory, { mode: 0o700 }); fs.chmodSync(plan.target.dataDirectory, 0o700); }
      catch (e) { throw fail(e.code === 'EEXIST' ? 'BIND_TARGET_OCCUPIED' : 'RUNTIME_CREATE_FAILED'); }
      writeJsonAtomic(runtimeFile(plan.target.dataDirectory, 'bind-request.json'), plan.request, null);
    } else {
      const current = readBinding(plan.target.dataDirectory);
      if (!current.committed || !casEqual(current.value, plan.binding)) throw fail('BINDING_CHANGED');
    }
    for (const [key, value] of Object.entries(plan.target)) patch.config.set(key, patch.doc.createNode(value));
    const rendered = String(patch.doc), check = parsePatch(rendered);
    if (!check.row || !targetMatches(configValues(check), plan.target)) throw fail('PROFILE_RENDER_INVALID');
    unchanged(patch); backupProfile(patch);
    writeTextAtomic(patch.file, rendered, Number(patch.snapshot.stat.mode & 0o777n), () => unchanged(patch));
    return { changed: plan.kind === 'fresh' || !targetMatches(plan.source.config, plan.target) };
  });
}
function reconcileBinding(plan) {
  assertPlan(plan);
  const active = readActiveConfig(plan.profilesRoot);
  if (active.profile !== plan.source.profile || active.file !== plan.source.file || !targetMatches(active.config, plan.target)) return { targetCurrent: false, committed: false, changed: false };
  const b = readBinding(plan.target.dataDirectory);
  const matches = b.valid && b.value.sessionId === plan.target.sessionId && b.value.revision === plan.target.revision
    && (plan.kind === 'fresh' ? b.value.setupNonce === plan.request.nonce : casEqual(b.value, plan.binding));
  return { targetCurrent: true, committed: !!(matches && b.committed),
    changed: plan.kind === 'fresh' || !targetMatches(plan.source.config, plan.target), binding: matches ? b.value : null };
}
function readHostEvidence(plan, { now = Date.now(), enablePlan = null, currentEpoch } = {}) {
  const binding = reconcileBinding(plan);
  if (!binding.targetCurrent || !binding.committed) return { bindingVerified: false, confirmed: false };
  const status = readStatus(plan.target.dataDirectory, { now }), s = status.value;
  const fresh = status.connected && s.coreSha256 === CORE_SHA256 && s.sourceContract === 'verified'
    && s.binding.bound && s.binding.id === binding.binding.id && s.binding.revision === plan.target.revision
    && s.canEnable && s.stateEpoch !== plan.previousStateEpoch && s.writtenAt > plan.preparedAt
    && typeof currentEpoch === 'string' && s.stateEpoch === currentEpoch;
  const c = readControl(plan.target.dataDirectory);
  const controlMatches = enablePlan && c.valid && casEqual(c.value, enablePlan.value);
  return { bindingVerified: !!fresh, binding: binding.binding, epoch: fresh ? s.stateEpoch : null,
    confirmed: !!(fresh && enablePlan && controlMatches && s.writtenAt > enablePlan.value.updatedAt
      && s.enabled && s.effectiveEnabled && s.dispatchReady && effectiveEnabled(c.value, { now })) };
}
function prepareEnable(plan, { now = Date.now(), currentEpoch } = {}) {
  assertPlan(plan); validateClock(now, plan.preparedAt, plan.expiresAt);
  const evidence = readHostEvidence(plan, { now, currentEpoch });
  if (!evidence.bindingVerified) throw fail('HOST_BINDING_UNCONFIRMED');
  const patch = runtimePatch(plan.profilesRoot);
  if (!targetMatches(configValues(patch), plan.target)) throw fail('PROFILE_CONFIG_CHANGED');
  const file = controlPath(plan.target.dataDirectory), snapshot = atomicSnapshot(file);
  const current = controlFromSnapshot(file, snapshot);
  if (current.exists && !current.valid) throw fail(current.code);
  const value = { ...(current.value || defaultControl()), enabled: true,
    toggleRevision: increment(current.value?.toggleRevision ?? 0, 'CONTROL_REVISION_EXHAUSTED'),
    forBindingId: evidence.binding.id, forBindingRevision: evidence.binding.revision,
    leaseExpiresAt: null, requestedBy: 'local-ui', updatedAt: now, adapterContract: { ...CONTRACT } };
  validateControl(value);
  return { schema: 1, operationId: plan.operationId, file, sourceCas: cas(snapshot),
    profileCas: cas(patch.snapshot), binding: evidence.binding, stateEpoch: evidence.epoch, value };
}
function commitEnable(plan, enablePlan, { now = Date.now() } = {}) {
  assertPlan(plan); validateClock(now, plan.preparedAt, plan.expiresAt);
  if (enablePlan.operationId !== plan.operationId || enablePlan.file !== controlPath(plan.target.dataDirectory)) throw fail('ENABLE_PLAN_INVALID');
  validateControl(enablePlan.value);
  const initial = runtimePatch(plan.profilesRoot);
  return withProfileLock(initial, plan.profilesRoot, patch => {
    if (!targetMatches(configValues(patch), plan.target) || !casEqual(cas(patch.snapshot), enablePlan.profileCas)) throw fail('PROFILE_CONFIG_CHANGED');
    const b = readBinding(plan.target.dataDirectory);
    if (!b.committed || !casEqual(b.value, enablePlan.binding)) throw fail('BINDING_CHANGED');
    return withControlLock(plan.target.dataDirectory, () => {
      const snapshot = atomicSnapshot(enablePlan.file);
      if (!casEqual(cas(snapshot), enablePlan.sourceCas)) throw fail('CONTROL_CONFIG_CHANGED');
      writeJsonAtomicChecked(enablePlan.file, enablePlan.value, snapshot, () => unchanged(patch));
      return enablePlan.value;
    });
  });
}
function readActiveSnapshot({ profilesRoot, now = Date.now() } = {}) {
  const check = checkConfiguration(profilesRoot);
  if (check.configurationRequired) return { configurationRequired: true, code: check.code || 'CONFIGURATION_REQUIRED' };
  const active = readActiveConfig(profilesRoot), dir = active.config.dataDirectory;
  return { configurationRequired: false, active, binding: readBinding(dir), control: readControl(dir), status: readStatus(dir, { now }) };
}
function disableForActiveBinding(dir, { profilesRoot, sessionId, revision, bindingId, bindingRevision, expectedActive, expectedControl } = {}) {
  absolute(dir, 'RUNTIME_DIRECTORY_REQUIRED'); absolute(profilesRoot, 'PROFILES_ROOT_REQUIRED');
  const root = assertRuntimeDirectory(dir), sid = normalizeSessionId(sessionId);
  const initial = runtimePatch(profilesRoot); configValues(initial);
  return withProfileLock(initial, profilesRoot, patch => {
    const cfg = configValues(patch); assertExpectedActive(patch, cfg, expectedActive);
    const binding = readBinding(root);
    if (!sameLocalPath(cfg.dataDirectory, root) || cfg.sessionId !== sid || cfg.revision !== revision
      || !binding.valid || !binding.committed || binding.value.sessionId !== sid || binding.value.revision !== revision
      || binding.value.id !== bindingId || binding.value.revision !== bindingRevision) throw fail('PROFILE_CONFIG_CHANGED');
    const verifyActive = () => {
      const fresh = runtimePatch(profilesRoot), current = readBinding(root);
      if (fresh.file !== patch.file || fresh.profile !== patch.profile || fresh.snapshot.hash !== patch.snapshot.hash
        || !current.committed || !casEqual(current.value, binding.value)) throw fail('PROFILE_CONFIG_CHANGED');
      unchanged(patch);
    };
    return withControlLock(root, () => {
      verifyActive();
      const current = readControl(root);
      if (expectedControl !== undefined) assertExpectedControl(controlPath(root), atomicSnapshot(controlPath(root)), expectedControl);
      const prev = current.valid ? current.value : { ...defaultControl(), forBindingId: bindingId, forBindingRevision: bindingRevision };
      return saveControlUnlocked(root, { ...prev, enabled: false, leaseExpiresAt: null }, { allowCorrupt: true, expectedControl: current }, verifyActive);
    });
  });
}
function enableForCurrentHost(dir, options = {}) {
  const epoch = options.expectedStateEpoch;
  if (!UUID_V4.test(epoch || '')) throw fail('HOST_EPOCH_REQUIRED');
  function verify() {
    const status = readStatus(dir), s = status.value;
    if (!status.connected || s.stateEpoch !== epoch || s.coreSha256 !== CORE_SHA256 || s.sourceContract !== 'verified'
      || !s.canEnable || !s.binding.bound || s.binding.id !== options.bindingId || s.binding.revision !== options.bindingRevision) throw fail('HOST_BINDING_UNCONFIRMED');
  }
  verify();
  return enableForActiveBinding(dir, { ...options, verifyHost: verify });
}
module.exports = { CONTROL_API_VERSION, SCHEMA, CONTRACT, CONNECT_WINDOW_MS, BIND_TTL_MS, OPERATION_TTL_MS,
  readActiveSnapshot, disableForActiveBinding, enableForCurrentHost,
  controlPath, statusPath, readControl, writeJsonAtomic, validateControl, validateStatus, saveControl,
  enableForBinding, disable, effectiveEnabled, readStatus, summarize, defaultControl, normalizeSessionId,
  rebindSession, runtimePatch, readActiveConfig, assertRuntimeDirectory, readBinding, enableForActiveBinding,
  checkConfiguration, prepareBinding, commitBinding, reconcileBinding, readHostEvidence, prepareEnable, commitEnable };


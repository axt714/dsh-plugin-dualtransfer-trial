import path from 'node:path';
import { types } from 'node:util';
import { readPrivate, atomicPrivate } from './private-fs.mjs';
import { validateAgentMessageScope } from './agent-message-store.mjs';

const PAIR_KEYS = ['pairingId', 'generation', 'localDeviceId', 'peerDeviceId'];
const SESSION = /^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const MAX_RULES = 128, MAX_BYTES = 128 * 1024, ERRORS = new WeakMap();
const CODES = new Set(['AGENT_HISTORY_VIEW_UNAVAILABLE', 'AGENT_HISTORY_VIEW_FULL', 'AGENT_HISTORY_VIEW_STALE', 'AGENT_REPLY_FORBIDDEN', 'AGENT_REPLY_SESSION_REQUIRED']);
export function getAgentHistoryViewErrorCode(error) { return ERRORS.get(error) ?? null; }
function fail(code = 'AGENT_HISTORY_VIEW_UNAVAILABLE') {
  if (!CODES.has(code)) code = 'AGENT_HISTORY_VIEW_UNAVAILABLE';
  const error = Object.assign(new Error(code), { code });
  Object.defineProperty(error, 'stack', { value: code }); ERRORS.set(error, code); throw error;
}
const check = (value, code) => { if (!value) fail(code); };
const integer = value => Number.isSafeInteger(value) && value >= 0;
function record(value, keys) {
  check(value && typeof value === 'object' && !Array.isArray(value) && !types.isProxy(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const descriptors = Object.getOwnPropertyDescriptors(value), own = Reflect.ownKeys(descriptors);
  check(own.length === keys.length && keys.every(key => own.includes(key))
    && own.every(key => typeof key === 'string' && descriptors[key].enumerable && Object.hasOwn(descriptors[key], 'value')));
}
function keyFor(scope, sessionId) {
  check(typeof sessionId === 'string' && SESSION.test(sessionId), 'AGENT_REPLY_SESSION_REQUIRED');
  try { validateAgentMessageScope(scope); } catch { fail(); }
  return Object.freeze({ sessionId, ...Object.fromEntries(PAIR_KEYS.map(key => [key, scope[key]])) });
}
const sameKey = (left, right) => ['sessionId', ...PAIR_KEYS].every(key => left[key] === right[key]);
function decode(value) {
  record(value, ['schema', 'revision', 'rules']);
  check(value.schema === 1 && integer(value.revision) && Array.isArray(value.rules) && !types.isProxy(value.rules)
    && value.rules.length <= MAX_RULES && Reflect.ownKeys(value.rules).length === value.rules.length + 1);
  const seen = new Set(), rules = [];
  for (let index = 0; index < value.rules.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value.rules, String(index));
    check(descriptor && Object.hasOwn(descriptor, 'value')); const rule = descriptor.value;
    record(rule, ['sessionId', ...PAIR_KEYS, 'clearedThroughSeq']);
    check(integer(rule.clearedThroughSeq) && rule.clearedThroughSeq > 0);
    const key = keyFor({ ...Object.fromEntries(PAIR_KEYS.map(name => [name, rule[name]])),
      localTargetToken: '0'.repeat(64), peerTargetToken: '0'.repeat(64) }, rule.sessionId);
    const label = JSON.stringify(key); check(!seen.has(label)); seen.add(label);
    rules.push(Object.freeze({ ...key, clearedThroughSeq: rule.clearedThroughSeq }));
  }
  const result = Object.freeze({ schema: 1, revision: value.revision, rules: Object.freeze(rules) });
  check(Buffer.byteLength(JSON.stringify(result), 'utf8') <= MAX_BYTES); return result;
}
/** Display metadata only. Never deletes, filters or repairs the canonical ledger.
 * Capacity fails closed rather than evicting an old watermark and resurrecting it. */
export function createAgentHistoryView({ directory, storage } = {}) {
  check(typeof directory === 'string' && path.isAbsolute(directory) && !directory.includes('\0')
    && path.resolve(directory) !== path.parse(directory).root);
  const filename = path.join(directory, 'history-view.json');
  storage ??= Object.freeze({ read: () => readPrivate(filename), write: value => atomicPrivate(filename, value) });
  check(storage && ['read', 'write'].every(key => typeof storage[key] === 'function'));
  let state = null, baseline = null, closed = false, fault = false, queue = Promise.resolve();
  const ready = () => check(!closed && !fault && state !== null);
  function authority(assertOwner) {
    check(typeof assertOwner === 'function' && !types.isProxy(assertOwner), 'AGENT_REPLY_FORBIDDEN');
    let result; try { result = assertOwner(); } catch { fail('AGENT_REPLY_FORBIDDEN'); }
    check(result === true, 'AGENT_REPLY_FORBIDDEN');
  }
  function snapshot() { return Object.freeze({ available: !closed && !fault && state !== null, revision: state?.revision ?? 0 }); }
  function read(scope, sessionId) { ready(); const key = keyFor(scope, sessionId); return state.rules.find(rule => sameKey(rule, key))?.clearedThroughSeq ?? 0; }
  async function open() {
    check(!closed && !fault); if (state) return snapshot();
    try {
      const disk = await storage.read(); check(!closed);
      state = disk === null ? decode({ schema: 1, revision: 0, rules: [] }) : decode(disk);
      baseline = disk === null ? null : JSON.stringify(state); return snapshot();
    } catch { fault = true; fail(); }
  }
  async function advance(input, scope, sessionId, assertOwner) {
    ready(); record(input, ['throughSeq', 'expectedRevision']);
    check(integer(input.throughSeq) && integer(input.expectedRevision));
    const clean = Object.freeze({ ...input }), key = keyFor(scope, sessionId); authority(assertOwner);
    const result = queue.then(async () => {
      ready(); authority(assertOwner); check(state.revision === clean.expectedRevision, 'AGENT_HISTORY_VIEW_STALE');
      const previous = state.rules.find(rule => sameKey(rule, key)), through = previous?.clearedThroughSeq ?? 0;
      if (clean.throughSeq <= through) return Object.freeze({ changed: false, clearedThroughSeq: through });
      check(previous || state.rules.length < MAX_RULES, 'AGENT_HISTORY_VIEW_FULL');
      check(state.revision < Number.MAX_SAFE_INTEGER);
      const next = decode({ schema: 1, revision: state.revision + 1,
        rules: [...state.rules.filter(rule => !sameKey(rule, key)), { ...key, clearedThroughSeq: clean.throughSeq }] });
      try {
        const disk = await storage.read(); ready(); authority(assertOwner);
        check((disk === null ? null : JSON.stringify(decode(disk))) === baseline);
        check(state.revision === clean.expectedRevision, 'AGENT_HISTORY_VIEW_STALE');
        await storage.write(next); ready(); state = next; baseline = JSON.stringify(next); authority(assertOwner);
      } catch (error) {
        const code = getAgentHistoryViewErrorCode(error);
        if (code === 'AGENT_REPLY_FORBIDDEN' || code === 'AGENT_HISTORY_VIEW_STALE') throw error;
        fault = true; fail();
      }
      return Object.freeze({ changed: true, clearedThroughSeq: clean.throughSeq });
    });
    queue = result.catch(() => undefined); return result;
  }
  async function drain() { await queue; check(!fault); return snapshot(); }
  async function close() { closed = true; await queue; check(!fault); return snapshot(); }
  return Object.freeze({ open, read, advance, snapshot, drain, close });
}

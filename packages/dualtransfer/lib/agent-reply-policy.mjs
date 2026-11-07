import path from 'node:path';
import { types } from 'node:util';
import { readPrivate, atomicPrivate } from './private-fs.mjs';
import { validateAgentMessageScope } from './agent-message-store.mjs';

const PROTOCOL = 'agent-reply-policy-v1';
const PAIR_KEYS = ['pairingId', 'generation', 'localDeviceId', 'peerDeviceId'];
const SESSION = /^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const MAX_RULES = 256;
const MAX_BYTES = 256 * 1024;
const OWN_ERRORS = new WeakMap();
const CODES = new Set(['AGENT_REPLY_POLICY_UNAVAILABLE', 'AGENT_REPLY_STALE', 'AGENT_REPLY_FORBIDDEN', 'AGENT_REPLY_SESSION_REQUIRED']);
export function getAgentReplyPolicyErrorCode(error) { return OWN_ERRORS.get(error) ?? null; }
function fail(code = 'AGENT_REPLY_POLICY_UNAVAILABLE') {
  if (!CODES.has(code)) code = 'AGENT_REPLY_POLICY_UNAVAILABLE';
  const error = Object.assign(new Error(code), { code });
  Object.defineProperty(error, 'stack', { value: code }); OWN_ERRORS.set(error, code); throw error;
}
const check = (condition, code) => { if (!condition) fail(code); };
const integer = value => Number.isSafeInteger(value) && value >= 0;
function record(value, keys) {
  check(value !== null && typeof value === 'object' && !types.isProxy(value) && !Array.isArray(value)
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
  const rules = [], seen = new Set();
  for (let index = 0; index < value.rules.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value.rules, String(index));
    check(descriptor && Object.hasOwn(descriptor, 'value'));
    const rule = descriptor.value;
    record(rule, ['sessionId', ...PAIR_KEYS, 'mode', 'revision']);
    check(typeof rule.sessionId === 'string' && SESSION.test(rule.sessionId) && ['ask', 'trusted', 'deny'].includes(rule.mode)
      && integer(rule.revision) && rule.revision > 0 && rule.revision <= value.revision);
    // Reuse the exact identity validator, with inert tokens that are never saved.
    try { validateAgentMessageScope({ ...Object.fromEntries(PAIR_KEYS.map(key => [key, rule[key]])), localTargetToken: '0'.repeat(64), peerTargetToken: '0'.repeat(64) }); }
    catch { fail(); }
    const key = JSON.stringify(['sessionId', ...PAIR_KEYS].map(name => rule[name]));
    check(!seen.has(key)); seen.add(key); rules.push(Object.freeze({ ...rule }));
  }
  const result = Object.freeze({ schema: 1, revision: value.revision, rules: Object.freeze(rules) });
  check(Buffer.byteLength(JSON.stringify(result), 'utf8') <= MAX_BYTES); return result;
}

/** Rules only, never message bodies or a second task database. Construction is IO-free.
 * The provider owns the encompassing Root lease; storage is an explicit pure-test seam. */
export function createAgentReplyPolicy({ directory, storage } = {}) {
  check(typeof directory === 'string' && path.isAbsolute(directory) && !directory.includes('\0')
    && path.resolve(directory) !== path.parse(directory).root);
  const filename = path.join(directory, 'reply-policy.json');
  storage ??= Object.freeze({ read: () => readPrivate(filename), write: value => atomicPrivate(filename, value) });
  check(storage && ['read', 'write'].every(key => typeof storage[key] === 'function'));
  let state = null, baseline = null, fault = false, closed = false, queue = Promise.resolve();
  function ready() { check(!closed && !fault && state !== null); }
  function authority(assertOwner) {
    check(typeof assertOwner === 'function', 'AGENT_REPLY_FORBIDDEN');
    let result; try { result = assertOwner(); } catch { fail('AGENT_REPLY_FORBIDDEN'); }
    check(result === true, 'AGENT_REPLY_FORBIDDEN');
  }
  function snapshot() {
    return Object.freeze({ protocol: PROTOCOL, available: !closed && !fault && state !== null, revision: state?.revision ?? 0,
      semantics: 'receipts-only', defaultMode: 'trusted' });
  }
  function read(scope, sessionId) {
    ready(); const key = keyFor(scope, sessionId), rule = state.rules.find(item => sameKey(item, key));
    const mode = rule?.mode ?? 'trusted';
    return Object.freeze({ mode, revision: rule?.revision ?? 0, policyRevision: state.revision,
      trustScope: mode === 'trusted' ? key : null });
  }
  async function open() {
    check(!closed && !fault);
    if (state) return snapshot();
    try {
      const value = await storage.read(); check(!closed);
      state = value === null ? decode({ schema: 1, revision: 0, rules: [] }) : decode(value);
      baseline = value === null ? null : JSON.stringify(state); return snapshot();
    } catch { fault = true; fail(); } // Preserve corrupt state: no rewrite, reset or repair.
  }
  async function set(input, scope, sessionId, assertOwner) {
    ready(); record(input, ['mode', 'expectedRevision']);
    check(['ask', 'trusted', 'deny'].includes(input.mode) && integer(input.expectedRevision));
    const clean = Object.freeze({ ...input }), key = keyFor(scope, sessionId);
    authority(assertOwner);
    const result = queue.then(async () => {
      ready(); authority(assertOwner); check(state.revision === clean.expectedRevision, 'AGENT_REPLY_STALE');
      check(state.revision < Number.MAX_SAFE_INTEGER);
      const revision = state.revision + 1, previous = state.rules.find(item => sameKey(item, key));
      check(previous || state.rules.length < MAX_RULES);
      const next = decode({ schema: 1, revision,
        rules: [...state.rules.filter(item => !sameKey(item, key)), { ...key, mode: clean.mode, revision }] });
      try {
        const disk = await storage.read(); ready(); authority(assertOwner);
        check((disk === null ? null : JSON.stringify(decode(disk))) === baseline);
        check(state.revision === clean.expectedRevision, 'AGENT_REPLY_STALE');
        await storage.write(next);
        // A retired owner may have written only its captured key. It must not
        // observe success or send anything under the replacement authority.
        ready(); state = next; baseline = JSON.stringify(next); authority(assertOwner);
      } catch (error) {
        const code = getAgentReplyPolicyErrorCode(error);
        if (code === 'AGENT_REPLY_FORBIDDEN' || code === 'AGENT_REPLY_STALE') throw error;
        fault = true; fail();
      }
      return Object.freeze({ mode: clean.mode, revision, policyRevision: state.revision, trustScope: clean.mode === 'trusted' ? key : null });
    });
    queue = result.catch(() => undefined); return result;
  }
  async function drain() { await queue; check(!fault); return snapshot(); }
  async function close() { closed = true; await queue; check(!fault); return snapshot(); }
  return Object.freeze({ open, read, set, snapshot, drain, close });
}

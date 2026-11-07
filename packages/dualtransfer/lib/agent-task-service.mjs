import { randomUUID } from 'node:crypto';
import { types } from 'node:util';
import { validateAgentMessageScope } from './agent-message-store.mjs';
import { getAgentReplyPolicyErrorCode } from './agent-reply-policy.mjs';
import { getAgentHistoryViewErrorCode } from './agent-history-view.mjs';
import { parseAgentReceipt, encodeAgentReceipt, receiptMessageIds, agentReceiptMessageId } from './agent-receipt.mjs';

const PREFIX = 'DTAGENT/1\n';
const PROTOCOL = 'dualtransfer.agent/1';
const MAX_BYTES = 16 * 1024;
const DEFAULT_TTL = 30 * 60 * 1000;
const MAX_TTL = 24 * 60 * 60 * 1000;
const FUTURE_SKEW = 120 * 1000;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$(?![\s\S])/;
const LOWER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const TOKEN = /^[0-9a-f]{64}$(?![\s\S])/;
const EVENT_FIELDS = ['protocol', 'type', 'messageId', 'taskId', 'replyTo', 'pairingId', 'generation', 'fromDeviceId', 'toDeviceId', 'fromTargetToken', 'toTargetToken', 'createdAt', 'expiresAt', 'payload'];
const ROW_FIELDS = ['id', 'channel', 'text', 'conversation', 'sender', 'created', 'replyTo'];
const SCOPE_FIELDS = ['pairingId', 'generation', 'localDeviceId', 'peerDeviceId', 'localTargetToken', 'peerTargetToken'];
const SESSION = /^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const MAX_PENDING = 32, MAX_PENDING_BYTES = 512 * 1024, ONCE_TTL = 5 * 60 * 1000, HISTORY_BYTES = 64 * 1024;

const OWN_ERRORS = new WeakMap();
const ERROR_CODES = new Set(`AGENT_EVENT_INVALID AGENT_EVENT_TYPE_INVALID AGENT_EVENT_TOO_LARGE AGENT_SCOPE_INVALID
AGENT_TASK_CONFLICT AGENT_TASK_REFERENCE_INVALID AGENT_TASK_DIRECTION_INVALID AGENT_TASK_TERMINAL AGENT_TASK_OUTPUT_BUDGET AGENT_TASK_RESULT_CONFLICT
AGENT_SERVICE_OPTIONS_INVALID AGENT_SERVICE_CLOSED AGENT_CONTEXT_INVALID AGENT_NOT_READY AGENT_CONTEXT_RETIRED AGENT_CLOCK_INVALID
AGENT_EVENT_EXPIRED_OR_FUTURE AGENT_HISTORY_UNAVAILABLE AGENT_HISTORY_INVALID AGENT_OPTIONS_INVALID AGENT_ID_GENERATION_FAILED
AGENT_MESSAGE_CONFLICT AGENT_MESSAGE_ID_INVALID AGENT_RETRY_NOT_FOUND AGENT_RECEIVE_OPTIONS_INVALID AGENT_PEER_INVALID AGENT_STORE_ACK_INVALID
AGENT_DRAIN_FAILED AGENT_SERVICE_FAILED AGENT_REPLY_APPROVAL_REQUIRED AGENT_REPLY_DENIED AGENT_REPLY_EXPIRED AGENT_REPLY_NOT_FOUND
AGENT_REPLY_SESSION_REQUIRED AGENT_REPLY_CONTEXT_RETIRED AGENT_REPLY_POLICY_UNAVAILABLE AGENT_REPLY_QUEUE_FULL AGENT_REPLY_STALE
AGENT_REPLY_FORBIDDEN AGENT_HISTORY_PAGE_INVALID AGENT_HISTORY_CLEAR_INVALID AGENT_HISTORY_VIEW_UNAVAILABLE
AGENT_HISTORY_VIEW_FULL AGENT_HISTORY_VIEW_STALE AGENT_RECEIPT_BATCH_INVALID AGENT_RECEIPT_CONFLICT AGENT_RECEIPT_RESERVED`.split(/\s+/));
export function getAgentTaskServiceErrorCode(error) { return OWN_ERRORS.get(error) ?? null; }
function fail(code, ids) {
  if (!ERROR_CODES.has(code)) code = 'AGENT_SERVICE_FAILED';
  const error = Object.assign(new Error(code), { code });
  Object.defineProperty(error, 'stack', { value: code, writable: false });
  if (ids) Object.assign(error, { messageId: ids.messageId, taskId: ids.taskId });
  OWN_ERRORS.set(error, code); throw error;
}
function requireValue(value, code = 'AGENT_EVENT_INVALID') { if (!value) fail(code); }
function record(value, fields, code = 'AGENT_EVENT_INVALID') {
  requireValue(value !== null && typeof value === 'object' && !types.isProxy(value) && !Array.isArray(value), code);
  requireValue(Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null, code);
  const keys = Reflect.ownKeys(value), descriptors = Object.getOwnPropertyDescriptors(value);
  requireValue(keys.length === fields.length && fields.every(key => keys.includes(key)) &&
    keys.every(key => typeof key === 'string' && descriptors[key].enumerable && Object.hasOwn(descriptors[key], 'value')), code);
}
function text(value, nonempty = false) {
  requireValue(typeof value === 'string' && value.isWellFormed() && (!nonempty || value.trim().length > 0));
  return value;
}
function integer(value) { return Number.isSafeInteger(value) && value >= 0; }
function frozen(value) {
  for (const child of Object.values(value)) if (child && typeof child === 'object') frozen(child);
  return Object.freeze(value);
}
function payloadFor(type, value) {
  switch (type) {
    case 'message': record(value, ['text']); return { text: text(value.text) };
    case 'task.request': {
      record(value, ['goal', 'scope', 'acceptance', 'outputBudgetBytes']);
      requireValue(Array.isArray(value.scope) && !types.isProxy(value.scope) && value.scope.length <= 16 &&
        Reflect.ownKeys(value.scope).length === value.scope.length + 1 && integer(value.outputBudgetBytes) &&
        value.outputBudgetBytes >= 1 && value.outputBudgetBytes <= MAX_BYTES);
      const scope = [];
      for (let index = 0; index < value.scope.length; index++) {
        const item = Object.getOwnPropertyDescriptor(value.scope, String(index));
        requireValue(item && Object.hasOwn(item, 'value'));
        const description = text(item.value, true);
        requireValue(Buffer.byteLength(description, 'utf8') <= 512); scope.push(description);
      }
      return { goal: text(value.goal, true), scope,
        acceptance: text(value.acceptance, true), outputBudgetBytes: value.outputBudgetBytes };
    }
    case 'progress':
      record(value, ['state', 'text']);
      requireValue(['accepted', 'running', 'blocked', 'waiting-authorization'].includes(value.state));
      return { state: value.state, text: text(value.text) };
    case 'result':
      record(value, ['outcome', 'text']);
      requireValue(['succeeded', 'failed', 'needs-authorization', 'cancelled'].includes(value.outcome));
      return { outcome: value.outcome, text: text(value.text) };
    case 'cancel.request': record(value, ['reason']); return { reason: text(value.reason) };
    default: fail('AGENT_EVENT_TYPE_INVALID');
  }
}
function validatedEvent(value) {
  record(value, EVENT_FIELDS);
  requireValue(value.protocol === PROTOCOL && typeof value.messageId === 'string' && LOWER_UUID.test(value.messageId));
  for (const key of ['pairingId', 'generation', 'fromDeviceId', 'toDeviceId']) requireValue(typeof value[key] === 'string' && UUID.test(value[key]));
  requireValue(typeof value.fromTargetToken === 'string' && TOKEN.test(value.fromTargetToken) &&
    typeof value.toTargetToken === 'string' && TOKEN.test(value.toTargetToken));
  requireValue(integer(value.createdAt) && integer(value.expiresAt) && value.expiresAt > value.createdAt && value.expiresAt - value.createdAt <= MAX_TTL);
  if (value.type === 'message') requireValue(value.taskId === null && value.replyTo === null);
  else {
    requireValue(typeof value.taskId === 'string' && UUID.test(value.taskId));
    requireValue(value.type === 'task.request' ? value.replyTo === null : typeof value.replyTo === 'string' && LOWER_UUID.test(value.replyTo));
  }
  const result = {};
  for (const key of EVENT_FIELDS) result[key] = key === 'payload' ? payloadFor(value.type, value.payload) : value[key];
  return frozen(result);
}

// Parse rather than using a reviver: duplicate keys must not silently overwrite
// earlier authority fields. The byte limit and depth bound precede allocation.
function strictJSON(source) {
  let position = 0;
  function space() { while (/[\x20\x09\x0a\x0d]/.test(source[position] || '') && position < source.length) position++; }
  function string() {
    const start = position++;
    while (position < source.length) {
      const character = source[position++];
      if (character === '\\') { position++; continue; }
      if (character === '"') return JSON.parse(source.slice(start, position));
    }
    fail('AGENT_EVENT_INVALID');
  }
  function value(depth) {
    requireValue(depth <= 12); space();
    const character = source[position];
    if (character === '"') return string();
    if (character === '{' || character === '[') {
      position++; space();
      const object = character === '{', result = object ? Object.create(null) : [], keys = new Set();
      const end = object ? '}' : ']';
      if (source[position] === end) { position++; return result; }
      while (position < source.length) {
        space(); let key;
        if (object) {
          requireValue(source[position] === '"'); key = string();
          requireValue(!keys.has(key)); keys.add(key); space(); requireValue(source[position++] === ':');
        }
        const child = value(depth + 1);
        if (object) result[key] = child; else result.push(child);
        space(); const next = source[position++];
        if (next === end) return result;
        requireValue(next === ',');
      }
      fail('AGENT_EVENT_INVALID');
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(source.slice(position));
    requireValue(match); position += match[0].length; return JSON.parse(match[0]);
  }
  const result = value(0); space(); requireValue(position === source.length); return result;
}
export function encodeAgentTaskEvent(event) {
  try {
    const result = PREFIX + JSON.stringify(validatedEvent(event));
    requireValue(Buffer.byteLength(result, 'utf8') <= MAX_BYTES, 'AGENT_EVENT_TOO_LARGE'); return result;
  } catch (error) { if (getAgentTaskServiceErrorCode(error)) throw error; fail('AGENT_EVENT_INVALID'); }
}
export function decodeAgentTaskEvent(encoded) {
  try {
    requireValue(typeof encoded === 'string' && encoded.isWellFormed() && encoded.startsWith(PREFIX));
    requireValue(Buffer.byteLength(encoded, 'utf8') <= MAX_BYTES, 'AGENT_EVENT_TOO_LARGE');
    return validatedEvent(strictJSON(encoded.slice(PREFIX.length)));
  } catch (error) { if (getAgentTaskServiceErrorCode(error)) throw error; fail('AGENT_EVENT_INVALID'); }
}
function scopeCopy(value) {
  record(value, SCOPE_FIELDS, 'AGENT_SCOPE_INVALID');
  const copy = Object.fromEntries(SCOPE_FIELDS.map(key => [key, value[key]]));
  try { validateAgentMessageScope(copy); } catch { fail('AGENT_SCOPE_INVALID'); }
  return Object.freeze(copy);
}
function sameScope(left, right) { return SCOPE_FIELDS.every(key => left[key] === right[key]); }
function binding(event, scope, direction) {
  const outgoing = direction === 'out';
  return event.pairingId === scope.pairingId && event.generation === scope.generation &&
    event.fromDeviceId === scope[outgoing ? 'localDeviceId' : 'peerDeviceId'] &&
    event.toDeviceId === scope[outgoing ? 'peerDeviceId' : 'localDeviceId'] &&
    event.fromTargetToken === scope[outgoing ? 'localTargetToken' : 'peerTargetToken'] &&
    event.toTargetToken === scope[outgoing ? 'peerTargetToken' : 'localTargetToken'];
}
function inputRow(value) {
  record(value, ROW_FIELDS);
  requireValue(value.channel === 'agent' && typeof value.id === 'string' && LOWER_UUID.test(value.id));
  for (const [key, limit] of [['conversation', 100], ['sender', 80]]) requireValue(typeof value[key] === 'string' && value[key].isWellFormed() && value[key].length <= limit);
  const event = decodeAgentTaskEvent(value.text);
  requireValue(value.id === event.messageId && value.created === event.createdAt && value.replyTo === event.replyTo);
  return { row: Object.freeze(Object.fromEntries(ROW_FIELDS.map(key => [key, value[key]]))), event };
}
function sameRow(left, right) { return ROW_FIELDS.every(key => left[key] === right[key]); }
function applyEvent(tasks, item) {
  const { event, direction } = item;
  if (event.type === 'message') return;
  const previous = tasks.get(event.taskId);
  if (event.type === 'task.request') {
    requireValue(!previous, 'AGENT_TASK_CONFLICT');
    tasks.set(event.taskId, { request: item, progress: [], result: null, cancellations: [] }); return;
  }
  requireValue(previous && previous.request.event.messageId === event.replyTo, 'AGENT_TASK_REFERENCE_INVALID');
  const sameDirection = previous.request.direction === direction;
  if (event.type === 'cancel.request') {
    requireValue(sameDirection, 'AGENT_TASK_DIRECTION_INVALID'); previous.cancellations.push(item); return;
  }
  requireValue(!sameDirection, 'AGENT_TASK_DIRECTION_INVALID');
  if (event.type === 'progress') {
    requireValue(!previous.result, 'AGENT_TASK_TERMINAL'); previous.progress.push(item);
  } else {
    requireValue(Buffer.byteLength(event.payload.text, 'utf8') <= previous.request.event.payload.outputBudgetBytes, 'AGENT_TASK_OUTPUT_BUDGET');
    requireValue(!previous.result || JSON.stringify(previous.result.event.payload) === JSON.stringify(event.payload), 'AGENT_TASK_RESULT_CONFLICT');
    previous.result ||= item;
  }
}

/** Pure coordinator: no filesystem, SDK, model, Goal or transport ownership. */
export function createAgentTaskService({ store, transport, getContext, now = Date.now, randomId = randomUUID, replyPolicy = null, historyView = null, getOwnerSession = () => null, onDrainFailure = null }) {
  requireValue(store && ['appendOutgoing', 'ingestIncoming', 'messagesForScope'].every(key => typeof store[key] === 'function') &&
    transport && typeof transport.send === 'function' && typeof getContext === 'function' && typeof now === 'function' && typeof randomId === 'function'
    && typeof getOwnerSession === 'function' && (onDrainFailure === null || typeof onDrainFailure === 'function' && !types.isProxy(onDrainFailure)
      && !types.isAsyncFunction(onDrainFailure) && !types.isGeneratorFunction(onDrainFailure))
    && (replyPolicy === null || ['read', 'set', 'snapshot'].every(key => typeof replyPolicy[key] === 'function'))
    && (historyView === null || ['read', 'advance', 'snapshot'].every(key => typeof historyView[key] === 'function')), 'AGENT_SERVICE_OPTIONS_INVALID');
  let closed = false, queue = Promise.resolve(), drainPromise = null, closePromise = null;
  function capture(ready = true, requireSession = false) {
    requireValue(!closed, 'AGENT_SERVICE_CLOSED');
    const context = getContext();
    record(context, ['scope', 'localReady', 'peerReady', 'authorityVersion'], 'AGENT_CONTEXT_INVALID');
    requireValue(typeof context.localReady === 'boolean' && typeof context.peerReady === 'boolean' &&
      (integer(context.authorityVersion) || typeof context.authorityVersion === 'string' && context.authorityVersion.length > 0), 'AGENT_CONTEXT_INVALID');
    requireValue(context.localReady && (!ready || context.peerReady), 'AGENT_NOT_READY');
    let sessionId; try { sessionId = getOwnerSession(); } catch { fail('AGENT_REPLY_SESSION_REQUIRED'); }
    requireValue(sessionId === null || typeof sessionId === 'string' && SESSION.test(sessionId), 'AGENT_REPLY_SESSION_REQUIRED');
    requireValue(!requireSession || sessionId !== null, 'AGENT_REPLY_SESSION_REQUIRED');
    return Object.freeze({ scope: scopeCopy(context.scope), localReady: context.localReady, peerReady: context.peerReady, authorityVersion: context.authorityVersion, sessionId });
  }
  function current(snapshot, ready = true) {
    try {
      const next = capture(ready);
      return next.authorityVersion === snapshot.authorityVersion && next.localReady === snapshot.localReady &&
        next.peerReady === snapshot.peerReady && next.sessionId === snapshot.sessionId && sameScope(next.scope, snapshot.scope);
    } catch { return false; }
  }
  function checkCurrent(snapshot, ready = true) { requireValue(current(snapshot, ready), 'AGENT_CONTEXT_RETIRED'); }
  function clock() { const value = now(); requireValue(integer(value), 'AGENT_CLOCK_INVALID'); return value; }
  function fresh(event) { const time = clock(); requireValue(event.expiresAt > time && event.createdAt <= time + FUTURE_SKEW, 'AGENT_EVENT_EXPIRED_OR_FUTURE'); }
  function enqueue(snapshot, work, ready = true) {
    const result = queue.then(() => { checkCurrent(snapshot, ready); return work(); });
    queue = result.catch(() => undefined); return result;
  }
  function savedItem(snapshot, row) {
    if (typeof row?.text !== 'string' || !row.text.startsWith(PREFIX)) return null;
    let pair;
    try { pair = inputRow(Object.fromEntries(ROW_FIELDS.map(key => [key, row[key]]))); } catch { return null; }
    if (!['in', 'out'].includes(row.direction) || !binding(pair.event, snapshot.scope, row.direction)) return null;
    const gate = row.direction === 'out' ? row.replyGate ?? { state: 'legacy-unapproved', revision: 0, sessionId: null,
      policyRevision: 0, approvedAt: null, approvalExpiresAt: null, firstDispatchAt: null, firstDispatchOrder: null, legacy: true } : null;
    const dispatched = row.direction === 'in' || gate.firstDispatchAt !== null;
    return { ...pair, direction: row.direction, delivered: row.delivered === true, gate, saved: row, dispatched,
      protocolFact: dispatched || gate?.legacy === true };
  }
  async function history(snapshot, ready = true) {
    let rows;
    try { rows = await store.messagesForScope(snapshot.scope); } catch { fail('AGENT_HISTORY_UNAVAILABLE'); }
    checkCurrent(snapshot, ready);
    requireValue(Array.isArray(rows), 'AGENT_HISTORY_INVALID');
    const ids = new Map(), tasks = new Map();
    for (const row of rows) {
      const item = savedItem(snapshot, row); if (item === null) continue;
      requireValue(!ids.has(row.id), 'AGENT_HISTORY_INVALID'); ids.set(row.id, item);
    }
    // Admission and first dispatch share a durable logical order, not draft seq
    // or a wall clock. Legacy rows retain their old ledger order conservatively;
    // legacy provenance is not proof of a real send or a fabricated timestamp.
    const protocol = [...ids.values()].filter(item => item.protocolFact).map(item => {
      const order = item.gate?.legacy ? item.saved.admissionOrder ?? item.saved.seq
        : item.direction === 'in' ? item.saved.admissionOrder : item.gate.firstDispatchOrder;
      requireValue(integer(order) && order > 0, 'AGENT_HISTORY_INVALID'); return { item, order };
    });
    for (const { item } of protocol.sort((a, b) => a.order - b.order)) applyEvent(tasks, item);
    return { ids, tasks, rows };
  }
  function makeEvent(type, payload, options, snapshot, taskId, replyTo, createdAt) {
    const expiresAt = options.expiresAt ?? createdAt + DEFAULT_TTL;
    const event = validatedEvent({ protocol: PROTOCOL, type, messageId: options.messageId ?? randomId(),
      taskId: type === 'task.request' ? options.taskId ?? randomId() : taskId, replyTo,
      pairingId: snapshot.scope.pairingId, generation: snapshot.scope.generation,
      fromDeviceId: snapshot.scope.localDeviceId, toDeviceId: snapshot.scope.peerDeviceId,
      fromTargetToken: snapshot.scope.localTargetToken, toTargetToken: snapshot.scope.peerTargetToken,
      createdAt, expiresAt, payload });
    const row = Object.freeze({ id: event.messageId, channel: 'agent', text: encodeAgentTaskEvent(event), conversation: '', sender: 'agent',
      created: createdAt, replyTo });
    return { row, event, direction: 'out', delivered: false };
  }
  function outcome(item, extra = {}) {
    return Object.freeze({ messageId: item.event.messageId, taskId: item.event.taskId, committed: true,
      delivery: 'pending', uncertain: false, retired: false, ...extra });
  }
  function retired(item) { return outcome(item, { delivery: 'uncertain', uncertain: true, retired: true }); }
  function ruleFor(snapshot) {
    requireValue(replyPolicy !== null, 'AGENT_REPLY_POLICY_UNAVAILABLE');
    try { return replyPolicy.read(snapshot.scope, snapshot.sessionId); }
    catch { fail('AGENT_REPLY_POLICY_UNAVAILABLE'); }
  }
  function owner(snapshot, assertOwner) {
    checkCurrent(snapshot);
    requireValue(typeof assertOwner === 'function' && !types.isProxy(assertOwner), 'AGENT_REPLY_FORBIDDEN');
    let result; try { result = assertOwner(); } catch { fail('AGENT_REPLY_FORBIDDEN'); }
    requireValue(result === true, 'AGENT_REPLY_FORBIDDEN');
  }
  function receiptOf(item) { return item.event.type === 'message' ? parseAgentReceipt(item.event.payload.text) : null; }
  function permission(snapshot, item) {
    const gate = item.gate, receipt = receiptOf(item), rule = receipt ? ruleFor(snapshot) : null, time = clock();
    if (gate.state === 'denied' || rule?.mode === 'deny') return 'denied';
    if (item.event.expiresAt <= time || item.event.createdAt > time + FUTURE_SKEW) return 'expired';
    if (gate.sessionId !== null && gate.sessionId !== snapshot.sessionId) return 'revoked';
    if (gate.state === 'awaiting-approval' || gate.state === 'legacy-unapproved') return gate.state;
    if (gate.approvalExpiresAt === null || gate.approvalExpiresAt <= time) return 'expired';
    if (gate.sessionId !== snapshot.sessionId || rule && (gate.policyRevision !== rule.revision
      || gate.state === 'trusted' && rule.mode !== 'trusted')) return 'revoked';
    return gate.state;
  }
  function notAuthorized(item, state) {
    return outcome(item, { delivery: state === 'denied' ? 'denied' : state === 'expired' ? 'expired' : 'awaiting-approval',
      replyAuthorization: Object.freeze({ state, revision: item.gate.revision }) });
  }
  async function persistGate(snapshot, item, gate) {
    requireValue(typeof store.setReplyGate === 'function', 'AGENT_REPLY_POLICY_UNAVAILABLE');
    let row;
    try { row = await store.setReplyGate({ messageId: item.row.id, expectedRevision: item.gate.revision, gate }, snapshot.scope); }
    catch { fail('AGENT_REPLY_POLICY_UNAVAILABLE'); }
    item.gate = row.replyGate; item.saved = row; item.dispatched = item.gate.firstDispatchAt !== null;
    item.protocolFact = item.dispatched || item.gate.legacy;
    return row;
  }
  async function transmit(snapshot, item, append, assertOwner = null) {
    fresh(item.event); checkCurrent(snapshot);
    if (assertOwner) owner(snapshot, assertOwner);
    if (append) {
      // Ordinary authorized business sends are not receipt approvals. Existing
      // drafts keep their original gate because only a new append reaches here.
      const rule = receiptOf(item) ? ruleFor(snapshot) : { mode: 'trusted', revision: 0 }, time = clock();
      item.gate = Object.freeze({ state: rule.mode === 'trusted' ? 'trusted' : rule.mode === 'deny' ? 'denied' : 'awaiting-approval',
        revision: 0, sessionId: snapshot.sessionId, policyRevision: rule.revision,
        approvedAt: rule.mode === 'trusted' ? time : null, approvalExpiresAt: rule.mode === 'trusted' ? item.event.expiresAt : null,
        firstDispatchAt: null, firstDispatchOrder: null, legacy: false });
      if (item.gate.state === 'awaiting-approval') {
        const state = await history(snapshot);
        const waiting = pendingItems(snapshot, state.rows);
        requireValue(waiting.length < MAX_PENDING && waiting.reduce((size, value) => size + Buffer.byteLength(value.row.text, 'utf8'), 0)
          + Buffer.byteLength(item.row.text, 'utf8') <= MAX_PENDING_BYTES, 'AGENT_REPLY_QUEUE_FULL');
      }
      let saved;
      try { saved = await store.appendOutgoing(item.row, snapshot.scope, item.gate); }
      catch {
        if (receiptOf(item)) closed = true; // No second completion attempt after an unknown receipt commit.
        return outcome(item, { committed: null, delivery: 'uncertain', uncertain: true, retired: !current(snapshot), error: 'AGENT_STORE_UNCERTAIN' });
      }
      item.gate = saved.replyGate; item.saved = saved; item.dispatched = item.gate.firstDispatchAt !== null;
      item.protocolFact = item.dispatched || item.gate.legacy;
      if (!current(snapshot)) return retired(item);
      if (assertOwner) owner(snapshot, assertOwner);
    }
    if (item.delivered) return outcome(item, { delivery: 'peer-received' });
    const state = permission(snapshot, item);
    if (!['approved', 'trusted'].includes(state)) return notAuthorized(item, state);
    // Revalidate protocol legality only when this is the first actual dispatch.
    if (!item.protocolFact) { const active = await history(snapshot); applyEvent(active.tasks, item); }
    checkCurrent(snapshot); if (assertOwner) owner(snapshot, assertOwner);
    fresh(item.event);
    const finalState = permission(snapshot, item);
    if (!['approved', 'trusted'].includes(finalState)) return notAuthorized(item, finalState);
    const attemptedAt = clock();
    // Invoke exactly once before recording an attempt. A denied/draft row never
    // becomes terminal merely because it was persisted or permission was granted.
    let sending;
    try { sending = Promise.resolve(transport.send(item.row, snapshot.scope)); } catch (error) { sending = Promise.reject(error); }
    const joined = sending.then(() => false, () => true);
    if (!item.dispatched) {
      try { await persistGate(snapshot, item, { ...item.gate, revision: item.gate.revision + 1, firstDispatchAt: attemptedAt }); }
      catch {
        // The wire may already contain these bytes but its durable attempt fact
        // is uncertain. Retire this service instead of allowing any replay or a
        // conflicting terminal event, even if a test adapter reports healthy IO.
        closed = true; await joined;
        return outcome(item, { delivery: 'uncertain', uncertain: true, retired: true, error: 'AGENT_STORE_UNCERTAIN' });
      }
    }
    const sendFailed = await joined;
    if (!current(snapshot)) return retired(item);
    if (assertOwner) owner(snapshot, assertOwner);
    try {
      const saved = (await history(snapshot)).ids.get(item.event.messageId);
      requireValue(saved && saved.direction === 'out' && sameRow(saved.row, item.row), 'AGENT_HISTORY_INVALID');
      if (assertOwner) owner(snapshot, assertOwner);
      return outcome(item, { delivery: saved.delivered ? 'peer-received' : sendFailed ? 'uncertain' : 'pending', uncertain: !saved.delivered && sendFailed,
        replyAuthorization: Object.freeze({ state: permission(snapshot, saved), revision: saved.gate.revision }) });
    } catch { return current(snapshot) ? outcome(item, { delivery: 'uncertain', uncertain: true, error: 'AGENT_DELIVERY_UNCERTAIN' }) : retired(item); }
  }
  async function outgoing(type, payload, options = {}, referenceTaskId = null) {
    const snapshot = capture();
    // Copy caller-owned payload/options before queueing; never observe later edits.
    const copiedPayload = payloadFor(type, payload);
    requireValue(type !== 'message' || parseAgentReceipt(copiedPayload.text) === null, 'AGENT_RECEIPT_RESERVED');
    requireValue(options !== null && typeof options === 'object' && !types.isProxy(options), 'AGENT_OPTIONS_INVALID');
    const keys = Reflect.ownKeys(options), allowed = type === 'task.request' ? ['messageId', 'taskId', 'expiresAt'] : ['messageId', 'expiresAt'];
    record(options, keys, 'AGENT_OPTIONS_INVALID');
    requireValue(keys.every(key => allowed.includes(key)), 'AGENT_OPTIONS_INVALID');
    for (const key of keys) requireValue(key === 'expiresAt' ? integer(options[key]) :
      typeof options[key] === 'string' && (key === 'messageId' ? LOWER_UUID : UUID).test(options[key]), 'AGENT_OPTIONS_INVALID');
    const copiedOptions = { ...options, messageId: options.messageId ?? randomId() };
    if (type === 'task.request') copiedOptions.taskId = options.taskId ?? randomId();
    requireValue(typeof copiedOptions.messageId === 'string' && LOWER_UUID.test(copiedOptions.messageId) &&
      (type !== 'task.request' || typeof copiedOptions.taskId === 'string' && UUID.test(copiedOptions.taskId)), 'AGENT_ID_GENERATION_FAILED');
    const createdAt = clock();
    return enqueue(snapshot, async () => {
      const state = await history(snapshot);
      let replyTo = null;
      if (referenceTaskId !== null) {
        requireValue(typeof referenceTaskId === 'string' && UUID.test(referenceTaskId), 'AGENT_TASK_REFERENCE_INVALID');
        const request = state.tasks.get(referenceTaskId)?.request;
        requireValue(request, 'AGENT_TASK_REFERENCE_INVALID'); replyTo = request.event.messageId;
      }
      // The operation's timestamp is captured before queue entry, not refreshed
      // while waiting behind another operation.
      const item = makeEvent(type, copiedPayload, copiedOptions, snapshot, referenceTaskId, replyTo, createdAt);
      const existing = state.ids.get(item.event.messageId);
      if (existing) requireValue(existing.direction === 'out' && sameRow(existing.row, item.row), 'AGENT_MESSAGE_CONFLICT');
      else applyEvent(state.tasks, item);
      requireValue(snapshot.sessionId !== null, 'AGENT_REPLY_SESSION_REQUIRED');
      return transmit(snapshot, existing ?? item, !existing);
    });
  }
  async function sendMessage(payload, options) { return outgoing('message', payload, options); }
  async function request(payload, options) {
    requireValue(payload && typeof payload === 'object' && !types.isProxy(payload));
    const keys = Reflect.ownKeys(payload);
    record(payload, keys);
    requireValue(keys.length >= 3 && keys.every(key => ['goal', 'scope', 'acceptance', 'outputBudgetBytes'].includes(key)) &&
      ['goal', 'scope', 'acceptance'].every(key => keys.includes(key)));
    return outgoing('task.request', { ...payload, outputBudgetBytes: Object.hasOwn(payload, 'outputBudgetBytes') ? payload.outputBudgetBytes : 4096 }, options);
  }
  async function progress(payload, options) {
    record(payload, ['taskId', 'state', 'text']); return outgoing('progress', { state: payload.state, text: payload.text }, options, payload.taskId);
  }
  async function result(payload, options) {
    record(payload, ['taskId', 'outcome', 'text']); return outgoing('result', { outcome: payload.outcome, text: payload.text }, options, payload.taskId);
  }
  async function cancel(payload, options) {
    record(payload, ['taskId', 'reason']); return outgoing('cancel.request', { reason: payload.reason }, options, payload.taskId);
  }
  async function retry(input) {
    record(input, ['messageId'], 'AGENT_OPTIONS_INVALID');
    const { messageId } = input;
    const snapshot = capture(); requireValue(typeof messageId === 'string' && LOWER_UUID.test(messageId), 'AGENT_MESSAGE_ID_INVALID');
    return enqueue(snapshot, async () => {
      const state = await history(snapshot), item = state.ids.get(messageId);
      requireValue(item && item.direction === 'out', 'AGENT_RETRY_NOT_FOUND');
      if (item.delivered) return outcome(item, { delivery: 'peer-received' });
      requireValue(snapshot.sessionId !== null, 'AGENT_REPLY_SESSION_REQUIRED');
      // Receipt retry is never a model/transport replay path. Only the original
      // completion hook or an explicit owner approval may send it once.
      if (receiptOf(item)) return outcome(item, { delivery: item.dispatched ? 'pending' : 'not-sent' });
      return transmit(snapshot, item, false);
    });
  }
  async function receive(message, options) {
    const snapshot = capture();
    requireValue(options && typeof options === 'object' && !types.isProxy(options), 'AGENT_RECEIVE_OPTIONS_INVALID');
    const keys = Reflect.ownKeys(options);
    record(options, keys, 'AGENT_RECEIVE_OPTIONS_INVALID');
    requireValue(keys.every(key => ['scope', 'authenticatedPeerDeviceId', 'device'].includes(key)) &&
      Object.hasOwn(options, 'scope') && Object.hasOwn(options, 'authenticatedPeerDeviceId'), 'AGENT_RECEIVE_OPTIONS_INVALID');
    requireValue(sameScope(scopeCopy(options.scope), snapshot.scope) && options.authenticatedPeerDeviceId === snapshot.scope.peerDeviceId, 'AGENT_PEER_INVALID');
    const device = options.device ?? 'unknown'; requireValue(typeof device === 'string' && device.isWellFormed(), 'AGENT_RECEIVE_OPTIONS_INVALID');
    const item = { ...inputRow(message), direction: 'in', delivered: true };
    requireValue(binding(item.event, snapshot.scope, 'in'), 'AGENT_PEER_INVALID'); fresh(item.event);
    return enqueue(snapshot, async () => {
      fresh(item.event);
      const state = await history(snapshot), previous = state.ids.get(item.event.messageId);
      fresh(item.event);
      if (previous) requireValue(previous.direction === 'in' && sameRow(previous.row, item.row), 'AGENT_MESSAGE_CONFLICT');
      else applyEvent(state.tasks, item);
      try {
        const ids = await store.ingestIncoming([item.row], snapshot.scope, { device });
        if (!current(snapshot)) return Object.freeze({ ...retired(item), acknowledge: false });
        requireValue(Array.isArray(ids) && ids.length === 1 && ids[0] === item.row.id, 'AGENT_STORE_ACK_INVALID');
      } catch { return outcome(item, { committed: null, delivery: 'uncertain', uncertain: true, retired: !current(snapshot), acknowledge: false, error: 'AGENT_STORE_UNCERTAIN' }); }
      try { fresh(item.event); }
      catch { return outcome(item, { delivery: 'received', acknowledge: false, dispatch: false, error: 'AGENT_EVENT_EXPIRED_OR_FUTURE' }); }
      // Freshness/dedup hint only, never execution authorization. A future
      // canonical provider must independently filter expired/retired deliveries.
      return outcome(item, { delivery: 'received', acknowledge: true, duplicate: Boolean(previous), dispatch: !previous });
    });
  }
  async function status(input) {
    record(input, ['taskId'], 'AGENT_OPTIONS_INVALID');
    const { taskId } = input;
    const snapshot = capture(false); requireValue(typeof taskId === 'string' && UUID.test(taskId), 'AGENT_TASK_REFERENCE_INVALID');
    // Status joins the same drain barrier, but does not require peer readiness.
    return enqueue(snapshot, async () => {
      const { tasks } = await history(snapshot, false);
      const task = tasks.get(taskId);
      if (!task) return Object.freeze({ taskId, found: false, state: 'unknown', locallyVerified: false });
      const reported = task.result;
      return frozen({ taskId, found: true, requestMessageId: task.request.event.messageId,
        direction: task.request.direction, delivery: task.request.direction === 'in' ? 'received' : task.request.delivered ? 'peer-received' : 'pending',
        state: reported ? reported.direction === 'in' ? 'result-received' : 'result-sent' : task.cancellations.length ? 'cancel-requested' : task.progress.at(-1)?.event.payload.state ?? 'requested',
        payload: { ...task.request.event.payload, scope: [...task.request.event.payload.scope] }, cancelRequested: task.cancellations.length > 0,
        result: reported ? { messageId: reported.event.messageId, ...reported.event.payload, peerReported: reported.direction === 'in', locallyVerified: false } : null,
        locallyVerified: false });
    }, false);
  }
  function unavailableHistory() {
    return frozen({ protocol: 'agent-history-v1', available: false, items: [], hasMore: false, nextBeforeSeq: null,
      epoch: null, revision: 0, globalTail: 0 });
  }
  function unavailablePolicy() {
    return frozen({ protocol: 'agent-reply-policy-v1', available: false, semantics: 'receipts-only', defaultMode: 'trusted', mode: 'trusted', revision: 0,
      sessionId: null, trustScope: null, pending: [], pendingCount: 0, legacyPending: [], legacyPendingCount: 0 });
  }
  async function scopedRows(snapshot) {
    let rows;
    try { rows = await store.messagesForScope(snapshot.scope); } catch { fail('AGENT_HISTORY_UNAVAILABLE'); }
    checkCurrent(snapshot); requireValue(Array.isArray(rows), 'AGENT_HISTORY_INVALID'); return rows;
  }
  function pendingItems(snapshot, rows) {
    const time = clock();
    return rows.map(row => savedItem(snapshot, row)).filter(item => item && item.direction === 'out' && !item.delivered
      && item.event.expiresAt > time && item.event.createdAt <= time + FUTURE_SKEW
      && (item.gate.sessionId === snapshot.sessionId || item.gate.state === 'legacy-unapproved' && item.gate.sessionId === null)
      && !['approved', 'trusted', 'denied'].includes(permission(snapshot, item))).sort((a, b) => b.saved.seq - a.saved.seq);
  }
  async function businessHistory(input) {
    record(input, ['beforeSeq', 'limit'], 'AGENT_HISTORY_PAGE_INVALID');
    const { beforeSeq, limit } = input;
    requireValue((beforeSeq === null || integer(beforeSeq) && beforeSeq > 0) && integer(limit) && limit >= 1 && limit <= 50, 'AGENT_HISTORY_PAGE_INVALID');
    let snapshot;
    try { snapshot = capture(true, true); } catch { return unavailableHistory(); }
    return enqueue(snapshot, async () => {
      const allRows = await scopedRows(snapshot);
      let clearedThroughSeq = 0;
      try { clearedThroughSeq = historyView?.read(snapshot.scope, snapshot.sessionId) ?? 0; }
      catch (error) { fail(getAgentHistoryViewErrorCode(error) ?? 'AGENT_HISTORY_VIEW_UNAVAILABLE'); }
      requireValue(integer(clearedThroughSeq), 'AGENT_HISTORY_VIEW_UNAVAILABLE');
      const rows = allRows.filter(row => row.seq > clearedThroughSeq && (beforeSeq === null || row.seq < beforeSeq)).sort((a, b) => b.seq - a.seq);
      const meta = store.snapshot();
      requireValue(typeof meta.epoch === 'string' && integer(meta.revision) && integer(meta.globalTail), 'AGENT_HISTORY_INVALID');
      const items = [];
      const page = () => ({ protocol: 'agent-history-v1', available: true, items, hasMore: rows.length > items.length,
        nextBeforeSeq: rows.length > items.length ? items.at(-1)?.seq ?? null : null,
        epoch: meta.epoch, revision: meta.revision, globalTail: meta.globalTail });
      for (const row of rows.slice(0, limit)) {
        const item = savedItem(snapshot, row), inbound = row.direction === 'in';
        const gate = item?.gate ?? row.replyGate;
        const authorization = inbound ? 'not-applicable' : item ? permission(snapshot, item) : gate?.state === 'denied' ? 'denied' : 'legacy-unapproved';
        items.push({ seq: row.seq, direction: row.direction, messageId: row.id, taskId: item?.event.taskId ?? null,
          replyTo: item?.event.replyTo ?? row.replyTo, type: item?.event.type ?? 'unrecognized', createdAt: row.created,
          expiresAt: item?.event.expiresAt ?? null, receivedAt: inbound ? row.received : null,
          payload: item ? item.event.payload : null, delivery: inbound ? 'received' : row.delivered ? 'peer-received'
            : gate?.legacy || gate?.firstDispatchAt !== null ? 'pending' : 'not-sent',
          replyAuthorization: { state: authorization, revision: inbound ? 0 : gate?.revision ?? 0 }, locallyVerified: false });
        if (Buffer.byteLength(JSON.stringify(page()), 'utf8') > HISTORY_BYTES) { items.pop(); break; }
      }
      requireValue(rows.length === 0 || items.length > 0, 'AGENT_HISTORY_PAGE_INVALID');
      checkCurrent(snapshot); return frozen(page());
    });
  }
  async function publicPolicySnapshot() {
    let snapshot;
    try { snapshot = capture(true, true); } catch { return unavailablePolicy(); }
    return enqueue(snapshot, async () => {
      const rows = await scopedRows(snapshot), rule = ruleFor(snapshot), waiting = pendingItems(snapshot, rows);
      const receipts = waiting.filter(item => receiptOf(item)), legacy = waiting.filter(item => !receiptOf(item));
      const metadata = item => ({ messageId: item.row.id, seq: item.saved.seq, type: item.event.type,
        createdAt: item.event.createdAt, expiresAt: item.event.expiresAt, revision: item.gate.revision });
      checkCurrent(snapshot);
      return frozen({ protocol: 'agent-reply-policy-v1', available: true, semantics: 'receipts-only', defaultMode: 'trusted', mode: rule.mode, revision: rule.policyRevision,
        sessionId: snapshot.sessionId, trustScope: rule.trustScope, pendingCount: receipts.length,
        pending: receipts.slice(0, MAX_PENDING).map(item => ({ ...metadata(item), kind: 'receipt', sourceMessageIds: [...receiptOf(item).messageIds] })),
        legacyPendingCount: legacy.length, legacyPending: legacy.slice(0, MAX_PENDING).map(item => ({ ...metadata(item), kind: 'legacy-business' })) });
    });
  }
  async function setReplyPolicy(input, assertOwner) {
    requireValue(input !== null && typeof input === 'object' && !types.isProxy(input), 'AGENT_OPTIONS_INVALID');
    const keys = Reflect.ownKeys(input);
    record(input, keys, 'AGENT_OPTIONS_INVALID');
    requireValue(keys.includes('mode') && keys.includes('expectedRevision')
      && keys.every(key => ['mode', 'expectedRevision', 'expectedSessionId'].includes(key))
      && ['ask', 'trusted', 'deny'].includes(input.mode) && integer(input.expectedRevision), 'AGENT_OPTIONS_INVALID');
    const clean = Object.freeze({ ...input }), snapshot = capture(true, true);
    requireValue(clean.expectedSessionId === undefined || clean.expectedSessionId === snapshot.sessionId, 'AGENT_REPLY_CONTEXT_RETIRED');
    owner(snapshot, assertOwner); requireValue(replyPolicy !== null, 'AGENT_REPLY_POLICY_UNAVAILABLE');
    await enqueue(snapshot, async () => {
      owner(snapshot, assertOwner);
      try { await replyPolicy.set({ mode: clean.mode, expectedRevision: clean.expectedRevision }, snapshot.scope, snapshot.sessionId,
        () => { owner(snapshot, assertOwner); return true; }); }
      catch (error) { fail(getAgentReplyPolicyErrorCode(error) ?? 'AGENT_REPLY_POLICY_UNAVAILABLE'); }
      owner(snapshot, assertOwner);
    });
    owner(snapshot, assertOwner);
    const result = await publicPolicySnapshot(); owner(snapshot, assertOwner); return result;
  }
  async function clearHistory(input, assertOwner) {
    requireValue(input && typeof input === 'object' && !types.isProxy(input), 'AGENT_HISTORY_CLEAR_INVALID');
    const keys = Reflect.ownKeys(input); record(input, keys, 'AGENT_HISTORY_CLEAR_INVALID');
    requireValue(keys.includes('throughSeq') && keys.every(key => ['throughSeq', 'expectedSessionId'].includes(key))
      && integer(input.throughSeq), 'AGENT_HISTORY_CLEAR_INVALID');
    const clean = Object.freeze({ ...input }), snapshot = capture(true, true);
    requireValue(clean.expectedSessionId === undefined || clean.expectedSessionId === snapshot.sessionId, 'AGENT_REPLY_CONTEXT_RETIRED');
    owner(snapshot, assertOwner);
    return enqueue(snapshot, async () => {
      owner(snapshot, assertOwner);
      const meta = store.snapshot();
      requireValue(integer(meta.globalTail) && clean.throughSeq <= meta.globalTail, 'AGENT_HISTORY_CLEAR_INVALID');
      requireValue(historyView !== null, 'AGENT_HISTORY_VIEW_UNAVAILABLE');
      let value;
      try { value = await historyView.advance({ throughSeq: clean.throughSeq, expectedRevision: historyView.snapshot().revision },
        snapshot.scope, snapshot.sessionId, () => { owner(snapshot, assertOwner); return true; }); }
      catch (error) { fail(getAgentHistoryViewErrorCode(error) ?? 'AGENT_HISTORY_VIEW_UNAVAILABLE'); }
      owner(snapshot, assertOwner);
      return frozen({ protocol: 'agent-history-clear-v1', changed: value.changed, clearedThroughSeq: value.clearedThroughSeq, retainedSafetyRecords: true });
    });
  }
  function receiptCompletion(status, item, sourceCount, result = null) {
    let delivery = result?.delivery ?? (item?.delivered ? 'peer-received' : item?.dispatched ? 'pending'
      : item?.gate.state === 'denied' ? 'denied' : item?.gate.state === 'awaiting-approval' ? 'awaiting-approval' : 'not-sent');
    if (!['pending', 'peer-received', 'awaiting-approval', 'denied', 'uncertain', 'not-sent'].includes(delivery)) delivery = 'not-sent';
    return frozen({ protocol: 'agent-receipt-completion-v1', status, receiptMessageId: item?.event.messageId ?? null,
      sourceCount, committed: result?.committed === null ? null : true, delivery, duplicate: status === 'already-recorded',
      uncertain: result?.uncertain === true, retired: result?.retired === true, receivedFactOnly: true });
  }
  async function completeIncomingBatch(input, assertOwner) {
    record(input, ['messageIds'], 'AGENT_RECEIPT_BATCH_INVALID');
    let messageIds; try { messageIds = receiptMessageIds(input.messageIds); } catch { fail('AGENT_RECEIPT_BATCH_INVALID'); }
    const snapshot = capture(true, true), createdAt = clock(); owner(snapshot, assertOwner);
    return enqueue(snapshot, async () => {
      owner(snapshot, assertOwner);
      const state = await history(snapshot); owner(snapshot, assertOwner);
      const sources = messageIds.map(id => state.ids.get(id));
      requireValue(sources.every(item => item && item.direction === 'in'), 'AGENT_RECEIPT_BATCH_INVALID');
      const eligibleIds = sources.filter(item => !receiptOf(item)).map(item => item.row.id);
      if (!eligibleIds.length) return receiptCompletion('skipped', null, 0);
      const text = encodeAgentReceipt(eligibleIds), id = agentReceiptMessageId(snapshot.scope, eligibleIds), existing = state.ids.get(id);
      if (existing) {
        requireValue(existing.direction === 'out' && receiptOf(existing) && existing.event.payload.text === text, 'AGENT_RECEIPT_CONFLICT');
        // The canonical row, not a second delivery database, is the idempotency
        // fact. Never re-enter transmit after a duplicate or process restart.
        return receiptCompletion('already-recorded', existing, eligibleIds.length);
      }
      const item = makeEvent('message', { text }, { messageId: id }, snapshot, null, null, createdAt);
      owner(snapshot, assertOwner);
      const result = await transmit(snapshot, item, true, assertOwner);
      return receiptCompletion(result.uncertain ? 'uncertain' : 'recorded', item, eligibleIds.length, result);
    });
  }
  async function decideReply(input, assertOwner, approve) {
    record(input, ['messageId', 'expectedRevision'], 'AGENT_OPTIONS_INVALID');
    const { messageId, expectedRevision } = input;
    requireValue(typeof messageId === 'string' && LOWER_UUID.test(messageId) && integer(expectedRevision), 'AGENT_OPTIONS_INVALID');
    const snapshot = capture(true, true); owner(snapshot, assertOwner);
    return enqueue(snapshot, async () => {
      owner(snapshot, assertOwner);
      const item = (await history(snapshot)).ids.get(messageId); owner(snapshot, assertOwner);
      requireValue(item && item.direction === 'out' && !item.delivered, 'AGENT_REPLY_NOT_FOUND');
      requireValue(item.gate.sessionId === snapshot.sessionId || item.gate.state === 'legacy-unapproved' && item.gate.sessionId === null, 'AGENT_REPLY_CONTEXT_RETIRED');
      requireValue(item.gate.revision === expectedRevision, 'AGENT_REPLY_STALE');
      const receipt = receiptOf(item), rule = receipt ? ruleFor(snapshot) : { mode: 'trusted', revision: 0 }, time = clock();
      if (approve) {
        requireValue(item.gate.state !== 'denied' && rule.mode !== 'deny', 'AGENT_REPLY_DENIED');
        // An explicit receipt approval is single-use as well. A known attempt is
        // never made into a new approval by fetching a newer row revision.
        requireValue(!receipt || !item.dispatched && !['approved', 'trusted'].includes(item.gate.state), 'AGENT_REPLY_NOT_FOUND');
        requireValue(item.event.expiresAt > time && item.event.createdAt <= time + FUTURE_SKEW, 'AGENT_REPLY_EXPIRED');
        if (!item.protocolFact) { const active = await history(snapshot); owner(snapshot, assertOwner); applyEvent(active.tasks, item); }
      }
      const gate = { ...item.gate, state: approve ? 'approved' : 'denied', revision: item.gate.revision + 1,
        sessionId: snapshot.sessionId, policyRevision: rule.revision, approvedAt: approve ? time : null,
        approvalExpiresAt: approve ? Math.min(item.event.expiresAt, time + ONCE_TTL) : null };
      owner(snapshot, assertOwner); await persistGate(snapshot, item, gate); owner(snapshot, assertOwner);
      // Exactly this ID, original bytes and original expiry. No queue scan and no
      // second Root retry. Denial records only its fact, never protocol terminality.
      if (approve) return transmit(snapshot, item, false, assertOwner);
      return notAuthorized(item, 'denied');
    });
  }
  async function approveReply(input, assertOwner) { return decideReply(input, assertOwner, true); }
  async function denyReply(input, assertOwner) { return decideReply(input, assertOwner, false); }
  function drain() {
    if (!drainPromise) {
      drainPromise = (async () => {
        let barrier;
        do { barrier = queue; await barrier; if (typeof store.flush === 'function') await store.flush(); } while (barrier !== queue);
        return true;
      })().catch(error => {
        // Private synchronous diagnostics only; never a cleanup or an async join.
        try { onDrainFailure?.(error); } catch {}
        fail('AGENT_DRAIN_FAILED');
      }).finally(() => { drainPromise = null; });
    }
    return drainPromise;
  }
  function close() {
    closed = true;
    closePromise ||= drain(); return closePromise;
  }
  function protect(method) {
    return (...args) => method(...args).catch(error => { if (OWN_ERRORS.has(error)) throw error; fail('AGENT_SERVICE_FAILED'); });
  }
  return Object.freeze({ sendMessage: protect(sendMessage), request: protect(request), progress: protect(progress), result: protect(result),
    cancel: protect(cancel), status: protect(status), retry: protect(retry), receive: protect(receive), history: protect(businessHistory),
    replyPolicySnapshot: protect(publicPolicySnapshot), setReplyPolicy: protect(setReplyPolicy), approveReply: protect(approveReply),
    denyReply: protect(denyReply), clearHistory: protect(clearHistory), completeIncomingBatch: protect(completeIncomingBatch), flush: drain, drain, close });
}

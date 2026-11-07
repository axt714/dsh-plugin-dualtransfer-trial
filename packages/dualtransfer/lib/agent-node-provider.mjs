import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { types } from 'node:util';
import { createAgentMessageStore, validateAgentMessageScope } from './agent-message-store.mjs';
import { createAgentTaskService, decodeAgentTaskEvent, getAgentTaskServiceErrorCode } from './agent-task-service.mjs';
import { safeDirectory, exclusiveFile, syncDir } from './private-fs.mjs';
import { createAgentReplyPolicy } from './agent-reply-policy.mjs';
import { createAgentHistoryView } from './agent-history-view.mjs';
import { assertRuntimeCapability, beginRuntimeBarrier, failRuntimeBarrier, createFailureLatch, brandAgentFailure, getAgentFailureDetails } from './agent-failure.mjs';

const SCOPE_KEYS = ['pairingId', 'generation', 'localDeviceId', 'peerDeviceId', 'localTargetToken', 'peerTargetToken'];
const CONTEXT_KEYS = ['scope', 'localReady', 'peerReady', 'authorityVersion'];
const LOWER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$(?![\s\S])/;
const SESSION = /^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const BODY_LIMIT = 16 * 1024;
// The frozen local-client caps the whole response at 2 MiB. Budget the final
// JSON envelope, not just event text or the requested number of rows.
const PAGE_RESPONSE_LIMIT = 1024 * 1024;
const OWN_ERRORS = new WeakMap(), HTTP_STATUS = new WeakMap();
const ERROR_CODES = new Set(`AGENT_PROVIDER_INPUT_INVALID AGENT_PROVIDER_CONTEXT_INVALID AGENT_PROVIDER_BODY_INVALID AGENT_PROVIDER_OPTIONS_INVALID
AGENT_PROVIDER_NOT_RUNNING AGENT_PROVIDER_DIRECTORY_UNSAFE AGENT_PROVIDER_DIRECTORY_CHANGED AGENT_PROVIDER_DIRECTORY_LAYOUT AGENT_PROVIDER_CLIENT_EXISTS
AGENT_PROVIDER_CONTEXT_RETIRED AGENT_PROVIDER_OPERATION_FAILED AGENT_PROVIDER_PEER_INVALID AGENT_PROVIDER_ACK_INVALID AGENT_PROVIDER_ABORTED
AGENT_PROVIDER_PAGE_INVALID AGENT_PROVIDER_CLOCK_INVALID AGENT_PROVIDER_PAGE_TOO_LARGE AGENT_PROVIDER_LOCAL_ONLY AGENT_PROVIDER_HEADERS_INVALID
AGENT_PROVIDER_ORIGIN_FORBIDDEN AGENT_PROVIDER_HOST_INVALID AGENT_PROVIDER_UNAUTHORIZED AGENT_PROVIDER_CONTENT_TYPE_INVALID AGENT_PROVIDER_BODY_TOO_LARGE
AGENT_PROVIDER_ROUTE_INVALID AGENT_PROVIDER_METHOD_INVALID AGENT_PROVIDER_RETIRED AGENT_PROVIDER_LISTEN_FAILED AGENT_PROVIDER_HTTP_FAILED
AGENT_PROVIDER_START_FAILED AGENT_PROVIDER_DRAIN_FAILED AGENT_PROVIDER_STOP_FAILED`.split(/\s+/));
export function getAgentNodeProviderErrorCode(error) { return OWN_ERRORS.get(error) ?? null; }
function failure(code, serviceError) {
  if (!ERROR_CODES.has(code) && getAgentTaskServiceErrorCode(serviceError) !== code) code = 'AGENT_PROVIDER_OPERATION_FAILED';
  const error = Object.assign(new Error(code), { code });
  Object.defineProperty(error, 'stack', { value: code }); OWN_ERRORS.set(error, code); return error;
}
function protectedError(error) {
  if (getAgentNodeProviderErrorCode(error)) return error;
  const code = getAgentTaskServiceErrorCode(error);
  return code ? failure(code, error) : failure('AGENT_PROVIDER_OPERATION_FAILED');
}
function insist(value, code = 'AGENT_PROVIDER_INPUT_INVALID') { if (!value) throw failure(code); }
function record(value, required, optional = []) {
  insist(value !== null && typeof value === 'object' && !Array.isArray(value) && !types.isProxy(value));
  insist([Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const keys = Reflect.ownKeys(value), descriptors = Object.getOwnPropertyDescriptors(value);
  insist(required.every(key => keys.includes(key)) && keys.every(key => typeof key === 'string' &&
    [...required, ...optional].includes(key) && descriptors[key].enumerable && Object.hasOwn(descriptors[key], 'value')));
}
const integer = value => Number.isSafeInteger(value) && value >= 0;
const sameScope = (left, right) => left === null || right === null ? left === right : SCOPE_KEYS.every(key => left[key] === right[key]);
function copiedScope(value) {
  record(value, SCOPE_KEYS);
  try { return validateAgentMessageScope(Object.fromEntries(SCOPE_KEYS.map(key => [key, value[key]]))); }
  catch { throw failure('AGENT_PROVIDER_CONTEXT_INVALID'); }
}
// Reject duplicate JSON keys (including escaped spellings), excessive nesting and
// trailing input before JSON.parse can silently choose a different field value.
function parseBody(bytes) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw failure('AGENT_PROVIDER_BODY_INVALID'); }
  let at = 0;
  const space = () => { while (/[\x20\t\r\n]/.test(text[at] ?? '') && at < text.length) at++; };
  const string = () => {
    const re = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
    re.lastIndex = at; const match = re.exec(text); insist(match, 'AGENT_PROVIDER_BODY_INVALID');
    at = re.lastIndex; return JSON.parse(match[0]);
  };
  const value = depth => {
    insist(depth <= 16, 'AGENT_PROVIDER_BODY_INVALID'); space();
    if (text[at] === '"') { string(); return; }
    if (text[at] === '{' || text[at] === '[') {
      const object = text[at++] === '{', end = object ? '}' : ']', keys = new Set(); space();
      if (text[at] === end) { at++; return; }
      for (;;) {
        if (object) { const key = string(); insist(!keys.has(key), 'AGENT_PROVIDER_BODY_INVALID'); keys.add(key); space(); insist(text[at++] === ':', 'AGENT_PROVIDER_BODY_INVALID'); }
        value(depth + 1); space(); if (text[at] === end) { at++; return; }
        insist(text[at++] === ',', 'AGENT_PROVIDER_BODY_INVALID'); space();
      }
    }
    const re = /(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/y;
    re.lastIndex = at; insist(re.exec(text), 'AGENT_PROVIDER_BODY_INVALID'); at = re.lastIndex;
  };
  try { value(0); space(); insist(at === text.length, 'AGENT_PROVIDER_BODY_INVALID'); return JSON.parse(text); }
  catch { throw failure('AGENT_PROVIDER_BODY_INVALID'); }
}

/** Explicit-directory Node carrier. No filesystem, context call or socket at construction. */
export function createAgentNodeProvider({ directory, getContext, transport, now = Date.now, getOwnerSession = () => null, runtime }) {
  insist(typeof directory === 'string' && path.isAbsolute(directory) && !directory.includes('\0') &&
    path.resolve(directory) !== path.parse(directory).root && typeof getContext === 'function' && typeof now === 'function' && typeof getOwnerSession === 'function' &&
    transport && ['start', 'send', 'stop', 'flush', 'snapshot'].every(key => typeof transport[key] === 'function'), 'AGENT_PROVIDER_OPTIONS_INVALID');
  directory = path.resolve(directory);
  assertRuntimeCapability(runtime);
  const failures = createFailureLatch();
  const clientPath = path.join(directory, 'client.json'), ownerPath = path.join(directory, 'agent-node-provider.owner.lock');
  const store = createAgentMessageStore({ directory: path.join(directory, 'messages'), now, runtime });
  const replyPolicy = createAgentReplyPolicy({ directory });
  const historyView = createAgentHistoryView({ directory });
  const noHistory = Object.freeze({ protocol: 'agent-history-v1', available: false, items: Object.freeze([]),
    hasMore: false, nextBeforeSeq: null, epoch: null, revision: 0, globalTail: 0 });
  const noPolicy = Object.freeze({ protocol: 'agent-reply-policy-v1', available: false, semantics: 'receipts-only', defaultMode: 'trusted', mode: 'trusted', revision: 0,
    sessionId: null, trustScope: null, pending: Object.freeze([]), pendingCount: 0, legacyPending: Object.freeze([]), legacyPendingCount: 0 });
  let phase = 'idle', retired = false, fault = null, rootStat = null, releaseOwner = null, releaseClient = null;
  let service = null, server = null, port = null, token = null, transportStarted = false;
  let starting = null, stopping = null, draining = null, serviceClosing = null;
  const pending = new Set(), sockets = new Set();
  function snapshot() {
    const source = store.snapshot();
    return Object.freeze({ phase, listening: Boolean(server?.listening), port: server?.listening ? port : null,
      leaseHeld: releaseOwner !== null, errorCode: fault, store: Object.freeze({ phase: source.phase, epoch: source.epoch,
        globalTail: source.globalTail, revision: source.revision, total: source.total, pending: source.pending,
        errorCode: source.errorCode, directoryDurability: source.directoryDurability, permissionModel: source.permissionModel }) });
  }
  function admit() { insist(!retired && phase === 'running', 'AGENT_PROVIDER_NOT_RUNNING'); }
  function verifyRoot() {
    try { insist(safeDirectory(directory), 'AGENT_PROVIDER_DIRECTORY_UNSAFE'); }
    catch { throw failure('AGENT_PROVIDER_DIRECTORY_UNSAFE'); }
    const current = fs.lstatSync(directory, { bigint: true });
    insist(current.isDirectory() && !current.isSymbolicLink() && (process.platform === 'win32' ||
      (current.mode & 0o077n) === 0n && current.uid === BigInt(process.getuid())), 'AGENT_PROVIDER_DIRECTORY_UNSAFE');
    insist(!rootStat || current.dev === rootStat.dev && current.ino === rootStat.ino, 'AGENT_PROVIDER_DIRECTORY_CHANGED');
    return current;
  }
  function prepareRoot() {
    insist(safeDirectory(path.dirname(directory)), 'AGENT_PROVIDER_DIRECTORY_UNSAFE');
    try { fs.lstatSync(directory); }
    catch (error) { if (error.code !== 'ENOENT') throw error; fs.mkdirSync(directory, { mode: 0o700 }); syncDir(path.dirname(directory)); }
    rootStat = verifyRoot();
    const entries = fs.readdirSync(directory);
    insist(entries.every(name => ['messages', 'reply-policy.json', 'history-view.json', 'client.json', 'agent-node-provider.owner.lock'].includes(name)), 'AGENT_PROVIDER_DIRECTORY_LAYOUT');
    // An existing credential is an exception only for this run's fully checked
    // journal member. Existence, plausible JSON or a dead PID are not authority.
    insist(!entries.includes('client.json') || runtime !== undefined && runtime.canAcquire(clientPath) === true, 'AGENT_PROVIDER_CLIENT_EXISTS');
    const owner = { protocol: 'dualtransfer.agent-node/1', owner: randomUUID(), pid: process.pid };
    releaseOwner = runtime === undefined ? exclusiveFile(ownerPath, owner) : runtime.acquire(ownerPath, owner);
    verifyRoot();
  }
  function context() {
    let source;
    try { source = getContext(); record(source, CONTEXT_KEYS); }
    catch { throw failure('AGENT_PROVIDER_CONTEXT_INVALID'); }
    insist(typeof source.localReady === 'boolean' && typeof source.peerReady === 'boolean' &&
      (integer(source.authorityVersion) || typeof source.authorityVersion === 'string' && source.authorityVersion.length > 0), 'AGENT_PROVIDER_CONTEXT_INVALID');
    const sessionId = getOwnerSession();
    insist(sessionId === null || typeof sessionId === 'string' && SESSION.test(sessionId), 'AGENT_PROVIDER_CONTEXT_INVALID');
    return Object.freeze({ scope: source.scope === null ? null : copiedScope(source.scope), localReady: source.localReady,
      peerReady: source.peerReady, authorityVersion: source.authorityVersion, sessionId });
  }
  function current(captured) {
    admit(); const next = context();
    insist(next.authorityVersion === captured.authorityVersion && next.localReady === captured.localReady &&
      next.peerReady === captured.peerReady && next.sessionId === captured.sessionId && sameScope(next.scope, captured.scope), 'AGENT_PROVIDER_CONTEXT_RETIRED');
  }
  function accepted(work) {
    try {
      admit(); const result = Promise.resolve(work()).catch(error => { throw protectedError(error); }); pending.add(result);
      result.then(() => pending.delete(result), () => pending.delete(result)); return result;
    } catch (error) { return Promise.reject(protectedError(error)); }
  }
  function serviceCall(name, args) { return accepted(() => service[name](...args)); }
  function ownedCall(name, input, assertOwner) {
    return accepted(() => {
      insist(typeof assertOwner === 'function' && !types.isProxy(assertOwner));
      const captured = context(), sessionId = getOwnerSession();
      const guard = () => {
        insist(assertOwner() === true); current(captured);
        insist(getOwnerSession() === sessionId, 'AGENT_PROVIDER_CONTEXT_RETIRED');
        verifyRoot(); return true;
      };
      guard(); return service[name](input, guard);
    });
  }
  function history(input) { return retired || phase !== 'running' ? Promise.resolve(noHistory) : serviceCall('history', [input]); }
  function replyPolicySnapshot() { return retired || phase !== 'running' ? Promise.resolve(noPolicy) : serviceCall('replyPolicySnapshot', []); }
  function onMessage(input) {
    return accepted(() => {
      record(input, ['message', 'scope', 'authenticatedPeerDeviceId'], ['device']);
      return service.receive(input.message, { scope: input.scope, authenticatedPeerDeviceId: input.authenticatedPeerDeviceId,
        ...(input.device === undefined ? {} : { device: input.device }) });
    });
  }
  function onAck(input) {
    return accepted(() => {
      record(input, ['ids', 'scope', 'authenticatedPeerDeviceId']);
      const captured = context(), scope = copiedScope(input.scope), ids = input.ids;
      insist(captured.scope !== null && captured.localReady && captured.peerReady && sameScope(scope, captured.scope) &&
        input.authenticatedPeerDeviceId === captured.scope.peerDeviceId, 'AGENT_PROVIDER_PEER_INVALID');
      insist(Array.isArray(ids) && ids.length > 0 && ids.length <= 64 && ids.every(id => typeof id === 'string' && LOWER_UUID.test(id)) &&
        new Set(ids).size === ids.length, 'AGENT_PROVIDER_ACK_INVALID');
      const clean = ids.slice();
      return Promise.resolve().then(async () => { current(captured); verifyRoot(); const done = await store.acknowledge(clean, scope); current(captured); return Object.freeze(done.slice()); });
    });
  }
  function checkSignal(signal) { insist(!signal?.aborted, 'AGENT_PROVIDER_ABORTED'); }
  function readPage(input, options = {}) {
    return accepted(() => {
      record(input, ['since', 'limit'], ['channel', 'direction']); record(options, [], ['signal']);
      const { since, limit } = input, { signal } = options;
      insist(integer(since) && integer(limit) && limit >= 1 && limit <= 100 &&
        (input.direction === undefined || input.direction === 'in') && (input.channel === undefined || input.channel === 'agent'), 'AGENT_PROVIDER_PAGE_INVALID');
      insist(signal === undefined || !types.isProxy(signal) && signal instanceof AbortSignal, 'AGENT_PROVIDER_INPUT_INVALID');
      checkSignal(signal); const captured = context();
      return Promise.resolve().then(() => {
        current(captured); checkSignal(signal); const meta = store.snapshot();
        insist(since <= meta.globalTail, 'AGENT_PROVIDER_PAGE_INVALID');
        const time = now(); insist(integer(time), 'AGENT_PROVIDER_CLOCK_INVALID');
        const rows = captured.scope === null ? [] : store.messagesForScope(captured.scope).filter(row => {
          if (row.direction !== 'in' || row.channel !== 'agent' || row.seq <= since) return false;
          try {
            const event = decodeAgentTaskEvent(row.text), scope = captured.scope;
            return row.id === event.messageId && row.created === event.createdAt && row.replyTo === event.replyTo &&
              event.pairingId === scope.pairingId && event.generation === scope.generation &&
              event.fromDeviceId === scope.peerDeviceId && event.toDeviceId === scope.localDeviceId &&
              event.fromTargetToken === scope.peerTargetToken && event.toTargetToken === scope.localTargetToken &&
              event.expiresAt > time && event.createdAt <= time + 120000;
          } catch { return false; }
        });
        current(captured); checkSignal(signal);
        const messages = [];
        const page = () => ({ messages, next: messages.at(-1)?.seq ?? since, more: rows.length > messages.length,
          revision: meta.revision, epoch: meta.epoch, globalTail: meta.globalTail });
        for (const row of rows.slice(0, limit)) {
          const { admissionOrder, ...publicRow } = row; // Internal fold order is not frozen-reader wire.
          messages.push(Object.freeze(publicRow));
          if (Buffer.byteLength(JSON.stringify({ ok: true, value: page() }), 'utf8') > PAGE_RESPONSE_LIMIT) {
            messages.pop(); break;
          }
        }
        // With the frozen 16 KiB event limit, one legal row always fits. Never
        // return more:true without progress if that contract changes later.
        insist(rows.length === 0 || messages.length > 0, 'AGENT_PROVIDER_PAGE_TOO_LARGE');
        Object.freeze(messages); return Object.freeze(page());
      });
    });
  }
  function response(res, status, value) {
    if (res.destroyed || res.writableEnded) return;
    const body = Buffer.from(JSON.stringify(value));
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': body.length,
      'cache-control': 'no-store', 'x-content-type-options': 'nosniff', connection: 'close' }); res.end(body);
  }
  function httpFailure(code, status = 400) { const error = failure(code); HTTP_STATUS.set(error, status); throw error; }
  function headers(req) {
    if (req.socket.remoteAddress !== '127.0.0.1' || req.socket.localAddress !== '127.0.0.1') httpFailure('AGENT_PROVIDER_LOCAL_ONLY', 403);
    if (req.rawHeaders.length > 64) httpFailure('AGENT_PROVIDER_HEADERS_INVALID');
    const names = new Set();
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const key = req.rawHeaders[i].toLowerCase();
      if (names.has(key)) httpFailure('AGENT_PROVIDER_HEADERS_INVALID'); names.add(key);
    }
    if (names.has('origin') || names.has('referer')) httpFailure('AGENT_PROVIDER_ORIGIN_FORBIDDEN', 403);
    if (req.headers.host !== `127.0.0.1:${port}`) httpFailure('AGENT_PROVIDER_HOST_INVALID', 403);
    const auth = req.headers.authorization;
    if (typeof auth !== 'string' || !/^Bearer [0-9a-f]{64}$(?![\s\S])/.test(auth) ||
      !token || !timingSafeEqual(Buffer.from(auth.slice(7)), Buffer.from(token))) httpFailure('AGENT_PROVIDER_UNAUTHORIZED', 401);
    if (names.has('transfer-encoding') || names.has('content-encoding') || names.has('expect')) httpFailure('AGENT_PROVIDER_HEADERS_INVALID');
  }
  async function body(req) {
    if (!/^application\/json(?:; charset=utf-8)?$(?![\s\S])/i.test(req.headers['content-type'] ?? '')) httpFailure('AGENT_PROVIDER_CONTENT_TYPE_INVALID', 415);
    const length = req.headers['content-length'];
    if (typeof length !== 'string' || !DECIMAL.test(length)) httpFailure('AGENT_PROVIDER_BODY_INVALID');
    if (Number(length) > BODY_LIMIT) httpFailure('AGENT_PROVIDER_BODY_TOO_LARGE', 413);
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > BODY_LIMIT) httpFailure('AGENT_PROVIDER_BODY_TOO_LARGE', 413); chunks.push(chunk); }
    if (size !== Number(length)) httpFailure('AGENT_PROVIDER_BODY_INVALID');
    return parseBody(Buffer.concat(chunks, size));
  }
  async function handle(req, res) {
    try {
      headers(req); admit();
      // The bearer admits this request under this authority, before any body
      // await. A later binding must never inherit an already-admitted POST.
      const admittedContext = context();
      const target = req.url;
      if (typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//') || /[%#\\]/.test(target)) httpFailure('AGENT_PROVIDER_ROUTE_INVALID');
      const url = new URL(target, `http://127.0.0.1:${port}`);
      if (url.pathname !== target.split('?')[0]) httpFailure('AGENT_PROVIDER_ROUTE_INVALID');
      if (req.method === 'GET') {
        if (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0') httpFailure('AGENT_PROVIDER_BODY_INVALID');
        if (target === '/status') { current(admittedContext); return response(res, 200, { ok: true, value: snapshot() }); }
        if (url.pathname !== '/messages') httpFailure('AGENT_PROVIDER_ROUTE_INVALID', 404);
        const keys = [...url.searchParams.keys()];
        if (keys.length !== 4 || new Set(keys).size !== 4 || !['since', 'limit', 'direction', 'channel'].every(key => keys.includes(key)) ||
          !DECIMAL.test(url.searchParams.get('since')) || !DECIMAL.test(url.searchParams.get('limit'))) httpFailure('AGENT_PROVIDER_PAGE_INVALID');
        const value = await readPage({ since: Number(url.searchParams.get('since')), limit: Number(url.searchParams.get('limit')),
          direction: url.searchParams.get('direction'), channel: url.searchParams.get('channel') });
        current(admittedContext); return response(res, 200, { ok: true, value });
      }
      if (req.method !== 'POST') httpFailure('AGENT_PROVIDER_METHOD_INVALID', 405);
      if (target.includes('?')) httpFailure('AGENT_PROVIDER_ROUTE_INVALID');
      const routes = { '/agent/message': 'sendMessage', '/agent/request': 'request', '/agent/progress': 'progress',
        '/agent/result': 'result', '/agent/cancel': 'cancel', '/agent/status': 'status', '/agent/retry': 'retry' };
      const method = Object.hasOwn(routes, url.pathname) ? routes[url.pathname] : null;
      if (!method) httpFailure('AGENT_PROVIDER_ROUTE_INVALID', 404);
      const input = await body(req); current(admittedContext);
      let value;
      if (method === 'status' || method === 'retry') { current(admittedContext); value = await serviceCall(method, [input]); }
      else { record(input, ['payload'], ['options']); current(admittedContext); value = await serviceCall(method, [input.payload, input.options]); }
      current(admittedContext); response(res, 200, { ok: true, value });
    } catch (error) {
      const ownCode = getAgentNodeProviderErrorCode(error), status = ownCode ? HTTP_STATUS.get(error) ?? (retired ? 503 : 400) : 400;
      response(res, status, { ok: false, error: { code: ownCode ?? 'AGENT_PROVIDER_OPERATION_FAILED' } });
    } finally { req.resume(); }
  }
  function closeHTTP() {
    if (!server) return Promise.resolve();
    const currentServer = server;
    const done = new Promise((resolve, reject) => currentServer.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(error) : resolve()));
    currentServer.closeAllConnections(); for (const socket of sockets) socket.destroy(); return done;
  }
  function start() {
    if (retired) return Promise.reject(failure('AGENT_PROVIDER_RETIRED'));
    if (starting) return starting;
    phase = 'starting';
    starting = (async () => {
      prepareRoot(); insist(!retired, 'AGENT_PROVIDER_RETIRED');
      await store.open(); verifyRoot(); insist(!retired, 'AGENT_PROVIDER_RETIRED');
      await replyPolicy.open(); verifyRoot(); insist(!retired, 'AGENT_PROVIDER_RETIRED');
      await historyView.open(); verifyRoot(); insist(!retired, 'AGENT_PROVIDER_RETIRED');
      service = createAgentTaskService({ store, transport, getContext, now, replyPolicy, historyView, getOwnerSession,
        onDrainFailure(error) { failures.capture(error, { stage: 'provider-drain', origin: 'provider', lifecycle: 'stop' }); } });
      transportStarted = true; await transport.start(Object.freeze({ onMessage, onAck }));
      verifyRoot(); insist(!retired, 'AGENT_PROVIDER_RETIRED');
      token = randomBytes(32).toString('hex');
      server = http.createServer({ maxHeaderSize: 8192, requireHostHeader: true }, (req, res) => { void handle(req, res); });
      // Do not silently truncate rawHeaders: an Origin after the cap must be rejected.
      server.maxHeadersCount = 0; server.requestTimeout = 3000; server.headersTimeout = 3000;
      server.on('checkContinue', (req, res) => { void handle(req, res); });
      server.on('checkExpectation', (req, res) => { void handle(req, res); });
      server.keepAliveTimeout = 1; server.maxRequestsPerSocket = 1;
      server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); });
      server.on('clientError', (_error, socket) => { if (!socket.destroyed) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); });
      await new Promise((resolve, reject) => {
        const failed = () => reject(failure('AGENT_PROVIDER_LISTEN_FAILED'));
        server.once('error', failed); server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => { server.removeListener('error', failed); resolve(); });
      });
      server.on('error', () => { fault ??= 'AGENT_PROVIDER_HTTP_FAILED'; retired = true; phase = 'failed'; });
      port = server.address().port; verifyRoot(); insist(!retired, 'AGENT_PROVIDER_RETIRED');
      const client = { url: `http://127.0.0.1:${port}`, token };
      releaseClient = runtime === undefined ? exclusiveFile(clientPath, client) : runtime.acquire(clientPath, client);
      phase = 'running'; return snapshot();
    })().catch(async error => {
      const rootCause = failures.capture(error, { stage: 'provider-start', origin: 'provider', lifecycle: 'start' });
      if (!(getAgentNodeProviderErrorCode(error) === 'AGENT_PROVIDER_RETIRED' && stopping)) {
        fault ??= getAgentNodeProviderErrorCode(error) ?? 'AGENT_PROVIDER_START_FAILED';
        let barrier;
        try {
          barrier = beginRuntimeBarrier(runtime, 'startup-cleanup');
          retired = true; phase = 'failed';
          const joins = [closeHTTP()];
          if (transportStarted) joins.push(transport.stop());
          const outcomes = await Promise.allSettled(joins);
          if (outcomes.some(item => item.status === 'rejected')) throw failure('AGENT_PROVIDER_DRAIN_FAILED');
          barrier?.complete();
        } catch (cleanup) { failRuntimeBarrier(runtime, barrier, cleanup, 'startup-cleanup');
          throw brandAgentFailure(failure('AGENT_PROVIDER_DRAIN_FAILED'), { rootCause }); }
        try { runtime?.fail(rootCause?.code ?? 'AGENT_PROVIDER_START_FAILED', 'provider-start'); } catch {}
      }
      throw brandAgentFailure(failure(fault ?? 'AGENT_PROVIDER_RETIRED'), { rootCause });
    });
    return starting;
  }
  async function join() { let batch; do { batch = [...pending]; await Promise.allSettled(batch); } while (pending.size > 0); }
  async function drainWork() {
    if (starting) { try { await starting; } catch (error) { if (fault || !stopping) throw error; } }
    if (phase === 'idle' || phase === 'stopped') return snapshot();
    await join();
    if (service) await service.drain();
    if (rootStat) { await replyPolicy.drain(); await historyView.drain(); }
    if (transportStarted) insist(await transport.flush() !== false, 'AGENT_PROVIDER_DRAIN_FAILED');
    await join(); verifyRoot(); await store.flush(); await store.drain();
    insist(!fault && !store.snapshot().errorCode, 'AGENT_PROVIDER_DRAIN_FAILED'); return snapshot();
  }
  // All data drainage, including shutdown, shares this independent barrier.
  // Keep a rejected barrier: retrying a failed flush must not release its owners.
  function ensureDrain() {
    if (!draining) {
      let barrier;
      try { barrier = beginRuntimeBarrier(runtime, 'provider-drain'); }
      catch (error) {
        const rootCause = failures.capture(error, { stage: 'provider-drain', origin: 'provider', lifecycle: 'stop' });
        failRuntimeBarrier(runtime, barrier, error, 'provider-drain');
        draining = Promise.reject(brandAgentFailure(failure('AGENT_PROVIDER_DRAIN_FAILED'), { rootCause }));
        draining.catch(() => {}); return draining;
      }
      const work = drainWork().then(value => { barrier?.complete(); return value; }).catch(error => {
        const rootCause = failures.capture(error, { stage: 'provider-drain', origin: 'provider', lifecycle: 'stop' });
        failRuntimeBarrier(runtime, barrier, error, 'provider-drain');
        fault ??= 'AGENT_PROVIDER_DRAIN_FAILED'; retired = true; phase = 'failed';
        throw brandAgentFailure(failure('AGENT_PROVIDER_DRAIN_FAILED'), { rootCause });
      });
      draining = work;
      work.then(() => { if (!stopping && draining === work) draining = null; }, () => {});
    }
    return draining;
  }
  function drain() {
    // Public drain during stop joins the entire stop. stop itself must only
    // join ensureDrain(), never this wrapper (which would await itself).
    return stopping ?? ensureDrain();
  }
  function stop() {
    if (stopping) return stopping;
    let barrier;
    try { barrier = beginRuntimeBarrier(runtime, 'provider-stop'); }
    catch (error) {
      const rootCause = failures.capture(error, { stage: 'provider-stop', origin: 'provider', lifecycle: 'stop' });
      failRuntimeBarrier(runtime, barrier, error, 'provider-stop');
      return Promise.reject(brandAgentFailure(failure('AGENT_PROVIDER_STOP_FAILED'), { rootCause }));
    }
    const wasRunning = phase === 'running';
    retired = true; phase = phase === 'idle' ? 'stopped' : 'stopping';
    const quiet = wasRunning ? Promise.resolve().then(() => transport.quiesce?.()) : Promise.resolve(); quiet.catch(() => {});
    if (service) { serviceClosing = service.close(); serviceClosing.catch(() => {}); }
    stopping = (async () => {
      if (starting) { try { await starting; } catch { if (fault) throw failure(fault); } }
      await quiet;
      if (transportStarted) await transport.quiesce?.();
      await closeHTTP();
      if (serviceClosing) await serviceClosing;
      if (service) await service.close();
      if (rootStat) { await ensureDrain(); verifyRoot(); }
      if (transportStarted) { insist(await transport.stop() !== false, 'AGENT_PROVIDER_STOP_FAILED'); transportStarted = false; }
      if (rootStat) {
        if (releaseClient) { releaseClient(); releaseClient = null; } token = null;
        await replyPolicy.close(); await historyView.close(); await store.close();
        if (releaseOwner) { verifyRoot(); releaseOwner(); releaseOwner = null; }
      }
      barrier?.complete(); phase = 'stopped'; return snapshot();
    })().catch(async error => {
      const rootCause = failures.capture(error, { stage: 'provider-stop', origin: 'provider', lifecycle: 'stop' });
      failRuntimeBarrier(runtime, barrier, error, 'provider-stop'); fault ??= 'AGENT_PROVIDER_STOP_FAILED'; phase = 'failed';
      try { await closeHTTP(); } catch {}
      if (transportStarted) { try { await transport.stop(); } catch {} }
      throw brandAgentFailure(failure('AGENT_PROVIDER_STOP_FAILED'), { rootCause });
    });
    return stopping;
  }
  return Object.freeze({ clientPath, start, stop, flush: drain, drain, readPage, snapshot, history, replyPolicySnapshot,
    setReplyPolicy: (input, assertOwner) => ownedCall('setReplyPolicy', input, assertOwner),
    approveReply: (input, assertOwner) => ownedCall('approveReply', input, assertOwner),
    denyReply: (input, assertOwner) => ownedCall('denyReply', input, assertOwner),
    clearHistory: (input, assertOwner) => ownedCall('clearHistory', input, assertOwner),
    completeIncomingBatch: (input, assertOwner) => ownedCall('completeIncomingBatch', input, assertOwner),
    sendMessage: (...args) => serviceCall('sendMessage', args), request: (...args) => serviceCall('request', args),
    progress: (...args) => serviceCall('progress', args), result: (...args) => serviceCall('result', args),
    cancel: (...args) => serviceCall('cancel', args), retry: (...args) => serviceCall('retry', args),
    status: (...args) => args.length === 0 ? snapshot() : serviceCall('status', args) });
}

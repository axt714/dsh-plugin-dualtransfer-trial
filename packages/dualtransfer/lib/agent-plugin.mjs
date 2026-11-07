import path from 'node:path';
import { networkInterfaces } from 'node:os';
import { isIPv4 } from 'node:net';
import { randomUUID } from 'node:crypto';
import { types } from 'node:util';
import { failure, safeDirectory } from './private-fs.mjs';
import { verifySourceContract } from './source-contract.mjs';
import { createAgentNodeProvider, getAgentNodeProviderErrorCode } from './agent-node-provider.mjs';
import { createAgentPeerTransport } from './agent-peer-transport.mjs';
import { createAgentHostBinding, isAgentHostRetryableReadError } from './agent-host-binding.mjs';
import { createRuntimeOwnership } from './agent-runtime-ownership.mjs';
import { beginRuntimeBarrier, failRuntimeBarrier, createFailureLatch, brandAgentFailure, getAgentFailureDetails, safeFailureCode } from './agent-failure.mjs';

const SESSION = /^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/u;
const MESSAGE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/u;
const SCOPE_KEYS = Object.freeze(['pairingId', 'generation', 'localDeviceId', 'peerDeviceId', 'localTargetToken', 'peerTargetToken']);
const OWNER_DATA_ACTIONS = new Set(['history', 'replyPolicy', 'setReplyPolicy', 'approveReply', 'denyReply', 'clearHistory']);
const BINDING_STAGES = new Set(['queued', 'acquiring-owner', 'draining-previous', 'resolving-agent', 'persisting-session',
  'opening-core', 'registering-tools', 'initializing-reader', 'committing-binding', 'publishing-readiness',
  'waiting-peer', 'ready', 'failed', 'retired']);
const drainFailureDetails = new WeakMap();
const sameScope = (a, b) => a === null || b === null ? a === b : SCOPE_KEYS.every(key => a[key] === b[key]);
const C6_DATA_ERRORS = new Set(['AGENT_RECEIPT_BATCH_INVALID', 'AGENT_RECEIPT_CONFLICT', 'AGENT_RECEIPT_RESERVED',
  'AGENT_HISTORY_CLEAR_INVALID', 'AGENT_HISTORY_VIEW_UNAVAILABLE', 'AGENT_HISTORY_VIEW_FULL', 'AGENT_HISTORY_VIEW_STALE']);
function code(error) {
  const branded = getAgentNodeProviderErrorCode(error);
  if (C6_DATA_ERRORS.has(branded)) return branded;
  const value = error?.code;
  // Reject forged or future leaf names in these new families; a prefix is not a public allowlist.
  if (typeof value === 'string' && (value.startsWith('AGENT_RECEIPT_') || value.startsWith('AGENT_HISTORY_CLEAR_')
    || value.startsWith('AGENT_HISTORY_VIEW_'))) return 'AGENT_OPERATION_FAILED';
  return /^[A-Z][A-Z0-9_]{0,63}$(?![\s\S])/u.test(value ?? '') ? value : 'AGENT_OPERATION_FAILED';
}
function record(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value)
    || Reflect.ownKeys(value).length !== keys.length || keys.some(key => {
      const d = Object.getOwnPropertyDescriptor(value, key); return !d || !Object.hasOwn(d, 'value');
    })) throw failure('INVALID_INPUT');
}
function check(assert) { if (typeof assert !== 'function' || assert() !== true) throw failure('INVALID_CONTEXT'); }
const select = (value, keys) => Object.fromEntries(keys.filter(key => Object.hasOwn(value ?? {}, key)).map(key => [key, value[key]]));

/** One explicitly started, new Agent-only lifecycle. No legacy runtime or root is adopted. */
export function createAgentOnlyController({ ctx, defineTool, createUserMessage, Session, SessionId }, seams = {}) {
  const makePeer = seams.createTransport ?? createAgentPeerTransport;
  const makeProvider = seams.createProvider ?? createAgentNodeProvider;
  const makeBinding = seams.createBinding ?? createAgentHostBinding;
  const validateSource = seams.verifySourceContract ?? (() => verifySourceContract({ createUserMessage, Session, SessionId }));
  const makeOwnership = seams.createRuntimeOwnership ?? createRuntimeOwnership;
  const failures = createFailureLatch();
  const timers = seams.timers ?? { setInterval, clearInterval };
  const readInterfaces = seams.networkInterfaces ?? networkInterfaces;
  const noEndpoint = Object.freeze({ listening: false, port: null, addresses: Object.freeze([]) });
  let phase = 'off', closed = false, errorCode = null, release = null;
  let peer = null, provider = null, binding = null, starting = null, stopping = null, interval = null;
  let tickTail = Promise.resolve(), lifecycle = 0, tickPending = false, bindingOperationId = null;
  let disposePromise = null, drainDiagnostic = null, runtime = null, runtimeOpened = false;
  const readinessRetirements = new Set();
  // Only the Host receives this view. Each withdrawal gets a single-call
  // capability; external owner operations still close immediately.
  function hostTransport(transport) {
    return Object.freeze({ ...transport,
      setTargetReadiness(value, authorization) {
        if (value?.ready !== false || value.localTargetToken !== null) return transport.setTargetReadiness(value, authorization);
        let active = true;
        const retirementOwner = () => {
          if (!active || peer !== transport) return false;
          active = false;
          return authorization() === true;
        };
        readinessRetirements.add(retirementOwner);
        try { return transport.setTargetReadiness({ ready: false, localTargetToken: null }, retirementOwner); }
        finally { active = false; readinessRetirements.delete(retirementOwner); }
      },
    });
  }
  function failedDrain(stages) {
    // Only locally selected, bounded stage names leave this boundary; never child messages, paths or causes.
    drainDiagnostic = Object.freeze({ protocol: 'agent-drain-v1', lifecycle, stages: Object.freeze([...stages]) });
    const error = failure('AGENT_DRAIN_FAILED');
    error.message = `AGENT_DRAIN_FAILED:${stages.join(',')}`;
    drainFailureDetails.set(error, drainDiagnostic);
    return brandAgentFailure(error, { rootCause: failures.snapshot(), drain: drainDiagnostic });
  }
  function assertOpen(assert) { if (closed) throw failure('AGENT_CONTROLLER_CLOSED'); check(assert); }
  function localEndpoint(transport) {
    const ticket = lifecycle, port = transport?.port;
    const current = () => !closed && phase === 'running' && ticket === lifecycle;
    if (!current() || transport?.listening !== true || !Number.isInteger(port) || port < 1 || port > 65535) return noEndpoint;
    const addresses = [], seen = new Set();
    try {
      const interfaces = readInterfaces();
      if (interfaces && typeof interfaces === 'object' && !Array.isArray(interfaces) && !types.isProxy(interfaces)) {
        // OS metadata only: cap interfaces, entries per interface and returned IPv4s.
        outer: for (const interfaceName of Object.keys(interfaces).slice(0, 64)) {
          if (interfaceName.length > 80 || interfaceName !== interfaceName.trim()
            || !/^[\p{L}\p{M}\p{N}_.:() @#+-]+$(?![\s\S])/u.test(interfaceName)) continue;
          const entries = Object.getOwnPropertyDescriptor(interfaces, interfaceName)?.value;
          if (!Array.isArray(entries) || types.isProxy(entries)) continue;
          for (let index = 0; index < Math.min(entries.length, 32); index++) {
            const item = Object.getOwnPropertyDescriptor(entries, String(index))?.value;
            if (!item || typeof item !== 'object' || types.isProxy(item)) continue;
            const fields = Object.getOwnPropertyDescriptors(item), address = fields.address?.value, family = fields.family?.value;
            if (fields.internal?.value !== false || (family !== 'IPv4' && family !== 4) || typeof address !== 'string' || !isIPv4(address)) continue;
            const first = Number(address.split('.')[0]);
            if (first === 0 || first === 127 || first >= 224 || seen.has(address)) continue;
            seen.add(address); addresses.push(Object.freeze({ address, interfaceName }));
            if (addresses.length === 16) break outer;
          }
        }
      }
    } catch { addresses.length = 0; } // Enumeration failure never invents an address or leaks OS errors.
    if (!current()) return noEndpoint;
    return Object.freeze({ listening: true, port, addresses: Object.freeze(addresses) });
  }
  function snapshot(sessionId, operationId, observed, assert) {
    const p = provider?.snapshot() ?? { phase: 'off', listening: false };
    const t = peer?.snapshot() ?? { phase: 'off', paired: false, connected: false };
    const endpoint = localEndpoint(t);
    const local = binding?.status() ?? { bound: false, dispatchReady: false };
    const sameOwner = sessionId === undefined || local.sessionId === sessionId;
    const selected = operationId ?? (sameOwner ? local.operationId ?? bindingOperationId : null);
    const operation = observed ?? (binding && selected ? sessionId === undefined
      ? binding.query({ operationId: selected }) : binding.queryForSession({ sessionId, operationId: selected }, assert) : null);
    if (operation && operation.operationId !== selected) throw failure('OPERATION_ID_MISMATCH');
    // Querying A never changes the global selector or borrows B's live READY.
    const active = sameOwner && local.bound === true && local.operationId === selected && operation?.localReady === true;
    const stageOwned = typeof selected === 'string' && selected === operation?.bindingStageOperationId
      && BINDING_STAGES.has(operation.bindingStage);
    const b = { status: 'unconfirmed', ...operation, bound: active, localReady: active && local.localReady === true,
      dispatchReady: active && local.dispatchReady === true && operation?.status === 'confirmed' && operation.dispatchReady === true,
      // Stage is a current-operation observation, never another source of readiness or authority.
      bindingStage: stageOwned ? operation.bindingStage : null,
      bindingStageOperationId: stageOwned ? selected : null,
      resourceErrorCode: operation?.resourceErrorCode ?? null,
      rootCause: operation?.rootCause ?? null };
    const pairings = Array.isArray(t.pendingPairings) ? t.pendingPairings.map(item => select(item,
      ['pairingId', 'localApproved', 'peerApproved', 'expiresAt'])) : [];
    return { protocol: 'agent-only-v1', agentOnly: true, phase, errorCode, drain: drainDiagnostic,
      rootCause: failures.snapshot() ?? operation?.rootCause ?? null, localEndpoint: endpoint,
      provider: select(p, ['phase', 'listening', 'port', 'leaseHeld', 'errorCode']),
      peer: { ...select(t, ['phase', 'state', 'listening', 'port', 'deviceId', 'paired', 'connected', 'peerDeviceId', 'pairingId',
        'localReady', 'peerReady', 'ready', 'pendingPairingId', 'pendingExpiresAt', 'peerFingerprint', 'invitationPending', 'authorityVersion', 'lastErrorCode']), pendingPairings: pairings },
      binding: select(b, ['protocol', 'operationId', 'status', 'phase', 'bound', 'localReady', 'dispatchReady', 'changed', 'errorCode', 'updatedAt', 'expiresAt',
        'bindingStage', 'bindingStageOperationId', 'resourceErrorCode', 'rootCause']) };
  }
  function directory() {
    const profile = ctx.get?.('profileContext');
    if (!profile || typeof profile.dir !== 'string' || !path.isAbsolute(profile.dir)
      || path.resolve(profile.dir) === path.parse(path.resolve(profile.dir)).root
      || path.resolve(profile.patchPath ?? '') !== path.join(path.resolve(profile.dir), 'cordis.patch.yml')) throw failure('AGENT_PROFILE_AUTHORITY_REQUIRED');
    return path.join(path.resolve(profile.dir), 'agent-only-v1');
  }
  function context() {
    if (phase !== 'running' || !binding) return { scope: null, localReady: false, peerReady: false, authorityVersion: lifecycle };
    return binding.getContext();
  }
  // Process-local attestation only. No JSON field or target token proves Session authority.
  function ownerSession() {
    if (closed || phase !== 'running' || !binding) return null;
    const local = binding.status();
    return local.bound === true && local.localReady === true && typeof local.sessionId === 'string'
      && SESSION.test(local.sessionId) ? local.sessionId : null;
  }
  async function start(assert) {
    assertOpen(assert);
    if (phase === 'failed') throw brandAgentFailure(failure('AGENT_LIFECYCLE_FAILED'), { rootCause: failures.snapshot(), drain: drainDiagnostic });
    if (stopping) throw failure('AGENT_STOP_IN_PROGRESS');
    if (phase === 'running') return snapshot();
    if (starting) { await starting; assertOpen(assert); return snapshot(); }
    phase = 'starting'; errorCode = null; const ticket = ++lifecycle;
    let startupStage = 'source-contract';
    const assertStart = () => {
      assertOpen(assert);
      if (phase !== 'starting' || ticket !== lifecycle) throw failure('AGENT_START_RETIRED');
    };
    starting = (async () => {
      try {
        if (validateSource() !== 'verified') throw failure('SOURCE_CONTRACT_REFUSED');
        assertStart(); startupStage = 'profile-authority';
        const root = directory(); assertStart(); startupStage = 'ownership-open';
        // Only initialize the authorized runtime directory. This neither adopts
        // old leases nor substitutes for the native root/ACL/anchor proof below.
        safeDirectory(root, { create: true });
        runtime = makeOwnership({ directory: root });
        if (!runtime || !['open', 'acquire', 'canAcquire', 'prepareDirectory', 'beginBarrier', 'fail', 'started', 'close', 'snapshot']
          .every(key => typeof runtime[key] === 'function')) throw failure('AGENT_OWNERSHIP_CAPABILITY_REQUIRED');
        await runtime.open(); runtimeOpened = true; assertStart(); startupStage = 'product-owner';
        release = runtime.acquire(path.join(root, 'owner.lock'), { schema: 1, product: 'dsh-agent-only-v1', pid: process.pid, nonce: randomUUID() });
        peer = makePeer({ directory: path.join(root, 'peer'), host: '0.0.0.0', port: 0, runtime,
          authorizeOwner: (authorization, purpose) => typeof authorization === 'function'
            && (readinessRetirements.has(authorization) ? purpose === 'retire-readiness' : !closed) && authorization() === true });
        provider = makeProvider({ directory: path.join(root, 'provider'), transport: peer, getContext: context, getOwnerSession: ownerSession, runtime });
        binding = makeBinding({ ctx, directory: path.join(root, 'host'), provider, transport: hostTransport(peer), defineTool, createUserMessage, runtime });
        startupStage = 'provider-start'; await provider.start(); assertStart();
        interval = timers.setInterval(() => {
          if (closed || phase !== 'running' || tickPending) return;
          tickPending = true;
          tickTail = tickTail.then(async () => {
            if (phase !== 'running' || closed) return;
            await binding.tick();
            if (errorCode === 'READ_IO_FAILED' && !failures.snapshot()) errorCode = null;
          }).catch(error => {
              if (isAgentHostRetryableReadError(error)) { errorCode = 'READ_IO_FAILED'; return; }
              errorCode = code(error);
              failures.capture(error, { stage: 'tick', origin: 'host', lifecycle: 'bind' });
              try { runtime?.fail(safeFailureCode(error), 'tick'); } catch {}
            }).finally(() => { tickPending = false; });
        }, 1000); interval?.unref?.();
        startupStage = 'runtime-started'; runtime.started(); phase = 'running';
        return snapshot();
      } catch (error) {
        // An intentional concurrent retirement is joined by stopInternal, not a
        // fictitious startup failure or a second close of its active barrier.
        if (['AGENT_START_RETIRED', 'AGENT_CONTROLLER_CLOSED'].includes(code(error))
          && (closed || stopping || ticket !== lifecycle)) throw error;
        const rootCause = failures.capture(error, { stage: startupStage,
          origin: ['ownership-open', 'product-owner', 'runtime-started'].includes(startupStage) ? 'ownership' : 'controller', lifecycle: 'start' });
        phase = 'failed'; errorCode = code(error);
        if (runtimeOpened) { try { runtime.fail(rootCause?.code ?? 'AGENT_OPERATION_FAILED', startupStage); } catch {} }
        let cleanupStage = 'startup-cleanup', barrier;
        try {
          if (binding || provider || release) {
            barrier = beginRuntimeBarrier(runtime ?? undefined, 'startup-cleanup');
            await binding?.dispose(); await provider?.stop();
            cleanupStage = 'owner-release'; if (release) { release(); release = null; }
            barrier?.complete();
          }
          cleanupStage = 'runtime-close'; await runtime?.close(); runtime = null; runtimeOpened = false;
        } catch (cleanup) {
          failRuntimeBarrier(runtime ?? undefined, barrier, cleanup, cleanupStage);
          errorCode = 'AGENT_DRAIN_FAILED'; throw failedDrain([cleanupStage]);
        }
        throw brandAgentFailure(failure(errorCode), { rootCause });
      }
    })();
    try { return await starting; } finally { starting = null; }
  }
  function preserveBindingCause() {
    // A confirmed current binding failure predates generic teardown errors.
    // Promote its already-safe process-local projection only when retiring the
    // whole controller; normal foreign-session observations still stay fenced.
    const rootCause = binding?.status()?.rootCause;
    if (rootCause && !failures.snapshot()) failures.capture(brandAgentFailure(failure('HOST_BIND_FAILED'), { rootCause }),
      { stage: 'host-bind', origin: 'host', lifecycle: 'bind' });
  }
  function stopInternal(preparedBarrier) {
    if (stopping) return stopping;
    preserveBindingCause();
    let barrier;
    try { barrier = preparedBarrier === undefined ? beginRuntimeBarrier(runtime ?? undefined, 'controller-stop') : preparedBarrier; }
    catch (error) {
      failures.capture(error, { stage: 'ownership-barrier', origin: 'ownership', lifecycle: 'stop' });
      failRuntimeBarrier(runtime ?? undefined, null, error, 'ownership-barrier');
      phase = 'failed'; errorCode = 'AGENT_DRAIN_FAILED'; return Promise.reject(failedDrain(['ownership-barrier']));
    }
    const quiesceRunningPeer = phase === 'running';
    phase = 'stopping'; lifecycle += 1;
    if (interval !== null) { timers.clearInterval(interval); interval = null; }
    const localDrain = (() => { try { return binding?.dispose(); } catch (error) { return Promise.reject(error); } })();
    // Interrupt native writes before Host/queue joins; final stop still owns all
    // socket/frame/identity joins and every release. Startup keeps its old join.
    const quiet = quiesceRunningPeer ? Promise.resolve().then(() => peer?.quiesce?.()) : Promise.resolve();
    stopping = (async () => {
      const [host, startup] = await Promise.all([
        Promise.allSettled([localDrain, tickTail, quiet]), Promise.allSettled([starting]),
      ]);
      const network = await Promise.allSettled([Promise.resolve().then(() => provider?.stop())]);
      const stages = [];
      if (host[0].status === 'rejected') {
        failures.capture(host[0].reason, { stage: 'host-dispose', origin: 'host', lifecycle: 'stop' }); stages.push('host-dispose');
      }
      if (host[1].status === 'rejected') {
        failures.capture(host[1].reason, { stage: 'tick', origin: 'host', lifecycle: 'stop' }); stages.push('tick-join');
      }
      if (host[2].status === 'rejected') {
        failures.capture(host[2].reason, { stage: 'transport-stop', origin: 'peer', lifecycle: 'stop' }); stages.push('transport-stop');
      }
      if (startup.some(item => item.status === 'rejected' && item.reason?.code === 'AGENT_DRAIN_FAILED')) stages.push('startup-cleanup');
      if (network[0].status === 'rejected') {
        failures.capture(network[0].reason, { stage: 'provider-stop', origin: 'provider', lifecycle: 'stop' }); stages.push('provider-stop');
      }
      if (stages.length) throw failedDrain(stages);
      try { if (release) { release(); release = null; } }
      catch (error) {
        failures.capture(error, { stage: 'owner-release', origin: 'ownership', lifecycle: 'stop' }); throw failedDrain(['owner-release']);
      }
      try { barrier?.complete(); await runtime?.close(); }
      catch (error) {
        failures.capture(error, { stage: 'runtime-close', origin: 'ownership', lifecycle: 'stop' }); throw failedDrain(['runtime-close']);
      }
      runtime = null; runtimeOpened = false;
      peer = null; provider = null; binding = null; bindingOperationId = null; phase = closed ? 'closed' : 'off'; errorCode = null; drainDiagnostic = null;
      failures.clear(); return snapshot();
    })().catch(error => {
      failRuntimeBarrier(runtime ?? undefined, barrier, error, 'controller-stop'); phase = 'failed'; errorCode = 'AGENT_DRAIN_FAILED';
      throw getAgentFailureDetails(error) ? error : failedDrain(['runtime-close']);
    });
    const finish = () => { stopping = null; }; stopping.then(finish, finish); return stopping;
  }
  function queryFence(assert, ticket, host, state) {
    if (assert !== undefined) assertOpen(assert);
    if (ticket !== lifecycle || host !== binding || state !== phase) throw failure('AGENT_QUERY_RETIRED');
  }
  async function query(payload, assert) {
    record(payload, ['sessionId', 'operationId']);
    payload = Object.freeze({ sessionId: payload.sessionId, operationId: payload.operationId });
    if (!SESSION.test(payload.sessionId ?? '') || !UUID.test(payload.operationId ?? '')) throw failure('INVALID_INPUT');
    assertOpen(assert);
    const ticket = lifecycle, host = binding, state = phase;
    // A miss is indistinguishable from a foreign owner; neither is observed.
    const value = host ? await host.queryForSession(payload, assert) : null;
    queryFence(assert, ticket, host, state);
    if (!value || value.status === 'unknown') throw failure('NOT_FOUND');
    if (value.operationId !== payload.operationId) throw failure('OPERATION_ID_MISMATCH');
    const local = host.status();
    const active = local.operationId === payload.operationId && local.sessionId === payload.sessionId && local.bound === true;
    const stageOwned = value.bindingStageOperationId === payload.operationId && BINDING_STAGES.has(value.bindingStage);
    const result = Object.freeze({ ...value, localReady: active && local.localReady === true && value.localReady === true,
      dispatchReady: active && local.dispatchReady === true && value.dispatchReady === true && value.status === 'confirmed',
      bindingStage: stageOwned ? value.bindingStage : null,
      bindingStageOperationId: stageOwned ? payload.operationId : null,
      resourceErrorCode: value.resourceErrorCode ?? null,
      rootCause: value.rootCause ?? null });
    queryFence(assert, ticket, host, state);
    return result;
  }
  function captureOwnerData(sessionId, assert) {
    assertOpen(assert);
    if (phase !== 'running' || !binding || !provider || typeof sessionId !== 'string' || !SESSION.test(sessionId)) throw failure('NOT_FOUND');
    const local = binding.status();
    if (local.bound !== true || local.sessionId !== sessionId) throw failure('NOT_FOUND');
    const current = context();
    return { lifecycle, host: binding, source: provider, sessionId, operationId: local.operationId,
      localReady: local.localReady === true, authorityVersion: current.authorityVersion,
      contextLocalReady: current.localReady === true, peerReady: current.peerReady === true,
      scope: current.scope ? Object.freeze(Object.fromEntries(SCOPE_KEYS.map(key => [key, current.scope[key]]))) : null };
  }
  function checkOwnerData(captured, assert) {
    assertOpen(assert);
    if (phase !== 'running' || captured.lifecycle !== lifecycle || captured.host !== binding || captured.source !== provider) throw failure('AGENT_OWNER_ACTION_RETIRED');
    const local = binding.status(), current = context();
    if (local.bound !== true || local.sessionId !== captured.sessionId || local.operationId !== captured.operationId
      || (local.localReady === true) !== captured.localReady || current.authorityVersion !== captured.authorityVersion
      || (current.localReady === true) !== captured.contextLocalReady || (current.peerReady === true) !== captured.peerReady
      || !sameScope(captured.scope, current.scope ?? null)) throw failure('AGENT_OWNER_ACTION_RETIRED');
  }
  async function ownerDataAction(action, payload, assert) {
    const captured = captureOwnerData(payload.sessionId, assert);
    const guard = () => { try { checkOwnerData(captured, assert); return true; } catch { return false; } };
    const mutation = action !== 'history' && action !== 'replyPolicy';
    if (mutation && payload.confirm !== true) throw failure('INVALID_INPUT');
    if (mutation && (!captured.scope || !captured.localReady || !captured.contextLocalReady || !captured.peerReady)) throw failure('NOT_FOUND');
    let result;
    try {
      checkOwnerData(captured, assert);
      if (action === 'history') result = await captured.source.history({ beforeSeq: payload.beforeSeq, limit: payload.limit });
      else if (action === 'replyPolicy') result = await captured.source.replyPolicySnapshot();
      else if (action === 'setReplyPolicy') {
        // Optimistic identity check, not authority: an old panel cannot trust a newly paired device.
        if (payload.pairingId !== captured.scope.pairingId) throw failure('NOT_FOUND');
        result = await captured.source.setReplyPolicy({ mode: payload.mode, expectedRevision: payload.expectedRevision,
          expectedSessionId: captured.sessionId }, guard);
      } else if (action === 'clearHistory') {
        // Clearing is a scoped view mutation, never permission to remove task/transport evidence.
        if (payload.pairingId !== captured.scope.pairingId) throw failure('NOT_FOUND');
        result = await captured.source.clearHistory({ throughSeq: payload.throughSeq,
          expectedSessionId: captured.sessionId }, guard);
      } else {
        const value = { messageId: payload.messageId, expectedRevision: payload.expectedRevision };
        // approveReply itself sends this original ID once. Never add a second retry here.
        result = action === 'approveReply' ? await captured.source.approveReply(value, guard) : await captured.source.denyReply(value, guard);
      }
      checkOwnerData(captured, assert);
    } catch (error) { checkOwnerData(captured, assert); throw error; }
    const field = action === 'history' ? 'history' : action === 'replyPolicy' || action === 'setReplyPolicy' ? 'replyPolicy' : 'operation';
    return { ...snapshot(captured.sessionId, undefined, undefined, guard), [field]: result };
  }
  async function ownerAction(action, payload, assert, bindSignal) {
    assertOpen(assert);
    if (OWNER_DATA_ACTIONS.has(action)) return ownerDataAction(action, payload, assert);
    if (action === 'status') return snapshot(payload.sessionId, undefined, undefined, assert);
    if (action === 'start') { await start(assert); assertOpen(assert); return snapshot(payload.sessionId, undefined, undefined, assert); }
    if (action === 'stop') { const result = await stopInternal(); check(assert); return result; }
    if (action === 'query') {
      const ticket = lifecycle, host = binding, state = phase;
      const value = await query(payload, assert); queryFence(assert, ticket, host, state);
      return { ...snapshot(payload.sessionId, payload.operationId, value, assert), operation: value };
    }
    if (action === 'bind') { await start(assert); assertOpen(assert); }
    if (phase !== 'running' || !provider || !binding || !peer) throw failure('AGENT_NOT_STARTED');
    let value;
    if (action === 'bind') {
      if (!UUID.test(payload.operationId ?? '')) throw failure('INVALID_INPUT');
      bindingOperationId = payload.operationId;
      const ticket = lifecycle, host = binding, state = phase;
      const accepted = await host.bind({ sessionId: payload.sessionId, operationId: payload.operationId }, assert, bindSignal);
      queryFence(assert, ticket, host, state);
      const current = await query({ sessionId: payload.sessionId, operationId: payload.operationId }, assert);
      queryFence(assert, ticket, host, state);
      value = { ...current, changed: accepted.changed === true };
    }
    else if (action === 'invite') value = await peer.createInvitation({ ttlMs: 120000 }, assert);
    else if (action === 'connect') value = await peer.connectInvitation({ invitation: payload.invitation, host: payload.host, port: payload.port }, assert);
    else if (action === 'updateEndpoint') value = await peer.updateEndpoint({ pairingId: payload.pairingId, host: payload.host, port: payload.port }, assert, bindSignal);
    else if (action === 'approve') value = await peer.approvePairing({ pairingId: payload.pairingId }, assert);
    else if (action === 'reject') value = await peer.rejectPairing({ pairingId: payload.pairingId }, assert);
    else if (action === 'forget') value = await peer.forgetPairing({ pairingId: payload.pairingId }, assert);
    else throw failure('INVALID_INPUT');
    assertOpen(assert);
    const view = snapshot(payload.sessionId, action === 'bind' ? payload.operationId : undefined, action === 'bind' ? value : undefined, assert);
    return action === 'invite' ? { ...view, invitation: value } : { ...view, operation: value };
  }
  return Object.freeze({ snapshot, start, ownerAction,
    async bind(payload, assert, signal) { return ownerAction('bind', payload, assert, signal); }, query,
    dispose() {
      if (disposePromise) return disposePromise;
      if (stopping) { closed = true; disposePromise = stopping; return disposePromise; }
      preserveBindingCause();
      let barrier;
      try { barrier = beginRuntimeBarrier(runtime ?? undefined, 'controller-stop'); }
      catch (error) {
        failures.capture(error, { stage: 'ownership-barrier', origin: 'ownership', lifecycle: 'stop' });
        failRuntimeBarrier(runtime ?? undefined, null, error, 'ownership-barrier');
        closed = true; phase = 'failed'; errorCode = 'AGENT_DRAIN_FAILED';
        disposePromise = Promise.reject(failedDrain(['ownership-barrier'])); disposePromise.catch(() => {}); return disposePromise;
      }
      closed = true; disposePromise = stopInternal(barrier); return disposePromise;
    } });
}

const ACTION_KEYS = Object.freeze({ status: [], start: ['confirm'], stop: ['confirm'], bind: ['confirm', 'operationId'],
  query: ['operationId'], invite: ['confirm'], connect: ['confirm', 'invitation', 'host', 'port'], updateEndpoint: ['pairingId', 'host', 'port', 'confirm'],
  approve: ['confirm', 'pairingId'], reject: ['confirm', 'pairingId'], forget: ['confirm', 'pairingId'],
  history: ['beforeSeq', 'limit'], replyPolicy: [], setReplyPolicy: ['confirm', 'mode', 'expectedRevision', 'pairingId'],
  approveReply: ['confirm', 'messageId', 'expectedRevision'], denyReply: ['confirm', 'messageId', 'expectedRevision'],
  clearHistory: ['confirm', 'throughSeq', 'pairingId'] });
export function createAgentOnlyRpcHandler(ctx, connection, controller, resolveContext) {
  const owner = peer => peer?.principal?.kind === 'owner' && peer === connection.browserPeer && connection.allowsRemoteAuthorities !== true;
  return async (method, request, signal, peer) => {
    try {
      if (!owner(peer)) throw failure('FORBIDDEN');
      if (method !== 'agent') throw failure('NOT_FOUND');
      record(request, ['action', 'payload']);
      const { action, payload: raw } = request;
      if (typeof action !== 'string' || !Object.hasOwn(ACTION_KEYS, action)) throw failure('INVALID_INPUT');
      const keys = ['sessionId', ...ACTION_KEYS[action]]; record(raw, keys);
      const payload = Object.freeze(Object.fromEntries(keys.map(key => [key, Object.getOwnPropertyDescriptor(raw, key).value])));
      if (typeof payload.sessionId !== 'string' || !SESSION.test(payload.sessionId) || (Object.hasOwn(payload, 'confirm') && payload.confirm !== true)
        || (Object.hasOwn(payload, 'operationId') && (typeof payload.operationId !== 'string' || !UUID.test(payload.operationId)))
        || (Object.hasOwn(payload, 'pairingId') && (typeof payload.pairingId !== 'string' || !UUID.test(payload.pairingId)))
        || (action === 'history' && ((payload.beforeSeq !== null && (!Number.isSafeInteger(payload.beforeSeq) || payload.beforeSeq < 1))
          || !Number.isSafeInteger(payload.limit) || payload.limit < 1 || payload.limit > 50))
        || (Object.hasOwn(payload, 'throughSeq') && (!Number.isSafeInteger(payload.throughSeq) || payload.throughSeq < 0))
        || (Object.hasOwn(payload, 'expectedRevision') && (!Number.isSafeInteger(payload.expectedRevision) || payload.expectedRevision < 0))
        || (action === 'setReplyPolicy' && !['ask', 'trusted', 'deny'].includes(payload.mode))
        || (Object.hasOwn(payload, 'messageId') && (typeof payload.messageId !== 'string' || !MESSAGE_ID.test(payload.messageId)))
        || (['connect', 'updateEndpoint'].includes(action) && (typeof payload.host !== 'string' || payload.host.length > 253 || !payload.host.length
          || /[\s/\\@?#\x00]/u.test(payload.host) || !Number.isSafeInteger(payload.port) || payload.port < 1 || payload.port > 65535))
        || (action === 'connect' && (typeof payload.invitation !== 'string' || Buffer.byteLength(payload.invitation) > 8192))) throw failure('INVALID_INPUT');
      const binding = action === 'bind';
      // Cancellation ends this wait, not the live owner/Agent/Session authority.
      // The Host separately owns this bind's AbortSignal and true retirement.
      const current = () => owner(peer) && (binding || !signal?.aborted);
      if (signal?.aborted) throw failure('INVALID_CONTEXT');
      const observation = ['status', 'query', 'history', 'replyPolicy'].includes(action);
      const valid = await resolveContext(ctx, payload.sessionId, { ...(binding ? {} : { signal }), observation, assertCurrent: current });
      const assert = () => current() && valid(); check(assert);
      if (signal?.aborted) throw failure('INVALID_CONTEXT');
      const value = await controller.ownerAction(action, payload, assert, binding || action === 'updateEndpoint' ? signal : undefined); check(assert);
      if (signal?.aborted) throw failure('INVALID_CONTEXT');
      return { ok: true, value };
    } catch (error) {
      // Only an error branded after this invocation's authorization can carry
      // diagnostics. Invalid/auth/stale-scope failures never borrow a snapshot.
      const branded = getAgentFailureDetails(error), drain = drainFailureDetails.get(error);
      const details = branded ?? (drain ? { drain } : {});
      return { ok: false, error: { code: code(error), message: 'Agent操作未确认。', details } };
    }
  };
}

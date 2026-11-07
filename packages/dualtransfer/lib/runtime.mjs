import { randomUUID } from 'node:crypto';
import { normalizeConfig, configured } from './config.mjs';
import { CORE_SHA256, controlState, nonnegative } from './wire.mjs';
import { createStorage } from './storage.mjs';
import { verifySourceContract } from './source-contract.mjs';
import { openCore } from './vendor/core.mjs';
import { createTransportReader } from './vendor/reader.mjs';
import { createDshDispatcher } from './vendor/dsh-dispatcher.mjs';
import { createBoundTools } from './vendor/bound-tools.mjs';
const refuse = () => Object.assign(new Error('RUNTIME_NOT_READY'), { code: 'RUNTIME_NOT_READY' });
const READER_CODES = new Set(['READ_IO_FAILED', 'INVALID_PAGE', 'INVALID_PAGE_METADATA', 'INVALID_PAGE_MESSAGE',
  'INVALID_PAGE_SEQUENCE', 'PAGE_NO_PROGRESS', 'EPOCH_CHANGED', 'GLOBAL_TAIL_REGRESSION',
  'INGEST_FAILED', 'MESSAGE_ID_CONFLICT', 'CURSOR_PERSIST_FAILED', 'READER_BLOCKED']);
const STORAGE_CODES = new Set(['INVALID_DIRECTORY', 'BIND_REQUEST_REQUIRED', 'BIND_REQUEST_INVALID',
  'PRIVATE_STATE_CONFLICT', 'PRIVATE_STATE_IO', 'STATE_WRITE_FAILED', 'OWNER_LOCKED', 'CORRUPT_JOURNAL',
  'BINDING_MISMATCH', 'LOCK_FAILED', 'LOCK_WRITE_FAILED', 'STORAGE_OPEN_FAILED', 'STATE_READ_FAILED']);
const fixed = (error, fallback) => STORAGE_CODES.has(error?.code) || READER_CODES.has(error?.code) ? error.code : fallback;

/** Production lifecycle and ordinary I/O. Seams are in-process test dependencies,
 * NOT remote methods, peer parameters, model tools or alternative state machines. */
export function mountRuntime(ctx, input = {}, seams = {}) {
  const config = normalizeConfig(input);
  const expected = Object.freeze({ sessionId: config.sessionId, revision: config.revision });
  const clock = seams.clock ?? Date.now;
  const uuid = seams.uuid ?? randomUUID;
  const timers = seams.timers ?? { setTimeout, clearTimeout };
  const makeStorage = seams.createStorage ?? createStorage;
  const makeCore = seams.openCore ?? openCore;
  const makeReader = seams.createReader ?? createTransportReader;
  const makeBaseDispatcher = seams.createDispatcher ?? createDshDispatcher;
  const makeClient = seams.createLocalAgentClient;
  const stateEpoch = uuid();
  let closed = false, poisoned = false, bootstrapBlocked = false, originalAgent = null, current = null;
  let timer, pollPromise = null, shutdownPromise, disposalPromise, sourceContract = 'unknown', state = config.enabled ? 'starting' : 'disabled';
  let lastError = null, cleanupFailed = false;
  const retired = new Set(), effectDrains = new Set(), listenerDisposers = [];
  const now = () => { const value = clock(); if (!nonnegative(value)) throw refuse(); return value; };
  function live() {
    const agent = ctx.agents?.get(expected.sessionId);
    return agent && agent.id === expected.sessionId && agent.session?.id === expected.sessionId
      && ctx.sessions?.get(expected.sessionId) === agent.session ? agent : null;
  }
  function alive(r) {
    return !closed && !poisoned && !!r && !r.retired && current === r
      && live() === r.agent && originalAgent === r.agent;
  }
  function assertAlive(r) { if (!alive(r)) throw refuse(); }
  function canEnable(r) {
    return alive(r) && config.enabled && r.initialized && r.privateReady && r.toolsReady
      && r.storeValidated && !r.transportError && !r.fatalError && !r.publicFailed
      && r.reader?.status().phase === 'ready' && sourceContract === 'verified'
      && r.control.kind !== 'corrupt';
  }
  function effective(r) { return alive(r) && config.enabled && r.privateReady && r.control.effective === true; }
  const permitted = r => canEnable(r) && effective(r);
  function errorFor(r) {
    const code = r?.fatalError ?? (r?.transportError ? 'READ_IO_FAILED' : null)
      ?? (r?.publicFailed ? 'STATUS_WRITE_FAILED' : null)
      ?? (sourceContract === 'refused' ? 'SOURCE_CONTRACT_REFUSED' : null) ?? r?.control?.code ?? lastError;
    return code ? { code, at: r?.errorAt ?? now() } : null;
  }
  function snapshot(r = current) {
    const enabled = r?.control?.enabled === true, effectiveEnabled = effective(r), ready = canEnable(r);
    const core = r?.coreStatus ?? { phase: 'idle', queued: 0 };
    return Object.freeze({ schema: 1, adapterContract: 2, writtenAt: now(), hostPid: process.pid,
      coreSha256: CORE_SHA256, coreSchema: 1, stateEpoch,
      storeEpoch: r?.reader?.status().state?.epoch ?? null, globalTail: r?.globalTail ?? null,
      binding: { bound: r?.privateReady === true, id: r?.binding?.id ?? null,
        revision: r?.binding?.revision ?? null, label: 'Local Agent binding' },
      enabled, effectiveEnabled, canEnable: ready, dispatchReady: ready && effectiveEnabled, sourceContract,
      pending: { queued: core.queued, phase: core.phase, uncertain: core.phase === 'uncertain' },
      cooldownUntil: r?.cooldownUntil ?? null, lastPollAt: r?.lastPollAt ?? null, error: errorFor(r) });
  }
  function publish(r, final = false) {
    if (!r?.owner || (r.retired && !final)) return Promise.resolve();
    const operation = r.writeTail.then(async () => {
      if (!r.owner || (r.retired && !final)) return;
      try { await r.storage.writePublic(snapshot(r)); r.publicFailed = false; }
      catch { r.publicFailed = true; r.errorAt = now(); }
    });
    r.writeTail = operation.catch(() => {});
    return operation;
  }
  async function refreshControl(r) {
    if (!alive(r)) return false;
    let value;
    // Serialize actual control reads rather than letting a newer heartbeat's
    // sequence spuriously reject an older still-valid permission check.
    const read = r.controlTail.then(() => alive(r) ? r.storage.readControl() : null);
    r.controlTail = read.then(() => undefined, () => undefined);
    r.controlReads.add(read);
    try { value = controlState(await read, r.binding, now()); }
    catch { value = Object.freeze({ kind: 'corrupt', enabled: false, effective: false, code: 'CONTROL_INVALID' }); }
    finally { r.controlReads.delete(read); }
    if (!alive(r)) return false;
    r.control = value;
    if (value.code) r.errorAt = now();
    return permitted(r);
  }
  async function freshGate(r, exec = null) {
    if (exec?.signal?.aborted || (exec && exec.agent !== r.agent)) return false;
    const accepted = await refreshControl(r);
    return accepted && !exec?.signal?.aborted && (!exec || exec.agent === r.agent) && permitted(r);
  }
  function gateDispatcher(r) {
    const base = makeBaseDispatcher({ ctx, binding: expected, createUserMessage: seams.createUserMessage,
      isEnabled: () => permitted(r) });
    const wrap = name => args => {
      const operation = (async () => {
        if (!await freshGate(r)) throw refuse();
        const value = await base[name](args);
        if (!await freshGate(r)) throw refuse();
        return value;
      })();
      // Core's deadline may win without cancelling native persistence. Its late
      // promise must still be joined before releasing this instance's owner.
      r.nativeCalls.add(operation);
      operation.then(() => r.nativeCalls.delete(operation), () => r.nativeCalls.delete(operation));
      return operation;
    };
    return Object.freeze({ resolve: wrap('resolve'), followup: wrap('followup'), flush: wrap('flush'),
      close() { base.close(); } });
  }
  function ownTool(r, execute) {
    return async (args, exec) => {
      const operation = (async () => {
        if (!await freshGate(r, exec)) throw refuse();
        const result = await execute(args, exec);
        // Includes the second signal/exact-runtime check AFTER control-file await.
        // Refusal suppresses a result; it cannot undo a complete already committed.
        if (!await freshGate(r, exec)) throw refuse();
        return result;
      })();
      r.toolCalls.add(operation);
      operation.then(() => r.toolCalls.delete(operation), () => r.toolCalls.delete(operation));
      return operation;
    };
  }
  function installTools(r) {
    const definitions = createBoundTools({ ctx, binding: expected, core: r.core,
      isBindingCurrent: () => alive(r), isEnabled: () => permitted(r) });
    let started = false, failure;
    try {
      r.scopeDisposer = r.agent.ctx.effect(function* () {
        started = true;
        try {
          for (const definition of definitions) {
            assertAlive(r);
            const disposer = r.agent.ctx.tools.register(seams.defineTool({ ...definition,
              execute: ownTool(r, definition.execute) }));
            r.toolDisposers.push(disposer); yield disposer;
          }
          r.toolsReady = true;
        } catch (error) { failure = error; }
        yield () => retire(r, 'binding-stale', !closed, true);
        if (failure) throw failure;
      }, 'dualtransfer-runtime-bound-tools');
    } catch (error) {
      if (!started) void retire(r, 'tool-initialization-failed');
      throw error;
    }
  }
  async function readPage(r, args) {
    assertAlive(r);
    if (!r.client) r.client = makeClient({ agentClientConfigPath: config.agentClientConfigPath });
    const client = r.client;
    try {
      const page = await client.readPage(args, { signal: r.abort.signal });
      assertAlive(r);
      r.pageMeta = { epoch: page?.epoch, globalTail: page?.globalTail };
      return page;
    } catch {
      r.transportError = true; r.errorAt = now();
      // A public deadline is not a resource-drain guarantee. Never stack another
      // request behind an unresolved old FS operation; heartbeat remains separate.
      r.clientDrain = Promise.resolve(client.close());
      await r.clientDrain;
      if (r.client === client) r.client = null;
      throw Object.assign(new Error('READ_IO_FAILED'), { code: 'READ_IO_FAILED' });
    }
  }
  function markPage(r) {
    assertAlive(r);
    r.lastPollAt = now(); r.storeValidated = true; r.transportError = false;
    r.globalTail = r.pageMeta?.globalTail ?? r.reader.status().state?.cursor ?? null;
  }
  async function coreStatus(r) {
    const value = await r.core.status();
    if (alive(r)) r.coreStatus = value;
    return value;
  }
  function retire(r, reason, stale = false, fromScope = false) {
    if (stale) poisoned = true;
    if (!r) return Promise.resolve();
    if (!r.retired) {
      r.retired = true; r.toolsReady = false;
      if (timer !== undefined && timer !== null) { timers.clearTimeout(timer); timer = null; }
      state = closed ? 'stopped' : reason;
      try { r.dispatcher?.close(); } catch { cleanupFailed = true; }
      r.abort.abort();
      try { r.readerClose = r.reader?.close(); } catch { cleanupFailed = true; }
      try { r.clientDrain = r.client?.close() ?? r.clientDrain; } catch { cleanupFailed = true; }
    }
    if (!r.cleanupPromise) {
      r.cleanupPromise = (async () => {
        // The currently awaited open/bootstrap may still produce an owned Core.
        await r.bootstrapDone;
        const resources = await Promise.allSettled([r.readerClose, r.clientDrain]);
        if (resources.some(result => result.status === 'rejected')) cleanupFailed = true;
        // A cancelled tool/dispatch operation may reject normally after the synchronous gate closed.
        await Promise.allSettled([r.dispatchPromise, ...r.toolCalls]);
        while (r.nativeCalls.size || r.controlReads.size) {
          await Promise.allSettled([...r.nativeCalls, ...r.controlReads]);
        }
        for (const dispose of [...r.toolDisposers].reverse()) {
          try { await dispose(); } catch { cleanupFailed = true; }
        }
        await publish(r, true); await r.writeTail;
        try { r.storage.close(); } catch { cleanupFailed = true; }
        r.owner = false;
        try { await r.core?.close(); } catch { cleanupFailed = true; }
      })().finally(() => { retired.delete(r.cleanupPromise); });
      retired.add(r.cleanupPromise);
    }
    if (!fromScope && r.scopeDisposer) {
      const dispose = r.scopeDisposer; r.scopeDisposer = null;
      try {
        const drain = Promise.resolve(dispose()).catch(() => { cleanupFailed = true; }).finally(() => effectDrains.delete(drain));
        effectDrains.add(drain);
      } catch { cleanupFailed = true; }
    }
    return r.cleanupPromise;
  }
  async function bootstrap() {
    if (closed || poisoned || bootstrapBlocked || !config.enabled || current) return current;
    if (!configured(config)) { state = 'not-configured'; lastError = 'INVALID_LOCAL_CONFIGURATION'; return null; }
    const agent = live();
    if (!agent || (originalAgent && originalAgent !== agent)) {
      if (originalAgent) poisoned = true;
      state = 'not-live'; return null;
    }
    if (typeof agent.ctx?.effect !== 'function' || typeof agent.ctx?.tools?.register !== 'function'
        || typeof seams.defineTool !== 'function' || typeof makeClient !== 'function'
        || typeof ctx.sessionController?.resolveAgent !== 'function' || typeof ctx.sessions?.flush !== 'function') {
      state = 'formal-services-unavailable'; lastError = 'FORMAL_SERVICES_UNAVAILABLE'; return null;
    }
    originalAgent ??= agent;
    if (sourceContract === 'unknown') sourceContract = verifySourceContract(seams);
    if (sourceContract !== 'verified') {
      state = 'source-contract-refused'; lastError = 'SOURCE_CONTRACT_REFUSED'; return null;
    }
    const storage = makeStorage({ directory: config.dataDirectory });
    let before;
    try { before = await storage.preflight(expected, now()); }
    catch (error) { bootstrapBlocked = true; lastError = fixed(error, 'PRIVATE_STATE_CONFLICT'); state = 'manual-conflict'; return null; }
    if (closed || poisoned || live() !== agent) { storage.close(); return null; }
    if (before.kind === 'unbound') { storage.close(); state = 'unbound'; lastError = 'BIND_REQUEST_REQUIRED'; return null; }
    let finishBootstrap;
    const r = { agent, storage, binding: before.binding ?? null, core: null, reader: null, client: null,
      abort: new AbortController(), retired: false, owner: false, initialized: false, privateReady: false,
      toolsReady: false, storeValidated: false, transportError: false, fatalError: null, publicFailed: false,
      control: controlState(null, null, now()), controlTail: Promise.resolve(), toolDisposers: [], toolCalls: new Set(),
      nativeCalls: new Set(), controlReads: new Set(),
      writeTail: Promise.resolve(), bootstrapDone: new Promise(resolve => { finishBootstrap = resolve; }) };
    current = r; state = 'opening'; lastError = null;
    try {
      r.dispatcher = gateDispatcher(r);
      r.core = await makeCore({ directory: config.dataDirectory, binding: expected,
        dispatcher: r.dispatcher, isEnabled: () => freshGate(r) });
      r.owner = true; storage.setOwner(true); assertAlive(r);
      await storage.verifyOwned(before, expected, now()); assertAlive(r);
      r.binding = before.kind === 'fresh' ? await storage.prepare(before, expected, now()) : before.binding;
      assertAlive(r);
      r.reader = makeReader({ binding: { bindingId: r.binding.id, bindingRevision: r.binding.revision },
        initial: before.kind === 'fresh' ? null : before.cursor,
        readPage: args => readPage(r, args), core: r.core,
        persistCursor: value => { assertAlive(r); return storage.persistCursor(value, r.binding); } });
      installTools(r);
      if (before.kind === 'fresh') {
        await r.reader.firstBind({ firstBind: true }); assertAlive(r);
        r.binding = await storage.commitBinding(r.binding); assertAlive(r);
        markPage(r);
      }
      r.privateReady = true; r.initialized = true;
      await refreshControl(r);
      // Resume validates the live epoch even with UI off; no historical barrier.
      if (before.kind === 'resume') {
        try { await r.reader.pump(); markPage(r); }
        catch (error) {
          if (error?.code !== 'READ_IO_FAILED' || error.retryable !== true) r.fatalError = fixed(error, 'READER_BLOCKED');
          r.errorAt = now();
        }
      }
      await coreStatus(r); state = r.fatalError ? 'manual-conflict' : 'running';
      await publish(r);
    } catch (error) {
      bootstrapBlocked = true; r.fatalError = fixed(error, 'INITIALIZATION_FAILED'); r.errorAt = now();
      void retire(r, 'manual-conflict');
    } finally { finishBootstrap(); }
    return r;
  }
  function dispatch(r) {
    if (r.dispatchPromise || !permitted(r)) return;
    r.dispatchPromise = (async () => {
      if (!await freshGate(r)) return;
      const result = await r.core.dispatchNext();
      if (result.outcome === 'cooldown' && nonnegative(result.retryAfterMs)) r.cooldownUntil = now() + result.retryAfterMs;
      else r.cooldownUntil = null;
      await coreStatus(r); await publish(r);
    })().catch(() => { if (alive(r)) { r.fatalError = 'CORE_OPERATION_FAILED'; r.errorAt = now(); } })
      .finally(() => { r.dispatchPromise = null; });
  }
  function poll() {
    if (pollPromise) return pollPromise;
    if (closed || poisoned || bootstrapBlocked || !config.enabled) return Promise.resolve();
    const operation = (async () => {
      const r = current ?? await bootstrap();
      if (!alive(r) || !r.initialized) return;
      await refreshControl(r);
      if (!r.fatalError && r.reader.status().phase === 'ready') {
        try { await r.reader.pump(); markPage(r); }
        catch (error) {
          if (error?.code !== 'READ_IO_FAILED' || error.retryable !== true) r.fatalError = fixed(error, 'READER_BLOCKED');
          r.errorAt = now();
        }
      }
      if (!alive(r)) return;
      const status = await coreStatus(r);
      if (!r.dispatchPromise && permitted(r) && ((status.phase === 'idle' && status.queued > 0) || status.phase === 'pending')) dispatch(r);
      await publish(r);
    })().catch(async error => {
      lastError = fixed(error, 'RUNTIME_IO_FAILED');
      if (alive(current)) { current.fatalError = lastError; current.errorAt = now(); await publish(current); }
    });
    pollPromise = operation.finally(() => { pollPromise = null; });
    return pollPromise;
  }
  async function heartbeat() {
    const r = current;
    if (closed || !alive(r) || !r.owner) return;
    await refreshControl(r); await publish(r);
  }
  function schedule() {
    if (closed || poisoned || !config.enabled || seams.autoStart === false) return;
    timer = timers.setTimeout(() => {
      timer = null; schedule(); void poll(); void heartbeat();
    }, 5000);
  }
  function shutdown() {
    if (shutdownPromise) return shutdownPromise;
    closed = true; state = 'stopped';
    if (timer !== undefined && timer !== null) { timers.clearTimeout(timer); timer = null; }
    const listenerCleanup = listenerDisposers.splice(0).map(dispose => {
      try { return dispose(); } catch { cleanupFailed = true; return undefined; }
    });
    const cleanup = retire(current, 'stopped');
    shutdownPromise = (async () => {
      const drains = await Promise.allSettled([pollPromise, cleanup, ...listenerCleanup]);
      if (drains.some(result => result.status === 'rejected')) cleanupFailed = true;
      while (retired.size || effectDrains.size) {
        const pending = await Promise.allSettled([...retired, ...effectDrains]);
        if (pending.some(result => result.status === 'rejected')) cleanupFailed = true;
      }
      // Failure to prove release is a failed owner barrier, never permission to mount another Core.
      if (cleanupFailed) throw Object.assign(new Error('RUNTIME_DRAIN_FAILED'), { code: 'RUNTIME_DRAIN_FAILED' });
    })();
    return shutdownPromise;
  }
  const scopeDispose = ctx.effect(function* () {
    const created = ctx.on('agent/created', payload => {
      const { agent, signal } = payload ?? {};
      if (closed || signal?.aborted || !agent || agent.id !== expected.sessionId || live() !== agent) return;
      if (originalAgent && originalAgent !== agent) { poisoned = true; return retire(current, 'binding-stale', true); }
      return poll();
    });
    listenerDisposers.push(created); yield created;
    const disposed = ctx.on('agent/disposed', payload => {
      const { agent } = payload ?? {};
      if (agent && agent === originalAgent) { poisoned = true; return retire(current, 'binding-stale', true); }
    });
    listenerDisposers.push(disposed); yield disposed;
    yield shutdown;
  }, 'dualtransfer-agent-runtime');
  if (config.enabled && seams.autoStart !== false) { schedule(); void poll(); }
  return Object.freeze({ status: () => snapshot(), tick: poll, heartbeat,
    async idle() {
      await pollPromise;
      const r = current;
      if (r?.dispatchPromise) await r.dispatchPromise;
      if (r) await r.writeTail;
    },
    dispose() {
      if (disposalPromise) return disposalPromise;
      const done = shutdown(); let effectDrain;
      try { effectDrain = scopeDispose(); } catch (error) { cleanupFailed = true; effectDrain = Promise.reject(error); }
      disposalPromise = Promise.all([done, effectDrain]).then(() => {
        if (cleanupFailed) throw Object.assign(new Error('RUNTIME_DRAIN_FAILED'), { code: 'RUNTIME_DRAIN_FAILED' });
      });
      return disposalPromise;
    },
    diagnostics: () => Object.freeze({ state, cleanupFailed }) });
}

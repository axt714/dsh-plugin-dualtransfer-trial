import path from 'node:path';
import { userInfo } from 'node:os';
import { randomUUID } from 'node:crypto';
import { normalizeConfig, sameTuple } from './config.mjs';
import { mountRuntime } from './runtime.mjs';
import { exclusiveFile, failure } from './private-fs.mjs';
const PRODUCT = Symbol.for('dsh.dualtransfer.product-owner.v1');
const LEGACY = new Set(['dualtransfer-bind', 'dualtransfer-agent-wake-runtime', '@local/dualtransfer-bind', '@local/dualtransfer-agent-wake-runtime']);
export function reserveProduct(ctx) {
  const token = {};
  if (globalThis[PRODUCT]) throw failure('PRODUCT_ALREADY_ACTIVE');
  for (const runtime of ctx.registry.values()) {
    if (LEGACY.has(runtime.name) && [...runtime.fibers].some(fiber => fiber.uid !== null)) throw failure('LEGACY_PLUGIN_ACTIVE');
  }
  globalThis[PRODUCT] = token;
  return () => { if (globalThis[PRODUCT] === token) delete globalThis[PRODUCT]; };
}
export function rejectLegacyFiber(fiber) {
  if (fiber.uid !== null && LEGACY.has(fiber.runtime?.name)) throw failure('LEGACY_PLUGIN_EXCLUDED');
}
export function fixedProductLeasePath() {
  // OS account database, not profilesRoot, runtime root, appDirectory, or HOME override.
  return path.join(userInfo().homedir, '.dsh', 'dualtransfer-product', 'owner.lock');
}
export function createSupervisor(ctx, { mount = mountRuntime, runtimeSeams = {}, leasePath = fixedProductLeasePath(), acquireLease = exclusiveFile } = {}) {
  let desired = normalizeConfig(), generation = 0, closed = false, runtime = null, mounted = null;
  let tail = Promise.resolve(), draining = null, releaseLease = null, errorCode = null;
  let disposal = null, disposeDrained = false;
  const listeners = new Set();
  function notify() { for (const fn of listeners) { try { fn(); } catch {} } }
  function authorize() {
    if (closed) throw failure('SUPERVISOR_CLOSED');
    if (!releaseLease) releaseLease = acquireLease(leasePath, { schema: 1, product: 'dsh-plugin-dualtransfer', pid: process.pid, nonce: randomUUID() });
  }
  function retire() {
    if (!runtime) return;
    const old = runtime; runtime = null; mounted = null;
    // dispose closes all gates and aborts continuations synchronously, before returning its drain promise.
    let result;
    try { result = old.dispose(); } catch (error) { result = Promise.reject(error); }
    // A failed retirement remains a failed barrier; never mount another Core behind it.
    draining = Promise.resolve(result); notify();
  }
  function enqueue() {
    const requested = generation;
    tail = tail.then(async () => {
      if (draining) { const drain = draining; await drain; if (draining === drain) draining = null; }
      if (closed || requested !== generation) return;
      if (!desired.enabled) return;
      authorize();
      const target = desired;
      const next = mount(ctx, target, runtimeSeams);
      if (closed || requested !== generation) {
        // A reentrant update/dispose during mount must retain this failed drain,
        // even when enqueue's reporting catch fulfills its own tail.
        let drain;
        try { drain = Promise.resolve(next.dispose()); } catch (error) { drain = Promise.reject(error); }
        draining = drain;
        await drain;
        if (draining === drain) draining = null;
        return;
      }
      runtime = next; mounted = target; errorCode = null; notify();
    }).catch(() => { errorCode = 'RUNTIME_SUPERVISOR_FAILED'; notify(); });
    return tail;
  }
  function update(input, { force = false } = {}) {
    if (closed) return tail;
    const next = normalizeConfig(input);
    if (!force && sameTuple(next, desired)) return tail;
    desired = next; generation += 1;
    retire(); return enqueue();
  }
  return Object.freeze({
    update, authorize,
    activate(target, previousEpoch) {
      if (!sameTuple(desired, target) || !desired.enabled || closed) return false;
      if (!runtime || runtime.status().stateEpoch === previousEpoch) update(target, { force: true });
      return true;
    },
    currentEpoch(target) { return !closed && runtime && sameTuple(mounted, target) ? runtime.status().stateEpoch : null; },
    isCurrent(target, epoch) { return !!epoch && this.currentEpoch(target) === epoch; },
    subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
    async idle() { await tail; if (runtime) await runtime.idle(); },
    async pulse() { if (runtime) { await runtime.heartbeat(); await runtime.idle(); } },
    status: () => ({ closed, generation, errorCode, mounted: !!runtime }),
    dispose() {
      if (!closed) { closed = true; generation += 1; retire(); }
      if (disposal) return disposal;
      // Only a completed drain permits retrying the same owned release. A failed
      // drain remains a failed barrier; never reopen gates or mount another Core.
      const prerequisite = disposeDrained ? Promise.resolve() : tail;
      const attempt = prerequisite.then(async () => {
        if (!disposeDrained) {
          if (draining) { await draining; draining = null; }
          disposeDrained = true;
        }
        if (releaseLease) { releaseLease(); releaseLease = null; }
        listeners.clear();
      });
      disposal = attempt; tail = attempt;
      const finished = () => { if (disposal === attempt) disposal = null; };
      attempt.then(finished, finished);
      return attempt;
    },
  });
}

import z from '@deepseek-ai/schemastery';
import { randomUUID } from 'node:crypto';
import { types } from 'node:util';
import { defineTool } from '@deepseek-ai/dsh-tools';
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import { Session, SessionId } from '@deepseek-ai/dsh-session';
import { createConfigSchema } from './config.mjs';
import { createAgentOnlyController, createAgentOnlyRpcHandler } from './agent-plugin.mjs';
import { failure } from './private-fs.mjs';
const SESSION = /^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/u;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/u;
const PRODUCT = Symbol.for('dsh.dualtransfer.product-owner.v1');
const LEGACY = new Set(['dualtransfer-bind', 'dualtransfer-agent-wake-runtime', '@local/dualtransfer-bind', '@local/dualtransfer-agent-wake-runtime']);
// Registration exclusion is process-only; this does not acquire or repair the old product's disk lease.
function reserveEntry(ctx) {
  if (globalThis[PRODUCT]) throw failure('PRODUCT_ALREADY_ACTIVE');
  for (const runtime of ctx.registry.values()) {
    if (LEGACY.has(runtime.name) && [...runtime.fibers].some(fiber => fiber.uid !== null)) throw failure('LEGACY_PLUGIN_ACTIVE');
  }
  const owner = {}; globalThis[PRODUCT] = owner;
  return () => { if (globalThis[PRODUCT] === owner) delete globalThis[PRODUCT]; };
}
function rejectLegacy(fiber) {
  if (fiber.uid !== null && LEGACY.has(fiber.runtime?.name)) throw failure('LEGACY_PLUGIN_EXCLUDED');
}
export const name = 'dsh-plugin-dualtransfer';
export const inject = ['tools', 'agents', 'sessions', 'sessionController', 'profileContext'];
export const Config = createConfigSchema(z);
export const RPC_CHANNEL = '/dualtransfer-rpc';
function liveAgent(ctx, sessionId) {
  const agent = ctx.agents.get(sessionId);
  return agent?.id === sessionId && agent.session?.id === sessionId && ctx.sessions.get(sessionId) === agent.session ? agent : null;
}
export async function resolveLocalContext(ctx, sessionId, { signal, expectedAgent, observation = false, assertCurrent } = {}) {
  const allowed = () => !signal?.aborted && (assertCurrent === undefined || assertCurrent() === true);
  if (typeof sessionId !== 'string' || !SESSION.test(sessionId) || !allowed()) throw failure('INVALID_CONTEXT');
  if (observation) {
    // Public SessionStore is live-only, not a persisted-session exists API. Never resume for a read.
    const session = ctx.sessions.get(sessionId);
    if (!session || session.id !== sessionId) throw failure('INVALID_CONTEXT');
    const valid = () => allowed() && ctx.sessions.get(sessionId) === session && session.id === sessionId;
    if (!valid()) throw failure('INVALID_CONTEXT');
    return valid;
  }
  const previous = liveAgent(ctx, sessionId);
  if ((expectedAgent && previous !== expectedAgent) || typeof ctx.sessionController?.resolveAgent !== 'function') throw failure('INVALID_CONTEXT');
  // Only an explicitly authorized action reaches this resolver. Cold sessions need not be live first.
  const resolved = await ctx.sessionController.resolveAgent(sessionId);
  const agent = liveAgent(ctx, sessionId), session = agent?.session;
  if (!agent || resolved?.agent !== agent || (previous && previous !== agent) || (expectedAgent && expectedAgent !== agent) || !allowed()) throw failure('INVALID_CONTEXT');
  const valid = () => allowed() && liveAgent(ctx, sessionId) === agent && agent.session === session;
  if (!valid()) throw failure('INVALID_CONTEXT');
  return valid;
}
const errorResult = error => ({ ok: false, error: { code: /^[A-Z][A-Z0-9_]{0,63}$(?![\s\S])/u.test(error?.code ?? '') ? error.code : 'OPERATION_FAILED', message: '操作未确认；请留在当前本机会话查询。', details: {} } });
function requestRecord(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value)
    || Reflect.ownKeys(value).length !== keys.length || keys.some(key => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key); return !descriptor || !Object.hasOwn(descriptor, 'value');
    })) throw failure('INVALID_INPUT');
  return Object.freeze(Object.fromEntries(keys.map(key => [key, Object.getOwnPropertyDescriptor(value, key).value])));
}
function validateRequest(request) {
  const { action, payload: raw } = requestRecord(request, ['action', 'payload']);
  if (!['check', 'start', 'query', 'cancel-wait'].includes(action)) throw failure('INVALID_INPUT');
  const keys = action === 'check' ? ['sessionId'] : action === 'start' ? ['confirm', 'operationId', 'sessionId'] : ['operationId', 'sessionId'];
  const payload = requestRecord(raw, keys);
  if (!SESSION.test(payload.sessionId ?? '') || (action === 'start' && payload.confirm !== true)
    || (action !== 'check' && !UUID_V4.test(payload.operationId ?? ''))) throw failure('INVALID_INPUT');
  return { action, payload };
}
export function createRpcHandler(ctx, connection, manager, isClosed = () => false) {
  const owner = peer => peer?.principal?.kind === 'owner' && peer === connection.browserPeer && connection.allowsRemoteAuthorities !== true;
  return async (method, request, signal, peer) => {
    try {
      if (!owner(peer)) throw failure('FORBIDDEN');
      if (method !== 'operation') throw failure('NOT_FOUND');
      const { action, payload } = validateRequest(request);
      const current = () => owner(peer) && !signal?.aborted && !isClosed();
      // A capability check is not an assertion that a persisted Session exists or an Agent is active.
      // In particular it must not resume a historical session, start collaboration or bind it.
      if (!current()) throw failure('INVALID_CONTEXT');
      const assert = action === 'check' ? current : await resolveLocalContext(ctx, payload.sessionId,
        { signal, assertCurrent: current, observation: action !== 'start' });
      if (!current() || !assert()) throw failure('INVALID_CONTEXT');
      const value = action === 'check' ? await manager.check(payload.sessionId)
        : action === 'start' ? await manager.start(payload.sessionId, payload.operationId, () => owner(peer) && assert())
        : action === 'query' ? await manager.query(payload.sessionId, payload.operationId, () => owner(peer) && assert())
        : await manager.cancelWait(payload.sessionId, payload.operationId, () => owner(peer) && assert());
      if (!owner(peer) || !assert()) throw failure('INVALID_CONTEXT');
      return { ok: true, value };
    } catch (error) { return errorResult(error); }
  };
}
function bindTool(ctx, manager) {
  return ctx.tools.register(defineTool({
    name: 'dualtransfer_bind_this_session',
    description: '仅当用户明确要求「绑到这条 / 就在这条对话里收」时，把双机传输绑定到当前本机会话。会保留旧状态；pending只是受理，只有正式Host确认后才能报告开启。不得自行调用。',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: {
      protocol: { type: 'string', const: 'operation-v1', required: true }, operationId: { type: 'string', required: true },
      status: { type: 'string', enum: ['pending', 'confirmed', 'unconfirmed', 'failed', 'cancelled', 'superseded'], required: true },
      phase: { type: 'string', enum: ['prepared', 'committing', 'awaiting-host', 'settled'], required: true },
      dispatchReady: { type: 'boolean', required: true }, changed: { type: 'boolean', required: true }, waitCancelled: { type: 'boolean', required: true },
      errorCode: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
      updatedAt: { type: 'integer', required: true }, expiresAt: { type: 'integer', required: true },
    } },
    render(_args, value) { return [{ type: 'text', text: value?.dispatchReady === true ? '正式Host已确认当前绑定开启。' : `操作${value?.operationId || ''}：${value?.status || 'unconfirmed'}；尚未确认开启。` }]; } },
    timeoutMs: 60000,
    async execute(args, exec) {
      if (args !== undefined && (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(args).length)) throw failure('INVALID_INPUT');
      const agent = exec?.agent;
      const assert = await resolveLocalContext(ctx, agent?.id, { signal: exec?.signal, expectedAgent: agent });
      if (!assert()) throw failure('INVALID_CONTEXT');
      return manager.start(agent.id, randomUUID(), assert);
    },
  }));
}
function compatibleOperation(value, operationId) {
  const r = value?.operation ?? value ?? {};
  if (r.operationId !== operationId) throw failure('OPERATION_ID_MISMATCH');
  const statuses = ['pending', 'confirmed', 'unconfirmed', 'failed', 'cancelled', 'superseded'];
  return { protocol: 'operation-v1', operationId,
    status: statuses.includes(r.status) ? r.status : 'unconfirmed',
    phase: ['prepared', 'committing', 'awaiting-host', 'settled'].includes(r.phase) ? r.phase : 'settled',
    dispatchReady: r.status === 'confirmed' && r.dispatchReady === true,
    changed: r.changed === true, waitCancelled: r.waitCancelled === true,
    errorCode: r.errorCode ?? null, updatedAt: Number.isSafeInteger(r.updatedAt) && r.updatedAt >= 0 ? r.updatedAt : 0,
    expiresAt: Number.isSafeInteger(r.expiresAt) && r.expiresAt >= 0 ? r.expiresAt : 0 };
}
// Shared by the installed entry and narrow in-memory Host/Session tests.
export function createAgentOperationManager(controller, isClosed = () => false) {
  const guard = assert => { if (isClosed() || typeof assert !== 'function' || assert() !== true) throw failure('INVALID_CONTEXT'); };
  return Object.freeze({
    check() { return { protocol: 'operation-v1', agentOnly: true, configurationRequired: false, observation: 'capability-only', sessionExistenceVerified: false }; },
    async start(sessionId, operationId, assert) {
      guard(assert); const value = await controller.bind({ sessionId, operationId }, assert);
      guard(assert); return compatibleOperation(value, operationId);
    },
    async query(sessionId, operationId, assert) {
      guard(assert); const value = await controller.query({ sessionId, operationId }, assert);
      guard(assert); return compatibleOperation(value, operationId);
    },
    async cancelWait(sessionId, operationId, assert) {
      guard(assert); const value = await controller.query({ sessionId, operationId }, assert);
      guard(assert); return { ...compatibleOperation(value, operationId), waitCancelled: true };
    },
  });
}
export function apply(ctx, _config) {
  // 0.2 never starts/adopts the old App client, supervisor, fixed product lease or configuration tuple.
  return ctx.effect(() => {
    const releaseEntry = reserveEntry(ctx);
    let controller;
    try { controller = createAgentOnlyController({ ctx, defineTool, createUserMessage, Session, SessionId }); }
    catch (error) { releaseEntry(); throw error; }
    const disposers = []; let closed = false;
    const manager = createAgentOperationManager(controller, () => closed);
    const retire = () => disposers.splice(0).reverse().map(registration => {
      try {
        if (typeof registration === 'function') return registration();
        if (typeof registration?.dispose === 'function' && typeof registration?.await === 'function') {
          registration.dispose(); return registration.await();
        }
        throw failure('REGISTRATION_DRAIN_FAILED');
      } catch (error) { return Promise.reject(error); }
    });
    try {
      disposers.push(ctx.on('internal/plugin', rejectLegacy));
      disposers.push(bindTool(ctx, manager));
      disposers.push(ctx.inject(['connection', 'webServer'], rpcCtx => {
        const connection = rpcCtx.connection; let prototype = connection, getter;
        while (prototype && !getter) { getter = Object.getOwnPropertyDescriptor(prototype, 'rpc')?.get; prototype = Object.getPrototypeOf(prototype); }
        if (!getter) throw failure('FORMAL_RPC_UNAVAILABLE');
        const rpc = getter.call(connection);
        const agent = createAgentOnlyRpcHandler(ctx, connection, controller, (ownerCtx, sessionId, options) => resolveLocalContext(ownerCtx, sessionId,
          { ...options, assertCurrent: () => !closed && (options.assertCurrent === undefined || options.assertCurrent() === true) }));
        const compatibility = createRpcHandler(ctx, connection, manager, () => closed);
        return rpc.handle(RPC_CHANNEL, async (method, ...args) => {
          if (method === 'agent') return agent(method, ...args);
          const reply = await compatibility(method, ...args);
          // A retained C4 operation must still switch the new renderer to the Agent-only panel.
          return reply.ok ? { ...reply, value: { ...reply.value, agentOnly: true } } : reply;
        });
      }));
    } catch (error) {
      closed = true; Promise.all([controller.dispose(), ...retire()]).then(releaseEntry, () => {}); throw error;
    }
    let disposal = null;
    return () => {
      // A second teardown must observe the same real outcome, never turn a failed drain into a no-op success.
      if (disposal) return disposal;
      closed = true;
      let drain; try { drain = controller.dispose(); } catch (error) { drain = Promise.reject(error); }
      disposal = Promise.allSettled([drain, ...retire()]).then(results => {
        const failed = results.find(result => result.status === 'rejected');
        if (failed) throw failed.reason;
        releaseEntry();
      });
      return disposal;
    };
  }, 'dualtransfer-agent-only-product');
}

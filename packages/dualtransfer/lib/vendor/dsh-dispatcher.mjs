// Work-copy adapter. It does not connect to, mutate, or install into a live Host.
// Runtime seams are injected so the exact formal calls can be tested offline.
export const SOURCE_KIND = 'dual-transfer-agent-notice';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function refusal(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

export function createDshDispatcher({ ctx, binding, createUserMessage, isEnabled = () => false }) {
  if (!ctx || !binding || typeof binding.sessionId !== 'string' || !binding.sessionId
      || !Number.isSafeInteger(binding.revision) || binding.revision < 1
      || typeof createUserMessage !== 'function' || typeof isEnabled !== 'function') {
    throw refusal('INVALID_ADAPTER_CONFIGURATION');
  }
  const expected = Object.freeze({ sessionId: binding.sessionId, revision: binding.revision });
  const targets = new WeakSet();
  const submissions = new WeakMap();
  const attempted = new Set();
  let closed = false;

  function gate(sessionId, revision) {
    if (closed || isEnabled() !== true) throw refusal('ADAPTER_PAUSED');
    if (sessionId !== expected.sessionId || revision !== expected.revision) {
      throw refusal('BINDING_MISMATCH');
    }
  }

  function liveAgent() {
    const agent = ctx.agents?.get(expected.sessionId);
    if (!agent || agent.id !== expected.sessionId
        || agent.session?.id !== expected.sessionId
        || ctx.sessions?.get(expected.sessionId) !== agent.session) {
      throw refusal('TARGET_NOT_LIVE');
    }
    return agent;
  }

  function targetAgent(target) {
    if (!target || typeof target !== 'object' || !targets.has(target)) {
      throw refusal('FOREIGN_TARGET_HANDLE');
    }
    const agent = liveAgent();
    if (target.agent !== agent) throw refusal('TARGET_LIFECYCLE_CHANGED');
    return agent;
  }

  return Object.freeze({
    async resolve({ sessionId, revision }) {
      gate(sessionId, revision);
      // resolveAgent can resume an unloaded session. Deliberately require the
      // same live registry object first, and reject any replacement after await.
      const before = liveAgent();
      if (typeof ctx.sessionController?.resolveAgent !== 'function') {
        throw refusal('FORMAL_RESOLVER_UNAVAILABLE');
      }
      const target = await ctx.sessionController.resolveAgent(sessionId);
      gate(sessionId, revision);
      if (!target || typeof target !== 'object' || 'error' in target) {
        // Do not forward arbitrary Host/provider error strings into durable logs.
        throw refusal('FORMAL_RESOLVE_REJECTED');
      }
      if (target.agent !== before || liveAgent() !== before) {
        throw refusal('TARGET_LIFECYCLE_CHANGED');
      }
      targets.add(target);
      return { sessionId, target };
    },

    async followup({ target, sessionId, revision, requestId, mode, nonhuman, prompt }) {
      gate(sessionId, revision);
      const agent = targetAgent(target);
      if (mode !== 'queue' || nonhuman !== true || !UUID.test(requestId)
          || typeof prompt !== 'string' || !prompt.trim() || prompt.length > 4096) {
        throw refusal('INVALID_NOTICE_CONTRACT');
      }
      if (attempted.has(requestId)) throw refusal('DUPLICATE_SUBMISSION_ATTEMPT');
      const message = createUserMessage({
        content: [{ type: 'text', text: prompt }],
        source: { kind: SOURCE_KIND, batchId: requestId, bindingRevision: revision },
      });
      if (message?.role !== 'user' || message.source?.kind !== SOURCE_KIND
          || message.source.batchId !== requestId || 'rpcId' in message.source
          || 'principal' in message.source || typeof agent.followup !== 'function') {
        throw refusal('INVALID_FORMAL_MESSAGE_FACTORY');
      }
      // Once attempted, never repeat automatically even if the Host throws.
      // The durable core owns uncertain outcomes and recovery decisions.
      attempted.add(requestId);
      gate(sessionId, revision);
      targetAgent(target);
      // Native followup has ONE argument and intrinsically queues next-turn.
      // Never call steer(), cancel(), prompt RPC, or send untrusted body text.
      agent.followup(message);
      const submission = Object.freeze({ requestId, messageId: message.id });
      submissions.set(submission, { target, requestId, flush: undefined });
      return submission;
    },

    async flush({ target, submission, requestId }) {
      gate(expected.sessionId, expected.revision);
      targetAgent(target);
      const tracked = submission && typeof submission === 'object'
        ? submissions.get(submission) : undefined;
      if (!tracked || tracked.target !== target || tracked.requestId !== requestId) {
        throw refusal('FOREIGN_SUBMISSION_HANDLE');
      }
      if (!tracked.flush) {
        tracked.flush = (async () => {
          if (typeof ctx.sessions?.flush !== 'function') throw refusal('SESSION_FLUSH_UNAVAILABLE');
          // Native flush(session) returns false when no durability listener participated.
          // Merely resolving (or passing no session) is NOT durable admission.
          const persisted = await ctx.sessions.flush(target.agent.session);
          if (persisted !== true) throw refusal('SESSION_PERSISTENCE_NOT_ACKNOWLEDGED');
          gate(expected.sessionId, expected.revision);
          targetAgent(target);
          // This receipt certifies persisted inbox admission, NOT model read,
          // processing, reply delivery, or any remote acknowledgement.
          return Object.freeze({ accepted: true, requestId });
        })();
      }
      return tracked.flush;
    },

    close() { closed = true; },
  });
}

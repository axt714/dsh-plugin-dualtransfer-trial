import path from 'node:path';
import { createRequire } from 'node:module';
import { readPrivate, atomicPrivate, failure } from './private-fs.mjs';
import { validateConfigurationPlan } from './config-mutation.mjs';
const require = createRequire(import.meta.url);
export const control = require('../control/agent-wake.js');
export const PROTOCOL = 'operation-v1';
export const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const SESSION = /^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const STATUSES = new Set(['pending', 'confirmed', 'unconfirmed', 'failed', 'cancelled', 'superseded']);
const PHASES = new Set(['prepared', 'committing', 'awaiting-host', 'settled']);
const STAGES = new Set(['not-started', 'prepared', 'committing', 'done']);
const safeCode = (error, fallback = 'OPERATION_FAILED') => /^[A-Z][A-Z0-9_]{0,63}$/u.test(error?.code ?? '') ? error.code : fallback;
export function publicOperation(record) {
  return Object.freeze({ protocol: PROTOCOL, operationId: record.operationId, status: record.status,
    phase: record.phase, dispatchReady: record.status === 'confirmed' && record.dispatchReady === true,
    changed: record.changed === true, waitCancelled: record.waitCancelled === true,
    errorCode: record.errorCode ?? null, updatedAt: record.updatedAt, expiresAt: record.expiresAt });
}
function validateJournal(value) {
  if (!value || value.schema !== 1 || Object.keys(value).some(k => !['schema', 'revision', 'records'].includes(k)) || !Number.isSafeInteger(value.revision) || value.revision < 0 || !Array.isArray(value.records) || value.records.length > 512) throw failure('OPERATION_JOURNAL_CORRUPT');
  const ids = new Set();
  for (const r of value.records) {
    if (!r || !UUID_V4.test(r.operationId ?? '') || ids.has(r.operationId) || !SESSION.test(r.sessionId ?? '')
      || r.intent !== 'bind-and-enable' || !STATUSES.has(r.status) || !PHASES.has(r.phase)
      || !STAGES.has(r.bindingStage) || !STAGES.has(r.enableStage) || typeof r.waitCancelled !== 'boolean'
      || typeof r.changed !== 'boolean' || typeof r.dispatchReady !== 'boolean'
      || !Number.isSafeInteger(r.preparedAt) || r.preparedAt < 0 || r.expiresAt !== r.preparedAt + 120000
      || !Number.isSafeInteger(r.updatedAt) || r.updatedAt < r.preparedAt
      || !(r.errorCode === null || /^[A-Z][A-Z0-9_]{0,63}$/u.test(r.errorCode))) throw failure('OPERATION_JOURNAL_CORRUPT');
    if (r.configurationPlan !== undefined) {
      try { validateConfigurationPlan(r.configurationPlan); } catch { throw failure('OPERATION_JOURNAL_CORRUPT'); }
      if (!['not-started', 'committing', 'done'].includes(r.configurationStage)
        || r.configurationPlan.operationId !== r.operationId || r.configurationPlan.sessionId !== r.sessionId
        || r.configurationPlan.preparedAt !== r.preparedAt || r.configurationPlan.expiresAt !== r.expiresAt
        || (!r.plan && (r.bindingStage !== 'not-started' || r.enableStage !== 'not-started' || r.enablePlan !== null))) throw failure('OPERATION_JOURNAL_CORRUPT');
    }
    // Old schema-1 records keep exactly their original plan and stage interpretation.
    if (r.plan ? r.plan.operationId !== r.operationId || r.plan.target?.sessionId !== r.sessionId
      || r.plan.preparedAt !== r.preparedAt || r.plan.expiresAt !== r.expiresAt
      : !r.configurationPlan) throw failure('OPERATION_JOURNAL_CORRUPT');
    ids.add(r.operationId);
  }
  return value;
}
export function createOperationManager({ profilesRoot, configuration, supervisor, resolveContext, controlApi = control,
  clock = Date.now, writeJournal = atomicPrivate, readJournal = readPrivate, timers = { setTimeout, clearTimeout } }) {
  let authoritativeRoot = null;
  function root() {
    const current = configuration ? configuration.profilesRoot() : profilesRoot;
    if (!current || !path.isAbsolute(current)) return null;
    const resolved = path.resolve(current);
    if (authoritativeRoot && authoritativeRoot !== resolved) throw failure('PROFILE_CONTEXT_CHANGED');
    return authoritativeRoot = resolved;
  }
  function journalFile() { const directory = root(); return directory ? path.join(directory, '.dualtransfer', 'operations-v1', 'operations.json') : null; }
  // Ephemeral owner capability; it is deliberately NOT reconstructed from a durable initialization intent.
  const authorizations = new Map();
  let closed = false, working = false, wakeRequested = false, workPromise = null, scheduled = null, fatal = null, lastClock = 0;
  const now = () => {
    const n = clock();
    if (!Number.isSafeInteger(n) || n < 0 || n < lastClock) throw failure('OPERATION_CLOCK_INVALID');
    lastClock = n; return n;
  };
  function load() {
    const file = journalFile();
    if (!file) return { schema: 1, revision: 0, records: [] };
    return validateJournal(readJournal(file) ?? { schema: 1, revision: 0, records: [] });
  }
  function save(journal) {
    if (closed) throw failure('OPERATION_CONTEXT_RETIRED');
    const file = journalFile();
    if (!file) throw failure('CONFIGURATION_REQUIRED');
    validateJournal(journal);
    const latest = load();
    if (latest.revision !== journal.revision) throw failure('OPERATION_JOURNAL_CHANGED');
    journal.revision += 1; writeJournal(file, journal);
  }
  function active(r, n) { return !closed && !r.waitCancelled && r.status === 'pending' && r.phase !== 'settled' && n >= r.preparedAt && n < r.expiresAt; }
  function observe(record, n) {
    // A late ACK is an observation of an already committed effect, not renewed work authority.
    // Keep the original projection; currentWork/settleFailure guard the durable terminal record.
    const r = structuredClone(record);
    let reconcile;
    try {
      if (r.configurationPlan && (!r.plan || r.configurationStage !== 'done')) {
        reconcile = configuration?.reconcile(r.configurationPlan, controlApi);
        r.changed ||= reconcile?.changed === true;
        r.dispatchReady = false;
        if (r.configurationStage !== 'not-started' || n >= r.expiresAt || r.waitCancelled || !authorizations.has(r.operationId)) {
          r.status = r.waitCancelled ? 'cancelled' : 'unconfirmed'; r.phase = 'settled';
          r.errorCode = r.waitCancelled ? 'WAIT_CANCELLED' : n >= r.expiresAt ? 'OPERATION_EXPIRED' : r.errorCode ?? 'CONFIGURATION_COMMIT_UNCONFIRMED';
        }
        return r;
      }
      reconcile = controlApi.reconcileBinding(r.plan);
      r.changed ||= reconcile.changed === true;
      if (!reconcile.targetCurrent) {
        if (r.bindingStage !== 'not-started') { r.status = 'superseded'; r.phase = 'settled'; r.errorCode = 'TARGET_NOT_CURRENT'; }
        else if (r.status === 'pending' && n >= r.expiresAt) { r.status = 'unconfirmed'; r.phase = 'settled'; r.errorCode = 'OPERATION_EXPIRED'; }
        r.dispatchReady = false; return r;
      }
      const evidence = controlApi.readHostEvidence(r.plan, { now: n, enablePlan: r.enablePlan,
        currentEpoch: supervisor.currentEpoch(r.plan.target) });
      if (r.enablePlan && ['committing', 'done'].includes(r.enableStage) && evidence.confirmed) {
        r.status = 'confirmed'; r.phase = 'settled'; r.dispatchReady = true; r.errorCode = null;
      } else {
        r.dispatchReady = false;
        if (r.status === 'confirmed') { r.status = 'unconfirmed'; r.phase = 'settled'; r.errorCode = 'HOST_ACK_NOT_CURRENT'; }
        if (n < r.preparedAt) { r.status = 'unconfirmed'; r.phase = 'settled'; r.errorCode = 'OPERATION_CLOCK_INVALID'; }
        else if (n >= r.expiresAt || r.waitCancelled) {
          if (r.status !== 'cancelled') r.status = 'unconfirmed';
          r.phase = 'settled'; r.errorCode = r.waitCancelled ? 'WAIT_CANCELLED' : 'OPERATION_EXPIRED';
        }
      }
    } catch (error) {
      r.dispatchReady = false;
      r.status = r.status === 'cancelled' ? 'cancelled' : 'unconfirmed'; r.phase = 'settled'; r.errorCode = safeCode(error);
    }
    return r;
  }
  function settleExpired(journal, n, operationId = null) {
    let changed = false;
    for (const r of journal.records) {
      if (r.status !== 'pending' || (operationId && r.operationId !== operationId) || n < r.expiresAt) continue;
      Object.assign(r, observe(r, n), { status: r.waitCancelled ? 'cancelled' : 'unconfirmed', phase: 'settled',
        dispatchReady: false, errorCode: r.waitCancelled ? 'WAIT_CANCELLED' : 'OPERATION_EXPIRED', updatedAt: n });
      changed = true;
    }
    if (changed) save(journal);
    return changed;
  }
  function currentWork(journal, record, n) {
    const latest = load(), current = latest.records.find(r => r.operationId === record.operationId);
    // An old continuation owns only its original ID, never another pending record or a settled outcome.
    if (!current || current.status !== 'pending' || current.phase === 'settled' || current.waitCancelled) return false;
    if (settleExpired(latest, n, record.operationId)) return false;
    if (latest.revision !== journal.revision) throw failure('OPERATION_JOURNAL_CHANGED');
    return active(record, n);
  }
  function settleFailure(operationId, error) {
    const journal = load(), r = journal.records.find(record => record.operationId === operationId);
    if (!r || r.status !== 'pending' || r.phase === 'settled' || r.waitCancelled) return;
    const n = now();
    if (settleExpired(journal, n, operationId)) return;
    Object.assign(r, observe(r, n), { status: 'unconfirmed', phase: 'settled', dispatchReady: false,
      errorCode: safeCode(error), updatedAt: n });
    save(journal);
  }
  async function context(sessionId) {
    if (closed) throw failure('OPERATION_CONTEXT_RETIRED');
    const assert = await resolveContext(sessionId);
    if (closed || typeof assert !== 'function' || !assert()) throw failure('INVALID_CONTEXT');
    return () => !closed && assert();
  }
  function assertCurrent(assert) { if (closed || !assert()) throw failure('INVALID_CONTEXT'); }
  function launchWork() {
    // A busy wake must retain the actual in-flight drain, not replace it with a short return Promise.
    if (working) { wakeRequested = true; return workPromise; }
    workPromise = work(); return workPromise;
  }
  function queue(delay = 0) {
    if (closed || scheduled !== null || fatal) return;
    scheduled = timers.setTimeout(() => { scheduled = null; launchWork(); }, delay);
    scheduled?.unref?.();
  }
  async function work() {
    if (closed || working || fatal) return;
    working = true;
    let again = false, operationId = null;
    try {
      const journal = load();
      const r = journal.records.find(r => r.status === 'pending' && !r.waitCancelled);
      if (!r) return;
      operationId = r.operationId;
      let n = now();
      if (settleExpired(journal, n, operationId) || !active(r, n)) return;
      const contextValid = await context(r.sessionId);
      const caller = authorizations.get(r.operationId);
      const assert = () => contextValid() && (!caller || caller());
      assertCurrent(assert);
      if (!currentWork(journal, r, now())) return;
      if (r.configurationPlan && (!r.plan || r.configurationStage !== 'done')) {
        // A missing capability (restart), or any unknown SDK outcome, can ONLY reconcile.
        if (!configuration || !caller || r.configurationStage !== 'not-started') {
          Object.assign(r, observe(r, now())); r.status = 'unconfirmed'; r.phase = 'settled';
          r.errorCode ||= 'CONFIGURATION_COMMIT_UNCONFIRMED'; r.updatedAt = now(); save(journal); return;
        }
        n = now(); if (!currentWork(journal, r, n)) return;
        assertCurrent(assert);
        r.configurationStage = 'committing'; r.phase = 'committing'; r.updatedAt = n; save(journal);
        try {
          const result = await configuration.commit(r.configurationPlan,
            () => !closed && assert() && active(r, now()) && load().revision === journal.revision, controlApi);
          assertCurrent(assert);
          // Cancellation or expiry may have settled this exact record while SDK edit held its locks.
          if (!currentWork(journal, r, now())) return;
          r.changed ||= result.changed === true; r.configurationStage = 'done'; r.updatedAt = now(); save(journal);
          // Reuse the real Control plan after the full disabled tuple was read back at this exact patch.
          r.plan = controlApi.prepareBinding({ profilesRoot: root(), sessionId: r.sessionId, operationId: r.operationId,
            now: r.preparedAt, expiresAt: r.expiresAt });
          assertCurrent(assert); r.phase = 'prepared'; r.updatedAt = now(); save(journal);
        } catch (error) {
          if (closed) return;
          settleFailure(operationId, error);
          return;
        }
      }
      assertCurrent(assert); supervisor.authorize();
      if (r.bindingStage === 'not-started') {
        n = now(); if (!currentWork(journal, r, n)) return;
        assertCurrent(assert);
        // This durable mark is the no-replay barrier, including throws or process death during commit.
        r.bindingStage = 'committing'; r.phase = 'committing'; r.updatedAt = n; save(journal);
        try { const result = controlApi.commitBinding(r.plan, { now: n }); r.changed ||= result.changed === true; r.bindingStage = 'done'; }
        catch (error) { r.status = 'unconfirmed'; r.phase = 'settled'; r.errorCode = safeCode(error); r.updatedAt = now(); save(journal); return; }
        r.phase = 'awaiting-host'; r.updatedAt = now(); save(journal);
      }
      // A recovered committing record is only reconciled, never passed to commitBinding again.
      const state = controlApi.reconcileBinding(r.plan);
      r.changed ||= state.changed === true;
      if (!state.targetCurrent) { r.status = 'superseded'; r.phase = 'settled'; r.errorCode = 'TARGET_NOT_CURRENT'; r.updatedAt = now(); save(journal); return; }
      supervisor.activate(r.plan.target, r.plan.previousStateEpoch);
      await supervisor.idle(); assertCurrent(assert);
      n = now();
      if (!currentWork(journal, r, n)) return;
      const currentEpoch = supervisor.currentEpoch(r.plan.target);
      const evidence = controlApi.readHostEvidence(r.plan, { now: n, currentEpoch, enablePlan: r.enablePlan });
      if (!r.enablePlan && evidence.bindingVerified) {
        r.enablePlan = controlApi.prepareEnable(r.plan, { now: n, currentEpoch });
        r.enableStage = 'prepared'; r.updatedAt = n; save(journal);
      }
      if (r.enableStage === 'prepared' && active(r, now())) {
        assertCurrent(assert);
        if (!supervisor.isCurrent(r.plan.target, r.enablePlan.stateEpoch)) throw failure('HOST_MOUNT_CHANGED');
        r.enableStage = 'committing'; r.updatedAt = now(); save(journal);
        try { controlApi.commitEnable(r.plan, r.enablePlan, { now: r.updatedAt }); r.enableStage = 'done'; }
        catch (error) { r.status = 'unconfirmed'; r.phase = 'settled'; r.errorCode = safeCode(error); save(journal); return; }
      }
      // Reading/publishing real Host status is not emulated ACK; next heartbeat must postdate the enable request.
      if (['committing', 'done'].includes(r.enableStage)) { await supervisor.pulse(); assertCurrent(assert); }
      n = now(); if (!currentWork(journal, r, n)) return;
      const observed = observe(r, n); Object.assign(r, observed); r.updatedAt = n; save(journal);
      again = r.status === 'pending';
    } catch (error) {
      if (!closed) {
        try {
          if (operationId) settleFailure(operationId, error);
          else fatal = 'OPERATION_JOURNAL_FAILED';
        } catch { fatal = 'OPERATION_JOURNAL_FAILED'; }
      }
    } finally {
      working = false;
      const wake = wakeRequested; wakeRequested = false;
      if (wake) queue(); else if (again) queue(250);
    }
  }
  return Object.freeze({
    async check(sessionId) {
      const assert = await context(sessionId); assertCurrent(assert);
      // No journal, lease, authorization, runtime, credentials or network on a default-OFF check.
      const directory = root();
      const check = configuration ? configuration.check(controlApi)
        : directory ? controlApi.checkConfiguration(directory) : { configurationRequired: true };
      assertCurrent(assert);
      return { protocol: PROTOCOL, available: true, configurationRequired: check.configurationRequired === true };
    },
    async start(sessionId, operationId, assertAuthorized = () => true) {
      if (!SESSION.test(sessionId) || !UUID_V4.test(operationId) || typeof assertAuthorized !== 'function') throw failure('INVALID_INPUT');
      const assert = await context(sessionId); assertCurrent(assert);
      if (!assertAuthorized()) throw failure('INVALID_CONTEXT');
      const journal = load(), existing = journal.records.find(r => r.operationId === operationId);
      if (existing && (existing.sessionId !== sessionId || existing.intent !== 'bind-and-enable')) throw failure('OPERATION_ID_CONFLICT');
      const observedAt = now();
      settleExpired(journal, observedAt);
      if (existing) return publicOperation(observe(existing, observedAt));
      if (fatal) throw failure(fatal);
      if (journal.records.some(r => r.status === 'pending')) throw failure('OPERATION_BUSY');
      if (journal.records.length >= 512) throw failure('OPERATION_HISTORY_FULL');
      const directory = root();
      const check = configuration ? configuration.check(controlApi)
        : directory ? controlApi.checkConfiguration(directory) : { configurationRequired: true };
      if (!directory || (check.configurationRequired && !configuration)) throw failure('CONFIGURATION_REQUIRED');
      const n = now(), authorized = () => !closed && assert() && assertAuthorized();
      const configurationPlan = check.configurationRequired
        ? configuration.prepare({ sessionId, operationId, now: n, assertAuthorized: authorized }) : null;
      const plan = configurationPlan ? null : controlApi.prepareBinding({ profilesRoot: directory, sessionId, operationId, now: n });
      assertCurrent(authorized); supervisor.authorize();
      const r = { operationId, sessionId, intent: 'bind-and-enable', plan, enablePlan: null,
        preparedAt: n, expiresAt: n + 120000, updatedAt: n, status: 'pending', phase: 'prepared',
        bindingStage: 'not-started', enableStage: 'not-started', changed: false, waitCancelled: false,
        dispatchReady: false, errorCode: null,
        ...(configurationPlan ? { configurationPlan, configurationStage: 'not-started' } : {}) };
      // Initialization intent uses the SAME operationId and is durable before any SDK configuration write.
      journal.records.push(r); save(journal); authorizations.set(operationId, assertAuthorized);
      queue(); return publicOperation(r);
    },
    async query(sessionId, operationId) {
      await context(sessionId);
      const r = load().records.find(r => r.operationId === operationId);
      if (!r) throw failure('OPERATION_NOT_FOUND');
      if (r.sessionId !== sessionId) throw failure('OPERATION_ID_CONFLICT');
      // Observation only: no timer, lease acquisition, control write, mount, or authorisation.
      return publicOperation(observe(r, now()));
    },
    async cancelWait(sessionId, operationId, assertAuthorized = () => true) {
      if (!SESSION.test(sessionId) || !UUID_V4.test(operationId) || typeof assertAuthorized !== 'function') throw failure('INVALID_INPUT');
      const assert = await context(sessionId); assertCurrent(assert);
      if (!assertAuthorized()) throw failure('INVALID_CONTEXT');
      const journal = load(), r = journal.records.find(r => r.operationId === operationId);
      if (!r) throw failure('OPERATION_NOT_FOUND');
      if (r.sessionId !== sessionId) throw failure('OPERATION_ID_CONFLICT');
      supervisor.authorize();
      r.waitCancelled = true;
      if (r.bindingStage === 'not-started') { r.status = 'cancelled'; r.phase = 'settled'; r.errorCode = 'WAIT_CANCELLED'; }
      else Object.assign(r, observe(r, now()));
      r.updatedAt = now(); save(journal); return publicOperation(r);
    },
    recover() {
      // Existing enabled-context recovery may settle expired intent, never replay a mutation.
      // Default-OFF construction does not call recover or open this journal.
      const journal = load(), n = now();
      settleExpired(journal, n);
      if (journal.records.some(r => r.status === 'pending' && active(r, n))) queue();
    },
    work: launchWork, idle: async () => { await workPromise; },
    dispose() { closed = true; authorizations.clear(); if (scheduled !== null) { timers.clearTimeout(scheduled); scheduled = null; } return workPromise; },
  });
}

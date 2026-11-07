import fs from 'node:fs';
import path from 'node:path';
import { userInfo } from 'node:os';
import { isDeepStrictEqual } from 'node:util';
import { defaults, runtimeKeys } from './config.mjs';
import { isLocalAbsoluteConfigPath } from './vendor/local-client/config-path.mjs';
import { failure, safeDirectory } from './private-fs.mjs';

const PRODUCT = 'dsh-plugin-dualtransfer';
const SESSION = /^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
const samePath = (a, b) => isLocalAbsoluteConfigPath(a) && isLocalAbsoluteConfigPath(b)
  && (process.platform === 'win32' ? path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase() : path.resolve(a) === path.resolve(b));
function rawCopy(value) {
  if (!object(value)) throw failure('CONFIGURATION_RAW_UNSUPPORTED');
  // Expressions can change ordinary resolved values during reconciliation and force a self reload.
  function staticValue(v) {
    if (v && typeof v === 'object') {
      if (Object.hasOwn(v, '__jsExpr')) throw failure('CONFIGURATION_RAW_UNSUPPORTED');
      for (const child of Object.values(v)) staticValue(child);
    }
  }
  try {
    staticValue(value);
    const copy = JSON.parse(JSON.stringify(value));
    if (!isDeepStrictEqual(copy, value)) throw failure('CONFIGURATION_RAW_UNSUPPORTED');
    return copy;
  } catch { throw failure('CONFIGURATION_RAW_UNSUPPORTED'); }
}
function ordinary(raw) { return Object.fromEntries(Object.entries(raw).filter(([key]) => !runtimeKeys.includes(key))); }
function uninitializedTuple(raw) {
  // A missing client path is not permission to replace an existing or partial runtime identity.
  return object(raw) && ['enabled', 'sessionId', 'revision', 'dataDirectory'].every(key =>
    !Object.hasOwn(raw, key) || raw[key] === defaults[key]);
}
function disabledTuple(value) {
  return object(value) && Object.keys(value).length === runtimeKeys.length && runtimeKeys.every(key => Object.hasOwn(value, key))
    && value.enabled === false && value.sessionId === '' && Number.isSafeInteger(value.revision) && value.revision >= 1
    && isLocalAbsoluteConfigPath(value.dataDirectory) && isLocalAbsoluteConfigPath(value.agentClientConfigPath)
    && path.basename(value.dataDirectory) === `agent-wake-runtime-r${value.revision}`;
}
export function validateConfigurationPlan(plan) {
  if (!object(plan) || plan.schema !== 1 || plan.protocol !== 'configuration-v1' || !UUID.test(plan.operationId ?? '')
    || !SESSION.test(plan.sessionId ?? '') || !Number.isSafeInteger(plan.preparedAt) || plan.preparedAt < 0
    || plan.expiresAt !== plan.preparedAt + 120000 || plan.patchId !== PRODUCT || plan.entryId !== `include:${PRODUCT}`
    || !isLocalAbsoluteConfigPath(plan.profilesRoot) || !isLocalAbsoluteConfigPath(plan.profileDirectory)
    || !samePath(path.dirname(plan.profileDirectory), plan.profilesRoot)
    || !samePath(plan.patchPath, path.join(plan.profileDirectory, 'cordis.patch.yml'))
    || !disabledTuple(plan.target) || !samePath(path.dirname(plan.target.dataDirectory), plan.profileDirectory)
    || !uninitializedTuple(plan.sourceRaw)
    || !isDeepStrictEqual(rawCopy(plan.targetRaw), { ...rawCopy(plan.sourceRaw), ...plan.target })
    || !isDeepStrictEqual(ordinary(plan.sourceRaw), ordinary(plan.targetRaw))) throw failure('CONFIGURATION_PLAN_INVALID');
  return plan;
}

// No Loader construction, profile writes, credential reads, lease or journal work at construction.
// The optional platform seams are private to synthetic callers, never part of the RPC contract.
export function createConfigurationMutation(ctx, { profilesRoot = '', platform = process.platform,
  accountHome = () => userInfo().homedir, appData = () => process.env.APPDATA } = {}) {
  function profileAuthority() {
    const profile = ctx.get?.('profileContext'), editor = ctx.get?.('configEditor'), fiber = ctx.fiber, entry = fiber?.entry;
    if (!profile || !editor || typeof editor.entries !== 'function' || typeof editor.configuration !== 'function'
      || typeof editor.edit !== 'function' || !entry || !isLocalAbsoluteConfigPath(profile.dir)
      || !samePath(profile.patchPath, path.join(profile.dir, 'cordis.patch.yml'))
      || !samePath(editor.documentPath, profile.patchPath)) throw failure('CONFIGURATION_SDK_UNSUPPORTED');
    const root = path.dirname(path.resolve(profile.dir));
    if (root === path.parse(root).root || (profilesRoot !== '' && !samePath(profilesRoot, root))) throw failure('PROFILES_ROOT_MISMATCH');
    return { root, profile, editor, fiber, entry };
  }
  function authority() {
    const a = profileAuthority(), { root, profile, editor, fiber, entry } = a;
    const entries = editor.entries();
    if (!Array.isArray(entries) || entries.filter(row => row.options?.id === PRODUCT).length !== 1
      || !entries.includes(entry) || entry.id !== `include:${PRODUCT}` || entry.options?.id !== PRODUCT
      || entry.options?.name !== PRODUCT || entry.parent?.tree?.ctx?.fiber?.entry?.id !== 'include'
      || entry.fiber !== fiber || fiber.state !== 2) throw failure('PROFILE_NOT_ADDRESSABLE');
    const schema = fiber.runtime?.Config;
    if (!runtimeKeys.every(key => schema?.dict?.[key]?.meta?.volatile === true)) throw failure('CONFIGURATION_SDK_UNSUPPORTED');
    return { root, profile, editor, fiber, entry };
  }
  function snapshot() {
    const a = authority(), layers = a.editor.configuration();
    if (!Array.isArray(layers) || layers.filter(row => row.entry === a.entry).length !== 1) throw failure('PROFILE_NOT_ADDRESSABLE');
    const layer = layers.find(row => row.entry === a.entry);
    // configuration() returns detached layer rows, NOT an iterator/object keyed by entry id.
    rawCopy(layer.inherited); rawCopy(layer.override);
    const raw = rawCopy(a.entry.options.config ?? {});
    if (raw.profilesRoot !== undefined && raw.profilesRoot !== '' && !samePath(raw.profilesRoot, a.root)) throw failure('PROFILES_ROOT_MISMATCH');
    return { ...a, raw };
  }
  function assertPlanOwner(plan) {
    validateConfigurationPlan(plan);
    const a = authority();
    if (!samePath(a.root, plan.profilesRoot) || !samePath(a.profile.dir, plan.profileDirectory)
      || !samePath(a.profile.patchPath, plan.patchPath) || a.entry.id !== plan.entryId) throw failure('PROFILE_CONTEXT_CHANGED');
    return a;
  }
  function clientPath(raw) {
    if (raw.agentClientConfigPath !== undefined && raw.agentClientConfigPath !== null && raw.agentClientConfigPath !== '') {
      if (!isLocalAbsoluteConfigPath(raw.agentClientConfigPath)) throw failure('CLIENT_CONFIG_PATH_INVALID');
      return raw.agentClientConfigPath;
    }
    // Standard agent-client.py locations, not a path claimed to have come from the Host.
    const base = platform === 'darwin' ? path.join(accountHome(), 'Library', 'Application Support', 'DualTransfer')
      : platform === 'win32' && isLocalAbsoluteConfigPath(appData()) ? path.join(appData(), 'DualTransfer') : null;
    if (!base || !isLocalAbsoluteConfigPath(base)) throw failure('CLIENT_CONFIG_PATH_REQUIRED');
    return path.join(base, 'agent-client.json');
  }
  function assertActive(a, controlApi, target) {
    const active = controlApi.readActiveConfig(a.root);
    if (!samePath(active.file, a.profile.patchPath) || active.profile !== path.basename(a.profile.dir)
      || (target && !runtimeKeys.every(key => active.config[key] === target[key]))) throw failure('PROFILE_CONTROL_LAYOUT_UNSUPPORTED');
    return active;
  }
  return Object.freeze({
    profilesRoot() { return profileAuthority().root; },
    check(controlApi) {
      const a = authority(), check = controlApi.checkConfiguration(a.root);
      if (!check.configurationRequired) assertActive(a, controlApi);
      return check;
    },
    prepare({ sessionId, operationId, now, assertAuthorized }) {
      if (typeof assertAuthorized !== 'function' || !assertAuthorized()) throw failure('INVALID_CONTEXT');
      const a = snapshot();
      if ((a.raw.enabled ?? false) !== false) throw failure('CONFIGURATION_INCOMPLETE_ACTIVE');
      if (!uninitializedTuple(a.raw)) throw failure('CONFIGURATION_INCOMPLETE_EXISTING');
      const client = clientPath(a.raw);
      if (!safeDirectory(a.profile.dir)) throw failure('PROFILE_CONTEXT_CHANGED');
      // Select an absent Host runtime sibling only; no old rN or business Root is opened/adopted.
      let revision = 1, directory;
      for (; revision <= 1024; revision++) {
        const candidate = path.join(a.profile.dir, `agent-wake-runtime-r${revision}`);
        try { fs.lstatSync(candidate); }
        catch (error) { if (error.code !== 'ENOENT') throw failure('RUNTIME_DIRECTORY_UNSAFE'); directory = candidate; break; }
      }
      if (!directory) throw failure('RUNTIME_REVISION_EXHAUSTED');
      const target = { enabled: false, sessionId: '', revision, dataDirectory: directory, agentClientConfigPath: client };
      const plan = validateConfigurationPlan({ schema: 1, protocol: 'configuration-v1', operationId, sessionId,
        profilesRoot: a.root, profileDirectory: path.resolve(a.profile.dir), patchPath: a.profile.patchPath,
        entryId: a.entry.id, patchId: a.entry.options.id, preparedAt: now, expiresAt: now + 120000,
        sourceRaw: a.raw, targetRaw: { ...a.raw, ...target }, target });
      if (!assertAuthorized()) throw failure('INVALID_CONTEXT');
      return plan;
    },
    async commit(plan, assertAuthorized, controlApi) {
      const a = assertPlanOwner(plan); let callbacks = 0;
      if (!assertAuthorized()) throw failure('INVALID_CONTEXT');
      // Caller MUST durably mark committing before entering this at-most-once SDK edit.
      await a.editor.edit(a.entry, (current, inherited) => {
        if (++callbacks !== 1) throw failure('CONFIGURATION_SDK_UNSUPPORTED');
        const latest = assertPlanOwner(plan);
        if (!assertAuthorized() || latest.entry !== a.entry || latest.fiber !== a.fiber) throw failure('INVALID_CONTEXT');
        rawCopy(inherited);
        if (!isDeepStrictEqual(rawCopy(current), plan.sourceRaw)) throw failure('CONFIGURATION_CONFLICT');
        // Exactly five volatile changes; preserve every ordinary/unknown raw field, including absence of profilesRoot.
        return rawCopy(plan.targetRaw);
      });
      if (!assertAuthorized()) throw failure('INVALID_CONTEXT');
      if (callbacks !== 1 || !this.reconcile(plan, controlApi).targetCurrent) throw failure('CONFIGURATION_COMMIT_UNCONFIRMED');
      return { changed: true };
    },
    reconcile(plan, controlApi) {
      const a = assertPlanOwner(plan), current = rawCopy(a.entry.options.config ?? {});
      if (!isDeepStrictEqual(current, plan.targetRaw)) return { targetCurrent: false, changed: false };
      assertActive(a, controlApi, plan.target);
      return { targetCurrent: true, changed: true };
    },
  });
}

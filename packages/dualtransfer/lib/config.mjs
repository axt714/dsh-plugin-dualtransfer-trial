import path from 'node:path';
import { isLocalAbsoluteConfigPath } from './vendor/local-client/config-path.mjs';
export const defaults = Object.freeze({ enabled: false, sessionId: '', revision: 1, dataDirectory: '', agentClientConfigPath: '' });
export const runtimeKeys = Object.freeze(Object.keys(defaults));
export function createConfigSchema(z) {
  return z.object({
    profilesRoot: z.string().max(8192).default('').description('Explicit profiles root; ordinary changes reload this entry.'),
    enabled: z.boolean().default(false).volatile(),
    sessionId: z.string().max(256).default('').volatile(),
    revision: z.number().min(1).step(1).default(1).volatile(),
    dataDirectory: z.string().max(8192).default('').volatile(),
    agentClientConfigPath: z.string().max(8192).default('').volatile(),
  });
}
export function projectRuntime(config = {}) {
  return normalizeConfig(Object.fromEntries(runtimeKeys.map(key => [key,
    config[key] && typeof config[key].get === 'function' ? config[key].get() : config[key] ?? defaults[key]])));
}
export function normalizeConfig(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !runtimeKeys.includes(key))) throw new Error('INVALID_LOCAL_CONFIGURATION');
  const value = { ...defaults, ...input };
  if (typeof value.enabled !== 'boolean' || typeof value.sessionId !== 'string' || value.sessionId.length > 256
    || !Number.isSafeInteger(value.revision) || value.revision < 1 || typeof value.dataDirectory !== 'string'
    || value.dataDirectory.length > 8192 || typeof value.agentClientConfigPath !== 'string'
    || value.agentClientConfigPath.length > 8192 || [value.sessionId, value.dataDirectory, value.agentClientConfigPath].some(x => /[\x00-\x1f\x7f]/u.test(x))) throw new Error('INVALID_LOCAL_CONFIGURATION');
  return Object.freeze(value);
}
export function configured(config) {
  if (!/^session-[0-9a-f-]{36}$/u.test(config.sessionId) || !isLocalAbsoluteConfigPath(config.dataDirectory)
    || !isLocalAbsoluteConfigPath(config.agentClientConfigPath)) return false;
  const key = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
  return !['journal.json', 'owner.lock', 'binding.json', 'cursor.json', 'setup-used.json', 'bind-request.json', 'control.json', 'public-status.json'].some(name => key(config.agentClientConfigPath) === key(path.join(config.dataDirectory, name)));
}
export function sameTuple(a, b) { return !!a && !!b && runtimeKeys.every(key => a[key] === b[key]); }

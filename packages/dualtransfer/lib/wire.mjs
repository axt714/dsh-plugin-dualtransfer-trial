export const CORE_SHA256 = '9fc17b19d0f62d0391de7105b8269368288c9f67c8f6c27bf6337b98b41ad036';
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const EPOCH = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export const nonnegative = value => Number.isSafeInteger(value) && value >= 0;
export const positive = value => Number.isSafeInteger(value) && value > 0;
export const keysOnly = (value, fields) => record(value) && Object.keys(value).every(key => fields.includes(key));
export function controlState(raw, binding, now) {
  if (raw === null) return Object.freeze({ kind: 'missing', enabled: false, effective: false, code: null });
  const fields = ['schema', 'toggleRevision', 'enabled', 'forBindingId', 'forBindingRevision',
    'leaseExpiresAt', 'requestedBy', 'updatedAt', 'adapterContract'];
  if (!keysOnly(raw, fields) || raw.schema !== 1 || !nonnegative(raw.toggleRevision)
      || typeof raw.enabled !== 'boolean' || !UUID.test(raw.forBindingId ?? '')
      || !positive(raw.forBindingRevision) || !(raw.leaseExpiresAt === null || nonnegative(raw.leaseExpiresAt))
      || raw.requestedBy !== 'local-ui' || !nonnegative(raw.updatedAt)
      || !keysOnly(raw.adapterContract, ['min', 'max']) || !positive(raw.adapterContract.min)
      || !positive(raw.adapterContract.max) || raw.adapterContract.min > 2 || raw.adapterContract.max < 2) {
    return Object.freeze({ kind: 'corrupt', enabled: false, effective: false, code: 'CONTROL_INVALID' });
  }
  const same = raw.forBindingId === binding?.id && raw.forBindingRevision === binding?.revision;
  const expired = raw.leaseExpiresAt !== null && raw.leaseExpiresAt <= now;
  return Object.freeze({ kind: 'valid', enabled: raw.enabled,
    effective: raw.enabled && same && !expired,
    code: !same ? 'CONTROL_STALE_BINDING' : expired ? 'LEASE_EXPIRED' : null });
}
export function validRequest(value, expected, now) {
  return keysOnly(value, ['schema', 'nonce', 'sessionId', 'revision', 'createdAt', 'expiresAt'])
    && value.schema === 1 && UUID.test(value.nonce ?? '') && value.sessionId === expected.sessionId
    && value.revision === expected.revision && nonnegative(value.createdAt) && nonnegative(value.expiresAt)
    && value.createdAt <= now && value.expiresAt > now && value.expiresAt > value.createdAt
    && value.expiresAt - value.createdAt <= 300000;
}
export function validBinding(value, expected, state = 'committed') {
  return keysOnly(value, ['schema', 'id', 'sessionId', 'revision', 'state', 'setupNonce', 'createdAt'])
    && value.schema === 1 && UUID.test(value.id ?? '') && UUID.test(value.setupNonce ?? '')
    && value.sessionId === expected.sessionId && value.revision === expected.revision
    && value.state === state && nonnegative(value.createdAt);
}
export function validCursor(value, binding) {
  return keysOnly(value, ['schema', 'bindingId', 'bindingRevision', 'epoch', 'cursor'])
    && value.schema === 1 && value.bindingId === binding.id && value.bindingRevision === binding.revision
    && EPOCH.test(value.epoch ?? '') && nonnegative(value.cursor);
}
export function validUsed(value, binding) {
  return keysOnly(value, ['schema', 'nonce', 'bindingId', 'sessionId', 'revision', 'consumedAt'])
    && value.schema === 1 && value.nonce === binding.setupNonce && value.bindingId === binding.id
    && value.sessionId === binding.sessionId && value.revision === binding.revision
    && nonnegative(value.consumedAt);
}

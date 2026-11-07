import fs from 'node:fs';
import path from 'node:path';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto';
import { atomicPrivate, exclusiveFile, failure, readPrivate, safeDirectory, syncDir } from './private-fs.mjs';
import { assertRuntimeCapability, beginRuntimeBarrier, failRuntimeBarrier, createFailureLatch, brandAgentFailure } from './agent-failure.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$(?![\s\S])/;
const KEY = /^[a-f0-9]{64}$(?![\s\S])/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$(?![\s\S])/;
const assert = (yes, code) => { if (!yes) throw failure(code); };
const clone = value => JSON.parse(JSON.stringify(value));
const bytes = value => Buffer.from(JSON.stringify(value));
const publicFingerprint = publicKey => createHash('sha256').update(Buffer.from(publicKey, 'base64')).digest('hex');
function publicObject(value, keys, code = 'AGENT_IDENTITY_CORRUPT') {
  assert(value && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)), code);
  return value;
}
function publicKeyObject(value) {
  assert(typeof value === 'string' && value.length <= 128 && BASE64.test(value), 'AGENT_PUBLIC_KEY_INVALID');
  try {
    const key = createPublicKey({ key: Buffer.from(value, 'base64'), type: 'spki', format: 'der' });
    assert(key.asymmetricKeyType === 'ed25519' && key.export({ type: 'spki', format: 'der' }).toString('base64') === value, 'AGENT_PUBLIC_KEY_INVALID');
    return key;
  } catch { throw failure('AGENT_PUBLIC_KEY_INVALID'); }
}
export function verifyAgentPeerSignature(publicKey, value, signature) {
  try { return typeof signature === 'string' && signature.length <= 128 && BASE64.test(signature)
    && verify(null, bytes(value), publicKeyObject(publicKey), Buffer.from(signature, 'base64')); } catch { return false; }
}
export function validateAgentPeerEndpoint(value) {
  publicObject(value, ['host', 'port'], 'AGENT_PEER_ENDPOINT_INVALID');
  assert(typeof value.host === 'string' && value.host.length > 0 && value.host.length <= 253 && !/[\s/\\@?#\x00]/.test(value.host)
    && Number.isInteger(value.port) && value.port >= 1 && value.port <= 65535, 'AGENT_PEER_ENDPOINT_INVALID');
  return Object.freeze({ host: value.host, port: value.port });
}
function pair(value, pending = false) {
  const keys = ['pairingId', 'generation', 'peerDeviceId', 'peerPublicKey', 'pairKey', 'endpoint'];
  publicObject(value, pending ? [...keys, 'expiresAt', 'localApproved', 'remoteApproved'] : keys);
  assert(UUID.test(value.pairingId) && UUID.test(value.generation) && UUID.test(value.peerDeviceId) && KEY.test(value.pairKey), 'AGENT_IDENTITY_CORRUPT');
  publicKeyObject(value.peerPublicKey);
  if (value.endpoint !== null) validateAgentPeerEndpoint(value.endpoint);
  if (pending) assert(Number.isSafeInteger(value.expiresAt) && value.expiresAt > 0 && typeof value.localApproved === 'boolean' && typeof value.remoteApproved === 'boolean', 'AGENT_IDENTITY_CORRUPT');
  return value;
}
function validate(value) {
  const keys = ['schema', 'deviceId', 'publicKey', 'privateKey', 'invitation', 'pending', 'trust'];
  publicObject(value, value?.schema === 2 ? [...keys, 'listener'] : keys);
  assert((value.schema === 1 || value.schema === 2) && UUID.test(value.deviceId) && typeof value.privateKey === 'string' && value.privateKey.length <= 256 && BASE64.test(value.privateKey), 'AGENT_IDENTITY_CORRUPT');
  const publicKey = publicKeyObject(value.publicKey);
  try {
    const privateKey = createPrivateKey({ key: Buffer.from(value.privateKey, 'base64'), type: 'pkcs8', format: 'der' });
    assert(privateKey.asymmetricKeyType === 'ed25519' && createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).equals(publicKey.export({ format: 'der', type: 'spki' })), 'AGENT_IDENTITY_CORRUPT');
  } catch { throw failure('AGENT_IDENTITY_CORRUPT'); }
  if (value.schema === 2 && value.listener !== null) {
    const listener = publicObject(value.listener, ['port']);
    assert(Number.isInteger(listener.port) && listener.port >= 1 && listener.port <= 65535, 'AGENT_IDENTITY_CORRUPT');
  }
  if (value.invitation !== null) {
    const invitation = publicObject(value.invitation, ['id', 'key', 'expiresAt', 'used']);
    assert(UUID.test(invitation.id) && KEY.test(invitation.key) && Number.isSafeInteger(invitation.expiresAt) && invitation.expiresAt > 0 && typeof invitation.used === 'boolean', 'AGENT_IDENTITY_CORRUPT');
  }
  if (value.pending !== null) pair(value.pending, true);
  if (value.trust !== null) pair(value.trust);
  assert(!(value.pending && value.trust), 'AGENT_IDENTITY_CORRUPT');
  for (const candidate of [value.pending, value.trust]) if (candidate) assert(candidate.peerDeviceId !== value.deviceId && candidate.peerPublicKey !== value.publicKey, 'AGENT_IDENTITY_CORRUPT');
  return value;
}

/** Private capability for the transport implementation, never expose this object to RPC/tools. */
export function createAgentPeerIdentity({ directory, now = Date.now, runtime } = {}) {
  assert(typeof directory === 'string' && path.isAbsolute(directory) && path.resolve(directory) !== path.parse(directory).root && typeof now === 'function', 'AGENT_IDENTITY_OPTIONS_INVALID');
  assertRuntimeCapability(runtime);
  const file = path.join(directory, 'peer-identity.json'), lock = path.join(directory, 'peer-identity.owner.lock');
  const failures = createFailureLatch();
  let value = null, release = null, closed = false, fault = null, expected = null, closing = null;
  let rootStat = null, ownerStat = null, fileStat = null;
  const fields = ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs'];
  const sameStat = (a, b) => a && b && fields.every(key => a[key] === b[key]);
  const privateStat = (st, directory = false) => (directory ? st.isDirectory() : st.isFile() && st.nlink === 1n)
    && !st.isSymbolicLink() && (process.platform === 'win32' || ((st.mode & 0o077n) === 0n && st.uid === BigInt(process.getuid())));
  function active() { if (fault) throw failure(fault); assert(value && !closed, 'AGENT_IDENTITY_NOT_OPEN'); }
  function timestamp() { const time = now(); assert(Number.isSafeInteger(time) && time >= 0, 'AGENT_IDENTITY_CLOCK_INVALID'); return time; }
  function anchors() {
    assert(safeDirectory(directory), 'AGENT_IDENTITY_CHANGED');
    const root = fs.lstatSync(directory, { bigint: true }), owner = fs.lstatSync(lock, { bigint: true });
    assert(privateStat(root, true) && root.dev === rootStat.dev && root.ino === rootStat.ino && root.mode === rootStat.mode
      && root.uid === rootStat.uid && root.gid === rootStat.gid && privateStat(owner) && sameStat(owner, ownerStat), 'AGENT_IDENTITY_CHANGED');
  }
  function checked() {
    anchors(); const before = fs.lstatSync(file, { bigint: true });
    assert(privateStat(before) && sameStat(before, fileStat), 'AGENT_IDENTITY_CHANGED');
    const current = readPrivate(file), after = fs.lstatSync(file, { bigint: true });
    assert(current && JSON.stringify(current) === expected && sameStat(before, after), 'AGENT_IDENTITY_CHANGED'); anchors();
  }
  function durable() {
    active(); try { checked(); } catch (error) {
      fault = /^AGENT_|^PRIVATE_|^PRODUCT_OWNER_/.test(error.code ?? '') ? error.code : 'AGENT_IDENTITY_IO'; throw failure(fault);
    }
  }
  function commit(next) {
    active();
    try {
      checked(); validate(next); atomicPrivate(file, next); anchors();
      const latest = fs.lstatSync(file, { bigint: true }); assert(privateStat(latest), 'AGENT_IDENTITY_CHANGED');
      value = clone(next); expected = JSON.stringify(value); fileStat = latest; checked();
    }
    catch (error) { fault = /^AGENT_|^PRIVATE_|^PRODUCT_OWNER_/.test(error.code ?? '') ? error.code : 'AGENT_IDENTITY_IO'; throw failure(fault); }
  }
  function pending(id) { active(); assert(value.pending && value.pending.pairingId === id && value.pending.expiresAt > timestamp(), 'AGENT_PAIRING_EXPIRED'); return value.pending; }
  const api = {
    async open() {
      assert(!closed, 'AGENT_IDENTITY_CLOSED');
      if (value) { active(); return api.snapshot(); }
      try {
        safeDirectory(directory, { create: true });
        assert(fs.readdirSync(directory).every(name => name === path.basename(file) || name === path.basename(lock)), 'AGENT_IDENTITY_DIRECTORY_CONFLICT');
        rootStat = fs.lstatSync(directory, { bigint: true }); assert(privateStat(rootStat, true), 'AGENT_IDENTITY_CHANGED');
        const owner = { schema: 1, pid: process.pid, nonce: randomUUID() };
        release = runtime === undefined ? exclusiveFile(lock, owner) : runtime.acquire(lock, owner);
        ownerStat = fs.lstatSync(lock, { bigint: true }); anchors();
        let loaded = readPrivate(file);
        if (loaded === null) {
          const keys = generateKeyPairSync('ed25519');
          loaded = { schema: 2, deviceId: randomUUID(), publicKey: keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
            privateKey: keys.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'), invitation: null, pending: null, trust: null, listener: null };
          atomicPrivate(file, loaded);
        }
        fileStat = fs.lstatSync(file, { bigint: true }); assert(privateStat(fileStat), 'AGENT_IDENTITY_CHANGED');
        value = validate(loaded); expected = JSON.stringify(value); checked(); return api.snapshot();
      } catch (error) {
        const rootCause = failures.capture(error, { stage: 'identity-open', origin: 'identity', lifecycle: 'start' });
        fault = /^AGENT_|^PRIVATE_|^PRODUCT_OWNER_/.test(error.code ?? '') ? error.code : 'AGENT_IDENTITY_IO';
        throw brandAgentFailure(failure(fault), { rootCause });
      }
    },
    close() {
      if (closing) return closing;
      let barrier;
      try { barrier = beginRuntimeBarrier(runtime, 'identity-close'); }
      catch (error) {
        const rootCause = failures.capture(error, { stage: 'identity-close', origin: 'identity', lifecycle: 'stop' });
        failRuntimeBarrier(runtime, barrier, error, 'identity-close');
        closing = Promise.reject(brandAgentFailure(error, { rootCause })); closing.catch(() => {}); return closing;
      }
      closed = true;
      closing = (async () => {
        if (fault) throw failure(fault);
        if (value) { try { checked(); syncDir(directory); } catch (error) { fault = error.code === 'AGENT_IDENTITY_CHANGED' ? error.code : 'AGENT_IDENTITY_IO'; throw failure(fault); } }
        if (release) { release(); release = null; }
        barrier?.complete();
      })().catch(error => {
        const rootCause = failures.capture(error, { stage: 'identity-close', origin: 'identity', lifecycle: 'stop' });
        failRuntimeBarrier(runtime, barrier, error, 'identity-close'); throw brandAgentFailure(error, { rootCause });
      });
      return closing;
    },
    async flush() { active(); try { checked(); syncDir(directory); } catch { fault = 'AGENT_IDENTITY_IO'; throw failure(fault); } },
    snapshot() {
      return Object.freeze({ deviceId: value?.deviceId ?? null, fingerprint: value ? publicFingerprint(value.publicKey) : null,
        paired: Boolean(value?.trust), peerDeviceId: value?.trust?.peerDeviceId ?? value?.pending?.peerDeviceId ?? null,
        peerFingerprint: value?.trust || value?.pending ? publicFingerprint((value.trust ?? value.pending).peerPublicKey) : null,
        pairingId: value?.trust?.pairingId ?? null, generation: value?.trust?.generation ?? null,
        pendingPairingId: value?.pending?.pairingId ?? null, pendingExpiresAt: value?.pending?.expiresAt ?? null,
        invitationPending: Boolean(value?.invitation && !value.invitation.used && value.invitation.expiresAt > timestamp()), errorCode: fault });
    },
    publicIdentity() { active(); return Object.freeze({ deviceId: value.deviceId, publicKey: value.publicKey }); },
    listener() { durable(); return value.listener ? Object.freeze({ ...value.listener }) : null; },
    pinListener(port) {
      durable();
      assert(Number.isInteger(port) && port >= 1 && port <= 65535, 'AGENT_IDENTITY_LISTENER_INVALID');
      assert(!value.listener || value.listener.port === port, 'AGENT_IDENTITY_LISTENER_CONFLICT');
      if (!value.listener) commit({ ...value, schema: 2, listener: { port } });
      return Object.freeze({ port });
    },
    // Private transport CAS: the owner and the signed TLS proof are checked by
    // the caller; this guard additionally preserves the complete captured trust.
    updateEndpoint(expectedTrust, endpoint) {
      durable(); const next = validateAgentPeerEndpoint(endpoint);
      assert(value.trust && JSON.stringify(value.trust) === JSON.stringify(expectedTrust), 'AGENT_PEER_ENDPOINT_STALE');
      if (JSON.stringify(value.trust.endpoint) !== JSON.stringify(next)) commit({ ...value, trust: { ...value.trust, endpoint: next } });
      return next;
    },
    sign(data) { durable(); return sign(null, bytes(data), createPrivateKey({ key: Buffer.from(value.privateKey, 'base64'), type: 'pkcs8', format: 'der' })).toString('base64'); },
    createInvitation({ ttlMs = 120000 } = {}) {
      active(); assert(!value.trust && !value.pending, 'AGENT_PAIR_ALREADY_PRESENT');
      assert(Number.isSafeInteger(ttlMs) && ttlMs >= 100 && ttlMs <= 300000, 'AGENT_INVITATION_TTL_INVALID');
      const invitation = { id: randomUUID(), key: randomBytes(32).toString('hex'), expiresAt: timestamp() + ttlMs, used: false };
      commit({ ...value, invitation });
      return Object.freeze({ version: 1, invitationId: invitation.id, key: invitation.key, expiresAt: invitation.expiresAt, ...api.publicIdentity() });
    },
    invitationKey(id) {
      durable(); const invitation = value.invitation;
      return invitation && invitation.id === id && !invitation.used && invitation.expiresAt > timestamp() ? Buffer.from(invitation.key, 'hex') : null;
    },
    consumeInvitation(id) {
      active(); assert(api.invitationKey(id), 'AGENT_INVITATION_INVALID');
      commit({ ...value, invitation: { ...value.invitation, used: true } });
      return value.invitation.expiresAt;
    },
    beginPairing(candidate) {
      active(); assert(!value.trust && !value.pending, 'AGENT_PAIR_ALREADY_PRESENT'); pair(candidate, true);
      assert(candidate.expiresAt > timestamp() && candidate.peerDeviceId !== value.deviceId && candidate.peerPublicKey !== value.publicKey, 'AGENT_PAIRING_INVALID');
      commit({ ...value, pending: clone(candidate) }); return api.snapshot();
    },
    approveLocal(id) { const current = pending(id); commit({ ...value, pending: { ...current, localApproved: true } }); },
    approveRemote(id) { const current = pending(id); commit({ ...value, pending: { ...current, remoteApproved: true } }); },
    commitPairing(id) {
      const current = pending(id); assert(current.localApproved && current.remoteApproved, 'AGENT_PAIRING_APPROVAL_REQUIRED');
      const { expiresAt, localApproved, remoteApproved, ...trust } = current;
      commit({ ...value, pending: null, trust }); return api.snapshot();
    },
    rejectPairing(id) { active(); assert(value.pending && value.pending.pairingId === id, 'AGENT_PAIRING_INVALID'); commit({ ...value, pending: null }); },
    forgetPairing(id) { active(); assert(value.trust && value.trust.pairingId === id, 'AGENT_PAIRING_INVALID'); commit({ ...value, trust: null }); },
    pending() { durable(); return value.pending ? clone(value.pending) : null; },
    trust() { durable(); return value.trust ? clone(value.trust) : null; },
  };
  return Object.freeze(api);
}

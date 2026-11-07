import tls from 'node:tls';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { failure } from './private-fs.mjs';
import { assertRuntimeCapability, beginRuntimeBarrier, failRuntimeBarrier, createFailureLatch, brandAgentFailure } from './agent-failure.mjs';
import { validateAgentMessageScope } from './agent-message-store.mjs';
import { createAgentPeerIdentity, validateAgentPeerEndpoint, verifyAgentPeerSignature } from './agent-peer-identity.mjs';

const CIPHER = 'ECDHE-PSK-CHACHA20-POLY1305';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$(?![\s\S])/;
const HEX = /^[a-f0-9]{64}$(?![\s\S])/;
const MAX_FRAME = 64 * 1024;
const KEYS = ['id', 'channel', 'text', 'conversation', 'sender', 'created', 'replyTo'];
const assert = (yes, code) => { if (!yes) throw failure(code); };
const clone = value => JSON.parse(JSON.stringify(value));
function exact(value, keys) {
  try {
    if (!value || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return Reflect.ownKeys(descriptors).length === keys.length && keys.every(key => Object.hasOwn(descriptors, key)
      && descriptors[key].enumerable && Object.hasOwn(descriptors[key], 'value'));
  } catch { return false; }
}
const same = (a, b) => a && b && Object.keys(a).length === Object.keys(b).length && Object.keys(a).every(key => a[key] === b[key]);
const mirror = scope => ({ pairingId: scope.pairingId, generation: scope.generation, localDeviceId: scope.peerDeviceId,
  peerDeviceId: scope.localDeviceId, localTargetToken: scope.peerTargetToken, peerTargetToken: scope.localTargetToken });
function wireMessage(value) {
  assert(exact(value, KEYS), 'AGENT_PEER_MESSAGE_INVALID');
  value = Object.fromEntries(KEYS.map(key => [key, Object.getOwnPropertyDescriptor(value, key).value]));
  assert(typeof value.id === 'string' && UUID.test(value.id) && (value.replyTo === null || (typeof value.replyTo === 'string' && UUID.test(value.replyTo)))
    && value.channel === 'agent' && typeof value.text === 'string' && value.text.trim().length > 0 && Buffer.byteLength(value.text) <= 16384
    && typeof value.conversation === 'string' && value.conversation.length <= 100 && typeof value.sender === 'string' && value.sender.length <= 80
    && Number.isSafeInteger(value.created) && value.created >= 0, 'AGENT_PEER_MESSAGE_INVALID');
  return Object.freeze(Object.fromEntries(KEYS.map(key => [key, value[key]])));
}
const codeOf = error => typeof error?.code === 'string' && /^(?:AGENT|PRIVATE|PRODUCT_OWNER)_[A-Z_]+$(?![\s\S])/.test(error.code) ? error.code : 'AGENT_PEER_IO';

/** Pure listener metadata seam; never opens a socket or consults the HTTP provider. */
export function readAgentPeerListener(server, live) {
  let listening = false, port = null;
  try {
    listening = live === true && server?.listening === true;
    if (listening) {
      const address = server.address();
      if (address && typeof address === 'object' && !Array.isArray(address)
        && Number.isInteger(address.port) && address.port >= 1 && address.port <= 65535) port = address.port;
    }
  } catch { /* An unavailable address is not a usable advertised port. */ }
  return Object.freeze({ listening, port });
}

/**
 * Only the no-X509 branch of the one allowed PSK suite. Arguments must come from
 * the owned TLS socket/pskCallback, never a peer frame. TLS Finished, not this
 * shape check, proves possession of the protected 32-byte key. No PKIX bypass
 * is granted to any real, malformed or nonempty certificate.
 */
export function validateAgentPskServerIdentity({ expectedIdentity, selectedIdentity, key, protocol, cipher, certificate } = {}) {
  try {
    const id = '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}';
    const allowedIdentity = new RegExp(`^(?:invite:${id}|pair:${id}:${id})$(?![\\s\\S])`);
    if (typeof expectedIdentity !== 'string' || !allowedIdentity.test(expectedIdentity) || selectedIdentity !== expectedIdentity
      || !Buffer.isBuffer(key) || key.length !== 32 || protocol !== 'TLSv1.2' || cipher !== CIPHER
      || !exact(certificate, []) || Object.getPrototypeOf(certificate) !== Object.prototype) return failure('AGENT_PSK_IDENTITY_INVALID');
    return undefined;
  } catch { return failure('AGENT_PSK_IDENTITY_INVALID'); }
}

/** Owner-selected endpoints and new owned identity only. No App/Core/listener is loaded at construction. */
export function createAgentPeerTransport({ directory, host = '127.0.0.1', port = 0, authorizeOwner = () => false,
  now = Date.now, handshakeTimeoutMs = 5000, drainTimeoutMs = 5000, reconnectMs = 1000, runtime } = {}) {
  assert(typeof directory === 'string' && path.isAbsolute(directory) && typeof host === 'string' && host.length > 0
    && Number.isInteger(port) && port >= 0 && port <= 65535 && typeof authorizeOwner === 'function' && typeof now === 'function', 'AGENT_PEER_OPTIONS_INVALID');
  for (const value of [handshakeTimeoutMs, drainTimeoutMs, reconnectMs]) assert(Number.isSafeInteger(value) && value >= 50 && value <= 30000, 'AGENT_PEER_OPTIONS_INVALID');
  assertRuntimeCapability(runtime);
  const identity = createAgentPeerIdentity({ directory: path.join(directory, 'identity'), now, runtime });
  const failures = createFailureLatch();
  let live = false, started = false, state = 'stopped', server = null, starting = null, stopping = null;
  let quiescing = false, quiesceBarrier, networkClosing = null;
  let onMessage, onAck, peer = null, localReady = false, localToken = null, peerReady = false, peerToken = null;
  let authorityVersion = 0, lastErrorCode = null, dialing = false, reconnectTimer = null;
  const sockets = new Set(), channels = new Set(), jobs = new Set(), connectionJobs = new Set(), timers = new Set(), subscribers = new Set();
  const serverAuth = new WeakMap(), pairChannels = new Map();
  function currentScope() {
    if (!live || quiescing || !peer || peer.socket.destroyed || !localReady || !peerReady) return null;
    const trust = identity.trust(); if (!trust || !HEX.test(localToken ?? '') || !HEX.test(peerToken ?? '')) return null;
    return validateAgentMessageScope({ pairingId: trust.pairingId, generation: trust.generation,
      localDeviceId: identity.publicIdentity().deviceId, peerDeviceId: trust.peerDeviceId, localTargetToken: localToken, peerTargetToken: peerToken });
  }
  function snapshot() {
    const info = identity.snapshot();
    let ready = false; try { ready = currentScope() !== null; } catch { lastErrorCode = identity.snapshot().errorCode ?? 'AGENT_PEER_IDENTITY_UNAVAILABLE'; }
    return Object.freeze({ state: ready ? 'ready' : state, ...readAgentPeerListener(server, live), paired: info.paired,
      localReady, peerReady, ready, deviceId: info.deviceId, peerDeviceId: info.peerDeviceId, pairingId: info.pairingId,
      generation: info.generation, pendingPairingId: info.pendingPairingId, pendingExpiresAt: info.pendingExpiresAt,
      peerFingerprint: info.peerFingerprint, invitationPending: info.invitationPending, authorityVersion, lastErrorCode });
  }
  function notify() {
    authorityVersion++;
    const value = snapshot();
    for (const listener of [...subscribers]) { try { listener(value); } catch { lastErrorCode = 'AGENT_PEER_OBSERVER_FAILED'; } }
  }
  function error(error) { lastErrorCode = codeOf(error); notify(); return failure(lastErrorCode); }
  function active() { assert(live && !stopping && !quiescing, 'AGENT_PEER_STOPPED'); }
  function owner(authorization, purpose = 'operation') {
    const current = () => { if (purpose === 'retire-readiness') assert(live && !stopping, 'AGENT_PEER_STOPPED'); else active(); };
    current(); let accepted = false; try { accepted = authorizeOwner(authorization, purpose); } catch {}
    current(); assert(accepted === true, 'AGENT_PEER_OWNER_REQUIRED');
  }
  function later(fn, ms) {
    const timer = setTimeout(() => { timers.delete(timer); fn(); }, ms); timers.add(timer); return timer;
  }
  function cancel(timer) { if (timer) { clearTimeout(timer); timers.delete(timer); } }
  function tracked(promise, bucket = jobs) { bucket.add(promise); promise.then(() => bucket.delete(promise), () => bucket.delete(promise)); return promise; }
  function watch(socket) { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); if (quiescing) socket.destroy(); }
  function write(channel, value) {
    assert(live && !channel.socket.destroyed, 'AGENT_PEER_DISCONNECTED');
    const buffer = Buffer.from(JSON.stringify(value) + '\n'); assert(buffer.length <= MAX_FRAME, 'AGENT_PEER_FRAME_LIMIT');
    return tracked(new Promise((resolve, reject) => {
      const socket = channel.socket; let done = false, timer;
      const finish = code => {
        if (done) return; done = true;
        socket.removeListener('close', closed); socket.removeListener('error', failed); cancel(timer);
        if (code) reject(failure(code)); else resolve();
      };
      const closed = () => finish('AGENT_PEER_DISCONNECTED'), failed = () => finish('AGENT_PEER_WRITE_FAILED');
      socket.once('close', closed); socket.once('error', failed);
      // This write's deadline survives quiesce's reconnect/handshake timer cancellation.
      timer = setTimeout(() => { socket.destroy(); finish('AGENT_PEER_DRAIN_TIMEOUT'); }, drainTimeoutMs);
      try { socket.write(buffer, cause => finish(cause ? 'AGENT_PEER_WRITE_FAILED' : null)); }
      catch { failed(); }
    }));
  }
  function signed(channel, type, data) { return write(channel, { type, data, signature: identity.sign({ type, data }) }); }
  function clearPeer(channel) {
    if (peer !== channel) return;
    peer = null; peerReady = false; peerToken = null;
    if (live) { state = identity.snapshot().paired ? 'paired' : 'listening'; notify(); scheduleReconnect(); }
  }
  function closeChannel(channel) { cancel(channel.deadline); channel.socket.destroy(); }
  function expiry(channel, expiresAt) {
    cancel(channel.deadline);
    channel.deadline = later(() => { lastErrorCode = 'AGENT_PAIRING_EXPIRED'; closeChannel(channel); notify(); }, Math.max(1, expiresAt - now()));
  }
  async function readyFrame(channel, proofOnly = false) {
    const trust = identity.trust(); assert(trust, 'AGENT_PAIRING_REQUIRED');
    const ready = !proofOnly && localReady;
    await signed(channel, 'ready', { pairingId: trust.pairingId, generation: trust.generation,
      deviceId: identity.publicIdentity().deviceId, ready, targetToken: ready ? localToken : null, channelBinding: channel.binding });
  }
  async function activate(channel) {
    active(); const trust = identity.trust();
    assert(channel.authenticated && !channel.candidate && trust && channel.peerDeviceId === trust.peerDeviceId, 'AGENT_PEER_AUTHENTICATION_FAILED');
    if (peer === channel) return true;
    if (peer && !peer.socket.destroyed) {
      // Both endpoints may dial after a repair. Prefer the same physical
      // connection at both ends, while retaining the ordinary sole joiner.
      const preferredRole = identity.publicIdentity().deviceId < trust.peerDeviceId ? 'joiner' : 'inviter';
      if (channel.role !== preferredRole || peer.role === preferredRole) { closeChannel(channel); return false; }
      closeChannel(peer);
    }
    peer = channel; peerReady = false; peerToken = null; state = 'paired'; notify(); await readyFrame(channel); return true;
  }
  async function maybeCommit(channel) {
    active(); assert(!channel.socket.destroyed, 'AGENT_PEER_DISCONNECTED'); const pending = identity.pending();
    if (pending?.localApproved && pending.remoteApproved) {
      identity.commitPairing(pending.pairingId); channel.localCommitted = true; state = 'paired'; notify();
      await signed(channel, 'pair.committed', { pairingId: pending.pairingId, generation: pending.generation, deviceId: identity.publicIdentity().deviceId });
    }
    if (channel.localCommitted && channel.peerCommitted) {
      cancel(channel.deadline); closeChannel(channel);
      if (channel.role === 'joiner') scheduleReconnect(0);
    }
  }
  async function frame(channel, value) {
    active(); assert(!channel.socket.destroyed && channels.has(channel), 'AGENT_PEER_DISCONNECTED');
    assert(value && typeof value.type === 'string', 'AGENT_PEER_FRAME_INVALID');
    if (channel.mode === 'invite') {
      assert(exact(value, ['type', 'data', 'signature']), 'AGENT_PEER_FRAME_INVALID');
      const data = value.data;
      if (value.type === 'pair.hello') {
        assert(channel.role === 'inviter' && !channel.pending && exact(data, ['invitationId', 'deviceId', 'publicKey', 'nonce'])
          && data.invitationId === channel.invitationId && UUID.test(data.deviceId) && HEX.test(data.nonce)
          && data.deviceId !== identity.publicIdentity().deviceId && verifyAgentPeerSignature(data.publicKey, { type: value.type, data }, value.signature), 'AGENT_PEER_AUTHENTICATION_FAILED');
        const expiresAt = identity.consumeInvitation(data.invitationId), local = identity.publicIdentity();
        const pending = { pairingId: randomUUID(), generation: randomUUID(), peerDeviceId: data.deviceId, peerPublicKey: data.publicKey,
          pairKey: randomBytes(32).toString('hex'), endpoint: null, expiresAt, localApproved: false, remoteApproved: false };
        identity.beginPairing(pending); channel.pending = pending; channel.peerPublicKey = data.publicKey; channel.peerDeviceId = data.deviceId;
        pairChannels.set(pending.pairingId, channel); expiry(channel, expiresAt); state = 'approval-required'; notify();
        await signed(channel, 'pair.offer', { invitationId: data.invitationId, pairingId: pending.pairingId, generation: pending.generation,
          ...local, peerDeviceId: data.deviceId, peerNonce: data.nonce, pairKey: pending.pairKey, expiresAt });
      } else if (value.type === 'pair.offer') {
        const invitation = channel.invitation, local = identity.publicIdentity();
        assert(channel.role === 'joiner' && !channel.pending && exact(data, ['invitationId', 'pairingId', 'generation', 'deviceId', 'publicKey', 'peerDeviceId', 'peerNonce', 'pairKey', 'expiresAt'])
          && data.invitationId === invitation.invitationId && data.deviceId === invitation.deviceId && data.publicKey === invitation.publicKey
          && data.peerDeviceId === local.deviceId && data.peerNonce === channel.nonce && data.expiresAt === invitation.expiresAt
          && data.expiresAt > now() && verifyAgentPeerSignature(data.publicKey, { type: value.type, data }, value.signature), 'AGENT_PEER_AUTHENTICATION_FAILED');
        const pending = { pairingId: data.pairingId, generation: data.generation, peerDeviceId: data.deviceId, peerPublicKey: data.publicKey,
          pairKey: data.pairKey, endpoint: channel.endpoint, expiresAt: data.expiresAt, localApproved: false, remoteApproved: false };
        identity.beginPairing(pending); channel.pending = pending; channel.peerPublicKey = data.publicKey; channel.peerDeviceId = data.deviceId;
        pairChannels.set(pending.pairingId, channel); expiry(channel, data.expiresAt); state = 'approval-required'; notify();
        channel.resolveJoin?.(snapshot()); channel.resolveJoin = null;
      } else if (value.type === 'pair.approve' || value.type === 'pair.committed') {
        const pending = channel.pending;
        assert(pending && exact(data, ['pairingId', 'generation', 'deviceId']) && data.pairingId === pending.pairingId
          && data.generation === pending.generation && data.deviceId === pending.peerDeviceId && pending.expiresAt > now()
          && verifyAgentPeerSignature(pending.peerPublicKey, { type: value.type, data }, value.signature), 'AGENT_PEER_AUTHENTICATION_FAILED');
        if (value.type === 'pair.approve') {
          const current = identity.pending();
          if (current?.pairingId === pending.pairingId && !current.remoteApproved) identity.approveRemote(pending.pairingId);
          else assert(current?.remoteApproved || identity.trust()?.pairingId === pending.pairingId, 'AGENT_PAIRING_INVALID');
        } else channel.peerCommitted = true;
        await maybeCommit(channel);
      } else if (value.type === 'pair.reject') { closeChannel(channel); }
      else throw failure('AGENT_PAIRING_APPROVAL_REQUIRED');
      return;
    }
    const trust = identity.trust(); assert(trust && channel.peerDeviceId === trust.peerDeviceId, 'AGENT_PEER_AUTHENTICATION_FAILED');
    if (value.type === 'ready') {
      assert(exact(value, ['type', 'data', 'signature']), 'AGENT_PEER_READINESS_INVALID');
      const data = value.data;
      assert(exact(data, ['pairingId', 'generation', 'deviceId', 'ready', 'targetToken', 'channelBinding']) && data.pairingId === trust.pairingId
        && data.generation === trust.generation && data.deviceId === trust.peerDeviceId && typeof data.ready === 'boolean'
        && (data.ready ? typeof data.targetToken === 'string' && HEX.test(data.targetToken) : data.targetToken === null), 'AGENT_PEER_READINESS_INVALID');
      assert(data.channelBinding === channel.binding && verifyAgentPeerSignature(trust.peerPublicKey,
        { type: value.type, data }, value.signature), 'AGENT_PEER_AUTHENTICATION_FAILED');
      channel.authenticated = true; cancel(channel.deadline);
      if (channel.candidate) { channel.resolveProof(); return; }
      if (!await activate(channel) || peer !== channel || channel.socket.destroyed) return;
      if (peerReady !== data.ready || peerToken !== data.targetToken) { peerReady = data.ready; peerToken = data.targetToken; notify(); }
      return;
    }
    // Neither a probe nor a TLS-only socket may deliver business frames.
    assert(!channel.candidate && channel.authenticated && peer === channel, 'AGENT_PEER_AUTHENTICATION_FAILED');
    const scope = currentScope(), version = authorityVersion;
    assert(scope, 'AGENT_PEER_NOT_READY');
    if (value.type === 'message') {
      assert(exact(value, ['type', 'message', 'scope']), 'AGENT_PEER_FRAME_INVALID');
      const remote = validateAgentMessageScope(value.scope), message = wireMessage(value.message);
      assert(same(mirror(remote), scope), 'AGENT_PEER_SCOPE_MISMATCH');
      const result = await onMessage({ message: clone(message), scope: clone(scope), authenticatedPeerDeviceId: trust.peerDeviceId, device: 'authenticated-peer' });
      if (result?.acknowledge === true && live && peer === channel && authorityVersion === version && same(currentScope(), scope)) {
        await write(channel, { type: 'ack', ids: [message.id], scope: remote });
      }
    } else if (value.type === 'ack') {
      assert(exact(value, ['type', 'ids', 'scope']) && Array.isArray(value.ids) && value.ids.length >= 1 && value.ids.length <= 8
        && new Set(value.ids).size === value.ids.length && value.ids.every(id => typeof id === 'string' && UUID.test(id)
          && (channel.sent.has(id) || channel.acknowledged.has(id))), 'AGENT_PEER_ACK_INVALID');
      const local = validateAgentMessageScope(value.scope); assert(same(local, scope), 'AGENT_PEER_SCOPE_MISMATCH');
      for (const id of value.ids) assert(same((channel.sent.get(id) ?? channel.acknowledged.get(id)).scope, scope), 'AGENT_PEER_SCOPE_MISMATCH');
      const ids = value.ids.filter(id => channel.sent.has(id)); if (!ids.length) return;
      await onAck({ ids, scope: clone(scope), authenticatedPeerDeviceId: trust.peerDeviceId });
      if (live && peer === channel && authorityVersion === version && same(currentScope(), scope)) for (const id of ids) {
        channel.acknowledged.set(id, channel.sent.get(id)); channel.sent.delete(id);
        if (channel.acknowledged.size > 256) channel.acknowledged.delete(channel.acknowledged.keys().next().value);
      }
    } else throw failure('AGENT_PEER_FRAME_INVALID');
  }
  function attach(socket, info) {
    assert(live && socket.getProtocol() === 'TLSv1.2' && socket.getCipher()?.name === CIPHER, 'AGENT_PEER_AUTHENTICATION_FAILED');
    socket.disableRenegotiation(); watch(socket);
    const channel = { ...info, socket, binding: info.mode === 'pair' ? socket.exportKeyingMaterial(32, 'EXPORTER-DualTransfer-Agent-v1').toString('hex') : null,
      buffer: Buffer.alloc(0), chain: Promise.resolve(), queued: 0, sent: new Map(), acknowledged: new Map(), deadline: null };
    if (channel.candidate) {
      channel.proof = new Promise((resolve, reject) => { channel.resolveProof = resolve; channel.rejectProof = reject; });
      channel.proof.catch(() => {});
    }
    channels.add(channel);
    socket.once('close', () => {
      cancel(channel.deadline); channels.delete(channel); if (channel.pending) pairChannels.delete(channel.pending.pairingId);
      channel.rejectJoin?.(failure('AGENT_PEER_DISCONNECTED')); channel.rejectProof?.(failure('AGENT_PEER_DISCONNECTED')); clearPeer(channel);
    });
    socket.on('data', chunk => {
      try {
        assert(live && chunk.length + channel.buffer.length <= MAX_FRAME * 2, 'AGENT_PEER_FRAME_LIMIT');
        channel.buffer = Buffer.concat([channel.buffer, chunk]);
        let newline;
        while ((newline = channel.buffer.indexOf(10)) >= 0) {
          assert(newline > 0 && newline < MAX_FRAME && ++channel.queued <= 32, 'AGENT_PEER_FRAME_LIMIT');
          const bytes = channel.buffer.subarray(0, newline); channel.buffer = channel.buffer.subarray(newline + 1);
          assert(Buffer.from(bytes.toString('utf8')).equals(bytes), 'AGENT_PEER_FRAME_INVALID');
          let parsed; try { parsed = JSON.parse(bytes.toString('utf8')); } catch { throw failure('AGENT_PEER_FRAME_INVALID'); }
          const job = channel.chain.then(() => frame(channel, parsed));
          channel.chain = job.catch(cause => { if (channel.candidate) channel.rejectProof(cause); else error(cause); closeChannel(channel); }).finally(() => channel.queued--);
          tracked(channel.chain);
        }
        assert(channel.buffer.length < MAX_FRAME, 'AGENT_PEER_FRAME_LIMIT');
      } catch (cause) { if (channel.candidate) channel.rejectProof(cause); else error(cause); closeChannel(channel); }
    });
    if (channel.mode === 'pair') {
      channel.deadline = later(() => { channel.rejectProof?.(failure('AGENT_PEER_CONNECT_TIMEOUT')); closeChannel(channel); }, handshakeTimeoutMs);
      // Normal peers send their proof immediately, before admission. A probe
      // sends no signed-ready, so it cannot displace the remote healthy peer.
      if (!channel.candidate) tracked(readyFrame(channel, true).catch(cause => { error(cause); closeChannel(channel); }));
    } else channel.deadline = later(() => closeChannel(channel), handshakeTimeoutMs);
    return channel;
  }
  function tlsOptions() {
    return { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', ciphers: CIPHER, honorCipherOrder: true,
      handshakeTimeout: handshakeTimeoutMs };
  }
  function scheduleReconnect(delay = reconnectMs) {
    if (!live || quiescing || reconnectTimer || dialing || !identity.trust()?.endpoint) return;
    reconnectTimer = later(() => { reconnectTimer = null; tracked(connectTrusted().catch(cause => { if (live) { error(cause); scheduleReconnect(); } }), connectionJobs); }, delay);
  }
  async function dial(info, key, endpoint, onSocket) {
    active(); assert(!dialing, 'AGENT_PEER_CONNECTION_PENDING'); dialing = true;
    try {
      return await tracked(new Promise((resolve, reject) => {
        // PSK-only no-certificate branch, not a generic PKIX exception. TLS
        // Finished proves the selected protected key; ECDHE gives forward secrecy.
        let socket, selectedIdentity = null;
        socket = tls.connect({ ...tlsOptions(), ...endpoint, rejectUnauthorized: true,
          checkServerIdentity: (_hostname, certificate) => validateAgentPskServerIdentity({ expectedIdentity: info.pskIdentity,
            selectedIdentity, key, protocol: socket.getProtocol(), cipher: socket.getCipher()?.name, certificate }),
          pskCallback: () => { selectedIdentity = info.pskIdentity; return { identity: info.pskIdentity, psk: key }; } });
        watch(socket); onSocket?.(socket); const timeout = later(() => { socket.destroy(); reject(failure('AGENT_PEER_CONNECT_TIMEOUT')); }, handshakeTimeoutMs);
        socket.once('close', () => { cancel(timeout); reject(failure('AGENT_PEER_DISCONNECTED')); });
        socket.once('error', () => { cancel(timeout); reject(failure('AGENT_PEER_CONNECT_FAILED')); });
        socket.once('secureConnect', () => {
          cancel(timeout);
          try {
            assert(socket.authorized === true, 'AGENT_PEER_AUTHENTICATION_FAILED');
            const rejected = validateAgentPskServerIdentity({ expectedIdentity: info.pskIdentity, selectedIdentity, key,
              protocol: socket.getProtocol(), cipher: socket.getCipher()?.name, certificate: socket.getPeerCertificate(true) });
            if (rejected) throw rejected;
            resolve(attach(socket, info));
          } catch (cause) { socket.destroy(); reject(cause); }
        });
      }), connectionJobs);
    } finally { dialing = false; }
  }
  async function connectTrusted() {
    active(); const trust = identity.trust(); if (!trust?.endpoint || peer) return;
    const local = identity.publicIdentity();
    await dial({ mode: 'pair', role: 'joiner', peerDeviceId: trust.peerDeviceId,
      pskIdentity: `pair:${trust.pairingId}:${local.deviceId}` }, Buffer.from(trust.pairKey, 'hex'), trust.endpoint);
  }
  async function drain(includeConnections = false) {
    // flush drains accepted frames/writes, not a possibly offline reconnect.
    // stop first cancels sockets, then also drains every connection/owner join.
    const work = (async () => {
      while (jobs.size || (includeConnections && connectionJobs.size)) {
        await Promise.allSettled([...jobs, ...(includeConnections ? connectionJobs : [])]);
      }
    })();
    let timer;
    try { await Promise.race([work, new Promise((_, reject) => { timer = later(() => reject(failure('AGENT_PEER_DRAIN_TIMEOUT')), drainTimeoutMs); })]); }
    finally { cancel(timer); }
  }
  function closeNetwork() {
    if (networkClosing) return networkClosing;
    // Capture native close BEFORE destroy; destroyed alone is not a join.
    const closes = [...sockets].map(socket => socket.closed ? Promise.resolve() : new Promise(resolve => socket.once('close', resolve)));
    for (const socket of sockets) socket.destroy();
    const listener = server ? new Promise((resolve, reject) => server.close(cause => {
      if (cause && cause.code !== 'ERR_SERVER_NOT_RUNNING') reject(cause); else resolve();
    })) : Promise.resolve();
    networkClosing = Promise.all([listener, ...closes]); return networkClosing;
  }
  // Start interruption only. Identity/leases remain held until the real final
  // stop has joined native server, sockets, accepted frames and writes.
  function quiesce() {
    if (quiescing) return snapshot();
    quiesceBarrier = beginRuntimeBarrier(runtime, 'transport-stop');
    quiescing = true; localReady = false; localToken = null; peerReady = false; peerToken = null; state = 'quiescing'; notify();
    for (const timer of [...timers]) cancel(timer); reconnectTimer = null;
    for (const channel of channels) channel.rejectJoin?.(failure('AGENT_PEER_STOPPED'));
    for (const socket of sockets) socket.destroy();
    return snapshot();
  }
  const api = {
    start(callbacks = {}) {
      assert(!stopping && !quiescing, 'AGENT_PEER_STOPPED');
      if (starting) return starting;
      assert(typeof callbacks.onMessage === 'function' && typeof callbacks.onAck === 'function', 'AGENT_PEER_CALLBACKS_REQUIRED');
      onMessage = callbacks.onMessage; onAck = callbacks.onAck; state = 'starting';
      starting = (async () => {
        assert(tls.getCiphers().includes(CIPHER.toLowerCase()), 'AGENT_TLS_PSK_UNAVAILABLE');
        await identity.open(); assert(!stopping && !quiescing, 'AGENT_PEER_STOPPED');
        const listener = identity.listener();
        assert(!listener || port === 0 || port === listener.port, 'AGENT_IDENTITY_LISTENER_CONFLICT');
        server = tls.createServer({ ...tlsOptions(), rejectUnauthorized: true, requestCert: false,
          pskCallback(socket, id) {
            try {
              if (!live || quiescing || typeof id !== 'string' || id.length > 128) return null;
              if (id.startsWith('invite:')) {
                const invitationId = id.slice(7), key = identity.invitationKey(invitationId);
                if (key) serverAuth.set(socket, { mode: 'invite', role: 'inviter', invitationId, pskIdentity: id, key }); return key;
              }
              const parts = id.split(':'), trust = identity.trust();
              if (parts.length === 3 && parts[0] === 'pair' && trust?.pairingId === parts[1] && trust.peerDeviceId === parts[2]) {
                const key = Buffer.from(trust.pairKey, 'hex');
                serverAuth.set(socket, { mode: 'pair', role: 'inviter', peerDeviceId: trust.peerDeviceId, pskIdentity: id, key }); return key;
              }
            } catch {} return null;
          } }, socket => {
          try {
            const info = serverAuth.get(socket); assert(info, 'AGENT_PEER_AUTHENTICATION_FAILED');
            const rejected = validateAgentPskServerIdentity({ expectedIdentity: info.pskIdentity, selectedIdentity: info.pskIdentity,
              key: info.key, protocol: socket.getProtocol(), cipher: socket.getCipher()?.name, certificate: socket.getPeerCertificate(true) });
            if (rejected) throw rejected;
            const { key, ...channelInfo } = info; serverAuth.delete(socket); attach(socket, channelInfo);
          } catch (cause) { error(cause); socket.destroy(); }
        });
        server.maxConnections = 8; server.on('connection', watch); server.on('tlsClientError', () => {});
        server.on('error', cause => { if (started && live) error(cause); });
        await new Promise((resolve, reject) => {
          const failed = cause => { server.removeListener('listening', listened); reject(cause.code === 'EADDRINUSE' ? failure('AGENT_PEER_PORT_IN_USE') : cause); };
          const listened = () => { server.removeListener('error', failed); resolve(); };
          server.once('error', failed); server.once('listening', listened); server.listen({ host, port: listener?.port ?? port });
        });
        assert(!stopping && !quiescing, 'AGENT_PEER_STOPPED');
        const actual = readAgentPeerListener(server, true); assert(actual.port !== null, 'AGENT_IDENTITY_LISTENER_INVALID');
        identity.pinListener(actual.port); // Durable commit precedes admission and all publication.
        live = true; active(); started = true; state = identity.snapshot().paired ? 'paired' : 'listening'; notify(); scheduleReconnect(0); return snapshot();
      })().catch(async cause => {
        const rootCause = failures.capture(cause, { stage: 'transport-start', origin: 'peer', lifecycle: 'start' });
        live = false; state = 'failed'; for (const timer of [...timers]) cancel(timer); reconnectTimer = null;
        // Do not call stop here: stop joins starting, which is this promise.
        try { await closeNetwork(); await drain(true); }
        catch (cleanup) { throw brandAgentFailure(error(cleanup), { rootCause }); }
        throw brandAgentFailure(error(cause), { rootCause });
      });
      return starting;
    },
    async createInvitation(options = {}, authorization) {
      owner(authorization); const invitation = identity.createInvitation(options);
      const encoded = 'dtagent1.' + Buffer.from(JSON.stringify(invitation)).toString('base64url'); notify();
      return Object.freeze({ invitation: encoded, expiresAt: invitation.expiresAt, deviceId: invitation.deviceId,
        fingerprint: identity.snapshot().fingerprint, port: server.address().port });
    },
    async connectInvitation({ invitation, host: peerHost, port: peerPort } = {}, authorization) {
      owner(authorization); assert(!identity.trust() && !identity.pending(), 'AGENT_PAIR_ALREADY_PRESENT');
      assert(typeof invitation === 'string' && invitation.length <= 4096 && /^dtagent1\.[A-Za-z0-9_-]+$(?![\s\S])/.test(invitation), 'AGENT_INVITATION_INVALID');
      let decoded; try { decoded = JSON.parse(Buffer.from(invitation.slice(9), 'base64url').toString('utf8')); } catch { throw failure('AGENT_INVITATION_INVALID'); }
      assert(exact(decoded, ['version', 'invitationId', 'key', 'expiresAt', 'deviceId', 'publicKey']) && decoded.version === 1
        && UUID.test(decoded.invitationId) && HEX.test(decoded.key) && UUID.test(decoded.deviceId) && decoded.deviceId !== identity.publicIdentity().deviceId
        && Number.isSafeInteger(decoded.expiresAt) && decoded.expiresAt > now() && decoded.expiresAt - now() <= 300000, 'AGENT_INVITATION_INVALID');
      const endpoint = validateAgentPeerEndpoint({ host: peerHost, port: peerPort });
      const channel = await dial({ mode: 'invite', role: 'joiner', invitation: decoded, endpoint, pskIdentity: `invite:${decoded.invitationId}` }, Buffer.from(decoded.key, 'hex'), endpoint);
      const joined = tracked(new Promise((resolve, reject) => { channel.resolveJoin = resolve; channel.rejectJoin = reject; }), connectionJobs);
      joined.catch(() => {}); // The socket may close while its first encrypted write is awaited.
      channel.nonce = randomBytes(32).toString('hex');
      await signed(channel, 'pair.hello', { invitationId: decoded.invitationId, ...identity.publicIdentity(), nonce: channel.nonce });
      return joined;
    },
    updateEndpoint({ pairingId, host: peerHost, port: peerPort } = {}, authorization, signal) {
      owner(authorization); const captured = identity.trust();
      assert(captured && captured.pairingId === pairingId, 'AGENT_PEER_ENDPOINT_STALE');
      const endpoint = validateAgentPeerEndpoint({ host: peerHost, port: peerPort });
      const guard = () => { owner(authorization); assert(!signal?.aborted, 'AGENT_OWNER_ACTION_RETIRED'); };
      guard(); cancel(reconnectTimer); reconnectTimer = null;
      return tracked((async () => {
        let socket, channel, closed, committed = false;
        const aborted = () => socket?.destroy();
        try {
          const local = identity.publicIdentity();
          channel = await dial({ mode: 'pair', role: 'joiner', candidate: true, peerDeviceId: captured.peerDeviceId,
            pskIdentity: `pair:${captured.pairingId}:${local.deviceId}` }, Buffer.from(captured.pairKey, 'hex'), endpoint, owned => {
            socket = owned; closed = new Promise(resolve => owned.once('close', resolve));
            signal?.addEventListener('abort', aborted, { once: true }); if (signal?.aborted) aborted();
          });
          await channel.proof; await channel.chain;
          guard(); assert(!channel.socket.destroyed && channel.authenticated, 'AGENT_PEER_DISCONNECTED');
          identity.updateEndpoint(captured, endpoint); committed = true;
          return snapshot();
        } finally {
          signal?.removeEventListener('abort', aborted);
          if (channel) closeChannel(channel); else socket?.destroy();
          if (closed) await closed;
          // Only this probe's accepted frame chain, never a set containing this job.
          if (channel) await channel.chain;
          if (committed) scheduleReconnect(0); else if (live && !quiescing) scheduleReconnect();
        }
      })(), connectionJobs);
    },
    async approvePairing({ pairingId } = {}, authorization) {
      owner(authorization); assert(typeof pairingId === 'string' && UUID.test(pairingId), 'AGENT_PAIRING_INVALID');
      if (identity.trust()?.pairingId === pairingId) return snapshot();
      const channel = pairChannels.get(pairingId), pending = identity.pending();
      assert(channel && !channel.socket.destroyed && pending?.pairingId === pairingId, 'AGENT_PAIRING_INVALID');
      assert(pending.expiresAt > now(), 'AGENT_PAIRING_EXPIRED');
      if (pending.localApproved) return snapshot();
      identity.approveLocal(pairingId); notify();
      await signed(channel, 'pair.approve', { pairingId, generation: pending.generation, deviceId: identity.publicIdentity().deviceId });
      await maybeCommit(channel); return snapshot();
    },
    async rejectPairing({ pairingId } = {}, authorization) {
      owner(authorization); const channel = pairChannels.get(pairingId); identity.rejectPairing(pairingId);
      if (channel) closeChannel(channel); state = 'listening'; notify(); return snapshot();
    },
    async forgetPairing({ pairingId } = {}, authorization) {
      owner(authorization); identity.forgetPairing(pairingId); localReady = false; localToken = null;
      // Trust is gone; retire the active reference before the asynchronous socket close.
      if (peer) closeChannel(peer); peer = null; peerReady = false; peerToken = null; state = 'listening'; notify(); return snapshot();
    },
    async setTargetReadiness(value, authorization) {
      const valid = exact(value, ['ready', 'localTargetToken']) && typeof value.ready === 'boolean'
        && (value.ready ? typeof value.localTargetToken === 'string' && HEX.test(value.localTargetToken) : value.localTargetToken === null);
      // The actual validated method input selects the purpose, never a caller flag.
      owner(authorization, valid && value.ready === false ? 'retire-readiness' : 'operation');
      assert(valid, 'AGENT_PEER_READINESS_INVALID');
      if (localReady !== value.ready || localToken !== value.localTargetToken) { localReady = value.ready; localToken = value.localTargetToken; notify(); }
      if (!quiescing && peer) {
        try { await readyFrame(peer); }
        catch (cause) { if (!quiescing || value.ready !== false) throw cause; }
      }
      return snapshot();
    },
    async send(row, valueScope) {
      active(); const message = wireMessage(row), scope = validateAgentMessageScope(valueScope), current = currentScope(), channel = peer;
      assert(current && same(scope, current) && channel, 'AGENT_PEER_NOT_READY');
      assert(channel.sent.size < 64 || channel.sent.has(message.id), 'AGENT_PEER_BACKPRESSURE');
      const existing = channel.sent.get(message.id) ?? channel.acknowledged.get(message.id);
      assert(!existing || (same(existing.message, message) && same(existing.scope, scope)), 'AGENT_PEER_MESSAGE_CONFLICT');
      channel.sent.set(message.id, { message, scope });
      await write(channel, { type: 'message', message, scope }); return Object.freeze({ sent: true, id: message.id });
    },
    stop() {
      if (stopping) return stopping;
      let barrier;
      try { quiesce(); barrier = quiesceBarrier; }
      catch (cause) {
        const rootCause = failures.capture(cause, { stage: 'transport-stop', origin: 'peer', lifecycle: 'stop' });
        failRuntimeBarrier(runtime, barrier, cause, 'transport-stop'); return Promise.reject(brandAgentFailure(cause, { rootCause }));
      }
      live = false; localReady = false; localToken = null; peerReady = false; peerToken = null; state = 'stopping'; notify();
      for (const timer of [...timers]) cancel(timer); reconnectTimer = null;
      for (const channel of channels) channel.rejectJoin?.(failure('AGENT_PEER_STOPPED'));
      for (const socket of sockets) socket.destroy();
      stopping = (async () => {
        if (starting) { try { await starting; } catch {} }
        await closeNetwork(); await drain(true); await identity.close(); barrier?.complete(); state = 'stopped'; notify();
      })().catch(cause => {
        const rootCause = failures.capture(cause, { stage: 'transport-stop', origin: 'peer', lifecycle: 'stop' });
        failRuntimeBarrier(runtime, barrier, cause, 'transport-stop'); state = 'failed'; throw brandAgentFailure(error(cause), { rootCause });
      });
      return stopping;
    },
    async flush() { assert(live && !stopping, 'AGENT_PEER_STOPPED'); await drain(); await identity.flush(); return snapshot(); },
    quiesce,
    currentScope,
    subscribe(listener) { assert(typeof listener === 'function', 'AGENT_PEER_LISTENER_INVALID'); subscribers.add(listener); return () => subscribers.delete(listener); },
    snapshot,
    getSnapshot: snapshot,
  };
  return Object.freeze(api);
}

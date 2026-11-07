// One immutable private-root enrollment. No business migration or weak OS fallback.
// Effects use Runtime's original anchored broker; historical bytes are never rewritten.
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

const LIMIT = 4 * 1024 * 1024;
const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const ANCHOR = /^root-anchor-([0-9a-f]{64})\.json$/;
const COMMIT = /^commit-root-([0-9a-f]{64})$/;
const JOURNAL = /^journal(?:\.jsonl|-segment-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.jsonl)$/;
const sha = raw => createHash('sha256').update(raw).digest('hex');
const bytesOf = value => Buffer.from(JSON.stringify(value) + '\n');
const clone = value => structuredClone(value);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
function refuse(code) { throw Object.assign(new Error(code), { code }); }
const U64 = value => typeof value === 'string' && /^(?:0|[1-9]\d{0,19})$/.test(value) && BigInt(value) <= 0xffffffffffffffffn;
const FILE_ID = value => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value) && value !== '0'.repeat(32);
const stableIdentity = value => ({ dev: value.dev, ino: value.ino, birth: value.birth });
const scope = (platform, boot) => platform === 'win32'
  ? 'windows-kernel:' + boot + ':global-mutex:host-silo:0' : 'darwin-kernel:' + boot;
function id(value, platform) {
  if (platform === 'win32') {
    if (!exact(value, ['dev', 'ino', 'birth', 'nodeDev', 'nodeIno', 'nodeBirth', 'nativeFileId'])
      || !['dev', 'birth', 'nodeDev', 'nodeIno', 'nodeBirth'].every(key => U64(value[key]))
      || !FILE_ID(value.ino) || value.nativeFileId !== value.ino
      || value.birth === '0' || value.nodeIno === '0' || value.nodeBirth === '0') refuse('OWNER_ROOT_IDENTITY');
    return { ...value };
  }
  if (!exact(value, ['dev', 'ino', 'birth']) || !Object.values(value).every(U64)
    || value.ino === '0' || value.birth === '0') refuse('OWNER_ROOT_IDENTITY');
  return stableIdentity(value);
}
function nativeRoot(value) {
  if (!exact(value, ['protocol', 'platform', 'machineId', 'volumeId', 'boot', 'identity', 'persistentFileIds'])
    || value.protocol !== 'dsh-owner-root-evidence-v1' || !['darwin', 'win32'].includes(value.platform)
    || !['machineId', 'volumeId', 'boot'].every(key => UUID.test(value[key] ?? '') && value[key] !== '00000000-0000-0000-0000-000000000000')
    || value.persistentFileIds !== true) refuse('OWNER_ROOT_IDENTITY');
  if (value.platform === 'win32') {
    if (!exact(value.identity, ['dev', 'ino', 'birth']) || !U64(value.identity.dev)
      || !FILE_ID(value.identity.ino) || !U64(value.identity.birth) || value.identity.birth === '0') refuse('OWNER_ROOT_IDENTITY');
  } else id(value.identity, 'darwin');
  return value;
}
function boundary(value, platform) {
  if (!exact(value, ['basename', 'identity', 'bytes', 'sha256', 'lastSequence', 'lastRecordHash'])
    || !JOURNAL.test(value.basename ?? '') || !Number.isSafeInteger(value.bytes) || value.bytes < 1 || value.bytes > LIMIT
    || !HASH.test(value.sha256 ?? '') || !Number.isSafeInteger(value.lastSequence) || value.lastSequence < 1
    || !HASH.test(value.lastRecordHash ?? '')) refuse('OWNER_ROOT_BOUNDARY');
  id(value.identity, platform);
  return value;
}

export function createOwnerRoot({ rootId, bootstrap, evidence, controlIdentity, guardScope,
  legacyOrigin, inspectFile, createFile, listNames, effect }) {
  nativeRoot(evidence);
  const platform = evidence.platform;
  id(controlIdentity, platform); id(bootstrap.identity, platform); id(bootstrap.value.rootIdentity, platform);
  const historicalScope = platform === 'win32'
    ? /^windows-kernel:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}:global-mutex:host-silo:0$/
    : /^darwin-kernel:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
  if (guardScope !== scope(platform, evidence.boot) || !historicalScope.test(bootstrap.value.guardScope ?? '')
    || (platform === 'win32' && legacyOrigin !== undefined)) refuse('OWNER_ROOT_IDENTITY');
  let anchor = null, anchorHash = null, anchorFile = null, marker = null;
  let mapped = false, seenBoundary = false, fault = null, candidate = null;
  function physicalIdentity(value) {
    const checked = id(value, platform);
    return mapped && platform === 'darwin' ? { ...checked, dev: evidence.identity.dev } : checked;
  }
  const sameIdentity = (a, b) => isDeepStrictEqual(physicalIdentity(a), physicalIdentity(b));
  function sameBoundary(a, b) {
    return sameIdentity(a.identity, b.identity) && isDeepStrictEqual({ ...a, identity: b.identity }, b);
  }
  function origin(value) {
    if (!exact(value, ['protocol', 'rootId', 'bootstrapSha256', 'guardScope', 'baselineSha256', 'operatorSource', 'boundary'])
      || value.protocol !== 'dsh-owner-legacy-origin-v1' || value.rootId !== rootId
      || value.bootstrapSha256 !== bootstrap.sha256 || value.guardScope !== bootstrap.value.guardScope
      || !HASH.test(value.baselineSha256 ?? '') || typeof value.operatorSource !== 'string'
      || !value.operatorSource.trim() || value.operatorSource.length > 512 || /[\x00-\x1f\x7f]/.test(value.operatorSource)) refuse('OWNER_ROOT_INPUT');
    boundary(value.boundary, platform);
    return clone(value);
  }
  const explicitOrigin = legacyOrigin === undefined ? null : origin(legacyOrigin);
  function read(name, expected, expectedHash) {
    const result = inspectFile(name, expected, expectedHash);
    if (!object(result) || !Buffer.isBuffer(result.raw) || result.raw.length !== result.bytes
      || result.bytes > LIMIT || sha(result.raw) !== result.sha256) refuse('OWNER_ROOT_ANCHOR');
    id(result.identity, platform);
    return { ...result, basename: name };
  }
  function source(value) {
    if (exact(value, ['kind']) && ['new-root-native', 'same-boot-native'].includes(value.kind)) return;
    if (!exact(value, ['kind', 'origin']) || value.kind !== 'operator-confirmed') refuse('OWNER_ROOT_ANCHOR');
    origin(value.origin);
  }
  function checkAnchor(value) {
    if (!exact(value, ['protocol', 'rootId', 'bootstrap', 'root', 'controlIdentity', 'guardScope', 'source', 'boundary'])
      || value.protocol !== 'dsh-owner-root-anchor-v1' || value.rootId !== rootId
      || !exact(value.bootstrap, ['identity', 'bytes', 'sha256', 'rawBase64'])
      || value.bootstrap.bytes !== bootstrap.bytes || value.bootstrap.sha256 !== bootstrap.sha256
      || value.bootstrap.rawBase64 !== bootstrap.raw.toString('base64')) refuse('OWNER_ROOT_ANCHOR');
    nativeRoot(value.root); source(value.source); boundary(value.boundary, platform);
    id(value.bootstrap.identity, platform); id(value.controlIdentity, platform);
    if (value.root.platform !== platform || value.guardScope !== scope(platform, value.root.boot)
      || value.root.machineId !== evidence.machineId || value.root.volumeId !== evidence.volumeId
      || value.root.identity.ino !== evidence.identity.ino || value.root.identity.birth !== evidence.identity.birth
      || bootstrap.value.rootIdentity.ino !== evidence.identity.ino || bootstrap.value.rootIdentity.birth !== evidence.identity.birth
      || (platform === 'win32' && (value.root.identity.dev !== evidence.identity.dev
        || bootstrap.value.rootIdentity.dev !== evidence.identity.dev || value.source.kind === 'operator-confirmed'))) refuse('OWNER_ROOT_IDENTITY');
    if (value.source.kind !== 'operator-confirmed' && (value.guardScope !== bootstrap.value.guardScope
      || !isDeepStrictEqual(value.root.identity, stableIdentity(id(bootstrap.value.rootIdentity, platform))))) refuse('OWNER_ROOT_ANCHOR');
    mapped = true;
    if (!sameIdentity(value.bootstrap.identity, bootstrap.identity) || !sameIdentity(value.controlIdentity, controlIdentity)) refuse('OWNER_ROOT_IDENTITY');
    if (value.source.kind === 'operator-confirmed' && !sameBoundary(value.source.origin.boundary, value.boundary)) refuse('OWNER_ROOT_BOUNDARY');
  }
  function load() {
    const anchors = [], markers = [];
    for (const name of listNames()) {
      if (name.startsWith('root-anchor-')) {
        if (!ANCHOR.test(name)) refuse('OWNER_ROOT_LAYOUT');
        anchors.push(name);
      }
      if (name.startsWith('commit-root-')) {
        if (!COMMIT.test(name)) refuse('OWNER_ROOT_LAYOUT');
        markers.push(name);
      }
    }
    if (anchors.length > 1 || markers.length > 1 || (markers.length && !anchors.length)) refuse('OWNER_ROOT_COMMIT');
    if (!anchors.length) {
      if (explicitOrigin) {
        if (bootstrap.value.rootIdentity.ino !== evidence.identity.ino || bootstrap.value.rootIdentity.birth !== evidence.identity.birth) refuse('OWNER_ROOT_IDENTITY');
        mapped = true; // Explicit operator origin, NOT historical Native evidence.
      } else if (bootstrap.value.guardScope !== guardScope
        || !isDeepStrictEqual(stableIdentity(id(bootstrap.value.rootIdentity, platform)), evidence.identity)) {
        refuse('OWNER_ROOT_ORIGIN_REQUIRED');
      }
      return;
    }
    anchorFile = read(anchors[0]);
    anchorHash = ANCHOR.exec(anchors[0])[1];
    try { anchor = JSON.parse(anchorFile.raw.toString('utf8')); } catch { refuse('OWNER_ROOT_ANCHOR'); }
    if (anchorFile.sha256 !== anchorHash || !bytesOf(anchor).equals(anchorFile.raw)) refuse('OWNER_ROOT_ANCHOR');
    checkAnchor(anchor);
    if (markers.length) {
      if (markers[0] !== 'commit-root-' + anchorHash) refuse('OWNER_ROOT_COMMIT');
      marker = read(markers[0]);
      if (marker.bytes !== 0) refuse('OWNER_ROOT_COMMIT');
    } else {
      // Staging is resumable only in the SAME enrollment scope, not evidence for
      // a new boot or a new dev. An operator staging never grants implicit consent.
      if (anchor.guardScope !== guardScope || !isDeepStrictEqual(anchor.root, evidence)
        || !isDeepStrictEqual(anchor.controlIdentity, controlIdentity)
        || !isDeepStrictEqual(anchor.bootstrap.identity, bootstrap.identity)
        || (anchor.source.kind === 'operator-confirmed' && !isDeepStrictEqual(anchor.source.origin, explicitOrigin))) refuse('OWNER_ROOT_COMMIT');
    }
  }
  function record(value, checkpoint, prefix) {
    const recorded = value.state;
    const recordedDev = id(recorded.rootIdentity, platform).dev;
    const inScope = identity => id(identity, platform).dev === recordedDev;
    if (!inScope(recorded.bootstrapIdentity)
      || Object.values(recorded.parents).some(identity => !inScope(identity))
      || Object.values(recorded.entries).some(entry => !inScope(entry.identity) || !inScope(entry.parent))
      || (!checkpoint && (recorded.journalIdentity === null
        ? value.sequence !== 1 || value.event !== 'initialize' || recorded.phase !== 'initializing'
        : !inScope(recorded.journalIdentity)))) refuse('OWNER_ROOT_IDENTITY');
    const reference = value.state?.rootAnchor;
    if (!anchor) {
      if (reference !== undefined) refuse('OWNER_ROOT_COMMIT');
    } else {
      const enrolled = anchor.boundary;
      if (value.sequence === enrolled.lastSequence) {
        if (value.hash !== enrolled.lastRecordHash || !sameBoundary(enrolled, prefix(enrolled.bytes))) refuse('OWNER_ROOT_BOUNDARY');
        seenBoundary = true;
      }
      if (value.sequence <= enrolled.lastSequence) {
        if (reference !== undefined) refuse('OWNER_ROOT_BINDING');
      } else if (!marker || (!checkpoint && reference !== anchorHash)
        || (checkpoint && reference !== undefined && reference !== anchorHash)) refuse('OWNER_ROOT_BINDING');
    }
    const owner = value.state?.owner;
    if (owner !== null) {
      if (!object(owner) || owner.protocol !== 'dsh-owner-native-v1' || owner.platform !== platform
        || !UUID.test(owner.boot ?? '') || owner.guardScope !== scope(platform, owner.boot)
        || !UUID.test(value.state.runId ?? '')) refuse('OWNER_MEMBER_INSTANCE_MISMATCH');
      if ((!anchor || value.sequence <= anchor.boundary.lastSequence) && owner.guardScope !== bootstrap.value.guardScope) refuse('OWNER_ROOT_BINDING');
    }
  }
  function finish(actualBoundary) {
    boundary(actualBoundary, platform);
    if (anchor && (!seenBoundary || (!marker && !sameBoundary(anchor.boundary, actualBoundary)))) refuse('OWNER_ROOT_BOUNDARY');
    if (explicitOrigin && !anchor && !sameBoundary(explicitOrigin.boundary, actualBoundary)) refuse('OWNER_ROOT_BOUNDARY');
  }
  function prepare(actualBoundary, createdBootstrap) {
    finish(actualBoundary);
    if (marker) return null;
    if (!anchor) {
      anchor = { protocol: 'dsh-owner-root-anchor-v1', rootId,
        bootstrap: { identity: clone(bootstrap.identity), bytes: bootstrap.bytes, sha256: bootstrap.sha256,
          rawBase64: bootstrap.raw.toString('base64') }, root: clone(evidence), controlIdentity: clone(controlIdentity), guardScope,
        source: explicitOrigin ? { kind: 'operator-confirmed', origin: explicitOrigin }
          : { kind: createdBootstrap ? 'new-root-native' : 'same-boot-native' }, boundary: clone(actualBoundary) };
      const raw = bytesOf(anchor);
      if (raw.length > LIMIT) refuse('OWNER_JOURNAL_LIMIT');
      anchorHash = sha(raw);
      candidate = { raw, hash: anchorHash, basename: 'root-anchor-' + anchorHash + '.json' };
    } else candidate = { raw: anchorFile.raw, hash: anchorHash, basename: anchorFile.basename };
    return { hash: candidate.hash, bytes: candidate.raw.length };
  }
  function publish() {
    if (fault || marker || !candidate) refuse('OWNER_ROOT_TRANSITION_UNCERTAIN');
    effect(); // Before even O_EXCL staging. Every failure retains the caller's guard.
    try {
      if (!anchorFile) {
        const created = createFile(candidate.basename, candidate.raw);
        anchorFile = read(candidate.basename, created.identity, sha(candidate.raw));
      } else anchorFile = read(anchorFile.basename, anchorFile.identity, anchorFile.sha256);
      if (!anchorFile.raw.equals(candidate.raw)) refuse('OWNER_ROOT_ANCHOR');
      const name = 'commit-root-' + anchorHash;
      const created = createFile(name, Buffer.alloc(0));
      marker = read(name, created.identity, sha(Buffer.alloc(0)));
      if (marker.bytes !== 0) refuse('OWNER_ROOT_COMMIT');
      mapped = true;
    } catch (error) { fault = error; throw error; }
  }
  function assertWritable(value) {
    if (fault || !marker || value.rootAnchor !== anchorHash) refuse('OWNER_ROOT_TRANSITION_UNCERTAIN');
    try {
      const currentAnchor = read(anchorFile.basename, anchorFile.identity, anchorHash);
      const currentMarker = read(marker.basename, marker.identity, marker.sha256);
      if (!currentAnchor.raw.equals(anchorFile.raw) || currentMarker.bytes !== 0) refuse('OWNER_ROOT_COMMIT');
    } catch (error) { fault = error; throw error; }
  }
  function liveState(value) {
    const next = clone(value);
    for (const key of ['rootIdentity', 'bootstrapIdentity', 'journalIdentity']) next[key] = physicalIdentity(next[key]);
    for (const [name, expected] of Object.entries(next.parents)) next.parents[name] = physicalIdentity(expected);
    for (const entry of Object.values(next.entries)) {
      entry.identity = physicalIdentity(entry.identity); entry.parent = physicalIdentity(entry.parent);
    }
    if (marker) next.rootAnchor = anchorHash;
    return next;
  }
  return Object.freeze({ load, record, finish, prepare, publish, assertWritable, physicalIdentity, sameIdentity, liveState,
    markerName: () => marker?.basename ?? null, hash: () => marker ? anchorHash : null,
    stableRoot: () => anchor?.root ?? (explicitOrigin ? evidence : null) });
}

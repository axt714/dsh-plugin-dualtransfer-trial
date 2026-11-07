// Private ownership journal codec/segmentation. All effects remain in the
// original Runtime's anchored native/broker operations, never pathname writes.
import { createHash, randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

const PROTOCOL = 'dsh-owner-set-v2';
const LIMIT = 4 * 1024 * 1024;
const LEGACY = 'journal.jsonl';
const ZERO = '0'.repeat(64);
const UUID = '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}';
const SEGMENT = new RegExp(`^journal-segment-(${UUID})\\.jsonl$`);
const ARCHIVE = new RegExp(`^journal-archive-(${UUID})\\.jsonl$`);
const COMMIT = new RegExp(`^commit-([0-9a-f]{16})-(${UUID})-([0-9a-f]{64})$`);
const HASH = /^[0-9a-f]{64}$/;
const ID_KEYS = ['dev', 'ino', 'birth'];
const BRIDGE_KEYS = ['nodeDev', 'nodeIno', 'nodeBirth', 'nativeFileId'];
// Conservatively include the Windows bridge even on Darwin. These are the
// original adapter's finite ASCII field bounds, not guessed future inode ids.
const BOUND_ID = Object.freeze({ dev: 'x'.repeat(128), ino: 'x'.repeat(128), birth: 'x'.repeat(128),
  nodeDev: '9'.repeat(32), nodeIno: '9'.repeat(32), nodeBirth: '9'.repeat(32), nativeFileId: 'f'.repeat(32) });
const BOUND_UUID = '00000000-0000-0000-0000-000000000000';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const bytesOf = value => Buffer.from(JSON.stringify(value) + '\n');
const clone = value => structuredClone(value);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function refuse(code) { throw Object.assign(new Error(code), { code }); }
function exact(value, names) {
  return object(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
}
function identity(value) {
  const bridge = BRIDGE_KEYS.some(key => Object.hasOwn(value ?? {}, key));
  if (!exact(value, bridge ? [...ID_KEYS, ...BRIDGE_KEYS] : ID_KEYS)
    || !ID_KEYS.every(key => typeof value[key] === 'string' && /^[A-Za-z0-9:.-]{1,128}$/.test(value[key]))
    || (bridge && (!BRIDGE_KEYS.slice(0, 3).every(key => typeof value[key] === 'string' && /^\d{1,32}$/.test(value[key]))
      || !/^[0-9a-f]{32}$/.test(value.nativeFileId ?? '')))) refuse('OWNER_FILE_EVIDENCE_INVALID');
  return Object.fromEntries((bridge ? [...ID_KEYS, ...BRIDGE_KEYS] : ID_KEYS).map(key => [key, value[key]]));
}
function safeNext(value, amount = 1) {
  if (!Number.isSafeInteger(value) || value < 0 || !Number.isSafeInteger(value + amount)) refuse('OWNER_JOURNAL_SEQUENCE');
  return value + amount;
}
function lines(raw) {
  if (!Buffer.isBuffer(raw) || !raw.length || raw.length > LIMIT || raw.at(-1) !== 10) refuse('OWNER_JOURNAL_PARTIAL');
  const text = raw.toString('utf8');
  if (!Buffer.from(text).equals(raw)) refuse('OWNER_JOURNAL_INVALID');
  return text.split('\n').slice(0, -1);
}
function parse(text) {
  try { const value = JSON.parse(text); if (object(value)) return value; } catch { /* Fixed refusal below. */ }
  refuse('OWNER_JOURNAL_INVALID');
}

export function createOwnerJournal({ rootId, parentIdentity, inspectFile, createFile, appendFile,
  closeFile, listNames, effect, validateState, physicalIdentity = value => value,
  rootMarkerName = () => null, validateRecord = () => {} }) {
  const parent = identity(parentIdentity);
  let active = null, index = 0, sequence = 0, recordHash = ZERO;
  let lastCommittedState = null, fenced = false, selectedMarker = null, fault = null;
  let persisting = false, transitioning = false;
  function writable() { if (fault) refuse('OWNER_JOURNAL_TRANSITION_UNCERTAIN'); }
  function sameIdentity(a, b) {
    return isDeepStrictEqual(physicalIdentity(identity(a)), physicalIdentity(identity(b)));
  }
  function sameDescriptor(recorded, actual) {
    return object(recorded) && sameIdentity(recorded.identity, actual.identity)
      && isDeepStrictEqual({ ...recorded, identity: actual.identity }, actual);
  }
  function recordPrefix(current, end, record, fencedEnd = false) {
    return wanted => {
      if (wanted !== end && !(fencedEnd && wanted === current.bytes)) refuse('OWNER_ROOT_BOUNDARY');
      return { ...descriptor(current, record.sequence, record.hash), bytes: wanted,
        sha256: sha(current.raw.subarray(0, wanted)) };
    };
  }

  function file(basename, result, expectedRaw) {
    if (!object(result) || !Number.isSafeInteger(result.bytes) || result.bytes < 0 || result.bytes > LIMIT
      || !HASH.test(result.sha256 ?? '')) refuse('OWNER_FILE_EVIDENCE_INVALID');
    const raw = expectedRaw ?? result.raw;
    if (!Buffer.isBuffer(raw) || raw.length !== result.bytes || sha(raw) !== result.sha256) refuse('OWNER_FILE_EVIDENCE_INVALID');
    return { basename, identity: identity(result.identity), bytes: raw.length, sha256: result.sha256, raw };
  }
  function inspect(basename, expected, expectedHash, retain = false) {
    const value = file(basename, inspectFile(basename, expected, expectedHash, retain));
    if ((expected && !sameIdentity(value.identity, expected))
      || (expectedHash && value.sha256 !== expectedHash)) refuse('OWNER_FILE_EVIDENCE_INVALID');
    return value;
  }
  function create(basename, raw, retain = false) {
    writable();
    if (!Buffer.isBuffer(raw) || raw.length > LIMIT) refuse('OWNER_JOURNAL_LIMIT');
    effect();
    const result = createFile(basename, raw, retain);
    writable();
    return file(basename, result, raw);
  }
  function append(current, raw) {
    writable();
    const wanted = Buffer.concat([current.raw, raw]);
    if (wanted.length > LIMIT) refuse('OWNER_JOURNAL_LIMIT');
    effect();
    const result = appendFile(current.basename, current.identity, current.sha256, raw);
    writable();
    const value = file(current.basename, result, wanted);
    if (!isDeepStrictEqual(value.identity, current.identity)) refuse('OWNER_JOURNAL_IDENTITY');
    return value;
  }
  function descriptor(current, lastSequence = sequence, lastRecordHash = recordHash) {
    return { basename: current.basename, identity: clone(current.identity), bytes: current.bytes,
      sha256: current.sha256, lastSequence, lastRecordHash };
  }
  function encode(event, state, next, previous, headerHash) {
    const payload = { schema: headerHash === undefined ? 2 : 3, protocol: PROTOCOL, rootId,
      sequence: next, previous, event, ...(headerHash === undefined ? {} : { headerHash }), state: clone(state) };
    const hash = sha(Buffer.from(JSON.stringify(payload)));
    return { raw: bytesOf({ ...payload, hash }), hash, state: payload.state, sequence: next };
  }
  function decode(record, expectedSequence, previous, checkpoint = false, prefix) {
    const { hash, ...payload } = record;
    if (record.schema !== (checkpoint ? 3 : 2) || record.protocol !== PROTOCOL || record.rootId !== rootId
      || record.sequence !== expectedSequence || !Number.isSafeInteger(record.sequence)
      || record.previous !== previous || !HASH.test(hash ?? '')
      || sha(Buffer.from(JSON.stringify(payload))) !== hash) refuse('OWNER_JOURNAL_CHAIN');
    validateState(record.state);
    validateRecord(record, checkpoint, prefix);
    return { state: record.state, hash, sequence: record.sequence };
  }
  function fenceValue(prefix, archive) {
    return { schema: 3, protocol: PROTOCOL, kind: 'migration-fence', rootId,
      journalIdentity: clone(prefix.identity), prefix: { bytes: prefix.bytes, sha256: prefix.sha256,
        lastSequence: prefix.lastSequence, lastRecordHash: prefix.lastRecordHash }, archive };
  }
  function boundFence(prefix) {
    return bytesOf(fenceValue(prefix, { basename: `journal-archive-${BOUND_UUID}.jsonl`,
      identity: BOUND_ID, bytes: prefix.bytes, sha256: prefix.sha256 }));
  }
  function checkFence(value, line, legacy, prefixRaw, tip) {
    if (!exact(value, ['schema', 'protocol', 'kind', 'rootId', 'journalIdentity', 'prefix', 'archive'])
      || value.schema !== 3 || value.protocol !== PROTOCOL || value.kind !== 'migration-fence' || value.rootId !== rootId
      || !exact(value.prefix, ['bytes', 'sha256', 'lastSequence', 'lastRecordHash'])
      || !exact(value.archive, ['basename', 'identity', 'bytes', 'sha256'])
      || !ARCHIVE.test(value.archive.basename ?? '')) refuse('OWNER_JOURNAL_FENCE_INVALID');
    const recordedIdentity = identity(value.journalIdentity);
    if (!sameIdentity(recordedIdentity, legacy.identity)) refuse('OWNER_JOURNAL_FENCE_INVALID');
    // Construct canonical bytes with the ORIGINAL identities, not today's dev.
    const prefix = { ...descriptor(legacy, tip.sequence, tip.hash), identity: recordedIdentity,
      bytes: prefixRaw.length, sha256: sha(prefixRaw) };
    const archive = { basename: value.archive.basename, identity: identity(value.archive.identity),
      bytes: prefix.bytes, sha256: prefix.sha256 };
    if (recordedIdentity.dev !== archive.identity.dev) refuse('OWNER_JOURNAL_FENCE_INVALID');
    const expected = fenceValue(prefix, archive);
    if (!isDeepStrictEqual(value, expected) || !bytesOf(expected).equals(line)) refuse('OWNER_JOURNAL_FENCE_INVALID');
    const evidence = inspect(archive.basename, archive.identity, archive.sha256);
    if (evidence.bytes !== archive.bytes || !evidence.raw.equals(prefixRaw)) refuse('OWNER_JOURNAL_FENCE_INVALID');
  }
  function metadataNames() {
    const names = listNames();
    const markers = [];
    for (const name of names) {
      if (typeof name !== 'string') refuse('OWNER_JOURNAL_LAYOUT');
      if (name.startsWith('journal-segment-') && !SEGMENT.test(name)) refuse('OWNER_JOURNAL_LAYOUT');
      if (name.startsWith('journal-archive-') && !ARCHIVE.test(name)) refuse('OWNER_JOURNAL_LAYOUT');
      if (!name.startsWith('commit-')) continue;
      // Only the one immutable root marker already verified by Runtime is exempt.
      // The original C69 reader deliberately rejects this reserved commit prefix.
      if (name === rootMarkerName()) continue;
      const match = COMMIT.exec(name);
      if (!match) refuse('OWNER_JOURNAL_COMMIT');
      const number = BigInt('0x' + match[1]);
      if (number < 1n || number > BigInt(Number.MAX_SAFE_INTEGER)) refuse('OWNER_JOURNAL_SEQUENCE');
      markers.push({ basename: name, index: Number(number), generation: match[2], prefixHash: match[3] });
    }
    markers.sort((a, b) => a.index - b.index);
    const seen = new Set();
    for (const [offset, marker] of markers.entries()) {
      if (marker.index !== offset + 1 || seen.has(marker.generation)) refuse('OWNER_JOURNAL_COMMIT');
      seen.add(marker.generation);
    }
    return { names, markers };
  }
  function load() {
    if (active) refuse('OWNER_JOURNAL_UNAVAILABLE');
    const legacy = inspect(LEGACY);
    let tip = { sequence: 0, hash: ZERO, state: null }, hasFence = false;
    const texts = lines(legacy.raw);
    let offset = 0;
    for (const [position, text] of texts.entries()) {
      const value = parse(text), line = Buffer.from(text + '\n');
      if (value.schema === 3) {
        if (position !== texts.length - 1 || !tip.state) refuse('OWNER_JOURNAL_FENCE_INVALID');
        checkFence(value, line, legacy, legacy.raw.subarray(0, offset), tip);
        hasFence = true;
      } else {
        const fencedEnd = position === texts.length - 2 && parse(texts.at(-1)).schema === 3;
        tip = decode(value, safeNext(tip.sequence), tip.hash, false,
          recordPrefix(legacy, offset + line.length, value, fencedEnd));
      }
      offset += line.length;
    }
    if (!tip.state || !sameIdentity(tip.state.journalIdentity, legacy.identity)) refuse('OWNER_JOURNAL_IDENTITY');
    const { names, markers } = metadataNames();
    if (!hasFence && (markers.length || names.some(name => SEGMENT.test(name)))) refuse('OWNER_JOURNAL_FENCE_INVALID');
    let previousFile = legacy, lastMarker = null;
    for (const marker of markers) {
      const markerFile = inspect(marker.basename);
      if (markerFile.bytes !== 0) refuse('OWNER_JOURNAL_COMMIT');
      const basename = `journal-segment-${marker.generation}.jsonl`, segment = inspect(basename);
      const parts = lines(segment.raw);
      if (parts.length < 2) refuse('OWNER_JOURNAL_COMMIT');
      const header = parse(parts[0]), headerRaw = Buffer.from(parts[0] + '\n');
      if (!exact(header, ['schema', 'protocol', 'kind', 'rootId', 'generation', 'index', 'parent', 'predecessor'])
        || header.schema !== 3 || header.protocol !== PROTOCOL || header.kind !== 'segment-header' || header.rootId !== rootId
        || header.generation !== marker.generation || header.index !== marker.index || !bytesOf(header).equals(headerRaw)
        || !sameIdentity(header.parent, parent)
        || !sameDescriptor(header.predecessor, descriptor(previousFile, tip.sequence, tip.hash))) refuse('OWNER_JOURNAL_CHAIN');
      const checkpointValue = parse(parts[1]);
      if (!exact(checkpointValue, ['schema', 'protocol', 'rootId', 'sequence', 'previous', 'event', 'headerHash', 'state', 'hash'])
        || checkpointValue.event !== 'checkpoint' || checkpointValue.headerHash !== sha(headerRaw)) refuse('OWNER_JOURNAL_CHECKPOINT');
      const checkpointRaw = Buffer.from(parts[1] + '\n');
      if (!bytesOf(checkpointValue).equals(checkpointRaw)) refuse('OWNER_JOURNAL_CHECKPOINT');
      if (sha(Buffer.concat([headerRaw, checkpointRaw])) !== marker.prefixHash) refuse('OWNER_JOURNAL_COMMIT');
      let segmentOffset = headerRaw.length + checkpointRaw.length;
      const checkpoint = decode(checkpointValue, safeNext(tip.sequence), tip.hash, true,
        recordPrefix(segment, segmentOffset, checkpointValue));
      if (!sameIdentity(checkpoint.state.journalIdentity, segment.identity)) refuse('OWNER_JOURNAL_IDENTITY');
      const transportDev = identity(checkpoint.state.journalIdentity).dev;
      if (identity(header.parent).dev !== transportDev || identity(header.predecessor.identity).dev !== transportDev) refuse('OWNER_JOURNAL_IDENTITY');
      const expectedState = clone(tip.state);
      expectedState.journalIdentity = clone(identity(checkpoint.state.journalIdentity));
      if (!isDeepStrictEqual(checkpoint.state, expectedState)) refuse('OWNER_JOURNAL_CHECKPOINT');
      tip = checkpoint;
      for (const text of parts.slice(2)) {
        const value = parse(text);
        segmentOffset += Buffer.byteLength(text + '\n');
        tip = decode(value, safeNext(tip.sequence), tip.hash, false, recordPrefix(segment, segmentOffset, value));
        if (!sameIdentity(tip.state.journalIdentity, segment.identity)) refuse('OWNER_JOURNAL_IDENTITY');
      }
      previousFile = segment; lastMarker = markerFile;
    }
    // Unmarked staging cannot legitimately contain post-checkpoint bytes.
    const referenced = new Set(markers.map(marker => `journal-segment-${marker.generation}.jsonl`));
    for (const name of names) {
      if (!SEGMENT.test(name) || referenced.has(name)) continue;
      const raw = inspect(name).raw;
      const firstLF = raw.indexOf(0x0a);
      const secondLF = firstLF < 0 ? -1 : raw.indexOf(0x0a, firstLF + 1);
      if (secondLF >= 0 && secondLF + 1 < raw.length) refuse('OWNER_JOURNAL_COMMIT');
    }
    // Hold only the final selected journal. Sealed segments/archives/markers
    // were inspected with native evidence but did not acquire permanent FDs.
    active = inspect(previousFile.basename, previousFile.identity, previousFile.sha256, true);
    index = markers.length; sequence = tip.sequence; recordHash = tip.hash;
    lastCommittedState = clone(tip.state); fenced = hasFence; selectedMarker = lastMarker;
    return { state: clone(lastCommittedState), journal: active };
  }
  function initialize(state) {
    if (active || persisting || fault) refuse('OWNER_JOURNAL_UNAVAILABLE');
    persisting = true;
    try {
      const first = encode('initialize', state, 1, ZERO);
      active = create(LEGACY, first.raw, true);
      sequence = 1; recordHash = first.hash; lastCommittedState = clone(first.state);
      return active;
    } catch (error) { fault ??= error; throw error; }
    finally { persisting = false; }
  }
  function headerValue(generation, nextIndex, predecessor) {
    return { schema: 3, protocol: PROTOCOL, kind: 'segment-header', rootId,
      generation, index: nextIndex, parent: clone(parent), predecessor };
  }
  function freshBudget(event, state, generation, nextIndex, predecessor, newIdentity) {
    const header = bytesOf(headerValue(generation, nextIndex, predecessor));
    const checkpointState = clone(lastCommittedState); checkpointState.journalIdentity = clone(newIdentity);
    const checkpoint = encode('checkpoint', checkpointState, safeNext(sequence), recordHash, sha(header));
    const eventState = clone(state); eventState.journalIdentity = clone(newIdentity);
    const original = encode(event, eventState, safeNext(sequence, 2), checkpoint.hash);
    if (header.length + checkpoint.raw.length + original.raw.length > LIMIT) refuse('OWNER_JOURNAL_LIMIT');
    return { header, checkpoint, original };
  }
  function checkMarker() {
    if (!selectedMarker) return;
    const current = inspect(selectedMarker.basename, selectedMarker.identity, selectedMarker.sha256);
    if (current.bytes !== 0) refuse('OWNER_JOURNAL_COMMIT');
  }
  function rotate(event, state) {
    const generation = randomUUID(), nextIndex = safeNext(index), old = active;
    const firstFence = old.basename === LEGACY && !fenced;
    const archiveName = `journal-archive-${randomUUID()}.jsonl`;
    let predecessor = descriptor(old);
    // Reserve every unknown identity occurrence before archive/fence/header.
    if (firstFence) {
      const fence = boundFence(predecessor);
      if (old.bytes + fence.length > LIMIT) refuse('OWNER_JOURNAL_FENCE_SPACE');
      predecessor = { ...predecessor, bytes: old.bytes + fence.length, sha256: 'f'.repeat(64) };
    }
    freshBudget(event, state, generation, nextIndex, predecessor, BOUND_ID);
    // A synchronous transition latch precedes even the first archive effect.
    transitioning = true; effect();
    if (firstFence) {
      const original = inspect(old.basename, old.identity, old.sha256);
      const archive = create(archiveName, original.raw);
      const fence = bytesOf(fenceValue(descriptor(old), { basename: archiveName, identity: clone(archive.identity),
        bytes: archive.bytes, sha256: archive.sha256 }));
      if (old.bytes + fence.length > LIMIT) refuse('OWNER_JOURNAL_FENCE_SPACE');
      active = append(old, fence); fenced = true;
    }
    predecessor = descriptor(active);
    checkMarker();
    const header = bytesOf(headerValue(generation, nextIndex, predecessor));
    let next = create(`journal-segment-${generation}.jsonl`, header, true);
    const exactBudget = freshBudget(event, state, generation, nextIndex, predecessor, next.identity);
    if (!header.equals(exactBudget.header)) refuse('OWNER_JOURNAL_CHECKPOINT');
    next = append(next, exactBudget.checkpoint.raw);
    const markerName = `commit-${nextIndex.toString(16).padStart(16, '0')}-${generation}-${next.sha256}`;
    const marker = create(markerName, Buffer.alloc(0));
    const verifiedMarker = inspect(markerName, marker.identity, marker.sha256);
    if (verifiedMarker.bytes !== 0) refuse('OWNER_JOURNAL_COMMIT');
    // Publication is verified. Preserve the caller's speculative state and all
    // original lease/barrier closures; only its transport identity changes.
    active = next; index = nextIndex; sequence = exactBudget.checkpoint.sequence;
    recordHash = exactBudget.checkpoint.hash; lastCommittedState = clone(exactBudget.checkpoint.state);
    selectedMarker = verifiedMarker; state.journalIdentity = clone(next.identity);
    closeFile(old.basename, old.identity);
    const original = encode(event, state, safeNext(sequence), recordHash);
    active = append(active, original.raw);
    sequence = original.sequence; recordHash = original.hash;
    lastCommittedState = clone(original.state); transitioning = false;
    return active;
  }
  function preflight(event, state) {
    try {
      writable();
      if (persisting || transitioning || !active || !lastCommittedState) refuse('OWNER_JOURNAL_UNAVAILABLE');
      const record = encode(event, state, safeNext(sequence), recordHash);
      const wanted = active.bytes + record.raw.length;
      let fits = wanted <= LIMIT;
      if (fits && active.basename === LEGACY) {
        const possiblePrefix = { ...descriptor(active, record.sequence, record.hash), bytes: wanted, sha256: 'f'.repeat(64) };
        fits = !fenced && wanted + boundFence(possiblePrefix).length <= LIMIT;
      }
      if (fits) return;
      let predecessor = descriptor(active);
      if (active.basename === LEGACY && !fenced) {
        const fence = boundFence(predecessor);
        if (active.bytes + fence.length > LIMIT) refuse('OWNER_JOURNAL_FENCE_SPACE');
        predecessor = { ...predecessor, bytes: active.bytes + fence.length, sha256: 'f'.repeat(64) };
      }
      // Pure, conservative UTF8 H+CP+first-bound-event check, before root staging.
      freshBudget(event, state, BOUND_UUID, safeNext(index), predecessor, BOUND_ID);
    } catch (error) { fault ??= error; throw error; }
  }
  function persist(event, state) {
    if (fault || persisting || transitioning) {
      fault ??= Object.assign(new Error('OWNER_JOURNAL_TRANSITION_UNCERTAIN'), { code: 'OWNER_JOURNAL_TRANSITION_UNCERTAIN' });
      throw fault;
    }
    if (!active || !lastCommittedState) refuse('OWNER_JOURNAL_UNAVAILABLE');
    persisting = true;
    try {
      const record = encode(event, state, safeNext(sequence), recordHash);
      const wanted = active.bytes + record.raw.length;
      let fits = wanted <= LIMIT;
      if (fits && active.basename === LEGACY) {
        if (fenced) fits = false;
        else {
          const possiblePrefix = { ...descriptor(active, record.sequence, record.hash), bytes: wanted, sha256: 'f'.repeat(64) };
          fits = wanted + boundFence(possiblePrefix).length <= LIMIT;
        }
      }
      if (!fits) return rotate(event, state);
      checkMarker();
      active = append(active, record.raw);
      sequence = record.sequence; recordHash = record.hash; lastCommittedState = clone(record.state);
      return active;
    } catch (error) {
      // This gates fail(), release, stop and cleanup too. Neither uncertain
      // publication nor a failed capacity preflight grants a fallback append.
      fault ??= error;
      throw error;
    } finally { persisting = false; }
  }
  return Object.freeze({ initialize, load, preflight, persist, current: () => active,
    boundary: () => active ? descriptor(active) : null });
}

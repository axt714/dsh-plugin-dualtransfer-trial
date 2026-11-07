// Process-local diagnostics only. No error message, native text, path or token
// can become a root cause, and a JSON lookalike cannot brand an RPC failure.
const DETAILS = new WeakMap();
export const FAILURE_ORIGINS = Object.freeze(['controller', 'ownership', 'provider', 'store', 'identity', 'peer', 'host', 'core']);
export const FAILURE_STAGES = Object.freeze(['source-contract', 'profile-authority', 'ownership-open', 'product-owner',
  'provider-start', 'transport-start', 'store-open', 'identity-open', 'host-owner', 'host-bind', 'resolving-agent',
  'persisting-session', 'opening-core', 'registering-tools', 'initializing-reader', 'committing-binding', 'publishing-readiness',
  'startup-cleanup', 'controller-stop', 'host-dispose', 'host-retire', 'provider-drain', 'provider-stop', 'transport-stop',
  'store-close', 'identity-close', 'core-close', 'owner-release', 'runtime-close', 'runtime-started', 'tick', 'ownership-barrier']);
const ORIGINS = new Set(FAILURE_ORIGINS), STAGES = new Set(FAILURE_STAGES);
const CODES = new Set(`AGENT_OPERATION_FAILED AGENT_LIFECYCLE_FAILED AGENT_CONTROLLER_CLOSED AGENT_START_RETIRED AGENT_STOP_IN_PROGRESS
AGENT_PROFILE_AUTHORITY_REQUIRED SOURCE_CONTRACT_REFUSED AGENT_DRAIN_FAILED AGENT_OWNERSHIP_FAILED AGENT_OWNERSHIP_CAPABILITY_REQUIRED
PRODUCT_OWNER_LOCKED PRODUCT_OWNER_FAILED PRODUCT_OWNER_CHANGED PRIVATE_PATH_INVALID PRIVATE_PATH_UNSAFE PRIVATE_DIRECTORY_MODE
PRIVATE_FILE_UNSAFE PRIVATE_FILE_CORRUPT AGENT_STORE_IO AGENT_STORE_CHANGED AGENT_STORE_CORRUPT AGENT_STORE_DIRECTORY_CONFLICT
AGENT_STORE_CLOSED AGENT_STORE_NOT_OPEN AGENT_IDENTITY_IO AGENT_IDENTITY_CHANGED AGENT_IDENTITY_CORRUPT AGENT_IDENTITY_DIRECTORY_CONFLICT
AGENT_IDENTITY_CLOSED AGENT_IDENTITY_LISTENER_INVALID AGENT_IDENTITY_LISTENER_CONFLICT
AGENT_PEER_IO AGENT_PEER_STOPPED AGENT_PEER_DRAIN_TIMEOUT AGENT_PEER_PORT_IN_USE AGENT_PEER_ENDPOINT_STALE AGENT_TLS_PSK_UNAVAILABLE AGENT_PAIRING_REQUIRED
AGENT_PROVIDER_CLIENT_EXISTS AGENT_PROVIDER_DIRECTORY_UNSAFE AGENT_PROVIDER_DIRECTORY_CHANGED AGENT_PROVIDER_DIRECTORY_LAYOUT
AGENT_PROVIDER_START_FAILED AGENT_PROVIDER_DRAIN_FAILED AGENT_PROVIDER_STOP_FAILED AGENT_PROVIDER_HTTP_FAILED AGENT_PROVIDER_LISTEN_FAILED
AGENT_PROVIDER_RETIRED AGENT_PROVIDER_OPERATION_FAILED HOST_OWNER_LOCKED HOST_OWNER_FAILED HOST_UNCERTAIN_BINDING HOST_STATE_INVALID
HOST_STATE_IO HOST_BIND_FAILED HOST_BINDING_CAPACITY HOST_REVISION_EXHAUSTED HOST_DRAIN_FAILED HOST_NOT_READY HOST_FORMAL_SERVICES_UNAVAILABLE HOST_FORMAL_TARGET_INVALID
HOST_SESSION_NOT_PERSISTED HOST_TOOL_REGISTRATION_FAILED HOST_READER_NOT_READY HOST_TRANSPORT_INVALID HOST_PROVIDER_INVALID
HOST_BIND_EXPIRED HOST_ADMISSION_EXPIRED HOST_STAGE_INVALID HOST_BINDING_RETIRED HOST_AGENT_RETIRED HOST_AUTHORITY_RETIRED
LOCK_WRITE_FAILED LOCK_FAILED OWNER_LOCKED STORAGE_OPEN_FAILED STATE_READ_FAILED STATE_WRITE_FAILED CORRUPT_JOURNAL ADAPTER_TIMEOUT
AGENT_OWNER_UNSUPPORTED AGENT_OWNER_BUSY AGENT_OWNER_INCOMPLETE AGENT_OWNER_CHANGED AGENT_OWNER_BLOCKED AGENT_OWNER_IO
OWNER_OPERATION_FAILED OWNER_ROLE_UNSUPPORTED OWNER_DIRECTORY_INVALID OWNER_PATH_OUTSIDE OWNER_FILE_TYPE OWNER_PRIVATE_REQUIRED OWNER_FILE_LINKED
OWNER_ANCESTOR_CHANGED OWNER_ANCHOR_LOST OWNER_CAPABILITY_REVOKED OWNER_CHILD_UNCERTAIN OWNER_RUNTIME_BLOCKED OWNER_ANCESTOR_REPARSE
OWNER_FILE_REPLACED OWNER_FD_IDENTITY_MISMATCH OWNER_PARENT_NOT_ANCHORED OWNER_BROKER_OUTPUT OWNER_BROKER_FAILED OWNER_FILE_EVIDENCE_INVALID
OWNER_FILE_DATA_INVALID OWNER_BINDING_LAYOUT OWNER_INITIAL_DIRECTORY_MISSING OWNER_JOURNAL_UNAVAILABLE OWNER_JOURNAL_LIMIT OWNER_JOURNAL_STATE
OWNER_JOURNAL_MEMBER OWNER_JOURNAL_PARTIAL OWNER_JOURNAL_INVALID OWNER_JOURNAL_CHAIN OWNER_JOURNAL_IDENTITY OWNER_RECOVERY_INCOMPLETE
OWNER_JOURNAL_SEQUENCE OWNER_JOURNAL_TRANSITION_UNCERTAIN OWNER_JOURNAL_FENCE_INVALID OWNER_JOURNAL_LAYOUT
OWNER_JOURNAL_COMMIT OWNER_JOURNAL_CHECKPOINT OWNER_JOURNAL_FENCE_SPACE
OWNER_ROOT_INPUT OWNER_ROOT_ORIGIN_REQUIRED OWNER_ROOT_IDENTITY OWNER_ROOT_LAYOUT OWNER_ROOT_ANCHOR
OWNER_ROOT_COMMIT OWNER_ROOT_BOUNDARY OWNER_ROOT_BINDING OWNER_ROOT_TRANSITION_UNCERTAIN
OWNER_PARENT_OUTSIDE OWNER_PARENT_CHANGED OWNER_SET_MISMATCH OWNER_STOPPED_WITH_OWNERS OWNER_RUNNING_SET_INCOMPLETE OWNER_MEMBER_PARENT_CHANGED
OWNER_MEMBER_INSTANCE_MISMATCH OWNER_CLIENT_ASSOCIATION OWNER_BINDING_STATE_UNKNOWN OWNER_BINDING_STATE_UNCERTAIN OWNER_SET_ACTIVE
OWNER_GUARD_ERROR OWNER_SET_GUARD_BUSY OWNER_GUARD_LOST OWNER_OPEN_STATE OWNER_PLATFORM_UNSUPPORTED OWNER_LEGACY_MAINTENANCE_REQUIRED
OWNER_BOOTSTRAP_INVALID OWNER_BOOTSTRAP_SCOPE OWNER_RECORDED_DIRECTORY_MISSING OWNER_PROCESS_UNKNOWN OWNER_PROCESS_ACTIVE OWNER_PID_REUSED
OWNER_BOOT_CHANGED OWNER_LEASE_ACTIVE OWNER_LEASE_UNKNOWN OWNER_LEASE_MISSING OWNER_LEASE_SIZE OWNER_LEASE_REPLACED OWNER_RELEASE_STATE
OWNER_STAGE_INVALID OWNER_DRAIN_FAILED OWNER_RUNTIME_FAILED OWNER_START_INCOMPLETE OWNER_CLOSE_UNCERTAIN OWNER_MEMBER_LIMIT
OWNER_BOOTSTRAP_INCOMPLETE OWNER_IO_GUARD_BUSY OWNER_PROCESS_ABSENT OWNER_PROCESS_REUSED
OWNER_FS_TYPE OWNER_FS_PRIVATE OWNER_FS_LINK_COUNT OWNER_FS_IDENTITY_UNSUPPORTED OWNER_FS_PLATFORM_UNSUPPORTED OWNER_FS_ACL_UNVERIFIED
OWNER_FS_SIZE OWNER_FS_SHORT_READ OWNER_FS_SHORT_WRITE OWNER_FS_INPUT OWNER_FS_PARENT_REQUIRED OWNER_FS_PARENT_CHANGED OWNER_FS_REPARSE
OWNER_FS_FILE_CHANGED OWNER_FS_BYTES_CHANGED OWNER_FS_EXPECTED_REQUIRED OWNER_FS_DATA OWNER_FS_PREWRITE_CHANGED OWNER_FS_READBACK
OWNER_FS_POSTWRITE_CHANGED OWNER_FS_INPUT_SIZE OWNER_FS_PARENT_PROCESS OWNER_FS_IO_GUARD_BUSY OWNER_FS_IO_CLOSE_UNKNOWN OWNER_FS_FAILED
OWNER_FS_EACCES OWNER_FS_EPERM OWNER_FS_EEXIST OWNER_FS_ENOENT OWNER_FS_ELOOP OWNER_FS_ENOTDIR OWNER_FS_EIO OWNER_FS_ENOSPC OWNER_FS_EBADF
OWNER_NATIVE_INPUT OWNER_NATIVE_UNSUPPORTED OWNER_NATIVE_UNAVAILABLE OWNER_NATIVE_TIMEOUT OWNER_NATIVE_OUTPUT OWNER_NATIVE_PROCESS_UNKNOWN
OWNER_NATIVE_BOOT_UNKNOWN OWNER_NATIVE_BOOT_MISMATCH OWNER_NATIVE_NAMESPACE_UNKNOWN OWNER_NATIVE_ACL_UNKNOWN OWNER_NATIVE_IDENTITY_MISMATCH
OWNER_NATIVE_HASH_MISMATCH OWNER_NATIVE_IO_UNKNOWN OWNER_NATIVE_IO_UNCERTAIN OWNER_NATIVE_LIMIT OWNER_NATIVE_ANCHOR_UNKNOWN
OWNER_NATIVE_GUARD_BUSY OWNER_NATIVE_GUARD_UNKNOWN OWNER_NATIVE_PARENT_UNKNOWN`.split(/\s+/));
const AUTH_ERRORS = new Set(['INVALID_INPUT', 'INVALID_CONTEXT', 'FORBIDDEN', 'NOT_FOUND', 'OPERATION_ID_MISMATCH',
  'HOST_INPUT_INVALID', 'HOST_NOT_AUTHORIZED', 'HOST_CALLER_NOT_LIVE', 'HOST_TOOL_CALLER_INVALID', 'HOST_OPERATION_CONFLICT',
  'AGENT_QUERY_RETIRED', 'AGENT_OWNER_ACTION_RETIRED']);
const DRAIN_STAGES = new Set(['startup-cleanup', 'host-dispose', 'tick-join', 'provider-stop', 'owner-release', 'runtime-close', 'ownership-barrier']);
function ownCode(error) {
  try { const descriptor = Object.getOwnPropertyDescriptor(error, 'code'); return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null; }
  catch { return null; }
}
export function safeFailureCode(error, fallback = 'AGENT_OPERATION_FAILED') {
  const value = typeof error === 'string' ? error : ownCode(error);
  return CODES.has(value) ? value : CODES.has(fallback) ? fallback : 'AGENT_OPERATION_FAILED';
}
export function isAuthorityFailure(error) { return AUTH_ERRORS.has(ownCode(error)); }
export function createFailureLatch() {
  let first = null;
  return Object.freeze({
    capture(error, { stage, origin = 'controller', lifecycle = 'start' }) {
      if (!first && !isAuthorityFailure(error)) first = rootProjection(DETAILS.get(error)?.rootCause) ?? Object.freeze({
        code: safeFailureCode(error, origin === 'ownership' ? 'AGENT_OWNERSHIP_FAILED' : 'AGENT_OPERATION_FAILED'),
        stage: STAGES.has(stage) ? stage : 'controller-stop', origin: ORIGINS.has(origin) ? origin : 'controller',
        lifecycle: ['start', 'stop', 'bind'].includes(lifecycle) ? lifecycle : 'start' });
      return first;
    },
    snapshot: () => first,
    // Only the controller's confirmed full successful stop/release calls this.
    clear() { first = null; },
  });
}
function rootProjection(root) {
  return root && CODES.has(root.code) && STAGES.has(root.stage) && ORIGINS.has(root.origin)
    && ['start', 'stop', 'bind'].includes(root.lifecycle)
    ? Object.freeze({ code: root.code, stage: root.stage, origin: root.origin, lifecycle: root.lifecycle }) : null;
}
function drainProjection(drain) {
  if (!drain || drain.protocol !== 'agent-drain-v1' || !Number.isSafeInteger(drain.lifecycle) || drain.lifecycle < 0
    || !Array.isArray(drain.stages) || drain.stages.length > 8 || !drain.stages.every(stage => DRAIN_STAGES.has(stage))) return null;
  return Object.freeze({ protocol: 'agent-drain-v1', lifecycle: drain.lifecycle, stages: Object.freeze([...drain.stages]) });
}
export function brandAgentFailure(error, { rootCause = null, drain = null, resourceErrorCode = null } = {}) {
  if (!error || typeof error !== 'object' || isAuthorityFailure(error)) return error;
  const root = rootProjection(rootCause), currentDrain = drainProjection(drain);
  if (root || currentDrain) DETAILS.set(error, Object.freeze({ rootCause: root, ...(currentDrain ? { drain: currentDrain } : {}),
    ...(resourceErrorCode === null ? {} : { resourceErrorCode: safeFailureCode(resourceErrorCode) }) }));
  return error;
}
export function getAgentFailureDetails(error) { return DETAILS.get(error) ?? null; }
export function assertRuntimeCapability(runtime) {
  if (runtime === undefined) return;
  if (!runtime || !['acquire', 'canAcquire', 'beginBarrier', 'fail'].every(key => typeof runtime[key] === 'function')) {
    const error = Object.assign(new Error('AGENT_OWNERSHIP_CAPABILITY_REQUIRED'), { code: 'AGENT_OWNERSHIP_CAPABILITY_REQUIRED' }); throw error;
  }
}
// Synchronous, write-ahead barrier. A failure to persist must occur before work,
// not be converted into a successful resource join by a catch/finally handler.
export function beginRuntimeBarrier(runtime, stage) {
  assertRuntimeCapability(runtime);
  return runtime === undefined ? null : runtime.beginBarrier(stage);
}
export function failRuntimeBarrier(runtime, barrier, error, stage) {
  const code = safeFailureCode(error);
  try { barrier?.fail(code); } catch { /* Retain the primary failure and capability. */ }
  try { runtime?.fail(code, STAGES.has(stage) ? stage : 'ownership-barrier'); } catch { /* Unknown persistence is not success. */ }
}

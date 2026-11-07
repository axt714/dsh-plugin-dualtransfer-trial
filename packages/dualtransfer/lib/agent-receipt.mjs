import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { validateAgentMessageScope } from './agent-message-store.mjs';

const PREFIX = 'DTRECEIPT/1\n', PROTOCOL = 'dualtransfer.receipt/1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/;
const SCOPE_KEYS = ['pairingId', 'generation', 'localDeviceId', 'peerDeviceId', 'localTargetToken', 'peerTargetToken'];
function invalid() { throw new Error('AGENT_RECEIPT_BATCH_INVALID'); }
export function receiptMessageIds(value) {
  if (!Array.isArray(value) || types.isProxy(value) || value.length < 1 || value.length > 100 || Reflect.ownKeys(value).length !== value.length + 1) invalid();
  const ids = [];
  for (let index = 0; index < value.length; index++) {
    const item = Object.getOwnPropertyDescriptor(value, String(index));
    if (!item || !Object.hasOwn(item, 'value') || typeof item.value !== 'string' || !UUID.test(item.value)) invalid();
    ids.push(item.value);
  }
  if (new Set(ids).size !== ids.length) invalid();
  return Object.freeze(ids.sort());
}
export function encodeAgentReceipt(messageIds) {
  return PREFIX + JSON.stringify({ protocol: PROTOCOL, kind: 'received', messageIds: receiptMessageIds(messageIds) });
}
/** Strict canonical text only; neither recognition nor its contents grant authority. */
export function parseAgentReceipt(text) {
  if (typeof text !== 'string' || !text.startsWith(PREFIX) || text.length > 8192 || !text.isWellFormed()) return null;
  try {
    const value = JSON.parse(text.slice(PREFIX.length));
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 3 || value.protocol !== PROTOCOL || value.kind !== 'received') return null;
    const ids = receiptMessageIds(value.messageIds);
    // Round trip also rejects duplicate/escaped keys, extra whitespace, unsorted IDs
    // and every other spelling not emitted by the one versioned encoder.
    if (text !== encodeAgentReceipt(ids)) return null;
    return Object.freeze({ protocol: PROTOCOL, kind: 'received', messageIds: ids });
  } catch { return null; }
}
export function isAgentReceipt(text) { return parseAgentReceipt(text) !== null; }
export function agentReceiptMessageId(scope, messageIds) {
  validateAgentMessageScope(scope);
  const bytes = createHash('sha256').update(JSON.stringify(['dualtransfer.receipt.id/1', ...SCOPE_KEYS.map(key => scope[key]), receiptMessageIds(messageIds)])).digest();
  bytes[6] = (bytes[6] & 0x0f) | 0x50; bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

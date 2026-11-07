import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { SOURCE_KIND } from './vendor/dsh-dispatcher.mjs';
import { UUID } from './wire.mjs';
const TEXT = '本机来源表示能力自检；合成通知，不是用户授权，不发送到模型。';
/** Pure detached memory only. Never builds a Context, Store, Agent or provider. */
export function verifySourceContract({ createUserMessage, Session, SessionId, uuid = randomUUID } = {}) {
  try {
    if (typeof createUserMessage !== 'function' || typeof Session?.create !== 'function'
        || typeof Session?.fromRestore !== 'function' || typeof SessionId !== 'function') return 'refused';
    const batchId = uuid(), syntheticId = uuid();
    if (!UUID.test(batchId) || !UUID.test(syntheticId)) return 'refused';
    const source = { kind: SOURCE_KIND, batchId, bindingRevision: 1 };
    const message = createUserMessage({ source, content: [{ type: 'text', text: TEXT }] });
    if (message?.role !== 'user' || typeof message.id !== 'string' || !message.id
        || !isDeepStrictEqual(message.source, source)
        || !isDeepStrictEqual(message.content, [{ type: 'text', text: TEXT }])) return 'refused';
    const id = SessionId(syntheticId), session = Session.create(id);
    const event = session.append('user/message', message, { surfaceOp: 'append' });
    if (event?.surfaceOp !== 'append' || !isDeepStrictEqual(event.data, message)
        || !isDeepStrictEqual(session.deriveMessages(), [message])) return 'refused';
    const serialized = JSON.stringify({ header: session.header, events: [event] });
    const seed = JSON.parse(serialized), restore = JSON.parse(serialized);
    const recreated = Session.create(id, seed.events, seed.header);
    const restored = Session.fromRestore(id, restore.events, restore.header, 0, 'detached');
    if (!isDeepStrictEqual(recreated.deriveMessages(), [message])
        || !isDeepStrictEqual(restored.deriveMessages(), [message])) return 'refused';
    return 'verified';
  } catch { return 'refused'; }
}

// Pure injected transport cursor: no filesystem, transport, Host, dispatch, or timer calls.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TRANSPORT_ID = /^[a-f0-9-]{36}$/u; // Existing frozen Core transport schema.
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonnegative = value => Number.isSafeInteger(value) && value >= 0;
const positive = value => Number.isSafeInteger(value) && value > 0;
const uuid = value => typeof value === 'string' && UUID.test(value);

export class ReaderError extends Error {
  constructor(code, retryable = false) {
    super(code);
    this.name = 'ReaderError';
    this.code = code;
    this.retryable = retryable;
  }
}
const fail = code => { throw new ReaderError(code); };
const copyState = state => state === null ? null : { ...state };

function validBinding(binding) {
  return record(binding) && uuid(binding.bindingId) && positive(binding.bindingRevision);
}
function validState(state) {
  return validBinding(state) && state.schema === 1 && uuid(state.epoch) && nonnegative(state.cursor);
}
function cursorState(binding, epoch, cursor) {
  return Object.freeze({ schema: 1, bindingId: binding.bindingId,
    bindingRevision: binding.bindingRevision, epoch, cursor });
}
function normalizeMessage(message, since, tail, previous) {
  if (!record(message) || !nonnegative(message.seq) || message.seq <= since ||
      message.seq <= previous || message.seq > tail || message.direction !== 'in' ||
      message.channel !== 'agent' || typeof message.id !== 'string' ||
      !TRANSPORT_ID.test(message.id) || typeof message.text !== 'string' ||
      !message.text.trim() || Buffer.byteLength(message.text, 'utf8') > 16 * 1024 ||
      typeof message.conversation !== 'string' || message.conversation.length > 100 ||
      typeof message.sender !== 'string' || message.sender.length > 80 ||
      !nonnegative(message.created) || !(message.replyTo === null ||
        message.replyTo === undefined || (typeof message.replyTo === 'string' &&
          TRANSPORT_ID.test(message.replyTo)))) fail('INVALID_PAGE_MESSAGE');
  // Only existing Core schema fields cross the ingest boundary; seq is cursor-only.
  return { id: message.id, direction: 'in', channel: 'agent', text: message.text,
    conversation: message.conversation, sender: message.sender,
    created: message.created, replyTo: message.replyTo ?? null };
}
function validatePage(raw, { since, limit, epoch }) {
  let page;
  try { page = structuredClone(raw); } catch { fail('INVALID_PAGE'); }
  if (!record(page) || !uuid(page.epoch) || !nonnegative(page.globalTail) ||
      !nonnegative(page.revision) || !nonnegative(page.next) ||
      typeof page.more !== 'boolean' || !Array.isArray(page.messages) ||
      page.messages.length > limit) fail('INVALID_PAGE_METADATA');
  if (epoch !== null && page.epoch !== epoch) fail('EPOCH_CHANGED');
  if (page.globalTail < since) fail('GLOBAL_TAIL_REGRESSION');
  let last = since;
  const messages = [];
  for (const message of page.messages) {
    messages.push(normalizeMessage(message, since, page.globalTail, last));
    last = message.seq;
  }
  if (page.next !== last) fail('INVALID_PAGE_NEXT');
  if (page.more && page.next <= since) fail('PAGE_NO_PROGRESS');
  if (page.more && page.next >= page.globalTail) fail('INVALID_PAGE_MORE');
  return { messages, epoch: page.epoch, next: page.next, more: page.more,
    globalTail: page.globalTail };
}

/** Requires an explicit initial:null (authorized first-bind candidate), or full durable state.
 * binding is the expected local bindingId + numeric Core-authorized bindingRevision.
 * Host owns firstBind authorization, UUID generation, durable storage and Core consistency.
 */
export function createTransportReader(options) {
  if (!record(options) || !Object.hasOwn(options, 'initial')) fail('INITIAL_REQUIRED');
  if (!validBinding(options.binding)) fail('INVALID_BINDING');
  if (typeof options.readPage !== 'function' || typeof options.persistCursor !== 'function' ||
      !record(options.core) || typeof options.core.ingest !== 'function') fail('INVALID_DEPENDENCY');
  const limit = options.limit === undefined ? 100 : options.limit;
  if (!positive(limit) || limit > 100) fail('INVALID_LIMIT');
  const binding = Object.freeze({ bindingId: options.binding.bindingId,
    bindingRevision: options.binding.bindingRevision });
  let initial = null;
  if (options.initial !== null) {
    if (!validState(options.initial)) fail('INVALID_INITIAL_STATE');
    if (options.initial.bindingId !== binding.bindingId ||
        options.initial.bindingRevision !== binding.bindingRevision) fail('BINDING_MISMATCH');
    initial = cursorState(binding, options.initial.epoch, options.initial.cursor);
  }
  return new TransportReader({ binding, initial, readPage: options.readPage,
    ingest: options.core.ingest.bind(options.core), persistCursor: options.persistCursor, limit });
}

class TransportReader {
  #binding; #state; #readPage; #ingest; #persistCursor; #limit;
  #closed = false; #blockedCode = null; #inFlight = null; #closePromise = null;

  constructor({ binding, initial, readPage, ingest, persistCursor, limit }) {
    this.#binding = binding;
    this.#state = initial;
    this.#readPage = readPage;
    this.#ingest = ingest;
    this.#persistCursor = persistCursor;
    this.#limit = limit;
  }
  status() {
    return { phase: this.#closed ? 'closed' : this.#blockedCode ? 'blocked' :
      this.#state === null ? 'unbound' : 'ready',
    state: copyState(this.#state), blockedCode: this.#blockedCode };
  }
  #checkOpen() { if (this.#closed) fail('READER_CLOSED'); }
  #block(code) { this.#blockedCode = code; throw new ReaderError(code); }
  #start(work) {
    if (this.#closed) return Promise.reject(new ReaderError('READER_CLOSED'));
    if (this.#blockedCode) return Promise.reject(new ReaderError('READER_BLOCKED'));
    if (this.#inFlight) return Promise.reject(new ReaderError('READER_BUSY'));
    const operation = Promise.resolve().then(() => { this.#checkOpen(); return work(); });
    const result = operation.finally(() => {
      if (this.#inFlight === result) this.#inFlight = null;
    });
    this.#inFlight = result;
    return result;
  }
  async #read(since, limit, epoch) {
    this.#checkOpen();
    let raw;
    try {
      raw = await this.#readPage(Object.freeze({ since, limit, direction: 'in', channel: 'agent' }));
    } catch {
      this.#checkOpen();
      throw new ReaderError('READ_IO_FAILED', true);
    }
    this.#checkOpen();
    try { return validatePage(raw, { since, limit, epoch }); }
    catch (error) {
      this.#block(error instanceof ReaderError ? error.code : 'INVALID_PAGE');
    }
  }
  async #persist(next) {
    this.#checkOpen();
    try { await this.#persistCursor(Object.freeze(copyState(next))); }
    catch { this.#block('CURSOR_PERSIST_FAILED'); }
    this.#checkOpen();
    this.#state = next;
  }
  firstBind(authorization) {
    return this.#start(async () => {
      if (!record(authorization) || authorization.firstBind !== true) fail('FIRST_BIND_REQUIRED');
      if (this.#state !== null) fail('ALREADY_BOUND');
      const page = await this.#read(0, 1, null);
      this.#checkOpen();
      // The one historical sample is validated, never ingested, even when more:true.
      await this.#persist(cursorState(this.#binding, page.epoch, page.globalTail));
      return { outcome: 'bound', cursor: this.#state.cursor };
    });
  }
  pump() {
    return this.#start(async () => {
      if (this.#state === null) fail('UNBOUND');
      const before = this.#state;
      const page = await this.#read(before.cursor, this.#limit, before.epoch);
      this.#checkOpen();
      if (page.messages.length) {
        try { await this.#ingest(page.messages); }
        catch (error) {
          let conflict = false;
          try { conflict = error?.code === 'MESSAGE_ID_CONFLICT'; } catch { /* fixed safe code */ }
          this.#block(conflict ? 'MESSAGE_ID_CONFLICT' : 'INGEST_FAILED');
        }
        // close cannot undo completed ingest. No cursor call starts after the gate closes.
        this.#checkOpen();
      }
      const next = page.more ? page.next : page.globalTail;
      if (next !== before.cursor) await this.#persist(cursorState(this.#binding, before.epoch, next));
      return { outcome: next === before.cursor ? 'idle' : 'advanced', cursor: this.#state.cursor,
        messageCount: page.messages.length, more: page.more };
    });
  }
  close() {
    if (!this.#closePromise) {
      this.#closed = true; // Synchronous gate, then join only this instance's current operation.
      this.#closePromise = this.#inFlight ? this.#inFlight.then(() => undefined, () => undefined) :
        Promise.resolve();
    }
    return this.#closePromise;
  }
}

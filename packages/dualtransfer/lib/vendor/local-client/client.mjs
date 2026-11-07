import * as nativeFs from 'node:fs/promises';
import { Agent, request as nativeRequest } from 'node:http';
import { isLocalAbsoluteConfigPath } from './config-path.mjs';

const CONFIG_LIMIT = 16 * 1024;
const BODY_LIMIT = 2 * 1024 * 1024;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;

export class LocalAgentClientError extends Error {
  constructor(code) { super(code); this.name = 'LocalAgentClientError'; this.code = code; }
}
const error = (code) => new LocalAgentClientError(code);
const requireThat = (condition, code) => { if (!condition) throw error(code); };

function decodeObject(bytes, code) {
  try {
    const result = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    requireThat(object(result), code);
    return result;
  } catch { throw error(code); }
}

function configValues(bytes) {
  const config = decodeObject(bytes, 'CONFIG_INVALID_JSON');
  // Match raw spelling, not WHATWG's permissive hostname/IP/path normalization.
  requireThat(typeof config.url === 'string' && /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/.test(config.url), 'CONFIG_INVALID_URL');
  const port = Number(/^http:\/\/127\.0\.0\.1:([0-9]+)/.exec(config.url)[1]);
  requireThat(integer(port, 1, 65535), 'CONFIG_INVALID_URL');
  // Existing server creates 64 hex chars and accepts previously saved length-64 tokens.
  requireThat(typeof config.token === 'string' && /^[\x21-\x7e]{64}$/.test(config.token), 'CONFIG_INVALID_TOKEN');
  return { port, token: config.token };
}

function fileStat(stat) {
  requireThat(stat && stat.isFile() && !stat.isSymbolicLink?.(), 'CONFIG_NOT_REGULAR_FILE');
  requireThat(integer(stat.size, 0, CONFIG_LIMIT), 'CONFIG_TOO_LARGE');
}

async function readConfig(path, fs, operation) {
  let handle;
  try {
    fileStat(await fs.lstat(path));
    operation.check();
    handle = await fs.open(path, 'r');
    operation.check();
    fileStat(await handle.stat());
    operation.check();
    const bytes = Buffer.alloc(CONFIG_LIMIT + 1);
    let used = 0;
    while (used < bytes.length) {
      const { bytesRead } = await handle.read(bytes, used, bytes.length - used, used);
      operation.check();
      requireThat(integer(bytesRead, 0, bytes.length - used), 'CONFIG_IO_FAILED');
      if (bytesRead === 0) break;
      used += bytesRead;
    }
    requireThat(used <= CONFIG_LIMIT, 'CONFIG_TOO_LARGE');
    return configValues(bytes.subarray(0, used));
  } catch (caught) {
    if (caught instanceof LocalAgentClientError) throw caught;
    throw error('CONFIG_IO_FAILED');
  } finally {
    if (handle) {
      try { await handle.close(); }
      catch { if (!operation.settled) throw error('CONFIG_IO_FAILED'); }
    }
  }
}

// Keep only error/close guards after settlement until native streams close. Removing
// error handlers before destroy's asynchronous ECONNRESET could crash the process.
function watchStream(stream, onError, onPrematureClose) {
  let closed = false;
  const listeners = [];
  let resolveDrain;
  const drain = new Promise((resolve) => { resolveDrain = resolve; });
  const listen = (event, fn) => { listeners.push([event, fn]); stream.on(event, fn); };
  const stopData = () => {
    for (const [event, fn] of listeners) {
      if (event !== 'error' && event !== 'close') stream.removeListener(event, fn);
    }
  };
  listen('error', onError);
  listen('close', () => {
    if (closed) return;
    closed = true;
    for (const [event, fn] of listeners) stream.removeListener(event, fn);
    onPrematureClose();
    resolveDrain();
  });
  return { listen, stopData, drain };
}

function httpPage(config, args, request, operation) {
  let req, res, reqWatch, resWatch, ended = false, done = false;
  let rejectHttp;
  const drains = [];
  // Explicit private agent, no globalAgent and no environment proxy configuration.
  // Agent construction allocates no socket; only request below starts I/O.
  const agent = new Agent({ keepAlive: false, proxyEnv: Object.create(null) });
  const stop = (reason) => {
    if (reason) rejectHttp?.(reason);
    resWatch?.stopData();
    // Leave the response guard until request close, to destroy any late response.
    if (done && ended) reqWatch?.stopData();
    res?.destroy();
    req?.destroy();
    agent.destroy();
  };
  operation.cancelHttp = stop;
  operation.drainHttp = async () => {
    // A response may arrive between cancellation and request close.
    for (let index = 0; index < drains.length; index += 1) await drains[index];
  };
  const fail = (code) => {
    if (done) return;
    done = true;
    const reason = error(code);
    rejectHttp(reason);
    stop(reason);
  };
  return new Promise((resolve, reject) => {
    rejectHttp = reject;
    try {
      operation.check();
      req = request({
        protocol: 'http:', hostname: '127.0.0.1', family: 4, port: config.port,
        method: 'GET',
        path: `/messages?since=${args.since}&limit=${args.limit}&direction=in&channel=agent`,
        headers: { Authorization: `Bearer ${config.token}`, Accept: 'application/json' },
        agent, maxHeaderSize: 8192, insecureHTTPParser: false,
      });
      reqWatch = watchStream(req, () => fail('HTTP_IO_FAILED'), () => {
        if (!res && !operation.settled) fail('HTTP_IO_FAILED');
      });
      drains.push(reqWatch.drain);
      reqWatch.listen('response', (incoming) => {
        if (res) { incoming.destroy(); fail('HTTP_INVALID_RESPONSE'); return; }
        res = incoming;
        resWatch = watchStream(res, () => fail('HTTP_IO_FAILED'), () => {
          if (!ended && !operation.settled) fail('HTTP_IO_FAILED');
        });
        drains.push(resWatch.drain);
        if (operation.settled || done) { stop(error('CLIENT_ABORTED')); return; }
        if (integer(res.statusCode, 300, 399)) { fail('HTTP_REDIRECT'); return; }
        if (res.statusCode !== 200) { fail('HTTP_STATUS'); return; }
        const headers = res.headers ?? {};
        if (typeof headers['content-type'] !== 'string' || !/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(headers['content-type'].trim())) {
          fail('HTTP_CONTENT_TYPE'); return;
        }
        if (headers['content-encoding'] !== undefined && headers['content-encoding'] !== 'identity') {
          fail('HTTP_CONTENT_ENCODING'); return;
        }
        let declared;
        if (headers['content-length'] !== undefined) {
          if (typeof headers['content-length'] !== 'string' || !/^(0|[1-9][0-9]*)$/.test(headers['content-length'])) {
            fail('HTTP_CONTENT_LENGTH'); return;
          }
          declared = Number(headers['content-length']);
          if (!integer(declared, 0, BODY_LIMIT)) { fail('HTTP_BODY_TOO_LARGE'); return; }
        }
        // Fixed payload storage also bounds overhead for arbitrarily tiny chunks.
        const body = Buffer.alloc(BODY_LIMIT);
        let size = 0;
        resWatch.listen('aborted', () => fail('HTTP_IO_FAILED'));
        resWatch.listen('data', (chunk) => {
          if (done || operation.settled) return;
          if (!(chunk instanceof Uint8Array)) { fail('HTTP_INVALID_RESPONSE'); return; }
          if (chunk.byteLength > BODY_LIMIT - size) { fail('HTTP_BODY_TOO_LARGE'); return; }
          body.set(chunk, size);
          size += chunk.byteLength;
        });
        resWatch.listen('end', () => {
          ended = true;
          if (done || operation.settled) return;
          if (declared !== undefined && declared !== size) { fail('HTTP_CONTENT_LENGTH'); return; }
          try {
            const envelope = decodeObject(body.subarray(0, size), 'HTTP_INVALID_JSON');
            requireThat(envelope.ok === true && object(envelope.value), 'HTTP_INVALID_ENVELOPE');
            done = true;
            resolve(envelope.value);
          } catch (caught) { fail(caught.code ?? 'HTTP_INVALID_JSON'); }
        });
      });
      req.end();
    } catch { fail('HTTP_IO_FAILED'); }
  });
}

/** Lazy, local-only transport. All seams are trusted Host/test dependencies. */
export function createLocalAgentClient({
  agentClientConfigPath,
  timeoutMs = 3000,
  fs = nativeFs,
  request = nativeRequest,
  timers = { setTimeout, clearTimeout },
} = {}) {
  requireThat(isLocalAbsoluteConfigPath(agentClientConfigPath), 'INVALID_CONFIG_PATH');
  requireThat(integer(timeoutMs, 1, 10000), 'INVALID_TIMEOUT');
  requireThat(fs && typeof fs.lstat === 'function' && typeof fs.open === 'function' && typeof request === 'function' && timers && typeof timers.setTimeout === 'function' && typeof timers.clearTimeout === 'function', 'INVALID_DEPENDENCY');
  let closed = false, closing;
  const active = new Set();

  function readPage(args, { signal } = {}) {
    if (closed) return Promise.reject(error('CLIENT_CLOSED'));
    if (!object(args) || !integer(args.since, 0, Number.MAX_SAFE_INTEGER) || !integer(args.limit, 1, 100) || args.direction !== 'in' || args.channel !== 'agent') {
      return Promise.reject(error('INVALID_READ_ARGS'));
    }
    if (signal !== undefined && (!signal || typeof signal.aborted !== 'boolean' || typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function')) {
      return Promise.reject(error('INVALID_SIGNAL'));
    }
    if (signal?.aborted) return Promise.reject(error('CLIENT_ABORTED'));
    // Snapshot the only caller-controlled request fields before any await.
    const query = { since: args.since, limit: args.limit };
    let resolvePublic, rejectPublic, timer, work;
    const promise = new Promise((resolve, reject) => { resolvePublic = resolve; rejectPublic = reject; });
    const onAbort = () => operation.fail('CLIENT_ABORTED');
    const operation = {
      settled: false, reason: undefined,
      check() { if (this.settled) throw this.reason ?? error('CLIENT_CLOSED'); },
      cleanup() {
        if (timer !== undefined) { timers.clearTimeout(timer); timer = undefined; }
        signal?.removeEventListener('abort', onAbort);
      },
      fail(code) {
        if (this.settled) return;
        this.reason = error(code);
        this.settled = true;
        this.cleanup();
        this.cancelHttp?.(this.reason);
        rejectPublic(this.reason);
      },
    };
    active.add(operation);
    signal?.addEventListener('abort', onAbort, { once: true });
    timer = timers.setTimeout(() => operation.fail('IO_TIMEOUT'), timeoutMs);
    // Cancellation can land during a pending FS operation. Its eventual handle is
    // still closed in readConfig's finally; close() joins this complete work/drain.
    work = (async () => {
      try {
        operation.check();
        const config = await readConfig(agentClientConfigPath, fs, operation);
        operation.check();
        const page = await httpPage(config, query, request, operation);
        operation.check();
        operation.settled = true;
        operation.cleanup();
        resolvePublic(page);
      } catch (caught) {
        operation.fail(caught instanceof LocalAgentClientError ? caught.code : 'CLIENT_IO_FAILED');
      } finally {
        operation.cleanup();
        operation.cancelHttp?.();
        await operation.drainHttp?.();
        active.delete(operation);
      }
    })();
    operation.work = work;
    return promise;
  }

  function close() {
    if (closing) return closing;
    closed = true;
    const pending = [...active];
    for (const operation of pending) operation.fail('CLIENT_CLOSED');
    closing = Promise.all(pending.map((operation) => operation.work)).then(() => undefined);
    return closing;
  }
  return Object.freeze({ readPage, close });
}

// Dedicated bridge for one existing read-only directory-anchor keeper.
// No file mutations, models, network endpoints, path proof caches or retries.
import { parentPort, workerData } from 'node:worker_threads';
import { spawn } from 'node:child_process';

const { command, cwd, env, initialRequest, buffer, timeout, maxBytes } = workerData;
const header = new Int32Array(buffer, 0, 4);
const payload = new Uint8Array(buffer, 16);
let ready = false, failed = false, closing = false, closed = false;
let pending = null, output = '', stdoutEnded = false, stderrEnded = false;
let closeTimer;
const decoder = new TextDecoder('utf-8', { fatal: true });
const child = spawn(command, [], { cwd, env, shell: false, windowsHide: true,
  stdio: ['pipe', 'pipe', 'pipe'] });
function signal(reply, terminal = false) {
  const data = Buffer.from(JSON.stringify(reply));
  if (data.length > payload.length) return signal({ ok: false, code: 'OWNER_NATIVE_LIMIT' }, true);
  payload.set(data);
  Atomics.store(header, 1, data.length);
  // PENDING=1 -> SUCCESS=2 only if timeout has not won FAILED=3.
  if (terminal) Atomics.store(header, 0, 3);
  else if (Atomics.compareExchange(header, 0, 1, 2) !== 1) return false;
  Atomics.notify(header, 0);
  return true;
}
function fail(code) {
  if (failed) return;
  failed = true;
  Atomics.store(header, 2, 0);
  if (pending !== null) { signal({ ok: false, code }, 2); pending = null; }
  try { child.kill('SIGKILL'); } catch { /* No successful-close claim. */ }
  parentPort.postMessage({ type: 'failed', code });
}
const startupTimer = setTimeout(() => fail('OWNER_NATIVE_TIMEOUT'), timeout);
child.on('error', () => fail('OWNER_NATIVE_ANCHOR_UNKNOWN'));
child.stdin.on('error', () => fail('OWNER_NATIVE_ANCHOR_UNKNOWN'));
child.stderr.on('data', () => fail('OWNER_NATIVE_ANCHOR_UNKNOWN'));
child.stdout.on('end', () => {
  try { output += decoder.decode(); } catch { fail('OWNER_NATIVE_OUTPUT'); }
  stdoutEnded = true;
});
child.stderr.on('end', () => { stderrEnded = true; });
child.stdout.on('data', chunk => {
  if (failed) return;
  try { output += decoder.decode(chunk, { stream: true }); }
  catch { fail('OWNER_NATIVE_OUTPUT'); return; }
  if (Buffer.byteLength(output) > maxBytes) { fail('OWNER_NATIVE_OUTPUT'); return; }
  let newline;
  while ((newline = output.indexOf('\n')) >= 0) {
    const line = output.slice(0, newline).replace(/\r$/, '');
    output = output.slice(newline + 1);
    let reply;
    try { reply = JSON.parse(line); } catch { fail('OWNER_NATIVE_OUTPUT'); return; }
    if (!ready) {
      if (reply?.ok !== true) { fail(typeof reply?.code === 'string' ? reply.code : 'OWNER_NATIVE_OUTPUT'); return; }
      if (reply.ready !== true || output.length !== 0) { fail('OWNER_NATIVE_OUTPUT'); return; }
      ready = true;
      clearTimeout(startupTimer);
      Atomics.store(header, 2, 1);
      parentPort.postMessage({ type: 'ready', pid: child.pid, reply });
    } else {
      if (pending === null || reply?.queryId !== pending || !reply.reply || output.length !== 0) { fail('OWNER_NATIVE_OUTPUT'); return; }
      if (Atomics.load(header, 3) !== pending || !signal(reply.reply)) {
        fail('OWNER_NATIVE_TIMEOUT'); return;
      }
      pending = null;
    }
  }
});
parentPort.on('message', message => {
  if (message.type === 'abort') { fail('OWNER_NATIVE_TIMEOUT'); return; }
  if (message.type === 'close') {
    if (!ready || failed || closing || closed || pending !== null) { fail('OWNER_NATIVE_ANCHOR_UNKNOWN'); return; }
    closing = true;
    closeTimer = setTimeout(() => fail('OWNER_NATIVE_TIMEOUT'), timeout);
    child.stdin.end();
    return;
  }
  if (message.type !== 'query' || !ready || failed || closing || closed || pending !== null ||
      !Number.isInteger(message.id) || message.id < 1) { fail('OWNER_NATIVE_INPUT'); return; }
  pending = message.id;
  const input = JSON.stringify({ ...message.request, queryId: message.id }) + '\n';
  if (Buffer.byteLength(input) > maxBytes) { fail('OWNER_NATIVE_LIMIT'); return; }
  child.stdin.write(input);
});
child.on('close', (code, signalValue) => {
  closed = true;
  clearTimeout(startupTimer);
  clearTimeout(closeTimer);
  Atomics.store(header, 2, 0);
  if (pending !== null) { signal({ ok: false, code: 'OWNER_NATIVE_ANCHOR_UNKNOWN' }, 2); pending = null; }
  const graceful = ready && closing && !failed && code === 0 && signalValue === null &&
    stdoutEnded && stderrEnded && output.length === 0;
  parentPort.postMessage({ type: 'closed', graceful, code, signal: signalValue,
    stdoutEnded, stderrEnded });
  parentPort.close();
});
child.stdin.write(JSON.stringify(initialRequest) + '\n');

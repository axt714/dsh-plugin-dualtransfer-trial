// Private POSIX ownership operation broker. Not a Tool or a network service.
// The OS CWD pins the actual parent; only a basename and a verified FD are used.
// No lease path is renamed or unlinked. An effect on the old inode is NOT CAS.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import net from 'node:net';
import { probeProcessIdentity } from './agent-owner-platform.mjs';

const LIMIT = 4 * 1024 * 1024;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const identity = stat => ({ dev: String(stat.dev), ino: String(stat.ino), birth: String(stat.birthtimeNs) });
const same = (a, b) => !!a && !!b && ['dev', 'ino', 'birth'].every(key => a[key] === b[key]);
function checkedStat(stat, directory = false) {
  if (directory ? !stat.isDirectory() : !stat.isFile()) fail('OWNER_FS_TYPE');
  if (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('OWNER_FS_PRIVATE');
  if (!directory && stat.nlink !== 1n) fail('OWNER_FS_LINK_COUNT');
  if (!stat.ino || !stat.birthtimeNs) fail('OWNER_FS_IDENTITY_UNSUPPORTED');
  return identity(stat);
}
function noAcl(name) {
  if (process.platform !== 'darwin') fail('OWNER_FS_PLATFORM_UNSUPPORTED');
  const result = spawnSync('/bin/ls', ['-lde', name], {
    encoding: 'utf8', timeout: 2500, maxBuffer: 65536,
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C', LANG: 'C' },
  });
  if (result.error || result.status !== 0 || /^\s*\d+:/m.test(result.stdout ?? '')) fail('OWNER_FS_ACL_UNVERIFIED');
}
function readWhole(fd) {
  const size = fs.fstatSync(fd, { bigint: true }).size;
  if (size < 0n || size > BigInt(LIMIT)) fail('OWNER_FS_SIZE');
  const bytes = Buffer.alloc(Number(size));
  let read = 0;
  while (read < bytes.length) {
    const count = fs.readSync(fd, bytes, read, bytes.length - read, read);
    if (!count) fail('OWNER_FS_SHORT_READ');
    read += count;
  }
  return bytes;
}
function writeAll(fd, bytes, position = 0) {
  let written = 0;
  while (written < bytes.length) {
    const count = fs.writeSync(fd, bytes, written, bytes.length - written, position + written);
    if (!count) fail('OWNER_FS_SHORT_WRITE');
    written += count;
  }
}
function operate(input) {
  if (!input || !['inspect', 'create', 'replace', 'append', 'mkdir'].includes(input.action)
    || typeof input.name !== 'string' || !/^[A-Za-z0-9._-]{1,160}$/.test(input.name)
    || ['.', '..'].includes(input.name)) fail('OWNER_FS_INPUT');
  if (!input.expectedParent) fail('OWNER_FS_PARENT_REQUIRED');
  const directoryFd = fs.openSync('.', fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  let fd = null;
  try {
    const parent = checkedStat(fs.fstatSync(directoryFd, { bigint: true }), true);
    if (!same(parent, input.expectedParent)) fail('OWNER_FS_PARENT_CHANGED');
    noAcl('.');
    if (input.action === 'mkdir') {
      fs.mkdirSync(input.name, { mode: 0o700 });
      fd = fs.openSync(input.name, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const result = checkedStat(fs.fstatSync(fd, { bigint: true }), true);
      noAcl(input.name);
      fs.fsyncSync(fd); fs.fsyncSync(directoryFd);
      if (!same(identity(fs.statSync('.', { bigint: true })), parent)) fail('OWNER_FS_PARENT_CHANGED');
      return { identity: result };
    }
    const creating = input.action === 'create';
    if (!creating) {
      const named = fs.lstatSync(input.name, { bigint: true });
      if (named.isSymbolicLink()) fail('OWNER_FS_REPARSE');
    }
    fd = fs.openSync(input.name, fs.constants.O_NOFOLLOW | (creating
      ? fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL
      : input.action === 'inspect' ? fs.constants.O_RDONLY : fs.constants.O_RDWR), 0o600);
    const current = checkedStat(fs.fstatSync(fd, { bigint: true }));
    if (input.expected && !same(current, input.expected)) fail('OWNER_FS_FILE_CHANGED');
    if (!same(current, identity(fs.lstatSync(input.name, { bigint: true })))) fail('OWNER_FS_FILE_CHANGED');
    noAcl(input.name);
    const before = readWhole(fd);
    if (input.expectedHash && digest(before) !== input.expectedHash) fail('OWNER_FS_BYTES_CHANGED');
    if (input.action === 'inspect') return { identity: current, sha256: digest(before), bytes: before.length, data: before.toString('base64') };
    if (!creating && (!input.expected || !/^[0-9a-f]{64}$/.test(input.expectedHash ?? ''))) fail('OWNER_FS_EXPECTED_REQUIRED');
    // Bound the encoded input before decoding. The exact round trip below is
    // the canonical base64 check; a repeated-group regexp can overflow V8's
    // regexp stack for a valid payload at the documented four-MiB bound.
    if (typeof input.data !== 'string' || input.data.length > 4 * Math.ceil(LIMIT / 3)
      || input.data.length % 4 !== 0) fail('OWNER_FS_DATA');
    const payload = Buffer.from(input.data, 'base64');
    if (payload.toString('base64') !== input.data || payload.length > LIMIT
      || (input.length !== undefined && input.length !== payload.length)) fail('OWNER_FS_DATA');
    const after = input.action === 'append' ? Buffer.concat([before, payload]) : payload;
    if (after.length > LIMIT) fail('OWNER_FS_SIZE');
    // Recheck the SAME open FD immediately before the effect. Never operate by name.
    if (!same(checkedStat(fs.fstatSync(fd, { bigint: true })), current)
      || !same(identity(fs.fstatSync(directoryFd, { bigint: true })), parent)
      || digest(readWhole(fd)) !== digest(before)) fail('OWNER_FS_PREWRITE_CHANGED');
    writeAll(fd, payload, input.action === 'append' ? before.length : 0);
    if (input.action !== 'append') fs.ftruncateSync(fd, payload.length);
    fs.fsyncSync(fd);
    const readback = readWhole(fd);
    if (!readback.equals(after) || !same(checkedStat(fs.fstatSync(fd, { bigint: true })), current)) fail('OWNER_FS_READBACK');
    fs.fsyncSync(directoryFd);
    if (!same(identity(fs.lstatSync(input.name, { bigint: true })), current)
      || !same(identity(fs.statSync('.', { bigint: true })), parent)) fail('OWNER_FS_POSTWRITE_CHANGED');
    return { identity: current, sha256: digest(readback), bytes: readback.length };
  } finally {
    // Close errors propagate: they are not evidence of successful resource release.
    try { if (fd !== null) fs.closeSync(fd); } finally { fs.closeSync(directoryFd); }
  }
}
let ioServer = null;
let ioListening = false;
try {
  const raw = fs.readFileSync(0);
  if (raw.length > LIMIT * 2) fail('OWNER_FS_INPUT_SIZE');
  const input = JSON.parse(raw.toString('utf8'));
  if (input.action !== 'inspect') {
    if (!Number.isInteger(input.ioGuardPort) || input.ioGuardPort < 40000 || input.ioGuardPort >= 60000
      || !input.ownerProcess || input.ownerProcess.pid !== process.ppid) fail('OWNER_FS_PARENT_PROCESS');
    ioServer = net.createServer(socket => socket.destroy());
    await new Promise((resolve, reject) => {
      ioServer.once('error', () => reject(Object.assign(new Error('OWNER_FS_IO_GUARD_BUSY'), { code: 'OWNER_FS_IO_GUARD_BUSY' })));
      ioServer.listen({ host: '127.0.0.1', port: input.ioGuardPort, exclusive: true }, () => { ioListening = true; resolve(); });
    });
    // Hold I/O guard BEFORE parent-instance evidence and every possible effect.
    // After a parent crash, a new owner either finds this guard still busy or
    // a late broker must observe its original parent absent and refuse.
    if (probeProcessIdentity(input.ownerProcess).state !== 'active') fail('OWNER_FS_PARENT_PROCESS');
  }
  const result = operate(input);
  if (ioListening) {
    await new Promise((resolve, reject) => ioServer.close(error => error ? reject(error) : resolve()));
    ioListening = false;
  }
  fs.writeFileSync(1, JSON.stringify({ ok: true, result }) + '\n');
} catch (error) {
  if (ioListening) {
    try { await new Promise((resolve, reject) => ioServer.close(fault => fault ? reject(fault) : resolve())); }
    catch { error = Object.assign(new Error('OWNER_FS_IO_CLOSE_UNKNOWN'), { code: 'OWNER_FS_IO_CLOSE_UNKNOWN' }); }
    ioListening = false;
  }
  const original = typeof error?.code === 'string' ? error.code : '';
  const code = /^OWNER_FS_[A-Z_]{1,64}$/.test(original) ? original
    : new Set(['EACCES', 'EPERM', 'EEXIST', 'ENOENT', 'ELOOP', 'ENOTDIR', 'EIO', 'ENOSPC', 'EBADF']).has(original)
      ? 'OWNER_FS_' + original : 'OWNER_FS_FAILED';
  fs.writeFileSync(1, JSON.stringify({ ok: false, error: { code } }) + '\n');
  process.exitCode = 1;
}

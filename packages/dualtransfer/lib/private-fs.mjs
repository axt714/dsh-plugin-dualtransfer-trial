import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
export const failure = code => Object.assign(new Error(code), { code });
export function safeDirectory(directory, { create = false } = {}) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || path.resolve(directory) === path.parse(directory).root) throw failure('PRIVATE_PATH_INVALID');
  const resolved = path.resolve(directory);
  let current = path.parse(resolved).root;
  for (const name of resolved.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, name);
    let st;
    try { st = fs.lstatSync(current); }
    catch (e) {
      if (e.code !== 'ENOENT') throw failure('PRIVATE_PATH_UNSAFE');
      if (!create) return false;
      try { fs.mkdirSync(current, { mode: 0o700 }); } catch { throw failure('PRIVATE_PATH_UNSAFE'); }
      st = fs.lstatSync(current);
    }
    if (!st.isDirectory() || st.isSymbolicLink()) throw failure('PRIVATE_PATH_UNSAFE');
  }
  return true;
}
export function readPrivate(file) {
  if (!safeDirectory(path.dirname(file))) return null;
  const directory = fs.lstatSync(path.dirname(file));
  if (process.platform !== 'win32' && (directory.mode & 0o077)) throw failure('PRIVATE_DIRECTORY_MODE');
  let fd;
  try {
    const before = fs.lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (process.platform !== 'win32' && (before.mode & 0o077))) throw failure('PRIVATE_FILE_UNSAFE');
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.dev !== before.dev || st.ino !== before.ino || st.nlink !== 1 || st.size > 16 * 1024 * 1024
      || (process.platform !== 'win32' && (st.mode & 0o077))) throw failure('PRIVATE_FILE_UNSAFE');
    const bytes = fs.readFileSync(fd), text = bytes.toString('utf8');
    if (!Buffer.from(text).equals(bytes)) throw failure('PRIVATE_FILE_CORRUPT');
    try { return JSON.parse(text); } catch { throw failure('PRIVATE_FILE_CORRUPT'); }
  } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
export function syncDir(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY);
  let primary, unsupported = false, openedDirectory = false;
  try { openedDirectory = fs.fstatSync(fd).isDirectory(); fs.fsyncSync(fd); }
  catch (error) {
    if (openedDirectory && process.platform === 'win32' && error.code === 'EPERM') unsupported = true;
    else primary = error;
  }
  try { fs.closeSync(fd); } catch (error) { if (!primary) throw error; }
  if (primary) throw primary;
  // Only an opened Windows directory's fsync EPERM is unsupported. File fsync,
  // directory open and close still fail; this is not POSIX power-loss durability.
  return { directoryDurability: unsupported ? 'unsupported' : 'synced' };
}
export function atomicPrivate(file, value) {
  safeDirectory(path.dirname(file), { create: true });
  const dirStat = fs.lstatSync(path.dirname(file));
  if (process.platform !== 'win32' && (dirStat.mode & 0o077)) throw failure('PRIVATE_DIRECTORY_MODE');
  // Fail closed rather than replace links or untrusted existing state.
  readPrivate(file);
  const temporary = file + '.tmp-' + randomUUID();
  let fd, created = false;
  try {
    fd = fs.openSync(temporary, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
    created = true; fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    const latestDir = fs.lstatSync(path.dirname(file));
    if (!latestDir.isDirectory() || latestDir.isSymbolicLink() || latestDir.dev !== dirStat.dev || latestDir.ino !== dirStat.ino) throw failure('PRIVATE_PATH_UNSAFE');
    readPrivate(file); fs.renameSync(temporary, file); created = false; syncDir(path.dirname(file));
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    // Only this exact, locally-created temporary file is eligible for cleanup.
    if (created && path.dirname(temporary) === path.dirname(file)) { try { fs.unlinkSync(temporary); } catch {} }
  }
}
export function exclusiveFile(file, value) {
  // Serialization must not leave an O_EXCL file (or a newly-created directory).
  const contents = Buffer.from(JSON.stringify(value) + '\n');
  safeDirectory(path.dirname(file), { create: true });
  const directory = fs.lstatSync(path.dirname(file));
  if (process.platform !== 'win32' && (directory.mode & 0o077)) throw failure('PRIVATE_DIRECTORY_MODE');
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600); }
  catch (cause) {
    throw Object.assign(failure(cause.code === 'EEXIST' ? 'PRODUCT_OWNER_LOCKED' : 'PRODUCT_OWNER_FAILED'),
      { cause, sourceCode: cause.code, syscall: cause.syscall, stage: 'open' });
  }
  let owned, closeState = 'open', closeError, readerCloseError, stage = 'identity';
  const trustworthy = st => st.isFile() && !st.isSymbolicLink() && st.nlink === 1n
    && typeof st.dev === 'bigint' && st.dev >= 0n && typeof st.ino === 'bigint' && st.ino > 0n;
  const matches = st => owned && trustworthy(st) && st.dev === owned.dev && st.ino === owned.ino;
  const unchanged = (a, b) => matches(a) && matches(b) && a.size === b.size && a.mode === b.mode
    && typeof a.mtimeNs === 'bigint' && a.mtimeNs === b.mtimeNs
    && typeof a.ctimeNs === 'bigint' && a.ctimeNs === b.ctimeNs;
  const closeOwner = () => {
    if (closeState === 'closed') return;
    if (closeState === 'uncertain') throw closeError;
    // A failed close may already have closed/reused this number. Never retry it.
    closeState = 'uncertain';
    try { fs.closeSync(fd); } catch (error) { closeError = error; throw error; }
    closeState = 'closed';
  };
  const verifyOwned = () => {
    if (readerCloseError) throw readerCloseError;
    const before = fs.lstatSync(file, { bigint: true });
    if (!matches(before) || before.size !== BigInt(contents.length)) throw failure('PRODUCT_OWNER_CHANGED');
    let reader, primary, snapshot;
    try {
      reader = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      const opened = fs.fstatSync(reader, { bigint: true });
      if (!unchanged(before, opened)) throw failure('PRODUCT_OWNER_CHANGED');
      // Read only after no-follow open + fd identity checks, with an owned-size bound.
      const bytes = Buffer.alloc(contents.length + 1);
      let length = 0;
      while (length < bytes.length) {
        const count = fs.readSync(reader, bytes, length, bytes.length - length, length);
        if (!count) break;
        length += count;
      }
      snapshot = fs.fstatSync(reader, { bigint: true });
      if (length !== contents.length || !bytes.subarray(0, length).equals(contents) || !unchanged(opened, snapshot)) throw failure('PRODUCT_OWNER_CHANGED');
    } catch (error) { primary = error; }
    if (reader !== undefined) {
      try { fs.closeSync(reader); }
      catch (error) { readerCloseError = error; if (!primary) primary = error; }
    }
    if (primary) throw primary;
    // Recheck after reader close; changed paths, links and metadata are retained.
    if (!unchanged(snapshot, fs.lstatSync(file, { bigint: true }))) throw failure('PRODUCT_OWNER_CHANGED');
  };
  try {
    owned = fs.fstatSync(fd, { bigint: true });
    if (!trustworthy(owned)) throw failure('PRODUCT_OWNER_CHANGED');
    stage = 'chmod'; fs.fchmodSync(fd, 0o600);
    stage = 'write'; fs.writeFileSync(fd, contents);
    stage = 'file-sync'; fs.fsyncSync(fd);
    stage = 'directory-sync'; syncDir(path.dirname(file));
  } catch (error) {
    try { if (error.stage === undefined) error.stage = stage; } catch {}
    // Only this O_EXCL creation, with trustworthy fd identity AND complete matching
    // bytes, is eligible. Partial writes/unknown identity/uncertain close stay put.
    try {
      closeOwner();
      if (owned && trustworthy(owned)) { verifyOwned(); fs.unlinkSync(file); syncDir(path.dirname(file)); }
    } catch {} // Cleanup/close must not replace the acquisition's primary error.
    throw error;
  }
  let releaseStage = 'close';
  return () => {
    if (releaseStage === 'released') return;
    let attemptStage = releaseStage;
    try {
      if (releaseStage === 'close') { closeOwner(); releaseStage = 'verify'; }
      if (releaseStage === 'verify') {
        attemptStage = 'verify'; verifyOwned(); releaseStage = 'unlink';
      }
      if (releaseStage === 'unlink') {
        // An unlink failure requires fresh path/content verification on retry.
        attemptStage = 'unlink'; releaseStage = 'verify'; fs.unlinkSync(file); releaseStage = 'directory-sync';
      }
      // Once unlinked, retries may only sync the directory, never touch a new lock.
      if (releaseStage === 'directory-sync') { attemptStage = 'directory-sync'; syncDir(path.dirname(file)); releaseStage = 'released'; }
    } catch (error) {
      try { if (error.stage === undefined) error.stage = attemptStage; } catch {}
      throw error;
    }
  };
}

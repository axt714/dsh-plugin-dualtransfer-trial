import path from 'node:path';

const clean = (value) => typeof value === 'string' && !/[\x00-\x1f\x7f-\x9f]/.test(value);

// Pure validators also support opposite-platform matrix tests without changing
// the production factory's platform or accepting both path syntaxes there.
export function isWindowsLocalAbsolutePath(value) {
  return clean(value) && path.win32.isAbsolute(value) && /^[A-Za-z]:[\\/]/.test(value) && !value.slice(2).includes(':');
}

export function isPosixLocalAbsolutePath(value) {
  return clean(value) && path.posix.isAbsolute(value) && !value.startsWith('//');
}

export function isLocalAbsoluteConfigPath(value) {
  if (!clean(value) || !path.isAbsolute(value)) return false;
  return path.sep === '\\' ? isWindowsLocalAbsolutePath(value) : isPosixLocalAbsolutePath(value);
}

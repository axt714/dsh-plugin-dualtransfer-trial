'use strict';
// Pure path syntax policy. Never touches the filesystem or discovers a user's HOME.
const path = require('node:path');
const clean = value => typeof value === 'string' && !/[\x00-\x1f\x7f-\x9f]/.test(value);

function isLocalAbsolutePath(value, platform = process.platform) {
  if (!clean(value)) return false;
  if (platform === 'win32') {
    return path.win32.isAbsolute(value) && /^[A-Za-z]:[\\/]/.test(value) && !value.slice(2).includes(':');
  }
  return path.posix.isAbsolute(value) && !value.startsWith('//');
}

function sameLocalPath(left, right, platform = process.platform) {
  if (!isLocalAbsolutePath(left, platform) || !isLocalAbsolutePath(right, platform)) return false;
  if (platform === 'win32') return path.win32.resolve(left).toLowerCase() === path.win32.resolve(right).toLowerCase();
  return path.posix.resolve(left) === path.posix.resolve(right);
}

module.exports = { isLocalAbsolutePath, sameLocalPath };

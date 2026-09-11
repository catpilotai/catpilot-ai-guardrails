// POSIX example. The administrator-owned root and its ancestors must not be
// writable by an attacker. This is not a sandbox for an arbitrary directory tree.
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');

async function safeRead(directory, filename, maxBytes = 65536) {
  if (typeof filename !== 'string' || !filename || ['.', '..'].includes(filename)
      || /[\\/\x00]/.test(filename)) throw new Error('single basename required');
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 1048576) throw new Error('file limit');
  if (!constants.O_NOFOLLOW || process.platform === 'win32') throw new Error('POSIX no-follow required');
  const root = await fs.realpath(directory);
  const candidate = path.join(root, filename);
  const resolved = await fs.realpath(candidate);
  if (resolved !== candidate || path.dirname(resolved) !== root) throw new Error('symlink or path escape');
  const file = await fs.open(candidate, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    if (!info.isFile()) throw new Error('not a regular file');
    const buffer = Buffer.alloc(maxBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length > maxBytes) throw new Error('file too large');
    return buffer.subarray(0, length);
  } finally {
    await file.close();
  }
}

module.exports = { safeRead };

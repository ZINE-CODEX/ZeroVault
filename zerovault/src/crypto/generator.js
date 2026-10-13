/**
 * generator.js  -  random password generator
 * ------------------------------------------------------------------
 * Uses crypto.getRandomValues (secure randomness) and "rejection
 * sampling" to avoid modulo bias: if we simply did `random % 70`, some
 * characters would appear slightly more often than others, because 2^32
 * is not evenly divisible by 70. Instead we throw away random values
 * that fall in the uneven leftover range.
 */
const CHARSET =
  'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+?';
// (look-alike characters 0 O 1 l I are left out on purpose)

export function generatePassword(length = 20) {
  if (!Number.isInteger(length) || length < 8 || length > 128) {
    throw new RangeError('Length must be a whole number between 8 and 128.');
  }

  const limit = Math.floor(0x100000000 / CHARSET.length) * CHARSET.length;
  let out = '';
  const buffer = new Uint32Array(1);

  while (out.length < length) {
    globalThis.crypto.getRandomValues(buffer);
    if (buffer[0] >= limit) continue; // reject: would cause bias
    out += CHARSET[buffer[0] % CHARSET.length];
  }
  return out;
}

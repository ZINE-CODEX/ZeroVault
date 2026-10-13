/**
 * errors.js
 * ------------------------------------------------------------------
 * Small custom error classes so the UI can show a helpful message
 * instead of a generic "something went wrong".
 */

/** The input is not a ZeroVault file (wrong magic, truncated, bad header). */
export class FormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FormatError';
  }
}

/**
 * Decryption failed authentication. With AES-GCM this means EITHER the
 * password is wrong OR the data was modified. The cipher cannot tell
 * which, and we deliberately do not pretend to.
 */
export class DecryptionError extends Error {
  constructor(message = 'Wrong password, or the file has been modified or corrupted.') {
    super(message);
    this.name = 'DecryptionError';
  }
}

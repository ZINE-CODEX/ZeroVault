/**
 * Public API of the crypto layer. The UI and tests import from here,
 * never from the individual files, so internals can change freely.
 */
export { encryptBlob, decryptBlob } from './cipher.js';
export { encryptText, encryptTextWithInfo, decryptText } from './text.js';
export { estimateStrength } from './strength.js';
export { generatePassword } from './generator.js';
export { FormatError, DecryptionError } from './errors.js';
export { FILE_EXTENSION, DEFAULT_KDF_ITERATIONS } from './constants.js';

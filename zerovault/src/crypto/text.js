/**
 * text.js  -  encrypt/decrypt strings
 * ------------------------------------------------------------------
 * Text reuses the exact same file format as binary files. The only
 * extra step is converting to/from base64 so the result is a plain
 * string you can paste into a chat or email.
 */
import { encryptBlob, decryptBlob } from './cipher.js';
import { bytesToBase64, base64ToBytes } from './bytes.js';
import { FormatError } from './errors.js';

/**
 * Like encryptText(), but also returns details about the output
 * (chunk count, sizes, ...) which the UI uses for its "Inside your
 * encrypted file" panel.
 * @returns {Promise<{text: string, info: object}>}
 */
export async function encryptTextWithInfo(plaintext, password, options = {}) {
  const input = new Blob([new TextEncoder().encode(plaintext)]);
  const { blob, info } = await encryptBlob(input, password, options);
  return { text: bytesToBase64(new Uint8Array(await blob.arrayBuffer())), info };
}

/** @returns {Promise<string>} base64 text of a complete ZeroVault file */
export async function encryptText(plaintext, password, options = {}) {
  return (await encryptTextWithInfo(plaintext, password, options)).text;
}

/** @returns {Promise<string>} the original text */
export async function decryptText(base64, password, options = {}) {
  let bytes;
  try {
    bytes = base64ToBytes(base64);
  } catch {
    throw new FormatError('That does not look like encrypted text (invalid base64).');
  }
  const blob = await decryptBlob(new Blob([bytes]), password, options);
  return new TextDecoder('utf-8', { fatal: true }).decode(await blob.arrayBuffer());
}

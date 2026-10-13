/**
 * kdf.js  -  turning a human password into a real encryption key
 * ------------------------------------------------------------------
 * A password like "tiger2024" is not a usable AES key: it is short and
 * guessable. A KDF (key-derivation function) fixes this in two ways:
 *
 *   1. SALT: a random value stored in the file. It makes the derived key
 *      different for every file, so an attacker cannot precompute a table
 *      of "password -> key" and reuse it against many files.
 *
 *   2. WORK FACTOR: PBKDF2 repeats HMAC-SHA256 hundreds of thousands of
 *      times. That costs you ~0.2 seconds once, but costs an attacker the
 *      same 0.2 seconds for EVERY password guess.
 *
 * We use the browser's built-in implementation (Web Crypto), so there is
 * no third-party code to trust. The derived key is "non-extractable":
 * JavaScript can use it to encrypt/decrypt but can never read its bytes.
 */

const encoder = new TextEncoder();

/**
 * @param {string} password
 * @param {Uint8Array} salt        16 random bytes
 * @param {number} iterations      PBKDF2 iteration count
 * @returns {Promise<CryptoKey>}   AES-256-GCM key
 */
export async function deriveKey(password, salt, iterations) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new TypeError('A password is required.');
  }

  // Step 1: wrap the password bytes as key *material* for PBKDF2.
  // normalize('NFKC') makes visually identical Unicode passwords match
  // (e.g. "é" typed as one character vs. "e" + accent).
  const material = await globalThis.crypto.subtle.importKey(
    'raw',
    encoder.encode(password.normalize('NFKC')),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  // Step 2: stretch it into a 256-bit AES-GCM key.
  return globalThis.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt'],
  );
}

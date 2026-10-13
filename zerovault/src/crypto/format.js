/**
 * format.js  -  reading and writing the 38-byte file header
 * ------------------------------------------------------------------
 * Every encrypted file starts with a small, NON-secret header holding the
 * settings needed to decrypt it later (salt, iteration count, ...).
 * None of it helps an attacker without the password.
 *
 * The header is also fed into every chunk as "additional authenticated
 * data" (see cipher.js), so tampering with it makes decryption fail.
 *
 * Layout (full description in docs/FILE_FORMAT.md):
 *   0   4  magic "ZVLT"
 *   4   1  version
 *   5   1  KDF id
 *   6   4  PBKDF2 iterations (big-endian)
 *  10   4  plaintext chunk size (big-endian)
 *  14  16  salt
 *  30   8  IV prefix
 */
import {
  MAGIC, FORMAT_VERSION, KDF_PBKDF2_SHA256, HEADER,
  MIN_KDF_ITERATIONS, MAX_KDF_ITERATIONS, MAX_CHUNK_SIZE,
  SALT_LENGTH, IV_PREFIX_LENGTH,
} from './constants.js';
import { u32ToBytes, bytesToU32, concatBytes } from './bytes.js';
import { FormatError } from './errors.js';

/** Build the header bytes for a new file. */
export function encodeHeader({ iterations, chunkSize, salt, ivPrefix }) {
  return concatBytes(
    MAGIC,
    new Uint8Array([FORMAT_VERSION]),
    new Uint8Array([KDF_PBKDF2_SHA256]),
    u32ToBytes(iterations),
    u32ToBytes(chunkSize),
    salt,
    ivPrefix,
  );
}

/**
 * Parse and VALIDATE a header. Never trust a file's own claims:
 * every field is range-checked before it is used.
 *
 * @param {Uint8Array} bytes  at least HEADER.LENGTH bytes
 * @returns {{version:number, iterations:number, chunkSize:number,
 *            salt:Uint8Array, ivPrefix:Uint8Array, raw:Uint8Array}}
 */
export function decodeHeader(bytes) {
  if (bytes.length < HEADER.LENGTH) {
    throw new FormatError('File is too short to be a ZeroVault file.');
  }
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[HEADER.MAGIC + i] !== MAGIC[i]) {
      throw new FormatError('Not a ZeroVault file (missing "ZVLT" signature).');
    }
  }

  const version = bytes[HEADER.VERSION];
  if (version !== FORMAT_VERSION) {
    throw new FormatError(`Unsupported file version ${version}.`);
  }
  if (bytes[HEADER.KDF] !== KDF_PBKDF2_SHA256) {
    throw new FormatError('Unsupported key-derivation function.');
  }

  const iterations = bytesToU32(bytes, HEADER.ITERATIONS);
  if (iterations < MIN_KDF_ITERATIONS || iterations > MAX_KDF_ITERATIONS) {
    throw new FormatError('Header contains an unreasonable iteration count.');
  }

  const chunkSize = bytesToU32(bytes, HEADER.CHUNK_SIZE);
  if (chunkSize < 1 || chunkSize > MAX_CHUNK_SIZE) {
    throw new FormatError('Header contains an invalid chunk size.');
  }

  return {
    version,
    iterations,
    chunkSize,
    salt: bytes.slice(HEADER.SALT, HEADER.SALT + SALT_LENGTH),
    ivPrefix: bytes.slice(HEADER.IV_PREFIX, HEADER.IV_PREFIX + IV_PREFIX_LENGTH),
    raw: bytes.slice(0, HEADER.LENGTH), // kept to bind into each chunk's AAD
  };
}

/**
 * cipher.js  -  the heart of ZeroVault: chunked AES-256-GCM encryption
 * ------------------------------------------------------------------
 * WHY AES-GCM?
 *   GCM is "authenticated encryption": besides hiding the data it adds a
 *   16-byte tag to every encrypted chunk. If even ONE bit of the chunk,
 *   the password, or the bound metadata is wrong, decryption throws
 *   instead of returning garbage. So you can never silently get tampered data.
 *
 * WHY CHUNKS?
 *   Large files are cut into 1 MiB pieces that are encrypted one at a
 *   time, so a multi-GB file never has to sit in memory all at once.
 *
 * THE THREE RULES THAT KEEP CHUNKING SAFE
 *   1. Unique IV per chunk:  IV = 8 random bytes (per file) + chunk number.
 *      GCM breaks badly if a key+IV pair is ever reused. The counter
 *      guarantees uniqueness inside a file; the key is unique per file
 *      because the salt is random.
 *   2. Chunks can't be reordered or swapped: the chunk number is bound
 *      into each chunk's tag as "additional authenticated data" (AAD).
 *   3. Files can't be silently truncated: the AAD also carries a "this is
 *      the final chunk" flag. Cutting the file at a chunk boundary leaves a
 *      last chunk that was NOT flagged final, so authentication fails.
 *
 * The header (salt, iterations, ...) is part of every chunk's AAD too, so
 * editing the header invalidates the whole file.
 */
import {
  DEFAULT_KDF_ITERATIONS, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE,
  SALT_LENGTH, IV_PREFIX_LENGTH, IV_LENGTH, TAG_LENGTH, HEADER,
} from './constants.js';
import { randomBytes, u32ToBytes, concatBytes } from './bytes.js';
import { deriveKey } from './kdf.js';
import { encodeHeader, decodeHeader } from './format.js';
import { FormatError, DecryptionError } from './errors.js';

/** IV for chunk number `index`: 8 random per-file bytes + 4-byte counter. */
function buildIv(ivPrefix, index) {
  return concatBytes(ivPrefix, u32ToBytes(index)); // 8 + 4 = 12 bytes
}

/**
 * Additional authenticated data for one chunk:
 *   header (38 bytes) + chunk index (4 bytes) + final flag (1 byte)
 * It is NOT encrypted or stored per chunk; encryptor and decryptor each
 * rebuild it, and GCM refuses to decrypt if their versions differ.
 */
function buildAad(headerBytes, index, isFinal) {
  return concatBytes(headerBytes, u32ToBytes(index), new Uint8Array([isFinal ? 1 : 0]));
}

/**
 * Encrypt a Blob/File.
 *
 * @param {Blob} input
 * @param {string} password
 * @param {object} [options]
 * @param {number} [options.chunkSize]   plaintext bytes per chunk
 * @param {number} [options.iterations]  PBKDF2 iterations (lower only in tests!)
 * @param {(done:number,total:number)=>void} [options.onProgress]
 * @returns {Promise<{blob: Blob, info: object}>}
 *          `blob` is the encrypted file, `info` describes what was produced.
 */
export async function encryptBlob(input, password, options = {}) {
  const {
    chunkSize = DEFAULT_CHUNK_SIZE,
    iterations = DEFAULT_KDF_ITERATIONS,
    onProgress,
  } = options;

  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_CHUNK_SIZE) {
    throw new RangeError('Invalid chunk size.');
  }

  // 1. Fresh randomness for this file only.
  const salt = randomBytes(SALT_LENGTH);
  const ivPrefix = randomBytes(IV_PREFIX_LENGTH);

  // 2. Header + key.
  const header = encodeHeader({ iterations, chunkSize, salt, ivPrefix });
  const key = await deriveKey(password, salt, iterations);

  // 3. Encrypt chunk by chunk. An empty file still gets ONE (empty) chunk,
  //    so there is always a final, authenticated chunk to check.
  const chunkCount = Math.max(1, Math.ceil(input.size / chunkSize));
  const parts = [header];

  for (let index = 0; index < chunkCount; index++) {
    const start = index * chunkSize;
    const plain = await input.slice(start, start + chunkSize).arrayBuffer();
    const isFinal = index === chunkCount - 1;

    const cipher = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: buildIv(ivPrefix, index),
        additionalData: buildAad(header, index, isFinal),
        tagLength: TAG_LENGTH * 8,
      },
      key,
      plain,
    );

    parts.push(new Uint8Array(cipher)); // ciphertext + 16-byte tag
    if (onProgress) onProgress(index + 1, chunkCount);
  }

  const blob = new Blob(parts, { type: 'application/octet-stream' });
  return {
    blob,
    info: {
      iterations,
      chunkSize,
      chunkCount,
      plainSize: input.size,
      encryptedSize: blob.size,
      overheadBytes: blob.size - input.size,
    },
  };
}

/**
 * Decrypt a Blob/File produced by encryptBlob().
 *
 * @param {Blob} input
 * @param {string} password
 * @param {object} [options]
 * @param {(done:number,total:number)=>void} [options.onProgress]
 * @returns {Promise<Blob>} the original bytes
 * @throws {FormatError}     not a ZeroVault file / damaged header
 * @throws {DecryptionError} wrong password or data was modified
 */
export async function decryptBlob(input, password, options = {}) {
  const { onProgress } = options;

  // 1. Read + validate the header.
  const headerBytes = new Uint8Array(await input.slice(0, HEADER.LENGTH).arrayBuffer());
  const header = decodeHeader(headerBytes);

  // 2. Work out the chunk layout from the file size alone.
  //    Every encrypted chunk is (chunkSize + 16) bytes except possibly the last.
  const bodySize = input.size - HEADER.LENGTH;
  const encChunkSize = header.chunkSize + TAG_LENGTH;
  if (bodySize < TAG_LENGTH) throw new FormatError('File is truncated.');

  const chunkCount = Math.ceil(bodySize / encChunkSize);
  const lastChunkSize = bodySize - (chunkCount - 1) * encChunkSize;
  if (lastChunkSize < TAG_LENGTH) throw new FormatError('File is truncated.');

  // 3. Derive the key (slow on purpose: this is the brute-force speed bump).
  const key = await deriveKey(password, header.salt, header.iterations);

  // 4. Decrypt each chunk. Any failure means wrong password OR tampering.
  const parts = [];
  for (let index = 0; index < chunkCount; index++) {
    const start = HEADER.LENGTH + index * encChunkSize;
    const isFinal = index === chunkCount - 1;
    const cipher = await input.slice(start, start + encChunkSize).arrayBuffer();

    let plain;
    try {
      plain = await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: buildIv(header.ivPrefix, index),
          additionalData: buildAad(header.raw, index, isFinal),
          tagLength: TAG_LENGTH * 8,
        },
        key,
        cipher,
      );
    } catch {
      throw new DecryptionError();
    }

    parts.push(new Uint8Array(plain));
    if (onProgress) onProgress(index + 1, chunkCount);
  }

  return new Blob(parts, { type: 'application/octet-stream' });
}

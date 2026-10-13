/**
 * constants.js
 * ------------------------------------------------------------------
 * Every "magic number" used by the encryption format lives here, with
 * a note on why it was chosen. Keeping them in one place makes the
 * format easy to audit and to version later.
 */

/** First 4 bytes of every encrypted file: ASCII "ZVLT" (ZeroVault). */
export const MAGIC = new Uint8Array([0x5a, 0x56, 0x4c, 0x54]);

/** File-format version. Bump this if the layout ever changes. */
export const FORMAT_VERSION = 1;

/** Identifier for the key-derivation function stored in the header. */
export const KDF_PBKDF2_SHA256 = 1;

/**
 * PBKDF2 iteration count for new files.
 * 600,000 is the OWASP (2023) recommendation for PBKDF2-HMAC-SHA256.
 * Higher = slower password guessing for an attacker (and slightly slower
 * unlocking for you, usually well under a second).
 */
export const DEFAULT_KDF_ITERATIONS = 600_000;

/**
 * Sanity bounds applied when READING a file. Without an upper bound, a
 * malicious file could ask for billions of iterations and freeze the tab.
 */
export const MIN_KDF_ITERATIONS = 1_000;
export const MAX_KDF_ITERATIONS = 10_000_000;

/** Random salt length in bytes (128 bits). Unique per file. */
export const SALT_LENGTH = 16;

/**
 * AES-GCM needs a 96-bit (12 byte) IV that is NEVER reused with the same
 * key. We build it as: 8 random bytes (per file) + 4-byte chunk counter.
 */
export const IV_PREFIX_LENGTH = 8;
export const IV_LENGTH = 12;

/** GCM authentication tag length: 128 bits (16 bytes), the maximum. */
export const TAG_LENGTH = 16;

/** Plain-text bytes encrypted per chunk (1 MiB). Keeps memory use low. */
export const DEFAULT_CHUNK_SIZE = 1024 * 1024;
export const MAX_CHUNK_SIZE = 64 * 1024 * 1024;

/** Header layout (byte offsets). Total = 38 bytes. See docs/FILE_FORMAT.md */
export const HEADER = Object.freeze({
  MAGIC: 0, //       4 bytes
  VERSION: 4, //     1 byte
  KDF: 5, //         1 byte
  ITERATIONS: 6, //  4 bytes, big-endian
  CHUNK_SIZE: 10, // 4 bytes, big-endian
  SALT: 14, //       16 bytes
  IV_PREFIX: 30, //  8 bytes
  LENGTH: 38,
});

/** Conventional extension for encrypted files. */
export const FILE_EXTENSION = '.zvlt';

/**
 * bytes.js
 * ------------------------------------------------------------------
 * Tiny helpers for working with raw bytes: big-endian integers,
 * concatenation, and base64 (used so encrypted TEXT can be copy-pasted).
 */

/** Write a 32-bit unsigned integer, big-endian, into a new 4-byte array. */
export function u32ToBytes(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false); // false = big-endian
  return out;
}

/** Read a 32-bit unsigned big-endian integer from `bytes` at `offset`. */
export function bytesToU32(bytes, offset = 0) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);
}

/** Join several Uint8Arrays into one. */
export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** Cryptographically secure random bytes (never use Math.random for this). */
export function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Uint8Array -> base64 string.
 * Done in slices because String.fromCharCode(...hugeArray) overflows
 * the call stack for large inputs.
 */
export function bytesToBase64(bytes) {
  const SLICE = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += SLICE) {
    binary += String.fromCharCode(...bytes.subarray(i, i + SLICE));
  }
  return btoa(binary);
}

/** base64 string -> Uint8Array. Whitespace/newlines are ignored. */
export function base64ToBytes(base64) {
  const binary = atob(base64.replace(/\s+/g, ''));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

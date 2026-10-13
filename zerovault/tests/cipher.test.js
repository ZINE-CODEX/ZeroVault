/**
 * Tests for the crypto core. Run with:  npm test
 *
 * We pass a LOW iteration count (1,000) so the suite runs in seconds.
 * Production code defaults to 600,000 (see constants.js).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encryptBlob, decryptBlob, encryptText, decryptText, DecryptionError, FormatError } from '../src/crypto/index.js';

const FAST = { iterations: 1000, chunkSize: 16 }; // tiny chunks => many chunks per test
const PASSWORD = 'correct horse battery staple';

const toBytes = async (blob) => new Uint8Array(await blob.arrayBuffer());
const makeBlob = (text) => new Blob([new TextEncoder().encode(text)]);

test('round-trip: text', async () => {
  const secret = 'Meet at dawn. Bring the keys. 🔑';
  const encrypted = await encryptText(secret, PASSWORD, FAST);
  assert.notEqual(encrypted, secret);
  assert.equal(await decryptText(encrypted, PASSWORD), secret);
});

test('round-trip: binary file spanning many chunks', async () => {
  const data = new Uint8Array(1000).map((_, i) => (i * 7) % 256);
  const { blob, info } = await encryptBlob(new Blob([data]), PASSWORD, FAST);
  assert.equal(info.chunkCount, Math.ceil(1000 / 16));
  const plain = await toBytes(await decryptBlob(blob, PASSWORD));
  assert.deepEqual(plain, data);
});

test('round-trip: size exactly a multiple of the chunk size', async () => {
  const data = new Uint8Array(64).fill(42); // 4 chunks of 16
  const { blob } = await encryptBlob(new Blob([data]), PASSWORD, FAST);
  assert.deepEqual(await toBytes(await decryptBlob(blob, PASSWORD)), data);
});

test('round-trip: empty file', async () => {
  const { blob, info } = await encryptBlob(new Blob([]), PASSWORD, FAST);
  assert.equal(info.chunkCount, 1);
  assert.equal((await decryptBlob(blob, PASSWORD)).size, 0);
});

test('wrong password is rejected', async () => {
  const { blob } = await encryptBlob(makeBlob('top secret'), PASSWORD, FAST);
  await assert.rejects(decryptBlob(blob, 'wrong password'), DecryptionError);
});

test('same input + password never produces the same output (random salt/IV)', async () => {
  const a = await toBytes((await encryptBlob(makeBlob('same'), PASSWORD, FAST)).blob);
  const b = await toBytes((await encryptBlob(makeBlob('same'), PASSWORD, FAST)).blob);
  assert.notDeepEqual(a, b);
});

test('flipping a single bit in the ciphertext is detected', async () => {
  const { blob } = await encryptBlob(makeBlob('x'.repeat(100)), PASSWORD, FAST);
  const bytes = await toBytes(blob);
  bytes[bytes.length - 20] ^= 0x01;
  await assert.rejects(decryptBlob(new Blob([bytes]), PASSWORD), DecryptionError);
});

test('editing the header (bound as AAD) is detected', async () => {
  const { blob } = await encryptBlob(makeBlob('x'.repeat(100)), PASSWORD, FAST);
  const bytes = await toBytes(blob);
  bytes[10 + 3] ^= 0x01; // change the stored chunk size by one
  await assert.rejects(decryptBlob(new Blob([bytes]), PASSWORD), (e) => e instanceof DecryptionError || e instanceof FormatError);
});

test('truncating at a chunk boundary is detected', async () => {
  const { blob } = await encryptBlob(new Blob([new Uint8Array(64)]), PASSWORD, FAST);
  const bytes = await toBytes(blob);
  const oneChunk = 16 + 16; // chunkSize + tag
  const truncated = bytes.slice(0, bytes.length - oneChunk); // drop the last chunk cleanly
  await assert.rejects(decryptBlob(new Blob([truncated]), PASSWORD), DecryptionError);
});

test('reordering two chunks is detected', async () => {
  const { blob } = await encryptBlob(new Blob([new Uint8Array(48).map((_, i) => i)]), PASSWORD, FAST);
  const bytes = await toBytes(blob);
  const H = 38, C = 32;
  const swapped = new Uint8Array(bytes);
  swapped.set(bytes.slice(H + C, H + 2 * C), H);      // chunk 1 -> position 0
  swapped.set(bytes.slice(H, H + C), H + C);          // chunk 0 -> position 1
  await assert.rejects(decryptBlob(new Blob([swapped]), PASSWORD), DecryptionError);
});

test('non-ZeroVault input gives a FormatError, not a crash', async () => {
  await assert.rejects(decryptBlob(makeBlob('this is just a text file with no header at all......'), PASSWORD), FormatError);
  await assert.rejects(decryptBlob(makeBlob('short'), PASSWORD), FormatError);
});

test('absurd iteration count in a header is refused (DoS guard)', async () => {
  const { blob } = await encryptBlob(makeBlob('hello'), PASSWORD, FAST);
  const bytes = await toBytes(blob);
  new DataView(bytes.buffer).setUint32(6, 4_000_000_000, false);
  await assert.rejects(decryptBlob(new Blob([bytes]), PASSWORD), FormatError);
});

test('onProgress reports every chunk', async () => {
  const calls = [];
  await encryptBlob(new Blob([new Uint8Array(40)]), PASSWORD, { ...FAST, onProgress: (d, t) => calls.push([d, t]) });
  assert.deepEqual(calls, [[1, 3], [2, 3], [3, 3]]);
});

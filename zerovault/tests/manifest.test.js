import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyManifest } from '../scripts/manifest.js';

test('SHA256SUMS is up to date (run `npm run manifest` if this fails)', async () => {
  assert.deepEqual(await verifyManifest(), []);
});

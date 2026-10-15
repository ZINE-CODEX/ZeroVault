/**
 * manifest.js  -  fingerprints of the app's files
 * ------------------------------------------------------------------
 * Writes SHA256SUMS: one SHA-256 hash per file the browser loads.
 * Anyone can verify their copy is unmodified:
 *
 *   Linux / macOS:   sha256sum -c SHA256SUMS      (macOS: shasum -a 256 -c SHA256SUMS)
 *   Any OS:          npm run verify
 *
 * src/config.js is deliberately NOT listed: you edit it with your own
 * Google client ID, so its contents differ per person.
 *
 * Run `npm run manifest` after changing any app file (a test fails if
 * you forget, so the list can never go stale).
 */
import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join, resolve, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const EXCLUDED = new Set(['src/config.js']);

async function listFiles(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await listFiles(full)));
    else out.push(full);
  }
  return out;
}

/** @returns {Promise<string>} the manifest text, in `sha256sum` format */
export async function buildManifest() {
  const files = [join(ROOT, 'index.html'), ...(await listFiles(join(ROOT, 'src')))]
    .map((f) => relative(ROOT, f).split(sep).join('/'))
    .filter((f) => !EXCLUDED.has(f))
    .sort();

  const lines = [];
  for (const file of files) {
    const hash = createHash('sha256').update(await readFile(join(ROOT, file))).digest('hex');
    lines.push(`${hash}  ${file}`); // two spaces = the format sha256sum expects
  }
  return `${lines.join('\n')}\n`;
}

/** @returns {Promise<string[]>} files whose hash does not match SHA256SUMS */
export async function verifyManifest() {
  const expected = await readFile(join(ROOT, 'SHA256SUMS'), 'utf8');
  const actual = await buildManifest();
  const want = new Map(expected.trim().split('\n').map((l) => l.split(/\s{2}/).reverse()));
  const have = new Map(actual.trim().split('\n').map((l) => l.split(/\s{2}/).reverse()));
  const bad = [];
  for (const name of new Set([...want.keys(), ...have.keys()])) {
    if (want.get(name) !== have.get(name)) bad.push(name);
  }
  return bad;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  if (process.argv.includes('--verify')) {
    const bad = await verifyManifest();
    if (bad.length) {
      console.error(`MISMATCH in: ${bad.join(', ')}`);
      process.exit(1);
    }
    console.log('OK: every file matches SHA256SUMS');
  } else {
    await writeFile(join(ROOT, 'SHA256SUMS'), await buildManifest());
    console.log('SHA256SUMS updated');
  }
}

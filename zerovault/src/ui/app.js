/**
 * app.js  -  wires the page to the crypto and cloud layers
 * ------------------------------------------------------------------
 * This file contains NO cryptography. It only:
 *   1. reads what the user typed/picked,
 *   2. calls the functions from ../crypto/index.js,
 *   3. shows results, progress and errors.
 *
 * Keeping the two apart means the security-critical code stays small,
 * testable in Node, and free of DOM concerns.
 */
import {
  encryptBlob, decryptBlob, encryptTextWithInfo, decryptText,
  estimateStrength, generatePassword,
  DecryptionError, FormatError, FILE_EXTENSION,
} from '../crypto/index.js';
import { GoogleDriveProvider } from '../cloud/googleDrive.js';

// ---- tiny DOM helpers ---------------------------------------------------
const $ = (id) => document.getElementById(id);

/** Show a message in a status element. kind: "ok" | "error" | "busy" */
function setStatus(el, message, kind = 'busy') {
  el.textContent = message;
  el.dataset.kind = kind;
}

/** Let the browser paint "Encrypting..." before we block on heavy work. */
const nextPaint = () => new Promise((resolve) => setTimeout(resolve, 20));

/** Turn any thrown error into a message a person can act on. */
function describeError(error) {
  if (error instanceof DecryptionError) return error.message;
  if (error instanceof FormatError) return error.message;
  if (error instanceof TypeError && /password/i.test(error.message)) return error.message;
  console.error(error);
  return error?.message || 'Something went wrong.';
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB'];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
  return `${value.toFixed(value < 10 ? 2 : 1)} ${units[i]}`;
}

/** Save a Blob as a download using a temporary link. */
function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

const encryptedName = (name) => `${name}${FILE_EXTENSION}`;
const decryptedName = (name) =>
  name.toLowerCase().endsWith(FILE_EXTENSION) ? name.slice(0, -FILE_EXTENSION.length) : `${name}.decrypted`;

// ---- progress bar -------------------------------------------------------
const progress = $('progress');
const onProgress = (done, total) => {
  progress.hidden = total <= 1; // not worth showing for tiny inputs
  progress.value = done / total;
};
const resetProgress = () => { progress.hidden = true; progress.value = 0; };

/**
 * Run `work` while disabling all buttons, so a second click cannot start a
 * second operation on top of the first. Always re-enables afterwards.
 */
async function runBusy(statusEl, message, work) {
  const buttons = document.querySelectorAll('button');
  buttons.forEach((b) => { b.disabled = true; });
  setStatus(statusEl, message, 'busy');
  await nextPaint();
  try {
    return await work();
  } catch (error) {
    setStatus(statusEl, describeError(error), 'error');
    return undefined;
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
    resetProgress();
    updateDriveUi(); // some buttons must stay hidden/disabled depending on state
  }
}

/** Returns the password or shows an error and returns null. */
function requirePassword(statusEl) {
  const password = $('password').value;
  if (!password) {
    setStatus(statusEl, 'Enter a password first.', 'error');
    return null;
  }
  return password;
}

/** Appended to "success" messages when the password is weak. */
function weakPasswordNote() {
  return estimateStrength($('password').value).score < 2
    ? ' Your password is weak: anyone who gets the file can try to guess it.'
    : '';
}

// ---- password panel -----------------------------------------------------
const passwordInput = $('password');

passwordInput.addEventListener('input', () => {
  const { score, label, bits, hints } = estimateStrength(passwordInput.value);
  $('strength-bar').dataset.score = String(score);
  $('strength-bar').style.width = passwordInput.value ? `${(score + 1) * 20}%` : '0';
  $('strength-label').textContent = passwordInput.value
    ? `${label} (about ${bits} bits). ${hints[0] ?? ''}`.trim()
    : 'Enter a password.';
});

$('toggle-password').addEventListener('click', (event) => {
  const show = passwordInput.type === 'password';
  passwordInput.type = show ? 'text' : 'password';
  event.currentTarget.textContent = show ? 'Hide' : 'Show';
  event.currentTarget.setAttribute('aria-pressed', String(show));
});

$('generate').addEventListener('click', () => {
  passwordInput.value = generatePassword(20);
  passwordInput.type = 'text'; // so the user can copy it before it is used
  $('toggle-password').textContent = 'Hide';
  $('toggle-password').setAttribute('aria-pressed', 'true');
  passwordInput.dispatchEvent(new Event('input'));
});

// ---- tabs ---------------------------------------------------------------
const tabs = [...document.querySelectorAll('[data-tab]')];
function selectTab(name) {
  for (const tab of tabs) {
    const active = tab.dataset.tab === name;
    tab.setAttribute('aria-selected', String(active));
    tab.tabIndex = active ? 0 : -1;
  }
  document.querySelectorAll('[data-panel]').forEach((p) => { p.hidden = p.dataset.panel !== name; });
  // Google's script is only fetched once the user actually opens the Drive tab.
  if (name === 'drive') drive.prepare().catch(() => {}); // errors are shown on Connect
}
tabs.forEach((tab) => tab.addEventListener('click', () => selectTab(tab.dataset.tab)));
// Arrow-key navigation between tabs (standard accessible tab behaviour)
$('tab-text').parentElement.addEventListener('keydown', (event) => {
  if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
  const i = tabs.findIndex((t) => t.getAttribute('aria-selected') === 'true');
  const next = tabs[(i + (event.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
  selectTab(next.dataset.tab);
  next.focus();
});

// ---- "inside your encrypted file" visual --------------------------------
function showAnatomy(info) {
  const bar = $('anatomy-bar');
  bar.replaceChildren();

  const header = document.createElement('div');
  header.className = 'seg header';
  header.textContent = 'header';
  bar.append(header);

  // Draw at most 16 chunk segments so huge files still render cleanly.
  const shown = Math.min(info.chunkCount, 16);
  for (let i = 0; i < shown; i++) {
    const seg = document.createElement('div');
    seg.className = 'seg chunk';
    seg.textContent = i === shown - 1 && info.chunkCount > shown ? `+${info.chunkCount - shown + 1}` : String(i + 1);
    bar.append(seg);
  }

  const facts = [
    ['Cipher', 'AES-256-GCM'],
    ['Key derivation', `PBKDF2-SHA256, ${info.iterations.toLocaleString()} rounds`],
    ['Chunks', `${info.chunkCount} (up to ${formatBytes(info.chunkSize)} each, each with its own 16-byte tag)`],
    ['Original size', formatBytes(info.plainSize)],
    ['Encrypted size', `${formatBytes(info.encryptedSize)} (+${info.overheadBytes} bytes of header and tags)`],
  ];
  const list = $('anatomy-facts');
  list.replaceChildren();
  for (const [term, value] of facts) {
    const dt = document.createElement('dt'); dt.textContent = term;
    const dd = document.createElement('dd'); dd.textContent = value;
    list.append(dt, dd);
  }
  $('anatomy').hidden = false;
}

// ---- TEXT tab -----------------------------------------------------------
const textStatus = $('text-status');

$('text-encrypt').addEventListener('click', async () => {
  const password = requirePassword(textStatus);
  if (!password) return;
  const text = $('text-input').value;
  if (!text) { setStatus(textStatus, 'Type some text to encrypt.', 'error'); return; }

  await runBusy(textStatus, 'Encrypting...', async () => {
    $('text-output').value = ''; // never leave a previous result on screen
    const { text: result, info } = await encryptTextWithInfo(text, password);
    $('text-output').value = result;
    showAnatomy(info);
    setStatus(textStatus, `Encrypted. Copy the result below and keep your password safe.${weakPasswordNote()}`, 'ok');
  });
});

$('text-decrypt').addEventListener('click', async () => {
  const password = requirePassword(textStatus);
  if (!password) return;
  const text = $('text-input').value.trim();
  if (!text) { setStatus(textStatus, 'Paste the encrypted text into the box above.', 'error'); return; }

  await runBusy(textStatus, 'Decrypting...', async () => {
    $('text-output').value = ''; // so a failed attempt can't show stale text
    $('text-output').value = await decryptText(text, password);
    setStatus(textStatus, 'Decrypted.', 'ok');
  });
});

$('text-copy').addEventListener('click', async () => {
  const value = $('text-output').value;
  if (!value) { setStatus(textStatus, 'Nothing to copy yet.', 'error'); return; }
  try {
    await navigator.clipboard.writeText(value);
    setStatus(textStatus, 'Copied to clipboard.', 'ok');
  } catch {
    $('text-output').select(); // fallback: select it so Ctrl+C works
    setStatus(textStatus, 'Could not access the clipboard. The text is selected, press Ctrl+C.', 'error');
  }
});

// ---- FILE tab -----------------------------------------------------------
const fileStatus = $('file-status');
const fileInput = $('file-input');
const fileDrop = $('file-drop');

function showChosenFile() {
  const file = fileInput.files[0];
  $('file-name').textContent = file ? `${file.name} (${formatBytes(file.size)})` : 'Choose a file, or drop it here';
}
fileInput.addEventListener('change', showChosenFile);

// Drag and drop
['dragenter', 'dragover'].forEach((type) =>
  fileDrop.addEventListener(type, (e) => { e.preventDefault(); fileDrop.classList.add('is-over'); }));
['dragleave', 'drop'].forEach((type) =>
  fileDrop.addEventListener(type, (e) => { e.preventDefault(); fileDrop.classList.remove('is-over'); }));
fileDrop.addEventListener('drop', (e) => {
  if (e.dataTransfer?.files?.length) {
    fileInput.files = e.dataTransfer.files;
    showChosenFile();
  }
});

function requireFile(statusEl, input) {
  const file = input.files[0];
  if (!file) setStatus(statusEl, 'Choose a file first.', 'error');
  return file ?? null;
}

$('file-encrypt').addEventListener('click', async () => {
  const password = requirePassword(fileStatus);
  const file = password && requireFile(fileStatus, fileInput);
  if (!file) return;

  await runBusy(fileStatus, 'Encrypting...', async () => {
    const { blob, info } = await encryptBlob(file, password, { onProgress });
    download(blob, encryptedName(file.name));
    showAnatomy(info);
    setStatus(fileStatus, `Encrypted. Saved as ${encryptedName(file.name)}.${weakPasswordNote()}`, 'ok');
  });
});

$('file-decrypt').addEventListener('click', async () => {
  const password = requirePassword(fileStatus);
  const file = password && requireFile(fileStatus, fileInput);
  if (!file) return;

  await runBusy(fileStatus, 'Decrypting...', async () => {
    const blob = await decryptBlob(file, password, { onProgress });
    download(blob, decryptedName(file.name));
    setStatus(fileStatus, `Decrypted. Saved as ${decryptedName(file.name)}.`, 'ok');
  });
});

// ---- GOOGLE DRIVE tab ---------------------------------------------------
// To add another service (Mega, Dropbox...), implement the interface in
// ../cloud/provider.js and put it here. The UI code below does not change.
const drive = new GoogleDriveProvider();
const driveStatus = $('drive-status');

/** Show/hide the Drive controls to match the current connection state. */
function updateDriveUi() {
  const configured = drive.isConfigured();
  const connected = drive.isConnected();

  $('drive-setup-note').hidden = configured;
  if (!configured) {
    $('drive-setup-note').textContent =
      'Google Drive is not set up yet. Add your OAuth client ID in src/config.js (steps are in the README).';
  }
  $('drive-connect').hidden = connected;
  $('drive-connect').disabled = !configured;
  $('drive-disconnect').hidden = !connected;
  $('drive-tools').hidden = !connected;
}

async function refreshDriveList() {
  const files = await drive.list();
  const list = $('drive-list');
  list.replaceChildren();

  if (files.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'empty';
    empty.textContent = 'Nothing here yet. Encrypt and upload a file above.';
    list.append(empty);
    return;
  }

  for (const file of files) {
    const item = document.createElement('li');

    const info = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'name';
    name.textContent = file.name; // textContent (not innerHTML) so file names can't inject HTML
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = `${formatBytes(file.size)}, ${new Date(file.modifiedTime).toLocaleString()}`;
    info.append(name, meta);

    const buttons = document.createElement('div');
    buttons.className = 'actions';
    const get = document.createElement('button');
    get.type = 'button';
    get.textContent = 'Download and decrypt';
    get.addEventListener('click', () => downloadFromDrive(file));
    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'ghost';
    del.textContent = 'Delete';
    del.addEventListener('click', () => deleteFromDrive(file));
    buttons.append(get, del);

    item.append(info, buttons);
    list.append(item);
  }
}

async function downloadFromDrive(file) {
  const password = requirePassword(driveStatus);
  if (!password) return;
  await runBusy(driveStatus, `Downloading ${file.name}...`, async () => {
    const encrypted = await drive.download(file);
    setStatus(driveStatus, 'Decrypting...', 'busy');
    const plain = await decryptBlob(encrypted, password, { onProgress });
    download(plain, decryptedName(file.name));
    setStatus(driveStatus, `Decrypted. Saved as ${decryptedName(file.name)}.`, 'ok');
  });
}

async function deleteFromDrive(file) {
  if (!confirm(`Delete "${file.name}" from Google Drive? This cannot be undone.`)) return;
  await runBusy(driveStatus, 'Deleting...', async () => {
    await drive.remove(file);
    await refreshDriveList();
    setStatus(driveStatus, 'Deleted.', 'ok');
  });
}

$('drive-connect').addEventListener('click', async () => {
  await runBusy(driveStatus, 'Waiting for Google sign-in...', async () => {
    await drive.connect();
    await refreshDriveList();
    setStatus(driveStatus, 'Connected. ZeroVault can only see files it uploads itself.', 'ok');
  });
});

$('drive-disconnect').addEventListener('click', () => {
  drive.disconnect();
  $('drive-list').replaceChildren();
  setStatus(driveStatus, 'Disconnected.', 'ok');
  updateDriveUi();
});

$('drive-refresh').addEventListener('click', async () => {
  await runBusy(driveStatus, 'Refreshing...', async () => {
    await refreshDriveList();
    setStatus(driveStatus, 'Up to date.', 'ok');
  });
});

$('drive-upload').addEventListener('click', async () => {
  const password = requirePassword(driveStatus);
  const file = password && requireFile(driveStatus, $('drive-file-input'));
  if (!file) return;

  await runBusy(driveStatus, 'Encrypting...', async () => {
    // 1. Encrypt locally. Only the encrypted blob is ever handed to the provider.
    const { blob, info } = await encryptBlob(file, password, { onProgress });
    showAnatomy(info);
    // 2. Upload.
    setStatus(driveStatus, 'Uploading encrypted file...', 'busy');
    await drive.upload(encryptedName(file.name), blob);
    await refreshDriveList();
    setStatus(driveStatus, `Uploaded ${encryptedName(file.name)}.${weakPasswordNote()}`, 'ok');
  });
});

// ---- start --------------------------------------------------------------
updateDriveUi();

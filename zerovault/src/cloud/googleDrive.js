/**
 * googleDrive.js  -  Google Drive backend (implements CloudProvider)
 * ------------------------------------------------------------------
 * HOW SIGN-IN WORKS
 *   We use Google Identity Services (the <script> tag in index.html).
 *   `initTokenClient` + `requestAccessToken` opens Google's consent popup
 *   and returns a short-lived ACCESS TOKEN (about 1 hour) straight to the
 *   browser. There is no backend server, no client secret, and the token
 *   is kept only in memory (never in localStorage), so closing the tab
 *   signs you out.
 *
 * HOW LITTLE ACCESS WE ASK FOR
 *   Scope `drive.file` = "see and manage only files this app created".
 *   ZeroVault can NOT read the rest of your Drive. This is also why the
 *   file list below only ever shows files uploaded through this app.
 *
 * All calls use the plain Drive REST API v3 through fetch(), so there is
 * no SDK to install.
 */
import { GOOGLE_CLIENT_ID } from '../config.js';

const SCOPE = 'https://www.googleapis.com/auth/drive.file';
const API = 'https://www.googleapis.com/drive/v3';
const UPLOAD_API = 'https://www.googleapis.com/upload/drive/v3';

export class GoogleDriveProvider {
  id = 'gdrive';
  label = 'Google Drive';

  /** @type {string|null} short-lived OAuth token, memory only */
  #token = null;
  #tokenClient = null;

  isConfigured() {
    return Boolean(GOOGLE_CLIENT_ID);
  }

  isConnected() {
    return this.#token !== null;
  }

  /** Opens the Google consent popup. Resolves once we hold a token. */
  connect() {
    return new Promise((resolve, reject) => {
      if (!this.isConfigured()) {
        reject(new Error('Google Drive is not configured. Set GOOGLE_CLIENT_ID in src/config.js.'));
        return;
      }
      const gis = globalThis.google?.accounts?.oauth2;
      if (!gis) {
        reject(new Error('Google sign-in script failed to load. Check your internet connection or ad blocker.'));
        return;
      }

      this.#tokenClient = gis.initTokenClient({
        client_id: GOOGLE_CLIENT_ID,
        scope: SCOPE,
        callback: (response) => {
          if (response.error) {
            reject(new Error(`Google sign-in failed: ${response.error}`));
            return;
          }
          this.#token = response.access_token;
          resolve();
        },
        error_callback: (err) => reject(new Error(`Google sign-in was cancelled or blocked (${err.type}).`)),
      });
      this.#tokenClient.requestAccessToken({ prompt: '' });
    });
  }

  disconnect() {
    if (this.#token) globalThis.google?.accounts?.oauth2?.revoke(this.#token, () => {});
    this.#token = null;
  }

  /** Upload an (already encrypted) blob. Returns the created file's details. */
  async upload(name, blob) {
    // Drive's "multipart" upload = one request containing a JSON part
    // (metadata: the file name) and a binary part (the file itself).
    const boundary = `zerovault_${crypto.randomUUID()}`;
    const body = new Blob([
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n`,
      JSON.stringify({ name, mimeType: 'application/octet-stream' }),
      `\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n`,
      blob,
      `\r\n--${boundary}--`,
    ]);

    const response = await this.#request(
      `${UPLOAD_API}/files?uploadType=multipart&fields=id,name,size,modifiedTime`,
      { method: 'POST', headers: { 'Content-Type': `multipart/related; boundary=${boundary}` }, body },
    );
    return this.#toRemoteFile(await response.json());
  }

  /** List files this app has uploaded (newest first). */
  async list() {
    const params = new URLSearchParams({
      q: "trashed = false and name contains '.zvlt'",
      fields: 'files(id,name,size,modifiedTime)',
      orderBy: 'modifiedTime desc',
      pageSize: '50',
    });
    const response = await this.#request(`${API}/files?${params}`);
    const data = await response.json();
    return (data.files ?? []).map((f) => this.#toRemoteFile(f));
  }

  /** Download the raw (encrypted) bytes of a file. */
  async download(file) {
    const response = await this.#request(`${API}/files/${encodeURIComponent(file.id)}?alt=media`);
    return response.blob();
  }

  async remove(file) {
    await this.#request(`${API}/files/${encodeURIComponent(file.id)}`, { method: 'DELETE' });
  }

  // ---- internals -------------------------------------------------

  /** fetch() with the auth header and friendly error messages. */
  async #request(url, init = {}) {
    if (!this.#token) throw new Error('Not connected to Google Drive.');

    const response = await fetch(url, {
      ...init,
      headers: { ...init.headers, Authorization: `Bearer ${this.#token}` },
    });

    if (response.status === 401) {
      this.#token = null; // tokens expire after about an hour
      throw new Error('Google Drive session expired. Click "Connect" again.');
    }
    if (!response.ok) {
      throw new Error(`Google Drive request failed (${response.status}).`);
    }
    return response;
  }

  #toRemoteFile(f) {
    return { id: f.id, name: f.name, size: Number(f.size ?? 0), modifiedTime: f.modifiedTime };
  }
}

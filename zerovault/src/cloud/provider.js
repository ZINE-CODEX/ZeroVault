/**
 * provider.js  -  the contract every cloud storage backend must follow
 * ------------------------------------------------------------------
 * The UI only talks to this interface, never to Google directly. That is
 * what makes adding Mega, Dropbox, OneDrive, etc. a matter of writing ONE
 * new file that implements these methods.
 *
 * IMPORTANT SECURITY PROPERTY: a provider only ever receives ENCRYPTED
 * blobs. Encryption/decryption happens before upload and after download,
 * in the UI layer, so a provider can never see plaintext or passwords.
 *
 * @typedef {Object} RemoteFile
 * @property {string} id            provider-specific file id
 * @property {string} name          file name
 * @property {number} size          size in bytes
 * @property {string} modifiedTime  ISO date string
 *
 * @typedef {Object} CloudProvider
 * @property {string} id                        short id, e.g. "gdrive"
 * @property {string} label                     display name, e.g. "Google Drive"
 * @property {() => boolean} isConfigured       are the required settings present?
 * @property {() => boolean} isConnected        is the user signed in right now?
 * @property {() => Promise<void>} connect      sign in (opens a popup)
 * @property {() => void} disconnect            sign out / drop the token
 * @property {(name: string, blob: Blob) => Promise<RemoteFile>} upload
 * @property {() => Promise<RemoteFile[]>} list
 * @property {(file: RemoteFile) => Promise<Blob>} download
 * @property {(file: RemoteFile) => Promise<void>} remove
 */
export {};

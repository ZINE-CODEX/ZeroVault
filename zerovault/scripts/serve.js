/**
 * serve.js  -  a tiny local web server with ZERO dependencies
 * ------------------------------------------------------------------
 * Why this exists: the Web Crypto API only works on http://localhost or
 * https://, so the app can't be opened straight from disk. Instead of
 * downloading a server from npm (more code to trust), we use Node's
 * built-in http module.
 *
 * Safety notes:
 *  - Listens on 127.0.0.1 only, so other devices on your network can't reach it.
 *  - Path traversal is blocked: requests can never escape the project folder.
 *  - Dotfiles (.git, .env ...) and node_modules are never served.
 *
 * Usage:  npm start            (default port 8080)
 *         PORT=3000 npm start
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const PORT = Number(process.env.PORT) || 8080;

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.md': 'text/plain; charset=utf-8',
};

function send(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': type,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

const server = createServer(async (req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');

  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  } catch {
    return send(res, 400, 'Bad request');
  }
  if (pathname.includes('\0')) return send(res, 400, 'Bad request');
  if (pathname.endsWith('/')) pathname += 'index.html';

  const target = resolve(ROOT, `.${pathname}`);
  const relative = target.slice(ROOT.length + 1);
  const blocked =
    !(target === ROOT || target.startsWith(ROOT + sep)) || // outside the project folder
    relative.split(sep).some((part) => part.startsWith('.') || part === 'node_modules');
  if (blocked) return send(res, 404, 'Not found');

  try {
    const data = await readFile(target);
    send(res, 200, req.method === 'HEAD' ? '' : data, TYPES[extname(target)] ?? 'application/octet-stream');
  } catch {
    send(res, 404, 'Not found');
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`ZeroVault running at http://localhost:${PORT}  (Ctrl+C to stop)`);
});

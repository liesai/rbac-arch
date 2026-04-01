#!/usr/bin/env node
import { createServer, request as httpRequest } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.DASH_PORT || 8111);
const API_BASE = process.env.API_BASE || 'http://127.0.0.1:8110';
const DIST_DIR = process.env.DIST_DIR || path.join(__dirname, 'dashboard', 'dist');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.map': 'application/json; charset=utf-8',
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, headers);
  res.end(body);
}

function withSecurityHeaders(headers = {}) {
  return {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    ...headers,
  };
}

function mapApiPath(urlPath) {
  const raw = urlPath.replace(/^\/api/, '');
  return raw.length ? raw : '/';
}

function proxyApi(req, res) {
  const upstreamUrl = new URL(API_BASE);
  const targetPath = mapApiPath(req.url || '/');

  const proxyReq = httpRequest(
    {
      protocol: upstreamUrl.protocol,
      hostname: upstreamUrl.hostname,
      port: upstreamUrl.port,
      method: req.method,
      path: targetPath,
      headers: {
        ...req.headers,
        host: `${upstreamUrl.hostname}:${upstreamUrl.port}`,
        origin: `${upstreamUrl.protocol}//${upstreamUrl.host}`,
      },
    },
    (proxyRes) => {
      const headers = { ...proxyRes.headers };
      delete headers['content-security-policy'];
      res.writeHead(proxyRes.statusCode || 502, withSecurityHeaders(headers));
      proxyRes.pipe(res);
    },
  );

  proxyReq.on('error', (err) => {
    send(
      res,
      502,
      JSON.stringify({ error: `API proxy error: ${err.message}` }),
      withSecurityHeaders({ 'Content-Type': 'application/json; charset=utf-8' }),
    );
  });

  if (req.method === 'GET' || req.method === 'HEAD') {
    proxyReq.end();
  } else {
    req.pipe(proxyReq);
  }
}

async function serveFile(req, res) {
  const url = new URL(req.url || '/', 'http://localhost');
  let reqPath = decodeURIComponent(url.pathname);

  if (reqPath === '/') reqPath = '/index.html';
  const absPath = path.normalize(path.join(DIST_DIR, reqPath));

  if (!absPath.startsWith(path.normalize(DIST_DIR))) {
    send(res, 403, 'Forbidden', withSecurityHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }));
    return;
  }

  let finalPath = absPath;
  if (!existsSync(finalPath)) {
    finalPath = path.join(DIST_DIR, 'index.html');
  }

  try {
    const body = await readFile(finalPath);
    const ext = path.extname(finalPath).toLowerCase();
    send(res, 200, body, withSecurityHeaders({ 'Content-Type': MIME[ext] || 'application/octet-stream' }));
  } catch {
    send(res, 404, 'Not found', withSecurityHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }));
  }
}

const server = createServer((req, res) => {
  const pathName = (req.url || '/').split('?')[0];
  if (pathName.startsWith('/api/')) {
    proxyApi(req, res);
    return;
  }
  serveFile(req, res);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`RBAC dashboard gateway listening on http://0.0.0.0:${PORT}`);
  console.log(`Static: ${DIST_DIR}`);
  console.log(`API proxy: /api -> ${API_BASE}`);
});

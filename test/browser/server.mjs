import { createServer } from 'node:https';
import { request as proxyRequest } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';

// Ephemeral, local test certificate. Production TLS is supplied by the deployment.
const directory = await mkdtemp(join(tmpdir(), 'ukda-browser-tls-'));
const keyPath = join(directory, 'key.pem'), certificatePath = join(directory, 'certificate.pem');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath,
  '-out', certificatePath, '-subj', '/CN=localhost', '-days', '1'], { stdio: 'ignore' });
const server = createServer({ key: await readFile(keyPath), cert: await readFile(certificatePath) }, async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'");
  try {
    const path = new URL(request.url, 'https://127.0.0.1:3555').pathname;
    // A test owns the real API fixture on this fixed loopback port. Forwarding
    // keeps browser cookies, Origin and the dedicated worker genuinely same-origin.
    if (path.startsWith('/v1/')) {
      const upstream = proxyRequest({ hostname: '127.0.0.1', port: 3556, path: request.url,
        method: request.method, headers: request.headers }, (incoming) => {
        response.writeHead(incoming.statusCode ?? 503, incoming.headers);
        incoming.pipe(response);
      });
      upstream.on('error', () => { if (!response.headersSent) response.writeHead(503); response.end(); });
      request.on('aborted', () => upstream.destroy());
      request.pipe(upstream);
      return;
    }
    if (request.method !== 'GET') throw new Error();
    if (path === '/') {
      response.setHeader('Content-Type', 'text/html; charset=utf-8');
      response.end('<!doctype html><title>UKDA browser verification</title><script type="module" src="/harness.js"></script>');
      return;
    }
    if (path === '/harness.js') {
      response.setHeader('Content-Type', 'text/javascript; charset=utf-8');
      response.end("import * as client from '/client.js'; window.ukda = client;");
      return;
    }
    if (!/^\/[a-zA-Z0-9_.-]+\.js$/.test(path)) throw new Error();
    const bytes = await readFile(join('dist/browser', basename(path)));
    response.setHeader('Content-Type', 'text/javascript; charset=utf-8');
    response.end(bytes);
  } catch { response.statusCode = 404; response.end(); }
});
await new Promise((resolve, reject) => { server.once('error', reject); server.listen(3555, '127.0.0.1', resolve); });
console.log('Local HTTPS browser verification server ready');
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  server.close(() => { void rm(directory, { recursive: true, force: true }).finally(() => process.exit(0)); });
});

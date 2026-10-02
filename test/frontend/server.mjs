import { createServer } from 'node:https';
import { request as proxyRequest } from 'node:http';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Serve the real, centrally built Next product. Each serial test owns a real
// database-backed authenticationFixture API, exactly as the protocol suite does.
const next = process.env.UKDA_FRONTEND_EXTERNAL === '1' ? null : spawn(process.execPath, ['node_modules/next/dist/bin/next', 'start', 'web', '-p', '3557', '-H', '127.0.0.1'], {
  stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env, NODE_ENV: 'production', UKDA_API_ORIGIN: 'http://127.0.0.1:3556' },
});
const directory = await mkdtemp(join(tmpdir(), 'ukda-frontend-tls-'));
const keyPath = join(directory, 'key.pem'), certificatePath = join(directory, 'certificate.pem');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath,
  '-out', certificatePath, '-subj', '/CN=localhost', '-days', '1'], { stdio: 'ignore' });
const server = createServer({ key: await readFile(keyPath), cert: await readFile(certificatePath) }, (request, response) => {
  // Every request passes through the real Next product, including its same-origin
  // API proxy. The fixture API is never exposed directly to the browser.
  const upstream = proxyRequest({ hostname: '127.0.0.1', port: 3557,
    path: request.url, method: request.method, headers: request.headers }, incoming => {
    response.writeHead(incoming.statusCode ?? 503, incoming.headers); incoming.pipe(response);
  });
  upstream.on('error', () => { if (!response.headersSent) response.writeHead(503); response.end(); });
  request.on('aborted', () => upstream.destroy()); request.pipe(upstream);
});
await new Promise((resolve, reject) => { server.once('error', reject); server.listen(3555, '127.0.0.1', resolve); });
let stopping = false;
const close = async code => {
  if (stopping) return; stopping = true;
  server.closeAllConnections(); server.close(); next?.kill('SIGTERM');
  await rm(directory, { recursive: true, force: true }); process.exit(code);
};
next?.once('exit', code => { if (!stopping) void close(code ?? 1); });
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void close(0); });

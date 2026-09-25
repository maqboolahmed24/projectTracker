import assert from 'node:assert/strict';
import test from 'node:test';
import { Writable } from 'node:stream';
import { loadConfig } from '../src/config.js';
import { buildApp } from '../src/app.js';
import type { Databases } from '../src/db.js';

const env = {
  NODE_ENV: 'test', LOG_LEVEL: 'silent',
  DATABASE_URL: 'postgres://test:password@localhost:55432/application',
  CONTROL_DATABASE_URL: 'postgres://test:password@localhost:55433/control',
};
function fakeDatabases(ready: () => Promise<void>): Databases {
  return { ready, close: async () => {}, application: {} as Databases['application'], control: {} as Databases['control'] };
}

test('reject invalid or unsafe configuration without exposing values', () => {
  assert.throws(() => loadConfig({ ...env, PORT: 'secret-invalid-port' }), /Invalid configuration: PORT/);
  assert.throws(() => loadConfig({ ...env, ADMIN_DATABASE_URL: 'postgres://admin:secret@localhost/application' }), /must not include migration credentials/);
  assert.throws(() => loadConfig({ ...env, CONTROL_DATABASE_URL: env.DATABASE_URL }), /must be separate/);
  assert.throws(() => loadConfig({ ...env, DATABASE_URL: 'postgres://test:password@localhost/application', CONTROL_DATABASE_URL: 'postgres://other:password@localhost:5432/%61pplication' }), /must be separate/);
  assert.throws(() => loadConfig({ ...env, NODE_ENV: 'production' }), /requires HTTPS/);
  assert.throws(() => loadConfig({ ...env, APP_ORIGIN: 'http://localhost:3400/path' }), /without a path/);
  const production = loadConfig({ ...env, NODE_ENV: 'production', APP_ORIGIN: 'https://projects.example.test' });
  assert.equal(production.PORT, 3400);
});

test('liveness and readiness are distinct; failures contain no database details', async (t) => {
  let unavailable = false;
  const app = buildApp(loadConfig(env), fakeDatabases(async () => { if (unavailable) throw new Error('postgres://super-secret'); }));
  t.after(() => app.close());
  assert.equal((await app.inject('/health/live')).statusCode, 200);
  assert.deepEqual((await app.inject('/health/ready')).json(), { status: 'ready' });
  unavailable = true;
  const response = await app.inject('/health/ready');
  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), { status: 'unavailable' });
  assert.equal((await app.inject('/health/live')).statusCode, 200);
});

test('errors are sanitised and correlation IDs cannot be supplied by the caller', async (t) => {
  const app = buildApp(loadConfig(env), fakeDatabases(async () => {}));
  app.get('/test-error', async () => { throw new Error('sensitive internal value'); });
  t.after(() => app.close());
  const response = await app.inject({ url: '/test-error', headers: { 'x-request-id': 'attacker-controlled' } });
  assert.equal(response.statusCode, 500);
  assert.equal(response.body.includes('sensitive'), false);
  assert.notEqual(response.headers['x-request-id'], 'attacker-controlled');
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.equal((await app.inject('/missing')).json().error.code, 'NOT_FOUND');
});

test('oversized and prototype-poisoned payloads are rejected', async (t) => {
  const app = buildApp(loadConfig(env), fakeDatabases(async () => {}));
  app.post('/test-body', async () => ({ accepted: true }));
  t.after(() => app.close());
  const tooLarge = await app.inject({ method: 'POST', url: '/test-body', payload: { value: 'x'.repeat(1024 * 1024) } });
  assert.equal(tooLarge.statusCode, 413);
  const poisoned = await app.inject({ method: 'POST', url: '/test-body', headers: { 'content-type': 'application/json' }, payload: '{"__proto__":{"admin":true}}' });
  assert.equal(poisoned.statusCode, 400);
});

test('request logs exclude secrets in paths, queries, headers, bodies, and thrown errors', async (t) => {
  const logs: string[] = [];
  const stream = new Writable({ write(chunk, _encoding, done) { logs.push(String(chunk)); done(); } });
  const app = buildApp(loadConfig({ ...env, LOG_LEVEL: 'info' }), fakeDatabases(async () => {}), stream);
  app.post('/logs/:account', async () => { throw new Error('error-secret'); });
  t.after(() => app.close());
  await app.inject({
    method: 'POST', url: '/logs/path-secret?token=query-secret',
    headers: { authorization: 'Bearer header-secret', cookie: 'session=cookie-secret' },
    payload: { password: 'password-secret', content: 'content-secret' },
  });
  const output = logs.join('');
  assert.match(output, /request completed/);
  assert.match(output, /INTERNAL_ERROR/);
  for (const secret of ['path-secret', 'query-secret', 'header-secret', 'cookie-secret', 'password-secret', 'content-secret', 'error-secret']) {
    assert.equal(output.includes(secret), false, `${secret} leaked into logs`);
  }
});

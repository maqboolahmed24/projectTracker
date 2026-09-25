import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';
import * as opaqueLibrary from '@serenity-kit/opaque';
import { loadConfig } from '../src/config.js';
import { createDatabases } from '../src/db.js';
import { buildApp } from '../src/app.js';
import { startLogin } from '../src/client/opaque.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';
import { SessionService } from '../src/modules/identity/sessions.js';
import { AuthenticationService } from '../src/modules/identity/authentication.js';
import { RequestBudgets } from '../src/modules/identity/budgets.js';
import { registerAuthenticationRoutes } from '../src/modules/identity/auth-routes.js';

test('CP04: authentication routes enforce origin, strict inputs and account/workspace/source limits without logging secrets', async (t) => {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'info' });
  const databases = createDatabases(config);
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'auth-routes-test' });
  await opaqueLibrary.ready;
  const opaque = new OpaqueService({ serverSetup: opaqueLibrary.server.createSetup(), setupId: 'auth-routes-test', serverIdentity: config.APP_ORIGIN });
  const sessions = new SessionService({ databases, secrets, origin: config.APP_ORIGIN });
  const authentication = new AuthenticationService({ databases, secrets, opaque, sessions, origin: config.APP_ORIGIN });
  const budgets = new RequestBudgets(databases.control, secrets);
  const logs: string[] = [];
  const app = buildApp(config, databases, new Writable({ write(chunk, _encoding, done) { logs.push(String(chunk)); done(); } }));
  registerAuthenticationRoutes(app, { origin: config.APP_ORIGIN, authentication, sessions, budgets });
  const workspaceId = randomUUID(), accountId = randomUUID();
  const source = '192.0.2.37';
  const rows = [
    { purpose: 'authentication-account', key: `${workspaceId}:${accountId}`, limit: 15 },
    { purpose: 'authentication-workspace', key: workspaceId, limit: 120 },
    { purpose: 'authentication-source', key: source, limit: 60 },
  ];
  const digests = rows.map((row) => secrets.digest(`rate:${row.purpose}`, row.key));
  t.after(async () => {
    try {
      await databases.control.query('DELETE FROM security.auth_attempts WHERE workspace_id=$1', [workspaceId]);
      await databases.control.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [digests]);
    } finally { await app.close(); }
  });
  const secret = 'Never upload this private password 578';
  const login = await startLogin(secret);
  const payload = { workspaceId, accountId, startLoginRequest: login.startLoginRequest };
  const post = (path: string, body: object = payload, headers: Record<string, string> = { origin: config.APP_ORIGIN }) =>
    app.inject({ method: 'POST', url: `/v1/auth/${path}`, headers, payload: body, remoteAddress: source });
  assert.equal((await post('login/start', payload, {})).statusCode, 403);
  assert.equal((await post('login/start', payload, { origin: 'https://other.example' })).statusCode, 403);
  assert.equal((await post('login/start', payload, { origin: config.APP_ORIGIN, 'sec-fetch-site': 'cross-site' })).statusCode, 403);
  assert.equal((await post('login/start', { ...payload, password: secret })).statusCode, 400);
  assert.equal((await post(`login/start?password=${encodeURIComponent(secret)}`)).statusCode, 400);
  assert.equal((await post('login/start', { ...payload, accountId: 'a username instead of an opaque account reference' })).statusCode, 400);
  const started = await post('login/start');
  assert.equal(started.statusCode, 200);
  assert.equal(started.headers['cache-control'], 'no-store');
  assert.equal(started.headers['set-cookie'], undefined);
  assert.deepEqual(Object.keys(started.json()).sort(), ['configuration', 'expiresAt', 'loginId', 'loginResponse']);
  const failed = await post('login/finish', { loginId: started.json().loginId, finishLoginRequest: secrets.token() });
  assert.equal(failed.statusCode, 401);
  assert.equal(failed.json().error.code, 'AUTHENTICATION_FAILED');
  const replay = await post('login/finish', { loginId: started.json().loginId, finishLoginRequest: secrets.token() });
  assert.equal(replay.statusCode, 401);
  assert.equal(replay.json().error.code, 'AUTHENTICATION_FAILED');
  for (const row of rows) {
    // Seed preceding traffic at the actual shared counters, then exercise both
    // sides of the HTTP boundary without doing hundreds of redundant exchanges.
    await databases.control.query('UPDATE security.request_budgets SET attempts=1 WHERE bucket_digest=ANY($1::bytea[])', [digests]);
    const digest = secrets.digest(`rate:${row.purpose}`, row.key);
    await databases.control.query('UPDATE security.request_budgets SET attempts=$2 WHERE bucket_digest=$1', [digest, row.limit - 1]);
    assert.equal((await post('login/start')).statusCode, 200, `${row.purpose} must permit the final allowed attempt`);
    const exceeded = await post('login/start');
    assert.equal(exceeded.statusCode, 429, `${row.purpose} must deny the next attempt`);
    assert.equal(exceeded.json().error.code, 'RATE_LIMITED');
    assert.equal((await databases.control.query('SELECT attempts FROM security.request_budgets WHERE bucket_digest=$1', [digest])).rows[0].attempts, row.limit + 1);
  }
  const recorded = logs.join('');
  for (const value of [secret, login.startLoginRequest, workspaceId, accountId, 'a username instead of an opaque account reference']) {
    assert.equal(recorded.includes(value), false, 'Authentication diagnostics contain only route/status/request IDs');
  }
});

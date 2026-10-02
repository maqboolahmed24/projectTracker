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
import { AppError } from '../src/errors.js';
import type { RequestBudget } from '../src/modules/identity/budgets.js';
import { SESSION_COOKIE_NAME, type SessionPrincipal } from '../src/modules/identity/sessions.js';

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

test('frontend: session refresh has durable source/session bounds independent of password attempt budgets', async (t) => {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }), databases = createDatabases(config);
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'session-refresh-route-test' });
  const workspaceId = randomUUID(), accountId = randomUUID(), sessionId = randomUUID(), source = '192.0.2.39';
  const cookieValue = `v1.${workspaceId}.${sessionId}.${secrets.token()}`, csrfToken = secrets.token();
  const principal: SessionPrincipal = { workspaceId, profileId: accountId, accountId, sessionId, deviceId: randomUUID(), accessLevel: 'device_approved',
    securityHead: 'a'.repeat(64), securityVersion: '1', dataGeneration: '1', credentialGeneration: '1', sessionGeneration: '1', csrfToken,
    authenticatedAt: new Date(), idleExpiresAt: new Date(Date.now() + 1800000), absoluteExpiresAt: new Date(Date.now() + 43200000) };
  // Exercise the HTTP classification with real durable counters. Authentication
  // cryptography and live session authority are covered by their service tests.
  let authenticated = 0;
  const sessions = new SessionService({ databases, secrets, origin: config.APP_ORIGIN });
  sessions.authenticate = async value => { authenticated++; if (value !== cookieValue) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401); return principal; };
  const authentication = { startLogin: async () => ({ started: true }), startReauthentication: async () => ({ started: true }) } as unknown as AuthenticationService;
  const seen = new Map<string, Buffer>(), real = new RequestBudgets(databases.control, secrets);
  const budgets = { async take(entries: readonly RequestBudget[]) { for (const entry of entries) { const digest = secrets.digest(`rate:${entry.purpose}`, entry.key); seen.set(digest.toString('hex'), digest); } await real.take(entries); } };
  const app = buildApp(config, databases); registerAuthenticationRoutes(app, { origin: config.APP_ORIGIN, authentication, sessions, budgets });
  t.after(async () => { try { if (seen.size) await databases.control.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[...seen.values()]]); } finally { await app.close(); } });
  const headers = { origin: config.APP_ORIGIN, cookie: `${SESSION_COOKIE_NAME}=${cookieValue}`, 'x-csrf-token': csrfToken };
  const post = (path: string, payload: object = {}, requestHeaders: Record<string, string> = headers) => app.inject({ method: 'POST', url: `/v1/auth/${path}`, headers: requestHeaders, payload, remoteAddress: source });
  const digest = (purpose: string, key: string) => secrets.digest(`rate:${purpose}`, key);
  const attempts = async (purpose: string, key: string) => (await databases.control.query<{ attempts: number }>('SELECT attempts FROM security.request_budgets WHERE bucket_digest=$1', [digest(purpose, key)])).rows[0]?.attempts;
  for (const requestHeaders of [{}, { ...headers, origin: 'https://foreign.example' }, { ...headers, 'sec-fetch-site': 'cross-site' }]) assert.equal((await post('session', {}, requestHeaders)).statusCode, 403);
  assert.equal((await post('session?sessionId=untrusted')).statusCode, 400);
  assert.equal(seen.size, 0); assert.equal(authenticated, 0, 'Origin and query checks precede budgets and session lookup');
  assert.equal((await post('session', {}, { origin: config.APP_ORIGIN })).statusCode, 401);
  assert.equal(await attempts('session-refresh-source', source), 1); assert.equal(authenticated, 0);
  assert.equal((await post('session', { sessionId: randomUUID() })).statusCode, 400);
  for (let i = 0; i < 65; i++) assert.equal((await post('session')).statusCode, 200, 'Valid polling exceeds the password source allowance without consuming it');
  assert.equal(await attempts('authentication-source', source), undefined);
  assert.equal(await attempts('session-refresh-session', `${workspaceId}:${sessionId}`), 65);
  const login = { workspaceId, accountId, startLoginRequest: secrets.token() };
  assert.equal((await post('login/start', login)).statusCode, 200);
  assert.equal((await post('reauth/start', { startLoginRequest: secrets.token() })).statusCode, 200);
  assert.equal(await attempts('authentication-source', source), 2);
  assert.equal(await attempts('authentication-account', `${workspaceId}:${accountId}`), 2);
  const seed = (purpose: string, key: string, value: number) => databases.control.query('UPDATE security.request_budgets SET attempts=$2 WHERE bucket_digest=$1', [digest(purpose, key), value]);
  await seed('authentication-account', `${workspaceId}:${accountId}`, 14);
  assert.equal((await post('login/start', login)).statusCode, 200); assert.equal((await post('reauth/start', { startLoginRequest: secrets.token() })).statusCode, 429);
  await seed('authentication-account', `${workspaceId}:${accountId}`, 1); await seed('authentication-source', source, 59);
  assert.equal((await post('login/start', login)).statusCode, 200); assert.equal((await post('login/start', login)).statusCode, 429);
  assert.equal((await post('session')).statusCode, 200, 'Password-source exhaustion does not disable session freshness');
  await seed('session-refresh-session', `${workspaceId}:${sessionId}`, 599);
  assert.equal((await post('session')).statusCode, 200); assert.equal((await post('session')).statusCode, 429);
  await seed('session-refresh-source', source, 2999);
  assert.equal((await post('session', {}, { origin: config.APP_ORIGIN })).statusCode, 401);
  const before = authenticated;
  assert.equal((await post('session')).statusCode, 429); assert.equal(authenticated, before, 'Exhausted source blocks before authentication');
});

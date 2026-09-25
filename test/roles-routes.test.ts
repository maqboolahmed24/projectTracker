import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';
import test, { type TestContext } from 'node:test';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createDatabases } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { RequestBudgets, type RequestBudget } from '../src/modules/identity/budgets.js';
import type { RoleService } from '../src/modules/identity/roles.js';
import { roleAccountBudget, registerRoleRoutes } from '../src/modules/identity/roles-routes.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
async function fixture(t: TestContext) {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'info' }), databases = createDatabases(config);
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'role-http-test' });
  const workspaceId = randomUUID(), operationId = randomUUID(), accountId = randomUUID(), csrfToken = secrets.token();
  const cookie = `v1.${workspaceId}.${randomUUID()}.${secrets.token()}`, calls: { method: string; args: unknown[] }[] = [], logs: string[] = [];
  let failure: Error | undefined;
  const roles = new Proxy({}, { get(_target, method) { return async (...args: unknown[]) => { calls.push({ method: String(method), args }); if (failure) throw failure; return { handled: String(method) }; }; } }) as RoleService;
  const real = new RequestBudgets(databases.control, secrets), seen = new Map<string, Buffer>();
  const budgets = { async take(entries: readonly RequestBudget[]) { for (const entry of entries) { const hash = secrets.digest(`rate:${entry.purpose}`, entry.key); seen.set(hash.toString('hex'), hash); } await real.take(entries); } };
  const app = buildApp(config, databases, new Writable({ write(chunk, _encoding, done) { logs.push(String(chunk)); done(); } }));
  registerRoleRoutes(app, { origin: config.APP_ORIGIN, roles, budgets });
  t.after(async () => { try { if (seen.size) await databases.control.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[...seen.values()]]); } finally { await app.close(); } });
  const headers = { origin: config.APP_ORIGIN, cookie: `${SESSION_COOKIE_NAME}=${cookie}`, 'x-csrf-token': csrfToken }, reference = { workspaceId, operationId };
  const post = (path: string, body: object | string = reference, custom: Record<string, string> = headers) => app.inject({ method: 'POST', url: `/v1/auth/roles/${path}`, payload: body, headers: custom, remoteAddress: '192.0.2.95' });
  const digest = (purpose: string, key: string) => secrets.digest(`rate:${purpose}`, key);
  const count = async (purpose: string, key: string) => (await databases.control.query('SELECT attempts FROM security.request_budgets WHERE bucket_digest=$1', [digest(purpose, key)])).rows[0]?.attempts;
  return { app, databases, secrets, seen, workspaceId, operationId, accountId, cookie, csrfToken, headers, reference, post, calls, logs, digest, count, accountBudget: roleAccountBudget(budgets), fail(value: Error) { failure = value; } };
}

test('CP06: role HTTP rejects foreign origins, query secrets, duplicate JSON and private/unknown fields without logging them', async (t) => {
  const f = await fixture(t), secret = 'private-role-label-secret';
  for (const headers of [{}, { ...f.headers, origin: 'https://foreign.example' }, { ...f.headers, 'sec-fetch-site': 'cross-site' }]) assert.equal((await f.post('status', f.reference, headers)).statusCode, 403);
  assert.equal(f.seen.size, 0); assert.equal((await f.post(`status?password=${secret}`)).statusCode, 400);
  for (const field of ['displayName', 'password', 'phrase', 'privateKey', 'resumeToken']) assert.equal((await f.post('status', { ...f.reference, [field]: secret })).statusCode, 400);
  assert.equal((await f.post('status', `{"workspaceId":"${f.workspaceId}","operationId":"${f.operationId}","operationId":"${randomUUID()}"}`, { ...f.headers, 'content-type': 'application/json' })).statusCode, 400);
  assert.equal(f.calls.length, 0); assert.equal(f.logs.join('').includes(secret), false);
});

test('CP06: every role endpoint requires current cookie and CSRF; history permits public correlation before staging', async (t) => {
  const f = await fixture(t), context = { ...f.reference, roleId: randomUUID(), action: 'create' };
  for (const [path, body] of [['context', context], ['status', f.reference], ['finalize', { ...f.reference, requestHash: 'a'.repeat(64) }], ['list', { workspaceId: f.workspaceId }], ['history', { ...f.reference, afterVersion: '0' }]] as const) {
    assert.equal((await f.post(path, body, { origin: f.headers.origin, 'x-csrf-token': f.csrfToken })).statusCode, 401);
    assert.equal((await f.post(path, body, { origin: f.headers.origin, cookie: f.headers.cookie })).statusCode, 403);
  }
  assert.equal((await f.post('context', context)).statusCode, 200);
  assert.deepEqual(f.calls.at(-1), { method: 'context', args: [f.cookie, f.csrfToken, context] });
  assert.equal((await f.post('list', { workspaceId: f.workspaceId })).statusCode, 200);
  assert.deepEqual(f.calls.at(-1), { method: 'list', args: [f.cookie, f.csrfToken, { workspaceId: f.workspaceId, limit: 50 }] });
  assert.equal((await f.post('history', { ...f.reference, afterVersion: '1' })).statusCode, 400);
  assert.equal((await f.post('history', { ...f.reference, afterVersion: '0' })).statusCode, 200);
  assert.equal(f.calls.at(-1)!.method, 'withAuthorizedHistory');
  for (const secret of [f.cookie, f.csrfToken]) assert.equal(f.logs.join('').includes(secret), false);
});

test('CP06: role operation/history quotas are separate and resolved Owner budgets accumulate across operation IDs', async (t) => {
  const f = await fixture(t), key = `${f.workspaceId}:${f.operationId}`;
  assert.equal((await f.post('status')).statusCode, 200);
  await f.databases.control.query('UPDATE security.request_budgets SET attempts=120 WHERE bucket_digest=$1', [f.digest('role-operation', key)]);
  assert.equal((await f.post('status')).statusCode, 429); assert.equal(await f.count('role-operation', key), 121);
  assert.equal((await f.post('history', { ...f.reference, afterVersion: '0' })).statusCode, 200);
  const target = { workspaceId: f.workspaceId, accountId: f.accountId, history: false };
  await f.accountBudget(target); await f.accountBudget(target); assert.equal(await f.count('role-account', `${f.workspaceId}:${f.accountId}`), 2);
  await f.databases.control.query('UPDATE security.request_budgets SET attempts=120 WHERE bucket_digest=$1', [f.digest('role-account', `${f.workspaceId}:${f.accountId}`)]);
  await assert.rejects(f.accountBudget(target), (e: unknown) => e instanceof AppError && e.code === 'RATE_LIMITED');
  await f.accountBudget({ ...target, accountId: randomUUID() }); await f.accountBudget({ ...target, history: true });
  assert.equal(await f.count('role-history-account', `${f.workspaceId}:${f.accountId}`), 1);
});

test('CP06: unexpected role service errors return a bounded safe message', async (t) => {
  const f = await fixture(t), secret = `postgres-secret-${randomUUID()}`; f.fail(new Error(secret));
  const response = await f.post('status'); assert.equal(response.statusCode, 503); assert.equal(response.json().error.code, 'ROLE_UNAVAILABLE');
  assert.ok(response.body.length < 512); assert.equal(response.body.includes(secret), false); assert.equal(f.logs.join('').includes(secret), false);
});

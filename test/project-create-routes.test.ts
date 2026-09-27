import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';
import test, { type TestContext } from 'node:test';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createDatabases } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { RequestBudgets, type RequestBudget } from '../src/modules/identity/budgets.js';
import type { ProjectCreateService } from '../src/modules/work/project-create.js';
import { projectCreateAccountBudget, registerProjectCreateRoutes } from '../src/modules/work/project-create-routes.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
async function fixture(t: TestContext) {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'info' }), databases = createDatabases(config);
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'project-create-http-test' });
  const workspaceId = randomUUID(), operationId = randomUUID(), accountId = randomUUID(), csrfToken = secrets.token();
  const cookie = `v1.${workspaceId}.${randomUUID()}.${secrets.token()}`, calls: { method: string; args: unknown[] }[] = [], logs: string[] = [];
  let failure: Error | undefined;
  const projectCreation = new Proxy({}, { get(_target, method) { return async (...args: unknown[]) => { calls.push({ method: String(method), args }); if (failure) throw failure; return { handled: String(method) }; }; } }) as ProjectCreateService;
  const real = new RequestBudgets(databases.control, secrets), seen = new Map<string, Buffer>();
  const budgets = { async take(entries: readonly RequestBudget[]) { for (const entry of entries) { const hash = secrets.digest(`rate:${entry.purpose}`, entry.key); seen.set(hash.toString('hex'), hash); } await real.take(entries); } };
  const app = buildApp(config, databases, new Writable({ write(chunk, _encoding, done) { logs.push(String(chunk)); done(); } }));
  registerProjectCreateRoutes(app, { origin: config.APP_ORIGIN, projectCreation, budgets });
  t.after(async () => { try { if (seen.size) await databases.control.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[...seen.values()]]); } finally { await app.close(); } });
  const headers = { origin: config.APP_ORIGIN, cookie: `${SESSION_COOKIE_NAME}=${cookie}`, 'x-csrf-token': csrfToken }, reference = { workspaceId, operationId };
  const post = (path: string, body: object | string = reference, custom: Record<string, string> = headers) => app.inject({ method: 'POST', url: `/v1/work/projects/create/${path}`, payload: body, headers: custom, remoteAddress: '192.0.2.97' });
  const digest = (purpose: string, key: string) => secrets.digest(`rate:${purpose}`, key);
  const count = async (purpose: string, key: string) => (await databases.control.query('SELECT attempts FROM security.request_budgets WHERE bucket_digest=$1', [digest(purpose, key)])).rows[0]?.attempts;
  return { app, databases, secrets, seen, workspaceId, operationId, accountId, cookie, csrfToken, headers, reference, post, calls, logs, digest, count, accountBudget: projectCreateAccountBudget(budgets), fail(value: Error) { failure = value; } };
}

test('CP07: project creation HTTP requires exact origin/session/CSRF and rejects private fields and query secrets', async (t) => {
  const f = await fixture(t), privateName = 'Private project alpha', context = { ...f.reference, projectId: randomUUID() };
  for (const headers of [{}, { ...f.headers, origin: 'https://foreign.example' }, { ...f.headers, 'sec-fetch-site': 'cross-site' }])
    assert.equal((await f.post('context', context, headers)).statusCode, 403);
  assert.equal(f.seen.size, 0);
  assert.equal((await f.post('context', context, { origin: f.headers.origin, 'x-csrf-token': f.csrfToken })).statusCode, 401);
  assert.equal((await f.post('context', context, { origin: f.headers.origin, cookie: f.headers.cookie })).statusCode, 403);
  for (const field of ['name','password','phrase','projectKey','privateKey','selected'])
    assert.equal((await f.post('context', { ...context, [field]: privateName })).statusCode, 400);
  assert.equal((await f.post(`status?name=${encodeURIComponent(privateName)}`)).statusCode, 400);
  assert.equal(f.calls.length, 0); assert.equal(f.logs.join('').includes(privateName), false);
  assert.equal((await f.post('context', context)).statusCode, 200);
  assert.deepEqual(f.calls.at(-1), { method: 'context', args: [f.cookie, f.csrfToken, context] });
  assert.equal((await f.post('finalize', { ...f.reference, requestHash: 'a'.repeat(64) })).statusCode, 200);
  assert.equal((await f.post('status')).statusCode, 200);
  assert.equal((await f.post('history', { ...f.reference, afterVersion: '1' })).statusCode, 400);
  assert.equal((await f.post('history', { ...f.reference, afterVersion: '0' })).statusCode, 200);
  assert.equal(f.calls.at(-1)!.method, 'withAuthorizedHistory');
});
test('CP07: project creation HTTP enforces stable operation, independent history/account quotas and safe failures', async (t) => {
  const f = await fixture(t), key = `${f.workspaceId}:${f.operationId}`;
  assert.equal((await f.post('status')).statusCode, 200);
  await f.databases.control.query('UPDATE security.request_budgets SET attempts=120 WHERE bucket_digest=$1', [f.digest('project-create-operation', key)]);
  assert.equal((await f.post('status')).statusCode, 429);
  assert.equal((await f.post('history', { ...f.reference, afterVersion: '0' })).statusCode, 200);
  const scope = { workspaceId: f.workspaceId, accountId: f.accountId, history: false };
  await f.accountBudget(scope); await f.accountBudget(scope); assert.equal(await f.count('project-create-account', `${f.workspaceId}:${f.accountId}`), 2);
  await f.databases.control.query('UPDATE security.request_budgets SET attempts=120 WHERE bucket_digest=$1', [f.digest('project-create-account', `${f.workspaceId}:${f.accountId}`)]);
  await assert.rejects(f.accountBudget(scope), (e: unknown) => e instanceof AppError && e.code === 'RATE_LIMITED');
  await f.accountBudget({ ...scope, history: true });
  const secret = `database-private-${randomUUID()}`; f.fail(new Error(secret));
  const response = await f.post('status', { workspaceId: f.workspaceId, operationId: randomUUID() });
  assert.equal(response.statusCode, 503); assert.equal(response.json().error.code, 'PROJECT_UNAVAILABLE');
  assert.ok(response.body.length < 512); assert.equal(f.logs.join('').includes(secret), false);
});

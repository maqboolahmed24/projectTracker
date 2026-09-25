import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';
import test, { type TestContext } from 'node:test';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createDatabases } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { RequestBudgets, type RequestBudget } from '../src/modules/identity/budgets.js';
import type { EnrolmentService } from '../src/modules/identity/enrolment.js';
import { enrolmentAccountBudget, registerEnrolmentRoutes } from '../src/modules/identity/enrolment-routes.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';

// HTTP boundary checks use a fake service and real durable counters; service tests
// separately verify transactional permissions, cryptographic proofs and receipts.
async function fixture(t: TestContext) {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'info' });
  const databases = createDatabases(config), secrets = new ServiceSecrets({
    SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'enrolment-http-test' });
  const workspaceId = randomUUID(), accountId = randomUUID(), operationId = randomUUID(), resumeToken = secrets.token();
  const cookieValue = `v1.${workspaceId}.${randomUUID()}.${secrets.token()}`, csrfToken = secrets.token(), source = '192.0.2.94';
  const logs: string[] = [], calls: { method: string; args: unknown[] }[] = [];
  let failure: Error | undefined;
  const enrolment = new Proxy({}, { get(_target, method) { return async (...args: unknown[]) => {
    calls.push({ method: String(method), args }); if (failure) throw failure; return { handled: String(method) };
  }; } }) as EnrolmentService;
  const real = new RequestBudgets(databases.control, secrets), seen = new Map<string, Buffer>();
  const budgets = { async take(entries: readonly RequestBudget[]) {
    for (const entry of entries) { const hash = secrets.digest(`rate:${entry.purpose}`, entry.key); seen.set(hash.toString('hex'), hash); }
    await real.take(entries);
  } };
  const app = buildApp(config, databases, new Writable({ write(chunk, _encoding, done) { logs.push(String(chunk)); done(); } }));
  registerEnrolmentRoutes(app, { origin: config.APP_ORIGIN, enrolment, budgets });
  t.after(async () => { try {
    if (seen.size) await databases.control.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[...seen.values()]]);
  } finally { await app.close(); } });
  const headers = { origin: config.APP_ORIGIN }, ownerHeaders = { ...headers, cookie: `${SESSION_COOKIE_NAME}=${cookieValue}`, 'x-csrf-token': csrfToken };
  const reference = { workspaceId, operationId }, capability = { ...reference, resumeToken };
  const post = (path: string, body: object | string = capability, requestHeaders: Record<string, string> = headers) =>
    app.inject({ method: 'POST', url: `/v1/auth/enrolment/${path}`, payload: body, headers: requestHeaders, remoteAddress: source });
  const bucket = (purpose: string, key: string) => secrets.digest(`rate:${purpose}`, key);
  const attempts = async (purpose: string, key: string) =>
    (await databases.control.query<{ attempts: number }>('SELECT attempts FROM security.request_budgets WHERE bucket_digest=$1', [bucket(purpose, key)])).rows[0]?.attempts;
  return { app, databases, secrets, workspaceId, accountId, operationId, resumeToken, cookieValue, csrfToken,
    source, logs, calls, seen, headers, ownerHeaders, reference, capability, post, bucket, attempts,
    accountBudget: enrolmentAccountBudget(budgets), fail(error?: Error) { failure = error; } };
}

test('CP06: enrolment HTTP boundary rejects foreign origins, query secrets, duplicate JSON and plaintext private fields', async (t) => {
  const f = await fixture(t), secret = 'private-name-password-phrase';
  for (const headers of [{}, { origin: 'https://foreign.example' }, { ...f.headers, 'sec-fetch-site': 'cross-site' }]) {
    assert.equal((await f.post('status', f.capability, headers)).statusCode, 403);
  }
  assert.equal(f.seen.size, 0);
  assert.equal((await f.post(`status?password=${secret}`)).statusCode, 400);
  for (const key of ['password', 'phrase', 'displayName', 'privateKey', 'unexpected']) {
    assert.equal((await f.post('status', { ...f.capability, [key]: secret })).statusCode, 400);
  }
  const duplicate = `{"workspaceId":"${f.workspaceId}","operationId":"${f.operationId}","resumeToken":"${f.resumeToken}","resumeToken":"${f.secrets.token()}"}`;
  assert.equal((await f.post('status', duplicate, { ...f.headers, 'content-type': 'application/json' })).statusCode, 400);
  assert.equal((await f.post('status', { ...f.capability, padding: 'x'.repeat(1024 * 1024) })).statusCode, 413);
  assert.equal(f.calls.length, 0); assert.equal(f.logs.join('').includes(secret), false);
});

test('CP06: Owner and promotion actions require cookie and CSRF; target resume ignores a stale cookie', async (t) => {
  const f = await fixture(t), promotion = { ...f.reference, accountId: f.accountId };
  assert.equal((await f.post('promotion/begin', promotion, { ...f.headers, 'x-csrf-token': f.csrfToken })).statusCode, 401);
  assert.equal((await f.post('promotion/begin', promotion, { ...f.headers, cookie: `${SESSION_COOKIE_NAME}=${f.cookieValue}` })).statusCode, 403);
  assert.equal((await f.post('promotion/claim', f.capability)).statusCode, 403, 'A known operation capability cannot replace current target authentication');
  assert.equal((await f.post('claim', f.capability, f.ownerHeaders)).statusCode, 400, 'Owner claim accepts a public reference only');
  const issuance = { ...promotion, kind: 'join_member', roleId: randomUUID(), projectIds: [] };
  assert.equal((await f.post('join/context', issuance)).statusCode, 403);
  assert.equal((await f.post('join/context', issuance, f.ownerHeaders)).statusCode, 200);
  assert.deepEqual(f.calls.at(-1), { method: 'issuanceContext', args: [f.cookieValue, f.csrfToken, issuance] });
  assert.equal((await f.post('join/history', { ...f.reference, afterVersion: '0' })).statusCode, 403);
  assert.equal((await f.post('join/history', { ...f.reference, afterVersion: '1' }, f.ownerHeaders)).statusCode, 400);
  assert.equal((await f.post('join/history', { ...f.reference, afterVersion: '0' }, f.ownerHeaders)).statusCode, 200);
  assert.equal(f.calls.at(-1)!.method, 'withIssuanceHistory');
  assert.equal((await f.post('promotion/begin', promotion, f.ownerHeaders)).statusCode, 200);
  assert.deepEqual(f.calls.at(-1), { method: 'beginPromotion', args: [f.cookieValue, f.csrfToken, promotion] });
  assert.equal((await f.post('promotion/claim', f.capability, f.ownerHeaders)).statusCode, 200);
  assert.deepEqual(f.calls.at(-1), { method: 'claimPromotion', args: [f.capability, { cookieValue: f.cookieValue, csrfToken: f.csrfToken }] });
  assert.equal((await f.post('finalize', { ...f.capability, requestHash: 'a'.repeat(64) }, f.ownerHeaders)).statusCode, 400);
  assert.equal((await f.post('finalize', { ...f.reference, requestHash: 'a'.repeat(64) })).statusCode, 403);
  assert.equal((await f.post('materials', f.capability, f.ownerHeaders)).statusCode, 400);
  const status = await f.post('status', f.capability, { ...f.ownerHeaders, 'x-csrf-token': 'stale' });
  assert.equal(status.statusCode, 200); assert.equal(status.headers['cache-control'], 'no-store');
  assert.equal(status.headers['set-cookie'], undefined);
  assert.deepEqual(f.calls.at(-1), { method: 'status', args: [f.capability, undefined] });
  for (const secret of [f.cookieValue, f.csrfToken, f.resumeToken]) assert.equal(f.logs.join('').includes(secret), false);
});

test('CP06: JOIN accepts only canonical codes and durable quotas bound repeated guessing without storing raw codes', async (t) => {
  const f = await fixture(t), code = 'JOIN-ABCD-EFGH-JKLM';
  for (const invalid of ['ABCD-EFGH-JKLM', 'join-abcd-efgh-jklm', 'JOIN-0000-OOOO-IIII', `${code} `]) {
    assert.equal((await f.post('join/begin', { workspaceId: f.workspaceId, code: invalid, resumeToken: f.resumeToken })).statusCode, 400);
  }
  const body = { workspaceId: f.workspaceId, code, resumeToken: f.resumeToken };
  assert.equal((await f.post('join/begin', body)).statusCode, 200);
  const key = `${f.workspaceId}:${code}`;
  await f.databases.control.query('UPDATE security.request_budgets SET attempts=119 WHERE bucket_digest=$1', [f.bucket('enrolment-operation', key)]);
  assert.equal((await f.post('join/begin', body)).statusCode, 200);
  assert.equal((await f.post('join/begin', body)).statusCode, 429);
  assert.equal(await f.attempts('enrolment-operation', key), 121, 'Denied counter commits');
  const stored = JSON.stringify((await f.databases.control.query('SELECT * FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[...f.seen.values()]])).rows);
  for (const value of [code, f.workspaceId, f.resumeToken, f.source]) {
    assert.equal(stored.includes(value), false); assert.equal(f.logs.join('').includes(value), false);
  }
});

test('CP06: history requires anchored cursors and current-session authority while using independent quotas', async (t) => {
  const f = await fixture(t), request = { ...f.capability, mode: 'transcript', afterVersion: '0' };
  assert.equal((await f.post('history', { ...request, afterVersion: '1' })).statusCode, 400);
  assert.equal((await f.post('history', { ...request, mode: 'current' })).statusCode, 403);
  assert.equal((await f.post('history', { ...request, mode: 'current' }, f.ownerHeaders)).statusCode, 200);
  assert.deepEqual(f.calls.at(-1)!.args.slice(0, 2), [f.capability, { cookieValue: f.cookieValue, csrfToken: f.csrfToken }]);
  assert.equal((await f.post('status')).statusCode, 200);
  const ordinary = await f.attempts('enrolment-source', f.source);
  assert.equal((await f.post('history', request)).statusCode, 200);
  assert.equal(f.calls.at(-1)!.args[1], undefined);
  await f.databases.control.query('UPDATE security.request_budgets SET attempts=999 WHERE bucket_digest=$1',
    [f.bucket('enrolment-history-operation', `${f.workspaceId}:${f.operationId}`)]);
  assert.equal((await f.post('history', request)).statusCode, 200);
  assert.equal((await f.post('history', request)).statusCode, 429);
  assert.equal(await f.attempts('enrolment-source', f.source), ordinary);
});

test('CP06: replacement operations share resolved-target quotas and unexpected errors do not expose service secrets', async (t) => {
  const f = await fixture(t), target = { workspaceId: f.workspaceId, accountId: f.accountId, history: false };
  await f.accountBudget(target); await f.accountBudget(target);
  assert.equal(await f.attempts('enrolment-target-account', `${f.workspaceId}:${f.accountId}`), 2);
  await f.databases.control.query('UPDATE security.request_budgets SET attempts=120 WHERE bucket_digest=$1',
    [f.bucket('enrolment-target-account', `${f.workspaceId}:${f.accountId}`)]);
  await assert.rejects(f.accountBudget(target), (error: unknown) => error instanceof AppError && error.code === 'RATE_LIMITED');
  await f.accountBudget({ ...target, accountId: randomUUID() });
  await f.accountBudget({ ...target, history: true });
  assert.equal(await f.attempts('enrolment-target-history-account', `${f.workspaceId}:${f.accountId}`), 1);
  const secret = `database-private-detail-${randomUUID()}`; f.fail(new Error(secret));
  const response = await f.post('status');
  assert.equal(response.statusCode, 503); assert.equal(response.json().error.code, 'ENROLMENT_UNAVAILABLE');
  assert.ok(response.body.length < 512); assert.equal(response.body.includes(secret), false); assert.equal(f.logs.join('').includes(secret), false);
});

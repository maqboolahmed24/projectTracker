import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';
import test, { type TestContext } from 'node:test';
import type { PoolClient } from 'pg';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createDatabases } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { createRequestBudgetPool, RequestBudgets, type RequestBudget } from '../src/modules/identity/budgets.js';
import type { RecoveryService } from '../src/modules/identity/recovery.js';
import { recoveryAccountBudget, registerRecoveryRoutes } from '../src/modules/identity/recovery-routes.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';

/** These tests isolate the HTTP adapter with a fake service and actual durable rate counters. */
async function fixture(t: TestContext) {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'info' });
  const databases = createDatabases(config);
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'recovery-routes-test' });
  const workspaceId = randomUUID(), accountId = randomUUID(), operationId = randomUUID(), resumeToken = secrets.token();
  const cookieValue = `v1.${workspaceId}.${randomUUID()}.${secrets.token()}`, csrfToken = secrets.token(), source = '192.0.2.83';
  const logs: string[] = [], calls: { method: string; args: unknown[] }[] = [];
  let failure: Error | undefined;
  const recovery = new Proxy({}, { get(_target, method) {
    return async (...args: unknown[]) => {
      calls.push({ method: String(method), args });
      if (failure) throw failure;
      // History callback execution/database visibility is exercised by service/history suites.
      return { handled: String(method) };
    };
  } }) as RecoveryService;
  const realBudgets = new RequestBudgets(databases.control, secrets), seen = new Map<string, Buffer>();
  const budgets = { async take(entries: readonly RequestBudget[]) {
    for (const entry of entries) {
      const digest = secrets.digest(`rate:${entry.purpose}`, entry.key); seen.set(digest.toString('hex'), digest);
    }
    await realBudgets.take(entries);
  } };
  const app = buildApp(config, databases, new Writable({ write(chunk, _encoding, done) { logs.push(String(chunk)); done(); } }));
  registerRecoveryRoutes(app, { origin: config.APP_ORIGIN, recovery, budgets });
  t.after(async () => {
    try { if (seen.size) await databases.control.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[...seen.values()]]); }
    finally { await app.close(); }
  });
  const headers = { origin: config.APP_ORIGIN }, ownerHeaders = { ...headers, cookie: `${SESSION_COOKIE_NAME}=${cookieValue}`, 'x-csrf-token': csrfToken };
  const reference = { workspaceId, operationId }, capability = { ...reference, resumeToken };
  const post = (path: string, body: object | string = capability, requestHeaders: Record<string, string> = headers) =>
    app.inject({ method: 'POST', url: `/v1/auth/recovery/${path}`, headers: requestHeaders, payload: body, remoteAddress: source });
  const bucket = (purpose: string, key: string) => secrets.digest(`rate:${purpose}`, key);
  const attempts = async (purpose: string, key: string) =>
    (await databases.control.query<{ attempts: number }>('SELECT attempts FROM security.request_budgets WHERE bucket_digest=$1', [bucket(purpose, key)])).rows[0]?.attempts;
  return { app, databases, secrets, config, workspaceId, accountId, operationId, resumeToken, source, cookieValue, csrfToken,
    headers, ownerHeaders, reference, capability, post, calls, seen, logs, bucket, attempts, accountBudget: recoveryAccountBudget(budgets),
    fail(error?: Error) { failure = error; } };
}

test('CP05: recovery routes reject foreign origins, query credentials, duplicate JSON and private/unknown body fields', async (t) => {
  const f = await fixture(t), secret = 'Private recovery phrase/password must never reach a route';
  const rejectedHeaders: Record<string, string>[] = [{}, { origin: 'https://foreign.example' }, { ...f.headers, 'sec-fetch-site': 'cross-site' }];
  for (const headers of rejectedHeaders) {
    const response = await f.post('status', f.capability, headers);
    assert.equal(response.statusCode, 403); assert.equal(response.json().error.code, 'ORIGIN_REJECTED');
  }
  assert.equal(f.seen.size, 0, 'Origin rejection precedes database rate work');
  assert.equal((await f.post(`status?phrase=${encodeURIComponent(secret)}`)).statusCode, 400);
  for (const field of ['password', 'phrase', 'privateKey', 'registrationRecord', 'unexpected']) {
    const response = await f.post('status', { ...f.capability, [field]: secret });
    assert.equal(response.statusCode, 400); assert.equal(response.json().error.code, 'INVALID_REQUEST');
  }
  const duplicate = `{"workspaceId":"${f.workspaceId}","workspaceId":"${randomUUID()}","operationId":"${f.operationId}","resumeToken":"${f.resumeToken}"}`;
  assert.equal((await f.post('status', duplicate, { ...f.headers, 'content-type': 'application/json' })).statusCode, 400);
  assert.equal((await f.post('status', { ...f.capability, padding: 'x'.repeat(1024 * 1024) })).statusCode, 413);
  assert.equal(f.calls.length, 0);
  assert.equal(f.logs.join('').includes(secret), false);
});

test('CP05: resolved-target budgets aggregate across operations, isolate accounts/workspaces and independently bound history', async (t) => {
  const f = await fixture(t), otherAccount = randomUUID(), otherWorkspace = randomUUID();
  for (const history of [false, true]) {
    const target = { workspaceId: f.workspaceId, accountId: f.accountId, history };
    const accountPurpose = history ? 'recovery-target-history-account' : 'recovery-target-account';
    const workspacePurpose = history ? 'recovery-target-history-workspace' : 'recovery-target-workspace';
    const accountKey = `${f.workspaceId}:${f.accountId}`, accountLimit = history ? 1000 : 120, workspaceLimit = history ? 4000 : 480;
    // No operation ID is part of this callback: different valid ceremonies share the same resolved profile quota.
    await f.accountBudget(target); await f.accountBudget(target);
    assert.equal(await f.attempts(accountPurpose, accountKey), 2);
    await f.databases.control.query('UPDATE security.request_budgets SET attempts=$2 WHERE bucket_digest=$1', [f.bucket(accountPurpose, accountKey), accountLimit - 1]);
    await f.accountBudget(target);
    await assert.rejects(f.accountBudget(target), (error: unknown) => error instanceof AppError && error.code === 'RATE_LIMITED');
    assert.equal(await f.attempts(accountPurpose, accountKey), accountLimit + 1, 'Denied target attempts stay committed');
    await f.accountBudget({ ...target, accountId: otherAccount });
    assert.equal(await f.attempts(accountPurpose, `${f.workspaceId}:${otherAccount}`), 1, 'Another account has its own quota');
    await f.accountBudget({ ...target, workspaceId: otherWorkspace });
    assert.equal(await f.attempts(accountPurpose, `${otherWorkspace}:${f.accountId}`), 1, 'The same opaque account ID in another workspace is isolated');
    await f.databases.control.query('UPDATE security.request_budgets SET attempts=$2 WHERE bucket_digest=$1', [f.bucket(workspacePurpose, f.workspaceId), workspaceLimit - 1]);
    await f.accountBudget({ ...target, accountId: otherAccount });
    await assert.rejects(f.accountBudget({ ...target, accountId: otherAccount }), (error: unknown) => error instanceof AppError && error.code === 'RATE_LIMITED');
    assert.equal(await f.attempts(workspacePurpose, f.workspaceId), workspaceLimit + 1);
    await f.accountBudget({ ...target, workspaceId: otherWorkspace });
    assert.equal(await f.attempts(workspacePurpose, otherWorkspace), 2);
  }
  assert.equal(await f.attempts('recovery-target-account', `${f.workspaceId}:${f.accountId}`), 121, 'History did not consume ordinary target counters');
  assert.equal(await f.attempts('recovery-source', f.source), undefined, 'Trusted-target callback is distinct from route prelookup budgets');
  const stored = JSON.stringify((await f.databases.control.query('SELECT * FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[...f.seen.values()]])).rows);
  for (const value of [f.workspaceId, f.accountId, otherWorkspace, otherAccount]) assert.equal(stored.includes(value), false);
});

test('CP05: resolved-target counters complete while every authority-pool connection is held', async (t) => {
  const f = await fixture(t), pool = createRequestBudgetPool(f.config);
  const held: PoolClient[] = [];
  for (const [purpose, key] of [['recovery-target-account', `${f.workspaceId}:${f.accountId}`], ['recovery-target-workspace', f.workspaceId]]) {
    const digest = f.bucket(purpose!, key!); f.seen.set(digest.toString('hex'), digest);
  }
  try {
    for (let index = 0; index < 10; index++) held.push(await f.databases.control.connect());
    assert.equal(f.databases.control.totalCount, 10); assert.equal(f.databases.control.idleCount, 0);
    await recoveryAccountBudget(new RequestBudgets(pool, f.secrets))({ workspaceId: f.workspaceId, accountId: f.accountId, history: false });
    assert.equal((await pool.query<{ attempts: number }>('SELECT attempts FROM security.request_budgets WHERE bucket_digest=$1',
      [f.bucket('recovery-target-account', `${f.workspaceId}:${f.accountId}`)])).rows[0]?.attempts, 1);
    assert.equal(f.databases.control.idleCount, 0, 'The callback completed without borrowing the held authority connections');
  } finally {
    for (const client of held) client.release();
    await pool.end();
  }
});

test('CP05: recovery Owner operations require a session cookie and CSRF, while explicit target capabilities ignore a stale cookie', async (t) => {
  const f = await fixture(t), issue = { workspaceId: f.workspaceId, accountId: f.accountId, resetId: f.operationId };
  assert.equal((await f.post('reset/issue', issue, { ...f.headers, 'x-csrf-token': f.csrfToken })).statusCode, 401);
  assert.equal((await f.post('reset/issue', issue, { ...f.headers, cookie: `${SESSION_COOKIE_NAME}=${f.cookieValue}` })).statusCode, 403);
  assert.equal((await f.post('claim', f.reference, { ...f.ownerHeaders, 'x-csrf-token': '' })).statusCode, 403);
  assert.equal((await f.post('claim', f.capability, f.ownerHeaders)).statusCode, 400, 'Owner QR/reference must exclude the target capability');
  const issued = await f.post('reset/issue', issue, f.ownerHeaders);
  assert.equal(issued.statusCode, 200); assert.equal(issued.headers['set-cookie'], undefined); assert.equal(issued.headers['cache-control'], 'no-store');
  assert.deepEqual(f.calls.at(-1), { method: 'issueReset', args: [f.cookieValue, f.csrfToken, issue] });
  assert.equal((await f.post('inspect', f.reference, f.ownerHeaders)).statusCode, 200);
  assert.deepEqual(f.calls.at(-1), { method: 'inspect', args: [f.reference, { cookieValue: f.cookieValue, csrfToken: f.csrfToken }] });
  assert.equal((await f.post('inspect', f.capability, { ...f.ownerHeaders, 'x-csrf-token': 'stale-token' })).statusCode, 200);
  assert.deepEqual(f.calls.at(-1), { method: 'inspect', args: [f.capability, undefined] });
  assert.equal((await f.post('finalize', { ...f.capability, requestHash: 'a'.repeat(64) }, { ...f.ownerHeaders, 'x-csrf-token': 'stale-token' })).statusCode, 200);
  assert.equal(f.calls.at(-1)!.args[1], undefined);
  assert.equal((await f.post('finalize', { ...f.reference, requestHash: 'a'.repeat(64) }, f.ownerHeaders)).statusCode, 200);
  assert.deepEqual(f.calls.at(-1)!.args[1], { cookieValue: f.cookieValue, csrfToken: f.csrfToken });
  for (const secret of [f.cookieValue, f.csrfToken, f.resumeToken]) assert.equal(f.logs.join('').includes(secret), false);
});

test('CP05: recovery history requires anchored cursors, selects current-session authority and has independent bounded quotas', async (t) => {
  const f = await fixture(t), history = { ...f.capability, mode: 'transcript', afterVersion: '0' };
  assert.equal((await f.post('history', { ...history, afterVersion: '1' })).statusCode, 400);
  assert.equal((await f.post('history', { ...history, mode: 'current' })).statusCode, 403);
  assert.equal((await f.post('history', { ...history, mode: 'current' }, f.ownerHeaders)).statusCode, 200);
  assert.deepEqual(f.calls.at(-1)!.args.slice(0, 2), [f.capability, { cookieValue: f.cookieValue, csrfToken: f.csrfToken }]);
  assert.equal((await f.post('status')).statusCode, 200);
  const ordinarySource = await f.attempts('recovery-source', f.source), ordinaryOperation = await f.attempts('recovery-operation', `${f.workspaceId}:${f.operationId}`);
  assert.equal((await f.post('history', history)).statusCode, 200);
  assert.equal(f.calls.at(-1)!.method, 'withAuthorizedHistory'); assert.equal(f.calls.at(-1)!.args[1], undefined);
  const historyRows = [
    { purpose: 'recovery-history-source', key: f.source, limit: 1200 },
    { purpose: 'recovery-history-workspace', key: f.workspaceId, limit: 4000 },
    { purpose: 'recovery-history-operation', key: `${f.workspaceId}:${f.operationId}`, limit: 1000 },
  ];
  const digests = historyRows.map((row) => f.bucket(row.purpose, row.key));
  for (const row of historyRows) {
    await f.databases.control.query('UPDATE security.request_budgets SET attempts=1 WHERE bucket_digest=ANY($1::bytea[])', [digests]);
    await f.databases.control.query('UPDATE security.request_budgets SET attempts=$2 WHERE bucket_digest=$1', [f.bucket(row.purpose, row.key), row.limit - 1]);
    assert.equal((await f.post('history', history)).statusCode, 200, `${row.purpose}: final allowed request`);
    const denied = await f.post('history', history);
    assert.equal(denied.statusCode, 429); assert.equal(denied.json().error.code, 'RATE_LIMITED');
    assert.equal(await f.attempts(row.purpose, row.key), row.limit + 1, 'Denied counters remain committed');
  }
  assert.equal(await f.attempts('recovery-source', f.source), ordinarySource);
  assert.equal(await f.attempts('recovery-operation', `${f.workspaceId}:${f.operationId}`), ordinaryOperation);
});

test('CP05: recovery credential limits are durable and raw service failures remain bounded and secret-free', async (t) => {
  const f = await fixture(t), input = { workspaceId: f.workspaceId, accountId: f.accountId, operationId: f.operationId, resumeToken: f.resumeToken };
  assert.equal((await f.post('phrase/begin', input)).statusCode, 200);
  const rows = [
    { purpose: 'recovery-source', key: f.source, limit: 120 },
    { purpose: 'recovery-workspace', key: f.workspaceId, limit: 480 },
    { purpose: 'recovery-operation', key: `${f.workspaceId}:${f.operationId}`, limit: 120 },
    { purpose: 'recovery-account', key: `${f.workspaceId}:${f.accountId}`, limit: 15 },
  ];
  const digests = rows.map((row) => f.bucket(row.purpose, row.key));
  for (const row of rows) {
    await f.databases.control.query('UPDATE security.request_budgets SET attempts=1 WHERE bucket_digest=ANY($1::bytea[])', [digests]);
    await f.databases.control.query('UPDATE security.request_budgets SET attempts=$2 WHERE bucket_digest=$1', [f.bucket(row.purpose, row.key), row.limit - 1]);
    assert.equal((await f.post('phrase/begin', input)).statusCode, 200);
    const denied = await f.post('phrase/begin', input); assert.equal(denied.statusCode, 429); assert.equal(denied.json().error.code, 'RATE_LIMITED');
  }
  await f.databases.control.query('UPDATE security.request_budgets SET attempts=1 WHERE bucket_digest=ANY($1::bytea[])', [digests]);
  const secret = `sensitive database/password detail ${randomUUID()}`;
  f.fail(new Error(secret));
  const unavailable = await f.post('status');
  assert.equal(unavailable.statusCode, 503); assert.equal(unavailable.json().error.code, 'RECOVERY_UNAVAILABLE');
  assert.ok(unavailable.body.length < 512); assert.equal(unavailable.body.includes(secret), false);
  assert.equal(f.logs.join('').includes(secret), false);
  f.fail(new AppError('RECOVERY_INVALID', 'Recovery is unavailable; restart with a current recovery method', 401));
  assert.equal((await f.post('status')).json().error.code, 'RECOVERY_INVALID');
  const stored = JSON.stringify((await f.databases.control.query('SELECT * FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[...f.seen.values()]])).rows);
  for (const value of [f.source, f.workspaceId, f.accountId, f.resumeToken]) assert.equal(stored.includes(value), false);
});

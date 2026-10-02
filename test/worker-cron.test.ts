import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { loadConfig } from '../src/config.js';
import { createDatabases } from '../src/db.js';
import { startWorker } from '../src/worker.js';

async function eventually(check: () => Promise<boolean>, timeout = 10000) {
  const deadline = Date.now() + timeout;
  while (!await check()) {
    if (Date.now() >= deadline) throw new Error('Cleanup job did not settle');
    await delay(25);
  }
}

test('CP11 cleanup: native cron metadata and manual jobs prune expired rows, preserve live rows, and reject other metadata', { timeout: 30000 }, async t => {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent', HOST: '127.0.0.1' });
  const databases = createDatabases(config), workspaceId = randomUUID();
  const expiredLogin = randomUUID(), liveLogin = randomUUID();
  const expiredBudget = randomBytes(32), liveBudget = randomBytes(32), keys: string[] = [];
  let worker: Awaited<ReturnType<typeof startWorker>> | undefined;
  t.after(async () => {
    await worker?.stop();
    try {
      for (const key of keys) await databases.application.query('SELECT graphile_worker.remove_job($1)', [key]);
      await databases.control.query('DELETE FROM security.auth_attempts WHERE workspace_id=$1', [workspaceId]);
      await databases.control.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[expiredBudget, liveBudget]]);
    } finally { await databases.close(); }
  });

  // These are isolated retention rows, not fabricated authentication authority.
  // Old dates put the expired rows inside the bounded cleanup batch even when
  // the shared development database has accumulated other expired attempts.
  await databases.control.query(`INSERT INTO security.request_budgets(bucket_digest,window_started_at,attempts,expires_at)
    VALUES($1,'1970-01-01T00:00:00Z',1,'1970-01-01T00:01:00Z'),
      ($2,clock_timestamp(),1,clock_timestamp()+interval '1 hour')`, [expiredBudget, liveBudget]);
  await databases.control.query(`INSERT INTO security.auth_attempts(login_id,purpose,workspace_id,profile_id,eligible,
      expected_credential_generation,expected_session_generation,expected_data_generation,state,
      server_state_ciphertext,server_state_key_id,created_at,expires_at)
    VALUES($1,'login',$3,$4,false,0,0,0,'issued','retention-fixture','retention-fixture','1970-01-01T00:00:00Z','1970-01-01T00:01:00Z'),
      ($2,'login',$3,$4,false,0,0,0,'issued','retention-fixture','retention-fixture',clock_timestamp(),clock_timestamp()+interval '110 seconds')`,
  [expiredLogin, liveLogin, workspaceId, randomUUID()]);

  worker = await startWorker(config, { port: 0 });
  const current = async (id: string) => (await databases.application.query(
    'SELECT id::text,attempts,max_attempts,locked_at,last_error FROM graphile_worker.jobs WHERE id=$1', [id])).rows[0];
  const enqueue = async (payload: Record<string, unknown>) => {
    const key = `cleanup-fixture:${randomUUID()}`; keys.push(key);
    return worker!.runner.addJob('request_budget_cleanup', payload, { jobKey: key, maxAttempts: 1 });
  };
  const timestamp = new Date().toISOString();
  for (const payload of [
    { unexpected: 'private-fixture-value' },
    { _cron: { ts: timestamp, backfilled: false, unexpected: 'private-fixture-value' } },
    { _cron: { ts: 'invalid-time', backfilled: false } },
    { _cron: { ts: timestamp, backfilled: 'false' } },
  ]) {
    const job = await enqueue(payload);
    await eventually(async () => { const row = await current(job.id); return row?.attempts === 1 && !row.locked_at && !!row.last_error; });
    const row = await current(job.id);
    assert.equal(row.max_attempts, 1);
    assert.match(row.last_error, /JOB_RETRYABLE/);
    assert.equal(row.last_error.includes('private-fixture-value'), false, 'safeJob keeps rejected payload details out of queue errors');
  }

  // This is the exact JSON shape persisted by Graphile makeJobForItem. A job
  // disappears only after successful execution; failed jobs remain observable.
  const scheduled = await enqueue({ _cron: { ts: timestamp, backfilled: false } });
  await eventually(async () => !await current(scheduled.id));
  const attempts = (await databases.control.query('SELECT login_id FROM security.auth_attempts WHERE workspace_id=$1', [workspaceId])).rows;
  assert.deepEqual(attempts.map(row => row.login_id), [liveLogin]);
  const budgets = (await databases.control.query('SELECT bucket_digest FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[expiredBudget, liveBudget]])).rows;
  assert.equal(budgets.length, 1);
  assert.deepEqual(budgets[0]!.bucket_digest, liveBudget);

  for (const payload of [{}, { _cron: { ts: timestamp, backfilled: true } }]) {
    const job = await enqueue(payload);
    await eventually(async () => !await current(job.id));
  }
  assert.equal((await databases.control.query('SELECT 1 FROM security.auth_attempts WHERE login_id=$1', [liveLogin])).rowCount, 1);
  assert.equal((await databases.control.query('SELECT 1 FROM security.request_budgets WHERE bucket_digest=$1', [liveBudget])).rowCount, 1);
});

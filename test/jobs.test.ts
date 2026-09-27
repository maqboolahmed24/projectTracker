import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { Task } from 'graphile-worker';
import { safeJob, failedJobs, jobMetrics, reconcileJobFailure, reconcileFailedJobs, replayJob, JOB_JITTER_MAX_MS } from '../src/jobs.js';
import { loadConfig } from '../src/config.js';
import { startWorker } from '../src/worker.js';
import { deliverNotificationJob } from '../src/modules/notifications/delivery.js';
import { planningFixture } from './planning-fixture.js';
type TaskHelpers = Parameters<Task>[1];

async function eventually(check: () => Promise<boolean>, timeout = 10000) {
  const until = Date.now() + timeout;
  while (!await check()) { if (Date.now() >= until) throw new Error('Queue condition did not settle'); await delay(25); }
}

test('CP11 jobs: jitter is bounded, only retryable attempts wait, and queue errors contain no task error', async () => {
  const waits: number[] = [];
  for (const random of [-1, 0.5, 2, Number.NaN]) {
    const task = safeJob(async () => { throw new Error('synthetic-private-task-error'); }, { random: () => random, sleep: async ms => { waits.push(ms); } });
    await assert.rejects(async () => task({}, { job: { attempts: 1, max_attempts: 10 } } as TaskHelpers), { message: 'JOB_RETRYABLE' });
  }
  assert.deepEqual(waits, [0, JOB_JITTER_MAX_MS / 2, JOB_JITTER_MAX_MS, 0]);
  const task = safeJob(async () => { throw new Error('synthetic-private-task-error'); }, { sleep: async () => { assert.fail('Exhausted job must not wait'); } });
  await assert.rejects(async () => task({}, { job: { attempts: 10, max_attempts: 10 } } as TaskHelpers), { message: 'JOB_RETRYABLE' });
  let called = 0;
  await safeJob(async () => { called++; })({}, {} as TaskHelpers);
  assert.equal(called, 1);
});

test('CP11 jobs: real queue fails after ten attempts, mirrors rollback failures, retains identity on replay, and delivers once', { timeout: 60000 }, async t => {
  let worker: Awaited<ReturnType<typeof startWorker>> | undefined, releaseLast = () => {};
  t.after(async () => { releaseLast(); await worker?.stop(); });
  const f = await planningFixture(t), taskId = randomUUID();
  const draft = await f.preparePlanning({ action: 'create_task', task: { id: taskId, phaseId: null, milestoneId: null,
    assigneeIds: [f.accountId], leadProfileId: f.accountId } }, { content: { title: 'Job retry fixture', description: '', acceptanceCriteria: '' } });
  await f.save(draft);
  const outbox = (await f.admin.application.query('SELECT id,data_generation FROM app.outbox WHERE workspace_id=$1 AND operation_id=$2', [f.workspaceId, draft.mutation.body.binding.operationId])).rows[0];
  const key = `notification:${f.workspaceId}:${outbox.data_generation}:${outbox.id}`;
  const job = (await f.databases.application.query('SELECT id::text,key FROM graphile_worker.jobs WHERE key=$1', [key])).rows[0];
  assert.ok(job);
  let failures = 0, fail = true, enteredLast = false;
  const lastAttempt = new Promise<void>(resolve => { releaseLast = resolve; });
  worker = await startWorker(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent', HOST: '127.0.0.1' }), { port: 0,
    taskOverrides: { notification_delivery: async payload => {
      const selected = (payload as { outboxId?: string }).outboxId === outbox.id;
      if (selected && fail) {
        failures++;
        if (failures === 10) { enteredLast = true; await lastAttempt; }
        await deliverNotificationJob(f.databases, payload, { beforeCommit: async () => { throw new Error('synthetic-private-delivery-error'); } });
      } else await deliverNotificationJob(f.databases, payload);
    } } });
  const current = async () => (await f.databases.application.query('SELECT id::text,key,attempts,max_attempts,last_error,locked_at,run_at FROM graphile_worker.jobs WHERE id=$1', [job.id])).rows[0];
  for (let attempt = 1; attempt <= 10; attempt++) {
    if (attempt === 10) {
      await eventually(async () => enteredLast);
      assert.equal((await failedJobs(f.databases.application, { after: String(BigInt(job.id) - 1n), limit: 1 })).jobs.some(j => j.id === job.id), false);
      await assert.rejects(replayJob(f.databases, job.id), /JOB_NOT_REPLAYABLE/);
      const metrics = await jobMetrics(f.databases.application);
      assert.ok(metrics.pending >= 1, 'The running last attempt is pending, not exhausted');
      releaseLast();
    }
    await eventually(async () => { const row = await current(); return row?.attempts === attempt && !row.locked_at && !!row.last_error; });
    const row = await current();
    assert.equal(row.id, job.id); assert.equal(row.key, key); assert.equal(row.max_attempts, 10);
    assert.equal(row.last_error.includes('synthetic-private-delivery-error'), false);
    const remaining = row.run_at.getTime() - Date.now();
    assert.ok(remaining >= Math.exp(attempt) * 1000 - 2000 && remaining <= Math.exp(attempt) * 1000 + 1000, 'Native bounded exponential delay is persisted');
    await eventually(async () => (await f.admin.application.query('SELECT attempts FROM app.outbox WHERE workspace_id=$1 AND id=$2', [f.workspaceId, outbox.id])).rows[0]?.attempts === attempt);
    if (attempt < 10) await f.databases.application.query('SELECT graphile_worker.reschedule_jobs(ARRAY[$1::bigint],run_at:=clock_timestamp())', [job.id]);
  }
  const failed = await failedJobs(f.databases.application, { after: String(BigInt(job.id) - 1n), limit: 1 });
  assert.equal(failed.jobs[0]?.state, 'failed'); assert.equal(failed.jobs[0]?.failure, 'JOB_RETRYABLE');
  assert.equal(JSON.stringify(failed).includes('payload'), false);
  assert.equal((await worker.app.inject('/health/queue')).statusCode, 200);
  await delay(1100); assert.equal(failures, 10, 'No eleventh automatic attempt');
  const before = (await f.admin.application.query('SELECT revision FROM app.outbox WHERE workspace_id=$1 AND id=$2', [f.workspaceId, outbox.id])).rows[0];
  await reconcileFailedJobs(f.databases); await reconcileJobFailure(f.databases, job.id);
  assert.deepEqual((await f.admin.application.query('SELECT revision FROM app.outbox WHERE workspace_id=$1 AND id=$2', [f.workspaceId, outbox.id])).rows[0], before, 'Startup failure reconciliation is idempotent');
  assert.equal((await f.context()).graph.tasks.filter(task => task.id === taskId).length, 1, 'Job failures do not replay the business action');
  fail = false;
  assert.deepEqual(await replayJob(f.databases, job.id), { id: job.id, state: 'pending' });
  await eventually(async () => !await current());
  const delivered = (await f.admin.application.query('SELECT state,attempts FROM app.outbox WHERE workspace_id=$1 AND id=$2', [f.workspaceId, outbox.id])).rows[0];
  assert.deepEqual(delivered, { state: 'complete', attempts: 1 });
  await deliverNotificationJob(f.databases, { workspaceId: f.workspaceId, outboxId: outbox.id, dataGeneration: outbox.data_generation });
  assert.deepEqual((await f.admin.application.query('SELECT state,attempts FROM app.outbox WHERE workspace_id=$1 AND id=$2', [f.workspaceId, outbox.id])).rows[0], delivered);
  await assert.rejects(replayJob(f.databases, job.id), /JOB_NOT_REPLAYABLE/);
});

test('CP11 jobs: operator replay rejects obsolete generations, deletion, unknown tasks, and malformed IDs', async t => {
  let f: Awaited<ReturnType<typeof planningFixture>>;
  const keys: string[] = [];
  t.after(async () => { if (f) for (const key of keys) await f.databases.application.query('SELECT graphile_worker.remove_job($1)', [key]); });
  f = await planningFixture(t);
  async function failed(task: string, key: string) {
    keys.push(key);
    const row = (await f.databases.application.query("SELECT id::text FROM graphile_worker.add_job($1,'{}'::json,job_key:=$2,max_attempts:=10,run_at:=clock_timestamp()+interval '1 hour')", [task, key])).rows[0];
    await f.databases.application.query("SELECT graphile_worker.permanently_fail_jobs(ARRAY[$1::bigint],error_message:='JOB_RETRYABLE')", [row.id]);
    return row.id as string;
  }
  const stale = await failed('notification_delivery', `notification:${f.workspaceId}:999:${randomUUID()}`);
  await assert.rejects(replayJob(f.databases, stale), /JOB_OBSOLETE/);
  const deleted = await failed('activation_projection', `activation:${f.workspaceId}`);
  await f.admin.control.query("UPDATE security.workspaces SET lifecycle='pending_deletion',deletion_requested_at=clock_timestamp()-interval '168 hours 1 second',delete_after=clock_timestamp()-interval '1 second' WHERE workspace_id=$1", [f.workspaceId]);
  await assert.rejects(replayJob(f.databases, deleted), /JOB_OBSOLETE/, 'A delayed deletion worker cannot make elapsed work replayable');
  await f.admin.control.query("UPDATE security.workspaces SET lifecycle='deleted',deleted_at=clock_timestamp() WHERE workspace_id=$1", [f.workspaceId]);
  await assert.rejects(replayJob(f.databases, deleted), /JOB_OBSOLETE/);
  const unknown = await failed('unlisted_fixture_task', `fixture:${randomUUID()}`);
  await assert.rejects(replayJob(f.databases, unknown), /JOB_NOT_REPLAYABLE/);
  await assert.rejects(replayJob(f.databases, '1 OR true'));
});

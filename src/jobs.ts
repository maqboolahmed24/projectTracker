import { randomInt } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { Task } from 'graphile-worker';
import type pg from 'pg';
import { z } from 'zod';
import { transaction, type Databases } from './db.js';
import { tenantTransaction } from './persistence.js';
import { identifier, positiveCounter } from './shared/contracts.js';
import { deletionElapsed } from './modules/lifecycle/deadline.js';

export const JOB_MAX_ATTEMPTS = 10;
export const JOB_JITTER_MAX_MS = 1000;
const jobId = z.string().regex(/^[1-9][0-9]{0,18}$/);
const tasks = ['notification_delivery', 'activation_projection', 'request_budget_cleanup'] as const;
const taskName = z.enum(tasks);
const notificationKey = z.tuple([z.literal('notification'), identifier, positiveCounter, identifier]);
const projectionKey = z.tuple([z.literal('activation'), identifier]);

/** Queue errors are stored by Graphile, so sanitise before throwing, not only in the logger. */
export function safeJob(task: Task, options: { random?: () => number; sleep?: (ms: number) => Promise<void> } = {}): Task {
  return async (payload, helpers) => {
    try { await task(payload, helpers); }
    catch {
      // Graphile adds its bounded exp(min(attempt,10)) delay after this failure.
      // A short random delay shifts that persisted retry timestamp without
      // altering private queue tables or keeping a worker occupied for minutes.
      if (helpers.job.attempts < helpers.job.max_attempts) {
        const sample = options.random ? options.random() : randomInt(JOB_JITTER_MAX_MS + 1) / JOB_JITTER_MAX_MS;
        const milliseconds = Math.floor(Math.max(0, Math.min(1, Number.isFinite(sample) ? sample : 0)) * JOB_JITTER_MAX_MS);
        await (options.sleep ?? (async ms => { await delay(ms); }))(milliseconds);
      }
      throw new Error('JOB_RETRYABLE');
    }
  };
}

interface QueueRow { id: string; task_identifier: string; key: string | null; attempts: number; max_attempts: number;
  run_at: Date; created_at: Date; updated_at: Date; locked_at: Date | null; last_error: string | null }
const columns = 'id::text,task_identifier,key,attempts,max_attempts,run_at,created_at,updated_at,locked_at,last_error';
function reference(row: QueueRow) {
  if (row.task_identifier === 'notification_delivery') {
    const key = notificationKey.safeParse(row.key?.split(':'));
    if (key.success) return { workspaceId: key.data[1], generation: key.data[2], outboxId: key.data[3] };
  }
  if (row.task_identifier === 'activation_projection') {
    const key = projectionKey.safeParse(row.key?.split(':'));
    if (key.success) return { workspaceId: key.data[1], generation: undefined, outboxId: undefined };
  }
  return undefined;
}
function publicJob(row: QueueRow) {
  return { id: row.id, task: taskName.parse(row.task_identifier), attempts: row.attempts, maxAttempts: row.max_attempts,
    nextAttemptAt: row.run_at.toISOString(), createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString(),
    state: row.locked_at ? 'running' : row.attempts >= row.max_attempts ? 'failed' : 'pending',
    failure: row.last_error === null ? null : 'JOB_RETRYABLE', ...reference(row) };
}

/** Operational access only: no payloads, content names, raw errors or credentials. */
export async function failedJobs(pool: pg.Pool, options: { after?: string; limit?: number } = {}) {
  const after = options.after === undefined ? '0' : jobId.parse(options.after), limit = z.number().int().min(1).max(100).parse(options.limit ?? 50);
  const rows = (await pool.query<QueueRow>(`SELECT ${columns} FROM graphile_worker.jobs
    WHERE task_identifier=ANY($1::text[]) AND attempts>=max_attempts AND locked_at IS NULL AND id>$2::bigint
    ORDER BY id LIMIT $3`, [tasks, after, limit + 1])).rows;
  const page = rows.slice(0, limit);
  return { jobs: page.map(publicJob), next: rows.length > limit ? page.at(-1)!.id : null };
}

/** Mirror persisted queue failures, including failures whose delivery transaction rolled back. */
export async function reconcileJobFailure(databases: Databases, id: string): Promise<boolean> {
  return transaction(databases.application, async client => {
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.job:'||$1,0))", [jobId.parse(id)]);
    // Re-read after taking the same lock as operator replay. Graphile's updated_at
    // does not change on every failed attempt and cannot order these callbacks.
    const row = (await client.query<QueueRow>(`SELECT ${columns} FROM graphile_worker.jobs WHERE id=$1`, [id])).rows[0];
    if (!row || row.task_identifier !== 'notification_delivery' || row.attempts === 0) return true;
    if (row.locked_at) return false;
    if (!row.last_error) return true;
    const ref = reference(row); if (!ref?.outboxId) return true;
    await client.query("SELECT set_config('ukda.workspace_id',$1,true),set_config('ukda.profile_id','',true)", [ref.workspaceId]);
    await client.query(`UPDATE app.outbox SET attempts=GREATEST(attempts,$4),
      state=CASE WHEN $4>=max_attempts THEN 'failed' ELSE 'pending' END,available_at=$5,
      revision=revision+1,updated_at=clock_timestamp()
      WHERE workspace_id=$1 AND id=$2 AND data_generation=$3 AND notification_version=1 AND state<>'complete'
      AND (attempts<$4 OR state<>CASE WHEN $4>=max_attempts THEN 'failed' ELSE 'pending' END OR available_at<>$5)`,
    [ref.workspaceId, ref.outboxId, ref.generation, row.attempts, row.run_at]);
    return true;
  });
}

/** Startup repair handles a process dying after durable queue failure but before its event callback. */
export async function reconcileFailedJobs(databases: Databases): Promise<void> {
  let after = '0';
  while (true) {
    const rows = (await databases.application.query<{ id: string }>(`SELECT id::text FROM graphile_worker.jobs
      WHERE task_identifier='notification_delivery' AND attempts>0 AND locked_at IS NULL AND id>$1::bigint ORDER BY id LIMIT 100`, [after])).rows;
    for (const row of rows) await reconcileJobFailure(databases, row.id);
    if (rows.length < 100) return; after = rows.at(-1)!.id;
  }
}

/** Keep the original durable job ID/key/payload; the public API skips locked jobs. */
export async function replayJob(databases: Databases, id: string) {
  const selectedId = jobId.parse(id);
  return transaction(databases.application, async client => {
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.job:'||$1,0))", [selectedId]);
  const row = (await client.query<QueueRow>(`SELECT ${columns} FROM graphile_worker.jobs WHERE id=$1`, [selectedId])).rows[0];
  if (!row || !taskName.safeParse(row.task_identifier).success || row.locked_at || row.attempts < row.max_attempts) throw new Error('JOB_NOT_REPLAYABLE');
  const ref = reference(row);
  if (row.task_identifier !== 'request_budget_cleanup') {
    if (!ref) throw new Error('JOB_NOT_REPLAYABLE');
    await client.query("SELECT pg_advisory_xact_lock_shared(hashtextextended('ukda.workspace:'||$1,0))", [ref.workspaceId]);
    const authority = await tenantTransaction(databases.control, ref.workspaceId, undefined, async client =>
      (await client.query<{ lifecycle: string; delete_after: Date | null; data_generation: string }>('SELECT lifecycle,delete_after,data_generation FROM security.workspaces WHERE workspace_id=$1', [ref.workspaceId])).rows[0]);
    if (!authority || deletionElapsed(authority) || ref.generation && ref.generation !== authority.data_generation) throw new Error('JOB_OBSOLETE');
  }
  // Use SQL directly: Graphile 0.18's JS helper treats attempts:0 as omitted.
  const reschedule = async (client: Pick<pg.PoolClient, 'query'>) => {
    const replayed = await client.query<{ id: string }>(`SELECT id::text FROM graphile_worker.reschedule_jobs(
      ARRAY[$1::bigint],run_at:=clock_timestamp(),attempts:=0,max_attempts:=$2)`, [selectedId, JOB_MAX_ATTEMPTS]);
    if (replayed.rows[0]?.id !== selectedId) throw new Error('JOB_NOT_REPLAYABLE');
  };
  if (ref?.outboxId) {
    await client.query("SELECT set_config('ukda.workspace_id',$1,true),set_config('ukda.profile_id','',true)", [ref.workspaceId]);
    await client.query(`UPDATE app.outbox SET state='pending',attempts=0,available_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp()
      WHERE workspace_id=$1 AND id=$2 AND data_generation=$3 AND notification_version=1 AND state='failed'`, [ref.workspaceId, ref.outboxId, ref.generation]);
  }
  await reschedule(client);
  return { id: selectedId, state: 'pending' as const };
  });
}

export async function jobMetrics(pool: pg.Pool) {
  const row = (await pool.query<{ pending: number; failed: number; oldest_pending_seconds: number | null }>(`SELECT
    count(*) FILTER(WHERE locked_at IS NOT NULL OR attempts<max_attempts)::integer AS pending,
    count(*) FILTER(WHERE locked_at IS NULL AND attempts>=max_attempts)::integer AS failed,
    EXTRACT(EPOCH FROM clock_timestamp()-min(created_at) FILTER(WHERE locked_at IS NOT NULL OR attempts<max_attempts))::float8 AS oldest_pending_seconds
    FROM graphile_worker.jobs WHERE task_identifier=ANY($1::text[])`, [tasks])).rows[0]!;
  return { pending: row.pending, failed: row.failed, oldestPendingSeconds: row.oldest_pending_seconds === null ? null : Math.max(0, row.oldest_pending_seconds) };
}

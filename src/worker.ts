import { pathToFileURL } from 'node:url';
import Fastify from 'fastify';
import { Logger, parseCrontab, run, type Task, type Runner } from 'graphile-worker';
import { z } from 'zod';
import { loadConfig, type Config } from './config.js';
import { createDatabases } from './db.js';
import { identifier } from './shared/contracts.js';
import { projectAuthoritativeWorkspace } from './modules/identity/projection.js';
import { pruneRequestBudgets } from './modules/identity/budgets.js';
import { pruneAuthenticationAttempts } from './modules/identity/authentication-cleanup.js';
import { deliverNotificationJob } from './modules/notifications/delivery.js';
import { safeJob, reconcileJobFailure, reconcileFailedJobs, jobMetrics } from './jobs.js';
import { recoveryHealth } from './recovery-health.js';

// Graphile adds this metadata to scheduled jobs before JSON persistence. Manual
// cleanup jobs still use {}, and no other payload fields are accepted.
const cleanupPayload = z.strictObject({
  _cron: z.strictObject({ ts: z.iso.datetime(), backfilled: z.boolean() }).optional(),
});

/** Queue payloads are operational metadata only; this foundation task accepts none. */
export const healthProbe: Task = async (payload, helpers) => {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).length !== 0) {
    throw new Error('health_probe requires an empty payload');
  }
  await helpers.withPgClient(async (client) => { await client.query('SELECT 1'); });
};

/** Never forward Graphile messages/meta: errors can contain SQL, payloads or URLs. */
export function workerLogger(silent = false): Logger {
  return new Logger(() => (level) => {
    if (!silent && (level === 'error' || level === 'warning')) {
      process.stderr.write(`${JSON.stringify({ level, code: 'WORKER_RUNTIME_EVENT' })}\n`);
    }
  });
}

export async function startWorker(config: Config, options: { port?: number;
  /** Test-only fault injection; never accepted in a running development/production service. */
  taskOverrides?: Partial<Record<'notification_delivery' | 'activation_projection', Task>> } = {}) {
  if (options.taskOverrides && config.NODE_ENV !== 'test') throw new Error('Worker test overrides are not enabled');
  const databases = createDatabases(config);
  const pool = databases.application;
  pool.on('connect', (client) => { client.on('error', () => {}); });
  const app = Fastify({ logger: false });
  let runner: Runner | undefined;
  let running = true;
  let lastQueueContact = 0;
  let stopPromise: Promise<void> | undefined;
  const failedIds = new Set<string>();
  let failureUpdate: Promise<void> | undefined, reconciliationTimer: ReturnType<typeof setInterval> | undefined;
  const reconcile = () => {
    if (failureUpdate || !failedIds.size) return failureUpdate ?? Promise.resolve();
    failureUpdate = (async () => {
      for (const id of failedIds) if (await reconcileJobFailure(databases, id)) failedIds.delete(id);
    })().catch(() => { lastQueueContact = 0; }).finally(() => { failureUpdate = undefined; });
    return failureUpdate;
  };

  try {
    // Only bootstrap scripts may perform DDL. An absent/outdated schema fails startup.
    await pool.query('SELECT 1 FROM graphile_worker.jobs LIMIT 0');
    await reconcileFailedJobs(databases);
    runner = await run({
      pgPool: pool,
      schema: 'graphile_worker',
      concurrency: 1,
      pollInterval: 1000,
      noHandleSignals: true,
      logger: workerLogger(config.LOG_LEVEL === 'silent'),
      taskList: {
        health_probe: healthProbe,
        notification_delivery: safeJob(options.taskOverrides?.notification_delivery ?? (async (payload) => { await deliverNotificationJob(databases, payload); })),
        activation_projection: safeJob(options.taskOverrides?.activation_projection ?? (async (payload) => {
          const { workspaceId } = z.object({ workspaceId: identifier }).strict().parse(payload);
          await projectAuthoritativeWorkspace(databases, workspaceId);
        })),
        request_budget_cleanup: safeJob(async (payload) => {
          cleanupPayload.parse(payload);
          await pruneRequestBudgets(databases.control);
          await pruneAuthenticationAttempts(databases.control);
        }),
      },
      parsedCronItems: parseCrontab('*/5 * * * * request_budget_cleanup ?max=10 {}'),
    });
    void runner.promise.then(() => { running = false; }, () => { running = false; });
    runner.events.on('worker:getJob:empty', () => { lastQueueContact = Date.now(); });
    runner.events.on('localQueue:getJobs:complete', () => { lastQueueContact = Date.now(); });
    runner.events.on('job:complete', () => { lastQueueContact = Date.now(); });
    runner.events.on('job:complete', ({ job, error }) => {
      if (!error) return;
      failedIds.add(job.id);
      void reconcile();
    });
    // Graphile 0.18 emits job:complete before its batched failure SQL settles.
    // Poll only those exact IDs still locked; startup repairs a process crash.
    reconciliationTimer = setInterval(() => { void reconcile(); }, 1000);
    reconciliationTimer.unref();
    runner.events.on('worker:getJob:error', () => { lastQueueContact = 0; });
    runner.events.on('worker:fatalError', () => { lastQueueContact = 0; });

    app.addHook('onRequest', async (_request, reply) => {
      reply.header('cache-control', 'no-store');
      reply.header('x-content-type-options', 'nosniff');
    });
    app.get('/health/live', async () => ({ status: 'ok', service: 'ukda-worker' }));
    app.get('/health/queue', async (_request, reply) => {
      try { return { status: 'ok', ...await jobMetrics(pool) }; }
      catch { return reply.code(503).send({ status: 'unavailable' }); }
    });
    app.get('/health/recovery', async (_request, reply) => {
      try {
        const result = await recoveryHealth(databases.control);
        return reply.code(result.status === 'healthy' ? 200 : 503).send(result);
      } catch { return reply.code(503).send({ status: 'unavailable' }); }
    });
    app.get('/health/ready', async (_request, reply) => {
      try {
        if (!running || Date.now() - lastQueueContact > 15_000) throw new Error('Queue polling unavailable');
        await databases.ready();
        return { status: 'ready' };
      } catch {
        return reply.code(503).send({ status: 'unavailable' });
      }
    });
    await app.listen({ host: config.HOST, port: options.port ?? config.PORT });
  } catch {
    clearInterval(reconciliationTimer);
    await app.close();
    await runner?.stop().catch(() => {});
    await failureUpdate;
    await databases.close();
    throw new Error('Worker startup failed; check database access and run worker:migrate before starting');
  }

  const activeRunner = runner;

  const stop = () => {
    stopPromise ??= (async () => {
      running = false;
      clearInterval(reconciliationTimer);
      await app.close();
      // A stopped runner may already have released itself after a fatal queue error.
      await activeRunner.stop().catch(() => {});
      await failureUpdate;
      await reconcile();
      await databases.close();
    })();
    return stopPromise;
  };
  return { app, runner: activeRunner, pool, stop };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const worker = await startWorker(loadConfig({ ...process.env, PORT: process.env.PORT ?? '3401' }));
    let requestedShutdown = false;
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
      process.once(signal, () => {
        requestedShutdown = true;
        void worker.stop().catch(() => { process.exitCode = 1; });
      });
    }
    await worker.runner.promise;
    await worker.stop();
    if (!requestedShutdown) process.exitCode = 1;
  } catch {
    process.stderr.write('Worker startup failed; check configuration and worker migrations\n');
    process.exitCode = 1;
  }
}

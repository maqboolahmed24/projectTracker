import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer, connect, type Socket } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { startWorker } from '../src/worker.js';

async function eventually(check: () => Promise<boolean>, timeout = 10_000): Promise<void> {
  const deadline = Date.now() + timeout;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error('Timed out waiting for worker');
    await delay(50);
  }
}

test('real queue deduplicates pending jobs, executes them as a restricted role, and fails readiness on database outage', {
  timeout: 25_000,
}, async (t) => {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent', HOST: '127.0.0.1' });
  const target = new URL(config.DATABASE_URL);
  const sockets = new Set<Socket>();
  // Cut only this worker's real TCP connections; other development services stay up.
  const proxy = createServer((downstream) => {
    const upstream = connect({ host: target.hostname, port: Number(target.port || 5432) });
    for (const socket of [downstream, upstream]) {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      socket.on('error', () => { downstream.destroy(); upstream.destroy(); });
    }
    downstream.pipe(upstream).pipe(downstream);
  });
  await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  let proxyClosed = false;
  const disconnect = async () => {
    if (proxyClosed) return;
    proxyClosed = true;
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve, reject) => proxy.close((error) => error ? reject(error) : resolve()));
  };
  t.after(disconnect);
  const address = proxy.address();
  assert(address && typeof address !== 'string');
  const proxiedUrl = new URL(target);
  proxiedUrl.hostname = '127.0.0.1';
  proxiedUrl.port = String(address.port);
  const worker = await startWorker({ ...config, DATABASE_URL: proxiedUrl.toString() }, { port: 0 });
  t.after(() => worker.stop());

  await eventually(async () => (await worker.app.inject('/health/ready')).statusCode === 200);
  const role = await worker.pool.query<{ rolsuper: boolean; rolbypassrls: boolean; can_create: boolean }>(`
    SELECT rolsuper, rolbypassrls, has_schema_privilege(current_user, 'graphile_worker', 'CREATE') AS can_create
    FROM pg_roles WHERE rolname = current_user
  `);
  assert.deepEqual(role.rows[0], { rolsuper: false, rolbypassrls: false, can_create: false });

  const jobKey = `foundation-probe-${randomUUID()}`;
  t.after(async () => {
    // Use a direct connection so cleanup also works after the proxy outage.
    const cleanup = new pg.Pool({ connectionString: config.DATABASE_URL, connectionTimeoutMillis: 1500 });
    try {
      await cleanup.query('SELECT graphile_worker.remove_job($1)', [jobKey]);
    } finally {
      await cleanup.end();
    }
  });
  const future = new Date(Date.now() + 60_000);
  const first = await worker.runner.addJob('health_probe', {}, { jobKey, runAt: future, maxAttempts: 1 });
  const retried = await worker.runner.addJob('health_probe', {}, { jobKey, runAt: future, maxAttempts: 1 });
  assert.equal(retried.id, first.id, 'retry before execution must update the existing pending job');
  const ready = await worker.runner.addJob('health_probe', {}, { jobKey, runAt: new Date(), maxAttempts: 1 });
  assert.equal(ready.id, first.id);
  // Any real worker sharing this development queue may claim the probe. Successful
  // completion removes it; failed/exhausted jobs remain visible. Our unique job is
  // never explicitly removed until cleanup, so observe the database, not local events.
  await eventually(async () => {
    const remaining = await worker.pool.query('SELECT id FROM graphile_worker.jobs WHERE id = $1', [first.id]);
    return remaining.rowCount === 0;
  });

  await disconnect();
  await eventually(async () => (await worker.app.inject('/health/ready')).statusCode === 503);
  const response = await worker.app.inject('/health/ready');
  assert.deepEqual(response.json(), { status: 'unavailable' });
  assert.equal((await worker.app.inject('/health/live')).statusCode, 200);
});

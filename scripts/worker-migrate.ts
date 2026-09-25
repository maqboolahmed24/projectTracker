import { pathToFileURL } from 'node:url';
import { runMigrations } from 'graphile-worker';
import pg from 'pg';
import { loadConfig, type Config } from '../src/config.js';
import { workerLogger } from '../src/worker.js';

/** Bootstrap only: https://worker.graphile.org/docs/schema#using-a-postgresql-user-with-restricted-rights */
export async function migrateWorker(config: Config): Promise<void> {
  if (!config.ADMIN_DATABASE_URL) throw new Error('ADMIN_DATABASE_URL is required for worker migrations');
  const adminUrl = new URL(config.ADMIN_DATABASE_URL);
  const runtimeUrl = new URL(config.DATABASE_URL);
  if (adminUrl.host !== runtimeUrl.host || adminUrl.pathname !== runtimeUrl.pathname || adminUrl.username === runtimeUrl.username) {
    throw new Error('Worker migration requires separate admin and runtime roles on the same application database');
  }
  const role = pg.escapeIdentifier(decodeURIComponent(runtimeUrl.username));
  const pool = new pg.Pool({ connectionString: config.ADMIN_DATABASE_URL, connectionTimeoutMillis: 3000, max: 2 });
  pool.on('error', () => {});
  pool.on('connect', (client) => { client.on('error', () => {}); });
  try {
    await runMigrations({ pgPool: pool, schema: 'graphile_worker', logger: workerLogger(config.LOG_LEVEL === 'silent') });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // Graphile executes its private queue implementation as this restricted role.
      // The role owns neither this schema nor its tables and cannot run migrations.
      await client.query(`
        REVOKE ALL ON SCHEMA graphile_worker FROM PUBLIC;
        REVOKE ALL ON ALL TABLES IN SCHEMA graphile_worker FROM PUBLIC;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA graphile_worker FROM PUBLIC;
        REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA graphile_worker FROM PUBLIC;
        GRANT USAGE ON SCHEMA graphile_worker TO ${role};
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA graphile_worker TO ${role};
        GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA graphile_worker TO ${role};
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA graphile_worker TO ${role};
        REVOKE INSERT, UPDATE, DELETE ON graphile_worker.migrations FROM ${role};
      `);
      // Upstream deliberately enables deny-by-default RLS on queue tables because
      // its usual database-owner runner bypasses RLS. Allow only this service role
      // within the isolated queue schema; never grant global BYPASSRLS.
      const protectedTables = await client.query<{ tablename: string }>(`
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'graphile_worker' AND rowsecurity
      `);
      for (const { tablename } of protectedTables.rows) {
        const table = `graphile_worker.${pg.escapeIdentifier(tablename)}`;
        await client.query(`DROP POLICY IF EXISTS ukda_worker_runtime ON ${table}`);
        await client.query(`CREATE POLICY ukda_worker_runtime ON ${table} TO ${role} USING (true) WITH CHECK (true)`);
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await migrateWorker(loadConfig(process.env, { allowAdmin: true }));
    process.stdout.write('Worker schema migrated and runtime permissions granted\n');
  } catch {
    process.stderr.write('Worker migration failed; check admin configuration and database availability\n');
    process.exitCode = 1;
  }
}

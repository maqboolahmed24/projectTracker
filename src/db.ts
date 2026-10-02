import pg from 'pg';
import type { Config } from './config.js';

export interface Databases {
  application: pg.Pool;
  control: pg.Pool;
  ready(): Promise<void>;
  close(): Promise<void>;
}

export function createDatabases(config: Config): Databases {
  const common = { max: 10, connectionTimeoutMillis: 3000, idleTimeoutMillis: 30_000, statement_timeout: 15_000 };
  const application = new pg.Pool({ ...common, connectionString: config.DATABASE_URL, application_name: 'ukda-application' });
  const control = new pg.Pool({ ...common, connectionString: config.CONTROL_DATABASE_URL, application_name: 'ukda-security-control' });
  // Idle-connection errors must not crash the process or print connection strings.
  for (const pool of [application, control]) pool.on('error', () => {});
  return {
    application, control,
    async ready() { await Promise.all([application.query('SELECT 1'), control.query('SELECT 1')]); },
    async close() { await Promise.all([application.end(), control.end()]); },
  };
}

/** All statements in a transaction use the same checked-out connection. */
export async function transaction<T>(pool: pg.Pool, action: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await action(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

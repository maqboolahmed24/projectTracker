import pg from 'pg';
import type { Config } from '../../config.js';
import { transaction } from '../../db.js';
import { AppError } from '../../errors.js';
import { ServiceSecrets } from './secrets.js';

export interface RequestBudget { purpose: string; key: string; limit: number; windowMs: number }

/** Counter transactions may run while an identity transaction owns an authority lock. */
export function createRequestBudgetPool(config: Pick<Config, 'CONTROL_DATABASE_URL'>): pg.Pool {
  const pool = new pg.Pool({ connectionString: config.CONTROL_DATABASE_URL, max: 2,
    connectionTimeoutMillis: 3000, idleTimeoutMillis: 30_000, statement_timeout: 15_000,
    application_name: 'ukda-request-budgets' });
  pool.on('error', () => {});
  return pool;
}

/** Shared, atomic counters. Only keyed digests survive beyond the request. */
export class RequestBudgets {
  constructor(private readonly pool: pg.Pool, private readonly secrets: ServiceSecrets) {}

  async take(budgets: readonly RequestBudget[]): Promise<void> {
    if (!budgets.length || budgets.some((b) => !Number.isInteger(b.limit) || b.limit < 1 || b.limit > 100000 ||
      !Number.isInteger(b.windowMs) || b.windowMs < 1000 || b.windowMs > 86400000 || !b.purpose || !b.key)) {
      throw new Error('Invalid request budget configuration');
    }
    // Deterministic lock order avoids cross-source/account deadlocks.
    const rows = budgets.map((budget) => ({ ...budget, digest: this.secrets.digest(`rate:${budget.purpose}`, budget.key) }))
      .sort((a, b) => Buffer.compare(a.digest, b.digest));
    let exceeded: boolean;
    try {
      exceeded = await transaction(this.pool, async (client) => {
        let limited = false;
        for (const row of rows) {
          const result = await client.query<{ attempts: number }>(`INSERT INTO security.request_budgets
            (bucket_digest,window_started_at,attempts,expires_at)
            VALUES($1,clock_timestamp(),1,clock_timestamp()+($2 * interval '1 millisecond'))
            ON CONFLICT(bucket_digest) DO UPDATE SET
              attempts=CASE WHEN security.request_budgets.expires_at<=clock_timestamp() THEN 1
                ELSE LEAST(security.request_budgets.attempts+1,$3+1) END,
              window_started_at=CASE WHEN security.request_budgets.expires_at<=clock_timestamp() THEN clock_timestamp()
                ELSE security.request_budgets.window_started_at END,
              expires_at=CASE WHEN security.request_budgets.expires_at<=clock_timestamp() THEN clock_timestamp()+($2 * interval '1 millisecond')
                ELSE security.request_budgets.expires_at END RETURNING attempts`, [row.digest, row.windowMs, row.limit]);
          if (result.rows[0]!.attempts > row.limit) limited = true;
        }
        return limited;
      });
    } catch { throw new AppError('SETUP_UNAVAILABLE', 'Setup is temporarily unavailable; retry the same operation', 503); }
    // Throw after commit, so rejected requests cannot roll back their rate counters.
    if (exceeded) throw new AppError('RATE_LIMITED', 'Too many attempts; try again later', 429);
  }
}

/** Hosted cleanup; bounded batches keep request processing independent of retention work. */
export async function pruneRequestBudgets(pool: pg.Pool): Promise<void> {
  await pool.query(`DELETE FROM security.request_budgets WHERE bucket_digest IN
    (SELECT bucket_digest FROM security.request_budgets WHERE expires_at < clock_timestamp()
     ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)`);
}

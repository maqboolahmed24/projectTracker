import type pg from 'pg';

/** Expired attempt IDs have no further authority; a missing ID always fails authentication. */
export async function pruneAuthenticationAttempts(pool: pg.Pool): Promise<number> {
  const result = await pool.query(`DELETE FROM security.auth_attempts WHERE login_id IN
    (SELECT login_id FROM security.auth_attempts WHERE expires_at <= clock_timestamp()
     ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)`);
  return result.rowCount ?? 0;
}

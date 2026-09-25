import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { pruneAuthenticationAttempts } from '../src/modules/identity/authentication-cleanup.js';

test('CP04: hosted cleanup erases expired authentication state and preserves live single-use attempts', async (t) => {
  assert.ok(process.env.CONTROL_DATABASE_URL);
  const pool = new pg.Pool({ connectionString: process.env.CONTROL_DATABASE_URL });
  const workspaceId = randomUUID(), profileId = randomUUID();
  const expiredIssued = randomUUID(), expiredConsumed = randomUUID(), liveIssued = randomUUID(), liveConsumed = randomUUID();
  t.after(async () => {
    await pool.query('DELETE FROM security.auth_attempts WHERE workspace_id=$1', [workspaceId]);
    await pool.end();
  });
  for (const [id, expired, consumed] of [[expiredIssued, true, false], [expiredConsumed, true, true],
    [liveIssued, false, false], [liveConsumed, false, true]] as const) {
    await pool.query(`INSERT INTO security.auth_attempts(login_id,purpose,workspace_id,profile_id,eligible,
      expected_credential_generation,expected_session_generation,expected_data_generation,state,
      server_state_ciphertext,server_state_key_id,outcome,created_at,expires_at,consumed_at)
      VALUES($1,'login',$2,$3,false,0,0,0,$4,$5,$6,$7,
        statement_timestamp()-($8 * interval '1 second'),statement_timestamp()+($9 * interval '1 second'),$10)`,
    [id, workspaceId, profileId, consumed ? 'consumed' : 'issued', consumed ? null : 'synthetic-encrypted-state',
      consumed ? null : 'test', consumed ? 'failed' : null, expired ? 180 : 0, expired ? -60 : 120,
      consumed ? new Date() : null]);
  }
  await pruneAuthenticationAttempts(pool);
  const rows = (await pool.query<{ login_id: string; state: string; server_state_ciphertext: string | null }>(
    'SELECT login_id,state,server_state_ciphertext FROM security.auth_attempts WHERE workspace_id=$1 ORDER BY login_id', [workspaceId])).rows;
  assert.deepEqual(rows.map((r) => r.login_id), [liveIssued, liveConsumed].sort());
  assert.equal(rows.find((r) => r.login_id === liveIssued)?.state, 'issued');
  assert.equal(rows.find((r) => r.login_id === liveIssued)?.server_state_ciphertext, 'synthetic-encrypted-state');
  assert.equal(rows.find((r) => r.login_id === liveConsumed)?.server_state_ciphertext, null);
  // Cleanup does not turn a consumed live proof back into an issued proof.
  await assert.rejects(pool.query("UPDATE security.auth_attempts SET state='issued',outcome=NULL,consumed_at=NULL,server_state_ciphertext='x',server_state_key_id='test' WHERE login_id=$1", [liveConsumed]),
    (error: unknown) => (error as { code?: string }).code === '23514');
});

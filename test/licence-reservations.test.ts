import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test, { type TestContext } from 'node:test';
import { parseEnv } from 'node:util';
import pg from 'pg';
import { AppError } from '../src/errors.js';
import { LicenceReservations, type ActivationStatus } from '../src/modules/identity/licences.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';

const HOUR = 60 * 60 * 1000;
const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;

async function fixture(t: TestContext) {
  const local = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ? undefined :
    parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const adminUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local?.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(adminUrl, 'Licence integration tests require explicit control admin fixture credentials');
  assert.ok(process.env.CONTROL_DATABASE_URL, 'Licence integration tests require CONTROL_DATABASE_URL');
  const pool = new pg.Pool({ connectionString: process.env.CONTROL_DATABASE_URL, max: 6 });
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'cp03-licence-test' });
  let time = new Date();
  const service = new LicenceReservations(pool, secrets, { now: () => new Date(time) });
  const licences: string[] = [];
  t.after(async () => {
    try {
      await admin.query('BEGIN');
      const attempts = await admin.query<{ workspace_id: string }>('SELECT workspace_id FROM security.activation_attempts WHERE licence_id = ANY($1::uuid[])', [licences]);
      for (const row of attempts.rows) {
        await admin.query("SELECT set_config('ukda.workspace_id', $1, true)", [row.workspace_id]);
        await admin.query('DELETE FROM security.workspaces WHERE workspace_id = $1', [row.workspace_id]);
      }
      await admin.query('DELETE FROM security.activation_attempts WHERE licence_id = ANY($1::uuid[])', [licences]);
      await admin.query('DELETE FROM security.licences WHERE licence_id = ANY($1::uuid[])', [licences]);
      await admin.query('COMMIT');
    } catch (error) {
      await admin.query('ROLLBACK');
      throw error;
    } finally { await Promise.allSettled([pool.end(), admin.end()]); }
  });
  const issue = async () => {
    const issued = await service.issueLicence(); licences.push(issued.licenceId); return issued;
  };
  return { service, secrets, pool, admin, issue,
    advance: (milliseconds: number) => { time = new Date(time.getTime() + milliseconds); } };
}

test('CP03: concurrent lost-response retries reserve once and require the original resume token', async (t) => {
  const { service, secrets, admin, issue } = await fixture(t);
  const issued = await issue();
  const input = { licenceKey: issued.licenceKey, operationId: randomUUID(), resumeToken: secrets.token() };
  const results = await Promise.all([service.reserve(input), service.reserve(input)]);
  assert.deepEqual(results[0], results[1]);
  const result = results[0]!;
  assert.equal(result.reservationGeneration, '1');
  assert.equal(result.draftGeneration, '1');
  assert.equal(new Date(result.resumeExpiresAt).getTime(), new Date(result.expiresAt).getTime());
  assert.deepEqual(await service.status(result.activationId, input.resumeToken), result);
  await assert.rejects(service.reserve({ ...input, resumeToken: secrets.token() }), code('ACTIVATION_INVALID'));
  await assert.rejects(service.status(result.activationId, secrets.token()), code('ACTIVATION_INVALID'));
  await assert.rejects(service.reserve({ ...input, operationId: randomUUID(), resumeToken: secrets.token() }), code('LICENCE_UNAVAILABLE'));
  const stored = (await admin.query('SELECT verification_digest, verification_key_id FROM security.licences WHERE licence_id = $1', [issued.licenceId])).rows[0];
  assert.ok(Buffer.isBuffer(stored.verification_digest));
  assert.equal(stored.verification_digest.length, 32);
  assert.equal(secrets.matches('licence', issued.licenceKey, stored.verification_digest), true);
  const attempt = (await admin.query('SELECT resume_digest, staged_public_state FROM security.activation_attempts WHERE activation_id = $1', [result.activationId])).rows[0];
  assert.equal(secrets.matches('activation-resume', input.resumeToken, attempt.resume_digest), true);
  for (const secret of [issued.licenceKey, input.resumeToken]) {
    assert.equal(JSON.stringify(result).includes(secret), false);
    assert.equal(JSON.stringify(attempt.staged_public_state).includes(secret), false);
  }
});

test('CP03: competing reservation operations cannot take over a licence claim', async (t) => {
  const { service, secrets, issue } = await fixture(t);
  const { licenceKey } = await issue();
  const outcomes = await Promise.allSettled([1, 2].map(() => service.reserve({ licenceKey, operationId: randomUUID(), resumeToken: secrets.token() })));
  assert.equal(outcomes.filter((result) => result.status === 'fulfilled').length, 1);
  const rejected = outcomes.find((result) => result.status === 'rejected');
  assert.ok(rejected?.status === 'rejected' && code('LICENCE_UNAVAILABLE')(rejected.reason));
  for (const invalid of ['LIC-short', `LIC-${secrets.token()}=`, `LIC-${secrets.token()}`]) {
    await assert.rejects(service.reserve({ licenceKey: invalid, operationId: randomUUID(), resumeToken: secrets.token() }), code('LICENCE_UNAVAILABLE'));
  }
});

test('CP03: an expired unused claim restarts with a fresh workspace and invalidates the old generation', async (t) => {
  const { service, secrets, admin, issue, advance } = await fixture(t);
  const issued = await issue();
  const input = { licenceKey: issued.licenceKey, operationId: randomUUID(), resumeToken: secrets.token() };
  const first = await service.reserve(input);
  await service.withAttempt(first.activationId, input.resumeToken, async (client, row) => {
    await client.query(`INSERT INTO security.staged_objects
      (workspace_id, object_id, object_kind, object_hash, versioned_object, staged_operation_id)
      VALUES ($1, $2, 'encrypted_workspace', repeat('a',64), '{}', $3)`, [row.workspace_id, randomUUID(), randomUUID()]);
    await client.query("UPDATE security.activation_attempts SET staged_registration_record = 'AA' WHERE activation_id = $1", [row.activation_id]);
  });
  advance(HOUR);
  await assert.rejects(service.status(first.activationId, input.resumeToken), code('ACTIVATION_EXPIRED'));
  await assert.rejects(service.reserve(input), code('ACTIVATION_EXPIRED'));
  const replacementInput = { ...input, operationId: randomUUID(), resumeToken: secrets.token() };
  const replacement = await service.reserve(replacementInput);
  assert.equal(replacement.reservationGeneration, '2');
  assert.notEqual(replacement.workspaceId, first.workspaceId);
  assert.notEqual(replacement.accountId, first.accountId);
  assert.equal((await admin.query('SELECT * FROM security.workspaces WHERE workspace_id = $1', [first.workspaceId])).rowCount, 0);
  assert.equal((await admin.query('SELECT * FROM security.staged_objects WHERE workspace_id = $1', [first.workspaceId])).rowCount, 0);
  assert.deepEqual((await admin.query('SELECT state, staged_registration_record FROM security.activation_attempts WHERE activation_id = $1', [first.activationId])).rows[0],
    { state: 'expired', staged_registration_record: null });
  await assert.rejects(service.status(first.activationId, input.resumeToken), code('ACTIVATION_INVALID'));
  await admin.query("UPDATE security.licences SET state = 'revoked' WHERE licence_id = $1", [issued.licenceId]);
  await assert.rejects(service.status(replacement.activationId, replacementInput.resumeToken), code('ACTIVATION_INVALID'));
});

test('CP03: draft replacement races serialize and retries never erase a newer staged draft', async (t) => {
  const { service, secrets, issue } = await fixture(t);
  const { licenceKey } = await issue();
  const resumeToken = secrets.token();
  const first = await service.reserve({ licenceKey, operationId: randomUUID(), resumeToken });
  async function stage() {
    await service.withAttempt(first.activationId, resumeToken, async (client, row, now) => {
      await client.query(`INSERT INTO security.staged_objects
        (workspace_id, object_id, object_kind, object_hash, versioned_object, staged_operation_id)
        VALUES ($1, $2, 'encrypted_workspace', repeat('a',64), '{}', $3)`, [row.workspace_id, randomUUID(), randomUUID()]);
      await client.query(`UPDATE security.activation_attempts SET staged_payload_hash = repeat('b',64), staged_registration_record = 'AA',
        proof_id = $2, proof_server_state = 'synthetic-protected-state', proof_expires_at = $3,
        proof_verified_at = $4 WHERE activation_id = $1`, [row.activation_id, randomUUID(), new Date(now.getTime() + 1000), now]);
    });
  }
  await stage();
  const operations = [randomUUID(), randomUUID()];
  const outcomes = await Promise.allSettled(operations.map((operationId) => service.replaceDraft(first.activationId, resumeToken, { expectedDraftGeneration: '1', operationId })));
  assert.equal(outcomes.filter((result) => result.status === 'fulfilled').length, 1);
  const winnerIndex = outcomes.findIndex((result) => result.status === 'fulfilled');
  const winningOperation = operations[winnerIndex]!;
  const rejected = outcomes.find((result) => result.status === 'rejected');
  assert.ok(rejected?.status === 'rejected' && code('DRAFT_CONFLICT')(rejected.reason));
  const replaced = await service.status(first.activationId, resumeToken);
  assert.equal(replaced.draftGeneration, '2');
  assert.equal(replaced.accountId, first.accountId);
  await service.withAttempt(first.activationId, resumeToken, async (client, row) => {
    for (const property of ['staged_payload_hash', 'staged_registration_record', 'proof_id', 'proof_server_state', 'proof_expires_at', 'proof_verified_at'] as const) assert.equal(row[property], null);
    assert.equal((await client.query('SELECT * FROM security.staged_objects WHERE workspace_id = $1', [row.workspace_id])).rowCount, 0);
  });
  await stage();
  assert.equal((await service.replaceDraft(first.activationId, resumeToken, { expectedDraftGeneration: '1', operationId: winningOperation })).draftGeneration, '2');
  await service.withAttempt(first.activationId, resumeToken, async (client, row) => {
    assert.equal((await client.query('SELECT * FROM security.staged_objects WHERE workspace_id = $1', [row.workspace_id])).rowCount, 1);
    assert.notEqual(row.proof_id, null);
  });
  assert.equal((await service.replaceDraft(first.activationId, resumeToken, { expectedDraftGeneration: '2', operationId: randomUUID() })).draftGeneration, '3');
  assert.equal((await service.replaceDraft(first.activationId, resumeToken, { expectedDraftGeneration: '1', operationId: winningOperation })).draftGeneration, '2');
  assert.equal((await service.status(first.activationId, resumeToken)).draftGeneration, '3');
  await assert.rejects(service.replaceDraft(first.activationId, resumeToken, { expectedDraftGeneration: '2', operationId: winningOperation }), code('OPERATION_CONFLICT'));
});

test('CP03: completion receipts recover a lost response for 24 hours without redeeming the consumed licence', async (t) => {
  const { service, secrets, admin, issue, advance } = await fixture(t);
  const { licenceKey, licenceId } = await issue();
  const input = { licenceKey, operationId: randomUUID(), resumeToken: secrets.token() };
  const reserved = await service.reserve(input);
  // This is a minimal lifecycle fixture for receipt retention, not cryptographic activation.
  const receipt = { workspaceId: reserved.workspaceId, accountId: reserved.accountId };
  await service.withAttempt(reserved.activationId, input.resumeToken, async (client, row, now) => {
    await client.query("UPDATE security.workspaces SET lifecycle = 'active', activated_at = $2 WHERE workspace_id = $1", [row.workspace_id, now]);
    await client.query(`UPDATE security.licences SET state = 'activated', activated_workspace_id = $2,
      activated_at = $3 WHERE licence_id = $1`, [row.licence_id, row.workspace_id, now]);
    await client.query(`UPDATE security.activation_attempts SET state = 'completed', completed_at = $2,
      request_hash = repeat('c',64), completion_receipt = $3, resume_expires_at = $4
      WHERE activation_id = $1`, [row.activation_id, now, receipt, new Date(now.getTime() + 24 * HOUR)]);
  });
  const completed: ActivationStatus = await service.status(reserved.activationId, input.resumeToken);
  assert.equal(completed.state, 'completed');
  assert.deepEqual(completed.receipt, receipt);
  assert.deepEqual(await service.reserve(input), completed);
  await assert.rejects(service.withAttempt(reserved.activationId, input.resumeToken, async () => {}), code('ACTIVATION_INVALID'));
  await assert.rejects(service.reserve({ ...input, operationId: randomUUID(), resumeToken: secrets.token() }), code('LICENCE_UNAVAILABLE'));
  for (const restrictedState of ['revoked', 'legacy_expired']) {
    await admin.query('UPDATE security.licences SET state = $2 WHERE licence_id = $1', [licenceId, restrictedState]);
    assert.deepEqual(await service.status(reserved.activationId, input.resumeToken), completed);
    assert.deepEqual(await service.reserve(input), completed);
    await assert.rejects(service.reserve({ ...input, operationId: randomUUID(), resumeToken: secrets.token() }), code('LICENCE_UNAVAILABLE'));
  }
  advance(24 * HOUR);
  await assert.rejects(service.status(reserved.activationId, input.resumeToken), code('ACTIVATION_EXPIRED'));
  await assert.rejects(service.reserve({ ...input, operationId: randomUUID(), resumeToken: secrets.token() }), code('LICENCE_UNAVAILABLE'));
});

test('CP03: withAttempt rolls back failed callbacks and supplies only its current tenant context', async (t) => {
  const { service, secrets, issue } = await fixture(t);
  const { licenceKey } = await issue();
  const resumeToken = secrets.token();
  const reserved = await service.reserve({ licenceKey, operationId: randomUUID(), resumeToken });
  await assert.rejects(service.withAttempt(reserved.activationId, resumeToken, async (client, row) => {
    assert.equal((await client.query("SELECT current_setting('ukda.workspace_id') AS workspace")).rows[0]?.workspace, row.workspace_id);
    await client.query('UPDATE security.activation_attempts SET proof_id = $2 WHERE activation_id = $1', [row.activation_id, randomUUID()]);
    throw new AppError('FIXTURE_FAILURE', 'Synthetic failure', 409);
  }), code('FIXTURE_FAILURE'));
  await service.withAttempt(reserved.activationId, resumeToken, async (_client, row) => { assert.equal(row.proof_id, null); });
});

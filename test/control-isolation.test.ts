import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test, { type TestContext } from 'node:test';
import { parseEnv } from 'node:util';
import pg from 'pg';

const tenantTables = ['workspaces', 'staged_objects', 'profiles', 'devices', 'recovery_authorities',
  'grants', 'ceremonies', 'sessions', 'security_transitions', 'operation_receipts', 'deletion_tombstones'] as const;

function identifiers() {
  return { workspace: randomUUID(), licence: randomUUID(), profile: randomUUID(), device: randomUUID(),
    object: randomUUID(), operation: randomUUID(), grant: randomUUID(), ceremony: randomUUID(),
    session: randomUUID(), tombstone: randomUUID() };
}

async function context(client: pg.Client, workspace: string) {
  await client.query("SELECT set_config('ukda.workspace_id', $1, true)", [workspace]);
}

async function expectSqlFailure(client: pg.Client, code: string, sql: string, values: unknown[] = []) {
  await client.query('SAVEPOINT expected_failure');
  try {
    await assert.rejects(client.query(sql, values), (error: unknown) => (error as { code?: string }).code === code);
  } finally {
    await client.query('ROLLBACK TO SAVEPOINT expected_failure');
    await client.query('RELEASE SAVEPOINT expected_failure');
  }
}

async function fixture(t: TestContext) {
  const localAdmin = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ? undefined :
    parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const adminUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? localAdmin?.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(adminUrl, 'Control isolation tests require explicit control admin fixture credentials');
  assert.ok(process.env.CONTROL_DATABASE_URL, 'Control isolation tests require CONTROL_DATABASE_URL');
  const admin = new pg.Client({ connectionString: adminUrl });
  const runtime = new pg.Client({ connectionString: process.env.CONTROL_DATABASE_URL });
  await Promise.all([admin.connect(), runtime.connect()]);
  t.after(async () => {
    // Fixtures never commit: even immutable deletion tombstones disappear by rollback.
    // No production rows, shared schemas, or trigger definitions are changed.
    await runtime.query('ROLLBACK').catch(() => {});
    await Promise.allSettled([runtime.end(), admin.end()]);
  });
  await runtime.query('BEGIN');
  const workspaces = [identifiers(), identifiers()] as const;
  for (const ids of workspaces) {
    await context(runtime, ids.workspace);
    await runtime.query(`INSERT INTO security.licences
      (licence_id, verification_digest, verification_key_id) VALUES ($1, $2, 'cp02-test')`,
    [ids.licence, randomBytes(32)]);
    await runtime.query(`INSERT INTO security.workspaces
      (workspace_id, licence_id, lifecycle, activated_at, security_head, security_version,
       data_generation, ownership_version, custody_epoch, write_schema)
      VALUES ($1, $2, 'active', now(), repeat('a', 64), 1, 2, 2, 2, 2)`, [ids.workspace, ids.licence]);
    await runtime.query(`INSERT INTO security.security_transitions
      (workspace_id, sequence, operation_id, previous_head, head, action, actor_kind, signed_transition)
      VALUES ($1, 1, $2, repeat('0', 64), repeat('a', 64), 'test_fixture', 'service', $3)`,
    [ids.workspace, ids.operation, { version: 1, signature: randomBytes(64).toString('base64url') }]);
    await runtime.query(`INSERT INTO security.staged_objects
      (workspace_id, object_id, object_kind, object_hash, versioned_object, staged_operation_id,
       state, committed_security_version)
      VALUES ($1, $2, 'signed_grant', repeat('b', 64), $3, $4, 'committed', 1)`,
    [ids.workspace, ids.object, { version: 1, ciphertext: randomBytes(32).toString('base64url') }, ids.operation]);
    await runtime.query(`INSERT INTO security.profiles
      (workspace_id, profile_id, state, is_owner, owner_ready_at, credential_generation,
       session_generation, invitation_generation, reset_generation, recovery_generation,
       opaque_registration_record, opaque_setup_id, opaque_config_id, opaque_identifiers)
      VALUES ($1, $2, 'active', true, now(), 2, 2, 2, 2, 2, $3, 'cp02-test', 'cp02-test', '{}')`,
    [ids.workspace, ids.profile, randomBytes(64).toString('base64url')]);
    await runtime.query(`INSERT INTO security.devices
      (workspace_id, device_id, profile_id, key_generation, signing_public_key, recipient_public_key,
       state, approval_security_version, approved_at)
      VALUES ($1, $2, $3, 1, $4, $5, 'active', 1, now())`,
    [ids.workspace, ids.device, ids.profile, randomBytes(32), randomBytes(32)]);
    await runtime.query(`INSERT INTO security.recovery_authorities
      (workspace_id, profile_id, generation, proof_public_key, recipient_public_key,
       custody_envelope_object_id, custody_epoch, kit_verified_at)
      VALUES ($1, $2, 1, $3, $4, $5, 2, now())`,
    [ids.workspace, ids.profile, randomBytes(32), randomBytes(32), ids.object]);
    await runtime.query(`INSERT INTO security.grants
      (workspace_id, grant_id, profile_id, device_id, grant_kind, scope_kind, generation,
       state, signed_grant_object_id, security_version, activated_at)
      VALUES ($1, $2, $3, $4, 'device', 'workspace', 1, 'active', $5, 1, now())`,
    [ids.workspace, ids.grant, ids.profile, ids.device, ids.object]);
    await runtime.query(`INSERT INTO security.ceremonies
      (workspace_id, ceremony_id, profile_id, device_id, kind, generation,
       expected_credential_generation, expected_ownership_version, expected_security_version,
       expected_custody_epoch, expires_at)
      VALUES ($1, $2, $3, $4, 'device_challenge', 1, 2, 2, 1, 2, now() + interval '1 hour')`,
    [ids.workspace, ids.ceremony, ids.profile, ids.device]);
    await runtime.query(`INSERT INTO security.sessions
      (workspace_id, session_id, profile_id, device_id, token_digest, token_key_id, csrf_digest,
       access_level, credential_generation, session_generation, data_generation,
       authenticated_at, idle_expires_at, absolute_expires_at)
      VALUES ($1, $2, $3, $4, $5, 'cp02-test', $6, 'device_approved', 2, 2, 2,
        now(), now() + interval '30 minutes', now() + interval '1 hour')`,
    [ids.workspace, ids.session, ids.profile, ids.device, randomBytes(32), randomBytes(32)]);
    await runtime.query(`INSERT INTO security.operation_receipts
      (workspace_id, operation_id, request_hash, operation_kind, security_version, outcome)
      VALUES ($1, $2, repeat('c', 64), 'test_fixture', 1, '{}')`, [ids.workspace, ids.operation]);
    await runtime.query(`INSERT INTO security.deletion_tombstones
      (workspace_id, entity_kind, entity_id, deleted_at, security_version)
      VALUES ($1, 'profile', $2, now(), 1)`, [ids.workspace, ids.tombstone]);
  }
  await runtime.query('SET CONSTRAINTS ALL IMMEDIATE');
  return { admin, runtime, first: workspaces[0], second: workspaces[1] };
}

test('CP02: every security tenant table forces isolation and absent context denies access', async (t) => {
  const { admin, runtime, first, second } = await fixture(t);
  const protectedTables = await admin.query<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean }>(`
    SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'security' AND c.relname = ANY($1::text[]) ORDER BY c.relname
  `, [tenantTables]);
  assert.equal(protectedTables.rows.length, tenantTables.length);
  for (const row of protectedTables.rows) {
    assert.equal(row.relrowsecurity, true, `${row.relname} must enable RLS`);
    assert.equal(row.relforcerowsecurity, true, `${row.relname} must force RLS`);
  }
  for (const own of [first, second]) {
    await context(runtime, own.workspace);
    const other = own === first ? second : first;
    for (const name of tenantTables) {
      const table = `security.${pg.escapeIdentifier(name)}`;
      const rows = await runtime.query<{ workspace_id: string }>(`SELECT workspace_id FROM ${table} WHERE workspace_id = ANY($1::uuid[])`, [[first.workspace, second.workspace]]);
      assert.deepEqual(rows.rows.map((row) => row.workspace_id), [own.workspace], `${name} must expose only its tenant`);
      assert.equal((await runtime.query(`DELETE FROM ${table} WHERE workspace_id = $1`, [other.workspace])).rowCount, 0);
    }
  }
  await context(runtime, '');
  for (const name of tenantTables) {
    assert.equal((await runtime.query(`SELECT * FROM security.${pg.escapeIdentifier(name)}`)).rowCount, 0, `${name} without context`);
  }
  await expectSqlFailure(runtime, '42501', 'INSERT INTO security.profiles (workspace_id, profile_id) VALUES ($1, $2)', [first.workspace, randomUUID()]);
  await context(runtime, first.workspace);
  await expectSqlFailure(runtime, '42501', 'INSERT INTO security.profiles (workspace_id, profile_id) VALUES ($1, $2)', [second.workspace, randomUUID()]);
  // Transaction-local context clears at a transaction boundary, including pooled reuse.
  await runtime.query('ROLLBACK');
  assert.equal((await runtime.query("SELECT nullif(current_setting('ukda.workspace_id', true), '') AS workspace")).rows[0]?.workspace, null);
});

test('CP02: security device, profile, and object relationships cannot cross workspace boundaries', async (t) => {
  const { runtime, first, second } = await fixture(t);
  await context(runtime, first.workspace);
  await expectSqlFailure(runtime, '23503', `INSERT INTO security.devices
    (workspace_id, device_id, profile_id, key_generation, signing_public_key, recipient_public_key)
    VALUES ($1, $2, $3, 1, $4, $5)`, [first.workspace, randomUUID(), second.profile, randomBytes(32), randomBytes(32)]);
  await expectSqlFailure(runtime, '23503', `INSERT INTO security.grants
    (workspace_id, grant_id, profile_id, device_id, grant_kind, scope_kind, generation, signed_grant_object_id)
    VALUES ($1, $2, $3, $4, 'device', 'workspace', 1, $5)`,
  [first.workspace, randomUUID(), first.profile, second.device, first.object]);
  await expectSqlFailure(runtime, '23503', `UPDATE security.profiles SET profile_object_id = $1
    WHERE workspace_id = $2 AND profile_id = $3`, [second.object, first.workspace, first.profile]);
  await expectSqlFailure(runtime, '23514', `INSERT INTO security.profiles
    (workspace_id, profile_id, state) VALUES ($1, $2, 'active')`, [first.workspace, randomUUID()]);
  await expectSqlFailure(runtime, '23514', `INSERT INTO security.profiles
    (workspace_id, profile_id, credential_generation, opaque_registration_record, opaque_config_id, opaque_identifiers)
    VALUES ($1, $2, 1, 'AA', 'cp02-test', '{}')`, [first.workspace, randomUUID()]);
});

test('CP02: authority generations and signed security records cannot be rewritten or regressed', async (t) => {
  const { runtime, first } = await fixture(t);
  await context(runtime, first.workspace);
  for (const column of ['data_generation', 'ownership_version', 'custody_epoch', 'write_schema']) {
    await expectSqlFailure(runtime, '23514', `UPDATE security.workspaces SET ${pg.escapeIdentifier(column)} = 1 WHERE workspace_id = $1`, [first.workspace]);
  }
  await expectSqlFailure(runtime, '23514', "UPDATE security.workspaces SET security_head = repeat('d', 64) WHERE workspace_id = $1", [first.workspace]);
  await runtime.query("UPDATE security.workspaces SET security_version = 2, security_head = repeat('d', 64) WHERE workspace_id = $1", [first.workspace]);
  await expectSqlFailure(runtime, '23514', "UPDATE security.workspaces SET security_version = 1, security_head = repeat('a', 64) WHERE workspace_id = $1", [first.workspace]);
  for (const column of ['credential_generation', 'session_generation', 'invitation_generation', 'reset_generation', 'recovery_generation']) {
    await expectSqlFailure(runtime, '23514', `UPDATE security.profiles SET ${pg.escapeIdentifier(column)} = 1 WHERE workspace_id = $1`, [first.workspace]);
  }
  for (const sql of [
    "UPDATE security.staged_objects SET versioned_object = '{}' WHERE workspace_id = $1",
    "UPDATE security.staged_objects SET object_hash = repeat('e', 64) WHERE workspace_id = $1",
    "UPDATE security.staged_objects SET state = 'staged' WHERE workspace_id = $1",
    "UPDATE security.security_transitions SET signed_transition = '{}' WHERE workspace_id = $1",
    "UPDATE security.operation_receipts SET outcome = '{\"changed\":true}' WHERE workspace_id = $1",
    'DELETE FROM security.deletion_tombstones WHERE workspace_id = $1',
    'UPDATE security.recovery_authorities SET custody_epoch = 1 WHERE workspace_id = $1',
  ]) await expectSqlFailure(runtime, '23514', sql, [first.workspace]);
  await expectSqlFailure(runtime, '23514', 'UPDATE security.devices SET signing_public_key = $2 WHERE workspace_id = $1', [first.workspace, randomBytes(32)]);
});

test('CP02: control runtime cannot own schema, bypass RLS, or perform DDL', async (t) => {
  const { runtime } = await fixture(t);
  const identity = (await runtime.query(`
    SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls,
      has_schema_privilege(current_user, 'security', 'CREATE') AS can_create,
      has_schema_privilege(current_user, 'ukda_migrations', 'USAGE') AS can_read_ledger,
      EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'security' AND c.relowner = current_user::regrole) AS owns_tables
    FROM pg_roles WHERE rolname = current_user
  `)).rows[0];
  assert.ok(identity);
  for (const [property, value] of Object.entries(identity)) assert.equal(value, false, property);
  await expectSqlFailure(runtime, '42501', 'CREATE TABLE security.cp02_forbidden (id integer)');
  await expectSqlFailure(runtime, '42501', 'ALTER TABLE security.workspaces DISABLE ROW LEVEL SECURITY');
  await expectSqlFailure(runtime, '42501', 'TRUNCATE security.workspaces CASCADE');
});

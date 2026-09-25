import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import pg from 'pg';
import * as opaqueLibrary from '@serenity-kit/opaque';
import { loadConfig } from '../src/config.js';
import { createDatabases, transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { dataTransaction, tenantTransaction } from '../src/persistence.js';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { startRegistration, finishRegistration, startLogin, finishLogin } from '../src/client/opaque.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { ActivationService } from '../src/modules/identity/activation.js';
import { LicenceReservations } from '../src/modules/identity/licences.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { EntitlementOperations, entitlementAllows, assertEntitlementAllows, entitlementPolicyActions, entitlementTransitionBody } from '../src/modules/identity/entitlements.js';
import { projectAuthoritativeWorkspace, withSecurityFence } from '../src/modules/identity/projection.js';
import { base64urlDecode, digestObject, verifyObject } from '../src/shared/crypto.js';

const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;

async function fixture(t: TestContext) {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const applicationUrl = process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ?? local.ADMIN_DATABASE_URL;
  const controlUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(applicationUrl && controlUrl, 'Entitlement integration tests require explicit fixture admin credentials');
  const db = createDatabases(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }));
  const admin = { application: new pg.Pool({ connectionString: applicationUrl }), control: new pg.Pool({ connectionString: controlUrl }) };
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'cp03-entitlements' });
  const reservations = new LicenceReservations(db.control, secrets), operations = new EntitlementOperations(db, secrets);
  const operator = { operatorId: randomUUID() };
  const licences: string[] = [];
  t.after(async () => {
    try {
      const workspaces = (await admin.control.query<{ workspace_id: string }>(`SELECT workspace_id FROM security.activation_attempts WHERE licence_id=ANY($1::uuid[])
        UNION SELECT activated_workspace_id AS workspace_id FROM security.licences WHERE licence_id=ANY($1::uuid[]) AND activated_workspace_id IS NOT NULL`, [licences])).rows;
      for (const { workspace_id } of workspaces) {
        await db.application.query('SELECT graphile_worker.remove_job($1)', [`activation:${workspace_id}`]);
        await transaction(admin.application, async (client) => {
          await client.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.workspace:'||$1,0))", [workspace_id]);
          for (const table of ['profiles', 'roles', 'workspaces']) await client.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [workspace_id]);
        });
      }
      await transaction(admin.control, async (client) => {
        await client.query('DELETE FROM security.entitlement_operations WHERE licence_id=ANY($1::uuid[])', [licences]);
        for (const { workspace_id } of workspaces) await client.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspace_id]);
        await client.query('DELETE FROM security.activation_attempts WHERE licence_id=ANY($1::uuid[])', [licences]);
        await client.query('DELETE FROM security.licences WHERE licence_id=ANY($1::uuid[])', [licences]);
      });
    } finally { await Promise.allSettled([db.close(), admin.application.end(), admin.control.end()]); }
  });
  const issue = async () => { const result = await reservations.issueLicence(); licences.push(result.licenceId); return result; };
  const activate = async () => {
    await opaqueLibrary.ready;
    const opaque = new OpaqueService({ serverSetup: opaqueLibrary.server.createSetup(), setupId: 'entitlement-fixture', serverIdentity: 'ukda:entitlement-fixture' });
    const service = new ActivationService({ databases: db, secrets, opaque, origin: 'http://localhost:3400' });
    const issued = await issue(), resumeToken = secrets.token();
    const reserved = await reservations.reserve({ licenceKey: issued.licenceKey, operationId: randomUUID(), resumeToken });
    const password = 'Private entitlement fixture passphrase 8271';
    const registration = await startRegistration(password);
    const response = await service.registration(reserved.activationId, resumeToken, { draftGeneration: '1', registrationRequest: registration.registrationRequest });
    const registered = await finishRegistration({ password, clientRegistrationState: registration.clientRegistrationState, registrationResponse: response.registrationResponse, configuration: response.configuration });
    const phrase = await newOwnerPhrase(), positions = [1, 8, 20];
    const prepared = await prepareOwnerActivation({ binding: { activationId: reserved.activationId, operationId: reserved.operationId,
      workspaceId: reserved.workspaceId, accountId: reserved.accountId, reservationGeneration: reserved.reservationGeneration,
      draftGeneration: '1', origin: 'http://localhost:3400' }, configuration: response.configuration,
      registrationRecord: registered.registrationRecord, exportKey: registered.exportKey, phrase,
      challengePositions: positions, challengeAnswers: positions.map((position) => phrase.split(' ')[position]!),
      displayName: 'Private entitlement owner', workspaceName: 'Private entitlement workspace' });
    const login = await startLogin(password);
    const proof = await service.startProof(reserved.activationId, resumeToken, { draftGeneration: '1', payload: prepared.payload, startLoginRequest: login.startLoginRequest });
    const finished = await finishLogin({ password, clientLoginState: login.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
    await service.finishProof(reserved.activationId, resumeToken, { draftGeneration: '1', proofId: proof.proofId, finishLoginRequest: finished.finishLoginRequest });
    assert.equal((await service.finalize(reserved.activationId, resumeToken, { draftGeneration: '1', requestHash: proof.requestHash })).state, 'completed');
    return { issued, reserved, phrase, password, prepared };
  };
  return { db, admin, secrets, reservations, operations, operator, issue, activate };
}

test('CP03: licence policy allows preservation/recovery actions and denies new writes or expanded access', () => {
  const permitted = ['authenticate', 'replace_device_existing_scopes', 'read', 'recover', 'change_password', 'revoke_access', 'export', 'request_deletion', 'cancel_deletion'];
  for (const action of entitlementPolicyActions) {
    assert.equal(entitlementAllows('active', action), true);
    for (const state of ['restricted', 'revoked']) {
      assert.equal(entitlementAllows(state, action), permitted.includes(action));
      if (permitted.includes(action)) assert.doesNotThrow(() => assertEntitlementAllows(state, action));
      else assert.throws(() => assertEntitlementAllows(state, action), code('WORKSPACE_RESTRICTED'));
    }
  }
  assert.equal(entitlementAllows('unknown', 'read'), false);
  assert.equal(entitlementAllows('active', 'mint_owner'), false);
});

test('CP03: unused entitlement restrictions are durable, signed and idempotent, and invalidate reserved setup', async (t) => {
  const f = await fixture(t), issued = await f.issue();
  const revoke = { licenceId: issued.licenceId, operationId: randomUUID(), action: 'revoke' as const };
  const results = await Promise.all([f.operations.change(revoke, f.operator), f.operations.change(revoke, f.operator)]);
  assert.deepEqual(results[0], results[1]);
  assert.equal(results[0]?.receipt.entitlementState, 'revoked');
  assert.equal(results[0]?.projection, null);
  assert.equal((await f.admin.control.query('SELECT count(*) FROM security.entitlement_operations WHERE licence_id=$1', [issued.licenceId])).rows[0]?.count, '1');
  assert.equal(await verifyObject(results[0]!.receipt.transition, base64urlDecode(await f.operations.publicSigningKey()), 'ukda.entitlement-transition.v1'), true);
  await assert.rejects(f.reservations.reserve({ licenceKey: issued.licenceKey, operationId: randomUUID(), resumeToken: f.secrets.token() }), code('LICENCE_UNAVAILABLE'));
  await assert.rejects(f.operations.change({ ...revoke, action: 'reinstate' }, f.operator), code('OPERATION_CONFLICT'));
  await assert.rejects(f.operations.change(revoke, { operatorId: randomUUID() }), code('OPERATION_CONFLICT'));
  await assert.rejects(f.operations.change({ ...revoke, action: 'promote_owner' } as unknown as typeof revoke, f.operator), code('INVALID_REQUEST'));
  await assert.rejects(f.admin.control.query("UPDATE security.entitlement_operations SET outcome='{}' WHERE operation_id=$1", [revoke.operationId]), (error: unknown) => (error as { code: string }).code === '23514');
  const reinstated = await f.operations.change({ ...revoke, operationId: randomUUID(), action: 'reinstate' }, f.operator);
  assert.equal(reinstated.receipt.entitlementState, 'available');
  const resumeToken = f.secrets.token();
  const attempt = await f.reservations.reserve({ licenceKey: issued.licenceKey, operationId: randomUUID(), resumeToken });
  assert.equal(attempt.reservationGeneration, '3');
  await f.operations.change({ ...revoke, operationId: randomUUID(), action: 'legacy_expire' }, f.operator);
  await assert.rejects(f.reservations.status(attempt.activationId, resumeToken), code('ACTIVATION_INVALID'));
  const cancelled = (await f.admin.control.query('SELECT state,staged_public_state,staged_registration_record,proof_server_state FROM security.activation_attempts WHERE activation_id=$1', [attempt.activationId])).rows[0];
  assert.deepEqual(cancelled, { state: 'cancelled', staged_public_state: {}, staged_registration_record: null, proof_server_state: null });
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.workspaces WHERE workspace_id=$1', [attempt.workspaceId])).rowCount, 0);
  assert.equal(JSON.stringify(results).includes(issued.licenceKey), false);
});

test('CP03: consumed entitlement transitions preserve identity/keys, restrict the data guard and never enable redemption', { timeout: 30_000 }, async (t) => {
  const f = await fixture(t), activated = await f.activate(), workspaceId = activated.reserved.workspaceId;
  const snapshot = () => tenantTransaction(f.db.control, workspaceId, undefined, async (client) => {
    const result: Record<string, unknown[]> = {};
    for (const table of ['profiles', 'devices', 'grants', 'recovery_authorities', 'staged_objects']) result[table] = (await client.query(`SELECT * FROM security.${table} WHERE workspace_id=$1 ORDER BY to_jsonb(${table})::text`, [workspaceId])).rows;
    return result;
  });
  const before = await snapshot();
  const lookupOutage = new Error('synthetic licence lookup outage');
  const licenceLookupUnavailable = { ...f.db, control: {
    connect: f.db.control.connect.bind(f.db.control),
    query: async (sql: string, values?: unknown[]) => {
      if (/\bsecurity\.licences\b/.test(sql)) throw lookupOutage;
      return f.db.control.query(sql, values);
    },
  } as unknown as pg.Pool };
  const initialHead = (await f.admin.control.query('SELECT security_head FROM security.workspaces WHERE workspace_id=$1', [workspaceId])).rows[0]?.security_head as string;
  await assert.rejects(new EntitlementOperations(licenceLookupUnavailable, f.secrets).change({ licenceId: activated.issued.licenceId,
    operationId: randomUUID(), action: 'revoke' }, f.operator), (error: unknown) => error === lookupOutage);
  assert.equal(await dataTransaction(licenceLookupUnavailable, { workspaceId, profileId: activated.reserved.accountId,
    securityHead: initialHead, securityVersion: '1', dataGeneration: '1' }, async (client) =>
    (await client.query('SELECT count(*) FROM app.profiles WHERE workspace_id=$1', [workspaceId])).rows[0]?.count), '1');
  const revoke = { licenceId: activated.issued.licenceId, operationId: randomUUID(), action: 'revoke' as const };
  const [first, retry] = await Promise.all([f.operations.change(revoke, f.operator), f.operations.change(revoke, f.operator)]);
  assert.deepEqual(first, retry); assert.equal(first.receipt.securityVersion, '2'); assert.equal(first.receipt.licenceState, 'restricted');
  assert.equal(first.projection?.state, 'ready');
  assert.equal(await digestObject(first.receipt.transition), first.receipt.securityHead);
  assert.equal(entitlementTransitionBody.safeParse({ ...first.receipt.transition.body, owners: [randomUUID()] }).success, false);
  const principal = { workspaceId, profileId: activated.reserved.accountId, securityHead: first.receipt.securityHead!, securityVersion: '2', dataGeneration: '1' };
  assert.equal(await dataTransaction(f.db, principal, async () => 'existing read works'), 'existing read works');
  await assert.rejects(dataTransaction(f.db, principal, async () => 'must not write', { write: true }), code('WORKSPACE_RESTRICTED'));
  const restored = await f.operations.change({ ...revoke, action: 'reinstate', operationId: randomUUID() }, f.operator);
  assert.equal(restored.receipt.entitlementState, 'activated'); assert.equal(restored.receipt.licenceState, 'active');
  assert.equal(await dataTransaction(f.db, { ...principal, securityHead: restored.receipt.securityHead!, securityVersion: '3' }, async () => 'write guard enabled', { write: true }), 'write guard enabled');
  // Replaying an old revoke reports that original result; it cannot reapply after reinstatement.
  assert.deepEqual((await f.operations.change(revoke, f.operator)).receipt, first.receipt);
  assert.equal((await f.admin.control.query('SELECT state,activated_workspace_id FROM security.licences WHERE licence_id=$1', [revoke.licenceId])).rows[0]?.state, 'activated');
  assert.equal((await f.admin.control.query('SELECT activated_workspace_id FROM security.licences WHERE licence_id=$1', [revoke.licenceId])).rows[0]?.activated_workspace_id, workspaceId);
  await assert.rejects(f.reservations.reserve({ licenceKey: activated.issued.licenceKey, operationId: randomUUID(), resumeToken: f.secrets.token() }), code('LICENCE_UNAVAILABLE'));
  assert.deepEqual(await snapshot(), before);
  for (const secret of [activated.phrase, activated.password, 'Private entitlement owner', 'Private entitlement workspace', activated.issued.licenceKey]) assert.equal(JSON.stringify([first, restored]).includes(secret), false);
  assert.equal((await f.admin.control.query('SELECT count(*) FROM security.security_transitions WHERE workspace_id=$1', [workspaceId])).rows[0]?.count, '3');
});

test('CP03: reinstatement preserves maintenance, deletion and restore restrictions and cannot revive a deleted workspace', { timeout: 30_000 }, async (t) => {
  const f = await fixture(t), activated = await f.activate(), workspaceId = activated.reserved.workspaceId;
  await withSecurityFence(f.db, workspaceId, async (client) => {
    // Privileged fixture arrangement; runtime entitlement operations below cannot modify these flags.
    await f.admin.control.query(`UPDATE security.workspaces SET content_maintenance=true,restore_quarantine=true,lifecycle='pending_deletion',
      deletion_requested_at=now(),delete_after=now()+interval '7 days' WHERE workspace_id=$1`, [workspaceId]);
    await projectAuthoritativeWorkspace(f.db, workspaceId, client);
  });
  await f.operations.change({ licenceId: activated.issued.licenceId, operationId: randomUUID(), action: 'legacy_expire' }, f.operator);
  const restored = await f.operations.change({ licenceId: activated.issued.licenceId, operationId: randomUUID(), action: 'reinstate' }, f.operator);
  for (const [pool, schema] of [[f.admin.control, 'security'], [f.admin.application, 'app']] as const) {
    const row = (await pool.query(`SELECT licence_state,content_maintenance,restore_quarantine,lifecycle FROM ${schema}.workspaces WHERE workspace_id=$1`, [workspaceId])).rows[0];
    assert.deepEqual(row, { licence_state: 'active', content_maintenance: true, restore_quarantine: true, lifecycle: 'pending_deletion' });
  }
  await assert.rejects(dataTransaction(f.db, { workspaceId, profileId: activated.reserved.accountId, securityHead: restored.receipt.securityHead!, securityVersion: restored.receipt.securityVersion!, dataGeneration: '1' }, async () => 'denied'), code('RESTORE_QUARANTINE'));
  await withSecurityFence(f.db, workspaceId, async () => {
    await f.admin.control.query("UPDATE security.workspaces SET lifecycle='deleted',deleted_at=now() WHERE workspace_id=$1", [workspaceId]);
  });
  const deleted = await f.operations.change({ licenceId: activated.issued.licenceId, operationId: randomUUID(), action: 'reinstate' }, f.operator);
  assert.deepEqual(deleted.projection, { state: 'deleted' }); assert.equal(deleted.receipt.securityVersion, null);
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [workspaceId])).rows[0]?.fence_closed, true);
  assert.equal((await f.admin.control.query('SELECT lifecycle FROM security.workspaces WHERE workspace_id=$1', [workspaceId])).rows[0]?.lifecycle, 'deleted');
  await assert.rejects(f.reservations.reserve({ licenceKey: activated.issued.licenceKey, operationId: randomUUID(), resumeToken: f.secrets.token() }), code('LICENCE_UNAVAILABLE'));
  // Simulate completed privileged retention: only the consumed entitlement's retired
  // workspace reference remains. Reinstatement must not recreate either store's rows.
  await withSecurityFence(f.db, workspaceId, async () => {
    await f.admin.control.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
    await transaction(f.admin.application, async (client) => {
      for (const table of ['profiles', 'roles', 'workspaces']) await client.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [workspaceId]);
    });
  });
  const retired = await f.operations.change({ licenceId: activated.issued.licenceId, operationId: randomUUID(), action: 'reinstate' }, f.operator);
  assert.equal(retired.receipt.entitlementState, 'activated'); assert.equal(retired.receipt.workspaceId, workspaceId);
  assert.deepEqual(retired.projection, { state: 'deleted' });
  for (const [pool, schema] of [[f.admin.control, 'security'], [f.admin.application, 'app']] as const) {
    assert.equal((await pool.query(`SELECT 1 FROM ${schema}.workspaces WHERE workspace_id=$1`, [workspaceId])).rowCount, 0);
  }
  await assert.rejects(f.reservations.reserve({ licenceKey: activated.issued.licenceKey, operationId: randomUUID(), resumeToken: f.secrets.token() }), code('LICENCE_UNAVAILABLE'));
});

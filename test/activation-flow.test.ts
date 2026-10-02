import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test, { type TestContext } from 'node:test';
import { parseEnv } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import * as opaqueLibrary from '@serenity-kit/opaque';
import pg from 'pg';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { ClientOpaqueError, finishLogin, finishRegistration, startLogin, startRegistration } from '../src/client/opaque.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { loadConfig } from '../src/config.js';
import { createDatabases, transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { ActivationService } from '../src/modules/identity/activation.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { tenantTransaction } from '../src/persistence.js';
import { initialContentHeader, initialRecipientHeader, transcriptFromGenesis, type ActivationBinding } from '../src/shared/activation.js';
import { base64urlDecode, decryptContent, digestObject, openRecipient } from '../src/shared/crypto.js';
import { startWorker } from '../src/worker.js';

type Hooks = NonNullable<ConstructorParameters<typeof ActivationService>[0]['hooks']>;
const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;
const flip = (value: string) => `${value[0] === 'a' ? 'b' : 'a'}${value.slice(1)}`;
const origin = 'http://localhost:3400';
const password = 'A private activation fixture passphrase 782';

async function fixture(t: TestContext) {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const applicationUrl = process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ?? local.ADMIN_DATABASE_URL;
  const controlUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(applicationUrl && controlUrl, 'Activation tests require explicit fixture admin credentials');
  const admin = { application: new pg.Pool({ connectionString: applicationUrl }), control: new pg.Pool({ connectionString: controlUrl }) };
  const databases = createDatabases(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }));
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'cp03-activation-test' });
  await opaqueLibrary.ready;
  const opaque = new OpaqueService({ serverSetup: opaqueLibrary.server.createSetup(), setupId: 'cp03-test-v1', serverIdentity: 'ukda:activation-test' });
  const serviceWith = (hooks: Hooks = {}) => new ActivationService({ databases, secrets, opaque, origin, hooks });
  const service = serviceWith();
  const issued = await service.reservations.issueLicence();
  const resumeToken = secrets.token();
  const reserved = await service.reservations.reserve({ licenceKey: issued.licenceKey, operationId: randomUUID(), resumeToken });
  const workspaceId = reserved.workspaceId;
  t.after(async () => {
    try {
      // Remove only this workspace's repair job; never reset a shared queue or schema.
      await databases.application.query('SELECT graphile_worker.remove_job($1)', [`activation:${workspaceId}`]);
      await transaction(admin.application, async (client) => {
        await client.query("SELECT set_config('ukda.workspace_id', $1, true)", [workspaceId]);
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.workspace:' || $1, 0))", [workspaceId]);
        await client.query('DELETE FROM app.profiles WHERE workspace_id=$1', [workspaceId]);
        await client.query('DELETE FROM app.roles WHERE workspace_id=$1', [workspaceId]);
        await client.query('DELETE FROM app.workspaces WHERE workspace_id=$1', [workspaceId]);
      });
      await transaction(admin.control, async (client) => {
        await client.query("SELECT set_config('ukda.workspace_id', $1, true)", [workspaceId]);
        await client.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
        await client.query('DELETE FROM security.activation_attempts WHERE licence_id=$1', [issued.licenceId]);
        await client.query('DELETE FROM security.licences WHERE licence_id=$1', [issued.licenceId]);
      });
    } finally { await Promise.allSettled([databases.close(), admin.application.end(), admin.control.end()]); }
  });
  const registrationStart = await startRegistration(password);
  const registrationResponse = await service.registration(reserved.activationId, resumeToken,
    { draftGeneration: reserved.draftGeneration, registrationRequest: registrationStart.registrationRequest });
  const registered = await finishRegistration({ password, clientRegistrationState: registrationStart.clientRegistrationState,
    registrationResponse: registrationResponse.registrationResponse, configuration: registrationResponse.configuration });
  const phrase = await newOwnerPhrase();
  const positions = [1, 8, 20];
  const binding: ActivationBinding = { activationId: reserved.activationId, operationId: reserved.operationId, workspaceId,
    accountId: reserved.accountId, reservationGeneration: reserved.reservationGeneration, draftGeneration: reserved.draftGeneration, origin };
  const displayName = `Private Owner ${randomUUID()}`;
  const workspaceName = `Private Workspace ${randomUUID()}`;
  const prepared = await prepareOwnerActivation({ binding, configuration: registrationResponse.configuration,
    registrationRecord: registered.registrationRecord, exportKey: registered.exportKey, phrase,
    challengePositions: positions, challengeAnswers: positions.map((position) => phrase.split(' ')[position]!), displayName, workspaceName });
  const startProof = async (suppliedPassword = password) => {
    const client = await startLogin(suppliedPassword);
    const proof = await service.startProof(reserved.activationId, resumeToken,
      { draftGeneration: '1', payload: prepared.payload, startLoginRequest: client.startLoginRequest });
    return { client, proof };
  };
  const prove = async () => {
    const { client, proof } = await startProof();
    const finished = await finishLogin({ password, clientLoginState: client.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
    assert.equal(finished.exportKey, registered.exportKey);
    await service.finishProof(reserved.activationId, resumeToken,
      { draftGeneration: '1', proofId: proof.proofId, finishLoginRequest: finished.finishLoginRequest });
    return { draftGeneration: '1', requestHash: proof.requestHash };
  };
  const tenantControl = <T>(action: Parameters<typeof tenantTransaction<T>>[3]) => tenantTransaction(databases.control, workspaceId, undefined, action);
  const tenantApplication = <T>(action: Parameters<typeof tenantTransaction<T>>[3]) => tenantTransaction(databases.application, workspaceId, reserved.accountId, action);
  return { service, serviceWith, databases, admin, issued, reserved, resumeToken, registered, phrase, prepared,
    binding, displayName, workspaceName, startProof, prove, tenantControl, tenantApplication };
}

test('CP03: atomic activation creates one Owner and supports identical concurrent finalization and client decryption', async (t) => {
  const f = await fixture(t);
  const request = await f.prove();
  const finals = await Promise.all([1, 2].map(() => f.service.finalize(f.reserved.activationId, f.resumeToken, request)));
  assert.equal(finals[0]?.state, 'completed');
  assert.deepEqual(finals[0], finals[1]);
  assert.deepEqual(await f.service.finalize(f.reserved.activationId, f.resumeToken, request), finals[0]);
  await assert.rejects(f.service.finalize(f.reserved.activationId, f.resumeToken, { ...request, requestHash: flip(request.requestHash) }), code('OPERATION_CONFLICT'));
  const controlRows = await f.tenantControl(async (client) => {
    const rows: Record<string, unknown[]> = {};
    for (const table of ['workspaces', 'profiles', 'devices', 'recovery_authorities', 'grants', 'roles', 'scope_heads', 'security_transitions', 'operation_receipts', 'staged_objects']) {
      rows[table] = (await client.query(`SELECT * FROM security.${table} WHERE workspace_id=$1`, [f.binding.workspaceId])).rows;
    }
    return rows;
  });
  assert.equal(controlRows.profiles?.length, 1);
  assert.equal((controlRows.profiles?.[0] as { is_owner: boolean }).is_owner, true);
  const ownerRole = controlRows.profiles![0] as { role_id: string; role_revision: string; role_assignment_object_id: string };
  assert.deepEqual([ownerRole.role_id, ownerRole.role_revision, ownerRole.role_assignment_object_id],
    [f.prepared.payload.genesis.body.roles.owner, '1', f.prepared.payload.genesis.body.genesisId]);
  assert.equal(controlRows.devices?.length, 1);
  assert.equal(controlRows.recovery_authorities?.length, 1);
  assert.equal(controlRows.grants?.length, 2);
  assert.equal((controlRows.grants as { grant_kind: string; device_id: string | null }[]).find((grant) => grant.grant_kind === 'owner')?.device_id, null);
  assert.equal(controlRows.roles?.length, 4);
  assert.equal(controlRows.scope_heads?.length, 1);
  assert.equal((controlRows.workspaces?.[0] as { current_custody_manifest_object_id: string }).current_custody_manifest_object_id, f.prepared.payload.genesis.body.custodyId);
  assert.equal(controlRows.security_transitions?.length, 1);
  assert.equal(controlRows.operation_receipts?.length, 1);
  assert.equal(controlRows.staged_objects?.length, 6);
  const applicationRows = await f.tenantApplication(async (client) => ({
    workspace: (await client.query('SELECT * FROM app.workspaces WHERE workspace_id=$1', [f.binding.workspaceId])).rows[0],
    profiles: (await client.query('SELECT * FROM app.profiles WHERE workspace_id=$1', [f.binding.workspaceId])).rows,
    roles: (await client.query('SELECT * FROM app.roles WHERE workspace_id=$1 ORDER BY template', [f.binding.workspaceId])).rows,
    scopes: (await client.query('SELECT * FROM app.scope_heads WHERE workspace_id=$1', [f.binding.workspaceId])).rows,
  }));
  assert.equal(applicationRows.workspace.fence_closed, false);
  assert.equal(applicationRows.workspace.security_version, '1');
  assert.equal(applicationRows.profiles.length, 1);
  assert.deepEqual(applicationRows.roles.map((role) => role.template), ['manager', 'member', 'owner', 'viewer']);
  assert.equal(applicationRows.scopes[0]?.key_epoch, '1');
  const bundle = await unwrapDeviceBundle({ workspaceId: f.binding.workspaceId, accountId: f.binding.accountId,
    deviceId: f.prepared.payload.genesis.body.device.id, credentialGeneration: '1' }, f.prepared.deviceWrapper, f.registered.exportKey);
  const transcript = transcriptFromGenesis(f.prepared.payload.genesis.body);
  const stored = new Map((controlRows.staged_objects as { object_id: string; versioned_object: unknown }[]).map((row) => [row.object_id, row.versioned_object]));
  const signingKey = base64urlDecode(bundle.signingPublicKey, 32);
  const deviceEnvelope = stored.get(transcript.deviceEnvelopeId) as typeof f.prepared.payload.objects.deviceCustody;
  const custody = await openRecipient(deviceEnvelope, base64urlDecode(bundle.recipientPrivateKey, 32), signingKey,
    initialRecipientHeader(transcript, f.prepared.payload.genesis.body.transcriptDigest, 'device')) as { custodyKey: string };
  const custodyEnvelope = stored.get(transcript.custodyId) as typeof f.prepared.payload.objects.custody;
  const keys = await decryptContent(custodyEnvelope, base64urlDecode(custody.custodyKey, 32), signingKey,
    initialContentHeader(transcript, 'custody')) as { workspaceKeys: { key: string }[] };
  const workspaceKey = base64urlDecode(keys.workspaceKeys[0]!.key, 32);
  const plaintextProfile = await decryptContent(applicationRows.profiles[0].encrypted_envelope, workspaceKey, signingKey,
    initialContentHeader(transcript, 'profile')) as { displayName: string };
  assert.equal(plaintextProfile.displayName, f.displayName);
  const plaintextWorkspace = await decryptContent(applicationRows.workspace.encrypted_envelope, workspaceKey, signingKey,
    initialContentHeader(transcript, 'workspace')) as { name: string; timezone: string };
  assert.equal(plaintextWorkspace.name, f.workspaceName);
  assert.equal(plaintextWorkspace.timezone, 'Europe/London');
  const attempt = (await f.admin.control.query('SELECT * FROM security.activation_attempts WHERE activation_id=$1', [f.reserved.activationId])).rows[0];
  assert.equal(attempt.staged_registration_record, null);
  assert.equal(attempt.proof_server_state, null);
  const providerRows = JSON.stringify({ controlRows, applicationRows, attempt });
  for (const secret of [password, f.phrase, f.displayName, f.workspaceName, f.registered.exportKey,
    bundle.signingPrivateKey, bundle.recipientPrivateKey, custody.custodyKey, keys.workspaceKeys[0]!.key, f.prepared.deviceWrapper.ciphertext]) {
    assert.equal(providerRows.includes(secret), false, 'provider rows must not contain client-only material');
  }
  workspaceKey.fill(0);
});

test('CP03: tampered ciphertext, genesis, and foreign context fail before any licence is consumed', async (t) => {
  const f = await fixture(t);
  for (const variant of ['ciphertext', 'genesis', 'context'] as const) {
    const payload = structuredClone(f.prepared.payload);
    if (variant === 'ciphertext') payload.objects.profile.ciphertext = flip(payload.objects.profile.ciphertext);
    if (variant === 'genesis') payload.genesis.signature = flip(payload.genesis.signature);
    if (variant === 'context') payload.genesis.body.workspaceId = randomUUID();
    const client = await startLogin(password);
    await assert.rejects(f.service.startProof(f.reserved.activationId, f.resumeToken,
      { draftGeneration: '1', payload, startLoginRequest: client.startLoginRequest }), code('INVALID_ACTIVATION_DRAFT'));
  }
  assert.equal((await f.admin.control.query('SELECT state FROM security.licences WHERE licence_id=$1', [f.issued.licenceId])).rows[0]?.state, 'reserved');
  await f.tenantControl(async (client) => {
    assert.equal((await client.query('SELECT * FROM security.profiles WHERE workspace_id=$1', [f.binding.workspaceId])).rowCount, 0);
    assert.equal((await client.query('SELECT * FROM security.staged_objects WHERE workspace_id=$1', [f.binding.workspaceId])).rowCount, 0);
  });
});

test('CP03: wrong password and consumed proof replay cannot finalize activation', async (t) => {
  const f = await fixture(t);
  const wrongPassword = 'A different private activation password 936';
  const wrong = await f.startProof(wrongPassword);
  await assert.rejects(finishLogin({ password: wrongPassword, clientLoginState: wrong.client.clientLoginState,
    loginResponse: wrong.proof.loginResponse, configuration: wrong.proof.configuration }),
  (error: unknown) => error instanceof ClientOpaqueError && error.code === 'AUTHENTICATION');
  const valid = await f.startProof();
  const finish = await finishLogin({ password, clientLoginState: valid.client.clientLoginState,
    loginResponse: valid.proof.loginResponse, configuration: valid.proof.configuration });
  const proofInput = { draftGeneration: '1', proofId: valid.proof.proofId, finishLoginRequest: finish.finishLoginRequest };
  await assert.rejects(f.service.finishProof(f.reserved.activationId, f.resumeToken,
    { ...proofInput, finishLoginRequest: randomBytes(64).toString('base64url') }), code('SETUP_PROOF_INVALID'));
  await assert.rejects(f.service.finishProof(f.reserved.activationId, f.resumeToken, proofInput), code('SETUP_PROOF_INVALID'));
  await assert.rejects(f.service.finalize(f.reserved.activationId, f.resumeToken,
    { draftGeneration: '1', requestHash: valid.proof.requestHash }), code('SETUP_PROOF_INVALID'));
  assert.equal((await f.service.reservations.status(f.reserved.activationId, f.resumeToken)).state, 'reserved');
});

test('CP03: interruption before authority commit rolls back activation and permits the same verified retry', async (t) => {
  const f = await fixture(t);
  const request = await f.prove();
  const interrupted = f.serviceWith({ beforeControlCommit: async () => { throw new Error('synthetic-before-commit'); } });
  await assert.rejects(interrupted.finalize(f.reserved.activationId, f.resumeToken, request), /synthetic-before-commit/);
  await f.tenantControl(async (client) => {
    assert.equal((await client.query('SELECT lifecycle FROM security.workspaces WHERE workspace_id=$1', [f.binding.workspaceId])).rows[0]?.lifecycle, 'pending_activation');
    for (const table of ['profiles', 'devices', 'grants', 'recovery_authorities', 'security_transitions', 'operation_receipts']) {
      assert.equal((await client.query(`SELECT * FROM security.${table} WHERE workspace_id=$1`, [f.binding.workspaceId])).rowCount, 0, table);
    }
    assert.equal((await client.query("SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND state='staged'", [f.binding.workspaceId])).rowCount, 6);
  });
  assert.equal((await f.admin.control.query('SELECT state FROM security.licences WHERE licence_id=$1', [f.issued.licenceId])).rows[0]?.state, 'reserved');
  assert.equal((await f.service.finalize(f.reserved.activationId, f.resumeToken, request)).state, 'completed');
});

test('CP03: lost response after authority commit recovers its original receipt and projection', async (t) => {
  const f = await fixture(t);
  const request = await f.prove();
  const interrupted = f.serviceWith({ afterControlCommit: async () => { throw new Error('synthetic-lost-response'); } });
  await assert.rejects(interrupted.finalize(f.reserved.activationId, f.resumeToken, request), /synthetic-lost-response/);
  const committed = await f.service.reservations.status(f.reserved.activationId, f.resumeToken);
  assert.equal(committed.state, 'completed');
  const recovered = await f.service.status(f.reserved.activationId, f.resumeToken);
  assert.equal(recovered.state, 'completed');
  assert.deepEqual(recovered.receipt, committed.receipt);
  const retried = await f.service.finalize(f.reserved.activationId, f.resumeToken, request);
  assert.deepEqual(retried.receipt, committed.receipt);
});

test('CP03: projection interruption leaves a closed fence and status safely finishes the projection', async (t) => {
  const f = await fixture(t);
  const request = await f.prove();
  let inspectedFence = false;
  const interrupted = f.serviceWith({ beforeProjection: async () => {
    await f.tenantApplication(async (client) => {
      assert.equal((await client.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.binding.workspaceId])).rows[0]?.fence_closed, true);
      assert.equal((await client.query('SELECT * FROM app.profiles WHERE workspace_id=$1', [f.binding.workspaceId])).rowCount, 0);
    });
    inspectedFence = true;
    throw new Error('synthetic-projection-interruption');
  } });
  const result = await interrupted.finalize(f.reserved.activationId, f.resumeToken, request);
  assert.equal(inspectedFence, true);
  assert.equal(result.state, 'finishing_setup');
  assert.equal((await f.service.status(f.reserved.activationId, f.resumeToken)).state, 'completed');
  await f.tenantApplication(async (client) => {
    assert.equal((await client.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.binding.workspaceId])).rows[0]?.fence_closed, false);
  });
  assert.equal(await digestObject(f.prepared.payload), request.requestHash);
});

test('CP03: the hosted worker repairs a committed activation without another browser request', async (t) => {
  const f = await fixture(t);
  const request = await f.prove();
  const interrupted = f.serviceWith({ beforeProjection: async () => { throw new Error('synthetic-worker-repair'); } });
  const result = await interrupted.finalize(f.reserved.activationId, f.resumeToken, request);
  assert.equal(result.state, 'finishing_setup');
  const worker = await startWorker(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent', HOST: '127.0.0.1' }), { port: 0 });
  try {
    const deadline = Date.now() + 10000;
    while (true) {
      const current = await f.tenantApplication(async (client) =>
        (await client.query('SELECT fence_closed,security_head FROM app.workspaces WHERE workspace_id=$1', [f.binding.workspaceId])).rows[0]);
      if (current?.fence_closed === false) {
        assert.equal(current.security_head, result.receipt.securityHead);
        break;
      }
      assert.ok(Date.now() < deadline, 'The queued projection did not finish within ten seconds');
      await delay(50);
    }
  } finally { await worker.stop(); }
});

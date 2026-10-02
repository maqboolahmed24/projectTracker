import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';
import { AppError } from '../src/errors.js';
import { transaction } from '../src/db.js';
import { startLogin, finishLogin, ClientOpaqueError } from '../src/client/opaque.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { PasswordChangeClientError } from '../src/client/password-change.js';
import { canonicalJson, digestObject } from '../src/shared/crypto.js';
import { passwordChangeBinding } from '../src/shared/password-change.js';
import { passwordFixture, oldPassword, newPassword } from './password-change-fixture.js';

const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;

test('CP04: password change preserves the signer and recovery authority, advances credentials and revokes other devices/sessions', async (t) => {
  const f = await passwordFixture(t), otherDevice = randomUUID(), otherGrant = randomUUID();
  const before = (await f.admin.control.query('SELECT * FROM security.recovery_authorities WHERE workspace_id=$1', [f.workspaceId])).rows;
  await f.admin.control.query("UPDATE security.licences SET state='revoked' WHERE licence_id=$1", [f.licence.licenceId]);
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='restricted' WHERE workspace_id=$1", [f.workspaceId]);
  // Existing second-device authority fixture isolates revocation from the separate pairing suite.
  await f.admin.control.query(`INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approval_security_version,approved_at)
    SELECT workspace_id,$2,profile_id,2,$3,$4,'active',1,now() FROM security.devices WHERE workspace_id=$1 AND device_id=$5`,
  [f.workspaceId, otherDevice, randomBytes(32), randomBytes(32), f.deviceId]);
  await f.admin.control.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,generation,state,signed_grant_object_id,key_manifest_object_id,key_epoch,permissions,security_version,activated_at)
    VALUES($1,$2,$3,$4,'device','workspace',2,'active',$5,$6,1,ARRAY['read_project'],1,now())`, [f.workspaceId, otherGrant, f.accountId, otherDevice, f.prepared.payload.genesis.body.genesisId, f.prepared.payload.genesis.body.custodyId]);
  const otherSession = await transaction(f.databases.control, (client) => f.sessions.issue(client, { workspaceId: f.workspaceId, profileId: f.accountId,
    deviceId: otherDevice, accessLevel: 'device_approved', credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1' }));
  const oldAuth = f.auth();
  const inflight = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId: f.accountId, startLoginRequest: (await startLogin(oldPassword)).startLoginRequest });
  const operationId = await f.draft(), pending = (await f.changes.get(operationId))!;
  assert.equal((await f.devices.getActive(f.workspaceId, f.accountId, f.deviceId))?.header.credentialGeneration, '1');
  const result = await f.controller.complete(operationId, newPassword);
  assert.equal(result.state, 'completed'); assert.equal(result.receipt.credentialGeneration, '2'); assert.equal(result.receipt.sessionGeneration, '2');
  assert.equal(result.receipt.securityVersion, '2'); assert.equal(result.receipt.keyGeneration, '1');
  assert.equal((await f.devices.getActive(f.workspaceId, f.accountId, f.deviceId))?.header.credentialGeneration, '2');
  await assert.rejects(f.sessions.authenticate(oldAuth.cookieValue)); await assert.rejects(f.sessions.authenticate(otherSession.cookieValue));
  assert.equal((await f.admin.control.query('SELECT state FROM security.auth_attempts WHERE login_id=$1', [inflight.loginId])).rows[0].state, 'consumed');
  assert.equal((await f.admin.control.query('SELECT state FROM security.devices WHERE workspace_id=$1 AND device_id=$2', [f.workspaceId, otherDevice])).rows[0].state, 'revoked');
  assert.equal((await f.admin.control.query('SELECT state FROM security.grants WHERE workspace_id=$1 AND grant_id=$2', [f.workspaceId, otherGrant])).rows[0].state, 'revoked');
  assert.deepEqual((await f.admin.control.query('SELECT * FROM security.recovery_authorities WHERE workspace_id=$1', [f.workspaceId])).rows, before);
  const logged = await f.login(newPassword);
  const wrapper = (await f.devices.get({ ...f.deviceContext, credentialGeneration: '2' }))!;
  assert.deepEqual(await unwrapDeviceBundle({ ...f.deviceContext, credentialGeneration: '2' }, wrapper, logged.exportKey), f.originalBundle);
  const old = await startLogin(oldPassword), response = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId: f.accountId, startLoginRequest: old.startLoginRequest });
  await assert.rejects(finishLogin({ password: oldPassword, clientLoginState: old.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration }),
    (error: unknown) => error instanceof ClientOpaqueError);
  const stored = JSON.stringify((await f.admin.control.query('SELECT * FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [f.workspaceId, operationId])).rows[0]);
  for (const secret of [oldPassword, newPassword, f.phrase, logged.exportKey, f.originalBundle.signingPrivateKey, f.originalBundle.recipientPrivateKey, pending.reference.resumeToken]) assert.equal(stored.includes(secret), false);
  assert.equal(stored.includes(pending.draft!.payload.registrationRecord), false);
});

test('CP04: interruption between local draft persistence and device staging retains the old wrapper and resumes the exact new draft', async (t) => {
  const f = await passwordFixture(t), operationId = randomUUID();
  await f.controller.begin(f.workspaceId, operationId);
  const stage = f.devices.stage.bind(f.devices);
  f.devices.stage = async () => { throw new Error('Injected local storage outage'); };
  await assert.rejects(f.controller.prepare(operationId, newPassword, newPassword));
  f.devices.stage = stage;
  const pending = await f.changes.get(operationId); assert.ok(pending?.draft);
  assert.equal(await f.devices.getStaged(operationId), undefined);
  assert.equal((await f.devices.getActive(f.workspaceId, f.accountId, f.deviceId))?.header.credentialGeneration, '1');
  await f.reopen(); await f.login(oldPassword);
  const result = await f.controller.complete(operationId, newPassword);
  assert.equal(result.receipt.wrapperHash, await digestObject(pending.draft.wrapper));
  assert.equal((await f.devices.getActive(f.workspaceId, f.accountId, f.deviceId))?.header.credentialGeneration, '2');
});

test('CP04: authoritative precommit failure rolls back credentials and the same staged operation succeeds on retry', async (t) => {
  const f = await passwordFixture(t), operationId = await f.draft();
  f.setHooks({ beforeControlCommit: async () => {
    assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].fence_closed, true);
    throw new Error('Injected precommit failure');
  } });
  await assert.rejects(f.controller.complete(operationId, newPassword), code('PASSWORD_CHANGE_UNAVAILABLE'));
  assert.equal((await f.admin.control.query('SELECT credential_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.accountId])).rows[0].credential_generation, '1');
  assert.equal((await f.admin.control.query('SELECT state FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [f.workspaceId, operationId])).rows[0].state, 'issued');
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2', [f.workspaceId, operationId])).rowCount, 0);
  await f.reopen(); await f.login(oldPassword); f.setHooks();
  assert.equal((await f.controller.complete(operationId, newPassword)).receipt.credentialGeneration, '2');
});

test('CP04: lost commit response and browser restart select only the new authenticated generation and recover the durable receipt', async (t) => {
  const f = await passwordFixture(t), operationId = await f.draft(), oldAuth = f.auth();
  f.setHooks({ afterControlCommit: async () => { throw new Error('Injected lost commit response'); } });
  await assert.rejects(f.controller.complete(operationId, newPassword));
  const pending = (await f.changes.get(operationId))!;
  assert.equal((await f.devices.getActive(f.workspaceId, f.accountId, f.deviceId))?.header.credentialGeneration, '1');
  assert.ok(await f.devices.getStaged(operationId)); assert.ok(await f.devices.get(f.deviceContext));
  await f.reopen(); f.setHooks();
  const status = await f.controller.resume(operationId); assert.equal(status.state, 'completed'); assert.ok(status.receipt);
  assert.equal((await f.devices.getActive(f.workspaceId, f.accountId, f.deviceId))?.header.credentialGeneration, '1', 'A public receipt alone must not promote after restart');
  const logged = await f.login(newPassword);
  await f.controller.resume(operationId, logged.session);
  assert.equal((await f.devices.getActive(f.workspaceId, f.accountId, f.deviceId))?.header.credentialGeneration, '2');
  const replay = await f.service.finalize({ ...pending.reference, requestHash: await digestObject(pending.draft!.payload) }, oldAuth);
  assert.equal(canonicalJson(replay.receipt), canonicalJson(status.receipt));
  await assert.rejects(f.service.finalize({ ...pending.reference, requestHash: 'f'.repeat(64) }, oldAuth), code('OPERATION_CONFLICT'));
  assert.equal((await f.admin.control.query("SELECT 1 FROM security.security_transitions WHERE workspace_id=$1 AND action='password.change'", [f.workspaceId])).rowCount, 1);
});

test('CP04: failed projection leaves password change committed and fenced, then status repairs the current projection', async (t) => {
  const f = await passwordFixture(t), operationId = await f.draft();
  f.setHooks({ beforeProjection: async () => {
    assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].fence_closed, true);
    throw new Error('Injected projection outage');
  } });
  assert.equal((await f.controller.complete(operationId, newPassword)).state, 'finishing');
  f.setHooks();
  assert.equal((await f.controller.resume(operationId)).state, 'completed');
  const projected = (await f.admin.application.query('SELECT fence_closed,security_version FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0];
  assert.equal(projected.fence_closed, false); assert.equal(projected.security_version, '2');
  assert.equal((await f.login(newPassword)).session.accessLevel, 'device_approved');
});

test('CP04: tampered drafts, failed new-password proof, stale authority and missing recent authentication cannot commit', async (t) => {
  const f = await passwordFixture(t), operationId = await f.draft(), pending = (await f.changes.get(operationId))!;
  const client = await startLogin(newPassword), payload = structuredClone(pending.draft!.payload);
  payload.transition.body.wrapperHash = 'f'.repeat(64);
  await assert.rejects(f.service.startProof({ ...pending.reference, payload, startLoginRequest: client.startLoginRequest }, f.auth()), code('OPERATION_CONFLICT'));
  const proof = await f.service.startProof({ ...pending.reference, payload: pending.draft!.payload, startLoginRequest: client.startLoginRequest }, f.auth());
  await assert.rejects(f.service.finishProof({ ...pending.reference, proofId: proof.proofId, finishLoginRequest: randomBytes(64).toString('base64url') }, f.auth()), code('PASSWORD_PROOF_REQUIRED'));
  const good = await finishLogin({ password: newPassword, clientLoginState: client.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
  await assert.rejects(f.service.finishProof({ ...pending.reference, proofId: proof.proofId, finishLoginRequest: good.finishLoginRequest }, f.auth()), code('PASSWORD_PROOF_REQUIRED'));
  await assert.rejects(f.service.finalize({ ...pending.reference, requestHash: proof.requestHash }, f.auth()), code('PASSWORD_PROOF_REQUIRED'));
  const ready = await f.stagedProof(operationId);
  const session = await f.sessions.authenticate(f.auth().cookieValue);
  await f.admin.control.query('UPDATE security.sessions SET authenticated_at=$3 WHERE workspace_id=$1 AND session_id=$2', [f.workspaceId, session.sessionId, new Date(Date.now() - 301000)]);
  await assert.rejects(f.service.finalize(ready, f.auth()), code('REAUTH_REQUIRED'));
  await f.login(oldPassword);
  await f.admin.control.query('UPDATE security.workspaces SET data_generation=data_generation+1 WHERE workspace_id=$1', [f.workspaceId]);
  await assert.rejects(f.service.finalize(ready, f.auth()));
  assert.equal((await f.admin.control.query('SELECT credential_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.accountId])).rows[0].credential_generation, '1');
});

test('CP04: identical concurrent finalization records one transition and cancellation never discards the active wrapper', async (t) => {
  const f = await passwordFixture(t), operationId = await f.draft(), request = await f.stagedProof(operationId), auth = f.auth();
  const results = await Promise.all([f.service.finalize(request, auth), f.service.finalize(request, auth)]);
  assert.equal(canonicalJson(results[0]!.receipt), canonicalJson(results[1]!.receipt));
  assert.equal((await f.admin.control.query("SELECT 1 FROM security.security_transitions WHERE workspace_id=$1 AND action='password.change'", [f.workspaceId])).rowCount, 1);
  await assert.rejects(f.controller.cancel(operationId));
  assert.ok(await f.devices.get(f.deviceContext)); assert.ok(await f.devices.getStaged(operationId));
});

test('CP04: storage failure before draft persistence and confirmed precommit cancellation preserve the old login', async (t) => {
  const f = await passwordFixture(t), operationId = randomUUID();
  await f.controller.begin(f.workspaceId, operationId);
  const save = f.changes.save.bind(f.changes);
  f.changes.save = async (_before, next) => { if (next.draft) throw new Error('Injected pending-store outage'); return save(_before, next); };
  await assert.rejects(f.controller.prepare(operationId, newPassword, newPassword));
  f.changes.save = save;
  assert.equal((await f.changes.get(operationId))?.draft, undefined);
  assert.equal(await f.devices.getStaged(operationId), undefined);
  assert.ok(await f.devices.get(f.deviceContext));
  await f.controller.prepare(operationId, newPassword, newPassword);
  assert.equal((await f.controller.cancel(operationId)).state, 'cancelled');
  assert.equal(await f.devices.getStaged(operationId), undefined);
  assert.ok(await f.devices.get(f.deviceContext));
  assert.equal((await f.login(oldPassword)).session.credentialGeneration, '1');
  const rows = await f.admin.control.query('SELECT 1 FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2', [f.workspaceId, operationId]);
  assert.equal(rows.rowCount, 0);
});

test('CP04: new-password proof expires after two minutes and its failed finish stays consumed', async (t) => {
  const f = await passwordFixture(t), operationId = await f.draft(), pending = (await f.changes.get(operationId))!;
  const client = await startLogin(newPassword);
  const proof = await f.service.startProof({ ...pending.reference, payload: pending.draft!.payload, startLoginRequest: client.startLoginRequest }, f.auth());
  const finish = await finishLogin({ password: newPassword, clientLoginState: client.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
  f.advance(121000);
  const input = { ...pending.reference, proofId: proof.proofId, finishLoginRequest: finish.finishLoginRequest };
  await assert.rejects(f.service.finishProof(input, f.auth()), code('PASSWORD_PROOF_REQUIRED'));
  await assert.rejects(f.service.finishProof(input, f.auth()), code('PASSWORD_PROOF_REQUIRED'));
  const row = (await f.admin.control.query('SELECT server_state_ciphertext,server_state_key_id,public_state FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [f.workspaceId, operationId])).rows[0];
  assert.equal(row.server_state_ciphertext, null); assert.equal(row.server_state_key_id, null); assert.equal(row.public_state.proofVerifiedAt, undefined);
  await assert.rejects(f.service.finalize({ ...pending.reference, requestHash: proof.requestHash }, f.auth()), code('PASSWORD_PROOF_REQUIRED'));
});

test('CP04: logout retains encrypted password drafts while explicit device forgetting deletes their duplicate wrappers', async (t) => {
  const f = await passwordFixture(t), operationId = await f.draft();
  f.controller.clear();
  assert.ok((await f.changes.get(operationId))?.draft);
  await f.changes.forgetDevice({ workspaceId: f.workspaceId, accountId: randomUUID(), deviceId: f.deviceId });
  assert.ok((await f.changes.get(operationId))?.draft, 'An unrelated account must not lose its pending change');
  await f.controller.forgetDevice({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId });
  await f.devices.forget(f.workspaceId, f.accountId, f.deviceId);
  assert.equal(await f.changes.get(operationId), undefined);
  assert.equal(await f.devices.getStaged(operationId), undefined);
  assert.equal(await f.devices.get(f.deviceContext), undefined);
});

test('CP04: a late password status response after Forget cannot restore either encrypted wrapper copy', async (t) => {
  const f = await passwordFixture(t), operationId = await f.draft();
  let requestStarted!: () => void, releaseResponse!: () => void;
  const requested = new Promise<void>((resolve) => { requestStarted = resolve; });
  const response = new Promise<void>((resolve) => { releaseResponse = resolve; });
  const status = f.transport.status.bind(f.transport);
  // Simulate a response that was already accepted when cancellation occurred.
  f.transport.status = async (input) => {
    const value = await status(input); requestStarted(); await response; return value;
  };
  const completion = f.controller.complete(operationId, newPassword);
  const rejected = assert.rejects(completion, (error: unknown) => error instanceof PasswordChangeClientError && error.code === 'CANCELLED');
  await requested;
  await f.controller.forgetDevice({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId });
  await f.devices.forget(f.workspaceId, f.accountId, f.deviceId);
  releaseResponse(); await rejected;
  assert.equal(await f.changes.get(operationId), undefined);
  assert.equal(await f.devices.getStaged(operationId), undefined);
  assert.equal(await f.devices.get(f.deviceContext), undefined);
  assert.equal((await f.admin.control.query('SELECT credential_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2',
    [f.workspaceId, f.accountId])).rows[0].credential_generation, '1');
});

test('CP04: Forget deletes password draft copies by identity even when ciphertext is malformed', async (t) => {
  const f = await passwordFixture(t), operationId = await f.draft();
  const pending = (await f.changes.get(operationId))!, corruptId = randomUUID(), unrelatedId = randomUUID();
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = f.factory.open(f.changeStoreName, 1);
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  });
  t.after(() => database.close());
  const corrupt = { ...pending, reference: { ...pending.reference, operationId: corruptId }, draft: { wrapper: 'broken ciphertext' } };
  const unrelated = { ...corrupt, reference: { ...pending.reference, operationId: unrelatedId },
    status: { binding: { workspaceId: f.workspaceId, accountId: randomUUID(), deviceId: f.deviceId } } };
  await new Promise<void>((resolve, reject) => {
    const transaction = database.transaction('changes', 'readwrite');
    transaction.objectStore('changes').put(corrupt); transaction.objectStore('changes').put(unrelated);
    transaction.oncomplete = () => resolve(); transaction.onabort = () => reject(transaction.error);
  });
  await f.controller.forgetDevice({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId });
  const remaining = await new Promise<unknown[]>((resolve, reject) => {
    const request = database.transaction('changes', 'readonly').objectStore('changes').getAll();
    request.onsuccess = () => resolve(request.result as unknown[]); request.onerror = () => reject(request.error);
  });
  assert.deepEqual(remaining, [unrelated]);
});

test('CP04: malformed password-change counters reject without throwing during request validation', () => {
  const valid = { version: 1, origin: 'https://ukda.example', workspaceId: randomUUID(), accountId: randomUUID(),
    operationId: randomUUID(), deviceId: randomUUID(), keyGeneration: '1', credentialGeneration: '1', nextCredentialGeneration: '2',
    sessionGeneration: '1', nextSessionGeneration: '2', dataGeneration: '1', securityVersion: '1', nextSecurityVersion: '2',
    securityHead: 'a'.repeat(64), ownershipVersion: '1', custodyEpoch: '1', signingPublicKey: randomBytes(32).toString('base64url'),
    recipientPublicKey: randomBytes(32).toString('base64url'), issuedAt: '2026-09-25T12:00:00.000Z', expiresAt: '2026-09-25T12:15:00.000Z' };
  assert.equal(passwordChangeBinding.safeParse(valid).success, true);
  for (const field of ['credentialGeneration', 'nextCredentialGeneration', 'sessionGeneration', 'nextSessionGeneration', 'securityVersion', 'nextSecurityVersion']) {
    for (const value of ['invalid', '', '0', '-1', '1.5', '9223372036854775808']) {
      assert.doesNotThrow(() => assert.equal(passwordChangeBinding.safeParse({ ...valid, [field]: value }).success, false));
    }
  }
});

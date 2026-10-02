import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomUUID } from 'node:crypto';
import { transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { RecoveryService } from '../src/modules/identity/recovery.js';
import { finishLogin, finishRegistration, startLogin, startRegistration } from '../src/client/opaque.js';
import { newOwnerPhrase, recoveryKeys } from '../src/client/recovery.js';
import { wrapDeviceBundle, unwrapDeviceBundle } from '../src/client/device-store.js';
import { base64urlDecode, base64urlEncode, canonicalJson, decryptContent, digestObject, encryptContent, generateRecipientKeyPair,
  generateSigningKeyPair, openRecipient, randomKey, sealRecipient, signObject, verifyObject } from '../src/shared/crypto.js';
import { recoveryConfirmationFor, recoveryRecipientHeader, type RecoveryApproval, type RecoveryBinding, type RecoveryDraft,
  type RecoveryReference, type RecoveryTranscript } from '../src/shared/recovery.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { passwordFixture, origin, oldPassword, newPassword } from './password-change-fixture.js';

const hasCode = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;
async function fixture(t: TestContext) {
  let f: Awaited<ReturnType<typeof passwordFixture>>;
  // Cross-profile approver foreign keys are intentionally not cascade deletes.
  t.after(async () => { if (f) await f.admin.control.query('DELETE FROM security.ceremonies WHERE workspace_id=$1', [f.workspaceId]); });
  f = await passwordFixture(t);
  let offset = 0, hooks: NonNullable<ConstructorParameters<typeof RecoveryService>[0]['hooks']> = {};
  let service = new RecoveryService({ ...f, origin, now: () => new Date(Date.now() + offset) });
  const ownerKey = base64urlDecode(f.originalBundle.signingPrivateKey);
  const custody = await openRecipient(f.prepared.payload.objects.deviceCustody, base64urlDecode(f.originalBundle.recipientPrivateKey),
    base64urlDecode(f.originalBundle.signingPublicKey), f.prepared.payload.objects.deviceCustody.header) as { custodyKey: string };
  const manifest = await decryptContent(f.prepared.payload.objects.custody, base64urlDecode(custody.custodyKey),
    base64urlDecode(f.originalBundle.signingPublicKey), f.prepared.payload.objects.custody.header) as { workspaceKeys: { epoch: string; key: string }[] };
  const workspaceKey = base64urlDecode(manifest.workspaceKeys[0]!.key);
  const scopeKeys = new Map<string, { epoch: string; key: string }[]>([[f.workspaceId, manifest.workspaceKeys]]);
  function rebuild() { service = new RecoveryService({ ...f, origin, hooks, now: () => new Date(Date.now() + offset) }); }
  async function phraseStart() {
    const ref = { workspaceId: f.workspaceId, operationId: randomUUID(), resumeToken: f.secrets.token() };
    const challenge = await service.beginPhrase({ ...ref, accountId: f.accountId });
    const keys = await recoveryKeys(f.phrase, f), proof = await signObject(challenge, keys.signing.privateKey);
    const view = await service.provePhrase({ ...ref, proof }); return { ref, challenge, proof, keys, view };
  }
  async function prepare(ref: RecoveryReference, binding: RecoveryBinding, password = newPassword) {
    const client = await startRegistration(password), response = await service.registration({ ...ref, registrationRequest: client.registrationRequest });
    const registered = await finishRegistration({ password, clientRegistrationState: client.clientRegistrationState, registrationResponse: response.registrationResponse, configuration: response.configuration });
    const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair(), deviceId = randomUUID();
    const phrase = binding.isOwner ? await newOwnerPhrase() : null, recovery = phrase ? await recoveryKeys(phrase, { workspaceId: f.workspaceId, accountId: binding.accountId }) : null;
    const bundle = { signingPrivateKey: base64urlEncode(signing.privateKey), recipientPrivateKey: base64urlEncode(recipient.privateKey),
      signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
    const context = { workspaceId: f.workspaceId, accountId: binding.accountId, deviceId, credentialGeneration: binding.nextCredentialGeneration };
    const wrapper = await wrapDeviceBundle(context, bundle, registered.exportKey); assert.deepEqual(await unwrapDeviceBundle(context, wrapper, registered.exportKey), bundle);
    const transcript: RecoveryTranscript = { version: 1, purpose: 'ukda.recovery-transcript.v1', binding,
      device: { id: deviceId, keyGeneration: binding.nextDeviceKeyGeneration, signingPublicKey: bundle.signingPublicKey, recipientPublicKey: bundle.recipientPublicKey },
      recovery: recovery ? { id: randomUUID(), generation: binding.nextRecoveryGeneration, signingPublicKey: base64urlEncode(recovery.signing.publicKey), recipientPublicKey: base64urlEncode(recovery.recipient.publicKey) } : null,
      configuration: response.configuration, registrationRecordHash: await digestObject(registered.registrationRecord), wrapperHash: await digestObject(wrapper) };
    const transcriptDigest = await digestObject(transcript), draft: RecoveryDraft = { transcript, registrationRecord: registered.registrationRecord, recipientConfirmation: null,
      newRecoveryConfirmation: recovery ? await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'new_recovery'), recovery.signing.privateKey) : null };
    const login = await startLogin(password), proof = await service.startProof({ ...ref, draft, startLoginRequest: login.startLoginRequest });
    const finish = await finishLogin({ password, clientLoginState: login.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
    assert.equal(finish.exportKey, registered.exportKey);
    await service.finishProof({ ...ref, proofId: proof.proofId, finishLoginRequest: finish.finishLoginRequest });
    draft.recipientConfirmation = await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'recipient'), signing.privateKey);
    await service.confirm(ref, draft.recipientConfirmation);
    return { draft, signing, recipient, recovery, phrase, wrapper, bundle, registered, proof, finish };
  }
  async function approve(ref: RecoveryReference, pending: Awaited<ReturnType<typeof prepare>>, authorizerKey: Uint8Array, auth?: ReturnType<typeof f.auth>) {
    const { transcript } = pending.draft, binding = transcript.binding, transcriptDigest = await digestObject(transcript);
    const authorizerConfirmation = await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'authorizer'), authorizerKey);
    const reference = auth ? { workspaceId: ref.workspaceId, operationId: ref.operationId } : ref;
    await service.confirm(reference, authorizerConfirmation, auth);
    const sender = binding.authorizer.kind === 'phrase' ? pending.signing.privateKey : authorizerKey;
    const deliveries: RecoveryApproval['deliveries'] = [];
    for (const scope of binding.scopes) {
      const content = scope.mode === 'custody' ? { version: 1, mode: 'custody', custodyEpoch: binding.custodyEpoch, custodyKey: custody.custodyKey,
        manifest: { id: f.prepared.payload.genesis.body.custodyId, digest: await digestObject(f.prepared.payload.objects.custody) } } :
        { version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, keys: scopeKeys.get(scope.scopeId)! };
      deliveries.push({ id: randomUUID(), envelope: await sealRecipient(recoveryRecipientHeader(transcript, transcriptDigest, scope, 'device'), content, sender) });
      if (scope.mode === 'custody') deliveries.push({ id: randomUUID(), envelope: await sealRecipient(recoveryRecipientHeader(transcript, transcriptDigest, scope, 'recovery'), content, sender) });
    }
    const approval: RecoveryApproval = { deliveries, transition: await signObject({ version: 1, purpose: 'ukda.account-recovery.v1' as const,
      transcript, transcriptDigest, recipientConfirmation: pending.draft.recipientConfirmation!, authorizerConfirmation,
      newRecoveryConfirmation: pending.draft.newRecoveryConfirmation, revokeAllDevices: true as const, revokeAllSessions: true as const,
      deliveries: await Promise.all(deliveries.map(async (item) => ({ id: item.id, scope: item.envelope.header.scope, scopeId: item.envelope.header.scopeId,
        keyEpoch: item.envelope.header.keyEpoch, recipientKind: item.envelope.header.recipientKind, recipientId: item.envelope.header.recipientId, digest: await digestObject(item.envelope) }))) }, authorizerKey) };
    const view = await service.stage(reference, approval, auth); return { approval, requestHash: view.requestHash! };
  }
  async function seedProfile(isOwner = false) {
    const accountId = randomUUID(), deviceId = randomUUID(), signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
    const config = await f.opaque.publicConfiguration(f.workspaceId, accountId), reg = await startRegistration(oldPassword);
    const response = await f.opaque.response(f.workspaceId, accountId, reg.registrationRequest);
    const registration = await finishRegistration({ password: oldPassword, clientRegistrationState: reg.clientRegistrationState, registrationResponse: response.registrationResponse, configuration: config });
    const profile = await encryptContent({ ...f.prepared.payload.objects.profile.header, recordId: accountId }, { displayName: isOwner ? 'Second Owner' : 'Member' }, workspaceKey, ownerKey);
    const profileId = randomUUID(), keyId = randomUUID(), recoveryId = randomUUID();
    const phrase = isOwner ? await newOwnerPhrase() : null, recovery = phrase ? await recoveryKeys(phrase, { workspaceId: f.workspaceId, accountId }) : null;
    const baseHeader = { ...f.prepared.payload.objects.deviceCustody.header, recipientAccountId: accountId, recipientId: deviceId, recipientPublicKey: base64urlEncode(recipient.publicKey) };
    const envelope = await sealRecipient(baseHeader, isOwner ? { version: 1, custodyEpoch: '1', custodyKey: custody.custodyKey } :
      { version: 1, mode: 'content', scope: 'workspace', scopeId: f.workspaceId, keyEpoch: '1', keys: manifest.workspaceKeys }, ownerKey);
    const recoveryEnvelope = recovery ? await sealRecipient({ ...baseHeader, recipientId: randomUUID(), recipientKind: 'recovery', recipientPublicKey: base64urlEncode(recovery.recipient.publicKey) }, { version: 1, custodyEpoch: '1', custodyKey: custody.custodyKey }, ownerKey) : null;
    // Seed already-active CP06 identities. This fixture does not claim the later invitation/promotion journey is implemented.
    await transaction(f.admin.control, async (client) => {
      for (const object of [{ id: profileId, kind: 'encrypted_profile', value: profile }, { id: keyId, kind: 'key_envelope', value: envelope },
        ...(recoveryEnvelope ? [{ id: recoveryId, kind: 'key_envelope', value: recoveryEnvelope }] : [])]) await client.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
        VALUES($1,$2,$3,$4,$5,$6,'committed',1)`, [f.workspaceId, object.id, object.kind, await digestObject(object.value), object.value, randomUUID()]);
      await client.query(`INSERT INTO security.profiles(workspace_id,profile_id,state,is_owner,owner_ready_at,profile_object_id,credential_generation,recovery_generation,opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers)
        VALUES($1,$2,'active',$3,$4,$5,1,$6,$7,$8,$9,$10)`, [f.workspaceId, accountId, isOwner, isOwner ? new Date() : null, profileId, isOwner ? 1 : 0, registration.registrationRecord, config.setupId, config.configId, config.identifiers]);
      await client.query(`INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approval_security_version,approved_at)
        VALUES($1,$2,$3,1,$4,$5,'active',1,now())`, [f.workspaceId, deviceId, accountId, signing.publicKey, recipient.publicKey]);
      for (const kind of isOwner ? ['owner', 'device'] : ['membership', 'device']) await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,activated_at)
        VALUES($1,$2,$3,$4,$5,'workspace',1,$6,'active',$7,$8,1,1,now())`, [f.workspaceId, randomUUID(), accountId, kind === 'device' ? deviceId : null, kind, ['read_project'], f.prepared.payload.genesis.body.genesisId, isOwner ? f.prepared.payload.genesis.body.custodyId : keyId]);
      if (recovery) await client.query(`INSERT INTO security.recovery_authorities(workspace_id,profile_id,generation,proof_public_key,recipient_public_key,custody_envelope_object_id,custody_epoch,state,kit_verified_at)
        VALUES($1,$2,1,$3,$4,$5,1,'active',now())`, [f.workspaceId, accountId, recovery.signing.publicKey, recovery.recipient.publicKey, recoveryId]);
    });
    return { accountId, deviceId, signing, recipient, phrase, recovery };
  }
  return { ...f, get service() { return service; }, phraseStart, prepare, approve, seedProfile, ownerKey, workspaceKey, scopeKeys, custodyKey: custody.custodyKey,
    advance(ms: number) { offset += ms; }, setHooks(value: typeof hooks) { hooks = value; rebuild(); } };
}

test('Owner phrase recovery replaces credentials and phrase, retires devices, preserves encrypted history and admits fresh approved delivery', async (t) => {
  const f = await fixture(t), oldSession = f.auth(), started = await f.phraseStart();
  const materials = await f.service.materials(started.ref); assert.ok(materials.some((item) => item.kind === 'custody_manifest'));
  const pending = await f.prepare(started.ref, started.view.binding!), approved = await f.approve(started.ref, pending, started.keys.signing.privateKey);
  async function assertProviderHasNoPlaintext() {
    const snapshots: unknown[] = [];
    for (const table of ['ceremonies', 'staged_objects', 'operation_receipts', 'profiles']) snapshots.push((await f.admin.control.query(`SELECT * FROM security.${table} WHERE workspace_id=$1`, [f.workspaceId])).rows);
    for (const table of ['workspaces', 'profiles']) snapshots.push((await f.admin.application.query(`SELECT * FROM app.${table} WHERE workspace_id=$1`, [f.workspaceId])).rows);
    const stored = JSON.stringify(snapshots);
    const forbidden = [oldPassword, newPassword, f.phrase, pending.phrase!, f.registered.exportKey, pending.registered.exportKey,
      f.originalBundle.signingPrivateKey, f.originalBundle.recipientPrivateKey, pending.bundle.signingPrivateKey, pending.bundle.recipientPrivateKey,
      base64urlEncode(started.keys.signing.privateKey), base64urlEncode(started.keys.recipient.privateKey),
      base64urlEncode(pending.recovery!.signing.privateKey), base64urlEncode(pending.recovery!.recipient.privateKey),
      base64urlEncode(f.workspaceKey), f.custodyKey, 'Password fixture Owner', 'Password fixture workspace'];
    // Never include scanned rows or secret values in failure diagnostics.
    assert.ok(forbidden.every((secret) => !stored.includes(secret)), 'Provider-visible rows must contain no customer plaintext or private key material');
  }
  await assertProviderHasNoPlaintext();
  const result = await f.service.finalize({ ...started.ref, requestHash: approved.requestHash }); assert.equal(result.state, 'completed');
  await assertProviderHasNoPlaintext();
  assert.equal(canonicalJson((await f.service.finalize({ ...started.ref, requestHash: approved.requestHash })).receipt), canonicalJson(result.receipt));
  assert.equal((await f.service.status(started.ref)).receipt?.securityHead, result.receipt.securityHead);
  await assert.rejects(f.sessions.authenticate(oldSession.cookieValue));
  assert.equal((await f.admin.control.query('SELECT count(*)::int count FROM security.recovery_authorities WHERE workspace_id=$1 AND state=\'active\'', [f.workspaceId])).rows[0].count, 1);
  const states = (await f.admin.control.query('SELECT generation,state FROM security.recovery_authorities WHERE workspace_id=$1 ORDER BY generation', [f.workspaceId])).rows;
  assert.deepEqual(states, [{ generation: '1', state: 'revoked' }, { generation: '2', state: 'active' }]);
  const history = await verifySecurityHistory({ workspaceId: f.workspaceId, origin, genesisFingerprint: await digestObject(f.prepared.payload.genesis),
    genesis: f.prepared.payload.genesis, transitions: [result.receipt.transition], expected: { securityHead: result.receipt.securityHead, securityVersion: result.receipt.securityVersion } });
  assert.equal(history.devices[f.deviceId]?.active, false); assert.equal(history.devices[pending.draft.transcript.device.id]?.active, true);
  assert.equal(await verifyObject(f.prepared.payload.genesis, base64urlDecode(f.originalBundle.signingPublicKey), 'ukda.genesis.v1'), true);
  const record = (await f.admin.control.query('SELECT versioned_object FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [f.workspaceId, f.workspaceId])).rows[0].versioned_object;
  assert.equal(canonicalJson(record), canonicalJson(f.prepared.payload.objects.workspace));
  const client = await startLogin(newPassword), login = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId: f.accountId, startLoginRequest: client.startLoginRequest });
  const finished = await finishLogin({ password: newPassword, clientLoginState: client.clientLoginState, loginResponse: login.loginResponse, configuration: login.configuration });
  const restricted = await f.authentication.finishLogin({ loginId: login.loginId, finishLoginRequest: finished.finishLoginRequest });
  await assert.rejects(f.service.delivery(restricted.cookieValue, started.ref.operationId));
  const challenge = await f.sessions.beginDeviceChallenge(restricted.cookieValue, restricted.csrfToken, pending.draft.transcript.device.id);
  const approvedSession = await f.sessions.completeDeviceChallenge(restricted.cookieValue, restricted.csrfToken, await signObject(challenge, pending.signing.privateKey));
  const delivery = await f.service.delivery(approvedSession.cookieValue, started.ref.operationId);
  const envelope = delivery.deliveries.find((item) => item.envelope.header.recipientKind === 'device')!.envelope;
  assert.ok(await openRecipient(envelope, pending.recipient.privateKey, pending.signing.publicKey, envelope.header));
  const oldPhraseRef = { workspaceId: f.workspaceId, operationId: randomUUID(), resumeToken: f.secrets.token() };
  const newChallenge = await f.service.beginPhrase({ ...oldPhraseRef, accountId: f.accountId });
  await assert.rejects(f.service.provePhrase({ ...oldPhraseRef, proof: await signObject(newChallenge, started.keys.signing.privateKey) }), hasCode('RECOVERY_INVALID'));
});

test('RESET replacement, one-holder redemption retry, explicit revocation and expiry retain the working password', async (t) => {
  const f = await fixture(t), member = await f.seedProfile();
  const issue = () => f.service.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: member.accountId, resetId: randomUUID() });
  const first = await issue(), second = await issue(), resumeToken = f.secrets.token();
  await assert.rejects(f.service.beginReset({ workspaceId: f.workspaceId, code: first.code, resumeToken }), hasCode('RECOVERY_INVALID'));
  const view = await f.service.beginReset({ workspaceId: f.workspaceId, code: second.code, resumeToken }); assert.equal(view.operationId, second.resetId);
  assert.equal((await f.service.beginReset({ workspaceId: f.workspaceId, code: second.code, resumeToken })).operationId, view.operationId);
  await assert.rejects(f.service.beginReset({ workspaceId: f.workspaceId, code: second.code, resumeToken: f.secrets.token() }), hasCode('RECOVERY_INVALID'));
  await f.service.revokeReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, resetId: second.resetId });
  await assert.rejects(f.service.beginReset({ workspaceId: f.workspaceId, code: second.code, resumeToken }), hasCode('RECOVERY_INVALID'));
  const third = await issue(); f.advance(900_001);
  await assert.rejects(f.service.beginReset({ workspaceId: f.workspaceId, code: third.code, resumeToken }), hasCode('RECOVERY_INVALID'));
  assert.equal((await f.admin.control.query('SELECT credential_generation,session_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, member.accountId])).rows[0].credential_generation, '1');
  const client = await startLogin(oldPassword), result = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId: member.accountId, startLoginRequest: client.startLoginRequest });
  assert.ok(await finishLogin({ password: oldPassword, clientLoginState: client.clientLoginState, loginResponse: result.loginResponse, configuration: result.configuration }));
});

test('Owner-assisted member recovery works with restricted entitlement, preserves membership and grants no recovery authority', async (t) => {
  const f = await fixture(t), member = await f.seedProfile();
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='restricted',content_maintenance=true,restore_quarantine=true WHERE workspace_id=$1", [f.workspaceId]);
  const issued = await f.service.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: member.accountId, resetId: randomUUID() });
  const ref = { workspaceId: f.workspaceId, operationId: issued.resetId, resumeToken: f.secrets.token() };
  await f.service.beginReset({ workspaceId: f.workspaceId, code: issued.code, resumeToken: ref.resumeToken });
  const view = await f.service.claim({ workspaceId: f.workspaceId, operationId: ref.operationId }, f.auth());
  assert.equal(view.binding!.isOwner, false); assert.equal(view.binding!.currentRecovery, null);
  await assert.rejects(f.service.materials(ref), hasCode('RECOVERY_FORBIDDEN'));
  const pending = await f.prepare(ref, view.binding!), approved = await f.approve(ref, pending, f.ownerKey, f.auth());
  const result = await f.service.finalize({ workspaceId: f.workspaceId, operationId: ref.operationId, requestHash: approved.requestHash }, f.auth());
  assert.equal(result.state, 'completed'); assert.equal(result.receipt.recoveryGeneration, '0');
  assert.equal((await f.admin.control.query('SELECT is_owner,state,credential_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, member.accountId])).rows[0].is_owner, false);
  assert.equal((await f.admin.control.query('SELECT count(*)::int count FROM security.recovery_authorities WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, member.accountId])).rows[0].count, 0);
  assert.equal((await f.admin.control.query("SELECT count(*)::int count FROM security.grants WHERE workspace_id=$1 AND profile_id=$2 AND state='active' AND grant_kind='owner'", [f.workspaceId, member.accountId])).rows[0].count, 0);
  const flags = (await f.admin.control.query('SELECT licence_state,content_maintenance,restore_quarantine FROM security.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0];
  assert.deepEqual(flags, { licence_state: 'restricted', content_maintenance: true, restore_quarantine: true });
});

test('An equal Owner can restore another Owner only with a fresh individual recovery authority', async (t) => {
  const f = await fixture(t), target = await f.seedProfile(true);
  const issued = await f.service.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: target.accountId, resetId: randomUUID() });
  const ref = { workspaceId: f.workspaceId, operationId: issued.resetId, resumeToken: f.secrets.token() };
  await f.service.beginReset({ workspaceId: f.workspaceId, code: issued.code, resumeToken: ref.resumeToken });
  const view = await f.service.claim({ workspaceId: f.workspaceId, operationId: ref.operationId }, f.auth());
  const pending = await f.prepare(ref, view.binding!), approved = await f.approve(ref, pending, f.ownerKey, f.auth());
  assert.ok(pending.phrase && pending.phrase !== target.phrase);
  const result = await f.service.finalize({ workspaceId: f.workspaceId, operationId: ref.operationId, requestHash: approved.requestHash }, f.auth());
  assert.equal(result.state, 'completed'); assert.equal(result.receipt.recoveryGeneration, '2');
  const owners = (await f.admin.control.query("SELECT count(*)::int count FROM security.profiles WHERE workspace_id=$1 AND state='active' AND is_owner", [f.workspaceId])).rows[0].count;
  assert.equal(owners, 2); assert.equal(await f.sessions.authenticate(f.auth().cookieValue).then(() => true), true);
});

test('CP06: RESET recovery restores a member after their last device is revoked without recreating personal membership', async (t) => {
  const f = await fixture(t), member = await f.seedProfile();
  const oldSession = await transaction(f.databases.control, (client) => f.sessions.issue(client, { workspaceId: f.workspaceId, profileId: member.accountId,
    credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1', accessLevel: 'device_approved', deviceId: member.deviceId }));
  const membership = (await f.admin.control.query("SELECT * FROM security.grants WHERE workspace_id=$1 AND profile_id=$2 AND grant_kind='membership'", [f.workspaceId, member.accountId])).rows[0];
  await transaction(f.admin.control, async (client) => {
    await client.query("UPDATE security.devices SET state='revoked',revoked_at=now() WHERE workspace_id=$1 AND profile_id=$2", [f.workspaceId, member.accountId]);
    await client.query("UPDATE security.grants SET state='revoked',revoked_at=now() WHERE workspace_id=$1 AND profile_id=$2 AND device_id IS NOT NULL", [f.workspaceId, member.accountId]);
  });
  await assert.rejects(f.sessions.authenticate(oldSession.cookieValue, { approved: true }), hasCode('DEVICE_APPROVAL_REQUIRED'));
  const issued = await f.service.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: member.accountId, resetId: randomUUID() });
  const ref = { workspaceId: f.workspaceId, operationId: issued.resetId, resumeToken: f.secrets.token() };
  await f.service.beginReset({ workspaceId: f.workspaceId, code: issued.code, resumeToken: ref.resumeToken });
  const view = await f.service.claim({ workspaceId: ref.workspaceId, operationId: ref.operationId }, f.auth());
  assert.deepEqual(view.binding!.scopes[0]!.sources.map((source) => source.grantId), [membership.grant_id]);
  const pending = await f.prepare(ref, view.binding!), approval = await f.approve(ref, pending, f.ownerKey, f.auth());
  await f.service.finalize({ workspaceId: ref.workspaceId, operationId: ref.operationId, requestHash: approval.requestHash }, f.auth());
  assert.deepEqual((await f.admin.control.query('SELECT * FROM security.grants WHERE workspace_id=$1 AND grant_id=$2', [f.workspaceId, membership.grant_id])).rows[0], membership);
  const login = await startLogin(newPassword), response = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId: member.accountId, startLoginRequest: login.startLoginRequest });
  const proof = await finishLogin({ password: newPassword, clientLoginState: login.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration });
  const restricted = await f.authentication.finishLogin({ loginId: response.loginId, finishLoginRequest: proof.finishLoginRequest });
  const challenge = await f.sessions.beginDeviceChallenge(restricted.cookieValue, restricted.csrfToken, pending.draft.transcript.device.id);
  const session = await f.sessions.completeDeviceChallenge(restricted.cookieValue, restricted.csrfToken, await signObject(challenge, pending.signing.privateKey));
  const delivery = await f.service.delivery(session.cookieValue, ref.operationId), envelope = delivery.deliveries[0]!.envelope;
  const payload = await openRecipient(envelope, pending.recipient.privateKey, base64urlDecode(f.originalBundle.signingPublicKey), envelope.header) as { mode: string; keys: { epoch: string; key: string }[] };
  assert.equal(payload.mode, 'content'); assert.equal(payload.keys[0]!.key, base64urlEncode(f.workspaceKey));
  assert.equal((await f.admin.control.query("SELECT count(*)::int count FROM security.devices WHERE workspace_id=$1 AND profile_id=$2 AND state='active'", [f.workspaceId, member.accountId])).rows[0].count, 1);
});

test('Failed phrase proofs are consumed and expired unproved challenges stop occupying the five-attempt budget after two minutes', async (t) => {
  const f = await fixture(t), refs = Array.from({ length: 5 }, () => ({ workspaceId: f.workspaceId, operationId: randomUUID(), resumeToken: f.secrets.token() }));
  const challenges = await Promise.all(refs.map((ref) => f.service.beginPhrase({ ...ref, accountId: f.accountId })));
  const sixth = { workspaceId: f.workspaceId, operationId: randomUUID(), resumeToken: f.secrets.token() };
  await assert.rejects(f.service.beginPhrase({ ...sixth, accountId: f.accountId }), hasCode('RATE_LIMITED'));
  const wrong = await generateSigningKeyPair();
  await assert.rejects(f.service.provePhrase({ ...refs[0]!, proof: await signObject(challenges[0]!, wrong.privateKey) }), hasCode('RECOVERY_INVALID'));
  const recovery = await recoveryKeys(f.phrase, f);
  await assert.rejects(f.service.provePhrase({ ...refs[0]!, proof: await signObject(challenges[0]!, recovery.signing.privateKey) }), hasCode('RECOVERY_INVALID'));
  f.advance(120_001);
  assert.ok(await f.service.beginPhrase({ ...sixth, accountId: f.accountId }));
  await assert.rejects(f.service.provePhrase({ ...refs[1]!, proof: await signObject(challenges[1]!, recovery.signing.privateKey) }), hasCode('RECOVERY_INVALID'));
});

test('Tampered confirmations and password-proof replay cannot authorize a new device or release recovery material', async (t) => {
  const f = await fixture(t), started = await f.phraseStart(), pending = await f.prepare(started.ref, started.view.binding!);
  await assert.rejects(f.service.finishProof({ ...started.ref, proofId: pending.proof.proofId, finishLoginRequest: pending.finish.finishLoginRequest }), hasCode('RECOVERY_INVALID'));
  const changed = { ...pending.draft.recipientConfirmation!, body: { ...pending.draft.recipientConfirmation!.body, transcriptDigest: 'f'.repeat(64) } };
  await assert.rejects(f.service.confirm(started.ref, changed), hasCode('RECOVERY_INVALID'));
  await assert.rejects(f.service.materials(started.ref), hasCode('RECOVERY_INVALID'));
  assert.equal((await f.admin.control.query('SELECT credential_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.accountId])).rows[0].credential_generation, '1');
});

test('A replacement RESET invalidates a staged recovery; a suspended member cannot be restored or promoted', async (t) => {
  const f = await fixture(t), target = await f.seedProfile();
  const issued = await f.service.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: target.accountId, resetId: randomUUID() });
  const ref = { workspaceId: f.workspaceId, operationId: issued.resetId, resumeToken: f.secrets.token() };
  await f.service.beginReset({ workspaceId: f.workspaceId, code: issued.code, resumeToken: ref.resumeToken });
  const view = await f.service.claim({ workspaceId: f.workspaceId, operationId: ref.operationId }, f.auth());
  const pending = await f.prepare(ref, view.binding!), approved = await f.approve(ref, pending, f.ownerKey, f.auth());
  await f.service.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: target.accountId, resetId: randomUUID() });
  await assert.rejects(f.service.finalize({ workspaceId: f.workspaceId, operationId: ref.operationId, requestHash: approved.requestHash }, f.auth()), hasCode('RECOVERY_INVALID'));
  await f.admin.control.query("UPDATE security.profiles SET state='suspended' WHERE workspace_id=$1 AND profile_id=$2", [f.workspaceId, target.accountId]);
  await assert.rejects(f.service.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: target.accountId, resetId: randomUUID() }), hasCode('RECOVERY_INVALID'));
  const row = (await f.admin.control.query('SELECT state,is_owner,credential_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, target.accountId])).rows[0];
  assert.deepEqual(row, { state: 'suspended', is_owner: false, credential_generation: '1' });
});

test('Removing the approving Owner or changing the security head prevents a previously staged recovery from committing', async (t) => {
  const f = await fixture(t), target = await f.seedProfile();
  const issued = await f.service.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: target.accountId, resetId: randomUUID() });
  const ref = { workspaceId: f.workspaceId, operationId: issued.resetId, resumeToken: f.secrets.token() };
  await f.service.beginReset({ workspaceId: f.workspaceId, code: issued.code, resumeToken: ref.resumeToken });
  const view = await f.service.claim({ workspaceId: f.workspaceId, operationId: ref.operationId }, f.auth());
  const pending = await f.prepare(ref, view.binding!), approved = await f.approve(ref, pending, f.ownerKey, f.auth());
  await f.admin.control.query("UPDATE security.profiles SET state='suspended' WHERE workspace_id=$1 AND profile_id=$2", [f.workspaceId, f.accountId]);
  await assert.rejects(f.service.finalize({ workspaceId: f.workspaceId, operationId: ref.operationId, requestHash: approved.requestHash }, f.auth()));
  assert.equal((await f.admin.control.query('SELECT credential_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, target.accountId])).rows[0].credential_generation, '1');
  await f.admin.control.query("UPDATE security.profiles SET state='active' WHERE workspace_id=$1 AND profile_id=$2", [f.workspaceId, f.accountId]);
  await f.admin.control.query('UPDATE security.workspaces SET security_version=security_version+1,security_head=$2 WHERE workspace_id=$1', [f.workspaceId, 'd'.repeat(64)]);
  await assert.rejects(f.service.finalize({ workspaceId: f.workspaceId, operationId: ref.operationId, requestHash: approved.requestHash }, f.auth()), hasCode('RECOVERY_CHANGED'));
});

test('Recovery failure before control commit keeps old authority; a lost committed response resolves one durable receipt and reopens projection', async (t) => {
  const f = await fixture(t), started = await f.phraseStart(), pending = await f.prepare(started.ref, started.view.binding!), approved = await f.approve(started.ref, pending, started.keys.signing.privateKey);
  f.setHooks({ beforeControlCommit: async () => { throw new Error('Injected transaction failure'); } });
  await assert.rejects(f.service.finalize({ ...started.ref, requestHash: approved.requestHash }), hasCode('RECOVERY_UNAVAILABLE'));
  assert.equal((await f.admin.control.query('SELECT credential_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.accountId])).rows[0].credential_generation, '1');
  assert.ok(await f.sessions.authenticate(f.auth().cookieValue));
  f.setHooks({ afterControlCommit: async () => { throw new Error('Injected response loss'); } });
  await assert.rejects(f.service.finalize({ ...started.ref, requestHash: approved.requestHash }), /Injected response loss/);
  assert.equal((await f.admin.control.query("SELECT count(*)::int count FROM security.operation_receipts WHERE workspace_id=$1 AND operation_kind='account.recover'", [f.workspaceId])).rows[0].count, 1);
  f.setHooks({ beforeProjection: async () => { throw new Error('Injected projection failure'); } });
  assert.equal((await f.service.status(started.ref)).state, 'finishing');
  f.setHooks({}); const status = await f.service.status(started.ref); assert.equal(status.state, 'completed');
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].fence_closed, false);
  assert.equal((await f.service.finalize({ ...started.ref, requestHash: approved.requestHash })).receipt.securityHead, status.receipt!.securityHead);
});

test('Recovery restores current project permissions and retained key epochs while excluding a revoked project', async (t) => {
  const f = await fixture(t), member = await f.seedProfile();
  async function seedProject(active: boolean) {
    const projectId = randomUUID(), manifestId = randomUUID(), grantId = randomUUID();
    const keys = [{ epoch: '1', key: base64urlEncode(await randomKey()) }, { epoch: '2', key: base64urlEncode(await randomKey()) }];
    f.scopeKeys.set(projectId, keys);
    const envelope = await sealRecipient({ ...f.prepared.payload.objects.deviceCustody.header, scope: 'project', scopeId: projectId, keyEpoch: '2',
      recipientAccountId: member.accountId, recipientId: member.deviceId, recipientPublicKey: base64urlEncode(member.recipient.publicKey) },
      { version: 1, mode: 'content', scope: 'project', scopeId: projectId, keyEpoch: '2', keys }, f.ownerKey);
    await transaction(f.admin.control, async (client) => {
      await client.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
        VALUES($1,$2,'key_envelope',$3,$4,$5,'committed',1)`, [f.workspaceId, manifestId, await digestObject(envelope), envelope, randomUUID()]);
      await client.query(`INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version)
        VALUES($1,'project',$2,2,$3,1)`, [f.workspaceId, projectId, manifestId]);
      await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,scope_id,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,activated_at,revoked_at)
        VALUES($1,$2,$3,'project','project',$4,1,ARRAY['read_project','comment']::text[],$5,$6,$7,2,1,now(),$8)`,
        [f.workspaceId, grantId, member.accountId, projectId, active ? 'active' : 'revoked', f.prepared.payload.genesis.body.genesisId, manifestId, active ? null : new Date()]);
    });
    const records = await Promise.all(keys.map((key) => encryptContent({ ...f.prepared.payload.objects.profile.header, scope: 'project', scopeId: projectId,
      recordId: randomUUID(), recordType: 'task', keyEpoch: key.epoch }, { title: `retained-epoch-${key.epoch}` }, base64urlDecode(key.key), f.ownerKey)));
    return { projectId, manifestId, grantId, keys, records };
  }
  const eligible = await seedProject(true), removed = await seedProject(false);
  const issued = await f.service.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: member.accountId, resetId: randomUUID() });
  const ref = { workspaceId: f.workspaceId, operationId: issued.resetId, resumeToken: f.secrets.token() };
  await f.service.beginReset({ workspaceId: f.workspaceId, code: issued.code, resumeToken: ref.resumeToken });
  const view = await f.service.claim({ workspaceId: ref.workspaceId, operationId: ref.operationId }, f.auth());
  assert.equal(view.binding!.scopes.length, 2);
  assert.equal(view.binding!.scopes.find((scope) => scope.scope === 'project')?.scopeId, eligible.projectId);
  assert.equal(view.binding!.scopes.find((scope) => scope.scope === 'project')?.keyEpoch, '2');
  const materials = await f.service.materials({ workspaceId: ref.workspaceId, operationId: ref.operationId }, f.auth());
  assert.ok(materials.some((item) => item.id === eligible.manifestId)); assert.ok(!materials.some((item) => item.id === removed.manifestId));
  const pending = await f.prepare(ref, view.binding!), approval = await f.approve(ref, pending, f.ownerKey, f.auth());
  await f.service.finalize({ workspaceId: ref.workspaceId, operationId: ref.operationId, requestHash: approval.requestHash }, f.auth());
  const activeProjectGrants = (await f.admin.control.query("SELECT device_id,key_epoch FROM security.grants WHERE workspace_id=$1 AND profile_id=$2 AND scope_id=$3 AND state='active'", [f.workspaceId, member.accountId, eligible.projectId])).rows;
  assert.equal(activeProjectGrants.length, 2); assert.ok(activeProjectGrants.every((grant) => grant.key_epoch === '2'));
  assert.equal(activeProjectGrants.filter((grant) => grant.device_id === null).length, 1);
  // The trusted auth fixture issues only after the full OPAQUE proof above; SessionService still checks the committed generation/device grant.
  const session = await transaction(f.databases.control, (client) => f.sessions.issue(client, { workspaceId: f.workspaceId, profileId: member.accountId,
    credentialGeneration: '2', sessionGeneration: '2', dataGeneration: '1', accessLevel: 'device_approved', deviceId: pending.draft.transcript.device.id }));
  const delivered = await f.service.delivery(session.cookieValue, ref.operationId);
  const envelope = delivered.deliveries.find((entry) => entry.envelope.header.scopeId === eligible.projectId)!.envelope;
  const payload = await openRecipient(envelope, pending.recipient.privateKey, base64urlDecode(f.originalBundle.signingPublicKey), envelope.header) as { keys: { epoch: string; key: string }[] };
  assert.equal(canonicalJson(payload.keys), canonicalJson(eligible.keys));
  for (const [index, record] of eligible.records.entries()) assert.equal((await decryptContent(record, base64urlDecode(payload.keys[index]!.key), base64urlDecode(f.originalBundle.signingPublicKey), record.header) as { title: string }).title, `retained-epoch-${index + 1}`);
  assert.ok(!delivered.deliveries.some((entry) => entry.envelope.header.scopeId === removed.projectId));
  assert.equal((await f.admin.control.query('SELECT state FROM security.grants WHERE workspace_id=$1 AND grant_id=$2', [f.workspaceId, removed.grantId])).rows[0].state, 'revoked');
  assert.equal((await f.admin.control.query("SELECT count(*)::int count FROM security.grants WHERE workspace_id=$1 AND profile_id=$2 AND scope_id=$3 AND state='active'", [f.workspaceId, member.accountId, removed.projectId])).rows[0].count, 0);
});

test('Resolved target budgets apply before reset/phrase mutation and history reads, independent of caller-supplied operation identifiers', async (t) => {
  const f = await fixture(t), target = await f.seedProfile(), charged: { workspaceId: string; accountId: string; history: boolean }[] = [];
  const limited = new RecoveryService({ ...f, origin, requestBudget: async (scope) => { charged.push(scope); throw new AppError('RATE_LIMITED', 'Try again later', 429); } });
  await assert.rejects(limited.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: target.accountId, resetId: randomUUID() }), hasCode('RATE_LIMITED'));
  assert.equal((await f.admin.control.query('SELECT reset_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, target.accountId])).rows[0].reset_generation, '0');
  const issued = await f.service.issueReset(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId: target.accountId, resetId: randomUUID() });
  await assert.rejects(limited.beginReset({ workspaceId: f.workspaceId, code: issued.code, resumeToken: f.secrets.token() }), hasCode('RATE_LIMITED'));
  assert.equal((await f.admin.control.query('SELECT public_state FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [f.workspaceId, issued.resetId])).rows[0].public_state.redeemedAt, undefined);
  const phraseRef = { workspaceId: f.workspaceId, operationId: randomUUID(), resumeToken: f.secrets.token() };
  await assert.rejects(limited.beginPhrase({ ...phraseRef, accountId: f.accountId }), hasCode('RATE_LIMITED'));
  assert.equal((await f.admin.control.query('SELECT count(*)::int count FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [f.workspaceId, phraseRef.operationId])).rows[0].count, 0);
  const started = await f.phraseStart(); let callbackCalled = false;
  await assert.rejects(limited.withAuthorizedHistory(started.ref, undefined, async () => { callbackCalled = true; }), hasCode('RATE_LIMITED'));
  assert.equal(callbackCalled, false);
  assert.deepEqual(charged, [
    { workspaceId: f.workspaceId, accountId: target.accountId, history: false },
    { workspaceId: f.workspaceId, accountId: target.accountId, history: false },
    { workspaceId: f.workspaceId, accountId: f.accountId, history: false },
    { workspaceId: f.workspaceId, accountId: f.accountId, history: true },
  ]);
});

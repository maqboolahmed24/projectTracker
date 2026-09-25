import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { EnrolmentService } from '../src/modules/identity/enrolment.js';
import { PairingService } from '../src/modules/identity/pairing.js';
import { startRegistration, finishRegistration, startLogin, finishLogin } from '../src/client/opaque.js';
import { newOwnerPhrase, recoveryKeys } from '../src/client/recovery.js';
import { unwrapDeviceBundle, wrapDeviceBundle, type DeviceBundle } from '../src/client/device-store.js';
import { prepareJoinEnrolment, preparePromotionEnrolment, rebindJoinEnrolment, confirmEnrolmentRecipient, confirmEnrolmentAuthorizer,
  encryptEnrolmentProfile, enrolmentDeviceContext, type PreparedEnrolment, type NewEnrolmentOwnerKit } from '../src/client/enrolment-crypto.js';
import { base64urlDecode, base64urlEncode, digestObject, decryptContent, encryptContent, generateRecipientKeyPair, generateSigningKeyPair, openRecipient, sealRecipient, signObject } from '../src/shared/crypto.js';
import { enrolmentRecipientHeader, enrolmentRecipientDevices, type EnrolmentApproval, type EnrolmentBinding, type EnrolmentReference } from '../src/shared/enrolment.js';
import type { EnrolmentAuth } from '../src/shared/enrolment-api.js';
import { pairingConfirmationFor, pairingRecipientHeader, type PairingApproval } from '../src/shared/pairing.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { passwordFixture, origin, newPassword } from './password-change-fixture.js';
const code = (expected: string) => (e: unknown) => e instanceof AppError && e.code === expected;
const password = newPassword;
async function kit(): Promise<NewEnrolmentOwnerKit> { const phrase = await newOwnerPhrase(), positions = [2, 8, 20]; return { phrase, positions, answers: positions.map((n) => phrase.split(' ')[n]!) }; }
async function fixture(t: TestContext) {
  let f: Awaited<ReturnType<typeof passwordFixture>>;
  t.after(async () => { if (f) await f.admin.control.query('DELETE FROM security.ceremonies WHERE workspace_id=$1', [f.workspaceId]); });
  f = await passwordFixture(t); let offset = 0, hooks: NonNullable<ConstructorParameters<typeof EnrolmentService>[0]['hooks']> = {};
  let service = new EnrolmentService({ ...f, origin, now: () => new Date(Date.now() + offset), hooks });
  const custody = await openRecipient(f.prepared.payload.objects.deviceCustody, base64urlDecode(f.originalBundle.recipientPrivateKey), base64urlDecode(f.originalBundle.signingPublicKey), f.prepared.payload.objects.deviceCustody.header) as { custodyKey: string };
  const manifest = await decryptContent(f.prepared.payload.objects.custody, base64urlDecode(custody.custodyKey), base64urlDecode(f.originalBundle.signingPublicKey), f.prepared.payload.objects.custody.header) as { workspaceKeys: { epoch: string; key: string }[] };
  const workspaceKey = base64urlDecode(manifest.workspaceKeys[0]!.key);
  async function issue(kind: 'join_member' | 'join_owner' = 'join_member', accountId: string = randomUUID(), auth: EnrolmentAuth = f.auth(), bundle = f.originalBundle) {
    const request = { workspaceId: f.workspaceId, accountId, operationId: randomUUID(), kind, roleId: f.prepared.payload.genesis.body.roles[kind === 'join_member' ? 'member' : 'owner'], projectIds: [] };
    const context = await service.issuanceContext(auth.cookieValue, auth.csrfToken, request);
    const profile = { id: randomUUID(), envelope: await encryptContent(context.header, { displayName: 'Pending private person', invitation: {
      version: 1, kind, role: context.role, workspaceId: f.workspaceId, accountId, operationId: request.operationId,
      projectScope: kind === 'join_owner' ? { mode: 'all_ordinary' } : { mode: 'selected', projectIds: [...request.projectIds].sort() },
    } }, workspaceKey, base64urlDecode(bundle.signingPrivateKey)) };
    const issued = await service.issueJoin(auth.cookieValue, auth.csrfToken, { ...request, profile });
    return { issued, request, profile };
  }
  async function begin(issued: Awaited<ReturnType<typeof issue>>['issued'], auth: EnrolmentAuth = f.auth()) {
    const ref: EnrolmentReference = { workspaceId: f.workspaceId, operationId: issued.operationId, resumeToken: f.secrets.token() };
    await service.begin({ workspaceId: ref.workspaceId, code: issued.code, resumeToken: ref.resumeToken });
    const view = await service.claim({ workspaceId: ref.workspaceId, operationId: ref.operationId }, auth); return { ref, binding: view.binding! };
  }
  async function prove(ref: EnrolmentReference, prepared: PreparedEnrolment, exportKey: string) {
    const login = await startLogin(password), proof = await service.startProof({ ...ref, draft: prepared.draft, startLoginRequest: login.startLoginRequest });
    const finish = await finishLogin({ password, clientLoginState: login.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
    assert.equal(finish.exportKey, exportKey); await service.finishProof({ ...ref, proofId: proof.proofId, finishLoginRequest: finish.finishLoginRequest }); return { proof, finish };
  }
  async function prepare(ref: EnrolmentReference, binding: EnrolmentBinding) {
    const start = await startRegistration(password), response = await service.registration({ ...ref, registrationRequest: start.registrationRequest });
    const registered = await finishRegistration({ password, clientRegistrationState: start.clientRegistrationState, registrationResponse: response.registrationResponse, configuration: response.configuration });
    const newOwnerKit = binding.kind === 'join_owner' ? await kit() : undefined;
    const prepared = await prepareJoinEnrolment({ binding, configuration: response.configuration, registrationRecord: registered.registrationRecord, exportKey: registered.exportKey, displayName: 'Confirmed private person', ...(newOwnerKit ? { newOwnerKit } : {}) }, binding);
    const proven = await prove(ref, prepared, registered.exportKey); return { prepared, registered, newOwnerKit, proven };
  }
  async function approve(ref: EnrolmentReference, prepared: PreparedEnrolment, exportKey: string, auth: EnrolmentAuth = f.auth(), bundle: DeviceBundle = f.originalBundle) {
    const transcript = prepared.draft.transcript, binding = transcript.binding, transcriptDigest = await digestObject(transcript), key = base64urlDecode(bundle.signingPrivateKey);
    prepared.draft.recipientConfirmation = await confirmEnrolmentRecipient({ prepared, exportKey, fingerprint: transcriptDigest }, binding);
    await service.confirm(ref, prepared.draft.recipientConfirmation);
    const { registrationRecord: _record, ...draft } = prepared.draft;
    const authorizerConfirmation = await confirmEnrolmentAuthorizer({ draft, fingerprint: transcriptDigest }, bundle, binding);
    const publicRef = { workspaceId: ref.workspaceId, operationId: ref.operationId }; await service.confirm(publicRef, authorizerConfirmation, auth);
    const deliveries: EnrolmentApproval['deliveries'] = [];
    for (const scope of binding.scopes) {
      const value = scope.mode === 'custody' ? { version: 1, mode: 'custody', custodyEpoch: binding.custodyEpoch, custodyKey: custody.custodyKey,
        manifest: { id: f.prepared.payload.genesis.body.custodyId, digest: await digestObject(f.prepared.payload.objects.custody) } } :
        { version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, keys: manifest.workspaceKeys };
      for (const device of enrolmentRecipientDevices(transcript)) deliveries.push({ id: randomUUID(), envelope: await sealRecipient(enrolmentRecipientHeader(transcript, transcriptDigest, scope, 'device', device.id), value, key) });
      if (scope.mode === 'custody') deliveries.push({ id: randomUUID(), envelope: await sealRecipient(enrolmentRecipientHeader(transcript, transcriptDigest, scope, 'recovery'), value, key) });
    }
    const profile = binding.kind === 'promote_owner' ? null : await encryptEnrolmentProfile({ draft, fingerprint: transcriptDigest }, bundle, workspaceKey, binding);
    const approval: EnrolmentApproval = { profile, deliveries, transition: await signObject({ version: 1 as const, purpose: binding.kind === 'promote_owner' ? 'ukda.owner-promotion.v1' as const : 'ukda.profile-enrolment.v1' as const,
      transcript, transcriptDigest, recipientConfirmation: prepared.draft.recipientConfirmation, authorizerConfirmation, newRecoveryConfirmation: prepared.draft.newRecoveryConfirmation,
      profile: profile ? { id: profile.id, profileId: binding.accountId, revision: binding.nextProfileRevision, digest: await digestObject(profile.envelope) } : null,
      deliveries: await Promise.all(deliveries.map(async (d) => ({ id: d.id, scope: d.envelope.header.scope, scopeId: d.envelope.header.scopeId, keyEpoch: d.envelope.header.keyEpoch, recipientKind: d.envelope.header.recipientKind, recipientId: d.envelope.header.recipientId, digest: await digestObject(d.envelope) }))) }, key) };
    const staged = await service.stage(publicRef, approval, auth); assert.equal(staged.approvalHash, await digestObject(approval)); return { approval, requestHash: staged.requestHash!, publicRef };
  }
  async function login(prepared: PreparedEnrolment, expectedExport: string) {
    const transcript = prepared.draft.transcript, binding = transcript.binding, start = await startLogin(password);
    const response = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId: binding.accountId, startLoginRequest: start.startLoginRequest });
    const finish = await finishLogin({ password, clientLoginState: start.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration }); assert.equal(finish.exportKey, expectedExport);
    const restricted = await f.authentication.finishLogin({ loginId: response.loginId, finishLoginRequest: finish.finishLoginRequest }), bundle = await unwrapDeviceBundle(enrolmentDeviceContext(transcript), prepared.deviceWrapper, finish.exportKey);
    const challenge = await f.sessions.beginDeviceChallenge(restricted.cookieValue, restricted.csrfToken, transcript.device.id);
    const session = await f.sessions.completeDeviceChallenge(restricted.cookieValue, restricted.csrfToken, await signObject(challenge, base64urlDecode(bundle.signingPrivateKey)));
    return { session, bundle, auth: { cookieValue: session.cookieValue, csrfToken: session.csrfToken } };
  }
  async function joined(kind: 'join_member' | 'join_owner' = 'join_member') { const invitation = await issue(kind), started = await begin(invitation.issued), draft = await prepare(started.ref, started.binding), staged = await approve(started.ref, draft.prepared, draft.registered.exportKey);
    const result = await service.finalize({ ...staged.publicRef, requestHash: staged.requestHash }, f.auth()); return { ...invitation, ...started, ...draft, ...staged, result, ...await login(draft.prepared, draft.registered.exportKey) }; }
  return { ...f, get enrolment() { return service; }, issue, begin, prepare, prove, approve, login, joined, workspaceKey, custody, manifest,
    advance(ms: number) { offset += ms; }, setHooks(nextHooks: typeof hooks) { hooks = nextHooks; service = new EnrolmentService({ ...f, origin, hooks, now: () => new Date(Date.now() + offset) }); } };
}

test('CP06: named member JOIN proves its password, commits once, preserves privacy and delivers only its encrypted content', async (t) => {
  const f = await fixture(t), invitation = await f.issue(), { ref, binding } = await f.begin(invitation.issued), draft = await f.prepare(ref, binding), staged = await f.approve(ref, draft.prepared, draft.registered.exportKey);
  const results = await Promise.all([1, 2].map(() => f.enrolment.finalize({ ...staged.publicRef, requestHash: staged.requestHash }, f.auth())));
  assert.equal(results[0]!.state, 'completed'); assert.deepEqual(results[0]!.receipt, results[1]!.receipt);
  assert.equal((await f.enrolment.status(ref)).receipt!.securityHead, results[0]!.receipt.securityHead);
  const logged = await f.login(draft.prepared, draft.registered.exportKey), delivered = await f.enrolment.delivery(logged.session.cookieValue, ref.operationId);
  assert.equal(delivered.deliveries.length, 1); assert.ok(!delivered.materials.some((m) => m.kind === 'custody_manifest'));
  const envelope = delivered.deliveries[0]!.envelope, keys = await openRecipient(envelope, base64urlDecode(logged.bundle.recipientPrivateKey), base64urlDecode(f.originalBundle.signingPublicKey), envelope.header) as { keys: { key: string }[] };
  assert.equal(keys.keys[0]!.key, f.manifest.workspaceKeys[0]!.key);
  const profile = await decryptContent(staged.approval.profile!.envelope, f.workspaceKey, base64urlDecode(f.originalBundle.signingPublicKey), staged.approval.profile!.envelope.header) as { displayName: string };
  assert.deepEqual(Object.keys(profile), ['displayName']); assert.equal(profile.displayName, 'Confirmed private person');
  const history = await verifySecurityHistory({ workspaceId: f.workspaceId, origin, genesisFingerprint: await digestObject(f.prepared.payload.genesis), genesis: f.prepared.payload.genesis, transitions: [results[0]!.receipt.transition], expected: { securityHead: results[0]!.receipt.securityHead, securityVersion: '2' } });
  assert.equal(history.profiles[binding.accountId]!.owner, false);
  const provider = JSON.stringify((await f.admin.control.query(`SELECT (SELECT jsonb_agg(c) FROM security.ceremonies c WHERE c.workspace_id=$1) AS ceremonies,(SELECT jsonb_agg(p) FROM security.profiles p WHERE p.workspace_id=$1) AS profiles,(SELECT jsonb_agg(o) FROM security.staged_objects o WHERE o.workspace_id=$1) AS objects`, [f.workspaceId])).rows);
  assert.ok([password, draft.registered.exportKey, logged.bundle.signingPrivateKey, logged.bundle.recipientPrivateKey, 'Confirmed private person', 'Pending private person'].every((secret) => !provider.includes(secret)), 'Provider rows retain no plaintext customer secrets or names');
  assert.equal((await f.admin.control.query("SELECT count(*)::int n FROM security.grants WHERE workspace_id=$1 AND profile_id=$2 AND grant_kind='membership' AND device_id IS NULL AND state='active'", [f.workspaceId, binding.accountId])).rows[0].n, 1);
});

test('CP06: Owner JOIN has equal invitation authority; promotion preserves password/profile/device and uses a fresh personal phrase', async (t) => {
  const f = await fixture(t), secondOwner = await f.joined('join_owner');
  assert.equal(secondOwner.result.receipt.ownershipVersion, '2');
  const keys = await recoveryKeys(secondOwner.newOwnerKit!.phrase, { workspaceId: f.workspaceId, accountId: secondOwner.binding.accountId });
  const delivery = await f.enrolment.delivery(secondOwner.session.cookieValue, secondOwner.ref.operationId), phraseEnvelope = delivery.deliveries.find((d) => d.envelope.header.recipientKind === 'recovery')!.envelope;
  assert.ok(await openRecipient(phraseEnvelope, keys.recipient.privateKey, base64urlDecode(f.originalBundle.signingPublicKey), phraseEnvelope.header));
  const invitation = await f.issue('join_member', randomUUID(), secondOwner.auth, secondOwner.bundle); assert.ok(invitation.issued.code);
  const member = await f.joined(), before = (await f.admin.control.query('SELECT * FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, member.binding.accountId])).rows[0];
  assert.deepEqual([before.role_id, before.role_revision, before.role_assignment_object_id],
    [member.binding.role.id, member.binding.role.revision, member.binding.approvalAttemptId]);
  const operationId = randomUUID(), ref = { workspaceId: f.workspaceId, operationId, resumeToken: f.secrets.token() };
  await f.enrolment.beginPromotion(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, operationId, accountId: member.binding.accountId });
  await f.enrolment.claimPromotion(ref, member.auth); const view = await f.enrolment.claim({ workspaceId: f.workspaceId, operationId }, f.auth());
  const newOwnerKit = await kit(), prepared = await preparePromotionEnrolment({ binding: view.binding!, deviceId: member.prepared.draft.transcript.device.id, existingWrapper: member.prepared.deviceWrapper, exportKey: member.registered.exportKey, newOwnerKit }, view.binding!);
  await f.enrolment.stagePromotion({ ...ref, draft: prepared.draft }, member.auth); const approved = await f.approve(ref, prepared, member.registered.exportKey);
  const result = await f.enrolment.finalize({ ...approved.publicRef, requestHash: approved.requestHash }, f.auth()); assert.equal(result.state, 'completed');
  const after = (await f.admin.control.query('SELECT * FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, member.binding.accountId])).rows[0];
  assert.deepEqual([after.role_id, after.role_revision, after.role_assignment_object_id],
    [view.binding!.role.id, view.binding!.role.revision, view.binding!.approvalAttemptId]);
  for (const column of ['opaque_registration_record', 'opaque_setup_id', 'opaque_config_id', 'opaque_identifiers', 'credential_generation', 'profile_object_id']) assert.deepEqual(after[column], before[column]);
  assert.equal(after.session_generation, '2'); assert.equal(after.is_owner, true); assert.deepEqual(prepared.deviceWrapper, member.prepared.deviceWrapper);
  await assert.rejects(f.sessions.authenticate(member.session.cookieValue)); assert.ok(await f.login(prepared, member.registered.exportKey));
  assert.equal((await f.admin.control.query("SELECT count(*)::int n FROM security.grants WHERE workspace_id=$1 AND profile_id=$2 AND grant_kind='membership' AND state='active'", [f.workspaceId, member.binding.accountId])).rows[0].n, 0);
});

test('CP06: JOIN replacement, revocation, one-holder redemption, failed password proof and expiry fail closed', async (t) => {
  const f = await fixture(t), first = await f.issue(), replacement = await f.issue('join_member', first.issued.accountId), token = f.secrets.token();
  await assert.rejects(f.enrolment.begin({ workspaceId: f.workspaceId, code: first.issued.code, resumeToken: token }), code('ENROLMENT_INVALID'));
  const ref = { workspaceId: f.workspaceId, operationId: replacement.issued.operationId, resumeToken: token };
  assert.equal((await f.enrolment.begin({ workspaceId: f.workspaceId, code: replacement.issued.code, resumeToken: token })).operationId, ref.operationId);
  assert.equal((await f.enrolment.begin({ workspaceId: f.workspaceId, code: replacement.issued.code, resumeToken: token })).operationId, ref.operationId);
  await assert.rejects(f.enrolment.begin({ workspaceId: f.workspaceId, code: replacement.issued.code, resumeToken: f.secrets.token() }), code('ENROLMENT_INVALID'));
  const view = await f.enrolment.claim(ref, f.auth()), draft = await f.prepare(ref, view.binding!);
  const start = await startLogin(password), proof = await f.enrolment.startProof({ ...ref, draft: draft.prepared.draft, startLoginRequest: start.startLoginRequest });
  await assert.rejects(f.enrolment.finishProof({ ...ref, proofId: proof.proofId, finishLoginRequest: 'AA' }), code('ENROLMENT_INVALID'));
  const finish = await finishLogin({ password, clientLoginState: start.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
  await assert.rejects(f.enrolment.finishProof({ ...ref, proofId: proof.proofId, finishLoginRequest: finish.finishLoginRequest }), code('ENROLMENT_INVALID'));
  assert.equal((await f.enrolment.inspect(ref)).passwordProved, false);
  await f.enrolment.revokeJoin(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, operationId: ref.operationId });
  await assert.rejects(f.enrolment.registration({ ...ref, registrationRequest: (await startRegistration(password)).registrationRequest }), code('ENROLMENT_INVALID'));
  const expires = await f.issue(); f.advance(3_600_001);
  await assert.rejects(f.enrolment.begin({ workspaceId: f.workspaceId, code: expires.issued.code, resumeToken: f.secrets.token() }), code('ENROLMENT_INVALID'));
  assert.equal((await f.admin.control.query('SELECT credential_generation,state FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, replacement.issued.accountId])).rows[0].credential_generation, '0');
});

test('CP06: staged approval takeover preserves exact registration and wrapper, rejects stale messages, and requires fresh proof', async (t) => {
  const f = await fixture(t), secondOwner = await f.joined('join_owner'), issued = await f.issue(), started = await f.begin(issued.issued), draft = await f.prepare(started.ref, started.binding);
  const old = await f.approve(started.ref, draft.prepared, draft.registered.exportKey), oldConfirmation = draft.prepared.draft.recipientConfirmation!;
  const taken = await f.enrolment.claim(old.publicRef, secondOwner.auth); assert.equal(taken.binding!.attemptGeneration, '2'); assert.notEqual(taken.binding!.approvalAttemptId, started.binding.approvalAttemptId);
  await assert.rejects(f.enrolment.finalize({ ...old.publicRef, requestHash: old.requestHash }, f.auth()), code('ENROLMENT_CHANGED'));
  const unlock = await startLogin(password), response = await f.enrolment.unlockStart({ ...started.ref, startLoginRequest: unlock.startLoginRequest });
  const finish = await finishLogin({ password, clientLoginState: unlock.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration });
  await f.enrolment.unlockFinish({ ...started.ref, proofId: response.proofId, finishLoginRequest: finish.finishLoginRequest }); assert.equal(finish.exportKey, draft.registered.exportKey);
  assert.equal((await f.enrolment.status(started.ref)).passwordProved, false);
  const rebound = await rebindJoinEnrolment({ prepared: draft.prepared, binding: taken.binding!, exportKey: finish.exportKey }, taken.binding!);
  await f.prove(started.ref, rebound, finish.exportKey);
  await assert.rejects(f.enrolment.confirm(started.ref, oldConfirmation), code('ENROLMENT_CHANGED'));
  assert.equal((await f.enrolment.inspect(started.ref)).state, 'verifying');
  const approval = await f.approve(started.ref, rebound, finish.exportKey, secondOwner.auth, secondOwner.bundle);
  const committed = await f.enrolment.finalize({ ...approval.publicRef, requestHash: approval.requestHash }, secondOwner.auth);
  assert.equal(committed.state, 'completed'); assert.equal(committed.receipt.approvalAttemptId, taken.binding!.approvalAttemptId);
  assert.deepEqual(rebound.deviceWrapper, draft.prepared.deviceWrapper); assert.equal(rebound.draft.registrationRecord, draft.prepared.draft.registrationRecord);
  const states = (await f.admin.control.query('SELECT object_id,state FROM security.staged_objects WHERE workspace_id=$1 AND object_id=ANY($2::uuid[])', [f.workspaceId, [started.binding.approvalAttemptId, taken.binding!.approvalAttemptId]])).rows;
  assert.equal(states.find((r) => r.object_id === started.binding.approvalAttemptId).state, 'staged');
  assert.equal(states.find((r) => r.object_id === taken.binding!.approvalAttemptId).state, 'committed');
});

test('CP06: rollback keeps invitation pending; lost commit and projection outage resume one durable receipt', async (t) => {
  const f = await fixture(t), issued = await f.issue(), started = await f.begin(issued.issued), draft = await f.prepare(started.ref, started.binding), approval = await f.approve(started.ref, draft.prepared, draft.registered.exportKey);
  f.setHooks({ beforeControlCommit: async () => { throw new Error('Injected before commit'); } });
  await assert.rejects(f.enrolment.finalize({ ...approval.publicRef, requestHash: approval.requestHash }, f.auth()));
  assert.equal((await f.admin.control.query('SELECT state,credential_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, issued.issued.accountId])).rows[0].state, 'pending');
  assert.equal((await f.enrolment.inspect(started.ref)).state, 'confirmed');
  let observedClosed = false;
  f.setHooks({ afterControlCommit: async () => {
    // Observe while the committing writer still holds the fence. A live worker may repair it after the lost response.
    observedClosed = (await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].fence_closed;
    throw new Error('Injected lost response');
  } });
  await assert.rejects(f.enrolment.finalize({ ...approval.publicRef, requestHash: approval.requestHash }, f.auth()));
  f.setHooks({ beforeProjection: async () => { throw new Error('Injected projection outage'); } });
  const finishing = await f.enrolment.status(started.ref); assert.equal(finishing.state, 'finishing'); assert.ok(finishing.receipt); assert.ok(observedClosed);
  f.setHooks({}); const completed = await f.enrolment.status(started.ref); assert.equal(completed.state, 'completed'); assert.deepEqual(completed.receipt, finishing.receipt);
  assert.equal((await f.admin.control.query("SELECT count(*)::int n FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2", [f.workspaceId, started.ref.operationId])).rows[0].n, 1);
});

test('CP06: restricted or changed authority blocks pending enrolment but preserves committed receipt and delivery', async (t) => {
  const f = await fixture(t), member = await f.joined(), issued = await f.issue(), pending = await f.begin(issued.issued), draft = await f.prepare(pending.ref, pending.binding), approval = await f.approve(pending.ref, draft.prepared, draft.registered.exportKey);
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='restricted' WHERE workspace_id=$1", [f.workspaceId]);
  await assert.rejects(f.enrolment.finalize({ ...approval.publicRef, requestHash: approval.requestHash }, f.auth()), code('WORKSPACE_RESTRICTED'));
  await assert.rejects(f.issue(), code('WORKSPACE_RESTRICTED'));
  assert.equal((await f.enrolment.status(member.ref)).state, 'completed'); assert.ok(await f.enrolment.delivery(member.session.cookieValue, member.ref.operationId));
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='active',lifecycle='pending_deletion',deletion_requested_at=now(),delete_after=now()+interval '7 days' WHERE workspace_id=$1", [f.workspaceId]);
  await assert.rejects(f.enrolment.finalize({ ...approval.publicRef, requestHash: approval.requestHash }, f.auth()), code('WORKSPACE_RESTRICTED'));
});

test('CP06: real member pairing then promotion preserves both healthy devices and delivers usable Owner custody independently', async (t) => {
  const f = await fixture(t), member = await f.joined(), accountId = member.binding.accountId;
  const pairing = new PairingService({ databases: f.databases, sessions: f.sessions, origin });
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair(), deviceId = randomUUID();
  t.after(() => { signing.privateKey.fill(0); recipient.privateKey.fill(0); });
  const bundle: DeviceBundle = { signingPrivateKey: base64urlEncode(signing.privateKey), signingPublicKey: base64urlEncode(signing.publicKey),
    recipientPrivateKey: base64urlEncode(recipient.privateKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
  const context = { workspaceId: f.workspaceId, accountId, deviceId, credentialGeneration: '1' };
  const wrapper = await wrapDeviceBundle(context, bundle, member.registered.exportKey);
  assert.deepEqual(await unwrapDeviceBundle(context, wrapper, member.registered.exportKey), bundle);
  async function passwordLogin() {
    const start = await startLogin(password), response = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId, startLoginRequest: start.startLoginRequest });
    const finish = await finishLogin({ password, clientLoginState: start.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration });
    assert.equal(finish.exportKey, member.registered.exportKey);
    return { session: await f.authentication.finishLogin({ loginId: response.loginId, finishLoginRequest: finish.finishLoginRequest }), exportKey: finish.exportKey };
  }
  const restricted = await passwordLogin(), operationId = randomUUID();
  await pairing.begin(restricted.session.cookieValue, restricted.session.csrfToken, { operationId, device: { id: deviceId, keyGeneration: '1',
    signingPublicKey: bundle.signingPublicKey, recipientPublicKey: bundle.recipientPublicKey }, localBundleDigest: await digestObject(wrapper) });
  const claimed = await pairing.claim(member.session.cookieValue, member.session.csrfToken, operationId), transcript = claimed.transcript!, transcriptDigest = claimed.transcriptDigest!;
  await pairing.confirm(restricted.session.cookieValue, restricted.session.csrfToken, await signObject(pairingConfirmationFor(transcript, transcriptDigest, 'recipient'), signing.privateKey));
  const confirmed = await pairing.confirm(member.session.cookieValue, member.session.csrfToken,
    await signObject(pairingConfirmationFor(transcript, transcriptDigest, 'approver'), base64urlDecode(member.bundle.signingPrivateKey)));
  const deliveries = await Promise.all(transcript.scopes.map(async (scope) => ({ id: randomUUID(), envelope: await sealRecipient(pairingRecipientHeader(transcript, transcriptDigest, scope),
    { version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, keys: f.manifest.workspaceKeys }, base64urlDecode(member.bundle.signingPrivateKey)) })));
  const approval: PairingApproval = { deliveries, grant: await signObject({ version: 1 as const, purpose: 'ukda.device-pair-grant.v1' as const,
    operationId, workspaceId: f.workspaceId, grantId: operationId, securityVersion: String(BigInt(transcript.securityVersion) + 1n), previousHead: transcript.securityHead,
    transcript, transcriptDigest, recipientConfirmation: confirmed.recipientConfirmation!, approverConfirmation: confirmed.approverConfirmation!,
    deliveries: await Promise.all(deliveries.map(async (delivery) => ({ id: delivery.id, scope: delivery.envelope.header.scope, scopeId: delivery.envelope.header.scopeId, digest: await digestObject(delivery.envelope) }))) }, base64urlDecode(member.bundle.signingPrivateKey)) };
  await pairing.stageApproval(member.session.cookieValue, member.session.csrfToken, approval);
  const paired = await pairing.commit(member.session.cookieValue, member.session.csrfToken, operationId); assert.equal(paired.projection.state, 'ready');
  const challenge = await f.sessions.beginDeviceChallenge(restricted.session.cookieValue, restricted.session.csrfToken, deviceId);
  const secondSession = await f.sessions.completeDeviceChallenge(restricted.session.cookieValue, restricted.session.csrfToken, await signObject(challenge, signing.privateKey));
  const pairedDelivery = await pairing.delivery(secondSession.cookieValue, operationId), pairedEnvelope = pairedDelivery.deliveries[0]!.envelope;
  const pairedContent = await openRecipient(pairedEnvelope, recipient.privateKey, base64urlDecode(member.bundle.signingPublicKey), pairedEnvelope.header) as { keys: { key: string }[] };
  assert.equal(pairedContent.keys[0]!.key, f.manifest.workspaceKeys[0]!.key);
  const beforeProfile = (await f.admin.control.query('SELECT opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers,credential_generation,profile_object_id FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, accountId])).rows[0];
  const readDevices = async () => (await f.admin.control.query('SELECT device_id,key_generation,signing_public_key,recipient_public_key,state,approval_security_version FROM security.devices WHERE workspace_id=$1 AND profile_id=$2 ORDER BY device_id', [f.workspaceId, accountId])).rows;
  const beforeDevices = await readDevices(); assert.equal(beforeDevices.length, 2);
  const ref = { workspaceId: f.workspaceId, operationId: randomUUID(), resumeToken: f.secrets.token() };
  await f.enrolment.beginPromotion(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId, accountId, operationId: ref.operationId });
  await f.enrolment.claimPromotion(ref, member.auth); const view = await f.enrolment.claim(ref, f.auth());
  assert.deepEqual(view.binding!.currentDevices.map((d) => d.id).sort(), [member.prepared.draft.transcript.device.id, deviceId].sort());
  const ownerKit = await kit(), prepared = await preparePromotionEnrolment({ binding: view.binding!, deviceId: member.prepared.draft.transcript.device.id,
    existingWrapper: member.prepared.deviceWrapper, exportKey: member.registered.exportKey, newOwnerKit: ownerKit }, view.binding!);
  await f.enrolment.stagePromotion({ ...ref, draft: prepared.draft }, member.auth);
  const staged = await f.approve(ref, prepared, member.registered.exportKey), promoted = await f.enrolment.finalize({ ...staged.publicRef, requestHash: staged.requestHash }, f.auth());
  assert.equal(promoted.state, 'completed'); assert.equal(promoted.receipt.transition.body.deliveries.length, 3);
  assert.deepEqual(await readDevices(), beforeDevices);
  assert.deepEqual((await f.admin.control.query('SELECT opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers,credential_generation,profile_object_id FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, accountId])).rows[0], beforeProfile);
  await assert.rejects(f.sessions.authenticate(member.session.cookieValue)); await assert.rejects(f.sessions.authenticate(secondSession.cookieValue));
  const firstOwner = await f.login(prepared, member.registered.exportKey), secondLogin = await passwordLogin();
  assert.equal(secondLogin.session.sessionGeneration, '2'); assert.deepEqual(await unwrapDeviceBundle(context, wrapper, secondLogin.exportKey), bundle);
  const secondChallenge = await f.sessions.beginDeviceChallenge(secondLogin.session.cookieValue, secondLogin.session.csrfToken, deviceId);
  const secondOwner = await f.sessions.completeDeviceChallenge(secondLogin.session.cookieValue, secondLogin.session.csrfToken, await signObject(secondChallenge, signing.privateKey));
  for (const device of [{ id: member.prepared.draft.transcript.device.id, cookie: firstOwner.session.cookieValue, recipient: base64urlDecode(member.bundle.recipientPrivateKey) },
    { id: deviceId, cookie: secondOwner.cookieValue, recipient: recipient.privateKey }]) {
    const delivered = await f.enrolment.delivery(device.cookie, ref.operationId);
    assert.equal(delivered.deliveries.length, 2); // This device and the new Owner phrase; no other device's ciphertext.
    assert.deepEqual(delivered.deliveries.filter((d) => d.envelope.header.recipientKind === 'device').map((d) => d.envelope.header.recipientId), [device.id]);
    const envelope = delivered.deliveries.find((d) => d.envelope.header.recipientKind === 'device')!.envelope;
    const custody = await openRecipient(envelope, device.recipient, base64urlDecode(f.originalBundle.signingPublicKey), envelope.header) as { custodyKey: string };
    assert.equal(custody.custodyKey, f.custody.custodyKey);
    const content = await decryptContent(f.prepared.payload.objects.custody, base64urlDecode(custody.custodyKey), base64urlDecode(f.originalBundle.signingPublicKey), f.prepared.payload.objects.custody.header) as { workspaceKeys: { key: string }[] };
    assert.equal(content.workspaceKeys[0]!.key, f.manifest.workspaceKeys[0]!.key);
  }
  const history = await verifySecurityHistory({ workspaceId: f.workspaceId, origin, genesisFingerprint: await digestObject(f.prepared.payload.genesis), genesis: f.prepared.payload.genesis,
    transitions: [member.result.receipt.transition, paired.receipt.grant, promoted.receipt.transition], expected: { securityHead: promoted.receipt.securityHead, securityVersion: promoted.receipt.securityVersion } });
  assert.equal(history.profiles[accountId]!.owner, true); assert.equal(history.devices[deviceId]!.scopes[0]!.mode, 'custody');
});

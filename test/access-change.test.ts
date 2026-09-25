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
import { transaction } from '../src/db.js';
import { AccessChangeService } from '../src/modules/identity/access-change.js';
import { EntitlementOperations } from '../src/modules/identity/entitlements.js';
import { prepareAccessChange, refreshAccessKeys } from '../src/client/access-change-crypto.js';
import { readOwnerCustodyKeyMaterial, readRecoveryCustodyKeyMaterial } from '../src/client/pairing.js';
import { accessReceiptTokenHash, type AccessRequest } from '../src/shared/access-change.js';
import type { SecurityHistoryInput } from '../src/shared/security-history.js';
import { provisionProjectScope } from './project-scope-fixture.js';
import { accessChangeFixture as fixture } from './access-change-fixture.js';
import { RecoveryService } from '../src/modules/identity/recovery.js';
import { recoveryConfirmationFor, recoveryRecipientHeader, type RecoveryTranscript, type RecoveryDraft, type RecoveryApproval } from '../src/shared/recovery.js';
const code = (expected: string) => (e: unknown) => e instanceof AppError && e.code === expected;
const password = newPassword;

test('CP06: ordinary access changes use signed project history, rotate lost scope keys and preserve remaining access', async (t) => {
  const f = await fixture(t), member = await f.joined(), project = await provisionProjectScope(f);
  const viewer = f.prepared.payload.genesis.body.roles.viewer;
  const added = await f.draft('set_access', member.binding.accountId, { roleId: viewer, projectIds: [project.projectId] });
  const results = await Promise.all([f.finalize(added), f.finalize(added)]); assert.equal(results[0]!.state, 'completed'); assert.deepEqual(results[0], results[1]);
  await assert.rejects(f.sessions.authenticate(member.session.cookieValue));
  let current = await f.login(member.prepared, member.registered.exportKey);
  const refreshed = await f.refresh(current.auth, current.bundle); assert.equal(refreshed.refreshed.scopeCount, 2);
  assert.ok(refreshed.delivery.materials.every((m) => m.kind === 'key_envelope'));
  const projected = (await f.admin.application.query('SELECT permissions,role_id FROM app.project_access WHERE workspace_id=$1 AND project_id=$2 AND profile_id=$3', [f.workspaceId, project.projectId, member.binding.accountId])).rows[0];
  assert.deepEqual(projected.permissions, ['read_project']); assert.equal(projected.role_id, viewer);
  const removed = await f.draft('set_access', member.binding.accountId, { roleId: viewer, projectIds: [] });
  assert.equal(removed.context.plan.rotations.length, 1); assert.equal(removed.context.plan.rotations[0]!.scopeId, project.projectId);
  assert.equal((await f.finalize(removed)).state, 'completed');
  current = await f.login(member.prepared, member.registered.exportKey); assert.equal((await f.refresh(current.auth, current.bundle)).refreshed.scopeCount, 1);
  const owner = await f.refresh(), state = await verifySecurityHistory(owner.history);
  const opened = await readOwnerCustodyKeyMaterial({ accountId: f.accountId, deviceId: f.deviceId, history: state, materials: owner.delivery.materials }, f.originalBundle);
  const keys = opened.manifest.projectKeys.find((p) => p.projectId === project.projectId)!.keys;
  assert.equal(keys.find((k) => k.epoch === '1')!.key, base64urlEncode(project.projectKey));
  assert.ok(keys.some((k) => k.epoch === '2')); assert.notEqual(keys.find((k) => k.epoch === '2')!.key, base64urlEncode(project.projectKey));
  assert.equal(state.dataGeneration, '1'); assert.equal(state.profiles[member.binding.accountId]!.role.id, viewer);
  assert.equal((await f.admin.application.query("SELECT state FROM app.project_access WHERE workspace_id=$1 AND project_id=$2 AND profile_id=$3", [f.workspaceId, project.projectId, member.binding.accountId])).rows[0].state, 'revoked');
  assert.deepEqual((await f.status(added)).receipt, results[0]!.receipt, 'Later access changes do not change the original durable receipt');
});

test('CP06: demotion rotates custody, preserves historical keys and remaining Owner phrase while former Owner becomes ordinary', async (t) => {
  const f = await fixture(t), owner = await f.joined('join_owner'), third = await f.joined('join_owner'), project = await provisionProjectScope(f);
  const prepared = await f.draft('demote_owner', owner.binding.accountId, { roleId: f.prepared.payload.genesis.body.roles.member, projectIds: [] });
  assert.equal(prepared.context.plan.rotateCustody, true);
  assert.ok(prepared.context.plan.recipients.filter((r) => r.kind === 'recovery').every((r) => [f.accountId, third.binding.accountId].includes(r.accountId)));
  assert.equal((await f.finalize(prepared)).state, 'completed');
  await assert.rejects(f.sessions.authenticate(owner.session.cookieValue));
  const notices = (await f.admin.application.query("SELECT recipient_profile_id,event_id,record_id FROM app.notifications WHERE workspace_id=$1 AND event_type='security.owner_demoted'", [f.workspaceId])).rows;
  assert.equal(notices.length, 1); assert.equal(notices[0].recipient_profile_id, third.binding.accountId);
  assert.equal(notices[0].event_id, prepared.reference.operationId); assert.equal(notices[0].record_id, owner.binding.accountId);
  const logged = await f.login(owner.prepared, owner.registered.exportKey), ordinary = await f.refresh(logged.auth, logged.bundle);
  assert.equal(ordinary.refreshed.scopeCount, 1); assert.ok(ordinary.delivery.materials.every((m) => m.kind === 'key_envelope'));
  const state = await verifySecurityHistory(await f.history()); assert.equal(state.profiles[owner.binding.accountId]!.owner, false);
  assert.equal(state.profiles[owner.binding.accountId]!.credentialGeneration, '1', 'Demotion preserves OPAQUE credentials');
  assert.ok(Object.values(state.recoveryAuthorities).filter((a) => a.accountId === owner.binding.accountId).every((a) => !a.active));
  const authority = state.recoveryAuthorities[`${f.accountId}:1`]!, object = (await f.admin.control.query('SELECT versioned_object FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [f.workspaceId, authority.custodyEnvelope.id])).rows[0].versioned_object;
  const keys = await recoveryKeys(f.phrase, { workspaceId: f.workspaceId, accountId: f.accountId });
  const delivered = await openRecipient(object, keys.recipient.privateKey, base64urlDecode(f.originalBundle.signingPublicKey), object.header) as { custodyEpoch: string; custodyKey: string; manifest: { id: string } };
  assert.equal(delivered.custodyEpoch, state.custodyEpoch);
  const manifestObject = (await f.admin.control.query('SELECT versioned_object FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [f.workspaceId, delivered.manifest.id])).rows[0].versioned_object;
  const manifest = await decryptContent(manifestObject, base64urlDecode(delivered.custodyKey), base64urlDecode(f.originalBundle.signingPublicKey), manifestObject.header) as { projectKeys: { projectId: string; keys: { epoch: string; key: string }[] }[] };
  assert.equal(manifest.projectKeys.find((p) => p.projectId === project.projectId)!.keys.find((k) => k.epoch === '1')!.key, base64urlEncode(project.projectKey));
  const departed = await recoveryKeys(owner.newOwnerKit!.phrase, { workspaceId: f.workspaceId, accountId: owner.binding.accountId });
  await assert.rejects(openRecipient(object, departed.recipient.privateKey, base64urlDecode(f.originalBundle.signingPublicKey), object.header));
});

test('CP06: self-removal survives rollback/lost commit with receipt-only continuation and no content authority', async (t) => {
  const f = await fixture(t); await f.joined('join_owner'); const prepared = await f.draft('remove', f.accountId);
  f.setAccessHooks({ beforeControlCommit: async () => { throw new Error('private rollback detail'); } });
  await assert.rejects(f.finalize(prepared), code('ACCESS_UNAVAILABLE'));
  assert.equal((await f.admin.control.query('SELECT state FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.accountId])).rows[0].state, 'active');
  assert.equal((await f.status(prepared)).state, 'staged');
  let closed = false;
  f.setAccessHooks({ afterControlCommit: async () => { closed = (await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].fence_closed; throw new Error('lost response'); } });
  await assert.rejects(f.finalize(prepared), code('ACCESS_UNAVAILABLE')); assert.ok(closed);
  f.setAccessHooks({ beforeProjection: async () => { throw new Error('projection temporarily unavailable'); } });
  const finishing = await f.status(prepared); assert.equal(finishing.state, 'finishing'); assert.ok(finishing.receipt);
  f.setAccessHooks(); const done = await f.status(prepared); assert.equal(done.state, 'completed'); assert.deepEqual(done.receipt, finishing.receipt);
  assert.deepEqual((await f.access.finalize(undefined, undefined, prepared.finalize)).receipt, done.receipt);
  await assert.rejects(f.access.status(undefined, undefined, { ...prepared.reference, receiptToken: f.secrets.token() }), code('ACCESS_FORBIDDEN'));
  await assert.rejects(f.access.currentDelivery(f.auth().cookieValue, f.auth().csrfToken, { workspaceId: f.workspaceId }));
  const profile = (await f.admin.control.query('SELECT state,opaque_registration_record,credential_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.accountId])).rows[0];
  assert.equal(profile.state, 'removed'); assert.equal(profile.opaque_registration_record, null); assert.equal(profile.credential_generation, '2');
  const provider = JSON.stringify((await f.admin.control.query('SELECT versioned_object FROM security.staged_objects WHERE workspace_id=$1', [f.workspaceId])).rows);
  for (const secret of [prepared.receiptToken, f.phrase, f.originalBundle.signingPrivateKey, 'Former member']) assert.equal(provider.includes(secret), false);
});

test('CP06: competing Owners can remove at most one another and cannot remove the final active Owner', async (t) => {
  const f = await fixture(t), pendingOwner = await f.issue('join_owner');
  const pending = (await f.admin.control.query('SELECT state,is_owner FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, pendingOwner.issued.accountId])).rows[0];
  assert.equal(pending.state, 'pending'); assert.equal(pending.is_owner, false);
  const initialHead = (await f.history()).expected;
  await assert.rejects(f.draft('remove', f.accountId), code('ACCESS_CHANGED'));
  assert.deepEqual((await f.history()).expected, initialHead, 'An issued Owner invitation is not an active co-Owner');
  const other = await f.joined('join_owner');
  const one = await f.draft('remove', other.binding.accountId), two = await f.draft('remove', f.accountId, null, other.auth, other.bundle);
  const results = await Promise.allSettled([f.finalize(one), f.finalize(two, other.auth)]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1); assert.equal(results.filter((r) => r.status === 'rejected').length, 1);
  const state = await verifySecurityHistory(await f.history()), remaining = Object.values(state.profiles).filter((p) => p.active && p.owner);
  assert.equal(remaining.length, 1);
  const auth = remaining[0]!.accountId === f.accountId ? f.auth() : other.auth;
  const ref = { workspaceId: f.workspaceId, operationId: randomUUID() }, token = f.secrets.token();
  await assert.rejects(f.access.context(auth.cookieValue, auth.csrfToken, { ...ref, action: 'remove', targetAccountId: remaining[0]!.accountId, desired: null, receiptTokenHash: await accessReceiptTokenHash(ref, token) }), code('ACCESS_CHANGED'));
});

test('CP06: removed Owner cannot claim or finalize a pending JOIN and remaining Owner takes over a fresh attempt', async (t) => {
  const f = await fixture(t), other = await f.joined('join_owner');
  const invitation = await f.issue('join_member', randomUUID(), other.auth, other.bundle);
  const started = await f.begin(invitation.issued, other.auth), prepared = await f.prepare(started.ref, started.binding);
  const approved = await f.approve(started.ref, prepared.prepared, prepared.registered.exportKey, other.auth, other.bundle);
  const publicRef = { workspaceId: f.workspaceId, operationId: started.ref.operationId };
  assert.equal((await f.enrolment.status(started.ref)).state, 'confirmed');

  const removal = await f.draft('remove', other.binding.accountId), removed = await f.finalize(removal);
  assert.equal(removed.state, 'completed');
  await assert.rejects(f.enrolment.claim(publicRef, other.auth), code('AUTH_REQUIRED'));
  await assert.rejects(f.enrolment.finalize({ ...publicRef, requestHash: approved.requestHash }, other.auth), code('AUTH_REQUIRED'));
  const pending = (await f.admin.control.query('SELECT state FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, invitation.issued.accountId])).rows[0];
  assert.equal(pending.state, 'pending');
  assert.equal((await f.enrolment.status(started.ref)).receipt, null);

  const taken = await f.enrolment.claim(publicRef, f.auth());
  assert.equal(taken.state, 'waiting_approval');
  assert.equal(taken.binding!.authorizer.accountId, f.accountId);
  assert.notEqual(taken.binding!.approvalAttemptId, started.binding.approvalAttemptId);
  assert.equal(taken.binding!.attemptGeneration, String(BigInt(started.binding.attemptGeneration) + 1n));
  assert.equal(taken.binding!.securityHead, removed.receipt!.securityHead);
  assert.equal(taken.passwordProved, false); assert.equal(taken.approvalStaged, false);
  assert.equal(taken.requestHash, null); assert.equal(taken.recipientConfirmation, null);
  await assert.rejects(f.enrolment.finalize({ ...publicRef, requestHash: approved.requestHash }, f.auth()), code('ENROLMENT_CHANGED'));
  assert.equal((await f.enrolment.status(started.ref)).binding!.approvalAttemptId, taken.binding!.approvalAttemptId);
});

test('CP06: another Owner completes a fresh replacement operation; stale grant edits and narrowed live project leases fail closed', async (t) => {
  const f = await fixture(t), other = await f.joined('join_owner'), member = await f.joined();
  const desired = { roleId: f.prepared.payload.genesis.body.roles.viewer, projectIds: [] };
  const old = await f.draft('set_access', member.binding.accountId, desired), replacement = await f.draft('set_access', member.binding.accountId, desired, other.auth, other.bundle);
  assert.equal((await f.finalize(replacement, other.auth)).state, 'completed'); await assert.rejects(f.finalize(old), code('ACCESS_CHANGED'));
  const project = await provisionProjectScope(f, { selected: [{ accountId: member.binding.accountId, roleId: desired.roleId }] });
  const pending = await f.draft('set_access', member.binding.accountId, { roleId: desired.roleId, projectIds: [] });
  const priorHead = (await f.history()).expected;
  await f.admin.control.query("UPDATE security.grants SET expires_at=created_at+interval '1 hour' WHERE workspace_id=$1 AND profile_id=$2 AND scope_kind='project' AND scope_id=$3 AND device_id IS NULL AND state='active'", [f.workspaceId, member.binding.accountId, project.projectId]);
  await assert.rejects(f.finalize(pending), code('ACCESS_CHANGED')); assert.deepEqual((await f.history()).expected, priorHead);
  assert.equal((await f.status(pending)).state, 'staged');
});

test('CP06: restricted and pending-deletion workspaces allow revocation; suspended removal cannot reactivate access', async (t) => {
  const f = await fixture(t), member = await f.joined(), other = await f.joined('join_owner');
  await new EntitlementOperations(f.databases, f.secrets).change({ licenceId: f.licence.licenceId, operationId: randomUUID(), action: 'revoke' }, { operatorId: randomUUID() });
  const ref = { workspaceId: f.workspaceId, operationId: randomUUID() }, receiptToken = f.secrets.token();
  await assert.rejects(f.access.context(f.auth().cookieValue, f.auth().csrfToken, { ...ref, action: 'set_access', targetAccountId: member.binding.accountId,
    desired: { roleId: f.prepared.payload.genesis.body.roles.manager, projectIds: [] }, receiptTokenHash: await accessReceiptTokenHash(ref, receiptToken) }), code('ACCESS_CHANGED'));
  await f.admin.control.query("UPDATE security.workspaces SET lifecycle='pending_deletion',deletion_requested_at=now(),delete_after=now()+interval '7 days' WHERE workspace_id=$1", [f.workspaceId]);
  const suspended = await f.draft('suspend', member.binding.accountId); assert.equal((await f.finalize(suspended)).state, 'completed');
  await assert.rejects(f.sessions.authenticate(member.session.cookieValue));
  const removed = await f.draft('remove', member.binding.accountId); assert.equal(removed.context.plan.rotations.length, 0); assert.equal((await f.finalize(removed)).state, 'completed');
  const demoted = await f.draft('demote_owner', other.binding.accountId, { roleId: f.prepared.payload.genesis.body.roles.viewer, projectIds: [] });
  assert.equal((await f.finalize(demoted)).state, 'completed'); assert.equal((await f.refresh()).refreshed.complete, true);
  assert.equal((await f.status(removed)).state, 'completed');
});

test('CP06: current delivery omits expired project envelopes while the workspace device remains approved', async (t) => {
  const f = await fixture(t), member = await f.joined(), accountId = member.binding.accountId;
  const project = await provisionProjectScope(f, { selected: [{ accountId, roleId: f.prepared.payload.genesis.body.roles.member }] });
  // A real signed pairing can delegate a shorter lease. Restore the source grant
  // after preparing that lease so its original signed authority remains exact.
  const pairing = new PairingService({ databases: f.databases, sessions: f.sessions, origin });
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair(), deviceId = randomUUID(), operationId = randomUUID();
  const bundle: DeviceBundle = { signingPrivateKey: base64urlEncode(signing.privateKey), signingPublicKey: base64urlEncode(signing.publicKey), recipientPrivateKey: base64urlEncode(recipient.privateKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
  const wrapper = await wrapDeviceBundle({ workspaceId: f.workspaceId, accountId, deviceId, credentialGeneration: '1' }, bundle, member.registered.exportKey);
  const login = await startLogin(password), response = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId, startLoginRequest: login.startLoginRequest });
  const finished = await finishLogin({ password, clientLoginState: login.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration });
  const restricted = await f.authentication.finishLogin({ loginId: response.loginId, finishLoginRequest: finished.finishLoginRequest });
  await pairing.begin(restricted.cookieValue, restricted.csrfToken, { operationId, device: { id: deviceId, keyGeneration: '1', signingPublicKey: bundle.signingPublicKey, recipientPublicKey: bundle.recipientPublicKey }, localBundleDigest: await digestObject(wrapper) });
  await f.admin.control.query("UPDATE security.grants SET expires_at=now()+interval '1 minute' WHERE workspace_id=$1 AND profile_id=$2 AND device_id=$3 AND scope_kind='project' AND scope_id=$4 AND state='active'", [f.workspaceId, accountId, member.prepared.draft.transcript.device.id, project.projectId]);
  const claimed = await pairing.claim(member.session.cookieValue, member.session.csrfToken, operationId), transcript = claimed.transcript!, transcriptDigest = claimed.transcriptDigest!;
  await pairing.confirm(restricted.cookieValue, restricted.csrfToken, await signObject(pairingConfirmationFor(transcript, transcriptDigest, 'recipient'), signing.privateKey));
  const confirmed = await pairing.confirm(member.session.cookieValue, member.session.csrfToken, await signObject(pairingConfirmationFor(transcript, transcriptDigest, 'approver'), base64urlDecode(member.bundle.signingPrivateKey)));
  const deliveries = await Promise.all(transcript.scopes.map(async (scope) => ({ id: randomUUID(), envelope: await sealRecipient(pairingRecipientHeader(transcript, transcriptDigest, scope),
    { version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch,
      keys: scope.scope === 'workspace' ? f.manifest.workspaceKeys : [{ epoch: '1', key: base64urlEncode(project.projectKey) }] }, base64urlDecode(member.bundle.signingPrivateKey)) })));
  const approval: PairingApproval = { deliveries, grant: await signObject({ version: 1 as const, purpose: 'ukda.device-pair-grant.v1' as const, operationId, workspaceId: f.workspaceId,
    grantId: operationId, securityVersion: String(BigInt(transcript.securityVersion) + 1n), previousHead: transcript.securityHead, transcript, transcriptDigest,
    recipientConfirmation: confirmed.recipientConfirmation!, approverConfirmation: confirmed.approverConfirmation!,
    deliveries: await Promise.all(deliveries.map(async (d) => ({ id: d.id, scope: d.envelope.header.scope, scopeId: d.envelope.header.scopeId, digest: await digestObject(d.envelope) }))) }, base64urlDecode(member.bundle.signingPrivateKey)) };
  await pairing.stageApproval(member.session.cookieValue, member.session.csrfToken, approval); assert.equal((await pairing.commit(member.session.cookieValue, member.session.csrfToken, operationId)).projection.state, 'ready');
  await f.admin.control.query("UPDATE security.grants SET expires_at=NULL WHERE workspace_id=$1 AND profile_id=$2 AND device_id=$3 AND scope_kind='project' AND scope_id=$4 AND state='active'", [f.workspaceId, accountId, member.prepared.draft.transcript.device.id, project.projectId]);
  const challenge = await f.sessions.beginDeviceChallenge(restricted.cookieValue, restricted.csrfToken, deviceId);
  const session = await f.sessions.completeDeviceChallenge(restricted.cookieValue, restricted.csrfToken, await signObject(challenge, signing.privateKey));
  assert.equal((await f.access.currentDelivery(session.cookieValue, session.csrfToken, { workspaceId: f.workspaceId })).materials.length, 2);
  f.advanceAccess(120_000);
  const delivered = await f.access.currentDelivery(session.cookieValue, session.csrfToken, { workspaceId: f.workspaceId });
  assert.equal(delivered.materials.length, 1); assert.equal(delivered.materials[0]!.id, deliveries.find((d) => d.envelope.header.scope === 'workspace')!.id);
});

test('CP06: remaining Owner completes real phrase recovery after custody rotation and preserves retained project history', async (t) => {
  const f = await fixture(t), departing = await f.joined('join_owner'), project = await provisionProjectScope(f);
  const removal = await f.draft('remove', departing.binding.accountId); assert.equal((await f.finalize(removal)).state, 'completed');
  const recovery = new RecoveryService({ ...f, origin }), ref = { workspaceId: f.workspaceId, operationId: randomUUID(), resumeToken: f.secrets.token() };
  await assert.rejects(recovery.beginPhrase({ ...ref, accountId: departing.binding.accountId }));
  const challenge = await recovery.beginPhrase({ ...ref, accountId: f.accountId }), priorKeys = await recoveryKeys(f.phrase, { workspaceId: f.workspaceId, accountId: f.accountId });
  const view = await recovery.provePhrase({ ...ref, proof: await signObject(challenge, priorKeys.signing.privateKey) }), binding = view.binding!;
  const state = await verifySecurityHistory(await f.history()), authority = state.recoveryAuthorities[`${f.accountId}:1`]!;
  const materials = await recovery.materials(ref), held = await readRecoveryCustodyKeyMaterial({ accountId: f.accountId, recoveryId: authority.id,
    recoveryGeneration: authority.generation, history: state, materials }, priorKeys.recipient.privateKey);
  assert.equal(held.manifest.custodyEpoch, state.custodyEpoch);
  const registration = await startRegistration(newPassword), registeredResponse = await recovery.registration({ ...ref, registrationRequest: registration.registrationRequest });
  const registered = await finishRegistration({ password: newPassword, clientRegistrationState: registration.clientRegistrationState, registrationResponse: registeredResponse.registrationResponse, configuration: registeredResponse.configuration });
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair(), deviceId = randomUUID(), phrase = await newOwnerPhrase();
  const replacementKeys = await recoveryKeys(phrase, { workspaceId: f.workspaceId, accountId: f.accountId });
  const bundle: DeviceBundle = { signingPrivateKey: base64urlEncode(signing.privateKey), recipientPrivateKey: base64urlEncode(recipient.privateKey), signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
  const context = { workspaceId: f.workspaceId, accountId: f.accountId, deviceId, credentialGeneration: binding.nextCredentialGeneration };
  const wrapper = await wrapDeviceBundle(context, bundle, registered.exportKey); assert.deepEqual(await unwrapDeviceBundle(context, wrapper, registered.exportKey), bundle);
  const transcript: RecoveryTranscript = { version: 1, purpose: 'ukda.recovery-transcript.v1', binding,
    device: { id: deviceId, keyGeneration: binding.nextDeviceKeyGeneration, signingPublicKey: bundle.signingPublicKey, recipientPublicKey: bundle.recipientPublicKey },
    recovery: { id: randomUUID(), generation: binding.nextRecoveryGeneration, signingPublicKey: base64urlEncode(replacementKeys.signing.publicKey), recipientPublicKey: base64urlEncode(replacementKeys.recipient.publicKey) },
    configuration: registeredResponse.configuration, registrationRecordHash: await digestObject(registered.registrationRecord), wrapperHash: await digestObject(wrapper) };
  const transcriptDigest = await digestObject(transcript), draft: RecoveryDraft = { transcript, registrationRecord: registered.registrationRecord, recipientConfirmation: null,
    newRecoveryConfirmation: await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'new_recovery'), replacementKeys.signing.privateKey) };
  const login = await startLogin(newPassword), proof = await recovery.startProof({ ...ref, draft, startLoginRequest: login.startLoginRequest });
  const verified = await finishLogin({ password: newPassword, clientLoginState: login.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
  assert.equal(verified.exportKey, registered.exportKey); await recovery.finishProof({ ...ref, proofId: proof.proofId, finishLoginRequest: verified.finishLoginRequest });
  draft.recipientConfirmation = await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'recipient'), signing.privateKey);
  const authorizerConfirmation = await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'authorizer'), priorKeys.signing.privateKey);
  await recovery.confirm(ref, draft.recipientConfirmation); await recovery.confirm(ref, authorizerConfirmation);
  const deliveries: RecoveryApproval['deliveries'] = [];
  for (const scope of binding.scopes) {
    const content = scope.mode === 'custody' ? held.payload : { version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch,
      keys: scope.scope === 'workspace' ? held.manifest.workspaceKeys : held.manifest.projectKeys.find((p) => p.projectId === scope.scopeId)!.keys };
    deliveries.push({ id: randomUUID(), envelope: await sealRecipient(recoveryRecipientHeader(transcript, transcriptDigest, scope, 'device'), content, signing.privateKey) });
    if (scope.mode === 'custody') deliveries.push({ id: randomUUID(), envelope: await sealRecipient(recoveryRecipientHeader(transcript, transcriptDigest, scope, 'recovery'), content, signing.privateKey) });
  }
  const approval: RecoveryApproval = { deliveries, transition: await signObject({ version: 1 as const, purpose: 'ukda.account-recovery.v1' as const, transcript, transcriptDigest,
    recipientConfirmation: draft.recipientConfirmation, authorizerConfirmation, newRecoveryConfirmation: draft.newRecoveryConfirmation, revokeAllDevices: true as const, revokeAllSessions: true as const,
    deliveries: await Promise.all(deliveries.map(async (d) => ({ id: d.id, scope: d.envelope.header.scope, scopeId: d.envelope.header.scopeId, keyEpoch: d.envelope.header.keyEpoch,
      recipientKind: d.envelope.header.recipientKind, recipientId: d.envelope.header.recipientId, digest: await digestObject(d.envelope) }))) }, priorKeys.signing.privateKey) };
  const staged = await recovery.stage(ref, approval), completed = await recovery.finalize({ ...ref, requestHash: staged.requestHash! }); assert.equal(completed.state, 'completed');
  await assert.rejects(f.sessions.authenticate(f.auth().cookieValue));
  const fresh = await startLogin(newPassword), response = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId: f.accountId, startLoginRequest: fresh.startLoginRequest });
  const finished = await finishLogin({ password: newPassword, clientLoginState: fresh.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration });
  const restricted = await f.authentication.finishLogin({ loginId: response.loginId, finishLoginRequest: finished.finishLoginRequest });
  const deviceChallenge = await f.sessions.beginDeviceChallenge(restricted.cookieValue, restricted.csrfToken, deviceId);
  const session = await f.sessions.completeDeviceChallenge(restricted.cookieValue, restricted.csrfToken, await signObject(deviceChallenge, signing.privateKey));
  const delivered = await recovery.delivery(session.cookieValue, ref.operationId), envelope = delivered.deliveries.find((d) => d.envelope.header.recipientId === deviceId && d.envelope.header.scope === 'project')!.envelope;
  const ring = await openRecipient(envelope, recipient.privateKey, signing.publicKey, envelope.header) as { keys: { epoch: string; key: string }[] };
  assert.equal(ring.keys.find((k) => k.epoch === '1')!.key, base64urlEncode(project.projectKey)); assert.ok(ring.keys.some((k) => k.epoch === '2'));
  assert.equal((await f.refresh({ cookieValue: session.cookieValue, csrfToken: session.csrfToken }, bundle)).refreshed.complete, true);
  const after = await verifySecurityHistory(await f.history()); assert.equal(after.profiles[f.accountId]!.owner, true); assert.equal(after.profiles[departing.binding.accountId]!.active, false);
});

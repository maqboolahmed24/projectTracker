import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { enrolmentDeviceContext, type PreparedEnrolment } from '../src/client/enrolment-crypto.js';
import { prepareJoinInvitation, prepareEnrolmentDraft, confirmEnrolmentTarget, verifyEnrolmentDraft, prepareEnrolmentApproval, verifyEnrolmentDelivery,
  type EnrolmentDelivery } from '../src/client/enrolment-controller.js';
import { IndexedEnrolmentStore, EnrolmentStoreError, type EnrolmentRecord } from '../src/client/enrolment-store.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../src/client/opaque.js';
import { base64urlDecode, base64urlEncode, canonicalJson, digestObject, generateRecipientKeyPair, generateSigningKeyPair, randomKey, signObject } from '../src/shared/crypto.js';
import { enrolmentBinding, type EnrolmentBinding, type EnrolmentApproval, type EnrolmentReceipt } from '../src/shared/enrolment.js';
import { pairingConfirmationFor, type PairingMaterial, type PairingScope, type PairingTranscript } from '../src/shared/pairing.js';
import { verifySecurityHistory, SecurityHistoryError, verifyEnrolmentTranscriptAgainstHistory, type HistoryScope, type SecurityHistoryInput, type SecurityHistoryState } from '../src/shared/security-history.js';

const origin = 'https://ukda.example', name = 'Private Rowan Example';
const next = (value: string) => String(BigInt(value) + 1n);
const flip = (value: string) => { const bytes = base64urlDecode(value); bytes[0] = bytes[0]! ^ 1; return base64urlEncode(bytes); };
const publicDraft = (prepared: PreparedEnrolment) => { const { registrationRecord: _record, ...draft } = prepared.draft; return draft; };
function scopeFrom(scope: HistoryScope): PairingScope {
  const { manifests, ...fields } = scope;
  return { ...fields, sources: manifests.map((entry) => ({ grantId: randomUUID(), generation: '1', manifestId: entry.id, manifestDigest: entry.digest })) };
}
async function ownerFixture() {
  // These helpers exercise actual envelope/signature cryptography. OPAQUE exchanges are covered by the server/browser tests.
  const workspaceId = randomUUID(), accountId = randomUUID(), exportKey = base64urlEncode(await randomKey()), phrase = await newOwnerPhrase();
  const configuration: OpaquePublicConfiguration = { configId: OPAQUE_CONFIG_ID, setupId: 'enrolment-controller', keyStretching: OPAQUE_KEY_STRETCHING,
    serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } };
  const prepared = await prepareOwnerActivation({ binding: { workspaceId, accountId, origin, activationId: randomUUID(), operationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1' },
    configuration, exportKey, registrationRecord: base64urlEncode(await randomKey()), phrase, challengePositions: [1, 9, 19],
    challengeAnswers: [1, 9, 19].map((index) => phrase.split(' ')[index]!), displayName: 'Private Original Owner', workspaceName: 'Private Workspace' });
  const genesis = prepared.payload.genesis, head = await digestObject(genesis);
  const history: SecurityHistoryInput = { workspaceId, origin, genesisFingerprint: head, genesis, transitions: [], expected: { securityHead: head, securityVersion: '1' } };
  const bundle = await unwrapDeviceBundle({ workspaceId, accountId, deviceId: genesis.body.device.id, credentialGeneration: '1' }, prepared.deviceWrapper, exportKey);
  const materials: PairingMaterial[] = [
    { id: genesis.body.custodyId, kind: 'custody_manifest', value: prepared.payload.objects.custody, digest: await digestObject(prepared.payload.objects.custody) },
    { id: genesis.body.deviceEnvelopeId, kind: 'key_envelope', value: prepared.payload.objects.deviceCustody, digest: await digestObject(prepared.payload.objects.deviceCustody) },
  ];
  return { history, state: await verifySecurityHistory(history), bundle, materials, configuration, accountId, deviceId: genesis.body.device.id, phrase, exportKey };
}
type OwnerFixture = Awaited<ReturnType<typeof ownerFixture>>;
function bindingFor(f: OwnerFixture, state: SecurityHistoryState, kind: EnrolmentBinding['kind'], accountId: string = randomUUID()): EnrolmentBinding {
  const owner = state.profiles[f.accountId]!, signer = state.devices[f.deviceId]!, target = state.profiles[accountId], promotion = kind === 'promote_owner';
  const role = Object.values(state.roles).find((value) => value.template === (kind === 'join_member' ? 'member' : 'owner'))!;
  const devices = Object.values(state.devices).filter((device) => device.accountId === accountId && device.active), now = Date.now();
  const maximum = devices.reduce((value, device) => BigInt(device.keyGeneration) > value ? BigInt(device.keyGeneration) : value, 0n).toString();
  return enrolmentBinding.parse({ version: 1, kind, origin, workspaceId: state.workspaceId, accountId, operationId: randomUUID(), approvalAttemptId: randomUUID(), attemptGeneration: '1', invitationGeneration: promotion ? '0' : '1',
    profile: promotion ? target!.profile : { id: accountId, revision: '1', objectId: randomUUID(), objectDigest: 'a'.repeat(64) }, nextProfileRevision: promotion ? target!.profile.revision : '2',
    role: { id: role.id, revision: role.revision, permissions: role.permissions }, credentialGeneration: promotion ? target!.credentialGeneration : '0', nextCredentialGeneration: '1',
    sessionGeneration: promotion ? target!.sessionGeneration : '0', nextSessionGeneration: promotion ? next(target!.sessionGeneration) : '1',
    recoveryGeneration: '0', nextRecoveryGeneration: kind === 'join_member' ? '0' : '1', deviceKeyGeneration: promotion ? maximum : '0', nextDeviceKeyGeneration: promotion ? maximum : '1',
    ownershipVersion: state.ownershipVersion, nextOwnershipVersion: kind === 'join_member' ? state.ownershipVersion : next(state.ownershipVersion),
    securityVersion: state.securityVersion, nextSecurityVersion: next(state.securityVersion), securityHead: state.securityHead, genesisFingerprint: state.genesisFingerprint,
    dataGeneration: state.dataGeneration, custodyEpoch: state.custodyEpoch, workspaceKeyEpoch: state.workspaceKeyEpoch,
    authorizer: { accountId: f.accountId, device: { id: signer.id, keyGeneration: signer.keyGeneration, signingPublicKey: signer.signingPublicKey, recipientPublicKey: signer.recipientPublicKey },
      credentialGeneration: owner.credentialGeneration, sessionGeneration: owner.sessionGeneration },
    currentDevices: promotion ? devices.map(({ id, keyGeneration, signingPublicKey, recipientPublicKey }) => ({ id, keyGeneration, signingPublicKey, recipientPublicKey })) : [],
    scopes: owner.scopes.map(scopeFrom).map((scope) => kind === 'join_member' ? { ...scope, mode: 'content', keyEpoch: state.workspaceKeyEpoch, permissions: role.permissions } : scope),
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 3_600_000).toISOString() });
}
async function appended(history: SecurityHistoryInput, transition: unknown) {
  const input = { ...history, transitions: [...history.transitions, transition], expected: { securityHead: await digestObject(transition), securityVersion: next(history.expected.securityVersion) } };
  return { history: input, state: await verifySecurityHistory(input) };
}
async function receiptFor(approval: EnrolmentApproval): Promise<EnrolmentReceipt> {
  const transcript = approval.transition.body.transcript, b = transcript.binding;
  return { version: 1, operationId: b.operationId, approvalAttemptId: b.approvalAttemptId, attemptGeneration: b.attemptGeneration,
    workspaceId: b.workspaceId, accountId: b.accountId, deviceId: transcript.device.id, credentialGeneration: b.nextCredentialGeneration,
    sessionGeneration: b.nextSessionGeneration, keyGeneration: transcript.device.keyGeneration, recoveryGeneration: b.nextRecoveryGeneration,
    ownershipVersion: b.nextOwnershipVersion, profileRevision: b.nextProfileRevision, dataGeneration: b.dataGeneration,
    securityVersion: b.nextSecurityVersion, securityHead: await digestObject(approval.transition), requestHash: await digestObject(approval),
    wrapperHash: transcript.wrapperHash, committedAt: new Date().toISOString(), transition: approval.transition };
}
async function approve(f: OwnerFixture, history: SecurityHistoryInput, prepared: PreparedEnrolment, exportKey: string) {
  const fingerprint = await digestObject(prepared.draft.transcript);
  prepared.draft.recipientConfirmation = await confirmEnrolmentTarget({ prepared, exportKey, history, fingerprint });
  return prepareEnrolmentApproval({ draft: publicDraft(prepared), fingerprint, history, materials: f.materials }, f.bundle);
}
async function pendingInvitation(f: OwnerFixture, binding: EnrolmentBinding, selectedRole = binding.role) {
  assert.notEqual(binding.kind, 'promote_owner');
  const kind = binding.kind === 'join_owner' ? 'join_owner' as const : 'join_member' as const;
  const request = { workspaceId: binding.workspaceId, accountId: binding.accountId, operationId: binding.operationId, kind, roleId: selectedRole.id, projectIds: [] };
  const issued = await prepareJoinInvitation({ request, history: f.history, displayName: 'Private pending invitation', context: {
    workspaceId: binding.workspaceId, accountId: binding.accountId, operationId: binding.operationId, kind,
    role: selectedRole, authorizer: binding.authorizer, genesisFingerprint: binding.genesisFingerprint,
    custodyEpoch: binding.custodyEpoch, current: f.history.expected, materials: f.materials,
    header: { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: binding.workspaceId,
      scope: 'workspace', scopeId: binding.workspaceId, recordId: binding.accountId, recordType: 'profile', schema: 1,
      keyEpoch: binding.workspaceKeyEpoch, revision: binding.profile.revision, operationId: binding.operationId, accountId: f.accountId,
      deviceId: f.deviceId, keyGeneration: '1', permissionVersion: selectedRole.revision, securityVersion: binding.securityVersion,
      securityHead: binding.securityHead, dataGeneration: binding.dataGeneration, action: 'profile.invite', approvalPolicyId: null, approvalPolicyRevision: null },
  } }, f.bundle);
  const digest = await digestObject(issued.profile.envelope);
  binding.profile = { ...binding.profile, objectId: issued.profile.id, objectDigest: digest };
  f.materials.push({ id: issued.profile.id, digest, kind: 'encrypted_profile', value: issued.profile.envelope });
}
async function joinedFixture(scopeExpiry: string | null = null, owner = false) {
  const f = await ownerFixture(), binding = bindingFor(f, f.state, owner ? 'join_owner' : 'join_member'), exportKey = base64urlEncode(await randomKey());
  await pendingInvitation(f, binding);
  if (scopeExpiry !== null) binding.scopes = binding.scopes.map((scope) => ({ ...scope, expiresAt: scopeExpiry }));
  const phrase = owner ? await newOwnerPhrase() : undefined, positions = [2, 8, 20];
  const prepared = await prepareEnrolmentDraft({ mode: 'join', history: f.history, input: { binding, exportKey, registrationRecord: base64urlEncode(await randomKey()), displayName: name,
    configuration: { ...f.configuration, identifiers: { client: `ukda:${binding.workspaceId}:${binding.accountId}`, server: origin } },
    ...(phrase ? { newOwnerKit: { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) } } : {}) } });
  const approval = await approve(f, f.history, prepared, exportKey), receipt = await receiptFor(approval), current = await appended(f.history, approval.transition);
  const bundle = await unwrapDeviceBundle(enrolmentDeviceContext(prepared.draft.transcript), prepared.deviceWrapper, exportKey);
  const delivery: EnrolmentDelivery = { receipt, deliveries: approval.deliveries, materials: [
    ...(owner ? f.materials : []), { id: approval.profile!.id, kind: 'encrypted_profile', value: approval.profile!.envelope, digest: await digestObject(approval.profile!.envelope) },
  ] };
  return { f, binding, prepared, approval, receipt, current, bundle, exportKey, delivery, phrase };
}

test('CP06: approved JOIN ciphertext yields its private profile name and rejects missing or altered delivery', async () => {
  const f = await joinedFixture();
  assert.deepEqual(await verifyEnrolmentDelivery({ delivery: f.delivery, history: f.current.history }, f.bundle), { complete: true, scopeCount: 1, displayName: name });
  await assert.rejects(verifyEnrolmentDelivery({ delivery: { ...f.delivery, materials: [] }, history: f.current.history }, f.bundle));
  const altered = structuredClone(f.delivery); altered.deliveries[0]!.envelope.ciphertext = flip(altered.deliveries[0]!.envelope.ciphertext);
  await assert.rejects(verifyEnrolmentDelivery({ delivery: altered, history: f.current.history }, f.bundle));
  const stale = { ...f.current.history, expected: f.f.history.expected };
  await assert.rejects(verifyEnrolmentDelivery({ delivery: f.delivery, history: stale }, f.bundle));
});

test('CP06: an authentic Viewer invitation cannot be substituted with a history-valid Member approval', async () => {
  const f = await ownerFixture(), binding = bindingFor(f, f.state, 'join_member'), viewer = Object.values(f.state.roles).find((role) => role.template === 'viewer')!;
  assert.equal(viewer.revision, binding.role.revision, 'Different builtin roles intentionally share the same revision');
  await pendingInvitation(f, binding, { id: viewer.id, revision: viewer.revision, permissions: viewer.permissions });
  const exportKey = base64urlEncode(await randomKey()), prepared = await prepareEnrolmentDraft({ mode: 'join', history: f.history, input: { binding,
    exportKey, registrationRecord: base64urlEncode(await randomKey()), displayName: name,
    configuration: { ...f.configuration, identifiers: { client: `ukda:${binding.workspaceId}:${binding.accountId}`, server: origin } } } });
  // The recipient and history agree on the provider's substituted Member binding; the authentic original encrypted intent must still stop approval.
  const fingerprint = await digestObject(prepared.draft.transcript);
  prepared.draft.recipientConfirmation = await confirmEnrolmentTarget({ prepared, exportKey, history: f.history, fingerprint });
  await assert.rejects(prepareEnrolmentApproval({ draft: publicDraft(prepared), fingerprint, history: f.history, materials: f.materials }, f.bundle));
});

test('CP06: two-device promotion accepts only the current device and recovery delivery subset', async (t) => {
  const f = await joinedFixture(), signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  t.after(() => { signing.privateKey.fill(0); recipient.privateKey.fill(0); });
  const other = { id: randomUUID(), keyGeneration: '1', signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
  const operationId = randomUUID(), now = Date.now(), memberDevice = f.prepared.draft.transcript.device;
  const pair: PairingTranscript = { version: 1, purpose: 'ukda.device-pair-transcript.v1', origin, workspaceId: f.binding.workspaceId, accountId: f.binding.accountId,
    operationId, ceremonyId: operationId, device: other, localBundleDigest: 'b'.repeat(64), approverAccountId: f.binding.accountId, approverDevice: memberDevice, approverIsOwner: false,
    credentialGeneration: '1', sessionGeneration: '1', approverCredentialGeneration: '1', approverSessionGeneration: '1', dataGeneration: '1', ownershipVersion: '1', custodyEpoch: '1',
    genesisFingerprint: f.binding.genesisFingerprint, securityHead: f.current.state.securityHead, securityVersion: f.current.state.securityVersion,
    scopes: f.current.state.profiles[f.binding.accountId]!.scopes.map(scopeFrom), issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 120_000).toISOString() };
  const digest = await digestObject(pair), memberSigning = base64urlDecode(f.bundle.signingPrivateKey, 64); t.after(() => memberSigning.fill(0));
  // Pairing ciphertext decryption has its own tests. The real signed grant establishes the second retained public identity here.
  const grant = await signObject({ version: 1 as const, purpose: 'ukda.device-pair-grant.v1' as const, operationId, workspaceId: f.binding.workspaceId, grantId: operationId,
    securityVersion: next(pair.securityVersion), previousHead: pair.securityHead, transcript: pair, transcriptDigest: digest,
    recipientConfirmation: await signObject(pairingConfirmationFor(pair, digest, 'recipient'), signing.privateKey),
    approverConfirmation: await signObject(pairingConfirmationFor(pair, digest, 'approver'), memberSigning),
    deliveries: pair.scopes.map((scope) => ({ id: randomUUID(), scope: scope.scope, scopeId: scope.scopeId, digest: 'c'.repeat(64) })) }, memberSigning);
  const paired = await appended(f.current.history, grant), binding = bindingFor(f.f, paired.state, 'promote_owner', f.binding.accountId);
  const phrase = await newOwnerPhrase(), positions = [2, 8, 20];
  const prepared = await prepareEnrolmentDraft({ mode: 'promotion', history: paired.history, input: { binding, deviceId: memberDevice.id,
    existingWrapper: f.prepared.deviceWrapper, exportKey: f.exportKey, newOwnerKit: { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) } } });
  const approval = await approve(f.f, paired.history, prepared, f.exportKey), receipt = await receiptFor(approval), promoted = await appended(paired.history, approval.transition);
  assert.equal(approval.deliveries.length, 3); assert.equal(approval.profile, null); assert.equal(canonicalJson(prepared.deviceWrapper), canonicalJson(f.prepared.deviceWrapper));
  const own = approval.deliveries.filter((entry) => entry.envelope.header.recipientKind === 'recovery' || entry.envelope.header.recipientId === memberDevice.id);
  assert.equal(own.length, 2);
  const delivery = { receipt, deliveries: own, materials: f.f.materials };
  assert.deepEqual(await verifyEnrolmentDelivery({ delivery, history: promoted.history, newOwnerPhrase: phrase }, f.bundle), { complete: true, scopeCount: 1 });
  await assert.rejects(verifyEnrolmentDelivery({ delivery: { ...delivery, deliveries: approval.deliveries }, history: promoted.history, newOwnerPhrase: phrase }, f.bundle));
  await assert.rejects(verifyEnrolmentDelivery({ delivery: { ...delivery, deliveries: own.filter((entry) => entry.envelope.header.recipientKind === 'device') }, history: promoted.history, newOwnerPhrase: phrase }, f.bundle));
  await assert.rejects(verifyEnrolmentDelivery({ delivery, history: promoted.history, newOwnerPhrase: await newOwnerPhrase() }, f.bundle));
});

test('CP06: a valid historical JOIN receipt does not authorize delivery after its personal and device lease expires', async (t) => {
  const deadline = Date.now() + 60_000, f = await joinedFixture(new Date(deadline).toISOString());
  assert.equal((await verifyEnrolmentDelivery({ delivery: f.delivery, history: f.current.history }, f.bundle)).complete, true);
  t.mock.timers.enable({ apis: ['Date'], now: deadline + 1 });
  await assert.rejects(verifyEnrolmentDelivery({ delivery: f.delivery, history: f.current.history }, f.bundle));
});

test('CP06: retired recipient keys are rejected before an approving Owner opens material or seals new custody', async (t) => {
  const f = await ownerFixture(), signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  const oldSigning = base64urlDecode(f.bundle.signingPrivateKey, 64);
  t.after(() => { signing.privateKey.fill(0); recipient.privateKey.fill(0); oldSigning.fill(0); });
  const device = { id: randomUUID(), keyGeneration: '1', signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
  const operationId = randomUUID(), now = Date.now();
  const pair: PairingTranscript = { version: 1, purpose: 'ukda.device-pair-transcript.v1', origin, workspaceId: f.history.workspaceId, accountId: f.accountId,
    operationId, ceremonyId: operationId, device, localBundleDigest: 'd'.repeat(64), approverAccountId: f.accountId,
    approverDevice: { ...f.history.genesis.body.device, keyGeneration: '1' }, approverIsOwner: true,
    credentialGeneration: '1', sessionGeneration: '1', approverCredentialGeneration: '1', approverSessionGeneration: '1', dataGeneration: '1', ownershipVersion: '1', custodyEpoch: '1',
    genesisFingerprint: f.history.genesisFingerprint, securityHead: f.state.securityHead, securityVersion: '1', scopes: f.state.profiles[f.accountId]!.scopes.map(scopeFrom),
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 120_000).toISOString() };
  const digest = await digestObject(pair);
  const grant = await signObject({ version: 1 as const, purpose: 'ukda.device-pair-grant.v1' as const, operationId, workspaceId: f.history.workspaceId, grantId: operationId,
    securityVersion: '2', previousHead: pair.securityHead, transcript: pair, transcriptDigest: digest,
    recipientConfirmation: await signObject(pairingConfirmationFor(pair, digest, 'recipient'), signing.privateKey),
    approverConfirmation: await signObject(pairingConfirmationFor(pair, digest, 'approver'), oldSigning),
    deliveries: pair.scopes.map((scope) => ({ id: randomUUID(), scope: scope.scope, scopeId: scope.scopeId, digest: 'e'.repeat(64) })) }, oldSigning);
  const paired = await appended(f.history, grant);
  const change = await signObject({ version: 1 as const, purpose: 'ukda.password-change.v1' as const,
    binding: { version: 1 as const, origin, workspaceId: f.history.workspaceId, accountId: f.accountId, operationId: randomUUID(), deviceId: device.id,
      keyGeneration: '1', credentialGeneration: '1', nextCredentialGeneration: '2', sessionGeneration: '1', nextSessionGeneration: '2',
      dataGeneration: '1', securityVersion: '2', nextSecurityVersion: '3', securityHead: paired.state.securityHead, ownershipVersion: '1', custodyEpoch: '1',
      signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 120_000).toISOString() },
    registrationRecordHash: '1'.repeat(64), configurationHash: await digestObject(f.configuration), wrapperHash: '2'.repeat(64), revokeOtherDevices: true as const, revokeAllSessions: true as const }, signing.privateKey);
  const retired = await appended(paired.history, change);
  assert.equal(retired.state.devices[f.deviceId]?.active, false, 'Signed password change retires the original device');
  const current = { ...f, history: retired.history, state: retired.state, deviceId: device.id,
    bundle: { signingPrivateKey: base64urlEncode(signing.privateKey), recipientPrivateKey: base64urlEncode(recipient.privateKey), signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey } };
  const binding = bindingFor(current, retired.state, 'join_owner'), phrase = await newOwnerPhrase(), positions = [2, 8, 20];
  const prepared = await prepareEnrolmentDraft({ mode: 'join', history: retired.history, input: { binding, exportKey: base64urlEncode(await randomKey()),
    registrationRecord: base64urlEncode(await randomKey()), displayName: name, configuration: { ...f.configuration, identifiers: { client: `ukda:${binding.workspaceId}:${binding.accountId}`, server: origin } },
    newOwnerKit: { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) } } });
  const historicalKey = f.bundle.recipientPublicKey;
  const failure = (error: unknown) => error instanceof SecurityHistoryError && error.code === 'INVALID_HISTORY';
  for (const kind of ['device', 'recovery'] as const) {
    const draft = publicDraft(structuredClone(prepared)); draft.transcript[kind]!.recipientPublicKey = historicalKey;
    assert.throws(() => verifyEnrolmentTranscriptAgainstHistory(draft.transcript, retired.state), failure);
    // No encrypted materials are supplied: authority rejection must happen before any decryption/sealing attempt or generic missing-material error.
    await assert.rejects(prepareEnrolmentApproval({ draft, fingerprint: await digestObject(draft.transcript), history: retired.history, materials: [] }, current.bundle), failure);
  }
});

function rawDatabase(factory: IDBFactory, databaseName: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => { const request = factory.open(databaseName, 1); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
}
function rawTransaction<T>(database: IDBDatabase, action: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => { const transaction = database.transaction('operations', 'readwrite'), request = action(transaction.objectStore('operations'));
    transaction.oncomplete = () => resolve(request.result); transaction.onerror = transaction.onabort = () => reject(transaction.error); });
}
test('CP06: IndexedDB preserves encrypted drafts across CAS conflicts and Forget removes a corrupted matching draft', async (t) => {
  const f = await joinedFixture(null, true), factory = new IDBFactory(), databaseName = randomUUID();
  const first = await IndexedEnrolmentStore.open(origin, databaseName, factory), second = await IndexedEnrolmentStore.open(origin, databaseName, factory), raw = await rawDatabase(factory, databaseName);
  t.after(() => { first.close(); second.close(); raw.close(); });
  const record: EnrolmentRecord = { version: 1, role: 'recipient', localId: randomUUID(), revision: 1, origin, workspaceId: f.binding.workspaceId,
    accountId: f.binding.accountId, deviceId: f.prepared.draft.transcript.device.id, operationId: f.binding.operationId, resumeToken: base64urlEncode(await randomKey()),
    genesisFingerprint: f.binding.genesisFingerprint, view: null, prepared: f.prepared, approval: null, receipt: null };
  await first.put(record, 0);
  const updates = await Promise.allSettled([first.put({ ...record, revision: 2 }, 1), second.put({ ...record, revision: 2 }, 1)]);
  assert.equal(updates.filter((result) => result.status === 'fulfilled').length, 1);
  const failed = updates.find((result) => result.status === 'rejected'); assert.ok(failed?.status === 'rejected' && failed.reason instanceof EnrolmentStoreError && failed.reason.code === 'CONFLICT');
  const stored = await second.get('recipient', record.localId); assert.equal(stored?.revision, 2);
  await verifyEnrolmentDraft({ prepared: stored!.prepared!, exportKey: f.exportKey, history: f.f.history });
  const rows = await rawTransaction(raw, (store) => store.getAll()), serialized = JSON.stringify(rows);
  for (const secret of [name, f.phrase!, f.f.phrase, f.exportKey, f.bundle.signingPrivateKey, f.bundle.recipientPrivateKey]) assert.equal(serialized.includes(secret), false, 'Persisted draft contains private plaintext');
  const key = `${origin}:recipient:${record.localId}`, corrupted = structuredClone(stored!);
  corrupted.prepared!.deviceWrapper.ciphertext = flip(corrupted.prepared!.deviceWrapper.ciphertext);
  await rawTransaction(raw, (store) => store.put(corrupted, key));
  await assert.rejects(verifyEnrolmentDraft({ prepared: (await first.get('recipient', record.localId))!.prepared!, exportKey: f.exportKey, history: f.f.history }));
  await rawTransaction(raw, (store) => store.put({ ...corrupted, prepared: { broken: true } }, key));
  await assert.rejects(first.get('recipient', record.localId));
  assert.equal((await first.capability(record.localId))?.operationId, record.operationId, 'Cancellation locator survives encrypted draft corruption');
  await first.forgetDevice({ workspaceId: record.workspaceId, accountId: record.accountId!, deviceId: record.deviceId! });
  assert.equal(await first.get('recipient', record.localId), undefined);
  assert.equal((await rawTransaction(raw, (store) => store.getAll())).length, 0);
});

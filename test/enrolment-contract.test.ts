import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test, { type TestContext } from 'node:test';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING } from '../src/client/opaque.js';
import { capabilities } from '../src/shared/contracts.js';
import { base64urlEncode, canonicalJson, decryptContent, digestObject, encryptContent, generateRecipientKeyPair,
  generateSigningKeyPair, openRecipient, randomKey, sealRecipient, signObject } from '../src/shared/crypto.js';
import { JOIN_CODE_ALPHABET, generateJoinCode, joinCode, enrolmentBinding, enrolmentTranscript, enrolmentOperationReference,
  enrolmentSetupNamePayload, enrolmentLabelContext, enrolmentLabelContextHash, enrolmentSetupNameHeader, enrolmentRecipientHeader,
  enrolmentRecipientDevices, enrolmentProfileHeader, enrolmentConfirmationFor, EnrolmentContractError,
  validateEnrolmentDraft, validateEnrolmentPublicDraft, validateEnrolmentPublicApproval, validateEnrolmentApproval,
  validateEnrolmentPayload, validateEnrolmentReceipt, type EnrolmentBinding, type EnrolmentPreName, type EnrolmentTranscript,
  type EnrolmentDraft, type EnrolmentApproval, type EnrolmentPayload, type EnrolmentReceipt } from '../src/shared/enrolment.js';

const invalid = (error: unknown) => error instanceof EnrolmentContractError;
const origin = 'https://ukda.example';
async function fixture(t: TestContext, kind: EnrolmentBinding['kind'] = 'join_member') {
  const [ownerSign, ownerRecipient, targetSign, targetRecipient, secondSign, secondRecipient, recoverySign, recoveryRecipient] =
    await Promise.all([generateSigningKeyPair(), generateRecipientKeyPair(), generateSigningKeyPair(), generateRecipientKeyPair(),
      generateSigningKeyPair(), generateRecipientKeyPair(), generateSigningKeyPair(), generateRecipientKeyPair()]);
  t.after(() => [ownerSign, ownerRecipient, targetSign, targetRecipient, secondSign, secondRecipient, recoverySign, recoveryRecipient]
    .forEach((key) => key.privateKey.fill(0)));
  const workspaceId = randomUUID(), accountId = randomUUID(), operationId = randomUUID(), projectId = randomUUID();
  const promotion = kind === 'promote_owner', owner = kind !== 'join_member';
  const device = { id: randomUUID(), keyGeneration: '1', signingPublicKey: base64urlEncode(targetSign.publicKey), recipientPublicKey: base64urlEncode(targetRecipient.publicKey) };
  const secondDevice = { id: randomUUID(), keyGeneration: '3', signingPublicKey: base64urlEncode(secondSign.publicKey), recipientPublicKey: base64urlEncode(secondRecipient.publicKey) };
  const source = () => ({ grantId: randomUUID(), generation: '1', manifestId: randomUUID(), manifestDigest: 'c'.repeat(64) });
  const binding: EnrolmentBinding = { version: 1, kind, origin, workspaceId, accountId, operationId,
    approvalAttemptId: randomUUID(), attemptGeneration: '1', invitationGeneration: promotion ? '0' : '2',
    profile: { id: accountId, revision: '2', objectId: randomUUID(), objectDigest: 'd'.repeat(64) }, nextProfileRevision: promotion ? '2' : '3',
    role: { id: randomUUID(), revision: '2', permissions: owner ? [...capabilities] : ['read_project', 'comment', 'create_tasks', 'edit_assigned_tasks'] },
    credentialGeneration: promotion ? '8' : '0', nextCredentialGeneration: promotion ? '8' : '1',
    sessionGeneration: promotion ? '7' : '0', nextSessionGeneration: promotion ? '8' : '1',
    recoveryGeneration: promotion ? '3' : '0', nextRecoveryGeneration: promotion ? '4' : owner ? '1' : '0',
    deviceKeyGeneration: promotion ? '3' : '0', nextDeviceKeyGeneration: promotion ? '3' : '1',
    ownershipVersion: '4', nextOwnershipVersion: owner ? '5' : '4', securityVersion: '8', nextSecurityVersion: '9',
    securityHead: 'a'.repeat(64), genesisFingerprint: 'b'.repeat(64), dataGeneration: '1', custodyEpoch: '9', workspaceKeyEpoch: '7',
    authorizer: { accountId: randomUUID(), credentialGeneration: '2', sessionGeneration: '3', device: { id: randomUUID(), keyGeneration: '2',
      signingPublicKey: base64urlEncode(ownerSign.publicKey), recipientPublicKey: base64urlEncode(ownerRecipient.publicKey) } },
    currentDevices: promotion ? [device, secondDevice] : [],
    scopes: [{ scope: 'workspace', scopeId: workspaceId, mode: owner ? 'custody' : 'content', keyEpoch: owner ? '9' : '7',
      permissions: owner ? [...capabilities] : ['read_project'], expiresAt: null, sources: [source()] },
    { scope: 'project', scopeId: projectId, mode: 'content', keyEpoch: '2', permissions: ['read_project', 'comment'], expiresAt: null, sources: [source()] }],
    issuedAt: '2026-09-26T12:00:00.000Z', expiresAt: '2026-09-26T13:00:00.000Z' };
  const registrationRecord = promotion ? null : base64urlEncode(await randomKey());
  const preName: EnrolmentPreName = { version: 1, binding, device,
    recovery: owner ? { id: randomUUID(), generation: binding.nextRecoveryGeneration, signingPublicKey: base64urlEncode(recoverySign.publicKey),
      recipientPublicKey: base64urlEncode(recoveryRecipient.publicKey) } : null, wrapperHash: 'e'.repeat(64),
    configuration: promotion ? null : { configId: OPAQUE_CONFIG_ID, setupId: 'enrolment-contract', keyStretching: OPAQUE_KEY_STRETCHING,
      serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } },
    registrationRecordHash: registrationRecord ? await digestObject(registrationRecord) : null };
  const labelHash = promotion ? null : await enrolmentLabelContextHash(preName);
  const name = 'Private joining person';
  const setupName = labelHash ? await sealRecipient(enrolmentSetupNameHeader(preName, labelHash), enrolmentSetupNamePayload.parse({ version: 1,
    mode: 'setup_name', workspaceId, accountId, operationId, approvalAttemptId: binding.approvalAttemptId,
    attemptGeneration: binding.attemptGeneration, labelContextDigest: labelHash, displayName: name }), targetSign.privateKey) : null;
  const transcript: EnrolmentTranscript = { ...preName, purpose: 'ukda.enrolment-transcript.v1', setupNameDigest: setupName ? await digestObject(setupName) : null };
  const transcriptDigest = await digestObject(transcript);
  const recipientConfirmation = await signObject(enrolmentConfirmationFor(transcript, transcriptDigest, 'recipient'), targetSign.privateKey);
  const authorizerConfirmation = await signObject(enrolmentConfirmationFor(transcript, transcriptDigest, 'authorizer'), ownerSign.privateKey);
  const newRecoveryConfirmation = owner ? await signObject(enrolmentConfirmationFor(transcript, transcriptDigest, 'new_recovery'), recoverySign.privateKey) : null;
  const draft: EnrolmentDraft = { transcript, registrationRecord, setupName, recipientConfirmation, newRecoveryConfirmation };
  const deliveries: EnrolmentApproval['deliveries'] = [];
  for (const scope of binding.scopes) {
    for (const recipient of enrolmentRecipientDevices(transcript)) deliveries.push({ id: randomUUID(), envelope:
      await sealRecipient(enrolmentRecipientHeader(transcript, transcriptDigest, scope, 'device', recipient.id),
        { version: 1, mode: scope.mode, retainedEpochs: ['1', scope.keyEpoch], key: base64urlEncode(await randomKey()) }, ownerSign.privateKey) });
    if (scope.mode === 'custody') deliveries.push({ id: randomUUID(), envelope:
      await sealRecipient(enrolmentRecipientHeader(transcript, transcriptDigest, scope, 'recovery'),
        { version: 1, mode: 'custody', key: base64urlEncode(await randomKey()) }, ownerSign.privateKey) });
  }
  const descriptors = await Promise.all(deliveries.map(async (entry) => ({ id: entry.id, scope: entry.envelope.header.scope,
    scopeId: entry.envelope.header.scopeId, keyEpoch: entry.envelope.header.keyEpoch, recipientKind: entry.envelope.header.recipientKind,
    recipientId: entry.envelope.header.recipientId, digest: await digestObject(entry.envelope) })));
  const workspaceKey = await randomKey(); t.after(() => workspaceKey.fill(0));
  const profile = promotion ? null : { id: randomUUID(), envelope: await encryptContent(enrolmentProfileHeader(transcript), { displayName: name }, workspaceKey, ownerSign.privateKey) };
  const transition = await signObject({ version: 1 as const, purpose: promotion ? 'ukda.owner-promotion.v1' as const : 'ukda.profile-enrolment.v1' as const,
    transcript, transcriptDigest, recipientConfirmation, authorizerConfirmation, newRecoveryConfirmation, deliveries: descriptors,
    profile: profile ? { id: profile.id, profileId: accountId, revision: binding.nextProfileRevision, digest: await digestObject(profile.envelope) } : null }, ownerSign.privateKey);
  const approval: EnrolmentApproval = { transition, deliveries, profile };
  const payload: EnrolmentPayload = { ...approval, registrationRecord, setupName };
  const receipt: EnrolmentReceipt = { version: 1, operationId, approvalAttemptId: binding.approvalAttemptId, attemptGeneration: '1',
    workspaceId, accountId, deviceId: device.id, credentialGeneration: binding.nextCredentialGeneration, sessionGeneration: binding.nextSessionGeneration,
    keyGeneration: device.keyGeneration, recoveryGeneration: binding.nextRecoveryGeneration, ownershipVersion: binding.nextOwnershipVersion,
    profileRevision: binding.nextProfileRevision, dataGeneration: binding.dataGeneration, securityVersion: binding.nextSecurityVersion,
    securityHead: await digestObject(transition), requestHash: await digestObject(payload), wrapperHash: transcript.wrapperHash,
    committedAt: '2026-09-26T12:15:00.000Z', transition };
  const resign = async (changed: EnrolmentPayload) => ({ ...changed, transition: await signObject(changed.transition.body, ownerSign.privateKey) });
  return { binding, preName, transcript, draft, approval, payload, receipt, ownerSign, ownerRecipient, targetSign, targetRecipient,
    workspaceKey, name, resign, labelHash };
}

test('CP06: JOIN is exactly twelve readable base32 symbols, distinct from RESET and private resume capabilities', () => {
  assert.equal(JOIN_CODE_ALPHABET.length, 32); assert.equal(new Set(JOIN_CODE_ALPHABET).size, 32);
  const codes = new Set(Array.from({ length: 128 }, generateJoinCode)); assert.equal(codes.size, 128);
  for (const code of codes) assert.equal(joinCode.safeParse(code).success, true);
  for (const code of ['RESET-ABCD-EFGH-JKLM', 'JOIN-ABCD-EFGH-JKLO', 'JOIN-ABCD-EFGH-JKL0', 'join-abcd-efgh-jklm', 'JOIN-ABCD-EFGH-JKLM '])
    assert.equal(joinCode.safeParse(code).success, false);
  assert.equal(enrolmentOperationReference.safeParse({ workspaceId: randomUUID(), operationId: randomUUID(), resumeToken: base64urlEncode(new Uint8Array(32)) }).success, false);
});

for (const kind of ['join_member', 'join_owner', 'promote_owner'] as const) test(`CP06: ${kind} verifies exact signed draft, delivery, profile and receipt`, async (t) => {
  const f = await fixture(t, kind), checked = await validateEnrolmentApproval(f.approval, f.draft, f.binding, f.transcript.configuration);
  assert.equal(checked.requestHash, f.receipt.requestHash);
  assert.equal((await validateEnrolmentPublicApproval(f.approval, f.binding, f.transcript.configuration)).securityHead, f.receipt.securityHead);
  assert.equal(canonicalJson(await validateEnrolmentReceipt(f.receipt, f.transcript)), canonicalJson(f.receipt));
  const { registrationRecord: _record, ...publicDraft } = f.draft;
  await validateEnrolmentPublicDraft(publicDraft, f.binding);
  await assert.rejects(validateEnrolmentPublicDraft({ ...publicDraft, registrationRecord: f.draft.registrationRecord }, f.binding), invalid);
  assert.equal(JSON.stringify(f.payload).includes(f.name), false);
  for (const secret of [base64urlEncode(f.targetSign.privateKey), base64urlEncode(f.ownerSign.privateKey), base64urlEncode(f.workspaceKey)])
    assert.equal(JSON.stringify(f.payload).includes(secret), false);
});

test('CP06: private JOIN label has acyclic exact attempt context and uses the workspace content epoch, not custody epoch', async (t) => {
  const f = await fixture(t, 'join_owner'), context = enrolmentLabelContext(f.preName);
  assert.equal(Object.hasOwn(context, 'setupNameDigest'), false); assert.equal(context.purpose, 'ukda.enrolment-label-context.v1');
  assert.notEqual(f.labelHash, await digestObject(f.transcript));
  assert.equal(f.draft.setupName!.header.keyEpoch, '7'); assert.equal(f.binding.custodyEpoch, '9');
  const clear = enrolmentSetupNamePayload.parse(await openRecipient(f.draft.setupName!, f.ownerRecipient.privateKey, f.targetSign.publicKey,
    enrolmentSetupNameHeader(f.preName, f.labelHash!)));
  assert.equal(clear.displayName, f.name); assert.equal(clear.approvalAttemptId, f.binding.approvalAttemptId);
  assert.equal(canonicalJson(await decryptContent(f.payload.profile!.envelope, f.workspaceKey, f.ownerSign.publicKey,
    enrolmentProfileHeader(f.transcript))), canonicalJson({ displayName: f.name }));
  assert.equal(f.payload.profile!.envelope.header.revision, '3'); assert.equal(f.payload.profile!.envelope.header.keyEpoch, '7');
});

test('CP06: takeover changes the immutable approval attempt without accepting old confirmations or replayed label packets', async (t) => {
  const f = await fixture(t, 'join_owner'), changed = structuredClone(f.binding);
  changed.approvalAttemptId = randomUUID(); changed.attemptGeneration = '2';
  await assert.rejects(validateEnrolmentPayload(f.payload, changed, f.transcript.configuration), invalid);
  const replacement = structuredClone(f.draft); replacement.transcript.binding = changed;
  assert.notEqual(await enrolmentLabelContextHash({ ...f.preName, binding: changed }), f.labelHash);
  assert.equal(replacement.transcript.wrapperHash, f.transcript.wrapperHash);
  assert.equal(replacement.transcript.registrationRecordHash, f.transcript.registrationRecordHash);
  await assert.rejects(validateEnrolmentDraft(replacement, changed, f.transcript.configuration), invalid);
  const swapped = structuredClone(f.payload); swapped.transition.body.authorizerConfirmation.body.approvalAttemptId = changed.approvalAttemptId;
  await assert.rejects(validateEnrolmentPayload(await f.resign(swapped), f.binding, f.transcript.configuration), invalid);
});

test('CP06: ordinary JOIN cannot gain ownership, phrase custody or a scope not present in trusted selected access', async (t) => {
  const f = await fixture(t), custody = structuredClone(f.binding); custody.scopes[0]!.mode = 'custody';
  assert.equal(enrolmentBinding.safeParse(custody).success, false);
  assert.equal(enrolmentBinding.safeParse({ ...f.binding, nextOwnershipVersion: '5' }).success, false);
  assert.equal(enrolmentBinding.safeParse({ ...f.binding, nextRecoveryGeneration: '1' }).success, false);
  assert.equal(enrolmentTranscript.safeParse({ ...f.transcript, recovery: { id: randomUUID(), generation: '1',
    signingPublicKey: base64urlEncode(await randomKey()), recipientPublicKey: base64urlEncode(await randomKey()) } }).success, false);
  const otherProject = structuredClone(f.binding); otherProject.scopes[1]!.scopeId = randomUUID();
  await assert.rejects(validateEnrolmentPayload(f.payload, otherProject, f.transcript.configuration), invalid);
  const otherRole = structuredClone(f.binding); otherRole.role.revision = '3';
  await assert.rejects(validateEnrolmentPayload(f.payload, otherRole, f.transcript.configuration), invalid);
});

test('CP06: promotion preserves OPAQUE, profile and every healthy device, with each original device generation', async (t) => {
  const f = await fixture(t, 'promote_owner');
  assert.equal(f.draft.registrationRecord, null); assert.equal(f.transcript.configuration, null); assert.equal(f.payload.profile, null);
  assert.equal(f.binding.nextCredentialGeneration, '8'); assert.equal(f.binding.nextSessionGeneration, '8');
  assert.equal(f.binding.nextRecoveryGeneration, '4', 'A former Owner receives a fresh generation, not generation one');
  assert.equal(f.receipt.keyGeneration, '1'); assert.equal(f.binding.deviceKeyGeneration, '3');
  for (const device of f.binding.currentDevices) for (const scope of f.binding.scopes) {
    const delivered = f.payload.deliveries.find((entry) => entry.envelope.header.recipientId === device.id && entry.envelope.header.scopeId === scope.scopeId);
    assert.equal(delivered?.envelope.header.recipientKeyGeneration, device.keyGeneration);
  }
  for (const altered of [{ ...f.binding, nextCredentialGeneration: '9' }, { ...f.binding, nextDeviceKeyGeneration: '4' },
    { ...f.binding, nextProfileRevision: '3' }, { ...f.binding, invitationGeneration: '1' }]) assert.equal(enrolmentBinding.safeParse(altered).success, false);
  await assert.rejects(validateEnrolmentPayload({ ...f.payload, registrationRecord: base64urlEncode(await randomKey()) }, f.binding, null), invalid);
  assert.equal(enrolmentTranscript.safeParse({ ...f.transcript, device: { ...f.transcript.device, id: randomUUID() } }).success, false);
  const missing = structuredClone(f.payload); missing.transition.body.deliveries.pop(); missing.deliveries.pop();
  await assert.rejects(validateEnrolmentPayload(await f.resign(missing), f.binding, null), invalid);
});

test('CP06: draft proof does not replace full target/Owner confirmation and Owner phrase verification', async (t) => {
  const f = await fixture(t, 'join_owner'), pending = { ...f.draft, recipientConfirmation: null };
  const start = await validateEnrolmentDraft(pending, f.binding, f.transcript.configuration);
  assert.equal(start.draftHash, (await validateEnrolmentDraft(f.draft, f.binding, f.transcript.configuration)).draftHash);
  await assert.rejects(validateEnrolmentApproval(f.approval, pending, f.binding, f.transcript.configuration), invalid);
  await assert.rejects(validateEnrolmentDraft({ ...f.draft, newRecoveryConfirmation: null }, f.binding, f.transcript.configuration), invalid);
  const changed = structuredClone(f.payload); changed.transition.body.authorizerConfirmation = f.draft.recipientConfirmation!;
  await assert.rejects(validateEnrolmentPayload(await f.resign(changed), f.binding, f.transcript.configuration), invalid);
});

test('CP06: credential, private-name, delivery and profile tampering fail despite a new outer Owner signature', async (t) => {
  const f = await fixture(t, 'join_owner');
  const modifications: ((payload: EnrolmentPayload) => void)[] = [
    (p) => { p.registrationRecord = base64urlEncode(new Uint8Array(32)); },
    (p) => { p.setupName!.header.ceremonyId = randomUUID(); },
    (p) => { p.deliveries[0]!.envelope.header.recipientId = randomUUID(); },
    (p) => { p.deliveries[0]!.envelope.ciphertext = base64urlEncode(new Uint8Array(64)); },
    (p) => { p.transition.body.deliveries[0]!.scopeId = randomUUID(); },
    (p) => { p.transition.body.deliveries[1]!.id = p.transition.body.deliveries[0]!.id; },
    (p) => { p.profile!.envelope.header.revision = '4'; },
    (p) => { p.transition.body.profile!.id = f.binding.profile.objectId; p.profile!.id = f.binding.profile.objectId; },
    (p) => { p.transition.body.profile!.revision = '4'; },
  ];
  for (const modify of modifications) { const changed = structuredClone(f.payload); modify(changed);
    await assert.rejects(validateEnrolmentPayload(await f.resign(changed), f.binding, f.transcript.configuration), invalid); }
  await assert.rejects(validateEnrolmentPayload({ ...f.payload, password: 'never a protocol field' }, f.binding, f.transcript.configuration), invalid);
});

test('CP06: receipt binds operation, immutable attempt, exact preserved device and resulting authority', async (t) => {
  const f = await fixture(t, 'promote_owner');
  for (const [field, value] of Object.entries({ operationId: randomUUID(), approvalAttemptId: randomUUID(), attemptGeneration: '2', accountId: randomUUID(),
    deviceId: f.binding.currentDevices[1]!.id, credentialGeneration: '9', ownershipVersion: '6', profileRevision: '3',
    keyGeneration: '3', securityHead: 'f'.repeat(64), wrapperHash: 'f'.repeat(64) })) {
    await assert.rejects(validateEnrolmentReceipt({ ...f.receipt, [field]: value }, f.transcript), invalid);
  }
});

test('CP06: malformed counters, identities, purpose, expiry and stale authority fail closed', async (t) => {
  const f = await fixture(t, 'join_owner');
  for (const field of ['attemptGeneration', 'invitationGeneration', 'credentialGeneration', 'nextCredentialGeneration', 'sessionGeneration',
    'nextSessionGeneration', 'recoveryGeneration', 'nextRecoveryGeneration', 'deviceKeyGeneration', 'nextDeviceKeyGeneration',
    'ownershipVersion', 'nextOwnershipVersion', 'securityVersion', 'nextSecurityVersion', 'workspaceKeyEpoch', 'custodyEpoch']) {
    for (const value of ['invalid', '-1', '01', '9223372036854775808']) assert.doesNotThrow(() =>
      assert.equal(enrolmentBinding.safeParse({ ...f.binding, [field]: value }).success, false));
  }
  for (const value of [{ ...f.binding, expiresAt: '2026-09-26T13:00:00.001Z' }, { ...f.binding, origin: 'https://ukda.example/path' },
    { ...f.binding, approvalAttemptId: f.binding.operationId }, { ...f.binding, profile: { ...f.binding.profile, id: randomUUID() } }])
    assert.equal(enrolmentBinding.safeParse(value).success, false);
  for (const field of ['securityHead', 'genesisFingerprint'] as const) await assert.rejects(validateEnrolmentPayload(f.payload,
    { ...f.binding, [field]: 'f'.repeat(64) }, f.transcript.configuration), invalid);
  const changed = structuredClone(f.payload); changed.transition.body.purpose = 'ukda.owner-promotion.v1';
  await assert.rejects(validateEnrolmentPayload(await f.resign(changed), f.binding, f.transcript.configuration), invalid);
});

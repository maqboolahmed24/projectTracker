import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { base64urlDecode, base64urlEncode, decryptContent, digestObject, generateRecipientKeyPair, generateSigningKeyPair, randomKey, verifyObject } from '../src/shared/crypto.js';
import { capabilities } from '../src/shared/contracts.js';
import { enrolmentBinding, enrolmentProfileHeader, validateEnrolmentDraft, type EnrolmentBinding } from '../src/shared/enrolment.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../src/client/opaque.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { wrapDeviceBundle, unwrapDeviceBundle, type DeviceBundle } from '../src/client/device-store.js';
import { wrapSetupName, unwrapSetupName, prepareJoinEnrolment, rebindJoinEnrolment, preparePromotionEnrolment,
  verifyPreparedEnrolment, confirmEnrolmentRecipient, confirmEnrolmentAuthorizer, openEnrolmentSetupName,
  encryptEnrolmentProfile, type SetupNameContext, type NewEnrolmentOwnerKit, type PreparedEnrolment } from '../src/client/enrolment-crypto.js';

const origin = 'https://ukda.example';
function flip(value: string): string { const bytes = base64urlDecode(value); bytes[0] = bytes[0]! ^ 1; return base64urlEncode(bytes); }
async function device(t: TestContext, generation = '1') {
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  t.after(() => { signing.privateKey.fill(0); recipient.privateKey.fill(0); });
  const publicDevice = { id: randomUUID(), keyGeneration: generation, signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
  const bundle: DeviceBundle = { signingPrivateKey: base64urlEncode(signing.privateKey), recipientPrivateKey: base64urlEncode(recipient.privateKey),
    signingPublicKey: publicDevice.signingPublicKey, recipientPublicKey: publicDevice.recipientPublicKey };
  return { publicDevice, bundle };
}
async function kit(): Promise<NewEnrolmentOwnerKit> {
  const phrase = await newOwnerPhrase(), positions = [2, 7, 20]; return { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) };
}
/** Expected binding stands for independently verified current history; this slice does not simulate a membership server. */
async function fixture(t: TestContext, kind: EnrolmentBinding['kind'] = 'join_member') {
  const workspaceId = randomUUID(), accountId = randomUUID(), authorizerId = randomUUID(), owner = await device(t), now = Date.now();
  const permissions = kind === 'join_member' ? ['read_project', 'comment'] as const : capabilities;
  const binding = enrolmentBinding.parse({ version: 1, kind, origin, workspaceId, accountId, operationId: randomUUID(), approvalAttemptId: randomUUID(), attemptGeneration: '1', invitationGeneration: '1',
    profile: { id: accountId, revision: '1', objectId: randomUUID(), objectDigest: 'a'.repeat(64) }, nextProfileRevision: '2',
    role: { id: randomUUID(), revision: '1', permissions: [...permissions] }, credentialGeneration: '0', nextCredentialGeneration: '1',
    sessionGeneration: '0', nextSessionGeneration: '1', recoveryGeneration: '0', nextRecoveryGeneration: kind === 'join_member' ? '0' : '1',
    deviceKeyGeneration: '0', nextDeviceKeyGeneration: '1', ownershipVersion: '3', nextOwnershipVersion: kind === 'join_member' ? '3' : '4',
    securityVersion: '7', nextSecurityVersion: '8', securityHead: 'b'.repeat(64), genesisFingerprint: 'c'.repeat(64), dataGeneration: '1', custodyEpoch: '5', workspaceKeyEpoch: '2',
    authorizer: { accountId: authorizerId, device: owner.publicDevice, credentialGeneration: '1', sessionGeneration: '1' }, currentDevices: [],
    scopes: [{ scope: 'workspace', scopeId: workspaceId, mode: kind === 'join_member' ? 'content' : 'custody', keyEpoch: kind === 'join_member' ? '2' : '5',
      permissions: [...permissions], expiresAt: null, sources: [{ grantId: randomUUID(), generation: '1', manifestId: randomUUID(), manifestDigest: 'd'.repeat(64) }] }],
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 3600000).toISOString() });
  const exportKey = base64urlEncode(await randomKey()), registrationRecord = base64urlEncode(await randomKey());
  const configuration: OpaquePublicConfiguration = { configId: OPAQUE_CONFIG_ID, keyStretching: OPAQUE_KEY_STRETCHING, setupId: 'enrolment-test',
    serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } };
  return { binding, owner, exportKey, registrationRecord, configuration };
}
const publicDraft = (prepared: PreparedEnrolment) => { const { registrationRecord: _record, ...draft } = prepared.draft; return draft; };
async function confirmed(prepared: PreparedEnrolment, exportKey: string, binding: EnrolmentBinding) {
  const fingerprint = await digestObject(prepared.draft.transcript);
  prepared.draft.recipientConfirmation = await confirmEnrolmentRecipient({ prepared, exportKey, fingerprint }, binding);
  return fingerprint;
}

test('CP06: local setup-name encryption uses fresh nonces, operation separation and exact authenticated context', async () => {
  const context: SetupNameContext = { origin, workspaceId: randomUUID(), accountId: randomUUID(), operationId: randomUUID(), credentialGeneration: '1' };
  const key = await randomKey(), copy = new Uint8Array(key), wrapper = await wrapSetupName(context, '  Rowan Example  ', key), next = await wrapSetupName(context, 'Rowan Example', key);
  assert.deepEqual(key, copy); assert.equal(await unwrapSetupName(context, wrapper, key), 'Rowan Example');
  assert.notEqual(wrapper.nonce, next.nonce); assert.notEqual(wrapper.ciphertext, next.ciphertext); assert.equal(JSON.stringify(wrapper).includes('Rowan'), false);
  for (const field of ['workspaceId', 'accountId', 'operationId'] as const) {
    await assert.rejects(unwrapSetupName({ ...context, [field]: randomUUID() }, wrapper, key));
    await assert.rejects(unwrapSetupName(context, { ...wrapper, header: { ...wrapper.header, [field]: randomUUID() } }, key));
  }
  await assert.rejects(unwrapSetupName({ ...context, origin: 'https://other.example' }, wrapper, key));
  await assert.rejects(unwrapSetupName({ ...context, credentialGeneration: '2' }, wrapper, key));
  await assert.rejects(unwrapSetupName(context, { ...wrapper, ciphertext: flip(wrapper.ciphertext) }, key));
  await assert.rejects(unwrapSetupName(context, wrapper, await randomKey()));
  await assert.rejects(wrapSetupName(context, ' ', key)); await assert.rejects(wrapSetupName(context, '\ud800', key));
  key.fill(0); copy.fill(0);
});

test('CP06: JOIN member encrypts the declared name to its exact Owner then emits a signed workspace profile ciphertext', async (t) => {
  const f = await fixture(t), prepared = await prepareJoinEnrolment({ ...f, displayName: 'Rowan Example' }, f.binding);
  assert.equal(prepared.draft.recipientConfirmation, null); assert.equal(prepared.draft.newRecoveryConfirmation, null);
  assert.equal(prepared.draft.transcript.recovery, null); assert.equal(prepared.draft.setupName?.header.keyEpoch, '2');
  await verifyPreparedEnrolment(prepared, f.exportKey, f.binding);
  const fingerprint = await digestObject(prepared.draft.transcript);
  await assert.rejects(openEnrolmentSetupName({ draft: publicDraft(prepared), fingerprint }, f.owner.bundle, f.binding));
  await assert.rejects(confirmEnrolmentRecipient({ prepared, exportKey: f.exportKey, fingerprint: fingerprint.slice(0, 8) }, f.binding));
  await confirmed(prepared, f.exportKey, f.binding);
  assert.equal(await openEnrolmentSetupName({ draft: publicDraft(prepared), fingerprint }, f.owner.bundle, f.binding), 'Rowan Example');
  const workspaceKey = await randomKey(); t.after(() => workspaceKey.fill(0));
  const profile = await encryptEnrolmentProfile({ draft: publicDraft(prepared), fingerprint }, f.owner.bundle, workspaceKey, f.binding);
  assert.equal(profile.envelope.header.keyEpoch, '2'); assert.equal(profile.envelope.header.revision, '2'); assert.equal(profile.envelope.header.recordId, f.binding.accountId);
  const decryptedProfile = await decryptContent(profile.envelope, workspaceKey, base64urlDecode(f.owner.publicDevice.signingPublicKey, 32), enrolmentProfileHeader(prepared.draft.transcript));
  assert.deepEqual(Object.keys(decryptedProfile as object), ['displayName']);
  assert.equal((decryptedProfile as { displayName: string }).displayName, 'Rowan Example');
  const proof = await confirmEnrolmentAuthorizer({ draft: publicDraft(prepared), fingerprint }, f.owner.bundle, f.binding);
  assert.equal(await verifyObject(proof, base64urlDecode(f.owner.publicDevice.signingPublicKey, 32), 'ukda.enrolment-confirmation.v1'), true);
  const json = JSON.stringify({ prepared, profile, proof });
  for (const secret of ['Rowan Example', f.exportKey, f.owner.bundle.signingPrivateKey, f.owner.bundle.recipientPrivateKey]) assert.equal(json.includes(secret), false);
});

test('CP06: Owner JOIN proves its independent phrase and rejects altered ciphertext or preverified authority', async (t) => {
  const f = await fixture(t, 'join_owner'), newOwnerKit = await kit();
  const prepared = await prepareJoinEnrolment({ ...f, displayName: 'Another Owner', newOwnerKit }, f.binding), fingerprint = await confirmed(prepared, f.exportKey, f.binding);
  await validateEnrolmentDraft(prepared.draft, f.binding, f.configuration);
  assert.ok(prepared.draft.newRecoveryConfirmation && prepared.draft.transcript.recovery);
  assert.equal(await verifyObject(prepared.draft.newRecoveryConfirmation, base64urlDecode(prepared.draft.transcript.recovery.signingPublicKey, 32), 'ukda.enrolment-confirmation.v1'), true);
  assert.notEqual(prepared.draft.transcript.recovery.signingPublicKey, prepared.draft.transcript.device.signingPublicKey);
  assert.equal(JSON.stringify(prepared).includes(newOwnerKit.phrase), false);
  await assert.rejects(prepareJoinEnrolment({ ...f, displayName: 'Another Owner' }, f.binding));
  await assert.rejects(prepareJoinEnrolment({ ...f, displayName: 'Another Owner', newOwnerKit: { ...newOwnerKit, answers: ['wrong', 'wrong', 'wrong'] } }, f.binding));
  await assert.rejects(verifyPreparedEnrolment(prepared, f.exportKey, { ...f.binding, securityHead: 'f'.repeat(64) }));
  const tampered = structuredClone(prepared); tampered.draft.setupName!.ciphertext = flip(tampered.draft.setupName!.ciphertext);
  await assert.rejects(openEnrolmentSetupName({ draft: publicDraft(tampered), fingerprint }, f.owner.bundle, f.binding));
  const wrongOwner = await device(t);
  await assert.rejects(openEnrolmentSetupName({ draft: publicDraft(prepared), fingerprint }, wrongOwner.bundle, f.binding));
  const wrongLocal = structuredClone(prepared); wrongLocal.deviceWrapper.ciphertext = flip(wrongLocal.deviceWrapper.ciphertext);
  await assert.rejects(confirmEnrolmentRecipient({ prepared: wrongLocal, exportKey: f.exportKey, fingerprint }, f.binding));
});

test('CP06: takeover reuses password/device/local name ciphertext while binding name and all proofs to the new Owner attempt', async (t) => {
  const f = await fixture(t, 'join_owner'), newOwnerKit = await kit(), prepared = await prepareJoinEnrolment({ ...f, displayName: 'Retained Name', newOwnerKit }, f.binding);
  const oldFingerprint = await confirmed(prepared, f.exportKey, f.binding), nextOwner = await device(t);
  const nextBinding = enrolmentBinding.parse({ ...f.binding, approvalAttemptId: randomUUID(), attemptGeneration: '2',
    authorizer: { ...f.binding.authorizer, accountId: randomUUID(), device: nextOwner.publicDevice } });
  const rebound = await rebindJoinEnrolment({ prepared, binding: nextBinding, exportKey: f.exportKey, newOwnerKit }, nextBinding);
  assert.deepEqual(rebound.deviceWrapper, prepared.deviceWrapper); assert.deepEqual(rebound.nameWrapper, prepared.nameWrapper);
  assert.equal(rebound.draft.registrationRecord, prepared.draft.registrationRecord); assert.deepEqual(rebound.draft.transcript.device, prepared.draft.transcript.device);
  assert.deepEqual(rebound.draft.transcript.recovery, prepared.draft.transcript.recovery); assert.equal(rebound.draft.recipientConfirmation, null);
  assert.notDeepEqual(rebound.draft.newRecoveryConfirmation, prepared.draft.newRecoveryConfirmation);
  assert.notEqual(rebound.draft.transcript.setupNameDigest, prepared.draft.transcript.setupNameDigest);
  await assert.rejects(confirmEnrolmentRecipient({ prepared: rebound, exportKey: f.exportKey, fingerprint: oldFingerprint }, nextBinding));
  const fingerprint = await confirmed(rebound, f.exportKey, nextBinding);
  assert.equal(await openEnrolmentSetupName({ draft: publicDraft(rebound), fingerprint }, nextOwner.bundle, nextBinding), 'Retained Name');
  await assert.rejects(openEnrolmentSetupName({ draft: publicDraft(rebound), fingerprint }, f.owner.bundle, nextBinding));
  await assert.rejects(rebindJoinEnrolment({ prepared, binding: nextBinding, exportKey: f.exportKey, newOwnerKit: await kit() }, nextBinding));
});

test('CP06: promotion retains the exact existing password wrapper, selected device and profile across unequal device generations', async (t) => {
  const f = await fixture(t, 'join_owner'), current = await device(t, '1'), other = await device(t, '4');
  const binding = enrolmentBinding.parse({ ...f.binding, kind: 'promote_owner', invitationGeneration: '0', credentialGeneration: '7', nextCredentialGeneration: '7',
    sessionGeneration: '8', nextSessionGeneration: '9', recoveryGeneration: '2', nextRecoveryGeneration: '3', deviceKeyGeneration: '4', nextDeviceKeyGeneration: '4',
    profile: { ...f.binding.profile, revision: '6' }, nextProfileRevision: '6', currentDevices: [current.publicDevice, other.publicDevice] });
  const context = { workspaceId: binding.workspaceId, accountId: binding.accountId, deviceId: current.publicDevice.id, credentialGeneration: '7' };
  const existingWrapper = await wrapDeviceBundle(context, current.bundle, f.exportKey), newOwnerKit = await kit();
  const prepared = await preparePromotionEnrolment({ binding, deviceId: current.publicDevice.id, existingWrapper, exportKey: f.exportKey, newOwnerKit }, binding);
  assert.deepEqual(prepared.deviceWrapper, existingWrapper); assert.deepEqual(await unwrapDeviceBundle(context, prepared.deviceWrapper, f.exportKey), current.bundle);
  assert.equal(prepared.nameWrapper, null); assert.equal(prepared.draft.setupName, null); assert.equal(prepared.draft.registrationRecord, null);
  assert.equal(prepared.draft.transcript.configuration, null); assert.equal(prepared.draft.transcript.device.keyGeneration, '1');
  assert.deepEqual(prepared.draft.transcript.binding.currentDevices, [current.publicDevice, other.publicDevice]);
  assert.deepEqual(prepared.draft.transcript.binding.profile, binding.profile); assert.equal(prepared.draft.transcript.recovery?.generation, '3');
  const fingerprint = await confirmed(prepared, f.exportKey, binding);
  await confirmEnrolmentAuthorizer({ draft: publicDraft(prepared), fingerprint }, f.owner.bundle, binding);
  await assert.rejects(encryptEnrolmentProfile({ draft: publicDraft(prepared), fingerprint }, f.owner.bundle, await randomKey(), binding));
  await assert.rejects(preparePromotionEnrolment({ binding, deviceId: other.publicDevice.id, existingWrapper, exportKey: f.exportKey, newOwnerKit }, binding));
  await assert.rejects(prepareJoinEnrolment({ ...f, binding, displayName: 'Unwanted Replacement', newOwnerKit }, binding));
});

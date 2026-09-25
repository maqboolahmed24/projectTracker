import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { readDeviceScopeKeyMaterial } from '../src/client/pairing.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../src/client/opaque.js';
import { base64urlDecode, base64urlEncode, canonicalJson, decryptContent, digestObject, encryptContent, generateRecipientKeyPair, generateSigningKeyPair, randomKey, signObject } from '../src/shared/crypto.js';
import { roleBinding, roleLabelHeader, validateRolePayload, validateRoleReceipt, type RoleBinding, type RoleDefinition, type RolePayload, type RoleReceipt } from '../src/shared/roles.js';
import { enrolmentBinding, enrolmentConfirmationFor, type EnrolmentTranscript } from '../src/shared/enrolment.js';
import { verifySecurityHistory, verifyRoleBindingAgainstHistory, verifyEnrolmentBindingAgainstHistory, SecurityHistoryError,
  type SecurityHistoryInput, type SecurityHistoryState } from '../src/shared/security-history.js';
import type { PairingScope } from '../src/shared/pairing.js';

const origin = 'https://ukda.example', label = 'Private custom reviewer';
const next = (value: string) => String(BigInt(value) + 1n);
const invalid = (error: unknown) => error instanceof SecurityHistoryError && error.code === 'INVALID_HISTORY';
const flip = (value: string) => { const bytes = base64urlDecode(value); bytes[0] = bytes[0]! ^ 1; return base64urlEncode(bytes); };
async function fixture(t: TestContext) {
  const workspaceId = randomUUID(), accountId = randomUUID(), exportKey = base64urlEncode(await randomKey()), phrase = await newOwnerPhrase();
  const configuration: OpaquePublicConfiguration = { configId: OPAQUE_CONFIG_ID, setupId: 'role-history', keyStretching: OPAQUE_KEY_STRETCHING,
    serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } };
  const prepared = await prepareOwnerActivation({ binding: { workspaceId, accountId, origin, activationId: randomUUID(), operationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1' },
    configuration, exportKey, registrationRecord: base64urlEncode(await randomKey()), phrase, challengePositions: [1, 9, 19], challengeAnswers: [1, 9, 19].map((index) => phrase.split(' ')[index]!),
    displayName: 'Role fixture Owner', workspaceName: 'Role fixture workspace' });
  const genesis = prepared.payload.genesis, fingerprint = await digestObject(genesis);
  const history: SecurityHistoryInput = { workspaceId, origin, genesisFingerprint: fingerprint, genesis, transitions: [], expected: { securityHead: fingerprint, securityVersion: '1' } };
  const state = await verifySecurityHistory(history), deviceId = genesis.body.device.id;
  const bundle = await unwrapDeviceBundle({ workspaceId, accountId, deviceId, credentialGeneration: '1' }, prepared.deviceWrapper, exportKey);
  const signing = base64urlDecode(bundle.signingPrivateKey, 64);
  const known = state.profiles[accountId]!.scopes[0]!;
  const scope: PairingScope = { scope: 'workspace', scopeId: workspaceId, mode: 'content', keyEpoch: '1', expiresAt: null,
    permissions: known.permissions, sources: known.manifests.map((manifest) => ({ grantId: randomUUID(), generation: '1', manifestId: manifest.id, manifestDigest: manifest.digest })) };
  const material = await readDeviceScopeKeyMaterial({ scopes: [scope], history: state,
    holder: { workspaceId, custodyEpoch: '1', approverAccountId: accountId, approverDevice: { ...genesis.body.device, keyGeneration: '1' } }, materials: [
      { id: genesis.body.custodyId, kind: 'custody_manifest', value: prepared.payload.objects.custody, digest: await digestObject(prepared.payload.objects.custody) },
      { id: genesis.body.deviceEnvelopeId, kind: 'key_envelope', value: prepared.payload.objects.deviceCustody, digest: await digestObject(prepared.payload.objects.deviceCustody) },
    ] }, bundle);
  const workspaceKey = base64urlDecode((material[0] as { keys: { epoch: string; key: string }[] }).keys[0]!.key, 32);
  t.after(() => { signing.fill(0); workspaceKey.fill(0); });
  return { history, state, signing, workspaceKey, accountId, deviceId, configuration, scope };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
function bindingFor(f: Fixture, state: SecurityHistoryState, action: RoleBinding['action'], roleId: string = randomUUID()): RoleBinding {
  const profile = state.profiles[f.accountId]!, device = state.devices[f.deviceId]!, known = state.roles[roleId], now = Date.now();
  return roleBinding.parse({ version: 1, origin, workspaceId: state.workspaceId, operationId: randomUUID(), action, roleId,
    previous: known ?? null, nextRevision: known ? next(known.revision) : '1',
    authorizer: { accountId: f.accountId, device: { id: device.id, keyGeneration: device.keyGeneration, signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey },
      credentialGeneration: profile.credentialGeneration, sessionGeneration: profile.sessionGeneration },
    securityVersion: state.securityVersion, nextSecurityVersion: next(state.securityVersion), securityHead: state.securityHead,
    dataGeneration: state.dataGeneration, ownershipVersion: state.ownershipVersion, custodyEpoch: state.custodyEpoch, workspaceKeyEpoch: state.workspaceKeyEpoch,
    genesisFingerprint: state.genesisFingerprint, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600_000).toISOString() });
}
async function payloadFor(f: Fixture, binding: RoleBinding, permissions: RoleDefinition['permissions'] = ['read_project', 'comment']): Promise<RolePayload> {
  const envelope = await encryptContent(roleLabelHeader(binding), { displayName: label }, f.workspaceKey, f.signing), id = randomUUID();
  const role: RoleDefinition = { id: binding.roleId, template: 'custom', revision: binding.nextRevision, state: binding.action === 'retire' ? 'retired' : 'active',
    permissions: binding.action === 'retire' ? binding.previous!.permissions : permissions, label: { id, revision: binding.nextRevision, digest: await digestObject(envelope) } };
  return { transition: await signObject({ version: 1 as const, purpose: 'ukda.custom-role-definition.v1' as const, binding, role }, f.signing), label: { id, envelope } };
}
async function append(history: SecurityHistoryInput, transition: unknown) {
  const input = { ...history, transitions: [...history.transitions, transition], expected: { securityHead: await digestObject(transition), securityVersion: next(history.expected.securityVersion) } };
  return { history: input, state: await verifySecurityHistory(input) };
}
async function memberTransition(t: TestContext, f: Fixture, state: SecurityHistoryState, roleId: string) {
  const role = state.roles[roleId]!, accountId = randomUUID(), signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  t.after(() => { signing.privateKey.fill(0); recipient.privateKey.fill(0); });
  const actor = state.devices[f.deviceId]!, owner = state.profiles[f.accountId]!, now = Date.now();
  const binding = enrolmentBinding.parse({ version: 1, kind: 'join_member', origin, workspaceId: state.workspaceId, accountId, operationId: randomUUID(), approvalAttemptId: randomUUID(),
    attemptGeneration: '1', invitationGeneration: '1', profile: { id: accountId, revision: '1', objectId: randomUUID(), objectDigest: 'a'.repeat(64) }, nextProfileRevision: '2',
    role: { id: role.id, revision: role.revision, permissions: role.permissions }, credentialGeneration: '0', nextCredentialGeneration: '1', sessionGeneration: '0', nextSessionGeneration: '1',
    recoveryGeneration: '0', nextRecoveryGeneration: '0', deviceKeyGeneration: '0', nextDeviceKeyGeneration: '1', ownershipVersion: state.ownershipVersion, nextOwnershipVersion: state.ownershipVersion,
    securityVersion: state.securityVersion, nextSecurityVersion: next(state.securityVersion), securityHead: state.securityHead, genesisFingerprint: state.genesisFingerprint,
    dataGeneration: state.dataGeneration, custodyEpoch: state.custodyEpoch, workspaceKeyEpoch: state.workspaceKeyEpoch,
    authorizer: { accountId: f.accountId, device: { id: actor.id, keyGeneration: actor.keyGeneration, signingPublicKey: actor.signingPublicKey, recipientPublicKey: actor.recipientPublicKey },
      credentialGeneration: owner.credentialGeneration, sessionGeneration: owner.sessionGeneration }, currentDevices: [], scopes: [{ ...f.scope, permissions: role.permissions }],
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 3_600_000).toISOString() });
  const transcript: EnrolmentTranscript = { version: 1, purpose: 'ukda.enrolment-transcript.v1', binding, device: { id: randomUUID(), keyGeneration: '1',
    signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) }, recovery: null, wrapperHash: 'b'.repeat(64),
    configuration: { ...f.configuration, identifiers: { client: `ukda:${state.workspaceId}:${accountId}`, server: origin } }, registrationRecordHash: 'c'.repeat(64), setupNameDigest: 'd'.repeat(64) };
  const digest = await digestObject(transcript);
  // Journal fixtures sign exact ciphertext descriptors; enrolment controller tests cover decrypting their actual ciphertexts.
  const transition = await signObject({ version: 1 as const, purpose: 'ukda.profile-enrolment.v1' as const, transcript, transcriptDigest: digest,
    recipientConfirmation: await signObject(enrolmentConfirmationFor(transcript, digest, 'recipient'), signing.privateKey),
    authorizerConfirmation: await signObject(enrolmentConfirmationFor(transcript, digest, 'authorizer'), f.signing), newRecoveryConfirmation: null,
    profile: { id: randomUUID(), profileId: accountId, revision: '2', digest: 'e'.repeat(64) },
    deliveries: [{ id: randomUUID(), scope: 'workspace' as const, scopeId: state.workspaceId, keyEpoch: '1', recipientKind: 'device' as const, recipientId: transcript.device.id, digest: 'f'.repeat(64) }] }, f.signing);
  return { binding, accountId, transition };
}

test('CP06: custom role labels are encrypted and the signed definition and receipt bind exact ciphertext', async (t) => {
  const f = await fixture(t), binding = bindingFor(f, f.state, 'create'), payload = await payloadFor(f, binding), checked = await validateRolePayload(payload, binding);
  verifyRoleBindingAgainstHistory(binding, f.state);
  assert.equal(JSON.stringify(payload).includes(label), false);
  assert.equal((await decryptContent(payload.label.envelope, f.workspaceKey, base64urlDecode(binding.authorizer.device.signingPublicKey, 32), roleLabelHeader(binding)) as { displayName: string }).displayName, label);
  const committed = await append(f.history, payload.transition);
  assert.equal(canonicalJson(committed.state.roles[binding.roleId]), canonicalJson(payload.transition.body.role));
  const receipt: RoleReceipt = { version: 1, workspaceId: binding.workspaceId, operationId: binding.operationId, roleId: binding.roleId, roleRevision: '1', securityVersion: '2',
    securityHead: checked.securityHead, requestHash: checked.requestHash, committedAt: new Date().toISOString(), transition: payload.transition };
  await validateRoleReceipt(receipt, binding);
  await assert.rejects(validateRoleReceipt({ ...receipt, roleRevision: '2' }, binding));
  const altered = structuredClone(payload); altered.label.envelope.ciphertext = flip(altered.label.envelope.ciphertext);
  await assert.rejects(validateRolePayload(altered, binding));
  await assert.rejects(validateRolePayload({ ...payload, label: { ...payload.label, id: randomUUID() } }, binding));
  await assert.rejects(validateRolePayload({ ...payload, transition: { ...payload.transition, signature: flip(payload.transition.signature) } }, binding));
});

test('CP06: updating role defaults leaves existing signed personal and device permission snapshots unchanged', async (t) => {
  const f = await fixture(t), create = await payloadFor(f, bindingFor(f, f.state, 'create'), ['read_project']);
  const created = await append(f.history, create.transition), member = await memberTransition(t, f, created.state, create.transition.body.role.id), joined = await append(created.history, member.transition);
  const profiles = canonicalJson(joined.state.profiles), devices = canonicalJson(joined.state.devices);
  const binding = bindingFor(f, joined.state, 'update', create.transition.body.role.id), updated = await append(joined.history, (await payloadFor(f, binding, ['read_project', 'manage_tasks'])).transition);
  assert.equal(updated.state.roles[binding.roleId]!.revision, '2'); assert.deepEqual(updated.state.roles[binding.roleId]!.permissions, ['read_project', 'manage_tasks']);
  assert.equal(canonicalJson(updated.state.profiles), profiles); assert.equal(canonicalJson(updated.state.devices), devices);
  assert.deepEqual(updated.state.profiles[member.accountId]!.role, { id: binding.roleId, revision: '1' });
  const retire = bindingFor(f, updated.state, 'retire', binding.roleId);
  assert.throws(() => verifyRoleBindingAgainstHistory(retire, updated.state), invalid);
  await assert.rejects(append(updated.history, (await payloadFor(f, retire)).transition), invalid);
  const projectOnly = structuredClone(updated.state); projectOnly.profiles[member.accountId]!.role = { id: f.history.genesis.body.roles.member, revision: '1' };
  projectOnly.profiles[member.accountId]!.projectRoles[randomUUID()] = { id: binding.roleId, revision: '1' };
  assert.throws(() => verifyRoleBindingAgainstHistory(retire, projectOnly), invalid);
});

test('CP06: unused custom roles retire permanently and cannot be enrolled, recreated, or edited as builtins', async (t) => {
  const f = await fixture(t), createBinding = bindingFor(f, f.state, 'create'), created = await append(f.history, (await payloadFor(f, createBinding)).transition);
  const member = await memberTransition(t, f, created.state, createBinding.roleId), retire = bindingFor(f, created.state, 'retire', createBinding.roleId);
  const retired = await append(created.history, (await payloadFor(f, retire)).transition);
  assert.equal(retired.state.roles[createBinding.roleId]!.state, 'retired');
  assert.throws(() => verifyRoleBindingAgainstHistory({ ...bindingFor(f, retired.state, 'create'), roleId: createBinding.roleId }, retired.state), invalid);
  assert.throws(() => bindingFor(f, retired.state, 'update', createBinding.roleId));
  assert.throws(() => verifyEnrolmentBindingAgainstHistory({ ...member.binding, securityHead: retired.state.securityHead, securityVersion: retired.state.securityVersion,
    nextSecurityVersion: next(retired.state.securityVersion), role: { ...member.binding.role, revision: '2' } }, retired.state), invalid);
  for (const id of Object.values(f.history.genesis.body.roles)) {
    assert.throws(() => verifyRoleBindingAgainstHistory({ ...bindingFor(f, f.state, 'create'), roleId: id }, f.state), invalid);
    assert.throws(() => bindingFor(f, f.state, 'update', id));
  }
});

test('CP06: role signatures require current Owner, device, scopes and exact authority without reserved capabilities', async (t) => {
  const f = await fixture(t), binding = bindingFor(f, f.state, 'create'), payload = await payloadFor(f, binding);
  for (const field of ['securityHead', 'genesisFingerprint'] as const) assert.throws(() => verifyRoleBindingAgainstHistory({ ...binding, [field]: '0'.repeat(64) }, f.state), invalid);
  for (const field of ['dataGeneration', 'ownershipVersion', 'custodyEpoch', 'workspaceKeyEpoch'] as const) assert.throws(() => verifyRoleBindingAgainstHistory({ ...binding, [field]: '2' }, f.state), invalid);
  for (const mutate of [
    (state: SecurityHistoryState) => { state.profiles[f.accountId]!.active = false; },
    (state: SecurityHistoryState) => { state.profiles[f.accountId]!.owner = false; },
    (state: SecurityHistoryState) => { state.devices[f.deviceId]!.active = false; },
    (state: SecurityHistoryState) => { state.devices[f.deviceId]!.scopes = []; },
    (state: SecurityHistoryState) => { state.profiles[f.accountId]!.scopes[0]!.expiresAt = binding.issuedAt; },
    (state: SecurityHistoryState) => { state.licenceState = 'restricted'; },
  ]) { const state = structuredClone(f.state); mutate(state); assert.throws(() => verifyRoleBindingAgainstHistory(binding, state), invalid); }
  for (const permissions of [['roles.manage'], ['read_project', 'read_project'], [], ['comment']]) {
    const altered = structuredClone(payload) as unknown as { transition: { body: { role: { permissions: string[] } } } }; altered.transition.body.role.permissions = permissions;
    await assert.rejects(validateRolePayload(altered, binding));
  }
  const other = await generateSigningKeyPair(); t.after(() => other.privateKey.fill(0));
  await assert.rejects(append(f.history, await signObject(payload.transition.body, other.privateKey)), invalid);
  const created = await append(f.history, payload.transition), stale = await payloadFor(f, { ...binding, operationId: randomUUID(), roleId: randomUUID() });
  await assert.rejects(append(created.history, stale.transition), invalid);
  for (const value of ['x', '-1', '99999999999999999999999999999']) {
    assert.doesNotThrow(() => assert.equal(roleBinding.safeParse({ ...binding, nextRevision: value }).success, false));
  }
});

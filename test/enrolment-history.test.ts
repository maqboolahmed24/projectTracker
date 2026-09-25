import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../src/client/opaque.js';
import { base64urlDecode, base64urlEncode, canonicalJson, digestObject, generateRecipientKeyPair, generateSigningKeyPair, randomKey, signObject } from '../src/shared/crypto.js';
import { capabilities } from '../src/shared/contracts.js';
import { enrolmentBinding, enrolmentConfirmationFor, enrolmentRecipientDevices, type EnrolmentBinding, type EnrolmentTranscript, type EnrolmentTransition } from '../src/shared/enrolment.js';
import { BUILTIN_ROLE_PERMISSIONS, type BuiltinRole } from '../src/shared/permissions.js';
import { pairingConfirmationFor, type PairingScope, type PairingTranscript } from '../src/shared/pairing.js';
import { transcriptFromGenesis } from '../src/shared/activation.js';
import { verifyEnrolmentBindingAgainstHistory, verifySecurityHistory, SecurityHistoryError, type HistoryScope, type SecurityHistoryInput, type SecurityHistoryState } from '../src/shared/security-history.js';

const origin = 'https://ukda.example';
const invalid = (error: unknown) => error instanceof SecurityHistoryError && error.code === 'INVALID_HISTORY';
const next = (value: string) => String(BigInt(value) + 1n);
async function keys(t: TestContext) {
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  t.after(() => { signing.privateKey.fill(0); recipient.privateKey.fill(0); });
  return { signing, recipient, device: { id: randomUUID(), keyGeneration: '1', signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) } };
}
type DeviceKeys = Awaited<ReturnType<typeof keys>>;
function sourceScope(scope: HistoryScope): PairingScope {
  const { manifests, ...fields } = scope;
  return { ...fields, sources: manifests.map((manifest) => ({ grantId: randomUUID(), generation: '1', manifestId: manifest.id, manifestDigest: manifest.digest })) };
}
async function fixture(t: TestContext) {
  const workspaceId = randomUUID(), accountId = randomUUID(), exportKey = base64urlEncode(await randomKey()), phrase = await newOwnerPhrase();
  const configuration: OpaquePublicConfiguration = { configId: OPAQUE_CONFIG_ID, setupId: 'enrolment-history', keyStretching: OPAQUE_KEY_STRETCHING,
    serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } };
  const prepared = await prepareOwnerActivation({ binding: { workspaceId, accountId, origin, activationId: randomUUID(), operationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1' },
    configuration, exportKey, registrationRecord: base64urlEncode(await randomKey()), phrase, challengePositions: [1, 9, 19],
    challengeAnswers: [1, 9, 19].map((index) => phrase.split(' ')[index]!), displayName: 'History Owner', workspaceName: 'History workspace' });
  const genesis = prepared.payload.genesis, genesisFingerprint = await digestObject(genesis);
  const bundle = await unwrapDeviceBundle({ workspaceId, accountId, deviceId: genesis.body.device.id, credentialGeneration: '1' }, prepared.deviceWrapper, exportKey);
  const signingKey = base64urlDecode(bundle.signingPrivateKey, 64); t.after(() => signingKey.fill(0));
  const input: SecurityHistoryInput = { workspaceId, origin, genesisFingerprint, genesis, transitions: [], expected: { securityHead: genesisFingerprint, securityVersion: '1' } };
  return { input, initial: await verifySecurityHistory(input), accountId, signingKey, deviceId: genesis.body.device.id, configuration };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;

function bindingFor(state: SecurityHistoryState, authorizerId: string, authorizerDeviceId: string,
  kind: EnrolmentBinding['kind'], accountId: string = randomUUID(), template: BuiltinRole = kind === 'join_member' ? 'member' : 'owner'): EnrolmentBinding {
  const authorizer = state.profiles[authorizerId]!, signer = state.devices[authorizerDeviceId]!, target = state.profiles[accountId];
  const role = Object.values(state.roles).find((entry) => entry.template === template)!, promotion = kind === 'promote_owner';
  const bindingRole = { id: role.id, revision: role.revision, permissions: role.permissions };
  const devices = Object.values(state.devices).filter((device) => device.accountId === accountId);
  const maximum = String(devices.reduce((value, device) => BigInt(device.keyGeneration) > value ? BigInt(device.keyGeneration) : value, 0n));
  const scopes = authorizer.scopes.map(sourceScope).map((scope) => kind === 'join_member' ? { ...scope, mode: 'content' as const,
    keyEpoch: scope.scope === 'workspace' ? state.workspaceKeyEpoch : scope.keyEpoch, permissions: [...bindingRole.permissions] } : scope);
  const now = Date.now();
  return enrolmentBinding.parse({ version: 1, kind, origin: state.origin, workspaceId: state.workspaceId, accountId,
    operationId: randomUUID(), approvalAttemptId: randomUUID(), attemptGeneration: '1', invitationGeneration: promotion ? '0' : '1',
    profile: promotion ? target!.profile : { id: accountId, revision: '1', objectId: randomUUID(), objectDigest: '1'.repeat(64) },
    nextProfileRevision: promotion ? target!.profile.revision : '2', role: bindingRole,
    credentialGeneration: promotion ? target!.credentialGeneration : '0', nextCredentialGeneration: promotion ? target!.credentialGeneration : '1',
    sessionGeneration: promotion ? target!.sessionGeneration : '0', nextSessionGeneration: promotion ? next(target!.sessionGeneration) : '1',
    recoveryGeneration: promotion ? target!.recoveryGeneration : '0', nextRecoveryGeneration: kind === 'join_member' ? '0' : promotion ? next(target!.recoveryGeneration) : '1',
    deviceKeyGeneration: promotion ? maximum : '0', nextDeviceKeyGeneration: promotion ? maximum : '1',
    ownershipVersion: state.ownershipVersion, nextOwnershipVersion: kind === 'join_member' ? state.ownershipVersion : next(state.ownershipVersion),
    securityVersion: state.securityVersion, nextSecurityVersion: next(state.securityVersion), securityHead: state.securityHead,
    genesisFingerprint: state.genesisFingerprint, dataGeneration: state.dataGeneration, custodyEpoch: state.custodyEpoch, workspaceKeyEpoch: state.workspaceKeyEpoch,
    authorizer: { accountId: authorizer.accountId, device: { id: signer.id, keyGeneration: signer.keyGeneration, signingPublicKey: signer.signingPublicKey, recipientPublicKey: signer.recipientPublicKey },
      credentialGeneration: authorizer.credentialGeneration, sessionGeneration: authorizer.sessionGeneration },
    currentDevices: promotion ? devices.filter((device) => device.active).map(({ id, keyGeneration, signingPublicKey, recipientPublicKey }) => ({ id, keyGeneration, signingPublicKey, recipientPublicKey })) : [],
    scopes, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 3_600_000).toISOString() });
}

/** Ciphertexts are checked separately by enrolment approval helpers; journal replay verifies their signed exact descriptors. */
async function transitionFor(t: TestContext, f: Fixture, binding: EnrolmentBinding, authorizerKey: Uint8Array, device?: DeviceKeys) {
  const target = device ?? await keys(t), recovery = binding.kind === 'join_member' ? null : await keys(t);
  const transcript: EnrolmentTranscript = { version: 1, purpose: 'ukda.enrolment-transcript.v1', binding, device: target.device,
    recovery: recovery ? { id: recovery.device.id, generation: binding.nextRecoveryGeneration, signingPublicKey: recovery.device.signingPublicKey, recipientPublicKey: recovery.device.recipientPublicKey } : null,
    wrapperHash: '2'.repeat(64), configuration: binding.kind === 'promote_owner' ? null : { ...f.configuration,
      identifiers: { ...f.configuration.identifiers, client: `ukda:${binding.workspaceId}:${binding.accountId}` } },
    registrationRecordHash: binding.kind === 'promote_owner' ? null : '3'.repeat(64), setupNameDigest: binding.kind === 'promote_owner' ? null : '4'.repeat(64) };
  async function sign(value: EnrolmentTranscript = transcript, signer = authorizerKey): Promise<EnrolmentTransition> {
    const transcriptDigest = await digestObject(value);
    const deliveries: EnrolmentTransition['body']['deliveries'] = [];
    for (const scope of value.binding.scopes) {
      for (const known of enrolmentRecipientDevices(value)) deliveries.push({ id: randomUUID(), scope: scope.scope, scopeId: scope.scopeId,
        keyEpoch: scope.keyEpoch, recipientKind: 'device', recipientId: known.id, digest: '5'.repeat(64) });
      if (scope.mode === 'custody') deliveries.push({ id: randomUUID(), scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch,
        recipientKind: 'recovery', recipientId: value.recovery!.id, digest: '6'.repeat(64) });
    }
    return signObject({ version: 1, purpose: value.binding.kind === 'promote_owner' ? 'ukda.owner-promotion.v1' : 'ukda.profile-enrolment.v1', transcript: value, transcriptDigest,
      recipientConfirmation: await signObject(enrolmentConfirmationFor(value, transcriptDigest, 'recipient'), target.signing.privateKey),
      authorizerConfirmation: await signObject(enrolmentConfirmationFor(value, transcriptDigest, 'authorizer'), signer),
      newRecoveryConfirmation: recovery ? await signObject(enrolmentConfirmationFor(value, transcriptDigest, 'new_recovery'), recovery.signing.privateKey) : null,
      profile: value.binding.kind === 'promote_owner' ? null : { id: randomUUID(), profileId: binding.accountId, revision: binding.nextProfileRevision, digest: '7'.repeat(64) }, deliveries }, signer);
  }
  return { target, recovery, transcript, sign, transition: await sign() };
}
async function append(input: SecurityHistoryInput, transition: unknown) {
  const latest = { ...input, transitions: [...input.transitions, transition], expected: { securityHead: await digestObject(transition), securityVersion: next(input.expected.securityVersion) } };
  return { input: latest, state: await verifySecurityHistory(latest) };
}

test('CP06: signed genesis anchors role IDs/default capabilities and the preserved encrypted profile reference', async (t) => {
  const f = await fixture(t);
  for (const template of Object.keys(BUILTIN_ROLE_PERMISSIONS) as BuiltinRole[]) {
    const role = f.initial.roles[f.input.genesis.body.roles[template]]!;
    assert.equal(role.template, template); assert.equal(role.revision, '1'); assert.deepEqual(role.permissions, [...BUILTIN_ROLE_PERMISSIONS[template]]);
  }
  assert.equal(f.initial.profiles[f.accountId]?.profile.objectId, f.accountId);
  assert.equal(f.initial.workspaceKeyEpoch, '1');
  const body = structuredClone(f.input.genesis.body); body.roles.member = body.roles.owner;
  body.transcriptDigest = await digestObject(transcriptFromGenesis(body));
  const genesis = await signObject(body, f.signingKey), head = await digestObject(genesis);
  await assert.rejects(verifySecurityHistory({ ...f.input, genesis, genesisFingerprint: head, expected: { securityHead: head, securityVersion: '1' } }), invalid);
});

test('CP06: member enrolment establishes only signed personal content scopes, not ownership or custody', async (t) => {
  const f = await fixture(t), binding = bindingFor(f.initial, f.accountId, f.deviceId, 'join_member');
  verifyEnrolmentBindingAgainstHistory(binding, f.initial);
  const joined = await transitionFor(t, f, binding, f.signingKey), result = await append(f.input, joined.transition);
  const profile = result.state.profiles[binding.accountId]!, device = result.state.devices[joined.target.device.id]!;
  assert.equal(profile.owner, false); assert.equal(profile.recoveryGeneration, '0'); assert.equal(result.state.ownershipVersion, '1');
  assert.equal(profile.profile.objectId, joined.transition.body.profile!.id); assert.equal(profile.profile.revision, '2');
  assert.equal(profile.scopes[0]?.mode, 'content'); assert.deepEqual(profile.scopes[0]?.permissions, [...BUILTIN_ROLE_PERMISSIONS.member]);
  assert.ok(profile.scopes[0]?.manifests.some((manifest) => manifest.id === binding.scopes[0]!.sources[0]!.manifestId));
  assert.equal(device.scopes[0]?.manifests.length, 1); assert.equal(device.scopes[0]?.manifests[0]?.id, joined.transition.body.deliveries[0]?.id);
  assert.deepEqual(Object.keys(result.state.recoveryAuthorities), [`${f.accountId}:1`]);
  const manager = bindingFor(result.state, f.accountId, f.deviceId, 'join_member', randomUUID(), 'manager');
  const managerTransition = await transitionFor(t, f, manager, f.signingKey), managed = await append(result.input, managerTransition.transition);
  assert.equal(managed.state.profiles[manager.accountId]?.owner, false);
  assert.deepEqual(managed.state.profiles[manager.accountId]?.scopes[0]?.permissions, [...capabilities]);
});

test('CP06: every newly enrolled Owner can authorize another Owner and retained source manifests remain verifiable', async (t) => {
  const f = await fixture(t), binding = bindingFor(f.initial, f.accountId, f.deviceId, 'join_owner');
  const second = await transitionFor(t, f, binding, f.signingKey), joined = await append(f.input, second.transition);
  assert.equal(joined.state.profiles[binding.accountId]?.owner, true); assert.equal(joined.state.ownershipVersion, '2');
  assert.equal(joined.state.recoveryAuthorities[`${binding.accountId}:1`]?.active, true);
  const nextBinding = bindingFor(joined.state, binding.accountId, second.target.device.id, 'join_owner');
  const third = await transitionFor(t, f, nextBinding, second.target.signing.privateKey), result = await append(joined.input, third.transition);
  assert.equal(result.state.ownershipVersion, '3'); assert.equal(Object.values(result.state.profiles).filter((profile) => profile.owner).length, 3);
  assert.equal(result.state.devices[f.deviceId]?.active, true); assert.equal(result.state.recoveryAuthorities[`${f.accountId}:1`]?.active, true);
  assert.ok(result.state.profiles[nextBinding.accountId]?.scopes[0]?.manifests.some((manifest) => manifest.id === f.input.genesis.body.custodyId));
});

test('CP06: member promotion preserves its exact profile, credential and all approved devices while adding independent Owner authority', async (t) => {
  const f = await fixture(t), binding = bindingFor(f.initial, f.accountId, f.deviceId, 'join_member');
  const member = await transitionFor(t, f, binding, f.signingKey), joined = await append(f.input, member.transition), second = await keys(t);
  const operationId = randomUUID(), now = Date.now();
  const pair: PairingTranscript = { version: 1, purpose: 'ukda.device-pair-transcript.v1', origin, workspaceId: f.input.workspaceId, operationId, ceremonyId: operationId,
    accountId: binding.accountId, device: second.device, localBundleDigest: '8'.repeat(64), approverAccountId: binding.accountId, approverDevice: member.target.device,
    approverIsOwner: false, credentialGeneration: '1', sessionGeneration: '1', approverCredentialGeneration: '1', approverSessionGeneration: '1',
    dataGeneration: '1', ownershipVersion: '1', custodyEpoch: '1', genesisFingerprint: f.input.genesisFingerprint, securityHead: joined.state.securityHead,
    securityVersion: joined.state.securityVersion, scopes: joined.state.profiles[binding.accountId]!.scopes.map(sourceScope),
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 60_000).toISOString() };
  const transcriptDigest = await digestObject(pair), grant = await signObject({ version: 1 as const, purpose: 'ukda.device-pair-grant.v1' as const,
    operationId, workspaceId: f.input.workspaceId, grantId: operationId, securityVersion: next(joined.state.securityVersion), previousHead: joined.state.securityHead,
    transcript: pair, transcriptDigest, recipientConfirmation: await signObject(pairingConfirmationFor(pair, transcriptDigest, 'recipient'), second.signing.privateKey),
    approverConfirmation: await signObject(pairingConfirmationFor(pair, transcriptDigest, 'approver'), member.target.signing.privateKey),
    deliveries: pair.scopes.map((scope) => ({ id: randomUUID(), scope: scope.scope, scopeId: scope.scopeId, digest: '9'.repeat(64) })) }, member.target.signing.privateKey);
  const paired = await append(joined.input, grant), promotion = bindingFor(paired.state, f.accountId, f.deviceId, 'promote_owner', binding.accountId);
  verifyEnrolmentBindingAgainstHistory(promotion, paired.state);
  for (const changed of [
    { ...promotion, currentDevices: promotion.currentDevices.slice(0, 1) },
    { ...promotion, profile: { ...promotion.profile, objectDigest: 'f'.repeat(64) } },
    { ...promotion, credentialGeneration: '2', nextCredentialGeneration: '2' },
    { ...promotion, currentDevices: promotion.currentDevices.map((device, index) => index ? device : { ...device, keyGeneration: '2' }) },
  ]) assert.throws(() => verifyEnrolmentBindingAgainstHistory(changed, paired.state), invalid);
  const promote = await transitionFor(t, f, promotion, f.signingKey, member.target), result = await append(paired.input, promote.transition);
  const profile = result.state.profiles[binding.accountId]!;
  assert.equal(profile.owner, true); assert.equal(profile.credentialGeneration, '1'); assert.equal(profile.sessionGeneration, '2'); assert.equal(profile.recoveryGeneration, '1');
  assert.equal(canonicalJson(profile.profile), canonicalJson(paired.state.profiles[binding.accountId]!.profile));
  for (const device of [member.target.device, second.device]) {
    const current = result.state.devices[device.id]!;
    assert.equal(current.active, true); assert.equal(current.signingPublicKey, device.signingPublicKey); assert.equal(current.recipientPublicKey, device.recipientPublicKey);
    assert.equal(current.scopes[0]?.mode, 'custody'); assert.equal(current.keyGeneration, device.keyGeneration);
  }
  assert.equal(result.state.recoveryAuthorities[`${binding.accountId}:1`]?.signingPublicKey, promote.recovery!.device.signingPublicKey);
});

test('CP06: binding validation rejects untrusted roles, stale authority, absent targets, revived identities and fabricated scopes', async (t) => {
  const f = await fixture(t), binding = bindingFor(f.initial, f.accountId, f.deviceId, 'join_member');
  const altered = (change: Partial<EnrolmentBinding>) => assert.throws(() => verifyEnrolmentBindingAgainstHistory({ ...binding, ...change }, f.initial), invalid);
  altered({ role: { ...binding.role, id: randomUUID() } }); altered({ role: { ...binding.role, revision: '2' } });
  altered({ role: { ...binding.role, permissions: [...capabilities] } });
  altered({ role: { id: f.input.genesis.body.roles.owner, revision: '1', permissions: [...capabilities] } });
  altered({ securityHead: 'f'.repeat(64) }); altered({ dataGeneration: '2' }); altered({ custodyEpoch: '2' }); altered({ workspaceKeyEpoch: '2' });
  altered({ authorizer: { ...binding.authorizer, sessionGeneration: '2' } });
  altered({ scopes: [{ ...binding.scopes[0]!, keyEpoch: '2' }] });
  altered({ scopes: [{ ...binding.scopes[0]!, sources: [{ ...binding.scopes[0]!.sources[0]!, manifestDigest: 'f'.repeat(64) }] }] });
  altered({ scopes: [...binding.scopes, { ...binding.scopes[0]!, scope: 'project', scopeId: randomUUID() }] });
  for (const modify of [
    (state: SecurityHistoryState) => { state.profiles[f.accountId]!.active = false; },
    (state: SecurityHistoryState) => { state.profiles[f.accountId]!.owner = false; },
    (state: SecurityHistoryState) => { state.devices[f.deviceId]!.active = false; },
    (state: SecurityHistoryState) => { state.licenceState = 'restricted'; },
    (state: SecurityHistoryState) => { state.profiles[binding.accountId] = { ...state.profiles[f.accountId]!, accountId: binding.accountId, active: false }; },
  ]) { const state = structuredClone(f.initial); modify(state); assert.throws(() => verifyEnrolmentBindingAgainstHistory(binding, state), invalid); }
});

test('CP06: known project scopes retain exact epochs, source authority and expiries; Owner flows cannot omit a project', async (t) => {
  const f = await fixture(t), state = structuredClone(f.initial), projectId = randomUUID();
  // Direct binding tests represent the trusted project state a future supported project transition will produce.
  // No unimplemented project action is accepted by the journal replay in this slice.
  const scope: HistoryScope = { scope: 'project', scopeId: projectId, mode: 'content', keyEpoch: '4', permissions: [...capabilities],
    expiresAt: null, manifests: [{ id: randomUUID(), digest: 'a'.repeat(64) }] };
  state.profiles[f.accountId]!.scopes.push(scope); state.devices[f.deviceId]!.scopes.push(structuredClone(scope));
  state.custodyEpoch = '7'; state.workspaceKeyEpoch = '3';
  state.profiles[f.accountId]!.scopes[0]!.keyEpoch = '7'; state.devices[f.deviceId]!.scopes[0]!.keyEpoch = '7';
  const member = bindingFor(state, f.accountId, f.deviceId, 'join_member');
  verifyEnrolmentBindingAgainstHistory(member, state);
  assert.equal(member.scopes[0]?.keyEpoch, '3');
  const owner = bindingFor(state, f.accountId, f.deviceId, 'join_owner'); verifyEnrolmentBindingAgainstHistory(owner, state);
  assert.equal(owner.scopes[0]?.keyEpoch, '7');
  assert.throws(() => verifyEnrolmentBindingAgainstHistory({ ...owner, scopes: owner.scopes.slice(0, 1) }, state), invalid);
  assert.throws(() => verifyEnrolmentBindingAgainstHistory({ ...member, scopes: member.scopes.map((entry) => entry.scope === 'project' ? { ...entry, keyEpoch: '5' } : entry) }, state), invalid);
  const expiry = new Date(Date.parse(member.issuedAt) + 60_000).toISOString();
  state.profiles[f.accountId]!.scopes[1]!.expiresAt = expiry; state.devices[f.deviceId]!.scopes[1]!.expiresAt = expiry;
  assert.throws(() => verifyEnrolmentBindingAgainstHistory(member, state), invalid);
  const finite = { ...member, scopes: member.scopes.map((entry) => entry.scope === 'project' ? { ...entry, expiresAt: expiry } : entry) };
  verifyEnrolmentBindingAgainstHistory(finite, state);
});

test('CP06: replay rejects forged signatures, reused device/recovery keys and a second activation of an enrolled identity', async (t) => {
  const f = await fixture(t), binding = bindingFor(f.initial, f.accountId, f.deviceId, 'join_owner');
  const prepared = await transitionFor(t, f, binding, f.signingKey), joined = await append(f.input, prepared.transition);
  const fake = await keys(t), forged = await prepared.sign(prepared.transcript, fake.signing.privateKey);
  await assert.rejects(append(f.input, forged), invalid);
  const badTarget = structuredClone(prepared.transition); badTarget.body.recipientConfirmation.signature = base64urlEncode(new Uint8Array(64));
  const resigned = await signObject(badTarget.body, f.signingKey); await assert.rejects(append(f.input, resigned), invalid);
  const duplicate = bindingFor(joined.state, f.accountId, f.deviceId, 'join_owner', binding.accountId);
  assert.throws(() => verifyEnrolmentBindingAgainstHistory(duplicate, joined.state), invalid);
  const fresh = bindingFor(joined.state, f.accountId, f.deviceId, 'join_owner'), reused = await transitionFor(t, f, fresh, f.signingKey, prepared.target);
  await assert.rejects(append(joined.input, reused.transition), invalid);
  const reusedRecovery = structuredClone(prepared.transcript);
  reusedRecovery.recovery = { ...reusedRecovery.recovery!, signingPublicKey: f.input.genesis.body.recovery.signingPublicKey,
    recipientPublicKey: f.input.genesis.body.recovery.recipientPublicKey };
  await assert.rejects(append(f.input, await prepared.sign(reusedRecovery)), invalid);
  const unknown = await signObject({ purpose: 'ukda.role-change.unsupported', workspaceId: f.input.workspaceId }, f.signingKey);
  await assert.rejects(append(joined.input, unknown), invalid);
});

test('CP06: promotion retains a healthy initiating device without reviving an expired paired device', async (t) => {
  const f = await fixture(t), join = bindingFor(f.initial, f.accountId, f.deviceId, 'join_member');
  const member = await transitionFor(t, f, join, f.signingKey), joined = await append(f.input, member.transition), second = await keys(t);
  const operationId = randomUUID(), issued = Date.now(), scopeExpiry = new Date(issued + 30_000).toISOString();
  const pair: PairingTranscript = { version: 1, purpose: 'ukda.device-pair-transcript.v1', origin, workspaceId: f.input.workspaceId,
    operationId, ceremonyId: operationId, accountId: join.accountId, device: second.device, localBundleDigest: '8'.repeat(64),
    approverAccountId: join.accountId, approverDevice: member.target.device, approverIsOwner: false,
    credentialGeneration: '1', sessionGeneration: '1', approverCredentialGeneration: '1', approverSessionGeneration: '1',
    dataGeneration: '1', ownershipVersion: '1', custodyEpoch: '1', genesisFingerprint: f.input.genesisFingerprint,
    securityHead: joined.state.securityHead, securityVersion: joined.state.securityVersion,
    scopes: joined.state.profiles[join.accountId]!.scopes.map(sourceScope).map((scope) => ({ ...scope, expiresAt: scopeExpiry })),
    issuedAt: new Date(issued).toISOString(), expiresAt: new Date(issued + 60_000).toISOString() };
  const transcriptDigest = await digestObject(pair);
  const grant = await signObject({ version: 1 as const, purpose: 'ukda.device-pair-grant.v1' as const,
    operationId, workspaceId: f.input.workspaceId, grantId: operationId, securityVersion: next(joined.state.securityVersion),
    previousHead: joined.state.securityHead, transcript: pair, transcriptDigest,
    recipientConfirmation: await signObject(pairingConfirmationFor(pair, transcriptDigest, 'recipient'), second.signing.privateKey),
    approverConfirmation: await signObject(pairingConfirmationFor(pair, transcriptDigest, 'approver'), member.target.signing.privateKey),
    deliveries: pair.scopes.map((scope) => ({ id: randomUUID(), scope: scope.scope, scopeId: scope.scopeId, digest: '9'.repeat(64) })) }, member.target.signing.privateKey);
  const paired = await append(joined.input, grant), full = bindingFor(paired.state, f.accountId, f.deviceId, 'promote_owner', join.accountId);
  full.issuedAt = new Date(issued + 60_000).toISOString(); full.expiresAt = new Date(issued + 3_660_000).toISOString();
  assert.equal(paired.state.devices[second.device.id]?.active, true, 'Expiry does not erase the public device identity');
  assert.throws(() => verifyEnrolmentBindingAgainstHistory(full, paired.state), invalid, 'Expired device cannot receive fresh Owner authority');
  const promotion = { ...full, currentDevices: full.currentDevices.filter((device) => device.id === member.target.device.id) };
  verifyEnrolmentBindingAgainstHistory(promotion, paired.state);
  assert.equal(promotion.deviceKeyGeneration, full.deviceKeyGeneration, 'Filtering recipients does not reset historical key generation');
  for (const change of ['expired_person', 'stale_device_epoch', 'unreadable_device'] as const) {
    const state = structuredClone(paired.state);
    if (change === 'expired_person') state.profiles[join.accountId]!.scopes[0]!.expiresAt = scopeExpiry;
    if (change === 'stale_device_epoch') state.devices[member.target.device.id]!.scopes[0]!.keyEpoch = '2';
    if (change === 'unreadable_device') state.devices[member.target.device.id]!.scopes[0]!.permissions = [];
    assert.throws(() => verifyEnrolmentBindingAgainstHistory(promotion, state), invalid);
  }
  const approved = await transitionFor(t, f, promotion, f.signingKey, member.target), result = await append(paired.input, approved.transition);
  assert.equal(result.state.profiles[join.accountId]?.owner, true);
  assert.equal(result.state.devices[member.target.device.id]?.scopes[0]?.mode, 'custody');
  assert.equal(result.state.devices[second.device.id]?.scopes[0]?.mode, 'content');
  assert.equal(result.state.devices[second.device.id]?.scopes[0]?.expiresAt, scopeExpiry);
  assert.ok(!approved.transition.body.deliveries.some((entry) => entry.recipientId === second.device.id));
});

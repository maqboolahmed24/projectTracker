import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../src/client/opaque.js';
import { base64urlDecode, base64urlEncode, canonicalJson, digestObject, generateRecipientKeyPair, generateSigningKeyPair, randomKey, encryptContent, sealRecipient, signObject } from '../src/shared/crypto.js';
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


import { AccessContractError, createAccessBinding, deriveAccessPlan, accessTranscriptDigest, accessCustodyHeader, accessProfileHeader,
  accessRecipientHeader, accessReceiptTokenHash, validateAccessPayload, validateAccessReceiptForPayload,
  type AccessBinding, type AccessPayload, type AccessPlan, type AccessTransition } from '../src/shared/access-change.js';
import { createScopeProvisionBinding, deriveScopeProvisionPlan, scopeProvisionTranscriptDigest, scopeProvisionCustodyHeader,
  scopeProvisionRecipientHeader, validateScopeProvisionPayload, type ScopeProvisionPayload } from '../src/shared/scope-provision.js';
const accessInvalid = (error: unknown) => error instanceof AccessContractError;
function actor(f: Fixture, state: SecurityHistoryState, accountId: string = f.accountId, deviceId: string = f.deviceId): AccessBinding['authorizer'] {
  const person = state.profiles[accountId]!, d = state.devices[deviceId]!;
  return { accountId, device: { id: d.id, keyGeneration: d.keyGeneration, signingPublicKey: d.signingPublicKey, recipientPublicKey: d.recipientPublicKey },
    credentialGeneration: person.credentialGeneration, sessionGeneration: person.sessionGeneration };
}
function times(offset = 0) { const now = Date.now() + offset; return { issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600_000).toISOString() }; }
async function accessFor(f: Fixture, state: SecurityHistoryState, target: string, action: AccessBinding['action'],
  desired: AccessBinding['desired'] = null, owner = actor(f, state), offset = 0) {
  const reference = { workspaceId: state.workspaceId, operationId: randomUUID() }, token = base64urlEncode(await randomKey());
  const binding = createAccessBinding({ ...reference, action, targetAccountId: target, desired, receiptTokenHash: await accessReceiptTokenHash(reference, token) }, state, owner, times(offset));
  return { binding, plan: deriveAccessPlan(binding, state), token };
}
async function accessJournal(binding: AccessBinding, plan: AccessPlan, signing: Uint8Array): Promise<AccessTransition> {
  return signObject({ version: 1 as const, purpose: 'ukda.access-change.v1' as const, binding, plan,
    transcriptDigest: await accessTranscriptDigest(binding, plan), custody: plan.rotateCustody ? { id: randomUUID(), revision: plan.nextCustodyEpoch, digest: 'a'.repeat(64) } : null,
    profile: binding.action === 'remove' ? { id: randomUUID(), revision: plan.target.profileRevision, digest: 'b'.repeat(64) } : null,
    deliveries: plan.recipients.map((recipient) => ({ id: randomUUID(), digest: 'c'.repeat(64), recipient })) }, signing);
}
async function provision(f: Fixture, current: { input: SecurityHistoryInput; state: SecurityHistoryState }, selected: { accountId: string; roleId: string }[] = []) {
  const binding = createScopeProvisionBinding({ workspaceId: current.state.workspaceId, operationId: randomUUID(), projectId: randomUUID(), selected }, current.state, actor(f, current.state), times());
  const plan = deriveScopeProvisionPlan(binding, current.state), id = randomUUID(), key = await randomKey();
  const custody = { id, envelope: await encryptContent(scopeProvisionCustodyHeader(binding, plan, id), { version: 1, retainedTestCiphertext: true }, key, f.signingKey) };
  const deliveries = await Promise.all(plan.recipients.map(async (recipient) => ({ id: randomUUID(), recipient,
    envelope: await sealRecipient(await scopeProvisionRecipientHeader(binding, plan, recipient), { version: 1, testKey: base64urlEncode(key) }, f.signingKey) })));
  key.fill(0);
  const transition = await signObject({ version: 1 as const, purpose: 'ukda.project-scope-provision.v1' as const, binding, plan,
    transcriptDigest: await scopeProvisionTranscriptDigest(binding, plan), custody: { id, revision: plan.nextCustodyEpoch, digest: await digestObject(custody.envelope) },
    deliveries: await Promise.all(deliveries.map(async (d) => ({ id: d.id, recipient: d.recipient, digest: await digestObject(d.envelope) }))) }, f.signingKey);
  const payload: ScopeProvisionPayload = { transition, custody, deliveries: deliveries.map(({ id, envelope }) => ({ id, envelope })) };
  await validateScopeProvisionPayload(payload, binding, current.state);
  return { ...await append(current.input, transition), payload, binding, plan };
}

test('CP06: signed project scope grants every Owner and selected members, validates complete ciphertext recipients', async (t) => {
  const f = await fixture(t), ownerBinding = bindingFor(f.initial, f.accountId, f.deviceId, 'join_owner');
  const owner = await transitionFor(t, f, ownerBinding, f.signingKey), owners = await append(f.input, owner.transition);
  const memberBinding = bindingFor(owners.state, f.accountId, f.deviceId, 'join_member');
  const member = await transitionFor(t, f, memberBinding, f.signingKey), joined = await append(owners.input, member.transition);
  const project = await provision(f, joined, [{ accountId: memberBinding.accountId, roleId: memberBinding.role.id }]);
  assert.equal(project.state.scopeHeads[`project:${project.binding.projectId}`]?.keyEpoch, '1');
  assert.equal(project.state.custodyEpoch, '2'); assert.equal(project.state.ownershipVersion, joined.state.ownershipVersion);
  for (const accountId of [f.accountId, ownerBinding.accountId, memberBinding.accountId]) {
    assert.ok(project.state.profiles[accountId]!.scopes.some((s) => s.scopeId === project.binding.projectId && s.keyEpoch === '1'));
    assert.ok(project.state.profiles[accountId]!.projectRoles[project.binding.projectId]);
  }
  assert.equal(project.plan.recipients.filter((r) => r.kind === 'recovery').length, 2);
  const missing = structuredClone(project.payload); missing.deliveries.pop();
  await assert.rejects(validateScopeProvisionPayload(missing, project.binding, joined.state));
  const tampered = structuredClone(project.payload); tampered.deliveries[0]!.envelope.header.scopeId = randomUUID();
  await assert.rejects(validateScopeProvisionPayload(tampered, project.binding, joined.state));
  const incomplete = structuredClone(project.payload.transition.body); incomplete.deliveries.pop();
  await assert.rejects(append(joined.input, await signObject(incomplete, f.signingKey)), invalid);
});

test('CP06: losing one project rotates only that content scope and custody, retaining personal workspace rights', async (t) => {
  const f = await fixture(t), join = bindingFor(f.initial, f.accountId, f.deviceId, 'join_member');
  const member = await transitionFor(t, f, join, f.signingKey), joined = await append(f.input, member.transition);
  const project = await provision(f, joined, [{ accountId: join.accountId, roleId: join.role.id }]);
  const access = await accessFor(f, project.state, join.accountId, 'set_access', { roleId: join.role.id, projectIds: [] });
  assert.deepEqual(access.plan.rotations, [{ scope: 'project', scopeId: project.binding.projectId, previousEpoch: '1', nextEpoch: '2' }]);
  assert.equal(access.plan.nextCustodyEpoch, '3'); assert.equal(access.plan.nextWorkspaceKeyEpoch, '1');
  assert.ok(!access.plan.recipients.some((r) => r.accountId === join.accountId && r.scope.scope === 'project'));
  const changed = await append(project.input, await accessJournal(access.binding, access.plan, f.signingKey));
  const target = changed.state.profiles[join.accountId]!;
  assert.equal(target.owner, false); assert.equal(target.sessionGeneration, '2'); assert.equal(target.credentialGeneration, '1');
  assert.deepEqual(Object.keys(target.projectRoles), []); assert.equal(target.scopes.length, 1); assert.equal(target.scopes[0]!.scope, 'workspace');
  assert.equal(changed.state.dataGeneration, project.state.dataGeneration);
  assert.equal(changed.state.scopeHeads[`project:${project.binding.projectId}`]?.keyEpoch, '2');
  assert.equal(changed.state.devices[member.target.device.id]!.scopes.length, 1);
  const forged = structuredClone(access.plan); forged.recipients.push(project.plan.recipients.find((r) => r.accountId === join.accountId)!);
  await assert.rejects(append(project.input, await accessJournal(access.binding, forged, f.signingKey)), invalid);
});

test('CP06: last Owner cannot depart; self demotion retires only that Owner custody authority and keeps historical keys public', async (t) => {
  const f = await fixture(t), memberRole = f.input.genesis.body.roles.member;
  await assert.rejects(accessFor(f, f.initial, f.accountId, 'demote_owner', { roleId: memberRole, projectIds: [] }), accessInvalid);
  const join = bindingFor(f.initial, f.accountId, f.deviceId, 'join_owner'), second = await transitionFor(t, f, join, f.signingKey);
  const joined = await append(f.input, second.transition), project = await provision(f, joined);
  const access = await accessFor(f, project.state, f.accountId, 'demote_owner', { roleId: memberRole, projectIds: [] });
  assert.equal(access.plan.nextOwnershipVersion, '3'); assert.equal(access.plan.nextCustodyEpoch, '3');
  assert.ok(!access.plan.recipients.some((r) => r.accountId === f.accountId && r.scope.mode === 'custody'));
  assert.ok(access.plan.recipients.some((r) => r.accountId === join.accountId && r.kind === 'recovery'));
  const changed = await append(project.input, await accessJournal(access.binding, access.plan, f.signingKey));
  assert.equal(changed.state.profiles[f.accountId]!.owner, false); assert.equal(changed.state.profiles[f.accountId]!.recoveryGeneration, '2');
  assert.equal(changed.state.recoveryAuthorities[`${f.accountId}:1`]!.active, false);
  assert.equal(changed.state.recoveryAuthorities[`${f.accountId}:1`]!.signingPublicKey, f.initial.recoveryAuthorities[`${f.accountId}:1`]!.signingPublicKey);
  assert.equal(changed.state.devices[f.deviceId]!.active, true); assert.equal(changed.state.devices[f.deviceId]!.scopes[0]!.mode, 'content');
  await assert.rejects(accessFor(f, changed.state, join.accountId, 'remove'), accessInvalid, 'Former Owner cannot issue new changes');
});

test('CP06: suspended profiles can be removed without reactivation; explicit reactivation keeps every old device revoked', async (t) => {
  const f = await fixture(t), join = bindingFor(f.initial, f.accountId, f.deviceId, 'join_member');
  const member = await transitionFor(t, f, join, f.signingKey), joined = await append(f.input, member.transition);
  const suspension = await accessFor(f, joined.state, join.accountId, 'suspend');
  const suspended = await append(joined.input, await accessJournal(suspension.binding, suspension.plan, f.signingKey));
  assert.equal(suspended.state.profiles[join.accountId]!.state, 'suspended'); assert.equal(suspended.state.devices[member.target.device.id]!.active, false);
  const removal = await accessFor(f, suspended.state, join.accountId, 'remove');
  assert.deepEqual(removal.plan.rotations, []); assert.equal(removal.plan.rotateCustody, false);
  const removed = await append(suspended.input, await accessJournal(removal.binding, removal.plan, f.signingKey));
  assert.equal(removed.state.profiles[join.accountId]!.state, 'removed'); assert.equal(removed.state.profiles[join.accountId]!.credentialGeneration, '2');
  assert.equal(removed.state.profiles[join.accountId]!.profile.revision, '3');
  await assert.rejects(accessFor(f, removed.state, join.accountId, 'reactivate_member', { roleId: join.role.id, projectIds: [] }), accessInvalid);
  const reactivation = await accessFor(f, suspended.state, join.accountId, 'reactivate_member', { roleId: join.role.id, projectIds: [] });
  const active = await append(suspended.input, await accessJournal(reactivation.binding, reactivation.plan, f.signingKey));
  assert.equal(active.state.profiles[join.accountId]!.active, true); assert.equal(active.state.profiles[join.accountId]!.owner, false);
  assert.equal(active.state.profiles[join.accountId]!.credentialGeneration, '1'); assert.equal(active.state.devices[member.target.device.id]!.active, false);
  assert.equal(reactivation.plan.recipients.length, 0); assert.equal(active.state.profiles[join.accountId]!.scopes.length, 1);
});

test('CP06: encrypted removal payload binds the exact profile revision and receipt survives actor self-removal', async (t) => {
  const f = await fixture(t), join = bindingFor(f.initial, f.accountId, f.deviceId, 'join_owner');
  const second = await transitionFor(t, f, join, f.signingKey), joined = await append(f.input, second.transition);
  const a = await accessFor(f, joined.state, f.accountId, 'remove'), key = await randomKey(), custodyId = randomUUID(), profileId = randomUUID();
  const custody = { id: custodyId, envelope: await encryptContent(accessCustodyHeader(a.binding, a.plan, custodyId), { version: 1 }, key, f.signingKey) };
  const profile = { id: profileId, envelope: await encryptContent(accessProfileHeader(a.binding, a.plan), { displayName: 'Former member' }, key, f.signingKey) };
  const deliveries = await Promise.all(a.plan.recipients.map(async (recipient) => ({ id: randomUUID(), recipient,
    envelope: await sealRecipient(await accessRecipientHeader(a.binding, a.plan, recipient), { key: base64urlEncode(key) }, f.signingKey) })));
  key.fill(0);
  const transition = await signObject({ version: 1 as const, purpose: 'ukda.access-change.v1' as const, binding: a.binding, plan: a.plan,
    transcriptDigest: await accessTranscriptDigest(a.binding, a.plan), custody: { id: custodyId, revision: a.plan.nextCustodyEpoch, digest: await digestObject(custody.envelope) },
    profile: { id: profileId, revision: a.plan.target.profileRevision, digest: await digestObject(profile.envelope) },
    deliveries: await Promise.all(deliveries.map(async (d) => ({ id: d.id, recipient: d.recipient, digest: await digestObject(d.envelope) }))) }, f.signingKey);
  const payload: AccessPayload = { transition, custody, profile, deliveries: deliveries.map(({ id, envelope }) => ({ id, envelope })) };
  const validated = await validateAccessPayload(payload, a.binding, joined.state), changed = await append(joined.input, transition);
  assert.equal(changed.state.profiles[f.accountId]!.state, 'removed'); assert.equal(changed.state.devices[f.deviceId]!.active, false);
  const receipt = { version: 1 as const, workspaceId: a.binding.workspaceId, operationId: a.binding.operationId, targetAccountId: f.accountId,
    securityVersion: a.binding.nextSecurityVersion, securityHead: validated.securityHead, requestHash: validated.requestHash, committedAt: new Date().toISOString(), transition };
  assert.equal((await validateAccessReceiptForPayload(receipt, payload)).operationId, a.binding.operationId);
  await assert.rejects(validateAccessReceiptForPayload({ ...receipt, requestHash: 'f'.repeat(64) }, payload), accessInvalid);
  const damaged = structuredClone(payload); damaged.profile!.envelope.header.revision = '99';
  await assert.rejects(validateAccessPayload(damaged, a.binding, joined.state), accessInvalid);
  assert.notEqual(await accessReceiptTokenHash({ workspaceId: a.binding.workspaceId, operationId: randomUUID() }, a.token), a.binding.receiptTokenHash);
  await assert.rejects(append(changed.input, transition), invalid, 'Old signed request cannot replay at a later head');
});

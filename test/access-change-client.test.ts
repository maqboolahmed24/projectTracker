import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { base64urlEncode, canonicalJson, randomKey } from '../src/shared/crypto.js';
import { rotateRetainedKeyrings, type RetainedCustodyManifest } from '../src/client/access-change-crypto.js';

async function manifestFixture() {
  const workspaceId = randomUUID(), projectId = randomUUID(), archivedProjectId = randomUUID();
  const manifest: RetainedCustodyManifest = { version: 1, custodyEpoch: '2',
    workspaceKeys: [{ epoch: '1', key: base64urlEncode(await randomKey()) }, { epoch: '2', key: base64urlEncode(await randomKey()) }],
    projectKeys: [{ projectId, keys: [{ epoch: '1', key: base64urlEncode(await randomKey()) }] },
      { projectId: archivedProjectId, keys: [{ epoch: '1', key: base64urlEncode(await randomKey()) }] }] };
  return { workspaceId, projectId, archivedProjectId, manifest };
}

test('CP06 access cryptography: fresh future keys preserve every historical ordinary and archived key epoch', async () => {
  const f = await manifestFixture(), before = canonicalJson(f.manifest), input = { ...f, nextCustodyEpoch: '3', rotations: [
    { scope: 'workspace' as const, scopeId: f.workspaceId, previousEpoch: '2', nextEpoch: '3' },
    { scope: 'project' as const, scopeId: f.projectId, previousEpoch: '1', nextEpoch: '2' }] };
  const first = await rotateRetainedKeyrings(input), second = await rotateRetainedKeyrings(input);
  assert.equal(canonicalJson(f.manifest), before, 'Preparation never mutates the previous committed manifest');
  assert.deepEqual(first.workspaceKeys.slice(0, 2), f.manifest.workspaceKeys);
  assert.deepEqual(first.projectKeys[0]!.keys.slice(0, 1), f.manifest.projectKeys[0]!.keys);
  assert.deepEqual(first.projectKeys[1], f.manifest.projectKeys[1], 'Archived retained keyring remains intact');
  assert.equal(first.custodyEpoch, '3'); assert.notEqual(first.workspaceKeys[2]!.key, f.manifest.workspaceKeys[1]!.key);
  assert.notEqual(first.workspaceKeys[2]!.key, second.workspaceKeys[2]!.key);
  assert.notEqual(first.projectKeys[0]!.keys[1]!.key, second.projectKeys[0]!.keys[1]!.key);
});

test('CP06 access cryptography: missing keys, skipped epochs, duplicate scopes and unrotated custody fail closed', async () => {
  const f = await manifestFixture(), rotation = { scope: 'workspace' as const, scopeId: f.workspaceId, previousEpoch: '2', nextEpoch: '3' };
  const input = { workspaceId: f.workspaceId, manifest: f.manifest, nextCustodyEpoch: '3', rotations: [rotation] };
  await assert.rejects(rotateRetainedKeyrings({ ...input, nextCustodyEpoch: '2' }));
  await assert.rejects(rotateRetainedKeyrings({ ...input, rotations: [rotation, rotation] }));
  await assert.rejects(rotateRetainedKeyrings({ ...input, rotations: [{ ...rotation, nextEpoch: '4' }] }));
  await assert.rejects(rotateRetainedKeyrings({ ...input, rotations: [{ ...rotation, scopeId: randomUUID() }] }));
  await assert.rejects(rotateRetainedKeyrings({ ...input, rotations: [{ scope: 'project', scopeId: randomUUID(), previousEpoch: '1', nextEpoch: '2' }] }));
});

import { IDBFactory } from 'fake-indexeddb';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { newOwnerPhrase, recoveryKeys } from '../src/client/recovery.js';
import { unwrapDeviceBundle, type DeviceBundle } from '../src/client/device-store.js';
import { prepareJoinInvitation, prepareEnrolmentDraft, confirmEnrolmentTarget, prepareEnrolmentApproval } from '../src/client/enrolment-controller.js';
import { enrolmentDeviceContext } from '../src/client/enrolment-crypto.js';
import { prepareAccessChange, refreshAccessKeys, AccessChangeClientError } from '../src/client/access-change-crypto.js';
import { IndexedAccessChangeStore, type AccessChangeRecord } from '../src/client/access-change-store.js';
import { AccessChangeController, HttpAccessChangeTransport, type AccessChangeTransport } from '../src/client/access-change-controller.js';
import { IndexedPairingStore, readOwnerCustodyKeyMaterial, readRecoveryCustodyKeyMaterial } from '../src/client/pairing.js';
import type { AuthController } from '../src/client/auth-controller.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../src/client/opaque.js';
import { digestObject } from '../src/shared/crypto.js';
import { enrolmentBinding, type EnrolmentBinding } from '../src/shared/enrolment.js';
import { accessReceiptTokenHash, createAccessBinding, deriveAccessPlan, type AccessRequest, type AccessPayload, type AccessReceipt, type AccessView, type AccessContext } from '../src/shared/access-change.js';
import { verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState } from '../src/shared/security-history.js';
import type { PairingMaterial } from '../src/shared/pairing.js';

const origin = 'https://access.ukda.example', next = (value: string) => String(BigInt(value) + 1n);
interface Actor { accountId: string; deviceId: string; bundle: DeviceBundle; phrase: string | undefined }
async function ownerFixture() {
  const workspaceId = randomUUID(), accountId = randomUUID(), exportKey = base64urlEncode(await randomKey()), phrase = await newOwnerPhrase();
  const configuration: OpaquePublicConfiguration = { configId: OPAQUE_CONFIG_ID, setupId: 'access-client', keyStretching: OPAQUE_KEY_STRETCHING,
    serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } };
  const prepared = await prepareOwnerActivation({ binding: { workspaceId, accountId, origin, activationId: randomUUID(), operationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1' },
    configuration, exportKey, registrationRecord: base64urlEncode(await randomKey()), phrase, challengePositions: [1, 9, 19],
    challengeAnswers: [1, 9, 19].map((index) => phrase.split(' ')[index]!), displayName: 'Private Owner', workspaceName: 'Private access workspace' });
  const genesis = prepared.payload.genesis, head = await digestObject(genesis), deviceId = genesis.body.device.id;
  const history: SecurityHistoryInput = { workspaceId, origin, genesisFingerprint: head, genesis, transitions: [], expected: { securityHead: head, securityVersion: '1' } };
  const bundle = await unwrapDeviceBundle({ workspaceId, accountId, deviceId, credentialGeneration: '1' }, prepared.deviceWrapper, exportKey);
  const materials: PairingMaterial[] = [
    { id: genesis.body.custodyId, kind: 'custody_manifest', value: prepared.payload.objects.custody, digest: await digestObject(prepared.payload.objects.custody) },
    { id: genesis.body.deviceEnvelopeId, kind: 'key_envelope', value: prepared.payload.objects.deviceCustody, digest: await digestObject(prepared.payload.objects.deviceCustody) },
    { id: genesis.body.recoveryEnvelopeId, kind: 'key_envelope', value: prepared.payload.objects.recoveryCustody, digest: await digestObject(prepared.payload.objects.recoveryCustody) },
  ];
  return { workspaceId, configuration, owner: { accountId, deviceId, bundle, phrase } as Actor, history, state: await verifySecurityHistory(history), materials };
}
type OwnerFixture = Awaited<ReturnType<typeof ownerFixture>>;
function actorAuthority(f: OwnerFixture, actor = f.owner) {
  const profile = f.state.profiles[actor.accountId]!, device = f.state.devices[actor.deviceId]!;
  return { accountId: actor.accountId, device: { id: device.id, keyGeneration: device.keyGeneration, signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey },
    credentialGeneration: profile.credentialGeneration, sessionGeneration: profile.sessionGeneration };
}
async function append(f: OwnerFixture, transition: unknown, version: string) {
  f.history = { ...f.history, transitions: [...f.history.transitions, transition], expected: { securityHead: await digestObject(transition), securityVersion: version } };
  f.state = await verifySecurityHistory(f.history);
}
async function join(f: OwnerFixture, owner = false): Promise<Actor> {
  const state = f.state, accountId = randomUUID(), operationId = randomUUID(), now = Date.now(), kind = owner ? 'join_owner' : 'join_member',
    role = Object.values(state.roles).find((entry) => entry.template === (owner ? 'owner' : 'member'))!, authorizer = actorAuthority(f);
  const profile = await prepareJoinInvitation({ request: { workspaceId: f.workspaceId, accountId, operationId, kind, roleId: role.id, projectIds: [] },
    history: f.history, displayName: 'Private invited account', context: { workspaceId: f.workspaceId, accountId, operationId, kind,
      role: { id: role.id, revision: role.revision, permissions: role.permissions }, authorizer, genesisFingerprint: state.genesisFingerprint,
      custodyEpoch: state.custodyEpoch, current: f.history.expected, materials: f.materials,
      header: { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: f.workspaceId, scope: 'workspace', scopeId: f.workspaceId,
        recordId: accountId, recordType: 'profile', schema: 1, keyEpoch: state.workspaceKeyEpoch, revision: '1', operationId, accountId: f.owner.accountId,
        deviceId: f.owner.deviceId, keyGeneration: authorizer.device.keyGeneration, permissionVersion: role.revision, securityVersion: state.securityVersion,
        securityHead: state.securityHead, dataGeneration: state.dataGeneration, action: 'profile.invite', approvalPolicyId: null, approvalPolicyRevision: null } } }, f.owner.bundle);
  const profileDigest = await digestObject(profile.profile.envelope); f.materials.push({ id: profile.profile.id, kind: 'encrypted_profile', value: profile.profile.envelope, digest: profileDigest });
  const binding: EnrolmentBinding = enrolmentBinding.parse({ version: 1, kind, origin, workspaceId: f.workspaceId, accountId, operationId,
    approvalAttemptId: randomUUID(), attemptGeneration: '1', invitationGeneration: '1', profile: { id: accountId, revision: '1', objectId: profile.profile.id, objectDigest: profileDigest },
    nextProfileRevision: '2', role: { id: role.id, revision: role.revision, permissions: role.permissions }, credentialGeneration: '0', nextCredentialGeneration: '1',
    sessionGeneration: '0', nextSessionGeneration: '1', recoveryGeneration: '0', nextRecoveryGeneration: owner ? '1' : '0', deviceKeyGeneration: '0', nextDeviceKeyGeneration: '1',
    ownershipVersion: state.ownershipVersion, nextOwnershipVersion: owner ? next(state.ownershipVersion) : state.ownershipVersion, securityVersion: state.securityVersion,
    nextSecurityVersion: next(state.securityVersion), securityHead: state.securityHead, genesisFingerprint: state.genesisFingerprint, dataGeneration: state.dataGeneration,
    custodyEpoch: state.custodyEpoch, workspaceKeyEpoch: state.workspaceKeyEpoch, authorizer, currentDevices: [],
    scopes: state.profiles[f.owner.accountId]!.scopes.map((scope) => { const { manifests, ...rest } = scope; return { ...rest,
      mode: owner ? 'custody' : 'content', keyEpoch: owner ? state.custodyEpoch : state.workspaceKeyEpoch, permissions: role.permissions,
      sources: manifests.map((entry) => ({ grantId: randomUUID(), generation: '1', manifestId: entry.id, manifestDigest: entry.digest })) }; }),
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 3600000).toISOString() });
  const exportKey = base64urlEncode(await randomKey()), phrase = owner ? await newOwnerPhrase() : undefined, positions = [1, 8, 20];
  const prepared = await prepareEnrolmentDraft({ mode: 'join', history: f.history, input: { binding, exportKey, displayName: 'Private confirmed account',
    configuration: { ...f.configuration, identifiers: { client: `ukda:${f.workspaceId}:${accountId}`, server: origin } }, registrationRecord: base64urlEncode(await randomKey()),
    ...(phrase ? { newOwnerKit: { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) } } : {}) } });
  const fingerprint = await digestObject(prepared.draft.transcript); prepared.draft.recipientConfirmation = await confirmEnrolmentTarget({ prepared, exportKey, history: f.history, fingerprint });
  const { registrationRecord: _record, ...draft } = prepared.draft;
  const approval = await prepareEnrolmentApproval({ draft, fingerprint, history: f.history, materials: f.materials }, f.owner.bundle);
  await append(f, approval.transition, binding.nextSecurityVersion);
  for (const object of approval.deliveries) f.materials.push({ id: object.id, kind: 'key_envelope', value: object.envelope, digest: await digestObject(object.envelope) });
  const bundle = await unwrapDeviceBundle(enrolmentDeviceContext(prepared.draft.transcript), prepared.deviceWrapper, exportKey);
  return { accountId, deviceId: prepared.draft.transcript.device.id, bundle, phrase };
}
async function contextFor(f: OwnerFixture, target: Actor, action: AccessRequest['action'], actor = f.owner, operationId: string = randomUUID()) {
  const receiptToken = base64urlEncode(await randomKey()), reference = { workspaceId: f.workspaceId, operationId }, now = Date.now();
  const desired = ['set_access', 'demote_owner', 'reactivate_member'].includes(action) ? { roleId: f.history.genesis.body.roles.member, projectIds: [] } : null;
  const request: AccessRequest = { ...reference, targetAccountId: target.accountId, action, desired, receiptTokenHash: await accessReceiptTokenHash(reference, receiptToken) };
  const binding = createAccessBinding(request, f.state, actorAuthority(f, actor), { issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600000).toISOString() });
  const context: AccessContext = { binding, plan: deriveAccessPlan(binding, f.state), materials: f.materials };
  return { request, context, receiptToken };
}
async function applyAccess(f: OwnerFixture, payload: AccessPayload): Promise<AccessReceipt> {
  const binding = payload.transition.body.binding; await append(f, payload.transition, binding.nextSecurityVersion);
  for (const [kind, object] of [['custody_manifest', payload.custody], ['encrypted_profile', payload.profile]] as const) if (object) f.materials.push({ id: object.id, kind, value: object.envelope, digest: await digestObject(object.envelope) });
  for (const object of payload.deliveries) f.materials.push({ id: object.id, kind: 'key_envelope', value: object.envelope, digest: await digestObject(object.envelope) });
  return { version: 1, workspaceId: f.workspaceId, operationId: binding.operationId, targetAccountId: binding.targetAccountId,
    securityVersion: binding.nextSecurityVersion, securityHead: f.state.securityHead, requestHash: await digestObject(payload), committedAt: new Date().toISOString(), transition: payload.transition };
}
function deliveryFor(f: OwnerFixture, actor = f.owner) {
  return { workspaceId: f.workspaceId, accountId: actor.accountId, deviceId: actor.deviceId, current: f.history.expected, materials: f.materials };
}

test('CP06 access client: Owner removal rotates custody and content while remaining Owner phrase retains the full historical keyring', async () => {
  const f = await ownerFixture(), successor = await join(f, true), old = await readOwnerCustodyKeyMaterial({ accountId: f.owner.accountId, deviceId: f.owner.deviceId, history: f.state, materials: f.materials }, f.owner.bundle);
  const prepared = await contextFor(f, f.owner, 'remove'), payload = await prepareAccessChange({ ...prepared, history: f.history }, f.owner.bundle);
  assert.equal(payload.transition.body.deliveries.some((delivery) => delivery.recipient.accountId === f.owner.accountId), false);
  assert.equal(canonicalJson(payload).includes(old.payload.custodyKey), false);
  await applyAccess(f, payload);
  assert.equal((await refreshAccessKeys({ history: f.history, delivery: deliveryFor(f, successor) }, successor.bundle)).custodyEpoch, '2');
  await assert.rejects(refreshAccessKeys({ history: f.history, delivery: deliveryFor(f) }, f.owner.bundle));
  const keys = await recoveryKeys(successor.phrase!, { workspaceId: f.workspaceId, accountId: successor.accountId });
  try {
    const authority = f.state.recoveryAuthorities[`${successor.accountId}:1`]!;
    const retained = await readRecoveryCustodyKeyMaterial({ accountId: successor.accountId, recoveryId: authority.id, recoveryGeneration: '1', history: f.state, materials: f.materials }, keys.recipient.privateKey);
    assert.deepEqual(retained.manifest.workspaceKeys.slice(0, 1), old.manifest.workspaceKeys); assert.equal(retained.manifest.workspaceKeys.length, 2);
    assert.notEqual(retained.payload.custodyKey, old.payload.custodyKey);
  } finally { keys.signing.privateKey.fill(0); keys.recipient.privateKey.fill(0); }
});

test('CP06 access client: suspension excludes recipient, reactivation cannot restore old devices, and tampered plans fail before sealing', async () => {
  const f = await ownerFixture(), member = await join(f), prepared = await contextFor(f, member, 'suspend');
  const altered = structuredClone(prepared); altered.context.plan.recipients.push({ ...altered.context.plan.recipients[0]!, accountId: member.accountId });
  await assert.rejects(prepareAccessChange({ ...altered, history: f.history }, f.owner.bundle), (error: unknown) => error instanceof AccessChangeClientError && error.code === 'INVALID_CHANGE');
  const payload = await prepareAccessChange({ ...prepared, history: f.history }, f.owner.bundle); await applyAccess(f, payload);
  assert.equal(f.state.profiles[member.accountId]?.state, 'suspended'); assert.equal(f.state.devices[member.deviceId]?.active, false);
  assert.equal((await refreshAccessKeys({ history: f.history, delivery: deliveryFor(f) }, f.owner.bundle)).complete, true);
  await assert.rejects(refreshAccessKeys({ history: f.history, delivery: deliveryFor(f, member) }, member.bundle));
  const reactivation = await contextFor(f, member, 'reactivate_member'), activated = await prepareAccessChange({ ...reactivation, history: f.history }, f.owner.bundle); await applyAccess(f, activated);
  assert.equal(f.state.profiles[member.accountId]?.state, 'active'); assert.equal(f.state.profiles[member.accountId]?.owner, false);
  assert.equal(f.state.devices[member.deviceId]?.active, false); assert.equal(activated.deliveries.some((delivery) => delivery.envelope.header.recipientId === member.deviceId), false);
});

test('CP06 access controller: self-removal lost commit reply resumes receipt-only after restart without materials or history', async () => {
  const f = await ownerFixture(); await join(f, true);
  const factory = new IDBFactory(), name = randomUUID(), pins = await IndexedPairingStore.open(origin, randomUUID(), factory); await pins.recordVerifiedHistory(f.history);
  let store = await IndexedAccessChangeStore.open(origin, name, factory), signedIn = true, historyReads = 0, commits = 0, payload: AccessPayload | undefined, receipt: AccessReceipt | undefined;
  const auth = { origin, current: () => signedIn ? { localAccess: 'unlocked', session: { workspaceId: f.workspaceId, accountId: f.owner.accountId,
    deviceId: f.owner.deviceId, credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1' } } : undefined,
    worker: { prepareAccessChange: (input: Parameters<typeof prepareAccessChange>[0]) => prepareAccessChange(input, f.owner.bundle) },
    logout: async () => { signedIn = false; } } as unknown as AuthController;
  const status = async (): Promise<AccessView> => receipt ? { state: 'completed', requestHash: receipt.requestHash, receipt } : payload ?
    { state: 'staged', requestHash: await digestObject(payload), receipt: null } : { state: 'absent', requestHash: null, receipt: null };
  const unexpected = async (): Promise<never> => { throw new Error('No post-removal content delivery is authorised'); };
  const transport: AccessChangeTransport = { origin, context: async (request) => {
    const now = Date.now(), binding = createAccessBinding(request, f.state, actorAuthority(f), { issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600000).toISOString() });
    return { binding, plan: deriveAccessPlan(binding, f.state), materials: f.materials };
  }, status, stage: async (value) => { assert.equal(canonicalJson((await store.get(value.transition.body.binding.operationId))?.payload), canonicalJson(value)); payload = value; return status(); },
  finalize: async () => { commits++; receipt = await applyAccess(f, payload!); throw new Error('Lost commit reply'); },
  history: async () => { historyReads++; return { genesis: f.history.genesis, transitions: f.history.transitions, anchor: f.history.expected, current: f.history.expected }; },
  delivery: unexpected, deliveryHistory: unexpected };
  let controller = new AccessChangeController(auth, transport, store, pins); const operationId = randomUUID();
  await assert.rejects(controller.remove({ accountId: f.owner.accountId, operationId }), /Lost commit reply/); assert.equal(commits, 1);
  const record = await store.get(operationId); assert.ok(record); assert.equal(canonicalJson(record).includes(f.owner.phrase!), false);
  assert.equal(record.payload.transition.body.binding.receiptTokenHash, await accessReceiptTokenHash({ workspaceId: f.workspaceId, operationId }, record.receiptToken));
  const previousReads = historyReads; store.close(); store = await IndexedAccessChangeStore.open(origin, name, factory); signedIn = false;
  controller = new AccessChangeController(auth, transport, store, pins); const result = await controller.resume(operationId);
  assert.equal(result.state, 'completed'); assert.equal(result.access, 'revoked'); assert.equal(historyReads, previousReads); assert.equal(commits, 1);
  const forged = receipt!; receipt = { ...forged, requestHash: '0'.repeat(64) }; await assert.rejects(controller.resume(operationId)); receipt = forged;
  await store.forgetDevice({ workspaceId: f.workspaceId, accountId: f.owner.accountId, deviceId: f.owner.deviceId }); assert.equal(await store.get(operationId), undefined);
  store.close(); pins.close();
});

test('CP06 access store: exact ciphertext is immutable and metadata-only Forget removes corrupt scoped drafts', async () => {
  const f = await ownerFixture(), target = await join(f), prepared = await contextFor(f, target, 'suspend'), payload = await prepareAccessChange({ ...prepared, history: f.history }, f.owner.bundle);
  const factory = new IDBFactory(), name = randomUUID(), store = await IndexedAccessChangeStore.open(origin, name, factory), operationId = prepared.request.operationId;
  const record: AccessChangeRecord = { version: 1, origin, workspaceId: f.workspaceId, accountId: f.owner.accountId, deviceId: f.owner.deviceId,
    operationId, receiptToken: prepared.receiptToken, payload };
  await store.put(record); await store.put(record);
  await assert.rejects(store.put({ ...record, receiptToken: base64urlEncode(await randomKey()) }));
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = factory.open(name, 1); request.onsuccess = () => resolve(request.result); request.onerror = reject; });
  await new Promise<void>((resolve, reject) => { const tx = db.transaction('operations', 'readwrite');
    tx.objectStore('operations').put({ ...record, payload: null }, `${origin}:${operationId}`); tx.objectStore('operations').put({ malformed: true }, 'unrelated'); tx.oncomplete = () => resolve(); tx.onabort = reject; }); db.close();
  await store.forgetDevice({ workspaceId: f.workspaceId, accountId: f.owner.accountId, deviceId: f.owner.deviceId }); assert.equal(await store.get(operationId), undefined); store.close();
});

test('CP06 access transport: receipt status needs no session and history does not upload richer request fields', async () => {
  const f = await ownerFixture(), reference = { workspaceId: f.workspaceId, operationId: randomUUID() }, token = base64urlEncode(await randomKey()); let seen = 0;
  const transport = new HttpAccessChangeTransport(origin, () => undefined, async (url, options) => {
    seen++; const body = JSON.parse(String(options?.body)); assert.deepEqual(body, { ...reference, receiptToken: token });
    const response = new Response(JSON.stringify({ state: 'absent', requestHash: null, receipt: null }), { status: 200, headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: String(url) }); return response;
  });
  assert.equal((await transport.status({ ...reference, receiptToken: token })).state, 'absent'); assert.equal(seen, 1);
  const authenticated = new HttpAccessChangeTransport(origin, () => token, async (url, options) => {
    assert.deepEqual(JSON.parse(String(options?.body)), reference);
    const response = new Response(JSON.stringify({ ...reference, mode: 'current', anchor: f.history.expected, current: f.history.expected,
      afterVersion: '0', genesis: f.history.genesis, transitions: [], nextAfterVersion: null }), { status: 200, headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: String(url) }); return response;
  });
  const richer = { ...reference, action: 'remove', desired: null, targetAccountId: f.owner.accountId };
  assert.deepEqual((await authenticated.history(richer)).anchor, f.history.expected);
});

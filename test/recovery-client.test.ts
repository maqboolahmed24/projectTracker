import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { newOwnerPhrase, recoveryKeys } from '../src/client/recovery.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { readDeviceScopeKeyMaterial, readRecoveryCustodyKeyMaterial } from '../src/client/pairing.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../src/client/opaque.js';
import { base64urlEncode, digestObject, randomKey } from '../src/shared/crypto.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../src/shared/security-history.js';
import type { PairingMaterial, PairingScope } from '../src/shared/pairing.js';

const origin = 'https://ukda.example';
async function custodyFixture(t: TestContext) {
  const workspaceId = randomUUID(), accountId = randomUUID(), phrase = await newOwnerPhrase(), exportKey = base64urlEncode(await randomKey());
  const configuration: OpaquePublicConfiguration = { configId: OPAQUE_CONFIG_ID, keyStretching: OPAQUE_KEY_STRETCHING,
    setupId: 'recovery-client-test', serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } };
  const binding = { origin, workspaceId, accountId, operationId: randomUUID(), activationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1' };
  const positions = [1, 8, 20];
  const prepared = await prepareOwnerActivation({ binding, configuration, registrationRecord: base64urlEncode(await randomKey()), exportKey,
    phrase, challengePositions: positions, challengeAnswers: positions.map((index) => phrase.split(' ')[index]!), displayName: 'Recovery test Owner', workspaceName: 'Recovery test workspace' });
  const genesis = prepared.payload.genesis, genesisFingerprint = prepared.recoveryKit.genesisFingerprint;
  const historyInput: SecurityHistoryInput = { workspaceId, origin, genesis, genesisFingerprint, transitions: [], expected: { securityHead: genesisFingerprint, securityVersion: '1' } };
  const history = await verifySecurityHistory(historyInput), recovery = await recoveryKeys(phrase, { workspaceId, accountId });
  t.after(() => { recovery.signing.privateKey.fill(0); recovery.recipient.privateKey.fill(0); });
  const values = [{ id: genesis.body.custodyId, kind: 'custody_manifest', value: prepared.payload.objects.custody },
    { id: genesis.body.deviceEnvelopeId, kind: 'key_envelope', value: prepared.payload.objects.deviceCustody },
    { id: genesis.body.recoveryEnvelopeId, kind: 'key_envelope', value: prepared.payload.objects.recoveryCustody }];
  const materials: PairingMaterial[] = await Promise.all(values.map(async (item) => ({ ...item, digest: await digestObject(item.value) })));
  const scopes: PairingScope[] = [{ scope: 'workspace', scopeId: workspaceId, mode: 'custody', keyEpoch: '1', expiresAt: null,
    permissions: [...genesis.body.ownerPermissions], sources: [{ grantId: randomUUID(), generation: '1', manifestId: genesis.body.custodyId, manifestDigest: materials[0]!.digest }] }];
  const bundle = await unwrapDeviceBundle({ workspaceId, accountId, deviceId: genesis.body.device.id, credentialGeneration: '1' }, prepared.deviceWrapper, exportKey);
  return { workspaceId, accountId, phrase, exportKey, prepared, historyInput, history, recovery, materials, scopes, bundle,
    input: { accountId, recoveryId: genesis.body.recovery.id, recoveryGeneration: '1', history, materials } };
}

test('CP05: a current Owner phrase and approved device recover the same verified custody hierarchy', async (t) => {
  const f = await custodyFixture(t);
  const recovered = await readRecoveryCustodyKeyMaterial(f.input, f.recovery.recipient.privateKey);
  assert.equal(recovered.manifest.custodyEpoch, '1'); assert.equal(recovered.manifest.workspaceKeys.length, 1);
  const device = await readDeviceScopeKeyMaterial({ scopes: f.scopes, history: f.history, materials: f.materials,
    holder: { workspaceId: f.workspaceId, custodyEpoch: '1', approverAccountId: f.accountId,
      approverDevice: { ...f.prepared.payload.genesis.body.device, keyGeneration: '1' } } }, f.bundle);
  assert.deepEqual(device, [recovered.payload]);
});

test('CP05: wrong phrase, retired recovery generation, removed ownership and replaced custody ciphertext fail closed', async (t) => {
  const f = await custodyFixture(t), wrong = await recoveryKeys(await newOwnerPhrase(), { workspaceId: f.workspaceId, accountId: f.accountId });
  try { await assert.rejects(readRecoveryCustodyKeyMaterial(f.input, wrong.recipient.privateKey)); }
  finally { wrong.signing.privateKey.fill(0); wrong.recipient.privateKey.fill(0); }
  await assert.rejects(readRecoveryCustodyKeyMaterial({ ...f.input, recoveryGeneration: '2' }, f.recovery.recipient.privateKey));
  for (const variant of ['inactive', 'not-owner', 'retired', 'custody-epoch'] as const) {
    const history = structuredClone(f.history);
    if (variant === 'inactive') history.profiles[f.accountId]!.active = false;
    if (variant === 'not-owner') history.profiles[f.accountId]!.owner = false;
    if (variant === 'retired') history.recoveryAuthorities[`${f.accountId}:1`]!.active = false;
    if (variant === 'custody-epoch') history.custodyEpoch = '2';
    await assert.rejects(readRecoveryCustodyKeyMaterial({ ...f.input, history }, f.recovery.recipient.privateKey));
  }
  const materials = structuredClone(f.materials); materials[0]!.digest = 'f'.repeat(64);
  await assert.rejects(readRecoveryCustodyKeyMaterial({ ...f.input, materials }, f.recovery.recipient.privateKey));
});

import { proveOwnerPhrase, prepareRecoveryDraft, verifyRecoveryDraftWrapper, confirmRecoveryRecipient,
  preparePhraseRecoveryApproval, prepareOwnerRecoveryApproval, verifyRecoveryDelivery } from '../src/client/recovery-controller.js';
import { recoveryBinding, validateRecoveryPhraseProof, validateRecoveryApproval, type RecoveryBinding } from '../src/shared/recovery.js';

async function phraseDraftFixture(t: TestContext, mode: 'phrase' | 'owner_reset' = 'phrase') {
  const f = await custodyFixture(t), old = f.prepared.payload.genesis.body;
  const now = Date.now();
  const operationId = randomUUID(), currentRecovery = { ...old.recovery, generation: '1' };
  const binding: RecoveryBinding = recoveryBinding.parse({ version: 1, origin, workspaceId: f.workspaceId, accountId: f.accountId, operationId,
    isOwner: true, credentialGeneration: '1', nextCredentialGeneration: '2', sessionGeneration: '1', nextSessionGeneration: '2',
    resetGeneration: mode === 'phrase' ? '0' : '1', recoveryGeneration: '1', nextRecoveryGeneration: '2', deviceKeyGeneration: '1', nextDeviceKeyGeneration: '2',
    dataGeneration: '1', securityVersion: '1', nextSecurityVersion: '2', securityHead: f.history.securityHead, genesisFingerprint: f.history.genesisFingerprint,
    ownershipVersion: '1', custodyEpoch: '1', currentRecovery, authorizer: mode === 'phrase' ? { kind: 'phrase', accountId: f.accountId, recovery: currentRecovery } :
      { kind: 'owner_reset', accountId: f.accountId, device: { ...old.device, keyGeneration: '1' }, credentialGeneration: '1', sessionGeneration: '1', resetId: operationId, resetGeneration: '1' },
    scopes: f.scopes, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 900000).toISOString() });
  const phrase = await newOwnerPhrase(), positions = [0, 6, 21];
  const next = await prepareRecoveryDraft({ binding, configuration: old.opaque, registrationRecord: base64urlEncode(await randomKey()), exportKey: f.exportKey,
    newOwnerKit: { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) } });
  const fingerprint = await digestObject(next.draft.transcript);
  const confirmation = await confirmRecoveryRecipient({ ...next, exportKey: f.exportKey, fingerprint, history: f.historyInput });
  const draft = { ...next.draft, recipientConfirmation: confirmation };
  const kit = { origin, workspaceId: f.workspaceId, accountId: f.accountId, genesisFingerprint: f.history.genesisFingerprint };
  return { ...f, binding, kit, next: { ...next, draft }, phrase, fingerprint };
}

test('CP05: phrase challenge is confined to the saved kit and fresh current recovery key', async (t) => {
  const f = await phraseDraftFixture(t);
  const now = Date.now();
  const challenge = { version: 1 as const, purpose: 'ukda.owner-phrase-challenge.v1' as const, binding: f.binding, proofId: randomUUID(),
    nonce: base64urlEncode(await randomKey()), issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 120000).toISOString() };
  const proof = await proveOwnerPhrase({ challenge, kit: f.kit, phrase: f.prepared.recoveryKit.phrase });
  await validateRecoveryPhraseProof(proof, challenge);
  await assert.rejects(proveOwnerPhrase({ challenge, kit: { ...f.kit, genesisFingerprint: 'a'.repeat(64) }, phrase: f.prepared.recoveryKit.phrase }));
  await assert.rejects(proveOwnerPhrase({ challenge, kit: f.kit, phrase: f.phrase }));
  await assert.rejects(proveOwnerPhrase({ challenge: { ...challenge, expiresAt: new Date(Date.now() - 1).toISOString() }, kit: f.kit, phrase: f.prepared.recoveryKit.phrase }));
});

test('CP05: local recovery draft has no plaintext secrets, requires word confirmation and full fingerprint, and detects readback replacement', async (t) => {
  const f = await phraseDraftFixture(t);
  await verifyRecoveryDraftWrapper({ ...f.next, exportKey: f.exportKey });
  const serialized = JSON.stringify(f.next);
  assert.equal(serialized.includes(f.phrase), false); assert.equal(serialized.includes(f.exportKey), false);
  assert.equal(serialized.includes('PrivateKey'), false);
  await assert.rejects(verifyRecoveryDraftWrapper({ ...f.next, exportKey: base64urlEncode(await randomKey()) }));
  await assert.rejects(confirmRecoveryRecipient({ ...f.next, exportKey: f.exportKey, fingerprint: f.fingerprint.slice(0, 8), history: f.historyInput }));
  await assert.rejects(prepareRecoveryDraft({ binding: f.binding, configuration: f.next.draft.transcript.configuration,
    registrationRecord: f.next.draft.registrationRecord, exportKey: f.exportKey }));
  await assert.rejects(prepareRecoveryDraft({ binding: f.binding, configuration: f.next.draft.transcript.configuration,
    registrationRecord: f.next.draft.registrationRecord, exportKey: f.exportKey,
    newOwnerKit: { phrase: f.prepared.recoveryKit.phrase, positions: [0, 6, 21], answers: [0, 6, 21].map((i) => f.prepared.recoveryKit.phrase.split(' ')[i]!) } }));
});

for (const mode of ['phrase', 'owner_reset'] as const) test(`CP05: ${mode} seals exact retained custody, rotates keys, and verifies committed replacement delivery`, async (t) => {
  const f = await phraseDraftFixture(t, mode);
  const input = { draft: f.next.draft, fingerprint: f.fingerprint, history: f.historyInput, materials: f.materials };
  const approval = mode === 'phrase' ? await preparePhraseRecoveryApproval({ ...input, wrapper: f.next.wrapper, exportKey: f.exportKey,
    phrase: f.prepared.recoveryKit.phrase, kit: f.kit }) : await prepareOwnerRecoveryApproval({ ...input, draft: { transcript: input.draft.transcript,
      recipientConfirmation: input.draft.recipientConfirmation, newRecoveryConfirmation: input.draft.newRecoveryConfirmation } }, f.bundle);
  const verified = await validateRecoveryApproval(approval, f.next.draft, f.binding, f.next.draft.transcript.configuration);
  const transcript = f.next.draft.transcript;
  const receipt = { version: 1 as const, operationId: f.binding.operationId, workspaceId: f.workspaceId, accountId: f.accountId, deviceId: transcript.device.id,
    credentialGeneration: '2', sessionGeneration: '2', keyGeneration: '2', recoveryGeneration: '2', dataGeneration: '1', securityVersion: '2', securityHead: verified.securityHead,
    requestHash: verified.requestHash, wrapperHash: transcript.wrapperHash, committedAt: new Date().toISOString(), transition: approval.transition };
  const history = { ...f.historyInput, transitions: [approval.transition], expected: { securityHead: receipt.securityHead, securityVersion: '2' } };
  const state = await verifySecurityHistory(history);
  assert.equal(state.devices[f.prepared.payload.genesis.body.device.id]!.active, false);
  assert.equal(state.recoveryAuthorities[`${f.accountId}:1`]!.active, false);
  const bundle = await unwrapDeviceBundle({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId: transcript.device.id, credentialGeneration: '2' }, f.next.wrapper, f.exportKey);
  const delivery = { receipt, deliveries: approval.deliveries, materials: [...f.materials.filter((item) => item.kind === 'custody_manifest'),
    ...await Promise.all(approval.deliveries.map(async (item) => ({ id: item.id, kind: 'key_envelope', value: item.envelope, digest: await digestObject(item.envelope) })))] };
  assert.deepEqual(await verifyRecoveryDelivery({ delivery, history, newOwnerPhrase: f.phrase }, bundle), { complete: true, scopeCount: 1 });
  await assert.rejects(verifyRecoveryDelivery({ delivery: { ...delivery, deliveries: [] }, history }, bundle));
  await assert.rejects(verifyRecoveryDelivery({ delivery, history: f.historyInput }, bundle));
});

import { IDBFactory } from 'fake-indexeddb';
import { IndexedDeviceStore } from '../src/client/device-store.js';
import { IndexedPairingStore } from '../src/client/pairing.js';
import { IndexedRecoveryStore, RecoveryController, type RecoveryTransport, type RecoveryRecipientRecord } from '../src/client/recovery-controller.js';
import type { AuthController } from '../src/client/auth-controller.js';
import type { RecoveryDraft, RecoveryView, RecoveryApproval, RecoveryReceipt } from '../src/shared/recovery.js';

/** OPAQUE exchange is stubbed here to isolate persistence/response-loss behavior; HTTP/browser suites exercise real OPAQUE. */
async function controllerFixture(t: TestContext) {
  const f = await phraseDraftFixture(t), factory = new IDBFactory(), name = randomUUID();
  const operations = await IndexedRecoveryStore.open(origin, `${name}-recovery`, factory), devices = await IndexedDeviceStore.open(`${name}-devices`, factory), pins = await IndexedPairingStore.open(origin, `${name}-pins`, factory);
  const now = Date.now(), localId = f.binding.operationId;
  const challenge = { version: 1 as const, purpose: 'ukda.owner-phrase-challenge.v1' as const, binding: f.binding, proofId: randomUUID(), nonce: base64urlEncode(await randomKey()),
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 120000).toISOString() };
  let draft: RecoveryDraft | undefined, approval: RecoveryApproval | undefined, receipt: RecoveryReceipt | null = null, authenticated = false, finalized = 0, loseFinal = false, loseStage = false;
  let signalReached: (() => void) | undefined, releaseStage: (() => void) | undefined, delayStage = false;
  const view = (): RecoveryView => ({ workspaceId: f.workspaceId, accountId: f.accountId, operationId: localId, state: receipt ? 'completed' : draft?.recipientConfirmation ? 'confirmed' : 'verifying',
    binding: f.binding, transcript: draft?.transcript ?? null, transcriptDigest: null, recipientConfirmation: draft?.recipientConfirmation ?? null, authorizerConfirmation: approval?.transition.body.authorizerConfirmation ?? null,
    newRecoveryConfirmation: draft?.newRecoveryConfirmation ?? null, approvalStaged: !!approval, passwordProved: !!draft, requestHash: receipt?.requestHash ?? null, receipt,
    expiresAt: f.binding.expiresAt, resumeExpiresAt: new Date(now + 86400000).toISOString() });
  const freshView = async () => { const value = view(); value.transcriptDigest = draft ? await digestObject(draft.transcript) : null;
    if (approval && draft) value.requestHash = await digestObject({ ...approval, registrationRecord: draft.registrationRecord }); return value; };
  const transport: RecoveryTransport = {
    origin, beginPhrase: async () => challenge, provePhrase: async ({ proof }) => { await validateRecoveryPhraseProof(proof, challenge); return freshView(); },
    status: freshView, inspect: freshView,
    registration: async () => ({ registrationResponse: base64urlEncode(await randomKey()), configuration: f.next.draft.transcript.configuration }),
    startProof: async (input) => { draft = structuredClone(input.draft); return { proofId: randomUUID(), expiresAt: challenge.expiresAt, loginResponse: base64urlEncode(await randomKey()), configuration: draft.transcript.configuration,
      draftHash: await digestObject({ transcript: draft.transcript, registrationRecord: draft.registrationRecord, newRecoveryConfirmation: draft.newRecoveryConfirmation }) }; },
    finishProof: async () => ({ verified: true }),
    confirm: async ({ confirmation }) => { if (confirmation.body.role === 'recipient') draft!.recipientConfirmation = confirmation; return freshView(); },
    materials: async () => f.materials,
    stage: async ({ approval: input }) => {
      if (approval) assert.deepEqual(input, approval, 'ambiguous stage must replay identical ciphertext');
      await validateRecoveryApproval(input, draft!, f.binding, draft!.transcript.configuration); approval = structuredClone(input);
      if (delayStage) { signalReached?.(); await new Promise<void>((resolve) => { releaseStage = resolve; }); }
      if (loseStage) { loseStage = false; throw new Error('lost stage response'); } return freshView();
    },
    finalize: async ({ requestHash }) => {
      assert.ok(approval && draft); const checked = await validateRecoveryApproval(approval, draft, f.binding, draft.transcript.configuration); assert.equal(requestHash, checked.requestHash);
      finalized++; receipt = { version: 1, operationId: localId, workspaceId: f.workspaceId, accountId: f.accountId, deviceId: draft.transcript.device.id,
        credentialGeneration: '2', sessionGeneration: '2', keyGeneration: '2', recoveryGeneration: '2', dataGeneration: '1', securityVersion: '2', securityHead: checked.securityHead,
        requestHash, wrapperHash: draft.transcript.wrapperHash, committedAt: new Date().toISOString(), transition: approval.transition };
      if (loseFinal) { loseFinal = false; throw new Error('lost final response'); } return { state: 'completed', receipt };
    },
    history: async (_ref, mode) => ({ genesis: f.historyInput.genesis, transitions: mode === 'current' && receipt ? [receipt.transition] : [],
      anchor: mode === 'current' && receipt ? { securityHead: receipt.securityHead, securityVersion: '2' } : f.historyInput.expected,
      current: receipt ? { securityHead: receipt.securityHead, securityVersion: '2' } : f.historyInput.expected }),
    delivery: async () => { assert.ok(authenticated && receipt && approval); return { receipt, deliveries: approval.deliveries, materials: f.materials.filter((item) => item.kind === 'custody_manifest') }; },
    cancel: async () => { const result = await freshView(); result.state = 'cancelled'; return result; },
    issueReset: async () => { throw new Error('not this fixture'); }, revokeReset: async () => { throw new Error('not this fixture'); },
    beginReset: async () => { throw new Error('not this fixture'); }, claim: async () => { throw new Error('not this fixture'); },
  };
  const worker = { proveOwnerPhrase, prepareRecoveryDraft, verifyRecoveryDraftWrapper, confirmRecoveryRecipient, preparePhraseRecoveryApproval,
    startRegistration: async () => ({ registrationRequest: base64urlEncode(await randomKey()), clientRegistrationState: base64urlEncode(await randomKey()) }),
    finishRegistration: async () => ({ registrationRecord: f.next.draft.registrationRecord, exportKey: f.exportKey }),
    startLogin: async () => ({ startLoginRequest: base64urlEncode(await randomKey()), clientLoginState: base64urlEncode(await randomKey()) }),
    finishLogin: async () => ({ finishLoginRequest: base64urlEncode(await randomKey()), exportKey: f.exportKey }),
    verifyRecoveryDelivery: async (input: Parameters<typeof verifyRecoveryDelivery>[0]) => {
      const wrapper = await devices.getActive(f.workspaceId, f.accountId, draft!.transcript.device.id); assert.ok(wrapper);
      const bundle = await unwrapDeviceBundle({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId: draft!.transcript.device.id, credentialGeneration: '2' }, wrapper, f.exportKey);
      return verifyRecoveryDelivery(input, bundle);
    },
  };
  const auth = { origin, worker, current: () => authenticated && receipt ? { localAccess: 'unlocked', session: { workspaceId: f.workspaceId, accountId: f.accountId,
    deviceId: receipt.deviceId, credentialGeneration: '2', sessionGeneration: '2', dataGeneration: '1', accessLevel: 'device_approved' } } : undefined } as unknown as AuthController;
  const controller = new RecoveryController(auth, transport, devices, operations, pins);
  t.after(() => { controller.clear(); operations.close(); devices.close(); pins.close(); });
  const prepare = async () => {
    await controller.beginPhrase(f.kit, localId); await controller.provePhrase(localId, f.prepared.recoveryKit.phrase);
    const positions = [0, 6, 21]; const prepared = await controller.prepare(localId, 'new-password', 'new-password', { phrase: f.phrase, positions, answers: positions.map((i) => f.phrase.split(' ')[i]!) });
    assert.ok(prepared.fingerprint); await controller.confirmRecipient(localId, prepared.fingerprint); return prepared.fingerprint;
  };
  return { ...f, factory, name, localId, controller, operations, devices, pins, auth, transport, prepare, receipt: () => receipt, finalized: () => finalized,
    authenticate: () => { authenticated = true; }, loseFinal: () => { loseFinal = true; }, loseStage: () => { loseStage = true; },
    delayStage: () => { delayStage = true; return new Promise<void>((resolve) => { signalReached = resolve; }); }, releaseStage: () => releaseStage?.() };
}

test('CP05: encrypted recovery draft survives lost final response/restart, promotes once and requires fresh login before content', async (t) => {
  const f = await controllerFixture(t), fingerprint = await f.prepare();
  const record = await f.operations.get('recipient', f.localId); assert.ok(record?.role === 'recipient' && record.prepared);
  assert.equal(await f.devices.getActive(f.workspaceId, f.accountId, record.deviceId!), undefined);
  f.loseFinal(); await assert.rejects(f.controller.approvePhrase(f.localId, fingerprint, f.prepared.recoveryKit.phrase), /lost final/);
  assert.equal(f.finalized(), 1); f.controller.clear();
  const restarted = new RecoveryController(f.auth, f.transport, f.devices, f.operations, f.pins);
  assert.equal((await restarted.resume(f.localId)).access, 'login_required');
  f.authenticate(); assert.equal((await restarted.resume(f.localId, f.phrase)).access, 'content_ready');
  assert.equal((await restarted.resume(f.localId, f.phrase)).access, 'content_ready'); assert.equal(f.finalized(), 1);
  const saved = JSON.stringify(await f.operations.get('recipient', f.localId));
  assert.equal(saved.includes(f.phrase), false); assert.equal(saved.includes(f.exportKey), false); assert.equal(saved.includes('new-password'), false);
  assert.equal((await f.operations.list())[0]?.operationId, f.localId);
});

test('CP05: ambiguous stage retries byte-identical approval without creating a second device', async (t) => {
  const f = await controllerFixture(t), fingerprint = await f.prepare(); f.loseStage();
  await assert.rejects(f.controller.approvePhrase(f.localId, fingerprint, f.prepared.recoveryKit.phrase), /lost stage/);
  const first = await f.operations.get('recipient', f.localId); assert.ok(first?.approval);
  await f.controller.approvePhrase(f.localId, fingerprint, f.prepared.recoveryKit.phrase);
  const next = await f.operations.get('recipient', f.localId); assert.deepEqual(next?.approval, first.approval); assert.equal(f.finalized(), 1);
});

test('CP05: Forget drains delayed recovery responses then removes corrupted matching local draft copies', async (t) => {
  const f = await controllerFixture(t), fingerprint = await f.prepare(); const record = await f.operations.get('recipient', f.localId); assert.ok(record?.deviceId);
  const reached = f.delayStage(), approving = f.controller.approvePhrase(f.localId, fingerprint, f.prepared.recoveryKit.phrase);
  const rejection = assert.rejects(approving, (error: unknown) => error instanceof Error && 'code' in error && error.code === 'CANCELLED'); await reached;
  const forgetting = f.controller.forgetDevice({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId: record.deviceId }); f.releaseStage(); await rejection; await forgetting;
  assert.equal(await f.operations.get('recipient', f.localId), undefined); assert.equal(f.finalized(), 0);
  const db = await new Promise<IDBDatabase>((resolve) => { const request = f.factory.open(`${f.name}-recovery`); request.onsuccess = () => resolve(request.result); });
  await new Promise<void>((resolve) => { const tx = db.transaction('operations', 'readwrite'); tx.objectStore('operations').put({ ...record, prepared: { corrupt: true } }, `${origin}:recipient:${f.localId}`); tx.oncomplete = () => resolve(); }); db.close();
  await f.operations.forgetDevice({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId: record.deviceId }); assert.equal(await f.operations.get('recipient', f.localId), undefined);
});

test('CP05: a corrupt precommit local bundle can cancel using capability metadata without promoting anything', async (t) => {
  const f = await controllerFixture(t); await f.prepare(); const record = await f.operations.get('recipient', f.localId); assert.ok(record?.deviceId);
  const db = await new Promise<IDBDatabase>((resolve) => { const request = f.factory.open(`${f.name}-recovery`); request.onsuccess = () => resolve(request.result); });
  await new Promise<void>((resolve) => { const tx = db.transaction('operations', 'readwrite'); tx.objectStore('operations').put({ ...record, prepared: { corrupt: true } }, `${origin}:recipient:${f.localId}`); tx.oncomplete = () => resolve(); }); db.close();
  assert.equal((await f.controller.cancel(f.localId)).state, 'cancelled');
  assert.equal(await f.devices.getStaged(f.localId), undefined); assert.equal(await f.operations.get('recipient', f.localId), undefined); assert.equal(f.finalized(), 0);
});

test('CP05: second phrase recovery uses only the new authority while retaining custody signed by the retired original device', async (t) => {
  const f = await phraseDraftFixture(t);
  const firstApproval = await preparePhraseRecoveryApproval({ ...f.next, fingerprint: f.fingerprint, history: f.historyInput,
    materials: f.materials, exportKey: f.exportKey, phrase: f.prepared.recoveryKit.phrase, kit: f.kit });
  const first = await validateRecoveryApproval(firstApproval, f.next.draft, f.binding, f.next.draft.transcript.configuration);
  const firstHistory = { ...f.historyInput, transitions: [firstApproval.transition], expected: { securityHead: first.securityHead, securityVersion: '2' } };
  const current = await verifySecurityHistory(firstHistory), newRecovery = f.next.draft.transcript.recovery!, now = Date.now();
  assert.equal(current.devices[f.prepared.payload.genesis.body.device.id]!.active, false);
  const retained = firstApproval.transition.body.deliveries.find((item) => item.recipientKind === 'device')!;
  const binding = recoveryBinding.parse({ ...f.binding, operationId: randomUUID(), credentialGeneration: '2', nextCredentialGeneration: '3',
    sessionGeneration: '2', nextSessionGeneration: '3', recoveryGeneration: '2', nextRecoveryGeneration: '3', deviceKeyGeneration: '2', nextDeviceKeyGeneration: '3',
    securityVersion: '2', nextSecurityVersion: '3', securityHead: first.securityHead, currentRecovery: newRecovery,
    authorizer: { kind: 'phrase', accountId: f.accountId, recovery: newRecovery },
    scopes: f.scopes.map((scope) => ({ ...scope, sources: [{ grantId: f.binding.operationId, generation: '2', manifestId: retained.id, manifestDigest: retained.digest }] })),
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 900000).toISOString() });
  const latestPhrase = await newOwnerPhrase(), exportKey = base64urlEncode(await randomKey()), positions = [1, 10, 20];
  const prepared = await prepareRecoveryDraft({ binding, configuration: f.next.draft.transcript.configuration, registrationRecord: base64urlEncode(await randomKey()), exportKey,
    newOwnerKit: { phrase: latestPhrase, positions, answers: positions.map((index) => latestPhrase.split(' ')[index]!) } });
  const fingerprint = await digestObject(prepared.draft.transcript);
  prepared.draft.recipientConfirmation = await confirmRecoveryRecipient({ ...prepared, fingerprint, history: firstHistory, exportKey });
  const materials: PairingMaterial[] = [...f.materials.filter((item) => item.kind === 'custody_manifest'), ...await Promise.all(firstApproval.deliveries.map(async (item) =>
    ({ id: item.id, kind: 'key_envelope', value: item.envelope, digest: await digestObject(item.envelope) })))];
  const input = { ...prepared, fingerprint, history: firstHistory, materials, exportKey, phrase: f.phrase, kit: f.kit };
  await assert.rejects(preparePhraseRecoveryApproval({ ...input, phrase: f.prepared.recoveryKit.phrase }), 'old phrase must not authorize recovery again');
  const approval = await preparePhraseRecoveryApproval(input);
  const checked = await validateRecoveryApproval(approval, prepared.draft, binding, prepared.draft.transcript.configuration);
  const receipt: RecoveryReceipt = { version: 1, operationId: binding.operationId, workspaceId: f.workspaceId, accountId: f.accountId, deviceId: prepared.draft.transcript.device.id,
    credentialGeneration: '3', sessionGeneration: '3', keyGeneration: '3', recoveryGeneration: '3', dataGeneration: '1', securityVersion: '3', securityHead: checked.securityHead,
    requestHash: checked.requestHash, wrapperHash: prepared.draft.transcript.wrapperHash, committedAt: new Date().toISOString(), transition: approval.transition };
  const history = { ...firstHistory, transitions: [...firstHistory.transitions, approval.transition], expected: { securityHead: checked.securityHead, securityVersion: '3' } };
  const bundle = await unwrapDeviceBundle({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId: receipt.deviceId, credentialGeneration: '3' }, prepared.wrapper, exportKey);
  assert.deepEqual(await verifyRecoveryDelivery({ history, newOwnerPhrase: latestPhrase, delivery: { receipt, deliveries: approval.deliveries,
    materials: materials.filter((item) => item.kind === 'custody_manifest') } }, bundle), { complete: true, scopeCount: 1 });
  const final = await verifySecurityHistory(history);
  assert.equal(final.recoveryAuthorities[`${f.accountId}:1`]!.active, false);
  assert.equal(final.recoveryAuthorities[`${f.accountId}:2`]!.active, false);
  assert.equal(final.recoveryAuthorities[`${f.accountId}:3`]!.active, true);
});

import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as opaque from '@serenity-kit/opaque';
import { IDBFactory } from 'fake-indexeddb';
import { testAuthWorker } from './client-worker-driver.js';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { AuthController, AuthClientError, type AuthTransport } from '../src/client/auth-controller.js';
import { IndexedDeviceStore, unwrapDeviceBundle } from '../src/client/device-store.js';
import { IndexedPairingStore, PairingController, PairingClientError, HttpPairingTransport, seedActivationPin, preparePairingApproval,
  createPairingDevice, confirmPairingRecipient, confirmPairingApprover,
  verifyPairingDelivery, verifyPairingReceipt, type PairingTransport } from '../src/client/pairing.js';
import { RememberedProfiles } from '../src/client/remembered-profiles.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';
import { base64urlDecode, base64urlEncode, digestObject, generateSigningKeyPair, randomKey, signObject, verifyObject } from '../src/shared/crypto.js';
import type { AuthSessionResult, DeviceChallenge } from '../src/shared/auth.js';
import type { PairingApproval, PairingBegin, PairingConfirmation, PairingMaterial, PairingReceipt, PairingTranscript, PairingView } from '../src/shared/pairing.js';
import type { SecurityHistoryInput } from '../src/shared/security-history.js';

const origin = 'https://ukda.example', password = 'Pairing fixture private password 237492';
const fails = (code: PairingClientError['code']) => (error: unknown) => error instanceof PairingClientError && error.code === code;
async function fixture(t: TestContext) {
  await opaque.ready;
  const workspaceId = randomUUID(), accountId = randomUUID(), phrase = await newOwnerPhrase();
  const serviceSigning = await generateSigningKeyPair(); t.after(() => serviceSigning.privateKey.fill(0));
  const trustedServiceKeys = { 'pairing-fixture-service': base64urlEncode(serviceSigning.publicKey) };
  const registrationWorker = testAuthWorker(origin);
  const opaqueServer = new OpaqueService({ serverSetup: opaque.server.createSetup(), setupId: 'pair-client', serverIdentity: origin });
  const started = await registrationWorker.startRegistration(password), response = await opaqueServer.response(workspaceId, accountId, started.registrationRequest);
  const registered = await registrationWorker.finishRegistration({ password, clientRegistrationState: started.clientRegistrationState, ...response });
  registrationWorker.close();
  const binding = { origin, workspaceId, accountId, activationId: randomUUID(), operationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1' };
  const positions = [1, 8, 20];
  const prepared = await prepareOwnerActivation({ binding, configuration: response.configuration, registrationRecord: registered.registrationRecord,
    exportKey: registered.exportKey, phrase, challengePositions: positions, challengeAnswers: positions.map((index) => phrase.split(' ')[index]!), displayName: 'Pairing Owner', workspaceName: 'Pairing workspace' });
  const genesis = prepared.payload.genesis, head = prepared.recoveryKit.genesisFingerprint, factory = new IDBFactory();
  const ownerDevice = { ...genesis.body.device, keyGeneration: '1' };
  const ownerBundle = await unwrapDeviceBundle({ workspaceId, accountId, deviceId: ownerDevice.id, credentialGeneration: '1' }, prepared.deviceWrapper, registered.exportKey);
  const materials: PairingMaterial[] = [
    { id: genesis.body.custodyId, kind: 'custody_manifest', value: prepared.payload.objects.custody, digest: await digestObject(prepared.payload.objects.custody) },
    { id: genesis.body.deviceEnvelopeId, kind: 'key_envelope', value: prepared.payload.objects.deviceCustody, digest: await digestObject(prepared.payload.objects.deviceCustody) },
  ];
  let view: PairingView | undefined, staged: PairingApproval | undefined, receipt: PairingReceipt | undefined;
  const extraTransitions: unknown[] = [];
  let latestHead: { securityHead: string; securityVersion: string } | undefined;
  let holdStage: (() => Promise<void>) | undefined, holdDelivery: (() => Promise<void>) | undefined;
  let loseStage = false, loseCommit = false, badDelivery = false, begins = 0, stages = 0, commits = 0;
  const snapshot = () => structuredClone(view!);
  const transports = new Set<() => void>();
  function authTransport(): AuthTransport {
    let session: AuthSessionResult | undefined, loginState: string | undefined, loginId: string | undefined, challenge: DeviceChallenge | undefined;
    const key = () => base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const issue = (deviceId: string | null, previous?: AuthSessionResult): AuthSessionResult => ({
      workspaceId, accountId, sessionId: randomUUID(), deviceId, accessLevel: deviceId ? 'device_approved' : 'restricted',
      credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1', csrfToken: key(),
      authenticatedAt: previous?.authenticatedAt ?? new Date().toISOString(), idleExpiresAt: new Date(Date.now() + 1_800_000).toISOString(),
      absoluteExpiresAt: previous?.absoluteExpiresAt ?? new Date(Date.now() + 43_200_000).toISOString(),
    });
    return {
      origin,
      async loginStart(input) {
        assert.equal(input.workspaceId, workspaceId); assert.equal(input.accountId, accountId);
        const result = await opaqueServer.startLogin(workspaceId, accountId, registered.registrationRecord, input.startLoginRequest);
        loginState = result.serverLoginState; loginId = randomUUID();
        return { loginId, loginResponse: result.loginResponse, configuration: response.configuration, expiresAt: new Date(Date.now() + 60_000).toISOString() };
      },
      async loginFinish(input) { assert.equal(input.loginId, loginId); await opaqueServer.finishLogin(workspaceId, accountId, loginState!, input.finishLoginRequest); session = issue(null); return session; },
      async session() { if (!session) throw new AuthClientError('AUTH_REQUIRED'); return { ...session, securityHead: latestHead?.securityHead ?? receipt?.securityHead ?? head, securityVersion: latestHead?.securityVersion ?? receipt?.securityVersion ?? '1' }; },
      async challengeStart(csrf, deviceId) {
        assert.equal(csrf, session?.csrfToken); assert.ok(session);
        const device = deviceId === ownerDevice.id ? ownerDevice : receipt?.deviceId === deviceId ? view!.request.device : undefined;
        assert.ok(device, 'Pending device cannot authenticate before authoritative pairing commit');
        challenge = { version: 1, purpose: 'ukda.device-challenge.v1', origin, workspaceId, accountId, sessionId: session.sessionId, deviceId,
          keyGeneration: '1', credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1', securityVersion: latestHead?.securityVersion ?? receipt?.securityVersion ?? '1',
          securityHead: latestHead?.securityHead ?? receipt?.securityHead ?? head, ownershipVersion: '1', custodyEpoch: '1', grantId: receipt?.grantId ?? randomUUID(), grantGeneration: '1',
          signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey, ceremonyId: randomUUID(), nonce: key(),
          issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 120_000).toISOString() };
        return challenge;
      },
      async challengeFinish(csrf, proof) {
        assert.equal(csrf, session?.csrfToken); assert.deepEqual(proof.body, challenge);
        assert.equal(await verifyObject(proof, base64urlDecode(challenge!.signingPublicKey), 'ukda.device-challenge.v1'), true);
        session = issue(challenge!.deviceId, session); return session;
      },
      async reauthStart() { throw new Error('fixture not used'); }, async reauthFinish() { throw new Error('fixture not used'); },
      async logout(csrf) { assert.equal(csrf, session?.csrfToken); session = undefined; return { loggedOut: true }; },
    };
  }
  const transport: PairingTransport = {
    origin,
    async begin(_csrf, input) {
      begins++; if (view) { assert.deepEqual(view.request, input); return snapshot(); }
      view = { operationId: input.operationId, state: 'waiting_approver', request: structuredClone(input), transcript: null, transcriptDigest: null,
        recipientConfirmation: null, approverConfirmation: null, approvalStaged: false, receipt: null }; return snapshot();
    },
    async inspect(operationId) { assert.equal(operationId, view?.operationId); return snapshot(); },
    async claim(_csrf, operationId) {
      assert.equal(operationId, view?.operationId); assert.ok(view);
      if (!view.transcript) {
        const source = materials[0]!;
        const transcript: PairingTranscript = { version: 1, purpose: 'ukda.device-pair-transcript.v1', origin, workspaceId, operationId, ceremonyId: operationId,
          accountId, device: view.request.device, localBundleDigest: view.request.localBundleDigest, approverAccountId: accountId, approverDevice: ownerDevice,
          approverIsOwner: true, credentialGeneration: '1', sessionGeneration: '1', approverCredentialGeneration: '1', approverSessionGeneration: '1',
          dataGeneration: '1', ownershipVersion: '1', custodyEpoch: '1', genesisFingerprint: head, securityHead: head, securityVersion: '1',
          scopes: [{ scope: 'workspace', scopeId: workspaceId, mode: 'custody', keyEpoch: '1', expiresAt: null, permissions: [...genesis.body.ownerPermissions],
            sources: [{ grantId: randomUUID(), generation: '1', manifestId: source.id, manifestDigest: source.digest }] }],
          issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() };
        view.transcript = transcript; view.transcriptDigest = await digestObject(transcript); view.state = 'verifying';
      }
      return snapshot();
    },
    async confirm(_csrf, confirmation) {
      assert.ok(view?.transcript); const role = confirmation.body.role;
      assert.equal(confirmation.body.transcriptDigest, view.transcriptDigest);
      assert.equal(await verifyObject(confirmation, base64urlDecode(role === 'recipient' ? view.transcript.device.signingPublicKey : ownerDevice.signingPublicKey), 'ukda.device-pair-confirmation.v1'), true);
      if (role === 'recipient') view.recipientConfirmation = structuredClone(confirmation); else view.approverConfirmation = structuredClone(confirmation);
      if (view.recipientConfirmation && view.approverConfirmation) view.state = 'confirmed'; return snapshot();
    },
    async materials() { return structuredClone(materials); },
    async stage(_csrf, input) {
      stages++; assert.equal(view?.state, 'confirmed');
      if (staged) assert.deepEqual(input, staged, 'Lost stage response must replay exact ciphertext and IDs');
      staged = structuredClone(input); view!.approvalStaged = true; await holdStage?.();
      if (loseStage) { loseStage = false; throw new AuthClientError('TRANSPORT'); } return snapshot();
    },
    async commit() {
      commits++; assert.ok(staged);
      receipt ??= { version: 1, operationId: view!.operationId, workspaceId, accountId, deviceId: view!.request.device.id,
        transcriptDigest: view!.transcriptDigest!, grantId: staged.grant.body.grantId, securityHead: await digestObject(staged.grant), securityVersion: '2',
        dataGeneration: '1', committedAt: new Date().toISOString(), grant: staged.grant };
      view!.receipt = receipt; view!.state = 'completed';
      if (loseCommit) { loseCommit = false; throw new AuthClientError('TRANSPORT'); }
      return { receipt: structuredClone(receipt), projection: 'ready' };
    },
    async delivery() { assert.ok(receipt); await holdDelivery?.(); return { receipt: structuredClone(receipt), deliveries: badDelivery ? [] : structuredClone(staged!.deliveries), materials: [structuredClone(materials[0]!)] }; },
    async history(_operationId, mode) { const expected = mode === 'current' && receipt ? latestHead ?? { securityHead: receipt.securityHead, securityVersion: receipt.securityVersion } : { securityHead: head, securityVersion: '1' }; return { genesis, transitions: mode === 'current' && receipt ? [receipt.grant, ...extraTransitions] : [], anchor: expected, current: latestHead ?? (receipt ? { securityHead: receipt.securityHead, securityVersion: receipt.securityVersion } : expected) }; },
  };
  async function actor(name: string, owner: boolean) {
    const devices = await IndexedDeviceStore.open(`devices-${name}`, factory), store = await IndexedPairingStore.open(origin, `pairing-${name}`, factory);
    const remembered = await RememberedProfiles.open(origin, `remembered-${name}`, factory), worker = testAuthWorker(origin), authentication = authTransport();
    if (owner && !(await devices.getActive(workspaceId, accountId, ownerDevice.id))) {
      await devices.stage(prepared.deviceWrapper, binding.operationId); await devices.commit(binding.operationId, { workspaceId, accountId, deviceId: ownerDevice.id, credentialGeneration: '1', operationId: binding.operationId });
      await seedActivationPin(store, genesis, { workspaceId, accountId, deviceId: ownerDevice.id, operationId: binding.operationId,
        genesisFingerprint: head, securityHead: head, securityVersion: '1' });
    }
    const auth = new AuthController(authentication, worker, devices, remembered), controller = new PairingController(auth, transport, devices, store, { remembered, trustedServiceKeys });
    const close = () => { controller.close(); worker.close(); devices.close(); store.close(); remembered.close(); transports.delete(close); }; transports.add(close);
    await auth.login({ workspaceId, accountId, ...(owner ? { deviceId: ownerDevice.id } : {}) }, password);
    return { auth, worker, devices, store, remembered, controller, close };
  }
  const owner = await actor('owner', true), target = await actor('target', false);
  t.after(() => { for (const close of transports) close(); });
  async function confirmed() {
    const pending = await target.controller.begin(), operationId = pending.operationId;
    const claimed = await owner.controller.claim(operationId); assert.ok(claimed.fingerprint);
    await target.controller.confirmRecipient(operationId, claimed.fingerprint);
    await owner.controller.confirmApprover(operationId, claimed.fingerprint); return operationId;
  }
  const history: SecurityHistoryInput = { workspaceId, origin, genesis, genesisFingerprint: head, transitions: [], expected: { securityHead: head, securityVersion: '1' }, trustedServiceKeys };
  return { factory, owner, target, actor, confirmed, transport, workspaceId, accountId, ownerBundle, phrase, exportKey: registered.exportKey, history, materials,
    async restrictLicence(action: 'revoke' | 'legacy_expire') {
      assert.ok(receipt);
      const before = latestHead ?? { securityHead: receipt.securityHead, securityVersion: receipt.securityVersion };
      const transition = await signObject({ version: 1 as const, purpose: 'ukda.entitlement-transition.v1' as const, action,
        operationId: randomUUID(), licenceId: randomUUID(), operatorId: randomUUID(), workspaceId,
        previousHead: before.securityHead, securityVersion: String(BigInt(before.securityVersion) + 1n), dataGeneration: '1',
        before: { entitlementState: 'activated' as const, licenceState: 'active' as const },
        after: { entitlementState: action === 'revoke' ? 'revoked' as const : 'legacy_expired' as const, licenceState: 'restricted' as const },
        changedAt: new Date().toISOString(), serviceKeyId: 'pairing-fixture-service', servicePublicKey: base64urlEncode(serviceSigning.publicKey) }, serviceSigning.privateKey);
      extraTransitions.push(transition); latestHead = { securityHead: await digestObject(transition), securityVersion: transition.body.securityVersion };
      return { ...history, transitions: [receipt.grant, ...extraTransitions], expected: latestHead };
    },
    async advanceHistory() {
      assert.ok(receipt); const operationId = randomUUID();
      const context = { workspaceId, accountId, deviceId: randomUUID(), credentialGeneration: '1' };
      const created = await createPairingDevice({ context, exportKey: registered.exportKey });
      const transcript: PairingTranscript = { ...view!.transcript!, operationId, ceremonyId: operationId, device: created.device,
        localBundleDigest: await digestObject(created.wrapper), securityHead: receipt.securityHead, securityVersion: '2' };
      const fingerprint = await digestObject(transcript);
      const prior = { ...history, transitions: [receipt.grant], expected: { securityHead: receipt.securityHead, securityVersion: '2' } };
      const approval = await preparePairingApproval({ transcript, fingerprint, history: prior,
        recipientConfirmation: await confirmPairingRecipient({ transcript, fingerprint, wrapper: created.wrapper, exportKey: registered.exportKey }),
        approverConfirmation: await confirmPairingApprover({ transcript, fingerprint, history: prior }, ownerBundle), materials }, ownerBundle);
      extraTransitions.push(approval.grant); latestHead = { securityHead: await digestObject(approval.grant), securityVersion: '3' };
      return { ...history, transitions: [receipt.grant, ...extraTransitions], expected: latestHead };
    },
    get view() { return snapshot(); }, get staged() { return staged; }, get receipt() { return receipt; },
    get begins() { return begins; }, get stages() { return stages; }, get commits() { return commits; },
    set holdStage(value: (() => Promise<void>) | undefined) { holdStage = value; }, set holdDelivery(value: (() => Promise<void>) | undefined) { holdDelivery = value; },
    set loseStage(value: boolean) { loseStage = value; }, set loseCommit(value: boolean) { loseCommit = value; }, set badDelivery(value: boolean) { badDelivery = value; } };
}

test('CP04: recipient draft is encrypted/read back before begin; full fingerprint and prior approver trust are mandatory', async (t) => {
  const f = await fixture(t), pending = await f.target.controller.begin();
  const draft = await f.target.store.get('recipient', pending.operationId); assert.ok(draft);
  assert.deepEqual(await f.target.devices.getStaged(pending.operationId), draft.wrapper);
  assert.equal(await f.target.devices.getActive(f.workspaceId, f.accountId, draft.context.deviceId), undefined);
  const untrusted = await IndexedPairingStore.open(origin, randomUUID(), new IDBFactory());
  const untrustedController = new PairingController(f.owner.auth, f.transport, f.owner.devices, untrusted);
  await assert.rejects(untrustedController.claim(pending.operationId), fails('TRUST_REQUIRED'));
  untrustedController.close(); untrusted.close();
  const claimed = await f.owner.controller.claim(pending.operationId); assert.ok(claimed.fingerprint);
  await assert.rejects(f.target.controller.confirmRecipient(pending.operationId, claimed.fingerprint.slice(0, 8)), fails('FINGERPRINT_MISMATCH'));
  assert.equal(f.view.recipientConfirmation, null);
  await f.target.controller.confirmRecipient(pending.operationId, claimed.fingerprint.toUpperCase());
  assert.equal((await f.target.store.pin(f.workspaceId))?.securityHead, f.history.genesisFingerprint);
  const stored = JSON.stringify(await f.target.store.get('recipient', pending.operationId));
  for (const secret of [password, f.phrase, f.exportKey, f.ownerBundle.signingPrivateKey, f.ownerBundle.recipientPrivateKey]) assert.equal(stored.includes(secret), false);
  assert.deepEqual(Object.keys((await f.target.store.list())[0]!).sort(), ['accountId', 'completed', 'deviceId', 'operationId', 'role', 'workspaceId']);
});

test('CP04: ambiguous stage and commit recover the same approval; restart promotes only matching receipt and decrypts every delivery', async (t) => {
  const f = await fixture(t), operationId = await f.confirmed();
  f.loseStage = true; await assert.rejects(f.owner.controller.approve(operationId), /TRANSPORT/);
  const approval = (await f.owner.store.get('approver', operationId))!.approval; assert.ok(approval);
  f.loseCommit = true; await assert.rejects(f.owner.controller.approve(operationId), /TRANSPORT/);
  assert.deepEqual(f.staged, approval); assert.equal(f.stages, 2); assert.equal(f.commits, 1);
  assert.deepEqual((await f.owner.controller.approve(operationId)).grant, approval.grant); assert.equal(f.commits, 1);
  const before = (await f.target.store.get('recipient', operationId))!;
  assert.equal(await f.target.devices.getActive(f.workspaceId, f.accountId, before.context.deviceId), undefined);
  f.target.close(); const restarted = await f.actor('target', false);
  assert.equal((await restarted.store.list())[0]!.operationId, operationId);
  const ready = await restarted.controller.resumeRecipient(operationId, 'This local profile'); assert.equal(ready.state, 'content_ready');
  assert.deepEqual(await restarted.devices.getActive(f.workspaceId, f.accountId, ready.deviceId), before.wrapper);
  assert.equal(restarted.auth.current()?.session.accessLevel, 'device_approved'); assert.equal((await restarted.remembered.list())[0]?.displayName, 'This local profile');
  assert.equal((await restarted.store.pin(f.workspaceId))?.securityVersion, '2');
  await restarted.auth.logout(); assert.equal((await restarted.remembered.list()).length, 1);
  assert.equal((await restarted.store.get('recipient', operationId))?.ready, true);
  await restarted.auth.forget({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId: ready.deviceId });
  assert.equal(await restarted.store.get('recipient', operationId), undefined); assert.equal(await restarted.devices.getStaged(operationId), undefined);
});

test('CP04: missing delivery remains explicitly incomplete with recoverable wrapper; tampered receipt and scope expansion fail', async (t) => {
  const f = await fixture(t), operationId = await f.confirmed(); await f.owner.controller.approve(operationId);
  f.badDelivery = true; await assert.rejects(f.target.controller.resumeRecipient(operationId), fails('INCOMPLETE_KEYS'));
  const draft = (await f.target.store.get('recipient', operationId))!;
  assert.equal(draft.ready, false); assert.ok(await f.target.devices.getActive(f.workspaceId, f.accountId, draft.context.deviceId));
  f.badDelivery = false; assert.equal((await f.target.controller.resumeRecipient(operationId)).state, 'content_ready');
  await assert.rejects(verifyPairingReceipt({ ...f.receipt!, deviceId: randomUUID() }, f.view.transcript!), fails('INVALID_PAIRING'));
  const expanded = structuredClone(f.view.transcript!); expanded.scopes.push({ ...expanded.scopes[0]!, scope: 'project', scopeId: randomUUID(), mode: 'content' });
  await assert.rejects(preparePairingApproval({ transcript: expanded, fingerprint: await digestObject(expanded), history: f.history,
    recipientConfirmation: f.view.recipientConfirmation!, approverConfirmation: f.view.approverConfirmation!, materials: f.materials }, f.ownerBundle), fails('INVALID_PAIRING'));
  const bundle = await unwrapDeviceBundle(draft.context, draft.wrapper, f.exportKey), delivery = await f.transport.delivery(operationId);
  delivery.materials[0]!.digest = 'f'.repeat(64);
  await assert.rejects(verifyPairingDelivery({ delivery, history: { ...f.history, transitions: [f.receipt!.grant],
    expected: { securityHead: f.receipt!.securityHead, securityVersion: '2' } } }, bundle), fails('INCOMPLETE_KEYS'));
});

test('CP04: local revision and trust pins refuse stale overwrite, rollback, and forgotten encrypted copies', async (t) => {
  const f = await fixture(t), pending = await f.target.controller.begin(), draft = (await f.target.store.get('recipient', pending.operationId))!;
  await f.target.store.save({ ...draft, revision: 2 }, 1);
  await assert.rejects(f.target.store.save({ ...draft, revision: 2, ready: true }, 1), fails('CONFLICT'));
  await assert.rejects(f.target.store.save({ ...draft, revision: 3, request: { ...draft.request, localBundleDigest: 'e'.repeat(64) } }, 2), fails('CONFLICT'));
  const operationId = pending.operationId, claimed = await f.owner.controller.claim(operationId);
  await f.target.controller.confirmRecipient(operationId, claimed.fingerprint!); await f.owner.controller.confirmApprover(operationId, claimed.fingerprint!);
  await f.owner.controller.approve(operationId);
  await assert.rejects(f.owner.store.recordVerifiedHistory(f.history), /ROLLBACK/);
  await f.target.auth.forget({ workspaceId: draft.context.workspaceId, accountId: draft.context.accountId, deviceId: draft.context.deviceId }); assert.equal(await f.target.store.get('recipient', operationId), undefined);
});


test('CP04: an older completed receipt resumes against later verified history and a newer local pin', async (t) => {
  const f = await fixture(t), operationId = await f.confirmed(); await f.owner.controller.approve(operationId);
  const later = await f.advanceHistory(); await f.target.store.recordVerifiedHistory(later);
  const result = await f.target.controller.resumeRecipient(operationId);
  assert.equal(result.state, 'content_ready'); assert.equal((await f.target.store.pin(f.workspaceId))?.securityVersion, '3');
  assert.equal((await f.target.store.get('recipient', operationId))?.receipt?.securityVersion, '2');
});

test('CP04: paginated history pins one anchor, rejects changed cursors and bounds complete records', async (t) => {
  const f = await fixture(t), operationId = randomUUID(), anchor = { securityHead: 'e'.repeat(64), securityVersion: '3' };
  const transitions = [{ body: { marker: 2 } }, { body: { marker: 3 } }];
  const requests: Record<string, unknown>[] = [];
  let mutation: 'none' | 'cursor' | 'anchor' | 'oversize' = 'none';
  const transport = new HttpPairingTransport(origin, (async (input, init) => {
    const body = JSON.parse(String(init!.body)) as Record<string, unknown>; requests.push(body);
    const first = body.afterVersion === undefined;
    const response = { workspaceId: f.workspaceId, operationId, mode: 'current', anchor: mutation === 'anchor' && !first ? { ...anchor, securityHead: 'f'.repeat(64) } : anchor,
      current: anchor, afterVersion: first ? '0' : mutation === 'cursor' ? '0' : '1', genesis: first ? f.history.genesis : null,
      transitions: first ? [] : mutation === 'oversize' ? [{ data: 'x'.repeat(1_048_577) }, transitions[1]] : transitions,
      nextAfterVersion: first ? '1' : null };
    const reply = new Response(JSON.stringify(response), { headers: { 'content-type': 'application/json' } });
    Object.defineProperty(reply, 'url', { value: String(input) }); return reply;
  }) as typeof fetch);
  assert.equal(JSON.stringify((await transport.history(operationId, 'current')).transitions), JSON.stringify(transitions));
  assert.deepEqual(requests[1], { operationId, mode: 'current', anchor, afterVersion: '1' });
  for (const variant of ['cursor', 'anchor', 'oversize'] as const) { mutation = variant; await assert.rejects(transport.history(operationId, 'current'), fails('INVALID_PAIRING')); }
});


test('CP04: Forget cancels pairing before commit and late approval responses cannot recreate its local record', async (t) => {
  const f = await fixture(t), operationId = await f.confirmed();
  let release!: () => void, enter!: () => void;
  const entered = new Promise<void>((resolve) => { enter = resolve; });
  f.holdStage = () => new Promise<void>((resolve) => { release = resolve; enter(); });
  const approving = f.owner.controller.approve(operationId), rejected = assert.rejects(approving, fails('CANCELLED'));
  await entered;
  const reference = { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.history.genesis.body.device.id };
  await f.owner.auth.forget(reference); release(); await rejected;
  assert.equal(f.commits, 0); assert.equal(await f.owner.store.get('approver', operationId), undefined);
  assert.equal(await f.owner.devices.getActive(reference.workspaceId, reference.accountId, reference.deviceId), undefined);
});

test('CP04: a late delivery after Forget cannot restore a pending bundle, completion record or remembered card', async (t) => {
  const f = await fixture(t), operationId = await f.confirmed(); await f.owner.controller.approve(operationId);
  let release!: () => void, enter!: () => void;
  const entered = new Promise<void>((resolve) => { enter = resolve; });
  f.holdDelivery = () => new Promise<void>((resolve) => { release = resolve; enter(); });
  const resuming = f.target.controller.resumeRecipient(operationId, 'Must stay forgotten'), rejected = assert.rejects(resuming, fails('CANCELLED'));
  await entered;
  const deviceId = f.view.request.device.id;
  await f.target.auth.forget({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId }); release(); await rejected;
  assert.equal(await f.target.store.get('recipient', operationId), undefined);
  assert.equal(await f.target.devices.getStaged(operationId), undefined); assert.equal((await f.target.remembered.list()).length, 0);
});


for (const action of ['revoke', 'legacy_expire'] as const) test(`CP04: ${action} restriction permits retained-scope replacement delivery with trusted current history`, async (t) => {
  const f = await fixture(t), operationId = await f.confirmed(); await f.owner.controller.approve(operationId);
  const history = await f.restrictLicence(action);
  const draft = (await f.target.store.get('recipient', operationId))!, bundle = await unwrapDeviceBundle(draft.context, draft.wrapper, f.exportKey);
  const delivery = await f.transport.delivery(operationId);
  await assert.rejects(verifyPairingDelivery({ delivery, history: { ...history, trustedServiceKeys: {} } }, bundle), /INVALID_HISTORY/);
  assert.equal((await f.target.controller.resumeRecipient(operationId)).state, 'content_ready');
  assert.equal((await f.target.store.pin(f.workspaceId))?.securityVersion, '3');
  const widened = structuredClone(delivery); widened.receipt.grant.body.transcript.scopes[0]!.scopeId = randomUUID();
  await assert.rejects(verifyPairingDelivery({ delivery: widened, history }, bundle));
});


test('CP04: Forget deletes matching corrupt ciphertext while unrelated malformed rows do not block cleanup', async (t) => {
  const f = await fixture(t), pending = await f.target.controller.begin();
  const draft = (await f.target.store.get('recipient', pending.operationId))!;
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = f.factory.open('pairing-target', 1); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  });
  t.after(() => database.close());
  await new Promise<void>((resolve, reject) => {
    const transaction = database.transaction('operations', 'readwrite'), store = transaction.objectStore('operations');
    store.put({ ...draft, wrapper: { corrupt: true } }, `${origin}:recipient:${pending.operationId}`);
    store.put({ unrelated: 'malformed' }, 'unrelated-corrupt');
    store.put({ origin, context: { workspaceId: randomUUID(), accountId: randomUUID(), deviceId: randomUUID() }, wrapper: { corrupt: true } }, 'different-identity');
    transaction.oncomplete = () => resolve(); transaction.onabort = () => reject(transaction.error);
  });
  await f.target.auth.forget({ workspaceId: draft.context.workspaceId, accountId: draft.context.accountId, deviceId: draft.context.deviceId });
  assert.equal(await f.target.store.get('recipient', pending.operationId), undefined); assert.equal(await f.target.devices.getStaged(pending.operationId), undefined);
  const remaining = await new Promise<unknown[]>((resolve, reject) => {
    const request = database.transaction('operations', 'readonly').objectStore('operations').getAllKeys();
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  });
  assert.deepEqual(remaining.sort(), ['different-identity', 'unrelated-corrupt']);
});

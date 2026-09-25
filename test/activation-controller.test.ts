import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as opaque from '@serenity-kit/opaque';
import { IDBFactory } from 'fake-indexeddb';
import { ActivationController, ActivationControllerError, HttpActivationTransport, IndexedActivationStore,
  type ActivationTransport, type ActivationReceipt, type ActivationStatus } from '../src/client/activation-controller.js';
import { IndexedDeviceStore } from '../src/client/device-store.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';
import { canonicalJson, digestObject } from '../src/shared/crypto.js';
import { validateActivationPayload, type ActivationBinding, type ActivationPayload } from '../src/shared/activation.js';
import { AuthClientError, AuthController, type AuthTransport } from '../src/client/auth-controller.js';
import { AuthWorkerClient } from '../src/client/auth-worker-client.js';
import { IndexedPairingStore, seedActivationPin } from '../src/client/pairing.js';

const origin = 'https://ukda.example';
const password = 'This owner has an unusual long passphrase 2965';
const code = (expected: ActivationControllerError['code']) => (error: unknown) => error instanceof ActivationControllerError && error.code === expected;

/** A real OPAQUE server with in-memory receipt state; persistence is tested separately. */
async function fixture() {
  await opaque.ready;
  const service = new OpaqueService({ serverSetup: opaque.server.createSetup(), setupId: 'activation-controller-tests', serverIdentity: 'ukda:tests' });
  const factory = new IDBFactory();
  const pendingName = randomUUID(); const deviceName = randomUUID();
  let pending = await IndexedActivationStore.open(pendingName, factory);
  let devices = await IndexedDeviceStore.open(deviceName, factory);
  let reserved: ActivationStatus | undefined;
  let token: string | undefined;
  let payload: ActivationPayload | undefined;
  let serverState: string | undefined;
  let proofId: string | undefined;
  let requestHash: string | undefined;
  let proofAccepted = false;
  let receipt: ActivationReceipt | undefined;
  let finalizations = 0; let proofStarts = 0; let registrations = 0;
  let loseReserve = false; let loseFinal = false; let loseProofStart = false; let loseProofFinish = false;
  let loseReplacement = false; let replacements = 0;
  const replacementOperations = new Map<string, { expected: string; generation: string }>();
  let alterReceipt: ((value: ActivationReceipt) => ActivationReceipt) | undefined;
  let beforeFinal: (() => Promise<void>) | undefined;
  const sent: unknown[] = [];
  function state() { assert.ok(reserved); return reserved; }
  function authenticate(id: string, supplied: string) { assert.equal(id, state().activationId); assert.equal(supplied, token); }
  function binding(): ActivationBinding {
    const { activationId, operationId, workspaceId, accountId, reservationGeneration, draftGeneration } = state();
    return { activationId, operationId, workspaceId, accountId, reservationGeneration, draftGeneration, origin };
  }
  const transport: ActivationTransport = {
    origin,
    async reserve(input) {
      sent.push(input);
      if (reserved) { assert.equal(input.operationId, reserved.operationId); assert.equal(input.resumeToken, token); return reserved; }
      token = input.resumeToken;
      reserved = { activationId: randomUUID(), operationId: input.operationId, workspaceId: randomUUID(), accountId: randomUUID(),
        reservationGeneration: '1', draftGeneration: '1', expiresAt: '2030-01-01T00:00:00.000Z', resumeExpiresAt: '2030-01-01T00:00:00.000Z', state: 'reserved' };
      if (loseReserve) { loseReserve = false; throw new Error('Lost reservation response'); }
      return reserved;
    },
    async status(id, supplied) {
      authenticate(id, supplied);
      return receipt ? { ...state(), state: 'completed', receipt: alterReceipt ? alterReceipt(receipt) : receipt }
        : { ...state(), configuration: await service.publicConfiguration(state().workspaceId, state().accountId) };
    },
    async registration(id, supplied, input) {
      authenticate(id, supplied); sent.push(input); registrations++;
      assert.equal(input.draftGeneration, state().draftGeneration);
      return service.response(state().workspaceId, state().accountId, input.registrationRequest);
    },
    async startProof(id, supplied, input) {
      authenticate(id, supplied); sent.push(input); proofStarts++;
      const configuration = await service.publicConfiguration(state().workspaceId, state().accountId);
      const checked = await validateActivationPayload(input.payload, binding(), configuration);
      if (requestHash) assert.equal(requestHash, checked.requestHash);
      requestHash = checked.requestHash; payload = checked.payload;
      const login = await service.startLogin(state().workspaceId, state().accountId, payload.opaqueRegistrationRecord, input.startLoginRequest);
      serverState = login.serverLoginState; proofId = randomUUID(); proofAccepted = false;
      if (loseProofStart) { loseProofStart = false; throw new Error('Lost proof response'); }
      return { proofId, expiresAt: '2030-01-01T00:00:00.000Z', loginResponse: login.loginResponse, requestHash, configuration };
    },
    async finishProof(id, supplied, input) {
      authenticate(id, supplied); sent.push(input);
      assert.equal(input.proofId, proofId); assert.ok(serverState);
      await service.finishLogin(state().workspaceId, state().accountId, serverState, input.finishLoginRequest);
      serverState = undefined; proofAccepted = true;
      if (loseProofFinish) { loseProofFinish = false; throw new Error('Lost proof completion'); }
      return { verified: true };
    },
    async finalize(id, supplied, input) {
      authenticate(id, supplied); sent.push(input); finalizations++;
      assert.equal(input.requestHash, requestHash); assert.ok(proofAccepted); assert.ok(payload);
      await beforeFinal?.();
      receipt = { workspaceId: state().workspaceId, accountId: state().accountId, deviceId: payload.genesis.body.device.id,
        operationId: state().operationId, credentialGeneration: '1', dataGeneration: '1', securityVersion: '1',
        securityHead: await digestObject(payload.genesis), genesisFingerprint: await digestObject(payload.genesis), completedAt: '2026-09-25T00:00:00.000Z' };
      if (loseFinal) { loseFinal = false; throw new Error('Lost finalization response'); }
      return { state: 'completed', receipt: alterReceipt ? alterReceipt(receipt) : receipt };
    },
    async replaceDraft(id, supplied, input) {
      authenticate(id, supplied); assert.equal(receipt, undefined);
      const existing = replacementOperations.get(input.operationId);
      if (existing) { assert.equal(existing.expected, input.expectedDraftGeneration); return { ...state(), draftGeneration: existing.generation }; }
      assert.equal(input.expectedDraftGeneration, state().draftGeneration);
      const generation = (BigInt(input.expectedDraftGeneration) + 1n).toString();
      replacementOperations.set(input.operationId, { expected: input.expectedDraftGeneration, generation });
      reserved = { ...state(), draftGeneration: generation };
      payload = undefined; serverState = undefined; proofId = undefined; requestHash = undefined; proofAccepted = false; replacements++;
      if (loseReplacement) { loseReplacement = false; throw new Error('Lost replacement response'); }
      return reserved;
    },
  };
  let controller = new ActivationController(transport, pending, devices);
  const phrase = await newOwnerPhrase();
  const positions = [1, 8, 20];
  const prepare = (operationId: string) => controller.prepare(operationId, { password, confirmation: password, phrase,
    challengePositions: positions, challengeAnswers: positions.map((position) => phrase.split(' ')[position]!),
    displayName: 'Private Owner Name 3964', workspaceName: 'Private Workspace Name 6834' });
  const reopen = async () => {
    pending.close(); devices.close();
    pending = await IndexedActivationStore.open(pendingName, factory); devices = await IndexedDeviceStore.open(deviceName, factory);
    controller = new ActivationController(transport, pending, devices);
  };
  const corruptDraft = async (id: string) => {
    const raw = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = factory.open(pendingName); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
    });
    try {
      await new Promise<void>((resolve, reject) => {
        const transaction = raw.transaction('pending', 'readwrite'); const store = transaction.objectStore('pending');
        const request = store.get(id); request.onsuccess = () => store.put({ ...request.result, draft: { corrupt: true } });
        transaction.oncomplete = () => resolve(); transaction.onabort = () => reject(transaction.error);
      });
    } finally { raw.close(); }
  };
  return { get controller() { return controller; }, get pending() { return pending; }, get devices() { return devices; }, transport, prepare, reopen, phrase, sent,
    corruptDraft, get replacements() { return replacements; }, loseReplacement() { loseReplacement = true; },
    state, get finalizations() { return finalizations; }, get proofStarts() { return proofStarts; }, get registrations() { return registrations; },
    loseReserve() { loseReserve = true; }, loseFinal() { loseFinal = true; }, loseProofStart() { loseProofStart = true; }, loseProofFinish() { loseProofFinish = true; },
    alterReceipt(callback: typeof alterReceipt) { alterReceipt = callback; }, beforeFinal(callback: typeof beforeFinal) { beforeFinal = callback; },
    close() { pending.close(); devices.close(); } };
}

test('CP03: activation controller persists and verifies local ciphertext before real OPAQUE finalization', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const id = await f.controller.create();
  assert.deepEqual(await f.controller.resume(id), { state: 'reserve_required' });
  await f.controller.reserve(id, 'LIC-test-only');
  assert.deepEqual(await f.controller.resume(id), { state: 'prepare_required' });
  const kit = await f.prepare(id);
  assert.equal(kit.phrase, f.phrase);
  assert.deepEqual(await f.controller.resume(id), { state: 'password_required' });
  const draft = (await f.pending.get(id))!.draft!;
  assert.equal(draft.verified, true);
  assert.deepEqual(await f.devices.getStaged(id), draft.wrapper);
  assert.equal(await f.devices.getActive(draft.context.workspaceId, draft.context.accountId, draft.context.deviceId), undefined);
  f.beforeFinal(async () => {
    assert.equal((await f.pending.get(id))!.draft!.verified, true);
    assert.deepEqual(await f.devices.getStaged(id), draft.wrapper);
    assert.equal(await f.devices.getActive(draft.context.workspaceId, draft.context.accountId, draft.context.deviceId), undefined);
  });
  const result = await f.controller.activate(id, password);
  assert.equal(result.state, 'completed');
  assert.equal(result.receipt.operationId, id);
  assert.deepEqual(await f.devices.getActive(draft.context.workspaceId, draft.context.accountId, draft.context.deviceId), draft.wrapper);
  assert.equal(f.registrations, 1); assert.equal(f.proofStarts, 1); assert.equal(f.finalizations, 1);
  const persisted = canonicalJson(await f.pending.get(id));
  const uploaded = canonicalJson(f.sent);
  for (const secret of [password, f.phrase, 'Private Owner Name 3964', 'Private Workspace Name 6834']) {
    assert.ok(!persisted.includes(secret)); assert.ok(!uploaded.includes(secret));
  }
  assert.ok(!uploaded.includes(draft.wrapper.ciphertext));
  assert.ok(!persisted.includes('exportKey')); assert.ok(!persisted.includes('signingPrivateKey'));
});

test('CP03: lost reservation and final response resume the same operation after IndexedDB reopen', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const id = await f.controller.create(); f.loseReserve();
  await assert.rejects(f.controller.reserve(id, 'LIC-test-only'));
  const original = await f.pending.get(id);
  await f.reopen();
  assert.equal((await f.pending.get(id))!.resumeToken, original!.resumeToken);
  await f.controller.reserve(id, 'LIC-test-only');
  assert.equal(f.state().operationId, id);
  await f.prepare(id); f.loseFinal();
  await assert.rejects(f.controller.activate(id, password));
  const draft = (await f.pending.get(id))!.draft!;
  assert.equal(await f.devices.getActive(draft.context.workspaceId, draft.context.accountId, draft.context.deviceId), undefined);
  await f.reopen();
  assert.equal((await f.controller.resume(id)).state, 'completed');
  assert.equal((await f.controller.resume(id)).state, 'completed');
  assert.equal(f.finalizations, 1); assert.equal(f.proofStarts, 1); assert.equal(f.registrations, 1);
  assert.deepEqual(await f.devices.getStaged(id), draft.wrapper);
  assert.deepEqual(await f.devices.getActive(draft.context.workspaceId, draft.context.accountId, draft.context.deviceId), draft.wrapper);
});

test('CP03: interrupted local staging cannot finalize and resumes the same encrypted draft', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const id = await f.controller.create(); await f.controller.reserve(id, 'LIC-test-only');
  f.devices.close();
  await assert.rejects(f.prepare(id));
  const draft = (await f.pending.get(id))!.draft!;
  assert.equal(draft.verified, false);
  assert.equal(f.proofStarts, 0); assert.equal(f.finalizations, 0);
  await f.reopen();
  assert.equal((await f.controller.resume(id, password)).state, 'completed');
  assert.equal((await f.pending.get(id))!.draft!.requestHash, draft.requestHash);
  assert.equal((await f.pending.get(id))!.draft!.verified, true);
  assert.deepEqual(await f.devices.getActive(draft.context.workspaceId, draft.context.accountId, draft.context.deviceId), draft.wrapper);
  assert.equal(f.registrations, 1); assert.equal(f.finalizations, 1);
});

test('CP03: wrong password and interrupted proofs preserve the identical recoverable draft', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const id = await f.controller.create(); await f.controller.reserve(id, 'LIC-test-only'); await f.prepare(id);
  const original = canonicalJson(await f.pending.get(id));
  await assert.rejects(f.controller.activate(id, 'This is a completely different password 2956'));
  assert.equal(f.finalizations, 0);
  f.loseProofStart(); await assert.rejects(f.controller.activate(id, password));
  await f.reopen();
  f.loseProofFinish(); await assert.rejects(f.controller.resume(id, password));
  assert.equal(f.finalizations, 0);
  assert.equal(canonicalJson(await f.pending.get(id)), original);
  assert.equal((await f.controller.resume(id, password)).state, 'completed');
  assert.equal(f.registrations, 1); assert.equal(f.finalizations, 1);
});

test('CP03: mismatched server receipt cannot promote a candidate; later authentic status can recover', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const id = await f.controller.create(); await f.controller.reserve(id, 'LIC-test-only'); await f.prepare(id);
  const draft = (await f.pending.get(id))!.draft!;
  f.alterReceipt((receipt) => ({ ...receipt, deviceId: randomUUID() }));
  await assert.rejects(f.controller.activate(id, password), code('RECEIPT_MISMATCH'));
  assert.equal(await f.devices.getActive(draft.context.workspaceId, draft.context.accountId, draft.context.deviceId), undefined);
  for (const field of ['workspaceId', 'accountId', 'operationId'] as const) {
    f.alterReceipt((receipt) => ({ ...receipt, [field]: randomUUID() }));
    await assert.rejects(f.controller.resume(id), code('RECEIPT_MISMATCH'));
  }
  f.alterReceipt((receipt) => ({ ...receipt, securityHead: '0'.repeat(64) }));
  await assert.rejects(f.controller.resume(id), code('RECEIPT_MISMATCH'));
  f.alterReceipt(undefined);
  assert.equal((await f.controller.resume(id)).state, 'completed');
  assert.equal(f.finalizations, 1);
});

test('CP03: pending-store compare-and-swap prevents stale tabs from overwriting a saved draft', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const id = await f.controller.create();
  const stale = (await f.pending.get(id))!;
  await f.controller.reserve(id, 'LIC-test-only');
  await assert.rejects(f.pending.save(stale, stale), code('CONFLICT'));
  assert.equal((await f.pending.get(id))!.status!.activationId, f.state().activationId);
  await f.prepare(id);
  await assert.rejects(f.prepare(id), code('CONFLICT'));
  assert.equal(f.registrations, 1);
});

test('CP03: confirmed replacement repairs corrupt drafts and retains idempotency after a lost response', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const id = await f.controller.create(); await f.controller.reserve(id, 'LIC-test-only'); await f.prepare(id);
  const old = (await f.pending.get(id))!.draft!;
  await f.corruptDraft(id);
  f.loseReplacement(); await assert.rejects(f.controller.replaceDraft(id));
  assert.deepEqual(await f.devices.getStaged(id), old.wrapper);
  await f.reopen();
  assert.deepEqual(await f.pending.list(), [{ operationId: id, origin, state: 'replacing_draft' }]);
  assert.equal((await f.controller.replaceDraft(id)).draftGeneration, '2');
  assert.equal(f.replacements, 1);
  assert.equal(await f.devices.getStaged(id), undefined);
  assert.equal((await f.pending.get(id))!.draft, undefined);
  await f.prepare(id);
  const next = (await f.pending.get(id))!.draft!;
  assert.notEqual(next.context.deviceId, old.context.deviceId);
  assert.equal(next.payload.genesis.body.draftGeneration, '2');
  assert.equal((await f.controller.activate(id, password)).state, 'completed');
  await assert.rejects(f.controller.replaceDraft(id), code('ALREADY_COMMITTED'));
  assert.deepEqual(await f.devices.getActive(next.context.workspaceId, next.context.accountId, next.context.deviceId), next.wrapper);
  assert.equal(f.replacements, 1);
});

test('CP03: HTTP activation transport pins HTTPS origin and never sends setup credentials in URLs', async () => {
  assert.throws(() => new HttpActivationTransport('http://ukda.example'), code('TRANSPORT'));
  assert.throws(() => new HttpActivationTransport('https://ukda.example/untrusted-path'), code('TRANSPORT'));
  assert.throws(() => new HttpActivationTransport('http://localhost.evil.example:3400'), code('TRANSPORT'));
  assert.throws(() => new HttpActivationTransport('http://192.168.1.2:3400'), code('TRANSPORT'));
  for (const loopback of ['http://localhost:3400', 'http://127.0.0.1:3400', 'http://[::1]:3400']) assert.equal(new HttpActivationTransport(loopback).origin, loopback);
  const activationId = randomUUID(); const operationId = randomUUID();
  const token = 'A'.repeat(43);
  const status: ActivationStatus = { activationId, operationId, workspaceId: randomUUID(), accountId: randomUUID(), reservationGeneration: '1', draftGeneration: '1',
    expiresAt: '2030-01-01T00:00:00.000Z', resumeExpiresAt: '2030-01-01T00:00:00.000Z', state: 'reserved' };
  let observedUrl = ''; let observed: RequestInit | undefined;
  let redirected = false; let responseUrl: string | undefined;
  const fetcher = (async (input: string | URL | Request, init?: RequestInit) => {
    observedUrl = String(input); observed = init;
    const response = new Response(canonicalJson(status), { status: 200, headers: { 'Content-Type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: responseUrl ?? String(input) });
    Object.defineProperty(response, 'redirected', { value: redirected });
    return response;
  }) as typeof fetch;
  const transport = new HttpActivationTransport(origin, fetcher);
  assert.deepEqual(await transport.status(activationId, token), status);
  assert.equal(observedUrl, `${origin}/v1/activation/${activationId}/status`);
  assert.ok(!observedUrl.includes(token));
  assert.equal((observed!.headers as Record<string, string>).Authorization, `Setup ${token}`);
  assert.equal(observed!.credentials, 'omit'); assert.equal(observed!.redirect, 'error');
  assert.equal(observed!.cache, 'no-store'); assert.equal(observed!.mode, 'same-origin');
  redirected = true;
  await assert.rejects(transport.status(activationId, token), code('TRANSPORT'));
  redirected = false; responseUrl = 'https://other.example/v1/activation/status';
  await assert.rejects(transport.status(activationId, token), code('TRANSPORT'));
});

test('CP03: HTTP error classification is allowlisted, sanitized, and never retried automatically', async () => {
  const activationId = randomUUID(); const token = 'A'.repeat(43);
  const privateMessage = 'Synthetic password phrase and private server diagnostics must not escape';
  const cases: Array<{ status: number; serverCode: string; expected: ActivationControllerError['code'] }> = [
    { status: 410, serverCode: 'ACTIVATION_EXPIRED', expected: 'EXPIRED' },
    { status: 429, serverCode: 'RATE_LIMITED', expected: 'RATE_LIMITED' },
    { status: 503, serverCode: 'SETUP_UNAVAILABLE', expected: 'UNAVAILABLE' },
    { status: 401, serverCode: 'SETUP_PROOF_INVALID', expected: 'PROOF_REQUIRED' },
    { status: 401, serverCode: 'AUTHENTICATION_FAILED', expected: 'PROOF_REQUIRED' },
    { status: 409, serverCode: 'DRAFT_CONFLICT', expected: 'CONFLICT' },
    { status: 409, serverCode: 'OPERATION_CONFLICT', expected: 'CONFLICT' },
    { status: 500, serverCode: 'ACTIVATION_EXPIRED', expected: 'TRANSPORT' },
    { status: 410, serverCode: 'UNRECOGNIZED_ERROR', expected: 'TRANSPORT' },
    { status: 429, serverCode: 'UNRECOGNIZED_ERROR', expected: 'TRANSPORT' },
    { status: 503, serverCode: 'UNRECOGNIZED_ERROR', expected: 'TRANSPORT' },
    { status: 404, serverCode: 'ACTIVATION_INVALID', expected: 'TRANSPORT' },
  ];
  for (const entry of cases) {
    let requests = 0;
    const transport = new HttpActivationTransport(origin, (async (input) => {
      requests++;
      const response = new Response(canonicalJson({ error: { code: entry.serverCode, message: privateMessage, requestId: 'test-only' } }),
        { status: entry.status, headers: { 'Content-Type': 'application/json' } });
      Object.defineProperty(response, 'url', { value: String(input) });
      return response;
    }) as typeof fetch);
    await assert.rejects(transport.status(activationId, token), (error: unknown) => {
      assert.ok(error instanceof ActivationControllerError);
      assert.equal(error.code, entry.expected);
      assert.equal(error.message, `Activation operation failed (${entry.expected})`);
      assert.equal(error.cause, undefined);
      assert.ok(!canonicalJson({ message: error.message, code: error.code }).includes(privateMessage));
      return true;
    });
    assert.equal(requests, 1);
  }
  for (const body of ['not JSON', '{"error":{"code":"ACTIVATION_EXPIRED"}}', '<html>Unavailable</html>']) {
    const transport = new HttpActivationTransport(origin, (async (input) => {
      const response = new Response(body, { status: 410, headers: { 'Content-Type': 'application/json' } });
      Object.defineProperty(response, 'url', { value: String(input) }); return response;
    }) as typeof fetch);
    await assert.rejects(transport.status(activationId, token), code('TRANSPORT'));
  }
  // A local/network exception is not an authenticated API expiry response.
  const failure = new HttpActivationTransport(origin, async () => { throw new ActivationControllerError('EXPIRED'); });
  await assert.rejects(failure.status(activationId, token), code('TRANSPORT'));
});

test('CP03: expired completion recovery returns expired and preserves committed local keys without retry or redemption', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const id = await f.controller.create(); await f.controller.reserve(id, 'LIC-test-only'); await f.prepare(id);
  await f.controller.activate(id, password);
  const saved = (await f.pending.get(id))!; const draft = saved.draft!;
  const urls: string[] = [];
  const expired = new HttpActivationTransport(origin, (async (input) => {
    urls.push(String(input));
    const response = new Response(canonicalJson({ error: { code: 'ACTIVATION_EXPIRED', message: 'Setup recovery has expired', requestId: 'test-expiry' } }),
      { status: 410, headers: { 'Content-Type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: String(input) }); return response;
  }) as typeof fetch);
  const controller = new ActivationController(expired, f.pending, f.devices);
  assert.deepEqual(await controller.resume(id, password), { state: 'expired' });
  assert.deepEqual(urls, [`${origin}/v1/activation/${saved.status!.activationId}/status`]);
  assert.deepEqual(await f.pending.get(id), saved);
  assert.deepEqual(await f.devices.getStaged(id), draft.wrapper);
  assert.deepEqual(await f.devices.getActive(draft.context.workspaceId, draft.context.accountId, draft.context.deviceId), draft.wrapper);
  assert.equal(f.finalizations, 1); assert.equal(f.registrations, 1); assert.equal(f.replacements, 0);
});

function signedOutAuth(devices: IndexedDeviceStore) {
  const denied = async () => { throw new AuthClientError('AUTH_REQUIRED'); };
  const transport: AuthTransport = { origin, loginStart: denied, loginFinish: denied, session: denied,
    challengeStart: denied, challengeFinish: denied, reauthStart: denied, reauthFinish: denied, logout: denied };
  const worker = new AuthWorkerClient({ origin, workerUrl: `${origin}/auth-worker.js` });
  return { auth: new AuthController(transport, worker, devices), close: () => worker.close() };
}

test('CP04: explicit Forget erases active and pending activation wrapper copies while preserving unrelated drafts', async (t) => {
  for (const state of ['pending', 'active'] as const) {
    const f = await fixture(), other = await fixture(); t.after(() => { f.close(); other.close(); });
    const id = await f.controller.create(); await f.controller.reserve(id, 'LIC-forget-fixture'); await f.prepare(id);
    const saved = (await f.pending.get(id))!, context = saved.draft!.context;
    if (state === 'active') await f.controller.activate(id, password);
    const otherId = await other.controller.create(); await other.controller.reserve(otherId, 'LIC-unrelated-fixture'); await other.prepare(otherId);
    const unrelated = (await other.pending.get(otherId))!;
    await f.pending.save(undefined, unrelated); await f.devices.stage(unrelated.draft!.wrapper, otherId);
    // Corrupt ciphertext metadata must not prevent finding the owning device's copy.
    if (state === 'pending') await f.corruptDraft(id);
    const local = signedOutAuth(f.devices); t.after(() => local.close());
    const detach = f.controller.attachAuthLifecycle(local.auth); t.after(detach);
    const reference = { workspaceId: context.workspaceId, accountId: context.accountId, deviceId: context.deviceId };
    await local.auth.forget(reference);
    assert.equal(await f.pending.get(id), undefined); assert.equal(await f.devices.getStaged(id), undefined);
    assert.equal(await f.devices.getActive(context.workspaceId, context.accountId, context.deviceId), undefined);
    assert.deepEqual(await f.pending.get(otherId), unrelated); assert.deepEqual(await f.devices.getStaged(otherId), unrelated.draft!.wrapper);
  }
});

test('CP04: a late activation response cannot recreate local wrappers after Forget', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const id = await f.controller.create(); await f.controller.reserve(id, 'LIC-forget-race'); await f.prepare(id);
  const context = (await f.pending.get(id))!.draft!.context;
  const local = signedOutAuth(f.devices); t.after(() => local.close()); f.controller.attachAuthLifecycle(local.auth);
  f.beforeFinal(() => local.auth.forget({ workspaceId: context.workspaceId, accountId: context.accountId, deviceId: context.deviceId }));
  await assert.rejects(f.controller.activate(id, password), code('CONFLICT'));
  assert.equal(await f.pending.get(id), undefined); assert.equal(await f.devices.getStaged(id), undefined);
  assert.equal(await f.devices.getActive(context.workspaceId, context.accountId, context.deviceId), undefined);
});

test('CP04: verified activation receipt hook seeds the independent genesis pin and retries after a lost response', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const pins = await IndexedPairingStore.open(origin, randomUUID(), new IDBFactory()); t.after(() => pins.close());
  let callbacks = 0;
  const controller = new ActivationController(f.transport, f.pending, f.devices, { onVerifiedReceipt: async (receipt, genesis) => {
    callbacks++; await seedActivationPin(pins, genesis, receipt);
  } });
  const id = await controller.create(); await controller.reserve(id, 'LIC-pin-fixture'); await f.prepare(id);
  const saved = (await f.pending.get(id))!;
  f.alterReceipt((receipt) => ({ ...receipt, workspaceId: randomUUID() }));
  await assert.rejects(controller.activate(id, password), code('RECEIPT_MISMATCH'));
  assert.equal(callbacks, 0); assert.equal(await pins.pin(saved.status!.workspaceId), undefined);
  f.alterReceipt(undefined);
  const result = await controller.resume(id); assert.equal(result.state, 'completed');
  assert.equal(callbacks, 1);
  assert.deepEqual(await pins.pin(saved.status!.workspaceId), { genesisFingerprint: saved.draft!.genesisFingerprint,
    securityHead: saved.draft!.genesisFingerprint, securityVersion: '1' });
  await controller.resume(id); assert.equal(callbacks, 2);
});

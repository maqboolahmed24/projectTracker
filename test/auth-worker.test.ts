import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Worker as ThreadWorker } from 'node:worker_threads';
import * as opaque from '@serenity-kit/opaque';
import { AuthWorkerClient, type AuthWorkerEndpoint } from '../src/client/auth-worker-client.js';
import { AuthWorkerError, checkAuthWorkerCapabilities, type DeviceProofContext } from '../src/client/auth-worker.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';
import { base64urlEncode, generateSigningKeyPair, generateRecipientKeyPair, randomKey, verifyObject } from '../src/shared/crypto.js';
import { wrapDeviceBundle } from '../src/client/device-store.js';
import type { DeviceChallenge } from '../src/shared/auth.js';
import { IDBFactory } from 'fake-indexeddb';

const origin = 'https://ukda.example';
const password = 'Worker only password chosen for test 96813';
const code = (expected: AuthWorkerError['code']) => (error: unknown) => error instanceof AuthWorkerError && error.code === expected;
function workerClient(unsupported?: 'wasm' | 'crypto' | 'indexedDB') {
  let onPost: ((message: unknown) => void) | undefined;
  const posted: unknown[] = []; let created = 0;
  const client = new AuthWorkerClient({ origin, createWorker: () => {
    created++;
    const worker = new ThreadWorker(new URL('./auth-worker-fixture.js', import.meta.url), { workerData: { origin, unsupported } });
    const listeners = new Map<EventListener, (value: unknown) => void>();
    const endpoint: AuthWorkerEndpoint = {
      postMessage(message) { posted.push(message); worker.postMessage(message); onPost?.(message); },
      terminate() { void worker.terminate(); },
      addEventListener(type, listener) {
        const wrapped = (value: unknown) => listener(type === 'message' ? new MessageEvent('message', { data: value }) : new Event(type));
        listeners.set(listener, wrapped); worker.on(type, wrapped);
      },
      removeEventListener(type, listener) {
        const wrapped = listeners.get(listener); if (wrapped) worker.off(type, wrapped); listeners.delete(listener);
      },
    };
    return endpoint;
  } });
  return { client, posted, get created() { return created; }, onPost(callback: typeof onPost) { onPost = callback; } };
}
async function registration(client: AuthWorkerClient) {
  await opaque.ready;
  const server = new OpaqueService({ serverSetup: opaque.server.createSetup(), setupId: 'worker-test', serverIdentity: origin });
  const workspaceId = randomUUID(); const accountId = randomUUID();
  const started = await client.startRegistration(password);
  const response = await server.response(workspaceId, accountId, started.registrationRequest);
  const registered = await client.finishRegistration({ password, clientRegistrationState: started.clientRegistrationState,
    registrationResponse: response.registrationResponse, configuration: response.configuration });
  return { server, workspaceId, accountId, registered, configuration: response.configuration };
}
async function deviceFixture(workspaceId = randomUUID(), accountId = randomUUID(), exportKey = '') {
  const signing = await generateSigningKeyPair(); const recipient = await generateRecipientKeyPair();
  const context = { workspaceId, accountId, deviceId: randomUUID(), credentialGeneration: '1' };
  const source = exportKey || base64urlEncode(await randomKey());
  const wrapper = await wrapDeviceBundle(context, {
    signingPrivateKey: base64urlEncode(signing.privateKey), signingPublicKey: base64urlEncode(signing.publicKey),
    recipientPrivateKey: base64urlEncode(recipient.privateKey), recipientPublicKey: base64urlEncode(recipient.publicKey),
  }, source);
  const proofContext: DeviceProofContext = { origin, ...context, sessionId: randomUUID(), keyGeneration: '1', sessionGeneration: '1',
    dataGeneration: '1', securityVersion: '1', securityHead: 'a'.repeat(64), ownershipVersion: '1', custodyEpoch: '1',
    grantId: randomUUID(), grantGeneration: '1', signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
  signing.privateKey.fill(0); recipient.privateKey.fill(0);
  const challenge: DeviceChallenge = { ...proofContext, version: 1, purpose: 'ukda.device-challenge.v1', ceremonyId: randomUUID(),
    nonce: base64urlEncode(await randomKey()), issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() };
  return { context, wrapper, exportKey: source, proofContext, challenge, signingPublicKey: signing.publicKey,
    input: { context, wrapper, exportKey: source, proofContext } };
}

test('CP04: a dedicated worker completes real OPAQUE registration/login and keeps session key private', async (t) => {
  const f = workerClient(); t.after(() => f.client.close());
  await f.client.ready();
  const registered = await registration(f.client);
  const start = await f.client.startLogin(password);
  const response = await registered.server.startLogin(registered.workspaceId, registered.accountId, registered.registered.registrationRecord, start.startLoginRequest);
  const result = await f.client.finishLogin({ password, clientLoginState: start.clientLoginState, loginResponse: response.loginResponse, configuration: registered.configuration });
  assert.equal(result.exportKey, registered.registered.exportKey);
  assert.equal('sessionKey' in result, false);
  await registered.server.finishLogin(registered.workspaceId, registered.accountId, response.serverLoginState, result.finishLoginRequest);
  assert.equal(f.created, 1);
  const bad = await f.client.startLogin('This is a different test password 915');
  const badResponse = await registered.server.startLogin(registered.workspaceId, registered.accountId, registered.registered.registrationRecord, bad.startLoginRequest);
  await assert.rejects(f.client.finishLogin({ password: 'This is a different test password 915', clientLoginState: bad.clientLoginState,
    loginResponse: badResponse.loginResponse, configuration: registered.configuration }), code('AUTHENTICATION'));
});

test('CP04: worker device proof binds every authority field and logout discards the usable key cache', async (t) => {
  const f = workerClient(); t.after(() => f.client.close());
  const device = await deviceFixture();
  await f.client.unlockDevice(device.input);
  const proof = await f.client.deviceProof(device.challenge);
  assert.equal(await verifyObject(proof, device.signingPublicKey, 'ukda.device-challenge.v1'), true);
  for (const field of ['sessionId', 'workspaceId', 'accountId', 'deviceId', 'grantId'] as const) {
    await assert.rejects(f.client.deviceProof({ ...device.challenge, [field]: randomUUID() }), code('CONTEXT_MISMATCH'));
  }
  for (const field of ['keyGeneration', 'credentialGeneration', 'sessionGeneration', 'dataGeneration', 'securityVersion', 'ownershipVersion', 'custodyEpoch', 'grantGeneration'] as const) {
    await assert.rejects(f.client.deviceProof({ ...device.challenge, [field]: '2' }), code('CONTEXT_MISMATCH'));
  }
  await assert.rejects(f.client.deviceProof({ ...device.challenge, origin: 'https://other.example' }), code('CONTEXT_MISMATCH'));
  await assert.rejects(f.client.deviceProof({ ...device.challenge, securityHead: 'b'.repeat(64) }), code('CONTEXT_MISMATCH'));
  await assert.rejects(f.client.deviceProof({ ...device.challenge, issuedAt: new Date(Date.now() - 200_000).toISOString(), expiresAt: new Date(Date.now() - 100_000).toISOString() }), code('CHALLENGE_EXPIRED'));
  await assert.rejects(f.client.deviceProof({ ...device.challenge, issuedAt: new Date(Date.now() + 60_000).toISOString(), expiresAt: new Date(Date.now() + 120_000).toISOString() }), code('CHALLENGE_EXPIRED'));
  f.client.logout();
  await assert.rejects(f.client.deviceProof(device.challenge), code('LOCKED'));
  assert.equal(f.created, 2);
  await f.client.unlockDevice(device.input);
  assert.equal(await verifyObject(await f.client.deviceProof(device.challenge), device.signingPublicKey, 'ukda.device-challenge.v1'), true);
});

test('CP04: per-call cancellation terminates in-flight worker work and leaves a fresh worker locked', async (t) => {
  const f = workerClient(); t.after(() => f.client.close());
  const device = await deviceFixture(); await f.client.unlockDevice(device.input);
  const abort = new AbortController();
  f.onPost((message) => {
    if ((message as { method: string }).method === 'startLogin') { f.onPost(undefined); queueMicrotask(() => abort.abort()); }
  });
  const first = f.client.startLogin(password, { signal: abort.signal });
  const second = f.client.startLogin(password);
  await Promise.all([assert.rejects(first, code('CANCELLED')), assert.rejects(second, code('CANCELLED'))]);
  await assert.rejects(f.client.deviceProof(device.challenge), code('LOCKED'));
  const alreadyAborted = new AbortController(); alreadyAborted.abort();
  const before = f.posted.length;
  await assert.rejects(f.client.startLogin(password, { signal: alreadyAborted.signal }), code('CANCELLED'));
  assert.equal(f.posted.length, before);
  f.client.close(); await assert.rejects(f.client.startLogin(password), code('CLOSED'));
});

test('CP04: missing browser facilities stop before password processing with no downgraded fallback', async () => {
  for (const unsupported of ['wasm', 'crypto', 'indexedDB'] as const) {
    const f = workerClient(unsupported);
    try {
      await assert.rejects(f.client.startRegistration(password), code('UNSUPPORTED'));
      assert.equal(f.posted.some((message) => (message as { method: string }).method === 'startRegistration'), false);
    } finally { f.client.close(); }
  }
  await assert.rejects(checkAuthWorkerCapabilities({ origin, crypto: globalThis.crypto, webAssembly: globalThis.WebAssembly,
    indexedDB: { open() { throw new Error('Storage unavailable with private diagnostics'); } } as unknown as IDBFactory }), code('UNSUPPORTED'));
  await checkAuthWorkerCapabilities({ origin, crypto: globalThis.crypto, webAssembly: globalThis.WebAssembly, indexedDB: new IDBFactory() });
  assert.throws(() => new AuthWorkerClient({ origin: 'http://untrusted.example', createWorker: () => { throw new Error(); } }), code('UNSUPPORTED'));
});

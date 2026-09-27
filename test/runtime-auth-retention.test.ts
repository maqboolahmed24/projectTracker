import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { openClient, type ClientRuntime } from '../src/client/runtime.js';
import { AuthWorkerClient } from '../src/client/auth-worker-client.js';
import { IndexedDeviceStore, wrapDeviceBundle } from '../src/client/device-store.js';
import { IndexedPasswordChangeStore, preparePasswordChange } from '../src/client/password-change.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING } from '../src/client/opaque.js';
import { base64urlEncode, canonicalJson, generateRecipientKeyPair, generateSigningKeyPair, randomKey } from '../src/shared/crypto.js';
import type { AuthSessionSnapshot } from '../src/client/auth-controller.js';
import type { PasswordChangeBinding } from '../src/shared/password-change.js';

test('CP13: composed runtime logout and close retain exact security drafts; explicit Forget erases them', async (t) => {
  const origin = 'https://ukda.example', NativeURL = globalThis.URL;
  const originalIndexedDB = Object.getOwnPropertyDescriptor(globalThis, 'indexedDB');
  // This test exercises real runtime wiring, controllers and IndexedDB stores.
  // Authentication/Worker initialization are fixtures; no server or browser is used.
  class BrowserModuleURL extends NativeURL {
    constructor(input: string | URL, base?: string | URL) {
      super(input === './auth-worker.js' ? `${origin}/auth-worker.js` : input, base);
    }
  }
  globalThis.URL = BrowserModuleURL;
  Object.defineProperty(globalThis, 'indexedDB', { configurable: true, value: new IDBFactory() });
  t.mock.method(AuthWorkerClient.prototype, 'ready', async () => {});
  const reference = { workspaceId: randomUUID(), accountId: randomUUID(), deviceId: randomUUID() };
  const now = Date.now(), encodedKey = () => base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const session: AuthSessionSnapshot = { ...reference, sessionId: randomUUID(), accessLevel: 'device_approved',
    credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1', csrfToken: encodedKey(),
    authenticatedAt: new Date(now).toISOString(), idleExpiresAt: new Date(now + 1_800_000).toISOString(),
    absoluteExpiresAt: new Date(now + 43_200_000).toISOString(), securityHead: 'a'.repeat(64), securityVersion: '1' };
  let signedIn = true;
  t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL) => {
    const url = String(input);
    let status = 200, body: unknown;
    if (url === `${origin}/v1/auth/session`) {
      if (signedIn) body = session;
      else { status = 401; body = { error: { code: 'AUTH_REQUIRED' } }; }
    } else if (url === `${origin}/v1/auth/logout`) { signedIn = false; body = { loggedOut: true }; }
    else throw new Error(`Unexpected request: ${url}`);
    const response = new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: url });
    return response;
  });
  let runtime: ClientRuntime | undefined;
  let devices: IndexedDeviceStore | undefined, changes: IndexedPasswordChangeStore | undefined;
  try {
    runtime = await openClient({ origin });
    devices = await IndexedDeviceStore.open(); changes = await IndexedPasswordChangeStore.open();
    const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair(), wrapping = await randomKey();
    const bundle = { signingPrivateKey: base64urlEncode(signing.privateKey), signingPublicKey: base64urlEncode(signing.publicKey),
      recipientPrivateKey: base64urlEncode(recipient.privateKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
    const operationId = randomUUID(), activeId = randomUUID();
    const binding: PasswordChangeBinding = { version: 1, origin, ...reference, operationId, keyGeneration: '1',
      signingPublicKey: bundle.signingPublicKey, recipientPublicKey: bundle.recipientPublicKey,
      credentialGeneration: '1', nextCredentialGeneration: '2', sessionGeneration: '1', nextSessionGeneration: '2',
      dataGeneration: '1', securityVersion: '1', nextSecurityVersion: '2', securityHead: session.securityHead,
      ownershipVersion: '1', custodyEpoch: '1', issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 900_000).toISOString() };
    const active = await wrapDeviceBundle({ ...reference, credentialGeneration: '1' }, bundle, wrapping);
    const draft = await preparePasswordChange({ binding, registrationRecord: encodedKey(), exportKey: encodedKey(),
      configuration: { configId: OPAQUE_CONFIG_ID, setupId: 'runtime-retention-test', serverStaticPublicKey: encodedKey(),
        identifiers: { client: `ukda:${reference.workspaceId}:${reference.accountId}`, server: origin }, keyStretching: OPAQUE_KEY_STRETCHING } }, bundle);
    signing.privateKey.fill(0); recipient.privateKey.fill(0); wrapping.fill(0);
    const pending = { version: 1 as const, origin, reference: { workspaceId: reference.workspaceId, operationId, resumeToken: encodedKey() },
      status: { state: 'issued' as const, binding, resumeExpiresAt: new Date(now + 86_400_000).toISOString() }, draft };
    await changes.save(undefined, pending);
    await devices.stage(active, activeId); await devices.commit(activeId, { ...reference, credentialGeneration: '1', operationId: activeId });
    await devices.stage(draft.wrapper, operationId);
    await runtime.remembered.remember({ ...reference, displayName: 'Local test profile' });
    const assertDraftRetained = async (message: string) => {
      const retained = await changes!.get(operationId);
      assert.ok(retained, message);
      assert.equal(canonicalJson(retained), canonicalJson(pending), message);
    };

    await runtime.auth.refresh(); await runtime.auth.logout();
    await assertDraftRetained('Logout must preserve the exact resume capability and encrypted draft');
    assert.deepEqual(await devices.getStaged(operationId), draft.wrapper);
    assert.deepEqual(await devices.getActive(reference.workspaceId, reference.accountId, reference.deviceId), active);
    assert.equal((await runtime.remembered.list()).length, 1);

    signedIn = true; await runtime.auth.refresh(); await runtime.close(); runtime = undefined;
    await assertDraftRetained('Runtime close must leave the draft recoverable after reopening');
    runtime = await openClient({ origin }); signedIn = true; await runtime.auth.refresh();
    await runtime.auth.forget(reference);
    assert.equal(await changes.get(operationId), undefined, 'Explicit Forget still erases the saved security draft');
    assert.equal(await devices.getStaged(operationId), undefined);
    assert.equal(await devices.getActive(reference.workspaceId, reference.accountId, reference.deviceId), undefined);
    assert.equal((await runtime.remembered.list()).length, 0);
  } finally {
    await runtime?.close(); devices?.close(); changes?.close();
    globalThis.URL = NativeURL;
    if (originalIndexedDB) Object.defineProperty(globalThis, 'indexedDB', originalIndexedDB);
    else Reflect.deleteProperty(globalThis, 'indexedDB');
  }
});

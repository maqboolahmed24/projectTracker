import { expect, test } from '@playwright/test';
import type * as Client from '../../src/client/index.js';

declare global { interface Window { ukda: typeof Client } }

test('CP04: HTTPS browser crypto and native IndexedDB preserve only a locally encrypted device across reload', async ({ page, browser }, testInfo) => {
  await page.goto('/');
  await page.waitForFunction(() => !!window.ukda);
  const saved = await page.evaluate(async () => {
    const { cryptography: crypto, IndexedDeviceStore, wrapDeviceBundle, unwrapDeviceBundle } = window.ukda;
    await crypto.ready;
    const signing = await crypto.generateSigningKeyPair(), recipient = await crypto.generateRecipientKeyPair();
    const context = { workspaceId: globalThis.crypto.randomUUID(), accountId: globalThis.crypto.randomUUID(),
      deviceId: globalThis.crypto.randomUUID(), credentialGeneration: '1' };
    const bundle = { signingPublicKey: crypto.base64urlEncode(signing.publicKey), signingPrivateKey: crypto.base64urlEncode(signing.privateKey),
      recipientPublicKey: crypto.base64urlEncode(recipient.publicKey), recipientPrivateKey: crypto.base64urlEncode(recipient.privateKey) };
    const exportKey = crypto.base64urlEncode(await crypto.randomKey());
    const wrapper = await wrapDeviceBundle(context, bundle, exportKey);
    const store = await IndexedDeviceStore.open('browser-roundtrip');
    const operationId = globalThis.crypto.randomUUID();
    await store.stage(wrapper, operationId);
    await store.commit(operationId, { ...context, operationId });
    const restored = await store.getActive(context.workspaceId, context.accountId, context.deviceId);
    if (!restored || (await unwrapDeviceBundle(context, restored, exportKey)).signingPrivateKey !== bundle.signingPrivateKey) throw new Error('Device read-back failed');
    const persisted = JSON.stringify(restored);
    if ([bundle.signingPrivateKey, bundle.recipientPrivateKey, exportKey].some((secret) => persisted.includes(secret))) throw new Error('Plaintext private material persisted');
    store.close(); signing.privateKey.fill(0); recipient.privateKey.fill(0);
    return { context, exportKey, signingPublicKey: bundle.signingPublicKey, wrapperDigest: await crypto.digestObject(wrapper),
      capabilities: { secure: isSecureContext, wasm: typeof WebAssembly === 'object', subtle: !!globalThis.crypto.subtle, indexedDB: !!globalThis.indexedDB } };
  });
  expect(saved.capabilities).toEqual({ secure: true, wasm: true, subtle: true, indexedDB: true });
  await page.reload();
  await page.waitForFunction(() => !!window.ukda);
  const reopened = await page.evaluate(async (saved) => {
    const { IndexedDeviceStore, unwrapDeviceBundle, cryptography } = window.ukda;
    const store = await IndexedDeviceStore.open('browser-roundtrip');
    const wrapper = await store.getActive(saved.context.workspaceId, saved.context.accountId, saved.context.deviceId);
    if (!wrapper) throw new Error('Saved wrapper missing');
    const bundle = await unwrapDeviceBundle(saved.context, wrapper, saved.exportKey);
    const digest = await cryptography.digestObject(wrapper);
    const wrongContext = { ...saved.context, accountId: crypto.randomUUID() };
    let rejected = false;
    try { await unwrapDeviceBundle(wrongContext, wrapper, saved.exportKey); } catch { rejected = true; }
    await store.forget(saved.context.workspaceId, saved.context.accountId, saved.context.deviceId);
    const forgotten = await store.getActive(saved.context.workspaceId, saved.context.accountId, saved.context.deviceId);
    store.close();
    return { digest, signingPublicKey: bundle.signingPublicKey, rejected, forgotten: forgotten === undefined };
  }, saved);
  expect(reopened).toEqual({ digest: saved.wrapperDigest, signingPublicKey: saved.signingPublicKey, rejected: true, forgotten: true });
  await testInfo.attach('runtime', { body: JSON.stringify({ engine: testInfo.project.name, version: browser.version() }), contentType: 'application/json' });
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory, IDBObjectStore as FakeIDBObjectStore } from 'fake-indexeddb';
import sodium from 'libsodium-wrappers';
import {
  DeviceStoreError, IndexedDeviceStore, wrapDeviceBundle, unwrapDeviceBundle,
  type DeviceBundle, type DeviceContext, type DeviceWrapper,
} from '../src/client/device-store.js';
import {
  base64urlDecode, base64urlEncode, canonicalJson, deriveKey,
  generateRecipientKeyPair, generateSigningKeyPair, randomKey,
} from '../src/shared/crypto.js';

const context = (): DeviceContext => ({
  workspaceId: randomUUID(), accountId: randomUUID(), deviceId: randomUUID(), credentialGeneration: '1',
});
const confirmation = (value: DeviceContext, operationId: string) => ({ ...value, operationId });
const errorCode = (code: DeviceStoreError['code']) => (error: unknown) => error instanceof DeviceStoreError && error.code === code;
const active = (store: IndexedDeviceStore, value: DeviceContext) => store.getActive(value.workspaceId, value.accountId, value.deviceId);
function flip(value: string): string {
  const bytes = base64urlDecode(value);
  bytes[0] = bytes[0]! ^ 1;
  return base64urlEncode(bytes);
}
async function fixture() {
  const signing = await generateSigningKeyPair();
  const recipient = await generateRecipientKeyPair();
  const bundle: DeviceBundle = {
    signingPrivateKey: base64urlEncode(signing.privateKey), recipientPrivateKey: base64urlEncode(recipient.privateKey),
    signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey),
  };
  signing.privateKey.fill(0); recipient.privateKey.fill(0);
  const key = await randomKey();
  const identity = context();
  return { bundle, key, identity, wrapper: await wrapDeviceBundle(identity, bundle, key) };
}
async function rawDatabase(factory: IDBFactory, name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = factory.open(name);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function rawRecords(database: IDBDatabase, store: string): Promise<unknown[]> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(store, 'readonly');
    const request = transaction.objectStore(store).getAll();
    transaction.oncomplete = () => resolve(request.result);
    transaction.onabort = () => reject(transaction.error);
  });
}

test('CP03: device ciphertext authenticates exact context with fresh nonces and independent key pairs', async () => {
  const { identity, bundle, key, wrapper } = await fixture();
  const encodedKey = base64urlEncode(key);
  assert.deepEqual(await unwrapDeviceBundle(identity, wrapper, encodedKey), bundle);
  const second = await wrapDeviceBundle(identity, bundle, encodedKey);
  assert.notEqual(wrapper.nonce, second.nonce);
  assert.notEqual(wrapper.ciphertext, second.ciphertext);
  assert.deepEqual(wrapper.header, { ...identity, version: 1, purpose: 'ukda.local-device.v1',
    derivation: { salt: 'ukda.hkdf.v1', purpose: 'ukda.device-wrap.v1' } });
  const serialized = canonicalJson(wrapper);
  for (const secret of [bundle.signingPrivateKey, bundle.recipientPrivateKey, encodedKey]) assert.ok(!serialized.includes(secret));
  for (const field of ['workspaceId', 'accountId', 'deviceId'] as const) {
    await assert.rejects(unwrapDeviceBundle({ ...identity, [field]: randomUUID() }, wrapper, key), errorCode('INVALID_WRAPPER'));
  }
  await assert.rejects(unwrapDeviceBundle({ ...identity, credentialGeneration: '2' }, wrapper, key), errorCode('INVALID_WRAPPER'));
  await assert.rejects(unwrapDeviceBundle(identity, wrapper, await randomKey()), errorCode('UNLOCK_FAILED'));
  await assert.rejects(unwrapDeviceBundle(identity, { ...wrapper, nonce: flip(wrapper.nonce) }, key), errorCode('UNLOCK_FAILED'));
  await assert.rejects(unwrapDeviceBundle(identity, { ...wrapper, ciphertext: flip(wrapper.ciphertext) }, key), errorCode('UNLOCK_FAILED'));
  const relocated = { ...wrapper, header: { ...wrapper.header, deviceId: randomUUID() } };
  await assert.rejects(unwrapDeviceBundle({ ...identity, deviceId: relocated.header.deviceId }, relocated, key), errorCode('UNLOCK_FAILED'));
});

test('CP03: invalid or inconsistent bundle keys and noncanonical wrappers fail closed', async () => {
  const { identity, bundle, key, wrapper } = await fixture();
  for (const invalid of [
    { ...bundle, signingPrivateKey: base64urlEncode(new Uint8Array(32)) },
    { ...bundle, recipientPrivateKey: 'not+base64url' },
    { ...bundle, signingPublicKey: flip(bundle.signingPublicKey) },
    { ...bundle, signingPrivateKey: flip(bundle.signingPrivateKey) },
    { ...bundle, recipientPublicKey: flip(bundle.recipientPublicKey) },
    { ...bundle, unexpected: 'private' },
  ]) await assert.rejects(wrapDeviceBundle(identity, invalid, key), errorCode('INVALID_BUNDLE'));
  for (const invalid of [
    { ...wrapper, nonce: `${wrapper.nonce}=` },
    { ...wrapper, extra: 'unsupported' },
    { ...wrapper, header: { ...wrapper.header, version: 2 } },
    { ...wrapper, header: { ...wrapper.header, derivation: { ...wrapper.header.derivation, salt: 'different' } } },
  ]) await assert.rejects(unwrapDeviceBundle(identity, invalid as DeviceWrapper, key), errorCode('INVALID_WRAPPER'));
  for (const invalid of ['not+a+key', new Uint8Array(31), new Uint8Array(1025)]) {
    await assert.rejects(wrapDeviceBundle(identity, bundle, invalid), errorCode('UNLOCK_FAILED'));
  }
  // A ciphertext from a valid key still cannot introduce an unsupported plaintext schema.
  const wrappingKey = await deriveKey(key, { version: 1, purpose: 'ukda.device-wrap.v1', workspaceId: identity.workspaceId, accountId: identity.accountId });
  const unsupported = new TextEncoder().encode(canonicalJson({ ...bundle, extra: 'unsupported' }));
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(unsupported, canonicalJson(wrapper.header), null, base64urlDecode(wrapper.nonce), wrappingKey);
  wrappingKey.fill(0); unsupported.fill(0);
  await assert.rejects(unwrapDeviceBundle(identity, { ...wrapper, ciphertext: base64urlEncode(ciphertext) }, key), errorCode('UNLOCK_FAILED'));
});

test('CP03: wrapping snapshots caller inputs before asynchronous work without changing caller key bytes', async () => {
  const { identity, bundle, key } = await fixture();
  const expectedIdentity = { ...identity };
  const expectedBundle = { ...bundle };
  const originalKey = key.slice();
  const pending = wrapDeviceBundle(identity, bundle, key);
  identity.deviceId = randomUUID(); bundle.signingPrivateKey = 'mutated'; key.fill(0);
  assert.deepEqual(await unwrapDeviceBundle(expectedIdentity, await pending, originalKey), expectedBundle);
  const callerKey = originalKey.slice();
  await wrapDeviceBundle(expectedIdentity, expectedBundle, callerKey);
  assert.deepEqual(callerKey, originalKey);
  let getterCalls = 0;
  const accessor = { ...expectedBundle, get recipientPrivateKey() { getterCalls++; return expectedBundle.recipientPrivateKey; } };
  await assert.rejects(wrapDeviceBundle(expectedIdentity, accessor, originalKey), errorCode('INVALID_BUNDLE'));
  assert.equal(getterCalls, 0);
});

test('CP03: IndexedDB stores ciphertext only, keeps old generation active, and survives reopen', async () => {
  const { identity, bundle, key, wrapper } = await fixture();
  const factory = new IDBFactory(); const name = randomUUID();
  let store = await IndexedDeviceStore.open(name, factory);
  const firstId = randomUUID(); const secondId = randomUUID();
  const nextContext = { ...identity, credentialGeneration: '2' };
  const nextKey = await randomKey();
  const nextWrapper = await wrapDeviceBundle(nextContext, bundle, nextKey);
  try {
    assert.equal(await store.get(identity), undefined);
    assert.equal(await active(store, identity), undefined);
    assert.equal(await store.stage(wrapper, firstId), firstId);
    assert.equal(await store.stage(wrapper, firstId), firstId);
    assert.deepEqual(await store.getStaged(firstId), wrapper);
    assert.deepEqual(await unwrapDeviceBundle(identity, (await store.getStaged(firstId))!, key), bundle);
    assert.equal(await active(store, identity), undefined);
    await store.commit(firstId, confirmation(identity, firstId));
    await store.stage(nextWrapper, secondId);
    assert.deepEqual(await active(store, identity), wrapper);
    store.close();
    store = await IndexedDeviceStore.open(name, factory);
    assert.deepEqual(await active(store, identity), wrapper);
    assert.deepEqual(await store.get(nextContext), nextWrapper);
    assert.deepEqual(await unwrapDeviceBundle(nextContext, (await store.getStaged(secondId))!, nextKey), bundle);
    await store.commit(secondId, confirmation(nextContext, secondId));
    await store.commit(secondId, confirmation(nextContext, secondId));
    assert.deepEqual(await active(store, identity), nextWrapper);
    assert.deepEqual(await store.getStaged(firstId), wrapper);
    const raw = await rawDatabase(factory, name);
    try {
      const candidates = await rawRecords(raw, 'candidates');
      assert.equal(candidates.length, 2);
      assert.deepEqual(Object.keys(candidates[0] as object).sort(), ['candidateId', 'deviceKey', 'generationKey', 'wrapper']);
      const serialized = canonicalJson({ candidates, active: await rawRecords(raw, 'active') });
      for (const secret of [bundle.signingPrivateKey, bundle.recipientPrivateKey, base64urlEncode(key), base64urlEncode(nextKey)]) assert.ok(!serialized.includes(secret));
    } finally { raw.close(); }
  } finally { store.close(); }
});

test('CP03: receipt mismatches, duplicate operation reuse, and generation rollback cannot replace active keys', async () => {
  const { identity, bundle, key, wrapper } = await fixture();
  const store = await IndexedDeviceStore.open(randomUUID(), new IDBFactory());
  const firstId = randomUUID(); const secondId = randomUUID(); const competingId = randomUUID();
  const nextContext = { ...identity, credentialGeneration: '2' };
  const nextWrapper = await wrapDeviceBundle(nextContext, bundle, key);
  try {
    await store.stage(wrapper, firstId);
    await store.commit(firstId, confirmation(identity, firstId));
    await assert.rejects(store.stage(nextWrapper, firstId), errorCode('CONFLICT'));
    await store.stage(nextWrapper, secondId);
    await assert.rejects(store.commit(secondId, confirmation(nextContext, firstId)), errorCode('RECEIPT_MISMATCH'));
    for (const incorrect of [{ ...nextContext, accountId: randomUUID() }, { ...nextContext, workspaceId: randomUUID() }, { ...nextContext, deviceId: randomUUID() }, identity]) {
      await assert.rejects(store.commit(secondId, confirmation(incorrect, secondId)), errorCode('RECEIPT_MISMATCH'));
    }
    const unknown = randomUUID();
    await assert.rejects(store.commit(unknown, confirmation(nextContext, unknown)), errorCode('NOT_FOUND'));
    assert.deepEqual(await active(store, identity), wrapper);
    await store.commit(secondId, confirmation(nextContext, secondId));
    await assert.rejects(store.commit(firstId, confirmation(identity, firstId)), errorCode('CONFLICT'));
    await store.stage(await wrapDeviceBundle(nextContext, bundle, key), competingId);
    await assert.rejects(store.commit(competingId, confirmation(nextContext, competingId)), errorCode('CONFLICT'));
    assert.deepEqual(await active(store, identity), nextWrapper);
    assert.deepEqual(await store.getStaged(firstId), wrapper);
  } finally { store.close(); }
});

test('CP03: ambiguous drafts require a candidate ID and never choose an arbitrary credential', async () => {
  const { identity, bundle, key, wrapper } = await fixture();
  const store = await IndexedDeviceStore.open(randomUUID(), new IDBFactory());
  const firstId = randomUUID(); const secondId = randomUUID();
  const second = await wrapDeviceBundle(identity, bundle, key);
  try {
    await store.stage(wrapper, firstId); await store.stage(second, secondId);
    await assert.rejects(store.get(identity), errorCode('CONFLICT'));
    assert.deepEqual(await store.getStaged(firstId), wrapper);
    assert.deepEqual(await store.getStaged(secondId), second);
    await store.commit(secondId, confirmation(identity, secondId));
    assert.deepEqual(await store.get(identity), second);
    assert.deepEqual(await store.getStaged(firstId), wrapper);
  } finally { store.close(); }
});

test('CP03: transaction abort after active pointer write preserves the previous active generation', async () => {
  const { identity, bundle, key, wrapper } = await fixture();
  const store = await IndexedDeviceStore.open(randomUUID(), new IDBFactory());
  const firstId = randomUUID(); const secondId = randomUUID();
  const nextContext = { ...identity, credentialGeneration: '2' };
  const second = await wrapDeviceBundle(nextContext, bundle, key);
  const originalPut = FakeIDBObjectStore.prototype.put;
  try {
    await store.stage(wrapper, firstId); await store.commit(firstId, confirmation(identity, firstId));
    await store.stage(second, secondId);
    FakeIDBObjectStore.prototype.put = function (value: unknown, id?: IDBValidKey) {
      const request = originalPut.call(this, value, id);
      if (this.name === 'active') request.addEventListener('success', () => this.transaction.abort());
      return request;
    };
    await assert.rejects(store.commit(secondId, confirmation(nextContext, secondId)), errorCode('STORAGE_FAILED'));
    FakeIDBObjectStore.prototype.put = originalPut;
    assert.deepEqual(await active(store, identity), wrapper);
    assert.deepEqual(await store.getStaged(secondId), second);
    await store.commit(secondId, confirmation(nextContext, secondId));
    assert.deepEqual(await active(store, identity), second);
  } finally { FakeIDBObjectStore.prototype.put = originalPut; store.close(); }
});

test('CP03: forgetting is atomic and device scoped; closed and unavailable storage fail explicitly', async () => {
  const { identity, bundle, key, wrapper } = await fixture();
  const store = await IndexedDeviceStore.open(randomUUID(), new IDBFactory());
  const firstId = randomUUID(); const secondId = randomUUID();
  const otherContext = { ...identity, deviceId: randomUUID() };
  const other = await wrapDeviceBundle(otherContext, bundle, key);
  const originalDelete = FakeIDBObjectStore.prototype.delete;
  try {
    await store.stage(wrapper, firstId); await store.commit(firstId, confirmation(identity, firstId));
    await store.stage(other, secondId); await store.commit(secondId, confirmation(otherContext, secondId));
    FakeIDBObjectStore.prototype.delete = function (id: IDBValidKey | IDBKeyRange) {
      const request = originalDelete.call(this, id);
      if (this.name === 'active') request.addEventListener('success', () => this.transaction.abort());
      return request;
    };
    await assert.rejects(store.forget(identity.workspaceId, identity.accountId, identity.deviceId), errorCode('STORAGE_FAILED'));
    FakeIDBObjectStore.prototype.delete = originalDelete;
    assert.deepEqual(await active(store, identity), wrapper);
    assert.deepEqual(await store.getStaged(firstId), wrapper);
    await store.forget(identity.workspaceId, identity.accountId, identity.deviceId);
    await store.forget(identity.workspaceId, identity.accountId, identity.deviceId);
    assert.equal(await active(store, identity), undefined);
    assert.equal(await store.getStaged(firstId), undefined);
    assert.deepEqual(await active(store, otherContext), other);
    store.close();
    await assert.rejects(active(store, otherContext), errorCode('CLOSED'));
    await assert.rejects(store.stage(wrapper), errorCode('CLOSED'));
  } finally { FakeIDBObjectStore.prototype.delete = originalDelete; store.close(); }
  await assert.rejects(IndexedDeviceStore.open('unavailable', {} as IDBFactory), errorCode('UNAVAILABLE'));
});

test('CP03: corrupt active records cannot silently fall back to an uncommitted candidate', async () => {
  const { identity, bundle, key, wrapper } = await fixture();
  const factory = new IDBFactory(); const name = randomUUID();
  const store = await IndexedDeviceStore.open(name, factory);
  const firstId = randomUUID(); const secondId = randomUUID();
  try {
    await store.stage(wrapper, firstId); await store.commit(firstId, confirmation(identity, firstId));
    const draft = await wrapDeviceBundle(identity, bundle, key);
    await store.stage(draft, secondId);
    const raw = await rawDatabase(factory, name);
    try {
      await new Promise<void>((resolve, reject) => {
        const transaction = raw.transaction('candidates', 'readwrite');
        transaction.objectStore('candidates').delete(firstId);
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(transaction.error);
      });
    } finally { raw.close(); }
    await assert.rejects(active(store, identity), errorCode('CORRUPT_STORAGE'));
    await assert.rejects(store.get(identity), errorCode('CORRUPT_STORAGE'));
    assert.deepEqual(await store.getStaged(secondId), draft);
  } finally { store.close(); }
});

test('CP03: explicit draft cleanup cannot delete active or newer replacement candidates', async () => {
  const { identity, bundle, key, wrapper } = await fixture();
  const store = await IndexedDeviceStore.open(randomUUID(), new IDBFactory());
  const id = randomUUID(); const draftId = randomUUID();
  try {
    await store.stage(wrapper, id); await store.commit(id, confirmation(identity, id));
    await assert.rejects(store.discardUncommitted(id, identity.deviceId), errorCode('CONFLICT'));
    assert.deepEqual(await active(store, identity), wrapper);
    const otherIdentity = { ...identity, deviceId: randomUUID() };
    const other = await wrapDeviceBundle(otherIdentity, bundle, key);
    await store.stage(other, draftId);
    await store.discardUncommitted(draftId, identity.deviceId);
    assert.deepEqual(await store.getStaged(draftId), other);
    await store.discardUncommitted(draftId, otherIdentity.deviceId);
    await store.discardUncommitted(draftId, otherIdentity.deviceId);
    assert.equal(await store.getStaged(draftId), undefined);
    assert.deepEqual(await active(store, identity), wrapper);
  } finally { store.close(); }
});

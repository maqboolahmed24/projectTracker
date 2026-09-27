import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { RememberedProfiles, RememberedProfileError, type RememberedProfileInput } from '../src/client/remembered-profiles.js';
import { IndexedDeviceStore, wrapDeviceBundle } from '../src/client/device-store.js';
import { base64urlEncode, generateRecipientKeyPair, generateSigningKeyPair, randomKey } from '../src/shared/crypto.js';
import type { AvatarSelection } from '../src/shared/avatar.js';

const origin = 'https://ukda.example';
const profile = (): RememberedProfileInput => ({ workspaceId: randomUUID(), accountId: randomUUID(), deviceId: randomUUID(), displayName: 'Remembered Owner' });
const reference = ({ workspaceId, accountId, deviceId }: RememberedProfileInput) => ({ workspaceId, accountId, deviceId });
const code = (expected: RememberedProfileError['code']) => (error: unknown) => error instanceof RememberedProfileError && error.code === expected;

test('CP04: remembered cards persist only an explicit local name and scoped nonsecret references', async () => {
  const factory = new IDBFactory(); const name = randomUUID(); const input = profile();
  let cards = await RememberedProfiles.open(origin, name, factory);
  try {
    const saved = await cards.remember(input);
    assert.deepEqual(Object.keys(saved).sort(), ['accountId', 'deviceId', 'displayName', 'origin', 'version', 'workspaceId']);
    input.displayName = 'Mutated caller copy';
    assert.equal((await cards.list())[0]!.displayName, 'Remembered Owner');
    cards.close(); cards = await RememberedProfiles.open(origin, name, factory);
    assert.deepEqual(await cards.list(), [saved], 'Closing/logout must retain the local card');
    await cards.remember({ ...input, displayName: 'Updated remembered name' });
    assert.equal((await cards.list()).length, 1);
    for (const extra of [{ password: 'not allowed' }, { exportKey: 'not allowed' }, { phrase: 'not allowed' }, { securityHead: 'a'.repeat(64) }, { arbitrary: {} }]) {
      await assert.rejects(cards.remember({ ...input, ...extra }), code('INVALID_PROFILE'));
    }
    let getterCalls = 0;
    await assert.rejects(cards.remember({ ...input, get displayName() { getterCalls++; return 'Must not run'; } }), code('INVALID_PROFILE'));
    assert.equal(getterCalls, 0);
    await assert.rejects(cards.remember({ ...input, displayName: '   ' }), code('INVALID_PROFILE'));
  } finally { cards.close(); }
});

test('CP04: profile cards are origin/account/device scoped with no remote member lookup', async () => {
  const factory = new IDBFactory(); const name = randomUUID();
  const one = await RememberedProfiles.open(origin, name, factory);
  const other = await RememberedProfiles.open('https://other.example', name, factory);
  const first = profile(); const second = { ...first, deviceId: randomUUID(), displayName: 'Second remembered device' };
  try {
    await one.remember(first); await one.remember(second);
    await other.remember({ ...first, displayName: 'Another origin name' });
    assert.equal((await one.list()).length, 2);
    assert.equal((await other.list()).length, 1);
    await one.remove(reference(first)); await one.remove(reference(first));
    assert.deepEqual((await one.list()).map((value) => value.deviceId), [second.deviceId]);
    assert.equal((await other.list())[0]!.displayName, 'Another origin name');
    one.close(); await assert.rejects(one.list(), code('CLOSED'));
  } finally { one.close(); other.close(); }
  await assert.rejects(RememberedProfiles.open('http://untrusted.example', name, factory), code('INVALID_PROFILE'));
});

test('CP04: validated optional avatar survives reload and name-only writes without crossing card boundaries', async () => {
  const factory = new IDBFactory(), name = randomUUID(), input = profile();
  let cards = await RememberedProfiles.open(origin, name, factory);
  const elsewhere = await RememberedProfiles.open('https://other.example', name, factory);
  const selected: AvatarSelection = { shapeId: 'shape-07', colourId: 'coral' };
  try {
    await cards.remember(input);
    cards.close(); cards = await RememberedProfiles.open(origin, name, factory);
    assert.equal((await cards.list())[0]!.avatar, undefined, 'Legacy cards remain readable');
    const saved = await cards.remember({ ...input, avatar: selected });
    selected.colourId = 'blue'; saved.avatar!.shapeId = 'shape-20';
    cards.close(); cards = await RememberedProfiles.open(origin, name, factory);
    assert.deepEqual((await cards.list())[0]!.avatar, { shapeId: 'shape-07', colourId: 'coral' });
    await cards.remember({ ...input, displayName: 'Updated name' });
    assert.deepEqual((await cards.list())[0]!.avatar, { shapeId: 'shape-07', colourId: 'coral' }, 'A name-only ceremony does not reset the avatar');
    await cards.remember({ ...input, avatar: { shapeId: 'shape-12', colourId: 'violet' } });
    assert.deepEqual((await cards.list())[0]!.avatar, { shapeId: 'shape-12', colourId: 'violet' });
    const otherDevice = { ...input, deviceId: randomUUID() }, otherAccount = { ...input, accountId: randomUUID() }, otherWorkspace = { ...input, workspaceId: randomUUID() };
    for (const other of [otherDevice, otherAccount, otherWorkspace]) {
      assert.equal((await cards.remember(other)).avatar, undefined);
    }
    assert.equal((await elsewhere.remember(input)).avatar, undefined);
    await cards.remove(reference(input));
    assert.equal((await cards.list()).length, 3);
    assert.equal((await elsewhere.list()).length, 1);
  } finally { cards.close(); elsewhere.close(); }
});

test('CP04: remembered avatar accepts only plain catalogue IDs without executing nested accessors', async () => {
  const cards = await RememberedProfiles.open(origin, randomUUID(), new IDBFactory()), input = profile();
  let getterCalls = 0;
  const selection = { shapeId: 'shape-07', colourId: 'coral' };
  const nestedGetter = { get shapeId() { getterCalls++; return 'shape-07'; }, colourId: 'coral' };
  const extraGetter = { ...selection, get url() { getterCalls++; return 'https://example.test/avatar.svg'; } };
  const inherited = Object.assign(Object.create(selection) as object, { colourId: 'coral' });
  const hidden = Object.defineProperty({ ...selection }, 'hidden', { value: 'ignored', enumerable: false });
  const symbolic = { ...selection, [Symbol('avatar')]: 'ignored' };
  try {
    for (const avatar of [null, [], 'coral', {}, { shapeId: 'shape-21', colourId: 'coral' },
      { shapeId: 'shape-07', colourId: '#e97667' }, { ...selection, svg: '<svg/>' },
      { ...selection, url: 'https://example.test/avatar.svg' }, nestedGetter, extraGetter, inherited, hidden, symbolic]) {
      await assert.rejects(cards.remember({ ...input, avatar } as RememberedProfileInput), code('INVALID_PROFILE'));
    }
    assert.equal(getterCalls, 0);
    assert.deepEqual(await cards.list(), []);
  } finally { cards.close(); }
});

test('CP04: explicit Forget removes all scoped encrypted generations then its card, preserving other devices', async () => {
  const factory = new IDBFactory();
  const cards = await RememberedProfiles.open(origin, randomUUID(), factory);
  const devices = await IndexedDeviceStore.open(randomUUID(), factory);
  const first = { ...profile(), avatar: { shapeId: 'shape-07', colourId: 'coral' } satisfies AvatarSelection }; const other = { ...first, deviceId: randomUUID(), displayName: 'Other device' };
  const signing = await generateSigningKeyPair(); const recipient = await generateRecipientKeyPair(); const exportKey = await randomKey();
  const bundle = { signingPrivateKey: base64urlEncode(signing.privateKey), signingPublicKey: base64urlEncode(signing.publicKey),
    recipientPrivateKey: base64urlEncode(recipient.privateKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
  const context = { ...reference(first), credentialGeneration: '1' };
  const one = await wrapDeviceBundle(context, bundle, exportKey);
  const two = await wrapDeviceBundle({ ...context, credentialGeneration: '2' }, bundle, exportKey);
  const otherContext = { ...reference(other), credentialGeneration: '1' };
  const otherWrapper = await wrapDeviceBundle(otherContext, bundle, exportKey);
  const firstId = randomUUID(); const secondId = randomUUID(); const otherId = randomUUID();
  try {
    await cards.remember(first); await cards.remember(other);
    await devices.stage(one, firstId); await devices.commit(firstId, { ...context, operationId: firstId });
    await devices.stage(two, secondId);
    await devices.stage(otherWrapper, otherId); await devices.commit(otherId, { ...otherContext, operationId: otherId });
    await assert.rejects(cards.forget(reference(first), { async forget() { throw new Error('Synthetic storage failure'); } }));
    assert.equal((await cards.list()).length, 2, 'Never remove the card when encrypted cleanup failed');
    await cards.forget(reference(first), devices); await cards.forget(reference(first), devices);
    assert.equal(await devices.getStaged(firstId), undefined); assert.equal(await devices.getStaged(secondId), undefined);
    assert.equal(await devices.getActive(first.workspaceId, first.accountId, first.deviceId), undefined);
    assert.deepEqual(await devices.getActive(other.workspaceId, other.accountId, other.deviceId), otherWrapper);
    assert.deepEqual((await cards.list()).map((card) => card.deviceId), [other.deviceId]);
    assert.deepEqual((await cards.list())[0]!.avatar, other.avatar);
  } finally { cards.close(); devices.close(); signing.privateKey.fill(0); recipient.privateKey.fill(0); exportKey.fill(0); }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'libsodium-wrappers';
import { randomUUID, createHmac } from 'node:crypto';
import { parseJsonStrict } from '../src/shared/json.js';
import {
  ready, canonicalJson, base64urlEncode, base64urlDecode, digestObject, signObject, verifyObject,
  generateSigningKeyPair, generateRecipientKeyPair, randomKey, encryptContent, decryptContent,
  verifyContentEnvelope, sealRecipient, openRecipient, verifyRecipientEnvelope, deriveKey, HKDF_SALT,
  type ContentHeader, type RecipientHeader,
} from '../src/shared/crypto.js';

function header(): ContentHeader {
  return { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: randomUUID(), scope: 'project', scopeId: randomUUID(), recordId: randomUUID(), recordType: 'task', schema: 1, keyEpoch: '1', revision: '1', operationId: randomUUID(), accountId: randomUUID(), deviceId: randomUUID(), keyGeneration: '1', permissionVersion: '1', securityVersion: '1', securityHead: 'a'.repeat(64), dataGeneration: '1', action: 'task.create', approvalPolicyId: null, approvalPolicyRevision: null };
}
function flip(encoded: string): string {
  const bytes = base64urlDecode(encoded);
  bytes[0] = bytes[0]! ^ 1;
  return base64urlEncode(bytes);
}

test('CP03: canonical JSON matches JCS ordering, numeric and Unicode vectors', () => {
  // RFC 8785 number serialization plus lexical property sorting, without normalization.
  assert.equal(canonicalJson({ numbers: [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27], literals: [null, true, false] }), '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}');
  assert.equal(canonicalJson({ '2': 2, '10': 1, '1': 0 }), '{"1":0,"10":1,"2":2}');
  assert.equal(canonicalJson({ '\u20ac': 1, '\r': 2, '\ufb33': 3, '1': 4, '\ud83d\ude00': 5, '\u0080': 6, '\u00f6': 7 }), '{"\\r":2,"1":4,"\u0080":6,"ö":7,"€":1,"😀":5,"דּ":3}');
  assert.equal(canonicalJson([-0, 1e21, 1e-7, 1e-6]), '[0,1e+21,1e-7,0.000001]');
  assert.notEqual(canonicalJson('é'), canonicalJson('e\u0301'));
  assert.equal(canonicalJson({ nested: [{ z: '🎉', a: '\b\t\n\f\r"\\' }] }), '{"nested":[{"a":"\\b\\t\\n\\f\\r\\\"\\\\","z":"🎉"}]}');
  // Parsing, not reserialization, is where duplicate source properties must be rejected.
  assert.throws(() => parseJsonStrict('{"a":1,"\\u0061":2}'));
});

test('CP03: canonicalization rejects values that JavaScript JSON would silently change', () => {
  const cycle: { self?: unknown } = {}; cycle.self = cycle;
  const sparse = new Array(1);
  const accessor = Object.defineProperty({}, 'x', { enumerable: true, get() { throw new Error('must not execute'); } });
  for (const invalid of [undefined, NaN, Infinity, -Infinity, 1n, Symbol('x'), () => {}, new Date(), new Uint8Array(2), '\ud800', '\udc00', { '\ud800': 'x' }, { x: undefined }, [undefined], sparse, cycle, accessor, { [Symbol('x')]: 'hidden' }]) {
    assert.throws(() => canonicalJson(invalid));
  }
  const shared = { x: 1 };
  assert.equal(canonicalJson([shared, shared]), '[{"x":1},{"x":1}]');
  let deep: unknown = 0;
  for (let i = 0; i < 66; i++) deep = [deep];
  assert.throws(() => canonicalJson(deep));
});

test('CP03: base64url is canonical and canonical object digests are stable', async () => {
  assert.equal(base64urlEncode(Uint8Array.of(255)), '_w');
  assert.deepEqual(base64urlDecode('_w', 1), Uint8Array.of(255));
  assert.equal(base64urlEncode(new Uint8Array()), '');
  for (const bad of ['_x', '_w==', '/w', '+w', '_', ' _w', '_w\n']) assert.throws(() => base64urlDecode(bad));
  assert.throws(() => base64urlDecode('_w', 2));
  const large = new Uint8Array(100_000).fill(255);
  assert.deepEqual(base64urlDecode(base64urlEncode(large)), large);
  assert.equal(await digestObject({}), '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a');
  assert.equal(await digestObject({ b: 2, a: 1 }), await digestObject({ a: 1, b: 2 }));
});

test('CP03: signed objects bind purpose/body and fail closed on tampering or malformed keys', async () => {
  const signer = await generateSigningKeyPair();
  const stranger = await generateSigningKeyPair();
  const body = { purpose: 'ukda.genesis.v1', workspaceId: randomUUID(), revision: '1' };
  const signed = await signObject(body, signer.privateKey);
  assert.equal(await verifyObject(signed, signer.publicKey, body.purpose), true);
  assert.equal((await signObject({ revision: '1', workspaceId: body.workspaceId, purpose: body.purpose }, signer.privateKey)).signature, signed.signature);
  assert.equal(await verifyObject(signed, stranger.publicKey, body.purpose), false);
  assert.equal(await verifyObject(signed, signer.publicKey, 'ukda.grant.v1'), false);
  assert.equal(await verifyObject({ ...signed, body: { ...signed.body, revision: '2' } }, signer.publicKey, body.purpose), false);
  assert.equal(await verifyObject({ ...signed, signature: flip(signed.signature) }, signer.publicKey, body.purpose), false);
  assert.equal(await verifyObject({ ...signed, signature: '_' }, signer.publicKey, body.purpose), false);
  assert.equal(await verifyObject(signed, new Uint8Array(1), body.purpose), false);
  const unknownField = { ...signed, extra: true };
  assert.equal(await verifyObject(unknownField, signer.publicKey, body.purpose), false);
  let getterCalls = 0;
  const accessor = { get body() { getterCalls++; return signed.body; }, signature: signed.signature };
  assert.equal(await verifyObject(accessor, signer.publicKey, body.purpose), false);
  assert.equal(getterCalls, 0);
  body.revision = '2';
  assert.equal(signed.body.revision, '1');
  assert.equal(await verifyObject(signed, signer.publicKey, body.purpose), true);
});

test('CP03: content encryption signs ciphertext and authenticates exact record context', async () => {
  const signer = await generateSigningKeyPair(), stranger = await generateSigningKeyPair();
  const key = await randomKey(), context = header();
  const plaintext = { title: 'Private project 🎉', estimate: 3, nested: ['a', 'b'] };
  const encrypted = await encryptContent(context, plaintext, key, signer.privateKey);
  assert.equal(await verifyContentEnvelope(encrypted, signer.publicKey, context), true);
  assert.equal(canonicalJson(await decryptContent(encrypted, key, signer.publicKey, context)), canonicalJson(plaintext));
  assert.equal(canonicalJson(encrypted).includes(plaintext.title), false);
  assert.notEqual((await encryptContent(context, plaintext, key, signer.privateKey)).nonce, encrypted.nonce);
  for (const changed of [
    { ...encrypted, nonce: flip(encrypted.nonce) }, { ...encrypted, ciphertext: flip(encrypted.ciphertext) },
    { ...encrypted, signature: flip(encrypted.signature) }, { ...encrypted, header: { ...context, revision: '2' } },
  ]) await assert.rejects(decryptContent(changed, key, signer.publicKey, context));
  await assert.rejects(decryptContent(encrypted, await randomKey(), signer.publicKey, context));
  await assert.rejects(decryptContent(encrypted, key, stranger.publicKey, context));
  for (const change of [{ workspaceId: randomUUID() }, { scopeId: randomUUID() }, { recordId: randomUUID() }, { keyEpoch: '2' }, { dataGeneration: '2' }, { deviceId: randomUUID() }, { securityHead: 'b'.repeat(64) }]) {
    await assert.rejects(decryptContent(encrypted, key, signer.publicKey, { ...context, ...change }));
  }
  // Even a valid signer cannot relabel existing AEAD ciphertext with another revision.
  const { signature: _oldSignature, ...unsigned } = encrypted;
  const relabeled = { ...unsigned, header: { ...context, revision: '2' } };
  const forged = { ...relabeled, signature: base64urlEncode(sodium.crypto_sign_detached(canonicalJson(relabeled), signer.privateKey)) };
  assert.equal(await verifyContentEnvelope(forged, signer.publicKey, relabeled.header), true);
  await assert.rejects(decryptContent(forged, key, signer.publicKey, relabeled.header));
});

test('CP03: async verification and encryption retain invocation-time key identity', async () => {
  const signer = await generateSigningKeyPair(), stranger = await generateSigningKeyPair();
  const body = { purpose: 'ukda.genesis.v1', role: 'member' };
  const signed = await signObject(body, stranger.privateKey);
  const trustedPublicKey = signer.publicKey.slice();
  const pendingVerification = verifyObject(signed, trustedPublicKey, body.purpose);
  trustedPublicKey.set(stranger.publicKey);
  assert.equal(await pendingVerification, false);

  const changing = await signObject(body, signer.privateKey);
  const pendingMutation = verifyObject(changing, signer.publicKey, body.purpose);
  changing.body.role = 'owner';
  assert.equal(await pendingMutation, false);

  const key = await randomKey(), originalKey = key.slice(), context = header();
  const pendingEncryption = encryptContent(context, { private: 'value' }, key, signer.privateKey);
  key.fill(0);
  const encrypted = await pendingEncryption;
  assert.equal(canonicalJson(await decryptContent(encrypted, originalKey, signer.publicKey, context)), '{"private":"value"}');
});

test('CP03: signed recipient envelopes bind signer, key, recipient, scope and inner context', async () => {
  await ready;
  const signer = await generateSigningKeyPair(), stranger = await generateSigningKeyPair();
  const recipient = await generateRecipientKeyPair(), otherRecipient = await generateRecipientKeyPair();
  const context: RecipientHeader = { version: 1, purpose: 'ukda.recipient.v1', algorithm: 'X25519-SealedBox', workspaceId: randomUUID(), scope: 'project', scopeId: randomUUID(), keyEpoch: '1', recipientAccountId: randomUUID(), recipientId: randomUUID(), recipientKind: 'device', recipientKeyGeneration: '1', recipientPublicKey: base64urlEncode(recipient.publicKey), senderAccountId: randomUUID(), senderDeviceId: randomUUID(), senderKeyGeneration: '1', securityVersion: '0', securityHead: '0'.repeat(64), ceremonyId: randomUUID(), transcriptDigest: 'a'.repeat(64) };
  const payload = { key: base64urlEncode(await randomKey()) };
  const envelope = await sealRecipient(context, payload, signer.privateKey);
  assert.equal(await verifyRecipientEnvelope(envelope, signer.publicKey, context), true);
  assert.equal(canonicalJson(await openRecipient(envelope, recipient.privateKey, signer.publicKey, context)), canonicalJson(payload));
  assert.equal(canonicalJson(envelope).includes(payload.key), false);
  await assert.rejects(openRecipient(envelope, otherRecipient.privateKey, signer.publicKey, context));
  await assert.rejects(openRecipient(envelope, recipient.privateKey, stranger.publicKey, context));
  for (const changed of [
    { ...envelope, ciphertext: flip(envelope.ciphertext) }, { ...envelope, signature: flip(envelope.signature) },
    { ...envelope, header: { ...context, recipientId: randomUUID() } },
  ]) await assert.rejects(openRecipient(changed, recipient.privateKey, signer.publicKey, context));
  for (const change of [{ workspaceId: randomUUID() }, { scopeId: randomUUID() }, { recipientId: randomUUID() }, { recipientAccountId: randomUUID() }, { recipientKeyGeneration: '2' }, { recipientPublicKey: base64urlEncode(otherRecipient.publicKey) }, { keyEpoch: '2' }, { ceremonyId: randomUUID() }, { transcriptDigest: 'b'.repeat(64) }]) {
    await assert.rejects(openRecipient(envelope, recipient.privateKey, signer.publicKey, { ...context, ...change }));
  }
  // Outer authenticity alone is insufficient if the sealed payload carries another context.
  const unsigned = { header: context, ciphertext: base64urlEncode(sodium.crypto_box_seal(canonicalJson({ header: { ...context, keyEpoch: '2' }, payload }), recipient.publicKey)) };
  const mismatched = { ...unsigned, signature: base64urlEncode(sodium.crypto_sign_detached(canonicalJson(unsigned), signer.privateKey)) };
  assert.equal(await verifyRecipientEnvelope(mismatched, signer.publicKey, context), true);
  await assert.rejects(openRecipient(mismatched, recipient.privateKey, signer.publicKey, context));
});

test('CP03: HKDF is deterministic and separates purpose, account, workspace and version', async () => {
  const input = Uint8Array.from({ length: 32 }, (_, index) => index);
  const context = { version: 1 as const, purpose: 'ukda.recovery-proof.v1', workspaceId: '11111111-1111-4111-8111-111111111111', accountId: '22222222-2222-4222-8222-222222222222' };
  const derived = await deriveKey(input, context);
  // Independent RFC 5869 HMAC extract/expand implementation for a single 32-byte block.
  const extracted = createHmac('sha256', HKDF_SALT).update(input).digest();
  const expected = createHmac('sha256', extracted).update(canonicalJson(context)).update(Uint8Array.of(1)).digest();
  assert.equal(base64urlEncode(derived), expected.toString('base64url'));
  assert.deepEqual(await deriveKey(input, context), derived);
  for (const change of [{ purpose: 'ukda.recovery-recipient.v1' }, { workspaceId: randomUUID() }, { accountId: randomUUID() }]) assert.notDeepEqual(await deriveKey(input, { ...context, ...change }), derived);
  await assert.rejects(deriveKey(input, { ...context, version: 2 } as unknown as typeof context));
  await assert.rejects(deriveKey(new Uint8Array(16), context));
  assert.equal(input[31], 31, 'derivation must not overwrite caller entropy');
});

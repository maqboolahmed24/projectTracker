import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import sodium from 'libsodium-wrappers';
import { z } from 'zod';
import { contentHeader } from '../src/shared/contracts.js';
import { ContentSchemaError, assertSupportedContentSchemas, contentDataV2, decodeContentData, encodeContentData, requireContentSchema, transformContentData1To2 } from '../src/shared/content-schema.js';
import { base64urlDecode, canonicalJson, decryptContent, digestObject, encryptContent, generateSigningKeyPair, randomKey, verifyContentEnvelope, type ContentHeader } from '../src/shared/crypto.js';
import { cryptoVector } from './crypto-vector.js';

function header(schema: 1 | 2): ContentHeader {
  return { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: randomUUID(), scope: 'project', scopeId: randomUUID(),
    recordId: randomUUID(), recordType: 'task', schema, keyEpoch: '1', revision: '1', operationId: randomUUID(), accountId: randomUUID(), deviceId: randomUUID(),
    keyGeneration: '1', permissionVersion: '1', securityVersion: '1', securityHead: 'a'.repeat(64), dataGeneration: '1', action: 'task.create', approvalPolicyId: null, approvalPolicyRevision: null };
}

test('CP11 schema: the reviewed 1-to-2 transform changes representation without defaulting, normalizing or losing fields', () => {
  const data = { title: '  Preserve original spacing  ', nested: { optional: null, dates: ['2026-10-25'] } };
  const validator = z.strictObject({ title: z.string().trim(), nested: z.strictObject({ optional: z.null(), dates: z.array(z.string()) }), description: z.string().default('') });
  const before = canonicalJson(data), target = transformContentData1To2('task', data, value => validator.parse(value));
  assert.equal(target.format, 'ukda.content-data.v2'); assert.equal(target.recordType, 'task');
  assert.equal(canonicalJson(target.data), before); assert.equal(canonicalJson(data), before);
  assert.equal(Object.hasOwn(target.data as object, 'description'), false);
  assert.equal(canonicalJson(decodeContentData(2, 'task', target)), before);
  assert.equal(canonicalJson(encodeContentData(1, 'task', data)), before);
  assert.throws(() => transformContentData1To2('task', { ...data, unknown: true }, value => validator.parse(value)));
});

test('CP11 schema: genuine schema-2 ciphertext authenticates the typed wrapper and decodes through the existing API', async () => {
  const signer = await generateSigningKeyPair(), key = await randomKey(), context = header(2), data = { title: 'Private schema 2', description: '' };
  const envelope = await encryptContent(context, data, key, signer.privateKey);
  assert.equal(await verifyContentEnvelope(envelope, signer.publicKey, context), true);
  const raw = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, base64urlDecode(envelope.ciphertext), canonicalJson(context), base64urlDecode(envelope.nonce), key);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(raw)), { format: 'ukda.content-data.v2', recordType: 'task', data });
  assert.equal(canonicalJson(await decryptContent(envelope, key, signer.publicKey, context)), canonicalJson(data));
  await assert.rejects(decryptContent(envelope, key, signer.publicKey, { ...context, schema: 1 }));
  assert.equal(await verifyContentEnvelope({ ...envelope, header: { ...context, schema: 1 } }, signer.publicKey, { ...context, schema: 1 }), false);
});

test('CP11 schema: explicit historical decoder preserves the frozen schema-1 signature, ciphertext digest and plaintext', async () => {
  const vector = await cryptoVector(), envelope = vector.content.envelope, before = canonicalJson(envelope);
  assert.equal(envelope.header.schema, 1);
  assert.equal(await digestObject(envelope), vector.content.envelopeDigest);
  assert.equal(canonicalJson(await decryptContent(envelope, base64urlDecode(vector.contentKey), base64urlDecode(vector.signingPublicKey), envelope.header)), vector.content.plaintextCanonical);
  assert.equal(canonicalJson(envelope), before);
});

test('CP11 schema: unknown versions, mismatched types, omitted data and extra wrapper fields fail closed', () => {
  for (const version of [0, 3, '2', null, undefined]) assert.throws(() => requireContentSchema(version), error => error instanceof ContentSchemaError && error.code === 'UPDATE_REQUIRED');
  assert.throws(()=>assertSupportedContentSchemas({context:{records:[{envelope:{header:{purpose:'ukda.content.v1',schema:3}}}]}}),error=>error instanceof ContentSchemaError&&error.code==='UPDATE_REQUIRED');
  const context = header(2); assert.equal(contentHeader.safeParse({ ...context, schema: 3 }).success, false);
  for (const wrapper of [{ format: 'ukda.content-data.v3', recordType: 'task', data: {} }, { format: 'ukda.content-data.v2', recordType: 'project', data: {} },
    { format: 'ukda.content-data.v2', recordType: 'task' }, { format: 'ukda.content-data.v2', recordType: 'task', data: {}, extra: true }]) {
    assert.throws(() => decodeContentData(2, 'task', wrapper), error => error instanceof ContentSchemaError && error.code === 'INVALID_CONTENT_SCHEMA');
  }
  assert.equal(contentDataV2.safeParse({ format: 'ukda.content-data.v2', recordType: 'task', data: undefined }).success, false);
});

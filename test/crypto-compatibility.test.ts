import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { canonicalJson, base64urlDecode, base64urlEncode, digestObject, deriveKey,
  decryptContent, verifyContentEnvelope, openRecipient } from '../src/shared/crypto.js';
import { recoveryKeys } from '../src/client/recovery.js';
import { cryptoVector } from './crypto-vector.js';

test('CP05: installed security libraries match the exact manifest and integrity-locked releases', async () => {
  const manifest = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  const lock = JSON.parse(await readFile(new URL('../../package-lock.json', import.meta.url), 'utf8'));
  for (const [name, version] of Object.entries({ 'libsodium-wrappers': '0.8.4', '@serenity-kit/opaque': '1.1.0', '@scure/bip39': '2.4.0' })) {
    assert.equal(manifest.dependencies[name], version);
    assert.equal(lock.packages[`node_modules/${name}`].version, version);
    assert.match(lock.packages[`node_modules/${name}`].integrity, /^sha512-/);
    const installed = JSON.parse(await readFile(new URL(`../../node_modules/${name}/package.json`, import.meta.url), 'utf8'));
    assert.equal(installed.version, version);
  }
  assert.match(lock.packages['node_modules/libsodium'].integrity, /^sha512-/);
});

test('CP05: frozen UTF-8, large-counter, ciphertext and Ed25519 vectors interoperate with native crypto', async () => {
  const f = await cryptoVector(), envelope = f.content.envelope;
  assert.equal(canonicalJson(envelope.header), f.content.headerCanonical);
  assert.equal(envelope.header.revision, '9007199254740993');
  assert.equal(canonicalJson(f.content.plaintext), f.content.plaintextCanonical);
  const { signature, ...unsigned } = envelope;
  assert.equal(await digestObject(unsigned), f.content.unsignedDigest);
  assert.equal(createHash('sha256').update(canonicalJson(unsigned), 'utf8').digest('hex'), f.content.unsignedDigest);
  assert.equal(await digestObject(envelope), f.content.envelopeDigest);
  const publicKey = base64urlDecode(f.signingPublicKey);
  const nativeKey = createPublicKey({ format: 'der', type: 'spki',
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publicKey]) });
  assert.equal(verify(null, Buffer.from(canonicalJson(unsigned), 'utf8'), nativeKey, base64urlDecode(signature)), true);
  assert.equal(await verifyContentEnvelope(envelope, publicKey, envelope.header), true);
  assert.equal(canonicalJson(await decryptContent(envelope, base64urlDecode(f.contentKey), publicKey, envelope.header)), f.content.plaintextCanonical);
  const changed = { ...envelope.header, revision: '9007199254740994' };
  await assert.rejects(decryptContent(envelope, base64urlDecode(f.contentKey), publicKey, changed));
  assert.equal(canonicalJson(await openRecipient(f.recipient.envelope, base64urlDecode(f.recipient.privateKey), publicKey,
    f.recipient.envelope.header)), canonicalJson(f.recipient.payload));
});

test('CP05: frozen recovery phrase derivations match the independent native HKDF vector', async () => {
  const f = await cryptoVector();
  assert.equal(base64urlEncode(await deriveKey(base64urlDecode(f.derivation.input), f.derivation.context)), f.derivation.expected);
  const keys = await recoveryKeys(f.recovery.phrase, f.recovery.context);
  try {
    assert.equal(base64urlEncode(keys.signing.publicKey), f.recovery.signingPublicKey);
    assert.equal(base64urlEncode(keys.recipient.publicKey), f.recovery.recipientPublicKey);
    assert.notEqual(f.recovery.signingPublicKey, f.recovery.recipientPublicKey);
  } finally { keys.signing.privateKey.fill(0); keys.recipient.privateKey.fill(0); }
});

import { expect, test } from '@playwright/test';
import { cryptoVector } from '../crypto-vector.js';
import type * as Client from '../../src/client/index.js';

declare global { interface Window { ukda: typeof Client } }

test('CP05: frozen Node-generated content, recipient and recovery vectors verify in the HTTPS browser', async ({ page }) => {
  const fixture = await cryptoVector();
  await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
  const result = await page.evaluate(async (f) => {
    const c = window.ukda.cryptography;
    const publicKey = c.base64urlDecode(f.signingPublicKey), key = c.base64urlDecode(f.contentKey);
    const envelope = f.content.envelope;
    const content = await c.decryptContent(envelope, key, publicKey, envelope.header);
    const recipient = await c.openRecipient(f.recipient.envelope, c.base64urlDecode(f.recipient.privateKey), publicKey, f.recipient.envelope.header);
    const derived = await c.deriveKey(c.base64urlDecode(f.derivation.input), f.derivation.context);
    const recovery = await window.ukda.recovery.recoveryKeys(f.recovery.phrase, f.recovery.context);
    let wrongScopeRejected = false;
    try { await c.decryptContent(envelope, key, publicKey, { ...envelope.header, scopeId: crypto.randomUUID() }); }
    catch { wrongScopeRejected = true; }
    try {
      return { header: c.canonicalJson(envelope.header), content: c.canonicalJson(content), digest: await c.digestObject(envelope),
        recipient: c.canonicalJson(recipient), derived: c.base64urlEncode(derived), recoverySigning: c.base64urlEncode(recovery.signing.publicKey),
        recoveryRecipient: c.base64urlEncode(recovery.recipient.publicKey), wrongScopeRejected };
    } finally { key.fill(0); derived.fill(0); recovery.signing.privateKey.fill(0); recovery.recipient.privateKey.fill(0); }
  }, fixture);
  expect(result).toEqual({ header: fixture.content.headerCanonical, content: fixture.content.plaintextCanonical, digest: fixture.content.envelopeDigest,
    recipient: JSON.stringify(fixture.recipient.payload), derived: fixture.derivation.expected,
    recoverySigning: fixture.recovery.signingPublicKey, recoveryRecipient: fixture.recovery.recipientPublicKey, wrongScopeRejected: true });
});

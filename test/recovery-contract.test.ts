import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test, { type TestContext } from 'node:test';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING } from '../src/client/opaque.js';
import { base64urlEncode, canonicalJson, digestObject, generateRecipientKeyPair, generateSigningKeyPair, randomKey, sealRecipient, signObject } from '../src/shared/crypto.js';
import { generateResetCode, RESET_CODE_ALPHABET, resetCode, recoveryBinding, recoveryTranscript, recoveryConfirmationFor,
  recoveryRecipientHeader, recoveryPhraseChallenge, validateRecoveryPhraseProof, validateRecoveryDraft, validateRecoveryApproval,
  validateRecoveryPayload, validateRecoveryPublicApproval, validateRecoveryReceipt, RecoveryContractError, recoveryOperationReference,
  type RecoveryBinding, type RecoveryTranscript, type RecoveryDraft, type RecoveryPayload, type RecoveryReceipt } from '../src/shared/recovery.js';

const origin = 'https://ukda.example';
const invalid = (error: unknown) => error instanceof RecoveryContractError;
async function fixture(t: TestContext, mode: 'phrase' | 'owner_reset' = 'phrase', isOwner = true) {
  const keys = await Promise.all([generateSigningKeyPair(), generateSigningKeyPair(), generateSigningKeyPair(), generateSigningKeyPair(), generateRecipientKeyPair(), generateRecipientKeyPair()]);
  t.after(() => keys.forEach((key) => key.privateKey.fill(0)));
  const [oldRecovery, approver, replacement, nextRecovery, recipient, recoveryRecipient] = keys as [typeof keys[number], typeof keys[number], typeof keys[number], typeof keys[number], typeof keys[number], typeof keys[number]];
  const workspaceId = randomUUID(), accountId = randomUUID(), operationId = randomUUID();
  const currentRecovery = { id: randomUUID(), generation: '1', signingPublicKey: base64urlEncode(oldRecovery.publicKey), recipientPublicKey: base64urlEncode(await randomKey()) };
  const approverDevice = { id: randomUUID(), keyGeneration: '1', signingPublicKey: base64urlEncode(approver.publicKey), recipientPublicKey: base64urlEncode(await randomKey()) };
  const binding: RecoveryBinding = { version: 1, origin, workspaceId, accountId, operationId, isOwner,
    credentialGeneration: '2', nextCredentialGeneration: '3', sessionGeneration: '2', nextSessionGeneration: '3',
    resetGeneration: mode === 'phrase' ? '0' : '1', recoveryGeneration: isOwner ? '1' : '0', nextRecoveryGeneration: isOwner ? '2' : '0',
    deviceKeyGeneration: '1', nextDeviceKeyGeneration: '2', dataGeneration: '1', securityVersion: '2', nextSecurityVersion: '3',
    securityHead: 'a'.repeat(64), genesisFingerprint: 'b'.repeat(64), ownershipVersion: '1', custodyEpoch: '1',
    currentRecovery: isOwner ? currentRecovery : null,
    authorizer: mode === 'phrase' ? { kind: 'phrase', accountId, recovery: currentRecovery } :
      { kind: 'owner_reset', accountId: randomUUID(), device: approverDevice, credentialGeneration: '1', sessionGeneration: '1', resetId: operationId, resetGeneration: '1' },
    scopes: [{ scope: 'workspace', scopeId: workspaceId, mode: isOwner ? 'custody' : 'content', keyEpoch: '1', expiresAt: null,
      permissions: ['read_project'], sources: [{ grantId: randomUUID(), generation: '1', manifestId: randomUUID(), manifestDigest: 'c'.repeat(64) }] }],
    issuedAt: '2026-09-25T12:00:00.000Z', expiresAt: '2026-09-25T12:15:00.000Z' };
  const registrationRecord = base64urlEncode(await randomKey());
  const transcript: RecoveryTranscript = { version: 1, purpose: 'ukda.recovery-transcript.v1', binding,
    device: { id: randomUUID(), keyGeneration: '2', signingPublicKey: base64urlEncode(replacement.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) },
    recovery: isOwner ? { id: randomUUID(), generation: '2', signingPublicKey: base64urlEncode(nextRecovery.publicKey), recipientPublicKey: base64urlEncode(recoveryRecipient.publicKey) } : null,
    configuration: { configId: OPAQUE_CONFIG_ID, setupId: 'recovery-contract', keyStretching: OPAQUE_KEY_STRETCHING,
      serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } },
    registrationRecordHash: await digestObject(registrationRecord), wrapperHash: 'd'.repeat(64) };
  const transcriptDigest = await digestObject(transcript);
  const authorizingKey = mode === 'phrase' ? oldRecovery.privateKey : approver.privateKey;
  const sealingKey = mode === 'phrase' ? replacement.privateKey : approver.privateKey;
  const recipientConfirmation = await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'recipient'), replacement.privateKey);
  const authorizerConfirmation = await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'authorizer'), authorizingKey);
  const newRecoveryConfirmation = isOwner ? await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'new_recovery'), nextRecovery.privateKey) : null;
  const draft: RecoveryDraft = { transcript, registrationRecord, recipientConfirmation, newRecoveryConfirmation };
  const deliveries: RecoveryPayload['deliveries'] = [];
  for (const scope of binding.scopes) {
    for (const kind of (scope.mode === 'custody' ? ['device', 'recovery'] : ['device']) as ('device' | 'recovery')[]) {
      deliveries.push({ id: randomUUID(), envelope: await sealRecipient(recoveryRecipientHeader(transcript, transcriptDigest, scope, kind),
        { version: 1, fixture: 'encrypted recovery material', key: base64urlEncode(await randomKey()) }, sealingKey) });
    }
  }
  const descriptors = await Promise.all(deliveries.map(async (delivery) => ({ id: delivery.id, scope: delivery.envelope.header.scope,
    scopeId: delivery.envelope.header.scopeId, keyEpoch: delivery.envelope.header.keyEpoch, recipientKind: delivery.envelope.header.recipientKind,
    recipientId: delivery.envelope.header.recipientId, digest: await digestObject(delivery.envelope) })));
  const transition = await signObject({ version: 1 as const, purpose: 'ukda.account-recovery.v1' as const, transcript, transcriptDigest,
    recipientConfirmation, authorizerConfirmation, newRecoveryConfirmation, deliveries: descriptors,
    revokeAllDevices: true as const, revokeAllSessions: true as const }, authorizingKey);
  const payload: RecoveryPayload = { transition, registrationRecord, deliveries };
  const receipt: RecoveryReceipt = { version: 1, operationId, workspaceId, accountId, deviceId: transcript.device.id,
    credentialGeneration: '3', sessionGeneration: '3', keyGeneration: '2', recoveryGeneration: isOwner ? '2' : '0',
    dataGeneration: '1', securityVersion: '3', securityHead: await digestObject(transition), requestHash: await digestObject(payload),
    wrapperHash: transcript.wrapperHash, committedAt: '2026-09-25T12:04:00.000Z', transition };
  return { binding, transcript, draft, payload, receipt, authorizingKey, replacement, oldRecovery };
}

test('CP05: RESET codes contain twelve independent readable base32 symbols and reject other credential formats', () => {
  assert.equal(RESET_CODE_ALPHABET.length, 32); assert.equal(new Set(RESET_CODE_ALPHABET).size, 32);
  const generated = new Set(Array.from({ length: 256 }, generateResetCode));
  assert.equal(generated.size, 256);
  for (const code of generated) assert.equal(resetCode.safeParse(code).success, true);
  for (const code of ['RESET-ABCD-EFGH-JKLO', 'RESET-ABCD-EFGH-JKL1', 'RESET-ABCD-EFGH', 'reset-abcd-efgh-jklm',
    'JOIN-ABCD-EFGH-JKLM', 'LIC-ABCD-EFGH-JKLM', 'RESET-ABCD-EFGH-JKLM ']) assert.equal(resetCode.safeParse(code).success, false);
  assert.equal(recoveryOperationReference.safeParse({ workspaceId: randomUUID(), operationId: randomUUID(), resumeToken: 'secret' }).success, false);
});

test('CP05: phrase and Owner-assisted transitions verify distinct authorizers and device envelope senders', async (t) => {
  for (const mode of ['phrase', 'owner_reset'] as const) {
    const f = await fixture(t, mode);
    assert.equal(recoveryBinding.safeParse(f.binding).success, true);
    const checked = await validateRecoveryApproval({ transition: f.payload.transition, deliveries: f.payload.deliveries }, f.draft, f.binding, f.transcript.configuration);
    assert.equal(checked.requestHash, f.receipt.requestHash);
    const publicApproval = await validateRecoveryPublicApproval({ transition: f.payload.transition, deliveries: f.payload.deliveries }, f.binding, f.transcript.configuration);
    assert.equal(publicApproval.securityHead, f.receipt.securityHead);
    assert.equal(Object.hasOwn(publicApproval.approval, 'registrationRecord'), false);
    assert.equal(canonicalJson(await validateRecoveryReceipt(f.receipt, f.transcript)), canonicalJson(f.receipt));
    const sender = f.payload.deliveries[0]!.envelope.header.senderDeviceId;
    assert.equal(sender, mode === 'phrase' ? f.transcript.device.id : f.binding.authorizer.kind === 'owner_reset' && f.binding.authorizer.device.id);
    assert.notEqual(sender, f.binding.currentRecovery!.id);
    assert.equal(f.payload.transition.body.newRecoveryConfirmation?.body.kitVerified, true);
  }
});

test('CP05: ordinary-member reset cannot introduce phrase custody, change ownership, or trust a different expected scope', async (t) => {
  const f = await fixture(t, 'owner_reset', false);
  await validateRecoveryPayload(f.payload, f.binding, f.transcript.configuration);
  assert.equal(f.transcript.recovery, null); assert.equal(f.payload.deliveries.length, 1);
  assert.equal(recoveryBinding.safeParse({ ...f.binding, isOwner: true }).success, false);
  const custody = structuredClone(f.binding); custody.scopes[0]!.mode = 'custody';
  assert.equal(recoveryBinding.safeParse(custody).success, false);
  assert.equal(recoveryTranscript.safeParse({ ...f.transcript, recovery: { id: randomUUID(), generation: '1',
    signingPublicKey: base64urlEncode(await randomKey()), recipientPublicKey: base64urlEncode(await randomKey()) } }).success, false);
  const changed = structuredClone(f.binding); changed.scopes[0]!.permissions = ['read_project', 'manage_tasks'];
  await assert.rejects(validateRecoveryPayload(f.payload, changed, f.transcript.configuration), invalid);
});

test('CP05: initial credential draft does not count as the recipient full-fingerprint confirmation', async (t) => {
  const f = await fixture(t, 'owner_reset');
  const unconfirmed = { ...f.draft, recipientConfirmation: null };
  await validateRecoveryDraft(unconfirmed, f.binding, f.transcript.configuration);
  await assert.rejects(validateRecoveryApproval({ transition: f.payload.transition, deliveries: f.payload.deliveries }, unconfirmed, f.binding, f.transcript.configuration), invalid);
  const missingKit = { ...f.draft, newRecoveryConfirmation: null };
  await assert.rejects(validateRecoveryDraft(missingKit, f.binding, f.transcript.configuration), invalid);
});

test('CP05: malformed counters, expiry, reset identity and stale recovery generations fail without throwing', async (t) => {
  const f = await fixture(t, 'owner_reset');
  for (const field of ['credentialGeneration', 'nextCredentialGeneration', 'sessionGeneration', 'nextSessionGeneration', 'recoveryGeneration',
    'nextRecoveryGeneration', 'deviceKeyGeneration', 'nextDeviceKeyGeneration', 'securityVersion', 'nextSecurityVersion']) {
    for (const value of ['', 'invalid', '-1', '1.5', '9223372036854775808']) {
      assert.doesNotThrow(() => assert.equal(recoveryBinding.safeParse({ ...f.binding, [field]: value }).success, false));
    }
  }
  assert.equal(recoveryBinding.safeParse({ ...f.binding, nextCredentialGeneration: '4' }).success, false);
  assert.equal(recoveryBinding.safeParse({ ...f.binding, expiresAt: '2026-09-25T12:15:00.001Z' }).success, false);
  assert.equal(recoveryBinding.safeParse({ ...f.binding, operationId: randomUUID() }).success, false);
  const changed = structuredClone(f.binding); changed.securityHead = 'e'.repeat(64);
  await assert.rejects(validateRecoveryPayload(f.payload, changed, f.transcript.configuration), invalid);
});

test('CP05: phrase proof binds nonce, authority, origin and two-minute lifetime independently from final transition signing', async (t) => {
  const f = await fixture(t);
  const challenge = recoveryPhraseChallenge.parse({ version: 1, purpose: 'ukda.owner-phrase-challenge.v1', binding: f.binding,
    proofId: randomUUID(), nonce: base64urlEncode(await randomKey()), issuedAt: f.binding.issuedAt, expiresAt: '2026-09-25T12:02:00.000Z' });
  const proof = await signObject(challenge, f.oldRecovery.privateKey);
  assert.equal(canonicalJson(await validateRecoveryPhraseProof(proof, challenge)), canonicalJson(proof));
  assert.equal(recoveryPhraseChallenge.safeParse({ ...challenge, expiresAt: '2026-09-25T12:02:00.001Z' }).success, false);
  await assert.rejects(validateRecoveryPhraseProof(proof, { ...challenge, nonce: base64urlEncode(await randomKey()) }), invalid);
  await assert.rejects(validateRecoveryPhraseProof(await signObject(challenge, f.replacement.privateKey), challenge), invalid);
  const otherOrigin = structuredClone(challenge); otherOrigin.binding.origin = 'https://other.ukda.example';
  await assert.rejects(validateRecoveryPhraseProof(proof, otherOrigin), invalid);
});

test('CP05: signed recovery rejects altered credentials, confirmations, ciphertext, headers, descriptors and receipt context', async (t) => {
  const f = await fixture(t);
  for (const alter of [
    (value: RecoveryPayload) => { value.registrationRecord = base64urlEncode(new Uint8Array(32)); },
    (value: RecoveryPayload) => { value.transition.body.recipientConfirmation.body.role = 'authorizer'; },
    (value: RecoveryPayload) => { value.transition.body.transcript.wrapperHash = 'e'.repeat(64); },
    (value: RecoveryPayload) => { value.deliveries[0]!.envelope.header.recipientId = randomUUID(); },
    (value: RecoveryPayload) => { value.deliveries[0]!.envelope.header.securityHead = 'e'.repeat(64); },
    (value: RecoveryPayload) => { value.deliveries[0]!.envelope.ciphertext = base64urlEncode(new Uint8Array(64)); },
    (value: RecoveryPayload) => { value.deliveries[0]!.envelope.signature = base64urlEncode(new Uint8Array(64)); },
    (value: RecoveryPayload) => { value.deliveries[1]!.id = value.deliveries[0]!.id; },
  ]) {
    const altered = structuredClone(f.payload); alter(altered);
    await assert.rejects(validateRecoveryPayload(altered, f.binding, f.transcript.configuration), invalid);
  }
  // Even a valid authorizer signature cannot authorize a duplicate/missing required delivery.
  const body = structuredClone(f.payload.transition.body); body.deliveries[1] = structuredClone(body.deliveries[0]!);
  const transition = await signObject(body, f.authorizingKey);
  await assert.rejects(validateRecoveryPayload({ ...f.payload, transition }, f.binding, f.transcript.configuration), invalid);
  for (const altered of [{ ...f.receipt, credentialGeneration: '4' }, { ...f.receipt, deviceId: randomUUID() }, { ...f.receipt, securityHead: 'e'.repeat(64) }]) {
    await assert.rejects(validateRecoveryReceipt(altered, f.transcript), invalid);
  }
});

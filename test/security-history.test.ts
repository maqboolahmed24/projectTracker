import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { newOwnerPhrase, recoveryKeys } from '../src/client/recovery.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../src/client/opaque.js';
import { base64urlDecode, base64urlEncode, digestObject, generateRecipientKeyPair, generateSigningKeyPair, randomKey, signObject } from '../src/shared/crypto.js';
import { verifySecurityHistory, verifyRecoveryBindingAgainstHistory, SecurityHistoryError, type SecurityHistoryInput, type SecurityHistoryState } from '../src/shared/security-history.js';
import { recoveryConfirmationFor, type RecoveryBinding, type RecoveryTranscript } from '../src/shared/recovery.js';
import { pairingConfirmationFor, type PairingTranscript } from '../src/shared/pairing.js';
import type { EntitlementTransitionBody } from '../src/shared/entitlement.js';

const origin = 'https://ukda.example';
const fails = (code = 'INVALID_HISTORY') => (error: unknown) => error instanceof SecurityHistoryError && error.code === code;
async function fixture(t: { after(callback: () => void): void }) {
  const workspaceId = randomUUID(), accountId = randomUUID();
  const configuration: OpaquePublicConfiguration = { configId: OPAQUE_CONFIG_ID, setupId: 'history-test', keyStretching: OPAQUE_KEY_STRETCHING,
    serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } };
  const exportKey = base64urlEncode(await randomKey()), phrase = await newOwnerPhrase();
  const binding = { workspaceId, accountId, origin, operationId: randomUUID(), activationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1' };
  const positions = [1, 9, 19];
  const prepared = await prepareOwnerActivation({ binding, configuration, exportKey, registrationRecord: base64urlEncode(await randomKey()),
    phrase, challengePositions: positions, challengeAnswers: positions.map((index) => phrase.split(' ')[index]!), displayName: 'History fixture', workspaceName: 'History fixture' });
  const genesis = prepared.payload.genesis, genesisFingerprint = prepared.recoveryKit.genesisFingerprint;
  const bundle = await unwrapDeviceBundle({ workspaceId, accountId, deviceId: genesis.body.device.id, credentialGeneration: '1' }, prepared.deviceWrapper, exportKey);
  const signingKey = base64urlDecode(bundle.signingPrivateKey);
  const operational = await generateSigningKeyPair();
  t.after(() => { signingKey.fill(0); operational.privateKey.fill(0); });
  const input: SecurityHistoryInput = { workspaceId, origin, genesisFingerprint, genesis, transitions: [],
    expected: { securityHead: genesisFingerprint, securityVersion: '1' }, trustedServiceKeys: { operational: base64urlEncode(operational.publicKey) } };
  return { input, genesis, signingKey, operational, workspaceId, accountId, configuration, phrase };
}

test('CP04: history pins genesis, verifies its signature and refuses unknown transitions or caller mutation', async (t) => {
  const f = await fixture(t);
  const state = await verifySecurityHistory(f.input);
  assert.equal(state.profiles[f.accountId]?.owner, true);
  assert.equal(state.devices[f.genesis.body.device.id]?.active, true);
  await assert.rejects(verifySecurityHistory({ ...f.input, genesisFingerprint: 'a'.repeat(64) }), fails('TRUST_MISMATCH'));
  const altered = structuredClone(f.input); altered.genesis.signature = base64urlEncode(new Uint8Array(64));
  altered.genesisFingerprint = await digestObject(altered.genesis); altered.expected.securityHead = altered.genesisFingerprint;
  await assert.rejects(verifySecurityHistory(altered), fails());
  const unknown = await signObject({ purpose: 'ukda.unimplemented.v1', owner: randomUUID() }, f.signingKey);
  await assert.rejects(verifySecurityHistory({ ...f.input, transitions: [unknown] }), fails());
  const concurrent = structuredClone(f.input);
  const checking = verifySecurityHistory(concurrent);
  concurrent.genesis.body.device.signingPublicKey = base64urlEncode(await randomKey());
  assert.equal((await checking).securityHead, f.input.genesisFingerprint);
});

test('CP04: entitlement history requires trusted operational keys and preserves the pinned head and customer authority', async (t) => {
  const f = await fixture(t);
  const body: EntitlementTransitionBody = { version: 1, purpose: 'ukda.entitlement-transition.v1', action: 'revoke',
    operationId: randomUUID(), licenceId: randomUUID(), operatorId: randomUUID(), workspaceId: f.workspaceId,
    previousHead: f.input.genesisFingerprint, securityVersion: '2', dataGeneration: '1',
    before: { entitlementState: 'activated', licenceState: 'active' }, after: { entitlementState: 'revoked', licenceState: 'restricted' },
    changedAt: new Date().toISOString(), serviceKeyId: 'operational', servicePublicKey: base64urlEncode(f.operational.publicKey) };
  const transition = await signObject(body, f.operational.privateKey), head = await digestObject(transition);
  const current = { ...f.input, transitions: [transition], expected: { securityHead: head, securityVersion: '2' } };
  const state = await verifySecurityHistory(current);
  assert.equal(state.licenceState, 'restricted');
  assert.equal(state.profiles[f.accountId]?.owner, true);
  assert.equal(state.devices[f.genesis.body.device.id]?.active, true);
  await assert.rejects(verifySecurityHistory({ ...current, trustedServiceKeys: {} }), fails());
  await assert.rejects(verifySecurityHistory({ ...current, trustedServiceKeys: { operational: base64urlEncode(await randomKey()) } }), fails());
  const escalation = await signObject({ ...body, owner: randomUUID() }, f.operational.privateKey);
  await assert.rejects(verifySecurityHistory({ ...current, transitions: [escalation], expected: { securityVersion: '2', securityHead: await digestObject(escalation) } }), fails());
  const pin = { genesisFingerprint: f.input.genesisFingerprint, securityHead: head, securityVersion: '2' };
  await assert.rejects(verifySecurityHistory({ ...f.input, pin }), fails('ROLLBACK'));
  await assert.rejects(verifySecurityHistory({ ...current, pin: { ...pin, securityHead: 'b'.repeat(64) } }), fails('ROLLBACK'));
  assert.equal((await verifySecurityHistory({ ...current, pin })).securityHead, head);
});

test('CP05: Owner recovery authority is derived from signed genesis and its exact envelope manifest', async (t) => {
  const f = await fixture(t), state = await verifySecurityHistory(f.input);
  assert.equal(state.profiles[f.accountId]?.recoveryGeneration, '1');
  assert.deepEqual(state.recoveryAuthorities[`${f.accountId}:1`], {
    ...f.genesis.body.recovery, accountId: f.accountId, generation: '1', active: true, custodyEpoch: '1',
    custodyEnvelope: { id: f.genesis.body.recoveryEnvelopeId,
      digest: f.genesis.body.manifest.find((entry) => entry.id === f.genesis.body.recoveryEnvelopeId)!.digest },
  });
  // Even a re-signed malformed root cannot establish an unbound recovery envelope.
  const malformed = structuredClone(f.genesis.body);
  malformed.manifest.find((entry) => entry.id === malformed.recoveryEnvelopeId)!.kind = 'encrypted_profile';
  const genesis = await signObject(malformed, f.signingKey), fingerprint = await digestObject(genesis);
  await assert.rejects(verifySecurityHistory({ ...f.input, genesis, genesisFingerprint: fingerprint,
    expected: { securityHead: fingerprint, securityVersion: '1' } }), fails());
});

test('CP05: recovery history retires old devices and phrase authority while retaining their public verification keys', async (t) => {
  const f = await fixture(t), initial = await verifySecurityHistory(f.input);
  const old = await recoveryKeys(f.phrase, { workspaceId: f.workspaceId, accountId: f.accountId });
  t.after(() => { old.signing.privateKey.fill(0); old.recipient.privateKey.fill(0); });
  async function prepare(state: SecurityHistoryState, authorizerPrivateKey: Uint8Array) {
    const profile = state.profiles[f.accountId]!, current = state.recoveryAuthorities[`${f.accountId}:${profile.recoveryGeneration}`]!;
    const deviceSigning = await generateSigningKeyPair(), deviceRecipient = await generateRecipientKeyPair();
    const phraseSigning = await generateSigningKeyPair(), phraseRecipient = await generateRecipientKeyPair();
    t.after(() => { for (const key of [deviceSigning, deviceRecipient, phraseSigning, phraseRecipient]) key.privateKey.fill(0); });
    const authority = { id: current.id, generation: current.generation, signingPublicKey: current.signingPublicKey, recipientPublicKey: current.recipientPublicKey };
    const maxDevice = Object.values(state.devices).filter((device) => device.accountId === f.accountId)
      .reduce((maximum, device) => BigInt(device.keyGeneration) > maximum ? BigInt(device.keyGeneration) : maximum, 0n);
    const binding: RecoveryBinding = { version: 1, origin, workspaceId: f.workspaceId, accountId: f.accountId, operationId: randomUUID(),
      isOwner: true, credentialGeneration: profile.credentialGeneration, nextCredentialGeneration: String(BigInt(profile.credentialGeneration) + 1n),
      sessionGeneration: profile.sessionGeneration, nextSessionGeneration: String(BigInt(profile.sessionGeneration) + 1n), resetGeneration: '0',
      recoveryGeneration: current.generation, nextRecoveryGeneration: String(BigInt(current.generation) + 1n), deviceKeyGeneration: String(maxDevice), nextDeviceKeyGeneration: String(maxDevice + 1n),
      dataGeneration: state.dataGeneration, securityVersion: state.securityVersion, nextSecurityVersion: String(BigInt(state.securityVersion) + 1n),
      securityHead: state.securityHead, genesisFingerprint: state.genesisFingerprint, ownershipVersion: state.ownershipVersion, custodyEpoch: state.custodyEpoch,
      currentRecovery: authority, authorizer: { kind: 'phrase', accountId: f.accountId, recovery: authority },
      scopes: profile.scopes.map((scope) => ({ ...scope, sources: scope.manifests.map((manifest) => ({ grantId: randomUUID(), generation: '1', manifestId: manifest.id, manifestDigest: manifest.digest })) }))
        .map(({ manifests: _manifests, ...scope }) => scope),
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 900_000).toISOString() };
    // Use a single fixed issue instant so the exact 15-minute schema limit is deterministic.
    binding.expiresAt = new Date(Date.parse(binding.issuedAt) + 900_000).toISOString();
    const transcript: RecoveryTranscript = { version: 1, purpose: 'ukda.recovery-transcript.v1', binding,
      device: { id: randomUUID(), keyGeneration: binding.nextDeviceKeyGeneration, signingPublicKey: base64urlEncode(deviceSigning.publicKey), recipientPublicKey: base64urlEncode(deviceRecipient.publicKey) },
      recovery: { id: randomUUID(), generation: binding.nextRecoveryGeneration, signingPublicKey: base64urlEncode(phraseSigning.publicKey), recipientPublicKey: base64urlEncode(phraseRecipient.publicKey) },
      configuration: f.configuration, registrationRecordHash: 'c'.repeat(64), wrapperHash: 'd'.repeat(64) };
    const transcriptDigest = await digestObject(transcript);
    const transition = await signObject({ version: 1 as const, purpose: 'ukda.account-recovery.v1' as const, transcript, transcriptDigest,
      recipientConfirmation: await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'recipient'), deviceSigning.privateKey),
      authorizerConfirmation: await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'authorizer'), authorizerPrivateKey),
      newRecoveryConfirmation: await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'new_recovery'), phraseSigning.privateKey),
      deliveries: [
        { id: randomUUID(), scope: 'workspace' as const, scopeId: f.workspaceId, keyEpoch: '1', recipientKind: 'device' as const, recipientId: transcript.device.id, digest: 'e'.repeat(64) },
        { id: randomUUID(), scope: 'workspace' as const, scopeId: f.workspaceId, keyEpoch: '1', recipientKind: 'recovery' as const, recipientId: transcript.recovery!.id, digest: 'f'.repeat(64) },
      ], revokeAllDevices: true as const, revokeAllSessions: true as const }, authorizerPrivateKey);
    return { transition, binding, transcript, phraseSigning };
  }
  const first = await prepare(initial, old.signing.privateKey);
  verifyRecoveryBindingAgainstHistory(first.binding, initial);
  const head = await digestObject(first.transition);
  const history = { ...f.input, transitions: [first.transition], expected: { securityHead: head, securityVersion: '2' } };
  const recovered = await verifySecurityHistory(history);
  assert.equal(recovered.profiles[f.accountId]?.owner, true);
  assert.equal(recovered.profiles[f.accountId]?.credentialGeneration, '2');
  assert.equal(recovered.devices[f.genesis.body.device.id]?.active, false);
  assert.equal(recovered.devices[f.genesis.body.device.id]?.signingPublicKey, f.genesis.body.device.signingPublicKey);
  assert.equal(recovered.devices[first.transcript.device.id]?.active, true);
  assert.equal(recovered.recoveryAuthorities[`${f.accountId}:1`]?.active, false);
  assert.equal(recovered.recoveryAuthorities[`${f.accountId}:2`]?.active, true);
  assert.throws(() => verifyRecoveryBindingAgainstHistory(first.binding, recovered), fails());
  const altered = structuredClone(first.binding); altered.scopes[0]!.permissions = ['read_project'];
  assert.throws(() => verifyRecoveryBindingAgainstHistory(altered, initial), fails());
  const retired = await prepare(recovered, old.signing.privateKey);
  await assert.rejects(verifySecurityHistory({ ...history, transitions: [first.transition, retired.transition],
    expected: { securityHead: await digestObject(retired.transition), securityVersion: '3' } }), fails());
  const replacement = await prepare(recovered, first.phraseSigning.privateKey);
  assert.equal((await verifySecurityHistory({ ...history, transitions: [first.transition, replacement.transition],
    expected: { securityHead: await digestObject(replacement.transition), securityVersion: '3' } })).profiles[f.accountId]?.recoveryGeneration, '3');
});

test('CP04: signed pairing and password change derive device authority, preserve history and reject retired signers', async (t) => {
  const f = await fixture(t);
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  t.after(() => { signing.privateKey.fill(0); recipient.privateKey.fill(0); });
  const custody = f.genesis.body.manifest.find((entry) => entry.id === f.genesis.body.custodyId)!;
  const operationId = randomUUID(), deviceId = randomUUID();
  const transcript: PairingTranscript = { version: 1, purpose: 'ukda.device-pair-transcript.v1', origin,
    workspaceId: f.workspaceId, operationId, ceremonyId: operationId, accountId: f.accountId,
    device: { id: deviceId, keyGeneration: '1', signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) },
    localBundleDigest: 'c'.repeat(64), approverAccountId: f.accountId, approverDevice: { ...f.genesis.body.device, keyGeneration: '1' },
    approverIsOwner: true, credentialGeneration: '1', sessionGeneration: '1', approverCredentialGeneration: '1', approverSessionGeneration: '1',
    dataGeneration: '1', ownershipVersion: '1', custodyEpoch: '1', genesisFingerprint: f.input.genesisFingerprint,
    securityHead: f.input.genesisFingerprint, securityVersion: '1',
    scopes: [{ scope: 'workspace', scopeId: f.workspaceId, mode: 'custody', keyEpoch: '1', expiresAt: null, permissions: [...f.genesis.body.ownerPermissions],
      sources: [{ grantId: randomUUID(), generation: '1', manifestId: custody.id, manifestDigest: custody.digest }] }],
    issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() };
  const approve = async (value: PairingTranscript) => {
    const transcriptDigest = await digestObject(value);
    return signObject({ version: 1 as const, purpose: 'ukda.device-pair-grant.v1' as const, operationId: value.operationId,
      workspaceId: f.workspaceId, grantId: value.operationId, securityVersion: String(BigInt(value.securityVersion) + 1n), previousHead: value.securityHead,
      transcript: value, transcriptDigest,
      recipientConfirmation: await signObject(pairingConfirmationFor(value, transcriptDigest, 'recipient'), signing.privateKey),
      approverConfirmation: await signObject(pairingConfirmationFor(value, transcriptDigest, 'approver'), f.signingKey),
      deliveries: value.scopes.map((scope) => ({ id: randomUUID(), scope: scope.scope, scopeId: scope.scopeId, digest: 'd'.repeat(64) })) }, f.signingKey);
  };
  const paired = await approve(transcript), pairedHead = await digestObject(paired);
  const pairedInput = { ...f.input, transitions: [paired], expected: { securityHead: pairedHead, securityVersion: '2' } };
  const state = await verifySecurityHistory(pairedInput);
  assert.equal(state.devices[deviceId]?.active, true);
  const change = await signObject({ version: 1 as const, purpose: 'ukda.password-change.v1' as const,
    binding: { version: 1 as const, origin, workspaceId: f.workspaceId, accountId: f.accountId, operationId: randomUUID(), deviceId,
      keyGeneration: '1', credentialGeneration: '1', nextCredentialGeneration: '2', sessionGeneration: '1', nextSessionGeneration: '2',
      dataGeneration: '1', securityVersion: '2', nextSecurityVersion: '3', securityHead: pairedHead, ownershipVersion: '1', custodyEpoch: '1',
      signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey),
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() },
    registrationRecordHash: '1'.repeat(64), configurationHash: await digestObject(f.configuration), wrapperHash: '2'.repeat(64),
    revokeOtherDevices: true as const, revokeAllSessions: true as const }, signing.privateKey);
  const changedHead = await digestObject(change);
  const changedInput = { ...f.input, transitions: [paired, change], expected: { securityHead: changedHead, securityVersion: '3' } };
  const changed = await verifySecurityHistory(changedInput);
  assert.equal(changed.profiles[f.accountId]?.credentialGeneration, '2');
  assert.equal(changed.devices[deviceId]?.active, true);
  assert.equal(changed.devices[f.genesis.body.device.id]?.active, false);
  assert.equal(changed.devices[f.genesis.body.device.id]?.signingPublicKey, f.genesis.body.device.signingPublicKey);
  const freshOperation = randomUUID();
  const forged = await approve({ ...transcript, operationId: freshOperation, ceremonyId: freshOperation,
    device: { ...transcript.device, id: randomUUID() }, credentialGeneration: '2', sessionGeneration: '2',
    approverCredentialGeneration: '2', approverSessionGeneration: '2', securityHead: changedHead, securityVersion: '3' });
  await assert.rejects(verifySecurityHistory({ ...changedInput, transitions: [paired, change, forged],
    expected: { securityHead: await digestObject(forged), securityVersion: '4' } }), fails());
  const expanded = await approve({ ...transcript, scopes: [...transcript.scopes, { ...transcript.scopes[0]!, scope: 'project', scopeId: randomUUID(), mode: 'content' }] });
  await assert.rejects(verifySecurityHistory({ ...pairedInput, transitions: [expanded], expected: { securityHead: await digestObject(expanded), securityVersion: '2' } }), fails());
  const replacedManifest = structuredClone(transcript); replacedManifest.scopes[0]!.sources[0]!.manifestDigest = 'e'.repeat(64);
  const replaced = await approve(replacedManifest);
  await assert.rejects(verifySecurityHistory({ ...pairedInput, transitions: [replaced], expected: { securityHead: await digestObject(replaced), securityVersion: '2' } }), fails());
  await assert.rejects(verifySecurityHistory({ ...changedInput, transitions: [change, paired] }), fails());
});

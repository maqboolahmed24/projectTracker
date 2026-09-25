import { capabilities } from '../shared/contracts.js';
import { activationBinding, activationManifest, initialContentHeader, initialRecipientHeader, validateActivationPayload, type ActivationBinding, type ActivationPayload, type ActivationTranscript } from '../shared/activation.js';
import { base64urlEncode, digestObject, encryptContent, generateRecipientKeyPair, generateSigningKeyPair, randomKey, sealRecipient, signObject } from '../shared/crypto.js';
import { startRegistration, type OpaquePublicConfiguration } from './opaque.js';
import { recoveryKeys, verifyRecoveryWords } from './recovery.js';
import { unwrapDeviceBundle, wrapDeviceBundle } from './device-store.js';

export async function beginActivationPassword(password: string, confirmation: string) {
  if (password !== confirmation) throw new Error('Passwords do not match');
  return startRegistration(password);
}

/** Runs locally. Only `payload` is uploaded; `deviceWrapper` stays in IndexedDB and the kit belongs to its Owner. */
export async function prepareOwnerActivation(input: {
  binding: ActivationBinding; configuration: OpaquePublicConfiguration;
  registrationRecord: string; exportKey: string;
  phrase: string; challengePositions: readonly number[]; challengeAnswers: readonly string[];
  displayName: string; workspaceName: string;
}) {
  const binding = activationBinding.parse(input.binding);
  if (!input.displayName.trim() || input.displayName.length > 200 || !input.workspaceName.trim() || input.workspaceName.length > 200) throw new Error('A name is required');
  verifyRecoveryWords(input.phrase, input.challengePositions, input.challengeAnswers);
  const signing = await generateSigningKeyPair();
  const recipient = await generateRecipientKeyPair();
  const recovery = await recoveryKeys(input.phrase, binding);
  const custodyKey = await randomKey();
  const workspaceKey = await randomKey();
  try {
    const transcript: ActivationTranscript = {
      ...binding, version: 1, purpose: 'ukda.activation-transcript.v1',
      device: { id: crypto.randomUUID(), signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) },
      recovery: { id: crypto.randomUUID(), signingPublicKey: base64urlEncode(recovery.signing.publicKey), recipientPublicKey: base64urlEncode(recovery.recipient.publicKey) },
      genesisId: crypto.randomUUID(), custodyId: crypto.randomUUID(), deviceEnvelopeId: crypto.randomUUID(), recoveryEnvelopeId: crypto.randomUUID(),
      roles: { owner: crypto.randomUUID(), manager: crypto.randomUUID(), member: crypto.randomUUID(), viewer: crypto.randomUUID() },
      opaque: input.configuration, registrationDigest: await digestObject(input.registrationRecord), ownerPermissions: [...capabilities],
    };
    const transcriptDigest = await digestObject(transcript);
    const custodyPayload = { version: 1, custodyEpoch: '1', custodyKey: base64urlEncode(custodyKey) };
    const objects = {
      workspace: await encryptContent(initialContentHeader(transcript, 'workspace'), { name: input.workspaceName, timezone: 'Europe/London' }, workspaceKey, signing.privateKey),
      profile: await encryptContent(initialContentHeader(transcript, 'profile'), { displayName: input.displayName }, workspaceKey, signing.privateKey),
      custody: await encryptContent(initialContentHeader(transcript, 'custody'), { version: 1, custodyEpoch: '1', workspaceKeys: [{ epoch: '1', key: base64urlEncode(workspaceKey) }], projectKeys: [] }, custodyKey, signing.privateKey),
      deviceCustody: await sealRecipient(initialRecipientHeader(transcript, transcriptDigest, 'device'), custodyPayload, signing.privateKey),
      recoveryCustody: await sealRecipient(initialRecipientHeader(transcript, transcriptDigest, 'recovery'), custodyPayload, signing.privateKey),
    };
    const { purpose: _purpose, ...publicSetup } = transcript;
    const genesis = await signObject({ ...publicSetup, purpose: 'ukda.genesis.v1' as const, transcriptDigest,
      manifest: (await activationManifest(transcript, objects)).map(({ value: _value, ...entry }) => entry) }, signing.privateKey);
    const genesisFingerprint = await digestObject(genesis);
    const recoveryProof = await signObject({ ...binding, version: 1 as const, purpose: 'ukda.recovery-proof.v1' as const,
      recoveryGeneration: '1' as const, genesisFingerprint }, recovery.signing.privateKey);
    const payload: ActivationPayload = { genesis, recoveryProof, objects, opaqueRegistrationRecord: input.registrationRecord };
    await validateActivationPayload(payload, binding, input.configuration);
    const context = { workspaceId: binding.workspaceId, accountId: binding.accountId, deviceId: transcript.device.id, credentialGeneration: '1' };
    const bundle = { signingPrivateKey: base64urlEncode(signing.privateKey), recipientPrivateKey: base64urlEncode(recipient.privateKey),
      signingPublicKey: transcript.device.signingPublicKey, recipientPublicKey: transcript.device.recipientPublicKey };
    const deviceWrapper = await wrapDeviceBundle(context, bundle, input.exportKey);
    // Verify before publishing any authority; persistence must repeat this check on the IndexedDB read-back.
    const roundTrip = await unwrapDeviceBundle(context, deviceWrapper, input.exportKey);
    if (roundTrip.signingPublicKey !== bundle.signingPublicKey || roundTrip.recipientPublicKey !== bundle.recipientPublicKey) throw new Error('Local device verification failed');
    return { payload, deviceWrapper, recoveryKit: { version: 1 as const, language: 'english' as const,
      application: binding.origin, workspaceId: binding.workspaceId, accountId: binding.accountId,
      genesisFingerprint, phrase: input.phrase } };
  } finally {
    signing.privateKey.fill(0); recipient.privateKey.fill(0); recovery.signing.privateKey.fill(0); recovery.recipient.privateKey.fill(0);
    custodyKey.fill(0); workspaceKey.fill(0);
  }
}

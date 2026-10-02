import { z } from 'zod';
import { binary, capabilities, contentEnvelope, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, recipientEnvelope, verifyContentEnvelope, verifyObject, verifyRecipientEnvelope, type ContentHeader, type RecipientHeader } from './crypto.js';
import type { OpaquePublicConfiguration } from '../client/opaque.js';

export const INITIAL_HEAD = '0'.repeat(64);
export const activationBinding = z.strictObject({
  activationId: identifier, operationId: identifier, workspaceId: identifier, accountId: identifier,
  reservationGeneration: positiveCounter, draftGeneration: positiveCounter, origin: z.string().url(),
});
export type ActivationBinding = z.infer<typeof activationBinding>;
const publicKeys = z.strictObject({ id: identifier, signingPublicKey: binary(32), recipientPublicKey: binary(32) });
const opaqueConfiguration = z.strictObject({
  configId: z.literal('ukda.opaque.ristretto255.argon2id-m64-t3-p4.v1'), setupId: z.string().min(1).max(128),
  serverStaticPublicKey: binary(32), identifiers: z.strictObject({ client: z.string().min(1).max(256), server: z.string().min(1).max(256) }),
  keyStretching: z.literal('memory-constrained'),
});
export const activationTranscript = activationBinding.extend({
  version: z.literal(1), purpose: z.literal('ukda.activation-transcript.v1'),
  device: publicKeys, recovery: publicKeys, genesisId: identifier, custodyId: identifier,
  deviceEnvelopeId: identifier, recoveryEnvelopeId: identifier,
  roles: z.strictObject({ owner: identifier, manager: identifier, member: identifier, viewer: identifier }),
  opaque: opaqueConfiguration, registrationDigest: digest,
  ownerPermissions: z.array(z.enum(capabilities)).length(capabilities.length),
});
export type ActivationTranscript = z.infer<typeof activationTranscript>;
const manifestEntry = z.strictObject({ id: identifier, kind: z.enum(['encrypted_workspace', 'encrypted_profile', 'custody_manifest', 'key_envelope']), digest });
export const genesisBody = activationTranscript.omit({ purpose: true }).extend({
  purpose: z.literal('ukda.genesis.v1'), transcriptDigest: digest, manifest: z.array(manifestEntry).length(5),
});
export type GenesisBody = z.infer<typeof genesisBody>;
export const activationObjects = z.strictObject({ workspace: contentEnvelope, profile: contentEnvelope, custody: contentEnvelope, deviceCustody: recipientEnvelope, recoveryCustody: recipientEnvelope });
const recoveryProofBody = activationBinding.extend({ version: z.literal(1), purpose: z.literal('ukda.recovery-proof.v1'), recoveryGeneration: z.literal('1'), genesisFingerprint: digest });
export const activationPayload = z.strictObject({
  genesis: z.strictObject({ body: genesisBody, signature: binary(64) }),
  recoveryProof: z.strictObject({ body: recoveryProofBody, signature: binary(64) }),
  objects: activationObjects, opaqueRegistrationRecord: binary(1, 4096),
});
export type ActivationPayload = z.infer<typeof activationPayload>;
export type ActivationObjects = z.infer<typeof activationObjects>;

export function transcriptFromGenesis(body: GenesisBody): ActivationTranscript {
  const { purpose: _purpose, manifest: _manifest, transcriptDigest: _digest, ...transcript } = body;
  return { ...transcript, purpose: 'ukda.activation-transcript.v1' };
}

export function initialContentHeader(transcript: ActivationTranscript, type: 'workspace' | 'profile' | 'custody'): ContentHeader {
  return {
    version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: transcript.workspaceId,
    scope: 'workspace', scopeId: transcript.workspaceId, recordId: type === 'workspace' ? transcript.workspaceId : type === 'profile' ? transcript.accountId : transcript.custodyId,
    recordType: type, schema: 1, keyEpoch: '1', revision: '1', operationId: transcript.operationId,
    accountId: transcript.accountId, deviceId: transcript.device.id, keyGeneration: '1', permissionVersion: '1',
    securityVersion: '0', securityHead: INITIAL_HEAD, dataGeneration: '1', action: 'workspace.activate',
    approvalPolicyId: null, approvalPolicyRevision: null,
  };
}

export function initialRecipientHeader(transcript: ActivationTranscript, transcriptDigest: string, kind: 'device' | 'recovery'): RecipientHeader {
  const recipient = kind === 'device' ? transcript.device : transcript.recovery;
  return { version: 1, purpose: 'ukda.recipient.v1', algorithm: 'X25519-SealedBox', workspaceId: transcript.workspaceId,
    scope: 'workspace', scopeId: transcript.workspaceId, keyEpoch: '1', recipientAccountId: transcript.accountId,
    recipientId: recipient.id, recipientKind: kind, recipientKeyGeneration: '1', recipientPublicKey: recipient.recipientPublicKey,
    senderAccountId: transcript.accountId, senderDeviceId: transcript.device.id, senderKeyGeneration: '1',
    securityVersion: '0', securityHead: INITIAL_HEAD, ceremonyId: transcript.activationId, transcriptDigest };
}

export async function activationManifest(transcript: ActivationTranscript, objects: ActivationObjects) {
  const values = [
    { id: transcript.workspaceId, kind: 'encrypted_workspace' as const, value: objects.workspace },
    { id: transcript.accountId, kind: 'encrypted_profile' as const, value: objects.profile },
    { id: transcript.custodyId, kind: 'custody_manifest' as const, value: objects.custody },
    { id: transcript.deviceEnvelopeId, kind: 'key_envelope' as const, value: objects.deviceCustody },
    { id: transcript.recoveryEnvelopeId, kind: 'key_envelope' as const, value: objects.recoveryCustody },
  ];
  return Promise.all(values.map(async (object) => ({ ...object, digest: await digestObject(object.value) })));
}

/** Public verification only: neither ciphertext plaintext nor a private key is supplied here. */
export async function validateActivationPayload(value: unknown, binding: ActivationBinding, configuration: OpaquePublicConfiguration) {
  const payload = activationPayload.parse(value);
  const body = payload.genesis.body;
  const transcript = transcriptFromGenesis(body);
  for (const key of Object.keys(binding) as (keyof ActivationBinding)[]) if (body[key] !== binding[key]) throw new Error('Invalid activation context');
  if (canonicalJson(body.opaque) !== canonicalJson(configuration) || body.registrationDigest !== await digestObject(payload.opaqueRegistrationRecord) ||
    canonicalJson(body.ownerPermissions) !== canonicalJson([...capabilities])) throw new Error('Invalid activation authority');
  const ids = [body.genesisId, body.workspaceId, body.accountId, body.custodyId, body.deviceEnvelopeId, body.recoveryEnvelopeId, ...Object.values(body.roles)];
  if (new Set(ids).size !== ids.length) throw new Error('Invalid activation object identities');
  const transcriptDigest = await digestObject(transcript);
  const signingKey = base64urlDecode(body.device.signingPublicKey, 32);
  if (transcriptDigest !== body.transcriptDigest || !await verifyObject(payload.genesis, signingKey, 'ukda.genesis.v1')) throw new Error('Invalid activation signature');
  const objects = await activationManifest(transcript, payload.objects);
  const manifest = objects.map(({ value: _value, ...entry }) => entry);
  if (canonicalJson(manifest) !== canonicalJson(body.manifest)) throw new Error('Invalid activation manifest');
  for (const type of ['workspace', 'profile', 'custody'] as const) {
    if (!await verifyContentEnvelope(payload.objects[type], signingKey, initialContentHeader(transcript, type))) throw new Error('Invalid activation content');
  }
  for (const kind of ['device', 'recovery'] as const) {
    if (!await verifyRecipientEnvelope(kind === 'device' ? payload.objects.deviceCustody : payload.objects.recoveryCustody,
      signingKey, initialRecipientHeader(transcript, transcriptDigest, kind))) throw new Error('Invalid activation key delivery');
  }
  const genesisFingerprint = await digestObject(payload.genesis);
  const expectedProof = { ...binding, version: 1, purpose: 'ukda.recovery-proof.v1', recoveryGeneration: '1', genesisFingerprint };
  if (canonicalJson(payload.recoveryProof.body) !== canonicalJson(expectedProof) ||
    !await verifyObject(payload.recoveryProof, base64urlDecode(body.recovery.signingPublicKey, 32), 'ukda.recovery-proof.v1')) throw new Error('Invalid recovery proof');
  return { payload, objects, genesisFingerprint, requestHash: await digestObject(payload) };
}

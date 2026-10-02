import { z } from 'zod';
import { genesisBody } from './activation.js';
import { binary, counter, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, recipientEnvelope, verifyObject, verifyRecipientEnvelope,
  type RecipientHeader } from './crypto.js';
import { pairingPublicDevice, pairingScope, type PairingScope } from './pairing.js';
import { parseJsonStrict } from './json.js';

export const RESET_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const RESET_CODE_TTL_MS = 900_000;
export const RECOVERY_PROOF_TTL_MS = 120_000;
export const resetCode = z.string().regex(/^RESET-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
/** Twelve independent five-bit symbols. The code is an online capability, never key material. */
export function generateResetCode(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(12));
  try {
    const symbols = Array.from(bytes, (byte) => RESET_CODE_ALPHABET[byte & 31]!).join('');
    return `RESET-${symbols.slice(0, 4)}-${symbols.slice(4, 8)}-${symbols.slice(8)}`;
  } finally { bytes.fill(0); }
}

export const recoveryPublicAuthority = z.strictObject({ id: identifier, generation: positiveCounter,
  signingPublicKey: binary(32), recipientPublicKey: binary(32) });
export type RecoveryPublicAuthority = z.infer<typeof recoveryPublicAuthority>;
export const recoveryAuthorizer = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('phrase'), accountId: identifier, recovery: recoveryPublicAuthority }),
  z.strictObject({ kind: z.literal('owner_reset'), accountId: identifier, device: pairingPublicDevice,
    credentialGeneration: positiveCounter, sessionGeneration: positiveCounter, resetId: identifier, resetGeneration: positiveCounter }),
]);
export type RecoveryAuthorizer = z.infer<typeof recoveryAuthorizer>;
const origin = z.string().max(256).refine((value) => {
  try {
    const parsed = new URL(value);
    return parsed.origin === value && (parsed.protocol === 'https:' || (parsed.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)));
  } catch { return false; }
});
const consecutive = (before: string, after: string) => counter.safeParse(before).success &&
  positiveCounter.safeParse(after).success && BigInt(after) === BigInt(before) + 1n;
const equal = (left: unknown, right: unknown) => canonicalJson(left) === canonicalJson(right);

/** Trusted early authority snapshot. The server/history verifier must derive it from current records. */
export const recoveryBinding = z.strictObject({
  version: z.literal(1), origin, workspaceId: identifier, accountId: identifier, operationId: identifier,
  isOwner: z.boolean(), credentialGeneration: positiveCounter, nextCredentialGeneration: positiveCounter,
  sessionGeneration: positiveCounter, nextSessionGeneration: positiveCounter,
  resetGeneration: counter, recoveryGeneration: counter, nextRecoveryGeneration: counter,
  deviceKeyGeneration: counter, nextDeviceKeyGeneration: positiveCounter,
  dataGeneration: positiveCounter, securityVersion: positiveCounter, nextSecurityVersion: positiveCounter,
  securityHead: digest, genesisFingerprint: digest, ownershipVersion: counter, custodyEpoch: counter,
  currentRecovery: recoveryPublicAuthority.nullable(), authorizer: recoveryAuthorizer,
  scopes: z.array(pairingScope).max(256), issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime(),
}).refine((value) => consecutive(value.credentialGeneration, value.nextCredentialGeneration) &&
  consecutive(value.sessionGeneration, value.nextSessionGeneration) && consecutive(value.securityVersion, value.nextSecurityVersion) &&
  consecutive(value.deviceKeyGeneration, value.nextDeviceKeyGeneration) &&
  Date.parse(value.expiresAt) > Date.parse(value.issuedAt) && Date.parse(value.expiresAt) - Date.parse(value.issuedAt) <= RESET_CODE_TTL_MS)
  .refine((value) => value.isOwner ? value.currentRecovery !== null &&
    value.currentRecovery.generation === value.recoveryGeneration && consecutive(value.recoveryGeneration, value.nextRecoveryGeneration) :
    value.currentRecovery === null && value.nextRecoveryGeneration === value.recoveryGeneration)
  .refine((value) => value.authorizer.kind === 'phrase' ? value.isOwner && value.authorizer.accountId === value.accountId &&
    equal(value.authorizer.recovery, value.currentRecovery) : value.authorizer.resetGeneration === value.resetGeneration && value.authorizer.resetId === value.operationId)
  .refine((value) => new Set(value.scopes.map((scope) => `${scope.scope}:${scope.scopeId}`)).size === value.scopes.length &&
    value.scopes.filter((scope) => scope.scope === 'workspace').length === 1 &&
    value.scopes.every((scope) => (scope.scope !== 'workspace' || scope.scopeId === value.workspaceId) &&
      (scope.mode !== 'custody' || (value.isOwner && scope.scope === 'workspace' && scope.keyEpoch === value.custodyEpoch)) &&
      new Set(scope.permissions).size === scope.permissions.length &&
      new Set(scope.sources.map((source) => source.grantId)).size === scope.sources.length) &&
    (!value.isOwner || value.scopes.filter((scope) => scope.mode === 'custody').length === 1));
export type RecoveryBinding = z.infer<typeof recoveryBinding>;
export const recoveryReference = z.strictObject({ workspaceId: identifier, operationId: identifier, resumeToken: binary(32) });
export type RecoveryReference = z.infer<typeof recoveryReference>;
/** Safe to share with an approving Owner; never add the recipient's resume capability to a QR. */
export const recoveryOperationReference = z.strictObject({ workspaceId: identifier, operationId: identifier });
export type RecoveryOperationReference = z.infer<typeof recoveryOperationReference>;
export const recoveryIssueReset = z.strictObject({ workspaceId: identifier, accountId: identifier, resetId: identifier });
export const recoveryRevokeReset = z.strictObject({ workspaceId: identifier, resetId: identifier });
export const recoveryBeginReset = z.strictObject({ workspaceId: identifier, code: resetCode, resumeToken: binary(32) });
export const recoveryBeginPhrase = recoveryReference.extend({ accountId: identifier });
export const recoveryIssuedReset = z.strictObject({ workspaceId: identifier, accountId: identifier, resetId: identifier,
  code: resetCode, resetGeneration: positiveCounter, expiresAt: z.iso.datetime() });
export type RecoveryIssuedReset = z.infer<typeof recoveryIssuedReset>;

export const recoveryTranscript = z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.recovery-transcript.v1'),
  binding: recoveryBinding, device: pairingPublicDevice, recovery: recoveryPublicAuthority.nullable(),
  configuration: genesisBody.shape.opaque, registrationRecordHash: digest, wrapperHash: digest,
}).refine((value) => value.device.keyGeneration === value.binding.nextDeviceKeyGeneration &&
  value.configuration.identifiers.client === `ukda:${value.binding.workspaceId}:${value.binding.accountId}` &&
  (value.binding.authorizer.kind !== 'owner_reset' || value.device.id !== value.binding.authorizer.device.id))
  .refine((value) => value.binding.isOwner ? value.recovery !== null && value.recovery.generation === value.binding.nextRecoveryGeneration &&
    value.recovery.id !== value.device.id && value.recovery.id !== value.binding.currentRecovery?.id &&
    value.recovery.signingPublicKey !== value.binding.currentRecovery?.signingPublicKey &&
    value.recovery.recipientPublicKey !== value.binding.currentRecovery?.recipientPublicKey : value.recovery === null);
export type RecoveryTranscript = z.infer<typeof recoveryTranscript>;

export const recoveryPhraseChallenge = z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.owner-phrase-challenge.v1'),
  binding: recoveryBinding, proofId: identifier, nonce: binary(32), issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime(),
}).refine((value) => value.binding.authorizer.kind === 'phrase' && Date.parse(value.issuedAt) >= Date.parse(value.binding.issuedAt) &&
  Date.parse(value.expiresAt) <= Date.parse(value.binding.expiresAt) && Date.parse(value.expiresAt) > Date.parse(value.issuedAt) &&
  Date.parse(value.expiresAt) - Date.parse(value.issuedAt) <= RECOVERY_PROOF_TTL_MS);
export type RecoveryPhraseChallenge = z.infer<typeof recoveryPhraseChallenge>;
export const recoveryPhraseProof = z.strictObject({ body: recoveryPhraseChallenge, signature: binary(64) });
export type RecoveryPhraseProof = z.infer<typeof recoveryPhraseProof>;
export const recoveryConfirmationBody = z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.recovery-confirmation.v1'),
  workspaceId: identifier, operationId: identifier, transcriptDigest: digest, role: z.enum(['recipient', 'authorizer', 'new_recovery']),
  accountId: identifier, signerId: identifier, signerGeneration: positiveCounter, kitVerified: z.literal(true).optional(),
}).refine((value) => (value.role === 'new_recovery') === (value.kitVerified === true));
export const recoveryConfirmation = z.strictObject({ body: recoveryConfirmationBody, signature: binary(64) });
export type RecoveryConfirmation = z.infer<typeof recoveryConfirmation>;
/** The recipient proves new credentials before an Owner can prepare/sign the final encrypted delivery. */
export const recoveryDraft = z.strictObject({ transcript: recoveryTranscript, registrationRecord: binary(1, 4096),
  recipientConfirmation: recoveryConfirmation.nullable(), newRecoveryConfirmation: recoveryConfirmation.nullable() });
export type RecoveryDraft = z.infer<typeof recoveryDraft>;
export const recoveryDeliveryDescriptor = z.strictObject({ id: identifier, scope: z.enum(['workspace', 'project']), scopeId: identifier,
  keyEpoch: positiveCounter, recipientKind: z.enum(['device', 'recovery']), recipientId: identifier, digest });
export const recoveryTransitionBody = z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.account-recovery.v1'),
  transcript: recoveryTranscript, transcriptDigest: digest,
  recipientConfirmation: recoveryConfirmation, authorizerConfirmation: recoveryConfirmation,
  newRecoveryConfirmation: recoveryConfirmation.nullable(), deliveries: z.array(recoveryDeliveryDescriptor).max(257),
  revokeAllDevices: z.literal(true), revokeAllSessions: z.literal(true),
});
export const recoveryTransition = z.strictObject({ body: recoveryTransitionBody, signature: binary(64) });
export type RecoveryTransition = z.infer<typeof recoveryTransition>;
export const recoveryApproval = z.strictObject({ transition: recoveryTransition,
  deliveries: z.array(z.strictObject({ id: identifier, envelope: recipientEnvelope })).max(257) });
export type RecoveryApproval = z.infer<typeof recoveryApproval>;
export const recoveryPayload = z.strictObject({ transition: recoveryTransition, registrationRecord: binary(1, 4096),
  deliveries: z.array(z.strictObject({ id: identifier, envelope: recipientEnvelope })).max(257) });
export type RecoveryPayload = z.infer<typeof recoveryPayload>;
export const recoveryReceipt = z.strictObject({ version: z.literal(1), operationId: identifier, workspaceId: identifier,
  accountId: identifier, deviceId: identifier, credentialGeneration: positiveCounter, sessionGeneration: positiveCounter,
  keyGeneration: positiveCounter, recoveryGeneration: counter, dataGeneration: positiveCounter,
  securityVersion: positiveCounter, securityHead: digest, requestHash: digest, wrapperHash: digest,
  committedAt: z.iso.datetime(), transition: recoveryTransition });
export type RecoveryReceipt = z.infer<typeof recoveryReceipt>;
export const recoveryResult = z.strictObject({ state: z.enum(['completed', 'finishing']), receipt: recoveryReceipt });
export type RecoveryResult = z.infer<typeof recoveryResult>;
/** Public/ciphertext ceremony state; OPAQUE records and resume tokens are deliberately excluded. */
export const recoveryView = z.strictObject({ workspaceId: identifier, accountId: identifier, operationId: identifier,
  state: z.enum(['issued', 'waiting_approval', 'verifying', 'confirmed', 'completed', 'finishing', 'expired', 'cancelled', 'revoked']),
  binding: recoveryBinding.nullable(), transcript: recoveryTranscript.nullable(), transcriptDigest: digest.nullable(),
  recipientConfirmation: recoveryConfirmation.nullable(), authorizerConfirmation: recoveryConfirmation.nullable(),
  newRecoveryConfirmation: recoveryConfirmation.nullable(), approvalStaged: z.boolean(), passwordProved: z.boolean(),
  requestHash: digest.nullable(), receipt: recoveryReceipt.nullable(), expiresAt: z.iso.datetime(), resumeExpiresAt: z.iso.datetime(),
});
export type RecoveryView = z.infer<typeof recoveryView>;
export const recoveryRegistration = recoveryReference.extend({ registrationRequest: binary(1, 4096) });
export const recoveryProofStart = recoveryReference.extend({ draft: recoveryDraft, startLoginRequest: binary(1, 4096) });
export const recoveryProofFinish = recoveryReference.extend({ proofId: identifier, finishLoginRequest: binary(1, 4096) });
export const recoveryFinalize = recoveryOperationReference.extend({ requestHash: digest });

export function recoveryConfirmationFor(transcript: RecoveryTranscript, transcriptDigest: string,
  role: RecoveryConfirmation['body']['role']): RecoveryConfirmation['body'] {
  const { binding } = transcript, authority = binding.authorizer;
  const signer = role === 'recipient' ? { accountId: binding.accountId, id: transcript.device.id, generation: transcript.device.keyGeneration } :
    role === 'new_recovery' ? transcript.recovery && { accountId: binding.accountId, id: transcript.recovery.id, generation: transcript.recovery.generation } :
    authority.kind === 'phrase' ? { accountId: authority.accountId, id: authority.recovery.id, generation: authority.recovery.generation } :
    { accountId: authority.accountId, id: authority.device.id, generation: authority.device.keyGeneration };
  if (!signer) throw new RecoveryContractError();
  return recoveryConfirmationBody.parse({ version: 1, purpose: 'ukda.recovery-confirmation.v1', workspaceId: binding.workspaceId,
    operationId: binding.operationId, transcriptDigest, role, accountId: signer.accountId, signerId: signer.id, signerGeneration: signer.generation,
    ...(role === 'new_recovery' ? { kitVerified: true } : {}) });
}

export function recoveryRecipientHeader(transcript: RecoveryTranscript, transcriptDigest: string, scope: PairingScope,
  recipientKind: 'device' | 'recovery'): RecipientHeader {
  const { binding } = transcript;
  const recipient = recipientKind === 'device' ? transcript.device : transcript.recovery;
  if (!recipient || !binding.scopes.some((known) => equal(known, scope)) ||
    (recipientKind === 'recovery' && (scope.mode !== 'custody' || scope.scope !== 'workspace'))) throw new RecoveryContractError();
  // Recovery proof keys never masquerade as device-envelope senders.
  const sender = binding.authorizer.kind === 'phrase' ? transcript.device : binding.authorizer.device;
  const senderAccountId = binding.authorizer.kind === 'phrase' ? binding.accountId : binding.authorizer.accountId;
  return { version: 1, purpose: 'ukda.recipient.v1', algorithm: 'X25519-SealedBox', workspaceId: binding.workspaceId,
    scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, recipientAccountId: binding.accountId,
    recipientId: recipient.id, recipientKind, recipientKeyGeneration: 'keyGeneration' in recipient ? recipient.keyGeneration : recipient.generation,
    recipientPublicKey: recipient.recipientPublicKey, senderAccountId, senderDeviceId: sender.id, senderKeyGeneration: sender.keyGeneration,
    securityVersion: binding.securityVersion, securityHead: binding.securityHead, ceremonyId: binding.operationId, transcriptDigest };
}

export class RecoveryContractError extends Error {
  constructor() { super('Invalid recovery contract'); this.name = 'RecoveryContractError'; }
}
function snapshot<T>(schema: z.ZodType<T>, value: unknown): T {
  try { return schema.parse(parseJsonStrict(canonicalJson(value))); } catch { throw new RecoveryContractError(); }
}
function authorizerKey(binding: RecoveryBinding): Uint8Array {
  return base64urlDecode(binding.authorizer.kind === 'phrase' ? binding.authorizer.recovery.signingPublicKey : binding.authorizer.device.signingPublicKey, 32);
}

/** Signature validity is separate from server-owned challenge expiry/single-use state. */
export async function validateRecoveryPhraseProof(value: unknown, expected: RecoveryPhraseChallenge): Promise<RecoveryPhraseProof> {
  const proof = snapshot(recoveryPhraseProof, value), challenge = snapshot(recoveryPhraseChallenge, expected);
  if (!equal(proof.body, challenge) || !await verifyObject(proof, authorizerKey(challenge.binding), 'ukda.owner-phrase-challenge.v1')) throw new RecoveryContractError();
  return proof;
}

export async function validateRecoveryDraft(value: unknown, expected: RecoveryBinding,
  configuration: z.infer<typeof genesisBody.shape.opaque>) {
  const draft = snapshot(recoveryDraft, value), binding = snapshot(recoveryBinding, expected);
  const { transcript, recipientConfirmation, newRecoveryConfirmation } = draft;
  const transcriptDigest = await digestObject(transcript);
  if (!equal(transcript.binding, binding) || !equal(transcript.configuration, configuration) ||
    transcript.registrationRecordHash !== await digestObject(draft.registrationRecord) || (recipientConfirmation && (
    !equal(recipientConfirmation.body, recoveryConfirmationFor(transcript, transcriptDigest, 'recipient')) ||
    !await verifyObject(recipientConfirmation, base64urlDecode(transcript.device.signingPublicKey, 32), 'ukda.recovery-confirmation.v1')))) throw new RecoveryContractError();
  if (transcript.recovery ? !newRecoveryConfirmation ||
    !equal(newRecoveryConfirmation.body, recoveryConfirmationFor(transcript, transcriptDigest, 'new_recovery')) ||
    !await verifyObject(newRecoveryConfirmation, base64urlDecode(transcript.recovery.signingPublicKey, 32), 'ukda.recovery-confirmation.v1') :
    newRecoveryConfirmation !== null) throw new RecoveryContractError();
  return { draft, transcriptDigest, draftHash: await digestObject(draft) };
}

/** Expected binding/configuration must come from current trusted authority, never this payload. */
export async function validateRecoveryTransition(value: unknown, expected: RecoveryBinding,
  configuration: z.infer<typeof genesisBody.shape.opaque>) {
  const transition = snapshot(recoveryTransition, value), binding = snapshot(recoveryBinding, expected);
  const { transcript, recipientConfirmation, authorizerConfirmation, newRecoveryConfirmation } = transition.body;
  if (!equal(transcript.binding, binding) || !equal(transcript.configuration, configuration)) throw new RecoveryContractError();
  const transcriptDigest = await digestObject(transcript);
  if (transition.body.transcriptDigest !== transcriptDigest ||
    !equal(recipientConfirmation.body, recoveryConfirmationFor(transcript, transcriptDigest, 'recipient')) ||
    !equal(authorizerConfirmation.body, recoveryConfirmationFor(transcript, transcriptDigest, 'authorizer')) ||
    !await verifyObject(recipientConfirmation, base64urlDecode(transcript.device.signingPublicKey, 32), 'ukda.recovery-confirmation.v1') ||
    !await verifyObject(authorizerConfirmation, authorizerKey(binding), 'ukda.recovery-confirmation.v1') ||
    !await verifyObject(transition, authorizerKey(binding), 'ukda.account-recovery.v1')) throw new RecoveryContractError();
  if (transcript.recovery ? !newRecoveryConfirmation ||
    !equal(newRecoveryConfirmation.body, recoveryConfirmationFor(transcript, transcriptDigest, 'new_recovery')) ||
    !await verifyObject(newRecoveryConfirmation, base64urlDecode(transcript.recovery.signingPublicKey, 32), 'ukda.recovery-confirmation.v1') :
    newRecoveryConfirmation !== null) throw new RecoveryContractError();
  const descriptors = transition.body.deliveries;
  if (new Set(descriptors.map((entry) => entry.id)).size !== descriptors.length ||
    descriptors.length !== binding.scopes.length + (binding.isOwner ? 1 : 0)) throw new RecoveryContractError();
  for (const scope of binding.scopes) {
    const matches = descriptors.filter((entry) => entry.scope === scope.scope && entry.scopeId === scope.scopeId && entry.keyEpoch === scope.keyEpoch);
    if (matches.filter((entry) => entry.recipientKind === 'device' && entry.recipientId === transcript.device.id).length !== 1 ||
      matches.length !== (scope.mode === 'custody' ? 2 : 1) || (scope.mode === 'custody' &&
      matches.filter((entry) => entry.recipientKind === 'recovery' && entry.recipientId === transcript.recovery?.id).length !== 1)) throw new RecoveryContractError();
  }
  return { transition, transcriptDigest, securityHead: await digestObject(transition) };
}

/** An approving Owner verifies delivery bytes without receiving the target's OPAQUE record. */
export async function validateRecoveryPublicApproval(value: unknown, expected: RecoveryBinding,
  configuration: z.infer<typeof genesisBody.shape.opaque>) {
  const approval = snapshot(recoveryApproval, value);
  const verified = await validateRecoveryTransition(approval.transition, expected, configuration);
  const { transcript } = approval.transition.body;
  if (new Set(approval.deliveries.map((delivery) => delivery.id)).size !== approval.deliveries.length ||
    approval.deliveries.length !== approval.transition.body.deliveries.length) throw new RecoveryContractError();
  const signer = transcript.binding.authorizer.kind === 'phrase' ? transcript.device : transcript.binding.authorizer.device;
  for (const descriptor of approval.transition.body.deliveries) {
    const delivery = approval.deliveries.find((entry) => entry.id === descriptor.id);
    const scope = transcript.binding.scopes.find((entry) => entry.scope === descriptor.scope && entry.scopeId === descriptor.scopeId);
    if (!delivery || !scope || await digestObject(delivery.envelope) !== descriptor.digest ||
      !await verifyRecipientEnvelope(delivery.envelope, base64urlDecode(signer.signingPublicKey, 32),
        recoveryRecipientHeader(transcript, verified.transcriptDigest, scope, descriptor.recipientKind))) throw new RecoveryContractError();
  }
  return { ...verified, approval };
}

/** No password, phrase, export key or private device bundle is accepted by this public verifier. */
export async function validateRecoveryPayload(value: unknown, expected: RecoveryBinding,
  configuration: z.infer<typeof genesisBody.shape.opaque>) {
  const payload = snapshot(recoveryPayload, value);
  const { approval: _approval, ...verified } = await validateRecoveryPublicApproval(
    { transition: payload.transition, deliveries: payload.deliveries }, expected, configuration);
  if (payload.transition.body.transcript.registrationRecordHash !== await digestObject(payload.registrationRecord)) throw new RecoveryContractError();
  return { ...verified, payload, requestHash: await digestObject(payload) };
}

/** Combines the exact target-staged credential draft with the later signed approval. */
export async function validateRecoveryApproval(value: unknown, expectedDraft: RecoveryDraft, expected: RecoveryBinding,
  configuration: z.infer<typeof genesisBody.shape.opaque>) {
  const approval = snapshot(recoveryApproval, value);
  const { draft } = await validateRecoveryDraft(expectedDraft, expected, configuration);
  if (!equal(approval.transition.body.transcript, draft.transcript) ||
    !equal(approval.transition.body.recipientConfirmation, draft.recipientConfirmation) ||
    !equal(approval.transition.body.newRecoveryConfirmation, draft.newRecoveryConfirmation)) throw new RecoveryContractError();
  return validateRecoveryPayload({ ...approval, registrationRecord: draft.registrationRecord }, expected, configuration);
}

export async function validateRecoveryReceipt(value: unknown, expected: RecoveryTranscript): Promise<RecoveryReceipt> {
  const receipt = snapshot(recoveryReceipt, value), transcript = snapshot(recoveryTranscript, expected), binding = transcript.binding;
  const verified = await validateRecoveryTransition(receipt.transition, binding, transcript.configuration);
  if (!equal(receipt.transition.body.transcript, transcript) || receipt.operationId !== binding.operationId || receipt.workspaceId !== binding.workspaceId ||
    receipt.accountId !== binding.accountId || receipt.deviceId !== transcript.device.id || receipt.credentialGeneration !== binding.nextCredentialGeneration ||
    receipt.sessionGeneration !== binding.nextSessionGeneration || receipt.keyGeneration !== binding.nextDeviceKeyGeneration ||
    receipt.recoveryGeneration !== binding.nextRecoveryGeneration || receipt.dataGeneration !== binding.dataGeneration ||
    receipt.securityVersion !== binding.nextSecurityVersion || receipt.securityHead !== verified.securityHead || receipt.wrapperHash !== transcript.wrapperHash) throw new RecoveryContractError();
  return receipt;
}

import { z } from 'zod';
import { binary, capabilities, counter, digest, identifier, positiveCounter } from './contracts.js';
import { recipientEnvelope, type RecipientHeader } from './crypto.js';

export const pairingPublicDevice = z.strictObject({ id: identifier, keyGeneration: positiveCounter,
  signingPublicKey: binary(32), recipientPublicKey: binary(32) });
export const pairingBegin = z.strictObject({ operationId: identifier, device: pairingPublicDevice,
  localBundleDigest: digest }).refine((value) => value.device.keyGeneration === '1');
export type PairingBegin = z.infer<typeof pairingBegin>;
export const pairingSource = z.strictObject({ grantId: identifier, generation: positiveCounter,
  manifestId: identifier, manifestDigest: digest });
export const pairingScope = z.strictObject({ scope: z.enum(['workspace', 'project']), scopeId: identifier,
  mode: z.enum(['custody', 'content']), keyEpoch: positiveCounter, expiresAt: z.iso.datetime().nullable(),
  permissions: z.array(z.enum(capabilities)).max(capabilities.length), sources: z.array(pairingSource).min(1).max(256) });
export type PairingScope = z.infer<typeof pairingScope>;
export const pairingTranscript = z.strictObject({
  version: z.literal(1), purpose: z.literal('ukda.device-pair-transcript.v1'), origin: z.string().url(),
  workspaceId: identifier, operationId: identifier, ceremonyId: identifier, accountId: identifier,
  device: pairingPublicDevice, localBundleDigest: digest,
  approverAccountId: identifier, approverDevice: pairingPublicDevice, approverIsOwner: z.boolean(),
  credentialGeneration: positiveCounter, sessionGeneration: positiveCounter,
  approverCredentialGeneration: positiveCounter, approverSessionGeneration: positiveCounter,
  dataGeneration: positiveCounter, ownershipVersion: counter, custodyEpoch: counter,
  genesisFingerprint: digest, securityHead: digest, securityVersion: positiveCounter,
  scopes: z.array(pairingScope).min(1).max(256), issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime(),
}).refine((value) => value.operationId === value.ceremonyId && value.device.id !== value.approverDevice.id &&
  Date.parse(value.expiresAt) > Date.parse(value.issuedAt) && Date.parse(value.expiresAt) - Date.parse(value.issuedAt) <= 600_000)
  .refine((value) => value.scopes.every((scope) => scope.scope !== 'workspace' || scope.scopeId === value.workspaceId));
export type PairingTranscript = z.infer<typeof pairingTranscript>;
export const pairingConfirmationBody = z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.device-pair-confirmation.v1'),
  workspaceId: identifier, operationId: identifier, transcriptDigest: digest,
  role: z.enum(['recipient', 'approver']), accountId: identifier, deviceId: identifier });
export const pairingConfirmation = z.strictObject({ body: pairingConfirmationBody, signature: binary(64) });
export type PairingConfirmation = z.infer<typeof pairingConfirmation>;
export const pairingDeliveryDescriptor = z.strictObject({ id: identifier, scope: z.enum(['workspace', 'project']), scopeId: identifier, digest });
export const pairingGrantBody = z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.device-pair-grant.v1'),
  operationId: identifier, workspaceId: identifier, grantId: identifier, securityVersion: positiveCounter, previousHead: digest,
  transcript: pairingTranscript, transcriptDigest: digest, recipientConfirmation: pairingConfirmation,
  approverConfirmation: pairingConfirmation, deliveries: z.array(pairingDeliveryDescriptor).min(1).max(256),
});
export const pairingGrant = z.strictObject({ body: pairingGrantBody, signature: binary(64) });
export type PairingGrant = z.infer<typeof pairingGrant>;
export const pairingApproval = z.strictObject({ grant: pairingGrant,
  deliveries: z.array(z.strictObject({ id: identifier, envelope: recipientEnvelope })).min(1).max(256) });
export type PairingApproval = z.infer<typeof pairingApproval>;
export const pairingReceipt = z.strictObject({ version: z.literal(1), operationId: identifier, workspaceId: identifier,
  accountId: identifier, deviceId: identifier, transcriptDigest: digest, grantId: identifier,
  securityHead: digest, securityVersion: positiveCounter, dataGeneration: positiveCounter, committedAt: z.iso.datetime(),
  grant: pairingGrant,
});
export type PairingReceipt = z.infer<typeof pairingReceipt>;
export interface PairingView {
  operationId: string; state: 'waiting_approver' | 'verifying' | 'confirmed' | 'completed' | 'expired' | 'cancelled';
  request: PairingBegin; transcript: PairingTranscript | null; transcriptDigest: string | null;
  recipientConfirmation: PairingConfirmation | null; approverConfirmation: PairingConfirmation | null;
  approvalStaged: boolean; receipt: PairingReceipt | null;
}
export interface PairingMaterial { id: string; digest: string; kind: string; value: unknown }
export interface PairingDelivery { receipt: PairingReceipt; deliveries: PairingApproval['deliveries']; materials: PairingMaterial[] }

export function pairingConfirmationFor(transcript: PairingTranscript, transcriptDigest: string,
  role: 'recipient' | 'approver'): z.infer<typeof pairingConfirmationBody> {
  return { version: 1, purpose: 'ukda.device-pair-confirmation.v1', workspaceId: transcript.workspaceId,
    operationId: transcript.operationId, transcriptDigest, role,
    accountId: role === 'recipient' ? transcript.accountId : transcript.approverAccountId,
    deviceId: role === 'recipient' ? transcript.device.id : transcript.approverDevice.id };
}
export function pairingRecipientHeader(transcript: PairingTranscript, transcriptDigest: string, scope: PairingScope): RecipientHeader {
  return { version: 1, purpose: 'ukda.recipient.v1', algorithm: 'X25519-SealedBox', workspaceId: transcript.workspaceId,
    scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, recipientAccountId: transcript.accountId,
    recipientId: transcript.device.id, recipientKind: 'device', recipientKeyGeneration: transcript.device.keyGeneration,
    recipientPublicKey: transcript.device.recipientPublicKey, senderAccountId: transcript.approverAccountId,
    senderDeviceId: transcript.approverDevice.id, senderKeyGeneration: transcript.approverDevice.keyGeneration,
    securityVersion: transcript.securityVersion, securityHead: transcript.securityHead,
    ceremonyId: transcript.ceremonyId, transcriptDigest };
}

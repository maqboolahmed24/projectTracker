import { z } from 'zod';
import { binary, contentEnvelope, contentHeader, digest, identifier, positiveCounter } from './contracts.js';
import { enrolmentBinding, enrolmentBegin, enrolmentConfirmation, enrolmentDraft, enrolmentOperationReference,
  enrolmentPublicDraft, enrolmentReceipt, enrolmentReference, enrolmentTranscript } from './enrolment.js';

export { enrolmentBegin };
const issuance = { workspaceId: identifier, accountId: identifier, operationId: identifier,
  kind: z.enum(['join_member', 'join_owner']), roleId: identifier, projectIds: z.array(identifier).max(255) };
export const enrolmentIssuanceRequest = z.strictObject(issuance).refine((v) => new Set(v.projectIds).size === v.projectIds.length);
export const enrolmentIssueJoin = z.strictObject({ ...issuance, profile: z.strictObject({ id: identifier, envelope: contentEnvelope }) }).refine((v) => new Set(v.projectIds).size === v.projectIds.length);
export const enrolmentIssuanceContext = z.strictObject({ workspaceId: identifier, accountId: identifier, operationId: identifier,
  kind: z.enum(['join_member', 'join_owner']), role: enrolmentBinding.shape.role, authorizer: enrolmentBinding.shape.authorizer,
  header: contentHeader, genesisFingerprint: digest, custodyEpoch: positiveCounter,
  current: z.strictObject({ securityHead: digest, securityVersion: positiveCounter }), materials: z.array(z.strictObject({ id: identifier, digest, kind: z.string(), value: z.unknown() })).max(4097) });
export type EnrolmentIssuanceContext = z.infer<typeof enrolmentIssuanceContext>;
export const enrolmentRevokeJoin = enrolmentOperationReference;
export const enrolmentBeginPromotion = z.strictObject({ workspaceId: identifier, accountId: identifier, operationId: identifier });
export const enrolmentClaimPromotion = enrolmentReference;
export const enrolmentRegistration = enrolmentReference.extend({ registrationRequest: binary(1, 4096) });
export const enrolmentProofStart = enrolmentReference.extend({ draft: enrolmentDraft, startLoginRequest: binary(1, 4096) });
export const enrolmentProofFinish = enrolmentReference.extend({ proofId: identifier, finishLoginRequest: binary(1, 4096) });
export const enrolmentUnlockStart = enrolmentReference.extend({ startLoginRequest: binary(1, 4096) });
export const enrolmentUnlockFinish = enrolmentProofFinish;
export const enrolmentPromotionDraft = enrolmentReference.extend({ draft: enrolmentDraft });
export const enrolmentView = z.strictObject({ workspaceId: identifier, accountId: identifier, operationId: identifier,
  kind: z.enum(['join_member', 'join_owner', 'promote_owner']),
  state: z.enum(['issued', 'waiting_approval', 'verifying', 'confirmed', 'completed', 'finishing', 'cancelled', 'revoked', 'expired']),
  binding: enrolmentBinding.nullable(), publicDraft: enrolmentPublicDraft.nullable(), transcript: enrolmentTranscript.nullable(),
  transcriptDigest: z.string().regex(/^[0-9a-f]{64}$/).nullable(), recipientConfirmation: enrolmentConfirmation.nullable(),
  newRecoveryConfirmation: enrolmentConfirmation.nullable(), authorizerConfirmation: enrolmentConfirmation.nullable(),
  passwordProved: z.boolean(), approvalStaged: z.boolean(), approvalHash: z.string().regex(/^[0-9a-f]{64}$/).nullable(), requestHash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  receipt: enrolmentReceipt.nullable(), expiresAt: z.iso.datetime(), resumeExpiresAt: z.iso.datetime() });
export type EnrolmentView = z.infer<typeof enrolmentView>;
export interface EnrolmentAuth { cookieValue: string; csrfToken: string }

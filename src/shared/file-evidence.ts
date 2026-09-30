import { z } from 'zod';
import { binary,digest,identifier,positiveCounter } from './contracts.js';
import { base64urlDecode,verifyObject } from './crypto.js';
import { fileBinding,fileEncryptedMetadata,fileManifest,fileReference,verifyFileBindingHistorical,type FileBinding } from './files.js';
import { planningContext,type PlanningContext,type PlanningSecurityResolver } from './planning-api.js';
export const FILE_EVIDENCE_MAX_ITEMS=64;
export const evidenceVersion=z.strictObject({fileId:identifier,versionId:identifier,manifestDigest:digest});
const versions=z.array(evidenceVersion).max(FILE_EVIDENCE_MAX_ITEMS).refine(v=>new Set(v.map(x=>x.fileId)).size===v.length);
export const fileVerificationBody=z.strictObject({purpose:z.literal('ukda.file-local-verification.v1'),binding:fileBinding,reference:evidenceVersion,verification:fileEncryptedMetadata});
export const fileVerification=z.strictObject({body:fileVerificationBody,signature:binary(64)});
export type FileVerification=z.infer<typeof fileVerification>;
export const fileSubmissionBody=z.strictObject({purpose:z.literal('ukda.file-submission.v1'),binding:fileBinding,submissionId:identifier,taskId:identifier,
 taskRevision:positiveCounter,taskContentRevision:positiveCounter,reviewPolicyRevision:positiveCounter,sources:versions,outputs:versions.refine(v=>v.length>0),verification:fileEncryptedMetadata});
export const fileSubmission=z.strictObject({body:fileSubmissionBody,signature:binary(64)});
export type FileSubmission=z.infer<typeof fileSubmission>;
export const fileReviewBody=z.strictObject({purpose:z.literal('ukda.file-review.v1'),binding:fileBinding,approvalId:identifier,submissionId:identifier,submissionDigest:digest,
 taskId:identifier,taskContentRevision:positiveCounter,reviewPolicyRevision:positiveCounter,reviewTaskRevision:positiveCounter,decision:z.literal('accept'),verification:fileEncryptedMetadata});
export const fileReview=z.strictObject({body:fileReviewBody,signature:binary(64)});
export type FileReview=z.infer<typeof fileReview>;
export const sharedFileApprovalBody=z.strictObject({purpose:z.literal('ukda.shared-file-approval.v1'),binding:fileBinding,approvalId:identifier,reference:evidenceVersion,verification:fileEncryptedMetadata});
export const sharedFileApproval=z.strictObject({body:sharedFileApprovalBody,signature:binary(64)});
export type SharedFileApproval=z.infer<typeof sharedFileApproval>;
export const fileApproval=z.union([fileReview,sharedFileApproval]);export type FileApproval=z.infer<typeof fileApproval>;
export const fileRevocationBody=z.strictObject({purpose:z.literal('ukda.file-approval-revocation.v1'),binding:fileBinding,approvalId:identifier,reason:fileEncryptedMetadata});
export const fileRevocation=z.strictObject({body:fileRevocationBody,signature:binary(64)});
export type FileRevocation=z.infer<typeof fileRevocation>;
export const evidenceContextRequest=fileReference.extend({taskId:identifier.optional(),versionId:identifier.optional()}).refine(v=>(v.taskId!==undefined)!==(v.versionId!==undefined));
export const evidenceContext=z.strictObject({planning:planningContext,binding:fileBinding,taskId:identifier.nullable(),manifests:z.array(fileManifest).max(FILE_EVIDENCE_MAX_ITEMS*2),
 sources:versions,outputs:versions,submission:fileSubmission.nullable(),approval:fileApproval.nullable(),revocation:fileRevocation.nullable()});
export type EvidenceContext=Omit<z.infer<typeof evidenceContext>,'planning'>&{planning:PlanningContext};
export const evidenceSubmitRequest=z.strictObject({submission:fileSubmission});
export const evidenceReviewRequest=z.strictObject({review:fileReview});
export const evidenceSharedRequest=z.strictObject({approval:sharedFileApproval});
export const evidenceRevokeRequest=z.strictObject({revocation:fileRevocation});
export const evidenceReceipt=z.strictObject({version:z.literal(1),workspaceId:identifier,projectId:identifier,operationId:identifier,dataGeneration:positiveCounter,requestHash:digest,
 action:z.enum(['submit','accept','approve_shared','revoke']),evidenceId:identifier,committedAt:z.iso.datetime()});
export type EvidenceReceipt=z.infer<typeof evidenceReceipt>;
export const evidenceView=z.strictObject({state:z.enum(['completed','absent']),receipt:evidenceReceipt.nullable()});export type EvidenceView=z.infer<typeof evidenceView>;
export const evidenceStatusRequest=fileReference.extend({dataGeneration:positiveCounter,requestHash:digest});
export function fileEvidenceCipherContext(body:{purpose:string;verification:unknown}|{purpose:string;reason:unknown}) {
 const {verification:_verification,reason:_reason,...rest}=body as {purpose:string;verification?:unknown;reason?:unknown};return {...rest,purpose:`${body.purpose}.private`};
}
export async function verifyFileEvidence(value:{body:{purpose:string;binding:FileBinding};signature:string},securityAt:PlanningSecurityResolver,owner=false):Promise<void> {
 const b=await verifyFileBindingHistorical(value.body.binding,securityAt,owner);
 if(!await verifyObject(value,base64urlDecode(b.signingPublicKey),value.body.purpose))throw new Error('Invalid file evidence');
}

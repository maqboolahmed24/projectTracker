import { z } from 'zod';
import { binary,counter,digest,identifier,positiveCounter } from './contracts.js';
import { fileBinding,fileEncryptedMetadata,fileReference,FILE_MAX_BATCH_ITEMS,verifyFileBindingHistorical,type FileBinding } from './files.js';
import { base64urlDecode,verifyObject } from './crypto.js';
import type { PlanningSecurityResolver } from './planning-api.js';
export const DELIVERY_PERMIT_TTL_MS=30000;
export const deliveryItem=z.strictObject({operation:z.enum(['add','replace','move','rename','remove']),fileId:identifier,versionId:identifier,manifestDigest:digest,approvalId:identifier});
export const deliveryBatchBody=z.strictObject({purpose:z.literal('ukda.file-delivery.v1'),binding:fileBinding,batchId:identifier,supersedes:identifier.nullable(),
 items:z.array(deliveryItem).min(1).max(FILE_MAX_BATCH_ITEMS),metadata:fileEncryptedMetadata,details:fileEncryptedMetadata});
export const deliveryBatch=z.strictObject({body:deliveryBatchBody,signature:binary(64)});
export type DeliveryBatch=z.infer<typeof deliveryBatch>;export type DeliveryBatchBody=z.infer<typeof deliveryBatchBody>;
export function deliveryMetadataContext(body:DeliveryBatchBody,purpose:'key'|'details') {
 const {metadata:_metadata,details:_details,...rest}=body;return {...rest,purpose:`ukda.file-delivery-${purpose}.v1`};
}
export const deliveryCreateRequest=z.strictObject({batch:deliveryBatch});
export const deliveryBatchRequest=fileReference.extend({batchId:identifier});
export const deliveryListRequest=fileReference.extend({after:identifier.optional(),limit:z.number().int().min(1).max(100).default(50)});
export const deliveryCommandBody=z.strictObject({purpose:z.literal('ukda.file-delivery-command.v1'),binding:fileBinding,batchId:identifier,frozenDigest:digest,
 action:z.enum(['confirm','cancel','record_package'])});
export const deliveryCommandRequest=z.strictObject({mutation:z.strictObject({body:deliveryCommandBody,signature:binary(64)})});
export const localServiceClaim=z.strictObject({serviceId:identifier,publicKey:binary(32)});
export const deliveryPairContextRequest=fileReference.extend(localServiceClaim.shape);
export const deliveryPairChallenge=z.strictObject({pairingId:identifier,nonce:binary(32),issuedAt:z.iso.datetime(),expiresAt:z.iso.datetime()});
export const deliveryPairBody=z.strictObject({purpose:z.literal('ukda.file-service-pair.v1'),binding:fileBinding,...localServiceClaim.shape,
 pairingId:identifier,nonce:binary(32),metadata:fileEncryptedMetadata});
export const deliveryPairRequest=z.strictObject({approval:z.strictObject({body:deliveryPairBody,signature:binary(64)}),proof:binary(64)});
export function deliveryPairMetadataContext(body:z.infer<typeof deliveryPairBody>){const {metadata:_metadata,...rest}=body;return {...rest,purpose:'ukda.file-service-metadata.v1'};}
export const deliveryServiceRecord=z.strictObject({serviceId:identifier,publicKey:binary(32),state:z.enum(['active','revoked']),dataGeneration:positiveCounter,approval:deliveryPairRequest});
export const deliveryServices=z.strictObject({services:z.array(deliveryServiceRecord).max(100)});
export const deliveryServiceCommandRequest=z.strictObject({mutation:z.strictObject({body:z.strictObject({purpose:z.literal('ukda.file-service-revoke.v1'),binding:fileBinding,
 serviceId:identifier,publicKey:binary(32)}),signature:binary(64)})});
export const deliveryPermitRequest=deliveryBatchRequest.extend({serviceId:identifier,index:z.number().int().min(0).max(FILE_MAX_BATCH_ITEMS-1)});
export const deliveryPermitBody=z.strictObject({purpose:z.literal('ukda.file-delivery-permit.v1'),version:z.literal(1),keyId:z.string().min(1).max(64),origin:z.string().url(),
 workspaceId:identifier,projectId:identifier,batchId:identifier,frozenDigest:digest,serviceId:identifier,permitId:identifier,nonce:binary(32),
 index:z.number().int().min(0).max(FILE_MAX_BATCH_ITEMS-1),itemDigest:digest,securityHead:digest,securityVersion:counter,dataGeneration:positiveCounter,
 issuedAt:z.iso.datetime(),expiresAt:z.iso.datetime()});
export const deliveryPermit=z.strictObject({body:deliveryPermitBody,signature:binary(64)});export type DeliveryPermit=z.infer<typeof deliveryPermit>;
export const publicationReceiptBody=z.strictObject({purpose:z.literal('ukda.local-file-publication.v1'),serviceId:identifier,workspaceId:identifier,projectId:identifier,
 batchId:identifier,frozenDigest:digest,permitIds:z.array(identifier).min(1).max(FILE_MAX_BATCH_ITEMS).refine(v=>new Set(v).size===v.length),
 resultDigest:digest,startedAt:z.iso.datetime(),completedAt:z.iso.datetime()});
export const publicationReceipt=z.strictObject({body:publicationReceiptBody,signature:binary(64)});export type PublicationReceipt=z.infer<typeof publicationReceipt>;
export const deliveryPublishBody=z.strictObject({purpose:z.literal('ukda.file-delivery-published.v1'),binding:fileBinding,batchId:identifier,frozenDigest:digest,receipt:publicationReceipt});
export const deliveryPublishRequest=z.strictObject({mutation:z.strictObject({body:deliveryPublishBody,signature:binary(64)})});
export const deliveryStatusRequest=fileReference.extend({dataGeneration:positiveCounter,requestHash:digest});
export const deliveryReceipt=z.strictObject({version:z.literal(1),workspaceId:identifier,projectId:identifier,operationId:identifier,dataGeneration:positiveCounter,requestHash:digest,
 action:z.enum(['create','confirm','cancel','record_package','pair','revoke_service','publish']),batchId:identifier.nullable(),frozenDigest:digest.nullable(),committedAt:z.iso.datetime()});
export type DeliveryReceipt=z.infer<typeof deliveryReceipt>;
export const deliveryView=z.strictObject({state:z.enum(['completed','absent']),receipt:deliveryReceipt.nullable()});export type DeliveryView=z.infer<typeof deliveryView>;
export const deliveryRecord=z.strictObject({batch:deliveryBatch,frozenDigest:digest,state:z.enum(['frozen','confirmed','cancelled','superseded','published']),createdAt:z.iso.datetime(),
 confirmation:deliveryCommandRequest.shape.mutation.nullable(),publication:publicationReceipt.nullable(),packageDownloads:z.number().int().nonnegative()});
export type DeliveryRecord=z.infer<typeof deliveryRecord>;
export const deliveryPage=z.strictObject({entries:z.array(deliveryRecord).max(100),nextCursor:identifier.nullable(),complete:z.boolean()});
export const deliveryCheck=z.strictObject({batchId:identifier,frozenDigest:digest,state:z.literal('confirmed'),checkedAt:z.iso.datetime()});
export async function verifyDeliveryBatch(value:unknown,securityAt:PlanningSecurityResolver):Promise<DeliveryBatch> {
 const batch=deliveryBatch.parse(value),b=await verifyFileBindingHistorical(batch.body.binding,securityAt,true);
 if(!await verifyObject(batch,base64urlDecode(b.signingPublicKey),'ukda.file-delivery.v1'))throw new Error('Invalid delivery batch');return batch;
}
export async function verifyOwnerFileObject<T extends {purpose:string;binding:FileBinding}>(value:{body:T;signature:string},securityAt:PlanningSecurityResolver,purpose:string):Promise<void> {
 const b=await verifyFileBindingHistorical(value.body.binding,securityAt,true);if(!await verifyObject(value,base64urlDecode(b.signingPublicKey),purpose))throw new Error('Invalid Owner file operation');
}

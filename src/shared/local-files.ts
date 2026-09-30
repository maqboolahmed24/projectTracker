import { z } from 'zod';
import { binary,digest,identifier } from './contracts.js';
import { deliveryBatch,deliveryPairRequest,deliveryPermit,publicationReceipt } from './file-delivery.js';
import { FILE_MAX_PLAIN_BYTES,FILE_EXTERNAL_MAX_BYTES } from './files.js';
export const localRelativePath=z.string().trim().min(1).max(1024).refine(p=>!p.startsWith('/')&&!p.includes('\\')&&
  !/[\u0000-\u001f\u007f]/u.test(p)&&p.split('/').every(c=>c.length>0&&c!=='.'&&c!=='..'&&!c.toLowerCase().startsWith('.maqbool')));
export const deliveryDetails=z.strictObject({version:z.literal(1),label:z.string().trim().min(1).max(160),rootLabel:z.string().trim().min(1).max(160),
  items:z.array(z.strictObject({destination:localRelativePath,fromPath:localRelativePath.optional(),expectedOldSha256:digest.nullable(),sha256:digest,
    plainBytes:z.number().int().min(1).max(FILE_EXTERNAL_MAX_BYTES),filename:z.string().min(1).max(240),externalPath:z.string().min(1).max(4096).optional()})).min(1).max(64)});
export type DeliveryDetails=z.infer<typeof deliveryDetails>;
export const localServiceStatus=z.strictObject({version:z.literal(1),serviceId:identifier,publicKey:binary(32),rootLabel:z.string().min(1).max(160),officeAvailable:z.boolean()});
export const localPairRequest=z.strictObject({code:z.string().min(8).max(128),approval:deliveryPairRequest.shape.approval});
export const localPairResponse=z.strictObject({proof:binary(64),token:binary(32),serviceId:identifier});
export const localApplyRequest=z.strictObject({batch:deliveryBatch,permit:deliveryPermit,detailsKey:binary(32),bytes:binary(1,FILE_MAX_PLAIN_BYTES).optional()});
export const localBatchRequest=z.strictObject({batchId:identifier});
export const localOperationResult=z.strictObject({index:z.number().int().min(0).max(63),state:z.literal('verified'),permitId:identifier,
  sha256:digest.nullable(),completedAt:z.iso.datetime()});
export const localProgress=z.strictObject({batchId:identifier,frozenDigest:digest,complete:z.boolean(),results:z.array(localOperationResult).max(64),receipt:publicationReceipt.nullable()});

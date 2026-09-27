import { z } from 'zod';
import { binary,counter,digest,identifier,positiveCounter } from './contracts.js';
import { base64urlDecode,verifyObject } from './crypto.js';

export const inboxReference=z.strictObject({workspaceId:identifier,operationId:identifier});
export const inboxBinding=inboxReference.extend({version:z.literal(1),origin:z.string().url(),accountId:identifier,deviceId:identifier,
  signingPublicKey:binary(32),keyGeneration:positiveCounter,credentialGeneration:positiveCounter,sessionGeneration:positiveCounter,
  dataGeneration:positiveCounter,securityHead:digest,securityVersion:positiveCounter,issuedAt:z.iso.datetime(),expiresAt:z.iso.datetime()});
export type InboxBinding=z.infer<typeof inboxBinding>;
export const inboxCommand=z.discriminatedUnion('action',[
  z.strictObject({action:z.literal('set_read'),records:z.array(z.strictObject({id:identifier,expectedRevision:positiveCounter})).min(1).max(100)
    .refine(rows=>new Set(rows.map(row=>row.id)).size===rows.length),read:z.boolean()}),
  z.strictObject({action:z.literal('set_project_muted'),projectId:identifier,expectedRevision:counter,muted:z.boolean()}),
]);
export type InboxCommand=z.infer<typeof inboxCommand>;
export const inboxMutation=z.strictObject({body:z.strictObject({purpose:z.literal('ukda.inbox.v1'),binding:inboxBinding,command:inboxCommand}),signature:binary(64)});
export type InboxMutation=z.infer<typeof inboxMutation>;
export const inboxReceipt=z.strictObject({workspaceId:identifier,operationId:identifier,actorId:identifier,dataGeneration:positiveCounter,
  requestHash:digest,committedAt:z.iso.datetime(),revisions:z.array(z.strictObject({id:identifier,revision:positiveCounter})).max(100)});
export type InboxReceipt=z.infer<typeof inboxReceipt>;
export const inboxListRequest=z.strictObject({workspaceId:identifier,after:identifier.optional(),limit:z.number().int().min(1).max(100).default(50),unreadOnly:z.boolean().default(false)});
export const inboxNotice=z.strictObject({id:identifier,revision:positiveCounter,readAt:z.iso.datetime().nullable(),createdAt:z.iso.datetime(),
  eventType:z.string().max(64),projectId:identifier.nullable(),recordId:identifier.nullable(),unavailable:z.boolean()});
export const inboxPage=z.strictObject({records:z.array(inboxNotice).max(100),nextCursor:identifier.nullable(),dataGeneration:positiveCounter,securityHead:digest,securityVersion:positiveCounter});
export const inboxPreference=z.strictObject({projectId:identifier,muted:z.boolean(),revision:counter});
export async function validateInboxMutation(value:unknown):Promise<InboxMutation>{
  const parsed=inboxMutation.parse(value),b=parsed.body.binding;
  if(Date.parse(b.expiresAt)<=Date.parse(b.issuedAt)||Date.parse(b.expiresAt)-Date.parse(b.issuedAt)>600000||
    !await verifyObject(parsed,base64urlDecode(b.signingPublicKey,32),'ukda.inbox.v1'))throw new Error('Invalid Inbox change');
  return parsed;
}

import { z } from 'zod';
import { binary, counter, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, verifyObject } from './crypto.js';
import { planningContext, type PlanningBinding, type PlanningContext, type PlanningSecurityResolver } from './planning-api.js';

export const FILE_MAX_PLAIN_BYTES = 25 * 1024 * 1024;
export const FILE_WORKSPACE_QUOTA_BYTES = 2 * 1024 * 1024 * 1024;
export const FILE_EXTERNAL_MAX_BYTES = 2 * 1024 * 1024 * 1024;
export const FILE_CHUNK_PLAIN_BYTES = 256 * 1024;
/** Packed XChaCha20 nonce (24), ciphertext and authentication tag (16). */
export const FILE_CHUNK_OVERHEAD = 40;
export const FILE_MAX_CHUNKS = Math.ceil(FILE_MAX_PLAIN_BYTES / FILE_CHUNK_PLAIN_BYTES);
export const FILE_MAX_ACTIVE_UPLOADS = 4, FILE_MAX_BATCH_ITEMS = 64, FILE_MAX_BATCH_BYTES = 250 * 1024 * 1024;
export const FILE_MAX_DOCUMENT_TASKS = 512, FILE_MAX_PER_PROJECT = 4096;
export const FILE_MAX_METADATA_BYTES = 32 * 1024, FILE_MAX_REQUEST_BYTES = 512 * 1024;
export const FILE_SUPPORTED_EXTENSIONS = ['pdf','docx','xlsx','pptx','rtf','txt','csv','png','jpg','jpeg','webp'] as const;

export const fileBinding = z.strictObject({
  version: z.literal(1), workspaceId: identifier, projectId: identifier, operationId: identifier,
  origin: z.string().url(), accountId: identifier, deviceId: identifier,
  credentialGeneration: positiveCounter, sessionGeneration: positiveCounter, keyGeneration: positiveCounter,
  signingPublicKey: binary(32), permissionVersion: positiveCounter, keyEpoch: positiveCounter,
  securityVersion: counter, securityHead: digest, dataGeneration: positiveCounter,
  writeSchema: z.union([z.literal(1),z.literal(2)]), issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime(),
});
export type FileBinding = z.infer<typeof fileBinding>;
export function fileBindingFromPlanning(b: PlanningBinding): FileBinding {
  return fileBinding.parse({ version:1,workspaceId:b.workspaceId,projectId:b.projectId,operationId:b.operationId,origin:b.origin,
    accountId:b.accountId,deviceId:b.deviceId,credentialGeneration:b.credentialGeneration,sessionGeneration:b.sessionGeneration,
    keyGeneration:b.keyGeneration,signingPublicKey:b.signingPublicKey,permissionVersion:b.permissionVersion,keyEpoch:b.keyEpoch,
    securityVersion:b.securityVersion,securityHead:b.securityHead,dataGeneration:b.dataGeneration,
    writeSchema:b.version===3?b.writeSchema:1,issuedAt:b.issuedAt,expiresAt:b.expiresAt });
}
export function assertFileBindingCurrent(binding: FileBinding, planning: PlanningContext, now: Date): void {
  const current=fileBindingFromPlanning(planning.binding), issued=Date.parse(binding.issuedAt),expires=Date.parse(binding.expiresAt);
  if (canonicalJson({...binding,issuedAt:current.issuedAt,expiresAt:current.expiresAt})!==canonicalJson(current) ||
    !Number.isFinite(issued) || issued>now.getTime()+30000 || expires<=now.getTime() || expires-issued>600000 || expires<=issued)
    throw new Error('File authority changed');
}
const taskIds=z.array(identifier).max(FILE_MAX_BATCH_ITEMS).refine(ids=>new Set(ids).size===ids.length);
export const fileEncryptedMetadata=z.strictObject({nonce:binary(24),ciphertext:binary(16,FILE_MAX_METADATA_BYTES)});
export const fileManifestBody=z.strictObject({
  purpose:z.literal('ukda.file-version.v1'),binding:fileBinding,fileId:identifier,versionId:identifier,
  version:positiveCounter,priorVersionId:identifier.nullable(),kind:z.enum(['source','output']),storage:z.enum(['managed','external']),
  plainBytes:z.number().int().min(1).max(FILE_EXTERNAL_MAX_BYTES),cipherBytes:z.number().int().nonnegative().max(FILE_MAX_PLAIN_BYTES+FILE_MAX_CHUNKS*FILE_CHUNK_OVERHEAD),
  chunkHashes:z.array(digest).max(FILE_MAX_CHUNKS),metadata:fileEncryptedMetadata,taskIds,
}).superRefine((v,c)=>{
  if ((v.version==='1')!==(v.priorVersionId===null)) c.addIssue({code:'custom',message:'Invalid version lineage'});
  if(v.storage==='external') { if(v.cipherBytes!==0||v.chunkHashes.length) c.addIssue({code:'custom',message:'External references have no managed bytes'}); }
  else if(v.plainBytes>FILE_MAX_PLAIN_BYTES || v.chunkHashes.length!==Math.ceil(v.plainBytes/FILE_CHUNK_PLAIN_BYTES) ||
    v.cipherBytes!==v.plainBytes+v.chunkHashes.length*FILE_CHUNK_OVERHEAD) c.addIssue({code:'custom',message:'Invalid managed file length'});
});
export const fileManifest=z.strictObject({body:fileManifestBody,signature:binary(64)});
export type FileManifest=z.infer<typeof fileManifest>;
export type FileManifestBody=z.infer<typeof fileManifestBody>;
export const fileReference=z.strictObject({workspaceId:identifier,projectId:identifier,operationId:identifier});
export const fileVersionRequest=fileReference.extend({versionId:identifier});
export const fileBeginRequest=z.strictObject({manifest:fileManifest});
export const fileChunkRequest=fileVersionRequest.extend({index:z.number().int().min(0).max(FILE_MAX_CHUNKS-1),bytes:binary(FILE_CHUNK_OVERHEAD+1,FILE_CHUNK_PLAIN_BYTES+FILE_CHUNK_OVERHEAD)});
export const fileReadChunkRequest=fileVersionRequest.extend({index:z.number().int().min(0).max(FILE_MAX_CHUNKS-1),purpose:z.enum(['preview','download'])});
export const fileCancelRequest=fileVersionRequest;
export const fileListRequest=fileReference.extend({after:identifier.optional(),limit:z.number().int().min(1).max(100).default(50),taskId:identifier.optional(),kind:z.enum(['source','output']).optional()});
export const fileVersionsRequest=fileReference.extend({fileId:identifier,afterVersion:counter.default('0'),limit:z.number().int().min(1).max(100).default(50)});
export const fileLinkBody=z.strictObject({purpose:z.literal('ukda.file-links.v1'),binding:fileBinding,fileId:identifier,
  taskIds,mode:z.enum(['latest','pinned']),versionId:identifier.nullable(),action:z.enum(['link','unlink'])})
  .refine(v=>(v.mode==='pinned')===(v.versionId!==null));
export const fileLinkRequest=z.strictObject({mutation:z.strictObject({body:fileLinkBody,signature:binary(64)})});
export const fileStatusRequest=fileReference.extend({dataGeneration:positiveCounter,requestHash:digest});
export const fileEditorPermitRequest=fileVersionRequest.extend({serviceId:identifier});
export const fileEditorPermitBody=z.strictObject({purpose:z.literal('ukda.file-edit-permit.v1'),keyId:z.string().min(1).max(64),origin:z.string().url(),
 workspaceId:identifier,projectId:identifier,serviceId:identifier,versionId:identifier,manifestDigest:digest,accountId:identifier,deviceId:identifier,
 credentialGeneration:positiveCounter,sessionGeneration:positiveCounter,dataGeneration:positiveCounter,permissionVersion:positiveCounter,keyEpoch:positiveCounter,
 issuedAt:z.iso.datetime(),expiresAt:z.iso.datetime(),permitId:identifier,nonce:binary(32)});
export const fileEditorPermit=z.strictObject({body:fileEditorPermitBody,signature:binary(64)});export type FileEditorPermit=z.infer<typeof fileEditorPermit>;
export interface FileQuota {limitBytes:number;usedBytes:number;reservedBytes:number;activeUploads:number;deploymentRemainingBytes:number}
export interface FileContext {planning:PlanningContext;binding:FileBinding;quota:FileQuota}
export interface FileVersion {manifest:FileManifest;state:'staged'|'ready'|'cancelled';createdAt:string;completedAt:string|null;receivedIndexes:number[]}
export interface FileEntry {fileId:string;kind:'source'|'output';latestVersionId:string;version:FileVersion;links:{taskId:string;mode:'latest'|'pinned';versionId:string|null}[]}
export interface FilePage {entries:FileEntry[];nextCursor:string|null;complete:boolean;quota:FileQuota}
export interface FileVersionPage {versions:FileVersion[];nextVersion:string|null;complete:boolean}
export interface FileReceipt {version:1;workspaceId:string;projectId:string;operationId:string;dataGeneration:string;requestHash:string;action:'begin'|'complete'|'cancel'|'link'|'unlink';fileId:string;versionId:string|null;committedAt:string}
export interface FileView {state:'completed'|'absent';receipt:FileReceipt|null}
export const fileQuota=z.strictObject({limitBytes:z.number().int().positive(),usedBytes:z.number().int().nonnegative(),reservedBytes:z.number().int().nonnegative(),
 activeUploads:z.number().int().min(0).max(FILE_MAX_ACTIVE_UPLOADS),deploymentRemainingBytes:z.number().int().nonnegative()});
export const fileContext=z.strictObject({planning:planningContext,binding:fileBinding,quota:fileQuota}) satisfies z.ZodType<FileContext>;
export const fileVersion=z.strictObject({manifest:fileManifest,state:z.enum(['staged','ready','cancelled']),createdAt:z.iso.datetime(),completedAt:z.iso.datetime().nullable(),
 receivedIndexes:z.array(z.number().int().min(0).max(FILE_MAX_CHUNKS-1)).max(FILE_MAX_CHUNKS).refine(v=>new Set(v).size===v.length)}) satisfies z.ZodType<FileVersion>;
export const fileEntry=z.strictObject({fileId:identifier,kind:z.enum(['source','output']),latestVersionId:identifier,version:fileVersion,
 links:z.array(z.strictObject({taskId:identifier,mode:z.enum(['latest','pinned']),versionId:identifier.nullable()})).max(FILE_MAX_DOCUMENT_TASKS)}) satisfies z.ZodType<FileEntry>;
export const filePage=z.strictObject({entries:z.array(fileEntry).max(100),nextCursor:identifier.nullable(),complete:z.boolean(),quota:fileQuota}) satisfies z.ZodType<FilePage>;
export const fileVersionPage=z.strictObject({versions:z.array(fileVersion).max(100),nextVersion:positiveCounter.nullable(),complete:z.boolean()}) satisfies z.ZodType<FileVersionPage>;
export const fileReceipt=z.strictObject({version:z.literal(1),workspaceId:identifier,projectId:identifier,operationId:identifier,dataGeneration:positiveCounter,
 requestHash:digest,action:z.enum(['begin','complete','cancel','link','unlink']),fileId:identifier,versionId:identifier.nullable(),committedAt:z.iso.datetime()}) satisfies z.ZodType<FileReceipt>;
export const fileView=z.strictObject({state:z.enum(['completed','absent']),receipt:fileReceipt.nullable()}) satisfies z.ZodType<FileView>;
export async function fileChunkDigest(bytes:Uint8Array):Promise<string> {
  const hash=new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',new Uint8Array(bytes)));
  return Array.from(hash,b=>b.toString(16).padStart(2,'0')).join('');
}
/** A manifest is authenticated against its historical active approved device. Current read access is checked separately. */
export async function verifyFileBindingHistorical(value:unknown,securityAt:PlanningSecurityResolver,requireOwner=false):Promise<FileBinding> {
  const b=fileBinding.parse(value),security=await securityAt(b.securityVersion,b.securityHead),device=security.devices[b.deviceId],profile=security.profiles[b.accountId];
  const available=(scope:{scope:string;scopeId:string;keyEpoch:string;expiresAt:string|null})=>scope.scope==='project'&&scope.scopeId===b.projectId&&scope.keyEpoch===b.keyEpoch&&(scope.expiresAt===null||Date.parse(scope.expiresAt)>Date.parse(b.issuedAt));
  const personal=profile?.scopes.find(available),deviceScope=device?.scopes.find(available),role=profile?security.roles[profile.projectRoles[b.projectId]?.id??profile.role.id]:undefined;
  if(security.workspaceId!==b.workspaceId || security.origin!==b.origin || security.dataGeneration!==b.dataGeneration ||
    security.securityHead!==b.securityHead || security.securityVersion!==b.securityVersion || (security.writeSchema??1)!==b.writeSchema || !device || device.accountId!==b.accountId || !device.active ||
    !profile?.active || (requireOwner&&!profile.owner) || profile.credentialGeneration!==b.credentialGeneration || profile.sessionGeneration!==b.sessionGeneration ||
    !personal?.permissions.includes('read_project') || !deviceScope?.permissions.includes('read_project') || role?.revision!==b.permissionVersion ||
    security.scopeHeads[`project:${b.projectId}`]?.keyEpoch!==b.keyEpoch || device.signingPublicKey!==b.signingPublicKey || device.keyGeneration!==b.keyGeneration ||
    Date.parse(b.expiresAt)<=Date.parse(b.issuedAt) || Date.parse(b.expiresAt)-Date.parse(b.issuedAt)>600000 ||
    (security.lifecycle!==undefined&&security.lifecycle!=='active') || security.licenceState!=='active') throw new Error('Invalid file authority');
  return b;
}
export async function verifyFileManifest(value:unknown,securityAt:PlanningSecurityResolver):Promise<FileManifest> {
  const manifest=fileManifest.parse(value),b=await verifyFileBindingHistorical(manifest.body.binding,securityAt);
  if(!await verifyObject(manifest,base64urlDecode(b.signingPublicKey),'ukda.file-version.v1'))throw new Error('Invalid file manifest');
  return manifest;
}

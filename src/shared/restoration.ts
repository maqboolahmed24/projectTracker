import { z } from 'zod';
import { binary, contentEnvelope, contentHeader, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyObject } from './crypto.js';
import type { SecurityHistoryState } from './security-history.js';
import { fileManifest,FILE_CHUNK_PLAIN_BYTES,FILE_CHUNK_OVERHEAD,FILE_WORKSPACE_QUOTA_BYTES } from './files.js';

/** Deliberate, versioned recovery inventory. Operational queues, disposable caches,
 * sessions and authentication authority never come from the content snapshot. */
export const RESTORE_LEGACY_TABLES = ['workspaces','profiles','roles','teams','team_members','projects','project_access','scope_heads',
  'project_phases','milestones','tasks','task_assignments','blockers','comments','updates','record_versions','audit_events',
  'project_planning_heads','planning_operations','collaboration_operations','reporting_settings','reporting_operations',
  'encrypted_upgrades','encrypted_upgrade_sources','encrypted_upgrade_operations','encrypted_upgrade_items'] as const;
export const RESTORE_FILE_TABLES=['project_files','file_versions','file_chunks','task_file_links','file_operations','file_storage_usage','file_submissions','file_reviews','file_review_items','file_approval_revocations','file_evidence_operations','file_delivery_batches','file_delivery_operations','file_local_services'] as const;
export const RESTORE_DISPOSABLE_FILE_TABLES=['file_upload_reservations','file_service_pairings','file_delivery_permits','file_editor_permits'] as const;
export const RESTORE_TABLES=[...RESTORE_LEGACY_TABLES,...RESTORE_FILE_TABLES] as const;
export const RESTORE_ROW_MAX_BYTES=384*1024*1024,RESTORE_BINARY_MAX_BYTES=FILE_WORKSPACE_QUOTA_BYTES;
export const RESTORE_MAX_OBJECTS = 20000;
export const RESTORE_MAX_BYTES = 16 * 1024 * 1024;
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
const signed=<T extends z.ZodType>(body:T)=>z.strictObject({body,signature:binary(64)});
const source=z.strictObject({securityHead:digest,securityVersion:positiveCounter,dataGeneration:positiveCounter,writeSchema:z.union([z.literal(1),z.literal(2)])});
const service=z.strictObject({serviceKeyId:z.string().min(1).max(64),servicePublicKey:binary(32)});
export const restoreObjectRef=z.strictObject({digest,header:contentHeader,current:z.boolean()});
export const restoreKeyEpoch=z.strictObject({scope:z.enum(['workspace','project']),scopeId:identifier,keyEpoch:positiveCounter});
export const restoreKeyRef=z.strictObject({id:identifier,digest,kind:z.string().min(1).max(64)});
export const restoreMissingRecord=z.strictObject({kind:z.enum(['project','content_after_checkpoint']),id:identifier.nullable(),reason:z.literal('after_checkpoint'),knownRevision:positiveCounter.nullable()});
export const restoreFileRef=z.strictObject({fileId:identifier,versionId:identifier,projectId:identifier,keyEpoch:positiveCounter,manifestDigest:digest,storage:z.enum(['managed','external']),plainBytes:z.number().int().positive().max(FILE_WORKSPACE_QUOTA_BYTES),current:z.boolean()});
const inventoryFields={
  objects:z.array(restoreObjectRef).max(RESTORE_MAX_OBJECTS),keyEpochs:z.array(restoreKeyEpoch).max(RESTORE_MAX_OBJECTS),
  projectIds:z.array(identifier).max(RESTORE_MAX_OBJECTS),keyObjects:z.array(restoreKeyRef).max(RESTORE_MAX_OBJECTS),
};
const table=(names:readonly [string,...string[]])=>z.array(z.strictObject({table:z.enum(names),count:z.number().int().min(0).max(RESTORE_MAX_OBJECTS),digest})).length(names.length);
function canonicalInventory(v:{tables:{table:string}[];objects:{digest:string}[];projectIds:string[];keyObjects:{id:string}[];keyEpochs:{scope:string;scopeId:string;keyEpoch:string}[];files?:{versionId:string;manifestDigest:string}[]},c:z.RefinementCtx){
  for(const [values,key] of [[v.tables.map(x=>x.table),'tables'],[v.objects.map(x=>x.digest),'objects'],[v.projectIds,'projectIds'],[v.keyObjects.map(x=>x.id),'keyObjects'],
    [v.keyEpochs.map(x=>`${x.scope}:${x.scopeId}:${x.keyEpoch}`),'keyEpochs']] as const)
    if(new Set(values).size!==values.length||!same(values,[...values].sort()))c.addIssue({code:'custom',message:'Inventory must be unique and canonical',path:[key]});
  if(v.files&&(new Set(v.files.map(f=>f.versionId)).size!==v.files.length||new Set(v.files.map(f=>f.manifestDigest)).size!==v.files.length||!same(v.files.map(f=>f.manifestDigest),v.files.map(f=>f.manifestDigest).sort())))c.addIssue({code:'custom',message:'File inventory must be unique and canonical',path:['files']});
}
const inventoryLegacy=z.strictObject({...inventoryFields,tables:table(RESTORE_LEGACY_TABLES)}).superRefine(canonicalInventory);
const inventoryFull=z.strictObject({...inventoryFields,tables:table(RESTORE_TABLES),files:z.array(restoreFileRef).max(RESTORE_MAX_OBJECTS)}).superRefine(canonicalInventory);
const inventory=z.union([inventoryFull,inventoryLegacy]);
const checkpointFields={workspaceId:identifier,checkpointId:identifier,capturedAt:z.iso.datetime(),source,...service.shape};
export const restoreCheckpointManifest=z.union([signed(z.strictObject({...checkpointFields,version:z.literal(1),purpose:z.literal('ukda.content-checkpoint.v1'),inventory:inventoryLegacy})),signed(z.strictObject({...checkpointFields,version:z.literal(2),purpose:z.literal('ukda.content-checkpoint.v2'),inventory:inventoryFull}))]);
export type RestoreCheckpointManifest=z.infer<typeof restoreCheckpointManifest>;
export type RestoreInventory=z.infer<typeof inventory>;
export type RestoreMissingRecord=z.infer<typeof restoreMissingRecord>;
export const restoreStart=signed(z.strictObject({version:z.literal(1),purpose:z.literal('ukda.restore-start.v1'),workspaceId:identifier,restoreId:identifier,
  operationId:identifier,operatorId:identifier,supersedesRestoreId:identifier.nullable(),previousHead:digest,securityVersion:positiveCounter,dataGeneration:positiveCounter,nextDataGeneration:positiveCounter,
  manifestDigest:digest,checkpointId:identifier,changedAt:z.iso.datetime(),...service.shape}));
export type RestoreStart=z.infer<typeof restoreStart>;
const reconciledFields={workspaceId:identifier,restoreId:identifier,manifestDigest:digest,source,reconciledAt:z.iso.datetime(),objects:z.array(restoreObjectRef).max(RESTORE_MAX_OBJECTS),samples:z.array(digest).min(1).max(512),keyEpochs:z.array(restoreKeyEpoch).max(RESTORE_MAX_OBJECTS),missingRecords:z.array(restoreMissingRecord).max(RESTORE_MAX_OBJECTS),...service.shape};
export const restoreReconciledManifest=z.union([signed(z.strictObject({...reconciledFields,version:z.literal(1),purpose:z.literal('ukda.restore-manifest.v1')})),signed(z.strictObject({...reconciledFields,version:z.literal(2),purpose:z.literal('ukda.restore-manifest.v2'),files:z.array(restoreFileRef).max(RESTORE_MAX_OBJECTS),fileSamples:z.array(digest).max(32)}))]);
export type RestoreReconciledManifest=z.infer<typeof restoreReconciledManifest>;
export const restoreBinding=z.strictObject({version:z.literal(1),workspaceId:identifier,restoreId:identifier,operationId:identifier,origin:z.string().url(),
  accountId:identifier,deviceId:identifier,credentialGeneration:positiveCounter,sessionGeneration:positiveCounter,keyGeneration:positiveCounter,signingPublicKey:binary(32),
  securityHead:digest,securityVersion:positiveCounter,nextSecurityVersion:positiveCounter,dataGeneration:positiveCounter,custodyEpoch:positiveCounter,
  manifestDigest:digest,reconciledDigest:digest,issuedAt:z.iso.datetime(),expiresAt:z.iso.datetime()});
export type RestoreBinding=z.infer<typeof restoreBinding>;
const verifyFields={binding:restoreBinding,verifiedSamples:z.array(digest).min(1).max(512),verifiedKeyEpochs:z.array(restoreKeyEpoch).max(RESTORE_MAX_OBJECTS),missingContentAcknowledged:z.literal(true)};
export const restoreVerification=z.union([signed(z.strictObject({...verifyFields,version:z.literal(1),purpose:z.literal('ukda.restore-verify.v1')})),signed(z.strictObject({...verifyFields,version:z.literal(2),purpose:z.literal('ukda.restore-verify.v2'),verifiedFileSamples:z.array(digest).max(32)}))]);
export type RestoreVerification=z.infer<typeof restoreVerification>;
const material=z.strictObject({id:identifier,digest,kind:z.string().min(1).max(64),value:z.unknown()});
export const restoreContext=z.strictObject({binding:restoreBinding,checkpoint:restoreCheckpointManifest,reconciled:restoreReconciledManifest,
  samples:z.array(contentEnvelope).min(1).max(512),materials:z.array(material).max(RESTORE_MAX_OBJECTS),fileSamples:z.array(z.strictObject({manifest:fileManifest,chunk:binary(FILE_CHUNK_OVERHEAD+1,FILE_CHUNK_PLAIN_BYTES+FILE_CHUNK_OVERHEAD).nullable()})).max(32).optional()});
export type RestoreContext=z.infer<typeof restoreContext>;
export const restoreReference=z.strictObject({workspaceId:identifier,restoreId:identifier});
export const restoreContextRequest=restoreReference.extend({operationId:identifier});
export const restoreStatusRequest=restoreReference.extend({operationId:identifier.optional(),requestHash:digest.optional()});
export const restoreView=z.strictObject({state:z.enum(['quarantined','ready_for_verification','completed','aborted']),workspaceId:identifier,restoreId:identifier,
  dataGeneration:positiveCounter,manifestDigest:digest,missingRecords:z.array(restoreMissingRecord).max(RESTORE_MAX_OBJECTS),
  verification:restoreVerification.nullable()});
export type RestoreView=z.infer<typeof restoreView>;
export class RestoreVerificationError extends Error { constructor(){super('Restore verification failed');this.name='RestoreVerificationError';} }
function invalid():never{throw new RestoreVerificationError();}
export async function verifyRestoreServiceObject(value:RestoreCheckpointManifest|RestoreStart|RestoreReconciledManifest,keys:Record<string,string>):Promise<void>{
  const b=value.body;if(keys[b.serviceKeyId]!==b.servicePublicKey||!await verifyObject<RestoreCheckpointManifest['body']|RestoreStart['body']|RestoreReconciledManifest['body']>(value,base64urlDecode(b.servicePublicKey,32),b.purpose))invalid();
}
export function verifyRestoreOwner(b:RestoreBinding,state:SecurityHistoryState):void{
  const p=state.profiles[b.accountId],d=state.devices[b.deviceId],active=state.activeRestore;
  if(!p?.active||!p.owner||!d?.active||d.accountId!==b.accountId||d.keyGeneration!==b.keyGeneration||d.signingPublicKey!==b.signingPublicKey||
    b.workspaceId!==state.workspaceId||b.origin!==state.origin||b.securityHead!==state.securityHead||b.securityVersion!==state.securityVersion||
    b.nextSecurityVersion!==String(BigInt(state.securityVersion)+1n)||b.dataGeneration!==state.dataGeneration||b.custodyEpoch!==state.custodyEpoch||
    b.credentialGeneration!==p.credentialGeneration||b.sessionGeneration!==p.sessionGeneration||!state.restoreQuarantine||
    !active||active.restoreId!==b.restoreId||active.manifestDigest!==b.manifestDigest||state.lifecycle==='deleted')invalid();
  if(Date.parse(b.expiresAt)<=Date.parse(b.issuedAt)||Date.parse(b.expiresAt)-Date.parse(b.issuedAt)>600000)invalid();
  const eligible=(s:typeof p.scopes[number])=>s.scope==='workspace'&&s.scopeId===state.workspaceId&&s.mode==='custody'&&s.keyEpoch===state.custodyEpoch&&
    s.permissions.includes('read_project')&&(s.expiresAt===null||Date.parse(s.expiresAt)>Date.parse(b.issuedAt));
  if(!p.scopes.some(eligible)||!d.scopes.some(eligible))invalid();
}
/** Service authority can quarantine/increment the generation only. Only a current
 * Owner's separately signed verification can end that quarantine. */
export async function applyRestoreTransition(state:SecurityHistoryState,value:unknown,trustedServiceKeys:Record<string,string>):Promise<SecurityHistoryState>{
  const result=structuredClone(state),start=restoreStart.safeParse(value);
  if(start.success){const t=start.data,b=t.body;await verifyRestoreServiceObject(t,trustedServiceKeys);
    if(b.workspaceId!==state.workspaceId||b.previousHead!==state.securityHead||b.securityVersion!==String(BigInt(state.securityVersion)+1n)||
      b.dataGeneration!==state.dataGeneration||b.nextDataGeneration!==String(BigInt(state.dataGeneration)+1n)||state.lifecycle==='deleted'||b.supersedesRestoreId!==(state.activeRestore?.restoreId??null))invalid();
    result.dataGeneration=b.nextDataGeneration;result.restoreQuarantine=true;result.activeRestore={restoreId:b.restoreId,manifestDigest:b.manifestDigest};
    result.securityHead=await digestObject(t);result.securityVersion=b.securityVersion;return result;
  }
  const t=restoreVerification.parse(value),b=t.body.binding;verifyRestoreOwner(b,state);
  if(!await verifyObject<RestoreVerification['body']>(t,base64urlDecode(b.signingPublicKey,32),t.body.purpose))invalid();
  result.restoreQuarantine=false;result.activeRestore=null;result.securityHead=await digestObject(t);result.securityVersion=b.nextSecurityVersion;return result;
}
/** Public proof validation; decrypted sample values/keys never enter this object. */
export async function validateRestoreVerification(value:unknown,context:RestoreContext,state:SecurityHistoryState):Promise<RestoreVerification>{
  const v=restoreVerification.parse(value);verifyRestoreOwner(v.body.binding,state);
  if(!same(v.body.binding,context.binding)||!same(v.body.verifiedSamples,context.reconciled.body.samples)||
    !same(v.body.verifiedKeyEpochs,context.reconciled.body.keyEpochs)||!await verifyObject<RestoreVerification['body']>(v,base64urlDecode(context.binding.signingPublicKey,32),v.body.purpose))invalid();
  if(context.reconciled.body.version===2){if(v.body.version!==2||!same(v.body.verifiedFileSamples,context.reconciled.body.fileSamples))invalid();}else if(v.body.version!==1)invalid();
  return v;
}

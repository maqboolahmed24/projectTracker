import { z } from 'zod';
import { binary, contentEnvelope, contentHeader, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyObject } from './crypto.js';
import type { SecurityHistoryState } from './security-history.js';

/** Deliberate, versioned recovery inventory. Operational queues, disposable caches,
 * sessions and authentication authority never come from the content snapshot. */
export const RESTORE_TABLES = ['workspaces','profiles','roles','teams','team_members','projects','project_access','scope_heads',
  'project_phases','milestones','tasks','task_assignments','blockers','comments','updates','record_versions','audit_events',
  'project_planning_heads','planning_operations','collaboration_operations','reporting_settings','reporting_operations',
  'encrypted_upgrades','encrypted_upgrade_sources','encrypted_upgrade_operations','encrypted_upgrade_items'] as const;
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
const inventory=z.strictObject({
  tables:z.array(z.strictObject({table:z.enum(RESTORE_TABLES),count:z.number().int().min(0).max(RESTORE_MAX_OBJECTS),digest})).length(RESTORE_TABLES.length),
  objects:z.array(restoreObjectRef).max(RESTORE_MAX_OBJECTS),keyEpochs:z.array(restoreKeyEpoch).max(RESTORE_MAX_OBJECTS),
  projectIds:z.array(identifier).max(RESTORE_MAX_OBJECTS),keyObjects:z.array(restoreKeyRef).max(RESTORE_MAX_OBJECTS),
}).superRefine((v,c)=>{
  for(const [values,key] of [[v.tables.map(x=>x.table),'tables'],[v.objects.map(x=>x.digest),'objects'],[v.projectIds,'projectIds'],[v.keyObjects.map(x=>x.id),'keyObjects'],
    [v.keyEpochs.map(x=>`${x.scope}:${x.scopeId}:${x.keyEpoch}`),'keyEpochs']] as const)
    if(new Set(values).size!==values.length||!same(values,[...values].sort()))c.addIssue({code:'custom',message:'Inventory must be unique and canonical',path:[key]});
});
export const restoreCheckpointManifest=signed(z.strictObject({version:z.literal(1),purpose:z.literal('ukda.content-checkpoint.v1'),
  workspaceId:identifier,checkpointId:identifier,capturedAt:z.iso.datetime(),source,inventory,...service.shape}));
export type RestoreCheckpointManifest=z.infer<typeof restoreCheckpointManifest>;
export type RestoreInventory=z.infer<typeof inventory>;
export type RestoreMissingRecord=z.infer<typeof restoreMissingRecord>;
export const restoreStart=signed(z.strictObject({version:z.literal(1),purpose:z.literal('ukda.restore-start.v1'),workspaceId:identifier,restoreId:identifier,
  operationId:identifier,operatorId:identifier,supersedesRestoreId:identifier.nullable(),previousHead:digest,securityVersion:positiveCounter,dataGeneration:positiveCounter,nextDataGeneration:positiveCounter,
  manifestDigest:digest,checkpointId:identifier,changedAt:z.iso.datetime(),...service.shape}));
export type RestoreStart=z.infer<typeof restoreStart>;
export const restoreReconciledManifest=signed(z.strictObject({version:z.literal(1),purpose:z.literal('ukda.restore-manifest.v1'),workspaceId:identifier,restoreId:identifier,
  manifestDigest:digest,source,reconciledAt:z.iso.datetime(),objects:z.array(restoreObjectRef).max(RESTORE_MAX_OBJECTS),
  samples:z.array(digest).min(1).max(512),keyEpochs:z.array(restoreKeyEpoch).max(RESTORE_MAX_OBJECTS),
  missingRecords:z.array(restoreMissingRecord).max(RESTORE_MAX_OBJECTS),...service.shape}));
export type RestoreReconciledManifest=z.infer<typeof restoreReconciledManifest>;
export const restoreBinding=z.strictObject({version:z.literal(1),workspaceId:identifier,restoreId:identifier,operationId:identifier,origin:z.string().url(),
  accountId:identifier,deviceId:identifier,credentialGeneration:positiveCounter,sessionGeneration:positiveCounter,keyGeneration:positiveCounter,signingPublicKey:binary(32),
  securityHead:digest,securityVersion:positiveCounter,nextSecurityVersion:positiveCounter,dataGeneration:positiveCounter,custodyEpoch:positiveCounter,
  manifestDigest:digest,reconciledDigest:digest,issuedAt:z.iso.datetime(),expiresAt:z.iso.datetime()});
export type RestoreBinding=z.infer<typeof restoreBinding>;
export const restoreVerification=signed(z.strictObject({version:z.literal(1),purpose:z.literal('ukda.restore-verify.v1'),binding:restoreBinding,
  verifiedSamples:z.array(digest).min(1).max(512),verifiedKeyEpochs:z.array(restoreKeyEpoch).max(RESTORE_MAX_OBJECTS),missingContentAcknowledged:z.literal(true)}));
export type RestoreVerification=z.infer<typeof restoreVerification>;
const material=z.strictObject({id:identifier,digest,kind:z.string().min(1).max(64),value:z.unknown()});
export const restoreContext=z.strictObject({binding:restoreBinding,checkpoint:restoreCheckpointManifest,reconciled:restoreReconciledManifest,
  samples:z.array(contentEnvelope).min(1).max(512),materials:z.array(material).max(RESTORE_MAX_OBJECTS)});
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
  if(!await verifyObject(t,base64urlDecode(b.signingPublicKey,32),'ukda.restore-verify.v1'))invalid();
  result.restoreQuarantine=false;result.activeRestore=null;result.securityHead=await digestObject(t);result.securityVersion=b.nextSecurityVersion;return result;
}
/** Public proof validation; decrypted sample values/keys never enter this object. */
export async function validateRestoreVerification(value:unknown,context:RestoreContext,state:SecurityHistoryState):Promise<RestoreVerification>{
  const v=restoreVerification.parse(value);verifyRestoreOwner(v.body.binding,state);
  if(!same(v.body.binding,context.binding)||!same(v.body.verifiedSamples,context.reconciled.body.samples)||
    !same(v.body.verifiedKeyEpochs,context.reconciled.body.keyEpochs)||!await verifyObject(v,base64urlDecode(context.binding.signingPublicKey,32),'ukda.restore-verify.v1'))invalid();
  return v;
}

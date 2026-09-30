import { z } from 'zod';
import { binary, permissionCapabilities, contentEnvelope, counter, digest, identifier, positiveCounter, type ContentEnvelope } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyContentEnvelope, verifyObject } from './crypto.js';
import { planningContext, planningAuthority, planningContentHeader, initialPlanningGraph, applyPlanningSecurityCleanup,
  type PlanningBinding, type PlanningContext, type PlanningSecurityResolver } from './planning-api.js';
import { assertTaskPlanningScope, evaluatePlanning, upgradePlanningGraph, type PlanningState } from './planning.js';
import { decidePermission, type PermissionAction } from './permissions.js';
import type { SecurityHistoryState } from './security-history.js';
import { upgradeItem, upgradeProof, validateUpgradeItems, verifyUpgradeItem, type UpgradeItem } from './encrypted-upgrades.js';

export const COLLABORATION_MAX_TEXT = 20_000, COLLABORATION_MAX_PAYLOAD_BYTES = 512 * 1024,
  COLLABORATION_MAX_PAGE_SIZE = 100, COLLABORATION_MAX_PAGE_BYTES = 8 * 1024 * 1024;
export const collaborationText = z.strictObject({ text: z.string().trim().min(1).max(COLLABORATION_MAX_TEXT) });
export const collaborationReason = z.string().trim().min(1).max(COLLABORATION_MAX_TEXT);
export const collaborationKind = z.enum(['comment','update']);
export const collaborationReference = z.strictObject({workspaceId:identifier,projectId:identifier,operationId:identifier});
export const collaborationContextRequest = collaborationReference.extend({entryId:identifier,kind:collaborationKind});
export const collaborationBindingV1 = collaborationContextRequest.extend({version:z.literal(1),origin:z.string().url(),accountId:identifier,deviceId:identifier,
  credentialGeneration:positiveCounter,sessionGeneration:positiveCounter,keyGeneration:positiveCounter,signingPublicKey:binary(32),
  permissionVersion:positiveCounter,permissions:z.array(z.enum(permissionCapabilities)),isOwner:z.boolean(),keyEpoch:positiveCounter,
  securityVersion:positiveCounter,securityHead:digest,dataGeneration:positiveCounter,
  planningAnchor:z.strictObject({version:counter,head:digest}),issuedAt:z.iso.datetime(),expiresAt:z.iso.datetime()});
export const collaborationBindingV2=collaborationBindingV1.extend({version:z.literal(2),writeSchema:z.union([z.literal(1),z.literal(2)])});
export const collaborationBinding=z.union([collaborationBindingV1,collaborationBindingV2]);
export type CollaborationBinding = z.infer<typeof collaborationBinding>;
const hide = {entryId:identifier,expectedRevision:positiveCounter,previousHead:digest,originalDigest:digest};
export const collaborationCommand = z.discriminatedUnion('action',[
  z.strictObject({action:z.literal('post_comment'),entryId:identifier,taskId:identifier}),
  z.strictObject({action:z.literal('post_update'),entryId:identifier,phaseId:identifier.nullable()}),
  z.strictObject({action:z.literal('hide_comment'),...hide}),z.strictObject({action:z.literal('hide_update'),...hide}),
  z.strictObject({action:z.literal('upgrade_content'),...hide}),
]);
export type CollaborationCommand = z.infer<typeof collaborationCommand>;
const objectRef = z.strictObject({id:identifier,digest});
const mutationBody={command:collaborationCommand,contentDigest:digest.nullable(),audit:objectRef};
export const collaborationMutation = z.union([
  z.strictObject({body:z.strictObject({purpose:z.literal('ukda.collaboration.v1'),binding:collaborationBindingV1,...mutationBody}),signature:binary(64)}),
  z.strictObject({body:z.strictObject({purpose:z.literal('ukda.collaboration.v2'),binding:collaborationBindingV2,...mutationBody,upgrade:upgradeProof.optional()}),signature:binary(64)})]);
export type CollaborationMutation = z.infer<typeof collaborationMutation>;
export const collaborationPayload = z.strictObject({mutation:collaborationMutation,content:contentEnvelope.nullable(),audit:z.strictObject({id:identifier,envelope:contentEnvelope}),upgradeItems:z.array(upgradeItem).length(1).optional()});
export type CollaborationPayload = z.infer<typeof collaborationPayload>;
export const collaborationEntry = z.strictObject({origin:z.discriminatedUnion('kind',[
  z.strictObject({kind:z.literal('post'),payload:collaborationPayload}),
  z.strictObject({kind:z.literal('planning'),operationId:identifier,entryId:identifier}),
]),moderation:collaborationPayload.nullable(),events:z.array(collaborationPayload).max(32).optional()});
export type CollaborationEntry = z.infer<typeof collaborationEntry>;
export const collaborationContext = z.strictObject({planning:planningContext,binding:collaborationBinding,entry:collaborationEntry.nullable()});
export type CollaborationContext = Omit<z.infer<typeof collaborationContext>,'planning'> & {planning:PlanningContext};
export const collaborationReceipt = z.strictObject({version:z.literal(1),workspaceId:identifier,projectId:identifier,operationId:identifier,entryId:identifier,kind:collaborationKind,
  revision:positiveCounter,head:digest,dataGeneration:positiveCounter,requestHash:digest,committedAt:z.iso.datetime(),mutation:collaborationMutation});
export type CollaborationReceipt = z.infer<typeof collaborationReceipt>;
export const collaborationView = z.strictObject({state:z.enum(['absent','completed']),receipt:collaborationReceipt.nullable()});
export type CollaborationView = z.infer<typeof collaborationView>;
export const collaborationStatusRequest = collaborationReference.extend({dataGeneration:positiveCounter,requestHash:digest});
export const collaborationListRequest = z.strictObject({workspaceId:identifier,projectId:identifier,kind:collaborationKind,
  taskId:identifier.optional(),phaseId:identifier.optional(),includeHidden:z.boolean().optional(),anchor:digest.optional(),after:identifier.optional(),limit:z.number().int().min(1).max(COLLABORATION_MAX_PAGE_SIZE).default(50)})
  .refine((v)=>(v.kind === 'comment' ? v.phaseId === undefined : v.taskId === undefined) && (v.after === undefined || v.anchor !== undefined));
export const collaborationPage = z.strictObject({planning:planningContext,entries:z.array(collaborationEntry).max(COLLABORATION_MAX_PAGE_SIZE),anchor:digest,nextCursor:identifier.nullable(),complete:z.boolean()});
export type CollaborationPage = Omit<z.infer<typeof collaborationPage>,'planning'> & {planning:PlanningContext};
export const collaborationHistoryRequest = collaborationContextRequest;
export const collaborationHistory = z.strictObject({planning:planningContext,entry:collaborationEntry});
export type CollaborationHistory = Omit<z.infer<typeof collaborationHistory>,'planning'> & {planning:PlanningContext};
const legacyAudit = z.strictObject({version:z.literal(1),action:z.enum(['post_comment','post_update','hide_comment','hide_update']),
  entryId:identifier,originalDigest:digest,beforeHidden:z.literal(false).nullable(),afterHidden:z.boolean(),reason:collaborationReason.nullable()})
  .refine(v=>v.action.startsWith('post_')?v.beforeHidden===null&&v.afterHidden===false&&v.reason===null:v.beforeHidden===false&&v.afterHidden===true&&v.reason!==null);
export const collaborationAudit=z.union([legacyAudit,z.strictObject({version:z.literal(2),action:z.literal('upgrade_content'),entryId:identifier,
  originalDigest:digest,beforeHidden:z.boolean(),afterHidden:z.boolean(),reason:z.null()}).refine(value=>value.beforeHidden===value.afterHidden)]);
export type CollaborationAudit = z.infer<typeof collaborationAudit>;

export interface CollaborationMetadata {
  workspaceId:string;projectId:string;entryId:string;kind:'comment'|'update';taskId:string|null;phaseId:string|null;
  revision:string;head:string;originHead:string;hidden:boolean;originalDigest:string;authorId:string;createdAt:string;
  moderatedBy:string|null;moderatedAt:string|null;
  lineageHeads?:{revision:string;head:string}[];
}
export interface VerifiedCollaborationEntry extends CollaborationMetadata {
  original:ContentEnvelope; originalHeader:ContentEnvelope['header']; signingPublicKey:string;
  auditHeaders:{id:string;envelope:ContentEnvelope;header:ContentEnvelope['header'];signingPublicKey:string}[];
  origin:CollaborationEntry['origin']; moderation:CollaborationPayload|null;
  current:ContentEnvelope;currentHeader:ContentEnvelope['header'];currentSigningPublicKey:string;
  representations:{item:UpgradeItem;sourceHeader:ContentEnvelope['header'];sourceSigningPublicKey:string;targetHeader:ContentEnvelope['header'];targetSigningPublicKey:string}[];
}
export type CollaborationFailure='invalid_context'|'permission_denied'|'scope_read_only'|'not_found'|'revision_conflict'|'already_exists'|'invalid_signature';
export class CollaborationError extends Error { constructor(readonly code:CollaborationFailure){super(code);this.name='CollaborationError';} }
function fail(code:CollaborationFailure):never { throw new CollaborationError(code); }
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
const isPost=(command:CollaborationCommand)=>command.action==='post_comment'||command.action==='post_update';
export function collaborationBindingFromPlanning(planning:PlanningBinding,entry:{entryId:string;kind:'comment'|'update'}):CollaborationBinding {
  return collaborationBinding.parse({...(planning.version===3?{version:2,writeSchema:planning.writeSchema}:{version:1}),...entry,workspaceId:planning.workspaceId,projectId:planning.projectId,operationId:planning.operationId,
    origin:planning.origin,accountId:planning.accountId,deviceId:planning.deviceId,credentialGeneration:planning.credentialGeneration,sessionGeneration:planning.sessionGeneration,
    keyGeneration:planning.keyGeneration,signingPublicKey:planning.signingPublicKey,permissionVersion:planning.permissionVersion,permissions:planning.permissions,isOwner:planning.isOwner,
    keyEpoch:planning.keyEpoch,securityVersion:planning.securityVersion,securityHead:planning.securityHead,dataGeneration:planning.dataGeneration,
    planningAnchor:{version:planning.beforeVersion,head:planning.beforeHead},issuedAt:planning.issuedAt,expiresAt:planning.expiresAt});
}
export function collaborationHeader(binding:CollaborationBinding,kind:'comment'|'update'|'audit',id:string=binding.entryId,revision='1'):ContentEnvelope['header'] {
  return {version:1,purpose:'ukda.content.v1',algorithm:'XChaCha20-Poly1305',workspaceId:binding.workspaceId,scope:'project',scopeId:binding.projectId,recordId:id,recordType:kind,
    schema:binding.version===2?binding.writeSchema:1,keyEpoch:binding.keyEpoch,revision,operationId:binding.operationId,accountId:binding.accountId,deviceId:binding.deviceId,keyGeneration:binding.keyGeneration,
    permissionVersion:binding.permissionVersion,securityVersion:binding.securityVersion,securityHead:binding.securityHead,dataGeneration:binding.dataGeneration,
    action:'collaboration.change',approvalPolicyId:null,approvalPolicyRevision:null};
}

/** Compare current security authority, deliberately excluding the preparation-only planning anchor. */
export async function assertCollaborationCurrentBinding(binding:CollaborationBinding,planning:PlanningContext,now=new Date()):Promise<void> {
  const expected=collaborationBindingFromPlanning(planning.binding,{entryId:binding.entryId,kind:binding.kind});
  if(!same(binding,{...expected,planningAnchor:binding.planningAnchor,issuedAt:binding.issuedAt,expiresAt:binding.expiresAt}) ||
    Date.parse(binding.issuedAt)>now.getTime()+30_000 || Date.parse(binding.expiresAt)<=now.getTime() ||
    Date.parse(binding.expiresAt)<=Date.parse(binding.issuedAt) || Date.parse(binding.expiresAt)-Date.parse(binding.issuedAt)>600_000) fail('invalid_context');
  await assertPlanningAnchor(binding,planning);
}
async function assertPlanningAnchor(binding:CollaborationBinding,planning:PlanningContext):Promise<void> {
  const version=BigInt(binding.planningAnchor.version);
  if(binding.workspaceId!==planning.binding.workspaceId || binding.projectId!==planning.binding.projectId || version>BigInt(planning.history.length)) fail('invalid_context');
  const anchored=version===0n?planning.creation:planning.history[Number(version-1n)];
  if(!anchored || await digestObject(anchored)!==binding.planningAnchor.head) fail('invalid_context');
}
/** Historical authority comes from authenticated security-history prefixes, never current role labels. */
export function verifyCollaborationBinding(binding:CollaborationBinding,security:SecurityHistoryState):void {
  const p=security.profiles[binding.accountId],d=security.devices[binding.deviceId],key=security.scopeHeads[`project:${binding.projectId}`];
  const available=(scope:{scope:string;scopeId:string;keyEpoch:string;expiresAt:string|null})=>scope.scope==='project'&&scope.scopeId===binding.projectId&&scope.keyEpoch===binding.keyEpoch&&
    (scope.expiresAt===null||Date.parse(scope.expiresAt)>Date.parse(binding.issuedAt));
  const personal=p?.scopes.find(available),device=d?.scopes.find(available),role=p?security.roles[p.projectRoles[binding.projectId]?.id??p.role.id]:undefined;
  const permissions=personal?.permissions.filter((permission)=>device?.permissions.includes(permission));
  if(security.workspaceId!==binding.workspaceId||security.origin!==binding.origin||security.securityHead!==binding.securityHead||security.securityVersion!==binding.securityVersion||
    security.dataGeneration!==binding.dataGeneration||security.licenceState!=='active'||security.entitlementState!=='activated'||!p?.active||!d?.active||d.accountId!==p.accountId||p.owner!==binding.isOwner||
    p.credentialGeneration!==binding.credentialGeneration||p.sessionGeneration!==binding.sessionGeneration||d.keyGeneration!==binding.keyGeneration||d.signingPublicKey!==binding.signingPublicKey||
    key?.keyEpoch!==binding.keyEpoch||role?.revision!==binding.permissionVersion||!permissions?.includes('read_project')||!same(permissions,binding.permissions)||
    (binding.version===2?binding.writeSchema:1)!==(security.writeSchema??1)&&!security.activeUpgrade||
    Date.parse(binding.expiresAt)<=Date.parse(binding.issuedAt)||Date.parse(binding.expiresAt)-Date.parse(binding.issuedAt)>600_000) fail('permission_denied');
}
function authorize(binding:CollaborationBinding,action:PermissionAction,task?:PlanningState['tasks'][number]):void {
  if(!decidePermission({actor:{workspaceId:binding.workspaceId,accountId:binding.accountId,active:true,isOwner:false},action,
    target:{workspaceId:binding.workspaceId,projectId:binding.projectId},
    access:{workspaceId:binding.workspaceId,projectId:binding.projectId,accountId:binding.accountId,state:'active',keysReady:true,permissions:binding.permissions},
    ...(task?{task:{workspaceId:task.workspaceId,projectId:task.projectId,assigneeIds:[...task.assigneeIds]}}:{})}).allowed) fail('permission_denied');
}
export type CollaborationChange=Omit<CollaborationMetadata,'head'|'originHead'|'originalDigest'>;
/** No global expected project revision: two independently identified posts can both commit. */
export function evaluateCollaboration(command:CollaborationCommand,binding:CollaborationBinding,graph:PlanningState,entry:VerifiedCollaborationEntry|null=null):CollaborationChange {
  if(command.entryId!==binding.entryId||binding.workspaceId!==graph.project.workspaceId||binding.projectId!==graph.project.id||
    command.action!=='upgrade_content'&&(command.action.endsWith('_comment')?'comment':'update')!==binding.kind) fail('invalid_context');
  if(isPost(command)) {
    if(entry) fail('already_exists');
    let taskId:string|null=null,phaseId:string|null=null;
    if(command.action==='post_comment') {
      const task=graph.tasks.find(t=>t.id===command.taskId);if(!task) fail('not_found');
      authorize(binding,'comments.create',task);
      if(task.state==='done'||task.state==='cancelled') fail('scope_read_only');
      try{assertTaskPlanningScope(graph,task.phaseId);}catch{fail('scope_read_only');}
      taskId=task.id;
    } else if(command.action==='post_update') {
      authorize(binding,'updates.create');
      try{assertTaskPlanningScope(graph,command.phaseId);}catch{fail('scope_read_only');}
      phaseId=command.phaseId;
    } else fail('invalid_context');
    return {workspaceId:binding.workspaceId,projectId:binding.projectId,entryId:binding.entryId,kind:binding.kind,taskId,phaseId,revision:'1',hidden:false,
      authorId:binding.accountId,createdAt:binding.issuedAt,moderatedBy:null,moderatedAt:null};
  }
  if(!entry||entry.entryId!==binding.entryId||entry.kind!==binding.kind||entry.workspaceId!==binding.workspaceId||entry.projectId!==binding.projectId) fail('not_found');
  if(command.action!=='hide_comment'&&command.action!=='hide_update'&&command.action!=='upgrade_content') fail('invalid_context');
  if(entry.revision!==command.expectedRevision||entry.head!==command.previousHead||entry.originalDigest!==command.originalDigest) fail('revision_conflict');
  if(command.action==='upgrade_content') {
    if(binding.version!==2||binding.writeSchema!==2||!binding.isOwner||!binding.permissions.includes('plan_projects')) fail('permission_denied');
    return {workspaceId:entry.workspaceId,projectId:entry.projectId,entryId:entry.entryId,kind:entry.kind,taskId:entry.taskId,phaseId:entry.phaseId,
      revision:String(BigInt(entry.revision)+1n),hidden:entry.hidden,authorId:entry.authorId,createdAt:entry.createdAt,moderatedBy:entry.moderatedBy,moderatedAt:entry.moderatedAt};
  }
  if(entry.hidden||binding.version===1&&command.expectedRevision!=='1') fail('revision_conflict');
  if(command.action==='hide_comment') {
    const task=graph.tasks.find(t=>t.id===entry.taskId);if(!task) fail('not_found');authorize(binding,'comments.moderate',task);
  }else authorize(binding,'updates.moderate');
  // Moderation is an explicit exception to terminal/archived lifecycle restrictions.
  return {workspaceId:entry.workspaceId,projectId:entry.projectId,entryId:entry.entryId,kind:entry.kind,taskId:entry.taskId,phaseId:entry.phaseId,
    revision:String(BigInt(entry.revision)+1n),hidden:true,authorId:entry.authorId,createdAt:entry.createdAt,moderatedBy:binding.accountId,moderatedAt:binding.issuedAt};
}
async function validateCryptography(value:unknown):Promise<CollaborationPayload> {
  if(new TextEncoder().encode(canonicalJson(value)).byteLength>COLLABORATION_MAX_PAYLOAD_BYTES) fail('invalid_context');
  const payload=collaborationPayload.parse(value),body=payload.mutation.body,b=body.binding,post=isPost(body.command),key=base64urlDecode(b.signingPublicKey,32);
  if(body.command.entryId!==b.entryId||body.command.action!=='upgrade_content'&&(body.command.action.endsWith('_comment')?'comment':'update')!==b.kind||
    payload.audit.id===b.entryId||body.audit.id!==payload.audit.id||body.audit.digest!==await digestObject(payload.audit.envelope)||
    !await verifyObject<CollaborationMutation['body']>(payload.mutation,key,body.purpose)||
    !await verifyContentEnvelope(payload.audit.envelope,key,collaborationHeader(b,'audit',payload.audit.id))) fail('invalid_signature');
  if(post) {
    if(!payload.content||body.contentDigest!==await digestObject(payload.content)||!await verifyContentEnvelope(payload.content,key,collaborationHeader(b,b.kind))) fail('invalid_signature');
  } else if(body.command.action==='upgrade_content') {
    if(body.purpose!=='ukda.collaboration.v2'||!body.upgrade||!payload.upgradeItems||!payload.content) fail('invalid_context');
    const {items}=await validateUpgradeItems(body.upgrade,payload.upgradeItems),item=items[0]!;
    if(items.length!==1||item.source.kind!==b.kind||item.source.id!==b.entryId||item.source.projectId!==b.projectId||
      item.source.revision!==body.command.expectedRevision||item.target.digest!==body.contentDigest||!same(item.envelope,payload.content)) fail('invalid_context');
    await verifyUpgradeItem(item,item.sourceEnvelope,collaborationHeader(b,b.kind,b.entryId,item.target.envelopeRevision),key);
  } else if(payload.content!==null||body.contentDigest!==null) fail('invalid_context');
  if(body.command.action!=='upgrade_content'&&(payload.upgradeItems||body.purpose==='ukda.collaboration.v2'&&body.upgrade)) fail('invalid_context');
  return payload;
}
/** Caller supplies current trusted authority/current locked graph and independently verified current entry. */
export async function validateCollaborationPayload(value:unknown,binding:CollaborationBinding,currentGraph:PlanningState,entry:VerifiedCollaborationEntry|null=null):Promise<{payload:CollaborationPayload;result:CollaborationMetadata}> {
  const payload=await validateCryptography(value),body=payload.mutation.body;
  if(!same(binding,body.binding)) fail('invalid_context');
  if(entry && (entry.auditHeaders.some(a=>a.id===payload.audit.id) || binding.operationId===(entry.origin.kind==='post'?entry.origin.payload.mutation.body.binding.operationId:entry.origin.operationId))) fail('invalid_context');
  const changed=evaluateCollaboration(body.command,binding,currentGraph,entry);
  if(body.command.action==='upgrade_content') {
    const item=payload.upgradeItems![0]!;
    if(!entry||!same(item.sourceEnvelope,entry.current)||item.source.envelopeRevision!==entry.currentHeader.revision||
      item.source.digest!==await digestObject(entry.current)) fail('revision_conflict');
  }
  const head=await digestObject(payload.mutation);
  return {payload,result:{...changed,head,originHead:isPost(body.command)?head:entry!.originHead,originalDigest:isPost(body.command)?body.contentDigest!:entry!.originalDigest}};
}
async function cleanupThrough(graph:PlanningState,from:string,security:SecurityHistoryState,at:string,securityAt:PlanningSecurityResolver):Promise<PlanningState> {
  if(BigInt(from)>BigInt(security.securityVersion)) fail('invalid_context');
  for(let version=BigInt(from)+1n;version<BigInt(security.securityVersion);version++) {
    const state=await securityAt(version.toString());
    if(state.workspaceId!==security.workspaceId||state.securityVersion!==version.toString()) fail('invalid_context');
    graph=applyPlanningSecurityCleanup(graph,state,'1970-01-01T00:00:00.000Z');
  }
  return applyPlanningSecurityCleanup(graph,security,at);
}
/** Reuse an already verified planning history for historical lifecycle provenance; this does not create another ledger. */
async function anchoredGraph(binding:CollaborationBinding,planning:PlanningContext,securityAt:PlanningSecurityResolver):Promise<PlanningState> {
  await assertPlanningAnchor(binding,planning);
  let graph=initialPlanningGraph(planning.creation),securityVersion=planning.creation.body.binding.nextSecurityVersion;
  for(const mutation of planning.history.slice(0,Number(binding.planningAnchor.version))) {
    const b=mutation.body.binding,security=await securityAt(b.securityVersion,b.securityHead);
    if(b.version!==1) graph=upgradePlanningGraph(graph);
    graph=await cleanupThrough(graph,securityVersion,security,b.issuedAt,securityAt);securityVersion=security.securityVersion;
    graph=evaluatePlanning(graph,mutation.body.command,planningAuthority(b)).state;
  }
  const security=await securityAt(binding.securityVersion,binding.securityHead);
  verifyCollaborationBinding(binding,security);
  return cleanupThrough(graph,securityVersion,security,binding.issuedAt,securityAt);
}
function planningOutcomePhase(planning:PlanningContext,operationId:string):string|null {
  const mutation=planning.history.find(m=>m.body.binding.operationId===operationId);if(!mutation) fail('not_found');
  const command=mutation.body.command;
  if('phaseId' in command) return command.phaseId;
  if('milestoneId' in command) return planning.graph.snapshots.find(s=>s.operationId===operationId)?.milestones.find(m=>m.id===command.milestoneId)?.phaseId??null;
  return null;
}
/**
 * `planning` must have passed verifyPlanningContext under the caller's authenticated
 * security history. Returned entries are authenticated; signatures do not prove
 * that the server returned every unseen post or moderation. Known-entry pins
 * detect rollback only for entries the client has previously observed.
 */
export async function verifyCollaborationEntry(value:unknown,planning:PlanningContext,securityAt:PlanningSecurityResolver):Promise<VerifiedCollaborationEntry> {
  const entry=collaborationEntry.parse(value);
  let verified:VerifiedCollaborationEntry;
  if(entry.origin.kind==='post') {
    const payload=await validateCryptography(entry.origin.payload),body=payload.mutation.body,b=body.binding;
    if(!isPost(body.command)) fail('invalid_context');
    const graph=await anchoredGraph(b,planning,securityAt),metadata=evaluateCollaboration(body.command,b,graph);
    verified={...metadata,head:await digestObject(payload.mutation),originHead:await digestObject(payload.mutation),originalDigest:body.contentDigest!,original:payload.content!,originalHeader:collaborationHeader(b,b.kind),
      signingPublicKey:b.signingPublicKey,auditHeaders:[{id:payload.audit.id,envelope:payload.audit.envelope,header:collaborationHeader(b,'audit',payload.audit.id),signingPublicKey:b.signingPublicKey}],origin:entry.origin,moderation:null,
      current:payload.content!,currentHeader:collaborationHeader(b,b.kind),currentSigningPublicKey:b.signingPublicKey,representations:[]};
    if((await securityAt(b.securityVersion,b.securityHead)).activeUpgrade) fail('invalid_context');
  }else {
    const origin=entry.origin,mutation=planning.history.find(m=>m.body.binding.operationId===origin.operationId),object=planning.outcomes.find(o=>o.id===origin.entryId);
    if(!mutation||!object||mutation.body.outcome?.id!==origin.entryId||mutation.body.outcome.digest!==await digestObject(object.envelope)) fail('not_found');
    const b=mutation.body.binding,header=planningContentHeader(b,'update',origin.entryId,'1');
    if(!await verifyContentEnvelope(object.envelope,base64urlDecode(b.signingPublicKey,32),header)) fail('invalid_signature');
    const audit=planning.audits.find(a=>a.id===mutation.body.audit.id);if(!audit) fail('not_found');
    verified={workspaceId:b.workspaceId,projectId:b.projectId,entryId:origin.entryId,kind:'update',taskId:null,phaseId:planningOutcomePhase(planning,origin.operationId),revision:'1',head:await digestObject(mutation),originHead:await digestObject(mutation),hidden:false,
      originalDigest:mutation.body.outcome.digest,authorId:b.accountId,createdAt:b.issuedAt,moderatedBy:null,moderatedAt:null,original:object.envelope,originalHeader:header,signingPublicKey:b.signingPublicKey,
      auditHeaders:[{id:audit.id,envelope:audit.envelope,header:planningContentHeader(b,'audit',audit.id,'1'),signingPublicKey:b.signingPublicKey}],origin,moderation:null,
      current:object.envelope,currentHeader:header,currentSigningPublicKey:b.signingPublicKey,representations:[]};
  }
  if(verified.workspaceId!==planning.binding.workspaceId||verified.projectId!==planning.binding.projectId) fail('invalid_context');
  verified.lineageHeads=[{revision:'1',head:verified.head}];
  if(entry.moderation&&entry.moderation.mutation.body.binding.version!==1) fail('invalid_context');
  const seen=new Set([entry.origin.kind==='post'?entry.origin.payload.mutation.body.binding.operationId:entry.origin.operationId]);
  let previousTime=Date.parse(verified.createdAt);
  for(const supplied of [...(entry.moderation?[entry.moderation]:[]),...(entry.events??[])]) {
    const payload=await validateCryptography(supplied),body=payload.mutation.body,b=body.binding,upgrading=body.command.action==='upgrade_content';
    if(verified.auditHeaders.some(a=>a.id===payload.audit.id)||isPost(body.command)||seen.has(b.operationId)||Date.parse(b.issuedAt)<previousTime) fail('invalid_context');
    seen.add(b.operationId);previousTime=Date.parse(b.issuedAt);
    const graph=await anchoredGraph(b,planning,securityAt),security=await securityAt(b.securityVersion,b.securityHead),
      result=await validateCollaborationPayload(payload,b,graph,verified);
    if(upgrading) {
      const item=payload.upgradeItems![0]!;
      if(body.purpose!=='ukda.collaboration.v2'||!body.upgrade||security.activeUpgrade?.migrationId!==body.upgrade.migrationId||
        security.activeUpgrade.manifestDigest!==body.upgrade.manifestDigest||!security.activeUpgrade.manifest.some(ref=>same(ref,item.source))) fail('invalid_context');
      verified.representations.push({item,sourceHeader:verified.currentHeader,sourceSigningPublicKey:verified.currentSigningPublicKey,
        targetHeader:collaborationHeader(b,b.kind,b.entryId,item.target.envelopeRevision),targetSigningPublicKey:b.signingPublicKey});
      verified.current=item.envelope;verified.currentHeader=collaborationHeader(b,b.kind,b.entryId,item.target.envelopeRevision);verified.currentSigningPublicKey=b.signingPublicKey;
    }else {if(security.activeUpgrade) fail('invalid_context');verified.moderation=payload;}
    verified={...verified,...result.result,lineageHeads:[...verified.lineageHeads!,{revision:result.result.revision,head:result.result.head}],
      auditHeaders:[...verified.auditHeaders,{id:payload.audit.id,envelope:payload.audit.envelope,header:collaborationHeader(b,'audit',payload.audit.id),signingPublicKey:b.signingPublicKey}]};
  }
  return verified;
}
export const collaborationPin=z.strictObject({workspaceId:identifier,projectId:identifier,entryId:identifier,kind:collaborationKind,revision:positiveCounter,head:digest});
export type CollaborationPin=z.infer<typeof collaborationPin>;
export function collaborationEntryPin(entry:CollaborationMetadata):CollaborationPin {
  return {workspaceId:entry.workspaceId,projectId:entry.projectId,entryId:entry.entryId,kind:entry.kind,revision:entry.revision,head:entry.head};
}
export function assertCollaborationPin(entry:CollaborationMetadata,pin?:CollaborationPin):void {
  if(!pin)return;
  if(pin.workspaceId!==entry.workspaceId||pin.projectId!==entry.projectId||pin.entryId!==entry.entryId||pin.kind!==entry.kind||BigInt(pin.revision)>BigInt(entry.revision)||
    pin.revision==='1'&&pin.head!==entry.originHead||pin.revision===entry.revision&&pin.head!==entry.head||BigInt(pin.revision)<BigInt(entry.revision)&&
      (entry.lineageHeads?.find(ref=>ref.revision===pin.revision)?.head??(pin.revision==='1'?entry.originHead:null))!==pin.head) fail('revision_conflict');
}

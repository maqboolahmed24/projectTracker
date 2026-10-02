import { z } from 'zod';
import { contentEnvelope } from '../shared/contracts.js';
import { base64urlDecode, canonicalJson, digestObject, encryptContent, signObject } from '../shared/crypto.js';
import { CONTENT_TRANSFORM_1_TO_2, transformContentData1To2 } from '../shared/content-schema.js';
import { identityUpgradeHeader, identityUpgradeHistory, upgradeOwnerBinding, upgradeProof, upgradeRecordRef,
  validateIdentityUpgrade, verifyUpgradeOwner, type IdentityUpgradePayload, type UpgradeItem, type UpgradeRecordRef } from '../shared/encrypted-upgrades.js';
import { upgradeContext, upgradeStart, upgradeFinish, validateUpgradeLifecycle, UPGRADE_MAX_MANIFEST_RECORDS,
  type UpgradeContext, type UpgradeStart, type UpgradeFinish } from '../shared/upgrade-api.js';
import { verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState } from '../shared/security-history.js';
import { planningUpgradeReference, type PlanningContext } from '../shared/planning-api.js';
import type { TeamContext } from '../shared/teams.js';
import type { CollaborationContext } from '../shared/collaboration.js';
import type { PairingMaterial } from '../shared/pairing.js';
import type { DeviceBundle } from './device-store.js';
import { readWorkspaceKeyRing, verifyTeamUpgradeTargets } from './teams-crypto.js';
import { verifyCollaborationUpgradeTargets } from './collaboration-crypto.js';
import { openVerifiedPlanning } from './planning-crypto.js';
import { decryptHistoricalContent, readIdentityUpgradeContent, validateIdentityContent } from './upgrade-content-crypto.js';

const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
const keyOf=(ref:Pick<UpgradeRecordRef,'kind'|'id'>)=>`${ref.kind}:${ref.id}`;
export class EncryptedUpgradeClientError extends Error {
  constructor(readonly code:'INVALID_UPGRADE'|'INCOMPLETE_KEYS'|'EXPIRED') { super(`Encrypted upgrade failed (${code})`);this.name='EncryptedUpgradeClientError'; }
}
function invalid():never { throw new EncryptedUpgradeClientError('INVALID_UPGRADE'); }
export interface PrepareUpgradeStartInput { context:UpgradeContext;history:SecurityHistoryInput;accountId:string;deviceId:string }
export interface PrepareIdentityUpgradeInput extends PrepareUpgradeStartInput { materials:PairingMaterial[];records:UpgradeContext['records'] }
export type UpgradeNativeProof={kind:'planning';context:PlanningContext}|{kind:'team';context:TeamContext}|{kind:'collaboration';context:CollaborationContext};
export interface PrepareUpgradeFinishInput extends PrepareUpgradeStartInput {
  materials:PairingMaterial[];records:UpgradeContext['records'];proofs:UpgradeNativeProof[];
}
async function opened(value:PrepareUpgradeStartInput,bundle:DeviceBundle) {
  const input=structuredClone(value),context=upgradeContext.parse(input.context),b=context.binding,state=await verifySecurityHistory(input.history);
  verifyUpgradeOwner(b,state);
  if(b.accountId!==input.accountId||b.deviceId!==input.deviceId||b.signingPublicKey!==bundle.signingPublicKey||
    state.devices[b.deviceId]?.recipientPublicKey!==bundle.recipientPublicKey||b.writeSchema!==(state.writeSchema??1)||
    b.manifestDigest!==await digestObject(context.manifest)||b.manifestCount!==context.manifest.length||
    b.completedDigest!==await digestObject(context.completed)||b.completedCount!==context.completed.length) invalid();
  if(Date.parse(b.issuedAt)>Date.now()+30_000||Date.parse(b.expiresAt)<=Date.now())throw new EncryptedUpgradeClientError('EXPIRED');
  const projects=new Set(context.manifest.flatMap(ref=>ref.projectId?[ref.projectId]:[]));
  for(const projectId of projects)for(const scopes of [state.profiles[b.accountId]!.scopes,state.devices[b.deviceId]!.scopes]) {
    if(!scopes.some(scope=>scope.scope==='project'&&scope.scopeId===projectId&&scope.keyEpoch===state.scopeHeads[`project:${projectId}`]?.keyEpoch&&
      scope.permissions.includes('read_project')&&scope.permissions.includes('plan_projects')&&
      (scope.expiresAt===null||Date.parse(scope.expiresAt)>Date.parse(b.issuedAt))))invalid();
  }
  return {input,context,state,b};
}
function active(context:UpgradeContext,state:SecurityHistoryState):void {
  if(!state.activeUpgrade||!['active','paused'].includes(context.state)||state.activeUpgrade.migrationId!==context.binding.migrationId||
    state.activeUpgrade.manifestDigest!==context.binding.manifestDigest||!same(state.activeUpgrade.manifest,context.manifest))invalid();
}
export async function prepareUpgradeStart(value:PrepareUpgradeStartInput,bundle:DeviceBundle):Promise<UpgradeStart> {
  const {context,state,b}=await opened(value,bundle);
  if(context.state!=='available'||state.activeUpgrade||(state.writeSchema??1)!==1||context.completed.length||context.start||context.finish)invalid();
  const signing=base64urlDecode(bundle.signingPrivateKey,64);
  try {
    const result=upgradeStart.parse(await signObject({purpose:'ukda.encrypted-upgrade-start.v1' as const,binding:b,
      sourceSchema:1 as const,targetSchema:2 as const,transformId:CONTENT_TRANSFORM_1_TO_2,manifest:context.manifest},signing));
    await validateUpgradeLifecycle(result,'start');return result;
  }finally{signing.fill(0);}
}
/** Check current identity refs against security history; a pending invitation remains content-only. */
async function identityReference(record:UpgradeContext['records'][number],state:SecurityHistoryState):Promise<UpgradeRecordRef> {
  const ref=upgradeRecordRef.parse(record.reference),h=record.envelope.header;
  if(!['workspace','profile','role'].includes(ref.kind)||ref.projectId!==null||ref.contentRevision!==null||h.workspaceId!==state.workspaceId||
    h.scope!=='workspace'||h.scopeId!==state.workspaceId||h.recordType!==ref.kind||h.recordId!==ref.id||h.schema!==ref.schema||
    h.keyEpoch!==ref.keyEpoch||h.revision!==ref.envelopeRevision||ref.digest!==await digestObject(record.envelope))invalid();
  const known=ref.kind==='workspace'?state.workspaceContent:ref.kind==='role'?state.roles[ref.id]?.label:
    state.profiles[ref.id]?{digest:state.profiles[ref.id]!.profile.objectDigest,revision:state.profiles[ref.id]!.profile.revision}:state.pendingProfileContent?.[ref.id];
  if(known?known.digest!==ref.digest||known.revision!==ref.revision:
    ref.kind!=='profile'||!state.activeUpgrade?.manifest.some(original=>same(original,ref)))invalid();
  return ref;
}
export async function prepareIdentityUpgrade(value:PrepareIdentityUpgradeInput,bundle:DeviceBundle):Promise<IdentityUpgradePayload> {
  const {context,state,b}=await opened(value,bundle);active(context,state);
  const records=z.array(z.strictObject({reference:upgradeRecordRef,envelope:contentEnvelope})).min(1).max(32).parse(value.records);
  if(new Set(records.map(record=>keyOf(record.reference))).size!==records.length)invalid();
  const binding=upgradeOwnerBinding.parse(Object.fromEntries(Object.keys(upgradeOwnerBinding.shape).map(key=>[key,b[key as keyof typeof b]]))),
    ring=await readWorkspaceKeyRing(value,state,bundle),current=ring.find(entry=>entry.epoch===b.workspaceKeyEpoch);
  if(!current)throw new EncryptedUpgradeClientError('INCOMPLETE_KEYS');
  const key=base64urlDecode(current.key,32),signing=base64urlDecode(bundle.signingPrivateKey,64),items:UpgradeItem[]=[];
  try {
    for(const record of records) {
      const source=await identityReference(record,state);
      if(source.schema!==1||!context.manifest.some(original=>keyOf(original)===keyOf(source)))invalid();
      const kind=source.kind as 'workspace'|'profile'|'role',plaintext=await decryptHistoricalContent(value.history,record.envelope,ring);
      transformContentData1To2(kind,plaintext,content=>validateIdentityContent(kind,content));
      const revision=String(BigInt(source.revision)+1n),target:UpgradeRecordRef={...source,revision,envelopeRevision:revision,schema:2,keyEpoch:b.workspaceKeyEpoch};
      const envelope=await encryptContent(identityUpgradeHeader(binding,target),plaintext,key,signing);target.digest=await digestObject(envelope);
      items.push({source,target,sourceEnvelope:record.envelope,envelope});
    }
    const proof=upgradeProof.parse({migrationId:b.migrationId,manifestDigest:b.manifestDigest,transformId:CONTENT_TRANSFORM_1_TO_2,sourceSchema:1,targetSchema:2,
      items:items.map(({source,target})=>({source,target}))});
    return validateIdentityUpgrade({mutation:await signObject({purpose:'ukda.identity-content-upgrade.v1' as const,binding,upgrade:proof,
      objects:items.map(item=>({kind:item.target.kind,recordId:item.target.id,id:crypto.randomUUID(),digest:item.target.digest}))},signing),upgradeItems:items},state);
  }finally{key.fill(0);signing.fill(0);}
}
export async function prepareUpgradeFinish(value:PrepareUpgradeFinishInput,bundle:DeviceBundle):Promise<UpgradeFinish> {
  const {context,state,b}=await opened(value,bundle);active(context,state);
  const records=z.array(z.strictObject({reference:upgradeRecordRef,envelope:contentEnvelope})).max(UPGRADE_MAX_MANIFEST_RECORDS).parse(value.records);
  if(context.completed.length!==context.manifest.length||records.length!==context.completed.length||
    new Set(records.map(record=>keyOf(record.reference))).size!==records.length||value.proofs.length>UPGRADE_MAX_MANIFEST_RECORDS)invalid();
  const byKey=new Map(records.map(record=>[keyOf(record.reference),record])),verified=new Map<string,UpgradeRecordRef>();
  const accept=(ref:UpgradeRecordRef)=>{
    const key=keyOf(ref);if(verified.has(key)||ref.schema!==2||!same(byKey.get(key)?.reference,ref))invalid();verified.set(key,ref);
  };
  const ring=await readWorkspaceKeyRing(value,state,bundle);
  for(const record of records)if(['workspace','profile','role'].includes(record.reference.kind)) {
    const ref=await identityReference(record,state),kind=ref.kind as 'workspace'|'profile'|'role';
    const transition=value.history.transitions.map(value=>identityUpgradeHistory.safeParse(value)).find(parsed=>parsed.success&&
      parsed.data.body.objects.some(object=>object.kind===kind&&object.recordId===ref.id&&object.digest===ref.digest));
    if(!transition?.success)invalid();
    await readIdentityUpgradeContent(value.history,transition.data,kind,ref.id,ring);accept(ref);
  }
  for(const proof of value.proofs) {
    const native=proof.kind==='collaboration'?proof.context.planning:proof.context;
    if(native.binding.securityHead!==b.securityHead||native.binding.securityVersion!==b.securityVersion||native.binding.dataGeneration!==b.dataGeneration)invalid();
    if(proof.kind==='planning') {
      const opened=await openVerifiedPlanning({context:proof.context,history:value.history,accountId:value.accountId,deviceId:value.deviceId},bundle);
      for(const record of opened.context.records)accept(await planningUpgradeReference(opened.context.graph,record));
    }else if(proof.kind==='team') {
      for(const ref of await verifyTeamUpgradeTargets({...value,context:proof.context},bundle))accept(ref);
    }else {
      for(const ref of await verifyCollaborationUpgradeTargets({...value,context:proof.context},bundle))accept(ref);
    }
  }
  const targets=[...verified.values()].sort((a,b)=>keyOf(a).localeCompare(keyOf(b)));
  if(!same(targets,context.completed)||!same(targets.map(({kind,id,projectId})=>({kind,id,projectId})),context.manifest.map(({kind,id,projectId})=>({kind,id,projectId}))))invalid();
  const signing=base64urlDecode(bundle.signingPrivateKey,64);
  try {
    const result=upgradeFinish.parse(await signObject({purpose:'ukda.encrypted-upgrade-finish.v1' as const,binding:b,
      sourceSchema:1 as const,targetSchema:2 as const,transformId:CONTENT_TRANSFORM_1_TO_2,targets},signing));
    await validateUpgradeLifecycle(result,'finish');return result;
  }finally{signing.fill(0);}
}

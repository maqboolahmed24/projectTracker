import { z } from 'zod';
import { base64urlDecode, canonicalJson, digestObject, signObject } from '../shared/crypto.js';
import { verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState } from '../shared/security-history.js';
import { EXPORT_MAX_PAGES, EXPORT_NOTICE, EXPORT_PAGE_BYTES, EXPORT_TOTAL_BYTES, exportStart, exportPage, exportFinalize, exportManifestKey,
  exportSourceManifest, exportSources, sortedExportManifest, type ExportBinding, type ExportStart, type ExportPage, type ExportFinalize, type ExportManifestRecord } from '../shared/export.js';
import type { PairingMaterial } from '../shared/pairing.js';
import type { DeviceBundle } from './device-store.js';
import { openVerifiedPlanning,planningSecurityResolver, type ReadablePlanning } from './planning-crypto.js';
import {verifyFileManifest} from '../shared/files.js';
import {readFileMetadataWithKeyRing} from './files-crypto.js';
import { readCollaboration } from './collaboration-crypto.js';
import { readTeamHistory, readWorkspaceKeyRing } from './teams-crypto.js';
import { readReportingSettings } from './reporting-settings-crypto.js';
import { readVerifiedIdentityContent } from './profile-crypto.js';
import { planningWireValue } from '../shared/planning-api.js';
import { PlanningHistoryPool } from './planning-history-pool.js';

export class ExportClientError extends Error {
  constructor(readonly code:'INVALID_EXPORT'|'CONFLICT'|'CANCELLED'|'TOO_LARGE'|'ACKNOWLEDGEMENT_REQUIRED'|'TRUST_REQUIRED') {super(`Export failed (${code})`);this.name='ExportClientError';}
}
export interface PrepareExportInput { start:ExportStart; pages:ExportPage[]; history:SecurityHistoryInput; materials:PairingMaterial[]; accountId:string; deviceId:string; acknowledgePlaintext:true }
export interface PreparedExport { json:string; documentDigest:string; finalize:ExportFinalize }
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
function invalid():never {throw new ExportClientError('INVALID_EXPORT');}
const bytes=(value:unknown)=>new TextEncoder().encode(canonicalJson(value)).byteLength;
function currentOwner(b:ExportBinding,state:SecurityHistoryState,bundle:DeviceBundle,input:PrepareExportInput) {
  if(state.lifecycle==='deleted'||state.restoreQuarantine||state.deletion&&Date.parse(state.deletion.deleteAfter)<=Date.now())invalid();
  const p=state.profiles[b.accountId],d=state.devices[b.deviceId],live=(s:{expiresAt:string|null})=>s.expiresAt===null||Date.parse(s.expiresAt)>Date.now();
  if(b.origin!==state.origin||b.workspaceId!==state.workspaceId||b.accountId!==input.accountId||b.deviceId!==input.deviceId||b.securityHead!==state.securityHead||b.securityVersion!==state.securityVersion||
    b.dataGeneration!==state.dataGeneration||!p?.active||!p.owner||!d?.active||d.accountId!==p.accountId||b.credentialGeneration!==p.credentialGeneration||b.sessionGeneration!==p.sessionGeneration||
    b.keyGeneration!==d.keyGeneration||b.signingPublicKey!==d.signingPublicKey||b.signingPublicKey!==bundle.signingPublicKey||d.recipientPublicKey!==bundle.recipientPublicKey||
    Date.parse(b.issuedAt)>Date.now()+30000||Date.parse(b.expiresAt)<=Date.now()||Date.parse(b.expiresAt)-Date.parse(b.issuedAt)>600000||Date.parse(b.expiresAt)<=Date.parse(b.issuedAt))invalid();
  const custody=(s:typeof p.scopes[number])=>s.scope==='workspace'&&s.scopeId===state.workspaceId&&s.mode==='custody'&&s.keyEpoch===state.custodyEpoch&&s.permissions.includes('read_project')&&live(s);
  if(!p.scopes.some(custody)||!d.scopes.some(custody))invalid();
  for(const head of Object.values(state.scopeHeads).filter(s=>s.scope==='project')) {
    const readable=(s:typeof p.scopes[number])=>s.scope==='project'&&s.scopeId===head.scopeId&&s.keyEpoch===head.keyEpoch&&s.permissions.includes('read_project')&&live(s);
    if(!p.scopes.some(readable)||!d.scopes.some(readable))invalid();
  }
}
const metadataFields=['id','workspaceId','projectId','revision','contentRevision','state','archived','phaseLabel','managerProfileId','teamId','reviewEnabled','reviewPolicyRevision',
  'displayOrder','leadProfileId','phaseId','milestoneId','ownerProfileId','assigneeIds','reviewerProfileId','submittedRevision','submittedPolicyRevision','approvalOperationId',
  'taskId','responsibleProfileId','createdBy','createdAt','resolvedBy','resolvedAt'] as const;
const contentFields=['name','description','objective','startDate','dueDate','completionCriteria','acceptanceCriteria','title','priority','documentReference','reason','nextAction'] as const;
function pick(value:unknown,fields:readonly string[]) {const row=value as Record<string,unknown>;return Object.fromEntries(fields.filter(key=>row[key]!==undefined).map(key=>[key,structuredClone(row[key])]));}
function snapshot(value:ReadablePlanning['audits'][number]['data']['snapshot']) {
  if(!value)return null;
  return {operationId:value.operationId,kind:value.kind,recordId:value.recordId,action:value.action,outcomeId:value.outcome.recordId,
    project:pick(value.project,metadataFields),waves:value.phases.map(r=>pick(r,metadataFields)),milestones:value.milestones.map(r=>pick(r,metadataFields)),
    tasks:value.tasks.map(r=>pick(r,metadataFields)),blockers:(value.blockers??[]).map(r=>pick(r,metadataFields)),
    carriedWork:value.carriedWork.map(r=>({...pick(r,['operationId','taskId','taskRevision','fromPhaseId','toPhaseId','fromMilestoneId','toMilestoneId']),reasonId:r.reason.recordId}))};
}
/** Worker-only: verify every native source, then serialize a fixed business-data
 * allowlist. Signed security objects, ciphertext and key envelopes never appear
 * in the returned document. The controller still requires final server approval. */
export async function prepareExport(value:PrepareExportInput,bundle:DeviceBundle):Promise<PreparedExport> {
  if(value.acknowledgePlaintext!==true)throw new ExportClientError('ACKNOWLEDGEMENT_REQUIRED');
  if(value.pages.length>EXPORT_MAX_PAGES||bytes(planningWireValue({...value,pages:[]}))>EXPORT_TOTAL_BYTES)throw new ExportClientError('TOO_LARGE');
  const input=structuredClone({...value,pages:[]}),start=exportStart.parse(input.start),pages:ExportPage[]=[],planningHistories=new PlanningHistoryPool();
  let wireBytes=bytes(planningWireValue({...input,pages:[]}));
  for(const raw of value.pages){const page=exportPage.parse(raw) as ExportPage;wireBytes+=bytes(planningWireValue(page));if(wireBytes>EXPORT_TOTAL_BYTES)throw new ExportClientError('TOO_LARGE');
    try{if(page.data.kind==='project')planningHistories.retain(page.data.context);else if(page.data.kind==='entry')planningHistories.retain(page.data.history.planning);}catch{invalid();}pages.push(page);}
  const b=start.binding,
    state=await verifySecurityHistory(input.history);currentOwner(b,state,bundle,input);
  if(b.manifestDigest!==await digestObject(start.manifest)||!same(start.manifest,sortedExportManifest([...start.manifest]))||
    new Set(start.manifest.map(exportManifestKey)).size!==start.manifest.length||!same(start.sources,exportSources(start.manifest))||
    pages.length!==b.sourceCount||pages.length!==start.sources.length||!same(start.sources.filter(s=>s.kind==='project').map(s=>s.id).sort(),Object.values(state.scopeHeads).filter(s=>s.scope==='project').map(s=>s.scopeId).sort()))invalid();
  const expected=new Map(start.manifest.map(r=>[exportManifestKey(r),r])),seen=new Set<string>(),refs:ExportManifestRecord[]=[];
  const keys={history:input.history,materials:input.materials,accountId:input.accountId,deviceId:input.deviceId};
  const output:{[key:string]:unknown}={exportSchema:1,purpose:'plaintext-data-exit',notice:EXPORT_NOTICE,workspace:null,exportedAt:b.issuedAt,complete:true,
    checkpoint:{dataGeneration:b.dataGeneration,securityVersion:b.securityVersion,manifestDigest:b.manifestDigest},manifest:start.manifest,
    projects:[],teams:[],waves:[],tasks:[],assignments:[],milestones:[],comments:[],updates:[],blockers:[],profiles:[],fileVersions:[],
    history:{planning:[],teams:[],collaboration:[],settings:[]}};
  const append=(key:string,value:unknown)=>(output[key] as unknown[]).push(value),history=output.history as Record<string,unknown[]>;
  const projectCheck=(context:import('../shared/planning-api.js').PlanningContext)=>{
    const a=context.binding;if(a.workspaceId!==b.workspaceId||a.accountId!==b.accountId||a.deviceId!==b.deviceId||a.securityHead!==b.securityHead||a.securityVersion!==b.securityVersion||a.dataGeneration!==b.dataGeneration)invalid();
  };
  const projectRings=new Map<string,{epoch:string;key:string}[]>(),securityAt=planningSecurityResolver(input.history,state);
  for(const [index,page]of pages.entries()) {
    if(bytes(planningWireValue(page))>EXPORT_PAGE_BYTES)throw new ExportClientError('TOO_LARGE');
    if(!same(page.binding,b)||!same(page.source,start.sources[index])||page.nextCursor!==(index+1<pages.length?exportManifestKey(page.source):null))invalid();
    const found=await exportSourceManifest(page.data);
    for(const ref of found){const key=exportManifestKey(ref);if(seen.has(key)||!expected.has(key)||!same(expected.get(key),ref))invalid();seen.add(key);refs.push(ref);}
    const data=page.data;
    if(data.kind==='workspace') {
      if(page.source.kind!=='workspace'||page.source.id!==b.workspaceId||page.source.projectId!==null)invalid();
      const ring=await readWorkspaceKeyRing(keys,state,bundle),raw=await readVerifiedIdentityContent(input.history,state,'workspace',b.workspaceId,data.workspace,ring),
        settings=await readReportingSettings({...keys,settings:data.settings},bundle);
      output.workspace={id:b.workspaceId,...pick(raw,['name']),timezone:settings.timezone,revision:data.workspace.header.revision,settingsRevision:settings.revision};
      if(!same(data.profiles.map(p=>p.id).sort(),Object.keys(state.profiles).sort()))invalid();
      for(const p of data.profiles) {const actual=state.profiles[p.id];if(!actual||p.state!==actual.state||p.revision!==actual.profile.revision)invalid();
        if(p.state==='removed'){if(p.envelope!==null)invalid();append('profiles',{id:p.id,revision:p.revision,state:p.state,displayName:'Former member'});}
        else {if(!p.envelope)invalid();const label=await readVerifiedIdentityContent(input.history,state,'profile',p.id,p.envelope,ring);append('profiles',{id:p.id,revision:p.revision,state:p.state,...pick(label,['displayName','avatar'])});}}
      for(const change of data.settings.history){const a=change.mutation.body.binding;history.settings!.push({revision:String(BigInt(a.expectedRevision)+1n),operationId:a.operationId,actorId:a.accountId,signedAt:a.issuedAt,timezone:change.mutation.body.timezone});}
    } else if(data.kind==='project') {
      projectCheck(data.context);if(page.source.kind!=='project'||page.source.id!==data.context.binding.projectId||page.source.projectId!==page.source.id)invalid();
      const {readable,ring}=await openVerifiedPlanning({...keys,context:data.context},bundle),g=readable.graph;projectRings.set(g.project.id,ring);
      const created=data.context.creation.body.binding;
      history.planning!.push({projectId:g.project.id,operationId:created.operationId,actorId:created.authorizer.accountId,signedAt:created.issuedAt,action:'create_project'});
      for(const record of readable.records) {const row=record.kind==='project'?g.project:record.kind==='phase'?g.phases.find(r=>r.id===record.id):record.kind==='milestone'?g.milestones.find(r=>r.id===record.id):record.kind==='task'?g.tasks.find(r=>r.id===record.id):g.blockers?.find(r=>r.id===record.id);if(!row)invalid();
        append(record.kind==='phase'?'waves':`${record.kind}s`,{...pick(row,metadataFields),...pick(record.content,contentFields)});
        if(record.kind==='task')for(const accountId of g.tasks.find(t=>t.id===record.id)!.assigneeIds)append('assignments',{projectId:g.project.id,taskId:record.id,profileId:accountId,taskRevision:record.revision});}
      for(const audit of readable.audits)if(audit.data.action!=='upgrade_content')history.planning!.push({projectId:g.project.id,id:audit.id,operationId:audit.operationId,actorId:audit.actorId,signedAt:audit.signedAt,action:audit.data.action,
        changes:audit.data.changed.map(c=>({kind:c.kind,id:c.id,before:c.before?pick(c.before,metadataFields):null,after:pick(c.after,metadataFields)})),
        closingSnapshot:snapshot(audit.data.snapshot),closingContents:audit.data.snapshotContents.map(r=>({kind:r.kind,id:r.id,revision:r.revision,content:pick(r.content,contentFields)})),closingSettings:audit.closingSettings?pick(audit.closingSettings,['revision','timezone']):null});
    } else if(data.kind==='file_versions') {
      if(page.source.kind!=='file_versions'||page.source.id!==data.manifests[0]!.body.versionId||!page.source.projectId)invalid();
      const ring=projectRings.get(page.source.projectId);if(!ring)invalid();
      for(const value of data.manifests){const manifest=await verifyFileManifest(value,securityAt),body=manifest.body;if(body.binding.workspaceId!==b.workspaceId||body.binding.projectId!==page.source.projectId||BigInt(body.binding.dataGeneration)>BigInt(b.dataGeneration))invalid();
        const {fileKey:_key,...metadata}=await readFileMetadataWithKeyRing(manifest,ring);
        append('fileVersions',{fileId:body.fileId,versionId:body.versionId,projectId:body.binding.projectId,version:body.version,priorVersionId:body.priorVersionId,
          kind:body.kind,storage:body.storage,plainBytes:body.plainBytes,taskIds:body.taskIds,authorId:body.binding.accountId,createdAt:body.binding.issuedAt,manifestDigest:await digestObject(manifest),
          contents:body.storage==='managed'?'download-separately':'external-metadata-only',...metadata});
      }
    } else if(data.kind==='team') {
      const team=await readTeamHistory({...keys,pages:data.pages},bundle),current=team.records.at(-1)!;
      if(page.source.kind!=='team'||page.source.id!==team.teamId||page.source.projectId!==null)invalid();
      append('teams',{id:team.teamId,revision:team.anchor.revision,...current.after});
      for(const change of team.records)if(change.action!=='upgrade_content')history.teams!.push({teamId:team.teamId,...pick(change,['revision','operationId','actorId','action','signedAt','serverRecordedAt','before','after'])});
    } else {
      projectCheck(data.history.planning);
      for(const ref of await exportSourceManifest({kind:'project',context:data.history.planning}))if(!expected.has(exportManifestKey(ref))||!same(expected.get(exportManifestKey(ref)),ref))invalid();
      const view=await readCollaboration({...keys,context:data.history.planning,entries:[data.history.entry],includeHidden:true},bundle),entry=view.records[0];
      if(!entry||page.source.kind!==entry.kind||page.source.id!==entry.entryId||page.source.projectId!==entry.projectId)invalid();
      append(entry.kind==='comment'?'comments':'updates',{id:entry.entryId,...pick(entry,['projectId','taskId','phaseId','revision','hidden','authorId','createdAt','text','moderation'])});
      const origin=data.history.entry.origin,original=origin.kind==='planning'?data.history.planning.history.find(m=>m.body.binding.operationId===origin.operationId):null;
      history.collaboration!.push({entryId:entry.entryId,kind:entry.kind,projectId:entry.projectId,origin:origin.kind,
        operationId:origin.kind==='post'?origin.payload.mutation.body.binding.operationId:origin.operationId,
        action:origin.kind==='post'?origin.payload.mutation.body.command.action:original!.body.command.action,actorId:entry.authorId,at:entry.createdAt,text:entry.text});
      if(entry.moderation)history.collaboration!.push({entryId:entry.entryId,kind:entry.kind,projectId:entry.projectId,action:entry.kind==='comment'?'hide_comment':'hide_update',...entry.moderation});
    }
  }
  if(!output.workspace||!same(sortedExportManifest(refs),start.manifest))invalid();
  const json=canonicalJson(output),byteLength=new TextEncoder().encode(json).byteLength;if(byteLength>EXPORT_TOTAL_BYTES)throw new ExportClientError('TOO_LARGE');
  const documentDigest=await digestObject(output),signing=base64urlDecode(bundle.signingPrivateKey,64);
  try {const finalize=exportFinalize.parse(await signObject({purpose:'ukda.plaintext-export.v1' as const,binding:b,documentDigest,byteLength,complete:true as const},signing));
    return {json,documentDigest,finalize};}finally{signing.fill(0);}
}

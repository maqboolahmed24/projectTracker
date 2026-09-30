import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { digestObject,canonicalJson } from '../../shared/crypto.js';
import { assertFileBindingCurrent,fileBindingFromPlanning,verifyFileManifest,type FileManifest } from '../../shared/files.js';
import { evidenceContextRequest,evidenceSubmitRequest,evidenceReviewRequest,evidenceSharedRequest,evidenceRevokeRequest,evidenceStatusRequest,
 fileSubmission,fileApproval,fileRevocation,verifyFileEvidence,FILE_EVIDENCE_MAX_ITEMS,type FileSubmission,type FileApproval,type FileReview,
 type EvidenceContext,type EvidenceView,type EvidenceReceipt } from '../../shared/file-evidence.js';
import type { PlanningContext,PlanningSecurityResolver } from '../../shared/planning-api.js';
import type { SessionService,SessionPrincipal } from '../identity/sessions.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { PlanningService } from '../work/planning.js';
const changed=()=>new AppError('FILE_EVIDENCE_CHANGED','The task, file or approval changed; refresh before continuing',409);
const forbidden=()=>new AppError('FILE_EVIDENCE_FORBIDDEN','You cannot review or approve this work',403);
const invalid=()=>new AppError('FILE_EVIDENCE_INVALID','Invalid file review request',400);
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
const ref=(b:{workspaceId:string;projectId:string;operationId:string})=>({workspaceId:b.workspaceId,projectId:b.projectId,operationId:b.operationId});
function parse<T>(schema:z.ZodType<T>,input:unknown):T {const r=schema.safeParse(input);if(!r.success)throw invalid();return r.data;}
type VersionRef={fileId:string;versionId:string;manifestDigest:string};
async function ready(a:pg.PoolClient,p:PlanningContext,r:VersionRef,securityAt:PlanningSecurityResolver):Promise<FileManifest> {
 const row=(await a.query<{manifest:FileManifest;data_generation:string;file_id:string;state:string}>('SELECT manifest,data_generation,file_id,state FROM app.file_versions WHERE workspace_id=$1 AND project_id=$2 AND id=$3',
 [p.binding.workspaceId,p.binding.projectId,r.versionId])).rows[0];
 if(!row||row.state!=='ready'||row.file_id!==r.fileId||BigInt(row.data_generation)>BigInt(p.binding.dataGeneration))throw changed();
 try{const manifest=await verifyFileManifest(row.manifest,securityAt);if(await digestObject(manifest)!==r.manifestDigest)throw changed();return manifest;}catch{throw changed();}
}
function currentTask(p:PlanningContext,id:string){const task=p.graph.tasks.find(t=>t.id===id);if(p.graph.version!==2||!task||!task.contentRevision)throw changed();return task;}
/** The planning completion request must immediately follow this submission's exact task revision. */
export function assertSubmissionInReview(p:PlanningContext,s:FileSubmission):void {
 const b=s.body,t=currentTask(p,b.taskId);
 if(!p.graph.project.reviewEnabled||t.state!=='review'||t.contentRevision!==b.taskContentRevision||t.submittedRevision!==b.taskContentRevision||t.submittedPolicyRevision!==b.reviewPolicyRevision||p.graph.project.reviewPolicyRevision!==b.reviewPolicyRevision)throw changed();
 const request=[...p.history].reverse().find(m=>m.body.command.action==='request_task_completion'&&m.body.command.taskId===b.taskId);
 if(!request||request.body.binding.before.tasks.find(x=>x.id===b.taskId)?.revision!==b.taskRevision||request.body.binding.accountId!==b.binding.accountId)throw changed();
}
export function assertAcceptedTask(p:PlanningContext,s:FileSubmission,r:FileReview):void {
 const b=s.body,t=p.graph.tasks.find(t=>t.id===b.taskId),v=r.body;
 if(!t||t.state!=='done'||!t.approvalOperationId||t.contentRevision!==b.taskContentRevision||t.submittedRevision!==b.taskContentRevision||t.submittedPolicyRevision!==b.reviewPolicyRevision||
 v.taskId!==b.taskId||v.submissionId!==b.submissionId||v.taskContentRevision!==b.taskContentRevision||v.reviewPolicyRevision!==b.reviewPolicyRevision||t.assigneeIds.includes(v.binding.accountId))throw changed();
 const approval=p.history.find(m=>m.body.binding.operationId===t.approvalOperationId),command=approval?.body.command;
 if(!approval||command?.action!=='approve_task'||command.taskId!==b.taskId||command.submittedRevision!==b.taskContentRevision||command.submittedPolicyRevision!==b.reviewPolicyRevision||
 approval.body.binding.accountId!==v.binding.accountId||approval.body.binding.before.tasks.find(x=>x.id===b.taskId)?.revision!==v.reviewTaskRevision)throw changed();
}
/** Delivery never treats a current filename or a later working version as reviewed. */
export async function assertDeliveryEvidence(a:pg.PoolClient,p:PlanningContext,versionId:string,securityAt:PlanningSecurityResolver):Promise<{
 approvalId:string;submissionId:string|null;versionId:string;fileId:string;manifestDigest:string;taskId:string|null}> {
 const rows=(await a.query<{id:string;signed_review:unknown;payload_digest:string;data_generation:string;submission_id:string|null;file_id:string;manifest_digest:string}>(`SELECT r.id,r.signed_review,r.payload_digest,r.data_generation,r.submission_id,i.file_id,i.manifest_digest
 FROM app.file_reviews r JOIN app.file_review_items i ON i.workspace_id=r.workspace_id AND i.approval_id=r.id AND i.project_id=r.project_id
 WHERE r.workspace_id=$1 AND r.project_id=$2 AND i.version_id=$3 ORDER BY r.created_at DESC,r.id LIMIT 129`,[p.binding.workspaceId,p.binding.projectId,versionId])).rows;
 if(rows.length>128)throw changed();
 for(const row of rows)try{
  const approval=fileApproval.parse(row.signed_review),b=approval.body;
  if(b.approvalId!==row.id||b.binding.workspaceId!==p.binding.workspaceId||b.binding.projectId!==p.binding.projectId||BigInt(row.data_generation)>BigInt(p.binding.dataGeneration)||await digestObject(approval)!==row.payload_digest)continue;
  await verifyFileEvidence(approval,securityAt,b.purpose==='ukda.shared-file-approval.v1');
  if((await a.query('SELECT 1 FROM app.file_approval_revocations WHERE workspace_id=$1 AND project_id=$2 AND approval_id=$3',[p.binding.workspaceId,p.binding.projectId,row.id])).rowCount)continue;
  let reference:VersionRef,taskId:string|null=null,submissionId:string|null=null;
  if(b.purpose==='ukda.shared-file-approval.v1') {reference=b.reference;if(row.submission_id!==null)continue;}
  else {
   const sub=(await a.query<{signed_submission:unknown;payload_digest:string;data_generation:string}>('SELECT signed_submission,payload_digest,data_generation FROM app.file_submissions WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[p.binding.workspaceId,p.binding.projectId,b.submissionId])).rows[0];
   if(!sub||BigInt(sub.data_generation)>BigInt(p.binding.dataGeneration))continue;const submission=fileSubmission.parse(sub.signed_submission);
   if(await digestObject(submission)!==sub.payload_digest||sub.payload_digest!==b.submissionDigest||submission.body.binding.workspaceId!==p.binding.workspaceId||submission.body.binding.projectId!==p.binding.projectId)continue;
   await verifyFileEvidence(submission,securityAt);assertAcceptedTask(p,submission,approval as FileReview);
   let selfAuthored=false;for(const item of submission.body.outputs){const output=await ready(a,p,item,securityAt);if(output.body.binding.accountId===b.binding.accountId)selfAuthored=true;}if(selfAuthored)continue;
   const selected=submission.body.outputs.find(x=>x.versionId===versionId);if(!selected)continue;reference=selected;taskId=b.taskId;submissionId=b.submissionId;
  }
  if(reference.versionId!==versionId||reference.fileId!==row.file_id||reference.manifestDigest!==row.manifest_digest)continue;
  const manifest=await ready(a,p,reference,securityAt);
  if(b.purpose==='ukda.file-review.v1'&&manifest.body.binding.accountId===b.binding.accountId)continue;
  return {approvalId:row.id,submissionId,versionId,fileId:reference.fileId,manifestDigest:reference.manifestDigest,taskId};
 }catch{/* An invalid retained approval cannot authorize publication. */}
 throw new AppError('FILE_EVIDENCE_REQUIRED','This exact file version needs an accepted review before delivery',409);
}
interface Options {databases:Databases;sessions:SessionService;secrets:ServiceSecrets;origin:string;planning?:PlanningService;requestBudget?:(scope:{workspaceId:string;accountId:string})=>Promise<void>}
export class FileEvidenceService {
 readonly #planning:PlanningService;constructor(readonly options:Options){this.#planning=options.planning??new PlanningService(options);}
 async #with<T>(cookie:string,csrf:string,r:{workspaceId:string;projectId:string;operationId:string},write:boolean,action:(a:pg.PoolClient,p:PlanningContext,principal:SessionPrincipal,now:Date,securityAt:PlanningSecurityResolver)=>Promise<T>):Promise<T>{
  return this.#planning.withCurrentContext(cookie,csrf,r,async(a,p,principal,now,securityAt)=>{await this.options.requestBudget?.({workspaceId:principal.workspaceId,accountId:principal.accountId});
   try{return await action(a,p,principal,now,securityAt);}catch(error){if(error instanceof AppError)throw error;throw new AppError('FILE_EVIDENCE_UNAVAILABLE','Review is temporarily unavailable; try again',503);}}, {write});
 }
 async #links(a:pg.PoolClient,p:PlanningContext,taskId:string,securityAt:PlanningSecurityResolver){
  const rows=(await a.query<{manifest:FileManifest|null;state:string|null}>(`SELECT v.manifest,v.state FROM app.task_file_links l JOIN app.project_files f ON f.workspace_id=l.workspace_id AND f.project_id=l.project_id AND f.id=l.file_id
 LEFT JOIN app.file_versions v ON v.workspace_id=l.workspace_id AND v.project_id=l.project_id AND v.id=CASE WHEN l.mode='pinned' THEN l.version_id ELSE f.latest_version_id END
 WHERE l.workspace_id=$1 AND l.project_id=$2 AND l.task_id=$3 ORDER BY l.file_id LIMIT 129`,[p.binding.workspaceId,p.binding.projectId,taskId])).rows;
  if(rows.length>128||rows.some(x=>!x.manifest||x.state!=='ready'))throw changed();const manifests:FileManifest[]=[],sources:VersionRef[]=[],outputs:VersionRef[]=[];
  for(const row of rows){let m:FileManifest;try{m=await verifyFileManifest(row.manifest,securityAt);}catch{throw changed();}const b=m.body;if(BigInt(b.binding.dataGeneration)>BigInt(p.binding.dataGeneration))throw changed();
   manifests.push(m);(b.kind==='source'?sources:outputs).push({fileId:b.fileId,versionId:b.versionId,manifestDigest:await digestObject(m)});}
  if(sources.length>FILE_EVIDENCE_MAX_ITEMS||outputs.length>FILE_EVIDENCE_MAX_ITEMS)throw changed();return {manifests,sources,outputs};
 }
 async #prior(a:pg.PoolClient,principal:SessionPrincipal,r:{workspaceId:string;projectId:string;operationId:string},hash:string):Promise<EvidenceView|null>{
  const row=(await a.query<{project_id:string;actor_profile_id:string;data_generation:string;request_digest:string;receipt:EvidenceReceipt}>('SELECT * FROM app.file_evidence_operations WHERE workspace_id=$1 AND operation_id=$2',[r.workspaceId,r.operationId])).rows[0];if(!row)return null;
  if(row.project_id!==r.projectId||row.actor_profile_id!==principal.accountId||row.data_generation!==principal.dataGeneration||row.request_digest!==hash)throw changed();return {state:'completed',receipt:row.receipt};
 }
 async #record(a:pg.PoolClient,principal:SessionPrincipal,r:{workspaceId:string;projectId:string;operationId:string},hash:string,payload:unknown,action:EvidenceReceipt['action'],evidenceId:string,now:Date):Promise<EvidenceView>{
  const receipt:EvidenceReceipt={version:1,...r,dataGeneration:principal.dataGeneration,requestHash:hash,action,evidenceId,committedAt:now.toISOString()};
  await a.query('INSERT INTO app.file_evidence_operations(workspace_id,project_id,operation_id,data_generation,actor_profile_id,request_digest,payload,receipt,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[r.workspaceId,r.projectId,r.operationId,principal.dataGeneration,principal.accountId,hash,payload,receipt,now]);
  await a.query('INSERT INTO app.operation_receipts(workspace_id,id,data_generation,operation_id,actor_profile_id,project_id,action,request_digest,encrypted_envelope,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[r.workspaceId,randomUUID(),principal.dataGeneration,r.operationId,principal.accountId,r.projectId,`file_evidence.${action}`,hash,{receipt},now]);return {state:'completed',receipt};
 }
 async context(cookie:string,csrf:string,input:unknown):Promise<EvidenceContext>{const r=parse(evidenceContextRequest,input);return this.#with(cookie,csrf,ref(r),false,async(a,p,_principal,_now,securityAt)=>{
  if(r.taskId){const task=currentTask(p,r.taskId),links=await this.#links(a,p,r.taskId,securityAt);
   const rows=(await a.query<{signed_submission:unknown;payload_digest:string}>('SELECT signed_submission,payload_digest FROM app.file_submissions WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 ORDER BY created_at DESC,id DESC LIMIT 128',[r.workspaceId,r.projectId,r.taskId])).rows;
   let submission:FileSubmission|null=null;for(const row of rows){const s=fileSubmission.parse(row.signed_submission);if(s.body.taskContentRevision===task.contentRevision&&s.body.reviewPolicyRevision===(task.submittedPolicyRevision??p.graph.project.reviewPolicyRevision)&&await digestObject(s)===row.payload_digest){try{await verifyFileEvidence(s,securityAt);if(task.state==='review')assertSubmissionInReview(p,s);submission=s;break;}catch{}}}
   let approval:FileApproval|null=null,revocation=null;if(submission){const row=(await a.query<{signed_review:unknown}>('SELECT signed_review FROM app.file_reviews WHERE workspace_id=$1 AND project_id=$2 AND submission_id=$3 ORDER BY created_at DESC,id DESC LIMIT 1',[r.workspaceId,r.projectId,submission.body.submissionId])).rows[0];if(row){approval=fileApproval.parse(row.signed_review);const rv=(await a.query<{signed_revocation:unknown}>('SELECT signed_revocation FROM app.file_approval_revocations WHERE workspace_id=$1 AND project_id=$2 AND approval_id=$3',[r.workspaceId,r.projectId,approval.body.approvalId])).rows[0];if(rv)revocation=fileRevocation.parse(rv.signed_revocation);}}
   return {planning:p,binding:fileBindingFromPlanning(p.binding),taskId:r.taskId,...links,submission,approval,revocation};
  }
  const row=(await a.query<{manifest:FileManifest;state:string}>('SELECT manifest,state FROM app.file_versions WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[r.workspaceId,r.projectId,r.versionId])).rows[0];if(!row||row.state!=='ready')throw changed();const m=await verifyFileManifest(row.manifest,securityAt);
  const reference={fileId:m.body.fileId,versionId:m.body.versionId,manifestDigest:await digestObject(m)};let approval:FileApproval|null=null,revocation=null;
  const item=(await a.query<{signed_review:unknown;signed_revocation:unknown|null}>(`SELECT r.signed_review,v.signed_revocation FROM app.file_reviews r JOIN app.file_review_items i ON i.workspace_id=r.workspace_id AND i.approval_id=r.id
 LEFT JOIN app.file_approval_revocations v ON v.workspace_id=r.workspace_id AND v.approval_id=r.id WHERE r.workspace_id=$1 AND r.project_id=$2 AND i.version_id=$3 ORDER BY r.created_at DESC LIMIT 1`,[r.workspaceId,r.projectId,r.versionId])).rows[0];if(item){approval=fileApproval.parse(item.signed_review);if(item.signed_revocation)revocation=fileRevocation.parse(item.signed_revocation);}
  return {planning:p,binding:fileBindingFromPlanning(p.binding),taskId:null,manifests:[m],sources:m.body.kind==='source'?[reference]:[],outputs:m.body.kind==='output'?[reference]:[],submission:null,approval,revocation};
 });}
 async submit(cookie:string,csrf:string,input:unknown):Promise<EvidenceView>{const payload=parse(evidenceSubmitRequest,input),s=payload.submission,b=s.body,r=ref(b.binding),hash=await digestObject(payload);
  return this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{const prior=await this.#prior(a,principal,r,hash);if(prior)return prior;
   try{assertFileBindingCurrent(b.binding,p,now);await verifyFileEvidence(s,securityAt);}catch{throw changed();}const t=currentTask(p,b.taskId);
   if(!p.graph.project.reviewEnabled||p.graph.project.state!=='active'||p.graph.project.archived||!['todo','in_progress'].includes(t.state)||t.revision!==b.taskRevision||t.contentRevision!==b.taskContentRevision||p.graph.project.reviewPolicyRevision!==b.reviewPolicyRevision)throw changed();
   if(!t.assigneeIds.includes(principal.accountId)&&!p.binding.permissions.includes('manage_tasks'))throw forbidden();
   const links=await this.#links(a,p,b.taskId,securityAt);if(!same(links.sources,b.sources)||!same(links.outputs,b.outputs))throw changed();
   await a.query('INSERT INTO app.file_submissions(workspace_id,project_id,id,task_id,data_generation,signed_submission,payload_digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[r.workspaceId,r.projectId,b.submissionId,b.taskId,principal.dataGeneration,s,await digestObject(s),now]);
   return this.#record(a,principal,r,hash,payload,'submit',b.submissionId,now);
  });}
 async review(cookie:string,csrf:string,input:unknown):Promise<EvidenceView>{const payload=parse(evidenceReviewRequest,input),review=payload.review,b=review.body,r=ref(b.binding),hash=await digestObject(payload);
  return this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{const prior=await this.#prior(a,principal,r,hash);if(prior)return prior;
   try{assertFileBindingCurrent(b.binding,p,now);await verifyFileEvidence(review,securityAt);}catch{throw changed();}
   const row=(await a.query<{signed_submission:unknown;payload_digest:string;data_generation:string}>('SELECT signed_submission,payload_digest,data_generation FROM app.file_submissions WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[r.workspaceId,r.projectId,b.submissionId])).rows[0];if(!row||BigInt(row.data_generation)>BigInt(principal.dataGeneration)||row.payload_digest!==b.submissionDigest)throw changed();
   const s=fileSubmission.parse(row.signed_submission);if(await digestObject(s)!==row.payload_digest)throw changed();await verifyFileEvidence(s,securityAt);assertSubmissionInReview(p,s);const t=currentTask(p,b.taskId);
   if(b.taskId!==s.body.taskId||t.revision!==b.reviewTaskRevision||b.taskContentRevision!==s.body.taskContentRevision||b.reviewPolicyRevision!==s.body.reviewPolicyRevision)throw changed();
   if(t.reviewerProfileId!==principal.accountId||t.assigneeIds.includes(principal.accountId)||!p.binding.permissions.includes('approve_tasks'))throw forbidden();
   const links=await this.#links(a,p,b.taskId,securityAt);if(!same(links.sources,s.body.sources)||!same(links.outputs,s.body.outputs)||links.manifests.some(m=>m.body.kind==='output'&&m.body.binding.accountId===principal.accountId))throw forbidden();
   await this.#storeApproval(a,p,review,s.body.outputs,b.submissionId,b.taskId,now);return this.#record(a,principal,r,hash,payload,'accept',b.approvalId,now);
  });}
 async #storeApproval(a:pg.PoolClient,p:PlanningContext,approval:FileApproval,items:VersionRef[],submissionId:string|null,taskId:string|null,now:Date){const b=approval.body;
  await a.query('INSERT INTO app.file_reviews(workspace_id,project_id,id,submission_id,task_id,data_generation,signed_review,payload_digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[p.binding.workspaceId,p.binding.projectId,b.approvalId,submissionId,taskId,p.binding.dataGeneration,approval,await digestObject(approval),now]);
  for(const item of items)await a.query('INSERT INTO app.file_review_items(workspace_id,project_id,approval_id,file_id,version_id,manifest_digest) VALUES($1,$2,$3,$4,$5,$6)',[p.binding.workspaceId,p.binding.projectId,b.approvalId,item.fileId,item.versionId,item.manifestDigest]);
 }
 async approveShared(cookie:string,csrf:string,input:unknown):Promise<EvidenceView>{const payload=parse(evidenceSharedRequest,input),approval=payload.approval,b=approval.body,r=ref(b.binding),hash=await digestObject(payload);
  return this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{const prior=await this.#prior(a,principal,r,hash);if(prior)return prior;try{assertFileBindingCurrent(b.binding,p,now);await verifyFileEvidence(approval,securityAt,true);}catch{throw forbidden();}
   const manifest=await ready(a,p,b.reference,securityAt);if(manifest.body.kind!=='source')throw forbidden();
   // A shared source may also be linked to tasks; explicit Owner approval is
   // distinguishable from a task's independent output review.
   await this.#storeApproval(a,p,approval,[b.reference],null,null,now);return this.#record(a,principal,r,hash,payload,'approve_shared',b.approvalId,now);
  });}
 async revoke(cookie:string,csrf:string,input:unknown):Promise<EvidenceView>{const payload=parse(evidenceRevokeRequest,input),revocation=payload.revocation,b=revocation.body,r=ref(b.binding),hash=await digestObject(payload);
  return this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{const prior=await this.#prior(a,principal,r,hash);if(prior)return prior;try{assertFileBindingCurrent(b.binding,p,now);await verifyFileEvidence(revocation,securityAt,true);}catch{throw forbidden();}
   const row=(await a.query('SELECT 1 FROM app.file_reviews WHERE workspace_id=$1 AND project_id=$2 AND id=$3 AND data_generation<=$4',[r.workspaceId,r.projectId,b.approvalId,principal.dataGeneration])).rows[0];if(!row)throw changed();
   await a.query('INSERT INTO app.file_approval_revocations(workspace_id,project_id,operation_id,approval_id,data_generation,signed_revocation,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)',[r.workspaceId,r.projectId,r.operationId,b.approvalId,principal.dataGeneration,revocation,now]);
   return this.#record(a,principal,r,hash,payload,'revoke',b.approvalId,now);
  });}
 async status(cookie:string,csrf:string,input:unknown):Promise<EvidenceView>{const r=parse(evidenceStatusRequest,input);return this.#with(cookie,csrf,ref(r),false,async(a,_p,principal)=>{if(r.dataGeneration!==principal.dataGeneration)throw changed();return await this.#prior(a,principal,r,r.requestHash)??{state:'absent',receipt:null};});}
}
/** Mandatory server gate for document tasks; legacy task signatures stay unchanged. */
export async function assertPlanningFileEvidence(a:pg.PoolClient,p:PlanningContext,payload:import('../../shared/planning-api.js').PlanningPayload,securityAt:PlanningSecurityResolver):Promise<void>{
 const command=payload.mutation.body.command;if(command.action!=='request_task_completion'&&command.action!=='approve_task')return;
 // The history rollout precedes the additive file migration on existing hosts.
 if(!(await a.query<{present:string|null}>("SELECT to_regclass('app.file_submissions')::text AS present")).rows[0]?.present)return;
 const rows=(await a.query<{manifest:FileManifest|null;state:string|null}>(`SELECT v.manifest,v.state FROM app.task_file_links l JOIN app.project_files f ON f.workspace_id=l.workspace_id AND f.project_id=l.project_id AND f.id=l.file_id
 LEFT JOIN app.file_versions v ON v.workspace_id=l.workspace_id AND v.project_id=l.project_id AND v.id=CASE WHEN l.mode='pinned' THEN l.version_id ELSE f.latest_version_id END
 WHERE l.workspace_id=$1 AND l.project_id=$2 AND l.task_id=$3 ORDER BY l.file_id LIMIT 129`,[p.binding.workspaceId,p.binding.projectId,command.taskId])).rows;
 if(!rows.length)return;if(rows.length>128||rows.some(r=>r.state!=='ready'||!r.manifest))throw changed();const task=currentTask(p,command.taskId),sources:VersionRef[]=[],outputs:VersionRef[]=[];
 for(const row of rows){const m=await verifyFileManifest(row.manifest,securityAt),b=m.body;if(BigInt(b.binding.dataGeneration)>BigInt(p.binding.dataGeneration))throw changed();(b.kind==='source'?sources:outputs).push({fileId:b.fileId,versionId:b.versionId,manifestDigest:await digestObject(m)});}
 if(!p.graph.project.reviewEnabled||!outputs.length||sources.length>64||outputs.length>64)throw new AppError('FILE_EVIDENCE_REQUIRED','Attach a finished file and submit it for review before completing this task',409);
 const submissions=(await a.query<{signed_submission:unknown;payload_digest:string}>(`SELECT signed_submission,payload_digest FROM app.file_submissions WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND data_generation<=$4
 AND signed_submission->'body'->>'taskContentRevision'=$5 ORDER BY created_at DESC,id DESC LIMIT 129`,[p.binding.workspaceId,p.binding.projectId,task.id,p.binding.dataGeneration,task.contentRevision])).rows;
 if(submissions.length>128)throw changed();
 for(const row of submissions)try{const s=fileSubmission.parse(row.signed_submission),b=s.body;if(await digestObject(s)!==row.payload_digest||!same(b.sources,sources)||!same(b.outputs,outputs)||b.binding.workspaceId!==p.binding.workspaceId||b.binding.projectId!==p.binding.projectId)continue;await verifyFileEvidence(s,securityAt);
  if(command.action==='request_task_completion'){if(b.taskRevision!==task.revision||b.reviewPolicyRevision!==p.graph.project.reviewPolicyRevision||b.binding.accountId!==p.binding.accountId)continue;return;}
  assertSubmissionInReview(p,s);const reviews=(await a.query<{signed_review:unknown;payload_digest:string}>(`SELECT signed_review,payload_digest FROM app.file_reviews WHERE workspace_id=$1 AND project_id=$2 AND submission_id=$3 AND data_generation<=$4 ORDER BY created_at DESC,id DESC LIMIT 129`,[p.binding.workspaceId,p.binding.projectId,b.submissionId,p.binding.dataGeneration])).rows;
  if(reviews.length>128)throw changed();for(const reviewRow of reviews){const review=parse(fileApproval,reviewRow.signed_review);if(review.body.purpose!=='ukda.file-review.v1')continue;const v=review.body;
   if(await digestObject(review)!==reviewRow.payload_digest||v.submissionDigest!==row.payload_digest||v.reviewTaskRevision!==task.revision||v.binding.accountId!==p.binding.accountId||v.taskContentRevision!==b.taskContentRevision||v.reviewPolicyRevision!==b.reviewPolicyRevision||v.taskId!==task.id||
    task.assigneeIds.includes(v.binding.accountId)||rows.some(r=>r.manifest?.body.kind==='output'&&r.manifest.body.binding.accountId===v.binding.accountId))continue;
   await verifyFileEvidence(review,securityAt);if((await a.query('SELECT 1 FROM app.file_approval_revocations WHERE workspace_id=$1 AND project_id=$2 AND approval_id=$3',[p.binding.workspaceId,p.binding.projectId,v.approvalId])).rowCount)continue;return;
  }
 }catch{/* A stale or invalid submission cannot authorize task completion. */}
 throw new AppError('FILE_EVIDENCE_REQUIRED',command.action==='approve_task'?'Check and accept these exact file versions before approving this task':'Submit these exact file versions before completing this task',409);
}

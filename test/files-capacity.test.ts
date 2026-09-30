import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {mkdir,writeFile} from 'node:fs/promises';
import {transaction} from '../src/db.js';
import {tenantTransaction} from '../src/persistence.js';
import {AppError} from '../src/errors.js';
import {base64urlDecode,canonicalJson,digestObject,encryptContent,signObject} from '../src/shared/crypto.js';
import {evaluatePlanning,planningRevisionSnapshot} from '../src/shared/planning.js';
import {planningAuthority,planningChangedRecords,planningCommand,planningContentHeader,planningGraphDigest,planningPayload,planningReceipt,clearPlanningReplayCache,type PlanningPayload,type PlanningContext} from '../src/shared/planning-api.js';
import {openVerifiedPlanning,readPlanning,planningSecurityResolver} from '../src/client/planning-crypto.js';
import {prepareFileLink,readFiles,readFileBytes} from '../src/client/files-crypto.js';
import {prepareFileVerification,prepareFileSubmission,prepareFileReview} from '../src/client/file-evidence-crypto.js';
import {FileEvidenceService,assertDeliveryEvidence} from '../src/modules/files/evidence-service.js';
import {RestorationService} from '../src/modules/restoration/service.js';
import {verifySecurityHistory} from '../src/shared/security-history.js';
import {fileServiceFixture} from './files-fixture.js';
import {origin} from './password-change-fixture.js';

/** One bounded representative workload on the real isolated database. Task
 * creation is genuinely signed fixture seeding; subsequent file/evidence/task
 * actions use the production services and cryptographic client code. */
test('512 document tasks support shared pinned inputs, contributors, external outputs, corrections and interrupted exact evidence',
 {skip:process.env.RUN_FILES_CAPACITY!=='1',timeout:600000},async t=>{
 const started=performance.now();let fixture:Awaited<ReturnType<typeof fileServiceFixture>>|undefined;
 t.after(async()=>{if(fixture)await transaction(fixture.admin.control,async c=>{await c.query("SET LOCAL session_replication_role='replica'");await c.query('DELETE FROM security.content_checkpoints WHERE workspace_id=$1',[fixture!.workspaceId]);});clearPlanningReplayCache();});
 const f=fixture=await fileServiceFixture(t),contributor=await f.joined('join_owner'),reviewer=await f.joined('join_owner'),owner=f.auth();
 await f.execute({action:'start_project'});await f.execute({action:'set_project_review',enabled:true,reviewers:[]},{outcome:'Independent document review'});
 const template=await f.context(),history=await f.history(),opened=await openVerifiedPlanning({context:template,history,accountId:f.accountId,deviceId:f.deviceId,historyPlaintext:false},f.originalBundle),key=base64urlDecode(opened.ring.at(-1)!.key,32),signing=base64urlDecode(f.originalBundle.signingPrivateKey,64);
 let graph=template.graph,lastVersion=template.binding.beforeVersion,lastHead=template.binding.beforeHead;const ids:string[]=[],payloads:PlanningPayload[]=[];
 try{for(let i=0;i<512;i++){
  const id=randomUUID(),operationId=randomUUID(),now=new Date(),binding={...template.binding,operationId,beforeVersion:lastVersion,beforeHead:lastHead,beforeGraphDigest:await planningGraphDigest(graph),before:planningRevisionSnapshot(graph),issuedAt:now.toISOString(),expiresAt:new Date(now.getTime()+600000).toISOString()} as PlanningContext['binding'];
  const content={title:`Document ${i+1}`,documentReference:`DOC-${String(i+1).padStart(4,'0')}`,description:'Work against the selected shared source.',acceptanceCriteria:'Return and independently review the exact output.',priority:'normal'},
   command=planningCommand.parse({action:'create_task',operationId,expected:binding.before,task:{id,phaseId:null,milestoneId:null,assigneeIds:[f.accountId,contributor.binding.accountId],leadProfileId:f.accountId,reviewerProfileId:reviewer.binding.accountId}}),result=evaluatePlanning(graph,command,planningAuthority(binding)),refs=planningChangedRecords(result),
   envelope=await encryptContent(planningContentHeader(binding,'task',id,'1'),content,key,signing),auditId=randomUUID(),auditEnvelope=await encryptContent(planningContentHeader(binding,'audit',auditId,'1'),{version:1,action:'create_task',changed:[{kind:'task',id,before:null,after:content}],snapshot:null,snapshotContents:[]},key,signing);
  const mutation=await signObject({purpose:'ukda.planning-mutation.v2' as const,binding:binding as Extract<typeof binding,{version:2}>,command,nextVersion:String(BigInt(lastVersion)+1n),afterGraphDigest:await planningGraphDigest(result.state),records:[{...refs[0]!,contentRevision:'1',digest:await digestObject(envelope)}],audit:{id:auditId,digest:await digestObject(auditEnvelope)},outcome:null},signing);
  const payload=planningPayload.parse({mutation,records:[{kind:'task',id,envelope}],audit:{id:auditId,envelope:auditEnvelope},outcome:null});payloads.push(payload);ids.push(id);graph=result.state;lastVersion=mutation.body.nextVersion;lastHead=await digestObject(mutation);
 }}finally{key.fill(0);signing.fill(0);}
 // Install only fixture-owned native, immutable creation rows. No bypass is
 // used for uploads, linking, submission, review, corrections or current reads.
 await transaction(f.admin.application,async c=>{await c.query("SELECT set_config('ukda.workspace_id',$1,true),set_config('ukda.profile_id',$2,true)",[f.workspaceId,f.accountId]);
  for(const p of payloads){const b=p.mutation.body.binding,r=p.records[0]!,task=graph.tasks.find(t=>t.id===r.id)!,requestHash=await digestObject(p),head=await digestObject(p.mutation),receipt=planningReceipt.parse({version:1,workspaceId:f.workspaceId,projectId:f.projectId,operationId:b.operationId,dataGeneration:b.dataGeneration,requestHash,planningVersion:p.mutation.body.nextVersion,planningHead:head,graphDigest:p.mutation.body.afterGraphDigest,committedAt:b.issuedAt,mutation:p.mutation});
   await c.query(`INSERT INTO app.tasks(workspace_id,id,project_id,state,revision,key_epoch,encrypted_envelope,lead_profile_id,content_revision,reviewer_profile_id) VALUES($1,$2,$3,'todo',1,$4,$5,$6,1,$7)`,[f.workspaceId,r.id,f.projectId,b.keyEpoch,r.envelope,f.accountId,reviewer.binding.accountId]);
   for(const member of task.assigneeIds)await c.query('INSERT INTO app.task_assignments(workspace_id,task_id,project_id,member_id,assigned_by) VALUES($1,$2,$3,$4,$5)',[f.workspaceId,r.id,f.projectId,member,f.accountId]);
   await c.query("INSERT INTO app.record_versions(workspace_id,id,project_id,record_type,record_id,record_revision,actor_profile_id,operation_id,key_epoch,encrypted_envelope) VALUES($1,$2,$3,'task',$4,1,$5,$6,$7,$8)",[f.workspaceId,randomUUID(),f.projectId,r.id,f.accountId,b.operationId,b.keyEpoch,r.envelope]);
   await c.query("INSERT INTO app.audit_events(workspace_id,id,project_id,actor_profile_id,operation_id,action,record_type,record_id,key_epoch,encrypted_envelope) VALUES($1,$2,$3,$4,$5,'planning.create_task','project',$3,$6,$7)",[f.workspaceId,p.audit.id,f.projectId,f.accountId,b.operationId,b.keyEpoch,p.audit.envelope]);
   await c.query('INSERT INTO app.planning_operations(workspace_id,project_id,operation_id,data_generation,planning_version,request_digest,signed_mutation,movements,receipt) VALUES($1,$2,$3,$4,$5,$6,$7,\'[]\',$8)',[f.workspaceId,f.projectId,b.operationId,b.dataGeneration,p.mutation.body.nextVersion,requestHash,p.mutation,receipt]);
  }
  await c.query('UPDATE app.project_planning_heads SET planning_version=$3,planning_head=$4,graph_digest=$5 WHERE workspace_id=$1 AND project_id=$2',[f.workspaceId,f.projectId,lastVersion,lastHead,await planningGraphDigest(graph)]);
 });
 payloads.length=0;const seeded=performance.now(),full=await f.context(),read=await readPlanning({context:full,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId,historyPlaintext:false},f.originalBundle);
 assert.equal(read.graph.tasks.length,512);assert.equal(read.records.filter(r=>r.kind==='task'&&typeof r.content.documentReference==='string').length,512);
 const source=await f.upload(await f.prepared('source',{size:256*1024+7}));let retried=false;
 for(let i=0;i<512;i+=64){const c=await f.files.context(owner.cookieValue,owner.csrfToken,f.reference()),request=await prepareFileLink({context:c.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId,binding:c.binding,fileId:source.manifest.body.fileId,taskIds:ids.slice(i,i+64),mode:'pinned',versionId:source.manifest.body.versionId,action:'link'},f.originalBundle);
  if(i===128){f.setFileHooks({afterCommit:async()=>{throw new Error('Lost bulk link response');}});await assert.rejects(f.files.link(owner.cookieValue,owner.csrfToken,request),/Lost bulk/);f.setFileHooks();retried=true;}
  await f.files.link(owner.cookieValue,owner.csrfToken,request);
 }
 assert.ok(retried);assert.equal((await f.admin.application.query('SELECT count(DISTINCT task_id)::int AS n FROM app.task_file_links WHERE workspace_id=$1',[f.workspaceId])).rows[0].n,512);
 const linked=performance.now(),outputs:Awaited<ReturnType<typeof f.prepared>>[]=[];
 for(const [index,taskId]of ids.slice(0,2).entries())outputs.push(await f.upload(await f.prepared('output',{taskIds:[taskId],size:index?128*1024:512*1024+9,storage:index?'external':'managed'},contributor.auth,contributor.bundle),contributor.auth));
 const evidence=new FileEvidenceService({...f,origin,planning:f.planning});
 async function submitReview(taskId:string,output:typeof outputs[number]){
  let c=await evidence.context(contributor.auth.cookieValue,contributor.auth.csrfToken,{...f.reference(),taskId}),input={context:c.planning,history:await f.history(),accountId:c.binding.accountId,deviceId:c.binding.deviceId};
  const proofs=await Promise.all(c.manifests.map(m=>prepareFileVerification({...input,manifest:m,...(m.body.storage==='external'?{file:new Blob([output.bytes])}:{chunks:m.body.versionId===source.manifest.body.versionId?source.chunks:output.chunks})},contributor.bundle)));
  const submission=await prepareFileSubmission({...input,evidence:c,proofs,submissionId:randomUUID()},contributor.bundle);await evidence.submit(contributor.auth.cookieValue,contributor.auth.csrfToken,submission);await evidence.submit(contributor.auth.cookieValue,contributor.auth.csrfToken,submission);
  await f.save(await f.preparePlanning({action:'request_task_completion',taskId,acceptanceConfirmed:true},{},contributor.auth,contributor.bundle),contributor.auth);
  c=await evidence.context(reviewer.auth.cookieValue,reviewer.auth.csrfToken,{...f.reference(),taskId});input={context:c.planning,history:await f.history(),accountId:c.binding.accountId,deviceId:c.binding.deviceId};
  const reviewProofs=await Promise.all(c.manifests.map(m=>prepareFileVerification({...input,manifest:m,...(m.body.storage==='external'?{file:new Blob([output.bytes])}:{chunks:m.body.versionId===source.manifest.body.versionId?source.chunks:output.chunks})},reviewer.bundle))),review=await prepareFileReview({...input,evidence:c,proofs:reviewProofs,approvalId:randomUUID()},reviewer.bundle);
  await evidence.review(reviewer.auth.cookieValue,reviewer.auth.csrfToken,review);await evidence.review(reviewer.auth.cookieValue,reviewer.auth.csrfToken,review);
  const task=c.planning.graph.tasks.find(t=>t.id===taskId)!;await f.save(await f.preparePlanning({action:'approve_task',taskId,submittedRevision:task.submittedRevision!,submittedPolicyRevision:task.submittedPolicyRevision!},{},reviewer.auth,reviewer.bundle),reviewer.auth);
 }
 for(let i=0;i<2;i++)await submitReview(ids[i]!,outputs[i]!);
 async function delivery(versionId:string){const p=await f.context(),history=await f.history(),resolve=planningSecurityResolver(history,await verifySecurityHistory(history));return tenantTransaction(f.databases.application,f.workspaceId,f.accountId,a=>assertDeliveryEvidence(a,p,versionId,resolve));}
 await delivery(outputs[0]!.manifest.body.versionId);await f.execute({action:'reopen_task',taskId:ids[0]!},{outcome:'Correct the returned file'});await assert.rejects(delivery(outputs[0]!.manifest.body.versionId),e=>e instanceof AppError&&e.code==='FILE_EVIDENCE_REQUIRED');
 const corrected=await f.upload(await f.prepared('output',{taskIds:[ids[0]!],size:512*1024+20,fileId:outputs[0]!.manifest.body.fileId,version:'2',priorVersionId:outputs[0]!.manifest.body.versionId},contributor.auth,contributor.bundle),contributor.auth);await submitReview(ids[0]!,corrected);await delivery(corrected.manifest.body.versionId);
 const version=await f.files.version(owner.cookieValue,owner.csrfToken,{...f.reference(),versionId:corrected.manifest.body.versionId}),chunks=[];for(let index=0;index<corrected.chunks.length;index++)chunks.push((await f.files.readChunk(owner.cookieValue,owner.csrfToken,{...f.reference(),versionId:corrected.manifest.body.versionId,index,purpose:'download'})).bytes);
 const finalContext=await f.context(),finalInput={context:finalContext,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId,historyPlaintext:false};assert.deepEqual(await readFileBytes({...finalInput,manifest:version.manifest,chunks},f.originalBundle),corrected.bytes);
 const [external]=await readFiles({...finalInput,manifests:[outputs[1]!.manifest]},f.originalBundle);assert.ok(external!.metadata.path);
 const service=new RestorationService({...f,origin}),checkpoint=await service.captureCheckpoint({workspaceId:f.workspaceId,checkpointId:randomUUID()},{operatorId:randomUUID()});assert.equal(checkpoint.manifest.body.version,2);if(checkpoint.manifest.body.version!==2)assert.fail();assert.equal(checkpoint.manifest.body.inventory.files.length,4);
 const quota=await f.files.context(owner.cookieValue,owner.csrfToken,f.reference()),storage=(await f.admin.application.query('SELECT sum(octet_length(cipher_bytes))::text AS bytes,count(*)::int AS chunks FROM app.file_chunks WHERE workspace_id=$1',[f.workspaceId])).rows[0];
 const measurement={measuredAt:new Date().toISOString(),node:process.version,tasks:512,documentLinks:512,contributors:2,independentReviewers:1,fullyReviewedRepresentativeTasks:2,corrections:1,sharedSources:1,managedVersions:3,externalReferences:1,
  operations:Number(finalContext.binding.beforeVersion),planningBytes:Buffer.byteLength(canonicalJson(finalContext)),binaryBytes:Number(storage.bytes),chunks:storage.chunks,quotaUsedBytes:quota.quota.usedBytes,quotaReservedBytes:quota.quota.reservedBytes,
  seedMs:Math.round(seeded-started),linkAndReadMs:Math.round(linked-seeded),representativeWorkflowMs:Math.round(performance.now()-linked),maxResidentMiB:Math.round(process.resourceUsage().maxRSS/1024),heapMiB:Math.round(process.memoryUsage().heapUsed/1024/1024),
  note:'Real isolated DB with512 genuinely signed document-task creations, shared pinned source for every task and representative real encrypted upload/review/correction/download/recovery inventory. Bulk link lost acknowledgement retries exactly. Task creation is fixture-seeded; only2 representative document tasks complete review. The separate2115-operation test covers all512 task lifecycles. Browser, actual local publication and physical WAL restore acceptance are separate.'};
 await mkdir('.local',{recursive:true});await writeFile('.local/files-capacity-measurement.json',JSON.stringify(measurement,null,2)+'\n',{mode:0o600});t.diagnostic(JSON.stringify(measurement));
});

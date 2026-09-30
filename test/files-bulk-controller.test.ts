import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {IDBFactory} from 'fake-indexeddb';
import {AppError} from '../src/errors.js';
import type {AuthController} from '../src/client/auth-controller.js';
import {PlanningController,HttpPlanningTransport} from '../src/client/planning-controller.js';
import {IndexedPlanningStore} from '../src/client/planning-store.js';
import {IndexedPairingStore} from '../src/client/pairing.js';
import {FilesController,HttpFilesTransport} from '../src/client/files-controller.js';
import {IndexedFilesStore} from '../src/client/files-store.js';
import {FileEvidenceController,HttpFileEvidenceTransport} from '../src/client/file-evidence-controller.js';
import {IndexedFileEvidenceStore} from '../src/client/file-evidence-store.js';
import {FileBulkController} from '../src/client/files-bulk.js';
import {IndexedFileBulkStore} from '../src/client/files-bulk-store.js';
import {sealFileBulk,openFileBulk} from '../src/client/files-bulk-crypto.js';
import {readPlanning,preparePlanning} from '../src/client/planning-crypto.js';
import {prepareFile,readFiles,readFileBytes,prepareFileLink,hashSelectedFile,FileClientError} from '../src/client/files-crypto.js';
import {prepareFileVerification,prepareFileSubmission,prepareFileReview,readFileEvidence} from '../src/client/file-evidence-crypto.js';
import {FileEvidenceService} from '../src/modules/files/evidence-service.js';
import {readAuthorizedSecurityHistoryPage} from '../src/modules/identity/security-history.js';
import {base64urlDecode,digestObject,signObject} from '../src/shared/crypto.js';
import {fileReview} from '../src/shared/file-evidence.js';
import {fileServiceFixture} from './files-fixture.js';
import {origin} from './password-change-fixture.js';

/** Actual controllers and cryptography with narrow HTTP dispatch directly to
 * the production services on isolated PostgreSQL; no fake business state. */
test('Bulk assignment and submission retain explicit mappings and successful items across lost acknowledgements',async t=>{
 const f=await fileServiceFixture(t),contributor=await f.joined('join_owner'),reviewer=await f.joined('join_owner'),owner=f.auth(),factory=new IDBFactory(),ids:string[]=[randomUUID(),randomUUID(),randomUUID()],refs=['DOC-A','DOC-B','DOC-C'];
 await f.execute({action:'start_project'});await f.execute({action:'set_project_review',enabled:true,reviewers:[]},{outcome:'Require independent document review'});
 for(let i=0;i<ids.length;i++)await f.execute({action:'create_task',task:{id:ids[i]!,phaseId:null,milestoneId:null,assigneeIds:[f.accountId],leadProfileId:f.accountId,reviewerProfileId:reviewer.binding.accountId}},{content:{title:`Document ${i+1}`,documentReference:refs[i]!}});
 const context=await f.context(),h=await f.history(),service=new FileEvidenceService({...f,origin,planning:f.planning}),
  pins=await IndexedPairingStore.open(origin,randomUUID(),factory),planningStore=await IndexedPlanningStore.open(origin,randomUUID(),factory),fileStore=await IndexedFilesStore.open(origin,randomUUID(),factory),
  evidenceName=randomUUID(),evidenceStore=await IndexedFileEvidenceStore.open(origin,evidenceName,factory),bulkStore=await IndexedFileBulkStore.open(origin,randomUUID(),factory);
 for(const store of [pins,planningStore,fileStore,evidenceStore,bulkStore])t.after(()=>store.close());await pins.recordVerifiedHistory(h);
 const worker={
  readPlanning:(v:Parameters<typeof readPlanning>[0])=>readPlanning(v,f.originalBundle),preparePlanning:(v:Parameters<typeof preparePlanning>[0])=>preparePlanning(v,f.originalBundle),
  prepareFile:(v:Parameters<typeof prepareFile>[0])=>prepareFile(v,f.originalBundle),readFiles:(v:Parameters<typeof readFiles>[0])=>readFiles(v,f.originalBundle),
  readFileBytes:(v:Parameters<typeof readFileBytes>[0])=>readFileBytes(v,f.originalBundle),prepareFileLink:(v:Parameters<typeof prepareFileLink>[0])=>prepareFileLink(v,f.originalBundle),hashFile:hashSelectedFile,
  prepareFileVerification:(v:Parameters<typeof prepareFileVerification>[0])=>prepareFileVerification(v,f.originalBundle),prepareFileSubmission:(v:Parameters<typeof prepareFileSubmission>[0])=>prepareFileSubmission(v,f.originalBundle),
  readFileEvidence:(v:Parameters<typeof readFileEvidence>[0])=>readFileEvidence(v,f.originalBundle),sealFileBulk:(v:Parameters<typeof sealFileBulk>[0])=>sealFileBulk(v,f.originalBundle),openFileBulk:(v:Parameters<typeof openFileBulk>[0])=>openFileBulk(v,f.originalBundle),
 },auth={origin,worker,current:()=>({localAccess:'unlocked',session:{workspaceId:f.workspaceId,accountId:f.accountId,deviceId:f.deviceId,credentialGeneration:context.binding.credentialGeneration,sessionGeneration:context.binding.sessionGeneration,dataGeneration:context.binding.dataGeneration}})} as unknown as AuthController;
 let loseAssignmentId:string|undefined,loseSubmissionId:string|undefined;let assignmentLost=false,submissionLost=false;
 const routes:Record<string,(body:unknown)=>Promise<unknown>>={
  '/v1/work/planning/context':b=>f.planning.context(owner.cookieValue,owner.csrfToken,b),
  '/v1/work/planning/history':body=>{const b=body as {workspaceId:string;projectId:string;operationId:string;afterVersion?:string;anchor?:{securityHead:string;securityVersion:string}};
   return f.planning.withAuthorizedHistory(owner.cookieValue,owner.csrfToken,b,(control,principal)=>readAuthorizedSecurityHistoryPage(control,{operationId:b.operationId,mode:'current',afterVersion:b.afterVersion??'0',...(b.anchor?{anchor:b.anchor}:{})},
    {workspaceId:b.workspaceId,current:{securityHead:principal.securityHead,securityVersion:principal.securityVersion},transcript:{securityHead:principal.securityHead,securityVersion:principal.securityVersion},lowerVersion:'1'}));},
  '/v1/work/planning/status':b=>f.planning.status(owner.cookieValue,owner.csrfToken,b),
  '/v1/work/planning/save':async b=>{const result=await f.planning.save(owner.cookieValue,owner.csrfToken,b);if(result.receipt?.operationId===loseAssignmentId&&!assignmentLost){assignmentLost=true;throw new Error('Lost committed assignment acknowledgement');}return result;},
  '/v1/files/context':b=>f.files.context(owner.cookieValue,owner.csrfToken,b),
  '/v1/files/version':b=>f.files.version(owner.cookieValue,owner.csrfToken,b),
  '/v1/files/versions':b=>f.files.versions(owner.cookieValue,owner.csrfToken,b),
  '/v1/files/begin':b=>f.files.begin(owner.cookieValue,owner.csrfToken,b),
  '/v1/files/chunk':b=>f.files.chunk(owner.cookieValue,owner.csrfToken,b),
  '/v1/files/complete':b=>f.files.complete(owner.cookieValue,owner.csrfToken,b),
  '/v1/files/read-chunk':b=>f.files.readChunk(owner.cookieValue,owner.csrfToken,b),
  '/v1/files/status':b=>f.files.status(owner.cookieValue,owner.csrfToken,b),
  '/v1/files/evidence/context':b=>service.context(owner.cookieValue,owner.csrfToken,b),
  '/v1/files/evidence/status':b=>service.status(owner.cookieValue,owner.csrfToken,b),
  '/v1/files/evidence/submit':async b=>{const result=await service.submit(owner.cookieValue,owner.csrfToken,b);if(result.receipt?.operationId===loseSubmissionId&&!submissionLost){submissionLost=true;throw new Error('Lost committed evidence acknowledgement');}return result;},
 };
 const fetcher:typeof fetch=async(url,init)=>{assert.equal(init?.method,'POST');assert.equal(new Headers(init.headers).get('X-CSRF-Token'),owner.csrfToken);const path=new URL(String(url)).pathname,action=routes[path];assert.ok(action,`Unexpected route ${path}`);
  let value:unknown,status=200;try{value=await action(JSON.parse(String(init.body)));}catch(error){if(!(error instanceof AppError))throw error;status=error.statusCode;value={error:{code:error.code}};}
  const response=new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});Object.defineProperty(response,'url',{value:String(url)});return response;};
 const access={refreshKeys:async()=>(await f.refresh()).refreshed},options={trustedServiceKeys:h.trustedServiceKeys??{}},planningTransport=new HttpPlanningTransport(origin,()=>owner.csrfToken,fetcher),
  planning=new PlanningController(auth,planningTransport,planningStore,pins,access,options),fileTransport=new HttpFilesTransport(origin,()=>owner.csrfToken,fetcher),
  files=new FilesController(auth,fileTransport,fileStore,pins,planningStore,access,planningTransport,options),evidence=new FileEvidenceController(auth,new HttpFileEvidenceTransport(origin,()=>owner.csrfToken,fetcher),fileTransport,evidenceStore,pins,planningStore,access,planningTransport,planning,options),
  bulk=new FileBulkController(auth,files,planning,evidence,bulkStore);
 await files.upload({projectId:f.projectId,file:new File(['Shared source'], 'source.txt',{type:'text/plain'}),kind:'source',storage:'managed',documentReference:'SOURCE',taskIds:ids});
 const assignment=await bulk.create({projectId:f.projectId,mode:'assign',label:'Explicit contributor mappings',items:ids.map((taskId,i)=>({taskId,documentReference:i===2?'WRONG-REFERENCE':refs[i]!,title:`Document ${i+1}`,assigneeIds:[f.accountId,contributor.binding.accountId],leadProfileId:f.accountId}))});
 loseAssignmentId=assignment.items[1]!.assignOperationId;
 const assigned=await bulk.execute(assignment.batchId);assert.ok(assignmentLost);assert.deepEqual(assigned.items.map(i=>i.state),['saved','error','error']);assert.equal(assigned.items[2]!.errorCode,'CONFLICT');
 const retry=await bulk.execute(assignment.batchId);assert.deepEqual(retry.items.map(i=>i.state),['saved','saved','error']);
 const assignmentCounts=(await f.admin.application.query("SELECT operation_id,count(*)::int AS n FROM app.planning_operations WHERE workspace_id=$1 AND operation_id=ANY($2::uuid[]) GROUP BY operation_id",[f.workspaceId,assignment.items.map(i=>i.assignOperationId)])).rows;
 assert.equal(assignmentCounts.length,2);assert.ok(assignmentCounts.every(r=>r.n===1));
 const assignedGraph=(await planning.read(f.projectId)).graph;assert.ok(assignedGraph.tasks.filter(t=>ids.slice(0,2).includes(t.id)).every(t=>t.assigneeIds.includes(contributor.binding.accountId)));assert.deepEqual(assignedGraph.tasks.find(t=>t.id===ids[2])!.assigneeIds,[f.accountId]);
 await assert.rejects(bulk.finish(assignment.batchId),e=>e instanceof FileClientError&&e.code==='CONFLICT');await bulk.discard(assignment.batchId);

 const selected=[new File(['Returned document A'],'return-a.txt',{type:'text/plain'}),new File(['Returned document B'],'return-b.txt',{type:'text/plain'})],
  submission=await bulk.create({projectId:f.projectId,mode:'submit',label:'Mapped returned documents',items:ids.slice(0,2).map((taskId,i)=>({taskId,documentReference:refs[i]!,title:`Document ${i+1}`,file:selected[i]!}))}),
  selection={files:Object.fromEntries(submission.items.map((item,i)=>[item.id,selected[i]!]))};
 loseSubmissionId=submission.items[1]!.submitOperationId;
 const first=await bulk.execute(submission.batchId,selection);assert.ok(submissionLost);assert.deepEqual(first.items.map(i=>i.state),['saved','error']);assert.equal(first.items[1]!.stage,'file_saved');
 const retried=await bulk.execute(submission.batchId,selection);assert.deepEqual(retried.items.map(i=>i.state),['saved','saved']);assert.ok(retried.items.every(i=>i.stage==='submitted'));
 const finished=await planning.read(f.projectId);assert.ok(finished.graph.tasks.filter(t=>ids.slice(0,2).includes(t.id)).every(t=>t.state==='review'));
 assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.file_submissions WHERE workspace_id=$1',[f.workspaceId])).rows[0].n,2);
 assert.equal((await f.admin.application.query("SELECT count(*)::int AS n FROM app.planning_operations WHERE workspace_id=$1 AND signed_mutation->'body'->'command'->>'action'='request_task_completion'",[f.workspaceId])).rows[0].n,2);
 assert.equal((await evidence.pending()).length,0);for(const item of submission.items)assert.equal((await evidenceStore.get(f.workspaceId,item.submitOperationId))?.completed,true);
 await bulk.finish(submission.batchId);assert.equal(await bulkStore.get(f.workspaceId,submission.batchId),undefined);

 // The displayed acknowledgement is a checkpoint, so a concurrent task edit
 // cannot silently submit the newly changed task or create another receipt.
 const displayed=await evidence.context(f.projectId,{taskId:ids[2]!});await f.execute({action:'assign_task',taskId:ids[2]!,assigneeIds:[f.accountId,contributor.binding.accountId],leadProfileId:f.accountId,teamId:null});
 const operationId=randomUUID();await assert.rejects(evidence.submit(f.projectId,ids[2]!,{operationId,reviewedContext:displayed}),e=>e instanceof FileClientError&&e.code==='CONFLICT');assert.equal(await evidenceStore.get(f.workspaceId,operationId),undefined);
 await assert.rejects(evidence.accept(f.projectId,ids[0]!,{operationId:submission.items[0]!.submitOperationId}),e=>e instanceof FileClientError&&e.code==='CONFLICT');
 // A fresh, unchanged acknowledgement succeeds despite different request
 // timestamps. A reviewer who authored the output cannot independently accept
 // it, even when they are an Owner and are not one of its assignees.
 const reviewerOutput=await f.upload(await f.prepared('output',{taskIds:[ids[2]!],size:77},reviewer.auth,reviewer.bundle),reviewer.auth),fresh=await evidence.context(f.projectId,{taskId:ids[2]!});
 assert.equal((await evidence.submit(f.projectId,ids[2]!,{reviewedContext:fresh})).state,'completed');
 const reviewContext=await service.context(reviewer.auth.cookieValue,reviewer.auth.csrfToken,{...f.reference(),taskId:ids[2]!}),reviewInput={context:reviewContext.planning,history:await f.history(),accountId:reviewContext.binding.accountId,deviceId:reviewContext.binding.deviceId,evidence:reviewContext},reviewProofs=[];
 for(const manifest of reviewContext.manifests){const chunks=[];for(let index=0;index<manifest.body.chunkHashes.length;index++)chunks.push((await f.files.readChunk(reviewer.auth.cookieValue,reviewer.auth.csrfToken,{...f.reference(),versionId:manifest.body.versionId,index,purpose:'preview'})).bytes);
  reviewProofs.push(await prepareFileVerification({...reviewInput,manifest,chunks},reviewer.bundle));}
 await assert.rejects(prepareFileReview({...reviewInput,proofs:reviewProofs,approvalId:randomUUID()},reviewer.bundle));
 const sub=reviewContext.submission!,task=reviewContext.planning.graph.tasks.find(t=>t.id===ids[2])!,body=fileReview.shape.body.parse({purpose:'ukda.file-review.v1',binding:reviewContext.binding,approvalId:randomUUID(),submissionId:sub.body.submissionId,submissionDigest:await digestObject(sub),taskId:task.id,taskContentRevision:sub.body.taskContentRevision,reviewPolicyRevision:sub.body.reviewPolicyRevision,reviewTaskRevision:task.revision,decision:'accept',verification:sub.body.verification}),signing=base64urlDecode(reviewer.bundle.signingPrivateKey,64);
 try{const request={review:fileReview.parse(await signObject(body,signing))};await assert.rejects(service.review(reviewer.auth.cookieValue,reviewer.auth.csrfToken,request),e=>e instanceof AppError&&e.code==='FILE_EVIDENCE_FORBIDDEN');}finally{signing.fill(0);}
 assert.equal(reviewContext.manifests.find(m=>m.body.versionId===reviewerOutput.manifest.body.versionId)!.body.binding.accountId,reviewer.binding.accountId);
 await evidence.forgetDevice({workspaceId:f.workspaceId,accountId:f.accountId,deviceId:f.deviceId});assert.equal(await evidenceStore.get(f.workspaceId,submission.items[0]!.submitOperationId),undefined);
 assert.ok(!(await files.pending()).length);assert.ok(!(await bulk.pending()).length);
});

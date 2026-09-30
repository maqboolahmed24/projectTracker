import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { tenantTransaction } from '../src/persistence.js';
import { FileEvidenceService,assertDeliveryEvidence } from '../src/modules/files/evidence-service.js';
import { prepareFileVerification,prepareFileSubmission,prepareFileReview,prepareSharedFileApproval,prepareFileRevocation } from '../src/client/file-evidence-crypto.js';
import { digestObject } from '../src/shared/crypto.js';
import { planningSecurityResolver } from '../src/client/planning-crypto.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { origin } from './password-change-fixture.js';
import { fileServiceFixture } from './files-fixture.js';
import {IDBFactory} from 'fake-indexeddb';
import {IndexedFileEvidenceStore,type StoredFileEvidence} from '../src/client/file-evidence-store.js';
import {FileEvidenceController} from '../src/client/file-evidence-controller.js';
import {FileClientError} from '../src/client/files-crypto.js';
const code=(expected:string)=>(e:unknown)=>e instanceof AppError&&e.code===expected;
test('Exact file evidence: actual bytes, independent review, immutable approved version, interrupted receipts and revocation',async t=>{
 const f=await fileServiceFixture(t),owner=f.auth(),reviewer=await f.joined('join_owner'),service=new FileEvidenceService({...f,origin,planning:f.planning}),taskId=randomUUID();
 await f.execute({action:'start_project'});await f.execute({action:'set_project_review',enabled:true,reviewers:[]},{outcome:'Require independent review'});
 await f.execute({action:'create_task',task:{id:taskId,phaseId:null,milestoneId:null,assigneeIds:[f.accountId],leadProfileId:f.accountId,reviewerProfileId:reviewer.binding.accountId}},{content:{title:'Private document review'}});
 const source=await f.upload(await f.prepared('source',{taskIds:[taskId],size:100})),output=await f.upload(await f.prepared('output',{taskIds:[taskId],size:120}));
 const uploaded=[source,output];
 async function context(auth=owner,bundle=f.originalBundle,target:{taskId?:string;versionId?:string}={taskId}){const evidence=await service.context(auth.cookieValue,auth.csrfToken,{...f.reference(),...target});
  return {evidence,context:evidence.planning,history:await f.history(),accountId:evidence.binding.accountId,deviceId:evidence.binding.deviceId,bundle};}
 async function proofs(c:Awaited<ReturnType<typeof context>>){return Promise.all(c.evidence.manifests.map(manifest=>prepareFileVerification({...c,manifest,chunks:uploaded.find(x=>x.manifest.body.versionId===manifest.body.versionId)!.chunks},c.bundle)));}
 await assert.rejects(f.execute({action:'request_task_completion',taskId,acceptanceConfirmed:true}),code('FILE_EVIDENCE_REQUIRED'));
 const first=await context(),submission=await prepareFileSubmission({...first,proofs:await proofs(first),submissionId:randomUUID()},f.originalBundle);
 const submitted=await service.submit(owner.cookieValue,owner.csrfToken,submission);assert.deepEqual(await service.submit(owner.cookieValue,owner.csrfToken,submission),submitted);
 // Completed signed receipts remain available for the stable operation IDs in
 // bulk retries, but never resume a different action, task or project.
 const factory=new IDBFactory(),name=randomUUID(),store=await IndexedFileEvidenceStore.open(origin,name,factory),b=submission.submission.body.binding,
  stored:StoredFileEvidence={completed:false,version:1,origin,workspaceId:f.workspaceId,accountId:f.accountId,deviceId:f.deviceId,operationId:b.operationId,flowOperationId:randomUUID(),taskId,action:'submit',payload:submission};
 await store.put(stored);await store.complete(f.workspaceId,b.operationId);assert.equal((await store.list(stored)).length,0);store.close();
 const reopened=await IndexedFileEvidenceStore.open(origin,name,factory);t.after(()=>reopened.close());assert.deepEqual((await reopened.get(f.workspaceId,b.operationId))?.payload,submission);
 await assert.rejects(reopened.put({...stored,flowOperationId:randomUUID()}),e=>e instanceof FileClientError&&e.code==='CONFLICT');
 type Args=ConstructorParameters<typeof FileEvidenceController>;
 const scoped={origin},auth={origin,current:()=>({localAccess:'unlocked',session:{workspaceId:f.workspaceId,accountId:f.accountId,deviceId:f.deviceId,dataGeneration:b.dataGeneration}})} as unknown as Args[0],
  controller=new FileEvidenceController(auth,scoped as unknown as Args[1],scoped as unknown as Args[2],reopened,scoped as unknown as Args[4],scoped as unknown as Args[5],{} as Args[6],{} as Args[7],{} as Args[8]);
 const conflict=(e:unknown)=>e instanceof FileClientError&&e.code==='CONFLICT';
 await assert.rejects(controller.accept(f.projectId,taskId,{operationId:b.operationId}),conflict);
 await assert.rejects(controller.submit(f.projectId,randomUUID(),{operationId:b.operationId}),conflict);
 await assert.rejects(controller.submit(randomUUID(),taskId,{operationId:b.operationId}),conflict);
 await reopened.forgetDevice(stored);assert.equal(await reopened.get(f.workspaceId,b.operationId),undefined);
 assert.equal((await service.status(owner.cookieValue,owner.csrfToken,{workspaceId:f.workspaceId,projectId:f.projectId,operationId:submission.submission.body.binding.operationId,dataGeneration:submission.submission.body.binding.dataGeneration,requestHash:await digestObject(submission)})).state,'completed');
 await f.execute({action:'request_task_completion',taskId,acceptanceConfirmed:true});
 const ownReview=await context();await assert.rejects(prepareFileReview({...ownReview,proofs:await proofs(ownReview),approvalId:randomUUID()},f.originalBundle));
 const reviewing=await context(reviewer.auth,reviewer.bundle),review=await prepareFileReview({...reviewing,proofs:await proofs(reviewing),approvalId:randomUUID()},reviewer.bundle);
 const pendingTask=reviewing.evidence.planning.graph.tasks.find(x=>x.id===taskId)!;
 await assert.rejects(f.save(await f.preparePlanning({action:'approve_task',taskId,submittedRevision:pendingTask.submittedRevision!,submittedPolicyRevision:pendingTask.submittedPolicyRevision!},{},reviewer.auth,reviewer.bundle),reviewer.auth),code('FILE_EVIDENCE_REQUIRED'));
 const accepted=await service.review(reviewer.auth.cookieValue,reviewer.auth.csrfToken,review);assert.deepEqual(await service.review(reviewer.auth.cookieValue,reviewer.auth.csrfToken,review),accepted);
 async function delivery(){const p=await f.context(),h=await f.history(),resolve=planningSecurityResolver(h,await verifySecurityHistory(h));
  return tenantTransaction(f.databases.application,f.workspaceId,f.accountId,a=>assertDeliveryEvidence(a,p,output.manifest.body.versionId,resolve));}
 await assert.rejects(delivery(),code('FILE_EVIDENCE_REQUIRED'));
 const task=reviewing.evidence.planning.graph.tasks.find(x=>x.id===taskId)!;
 const approval=await f.preparePlanning({action:'approve_task',taskId,submittedRevision:task.submittedRevision!,submittedPolicyRevision:task.submittedPolicyRevision!},{},reviewer.auth,reviewer.bundle);await f.save(approval,reviewer.auth);
 assert.equal((await delivery()).approvalId,review.review.body.approvalId);
 const hidden=JSON.stringify((await f.admin.application.query('SELECT signed_submission AS payload FROM app.file_submissions WHERE workspace_id=$1 UNION ALL SELECT signed_review FROM app.file_reviews WHERE workspace_id=$1',[f.workspaceId])).rows);
 assert.equal(hidden.includes('Private document review'),false);assert.equal(hidden.includes('/Volumes/'),false);
 const revokeContext=await context(),revocation=await prepareFileRevocation({...revokeContext,approvalId:review.review.body.approvalId,reason:'Private withdrawal'},f.originalBundle);
 await service.revoke(owner.cookieValue,owner.csrfToken,revocation);await assert.rejects(delivery(),code('FILE_EVIDENCE_REQUIRED'));
 await f.execute({action:'reopen_task',taskId},{outcome:'Correct the document'});await assert.rejects(delivery(),code('FILE_EVIDENCE_REQUIRED'));
 // A shared source requires explicit Owner approval and actual selected bytes.
 const external=await f.upload(await f.prepared('source',{storage:'external',size:90})),shared=await context(owner,f.originalBundle,{versionId:external.manifest.body.versionId});
 await assert.rejects(prepareFileVerification({...shared,manifest:external.manifest,file:new Blob([new Uint8Array(90)])},f.originalBundle));
 const proof=await prepareFileVerification({...shared,manifest:external.manifest,file:new Blob([external.bytes])},f.originalBundle),sharedApproval=await prepareSharedFileApproval({...shared,proofs:[proof],approvalId:randomUUID()},f.originalBundle);
 await service.approveShared(owner.cookieValue,owner.csrfToken,sharedApproval);
 await assert.rejects(f.admin.application.query('UPDATE app.file_reviews SET signed_review=$3 WHERE workspace_id=$1 AND id=$2',[f.workspaceId,review.review.body.approvalId,sharedApproval.approval]));
 const bad=structuredClone(submission);bad.submission.body.outputs[0]!.versionId=randomUUID();await assert.rejects(service.submit(owner.cookieValue,owner.csrfToken,bad),code('FILE_EVIDENCE_CHANGED'));
});

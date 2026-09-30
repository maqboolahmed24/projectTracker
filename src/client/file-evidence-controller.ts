import type { z } from 'zod';
import { identifier } from '../shared/contracts.js';
import { canonicalJson,digestObject } from '../shared/crypto.js';
import { evidenceContext,evidenceView,type EvidenceContext,type EvidenceReceipt,type EvidenceView,type FileVerification } from '../shared/file-evidence.js';
import { PLANNING_MAX_BYTES } from '../shared/planning-api.js';
import { verifySecurityHistory,type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthenticatedHttp,AuthClientError,type AuthController,type AuthRequestOptions } from './auth-controller.js';
import { FileClientError } from './files-crypto.js';
import { IndexedPairingStore } from './pairing.js';
import { IndexedPlanningStore } from './planning-store.js';
import { IndexedFileEvidenceStore,type StoredFileEvidence } from './file-evidence-store.js';
import type { AccessChangeController } from './access-change-controller.js';
import type { PlanningTransport,PlanningController } from './planning-controller.js';
import type { HttpFilesTransport } from './files-controller.js';
import type { ReadPlanningInput } from './planning-crypto.js';
import { assertOnline } from './write-state.js';
type Reference={workspaceId:string;projectId:string;operationId:string};
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
export class HttpFileEvidenceTransport extends AuthenticatedHttp {
 constructor(origin:string,private readonly csrfToken:()=>string|undefined,fetcher?:typeof fetch){super(origin,fetcher);}
 protected override responseLimit(){return PLANNING_MAX_BYTES;}
 private request<T>(path:string,body:unknown,schema:z.ZodType<T>,o?:AuthRequestOptions){const csrfToken=this.csrfToken();if(!csrfToken)throw new AuthClientError('AUTH_REQUIRED');return this.post(`/v1/files/evidence/${path}`,body,schema,{...o,csrfToken});}
 context(r:Reference&{taskId?:string;versionId?:string},o?:AuthRequestOptions):Promise<EvidenceContext>{return this.request('context',r,evidenceContext,o);}
 save(action:StoredFileEvidence['action'],payload:StoredFileEvidence['payload'],o?:AuthRequestOptions){return this.request(action==='accept'?'review':action==='approve_shared'?'approve-shared':action,payload,evidenceView,o);}
 status(r:Reference&{dataGeneration:string;requestHash:string},o?:AuthRequestOptions){return this.request('status',r,evidenceView,o);}
}
export interface EvidenceSelection {operationId?:string;reviewedContext?:EvidenceContext;externalFiles?:Record<string,Blob>;onProgress?:(checked:number,total:number)=>void}
export interface EvidenceProgress {state:'completed';operationId:string;evidenceId:string;taskId:string|null;receipt:EvidenceReceipt}
/** Only the bounded values the person acknowledged, excluding read-request
 * identities and timestamps. Never serialize the assembled planning history. */
function reviewCheckpoint(context:EvidenceContext){const b=context.binding,p=context.planning.binding,t=context.planning.graph.tasks.find(t=>t.id===context.taskId);
 return canonicalJson({workspaceId:b.workspaceId,projectId:b.projectId,accountId:b.accountId,deviceId:b.deviceId,dataGeneration:b.dataGeneration,securityHead:b.securityHead,
  securityVersion:b.securityVersion,keyEpoch:b.keyEpoch,permissionVersion:b.permissionVersion,planningHead:p.beforeHead,planningVersion:p.beforeVersion,
  task:t?{id:t.id,revision:t.revision,contentRevision:t.contentRevision,state:t.state,submittedRevision:t.submittedRevision,submittedPolicyRevision:t.submittedPolicyRevision,assigneeIds:t.assigneeIds,reviewerProfileId:t.reviewerProfileId}:null,
  sources:context.sources,outputs:context.outputs,submission:context.submission,approval:context.approval,revocation:context.revocation});
}
/** Exactly one evidence write followed by exactly one existing planning transition. */
export class FileEvidenceController {
 private epoch=0;private readonly requests=new Set<AbortController>();private readonly running=new Set<Promise<unknown>>();
 constructor(private readonly auth:AuthController,private readonly transport:HttpFileEvidenceTransport,private readonly files:HttpFilesTransport,
  private readonly store:IndexedFileEvidenceStore,private readonly pins:IndexedPairingStore,private readonly planningPins:IndexedPlanningStore,
  private readonly access:Pick<AccessChangeController,'refreshKeys'>,private readonly security:Pick<PlanningTransport,'history'>,private readonly planning:PlanningController,
  private readonly options:{trustedServiceKeys?:Record<string,string>;onWrite?:()=>void}={}){
  if([transport.origin,files.origin,store.origin,pins.origin,planningPins.origin].some(o=>o!==auth.origin))throw new FileClientError('CONFLICT');}
 clear(){this.epoch++;for(const r of this.requests)r.abort();this.requests.clear();}
 attachAuthLifecycle(){const a=this.auth.onClear(()=>this.clear()),b=this.auth.onForget(r=>this.forgetDevice(r));return()=>{a();b();};}
 async forgetDevice(r:{workspaceId:string;accountId:string;deviceId:string}){this.clear();await Promise.allSettled([...this.running]);await this.store.forgetDevice(r);}
 private check(e:number,s:AbortSignal){if(e!==this.epoch||s.aborted)throw new FileClientError('CANCELLED');}
 private run<T>(action:(signal:AbortSignal,epoch:number)=>Promise<T>){assertOnline();const r=new AbortController(),e=this.epoch;this.requests.add(r);const result=action(r.signal,e).then(v=>{this.check(e,r.signal);return v;});this.running.add(result);
  void result.finally(()=>{this.requests.delete(r);this.running.delete(result);}).catch(()=>{});return result;}
 private session(){const s=this.auth.current();if(s?.localAccess!=='unlocked'||!s.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');return s.session;}
 private reference(projectId:string,operationId:string=crypto.randomUUID()):Reference{return {workspaceId:this.session().workspaceId,projectId:identifier.parse(projectId),operationId:identifier.parse(operationId)};}
 private async current(ref:Reference,target:{taskId?:string;versionId?:string},signal:AbortSignal,epoch:number){const session=this.session();await this.access.refreshKeys();this.check(epoch,signal);
  const context=await this.transport.context({...ref,...target},{signal});this.check(epoch,signal);const b=context.binding;
  if(b.workspaceId!==ref.workspaceId||b.projectId!==ref.projectId||b.operationId!==ref.operationId||b.accountId!==session.accountId||b.deviceId!==session.deviceId)throw new FileClientError('CONFLICT');
  const pin=await this.pins.pin(ref.workspaceId);if(!pin)throw new FileClientError('INCOMPLETE_KEYS');const response=await this.security.history(ref,{signal});this.check(epoch,signal);if(!same(response.anchor,response.current))throw new FileClientError('CONFLICT');
  const history:SecurityHistoryInput={workspaceId:ref.workspaceId,origin:this.auth.origin,genesisFingerprint:pin.genesisFingerprint,genesis:response.genesis,transitions:response.transitions,expected:response.anchor,pin,trustedServiceKeys:this.options.trustedServiceKeys??{}};
  const state=await verifySecurityHistory(history),p=state.profiles[session.accountId],d=state.devices[session.deviceId!];this.check(epoch,signal);
  if(!p?.active||!d?.active||d.accountId!==session.accountId||p.credentialGeneration!==session.credentialGeneration||p.sessionGeneration!==session.sessionGeneration||state.dataGeneration!==session.dataGeneration)throw new FileClientError('CONFLICT');
  const planningPin=await this.planningPins.pin(ref),input:ReadPlanningInput={context:context.planning,history,historyPlaintext:false,accountId:session.accountId,deviceId:session.deviceId!,...(planningPin?{pin:planningPin}:{})};
  const read=await this.auth.worker.readPlanning(input,{signal});this.check(epoch,signal);await this.auth.worker.readFileEvidence({...input,evidence:context},{signal});this.check(epoch,signal);
  await this.planningPins.recordPin(read.pin);await this.pins.recordVerifiedHistory(history);this.check(epoch,signal);return {context,input,pin:read.pin};
 }
 context(projectId:string,target:{taskId?:string;versionId?:string}){return this.run(async(s,e)=>(await this.current(this.reference(projectId),target,s,e)).context);}
 private async proofs(current:{context:EvidenceContext;input:ReadPlanningInput},selection:EvidenceSelection,signal:AbortSignal,epoch:number){const refs=[...current.context.sources,...current.context.outputs],proofs:FileVerification[]=[];
  for(const reference of refs){const manifest=current.context.manifests.find(m=>m.body.versionId===reference.versionId);if(!manifest)throw new FileClientError('INVALID_FILE');const chunks:string[]=[];
   if(manifest.body.storage==='managed')for(let index=0;index<manifest.body.chunkHashes.length;index++){const chunk=await this.files.readChunk({...this.reference(manifest.body.binding.projectId),versionId:reference.versionId,index,purpose:'preview'},{signal});this.check(epoch,signal);if(chunk.index!==index||chunk.digest!==manifest.body.chunkHashes[index])throw new FileClientError('INVALID_FILE');chunks.push(chunk.bytes);}
   const file=selection.externalFiles?.[reference.versionId];if(manifest.body.storage==='external'&&!file)throw new FileClientError('CHANGED_FILE');
   proofs.push(await this.auth.worker.prepareFileVerification({...current.input,manifest,...(manifest.body.storage==='managed'?{chunks}:{file:file!})},{signal}));this.check(epoch,signal);selection.onProgress?.(proofs.length,refs.length);
  }return proofs;
 }
 private async write(projectId:string,target:{taskId?:string;versionId?:string},action:StoredFileEvidence['action'],selection:EvidenceSelection={},reason=''):Promise<EvidenceProgress>{return this.run(async(signal,epoch)=>{
  const reviewed=selection.reviewedContext?reviewCheckpoint(selection.reviewedContext):undefined,
   ref=this.reference(projectId,selection.operationId),s=this.session(),saved=await this.store.get(ref.workspaceId,ref.operationId);this.check(epoch,signal);
  if(saved){const payload=saved.payload,b='submission'in payload?payload.submission.body.binding:'review'in payload?payload.review.body.binding:'approval'in payload?payload.approval.body.binding:payload.revocation.body.binding;
   if(saved.action!==action||saved.taskId!==(target.taskId??null)||b.projectId!==ref.projectId||
    (target.versionId&&(!('approval'in payload)||payload.approval.body.reference.versionId!==target.versionId)))throw new FileClientError('CONFLICT');
   return this.finish(saved,signal,epoch);
  }
  const current=await this.current(ref,target,signal,epoch);if(reviewed!==undefined&&reviewed!==reviewCheckpoint(current.context))throw new FileClientError('CONFLICT');let payload:StoredFileEvidence['payload'];
  if(action==='revoke') {const approvalId=current.context.approval?.body.approvalId;if(!approvalId)throw new FileClientError('INVALID_FILE');payload=await this.auth.worker.prepareFileRevocation({...current.input,evidence:current.context,approvalId,reason},{signal});}
  else {const proofs=await this.proofs(current,selection,signal,epoch);
   payload=action==='submit'?await this.auth.worker.prepareFileSubmission({...current.input,evidence:current.context,proofs,submissionId:ref.operationId},{signal}):
    action==='accept'?await this.auth.worker.prepareFileReview({...current.input,evidence:current.context,proofs,approvalId:ref.operationId},{signal}):
    await this.auth.worker.prepareSharedFileApproval({...current.input,evidence:current.context,proofs,approvalId:ref.operationId},{signal});
  }
  this.check(epoch,signal);const record:StoredFileEvidence={completed:false,version:1,origin:this.auth.origin,workspaceId:ref.workspaceId,accountId:s.accountId,deviceId:s.deviceId!,operationId:ref.operationId,flowOperationId:crypto.randomUUID(),taskId:target.taskId??null,action,payload};
  await this.store.put(record);this.check(epoch,signal);return this.finish(record,signal,epoch);
 });}
 submit(projectId:string,taskId:string,selection:EvidenceSelection={}){return this.write(projectId,{taskId},'submit',selection);}
 accept(projectId:string,taskId:string,selection:EvidenceSelection={}){return this.write(projectId,{taskId},'accept',selection);}
 approveShared(projectId:string,versionId:string,selection:EvidenceSelection={}){return this.write(projectId,{versionId},'approve_shared',selection);}
 revoke(projectId:string,target:{taskId?:string;versionId?:string},reason=''){return this.write(projectId,target,'revoke',{},reason);}
 private async finish(record:StoredFileEvidence,signal:AbortSignal,epoch:number):Promise<EvidenceProgress>{const s=this.session(),payload=record.payload,b='submission'in payload?payload.submission.body.binding:'review'in payload?payload.review.body.binding:'approval'in payload?payload.approval.body.binding:payload.revocation.body.binding,
  ref=this.reference(b.projectId,record.operationId),requestHash=await digestObject(payload);if(record.accountId!==s.accountId||record.deviceId!==s.deviceId||b.dataGeneration!==s.dataGeneration)throw new FileClientError('CONFLICT');
  let view:EvidenceView=await this.transport.status({...ref,dataGeneration:b.dataGeneration,requestHash},{signal});this.check(epoch,signal);if(view.state==='absent')view=await this.transport.save(record.action,payload,{signal});this.check(epoch,signal);
  const r=view.receipt;if(!r||view.state!=='completed'||r.requestHash!==requestHash||r.operationId!==record.operationId||r.projectId!==b.projectId||r.workspaceId!==s.workspaceId||r.dataGeneration!==s.dataGeneration||r.action!==record.action)throw new FileClientError('CONFLICT');
  if(record.taskId&&(record.action==='submit'||record.action==='accept')){
   const pending=(await this.planning.pending()).find(x=>x.operationId===record.flowOperationId);this.check(epoch,signal);
   if(pending){await this.planning.resume(record.flowOperationId);this.check(epoch,signal);}
   else {const current=await this.current(ref,{taskId:record.taskId},signal,epoch),t=current.context.planning.graph.tasks.find(t=>t.id===record.taskId);if(!t)throw new FileClientError('CONFLICT');
    const already=current.context.planning.history.some(m=>m.body.binding.operationId===record.flowOperationId&&('taskId'in m.body.command)&&m.body.command.taskId===record.taskId&&m.body.command.action===(record.action==='submit'?'request_task_completion':'approve_task'));
    if(!already){
     if('submission'in payload){if(t.revision!==payload.submission.body.taskRevision)throw new FileClientError('CONFLICT');await this.planning.execute({projectId:b.projectId,operationId:record.flowOperationId,reviewed:current.pin,command:{action:'request_task_completion',taskId:record.taskId,acceptanceConfirmed:true}});}
     else if('review'in payload){if(current.context.revocation||t.revision!==payload.review.body.reviewTaskRevision||!t.submittedRevision||!t.submittedPolicyRevision)throw new FileClientError('CONFLICT');await this.planning.execute({projectId:b.projectId,operationId:record.flowOperationId,reviewed:current.pin,command:{action:'approve_task',taskId:record.taskId,submittedRevision:t.submittedRevision,submittedPolicyRevision:t.submittedPolicyRevision}});}
    }this.check(epoch,signal);
   }
  }
  await this.store.complete(ref.workspaceId,record.operationId);this.check(epoch,signal);this.options.onWrite?.();return {state:'completed',operationId:record.operationId,evidenceId:r.evidenceId,taskId:record.taskId,receipt:r};
 }
 pending(){const s=this.session();return this.store.list({workspaceId:s.workspaceId,accountId:s.accountId,deviceId:s.deviceId!});}
 resume(operationId:string){return this.run(async(s,e)=>{const r=await this.store.get(this.session().workspaceId,operationId);this.check(e,s);if(!r)throw new FileClientError('INVALID_FILE');return this.finish(r,s,e);});}
 discard(operationId:string){return this.store.remove(this.session().workspaceId,operationId);}
}

import { canonicalJson } from '../shared/crypto.js';
import { FILE_MAX_BATCH_BYTES,FILE_MAX_BATCH_ITEMS } from '../shared/files.js';
import { AuthClientError,type AuthController } from './auth-controller.js';
import { FileClientError } from './files-crypto.js';
import { fileBulkDraft,type FileBulkDraft,type FileBulkItem } from './files-bulk-crypto.js';
import type { IndexedFileBulkStore } from './files-bulk-store.js';
import type { FilesController } from './files-controller.js';
import type { FileEvidenceController } from './file-evidence-controller.js';
import type { PlanningController } from './planning-controller.js';
import type { ReadPlanningInput } from './planning-crypto.js';
import { assertOnline } from './write-state.js';

export type BulkMode=FileBulkDraft['mode'];
export interface BulkItemInput {id?:string;taskId?:string;documentReference:string;title:string;file?:File;storage?:'managed'|'external';path?:string;
 assigneeIds?:string[];leadProfileId?:string|null;reviewerProfileId?:string|null;phaseId?:string|null;existingFileId?:string;expectedVersionId?:string;skip?:boolean}
export interface BulkSelection {files?:Record<string,File>;externalFiles?:Record<string,Blob>;onProgress?:(draft:FileBulkDraft)=>void}
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
/** Finite, explicit mappings with stable operation identities and encrypted per-item outcomes. */
export class FileBulkController {
 private epoch=0;private readonly active=new Set<string>();private readonly paused=new Set<string>();private readonly running=new Set<Promise<unknown>>();
 constructor(private readonly auth:AuthController,private readonly files:FilesController,private readonly planning:PlanningController,private readonly evidence:FileEvidenceController,private readonly store:IndexedFileBulkStore){if(auth.origin!==store.origin)throw new FileClientError('CONFLICT');}
 clear(){this.epoch++;this.paused.clear();}
 attachAuthLifecycle(){const a=this.auth.onClear(()=>this.clear()),b=this.auth.onForget(r=>this.forgetDevice(r));return()=>{a();b();};}
 async forgetDevice(r:{workspaceId:string;accountId:string;deviceId:string}){this.clear();await Promise.allSettled([...this.running]);await this.store.forgetDevice(r);}
 private session(){const s=this.auth.current();if(s?.localAccess!=='unlocked'||!s.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');return s.session;}
 private check(epoch:number){if(epoch!==this.epoch)throw new FileClientError('CANCELLED');this.session();}
 private track<T>(work:()=>Promise<T>){const result=work();this.running.add(result);void result.finally(()=>this.running.delete(result)).catch(()=>{});return result;}
 private async save(draft:FileBulkDraft,input:ReadPlanningInput,initial=false){const before=draft.revision,next=initial?draft:{...draft,revision:String(BigInt(before)+1n)},encrypted=await this.auth.worker.sealFileBulk({...input,draft:next});await this.store.put(encrypted,initial?null:before);draft.revision=next.revision;}
 create(input:{projectId:string;mode:BulkMode;label:string;items:BulkItemInput[]}):Promise<FileBulkDraft>{return this.track(async()=>{assertOnline();const epoch=this.epoch;if(!input.items.length||input.items.length>FILE_MAX_BATCH_ITEMS)throw new FileClientError('TOO_LARGE');if(input.items.reduce((n,i)=>n+((i.storage??'managed')==='managed'?(i.file?.size??0):0),0)>FILE_MAX_BATCH_BYTES)throw new FileClientError('TOO_LARGE');
  const current=await this.files.verifiedContext(input.projectId);this.check(epoch);const items:FileBulkItem[]=[];
  if(input.mode==='register'&&current.context.planning.graph.tasks.length+input.items.filter(i=>!i.skip).length>512)throw new FileClientError('TOO_LARGE');
  for(const i of input.items){if(input.mode!=='register'&&!i.taskId)throw new FileClientError('INVALID_FILE');const hash=i.file&&!i.skip?await this.auth.worker.hashFile(i.file):null;this.check(epoch);
   items.push({id:i.id??crypto.randomUUID(),taskId:i.taskId??crypto.randomUUID(),createOperationId:crypto.randomUUID(),uploadOperationId:crypto.randomUUID(),submitOperationId:crypto.randomUUID(),assignOperationId:crypto.randomUUID(),fileId:i.existingFileId??crypto.randomUUID(),versionId:crypto.randomUUID(),existingFileId:i.existingFileId??null,expectedVersionId:i.expectedVersionId??null,documentReference:i.documentReference,title:i.title,filename:i.file?.name??'',plainBytes:i.file?.size??0,sha256:hash,storage:i.storage??'managed',path:i.path??'',assigneeIds:i.assigneeIds??[],leadProfileId:i.leadProfileId??null,reviewerProfileId:i.reviewerProfileId??null,phaseId:i.phaseId??null,state:i.skip?'skipped':'ready',stage:'pending',errorCode:null});
  }
  const draft=fileBulkDraft.parse({version:1,batchId:crypto.randomUUID(),projectId:input.projectId,mode:input.mode,label:input.label,createdAt:new Date().toISOString(),revision:'0',items});await this.save(draft,current.input,true);this.check(epoch);return draft;
 });}
 async read(batchId:string):Promise<FileBulkDraft>{const epoch=this.epoch,s=this.session(),record=await this.store.get(s.workspaceId,batchId);this.check(epoch);if(!record)throw new FileClientError('INVALID_FILE');const current=await this.files.verifiedContext(record.projectId);this.check(epoch);const draft=await this.auth.worker.openFileBulk({...current.input,record});this.check(epoch);return draft;}
 async pending(projectId?:string):Promise<FileBulkDraft[]>{const epoch=this.epoch,s=this.session(),records=await this.store.list({workspaceId:s.workspaceId,accountId:s.accountId,deviceId:s.deviceId!}),result:FileBulkDraft[]=[];for(const record of records){if(projectId&&record.projectId!==projectId)continue;const current=await this.files.verifiedContext(record.projectId);this.check(epoch);result.push(await this.auth.worker.openFileBulk({...current.input,record}));this.check(epoch);}return result;}
 pause(batchId:string){this.paused.add(batchId);}
 async finish(batchId:string){const draft=await this.read(batchId);if(this.active.has(batchId)||draft.items.some(i=>!['saved','skipped'].includes(i.state)))throw new FileClientError('CONFLICT');await this.store.remove(this.session().workspaceId,batchId);}
 async discard(batchId:string){await this.read(batchId);if(this.active.has(batchId))throw new FileClientError('CONFLICT');await this.store.remove(this.session().workspaceId,batchId);}
 execute(batchId:string,selection:BulkSelection={}):Promise<FileBulkDraft>{if(this.active.has(batchId))return Promise.reject(new AuthClientError('BUSY'));this.active.add(batchId);this.paused.delete(batchId);return this.track(async()=>{
  assertOnline();const epoch=this.epoch,s=this.session(),record=await this.store.get(s.workspaceId,batchId);this.check(epoch);if(!record)throw new FileClientError('INVALID_FILE');const current=await this.files.verifiedContext(record.projectId);this.check(epoch);const draft=await this.auth.worker.openFileBulk({...current.input,record});this.check(epoch);
  const persist=async()=>{this.check(epoch);await this.save(draft,current.input);this.check(epoch);selection.onProgress?.(structuredClone(draft));};
  for(const item of draft.items){if(['saved','skipped'].includes(item.state))continue;if(this.paused.has(batchId))break;this.check(epoch);item.state='working';item.errorCode=null;await persist();
   try{
    if(draft.mode==='assign'){const view=await this.planning.read(draft.projectId);this.check(epoch);const target=view.records.find(r=>r.kind==='task'&&r.id===item.taskId);if(!target||target.content.documentReference!==item.documentReference)throw new FileClientError('CONFLICT');if(!view.audits.some(a=>a.operationId===item.assignOperationId)){
      const pending=await this.planning.pending();this.check(epoch);if(pending.some(p=>p.operationId===item.assignOperationId))await this.planning.resume(item.assignOperationId);else await this.planning.execute({projectId:draft.projectId,operationId:item.assignOperationId,reviewed:view.pin,command:{action:'assign_task',taskId:item.taskId,assigneeIds:item.assigneeIds,leadProfileId:item.leadProfileId,teamId:view.graph.tasks.find(t=>t.id===item.taskId)?.teamId??null}});
     }this.check(epoch);item.stage='assigned';
    }else{
     if(draft.mode==='submit'&&item.stage!=='submitted'){const view=await this.planning.read(draft.projectId);this.check(epoch);const target=view.records.find(r=>r.kind==='task'&&r.id===item.taskId);if(!target||target.content.documentReference!==item.documentReference)throw new FileClientError('CONFLICT');}
     if(draft.mode==='register'&&item.stage==='pending'){const view=await this.planning.read(draft.projectId);this.check(epoch);const existing=view.graph.tasks.find(t=>t.id===item.taskId);
      if(existing){if(!view.audits.some(a=>a.operationId===item.createOperationId)||view.records.find(r=>r.kind==='task'&&r.id===item.taskId)?.content.documentReference!==item.documentReference)throw new FileClientError('CONFLICT');}
      else{if(view.records.some(r=>r.kind==='task'&&String(r.content.documentReference??'').trim().toLowerCase()===item.documentReference.toLowerCase()))throw new FileClientError('CONFLICT');const attempts=await this.planning.pending();if(attempts.some(p=>p.operationId===item.createOperationId))await this.planning.resume(item.createOperationId);else await this.planning.createTask({projectId:draft.projectId,taskId:item.taskId,operationId:item.createOperationId,title:item.title,documentReference:item.documentReference,assigneeIds:item.assigneeIds,leadProfileId:item.leadProfileId,reviewerProfileId:item.reviewerProfileId,phaseId:item.phaseId});}
      this.check(epoch);item.stage='task_created';await persist();
     }
     if(!['file_saved','submitted'].includes(item.stage)){let saved=false;try{const v=await this.files.version(draft.projectId,item.versionId);this.check(epoch);if(v.state==='ready'&&v.manifest.body.binding.operationId===item.uploadOperationId&&v.manifest.body.fileId===item.fileId&&v.metadata.sha256===item.sha256&&v.metadata.documentReference===item.documentReference)saved=true;else if(v.state==='ready')throw new FileClientError('CONFLICT');}catch(e){if(!(e&&typeof e==='object'&&'code'in e&&(e.code==='FILES_NOT_FOUND'||e.code==='NOT_FOUND')))throw e;}
      const unfinished=await this.files.pending();this.check(epoch);if(unfinished.some(p=>p.operationId===item.uploadOperationId))await this.files.resume(item.uploadOperationId);else if(!saved){const file=selection.files?.[item.id];if(!file||file.size!==item.plainBytes||file.name!==item.filename||await this.auth.worker.hashFile(file)!==item.sha256)throw new FileClientError('CHANGED_FILE');this.check(epoch);await this.files.upload({projectId:draft.projectId,file,kind:draft.mode==='register'?'source':'output',documentReference:item.documentReference,storage:item.storage,taskIds:[item.taskId],operationId:item.uploadOperationId,versionId:item.versionId,...(item.existingFileId?{fileId:item.existingFileId,...(item.expectedVersionId?{expectedVersionId:item.expectedVersionId}:{})}:{newFileId:item.fileId}),...(item.storage==='external'?{path:item.path}:{})});}
      this.check(epoch);item.stage='file_saved';await persist();
     }
     if(draft.mode==='submit'&&item.stage!=='submitted'){const externalFiles={...selection.externalFiles};if(item.storage==='external'&&selection.files?.[item.id])externalFiles[item.versionId]=selection.files[item.id]!;
      await this.evidence.submit(draft.projectId,item.taskId,{operationId:item.submitOperationId,externalFiles});this.check(epoch);item.stage='submitted';
     }
    }
    item.state='saved';item.errorCode=null;
   }catch(error){this.check(epoch);item.state='error';const code=error&&typeof error==='object'&&'serverCode'in error&&typeof error.serverCode==='string'?error.serverCode:error&&typeof error==='object'&&'code'in error?String(error.code):'FAILED';item.errorCode=/^[A-Z_]{1,64}$/.test(code)?code:'FAILED';}
   await persist();
  }
  return draft;
 }).finally(()=>{this.active.delete(batchId);this.paused.delete(batchId);});}
}

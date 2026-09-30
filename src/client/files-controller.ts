import { z } from 'zod';
import { binary, digest, identifier } from '../shared/contracts.js';
import { canonicalJson, digestObject } from '../shared/crypto.js';
import { fileContext,filePage,fileVersion,fileVersionPage,fileView,FILE_CHUNK_PLAIN_BYTES,FILE_CHUNK_OVERHEAD,
  type FileContext,type FileEntry,type FileManifest,type FilePage,type FileReceipt,type FileVersion,type FileVersionPage,type FileView } from '../shared/files.js';
import { verifySecurityHistory,type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthClientError,AuthenticatedHttp,type AuthController,type AuthRequestOptions } from './auth-controller.js';
import { IndexedFilesStore,type StoredFileUpload } from './files-store.js';
import { IndexedPairingStore } from './pairing.js';
import { IndexedPlanningStore } from './planning-store.js';
import { HttpPlanningTransport,type PlanningTransport } from './planning-controller.js';
import { FileClientError,type ReadableFileMetadata,type PrepareFileLinkInput } from './files-crypto.js';
import type { ReadPlanningInput } from './planning-crypto.js';
import type { AccessChangeController } from './access-change-controller.js';
import { assertOnline } from './write-state.js';
import { PLANNING_MAX_BYTES } from '../shared/planning-api.js';

type Reference={workspaceId:string;projectId:string;operationId:string};
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
const chunkResponse=z.strictObject({index:z.number().int().nonnegative(),bytes:binary(41,FILE_CHUNK_PLAIN_BYTES+FILE_CHUNK_OVERHEAD),digest});
const chunkReceipt=z.strictObject({state:z.literal('received'),index:z.number().int().nonnegative(),digest});
export class HttpFilesTransport extends AuthenticatedHttp {
  constructor(origin:string,private readonly csrfToken:()=>string|undefined,fetcher?:typeof fetch){super(origin,fetcher);}
  protected override responseLimit():number{return PLANNING_MAX_BYTES;}
  request<T>(path:string,body:unknown,schema:z.ZodType<T>,options?:AuthRequestOptions):Promise<T>{
    const csrfToken=this.csrfToken();if(!csrfToken)throw new AuthClientError('AUTH_REQUIRED');
    return this.post(`/v1/files/${path}`,body,schema,{...options,csrfToken});
  }
  context(ref:Reference,o?:AuthRequestOptions){return this.request('context',ref,fileContext,o);}
  list(ref:Reference&{after?:string;limit?:number;taskId?:string;kind?:'source'|'output'},o?:AuthRequestOptions){return this.request('list',ref,filePage,o);}
  version(ref:Reference&{versionId:string},o?:AuthRequestOptions){return this.request('version',ref,fileVersion,o);}
  versions(ref:Reference&{fileId:string;afterVersion?:string;limit?:number},o?:AuthRequestOptions){return this.request('versions',ref,fileVersionPage,o);}
  begin(manifest:FileManifest,o?:AuthRequestOptions){return this.request('begin',{manifest},fileView,o);}
  chunk(ref:Reference&{versionId:string;index:number;bytes:string},o?:AuthRequestOptions){return this.request('chunk',ref,chunkReceipt,o);}
  complete(ref:Reference&{versionId:string},o?:AuthRequestOptions){return this.request('complete',ref,fileView,o);}
  cancel(ref:Reference&{versionId:string},o?:AuthRequestOptions){return this.request('cancel',ref,fileView,o);}
  link(input:unknown,o?:AuthRequestOptions){return this.request('link',input,fileView,o);}
  readChunk(ref:Reference&{versionId:string;index:number;purpose:'preview'|'download'},o?:AuthRequestOptions){return this.request('read-chunk',ref,chunkResponse,o);}
  status(ref:Reference&{dataGeneration:string;requestHash:string},o?:AuthRequestOptions){return this.request('status',ref,fileView,o);}
}
export type ReadableFileEntry=FileEntry&{metadata:ReadableFileMetadata};
export type ReadableFileVersion=FileVersion&{metadata:ReadableFileMetadata};
export interface UploadFileInput {projectId:string;file:File;kind:'source'|'output';storage:'managed'|'external';documentReference:string;
  label?:string;path?:string;taskIds?:string[];fileId?:string;newFileId?:string;versionId?:string;operationId?:string;expectedVersionId?:string;
  onProgress?:(progress:{operationId:string;versionId:string;completedBytes:number;totalBytes:number;state:'preparing'|'uploading'|'saved'})=>void}
/** Authenticated headless file workflow. Filenames, paths, document hashes and keys are never persisted in clear. */
export class FilesController {
  private epoch=0;private uploads=0;private readonly requests=new Set<AbortController>();private readonly running=new Set<Promise<unknown>>();
  private readonly uploadRequests=new Map<string,{request:AbortController;result:Promise<unknown>}>();
  constructor(private readonly auth:AuthController,private readonly transport:HttpFilesTransport,private readonly store:IndexedFilesStore,
    private readonly pins:IndexedPairingStore,private readonly planningPins:IndexedPlanningStore,private readonly access:Pick<AccessChangeController,'refreshKeys'>,
    private readonly security:Pick<PlanningTransport,'history'>,private readonly options:{trustedServiceKeys?:Record<string,string>}={}){
    if([transport.origin,store.origin,pins.origin,planningPins.origin].some(o=>o!==auth.origin))throw new FileClientError('CONFLICT');
  }
  clear(){this.epoch++;for(const r of this.requests)r.abort();this.requests.clear();}
  attachAuthLifecycle(){const a=this.auth.onClear(()=>this.clear()),b=this.auth.onForget(r=>this.forgetDevice(r));return()=>{a();b();};}
  async forgetDevice(r:{workspaceId:string;accountId:string;deviceId:string}){this.clear();await Promise.allSettled([...this.running]);await this.store.forgetDevice(r);}
  private check(epoch:number,signal:AbortSignal){if(epoch!==this.epoch||signal.aborted)throw new FileClientError('CANCELLED');}
  private run<T>(work:(signal:AbortSignal,epoch:number)=>Promise<T>,operationId?:string):Promise<T>{
    assertOnline();const r=new AbortController(),epoch=this.epoch;this.requests.add(r);
    const result=work(r.signal,epoch).then(v=>{this.check(epoch,r.signal);return v;});this.running.add(result);
    if(operationId)this.uploadRequests.set(operationId,{request:r,result});
    void result.finally(()=>{this.requests.delete(r);this.running.delete(result);if(operationId&&this.uploadRequests.get(operationId)?.request===r)this.uploadRequests.delete(operationId);}).catch(()=>{});return result;
  }
  private session(){const s=this.auth.current();if(s?.localAccess!=='unlocked'||!s.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');return s.session;}
  private reference(projectId:string,operationId:string=crypto.randomUUID()):Reference{return {workspaceId:this.session().workspaceId,projectId:identifier.parse(projectId),operationId:identifier.parse(operationId)};}
  private async current(ref:Reference,signal:AbortSignal,epoch:number):Promise<{context:FileContext;input:ReadPlanningInput}>{
    const session=this.session();await this.access.refreshKeys();this.check(epoch,signal);
    const context=await this.transport.context(ref,{signal});this.check(epoch,signal);const b=context.binding;
    if(b.workspaceId!==session.workspaceId||b.accountId!==session.accountId||b.deviceId!==session.deviceId||b.projectId!==ref.projectId||b.operationId!==ref.operationId)throw new FileClientError('CONFLICT');
    const pin=await this.pins.pin(ref.workspaceId);this.check(epoch,signal);if(!pin)throw new FileClientError('INCOMPLETE_KEYS');
    const response=await this.security.history(ref,{signal});this.check(epoch,signal);
    if(!same(response.anchor,response.current))throw new FileClientError('CONFLICT');
    const history:SecurityHistoryInput={workspaceId:ref.workspaceId,origin:this.auth.origin,genesisFingerprint:pin.genesisFingerprint,genesis:response.genesis,
      transitions:response.transitions,expected:response.anchor,pin,trustedServiceKeys:this.options.trustedServiceKeys??{}};
    const state=await verifySecurityHistory(history);this.check(epoch,signal);const p=state.profiles[session.accountId],d=state.devices[session.deviceId!];
    if(!p?.active||!d?.active||d.accountId!==session.accountId||p.credentialGeneration!==session.credentialGeneration||
      p.sessionGeneration!==session.sessionGeneration||state.dataGeneration!==session.dataGeneration)throw new FileClientError('CONFLICT');
    const planningPin=await this.planningPins.pin(ref);this.check(epoch,signal);
    const input:ReadPlanningInput={context:context.planning,history,historyPlaintext:false,accountId:session.accountId,deviceId:session.deviceId!,...(planningPin?{pin:planningPin}:{})};
    // File-dialog cancellation aborts transport and discards the bounded worker
    // result. Account lock/logout still terminates the worker immediately.
    const view=await this.auth.worker.readPlanning(input);this.check(epoch,signal);
    await this.planningPins.recordPin(view.pin);await this.pins.recordVerifiedHistory(history);this.check(epoch,signal);return {context,input};
  }
  private async fence(before:FileContext,ref:Reference,signal:AbortSignal,epoch:number){
    const after=await this.transport.context(ref,{signal});this.check(epoch,signal);
    const pick=(v:FileContext)=>{const b=v.binding;return [b.accountId,b.deviceId,b.credentialGeneration,b.sessionGeneration,b.keyGeneration,b.securityVersion,b.securityHead,b.dataGeneration,b.keyEpoch,b.permissionVersion];};
    if(!same(pick(before),pick(after)))throw new FileClientError('CONFLICT');
  }
  context(projectId:string){return this.run(async(s,e)=>(await this.current(this.reference(projectId),s,e)).context);}
  verifiedContext(projectId:string,operationId?:string){return this.run(async(s,e)=>this.current(this.reference(projectId,operationId),s,e));}
  list(projectId:string,options:{after?:string;taskId?:string;kind?:'source'|'output';limit?:number}={}):Promise<Omit<FilePage,'entries'>&{entries:ReadableFileEntry[]}>{
    return this.run(async(signal,epoch)=>{const ref=this.reference(projectId),{context,input}=await this.current(ref,signal,epoch),page=await this.transport.list({...ref,...options},{signal});this.check(epoch,signal);
      const metadata=await this.auth.worker.readFiles({...input,manifests:page.entries.map(e=>e.version.manifest)});this.check(epoch,signal);
      await this.fence(context,ref,signal,epoch);return {...page,entries:page.entries.map(e=>{const m=metadata.find(m=>m.versionId===e.latestVersionId);if(!m)throw new FileClientError('INVALID_FILE');return {...e,metadata:m.metadata};})};});
  }
  versions(projectId:string,fileId:string,afterVersion?:string):Promise<Omit<FileVersionPage,'versions'>&{versions:ReadableFileVersion[]}>{
    return this.run(async(signal,epoch)=>{const ref=this.reference(projectId),{context,input}=await this.current(ref,signal,epoch),page=await this.transport.versions({...ref,fileId,...(afterVersion?{afterVersion}:{})},{signal});this.check(epoch,signal);
      const metadata=await this.auth.worker.readFiles({...input,manifests:page.versions.map(v=>v.manifest)});this.check(epoch,signal);await this.fence(context,ref,signal,epoch);
      return {...page,versions:page.versions.map(v=>{const m=metadata.find(m=>m.versionId===v.manifest.body.versionId);if(!m)throw new FileClientError('INVALID_FILE');return {...v,metadata:m.metadata};})};});
  }
  version(projectId:string,versionId:string):Promise<ReadableFileVersion>{return this.run(async(signal,epoch)=>{
    const ref=this.reference(projectId),{context,input}=await this.current(ref,signal,epoch),version=await this.transport.version({...ref,versionId},{signal});this.check(epoch,signal);
    const [m]=await this.auth.worker.readFiles({...input,manifests:[version.manifest]});this.check(epoch,signal);if(!m)throw new FileClientError('INVALID_FILE');
    await this.fence(context,ref,signal,epoch);return {...version,metadata:m.metadata};});}
  bytes(projectId:string,versionId:string,purpose:'preview'|'download'):Promise<{bytes:Uint8Array;metadata:ReadableFileMetadata}>{return this.run(async(signal,epoch)=>{
    const ref=this.reference(projectId),{context,input}=await this.current(ref,signal,epoch);
    const b=context.planning.binding;if(purpose==='download'&&b.version!==1&&!b.isOwner&&!b.permissions.includes('download_files'))throw new AuthClientError('FORBIDDEN');
    const version=await this.transport.version({...ref,versionId},{signal});this.check(epoch,signal);
    if(version.state!=='ready'||version.manifest.body.storage!=='managed')throw new FileClientError('INVALID_FILE');
    const [m]=await this.auth.worker.readFiles({...input,manifests:[version.manifest]});if(!m)throw new FileClientError('INVALID_FILE');
    const chunks:string[]=[];for(let index=0;index<version.manifest.body.chunkHashes.length;index++){
      const r=await this.transport.readChunk({...ref,versionId,index,purpose},{signal});this.check(epoch,signal);
      if(r.index!==index||r.digest!==version.manifest.body.chunkHashes[index])throw new FileClientError('INVALID_FILE');chunks.push(r.bytes);
    }
    const bytes=await this.auth.worker.readFileBytes({...input,manifest:version.manifest,chunks});
    try{this.check(epoch,signal);await this.fence(context,ref,signal,epoch);return {bytes,metadata:m.metadata};}catch(error){bytes.fill(0);throw error;}
  });}
  verifyExternal(projectId:string,versionId:string,file:File):Promise<{matches:boolean;metadata:ReadableFileMetadata}>{return this.run(async(signal,epoch)=>{
    const version=await this.version(projectId,versionId);this.check(epoch,signal);if(version.manifest.body.storage!=='external')throw new FileClientError('INVALID_FILE');
    if(file.size!==version.manifest.body.plainBytes)return {matches:false,metadata:version.metadata};
    const hash=await this.auth.worker.hashFile(file);this.check(epoch,signal);return {matches:hash===version.metadata.sha256,metadata:version.metadata};});}
  private receipt(view:FileView,ref:Reference,action:FileReceipt['action'],requestHash:string,generation:string):FileReceipt{
    const r=view.receipt;if(view.state!=='completed'||!r||r.workspaceId!==ref.workspaceId||r.projectId!==ref.projectId||r.operationId!==ref.operationId||
      r.action!==action||r.requestHash!==requestHash||r.dataGeneration!==generation)throw new FileClientError('CONFLICT');return r;
  }
  upload(input:UploadFileInput):Promise<FileReceipt>{
    assertOnline();if(this.uploads>=2)return Promise.reject(new AuthClientError('BUSY'));this.uploads++;
    const operationId=input.operationId??crypto.randomUUID();
    const result=this.run(async(signal,epoch)=>{const ref=this.reference(input.projectId,operationId),session=this.session();
      const saved=await this.store.get(ref.workspaceId,ref.operationId);this.check(epoch,signal);if(saved)return this.resumeRecord(saved,signal,epoch,input.onProgress);
      const {context,currentInput}=await this.current(ref,signal,epoch).then(v=>({context:v.context,currentInput:v.input}));
      let version='1',priorVersionId:string|null=null;const fileId=identifier.parse(input.fileId??input.newFileId??crypto.randomUUID()),versionId=identifier.parse(input.versionId??crypto.randomUUID());
      if(input.fileId){const page=await this.transport.versions({...ref,fileId,limit:100},{signal});this.check(epoch,signal);
        // Version pages are ascending. Walk once with a finite cap to find current lineage.
        let last=page.versions.at(-1),ready=page.versions.filter(v=>v.state==='ready').at(-1),staged=page.versions.some(v=>v.state==='staged'),next=page.nextVersion,rounds=0;while(next&&rounds++<64){const more=await this.transport.versions({...ref,fileId,afterVersion:next,limit:100},{signal});this.check(epoch,signal);last=more.versions.at(-1)??last;ready=more.versions.filter(v=>v.state==='ready').at(-1)??ready;staged||=more.versions.some(v=>v.state==='staged');next=more.nextVersion;}
        if(next||!last||!ready||staged||input.expectedVersionId&&ready.manifest.body.versionId!==input.expectedVersionId)throw new FileClientError('CONFLICT');version=String(BigInt(last.manifest.body.version)+1n);priorVersionId=ready.manifest.body.versionId;
      }
      input.onProgress?.({operationId:ref.operationId,versionId,completedBytes:0,totalBytes:input.file.size,state:'preparing'});
      const prepared=await this.auth.worker.prepareFile({...currentInput,binding:context.binding,fileId,versionId,version,priorVersionId,kind:input.kind,storage:input.storage,
        taskIds:input.taskIds??[],file:input.file,metadata:{filename:input.file.name,mediaType:input.file.type,documentReference:input.documentReference,label:input.label??'',...(input.path?{path:input.path}:{})}});this.check(epoch,signal);
      const record:StoredFileUpload={version:1,origin:this.auth.origin,workspaceId:ref.workspaceId,accountId:session.accountId,deviceId:session.deviceId!,operationId:ref.operationId,
        completeOperationId:crypto.randomUUID(),manifest:prepared.manifest,chunks:prepared.chunks};
      await this.store.put(record);this.check(epoch,signal);return this.resumeRecord(record,signal,epoch,input.onProgress);
    },operationId);return result.finally(()=>{this.uploads--;});
  }
  private async resumeRecord(record:StoredFileUpload,signal:AbortSignal,epoch:number,onProgress?:UploadFileInput['onProgress']):Promise<FileReceipt>{
    const session=this.session(),body=record.manifest.body,ref=this.reference(body.binding.projectId,record.operationId),generation=body.binding.dataGeneration;
    if(record.accountId!==session.accountId||record.deviceId!==session.deviceId||generation!==session.dataGeneration)throw new FileClientError('CONFLICT');
    const requestHash=await digestObject({manifest:record.manifest});
    let begun=await this.transport.status({...ref,dataGeneration:generation,requestHash},{signal});this.check(epoch,signal);
    if(begun.state==='absent')begun=await this.transport.begin(record.manifest,{signal});this.check(epoch,signal);this.receipt(begun,ref,'begin',requestHash,generation);
    if(body.storage==='external'){
      const receipt=this.receipt(begun,ref,'begin',requestHash,generation);await this.store.remove(ref.workspaceId,ref.operationId);this.check(epoch,signal);
      onProgress?.({operationId:ref.operationId,versionId:body.versionId,completedBytes:body.plainBytes,totalBytes:body.plainBytes,state:'saved'});return receipt;
    }
    const version=await this.transport.version({...ref,versionId:body.versionId},{signal});this.check(epoch,signal);
    if(!same(version.manifest,record.manifest)||version.state==='cancelled')throw new FileClientError('CONFLICT');
    const received=new Set(version.receivedIndexes);for(let index=0;index<record.chunks.length;index++){
      if(!received.has(index)){const r=await this.transport.chunk({...ref,versionId:body.versionId,index,bytes:record.chunks[index]!},{signal});this.check(epoch,signal);
        if(r.index!==index||r.digest!==body.chunkHashes[index])throw new FileClientError('INVALID_FILE');}
      onProgress?.({operationId:ref.operationId,versionId:body.versionId,completedBytes:Math.min(body.plainBytes,(index+1)*FILE_CHUNK_PLAIN_BYTES),totalBytes:body.plainBytes,state:'uploading'});
    }
    const completion={...ref,operationId:record.completeOperationId,versionId:body.versionId},completionHash=await digestObject(completion);
    let completed=await this.transport.status({...ref,operationId:record.completeOperationId,dataGeneration:generation,requestHash:completionHash},{signal});this.check(epoch,signal);
    if(completed.state==='absent')completed=await this.transport.complete(completion,{signal});this.check(epoch,signal);
    const receipt=this.receipt(completed,completion,'complete',completionHash,generation);await this.store.remove(ref.workspaceId,ref.operationId);this.check(epoch,signal);
    onProgress?.({operationId:ref.operationId,versionId:body.versionId,completedBytes:body.plainBytes,totalBytes:body.plainBytes,state:'saved'});return receipt;
  }
  savedUpload(projectId:string,operationId:string,versionId:string):Promise<FileReceipt|undefined>{return this.run(async(signal,epoch)=>{
    const ref=this.reference(projectId,operationId),{context}=await this.current(ref,signal,epoch);let version:FileVersion;
    try{version=await this.transport.version({...ref,versionId},{signal});}catch(error){if(error instanceof AuthClientError&&error.code==='NOT_FOUND')return;throw error;}this.check(epoch,signal);
    const b=version.manifest.body;if(version.state!=='ready'||b.binding.operationId!==operationId||b.binding.accountId!==this.session().accountId||b.binding.deviceId!==this.session().deviceId)return;
    const hash=await digestObject({manifest:version.manifest}),status=await this.transport.status({...ref,dataGeneration:b.binding.dataGeneration,requestHash:hash},{signal});this.check(epoch,signal);
    await this.fence(context,ref,signal,epoch);return this.receipt(status,ref,'begin',hash,b.binding.dataGeneration);
  });}
  pending(){const s=this.session();return this.store.list({workspaceId:s.workspaceId,accountId:s.accountId,deviceId:s.deviceId!});}
  resume(operationId:string,onProgress?:UploadFileInput['onProgress']):Promise<FileReceipt>{assertOnline();if(this.uploads>=2)return Promise.reject(new AuthClientError('BUSY'));this.uploads++;return this.run(async(s,e)=>{const r=await this.store.get(this.session().workspaceId,operationId);this.check(e,s);if(!r)throw new FileClientError('INVALID_FILE');return this.resumeRecord(r,s,e,onProgress);},operationId).finally(()=>{this.uploads--;});}
  async cancel(operationId:string):Promise<void>{
    const active=this.uploadRequests.get(operationId);active?.request.abort();if(active)await active.result.catch(()=>{});
    return this.run(async(signal,epoch)=>{const r=await this.store.get(this.session().workspaceId,operationId);this.check(epoch,signal);if(!r)return;
      const ref={...this.reference(r.manifest.body.binding.projectId),versionId:r.manifest.body.versionId},generation=r.manifest.body.binding.dataGeneration,
        beginRef={...ref,operationId:r.operationId},beginHash=await digestObject({manifest:r.manifest}),
        completion={...ref,operationId:r.completeOperationId},completionHash=await digestObject(completion);
      const complete=await this.transport.status({workspaceId:ref.workspaceId,projectId:ref.projectId,operationId:r.completeOperationId,dataGeneration:generation,requestHash:completionHash},{signal});this.check(epoch,signal);
      if(complete.state==='absent'){
        const begun=await this.transport.status({workspaceId:ref.workspaceId,projectId:ref.projectId,operationId:r.operationId,dataGeneration:generation,requestHash:beginHash},{signal});this.check(epoch,signal);
        if(begun.state==='completed'){await this.transport.cancel(ref,{signal});this.check(epoch,signal);}
      }
      await this.store.remove(r.workspaceId,r.operationId);
    });
  }
  link(projectId:string,input:Pick<PrepareFileLinkInput,'fileId'|'taskIds'|'mode'|'versionId'|'action'>):Promise<FileReceipt>{return this.run(async(signal,epoch)=>{
    const ref=this.reference(projectId),{context,input:planning}=await this.current(ref,signal,epoch),payload=await this.auth.worker.prepareFileLink({...planning,...input,binding:context.binding});this.check(epoch,signal);
    const result=await this.transport.link(payload,{signal});this.check(epoch,signal);return this.receipt(result,ref,input.action,await digestObject(payload),context.binding.dataGeneration);});}
}

import { z } from 'zod';
import { fileEditorPermit,type FileReceipt } from '../shared/files.js';
import { deliveryServices } from '../shared/file-delivery.js';
import { editorOpened,editorSnapshot,type EditorOpened } from '../shared/file-editor.js';
import { localServiceStatus } from '../shared/local-files.js';
import { base64urlDecode,base64urlEncode,digestObject } from '../shared/crypto.js';
import { AuthClientError,type AuthController } from './auth-controller.js';
import { FileClientError } from './files-crypto.js';
import type { FilesController,HttpFilesTransport,ReadableFileVersion } from './files-controller.js';
import type { ReadableDeliveryService } from './files-delivery-controller.js';
import { assertOnline } from './write-state.js';
export interface FileEditorLease extends EditorOpened {address:string;filename:string;baseVersionId:string;projectId:string;serviceId:string}
type Held={lease:FileEditorLease;version:ReadableFileVersion;uploadId:string;versionId:string};
/** The browser sends verified plaintext only to its explicitly paired local editor. */
export class FileEditorController {
 private epoch=0;private readonly requests=new Set<AbortController>();private readonly leases=new Map<string,Held>();
 constructor(private readonly auth:AuthController,private readonly files:FilesController,private readonly transport:HttpFilesTransport){}
 attachAuthLifecycle(){return this.auth.onClear(()=>this.clear());}
 clear(){this.epoch++;for(const r of this.requests)r.abort();this.requests.clear();for(const {lease} of this.leases.values())void this.post(lease.address,'editor/close',{leaseId:lease.leaseId},z.unknown(),lease.token).catch(()=>{});this.leases.clear();}
 private session(){const s=this.auth.current();if(s?.localAccess!=='unlocked'||!s.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');return s.session;}
 private address(value:string){const u=new URL(value);if(u.origin!==value||!['localhost','127.0.0.1'].includes(u.hostname)||u.port!=='3411'||!['https:','http:'].includes(u.protocol)||u.username||u.password)throw new FileClientError('CONFLICT');return u.origin;}
 private async post<T>(address:string,path:string,input:unknown,schema:z.ZodType<T>,token?:string):Promise<T>{
  const r=new AbortController();this.requests.add(r);const timer=setTimeout(()=>r.abort(),35000);
  try{const response=await fetch(this.address(address)+'/'+path,{method:'POST',headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},body:JSON.stringify(input),credentials:'omit',redirect:'error',cache:'no-store',signal:r.signal});
   if(!response.ok){if(response.status===403)throw new AuthClientError('FORBIDDEN');if(response.status===409)throw new FileClientError('CONFLICT');throw new AuthClientError('UNAVAILABLE');}
   if(!response.body||Number(response.headers.get('content-length')??0)>36*1024*1024)throw new FileClientError('INVALID_FILE');
   const reader=response.body.getReader(),chunks:Uint8Array[]=[];let count=0;try{while(true){const c=await reader.read();if(c.done)break;count+=c.value.length;if(count>36*1024*1024)throw new FileClientError('TOO_LARGE');chunks.push(c.value);}}finally{await reader.cancel().catch(()=>{});}
   const bytes=new Uint8Array(count);let at=0;for(const c of chunks){bytes.set(c,at);at+=c.length;c.fill(0);}try{return schema.parse(JSON.parse(new TextDecoder().decode(bytes)));}finally{bytes.fill(0);}
  }catch(error){if(error instanceof FileClientError||error instanceof AuthClientError)throw error;throw new AuthClientError('UNAVAILABLE');}finally{clearTimeout(timer);this.requests.delete(r);}
 }
 private check(epoch:number){this.session();if(epoch!==this.epoch)throw new FileClientError('CANCELLED');}
 async services(projectId:string):Promise<ReadableDeliveryService[]>{assertOnline();const epoch=this.epoch,{context,input}=await this.files.verifiedContext(projectId);this.check(epoch);
  const services=await this.transport.request('editor-services',{workspaceId:context.binding.workspaceId,projectId,operationId:crypto.randomUUID()},deliveryServices);this.check(epoch);
  const result:ReadableDeliveryService[]=[];for(const service of services.services){const opened=await this.auth.worker.readDeliveryService({...input,service});this.check(epoch);result.push({...service,metadata:opened.metadata});}return result;
 }
 async open(projectId:string,versionId:string,serviceId:string,options:{theme?:'light'|'dark'}={}):Promise<FileEditorLease>{
  assertOnline();const epoch=this.epoch,service=(await this.services(projectId)).find(s=>s.serviceId===serviceId);this.check(epoch);if(!service||service.state!=='active')throw new AuthClientError('UNAVAILABLE');
  const address=this.address(service.metadata.address),status=await this.post(address,'status',{},localServiceStatus);this.check(epoch);
  if(!status.officeAvailable||status.serviceId!==service.serviceId||status.publicKey!==service.publicKey)throw new AuthClientError('UNAVAILABLE');
  const version=await this.files.version(projectId,versionId),file=await this.files.bytes(projectId,versionId,'preview');
  try{this.check(epoch);if(!/\.(docx|xlsx|pptx)$/i.test(file.metadata.filename))throw new FileClientError('UNSUPPORTED_FORMAT');
   const s=this.session(),permit=await this.transport.request('editor-permit',{workspaceId:s.workspaceId,projectId,operationId:crypto.randomUUID(),versionId,serviceId},fileEditorPermit);this.check(epoch);
   if(permit.body.manifestDigest!==await digestObject(version.manifest)||permit.body.accountId!==s.accountId||permit.body.deviceId!==s.deviceId)throw new FileClientError('CONFLICT');
   const opened=await this.post(address,'editor/open',{permit,manifest:version.manifest,filename:file.metadata.filename,sha256:file.metadata.sha256,bytes:base64urlEncode(file.bytes),theme:options.theme??'light'},editorOpened);
   try{this.check(epoch);}catch(error){await this.post(address,'editor/close',{leaseId:opened.leaseId},z.unknown(),opened.token).catch(()=>{});throw error;}
   const lease={...opened,address,filename:file.metadata.filename,baseVersionId:versionId,projectId,serviceId};
   this.leases.set(lease.leaseId,{lease,version,uploadId:crypto.randomUUID(),versionId:crypto.randomUUID()});return lease;
  }finally{file.bytes.fill(0);}
 }
 async save(lease:FileEditorLease):Promise<{state:'saved';receipt:FileReceipt}|{state:'unchanged'}>{
  assertOnline();const epoch=this.epoch,held=this.leases.get(lease.leaseId);if(!held||held.lease!==lease)throw new FileClientError('CONFLICT');
  const completed=await this.files.savedUpload(lease.projectId,held.uploadId,held.versionId);this.check(epoch);if(completed){await this.close(lease);return {state:'saved',receipt:completed};}
  const pending=await this.files.pending();this.check(epoch);if(pending.some(p=>p.operationId===held.uploadId)){const receipt=await this.files.resume(held.uploadId);this.check(epoch);await this.close(lease);return {state:'saved',receipt};}
  // Current cloud permission is rechecked before asking for a snapshot, and the
  // normal upload path checks it again when it commits the immutable version.
  const s=this.session();await this.transport.request('editor-permit',{workspaceId:s.workspaceId,projectId:lease.projectId,operationId:crypto.randomUUID(),versionId:lease.baseVersionId,serviceId:lease.serviceId},fileEditorPermit);this.check(epoch);
  let snapshot=await this.post(lease.address,'editor/save',{leaseId:lease.leaseId},editorSnapshot,lease.token);this.check(epoch);
  for(let attempt=0;snapshot.state==='waiting'&&attempt<20;attempt++){await new Promise(resolve=>setTimeout(resolve,1500));this.check(epoch);snapshot=await this.post(lease.address,'editor/snapshot',{leaseId:lease.leaseId},editorSnapshot,lease.token);this.check(epoch);}
  if(snapshot.state==='unchanged'){await this.close(lease);return {state:'unchanged'};}
  if(snapshot.state!=='ready'||!snapshot.bytes||!snapshot.sha256||snapshot.filename!==lease.filename)throw new AuthClientError('UNAVAILABLE');
  const bytes=base64urlDecode(snapshot.bytes);try{const file=new File([new Uint8Array(bytes)],lease.filename,{type:held.version.metadata.mediaType}),hash=await this.auth.worker.hashFile(file);this.check(epoch);if(hash!==snapshot.sha256)throw new FileClientError('INVALID_FILE');
   const b=held.version.manifest.body,receipt=await this.files.upload({projectId:lease.projectId,file,storage:'managed',kind:b.kind,fileId:b.fileId,expectedVersionId:lease.baseVersionId,
    versionId:held.versionId,operationId:held.uploadId,documentReference:held.version.metadata.documentReference,label:held.version.metadata.label,taskIds:[]});this.check(epoch);
   await this.close(lease);return {state:'saved',receipt};
  }finally{bytes.fill(0);}
 }
 async close(lease:FileEditorLease){this.leases.delete(lease.leaseId);await this.post(lease.address,'editor/close',{leaseId:lease.leaseId},z.strictObject({closed:z.literal(true)}),lease.token).catch(()=>{});}
}

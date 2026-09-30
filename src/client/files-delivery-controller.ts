import { z } from 'zod';
import { Zip,ZipPassThrough } from 'fflate';
import { identifier } from '../shared/contracts.js';
import { base64urlEncode,canonicalJson,digestObject } from '../shared/crypto.js';
import { fileBinding,type FileManifest } from '../shared/files.js';
import { planningContext,PLANNING_MAX_BYTES } from '../shared/planning-api.js';
import { deliveryPairChallenge,deliveryPage,deliveryRecord,deliveryView,deliveryCheck,deliveryPermit,deliveryServices,
  type DeliveryBatch,type DeliveryReceipt,type DeliveryRecord,type DeliveryView,type PublicationReceipt } from '../shared/file-delivery.js';
import { AuthenticatedHttp,AuthClientError,type AuthController,type AuthRequestOptions } from './auth-controller.js';
import { FileClientError } from './files-crypto.js';
import { deliveryRelativePath,privateDeliveryService,type PrivateDeliveryDetails,type PrivateDeliveryService } from './files-delivery-crypto.js';
import { IndexedDeliveryStore,deliveryOperationBinding,type StoredDeliveryOperation } from './files-delivery-store.js';
import type { FilesController,HttpFilesTransport } from './files-controller.js';
import { assertOnline } from './write-state.js';
import { localServiceStatus,localPairResponse,localOperationResult,localProgress } from '../shared/local-files.js';
import { publicationReceipt } from '../shared/file-delivery.js';
import { parseJsonStrict } from '../shared/json.js';

type Reference={workspaceId:string;projectId:string;operationId:string};
type Current=Awaited<ReturnType<FilesController['verifiedContext']>>;
type Service=z.infer<typeof deliveryServices>['services'][number];
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
const pairContext=z.strictObject({planning:planningContext,binding:fileBinding,challenge:deliveryPairChallenge});
export class HttpDeliveryTransport extends AuthenticatedHttp {
  constructor(origin:string,private readonly csrfToken:()=>string|undefined,fetcher?:typeof fetch){super(origin,fetcher);}
  protected override responseLimit(){return PLANNING_MAX_BYTES;}
  request<T>(path:string,body:unknown,schema:z.ZodType<T>,options?:AuthRequestOptions){
    const csrfToken=this.csrfToken();if(!csrfToken)throw new AuthClientError('AUTH_REQUIRED');return this.post(`/v1/files/delivery/${path}`,body,schema,{...options,csrfToken});
  }
  list(ref:Reference&{after?:string;limit?:number},o?:AuthRequestOptions){return this.request('list',ref,deliveryPage,o);}
  get(ref:Reference&{batchId:string},o?:AuthRequestOptions){return this.request('get',ref,deliveryRecord,o);}
  check(ref:Reference&{batchId:string},o?:AuthRequestOptions){return this.request('check',ref,deliveryCheck,o);}
  services(ref:Reference,o?:AuthRequestOptions){return this.request('services',ref,deliveryServices,o);}
  pairContext(ref:Reference&{serviceId:string;publicKey:string},o?:AuthRequestOptions){return this.request('pair-context',ref,pairContext,o);}
  permit(ref:Reference&{batchId:string;serviceId:string;index:number},o?:AuthRequestOptions){return this.request('permit',ref,deliveryPermit,o);}
  status(ref:Reference&{dataGeneration:string;requestHash:string},o?:AuthRequestOptions){return this.request('status',ref,deliveryView,o);}
  save(action:StoredDeliveryOperation['action'],payload:StoredDeliveryOperation['payload'],o?:AuthRequestOptions){
    return this.request(action==='record_package'?'record-package':action==='revoke_service'?'revoke-service':action,payload,deliveryView,o);
  }
}
export type ReadableDelivery=DeliveryRecord&{details:PrivateDeliveryDetails;versions:{versionId:string;version:string;documentReference:string}[]};
export type ReadableDeliveryService=Service&{metadata:PrivateDeliveryService};
export interface CreateDeliveryItem {operation:DeliveryBatch['body']['items'][number]['operation'];versionId:string;approvalId:string;destination:string;fromPath?:string;expectedOldSha256:string|null}
export interface CreateDeliveryInput {projectId:string;label:string;rootLabel:string;items:CreateDeliveryItem[];supersedes?:string;operationId?:string}
export class LocalDeliveryError extends Error {
  constructor(readonly code:'DISK_FULL'|'LOCAL_TIMEOUT'|'LOCAL_BUSY'|'LOCAL_INTERRUPTED'){super(code);this.name='LocalDeliveryError';}
}
/** Finite workflows: freeze, separately confirm, package or verified local publication. */
export class DeliveryController {
  private epoch=0;private readonly requests=new Set<AbortController>();private readonly running=new Set<Promise<unknown>>();
  private readonly localConnections=new Map<string,{address:string;token:string;publicKey:string}>();
  constructor(private readonly auth:AuthController,private readonly transport:HttpDeliveryTransport,private readonly filesTransport:HttpFilesTransport,
    private readonly files:FilesController,private readonly store:IndexedDeliveryStore,private readonly options:{onWrite?:()=>void;localFetcher?:typeof fetch}={}){
    if([transport.origin,filesTransport.origin,store.origin].some(origin=>origin!==auth.origin))throw new FileClientError('CONFLICT');
  }
  clear(){this.epoch++;for(const request of this.requests)request.abort();this.requests.clear();this.localConnections.clear();}
  attachAuthLifecycle(){const clear=this.auth.onClear(()=>this.clear()),forget=this.auth.onForget(scope=>this.forgetDevice(scope));return()=>{clear();forget();};}
  async forgetDevice(scope:{workspaceId:string;accountId:string;deviceId:string}){this.clear();await Promise.allSettled([...this.running]);await this.store.forgetDevice(scope);}
  private session(){const current=this.auth.current();if(current?.localAccess!=='unlocked'||!current.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');return current.session;}
  private check(epoch:number,signal:AbortSignal){if(epoch!==this.epoch||signal.aborted)throw new FileClientError('CANCELLED');}
  private run<T>(action:(signal:AbortSignal,epoch:number)=>Promise<T>){assertOnline();const request=new AbortController(),epoch=this.epoch;this.requests.add(request);
    const result=action(request.signal,epoch).then(value=>{this.check(epoch,request.signal);return value;});this.running.add(result);
    void result.finally(()=>{this.requests.delete(request);this.running.delete(result);}).catch(()=>{});return result;
  }
  private reference(projectId:string,operationId:string=crypto.randomUUID()):Reference{return {workspaceId:this.session().workspaceId,projectId:identifier.parse(projectId),operationId:identifier.parse(operationId)};}
  private async current(ref:Reference,signal:AbortSignal,epoch:number):Promise<Current>{const current=await this.files.verifiedContext(ref.projectId,ref.operationId);this.check(epoch,signal);
    const b=current.context.binding,s=this.session();if(!current.context.planning.binding.isOwner)throw new AuthClientError('FORBIDDEN');
    if(b.accountId!==s.accountId||b.deviceId!==s.deviceId||b.workspaceId!==ref.workspaceId||b.projectId!==ref.projectId||b.operationId!==ref.operationId)throw new FileClientError('CONFLICT');return current;
  }
  private async fence(current:Current,ref:Reference,signal:AbortSignal,epoch:number){const after=await this.current(ref,signal,epoch);
    const fields=(value:Current)=>{const b=value.context.binding;return [b.workspaceId,b.projectId,b.accountId,b.deviceId,b.credentialGeneration,b.sessionGeneration,b.keyGeneration,b.permissionVersion,b.keyEpoch,b.securityHead,b.securityVersion,b.dataGeneration];};
    if(!same(fields(current),fields(after)))throw new FileClientError('CONFLICT');
  }
  private async manifests(record:DeliveryRecord,ref:Reference,signal:AbortSignal,epoch:number){const result:FileManifest[]=[];
    for(const item of record.batch.body.items){const version=await this.filesTransport.version({...ref,versionId:item.versionId},{signal});this.check(epoch,signal);
      if(version.state!=='ready'||version.manifest.body.fileId!==item.fileId||await digestObject(version.manifest)!==item.manifestDigest)throw new FileClientError('CONFLICT');result.push(version.manifest);
    }return result;
  }
  private async loaded(ref:Reference,batchId:string,current:Current,signal:AbortSignal,epoch:number){const record=await this.transport.get({...ref,batchId},{signal});this.check(epoch,signal);
    const manifests=await this.manifests(record,ref,signal,epoch);let service:Service|undefined;
    if(record.publication){const response=await this.transport.services(ref,{signal});this.check(epoch,signal);service=response.services.find(service=>service.serviceId===record.publication!.body.serviceId);if(!service)throw new FileClientError('CONFLICT');}
    const input={...current.input,record,manifests,...(service?{service}:{})},opened=await this.auth.worker.readDelivery(input,{signal});this.check(epoch,signal);
    return {record,manifests,input,readable:{...record,details:opened.details,versions:opened.versions} satisfies ReadableDelivery};
  }
  private async saved(action:StoredDeliveryOperation['action'],payload:StoredDeliveryOperation['payload'],signal:AbortSignal,epoch:number):Promise<DeliveryReceipt>{
    const session=this.session(),binding=deliveryOperationBinding({payload} as StoredDeliveryOperation),record:StoredDeliveryOperation={version:1,origin:this.auth.origin,
      workspaceId:binding.workspaceId,accountId:session.accountId,deviceId:session.deviceId!,operationId:binding.operationId,action,payload};
    await this.store.put(record);this.check(epoch,signal);return this.finish(record,signal,epoch);
  }
  private async finish(record:StoredDeliveryOperation,signal:AbortSignal,epoch:number){const session=this.session(),binding=deliveryOperationBinding(record),ref=this.reference(binding.projectId,record.operationId),hash=await digestObject(record.payload);
    if(record.accountId!==session.accountId||record.deviceId!==session.deviceId||binding.dataGeneration!==session.dataGeneration)throw new FileClientError('CONFLICT');
    let view:DeliveryView=await this.transport.status({...ref,dataGeneration:binding.dataGeneration,requestHash:hash},{signal});this.check(epoch,signal);
    if(view.state==='absent')view=await this.transport.save(record.action,record.payload,{signal});this.check(epoch,signal);const receipt=view.receipt;
    if(view.state!=='completed'||!receipt||receipt.workspaceId!==ref.workspaceId||receipt.projectId!==ref.projectId||receipt.operationId!==ref.operationId||
      receipt.dataGeneration!==binding.dataGeneration||receipt.requestHash!==hash||receipt.action!==record.action)throw new FileClientError('CONFLICT');
    await this.store.remove(ref.workspaceId,ref.operationId);this.check(epoch,signal);this.options.onWrite?.();return receipt;
  }
  create(input:CreateDeliveryInput):Promise<DeliveryReceipt>{return this.run(async(signal,epoch)=>{
    const ref=this.reference(input.projectId,input.operationId),current=await this.current(ref,signal,epoch),manifests:FileManifest[]=[];
    if(input.items.length<1||input.items.length>64)throw new FileClientError('TOO_LARGE');
    for(const item of input.items){deliveryRelativePath.parse(item.destination);const version=await this.filesTransport.version({...ref,versionId:item.versionId},{signal});this.check(epoch,signal);
      if(version.state!=='ready')throw new FileClientError('INVALID_FILE');manifests.push(version.manifest);}
    const metadata=await this.auth.worker.readFiles({...current.input,manifests},{signal});this.check(epoch,signal);
    const items:DeliveryBatch['body']['items']=[],privateItems:PrivateDeliveryDetails['items']=[];
    for(let i=0;i<input.items.length;i++){const item=input.items[i]!,manifest=manifests[i]!,m=metadata.find(row=>row.versionId===item.versionId)?.metadata;if(!m)throw new FileClientError('INVALID_FILE');
      items.push({operation:item.operation,fileId:manifest.body.fileId,versionId:item.versionId,manifestDigest:await digestObject(manifest),approvalId:item.approvalId});
      privateItems.push({destination:item.destination,...(item.fromPath?{fromPath:item.fromPath}:{}),expectedOldSha256:item.expectedOldSha256,sha256:m.sha256,
        plainBytes:manifest.body.plainBytes,filename:m.filename,...(m.path?{externalPath:m.path}:{})});}
    const payload=await this.auth.worker.prepareDelivery({...current.input,binding:current.context.binding,batchId:crypto.randomUUID(),supersedes:input.supersedes??null,
      items,details:{version:1,label:input.label,rootLabel:input.rootLabel,items:privateItems},manifests},{signal});this.check(epoch,signal);return this.saved('create',payload,signal,epoch);
  });}
  read(projectId:string,batchId:string):Promise<ReadableDelivery>{return this.run(async(signal,epoch)=>{const ref=this.reference(projectId),current=await this.current(ref,signal,epoch),loaded=await this.loaded(ref,batchId,current,signal,epoch);
    await this.fence(current,ref,signal,epoch);return loaded.readable;});}
  list(projectId:string,after?:string){return this.run(async(signal,epoch)=>{const ref=this.reference(projectId),current=await this.current(ref,signal,epoch),page=await this.transport.list({...ref,...(after?{after}:{}),limit:20},{signal});this.check(epoch,signal);
    const entries:ReadableDelivery[]=[];for(const record of page.entries)entries.push((await this.loaded(ref,record.batch.body.batchId,current,signal,epoch)).readable);
    await this.fence(current,ref,signal,epoch);return {...page,entries};});}
  private command(projectId:string,batchId:string,action:'confirm'|'cancel'|'record_package'){return this.run(async(signal,epoch)=>{const ref=this.reference(projectId),current=await this.current(ref,signal,epoch),loaded=await this.loaded(ref,batchId,current,signal,epoch);
    const payload=await this.auth.worker.prepareDeliveryCommand({...loaded.input,binding:current.context.binding,action},{signal});this.check(epoch,signal);return this.saved(action,payload,signal,epoch);});}
  confirm(projectId:string,batchId:string){return this.command(projectId,batchId,'confirm');}
  cancel(projectId:string,batchId:string){return this.command(projectId,batchId,'cancel');}
  checkDelivery(projectId:string,batchId:string){return this.run(async(signal,epoch)=>{const ref=this.reference(projectId);await this.current(ref,signal,epoch);return this.transport.check({...ref,batchId},{signal});});}
  downloadPackage(projectId:string,batchId:string,onProgress?:(completed:number,total:number)=>void):Promise<{blob:Blob;filename:string;receipt:DeliveryReceipt}>{return this.run(async(signal,epoch)=>{
    const ref=this.reference(projectId),current=await this.current(ref,signal,epoch),loaded=await this.loaded(ref,batchId,current,signal,epoch);
    const checked=await this.transport.check({...ref,batchId},{signal});this.check(epoch,signal);if(checked.frozenDigest!==loaded.record.frozenDigest)throw new FileClientError('CONFLICT');
    const parts:Blob[]=[];let error:Error|undefined,ended=false;const archive=new Zip((failure,chunk,final)=>{if(failure){error=failure;return;}parts.push(new Blob([new Uint8Array(chunk)]));if(final)ended=true;});
    const add=(name:string,bytes:Uint8Array)=>{const entry=new ZipPassThrough(name);archive.add(entry);entry.push(bytes,true);if(error)throw error;};
    try{add('.maqbool-package/delivery.json',new TextEncoder().encode(canonicalJson({version:1,batch:loaded.record.batch,frozenDigest:loaded.record.frozenDigest,details:loaded.readable.details})));
      for(let index=0;index<loaded.record.batch.body.items.length;index++){const item=loaded.record.batch.body.items[index]!,manifest=loaded.manifests[index]!;
        if(item.operation!=='remove'&&manifest.body.storage==='managed'){const result=await this.files.bytes(projectId,item.versionId,'download');this.check(epoch,signal);
          try{if(result.metadata.sha256!==loaded.readable.details.items[index]!.sha256)throw new FileClientError('CHANGED_FILE');add(loaded.readable.details.items[index]!.destination,result.bytes);}finally{result.bytes.fill(0);}}
        onProgress?.(index+1,loaded.record.batch.body.items.length);
      }
      archive.end();if(error||!ended)throw error??new FileClientError('INVALID_FILE');await this.fence(current,ref,signal,epoch);
      const payload=await this.auth.worker.prepareDeliveryCommand({...loaded.input,binding:current.context.binding,action:'record_package'},{signal});this.check(epoch,signal);
      const receipt=await this.saved('record_package',payload,signal,epoch),filename=`${loaded.readable.details.label.replace(/[^\p{L}\p{N}_. -]/gu,'_').slice(0,120)}.zip`;
      return {blob:new Blob(parts,{type:'application/zip'}),filename,receipt};
    }catch(error){archive.terminate();throw error;}finally{parts.length=0;}
  });}
  services(projectId:string):Promise<ReadableDeliveryService[]>{return this.run(async(signal,epoch)=>{const ref=this.reference(projectId),current=await this.current(ref,signal,epoch),response=await this.transport.services(ref,{signal});this.check(epoch,signal);
    const result:ReadableDeliveryService[]=[];for(const service of response.services){const read=await this.auth.worker.readDeliveryService({...current.input,service},{signal});this.check(epoch,signal);result.push({...service,metadata:read.metadata});}
    await this.fence(current,ref,signal,epoch);return result;});}
  pair(projectId:string,claim:{serviceId:string;publicKey:string},metadata:PrivateDeliveryService,
    prove:(approval:z.infer<typeof deliveryServices>['services'][number]['approval']['approval'])=>Promise<string>):Promise<DeliveryReceipt>{return this.run(async(signal,epoch)=>{
    const ref=this.reference(projectId),current=await this.current(ref,signal,epoch),context=await this.transport.pairContext({...ref,...claim},{signal});this.check(epoch,signal);
    // The pairing challenge owns the request authority; its issue times may differ from the preceding context.
    const pairedCurrent=await this.current(ref,signal,epoch);if(!same({...context.binding,issuedAt:pairedCurrent.context.binding.issuedAt,expiresAt:pairedCurrent.context.binding.expiresAt},pairedCurrent.context.binding))throw new FileClientError('CONFLICT');
    if(context.planning.binding.beforeHead!==pairedCurrent.context.planning.binding.beforeHead)throw new FileClientError('CONFLICT');
    const prepared=await this.auth.worker.prepareDeliveryPair({...pairedCurrent.input,context:context.planning,binding:context.binding,challenge:context.challenge,...claim,metadata:privateDeliveryService.parse(metadata)},{signal});this.check(epoch,signal);
    const proof=await prove(prepared.approval);this.check(epoch,signal);return this.saved('pair',{approval:prepared.approval,proof},signal,epoch);
  });}
  revokeService(projectId:string,serviceId:string){return this.run(async(signal,epoch)=>{const ref=this.reference(projectId),current=await this.current(ref,signal,epoch),response=await this.transport.services(ref,{signal});this.check(epoch,signal);
    const service=response.services.find(service=>service.serviceId===serviceId);if(!service)throw new FileClientError('INVALID_FILE');
    const payload=await this.auth.worker.prepareDeliveryServiceRevocation({...current.input,binding:current.context.binding,service},{signal});this.check(epoch,signal);return this.saved('revoke_service',payload,signal,epoch);});}
  permit(projectId:string,batchId:string,serviceId:string,index:number){return this.run(async(signal,epoch)=>{const ref=this.reference(projectId);await this.current(ref,signal,epoch);return this.transport.permit({...ref,batchId,serviceId,index},{signal});});}
  publicationMaterial(projectId:string,batchId:string,serviceId:string){return this.run(async(signal,epoch)=>{const ref=this.reference(projectId),current=await this.current(ref,signal,epoch),loaded=await this.loaded(ref,batchId,current,signal,epoch),response=await this.transport.services(ref,{signal});this.check(epoch,signal);
    const service=response.services.find(service=>service.serviceId===serviceId);if(!service)throw new FileClientError('INVALID_FILE');const checked=await this.transport.check({...ref,batchId},{signal});this.check(epoch,signal);
    if(checked.frozenDigest!==loaded.record.frozenDigest)throw new FileClientError('CONFLICT');const result=await this.auth.worker.preparePublicationMaterial({...loaded.input,service},{signal});this.check(epoch,signal);return {batch:loaded.record.batch,...result};});}
  publish(projectId:string,batchId:string,receipt:PublicationReceipt){return this.run(async(signal,epoch)=>{const ref=this.reference(projectId),current=await this.current(ref,signal,epoch),loaded=await this.loaded(ref,batchId,current,signal,epoch),response=await this.transport.services(ref,{signal});this.check(epoch,signal);
    const service=response.services.find(service=>service.serviceId===receipt.body.serviceId);if(!service)throw new FileClientError('INVALID_FILE');
    const payload=await this.auth.worker.prepareDeliveryPublish({...loaded.input,binding:current.context.binding,service,receipt},{signal});this.check(epoch,signal);return this.saved('publish',payload,signal,epoch);});}
  private connectionKey(projectId:string,serviceId:string){const s=this.session();return [s.workspaceId,s.accountId,s.deviceId,s.dataGeneration,projectId,serviceId].join(':');}
  private async local<T>(address:string,path:string,body:unknown,schema:z.ZodType<T>,signal:AbortSignal,token?:string):Promise<T>{
    const accepted=privateDeliveryService.shape.address.parse(address),url=new URL(path,accepted);
    if(url.origin!==new URL(accepted).origin)throw new FileClientError('CONFLICT');
    const timeout=AbortSignal.timeout(path==='/status'?10000:120000),bounded=AbortSignal.any([signal,timeout]);
    try{const response=await (this.options.localFetcher??fetch)(url,{method:'POST',credentials:'omit',cache:'no-store',redirect:'error',signal:bounded,
      headers:{'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})},body:canonicalJson(body)});
      const length=response.headers.get('content-length');if(length!==null&&Number(length)>512*1024)throw new FileClientError('INVALID_FILE');
      if(!response.body)throw new FileClientError('INVALID_FILE');const reader=response.body.getReader(),chunks:Uint8Array[]=[],max=512*1024;let size=0;
      try{for(;;){const result=await reader.read();if(result.done)break;size+=result.value.length;if(size>max)throw new FileClientError('TOO_LARGE');chunks.push(result.value);}}
      finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
      const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;chunk.fill(0);}
      let parsed:unknown;try{parsed=parseJsonStrict(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new FileClientError('INVALID_FILE');}finally{bytes.fill(0);}
      if(!response.ok){const error=z.strictObject({code:z.string().max(40)}).safeParse(parsed),code=error.success?error.data.code:'';
        if(code==='DISK_FULL')throw new LocalDeliveryError('DISK_FULL');if(code==='BUSY')throw new LocalDeliveryError('LOCAL_BUSY');if(code==='INTERRUPTED')throw new LocalDeliveryError('LOCAL_INTERRUPTED');
        if(response.status===409)throw new FileClientError('CONFLICT');if(response.status===401||response.status===403)throw new AuthClientError('FORBIDDEN');throw new AuthClientError('TRANSPORT');}
      try{return schema.parse(parsed);}catch{throw new FileClientError('INVALID_FILE');}
    }catch(error){if(signal.aborted)throw new FileClientError('CANCELLED');if(timeout.aborted)throw new LocalDeliveryError('LOCAL_TIMEOUT');
      if(error instanceof FileClientError||error instanceof LocalDeliveryError||error instanceof AuthClientError)throw error;throw new AuthClientError('TRANSPORT');}
  }
  localStatus(address:string){return this.run(async(signal,epoch)=>{const result=await this.local(address,'/status',{},localServiceStatus,signal);this.check(epoch,signal);return result;});}
  connectLocal(projectId:string,input:{address:string;code:string;label:string}){return this.run(async(signal,epoch)=>{
    const status=await this.local(input.address,'/status',{},localServiceStatus,signal);this.check(epoch,signal);
    const metadata:PrivateDeliveryService={version:1,label:input.label,rootLabel:status.rootLabel,address:input.address};
    const receipt=await this.pair(projectId,{serviceId:status.serviceId,publicKey:status.publicKey},metadata,async approval=>{
      const result=await this.local(input.address,'/pair',{code:input.code,approval},localPairResponse,signal);this.check(epoch,signal);
      if(result.serviceId!==status.serviceId)throw new FileClientError('CONFLICT');
      this.localConnections.set(this.connectionKey(projectId,status.serviceId),{address:input.address,token:result.token,publicKey:status.publicKey});return result.proof;
    });this.check(epoch,signal);return {receipt,serviceId:status.serviceId,rootLabel:status.rootLabel};
  });}
  isLocalConnected(projectId:string,serviceId:string){return this.localConnections.has(this.connectionKey(projectId,serviceId));}
  disconnectLocal(projectId:string,serviceId:string){this.localConnections.delete(this.connectionKey(projectId,serviceId));}
  /** Each operation gets a new current server permit; local receipts are checked before marking cloud publication. */
  publishLocal(projectId:string,batchId:string,serviceId:string,onProgress?:(completed:number,total:number)=>void):Promise<DeliveryReceipt>{return this.run(async(signal,epoch)=>{
    const ref=this.reference(projectId),current=await this.current(ref,signal,epoch),loaded=await this.loaded(ref,batchId,current,signal,epoch),response=await this.transport.services(ref,{signal});this.check(epoch,signal);
    const service=response.services.find(service=>service.serviceId===serviceId&&service.state==='active'),connection=this.localConnections.get(this.connectionKey(projectId,serviceId));
    if(!service||!connection)throw new AuthClientError('AUTH_REQUIRED');
    const serviceMetadata=await this.auth.worker.readDeliveryService({...current.input,service},{signal});this.check(epoch,signal);
    if(connection.publicKey!==service.publicKey||connection.address!==serviceMetadata.metadata.address||loaded.readable.details.rootLabel!==serviceMetadata.metadata.rootLabel)throw new FileClientError('CONFLICT');
    const status=await this.local(connection.address,'/status',{},localServiceStatus,signal);this.check(epoch,signal);if(status.serviceId!==serviceId||status.publicKey!==service.publicKey||status.rootLabel!==loaded.readable.details.rootLabel)throw new FileClientError('CONFLICT');
    let material=await this.auth.worker.preparePublicationMaterial({...loaded.input,service},{signal});this.check(epoch,signal);
    try{
      for(let index=0;index<loaded.record.batch.body.items.length;index++){
        const manifest=loaded.manifests[index]!,item=loaded.record.batch.body.items[index]!;let bytes:Uint8Array|undefined;
        try{if(['add','replace'].includes(item.operation)&&manifest.body.storage==='managed'){const read=await this.files.bytes(projectId,item.versionId,'download');bytes=read.bytes;this.check(epoch,signal);
            if(read.metadata.sha256!==loaded.readable.details.items[index]!.sha256)throw new FileClientError('CHANGED_FILE');}
          // Byte preparation may take time. Acquire the 30-second permit last.
          const permit=await this.transport.permit({...ref,batchId,serviceId,index},{signal});this.check(epoch,signal);
          const result=await this.local(connection.address,'/apply',{batch:loaded.record.batch,permit,detailsKey:material.detailsKey,...(bytes?{bytes:base64urlEncode(bytes)}:{})},localOperationResult,signal,connection.token);this.check(epoch,signal);
          if(result.index!==index||result.state!=='verified'||result.sha256!==(item.operation==='remove'?null:loaded.readable.details.items[index]!.sha256))throw new FileClientError('CHANGED_FILE');
          onProgress?.(index+1,loaded.record.batch.body.items.length);
        }finally{bytes?.fill(0);}
      }
      const receipt=await this.local(connection.address,'/finish',{batchId,itemCount:loaded.record.batch.body.items.length},publicationReceipt,signal,connection.token);this.check(epoch,signal);
      const progress=await this.local(connection.address,'/progress',{batchId},localProgress,signal,connection.token);this.check(epoch,signal);
      if(!progress.complete||!progress.receipt||!same(progress.receipt,receipt)||progress.frozenDigest!==loaded.record.frozenDigest||progress.results.length!==loaded.record.batch.body.items.length)throw new FileClientError('CONFLICT');
      const fresh=await this.current(ref,signal,epoch),payload=await this.auth.worker.prepareDeliveryPublish({...loaded.input,...fresh.input,binding:fresh.context.binding,service,receipt},{signal});this.check(epoch,signal);
      return this.saved('publish',payload,signal,epoch);
    }finally{material={detailsKey:''};}
  });}
  pending(){const session=this.session();return this.store.list({workspaceId:session.workspaceId,accountId:session.accountId,deviceId:session.deviceId!});}
  resume(operationId:string){return this.run(async(signal,epoch)=>{const record=await this.store.get(this.session().workspaceId,operationId);this.check(epoch,signal);if(!record)throw new FileClientError('INVALID_FILE');return this.finish(record,signal,epoch);});}
  discard(operationId:string){return this.run(async(signal,epoch)=>{const session=this.session(),record=await this.store.get(session.workspaceId,operationId);this.check(epoch,signal);
    if(!record||record.accountId!==session.accountId||record.deviceId!==session.deviceId)throw new FileClientError('CONFLICT');const binding=deliveryOperationBinding(record),ref=this.reference(binding.projectId,operationId);
    await this.transport.status({...ref,dataGeneration:binding.dataGeneration,requestHash:await digestObject(record.payload)},{signal});this.check(epoch,signal);await this.store.remove(session.workspaceId,operationId);this.check(epoch,signal);});}
}

import { z } from 'zod';
import { identifier } from '../shared/contracts.js';
import { canonicalJson } from '../shared/crypto.js';
import { evidenceSubmitRequest,evidenceReviewRequest,evidenceSharedRequest,evidenceRevokeRequest } from '../shared/file-evidence.js';
import { AuthenticatedHttp } from './auth-controller.js';
import { FileClientError } from './files-crypto.js';

export const storedFileEvidence = z.strictObject({completed:z.boolean().default(false),version:z.literal(1),origin:z.string(),workspaceId:identifier,accountId:identifier,deviceId:identifier,operationId:identifier,flowOperationId:identifier,taskId:identifier.nullable(),action:z.enum(['submit','accept','approve_shared','revoke']),payload:z.union([evidenceSubmitRequest,evidenceReviewRequest,evidenceSharedRequest,evidenceRevokeRequest])});
export type StoredFileEvidence=z.infer<typeof storedFileEvidence>;
function binding(r:StoredFileEvidence){const p=r.payload;return 'submission' in p?p.submission.body.binding:'review' in p?p.review.body.binding:'approval' in p?p.approval.body.binding:p.revocation.body.binding;}
/** Only signed ciphertext and bounded flow identifiers survive an interrupted review. */
export class IndexedFileEvidenceStore {
  private constructor(readonly origin:string,private readonly database:IDBDatabase){database.onversionchange=()=>database.close();}
  static async open(origin:string,name='maqbool-file-evidence-v1',factory:IDBFactory|undefined=globalThis.indexedDB):Promise<IndexedFileEvidenceStore>{
    const accepted=new AuthenticatedHttp(origin).origin;if(!factory)throw new FileClientError('STORAGE');
    return new Promise((resolve,reject)=>{let settled=false;const request=factory.open(name,1);
      request.onblocked=request.onerror=()=>{settled=true;reject(new FileClientError('STORAGE'));};
      request.onupgradeneeded=()=>request.result.createObjectStore('uploads');
      request.onsuccess=()=>settled?request.result.close():resolve(new IndexedFileEvidenceStore(accepted,request.result));});
  }
  private transaction<T>(mode:IDBTransactionMode,work:(store:IDBObjectStore,done:(v:T)=>void,fail:(e:unknown)=>void)=>void):Promise<T>{
    return new Promise((resolve,reject)=>{let tx:IDBTransaction;
      try{tx=this.database.transaction('uploads',mode,mode==='readwrite'?{durability:'strict'}:{});}catch{reject(new FileClientError('STORAGE'));return;}
      let value:T,finished=false,error:unknown;
      const fail=(e:unknown)=>{error=e;try{tx.abort();}catch{reject(e);}};
      tx.onabort=()=>reject(error instanceof FileClientError?error:new FileClientError('STORAGE'));
      tx.oncomplete=()=>finished?resolve(value):reject(new FileClientError('STORAGE'));
      try{work(tx.objectStore('uploads'),v=>{value=v;finished=true;},fail);}catch(e){fail(e);}
    });
  }
  private key(workspaceId:string,operationId:string){return `${this.origin}:${identifier.parse(workspaceId)}:${identifier.parse(operationId)}`;}
  private parse(value:unknown):StoredFileEvidence{
    const r=storedFileEvidence.parse(value),b=binding(r);
    if(r.origin!==this.origin||r.origin!==b.origin||r.workspaceId!==b.workspaceId||r.accountId!==b.accountId||
      r.deviceId!==b.deviceId||r.operationId!==b.operationId)throw new FileClientError('CONFLICT');
    return r;
  }
  get(workspaceId:string,operationId:string):Promise<StoredFileEvidence|undefined>{
    return this.transaction('readonly',(s,done,fail)=>{const r=s.get(this.key(workspaceId,operationId));r.onsuccess=()=>{try{done(r.result===undefined?undefined:this.parse(r.result));}catch(e){fail(e);}};});
  }
  put(value:StoredFileEvidence):Promise<void>{
    const record=this.parse(value),key=this.key(record.workspaceId,record.operationId);
    return this.transaction('readwrite',(s,done,fail)=>{const r=s.get(key);r.onsuccess=()=>{try{
      if(r.result!==undefined){if(canonicalJson(this.parse(r.result))!==canonicalJson(record))throw new FileClientError('CONFLICT');}
      else {const count=s.count();count.onsuccess=()=>{if(count.result>=8192)fail(new FileClientError('STORAGE'));else{s.add(record,key);done(undefined);}};return;}
      done(undefined);
    }catch(e){fail(e);}};});
  }
  complete(workspaceId:string,operationId:string):Promise<void>{return this.transaction('readwrite',(s,done,fail)=>{const r=s.get(this.key(workspaceId,operationId));r.onsuccess=()=>{try{if(r.result===undefined)throw new FileClientError('STORAGE');const record=this.parse(r.result);s.put({...record,completed:true},this.key(workspaceId,operationId));done(undefined);}catch(e){fail(e);}};});}
  remove(workspaceId:string,operationId:string):Promise<void>{return this.transaction('readwrite',(s,done)=>{s.delete(this.key(workspaceId,operationId));done(undefined);});}
  list(reference:{workspaceId:string;accountId:string;deviceId:string}):Promise<StoredFileEvidence[]>{
    return this.transaction('readonly',(s,done,fail)=>{const r=s.getAll();r.onsuccess=()=>{try{done(r.result.flatMap((v:unknown)=>{
      const record=this.parse(v);return record.workspaceId===reference.workspaceId&&record.accountId===reference.accountId&&record.deviceId===reference.deviceId&&!record.completed?[record]:[];}));}catch(e){fail(e);}};});
  }
  forgetDevice(reference:{workspaceId:string;accountId:string;deviceId:string}):Promise<void>{
    return this.transaction('readwrite',(s,done,fail)=>{const r=s.openCursor();r.onsuccess=()=>{try{const cursor=r.result;if(!cursor){done(undefined);return;}
      const record=this.parse(cursor.value);if(record.workspaceId===reference.workspaceId&&record.accountId===reference.accountId&&record.deviceId===reference.deviceId)cursor.delete();cursor.continue();}catch(e){fail(e);}};});
  }
  close(){this.database.close();}
}

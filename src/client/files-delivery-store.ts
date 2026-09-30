import { z } from 'zod';
import { identifier } from '../shared/contracts.js';
import { canonicalJson } from '../shared/crypto.js';
import { deliveryCreateRequest,deliveryCommandRequest,deliveryPairRequest,deliveryServiceCommandRequest,deliveryPublishRequest } from '../shared/file-delivery.js';
import { AuthenticatedHttp } from './auth-controller.js';
import { FileClientError } from './files-crypto.js';

export const storedDeliveryOperation=z.strictObject({version:z.literal(1),origin:z.string(),workspaceId:identifier,accountId:identifier,deviceId:identifier,
  operationId:identifier,action:z.enum(['create','confirm','cancel','record_package','pair','revoke_service','publish']),
  payload:z.union([deliveryCreateRequest,deliveryCommandRequest,deliveryPairRequest,deliveryServiceCommandRequest,deliveryPublishRequest])});
export type StoredDeliveryOperation=z.infer<typeof storedDeliveryOperation>;
export function deliveryOperationBinding(record:StoredDeliveryOperation){const p=record.payload;
  return 'batch'in p?p.batch.body.binding:'approval'in p?p.approval.body.binding:p.mutation.body.binding;}
/** Retries retain exact signatures and ciphertext; destinations, root names and keys remain encrypted. */
export class IndexedDeliveryStore {
  private constructor(readonly origin:string,private readonly database:IDBDatabase){database.onversionchange=()=>database.close();}
  static async open(origin:string,name='maqbool-deliveries-v1',factory:IDBFactory|undefined=globalThis.indexedDB):Promise<IndexedDeliveryStore>{
    const accepted=new AuthenticatedHttp(origin).origin;if(!factory)throw new FileClientError('STORAGE');
    return new Promise((resolve,reject)=>{let settled=false;const request=factory.open(name,1);
      request.onblocked=request.onerror=()=>{settled=true;reject(new FileClientError('STORAGE'));};
      request.onupgradeneeded=()=>request.result.createObjectStore('operations');
      request.onsuccess=()=>settled?request.result.close():resolve(new IndexedDeliveryStore(accepted,request.result));});
  }
  private transaction<T>(mode:IDBTransactionMode,work:(store:IDBObjectStore,done:(value:T)=>void,fail:(error:unknown)=>void)=>void):Promise<T>{
    return new Promise((resolve,reject)=>{let tx:IDBTransaction;
      try{tx=this.database.transaction('operations',mode,mode==='readwrite'?{durability:'strict'}:{});}catch{reject(new FileClientError('STORAGE'));return;}
      let value:T,finished=false,error:unknown;const fail=(e:unknown)=>{error=e;try{tx.abort();}catch{reject(e);}};
      tx.onabort=()=>reject(error instanceof FileClientError?error:new FileClientError('STORAGE'));
      tx.oncomplete=()=>finished?resolve(value):reject(new FileClientError('STORAGE'));
      try{work(tx.objectStore('operations'),v=>{value=v;finished=true;},fail);}catch(e){fail(e);}
    });
  }
  private key(workspaceId:string,operationId:string){return `${this.origin}:${identifier.parse(workspaceId)}:${identifier.parse(operationId)}`;}
  private parse(value:unknown){const record=storedDeliveryOperation.parse(value),binding=deliveryOperationBinding(record),p=record.payload;
    const action='batch'in p?'create':'approval'in p?'pair':p.mutation.body.purpose==='ukda.file-delivery-command.v1'?p.mutation.body.action:p.mutation.body.purpose==='ukda.file-service-revoke.v1'?'revoke_service':'publish';
    if(record.origin!==this.origin||record.origin!==binding.origin||record.workspaceId!==binding.workspaceId||record.accountId!==binding.accountId||
      record.deviceId!==binding.deviceId||record.operationId!==binding.operationId||record.action!==action)throw new FileClientError('CONFLICT');return record;
  }
  get(workspaceId:string,operationId:string):Promise<StoredDeliveryOperation|undefined>{return this.transaction('readonly',(store,done,fail)=>{const request=store.get(this.key(workspaceId,operationId));request.onsuccess=()=>{
    try{done(request.result===undefined?undefined:this.parse(request.result));}catch(error){fail(error);}};});}
  put(value:StoredDeliveryOperation):Promise<void>{const record=this.parse(value),key=this.key(record.workspaceId,record.operationId);
    return this.transaction('readwrite',(store,done,fail)=>{const request=store.get(key);request.onsuccess=()=>{try{
      if(request.result!==undefined){if(canonicalJson(this.parse(request.result))!==canonicalJson(record))throw new FileClientError('CONFLICT');done(undefined);}
      else{const count=store.count();count.onsuccess=()=>{if(count.result>=64)fail(new FileClientError('STORAGE'));else{store.add(record,key);done(undefined);}};}
    }catch(error){fail(error);}};});
  }
  remove(workspaceId:string,operationId:string):Promise<void>{return this.transaction('readwrite',(store,done)=>{store.delete(this.key(workspaceId,operationId));done(undefined);});}
  list(scope:{workspaceId:string;accountId:string;deviceId:string}):Promise<StoredDeliveryOperation[]>{return this.transaction('readonly',(store,done,fail)=>{const request=store.getAll();request.onsuccess=()=>{
    try{done(request.result.flatMap((value:unknown)=>{const r=this.parse(value);return r.workspaceId===scope.workspaceId&&r.accountId===scope.accountId&&r.deviceId===scope.deviceId?[r]:[];}));}catch(error){fail(error);}};});}
  forgetDevice(scope:{workspaceId:string;accountId:string;deviceId:string}):Promise<void>{return this.transaction('readwrite',(store,done,fail)=>{const request=store.openCursor();request.onsuccess=()=>{try{
    const cursor=request.result;if(!cursor){done(undefined);return;}const r=this.parse(cursor.value);
    if(r.workspaceId===scope.workspaceId&&r.accountId===scope.accountId&&r.deviceId===scope.deviceId)cursor.delete();cursor.continue();
  }catch(error){fail(error);}};});}
  close(){this.database.close();}
}

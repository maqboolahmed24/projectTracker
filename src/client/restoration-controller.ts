import { z } from 'zod';
import { canonicalJson,digestObject } from '../shared/crypto.js';
import { restoreContext,restoreView,restoreVerification,RESTORE_MAX_BYTES,type RestoreContext,type RestoreView,type RestoreVerification,
  type restoreContextRequest,type restoreStatusRequest } from '../shared/restoration.js';
import { verifySecurityHistory,type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthenticatedHttp,AuthClientError,type AuthController,type AuthRequestOptions } from './auth-controller.js';
import type { AccessChangeTransport } from './access-change-controller.js';
import { IndexedPairingStore } from './pairing.js';
import { IndexedSignedRequests,openRequestDatabase,requestIdentity } from './retry-store.js';
import { assertOnline,WriteError } from './write-state.js';
import type { ReadableRestoration,VerifyRestorationInput } from './restoration-crypto.js';
type ContextRequest=z.infer<typeof restoreContextRequest>;
type StatusRequest=z.infer<typeof restoreStatusRequest>;
export interface RestorationTransport {readonly origin:string;context(input:ContextRequest,options?:AuthRequestOptions):Promise<RestoreContext>;
  verify(input:RestoreVerification,options?:AuthRequestOptions):Promise<RestoreView>;status(input:StatusRequest,options?:AuthRequestOptions):Promise<RestoreView>}
export class HttpRestorationTransport extends AuthenticatedHttp implements RestorationTransport {
  constructor(origin:string,private readonly csrf:()=>string|undefined,fetcher?:typeof fetch){super(origin,fetcher);}
  private request<T>(path:string,input:unknown,schema:z.ZodType<T>,options?:AuthRequestOptions){const csrfToken=this.csrf();if(!csrfToken)throw new AuthClientError('AUTH_REQUIRED');return this.post('/v1/restoration/'+path,input,schema,{...options,csrfToken});}
  context(input:ContextRequest,options?:AuthRequestOptions){return this.request('context',input,restoreContext,options);}
  verify(input:RestoreVerification,options?:AuthRequestOptions){return this.request('verify',input,restoreView,options);}
  status(input:StatusRequest,options?:AuthRequestOptions){return this.request('status',input,restoreView,options);}
  protected override responseLimit(path:string){return path.startsWith('/v1/restoration/')?RESTORE_MAX_BYTES:super.responseLimit(path);}
}
const stored=requestIdentity.extend({version:z.literal(1),payload:restoreVerification});
type Stored=z.infer<typeof stored>;
export class IndexedRestorationStore extends IndexedSignedRequests<Stored>{
  private constructor(origin:string,database:IDBDatabase){super(origin,database,stored,r=>{const b=r.payload.body.binding;return {origin:b.origin,workspaceId:b.workspaceId,accountId:b.accountId,deviceId:b.deviceId,operationId:b.operationId};});}
  static async open(origin:string,name='ukda-restoration-requests-v1',factory:IDBFactory|undefined=globalThis.indexedDB){return new IndexedRestorationStore(origin,await openRequestDatabase(name,factory));}
}
export interface RestorationWorker {readRestoration(input:VerifyRestorationInput,options?:AuthRequestOptions):Promise<ReadableRestoration>;
  prepareRestorationVerification(input:VerifyRestorationInput,options?:AuthRequestOptions):Promise<RestoreVerification>}
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
/** No automatic verification or rebase. The caller explicitly acknowledges the
 * reported recovery point and missing work before submitting the Owner proof. */
export class RestorationController {
  private epoch=0;private readonly requests=new Set<AbortController>();private readonly running=new Set<Promise<unknown>>();private busy=false;
  constructor(private readonly auth:AuthController,private readonly transport:RestorationTransport,private readonly pins:IndexedPairingStore,
    private readonly security:Pick<AccessChangeTransport,'deliveryHistory'>,private readonly operations:IndexedRestorationStore,
    private readonly worker:RestorationWorker,private readonly options:{trustedServiceKeys?:Record<string,string>}={}){
    if([transport.origin,pins.origin,operations.origin].some(origin=>origin!==auth.origin))throw new WriteError('CONFLICT');}
  clear(){this.epoch++;for(const request of this.requests)request.abort();this.requests.clear();}
  attachAuthLifecycle(){const clear=this.auth.onClear(()=>this.clear()),forget=this.auth.onForget(ref=>this.forgetDevice(ref));return()=>{clear();forget();};}
  async forgetDevice(ref:{workspaceId:string;accountId:string;deviceId:string}){this.clear();await Promise.allSettled([...this.running]);await this.operations.forgetDevice(ref);}
  private session(){const current=this.auth.current();if(current?.localAccess!=='unlocked'||!current.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');return {...current.session,deviceId:current.session.deviceId};}
  private check(epoch:number){if(epoch!==this.epoch)throw new AuthClientError('CANCELLED');}
  private run<T>(work:(signal:AbortSignal,epoch:number)=>Promise<T>):Promise<T>{if(this.busy)return Promise.reject(new WriteError('RETRY_REQUIRED'));this.busy=true;
    const request=new AbortController(),epoch=this.epoch;this.requests.add(request);const promise=(async()=>{try{const value=await work(request.signal,epoch);this.check(epoch);return value;}finally{this.requests.delete(request);this.busy=false;}})();
    this.running.add(promise);void promise.finally(()=>this.running.delete(promise)).catch(()=>{});return promise;}
  private async history(signal:AbortSignal,epoch:number):Promise<SecurityHistoryInput>{const s=this.session(),pin=await this.pins.pin(s.workspaceId);this.check(epoch);if(!pin)throw new AuthClientError('CONTEXT_MISMATCH');
    const response=await this.security.deliveryHistory({workspaceId:s.workspaceId,operationId:crypto.randomUUID()},{signal});this.check(epoch);if(!same(response.current,response.anchor))throw new WriteError('CONFLICT');
    const history:SecurityHistoryInput={workspaceId:s.workspaceId,origin:this.auth.origin,genesisFingerprint:pin.genesisFingerprint,genesis:response.genesis,transitions:response.transitions,expected:response.anchor,pin,trustedServiceKeys:this.options.trustedServiceKeys??{}};
    const state=await verifySecurityHistory(history);if(state.dataGeneration!==s.dataGeneration)throw new WriteError('CONFLICT');return history;}
  private async input(restoreId:string,operationId:string,signal:AbortSignal,epoch:number):Promise<VerifyRestorationInput>{const s=this.session(),context=await this.transport.context({workspaceId:s.workspaceId,restoreId,operationId},{signal});this.check(epoch);
    const history=await this.history(signal,epoch);return {context,history,accountId:s.accountId,deviceId:s.deviceId};}
  inspect(restoreId:string){return this.run(async(signal,epoch)=>{const input=await this.input(restoreId,crypto.randomUUID(),signal,epoch),result=await this.worker.readRestoration(input,{signal});this.check(epoch);await this.pins.recordVerifiedHistory(input.history);return result;});}
  verify(restoreId:string,acknowledgeMissingContent:true,operationId=crypto.randomUUID()){return this.run(async(signal,epoch)=>{
    assertOnline();if(acknowledgeMissingContent!==true)throw new WriteError('CONFLICT');const s=this.session();if((await this.operations.list(s)).length)throw new WriteError('RETRY_REQUIRED');
    const input=await this.input(restoreId,operationId,signal,epoch),payload=await this.worker.prepareRestorationVerification(input,{signal});this.check(epoch);
    const pending:Stored={version:1,origin:this.auth.origin,workspaceId:s.workspaceId,accountId:s.accountId,deviceId:s.deviceId,operationId,payload};await this.operations.put(pending);this.check(epoch);
    return this.commit(pending,signal,epoch,false);
  });}
  resume(operationId:string){return this.run(async(signal,epoch)=>{assertOnline();const s=this.session(),pending=await this.operations.get(s.workspaceId,operationId);if(!pending||pending.accountId!==s.accountId||pending.deviceId!==s.deviceId)throw new WriteError('CONFLICT');return this.commit(pending,signal,epoch,true);});}
  private async commit(pending:Stored,signal:AbortSignal,epoch:number,statusFirst:boolean){const b=pending.payload.body.binding;
    let result=statusFirst?await this.transport.status({workspaceId:b.workspaceId,restoreId:b.restoreId,operationId:b.operationId,requestHash:await digestObject(pending.payload)},{signal}):null;this.check(epoch);
    if(result?.state!=='completed')result=await this.transport.verify(pending.payload,{signal});this.check(epoch);
    if(result.state==='completed'){
      if(!same(result.verification,pending.payload))throw new WriteError('CONFLICT');const history=await this.history(signal,epoch);this.check(epoch);
      if(!history.transitions.some(record=>same(record,pending.payload)))throw new WriteError('CONFLICT');await this.pins.recordVerifiedHistory(history);this.check(epoch);
      await this.operations.remove(pending.workspaceId,pending.operationId);
    }return result;
  }
  pending(){return this.operations.list(this.session());}
}

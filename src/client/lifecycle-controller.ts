import { z } from 'zod';
import { canonicalJson,digestObject } from '../shared/crypto.js';
import { lifecycleContext,lifecycleView,erasureList,type LifecycleBinding,type LifecycleMutation } from '../shared/lifecycle.js';
import { verifySecurityHistory,type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthenticatedHttp,AuthClientError,type AuthController,type AuthRequestOptions } from './auth-controller.js';
import { IndexedPairingStore } from './pairing.js';
import { HttpAccessChangeTransport } from './access-change-controller.js';
import { IndexedLifecycleStore } from './lifecycle-store.js';
import type { PrepareLifecycleInput } from './lifecycle-crypto.js';
import { assertOnline } from './write-state.js';

export class HttpLifecycleTransport extends AuthenticatedHttp{
 constructor(origin:string,private readonly csrf:()=>string|undefined,fetcher?:typeof fetch){super(origin,fetcher);}
 private request<T>(path:string,body:unknown,schema:z.ZodType<T>,options?:AuthRequestOptions){const csrfToken=this.csrf();if(!csrfToken)throw new AuthClientError('AUTH_REQUIRED');return this.post('/v1/lifecycle/'+path,body,schema,{...options,csrfToken});}
 context(body:{workspaceId:string;operationId:string;action:LifecycleBinding['action']},options?:AuthRequestOptions){return this.request('context',body,lifecycleContext,options);}
 save(body:LifecycleMutation,options?:AuthRequestOptions){return this.request('save',body,lifecycleView,options);}
 status(body:{workspaceId:string;operationId:string;requestHash:string;dataGeneration:string},options?:AuthRequestOptions){return this.request('status',body,lifecycleView,options);}
 erasures(workspaceId:string,options?:AuthRequestOptions){return this.request('erasures',{workspaceId},erasureList,options);}
}
export interface LifecycleControllerOptions {
 prepare:(input:PrepareLifecycleInput,options?:AuthRequestOptions)=>Promise<LifecycleMutation>;
 trustedServiceKeys?:Record<string,string>;
}
/** Exact signed drafts contain no workspace confirmation name or private keys. */
export class LifecycleController{
 private epoch=0;private readonly requests=new Set<AbortController>();private readonly running=new Set<Promise<unknown>>();
 constructor(private readonly auth:AuthController,private readonly transport:HttpLifecycleTransport,private readonly operations:IndexedLifecycleStore,
  private readonly pins:IndexedPairingStore,private readonly access:HttpAccessChangeTransport,private readonly options:LifecycleControllerOptions){
  if([transport.origin,operations.origin,pins.origin,access.origin].some(origin=>origin!==auth.origin))throw new Error('Lifecycle origin mismatch');
 }
 clear(){this.epoch++;for(const request of this.requests)request.abort();this.requests.clear();}
 attachAuthLifecycle(){const clear=this.auth.onClear(()=>this.clear()),forget=this.auth.onForget(ref=>this.forgetDevice(ref));return()=>{clear();forget();};}
 async forgetDevice(ref:{workspaceId:string;accountId:string;deviceId:string}){this.clear();await Promise.allSettled([...this.running]);await this.operations.forgetDevice(ref);}
 private session(){const current=this.auth.current();if(current?.localAccess!=='unlocked'||!current.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');return current.session;}
 private run<T>(work:(options:AuthRequestOptions)=>Promise<T>):Promise<T>{const request=new AbortController(),epoch=this.epoch;this.requests.add(request);
  const promise=(async()=>{try{const result=await work({signal:request.signal});if(epoch!==this.epoch)throw new AuthClientError('CANCELLED');return result;}finally{this.requests.delete(request);}})();
  this.running.add(promise);void promise.finally(()=>this.running.delete(promise)).catch(()=>{});return promise;
 }
 private check(options:AuthRequestOptions){if(options.signal?.aborted)throw new AuthClientError('CANCELLED');}
 private async history(workspaceId:string,operationId:string,options:AuthRequestOptions):Promise<SecurityHistoryInput>{
  const pin=await this.pins.pin(workspaceId);this.check(options);if(!pin)throw new Error('Workspace trust required');
  const page=await this.access.deliveryHistory({workspaceId,operationId},options);this.check(options);
  if(canonicalJson(page.anchor)!==canonicalJson(page.current))throw new Error('Security history changed');
  const history:SecurityHistoryInput={workspaceId,origin:this.auth.origin,genesisFingerprint:pin.genesisFingerprint,genesis:page.genesis,transitions:page.transitions,expected:page.anchor,pin,trustedServiceKeys:this.options.trustedServiceKeys??{}};
  await verifySecurityHistory(history);this.check(options);return history;
 }
 private async finish(payload:LifecycleMutation,options:AuthRequestOptions){
  assertOnline();this.check(options);const b=payload.body.binding,s=this.session();
  if(b.workspaceId!==s.workspaceId||b.accountId!==s.accountId||b.deviceId!==s.deviceId||b.dataGeneration!==s.dataGeneration)throw new Error('Lifecycle scope changed');
  const ref={workspaceId:b.workspaceId,operationId:b.operationId,dataGeneration:b.dataGeneration,requestHash:await digestObject(payload)};
  const prior=await this.transport.status(ref,options);this.check(options);
  const view=prior.receipt?prior:await this.transport.save(payload,options);this.check(options);
  if(!view.receipt||view.receipt.requestHash!==ref.requestHash||canonicalJson(view.receipt.transition)!==canonicalJson(payload)||view.receipt.actorId!==b.accountId)throw new Error('Lifecycle receipt mismatch');
  if(view.state==='completed'){
   const history=await this.history(b.workspaceId,b.operationId,options);
   if(!history.transitions.some(t=>canonicalJson(t)===canonicalJson(payload)))throw new Error('Lifecycle history incomplete');
   await this.operations.remove(b.workspaceId,b.operationId);this.check(options);
  }
  return view;
 }
 execute(action:LifecycleBinding['action'],confirmationName?:string,operationId:string=crypto.randomUUID()){
  return this.run(async options=>{
   assertOnline();const s=this.session(),prior=await this.operations.get(s.workspaceId,operationId);this.check(options);
   if(prior){if(prior.payload.body.binding.action!==action)throw new Error('Lifecycle operation reused');return this.finish(prior.payload,options);}
   const context=await this.transport.context({workspaceId:s.workspaceId,operationId,action},options);this.check(options);
   const history=await this.history(s.workspaceId,operationId,options),materials=action==='request_deletion'?(await this.access.delivery({workspaceId:s.workspaceId},options)).materials:[];
   this.check(options);
   const payload=await this.options.prepare({context,history,materials,accountId:s.accountId,deviceId:s.deviceId!,...(confirmationName===undefined?{}:{confirmationName})},options);this.check(options);
   await this.operations.put({version:1,origin:this.auth.origin,workspaceId:s.workspaceId,accountId:s.accountId,deviceId:s.deviceId!,operationId,payload});this.check(options);
   return this.finish(payload,options);
  });
 }
 requestDeletion(confirmationName:string,operationId?:string){return this.execute('request_deletion',confirmationName,operationId);}
 cancelDeletion(operationId?:string){return this.execute('cancel_deletion',undefined,operationId);}
 requestErasure(operationId?:string){return this.execute('request_erasure',undefined,operationId);}
 erasures(){return this.run(options=>this.transport.erasures(this.session().workspaceId,options));}
 resume(operationId:string){return this.run(async options=>{const pending=await this.operations.get(this.session().workspaceId,operationId);this.check(options);if(!pending)throw new Error('Lifecycle draft unavailable');return this.finish(pending.payload,options);});}
 pending(){const s=this.session();return this.operations.list({workspaceId:s.workspaceId,accountId:s.accountId,deviceId:s.deviceId!});}
}

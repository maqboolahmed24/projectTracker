import { z } from 'zod';
import { canonicalJson,digestObject } from '../shared/crypto.js';
import { inboxBinding,inboxPage,inboxNotice,inboxPreference,inboxReceipt,type InboxCommand,type InboxMutation,type InboxReceipt } from '../shared/inbox.js';
import { AuthenticatedHttp,AuthClientError,type AuthController,type AuthRequestOptions } from './auth-controller.js';
import { IndexedInboxStore } from './inbox-store.js';
import { assertOnline,isWriteConflict,WriteConflict } from './write-state.js';

export class HttpInboxTransport extends AuthenticatedHttp{
  constructor(origin:string,private readonly csrf:()=>string|undefined,fetcher?:typeof fetch){super(origin,fetcher);}
  private request<T>(path:string,body:unknown,schema:z.ZodType<T>,options?:AuthRequestOptions){const csrfToken=this.csrf();if(!csrfToken)throw new AuthClientError('AUTH_REQUIRED');return this.post('/v1/inbox/'+path,body,schema,{...options,csrfToken});}
  context(body:{workspaceId:string;operationId:string},options?:AuthRequestOptions){return this.request('context',body,z.strictObject({binding:inboxBinding}),options);}
  save(body:InboxMutation,options?:AuthRequestOptions){return this.request('save',body,inboxReceipt,options);}
  status(body:{workspaceId:string;operationId:string},options?:AuthRequestOptions){return this.request('status',body,z.strictObject({receipt:inboxReceipt.nullable()}),options);}
  list(body:{workspaceId:string;after?:string;limit?:number;unreadOnly?:boolean},options?:AuthRequestOptions){return this.request('list',body,inboxPage,options);}
  resolve(body:{workspaceId:string;notificationId:string},options?:AuthRequestOptions){return this.request('resolve',body,inboxNotice,options);}
  preference(body:{workspaceId:string;projectId:string},options?:AuthRequestOptions){return this.request('preference',body,inboxPreference,options);}
}
/** No notice details or decrypted content are cached or persisted by the Inbox. */
export class InboxController{
  private epoch=0;private readonly requests=new Set<AbortController>();private readonly running=new Set<Promise<unknown>>();
  constructor(private readonly auth:AuthController,private readonly transport:HttpInboxTransport,private readonly operations:IndexedInboxStore){if(auth.origin!==transport.origin||auth.origin!==operations.origin)throw new Error('Inbox origin mismatch');}
  clear(){this.epoch++;for(const request of this.requests)request.abort();this.requests.clear();}
  attachAuthLifecycle(){const clear=this.auth.onClear(()=>this.clear()),forget=this.auth.onForget(ref=>this.forgetDevice(ref));return()=>{clear();forget();};}
  async forgetDevice(reference:{workspaceId:string;accountId:string;deviceId:string}){this.clear();await Promise.allSettled([...this.running]);await this.operations.forgetDevice(reference);}
  private session(){const current=this.auth.current();if(current?.localAccess!=='unlocked'||!current.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');return current.session;}
  private run<T>(work:(options:AuthRequestOptions)=>Promise<T>):Promise<T>{const controller=new AbortController(),epoch=this.epoch;this.requests.add(controller);
    const promise=(async()=>{try{const result=await work({signal:controller.signal});if(epoch!==this.epoch)throw new Error('Inbox request cancelled');return result;}finally{this.requests.delete(controller);}})();
    this.running.add(promise);void promise.finally(()=>this.running.delete(promise)).catch(()=>{});return promise;}
  private check(options:AuthRequestOptions){if(options.signal?.aborted)throw new AuthClientError('CANCELLED');}
  list(input:{after?:string;limit?:number;unreadOnly?:boolean}={}){return this.run(async options=>{const session=this.session(),page=await this.transport.list({workspaceId:session.workspaceId,...input},options);
    if(page.dataGeneration!==session.dataGeneration)throw new Error('Inbox security state changed');return page;});}
  resolve(notificationId:string){return this.run(options=>this.transport.resolve({workspaceId:this.session().workspaceId,notificationId},options));}
  preference(projectId:string){return this.run(options=>this.transport.preference({workspaceId:this.session().workspaceId,projectId},options));}
  private async finish(payload:InboxMutation,options:AuthRequestOptions):Promise<InboxReceipt>{assertOnline();this.check(options);const session=this.session(),b=payload.body.binding;
    if(b.workspaceId!==session.workspaceId||b.accountId!==session.accountId||b.deviceId!==session.deviceId||b.dataGeneration!==session.dataGeneration)throw new Error('Inbox scope changed');
    const status=await this.transport.status({workspaceId:b.workspaceId,operationId:b.operationId},options);this.check(options);
    const receipt=status.receipt??await this.transport.save(payload,options);this.check(options);
    if(receipt.requestHash!==await digestObject(payload)||receipt.workspaceId!==b.workspaceId||receipt.operationId!==b.operationId||receipt.actorId!==b.accountId||receipt.dataGeneration!==b.dataGeneration)throw new Error('Inbox receipt mismatch');
    await this.operations.remove(b.workspaceId,b.operationId);this.check(options);return receipt;}
  execute(value:InboxCommand,operationId:string=crypto.randomUUID()){const command=structuredClone(value);return this.run(async options=>{
    assertOnline();const previous=await this.operations.get(this.session().workspaceId,operationId);this.check(options);
    if(previous){if(canonicalJson(previous.payload.body.command)!==canonicalJson(command))throw new Error('Inbox operation already used');return this.finish(previous.payload,options);}
    const session=this.session(),{binding}=await this.transport.context({workspaceId:session.workspaceId,operationId},options);
    if(binding.origin!==this.auth.origin||binding.workspaceId!==session.workspaceId||binding.accountId!==session.accountId||binding.deviceId!==session.deviceId||
      binding.credentialGeneration!==session.credentialGeneration||binding.sessionGeneration!==session.sessionGeneration||binding.dataGeneration!==session.dataGeneration)throw new Error('Inbox binding mismatch');
    this.check(options);const payload=await this.auth.worker.prepareInbox({binding,command},options);this.check(options);
    await this.operations.put({version:1,origin:this.auth.origin,workspaceId:binding.workspaceId,accountId:binding.accountId,deviceId:binding.deviceId,operationId,payload});this.check(options);
    try{return await this.finish(payload,options);}catch(error){if(isWriteConflict(error)){
      const current=command.action==='set_project_muted'?await this.preference(command.projectId):await Promise.all(command.records.map(row=>this.resolve(row.id)));
      throw new WriteConflict(operationId,current,command);
    }throw error;}
  });}
  setRead(records:{id:string;expectedRevision:string}[],read:boolean,operationId?:string){return this.execute({action:'set_read',records,read},operationId);}
  setProjectMuted(projectId:string,muted:boolean,expectedRevision:string,operationId?:string){return this.execute({action:'set_project_muted',projectId,muted,expectedRevision},operationId);}
  resume(operationId:string){return this.run(async options=>{assertOnline();const record=await this.operations.get(this.session().workspaceId,operationId);this.check(options);
    if(!record)throw new Error('Inbox draft unavailable; reload current preferences');return this.finish(record.payload,options);});}
  pending(){const session=this.session();return this.operations.list({workspaceId:session.workspaceId,accountId:session.accountId,deviceId:session.deviceId!});}
}

import { z } from 'zod';
import { canonicalJson,digestObject } from '../shared/crypto.js';
import { REPORTING_MAX_BYTES,reportingContext,reportingContextRequest,reportingRead,reportingReceipt,reportingSettings,reportingSettingsContext,reportingScope,reportingView,
  type ReportingContext,type ReportingRead,type ReportingReceipt,type ReportingScope,type ReportingSettings,type ReportingSettingsContext,
  type ReportingSettingsPayload,type ReportingSummaryPayload } from '../shared/reporting.js';
import { accessDelivery } from '../shared/access-change.js';
import { verifySecurityHistory,type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthenticatedHttp,AuthClientError,type AuthController,type AuthRequestOptions } from './auth-controller.js';
import type { AccessChangeController,AccessChangeTransport } from './access-change-controller.js';
import { IndexedPairingStore } from './pairing.js';
import { IndexedPlanningStore } from './planning-store.js';
import { ReportingClientError,type CalculateReportingInput,type ReadableReporting,type ReportingSettingsPin } from './reporting-crypto.js';
import { HttpLiveSource,LiveRefreshController,type LiveState } from './live-controller.js';
import type { ProgressHealth } from '../shared/progress.js';
import { IndexedReportingStore } from './reporting-store.js';
import { assertOnline,isWriteConflict,WriteConflict,WriteError } from './write-state.js';

type Reference={workspaceId:string;operationId:string};
type View=z.infer<typeof reportingView>;
export interface ReportingTransport {
  readonly origin:string;
  settings(input:{workspaceId:string},options?:AuthRequestOptions):Promise<ReportingSettings>;
  settingsContext(input:Reference,options?:AuthRequestOptions):Promise<ReportingSettingsContext>;
  settingsSave(input:ReportingSettingsPayload,options?:AuthRequestOptions):Promise<View>;
  context(input:z.infer<typeof reportingContextRequest>,options?:AuthRequestOptions):Promise<ReportingContext>;
  publish(input:ReportingSummaryPayload,options?:AuthRequestOptions):Promise<View>;
  status(input:Reference&{kind:'settings'|'summary';dataGeneration:string;requestHash:string},options?:AuthRequestOptions):Promise<View>;
  read(input:z.infer<typeof reportingContextRequest>,options?:AuthRequestOptions):Promise<ReportingRead>;
}
export class HttpReportingTransport extends AuthenticatedHttp implements ReportingTransport {
  constructor(origin:string,private readonly csrf:()=>string|undefined,fetcher?:typeof fetch){super(origin,fetcher);}
  private request<T>(path:string,input:unknown,schema:z.ZodType<T>,options?:AuthRequestOptions){
    const csrfToken=this.csrf();if(!csrfToken)throw new AuthClientError('AUTH_REQUIRED');return this.post('/v1/reporting/'+path,input,schema,{...options,csrfToken});
  }
  settings(input:{workspaceId:string},options?:AuthRequestOptions){return this.request('settings',input,reportingSettings,options);}
  settingsContext(input:Reference,options?:AuthRequestOptions){return this.request('settings/context',input,reportingSettingsContext,options);}
  settingsSave(input:ReportingSettingsPayload,options?:AuthRequestOptions){return this.request('settings/save',input,reportingView,options);}
  context(input:z.infer<typeof reportingContextRequest>,options?:AuthRequestOptions){return this.request('context',input,reportingContext,options);}
  publish(input:ReportingSummaryPayload,options?:AuthRequestOptions){return this.request('publish',input,reportingView,options);}
  status(input:Reference&{kind:'settings'|'summary';dataGeneration:string;requestHash:string},options?:AuthRequestOptions){return this.request(input.kind==='settings'?'settings/status':'status',input,reportingView,options);}
  read(input:z.infer<typeof reportingContextRequest>,options?:AuthRequestOptions){return this.request('read',input,reportingRead,options);}
  protected override responseLimit(path:string){return path.startsWith('/v1/reporting/')?REPORTING_MAX_BYTES:super.responseLimit(path);}
}
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
function scopeFor(value:ReportingScope):ReportingScope {
  return reportingScope.parse({...value,...('projectIds'in value?{projectIds:[...new Set(value.projectIds)].sort()}:{ }),
    ...(value.kind==='filtered'?{taskIds:[...new Set(value.taskIds)].sort()}:{})});
}
type Draft={kind:'settings';payload:ReportingSettingsPayload}|{kind:'summary';payload:ReportingSummaryPayload};
export interface ReportingLiveState extends LiveState<ReadableReporting> {
  currentHealth: ProgressHealth | null; lastCalculated: ReadableReporting | null;
}
/** Only exact signed ciphertext requests persist while acknowledgement is uncertain. */
export class ReportingController {
  private epoch=0;private readonly requests=new Set<AbortController>();private readonly running=new Set<Promise<unknown>>();
  private readonly settingsPins=new Map<string,ReportingSettingsPin>();private readonly watchers=new Set<LiveRefreshController<ReadableReporting>>();
  constructor(private readonly auth:AuthController,private readonly transport:ReportingTransport,private readonly pins:IndexedPairingStore,
    private readonly planningPins:IndexedPlanningStore,private readonly access:Pick<AccessChangeController,'refreshKeys'>,
    private readonly security:Pick<AccessChangeTransport,'delivery'|'deliveryHistory'>,
    private readonly operations:IndexedReportingStore,
    private readonly options:{trustedServiceKeys?:Record<string,string>}={}) {
    if([transport.origin,pins.origin,planningPins.origin,operations.origin].some(origin=>origin!==auth.origin))throw new ReportingClientError('CONFLICT');
  }
  clear(){this.epoch++;for(const request of this.requests)request.abort();this.requests.clear();this.settingsPins.clear();for(const watcher of this.watchers)watcher.stop();this.watchers.clear();}
  attachAuthLifecycle(){const clear=this.auth.onClear(()=>this.clear()),forget=this.auth.onForget(ref=>this.forgetDevice(ref));return()=>{clear();forget();};}
  async forgetDevice(reference:{workspaceId:string;accountId:string;deviceId:string}){this.clear();await Promise.allSettled([...this.running]);await this.operations.forgetDevice(reference);}
  private session(){const current=this.auth.current();if(current?.localAccess!=='unlocked'||!current.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');return current.session;}
  private check(epoch:number){if(epoch!==this.epoch)throw new ReportingClientError('CANCELLED');}
  private run<T>(work:(signal:AbortSignal,epoch:number)=>Promise<T>,signal?:AbortSignal):Promise<T>{
    const request=new AbortController(),epoch=this.epoch,onAbort=()=>request.abort();signal?.addEventListener('abort',onAbort,{once:true});if(signal?.aborted)request.abort();this.requests.add(request);
    const promise=(async()=>{try{const result=await work(request.signal,epoch);this.check(epoch);if(request.signal.aborted)throw new ReportingClientError('CANCELLED');return result;}
    finally{signal?.removeEventListener('abort',onAbort);this.requests.delete(request);}})();
    this.running.add(promise);void promise.finally(()=>this.running.delete(promise)).catch(()=>{});return promise;
  }
  private async keys(signal:AbortSignal,epoch:number){
    const session=this.session(),pin=await this.pins.pin(session.workspaceId);this.check(epoch);if(!pin)throw new ReportingClientError('TRUST_REQUIRED');
    await this.access.refreshKeys();this.check(epoch);
    const delivery=accessDelivery.parse(await this.security.delivery({workspaceId:session.workspaceId},{signal}));this.check(epoch);
    const response=await this.security.deliveryHistory({workspaceId:session.workspaceId,operationId:crypto.randomUUID()},{signal});this.check(epoch);
    if(!same(response.anchor,response.current)||!same(delivery.current,response.current)||delivery.accountId!==session.accountId||delivery.deviceId!==session.deviceId||delivery.workspaceId!==session.workspaceId)throw new ReportingClientError('CONFLICT');
    const history:SecurityHistoryInput={workspaceId:session.workspaceId,origin:this.auth.origin,genesisFingerprint:pin.genesisFingerprint,genesis:response.genesis,
      transitions:response.transitions,expected:response.anchor,pin,trustedServiceKeys:this.options.trustedServiceKeys??{}},state=await verifySecurityHistory(history);this.check(epoch);
    const p=state.profiles[session.accountId],d=state.devices[session.deviceId!];
    if(!p?.active||!d?.active||d.accountId!==session.accountId||p.credentialGeneration!==session.credentialGeneration||p.sessionGeneration!==session.sessionGeneration||state.dataGeneration!==session.dataGeneration)throw new ReportingClientError('CONFLICT');
    const settingsPin=this.settingsPins.get(session.workspaceId);
    return {history,materials:delivery.materials,accountId:session.accountId,deviceId:session.deviceId!,...(settingsPin?{settingsPin}:{})};
  }
  private async verifiedSettings(keys:Awaited<ReturnType<ReportingController['keys']>>,signal:AbortSignal,epoch:number){
    const settings=reportingSettings.parse(await this.transport.settings({workspaceId:keys.history.workspaceId},{signal}));this.check(epoch);
    const result=await this.auth.worker.readReportingSettings({...keys,settings},{signal});this.check(epoch);
    this.settingsPins.set(result.workspaceId,result.pin);await this.pins.recordVerifiedHistory(keys.history);this.check(epoch);return result;
  }
  settings(){return this.run(async(signal,epoch)=>this.verifiedSettings(await this.keys(signal,epoch),signal,epoch));}
  settingsProof(){return this.run(async(signal,epoch)=>{
    const keys=await this.keys(signal,epoch),settings=reportingSettings.parse(await this.transport.settings({workspaceId:keys.history.workspaceId},{signal}));this.check(epoch);
    const verified=await this.auth.worker.readReportingSettings({...keys,settings},{signal});this.check(epoch);
    this.settingsPins.set(verified.workspaceId,verified.pin);await this.pins.recordVerifiedHistory(keys.history);this.check(epoch);
    return {...keys,settings,settingsPin:verified.pin};
  });}
  private async input(scope:ReportingScope,operationId:string,signal:AbortSignal,epoch:number,read=false){
    const keys=await this.keys(signal,epoch),settings=await this.verifiedSettings(keys,signal,epoch);this.check(epoch);
    if(settings.timezone===null)throw new ReportingClientError('UNRECORDED_TIMEZONE');
    const request={workspaceId:keys.history.workspaceId,operationId,scope:scopeFor(scope),timezone:settings.timezone},
      response=read?await this.transport.read(request,{signal}):null,context=response?.context??await this.transport.context(request,{signal});this.check(epoch);
    if(context.binding.workspaceId!==request.workspaceId||context.binding.operationId!==operationId||!same(context.binding.scope,request.scope)||
      context.binding.accountId!==keys.accountId||context.binding.deviceId!==keys.deviceId)throw new ReportingClientError('INVALID_REPORTING');
    const planningPins=[];for(const project of context.projects){const pin=await this.planningPins.pin({workspaceId:request.workspaceId,projectId:project.binding.projectId});this.check(epoch);if(pin)planningPins.push(pin);}
    return {input:{...keys,context,planningPins,settingsPin:settings.pin} satisfies CalculateReportingInput,response};
  }
  private async remember(view:ReadableReporting,history:SecurityHistoryInput,epoch:number){
    this.check(epoch);this.settingsPins.set(view.settingsPin.workspaceId,view.settingsPin);
    for(const pin of view.planningPins){await this.planningPins.recordPin(pin);this.check(epoch);}await this.pins.recordVerifiedHistory(history);this.check(epoch);return view;
  }
  calculate(scope:ReportingScope,options:{signal?:AbortSignal}={}){return this.run(async(signal,epoch)=>{
    const {input}=await this.input(scope,crypto.randomUUID(),signal,epoch),view=await this.auth.worker.calculateReporting(input,{signal});return this.remember(view,input.history,epoch);
  },options.signal);}
  read(scope:ReportingScope){return this.run(async(signal,epoch)=>{
    const {input,response}=await this.input(scope,crypto.randomUUID(),signal,epoch,true);if(!response)throw new ReportingClientError('INVALID_REPORTING');
    const view=await this.auth.worker.readReporting({...input,response},{signal});return this.remember(view,input.history,epoch);
  });}
  private async finish(draft:Draft,signal:AbortSignal,epoch:number):Promise<ReportingReceipt>{
    assertOnline();
    const b=draft.payload.mutation.body.binding,session=this.session();
    if(b.workspaceId!==session.workspaceId||b.accountId!==session.accountId||b.deviceId!==session.deviceId||b.credentialGeneration!==session.credentialGeneration||b.sessionGeneration!==session.sessionGeneration||b.dataGeneration!==session.dataGeneration)throw new ReportingClientError('CONFLICT');
    const requestHash=await digestObject(draft.payload),reference={workspaceId:b.workspaceId,operationId:b.operationId,dataGeneration:b.dataGeneration,requestHash,kind:draft.kind},status=await this.transport.status(reference,{signal});this.check(epoch);
    if(status.state==='absent'&&status.receipt||status.state==='completed'&&!status.receipt)throw new ReportingClientError('INVALID_REPORTING');
    if(!status.receipt&&Date.parse(b.expiresAt)<=Date.now())throw new ReportingClientError('EXPIRED');
    const saved=status.receipt?status:draft.kind==='settings'?await this.transport.settingsSave(draft.payload,{signal}):await this.transport.publish(draft.payload,{signal});this.check(epoch);
    const receipt=reportingReceipt.parse(saved.receipt);
    if(saved.state!=='completed'||receipt.requestHash!==requestHash||receipt.workspaceId!==b.workspaceId||receipt.operationId!==b.operationId||receipt.accountId!==b.accountId||
      receipt.dataGeneration!==b.dataGeneration||receipt.kind!==draft.kind||receipt.head!==await digestObject(draft.payload.mutation))throw new ReportingClientError('INVALID_REPORTING');
    this.check(epoch);await this.operations.remove(b.workspaceId,b.operationId);this.check(epoch);this.relevantWrite();return receipt;
  }
  publish(scope:ReportingScope,operationId:string=crypto.randomUUID()){return this.run(async(signal,epoch)=>{
    assertOnline();if(await this.operations.get(this.session().workspaceId,operationId))throw new ReportingClientError('CONFLICT');this.check(epoch);
    const {input}=await this.input(scope,operationId,signal,epoch),payload=await this.auth.worker.prepareReporting(input,{signal});this.check(epoch);
    const draft:Draft={kind:'summary',payload};await this.persist(draft);this.check(epoch);return this.finish(draft,signal,epoch);
  });}
  setTimezone(timezone:string,reviewed:ReportingSettingsPin,operationId:string=crypto.randomUUID()){const prior=structuredClone(reviewed);return this.run(async(signal,epoch)=>{
    assertOnline();if(!prior)throw new WriteError('REVIEW_REQUIRED');if(await this.operations.get(this.session().workspaceId,operationId))throw new ReportingClientError('CONFLICT');this.check(epoch);
    const keys=await this.keys(signal,epoch),context=await this.transport.settingsContext({workspaceId:keys.history.workspaceId,operationId},{signal});this.check(epoch);
    if(context.binding.operationId!==operationId)throw new ReportingClientError('INVALID_REPORTING');
    const current=await this.auth.worker.readReportingSettings({...keys,settings:context.settings},{signal});this.check(epoch);
    if(!same(prior,current.pin))throw new WriteConflict(operationId,current,{timezone,reviewed:prior});
    const payload=await this.auth.worker.prepareReportingSettings({...keys,context,timezone},{signal});this.check(epoch);
    const draft:Draft={kind:'settings',payload};await this.persist(draft);this.check(epoch);
    try{return await this.finish(draft,signal,epoch);}catch(error){if(isWriteConflict(error))throw new WriteConflict(operationId,await this.settings(),{timezone,reviewed:prior});throw error;}
  });}
  private persist(draft:Draft){const b=draft.payload.mutation.body.binding;return this.operations.put({...draft,version:1,origin:this.auth.origin,
    workspaceId:b.workspaceId,operationId:b.operationId,accountId:b.accountId,deviceId:b.deviceId});}
  resume(operationId:string){return this.run(async(signal,epoch)=>{assertOnline();const draft=await this.operations.get(this.session().workspaceId,operationId);this.check(epoch);
    if(!draft)throw new ReportingClientError('NOT_FOUND');return this.finish(draft,signal,epoch);});}
  pending(){const session=this.session();return this.operations.list({workspaceId:session.workspaceId,accountId:session.accountId,deviceId:session.deviceId!});}
  relevantWrite(){for(const watcher of this.watchers)watcher.relevantWrite();}
  watch(scope:ReportingScope,onChange:(state:ReportingLiveState)=>void){
    const session=this.session(),watcher=new LiveRefreshController<ReadableReporting>({source:new HttpLiveSource(this.auth.origin,session.workspaceId,()=>this.auth.current()?.session.csrfToken),
      refresh:async signal=>{const value=await this.calculate(scope,{signal});return {value,asOfUtc:value.asOfUtc,nextMidnightUtc:value.nextMidnightUtc};},
      onChange:state=>onChange({...state,value:state.status==='current'?state.value:null,
        currentHealth:state.status==='current'?(state.value?.components.length===1?state.value.components[0]!.result.health:null):'not_enough_information',
        lastCalculated:state.status!=='current'&&state.value?{...state.value,status:'last-calculated'}:null})});
    this.watchers.add(watcher);const detach=watcher.attachLifecycle();watcher.start();return {setVisible:(visible:boolean)=>watcher.setVisible(visible),refocus:()=>watcher.refocus(),
      relevantWrite:()=>watcher.relevantWrite(),stop:()=>{detach();watcher.stop();this.watchers.delete(watcher);}};
  }
}

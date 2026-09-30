import { planningWireValue } from '../../shared/planning-api.js';
import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { assertAuthoritativeContentWrite, dataTransaction } from '../../persistence.js';
import { contentEnvelope } from '../../shared/contracts.js';
import { base64urlEncode, canonicalJson, digestObject } from '../../shared/crypto.js';
import { REPORTING_MAX_BYTES, REPORTING_MAX_SETTINGS, reportingActor, reportingBinding, reportingContextRequest, reportingLocalDate,
  reportingManifest, reportingProjectIds, reportingReceipt, reportingReference, reportingSettings, reportingSettingsBinding,
  reportingStatusRequest, reportingSameCheckpoint, validateReportingSettings, validateReportingSummary,
  type ReportingBinding, type ReportingContext, type ReportingRead, type ReportingReceipt, type ReportingScope, type ReportingSettings,
  type ReportingSettingsContext, type ReportingSettingsPayload, type ReportingSource, type ReportingSummaryPayload } from '../../shared/reporting.js';
import type { PlanningContext } from '../../shared/planning-api.js';
import type { PairingScope } from '../../shared/pairing.js';
import { SessionService, type SessionPrincipal } from '../identity/sessions.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { PlanningService, readCurrentDeviceProjectScopes } from './planning.js';
import { enqueueNotificationJob } from '../notifications/delivery.js';

interface Options { databases: Databases; sessions: SessionService; secrets: ServiceSecrets; origin: string; planning?: PlanningService;
  now?:()=>Date; requestBudget?:(scope:{workspaceId:string;accountId:string})=>Promise<void>;
  hooks?:{beforeCommit?:()=>Promise<void>;afterCommit?:()=>Promise<void>} }
export interface ReportingAuth { cookieValue:string; csrfToken:string }
interface Authority { writeSchema:number; principal:SessionPrincipal; scopes:PairingScope[]; isOwner:boolean; keyGeneration:string; signingPublicKey:string }
interface Operation { kind:'settings'|'summary'; actor_profile_id:string; project_ids:string[]; data_generation:string; request_digest:string;
  receipt:ReportingReceipt; payload:ReportingSettingsPayload|ReportingSummaryPayload }
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
const invalid=()=>new AppError('REPORTING_INVALID','Invalid reporting request',400);
const changed=()=>new AppError('REPORTING_CHANGED','Reporting sources or access changed; calculate again',409);
const forbidden=()=>new AppError('REPORTING_FORBIDDEN','Current scope does not permit this reporting operation',403);
const oversized=()=>new AppError('REPORTING_TOO_LARGE','Reporting scope exceeds the supported complete snapshot limit',413);
function parse<T>(schema:z.ZodType<T>,value:unknown):T {const p=schema.safeParse(value);if(!p.success)throw invalid();return p.data;}

/** Caller already holds the shared workspace fence and current approved authority. */
export async function readReportingSettings(application:pg.PoolClient,control:pg.PoolClient,principal:SessionPrincipal):Promise<ReportingSettings>{
  const a=application,c=control;
    const w=principal.workspaceId,source=(await c.query("SELECT object_hash,versioned_object FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$1 AND object_kind='encrypted_workspace' AND state='committed'",[w])).rows[0];
    if(!source||await digestObject(source.versioned_object)!==source.object_hash)throw changed();
    const initial=parse(contentEnvelope,source.versioned_object),row=(await a.query('SELECT revision,head,timezone FROM app.reporting_settings WHERE workspace_id=$1',[w])).rows[0];
    const operations=(await a.query<{payload:ReportingSettingsPayload;revision:string}>("SELECT payload,revision FROM app.reporting_operations WHERE workspace_id=$1 AND kind='settings' ORDER BY revision LIMIT $2",[w,REPORTING_MAX_SETTINGS+1])).rows;
    if(operations.length>REPORTING_MAX_SETTINGS)throw oversized();
    let head=source.object_hash,revision='0',timezone:string|null=null;
    for(const operation of operations){const payload=await validateReportingSettings(operation.payload),b=payload.mutation.body.binding;
      if(b.workspaceId!==w||b.initialDigest!==source.object_hash||b.expectedRevision!==revision||b.previousHead!==head||b.previousTimezone!==timezone||operation.revision!==String(BigInt(revision)+1n))throw changed();
      revision=operation.revision;head=await digestObject(payload.mutation);timezone=payload.mutation.body.timezone;}
    if(row?!same(row,{revision,head,timezone}):revision!=='0')throw changed();
    return reportingSettings.parse({workspaceId:w,initial,revision,head,timezone,history:operations.map(o=>o.payload),securityHead:principal.securityHead,securityVersion:principal.securityVersion,dataGeneration:principal.dataGeneration});
}

/** Caches are exact-scope ciphertext only; calculation never grants content access. */
export class ReportingService {
  readonly planning:PlanningService; readonly now:()=>Date;
  constructor(readonly options:Options){this.now=options.now??(()=>new Date());this.planning=options.planning??new PlanningService(options);}
  async #with<T>(auth:ReportingAuth,workspaceId:string,projectIds:string[],action:(a:pg.PoolClient,c:pg.PoolClient,p:Authority,now:Date)=>Promise<T>):Promise<T>{
    const initial=await this.options.sessions.authenticate(auth.cookieValue,{csrfToken:auth.csrfToken,approved:true});
    if(initial.workspaceId!==workspaceId)throw forbidden();
    return dataTransaction(this.options.databases,initial,async application=>{
      // One order across reporting requests; business writers use the same project locks.
      await application.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.reporting:' || $1,0))",[workspaceId]);
      for(const id of [...projectIds].sort())await application.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.project:' || $1 || ':' || $2,0))",[workspaceId,id]);
      return transaction(this.options.databases.control,async control=>{
        const now=this.now(),principal=await this.options.sessions.resolveCurrent(control,auth.cookieValue,{csrfToken:auth.csrfToken,approved:true},now);
        if(principal.workspaceId!==workspaceId||principal.securityHead!==initial.securityHead||principal.dataGeneration!==initial.dataGeneration)throw changed();
        const scopes=await readCurrentDeviceProjectScopes(control,principal,now);
        if(projectIds.some(id=>!scopes.some(s=>s.scope==='project'&&s.scopeId===id&&s.permissions.includes('read_project'))))throw forbidden();
        const profile=(await control.query("SELECT is_owner FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 AND state='active'",[workspaceId,principal.accountId])).rows[0];
        const device=(await control.query('SELECT key_generation,signing_public_key FROM security.devices WHERE workspace_id=$1 AND device_id=$2',[workspaceId,principal.deviceId])).rows[0];
        if(!profile||!device||!principal.deviceId)throw forbidden();
        await this.options.requestBudget?.({workspaceId,accountId:principal.accountId});
        const workspace=(await control.query('SELECT write_schema FROM security.workspaces WHERE workspace_id=$1',[workspaceId])).rows[0];
        return action(application,control,{writeSchema:workspace.write_schema,principal,scopes,isOwner:profile.is_owner,keyGeneration:device.key_generation,signingPublicKey:base64urlEncode(device.signing_public_key)},now);
      });
    });
  }
  #actor(p:Authority,operationId:string,now:Date){const s=p.principal;return reportingActor.parse({version:1,...(p.writeSchema===2?{writeSchema:2}:{}),workspaceId:s.workspaceId,operationId,origin:this.options.origin,
    accountId:s.accountId,deviceId:s.deviceId,credentialGeneration:s.credentialGeneration,sessionGeneration:s.sessionGeneration,keyGeneration:p.keyGeneration,signingPublicKey:p.signingPublicKey,
    securityVersion:s.securityVersion,securityHead:s.securityHead,dataGeneration:s.dataGeneration,isOwner:p.isOwner,issuedAt:now.toISOString(),expiresAt:new Date(now.getTime()+600_000).toISOString()});}
  #settings(a:pg.PoolClient,c:pg.PoolClient,p:Authority){return readReportingSettings(a,c,p.principal);}
  settings(auth:ReportingAuth,input:unknown):Promise<ReportingSettings>{const ref=parse(z.strictObject({workspaceId:reportingReference.shape.workspaceId}),input);
    return this.#with(auth,ref.workspaceId,[],(a,c,p)=>this.#settings(a,c,p));}
  async #writable(a:pg.PoolClient,workspaceId:string){const w=(await a.query('SELECT lifecycle,licence_state,content_maintenance FROM app.workspaces WHERE workspace_id=$1',[workspaceId])).rows[0];
    if(!w||w.lifecycle!=='active'||w.licence_state!=='active'||w.content_maintenance)throw new AppError('WORKSPACE_RESTRICTED','Workspace writes are temporarily restricted',423);}
  async #prepare(a:pg.PoolClient,kind:'settings'|'summary',binding:ReportingBinding|ReportingSettingsContext['binding'],now:Date){
    await a.query('DELETE FROM app.reporting_preparations WHERE workspace_id=$1 AND actor_profile_id=$2 AND expires_at<=$3',[binding.workspaceId,binding.accountId,now]);
    const existing=(await a.query('SELECT kind,binding FROM app.reporting_preparations WHERE workspace_id=$1 AND operation_id=$2',[binding.workspaceId,binding.operationId])).rows[0];
    if(existing){const old=existing.binding as typeof binding;
      const normalized={...binding,issuedAt:old.issuedAt,expiresAt:old.expiresAt,...('asOfUtc'in old?{asOfUtc:old.asOfUtc,localDate:old.localDate}:{})};
      if(existing.kind!==kind||!same(old,normalized))throw changed();return old;}
    const count=(await a.query('SELECT count(*)::int AS n FROM app.reporting_preparations WHERE workspace_id=$1 AND actor_profile_id=$2',[binding.workspaceId,binding.accountId])).rows[0].n;
    if(count>=256)throw new AppError('RATE_LIMITED','Too many current reporting preparations',429);
    await a.query('INSERT INTO app.reporting_preparations(workspace_id,operation_id,actor_profile_id,kind,data_generation,binding,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)',
      [binding.workspaceId,binding.operationId,binding.accountId,kind,binding.dataGeneration,binding,binding.expiresAt]);return binding;
  }
  async settingsContext(auth:ReportingAuth,input:unknown):Promise<ReportingSettingsContext>{const ref=parse(reportingReference,input);
    return this.#with(auth,ref.workspaceId,[],async(a,c,p,now)=>{if(!p.isOwner)throw forbidden();await this.#writable(a,ref.workspaceId);
      const settings=await this.#settings(a,c,p),binding=reportingSettingsBinding.parse({...this.#actor(p,ref.operationId,now),expectedRevision:settings.revision,previousHead:settings.head,initialDigest:await digestObject(settings.initial),previousTimezone:settings.timezone});
      return {settings,binding:reportingSettingsBinding.parse(await this.#prepare(a,'settings',binding,now))};});}
  async #receipt(a:pg.PoolClient,p:Authority,operationId:string,kind:'settings'|'summary',requestHash:string):Promise<ReportingReceipt|null>{
    const row=(await a.query<Operation>('SELECT * FROM app.reporting_operations WHERE workspace_id=$1 AND operation_id=$2 AND actor_profile_id=$3',[p.principal.workspaceId,operationId,p.principal.accountId])).rows[0];
    if(!row)return null;if(row.kind!==kind||row.data_generation!==p.principal.dataGeneration||row.request_digest!==requestHash)throw changed();
    if(row.project_ids.some(id=>!p.scopes.some(s=>s.scope==='project'&&s.scopeId===id)))throw forbidden();
    return parse(reportingReceipt,row.receipt);
  }
  async #checkPrepared(a:pg.PoolClient,p:Authority,kind:'settings'|'summary',b:ReportingBinding|ReportingSettingsContext['binding'],now:Date){
    const row=(await a.query('SELECT kind,binding FROM app.reporting_preparations WHERE workspace_id=$1 AND operation_id=$2 AND actor_profile_id=$3',[b.workspaceId,b.operationId,p.principal.accountId])).rows[0];
    if(!row||row.kind!==kind||!same(row.binding,b)||Date.parse(b.expiresAt)<=now.getTime()||!same(reportingActor.strip().parse(b),{...this.#actor(p,b.operationId,now),issuedAt:b.issuedAt,expiresAt:b.expiresAt}))throw changed();
  }
  async #operation(a:pg.PoolClient,p:Authority,kind:'settings'|'summary',payload:ReportingSettingsPayload|ReportingSummaryPayload,revision:string,now:Date):Promise<ReportingReceipt>{
    const b=payload.mutation.body.binding,hash=await digestObject(payload),head=await digestObject(payload.mutation),projectIds=kind==='summary'?reportingProjectIds((payload as ReportingSummaryPayload).mutation.body.binding.scope):[];
    const receipt=reportingReceipt.parse({version:1,workspaceId:b.workspaceId,operationId:b.operationId,accountId:b.accountId,dataGeneration:b.dataGeneration,requestHash:hash,kind,head,revision,committedAt:now.toISOString()});
    await a.query('INSERT INTO app.reporting_operations(workspace_id,operation_id,actor_profile_id,kind,project_ids,data_generation,revision,request_digest,payload,receipt,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
      [b.workspaceId,b.operationId,p.principal.accountId,kind,projectIds,b.dataGeneration,revision,hash,payload,receipt,now]);return receipt;
  }
  async saveSettings(auth:ReportingAuth,input:unknown){let payload:ReportingSettingsPayload;try{payload=await validateReportingSettings(input);}catch{throw invalid();}
    const b=payload.mutation.body.binding,view=await this.#with(auth,b.workspaceId,[],async(a,c,p,now)=>{
      const prior=await this.#receipt(a,p,b.operationId,'settings',await digestObject(payload));if(prior)return {state:'completed' as const,receipt:prior};
      await assertAuthoritativeContentWrite(c,b.workspaceId,[b.writeSchema??1]);
      if(!p.isOwner)throw forbidden();await this.options.sessions.resolveCurrent(c,auth.cookieValue,{csrfToken:auth.csrfToken,approved:true,recent:true},now);await this.#writable(a,b.workspaceId);await this.#checkPrepared(a,p,'settings',b,now);
      const settings=await this.#settings(a,c,p);if(settings.revision!==b.expectedRevision||settings.head!==b.previousHead||settings.timezone!==b.previousTimezone||await digestObject(settings.initial)!==b.initialDigest)throw changed();
      if(settings.history.length>=REPORTING_MAX_SETTINGS)throw oversized();const revision=String(BigInt(settings.revision)+1n),receipt=await this.#operation(a,p,'settings',payload,revision,now);
      await a.query('INSERT INTO app.reporting_settings(workspace_id,revision,head,timezone,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(workspace_id) DO UPDATE SET revision=EXCLUDED.revision,head=EXCLUDED.head,timezone=EXCLUDED.timezone,updated_at=EXCLUDED.updated_at',[b.workspaceId,revision,receipt.head,payload.mutation.body.timezone,now]);
      await a.query('UPDATE app.workspaces SET revision=revision+1,updated_at=$2 WHERE workspace_id=$1',[b.workspaceId,now]);
      await a.query("INSERT INTO app.audit_events(workspace_id,id,actor_profile_id,operation_id,action,record_type,record_id,key_epoch,encrypted_envelope,created_at) VALUES($1,$2,$3,$4,'workspace.timezone','workspace',$1,1,$5,$6)",[b.workspaceId,randomUUID(),b.accountId,b.operationId,{signedSettings:payload},now]);
      const outboxId=randomUUID();await a.query("INSERT INTO app.outbox(workspace_id,id,data_generation,operation_id,event_type,deduplication_key,encrypted_envelope,created_at,updated_at) VALUES($1,$2,$3,$4,'reporting.settings.changed',$5,$6,$7,$7)",[b.workspaceId,outboxId,b.dataGeneration,b.operationId,`reporting:${b.operationId}`,{operationId:b.operationId},now]);
      await enqueueNotificationJob(a,{workspaceId:b.workspaceId,outboxId,dataGeneration:b.dataGeneration,operationId:b.operationId,events:[]},now);
      await this.options.hooks?.beforeCommit?.();return {state:'completed' as const,receipt};});await this.options.hooks?.afterCommit?.();return view;
  }
  #visible(p:Authority){return p.scopes.filter(s=>s.scope==='project').map(s=>({projectId:s.scopeId,keyEpoch:s.keyEpoch,permissions:[...s.permissions].sort()})).sort((a,b)=>a.projectId.localeCompare(b.projectId));}
  async #fingerprint(p:Authority){return digestObject({securityHead:p.principal.securityHead,securityVersion:p.principal.securityVersion,dataGeneration:p.principal.dataGeneration,visibleScopes:this.#visible(p)});}
  async #checkSources(a:pg.PoolClient,p:Authority,sources:ReportingSource[]){
    for(const source of sources){const scope=p.scopes.find(s=>s.scope==='project'&&s.scopeId===source.projectId);
      if(!scope||scope.keyEpoch!==source.keyEpoch||!same([...scope.permissions].sort(),source.permissions))throw changed();
      const head=(await a.query('SELECT planning_version,planning_head FROM app.project_planning_heads WHERE workspace_id=$1 AND project_id=$2',[p.principal.workspaceId,source.projectId])).rows[0];
      if(head?head.planning_version!==source.planningVersion||head.planning_head!==source.planningHead:source.planningVersion!=='0')throw changed();
      const records:ReportingSource['records']=[];
      for(const [kind,table]of [['project','projects'],['phase','project_phases'],['milestone','milestones'],['task','tasks'],['blocker','blockers']]as const){
        const rows=(await a.query(`SELECT id,revision,${kind==='task'||kind==='blocker'?'content_revision':'revision'} AS content_revision,encrypted_envelope FROM app.${table} WHERE workspace_id=$1 AND ${kind==='project'?'id':'project_id'}=$2 ORDER BY id`,[p.principal.workspaceId,source.projectId])).rows;
        for(const row of rows)records.push({kind,id:row.id,revision:row.revision,contentRevision:row.content_revision,digest:await digestObject(row.encrypted_envelope)});
      }records.sort((a,b)=>a.kind.localeCompare(b.kind)||a.id.localeCompare(b.id));if(!same(records,source.records))throw changed();
    }
  }
  #checkScope(scope:ReportingScope,contexts:PlanningContext[]){const graph=contexts[0]!.graph;
    if(scope.kind==='phase'&&!graph.phases.some(p=>p.id===scope.id)||scope.kind==='milestone'&&!graph.milestones.some(m=>m.id===scope.id)||scope.kind==='filtered'&&scope.taskIds.some(id=>!graph.tasks.some(t=>t.id===id)))throw invalid();}
  async #current(auth:ReportingAuth,request:z.infer<typeof reportingContextRequest>,action:(a:pg.PoolClient,c:ReportingContext,p:Authority,now:Date)=>Promise<ReportingRead|ReportingContext>):Promise<ReportingRead|ReportingContext>{
    const ids=reportingProjectIds(request.scope),contexts:PlanningContext[]=[];
    // Each full context is independently authenticated. The final vector is then
    // checked while all selected projects are locked, so mixed revisions fail.
    for(const projectId of ids)contexts.push(await this.planning.context(auth.cookieValue,auth.csrfToken,{workspaceId:request.workspaceId,projectId,operationId:request.operationId}));
    this.#checkScope(request.scope,contexts);
    return this.#with(auth,request.workspaceId,ids,async(a,c,p,now)=>{
      if(contexts.some(v=>v.binding.securityHead!==p.principal.securityHead||v.binding.dataGeneration!==p.principal.dataGeneration))throw changed();
      if(request.scope.kind==='team'&&!(await a.query('SELECT 1 FROM app.teams WHERE workspace_id=$1 AND id=$2',[request.workspaceId,request.scope.teamId])).rowCount)throw invalid();
      const sources=await Promise.all(contexts.map(reportingManifest));await this.#checkSources(a,p,sources);const settings=await this.#settings(a,c,p);
      if(settings.timezone!==null&&settings.timezone!==request.timezone)throw changed();
      const candidate=reportingBinding.parse({...this.#actor(p,request.operationId,now),scope:request.scope,scopeHash:await digestObject(request.scope),visibleScopes:this.#visible(p),authorizationFingerprint:await this.#fingerprint(p),sources,
        settingsRevision:settings.revision,settingsHead:settings.head,initialDigest:await digestObject(settings.initial),timezone:request.timezone,
        asOfUtc:now.toISOString(),localDate:reportingLocalDate(now.toISOString(),request.timezone),complete:true,calculationVersion:'progress-health-v1'});
      const binding=reportingBinding.parse(await this.#prepare(a,'summary',candidate,now)),context:ReportingContext={binding,settings,projects:contexts};
      if(Buffer.byteLength(canonicalJson(planningWireValue(context)))>REPORTING_MAX_BYTES)throw oversized();return action(a,context,p,now);
    });
  }
  async context(auth:ReportingAuth,input:unknown):Promise<ReportingContext>{const ref=parse(reportingContextRequest,input);return this.#current(auth,ref,async(_a,context)=>context) as Promise<ReportingContext>;}
  async publish(auth:ReportingAuth,input:unknown){let payload:ReportingSummaryPayload;try{payload=await validateReportingSummary(input);}catch{throw invalid();}
    const b=payload.mutation.body.binding,ids=reportingProjectIds(b.scope),view=await this.#with(auth,b.workspaceId,ids,async(a,c,p,now)=>{
      const prior=await this.#receipt(a,p,b.operationId,'summary',await digestObject(payload));if(prior)return {state:'completed' as const,receipt:prior};
      await assertAuthoritativeContentWrite(c,b.workspaceId,payload.components.map(part=>part.envelope.header.schema));
      await this.#writable(a,b.workspaceId);await this.#checkPrepared(a,p,'summary',b,now);
      if(ids.some(id=>!p.scopes.find(s=>s.scope==='project'&&s.scopeId===id)?.permissions.includes('plan_projects')))throw forbidden();
      if(b.authorizationFingerprint!==await this.#fingerprint(p))throw changed();await this.#checkSources(a,p,b.sources);const settings=await this.#settings(a,c,p);
      if(settings.revision!==b.settingsRevision||settings.head!==b.settingsHead||await digestObject(settings.initial)!==b.initialDigest||settings.timezone!==null&&settings.timezone!==b.timezone||reportingLocalDate(now.toISOString(),b.timezone)!==b.localDate)throw changed();
      const latest=(await a.query('SELECT as_of_utc FROM app.reporting_summaries WHERE workspace_id=$1 AND scope_hash=$2 AND authorization_fingerprint=$3',[b.workspaceId,b.scopeHash,b.authorizationFingerprint])).rows[0];
      if(latest&&latest.as_of_utc.getTime()>Date.parse(b.asOfUtc))throw changed();
      const receipt=await this.#operation(a,p,'summary',payload,'0',now);
      await a.query('INSERT INTO app.reporting_summaries(workspace_id,scope_hash,authorization_fingerprint,operation_id,project_ids,as_of_utc) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(workspace_id,scope_hash,authorization_fingerprint) DO UPDATE SET operation_id=EXCLUDED.operation_id,project_ids=EXCLUDED.project_ids,as_of_utc=EXCLUDED.as_of_utc',[b.workspaceId,b.scopeHash,b.authorizationFingerprint,b.operationId,ids,b.asOfUtc]);
      await this.options.hooks?.beforeCommit?.();return {state:'completed' as const,receipt};});await this.options.hooks?.afterCommit?.();return view;
  }
  async read(auth:ReportingAuth,input:unknown):Promise<ReportingRead>{const ref=parse(reportingContextRequest,input);return this.#current(auth,ref,async(a,context)=>{
    const b=context.binding,row=(await a.query<{payload:ReportingSummaryPayload}>(`SELECT o.payload FROM app.reporting_summaries s JOIN app.reporting_operations o USING(workspace_id,operation_id)
      WHERE s.workspace_id=$1 AND s.scope_hash=$2 AND s.authorization_fingerprint=$3`,[b.workspaceId,b.scopeHash,b.authorizationFingerprint])).rows[0];
    if(!row)return {context,state:'missing',payload:null};const payload=await validateReportingSummary(row.payload);
    if(payload.mutation.body.binding.scopeHash!==b.scopeHash||payload.mutation.body.binding.authorizationFingerprint!==b.authorizationFingerprint)throw changed();
    return {context,state:reportingSameCheckpoint(payload.mutation.body.binding,b)?'current':'stale',payload};}) as Promise<ReportingRead>;}
  async status(auth:ReportingAuth,input:unknown){const ref=parse(reportingStatusRequest,input);return this.#with(auth,ref.workspaceId,[],async(a,_c,p)=>{
    if(ref.dataGeneration!==p.principal.dataGeneration)throw changed();const receipt=await this.#receipt(a,p,ref.operationId,ref.kind,ref.requestHash);return {state:receipt?'completed' as const:'absent' as const,receipt};});}
}

import { planningWireValue,PLANNING_HISTORY_MAX_BYTES } from '../../shared/planning-api.js';
import {fileManifest} from '../../shared/files.js';
import type pg from 'pg';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { dataTransaction, tenantTransaction } from '../../persistence.js';
import { contentEnvelope } from '../../shared/contracts.js';
import { base64urlDecode, base64urlEncode, canonicalJson, digestObject, verifyObject } from '../../shared/crypto.js';
import { EXPORT_MAX_PAGES, EXPORT_MAX_REFERENCES, EXPORT_PAGE_BYTES, EXPORT_TOTAL_BYTES, exportBinding, exportFinalize, exportManifestKey,
  exportPageRequest, exportReceipt, exportRecord, exportSources, exportSourceManifest, exportStartRequest, sortedExportManifest,
  type ExportBinding, type ExportFinalize, type ExportManifestRecord, type ExportPage, type ExportReceipt, type ExportSource, type ExportStart } from '../../shared/export.js';
import { SessionService, type SessionPrincipal } from '../identity/sessions.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { PlanningService, readCurrentDeviceProjectScopes } from '../work/planning.js';
import { TeamService } from '../work/teams.js';
import { CollaborationService } from '../collaboration/service.js';
import { readReportingSettings } from '../work/reporting.js';
import { finalizeDeletionIfDue } from '../lifecycle/deadline.js';

export interface ExportAuth { cookieValue:string; csrfToken:string }
interface Options { databases:Databases; sessions:SessionService; secrets:ServiceSecrets; origin:string; planning?:PlanningService;
  teams?:TeamService; collaboration?:CollaborationService; now?:()=>Date; hooks?:{beforePageRead?:()=>Promise<void>;beforeFinalize?:()=>Promise<void>} }
interface CapturedRow {kind:ExportManifestRecord['kind'];id:string;project_id:string|null;revision:string;value:unknown;state:string|null}
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
const changed=()=>new AppError('EXPORT_CHANGED','Export sources or authority changed; start a new export',409);
const forbidden=()=>new AppError('EXPORT_FORBIDDEN','A recently authenticated Owner with complete current access is required',403);
const tooLarge=()=>new AppError('EXPORT_TOO_LARGE','The complete export exceeds this release limit',413);
function parse<T>(schema:z.ZodType<T>,value:unknown):T {const r=schema.safeParse(value);if(!r.success)throw new AppError('EXPORT_INVALID','Invalid export request',400);return r.data;}
const tables={workspace:'workspaces',profile:'profiles',team:'teams',project:'projects',phase:'project_phases',milestone:'milestones',task:'tasks',blocker:'blockers',comment:'comments',update:'updates'} as const;

/** Each bounded page starts and ends at the same manifest. No database snapshot
 * survives a request, and no plaintext or key material enters this ledger. */
export class ExportService {
  readonly planning:PlanningService; readonly teams:TeamService; readonly collaboration:CollaborationService; readonly now:()=>Date;
  constructor(readonly options:Options) {
    const common={databases:options.databases,sessions:options.sessions,secrets:options.secrets,origin:options.origin,...(options.now?{now:options.now}:{})};
    this.planning=options.planning??new PlanningService(common);this.teams=options.teams??new TeamService(common);
    this.collaboration=options.collaboration??new CollaborationService({...common,planning:this.planning});this.now=options.now??(()=>new Date());}
  async #capture(a:pg.PoolClient,c:pg.PoolClient,p:SessionPrincipal) {
    const workspace=(await c.query('SELECT lifecycle,delete_after,restore_quarantine,custody_epoch FROM security.workspaces WHERE workspace_id=$1',[p.workspaceId])).rows[0];
    if(!workspace||!['active','pending_deletion'].includes(workspace.lifecycle)||workspace.restore_quarantine||workspace.lifecycle==='pending_deletion'&&workspace.delete_after&&new Date(workspace.delete_after).getTime()<=this.now().getTime())throw forbidden();
    const scopes=await readCurrentDeviceProjectScopes(c,p,this.now());
    if(!scopes.some(s=>s.scope==='workspace'&&s.scopeId===p.workspaceId&&s.mode==='custody'&&s.keyEpoch===workspace.custody_epoch&&s.permissions.includes('read_project')))throw forbidden();
    const projectIds=(await c.query("SELECT scope_id FROM security.scope_heads WHERE workspace_id=$1 AND scope_kind='project' ORDER BY scope_id",[p.workspaceId])).rows.map(r=>r.scope_id as string);
    if(projectIds.some(id=>!scopes.some(s=>s.scope==='project'&&s.scopeId===id&&s.permissions.includes('read_project'))))throw forbidden();
    const selects=Object.entries(tables).map(([kind,table])=>{
      const project=['project','phase','milestone','task','blocker','comment','update'].includes(kind);
      return `SELECT '${kind}'::text AS kind,${kind==='workspace'?'workspace_id':'id'} AS id,${project?(kind==='project'?'id':'project_id'):'NULL::uuid'} AS project_id,
        ${kind==='workspace'?"encrypted_envelope->'header'->>'revision'":'revision::text'} AS revision,
        ${kind==='profile'?"CASE WHEN state='removed' THEN jsonb_build_object('id',id,'state','removed') ELSE encrypted_envelope END":'encrypted_envelope'} AS value,
        ${kind==='profile'?'state::text':'NULL::text'} AS state FROM app.${table} WHERE workspace_id=$1 ${kind==='profile'?"AND state<>'pending'":''}`;
    });
    selects.push("SELECT 'planning_change',operation_id,project_id,planning_version::text,signed_mutation,NULL FROM app.planning_operations WHERE workspace_id=$1",
      "SELECT 'team_change',operation_id,NULL::uuid,record_revision::text,encrypted_envelope,NULL FROM app.record_versions WHERE workspace_id=$1 AND record_type='team'",
      "SELECT 'collaboration_change',operation_id,project_id,entry_revision::text,payload,NULL FROM app.collaboration_operations WHERE workspace_id=$1",
      "SELECT 'settings_change',operation_id,NULL::uuid,revision::text,payload,NULL FROM app.reporting_operations WHERE workspace_id=$1 AND kind='settings'",
      "SELECT 'settings',workspace_id,NULL::uuid,revision::text,to_jsonb(head),NULL FROM app.reporting_settings WHERE workspace_id=$1");
    if((await a.query("SELECT to_regclass('app.file_versions') AS present")).rows[0].present)selects.push("SELECT 'file_version',id,project_id,version::text,manifest,NULL FROM app.file_versions WHERE workspace_id=$1 AND state='ready'");
    // A transaction-local cursor retains one MVCC statement snapshot while
    // reading bounded pages. Large signed history never becomes one wire body.
    const rows:CapturedRow[]=[],manifest:ExportManifestRecord[]=[];let internalBytes=0;
    await a.query(`DECLARE ukda_export_capture NO SCROLL CURSOR FOR SELECT * FROM (${selects.join(' UNION ALL ')}) sources ORDER BY kind,id LIMIT $2`,[p.workspaceId,EXPORT_MAX_REFERENCES+1]);
    try{for(let n=0;n<=Math.ceil(EXPORT_MAX_REFERENCES/64);n++){const page=(await a.query<CapturedRow>('FETCH FORWARD 64 FROM ukda_export_capture')).rows;
      for(const row of page){if(rows.length>=EXPORT_MAX_REFERENCES)throw tooLarge();internalBytes+=Buffer.byteLength(canonicalJson(row));if(internalBytes>PLANNING_HISTORY_MAX_BYTES)throw tooLarge();
        manifest.push(row.kind==='settings'?{kind:'settings',id:row.id,projectId:null,revision:row.revision,digest:row.value as string}:await exportRecord(row.kind,row.id,row.project_id,row.revision,row.value));
        rows.push(['workspace','profile','file_version'].includes(row.kind)?row:{...row,value:null});}
      if(page.length<64)break;}}finally{await a.query('CLOSE ukda_export_capture');}
    if(!same(rows.filter(r=>r.kind==='project').map(r=>r.id).sort(),projectIds))throw changed();
    if(!manifest.some(r=>r.kind==='settings')) {
      const initial=(await c.query("SELECT object_hash FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$1 AND object_kind='encrypted_workspace' AND state='committed'",[p.workspaceId])).rows[0];
      if(!initial)throw changed();manifest.push({kind:'settings',id:p.workspaceId,projectId:null,revision:'0',digest:initial.object_hash});
    }
    sortedExportManifest(manifest);const sources=exportSources(manifest);
    if(sources.length>EXPORT_MAX_PAGES||manifest.length>EXPORT_MAX_REFERENCES||sources.filter(s=>s.kind==='workspace').length!==1||new Set(manifest.map(exportManifestKey)).size!==manifest.length)throw tooLarge();
    return {rows,manifest,sources,manifestDigest:await digestObject(manifest)};
  }
  async #with<T>(auth:ExportAuth,workspaceId:string,action:(a:pg.PoolClient,c:pg.PoolClient,p:SessionPrincipal,device:pg.QueryResultRow)=>Promise<T>):Promise<T> {
    await finalizeDeletionIfDue({databases:this.options.databases,secrets:this.options.secrets,workspaceId,now:this.now()});
    const initial=await this.options.sessions.authenticate(auth.cookieValue,{csrfToken:auth.csrfToken,approved:true,recent:true});
    if(initial.workspaceId!==workspaceId||!initial.deviceId)throw forbidden();
    return dataTransaction(this.options.databases,initial,a=>tenantTransaction(this.options.databases.control,workspaceId,undefined,async c=>{
      const p=await this.options.sessions.resolveCurrent(c,auth.cookieValue,{csrfToken:auth.csrfToken,approved:true,recent:true},this.now());
      if(p.workspaceId!==workspaceId||p.securityHead!==initial.securityHead||p.dataGeneration!==initial.dataGeneration)throw changed();
      const owner=(await c.query("SELECT 1 FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 AND state='active' AND is_owner",[workspaceId,p.accountId])).rowCount;
      const device=(await c.query("SELECT key_generation,signing_public_key FROM security.devices WHERE workspace_id=$1 AND device_id=$2 AND profile_id=$3 AND state='active' AND revoked_at IS NULL",[workspaceId,p.deviceId,p.accountId])).rows[0];
      if(!owner||!device)throw forbidden();return action(a,c,p,device);
    }));
  }
  #actor(b:ExportBinding,p:SessionPrincipal,d:pg.QueryResultRow) {if(b.origin!==this.options.origin||b.workspaceId!==p.workspaceId||b.accountId!==p.accountId||b.deviceId!==p.deviceId||
    b.credentialGeneration!==p.credentialGeneration||b.sessionGeneration!==p.sessionGeneration||b.keyGeneration!==d.key_generation||b.signingPublicKey!==base64urlEncode(d.signing_public_key)||
    b.securityHead!==p.securityHead||b.securityVersion!==p.securityVersion||b.dataGeneration!==p.dataGeneration||Date.parse(b.expiresAt)<=this.now().getTime())throw changed();}
  async start(auth:ExportAuth,input:unknown):Promise<ExportStart> {const ref=parse(exportStartRequest,input);
    return this.#with(auth,ref.workspaceId,async(a,c,p,d)=>{
      const captured=await this.#capture(a,c,p),now=this.now();
      const prior=(await a.query('SELECT binding,manifest FROM app.export_sessions WHERE workspace_id=$1 AND export_id=$2',[ref.workspaceId,ref.exportId])).rows[0];
      if(prior) {const b=parse(exportBinding,prior.binding);this.#actor(b,p,d);if(b.manifestDigest!==captured.manifestDigest||!same(prior.manifest,captured.manifest))throw changed();return {binding:b,manifest:captured.manifest,sources:captured.sources};}
      const binding=exportBinding.parse({version:1,...ref,origin:this.options.origin,accountId:p.accountId,deviceId:p.deviceId,credentialGeneration:p.credentialGeneration,
        sessionGeneration:p.sessionGeneration,keyGeneration:d.key_generation,signingPublicKey:base64urlEncode(d.signing_public_key),securityHead:p.securityHead,
        securityVersion:p.securityVersion,dataGeneration:p.dataGeneration,manifestDigest:captured.manifestDigest,sourceCount:captured.sources.length,
        issuedAt:now.toISOString(),expiresAt:new Date(now.getTime()+600000).toISOString()});
      await a.query('DELETE FROM app.export_sessions WHERE workspace_id=$1 AND expires_at<=$2',[ref.workspaceId,now]);
      if((await a.query('SELECT count(*)::int AS n FROM app.export_sessions WHERE workspace_id=$1 AND actor_profile_id=$2',[ref.workspaceId,p.accountId])).rows[0].n>=16)throw new AppError('RATE_LIMITED','Too many current export sessions',429);
      await a.query('INSERT INTO app.export_sessions(workspace_id,export_id,actor_profile_id,device_id,data_generation,binding,manifest,manifest_digest,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [ref.workspaceId,ref.exportId,p.accountId,p.deviceId,p.dataGeneration,binding,JSON.stringify(captured.manifest),binding.manifestDigest,binding.expiresAt]);
      return {binding,manifest:captured.manifest,sources:captured.sources};
    });
  }
  async #checked(auth:ExportAuth,ref:{workspaceId:string;exportId:string;manifestDigest:string}) {return this.#with(auth,ref.workspaceId,async(a,c,p,d)=>{
    const row=(await a.query('SELECT binding,manifest FROM app.export_sessions WHERE workspace_id=$1 AND export_id=$2',[ref.workspaceId,ref.exportId])).rows[0];if(!row)throw changed();
    const binding=parse(exportBinding,row.binding);this.#actor(binding,p,d);const captured=await this.#capture(a,c,p);
    if(ref.manifestDigest!==binding.manifestDigest||captured.manifestDigest!==binding.manifestDigest||!same(row.manifest,captured.manifest))throw changed();
    return {binding,...captured};
  });}
  async page(auth:ExportAuth,input:unknown):Promise<ExportPage> {const ref=parse(exportPageRequest,input),snapshot=await this.#checked(auth,ref);
    const index=ref.after===null?0:snapshot.sources.findIndex(s=>exportManifestKey(s)===ref.after)+1;
    if(ref.after!==null&&index===0||index>=snapshot.sources.length)throw changed();const source=snapshot.sources[index]!;
    await this.options.hooks?.beforePageRead?.();let data:ExportSource;
    if(source.kind==='workspace') {
      data=await this.#with(auth,ref.workspaceId,async(a,c,p)=>{const current=await this.#capture(a,c,p);if(current.manifestDigest!==snapshot.binding.manifestDigest)throw changed();
        return {kind:'workspace' as const,workspace:contentEnvelope.parse(current.rows.find(r=>r.kind==='workspace')!.value),
          profiles:current.rows.filter(r=>r.kind==='profile').map(r=>({id:r.id,revision:r.revision,state:r.state as 'active'|'suspended'|'removed',envelope:r.state==='removed'?null:contentEnvelope.parse(r.value)})),settings:await readReportingSettings(a,c,p)};});
    } else if(source.kind==='project')data={kind:'project',context:await this.planning.context(auth.cookieValue,auth.csrfToken,{workspaceId:ref.workspaceId,projectId:source.id,operationId:ref.exportId})};
    else if(source.kind==='file_versions') {
      const versions=snapshot.manifest.filter(r=>r.kind==='file_version'&&r.projectId===source.projectId),offset=versions.findIndex(r=>r.id===source.id);if(offset<0)throw changed();
      data={kind:'file_versions',manifests:versions.slice(offset,offset+100).map(r=>fileManifest.parse(snapshot.rows.find(row=>row.kind==='file_version'&&row.id===r.id)!.value))};
    } else if(source.kind==='team') {const pages=[];let afterRevision='0',anchor:undefined|{revision:string;digest:string};
      for(let n=0;n<512;n++){const page=await this.teams.history(auth,{workspaceId:ref.workspaceId,teamId:source.id,afterRevision,...(anchor?{anchor}:{}),limit:100});pages.push(page);
        if(page.complete)break;afterRevision=page.nextRevision!;anchor=page.anchor;}
      if(!pages.at(-1)?.complete)throw tooLarge();data={kind:'team',pages};
    } else data={kind:'entry',history:await this.collaboration.history(auth.cookieValue,auth.csrfToken,{workspaceId:ref.workspaceId,projectId:source.projectId!,operationId:ref.exportId,kind:source.kind,entryId:source.id})};
    const expected=new Map(snapshot.manifest.map(r=>[exportManifestKey(r),r]));
    for(const r of await exportSourceManifest(data)){const prior=expected.get(exportManifestKey(r));if(!prior||!same(prior,r))throw changed();}
    const page:ExportPage={binding:snapshot.binding,source,data,nextCursor:index+1<snapshot.sources.length?exportManifestKey(source):null};
    if(Buffer.byteLength(canonicalJson(planningWireValue(page)))>EXPORT_PAGE_BYTES)throw tooLarge();await this.#checked(auth,ref);return page;
  }
  async finalize(auth:ExportAuth,input:unknown):Promise<ExportReceipt> {const signed=parse(exportFinalize,input),b=signed.body.binding;
    if(!await verifyObject(signed,base64urlDecode(b.signingPublicKey,32),'ukda.plaintext-export.v1'))throw forbidden();
    await this.options.hooks?.beforeFinalize?.();
    return this.#with(auth,b.workspaceId,async(a,c,p,d)=>{
      this.#actor(b,p,d);const row=(await a.query('SELECT * FROM app.export_sessions WHERE workspace_id=$1 AND export_id=$2 FOR UPDATE',[b.workspaceId,b.exportId])).rows[0];
      if(!row||!same(row.binding,b)||(await this.#capture(a,c,p)).manifestDigest!==b.manifestDigest||row.document_digest&&row.document_digest!==signed.body.documentDigest)throw changed();
      const finalizedAt=row.finalized_at?new Date(row.finalized_at).toISOString():this.now().toISOString();
      await a.query('UPDATE app.export_sessions SET finalized_at=$3,document_digest=$4 WHERE workspace_id=$1 AND export_id=$2',[b.workspaceId,b.exportId,finalizedAt,signed.body.documentDigest]);
      return exportReceipt.parse({version:1,workspaceId:b.workspaceId,exportId:b.exportId,accountId:b.accountId,dataGeneration:b.dataGeneration,manifestDigest:b.manifestDigest,
        documentDigest:signed.body.documentDigest,finalizedAt,complete:true});
    });
  }
}

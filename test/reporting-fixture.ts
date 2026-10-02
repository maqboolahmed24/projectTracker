import { randomUUID } from 'node:crypto';
import type { TestContext } from 'node:test';
import { transaction } from '../src/db.js';
import { ReportingService, type ReportingAuth } from '../src/modules/work/reporting.js';
import { prepareReporting, prepareReportingSettings, calculateReporting, readReportingSettings } from '../src/client/reporting-crypto.js';
import { digestObject } from '../src/shared/crypto.js';
import type { ReportingScope } from '../src/shared/reporting.js';
import { planningFixture } from './planning-fixture.js';
import { origin } from './password-change-fixture.js';
export async function reportingFixture(t:TestContext){
  let f:Awaited<ReturnType<typeof planningFixture>>;
  t.after(async()=>{if(f)await transaction(f.admin.application,async c=>{
    await c.query("SET LOCAL session_replication_role='replica'");
    for(const table of ['reporting_summaries','reporting_operations','reporting_preparations','reporting_settings'])await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`,[f.workspaceId]);
  });});
  f=await planningFixture(t);let offset=0,hooks:NonNullable<ConstructorParameters<typeof ReportingService>[0]['hooks']>={};
  const make=()=>new ReportingService({...f,origin,planning:f.planning,now:()=>new Date(Date.now()+offset),hooks});let service=make();
  async function keys(auth=f.auth()){const delivery=await f.access.currentDelivery(auth.cookieValue,auth.csrfToken,{workspaceId:f.workspaceId}),principal=await f.sessions.authenticate(auth.cookieValue,{csrfToken:auth.csrfToken,approved:true});
    return {history:await f.history(),materials:delivery.materials,accountId:principal.accountId,deviceId:principal.deviceId!};}
  async function settings(auth=f.auth(),bundle=f.originalBundle){const value=await service.settings(auth,{workspaceId:f.workspaceId});return readReportingSettings({...await keys(auth),settings:value},bundle);}
  async function settingDraft(timezone:string,auth=f.auth(),bundle=f.originalBundle){const context=await service.settingsContext(auth,{workspaceId:f.workspaceId,operationId:randomUUID()});return prepareReportingSettings({...await keys(auth),context,timezone},bundle);}
  const defaultScope:ReportingScope={kind:'project',projectId:f.projectId};
  async function context(scope:ReportingScope=defaultScope,auth=f.auth(),bundle=f.originalBundle){const current=await settings(auth,bundle);if(!current.timezone)throw new Error('Unrecorded fixture timezone');return service.context(auth,{workspaceId:f.workspaceId,operationId:randomUUID(),scope,timezone:current.timezone});}
  async function draft(scope:ReportingScope=defaultScope,auth=f.auth(),bundle=f.originalBundle){return prepareReporting({...await keys(auth),context:await context(scope,auth,bundle)},bundle);}
  async function calculate(scope:ReportingScope=defaultScope,auth=f.auth(),bundle=f.originalBundle){return calculateReporting({...await keys(auth),context:await context(scope,auth,bundle)},bundle);}
  async function read(scope:ReportingScope=defaultScope,auth:ReportingAuth=f.auth(),bundle=f.originalBundle){const current=await settings(auth,bundle);if(!current.timezone)throw new Error('Unrecorded fixture timezone');return service.read(auth,{workspaceId:f.workspaceId,operationId:randomUUID(),scope,timezone:current.timezone});}
  async function status(payload:Awaited<ReturnType<typeof draft>>|Awaited<ReturnType<typeof settingDraft>>,kind:'settings'|'summary',auth=f.auth()){const b=payload.mutation.body.binding;return service.status(auth,{workspaceId:f.workspaceId,operationId:b.operationId,dataGeneration:b.dataGeneration,requestHash:await digestObject(payload),kind});}
  return {...f,reportingKeys:keys,reportingSettings:settings,settingDraft,reportingContext:context,summaryDraft:draft,calculate,readSummary:read,reportingStatus:status,
    get reporting(){return service;},setReportingHooks(value:typeof hooks={}){hooks=value;service=make();},advanceReporting(ms:number){offset+=ms;}};
}

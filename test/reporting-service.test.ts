import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { AppError } from '../src/errors.js';
import { buildApp } from '../src/app.js';
import { createDatabases } from '../src/db.js';
import { loadConfig } from '../src/config.js';
import { registerReportingRoutes } from '../src/modules/work/reporting-routes.js';
import { ReportingService } from '../src/modules/work/reporting.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import { RoleService } from '../src/modules/identity/roles.js';
import { prepareRoleChange } from '../src/client/roles-controller.js';
import { prepareReporting, calculateReporting, readReporting } from '../src/client/reporting-crypto.js';
import { base64urlDecode, digestObject, signObject } from '../src/shared/crypto.js';
import type { ReportingScope } from '../src/shared/reporting.js';
import type { Capability } from '../src/shared/permissions.js';
import { reportingFixture } from './reporting-fixture.js';
import { origin } from './password-change-fixture.js';
const code=(expected:string)=>(e:unknown)=>e instanceof AppError&&e.code===expected;
type Fixture=Awaited<ReturnType<typeof reportingFixture>>;
async function scoped(f:Fixture,permissions:Capability[]){const member=await f.joined(),roles=new RoleService({...f,origin}),auth=f.auth(),request={workspaceId:f.workspaceId,operationId:randomUUID(),roleId:randomUUID(),action:'create' as const};
  const context=await roles.context(auth.cookieValue,auth.csrfToken,request),payload=await prepareRoleChange({request,context,history:await f.history(),displayName:'Private reporting role',permissions},f.originalBundle);
  await roles.stage(auth.cookieValue,auth.csrfToken,payload);await roles.finalize(auth.cookieValue,auth.csrfToken,{workspaceId:f.workspaceId,operationId:request.operationId,requestHash:await digestObject(payload)});
  await f.finalize(await f.draft('set_access',member.binding.accountId,{roleId:request.roleId,projectIds:[f.projectId]}));return {...member,...await f.login(member.prepared,member.registered.exportKey)};}

test('CP10 settings: signed Owner timezone history is atomic, revisioned, preserves dates and activation bytes, and retries once',async t=>{
  const f=await reportingFixture(t),initial=await f.reporting.settings(f.auth(),{workspaceId:f.workspaceId});
  assert.equal(initial.revision,'0');assert.equal(initial.timezone,null);assert.equal((await f.reportingSettings()).timezone,'Europe/London');
  await f.execute({action:'edit_project',patch:{}},{content:{name:'Private dated project',startDate:'2026-09-20',dueDate:'2026-09-30'}});
  const before=(await f.read()).records,one=await f.settingDraft('America/New_York'),competing=await f.settingDraft('Asia/Tokyo');
  const workspaceBefore=(await f.admin.application.query('SELECT revision FROM app.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].revision;
  f.setReportingHooks({beforeCommit:async()=>{throw new Error('timezone interrupted');}});await assert.rejects(f.reporting.saveSettings(f.auth(),one),/timezone interrupted/);f.setReportingHooks();
  assert.equal((await f.reporting.settings(f.auth(),{workspaceId:f.workspaceId})).revision,'0');
  assert.equal((await f.admin.application.query("SELECT 1 FROM app.audit_events WHERE workspace_id=$1 AND operation_id=$2",[f.workspaceId,one.mutation.body.binding.operationId])).rowCount,0);
  f.setReportingHooks({afterCommit:async()=>{throw new Error('timezone reply lost');}});await assert.rejects(f.reporting.saveSettings(f.auth(),one),/timezone reply lost/);f.setReportingHooks();
  const receipt=await f.reportingStatus(one,'settings');assert.equal(receipt.state,'completed');assert.deepEqual(await f.reporting.saveSettings(f.auth(),one),receipt);
  await assert.rejects(f.reporting.saveSettings(f.auth(),competing),code('REPORTING_CHANGED'));
  const current=await f.reporting.settings(f.auth(),{workspaceId:f.workspaceId});assert.equal(current.revision,'1');assert.equal(current.timezone,'America/New_York');assert.deepEqual(current.initial,initial.initial);assert.deepEqual(current.history,[one]);
  assert.equal((await f.reportingSettings()).timezone,'America/New_York');assert.deepEqual((await f.read()).records,before);
  assert.equal((await f.admin.application.query('SELECT revision FROM app.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].revision,String(BigInt(workspaceBefore)+1n));
  const member=await f.joined();await assert.rejects(f.reporting.settingsContext(member.auth,{workspaceId:f.workspaceId,operationId:randomUUID()}),code('REPORTING_FORBIDDEN'));
  assert.equal((await f.reporting.settings(member.auth,{workspaceId:f.workspaceId})).revision,'1');
});

test('CP10 summary: encrypted exact checkpoints publish atomically, recover lost replies, reject forged server time and stale replacement',async t=>{
  const f=await reportingFixture(t),taskId=randomUUID();await f.execute({action:'create_task',task:{id:taskId,phaseId:null,milestoneId:null,assigneeIds:[f.accountId],leadProfileId:f.accountId}},{content:{title:'Private counted task',dueDate:'2026-12-31'}});
  const first=await f.summaryDraft(),b=first.mutation.body.binding;
  assert.equal(first.components.length,1);assert.equal(first.components[0]!.envelope.header.scopeId,f.projectId);assert.equal(JSON.stringify(first).includes('Private counted task'),false);
  const forged=structuredClone(first);forged.mutation.body.binding.asOfUtc=new Date(Date.parse(b.asOfUtc)-1000).toISOString();forged.mutation.body.binding.issuedAt=forged.mutation.body.binding.asOfUtc;forged.mutation.body.binding.expiresAt=new Date(Date.parse(b.expiresAt)-1000).toISOString();
  forged.mutation=await signObject(forged.mutation.body,base64urlDecode(f.originalBundle.signingPrivateKey));await assert.rejects(f.reporting.publish(f.auth(),forged),code('REPORTING_CHANGED'));
  f.setReportingHooks({beforeCommit:async()=>{throw new Error('cache interrupted');}});await assert.rejects(f.reporting.publish(f.auth(),first),/cache interrupted/);f.setReportingHooks();
  assert.equal((await f.reportingStatus(first,'summary')).state,'absent');assert.equal((await f.readSummary()).state,'missing');
  f.setReportingHooks({afterCommit:async()=>{throw new Error('cache reply lost');}});await assert.rejects(f.reporting.publish(f.auth(),first),/cache reply lost/);f.setReportingHooks();
  const status=await f.reportingStatus(first,'summary');assert.deepEqual(await f.reporting.publish(f.auth(),first),status);
  const current=await f.readSummary();assert.equal(current.state,'current');assert.equal((await readReporting({...await f.reportingKeys(),response:current},f.originalBundle)).status,'current');
  const older=await f.summaryDraft();f.advanceReporting(5);const newer=await f.summaryDraft();await f.reporting.publish(f.auth(),newer);await assert.rejects(f.reporting.publish(f.auth(),older),code('REPORTING_CHANGED'));
  const stale=await f.summaryDraft();await f.execute({action:'edit_task',taskId},{content:{title:'Private revised task',dueDate:'2027-01-01'}});
  await assert.rejects(f.reporting.publish(f.auth(),stale),code('REPORTING_CHANGED'));assert.equal((await f.readSummary()).state,'stale');
  const latest=await f.summaryDraft();await f.reporting.publish(f.auth(),latest);await f.reporting.saveSettings(f.auth(),await f.settingDraft('Asia/Tokyo'));
  assert.equal((await f.readSummary()).state,'stale');
});

test('CP10 scope: complete multi-project vectors isolate filters, reject incomplete or stale sources and never widen a reader',async t=>{
  const f=await reportingFixture(t),other=await f.createProject('Private second project'),ids=[f.projectId,other].sort(),scope:ReportingScope={kind:'visible_projects',projectIds:ids};
  const whole=await f.summaryDraft(scope);await f.reporting.publish(f.auth(),whole);
  assert.deepEqual(whole.components.map(p=>p.projectId),ids);assert.equal((await f.readSummary()).state,'missing');
  const narrowed=await f.summaryDraft({kind:'visible_projects',projectIds:[f.projectId]});await f.reporting.publish(f.auth(),narrowed);assert.equal((await f.readSummary(scope)).payload!.mutation.body.binding.scopeHash,whole.mutation.body.binding.scopeHash);
  const incomplete=structuredClone(whole);incomplete.components.pop();await assert.rejects(f.reporting.publish(f.auth(),incomplete),code('REPORTING_INVALID'));
  const pending=await f.summaryDraft(scope);await f.execute({action:'edit_project',patch:{}},{projectId:other,content:{name:'Changed other project'}});await assert.rejects(f.reporting.publish(f.auth(),pending),code('REPORTING_CHANGED'));
  const reader=await scoped(f,['read_project']),single:ReportingScope={kind:'project',projectId:f.projectId};
  const context=await f.reportingContext(single,reader.auth,reader.bundle),keys=await f.reportingKeys(reader.auth);
  assert.deepEqual(context.binding.visibleScopes.map(s=>s.projectId),[f.projectId]);assert.equal((await calculateReporting({...keys,context},reader.bundle)).status,'current');
  await assert.rejects(prepareReporting({...keys,context},reader.bundle));assert.equal((await f.readSummary(single,reader.auth,reader.bundle)).state,'missing');
  await assert.rejects(f.reportingContext(scope,reader.auth,reader.bundle));
  const planner=await scoped(f,['read_project','plan_projects']);const draft=await f.summaryDraft(single,planner.auth,planner.bundle);await f.reporting.publish(planner.auth,draft);
  assert.equal((await f.readSummary(single,planner.auth,planner.bundle)).state,'current');
  const pendingPlanner=await f.summaryDraft(single,planner.auth,planner.bundle);await f.finalize(await f.draft('suspend',planner.binding.accountId));
  await assert.rejects(f.reporting.publish(planner.auth,pendingPlanner));await assert.rejects(f.readSummary(single,planner.auth,planner.bundle));
});

test('CP10 reporting HTTP: strict current authentication, opaque/encrypted inputs and no-store; restricted settings remain readable',async t=>{
  const f=await reportingFixture(t),config=loadConfig({...process.env,APP_ORIGIN:origin,NODE_ENV:'test',LOG_LEVEL:'silent'}),app=buildApp(config,createDatabases(config));t.after(()=>app.close());
  registerReportingRoutes(app,{origin,reporting:f.reporting,budgets:{take:async()=>{}}});const headers={origin,cookie:`${SESSION_COOKIE_NAME}=${f.auth().cookieValue}`,'x-csrf-token':f.auth().csrfToken};
  const post=(path:string,payload:object,h=headers)=>app.inject({method:'POST',url:`/v1/reporting/${path}`,headers:h,payload});
  const settings=await post('settings',{workspaceId:f.workspaceId});assert.equal(settings.statusCode,200);assert.equal(settings.headers['cache-control'],'no-store');
  assert.equal((await post('settings',{workspaceId:f.workspaceId},{...headers,cookie:''})).statusCode,401);
  assert.equal((await post('settings',{workspaceId:f.workspaceId},{...headers,origin:'https://foreign.example'})).statusCode,403);
  assert.equal((await post('settings',{workspaceId:f.workspaceId},{...headers,'x-csrf-token':''})).statusCode,403);
  assert.equal((await post('settings',{workspaceId:f.workspaceId,name:'Plaintext'})).statusCode,400);assert.equal((await post('settings?secret=bad',{workspaceId:f.workspaceId})).statusCode,400);
  assert.equal((await post('settings',{workspaceId:randomUUID()})).statusCode,403);
  const payload=await f.summaryDraft();assert.equal((await post('publish',payload)).statusCode,200);
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='restricted' WHERE workspace_id=$1",[f.workspaceId]);await f.admin.application.query("UPDATE app.workspaces SET licence_state='restricted' WHERE workspace_id=$1",[f.workspaceId]);
  assert.equal((await post('settings',{workspaceId:f.workspaceId})).statusCode,200);assert.equal((await post('publish',payload)).statusCode,200);
  assert.equal((await post('settings/context',{workspaceId:f.workspaceId,operationId:randomUUID()})).statusCode,423);
});


test('CP10 checkpoint: a real edit between project reads invalidates the complete vector before any preparation is accepted',async t=>{
  const f=await reportingFixture(t),other=await f.createProject('Private parallel project'),projectIds=[f.projectId,other].sort();
  let interrupted=false;
  const planning=new Proxy(f.planning,{get(target,property){
    if(property==='context')return async(...args:Parameters<typeof target.context>)=>{
      const context=await target.context(...args);
      if(!interrupted){interrupted=true;await f.execute({action:'edit_project',patch:{}},{projectId:context.binding.projectId,content:{name:'Changed during multi-project read'}});}
      return context;
    };
    const value=Reflect.get(target,property,target);return typeof value==='function'?value.bind(target):value;
  }});
  const reporting=new ReportingService({...f,origin,planning}),operationId=randomUUID(),timezone=(await f.reportingSettings()).timezone!;
  await assert.rejects(reporting.context(f.auth(),{workspaceId:f.workspaceId,operationId,scope:{kind:'visible_projects',projectIds},timezone}),code('REPORTING_CHANGED'));
  assert.equal(interrupted,true);
  assert.equal((await f.admin.application.query('SELECT 1 FROM app.reporting_preparations WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,operationId])).rowCount,0);
  assert.equal((await f.reportingContext({kind:'visible_projects',projectIds})).binding.sources.length,2);
});

test('CP10 checkpoint: signed project-access revocation after a source read rejects the final context without a preparation',async t=>{
  const f=await reportingFixture(t),member=await f.joined(),roleId=f.prepared.payload.genesis.body.roles.viewer;
  await f.finalize(await f.draft('set_access',member.binding.accountId,{roleId,projectIds:[f.projectId]}));
  const reader=await f.login(member.prepared,member.registered.exportKey),before=await f.history();
  const operationId=randomUUID(),timezone=(await f.reportingSettings()).timezone!;
  let sourceReads=0,revocationHead:string|undefined;
  const planning=new Proxy(f.planning,{get(target,property){
    if(property==='context')return async(...args:Parameters<typeof target.context>)=>{
      const context=await target.context(...args);sourceReads++;
      assert.equal(context.binding.accountId,member.binding.accountId);
      assert.equal(context.binding.securityHead,before.expected.securityHead);
      // The source is already authenticated and read. Commit the actual signed
      // removal before reporting can authenticate its final complete vector.
      const removal=await f.draft('set_access',member.binding.accountId,{roleId,projectIds:[]});
      assert.equal((await f.finalize(removal)).state,'completed');
      revocationHead=await digestObject(removal.payload.transition);
      return context;
    };
    const value=Reflect.get(target,property,target);return typeof value==='function'?value.bind(target):value;
  }});
  const reporting=new ReportingService({...f,origin,planning});
  await assert.rejects(reporting.context(reader.auth,{workspaceId:f.workspaceId,operationId,scope:{kind:'project',projectId:f.projectId},timezone}),code('AUTH_REQUIRED'));
  assert.equal(sourceReads,1);assert.ok(revocationHead);assert.notEqual(revocationHead,before.expected.securityHead);
  assert.equal((await f.history()).expected.securityHead,revocationHead);
  const access=(await f.admin.application.query('SELECT state FROM app.project_access WHERE workspace_id=$1 AND project_id=$2 AND profile_id=$3',[f.workspaceId,f.projectId,member.binding.accountId])).rows;
  assert.deepEqual(access.map(row=>row.state),['revoked']);
  assert.equal((await f.admin.application.query('SELECT 1 FROM app.reporting_preparations WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,operationId])).rowCount,0);
  const current=await f.login(member.prepared,member.registered.exportKey);
  await assert.rejects(f.reportingContext({kind:'project',projectId:f.projectId},current.auth,current.bundle));
  assert.equal((await f.reportingContext()).binding.sources.length,1);
});

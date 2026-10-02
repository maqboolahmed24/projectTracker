import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { buildApp } from '../src/app.js';
import { createDatabases } from '../src/db.js';
import { loadConfig } from '../src/config.js';
import { prepareTeamChange } from '../src/client/teams-crypto.js';
import { registerExportRoutes } from '../src/modules/export/routes.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import { exportFixture } from './export-fixture.js';
import { origin } from './password-change-fixture.js';
const code=(value:string)=>(error:unknown)=>error instanceof AppError&&error.code===value;

test('CP12 export: complete manifest and native business history decrypt locally; finalize retries are exact and store no plaintext',async t=>{
  const f=await exportFixture(t),phaseId=randomUUID(),milestoneId=randomUUID(),taskId=randomUUID(),blockerId=randomUUID();
  await f.execute({action:'create_phase',phase:{id:phaseId,displayOrder:1,leadProfileId:f.accountId}},{content:{name:'Private wave',objective:'Iterative work',completionCriteria:'Reviewed results'}});
  await f.execute({action:'create_milestone',milestone:{id:milestoneId,phaseId,ownerProfileId:f.accountId}},{content:{name:'Private milestone',dueDate:'2027-01-01'}});
  await f.execute({action:'create_task',task:{id:taskId,phaseId,milestoneId,assigneeIds:[f.accountId],leadProfileId:f.accountId}},{content:{title:'Private export task',acceptanceCriteria:'Meets criteria'}});
  await f.execute({action:'create_blocker',blocker:{id:blockerId,taskId,responsibleProfileId:f.accountId}},{content:{reason:'Private blocker',nextAction:'Ask colleague'}});
  const commentId=randomUUID(),updateId=randomUUID();
  await f.saveCollaboration(await f.prepareCollaboration({action:'post_comment',entryId:commentId,taskId},{text:'Private comment export'}));
  await f.saveCollaboration(await f.prepareCollaboration({action:'post_update',entryId:updateId,phaseId},{text:'Private update export'}));
  const request={workspaceId:f.workspaceId,teamId:randomUUID(),operationId:randomUUID(),action:'create' as const},context=await f.exports.teams.context(f.auth(),request),
    payload=await prepareTeamChange({request,context,history:await f.history(),materials:(await f.refresh()).delivery.materials,accountId:f.accountId,deviceId:f.deviceId,name:'Private export team',memberIds:[f.accountId]},f.originalBundle);
  await f.exports.teams.save(f.auth(),payload);
  const prepared=await f.exportDraft(),document=JSON.parse(prepared.json),receipt=await f.exports.finalize(f.auth(),prepared.finalize);
  assert.equal(document.complete,true);assert.equal(document.exportSchema,1);assert.equal(document.waves[0].completionCriteria,'Reviewed results');
  assert.equal(document.milestones[0].name,'Private milestone');assert.equal(document.tasks[0].title,'Private export task');assert.equal(document.blockers[0].nextAction,'Ask colleague');
  assert.equal(document.teams[0].name,'Private export team');assert.equal(document.comments[0].text,'Private comment export');assert.equal(document.updates[0].text,'Private update export');
  assert.equal(document.history.planning.length,5);assert.equal(document.history.teams.length,1);assert.equal(document.assignments.length,1);
  assert.deepEqual(await f.exports.finalize(f.auth(),prepared.finalize),receipt);
  const row=(await f.admin.application.query('SELECT binding,manifest,document_digest,finalized_at FROM app.export_sessions WHERE workspace_id=$1 AND export_id=$2',[f.workspaceId,receipt.exportId])).rows[0];
  assert.equal(row.document_digest,prepared.documentDigest);assert.ok(row.finalized_at);assert.equal(JSON.stringify(row).includes('Private export task'),false);assert.equal(JSON.stringify(row).includes(f.originalBundle.signingPrivateKey),false);
});

test('CP12 export: concurrent source change invalidates a page and the final download gate',async t=>{
  const f=await exportFixture(t),start=await f.exports.start(f.auth(),{workspaceId:f.workspaceId,exportId:randomUUID(),acknowledgePlaintext:true});let changed=false;
  f.setExportHooks({beforePageRead:async()=>{if(!changed){changed=true;await f.execute({action:'edit_project',patch:{}},{content:{name:'Changed during export'}});}}});
  await assert.rejects(f.exports.page(f.auth(),{workspaceId:f.workspaceId,exportId:start.binding.exportId,manifestDigest:start.binding.manifestDigest,after:null}),code('EXPORT_CHANGED'));
  f.setExportHooks();const prepared=await f.exportDraft();
  f.setExportHooks({beforeFinalize:async()=>{await f.execute({action:'edit_project',patch:{}},{content:{name:'Changed before download'}});}});
  await assert.rejects(f.exports.finalize(f.auth(),prepared.finalize),code('EXPORT_CHANGED'));
  assert.equal((await f.admin.application.query('SELECT finalized_at FROM app.export_sessions WHERE workspace_id=$1 AND export_id=$2',[f.workspaceId,prepared.finalize.body.binding.exportId])).rows[0].finalized_at,null);
});

test('CP12 export: real Owner revocation aborts remaining pages and finalize; ordinary members cannot begin',async t=>{
  const f=await exportFixture(t),other=await f.joined('join_owner'),member=await f.joined();
  await assert.rejects(f.exports.start(member.auth,{workspaceId:f.workspaceId,exportId:randomUUID(),acknowledgePlaintext:true}),code('EXPORT_FORBIDDEN'));
  const prepared=await f.exportDraft(other.auth,other.bundle),b=prepared.finalize.body.binding;
  await f.finalize(await f.draft('remove',other.binding.accountId));
  await assert.rejects(f.exports.page(other.auth,{workspaceId:f.workspaceId,exportId:b.exportId,manifestDigest:b.manifestDigest,after:null}));
  await assert.rejects(f.exports.finalize(other.auth,prepared.finalize));
  const remaining=JSON.parse((await f.exportDraft()).json);
  assert.equal(remaining.profiles.find((p:{id:string})=>p.id===other.binding.accountId).displayName,'Former member');
});

test('CP12 export HTTP: explicit plaintext acknowledgement, origin, CSRF, recent auth and complete access are enforced; restrictions preserve data exit',async t=>{
  const f=await exportFixture(t),config=loadConfig({...process.env,APP_ORIGIN:origin,NODE_ENV:'test',LOG_LEVEL:'silent'}),app=buildApp(config,createDatabases(config));t.after(()=>app.close());
  registerExportRoutes(app,{origin,exports:f.exports,budgets:{take:async()=>{}}});const headers={origin,cookie:`${SESSION_COOKIE_NAME}=${f.auth().cookieValue}`,'x-csrf-token':f.auth().csrfToken};
  const post=(body:object,h=headers)=>app.inject({method:'POST',url:'/v1/export/start',headers:h,payload:body}),request={workspaceId:f.workspaceId,exportId:randomUUID(),acknowledgePlaintext:true};
  assert.equal((await post({...request,acknowledgePlaintext:false})).statusCode,400);assert.equal((await post(request,{...headers,cookie:''})).statusCode,401);
  assert.equal((await post(request,{...headers,origin:'https://foreign.example'})).statusCode,403);assert.equal((await post(request,{...headers,'x-csrf-token':''})).statusCode,403);
  const accepted=await post(request);assert.equal(accepted.statusCode,200);assert.equal(accepted.headers['cache-control'],'no-store');
  const principal=await f.sessions.authenticate(f.auth().cookieValue,{csrfToken:f.auth().csrfToken,approved:true}),
    authenticatedAt=(await f.admin.control.query('SELECT authenticated_at FROM security.sessions WHERE workspace_id=$1 AND session_id=$2',[f.workspaceId,principal.sessionId])).rows[0].authenticated_at;
  await f.admin.control.query("UPDATE security.sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE workspace_id=$1 AND session_id=$2",[f.workspaceId,principal.sessionId]);
  assert.equal((await post({...request,exportId:randomUUID()})).statusCode,401);
  await f.admin.control.query('UPDATE security.sessions SET authenticated_at=$3 WHERE workspace_id=$1 AND session_id=$2',[f.workspaceId,principal.sessionId,authenticatedAt]);
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='restricted',lifecycle='pending_deletion',deletion_requested_at=clock_timestamp(),delete_after=clock_timestamp()+interval '7 days' WHERE workspace_id=$1",[f.workspaceId]);
  await f.admin.application.query("UPDATE app.workspaces SET licence_state='restricted',lifecycle='pending_deletion' WHERE workspace_id=$1",[f.workspaceId]);
  assert.equal((await post({...request,exportId:randomUUID()})).statusCode,200);
  await f.admin.control.query('UPDATE security.workspaces SET restore_quarantine=true WHERE workspace_id=$1',[f.workspaceId]);
  assert.equal((await post({...request,exportId:randomUUID()})).statusCode,503);
});

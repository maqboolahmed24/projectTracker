import assert from 'node:assert/strict';
import test,{type TestContext} from 'node:test';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { AppError } from '../src/errors.js';
import { transaction } from '../src/db.js';
import { tenantTransaction } from '../src/persistence.js';
import { InboxService } from '../src/modules/notifications/inbox.js';
import { deliverNotificationJob,planningNotificationEvents } from '../src/modules/notifications/delivery.js';
import { prepareInbox } from '../src/client/inbox-crypto.js';
import { planningFixture } from './planning-fixture.js';
import { origin } from './password-change-fixture.js';
import { loadConfig } from '../src/config.js';
import { startWorker } from '../src/worker.js';
import Fastify from 'fastify';
import { registerInboxRoutes } from '../src/modules/notifications/inbox-routes.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';

type Fixture=Awaited<ReturnType<typeof planningFixture>>;
const code=(expected:string)=>(error:unknown)=>error instanceof AppError&&error.code===expected;
async function fixture(t:TestContext){let f:Fixture;
  t.after(async()=>{if(f){const jobs=await f.admin.application.query('SELECT key FROM graphile_worker.jobs WHERE key LIKE $1',[`notification:${f.workspaceId}:%`]);
    for(const row of jobs.rows)await f.admin.application.query('SELECT graphile_worker.remove_job($1)',[row.key]);
    await transaction(f.admin.application,async c=>{await c.query("SET LOCAL session_replication_role='replica'");
      await c.query('DELETE FROM app.inbox_operations WHERE workspace_id=$1',[f.workspaceId]);
      await c.query('DELETE FROM app.notification_preferences WHERE workspace_id=$1',[f.workspaceId]);});}});
  f=await planningFixture(t);
  const joined=await f.joined();await f.finalize(await f.draft('set_access',joined.binding.accountId,{roleId:f.prepared.payload.genesis.body.roles.member,projectIds:[f.projectId]}));
  const member={...joined,...await f.login(joined.prepared,joined.registered.exportKey)};
  const inbox=new InboxService({...f,origin});
  return{...f,member,inbox};
}
async function createShared(f:Awaited<ReturnType<typeof fixture>>){const taskId=randomUUID(),draft=await f.preparePlanning({action:'create_task',task:{id:taskId,phaseId:null,milestoneId:null,assigneeIds:[f.accountId,f.member.binding.accountId],leadProfileId:f.accountId}},
  {content:{title:'Private notification title',description:'Private notification description',acceptanceCriteria:'Private acceptance'}});
  await f.save(draft);const b=draft.mutation.body.binding,outbox=(await f.admin.application.query('SELECT * FROM app.outbox WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,b.operationId])).rows[0];
  return{taskId,draft,outbox,job:{workspaceId:f.workspaceId,outboxId:outbox.id,dataGeneration:b.dataGeneration}};}
async function change(f:Awaited<ReturnType<typeof fixture>>,command:Parameters<typeof prepareInbox>[0]['command']){
  const context=await f.inbox.context(f.member.auth.cookieValue,f.member.auth.csrfToken,{workspaceId:f.workspaceId,operationId:randomUUID()});
  return prepareInbox({binding:context.binding,command},f.member.bundle);
}

test('CP12: queued notifications cannot recreate inbox data after an elapsed deletion deadline before the finalizer runs',async t=>{
  const f=await fixture(t),created=await createShared(f);
  await f.admin.control.query("UPDATE security.workspaces SET lifecycle='pending_deletion',deletion_requested_at=clock_timestamp()-interval '168 hours 1 second',delete_after=clock_timestamp()-interval '1 second' WHERE workspace_id=$1",[f.workspaceId]);
  await deliverNotificationJob(f.databases,created.job);
  assert.equal((await f.admin.application.query("SELECT 1 FROM app.notifications WHERE workspace_id=$1 AND event_type='task.assignment'",[f.workspaceId])).rowCount,0);
  assert.equal((await f.admin.control.query('SELECT lifecycle FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].lifecycle,'pending_deletion','The assertion exercises deadline enforcement before durable finalization');
});

test('CP09: committed shared-task events queue only opaque metadata, delivery failure rolls back notices and duplicate delivery is harmless',async t=>{
  const f=await fixture(t),created=await createShared(f);
  await f.save(created.draft);
  const jobs=await f.admin.application.query('SELECT payload FROM graphile_worker._private_jobs WHERE key=$1',[`notification:${f.workspaceId}:${created.job.dataGeneration}:${created.outbox.id}`]);
  assert.equal(jobs.rowCount,1);assert.deepEqual(jobs.rows[0].payload,created.job);
  assert.equal(JSON.stringify(created.outbox.notification_events).includes('Private'),false);
  await assert.rejects(deliverNotificationJob(f.databases,created.job,{beforeCommit:async()=>{throw new Error('Delivery interrupted');}}),/Delivery interrupted/);
  assert.equal((await f.admin.application.query("SELECT 1 FROM app.notifications WHERE workspace_id=$1 AND event_type='task.assignment'",[f.workspaceId])).rowCount,0);
  assert.equal((await f.context()).graph.tasks[0]!.id,created.taskId,'Notification failure never repeats or undoes task creation');
  await deliverNotificationJob(f.databases,created.job);await deliverNotificationJob(f.databases,created.job);
  const rows=(await f.admin.application.query("SELECT * FROM app.notifications WHERE workspace_id=$1 AND event_type='task.assignment'",[f.workspaceId])).rows;
  assert.equal(rows.length,1);assert.equal(rows[0].recipient_profile_id,f.member.binding.accountId);assert.equal(rows[0].record_id,created.taskId);
  assert.deepEqual(rows[0].encrypted_envelope,{});
  assert.equal((await f.admin.application.query('SELECT 1 FROM app.notification_receipts WHERE workspace_id=$1 AND id=$2',[f.workspaceId,rows[0].id])).rowCount,1);
});

test('CP09: Inbox read flags and project mute use signed revision checks; ordinary notices honor mute and security notices do not',async t=>{
  const f=await fixture(t),created=await createShared(f);await deliverNotificationJob(f.databases,created.job);
  const page=await f.inbox.list(f.member.auth.cookieValue,f.member.auth.csrfToken,{workspaceId:f.workspaceId}),notice=page.records.find(row=>row.eventType==='task.assignment')!;
  assert.ok(notice);const read=await change(f,{action:'set_read',records:[{id:notice.id,expectedRevision:notice.revision}],read:true});
  const receipt=await f.inbox.save(f.member.auth.cookieValue,f.member.auth.csrfToken,read);
  assert.deepEqual(await f.inbox.save(f.member.auth.cookieValue,f.member.auth.csrfToken,read),receipt);
  assert.ok((await f.inbox.resolve(f.member.auth.cookieValue,f.member.auth.csrfToken,{workspaceId:f.workspaceId,notificationId:notice.id})).readAt);
  const stale=await change(f,{action:'set_read',records:[{id:notice.id,expectedRevision:notice.revision}],read:false});
  await assert.rejects(f.inbox.save(f.member.auth.cookieValue,f.member.auth.csrfToken,stale),code('INBOX_CHANGED'));
  const unread=await change(f,{action:'set_read',records:[{id:notice.id,expectedRevision:'2'}],read:false});await f.inbox.save(f.member.auth.cookieValue,f.member.auth.csrfToken,unread);
  assert.equal((await f.inbox.resolve(f.member.auth.cookieValue,f.member.auth.csrfToken,{workspaceId:f.workspaceId,notificationId:notice.id})).readAt,null);
  const mute=await change(f,{action:'set_project_muted',projectId:f.projectId,expectedRevision:'0',muted:true});await f.inbox.save(f.member.auth.cookieValue,f.member.auth.csrfToken,mute);
  await f.execute({action:'start_project'});const status=await f.preparePlanning({action:'start_task',taskId:created.taskId});await f.save(status);
  const outbox=(await f.admin.application.query('SELECT id FROM app.outbox WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,status.mutation.body.binding.operationId])).rows[0];
  await deliverNotificationJob(f.databases,{workspaceId:f.workspaceId,outboxId:outbox.id,dataGeneration:'1'});
  assert.equal((await f.admin.application.query("SELECT 1 FROM app.notifications WHERE workspace_id=$1 AND event_type='task.status'",[f.workspaceId])).rowCount,0);
  const access=await f.draft('set_access',f.member.binding.accountId,{roleId:f.prepared.payload.genesis.body.roles.viewer,projectIds:[f.projectId]});await f.finalize(access);
  const security=(await f.admin.application.query('SELECT recipient_profile_id,project_id,encrypted_envelope FROM app.notifications WHERE workspace_id=$1 AND event_id=$2',[f.workspaceId,access.reference.operationId])).rows;
  assert.deepEqual(security.map(row=>row.recipient_profile_id).sort(),[f.accountId,f.member.binding.accountId].sort());assert.ok(security.every(row=>row.project_id===null&&JSON.stringify(row.encrypted_envelope)==='{}'));
});

test('CP09: losing project access hides details but keeps a generic personal receipt; other people and tenants cannot read it',async t=>{
  const f=await fixture(t),created=await createShared(f);await deliverNotificationJob(f.databases,created.job);
  const notice=(await f.inbox.list(f.member.auth.cookieValue,f.member.auth.csrfToken,{workspaceId:f.workspaceId})).records.find(row=>row.eventType==='task.assignment')!;
  await f.execute({action:'start_project'});const pending=await f.preparePlanning({action:'start_task',taskId:created.taskId});await f.save(pending);
  const queued=(await f.admin.application.query('SELECT id FROM app.outbox WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,pending.mutation.body.binding.operationId])).rows[0];
  await f.finalize(await f.draft('set_access',f.member.binding.accountId,{roleId:f.prepared.payload.genesis.body.roles.member,projectIds:[]}));
  await deliverNotificationJob(f.databases,{workspaceId:f.workspaceId,outboxId:queued.id,dataGeneration:'1'});
  assert.equal((await f.admin.application.query("SELECT 1 FROM app.notifications WHERE workspace_id=$1 AND event_type='task.status'",[f.workspaceId])).rowCount,0,'Delivery rechecks current recipient access');
  const logged=await f.login(f.member.prepared,f.member.registered.exportKey);
  const unavailable=await f.inbox.resolve(logged.auth.cookieValue,logged.auth.csrfToken,{workspaceId:f.workspaceId,notificationId:notice.id});
  assert.equal(unavailable.eventType,'content.unavailable');assert.equal(unavailable.projectId,null);assert.equal(unavailable.recordId,null);assert.equal(unavailable.unavailable,true);
  await tenantTransaction(f.databases.application,f.workspaceId,f.member.binding.accountId,async c=>assert.equal((await c.query('SELECT id FROM app.notifications WHERE workspace_id=$1 AND id=$2',[f.workspaceId,notice.id])).rowCount,0));
  await assert.rejects(f.inbox.resolve(f.auth().cookieValue,f.auth().csrfToken,{workspaceId:f.workspaceId,notificationId:notice.id}),code('NOT_FOUND'));
  await assert.rejects(f.inbox.list(logged.auth.cookieValue,logged.auth.csrfToken,{workspaceId:randomUUID()}),code('NOT_FOUND'));
  assert.equal((await f.inbox.list(logged.auth.cookieValue,logged.auth.csrfToken,{workspaceId:f.workspaceId})).records.find(row=>row.id===notice.id)!.unavailable,true);
});

test('CP09 HTTP: Inbox enforces origin, CSRF, strict bodies, personal receipts and signed mutation replay',async t=>{
  const f=await fixture(t),created=await createShared(f);await deliverNotificationJob(f.databases,created.job);
  const app=Fastify({logger:false});t.after(()=>app.close());
  app.setErrorHandler((error,_request,reply)=>reply.code(error instanceof AppError?error.statusCode:503).send({error:{code:error instanceof AppError?error.code:'UNAVAILABLE'}}));
  registerInboxRoutes(app,{origin,inbox:f.inbox,budgets:{async take(){}}});
  const headers={origin,cookie:`${SESSION_COOKIE_NAME}=${f.member.auth.cookieValue}`,'x-csrf-token':f.member.auth.csrfToken};
  const post=(path:string,payload:object,custom=headers)=>app.inject({method:'POST',url:'/v1/inbox/'+path,headers:custom,payload});
  const ref={workspaceId:f.workspaceId};
  assert.equal((await post('list',ref,{...headers,origin:'https://foreign.example'})).statusCode,403);
  assert.equal((await post('list',ref,{...headers,'x-csrf-token':''})).statusCode,403);
  assert.equal((await post('list',ref,{...headers,cookie:''})).statusCode,401);
  assert.equal((await post('list',{...ref,title:'plaintext not accepted'})).statusCode,400);
  assert.equal((await post('list?details=forbidden',ref)).statusCode,400);
  const page=await post('list',ref);assert.equal(page.statusCode,200);assert.equal(page.headers['cache-control'],'no-store');assert.equal(page.body.includes('Private notification'),false);
  const notice=page.json().records.find((row:{eventType:string})=>row.eventType==='task.assignment');
  const signed=await change(f,{action:'set_read',records:[{id:notice.id,expectedRevision:notice.revision}],read:true});
  const forged=structuredClone(signed);forged.body.command={...signed.body.command,read:false} as typeof forged.body.command;
  assert.equal((await post('save',forged)).statusCode,400);
  const saved=await post('save',signed);assert.equal(saved.statusCode,200);assert.deepEqual((await post('save',signed)).json(),saved.json());
  assert.deepEqual((await post('status',{...ref,operationId:signed.body.binding.operationId})).json().receipt,saved.json());
  const ownerHeaders={...headers,cookie:`${SESSION_COOKIE_NAME}=${f.auth().cookieValue}`,'x-csrf-token':f.auth().csrfToken};
  assert.equal((await post('resolve',{...ref,notificationId:notice.id},ownerHeaders)).statusCode,404);
  assert.ok((await post('resolve',{...ref,notificationId:notice.id})).json().readAt);
});

test('CP09: task event calculation counts shared work once and targets both assignment sides plus only the named reviewer',async t=>{
  const f=await fixture(t),created=await createShared(f),before=(await f.context()).graph,after=structuredClone(before),reviewer=randomUUID();
  after.tasks[0]!.assigneeIds=[f.member.binding.accountId];after.tasks[0]!.state='review';after.tasks[0]!.reviewerProfileId=reviewer;
  const events=planningNotificationEvents(before,after,f.accountId);
  assert.deepEqual(events.map(row=>row.eventType),['task.assignment','task.status','review.requested']);
  assert.ok(events.every(row=>row.recordId===created.taskId));assert.deepEqual(events[0]!.recipientIds,[f.accountId,f.member.binding.accountId].sort());assert.deepEqual(events[2]!.recipientIds,[reviewer]);
});

test('CP09: the hosted worker delivers an actual committed task notification using its opaque durable job',async t=>{
  let worker:Awaited<ReturnType<typeof startWorker>>|undefined;t.after(async()=>{await worker?.stop();});
  const f=await fixture(t),created=await createShared(f);
  worker=await startWorker(loadConfig({...process.env,NODE_ENV:'test',LOG_LEVEL:'silent',HOST:'127.0.0.1'}),{port:0});
  const deadline=Date.now()+15000;let delivered=false;
  while(Date.now()<deadline){delivered=!!(await f.admin.application.query("SELECT 1 FROM app.notifications WHERE workspace_id=$1 AND event_type='task.assignment' AND record_id=$2",[f.workspaceId,created.taskId])).rowCount;if(delivered)break;await delay(50);}
  assert.equal(delivered,true);assert.equal((await f.admin.application.query("SELECT state FROM app.outbox WHERE workspace_id=$1 AND id=$2",[f.workspaceId,created.outbox.id])).rows[0].state,'complete');
});

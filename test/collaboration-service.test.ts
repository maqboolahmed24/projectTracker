import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { AppError } from '../src/errors.js';
import { RoleService } from '../src/modules/identity/roles.js';
import { prepareRoleChange } from '../src/client/roles-controller.js';
import { readCollaboration } from '../src/client/collaboration-crypto.js';
import { base64urlDecode, digestObject, signObject } from '../src/shared/crypto.js';
import { collaborationMutation } from '../src/shared/collaboration.js';
import type { CollaborationCommand } from '../src/shared/collaboration.js';
import { collaborationFixture } from './collaboration-fixture.js';
import { origin } from './password-change-fixture.js';

type Fixture=Awaited<ReturnType<typeof collaborationFixture>>;
const code=(expected:string)=>(error:unknown)=>error instanceof AppError&&error.code===expected;
async function hide(f:Fixture,kind:'comment'|'update',entryId:string,reason='Private moderation reason') {
  const record=(await f.readCollaboration(kind)).records.find((row)=>row.entryId===entryId)!;
  return f.prepareCollaboration({action:kind==='comment'?'hide_comment':'hide_update',entryId,expectedRevision:'1',previousHead:record.head,originalDigest:record.originalDigest},{reason});
}
async function commentOnly(f:Fixture) {
  const member=await f.joined(),roles=new RoleService({...f,origin}),request={workspaceId:f.workspaceId,operationId:randomUUID(),roleId:randomUUID(),action:'create' as const},auth=f.auth();
  const context=await roles.context(auth.cookieValue,auth.csrfToken,request),payload=await prepareRoleChange({request,context,history:await f.history(),displayName:'Private discussion role',permissions:['read_project','comment']},f.originalBundle);
  await roles.stage(auth.cookieValue,auth.csrfToken,payload);await roles.finalize(auth.cookieValue,auth.csrfToken,{workspaceId:f.workspaceId,operationId:request.operationId,requestHash:await digestObject(payload)});
  await f.finalize(await f.draft('set_access',member.binding.accountId,{roleId:request.roleId,projectIds:[f.projectId]}));
  return {...member,...await f.login(member.prepared,member.registered.exportKey)};
}

test('CP09 service: independent concurrent posts both survive without a planning CAS; lost replies and retries retain one exact operation',async(t)=>{
  const f=await collaborationFixture(t),taskId=await f.createTask(),before=await f.context(),ids=[randomUUID(),randomUUID()];
  const drafts=await Promise.all(ids.map((entryId,index)=>f.prepareCollaboration({action:'post_comment',entryId,taskId},{text:`Private simultaneous comment ${index}`})));
  const saved=await Promise.all(drafts.map((draft)=>f.saveCollaboration(draft)));assert.ok(saved.every((view)=>view.state==='completed'));
  assert.deepEqual((await f.readCollaboration('comment')).records.map((entry)=>entry.entryId).sort(),ids.sort());
  assert.equal((await f.context()).binding.beforeVersion,before.binding.beforeVersion);
  const third=await f.prepareCollaboration({action:'post_comment',entryId:randomUUID(),taskId},{text:'Private reply lost after commit'});
  f.setCollaborationHooks({afterCommit:async()=>{throw new Error('lost collaboration response');}});
  await assert.rejects(f.saveCollaboration(third),/lost collaboration response/);f.setCollaborationHooks();
  const recovered=await f.collaborationStatus(third);assert.equal(recovered.state,'completed');assert.deepEqual(await f.saveCollaboration(third),recovered);
  const changed=structuredClone(third);changed.audit.envelope.nonce=changed.content!.nonce;
  await assert.rejects(f.saveCollaboration(changed),code('COLLABORATION_CHANGED'));
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.collaboration_operations WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,third.mutation.body.binding.operationId])).rows[0].n,1);
  assert.equal((await f.listCollaboration('comment')).entries.length,3);
});

test('CP09 service: post, immutable history, audit, receipt and notification job commit or roll back together',async(t)=>{
  const f=await collaborationFixture(t),taskId=await f.createTask(),payload=await f.prepareCollaboration({action:'post_comment',entryId:randomUUID(),taskId},{text:'Private atomic comment'}),b=payload.mutation.body.binding;
  const tampered=structuredClone(payload);tampered.content!.nonce=tampered.audit.envelope.nonce;
  await assert.rejects(f.saveCollaboration(tampered),code('COLLABORATION_INVALID_SIGNATURE'));
  f.setCollaborationHooks({beforeCommit:async()=>{throw new Error('injected collaboration failure');}});
  await assert.rejects(f.saveCollaboration(payload),code('COLLABORATION_UNAVAILABLE'));f.setCollaborationHooks();
  for(const table of ['collaboration_operations','operation_receipts','audit_events','outbox']) assert.equal((await f.admin.application.query(`SELECT 1 FROM app.${table} WHERE workspace_id=$1 AND operation_id=$2`,[f.workspaceId,b.operationId])).rowCount,0);
  assert.equal((await f.admin.application.query('SELECT 1 FROM app.comments WHERE workspace_id=$1 AND id=$2',[f.workspaceId,b.entryId])).rowCount,0);
  assert.equal((await f.collaborationStatus(payload)).state,'absent');await f.saveCollaboration(payload);
  const outbox=(await f.admin.application.query('SELECT * FROM app.outbox WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,b.operationId])).rows[0];
  assert.equal(outbox.notification_version,1);assert.equal(outbox.notification_events.length,1);
  assert.deepEqual(outbox.notification_events[0].recipientIds,[f.accountId]);assert.equal(outbox.notification_events[0].recordId,b.entryId);
  const jobs=(await f.admin.application.query("SELECT payload FROM graphile_worker._private_jobs WHERE key=$1",[`notification:${f.workspaceId}:${b.dataGeneration}:${outbox.id}`])).rows;
  assert.equal(jobs.length,1);assert.deepEqual(jobs[0].payload,{workspaceId:f.workspaceId,outboxId:outbox.id,dataGeneration:b.dataGeneration});
  assert.equal(JSON.stringify({payload,outbox,jobs}).includes('Private atomic comment'),false);
});

test('CP09 service: archived moderation keeps original comments and planning outcomes in authenticated history',async(t)=>{
  const f=await collaborationFixture(t),taskId=await f.createTask(),commentId=randomUUID();
  const post=await f.prepareCollaboration({action:'post_comment',entryId:commentId,taskId},{text:'Private original remains in history'});await f.saveCollaboration(post);
  const late=await f.prepareCollaboration({action:'post_comment',entryId:randomUUID(),taskId},{text:'Must not enter a closed scope'});
  await f.execute({action:'cancel_project'},{outcome:'Private cancellation outcome'});await f.execute({action:'archive_project'});
  await assert.rejects(f.saveCollaboration(late),code('COLLABORATION_SCOPE_READ_ONLY'));
  const moderation=await hide(f,'comment',commentId);await f.saveCollaboration(moderation);
  assert.equal((await f.listCollaboration('comment')).entries.length,0);
  const auth=f.auth(),history=await f.collaboration.history(auth.cookieValue,auth.csrfToken,f.ref('comment',commentId));
  const decoded=await readCollaboration({context:history.planning,entries:[history.entry],history:await f.history(),accountId:f.accountId,deviceId:f.deviceId,includeHidden:true},f.originalBundle);
  assert.equal(decoded.records[0]!.text,'Private original remains in history');assert.equal(decoded.records[0]!.moderation!.reason,'Private moderation reason');
  const row=(await f.admin.application.query('SELECT * FROM app.comments WHERE workspace_id=$1 AND id=$2',[f.workspaceId,commentId])).rows[0];
  assert.equal(row.revision,'2');assert.equal(row.hidden,true);assert.deepEqual(row.encrypted_envelope,post.content);
  assert.equal((await f.admin.application.query("SELECT 1 FROM app.record_versions WHERE workspace_id=$1 AND record_type='comment' AND record_id=$2",[f.workspaceId,commentId])).rowCount,2);
  const outcome=(await f.readCollaboration('update')).records.find((entry)=>entry.text==='Private cancellation outcome')!;
  const outcomeBefore=(await f.read()).outcomes;await f.saveCollaboration(await hide(f,'update',outcome.entryId,'Hide the feed entry while preserving closure evidence'));
  assert.equal((await f.listCollaboration('update')).entries.length,0);assert.deepEqual((await f.read()).outcomes,outcomeBefore);
  const original=(await f.collaboration.history(auth.cookieValue,auth.csrfToken,f.ref('update',outcome.entryId))).entry;
  assert.equal(original.origin.kind,'planning');assert.ok(original.moderation);
});

test('CP09 service: comment-only custom roles post but cannot moderate; revoked authors cannot submit or retrieve details',async(t)=>{
  const f=await collaborationFixture(t),member=await commentOnly(f),taskId=await f.createTask(),entryId=randomUUID();
  const post=await f.prepareCollaboration({action:'post_comment',entryId,taskId},{text:'Private contribution from a scoped member'},member.auth,member.bundle);await f.saveCollaboration(post,member.auth);
  const row=(await f.readCollaboration('comment')).records[0]!,command:CollaborationCommand={action:'hide_comment',entryId,expectedRevision:'1',previousHead:row.head,originalDigest:row.originalDigest};
  await assert.rejects(f.prepareCollaboration(command,{reason:'Unprivileged moderation'},member.auth,member.bundle),/permission_denied/);
  const forbidden=await f.prepareCollaboration({action:'post_comment',entryId:randomUUID(),taskId},{text:'Validly signed scope for a denied command'},member.auth,member.bundle);
  forbidden.mutation.body.binding.entryId=entryId;forbidden.mutation.body.command=command;forbidden.content=null;forbidden.mutation.body.contentDigest=null;
  forbidden.mutation=collaborationMutation.parse(await signObject(forbidden.mutation.body,base64urlDecode(member.bundle.signingPrivateKey)));
  // All visible signatures/headers are valid; the current capability gate denies this hide.
  await assert.rejects(f.saveCollaboration(forbidden,member.auth),code('COLLABORATION_PERMISSION_DENIED'));assert.equal((await f.listCollaboration('comment')).entries.length,1);
  const pending=await f.prepareCollaboration({action:'post_comment',entryId:randomUUID(),taskId},{text:'Stale member draft'},member.auth,member.bundle);
  await f.finalize(await f.draft('suspend',member.binding.accountId));
  await assert.rejects(f.saveCollaboration(pending,member.auth));await assert.rejects(f.listCollaboration('comment',{},member.auth));
  assert.equal((await f.readCollaboration('comment')).records[0]!.text,'Private contribution from a scoped member');
  const other=await collaborationFixture(t);await assert.rejects(f.collaboration.context(other.auth().cookieValue,other.auth().csrfToken,f.ref('comment',entryId)));
});

test('CP09 service: anchored pages omit moderated entries before pagination and detect a changed feed',async(t)=>{
  const f=await collaborationFixture(t),taskId=await f.createTask(),ids=[randomUUID(),randomUUID(),randomUUID()].sort();
  for(const entryId of ids)await f.saveCollaboration(await f.prepareCollaboration({action:'post_comment',entryId,taskId},{text:'Private page entry'}));
  await f.saveCollaboration(await hide(f,'comment',ids[0]!));
  const first=await f.listCollaboration('comment',{taskId,limit:1});assert.equal(first.entries.length,1);assert.equal(first.nextCursor,ids[1]);assert.equal(first.complete,false);
  const second=await f.listCollaboration('comment',{taskId,limit:1,anchor:first.anchor,after:first.nextCursor!});assert.equal(second.complete,true);assert.equal(second.nextCursor,null);
  const stable=await f.listCollaboration('comment',{taskId,limit:1});
  await f.saveCollaboration(await f.prepareCollaboration({action:'post_comment',entryId:randomUUID(),taskId},{text:'Private later page entry'}));
  await assert.rejects(f.listCollaboration('comment',{taskId,limit:1,anchor:stable.anchor,after:stable.nextCursor!}),code('COLLABORATION_CHANGED'));
});

test('CP09 service: task carry preserves comment identity and history; independent wave updates retain their scope',async(t)=>{
  const f=await collaborationFixture(t),first=randomUUID(),second=randomUUID(),taskId=randomUUID();
  for(const [id,displayOrder]of [[first,0],[second,1]]as const)await f.execute({action:'create_phase',phase:{id,displayOrder,leadProfileId:null}},{content:{name:`Private wave ${displayOrder}`}});
  await f.execute({action:'create_task',task:{id:taskId,phaseId:first,milestoneId:null,assigneeIds:[f.accountId],leadProfileId:f.accountId}},{content:{title:'Private task with shared discussion'}});
  const comment=await f.prepareCollaboration({action:'post_comment',entryId:randomUUID(),taskId},{text:'Private comment before carry'});await f.saveCollaboration(comment);
  const update=await f.prepareCollaboration({action:'post_update',entryId:randomUUID(),phaseId:first},{text:'Private first-wave update'});await f.saveCollaboration(update);
  await f.execute({action:'carry_task',taskId,phaseId:second,milestoneId:null},{outcome:'Move the same work into the next wave'});
  const page=await f.listCollaboration('comment',{taskId});assert.equal(page.entries.length,1);assert.deepEqual(page.entries[0]!.origin,{kind:'post',payload:comment});
  assert.equal((await f.readCollaboration('comment')).records[0]!.text,'Private comment before carry');
  const wave=await f.listCollaboration('update',{phaseId:first});assert.equal(wave.entries.length,1);
  assert.equal(wave.entries[0]!.origin.kind,'post');assert.equal((await f.listCollaboration('update',{phaseId:second})).entries.length,1);
});

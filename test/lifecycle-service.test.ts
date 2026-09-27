import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { transaction } from '../src/db.js';
import { dataTransaction } from '../src/persistence.js';
import { EntitlementOperations } from '../src/modules/identity/entitlements.js';
import { RecoveryService } from '../src/modules/identity/recovery.js';
import { finalizeDeletionIfDue } from '../src/modules/lifecycle/deadline.js';
import { logicalPurgeWorkspace,completePhysicalPurge } from '../src/modules/lifecycle/purge.js';
import { prepareLifecycle,LifecycleClientError } from '../src/client/lifecycle-crypto.js';
import { startLogin,finishLogin } from '../src/client/opaque.js';
import { DELETION_DELAY_MS } from '../src/shared/lifecycle.js';
import { digestObject } from '../src/shared/crypto.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { lifecycleFixture } from './lifecycle-fixture.js';
import { origin,oldPassword } from './password-change-fixture.js';
const code=(expected:string)=>(e:unknown)=>e instanceof AppError&&e.code===expected;

test('CP12 lifecycle: Owner A requests, Owner B cancels, all Owners are notified, and independent restrictions survive',async t=>{
 const f=await lifecycleFixture(t),other=await f.joined('join_owner');
 await f.startUpgrade();
 const context=await f.lifecycle.context(f.auth(),{workspaceId:f.workspaceId,operationId:randomUUID(),action:'request_deletion'}),current=await f.refresh();
 await assert.rejects(prepareLifecycle({context,history:current.history,materials:current.delivery.materials,accountId:f.accountId,deviceId:f.deviceId,confirmationName:'wrong workspace'},f.originalBundle),
  e=>e instanceof LifecycleClientError&&e.code==='NAME_MISMATCH');
 const payload=await f.prepareLifecycle('request_deletion'),saved=await f.lifecycle.save(f.auth(),payload);
 assert.equal(saved.state,'completed');const deletion=saved.receipt!.deletion!;
 assert.equal(Date.parse(deletion.deleteAfter)-Date.parse(deletion.requestedAt),DELETION_DELAY_MS);
 assert.equal((await f.lifecycle.save(f.auth(),payload)).receipt!.requestHash,saved.receipt!.requestHash);
 const notices=(await f.admin.application.query("SELECT recipient_profile_id FROM app.notifications WHERE workspace_id=$1 AND event_type='security.deletion_requested'",[f.workspaceId])).rows;
 assert.deepEqual(notices.map(r=>r.recipient_profile_id).sort(),[f.accountId,other.binding.accountId].sort());
 await assert.rejects(f.preparePlanning({action:'start_project'}));
 assert.equal((await f.context()).graph.project.id,f.projectId,'Current read remains available');
 await new EntitlementOperations(f.databases,f.secrets).change({licenceId:f.licence.licenceId,operationId:randomUUID(),action:'legacy_expire'},{operatorId:randomUUID()});
 const cancelled=await f.prepareLifecycle('cancel_deletion',other.auth,other.bundle);
 assert.equal((await f.lifecycle.save(other.auth,cancelled)).state,'completed');
 const w=(await f.admin.control.query('SELECT lifecycle,licence_state,content_maintenance,active_upgrade_id,delete_after FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0];
 assert.equal(w.lifecycle,'active');assert.equal(w.licence_state,'restricted');assert.equal(w.content_maintenance,true);assert.ok(w.active_upgrade_id);assert.equal(w.delete_after,null);
 const history=await verifySecurityHistory(await f.history());assert.equal(history.lifecycle,'active');assert.equal(history.deletion,null);assert.ok(history.activeUpgrade);
});

test('CP12 lifecycle: interrupted projection/lost reply preserves one signed request, and stale or foreign cancellations fail',async t=>{
 const f=await lifecycleFixture(t),member=await f.joined();
 await assert.rejects(f.lifecycle.context(member.auth,{workspaceId:f.workspaceId,operationId:randomUUID(),action:'request_deletion'}),code('LIFECYCLE_FORBIDDEN'));
 const request=await f.prepareLifecycle('request_deletion');
 f.setLifecycleHooks({afterControlCommit:async()=>{throw new Error('projection interrupted');}});
 assert.equal((await f.lifecycle.save(f.auth(),request)).state,'finishing');f.setLifecycleHooks();
 const ref={workspaceId:f.workspaceId,operationId:request.body.binding.operationId,dataGeneration:request.body.binding.dataGeneration,requestHash:await digestObject(request)};
 assert.equal((await f.lifecycle.status(f.auth(),ref)).state,'completed');
 await assert.rejects(f.lifecycle.status(member.auth,ref),code('LIFECYCLE_CHANGED'));
 const cancel=await f.prepareLifecycle('cancel_deletion');
 f.setLifecycleHooks({afterCommit:async()=>{throw new Error('reply lost');}});
 await assert.rejects(f.lifecycle.save(f.auth(),cancel),/reply lost/);f.setLifecycleHooks();
 assert.equal((await f.lifecycle.save(f.auth(),cancel)).state,'completed');
 const again=await f.prepareLifecycle('request_deletion');await f.lifecycle.save(f.auth(),again);
 await assert.rejects(f.lifecycle.save(f.auth(),{...cancel,body:{...cancel.body,binding:{...cancel.body.binding,operationId:randomUUID()}}}));
 assert.equal((await verifySecurityHistory(await f.history())).deletion!.requestId,again.body.binding.operationId);
});

test('CP12 lifecycle: elapsed deadline overrides delayed workers, requester departure, cancellation, login, recovery and receipts',async t=>{
 const f=await lifecycleFixture(t),other=await f.joined('join_owner');
 const request=await f.prepareLifecycle('request_deletion'),receipt=(await f.lifecycle.save(f.auth(),request)).receipt!;
 await f.finalize(await f.draft('remove',f.accountId,null,other.auth,other.bundle),other.auth);
 const principal=await f.sessions.authenticate(other.auth.cookieValue,{approved:true}),before=await verifySecurityHistory(await f.history()),deadline=new Date(receipt.deletion!.deleteAfter);
 // No scheduler has run: transport authority still denies exactly at the deadline.
 t.mock.timers.enable({apis:['Date'],now:deadline});
 try{await assert.rejects(dataTransaction(f.databases,principal,async()=>true),code('NOT_FOUND'));}
 finally{t.mock.timers.reset();}
 assert.equal((await f.admin.control.query('SELECT lifecycle FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].lifecycle,'pending_deletion');
 assert.deepEqual(await finalizeDeletionIfDue({...f,workspaceId:f.workspaceId,now:deadline}),{deleted:true});
 assert.deepEqual(await finalizeDeletionIfDue({...f,workspaceId:f.workspaceId,now:new Date(deadline.getTime()+10000)}),{deleted:true});
 const after=await verifySecurityHistory(await f.history());assert.equal(after.lifecycle,'deleted');assert.equal(BigInt(after.dataGeneration),BigInt(before.dataGeneration)+1n);
 assert.equal((await f.admin.control.query("SELECT count(*)::int AS n FROM security.profiles WHERE workspace_id=$1 AND opaque_registration_record IS NOT NULL",[f.workspaceId])).rows[0].n,0);
 await assert.rejects(f.lifecycle.context(other.auth,{workspaceId:f.workspaceId,operationId:randomUUID(),action:'cancel_deletion'}));
 await assert.rejects(f.sessions.authenticate(other.auth.cookieValue,{approved:true}));
 await assert.rejects(async()=>{const started=await startLogin(oldPassword),response=await f.authentication.startLogin({workspaceId:f.workspaceId,accountId:f.accountId,startLoginRequest:started.startLoginRequest});
  const proof=await finishLogin({password:oldPassword,clientLoginState:started.clientLoginState,loginResponse:response.loginResponse,configuration:response.configuration});
  await f.authentication.finishLogin({loginId:response.loginId,finishLoginRequest:proof.finishLoginRequest});});
 await assert.rejects(new RecoveryService({...f,origin}).beginPhrase({workspaceId:f.workspaceId,accountId:other.binding.accountId,operationId:randomUUID(),resumeToken:f.secrets.token()}));
 await assert.rejects(f.lifecycle.status(other.auth,{workspaceId:f.workspaceId,operationId:request.body.binding.operationId,dataGeneration:request.body.binding.dataGeneration,requestHash:await digestObject(request)}));
 await assert.rejects(f.activation.reservations.reserve({licenceKey:f.licence.licenceKey,resumeToken:f.secrets.token(),operationId:randomUUID()}));
 const tombstones=(await f.admin.control.query('SELECT entity_kind,entity_id FROM security.deletion_tombstones WHERE workspace_id=$1',[f.workspaceId])).rows;
 assert.ok(tombstones.some(r=>r.entity_kind==='workspace'&&r.entity_id===f.workspaceId));assert.ok(tombstones.some(r=>r.entity_kind==='profile'&&r.entity_id===other.binding.accountId));
});

test('CP12 erasure: self-request is visible to Owners, fulfilled by signed removal, and last Owner still needs a successor',async t=>{
 const f=await lifecycleFixture(t),member=await f.joined();
 const memberRequest=await f.prepareLifecycle('request_erasure',member.auth,member.bundle);await f.lifecycle.save(member.auth,memberRequest);
 assert.equal((await f.lifecycle.erasures(f.auth(),f.workspaceId)).requests[0]!.accountId,member.binding.accountId);
 const ownerRequest=await f.prepareLifecycle('request_erasure');await f.lifecycle.save(f.auth(),ownerRequest);
 assert.equal((await f.lifecycle.erasures(f.auth(),f.workspaceId)).requests.find(r=>r.accountId===f.accountId)!.needsSuccessor,true);
 assert.equal((await f.lifecycle.erasures(member.auth,f.workspaceId)).requests.length,1);
 await assert.rejects(f.draft('remove',f.accountId));
 const before=(await f.admin.application.query('SELECT encrypted_envelope FROM app.projects WHERE workspace_id=$1 AND id=$2',[f.workspaceId,f.projectId])).rows[0].encrypted_envelope;
 await f.finalize(await f.draft('remove',member.binding.accountId));
 const erased=(await f.lifecycle.erasures(f.auth(),f.workspaceId)).requests.find(r=>r.accountId===member.binding.accountId)!;
 assert.equal(erased.state,'fulfilled');assert.ok(erased.fulfilledAt);
 assert.equal((await verifySecurityHistory(await f.history())).profiles[member.binding.accountId]!.state,'removed');
 assert.deepEqual((await f.admin.application.query('SELECT encrypted_envelope FROM app.projects WHERE workspace_id=$1 AND id=$2',[f.workspaceId,f.projectId])).rows[0].encrypted_envelope,before);
 await assert.rejects(f.sessions.authenticate(member.auth.cookieValue));
});

test('CP12 lifecycle: cancellation crossing the exact deadline rolls back while concurrent finalization wins once',async t=>{
 const f=await lifecycleFixture(t),other=await f.joined('join_owner');
 const request=await f.prepareLifecycle('request_deletion'),receipt=(await f.lifecycle.save(f.auth(),request)).receipt!;
 const deadline=Date.parse(receipt.deletion!.deleteAfter);
 // Authenticate again near the deadline; an original seven-day-old session is
 // not evidence that a recently authenticated Owner can cancel.
 t.mock.timers.enable({apis:['Date'],now:new Date(deadline-1000)});
 const fresh=await f.login(other.prepared,other.registered.exportKey);
 const cancel=await f.prepareLifecycle('cancel_deletion',fresh.auth,fresh.bundle);
 let entered!:()=>void,release!:()=>void;
 const paused=new Promise<void>(resolve=>{entered=resolve;}),gate=new Promise<void>(resolve=>{release=resolve;});
 f.setLifecycleHooks({beforeControlCommit:async()=>{entered();await gate;}});
 const cancellation=f.lifecycle.save(fresh.auth,cancel);
 const rejected=assert.rejects(cancellation,code('LIFECYCLE_CHANGED'));
 let finalized:Promise<{deleted:boolean}>|undefined;
 try{
  await Promise.race([paused,cancellation.then(()=>{throw new Error('Cancellation committed without reaching the pause');})]);
  t.mock.timers.setTime(deadline);
  finalized=finalizeDeletionIfDue({...f,workspaceId:f.workspaceId,now:new Date(deadline)});
  release();
  const results=await Promise.all([rejected,finalized]);
  assert.deepEqual(results[1],{deleted:true});
 }finally{release();await Promise.allSettled([rejected,...(finalized?[finalized]:[])]);t.mock.timers.reset();}
 const workspace=(await f.admin.control.query('SELECT lifecycle FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0];
 assert.equal(workspace.lifecycle,'deleted');
 assert.equal((await f.admin.control.query('SELECT 1 FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,cancel.body.binding.operationId])).rowCount,0);
 assert.equal((await f.admin.control.query('SELECT 1 FROM security.security_transitions WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,cancel.body.binding.operationId])).rowCount,0);
 const history=await verifySecurityHistory(await f.history());
 assert.equal(history.lifecycle,'deleted');assert.equal(history.deletion!.requestId,request.body.binding.operationId);
 const transitions=(await f.admin.control.query("SELECT 1 FROM security.security_transitions WHERE workspace_id=$1 AND signed_transition->'body'->>'purpose'='ukda.workspace-deleted.v1'",[f.workspaceId])).rowCount;
 assert.equal(transitions,1);
 assert.deepEqual(await finalizeDeletionIfDue({...f,workspaceId:f.workspaceId,now:new Date(deadline+1)}),{deleted:true});
 assert.equal((await f.admin.control.query("SELECT 1 FROM security.security_transitions WHERE workspace_id=$1 AND signed_transition->'body'->>'purpose'='ukda.workspace-deleted.v1'",[f.workspaceId])).rowCount,transitions);
});

test('CP12 purge: runtime cannot bypass immutable history, logical purge is retryable and physical completion remains separate',async t=>{
 const f=await lifecycleFixture(t);
 await f.joined(); // Retain real ceremony subject/approver, device, grant and session FKs.
 await f.startUpgrade();
 const request=await f.prepareLifecycle('request_deletion'),receipt=(await f.lifecycle.save(f.auth(),request)).receipt!;
 await finalizeDeletionIfDue({...f,workspaceId:f.workspaceId,now:new Date(receipt.deletion!.deleteAfter)});
 await assert.rejects(f.databases.application.query('SELECT app.purge_workspace_payloads($1)',[f.workspaceId]),{code:'42501'});
 await assert.rejects(f.databases.control.query('SELECT security.complete_physical_purge($1)',[f.workspaceId]),{code:'42501'});
 await assert.rejects(completePhysicalPurge(f.admin.control,f.workspaceId),/Logical purge required/);
 const result=await logicalPurgeWorkspace({databases:f.databases,application:f.admin.application,control:f.admin.control,workspaceId:f.workspaceId});
 assert.equal(result.state,'logical_payloads_deleted');assert.ok(result.applicationTables.includes('app.planning_operations'));assert.ok(result.controlTables.includes('security.security_transitions'));
 assert.equal((await f.admin.application.query('SELECT 1 FROM app.workspaces WHERE workspace_id=$1',[f.workspaceId])).rowCount,0);
 assert.equal((await f.admin.control.query('SELECT 1 FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rowCount,0);
 const progress=(await f.admin.control.query('SELECT * FROM security.workspace_purges WHERE workspace_id=$1',[f.workspaceId])).rows[0];
 assert.ok(progress.logical_payloads_deleted_at);assert.equal(progress.live_payloads_purged_at,null);assert.equal(progress.backup_expires_at,null);
 assert.ok((await f.admin.control.query('SELECT 1 FROM security.retired_security_links WHERE workspace_id=$1',[f.workspaceId])).rowCount!>0);
 for(const [pool,schema,retained] of [[f.admin.application,'app',['lifecycle_tombstones']],
  [f.admin.control,'security',['deletion_tombstones','workspace_purges','retired_security_links']]] as const){
  const tables=(await pool.query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname=$1 AND c.relkind='r' AND NOT(c.relname=ANY($2::text[]))
    AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='workspace_id' AND NOT a.attisdropped)`,[schema,retained])).rows;
  for(const {relname} of tables){
   assert.match(relname,/^[a-z_]+$/);
   assert.equal((await pool.query(`SELECT 1 FROM ${schema}.${relname} WHERE workspace_id=$1`,[f.workspaceId])).rowCount,0,`${schema}.${relname} has no deleted workspace payload`);
  }
  assert.equal((await pool.query(`SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname=$1 AND NOT t.tgisinternal AND t.tgenabled='D'`,[schema])).rowCount,0,'Purge restored immutable/user triggers');
 }
 await logicalPurgeWorkspace({databases:f.databases,application:f.admin.application,control:f.admin.control,workspaceId:f.workspaceId});
 assert.equal((await f.admin.control.query('SELECT activated_workspace_id FROM security.licences WHERE licence_id=$1',[f.licence.licenceId])).rows[0].activated_workspace_id,f.workspaceId);
 await assert.rejects(transaction(f.admin.control,async c=>c.query('INSERT INTO security.workspaces(workspace_id,licence_id) VALUES($1,$2)',[f.workspaceId,f.licence.licenceId])),/permanently retired/);
 // Only root's physical drill calls completePhysicalPurge after VACUUM, archive
 // boundary and clean checkpoints; this service test must not claim that work.
});

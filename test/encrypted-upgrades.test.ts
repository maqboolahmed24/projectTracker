import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { base64urlDecode,canonicalJson,digestObject,encryptContent,signObject } from '../src/shared/crypto.js';
import { prepareTeamChange,readTeamHistory } from '../src/client/teams-crypto.js';
import { preparePlanning } from '../src/client/planning-crypto.js';
import { RoleService } from '../src/modules/identity/roles.js';
import { prepareUpgradeStart } from '../src/client/encrypted-upgrades-crypto.js';
import { encryptedUpgradesFixture } from './encrypted-upgrades-fixture.js';
import { origin } from './password-change-fixture.js';

const code=(expected:string)=>(error:unknown)=>error instanceof AppError&&error.code===expected;
type Fixture=Awaited<ReturnType<typeof encryptedUpgradesFixture>>;
async function team(f:Fixture){
  const request={workspaceId:f.workspaceId,teamId:randomUUID(),operationId:randomUUID(),action:'create' as const},context=await f.teams.context(f.auth(),request),current=await f.refresh();
  const payload=await prepareTeamChange({request,context,history:current.history,materials:current.delivery.materials,accountId:f.accountId,deviceId:f.deviceId,
    name:'Private migration team',memberIds:[f.accountId]},f.originalBundle);
  await f.teams.save(f.auth(),payload);return payload;
}
async function customRole(f:Fixture){
  const roles=new RoleService({...f,origin}),auth=f.auth(),ref={workspaceId:f.workspaceId,operationId:randomUUID(),roleId:randomUUID(),action:'create' as const},
    context=await roles.context(auth.cookieValue,auth.csrfToken,ref),label={id:randomUUID(),envelope:await encryptContent(context.labelHeader,{displayName:'Private migrated role'},f.workspaceKey,base64urlDecode(f.originalBundle.signingPrivateKey))};
  const b=context.binding,payload={label,transition:await signObject({version:1 as const,purpose:'ukda.custom-role-definition.v1' as const,binding:b,
    role:{id:b.roleId,template:'custom' as const,revision:b.nextRevision,state:'active' as const,permissions:['read_project'] as const,label:{id:label.id,revision:b.nextRevision,digest:await digestObject(label.envelope)}}},base64urlDecode(f.originalBundle.signingPrivateKey))};
  const staged=await roles.stage(auth.cookieValue,auth.csrfToken,payload);await roles.finalize(auth.cookieValue,auth.csrfToken,{workspaceId:f.workspaceId,operationId:ref.operationId,requestHash:staged.requestHash!});
  return ref.roleId;
}

async function schemaMetadata(f:Fixture){
  for(const table of ['profiles','roles','teams','projects','project_phases','milestones','tasks','blockers','comments','updates']){
    const rows=(await f.admin.application.query(`SELECT id,schema_version,encrypted_envelope FROM app.${table} WHERE workspace_id=$1 AND encrypted_envelope ? 'header'`,[f.workspaceId])).rows;
    for(const row of rows)assert.equal(row.schema_version,row.encrypted_envelope.header.schema,`${table}:${row.id} schema metadata`);
  }
  const versions=(await f.admin.application.query('SELECT id,schema_version,encrypted_envelope FROM app.record_versions WHERE workspace_id=$1 ORDER BY id',[f.workspaceId])).rows;
  for(const row of versions){const envelope=row.encrypted_envelope.envelope??row.encrypted_envelope;
    assert.equal(row.schema_version,envelope.header.schema,`retained version ${row.id} schema metadata`);}
  const audits=(await f.admin.application.query("SELECT id,schema_version,encrypted_envelope FROM app.audit_events WHERE workspace_id=$1 AND encrypted_envelope ? 'header'",[f.workspaceId])).rows;
  for(const row of audits)assert.equal(row.schema_version,row.encrypted_envelope.header.schema,`audit ${row.id} schema metadata`);
  return versions;
}

test('CP11 upgrade: every current native lineage migrates once, preserves review intent and history, then accepts only schema 2 writes',async t=>{
  const f=await encryptedUpgradesFixture(t),second=await f.joined('join_owner'),roleId=await customRole(f),pending=await f.issue(),teamPayload=await team(f);
  const phaseId=randomUUID(),milestoneId=randomUUID(),taskId=randomUUID(),blockerId=randomUUID(),commentId=randomUUID();
  await f.execute({action:'create_phase',phase:{id:phaseId,displayOrder:0,leadProfileId:null}},{content:{name:'Migration wave'}});
  await f.execute({action:'create_milestone',milestone:{id:milestoneId,phaseId,ownerProfileId:null}},{content:{name:'Explicit acceptance'}});
  await f.execute({action:'create_task',task:{id:taskId,phaseId,milestoneId,assigneeIds:[second.binding.accountId],leadProfileId:second.binding.accountId}},{content:{title:'Private approved task',acceptanceCriteria:'Exact preserved content'}});
  await f.execute({action:'start_project'});await f.execute({action:'start_phase',phaseId});
  await f.execute({action:'set_project_review',enabled:true,reviewers:[{taskId,reviewerProfileId:f.accountId}]},{outcome:'Review is explicit'});
  await f.execute({action:'create_blocker',blocker:{id:blockerId,taskId,responsibleProfileId:f.accountId}},{content:{reason:'Waiting',nextAction:'Resolve'}});
  await f.execute({action:'resolve_blocker',blockerId},{outcome:'Dependency supplied'});
  await f.saveCollaboration(await f.prepareCollaboration({action:'post_comment',entryId:commentId,taskId},{text:'Retain the original discussion'}));
  await f.save(await f.preparePlanning({action:'request_task_completion',taskId,acceptanceConfirmed:true},{},second.auth,second.bundle),second.auth);
  let row=(await f.context()).graph.tasks[0]!;
  await f.execute({action:'approve_task',taskId,submittedRevision:row.submittedRevision!,submittedPolicyRevision:row.submittedPolicyRevision!});
  await f.execute({action:'accept_milestone',milestoneId},{outcome:'Retain this closing snapshot'});
  const before=await f.read(),legacyPayload=await f.preparePlanning({action:'edit_project',patch:{}},{content:{name:'Obsolete schema write'}}),
    snapshots=canonicalJson(before.graph.snapshots),approval={...before.graph.tasks[0]!},legacyHistory=canonicalJson((await f.context()).history);
  const historicalVersions=await schemaMetadata(f);
  const start=await f.startUpgrade();assert.equal(start.view.state,'completed');
  const manifest=(await f.upgradeContext(start.migrationId)).context.manifest;
  assert.deepEqual([...new Set(manifest.map(r=>r.kind))].sort(),['blocker','comment','milestone','phase','profile','project','role','task','team','update','workspace']);
  assert.ok(manifest.some(r=>r.kind==='role'&&r.id===roleId));assert.ok(manifest.some(r=>r.kind==='profile'&&r.id===pending.request.accountId));
  await assert.rejects(f.save(legacyPayload),code('WORKSPACE_RESTRICTED'));
  await f.allUpgradeBatches(start.migrationId);
  const complete=await f.upgradeInput(start.migrationId);assert.equal(complete.context.completed.length,manifest.length);
  assert.ok(complete.records.every(r=>r.reference.schema===2));
  const migratedVersions=await schemaMetadata(f);
  for(const row of historicalVersions)assert.deepEqual(migratedVersions.find(current=>current.id===row.id),row,'A migration does not rewrite historical schema metadata');
  const signedFinish=await f.finishUpgrade(start.migrationId);assert.equal(signedFinish.view.state,'completed');
  const after=await f.read(),upgraded=after.graph.tasks[0]!;
  for(const key of ['state','contentRevision','submittedRevision','submittedPolicyRevision','approvalOperationId','reviewerProfileId'] as const)assert.equal(upgraded[key],approval[key]);
  assert.equal(canonicalJson(after.graph.snapshots),snapshots);
  assert.equal(canonicalJson((await f.context()).history.slice(0,JSON.parse(legacyHistory).length)),legacyHistory);
  assert.equal(after.records.find(r=>r.kind==='task'&&r.id===taskId)!.content.title,'Private approved task');
  const discussion=await f.readCollaboration('comment');assert.equal(discussion.records[0]!.text,'Retain the original discussion');
  const current=await f.refresh(),historyPage=await f.teams.history(f.auth(),{workspaceId:f.workspaceId,teamId:teamPayload.envelope.header.recordId});
  const history=await readTeamHistory({pages:[historyPage],history:current.history,materials:current.delivery.materials,accountId:f.accountId,deviceId:f.deviceId},f.originalBundle);
  assert.equal(history.records.length,2);assert.deepEqual(history.records[1]!.before,history.records[1]!.after);
  await assert.rejects(f.save(legacyPayload),code('UPDATE_REQUIRED'));
  const edited=await f.preparePlanning({action:'edit_project',patch:{}},{content:{name:'New schema project'}});assert.ok(edited.records.every(r=>r.envelope.header.schema===2));await f.save(edited);
  await f.execute({action:'reopen_task',taskId},{outcome:'Schema 2 outcome is explicit'});
  const updateId=randomUUID();await f.saveCollaboration(await f.prepareCollaboration({action:'post_update',entryId:updateId,phaseId:null},{text:'New schema 2 update'}));
  const teamRequest={workspaceId:f.workspaceId,teamId:teamPayload.envelope.header.recordId,operationId:randomUUID(),action:'update' as const},teamContext=await f.teams.context(f.auth(),teamRequest),fresh=await f.refresh();
  await f.teams.save(f.auth(),await prepareTeamChange({request:teamRequest,context:teamContext,history:fresh.history,materials:fresh.delivery.materials,
    accountId:f.accountId,deviceId:f.deviceId,name:'Updated schema 2 team',memberIds:[f.accountId]},f.originalBundle));
  const newProject=await f.createProject('Schema 2 project after migration');
  assert.equal((await f.admin.application.query('SELECT schema_version FROM app.projects WHERE workspace_id=$1 AND id=$2',[f.workspaceId,newProject])).rows[0].schema_version,2);
  await schemaMetadata(f);
  const originalReceipt=await f.teams.save(f.auth(),teamPayload);assert.equal(originalReceipt.revision,'1');
  assert.equal((await f.admin.application.query('SELECT write_schema,content_maintenance FROM app.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].write_schema,2);
  assert.equal((await f.admin.control.query('SELECT write_schema,active_upgrade_id FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].active_upgrade_id,null);
  assert.equal(canonicalJson(complete.records).includes('Private approved task'),false);
});

test('CP11 upgrade: interrupted projection, atomic failed batch, lost reply and another Owner resume use retained exact receipts',async t=>{
  const f=await encryptedUpgradesFixture(t),second=await f.joined('join_owner');
  f.setUpgradeHooks({afterControlCommit:async()=>{throw new Error('Injected projection interruption');}});
  const start=await f.startUpgrade();assert.equal(start.view.state,'finishing');
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].fence_closed,true);
  f.setUpgradeHooks();
  const restored=await f.upgrades.status(f.auth(),{workspaceId:f.workspaceId,migrationId:start.migrationId,operationId:start.payload.body.binding.operationId,dataGeneration:start.payload.body.binding.dataGeneration,requestHash:await digestObject(start.payload)});
  assert.equal(restored.state,'completed');
  const batch=await f.prepareUpgradeBatch(start.migrationId,'planning');
  f.setPlanningHooks({beforeCommit:async()=>{throw new Error('Injected native rollback');}});
  await assert.rejects(f.upgrades.batch(f.auth(),batch));f.setPlanningHooks();
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.encrypted_upgrade_operations WHERE workspace_id=$1',[f.workspaceId])).rows[0].n,0);
  assert.equal((await f.context()).records[0]!.envelope.header.schema,1);
  f.setUpgradeHooks({afterCommit:async()=>{throw new Error('Injected lost batch reply');}});
  await assert.rejects(f.upgrades.batch(f.auth(),batch),/Injected lost batch reply/);f.setUpgradeHooks();
  const repeated=await f.upgrades.batch(f.auth(),batch);assert.equal(repeated.state,'completed');
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.encrypted_upgrade_operations WHERE workspace_id=$1',[f.workspaceId])).rows[0].n,1);
  await f.allUpgradeBatches(start.migrationId,second.auth,second.bundle);
  const finish=await f.finishUpgrade(start.migrationId,second.auth,second.bundle);assert.equal(finish.view.state,'completed');
  assert.equal(finish.view.receipt?.actorId,second.binding.accountId);
  assert.equal((await f.upgrades.start(f.auth(),start.payload)).receipt?.requestHash,await digestObject(start.payload));
});

test('CP11 upgrade: source manifest changes reject start without authority effects and an unknown schema rejects new writes',async t=>{
  const f=await encryptedUpgradesFixture(t),context=await f.upgradeInput(),start=await prepareUpgradeStart(context,f.originalBundle);
  await f.execute({action:'edit_project',patch:{}},{content:{name:'Changed before start'}});
  await assert.rejects(f.upgrades.start(f.auth(),start),code('UPGRADE_CHANGED'));
  const authority=(await f.admin.control.query('SELECT content_maintenance,active_upgrade_id FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0];
  assert.equal(authority.content_maintenance,false);assert.equal(authority.active_upgrade_id,null);
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].fence_closed,false);
  const payload=await f.preparePlanning({action:'edit_project',patch:{}},{content:{name:'Unsupported client write'}});
  // Transport guard test: no release exists for this authoritative future schema.
  await f.admin.control.query('UPDATE security.workspaces SET write_schema=99 WHERE workspace_id=$1',[f.workspaceId]);
  await assert.rejects(f.save(payload),code('UPDATE_REQUIRED'));
});

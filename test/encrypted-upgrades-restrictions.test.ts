import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { EntitlementOperations } from '../src/modules/identity/entitlements.js';
import { RecoveryService } from '../src/modules/identity/recovery.js';
import { projectAuthoritativeWorkspace,withSecurityFence } from '../src/modules/identity/projection.js';
import { prepareUpgradeFinish } from '../src/client/encrypted-upgrades-crypto.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { digestObject } from '../src/shared/crypto.js';
import { encryptedUpgradesFixture } from './encrypted-upgrades-fixture.js';
import { origin } from './password-change-fixture.js';

const code=(expected:string)=>(error:unknown)=>error instanceof AppError&&error.code===expected;

test('CP11 restrictions: removing the migration Owner rotates keys, invalidates prepared batches, and another Owner resumes verified history',async t=>{
  const f=await encryptedUpgradesFixture(t),other=await f.joined('join_owner'),member=await f.joined();
  const started=await f.startUpgrade(),staleOwnerBatch=await f.prepareUpgradeBatch(started.migrationId,'planning'),
    staleSurvivorBatch=await f.prepareUpgradeBatch(started.migrationId,'planning',f.projectId,other.auth,other.bundle);
  const recovery=new RecoveryService({...f,origin});
  const reset=await recovery.issueReset(other.auth.cookieValue,other.auth.csrfToken,{workspaceId:f.workspaceId,accountId:member.binding.accountId,resetId:randomUUID()});
  assert.ok(reset.code,'Recovery issuance remains available while business writes pause');
  await assert.rejects(f.draft('set_access',member.binding.accountId,{roleId:f.prepared.payload.genesis.body.roles.manager,projectIds:[f.projectId]},other.auth,other.bundle),code('WORKSPACE_RESTRICTED'));
  const before=await verifySecurityHistory(await f.history()),removal=await f.draft('remove',f.accountId,null,other.auth,other.bundle);
  assert.equal((await f.finalize(removal,other.auth)).state,'completed');
  const after=await verifySecurityHistory(await f.history());assert.equal(after.profiles[f.accountId]!.active,false);
  assert.ok(BigInt(after.workspaceKeyEpoch)>BigInt(before.workspaceKeyEpoch));assert.ok(BigInt(after.custodyEpoch)>BigInt(before.custodyEpoch));
  await assert.rejects(f.upgrades.batch(f.auth(),staleOwnerBatch));
  await assert.rejects(f.upgrades.batch(other.auth,staleSurvivorBatch),code('UPGRADE_CHANGED'));
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.encrypted_upgrade_operations WHERE workspace_id=$1',[f.workspaceId])).rows[0].n,0);
  await f.allUpgradeBatches(started.migrationId,other.auth,other.bundle);
  const result=await f.finishUpgrade(started.migrationId,other.auth,other.bundle);assert.equal(result.view.state,'completed');
  const current=await verifySecurityHistory(await f.history());assert.equal(current.writeSchema,2);assert.equal(current.profiles[f.accountId]!.active,false);
  const removed=(await f.admin.application.query('SELECT state,encrypted_envelope FROM app.profiles WHERE workspace_id=$1 AND id=$2',[f.workspaceId,f.accountId])).rows[0];
  assert.equal(removed.state,'removed');assert.equal(removed.encrypted_envelope.header.schema,2);
  await assert.rejects(f.upgrades.start(f.auth(),started.payload),'Old receipt never restores a removed Owner session');
});

test('CP11 restrictions: signed licence restriction and deletion/restore fences pause finishing without clearing another restriction',async t=>{
  const f=await encryptedUpgradesFixture(t),started=await f.startUpgrade();await f.allUpgradeBatches(started.migrationId);
  const input=await f.upgradeInput(started.migrationId),finish=await prepareUpgradeFinish({...input,proofs:[{kind:'planning',context:await f.context()}]},f.originalBundle);
  const operations=new EntitlementOperations(f.databases,f.secrets),operator={operatorId:randomUUID()};
  await operations.change({licenceId:f.licence.licenceId,operationId:randomUUID(),action:'legacy_expire'},operator);
  assert.equal((await f.upgradeContext(started.migrationId)).context.state,'paused');
  await assert.rejects(f.upgrades.finish(f.auth(),finish),code('WORKSPACE_RESTRICTED'));
  assert.equal((await f.admin.control.query('SELECT content_maintenance FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].content_maintenance,true);
  await operations.change({licenceId:f.licence.licenceId,operationId:randomUUID(),action:'reinstate'},operator);
  // CP12 owns the user-facing deletion/restore producers. These labelled fixture
  // transitions exercise the already-required authoritative restriction boundary.
  await withSecurityFence(f.databases,f.workspaceId,async app=>{
    await f.admin.control.query("UPDATE security.workspaces SET lifecycle='pending_deletion',deletion_requested_at=clock_timestamp(),delete_after=clock_timestamp()+interval '7 days' WHERE workspace_id=$1",[f.workspaceId]);
    await projectAuthoritativeWorkspace(f.databases,f.workspaceId,app);
  });
  assert.equal((await f.upgradeContext(started.migrationId)).context.state,'paused');
  await assert.rejects(f.upgrades.finish(f.auth(),finish),code('WORKSPACE_RESTRICTED'));
  await withSecurityFence(f.databases,f.workspaceId,async app=>{
    await f.admin.control.query("UPDATE security.workspaces SET lifecycle='active',deletion_requested_at=NULL,delete_after=NULL,restore_quarantine=true WHERE workspace_id=$1",[f.workspaceId]);
    await projectAuthoritativeWorkspace(f.databases,f.workspaceId,app);
  });
  await assert.rejects(f.upgrades.finish(f.auth(),finish),code('WORKSPACE_RESTRICTED'));
  let w=(await f.admin.control.query('SELECT write_schema,content_maintenance,restore_quarantine FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0];
  assert.deepEqual(w,{write_schema:1,content_maintenance:true,restore_quarantine:true});
  await withSecurityFence(f.databases,f.workspaceId,async app=>{
    await f.admin.control.query('UPDATE security.workspaces SET restore_quarantine=false WHERE workspace_id=$1',[f.workspaceId]);
    await projectAuthoritativeWorkspace(f.databases,f.workspaceId,app);
  });
  assert.equal((await f.finishUpgrade(started.migrationId)).view.state,'completed');
  w=(await f.admin.control.query('SELECT write_schema,content_maintenance,restore_quarantine FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0];
  assert.deepEqual(w,{write_schema:2,content_maintenance:false,restore_quarantine:false});
});

test('CP11 restrictions: a terminal deletion tombstone aborts upgrade progress and overrides retained start receipts',async t=>{
  const f=await encryptedUpgradesFixture(t),started=await f.startUpgrade(),batch=await f.prepareUpgradeBatch(started.migrationId,'planning');
  await f.upgrades.batch(f.auth(),batch);
  // CP12 deletion producer is not implemented yet; this is its fenced tombstone seam.
  await withSecurityFence(f.databases,f.workspaceId,async app=>{
    await f.admin.control.query("UPDATE security.workspaces SET lifecycle='deleted',deleted_at=clock_timestamp() WHERE workspace_id=$1",[f.workspaceId]);
    assert.equal((await projectAuthoritativeWorkspace(f.databases,f.workspaceId,app)).state,'deleted');
  });
  for(const [pool,schema] of [[f.admin.control,'security'],[f.admin.application,'app']] as const)
    assert.equal((await pool.query(`SELECT state FROM ${schema}.encrypted_upgrades WHERE workspace_id=$1 AND migration_id=$2`,[f.workspaceId,started.migrationId])).rows[0].state,'aborted');
  await assert.rejects(f.upgrades.batch(f.auth(),batch));
  await assert.rejects(f.upgrades.status(f.auth(),{workspaceId:f.workspaceId,migrationId:started.migrationId,operationId:started.payload.body.binding.operationId,
    dataGeneration:started.payload.body.binding.dataGeneration,requestHash:await digestObject(started.payload)}));
});

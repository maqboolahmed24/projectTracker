import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { EntitlementOperations } from '../src/modules/identity/entitlements.js';
import { projectAuthoritativeWorkspace } from '../src/modules/identity/projection.js';
import { base64urlDecode,canonicalJson,digestObject,signObject } from '../src/shared/crypto.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { readRestoration,prepareRestorationVerification } from '../src/client/restoration-crypto.js';
import { prepareReportingSettings,readReportingSettings } from '../src/client/reporting-crypto.js';
import { ReportingService } from '../src/modules/work/reporting.js';
import { planningPayload } from '../src/shared/planning-api.js';
import { restorationFixture } from './restoration-fixture.js';
import { oldPassword,newPassword,origin } from './password-change-fixture.js';
const code=(name:string)=>(error:unknown)=>error instanceof AppError&&error.code===name;

test('CP12 restore: later revocations and custody survive older content; absent later projects are reported and never reconstructed',async t=>{
  const f=await restorationFixture(t),other=await f.joined('join_owner'),member=await f.joined();
  await f.execute({action:'edit_project',patch:{}},{content:{name:'Retained history'}});const checkpoint=await f.checkpoint(),laterProject=await f.createProject('Missing after recovery point');
  await f.finalize(await f.draft('remove',member.binding.accountId));await f.finalize(await f.draft('remove',f.accountId,null,other.auth,other.bundle),other.auth);
  await new EntitlementOperations(f.databases,f.secrets).change({licenceId:f.licence.licenceId,operationId:randomUUID(),action:'legacy_expire'},f.operator);
  const before=await verifySecurityHistory(await f.history()),password=(await f.admin.control.query('SELECT opaque_registration_record FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2',[f.workspaceId,other.binding.accountId])).rows[0].opaque_registration_record;
  const restoreId=await f.begin(checkpoint.manifest);await assert.rejects(f.sessions.authenticate(other.auth.cookieValue));await f.install();
  await assert.rejects(f.restoreLogin());await f.restoration.reconcile({workspaceId:f.workspaceId,restoreId});
  const auth=await f.restoreLogin(other.binding.accountId,other.prepared.deviceWrapper.header.deviceId,other.bundle,newPassword);
  const context=await f.restoration.context(auth,{workspaceId:f.workspaceId,restoreId,operationId:randomUUID()}),history=await f.history(),input={context,history,accountId:other.binding.accountId,deviceId:other.prepared.deviceWrapper.header.deviceId};
  const report=await readRestoration(input,other.bundle);assert.ok(report.verifiedSamples>1);assert.ok(report.missingRecords.some(row=>row.kind==='project'&&row.id===laterProject));
  assert.equal(report.contentAfterCheckpoint,'unverified_or_missing');await assert.rejects(f.planning.context(auth.cookieValue,auth.csrfToken,f.reference()),error=>error instanceof AppError&&['RESTORE_QUARANTINE','SECURITY_FENCED'].includes(error.code));
  const payload=await prepareRestorationVerification(input,other.bundle),result=await f.restoration.verify(auth,payload);assert.equal(result.state,'completed');
  const after=await verifySecurityHistory(await f.history());assert.equal(after.profiles[f.accountId]!.active,false);assert.equal(after.profiles[member.binding.accountId]!.active,false);
  assert.equal(after.custodyEpoch,before.custodyEpoch);assert.equal(after.dataGeneration,String(BigInt(before.dataGeneration)+1n));assert.equal(after.licenceState,'restricted');assert.equal(after.restoreQuarantine,false);
  assert.equal((await f.admin.control.query('SELECT opaque_registration_record FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2',[f.workspaceId,other.binding.accountId])).rows[0].opaque_registration_record,password);
  await projectAuthoritativeWorkspace(f.databases,f.workspaceId);assert.equal((await f.admin.application.query('SELECT 1 FROM app.projects WHERE workspace_id=$1 AND id=$2',[f.workspaceId,laterProject])).rowCount,0);
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.project_creations WHERE workspace_id=$1 AND project_id=$2',[f.workspaceId,laterProject])).rowCount,1);
  assert.equal((await f.admin.application.query('SELECT state FROM app.profiles WHERE workspace_id=$1 AND id=$2',[f.workspaceId,f.accountId])).rows[0].state,'removed');
  assert.equal((await f.planning.context(auth.cookieValue,auth.csrfToken,f.reference())).records[0]!.envelope.header.revision,'2');
});

test('CP12 restore: a later actual password change remains authoritative and old temporary authentication cannot complete',async t=>{
  const f=await restorationFixture(t),checkpoint=await f.checkpoint(),operationId=randomUUID();
  await f.controller.begin(f.workspaceId,operationId);await f.controller.prepare(operationId,newPassword,newPassword);await f.controller.complete(operationId,newPassword);
  const current=(await f.admin.control.query('SELECT opaque_registration_record,credential_generation,session_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2',[f.workspaceId,f.accountId])).rows[0];
  const restoreId=await f.begin(checkpoint.manifest);await f.install();await f.restoration.reconcile({workspaceId:f.workspaceId,restoreId});
  await assert.rejects(f.restoreLogin(f.accountId,f.deviceId,f.originalBundle,oldPassword));const auth=await f.restoreLogin(f.accountId,f.deviceId,f.originalBundle,newPassword);
  assert.deepEqual((await f.admin.control.query('SELECT opaque_registration_record,credential_generation,session_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2',[f.workspaceId,f.accountId])).rows[0],current);
  assert.equal((await f.admin.control.query("SELECT count(*)::int n FROM security.ceremonies WHERE workspace_id=$1 AND state IN('issued','waiting_approval')",[f.workspaceId])).rows[0].n,0);
  assert.equal((await f.restoration.verify(auth,await f.restoreProof(restoreId,auth))).state,'completed');
});

test('CP12 restore: changed objects, projection interruption and missing decryption material keep quarantine until exact verified retry',async t=>{
  const f=await restorationFixture(t),checkpoint=await f.checkpoint(),restoreId=await f.begin(checkpoint.manifest);await f.install();
  await f.admin.application.query("UPDATE app.projects SET encrypted_envelope=jsonb_set(encrypted_envelope,'{nonce}','\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"') WHERE workspace_id=$1",[f.workspaceId]);
  await assert.rejects(f.restoration.reconcile({workspaceId:f.workspaceId,restoreId}),code('RESTORE_INCOMPLETE'));await f.install();
  f.setRestoreHooks({beforeProjection:async()=>{throw new Error('Injected restore projection outage');}});await assert.rejects(f.restoration.reconcile({workspaceId:f.workspaceId,restoreId}),/Injected/);f.setRestoreHooks();
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].fence_closed,true);
  await f.restoration.reconcile({workspaceId:f.workspaceId,restoreId});const auth=await f.restoreLogin(),context=await f.restoration.context(auth,{workspaceId:f.workspaceId,restoreId,operationId:randomUUID()}),history=await f.history();
  await assert.rejects(prepareRestorationVerification({context,history:{...history,trustedServiceKeys:{}},accountId:f.accountId,deviceId:f.deviceId},f.originalBundle));
  await assert.rejects(prepareRestorationVerification({context:{...context,materials:[]},history,accountId:f.accountId,deviceId:f.deviceId},f.originalBundle));
  const payload=await prepareRestorationVerification({context,history,accountId:f.accountId,deviceId:f.deviceId},f.originalBundle);
  const forged=await signObject({...payload.body,verifiedSamples:payload.body.verifiedSamples.slice(1)},base64urlDecode(f.originalBundle.signingPrivateKey));await assert.rejects(f.restoration.verify(auth,forged));
  assert.equal((await f.admin.control.query('SELECT restore_quarantine FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].restore_quarantine,true);
  f.setRestoreHooks({afterControlCommit:async()=>{throw new Error('Lost restore acknowledgement');}});await assert.rejects(f.restoration.verify(auth,payload),/Lost/);f.setRestoreHooks();
  const restored=await f.restoration.status(auth,{workspaceId:f.workspaceId,restoreId,operationId:payload.body.binding.operationId,requestHash:await digestObject(payload)});assert.equal(restored.state,'completed');
  assert.equal(canonicalJson(restored.verification),canonicalJson(payload));assert.equal((await f.restoration.verify(auth,payload)).state,'completed');
  assert.equal((await f.admin.control.query("SELECT count(*)::int n FROM security.security_transitions WHERE workspace_id=$1 AND action='workspace.restore_verified'",[f.workspaceId])).rows[0].n,1);
  await f.begin(checkpoint.manifest);await assert.rejects(f.restoration.begin({workspaceId:f.workspaceId,restoreId,manifest:checkpoint.manifest},f.operator),code('RESTORE_CHANGED'));
});

test('CP12 restore: a checkpoint before a completed encrypted schema upgrade cannot downgrade or reopen current schema authority',async t=>{
  const f=await restorationFixture(t),checkpoint=await f.checkpoint(),upgrade=await f.startUpgrade();await f.allUpgradeBatches(upgrade.migrationId);await f.finishUpgrade(upgrade.migrationId);
  const restoreId=await f.begin(checkpoint.manifest);await f.install();await assert.rejects(f.restoration.reconcile({workspaceId:f.workspaceId,restoreId}));
  const row=(await f.admin.control.query('SELECT write_schema,restore_quarantine,content_maintenance FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0];
  assert.deepEqual(row,{write_schema:2,restore_quarantine:true,content_maintenance:false});assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].fence_closed,true);
  await assert.rejects(f.restoration.context(await f.restoreLogin(),{workspaceId:f.workspaceId,restoreId,operationId:randomUUID()}));
});

test('CP12 restore: real member RESET and Owner phrase rotation survive an older checkpoint; current phrase recovery works in quarantine',async t=>{
  const f=await restorationFixture(t),member=await f.joined(),checkpoint=await f.checkpoint(),memberPassword='Restored member password 509723';
  const reset=await f.recover({accountId:member.binding.accountId,password:memberPassword}),rotated=await f.recover({accountId:f.accountId,phrase:f.phrase,password:newPassword});
  assert.ok(rotated.phrase&&rotated.phrase!==f.phrase);const before=await verifySecurityHistory(await f.history()),restoreId=await f.begin(checkpoint.manifest);await f.install();await f.restoration.reconcile({workspaceId:f.workspaceId,restoreId});
  await assert.rejects(f.restoreLogin(member.binding.accountId,member.prepared.deviceWrapper.header.deviceId,member.bundle,newPassword));
  await f.restoreLogin(member.binding.accountId,reset.deviceId,reset.bundle,memberPassword);
  const oldRef={workspaceId:f.workspaceId,accountId:f.accountId,operationId:randomUUID(),resumeToken:f.secrets.token()},challenge=await rotated.recovery.beginPhrase(oldRef);
  const {proveOwnerPhrase}=await import('../src/client/recovery-controller.js');
  await assert.rejects(proveOwnerPhrase({challenge,kit:{workspaceId:f.workspaceId,accountId:f.accountId,origin:before.origin,genesisFingerprint:before.genesisFingerprint},phrase:f.phrase}));
  const current=await f.recover({accountId:f.accountId,phrase:rotated.phrase!,password:'Restored Owner password 984623'});
  const proof=await f.restoreProof(restoreId,current.auth,current.bundle);assert.equal((await f.restoration.verify(current.auth,proof)).state,'completed');
  const after=await verifySecurityHistory(await f.history());assert.equal(after.profiles[f.accountId]!.recoveryGeneration,'3');assert.equal(after.profiles[member.binding.accountId]!.credentialGeneration,'2');
  assert.equal(after.devices[f.deviceId]!.active,false);assert.equal(after.devices[rotated.deviceId]!.active,false);assert.equal(after.devices[current.deviceId]!.active,true);
});

test('CP12 restore: Owner acknowledgement clears only quarantine and retains active maintenance and restricted licence',async t=>{
  const f=await restorationFixture(t),upgrade=await f.startUpgrade(),checkpoint=await f.checkpoint();
  await new EntitlementOperations(f.databases,f.secrets).change({licenceId:f.licence.licenceId,operationId:randomUUID(),action:'legacy_expire'},f.operator);
  const restoreId=await f.begin(checkpoint.manifest);await f.install();await f.restoration.reconcile({workspaceId:f.workspaceId,restoreId});const auth=await f.restoreLogin();
  assert.equal((await f.restoration.verify(auth,await f.restoreProof(restoreId,auth))).state,'completed');
  const row=(await f.admin.control.query('SELECT restore_quarantine,content_maintenance,licence_state,active_upgrade_id FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0];
  assert.deepEqual(row,{restore_quarantine:false,content_maintenance:true,licence_state:'restricted',active_upgrade_id:upgrade.migrationId});
});

test('CP12 restore: a real partial upgrade resumes in the new generation, retaining signed progress and timezone history',async t=>{
  const f=await restorationFixture(t),reporting=new ReportingService({...f,origin,planning:f.planning}),authBefore=f.auth(),keys=await f.refresh(authBefore,f.originalBundle);
  const setting=await prepareReportingSettings({context:await reporting.settingsContext(authBefore,{workspaceId:f.workspaceId,operationId:randomUUID()}),
    history:keys.history,materials:keys.delivery.materials,accountId:f.accountId,deviceId:f.deviceId,timezone:'Asia/Tokyo'},f.originalBundle);
  await reporting.saveSettings(authBefore,setting);
  const upgrade=await f.startUpgrade(),batch=await f.prepareUpgradeBatch(upgrade.migrationId,'planning'),committed=await f.upgrades.batch(authBefore,batch),
    native=planningPayload.parse(batch.payload),operationId=native.mutation.body.binding.operationId,pending=await f.prepareUpgradeBatch(upgrade.migrationId,'identity'),checkpoint=await f.checkpoint();
  assert.ok(checkpoint.manifest.body.inventory.tables.some(row=>row.table==='reporting_operations'&&row.count===1));
  assert.ok(checkpoint.manifest.body.inventory.objects.some(row=>row.current&&row.header.schema===1));
  assert.ok(checkpoint.manifest.body.inventory.objects.some(row=>row.current&&row.header.schema===2));
  const original=(await f.admin.application.query('SELECT signed_mutation,upgrade_items,receipt FROM app.planning_operations WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,operationId])).rows[0],
    originalSources=(await f.admin.application.query('SELECT source_reference,source_envelope FROM app.encrypted_upgrade_sources WHERE workspace_id=$1 ORDER BY record_type,record_id',[f.workspaceId])).rows;
  const restoreId=await f.begin(checkpoint.manifest);await f.install();await f.restoration.reconcile({workspaceId:f.workspaceId,restoreId});const auth=await f.restoreLogin(),proof=await f.restoreProof(restoreId,auth);
  f.setRestoreHooks({afterControlCommit:async()=>{throw new Error('Restore acknowledgement reply lost');}});
  await assert.rejects(f.restoration.verify(auth,proof),/reply lost/);f.setRestoreHooks();
  assert.equal((await f.admin.application.query('SELECT data_generation FROM app.encrypted_upgrades WHERE workspace_id=$1',[f.workspaceId])).rows[0].data_generation,'1');
  assert.equal((await f.restoration.status(auth,{workspaceId:f.workspaceId,restoreId})).state,'completed');
  for(const store of ['app','security'])assert.equal((await f.admin[store==='app'?'application':'control'].query(`SELECT data_generation FROM ${store}.encrypted_upgrades WHERE workspace_id=$1`,[f.workspaceId])).rows[0].data_generation,'2');
  assert.deepEqual((await f.admin.application.query('SELECT signed_mutation,upgrade_items,receipt FROM app.planning_operations WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,operationId])).rows[0],original);
  assert.deepEqual((await f.admin.application.query('SELECT source_reference,source_envelope FROM app.encrypted_upgrade_sources WHERE workspace_id=$1 ORDER BY record_type,record_id',[f.workspaceId])).rows,originalSources);
  assert.deepEqual((await f.admin.control.query('SELECT signed_start FROM security.encrypted_upgrades WHERE workspace_id=$1',[f.workspaceId])).rows[0].signed_start,upgrade.payload);
  await assert.rejects(f.upgrades.status(auth,{workspaceId:f.workspaceId,migrationId:upgrade.migrationId,operationId,dataGeneration:'1',requestHash:committed.receipt!.requestHash}),code('UPGRADE_CHANGED'));
  await assert.rejects(f.upgrades.batch(auth,pending));
  await assert.rejects(f.preparePlanning({action:'edit_project',patch:{}},{content:{name:'Paused ordinary write'}},auth));
  const restoredSettings=await reporting.settings(auth,{workspaceId:f.workspaceId}),current=await f.refresh(auth,f.originalBundle);
  assert.deepEqual(restoredSettings.history,[setting]);
  assert.equal((await readReportingSettings({settings:restoredSettings,history:current.history,materials:current.delivery.materials,accountId:f.accountId,deviceId:f.deviceId},f.originalBundle)).timezone,'Asia/Tokyo');
  await f.allUpgradeBatches(upgrade.migrationId,auth);const finished=await f.finishUpgrade(upgrade.migrationId,auth);assert.equal(finished.view.state,'completed');
  const final=await verifySecurityHistory(await f.history());assert.equal(final.writeSchema,2);assert.equal(final.activeUpgrade,null);assert.equal(final.dataGeneration,'2');
  assert.equal((await f.admin.control.query('SELECT content_maintenance FROM security.workspaces WHERE workspace_id=$1',[f.workspaceId])).rows[0].content_maintenance,false);
  await f.save(await f.preparePlanning({action:'edit_project',patch:{}},{content:{name:'Current schema after restored upgrade'}},auth),auth);
  assert.equal((await f.context(f.projectId,auth)).records.find(record=>record.kind==='project')!.envelope.header.schema,2);
});

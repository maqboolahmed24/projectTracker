import type pg from 'pg';
import { AppError } from '../../errors.js';
import { canonicalJson,digestObject } from '../../shared/crypto.js';
import { upgradeItemRefs,upgradeRecordRef } from '../../shared/encrypted-upgrades.js';
import type { SecurityHistoryState } from '../../shared/security-history.js';
import { readCurrentUpgradeRecords,upgradeRecordKey } from '../upgrades/records.js';

const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
function incomplete():never{throw new AppError('RESTORE_INCOMPLETE','The active upgrade requires its complete original source and retained progress; workspace remains quarantined',409);}

/** A restored partial upgrade may retain both representations. Its immutable
 * source set and every already transformed current record must still agree
 * with the authenticated migration, before an Owner can authorize resumption. */
export async function assertRestoredActiveUpgrade(application:pg.PoolClient,control:pg.PoolClient,state:SecurityHistoryState):Promise<void>{
  const active=state.activeUpgrade;if(!active)incomplete();
  const authoritative=(await control.query("SELECT * FROM security.encrypted_upgrades WHERE workspace_id=$1 AND migration_id=$2 AND state='active'",[state.workspaceId,active.migrationId])).rows[0],
    local=(await application.query("SELECT * FROM app.encrypted_upgrades WHERE workspace_id=$1 AND migration_id=$2 AND state='active'",[state.workspaceId,active.migrationId])).rows[0];
  if(!authoritative||!local||local.manifest_digest!==active.manifestDigest||!same(local.signed_start,authoritative.signed_start)||
    !same(local.source_manifest,active.manifest)||await digestObject(active.manifest)!==active.manifestDigest)incomplete();
  const sources=(await application.query('SELECT source_reference,source_envelope FROM app.encrypted_upgrade_sources WHERE workspace_id=$1 AND migration_id=$2 ORDER BY record_type,record_id',[state.workspaceId,active.migrationId])).rows;
  if(!same(sources.map(row=>upgradeRecordRef.parse(row.source_reference)),active.manifest))incomplete();
  for(const source of sources)if(await digestObject(source.source_envelope)!==source.source_reference.digest)incomplete();
  const targets=(await application.query(`SELECT DISTINCT ON(i.record_type,i.record_id) i.signed_item,i.target_envelope,o.signed_operation,o.request_digest
    FROM app.encrypted_upgrade_items i JOIN app.encrypted_upgrade_operations o USING(workspace_id,operation_id)
    WHERE i.workspace_id=$1 AND i.migration_id=$2 ORDER BY i.record_type,i.record_id,i.target_revision DESC,i.created_at DESC,i.operation_id`,[state.workspaceId,active.migrationId])).rows;
  const expected=new Map(active.manifest.map(ref=>[upgradeRecordKey(ref),ref]));
  for(const row of targets){
    const item=upgradeItemRefs.parse({source:row.signed_item.source,target:row.signed_item.target}),body=row.signed_operation?.mutation?.body;
    if(!expected.has(upgradeRecordKey(item.target))||await digestObject(row.target_envelope)!==item.target.digest||
      await digestObject(row.signed_operation)!==row.request_digest||body?.upgrade?.migrationId!==active.migrationId||body.upgrade.manifestDigest!==active.manifestDigest||
      !body.upgrade.items.some((ref:unknown)=>same(ref,item)))incomplete();
    expected.set(upgradeRecordKey(item.target),item.target);
  }
  const current=await readCurrentUpgradeRecords(application,state.workspaceId,control);
  if(!same(current.map(row=>upgradeRecordKey(row.reference)),active.manifest.map(upgradeRecordKey)))incomplete();
  for(const {reference:ref} of current){
    if(same(ref,expected.get(upgradeRecordKey(ref))))continue;
    // Recovery can replace an identity source while maintenance is active. Only
    // its independently authenticated current content can supersede that source.
    const known=ref.kind==='workspace'?state.workspaceContent:ref.kind==='profile'?state.profiles[ref.id]?.profile:ref.kind==='role'?state.roles[ref.id]?.label:undefined;
    const hash=known&&('objectDigest' in known?known.objectDigest:known.digest);
    if(ref.schema!==1||!known||hash!==ref.digest||known.revision!==ref.revision)incomplete();
  }
}

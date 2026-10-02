import type pg from 'pg';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { tenantTransaction } from '../../persistence.js';
import { canonicalJson,digestObject } from '../../shared/crypto.js';
import { validateUpgradeItems, type UpgradeItem, type UpgradeProof } from '../../shared/encrypted-upgrades.js';
import { upgradeReceipt, type UpgradeReceipt } from '../../shared/upgrade-api.js';
import type { SessionPrincipal } from '../identity/sessions.js';
import { readCurrentDeviceProjectScopes } from '../work/planning.js';
import { readCurrentUpgradeRecords,upgradeRecordKey } from './records.js';

export const upgradeChanged = () => new AppError('UPGRADE_CHANGED','Upgrade source or authority changed; reload before preparing a new batch',409);
export const upgradeForbidden = () => new AppError('UPGRADE_FORBIDDEN','A current approved Owner with current scope keys is required',403);
export const upgradeRestricted = () => new AppError('WORKSPACE_RESTRICTED','The encrypted upgrade is paused by another workspace restriction',423);
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);

/** Called inside the native business transaction, after exact receipt lookup.
 * The existing shared workspace fence remains held through progress commit. */
export async function assertCurrentUpgradeBatch(databases:Databases,application:pg.PoolClient,principal:SessionPrincipal,
  proofValue:unknown,itemValues:unknown,now:Date):Promise<{proof:UpgradeProof;items:UpgradeItem[]}> {
  const {proof,items}=await validateUpgradeItems(proofValue,itemValues);
  const ledger=(await application.query('SELECT * FROM app.encrypted_upgrades WHERE workspace_id=$1 AND migration_id=$2',
    [principal.workspaceId,proof.migrationId])).rows[0];
  if(!ledger||ledger.state!=='active'||ledger.data_generation!==principal.dataGeneration||ledger.manifest_digest!==proof.manifestDigest)throw upgradeChanged();
  await tenantTransaction(databases.control,principal.workspaceId,undefined,async control=>{
    const w=(await control.query('SELECT * FROM security.workspaces WHERE workspace_id=$1',[principal.workspaceId])).rows[0];
    if(!w||w.lifecycle==='deleted')throw new AppError('NOT_FOUND','Workspace not available',404);
    if(w.lifecycle!=='active'||w.licence_state!=='active'||w.restore_quarantine)throw upgradeRestricted();
    if(!w.content_maintenance||w.active_upgrade_id!==proof.migrationId||w.write_schema!==1||w.data_generation!==principal.dataGeneration||
      w.security_head!==principal.securityHead||w.security_version!==principal.securityVersion)throw upgradeChanged();
    if(!(await control.query("SELECT 1 FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 AND state='active' AND is_owner",[principal.workspaceId,principal.accountId])).rowCount)throw upgradeForbidden();
    const scopes=await readCurrentDeviceProjectScopes(control,principal,now);
    if(!scopes.some(s=>s.scope==='workspace'&&s.scopeId===principal.workspaceId&&s.mode==='custody'&&s.keyEpoch===w.custody_epoch&&s.permissions.includes('read_project')&&s.permissions.includes('plan_projects')))throw upgradeForbidden();
    for(const item of items){
      const kind=item.target.projectId?'project':'workspace',id=item.target.projectId??principal.workspaceId;
      const head=(await control.query('SELECT key_epoch FROM security.scope_heads WHERE workspace_id=$1 AND scope_kind=$2 AND scope_id=$3',[principal.workspaceId,kind,id])).rows[0];
      if(!head||head.key_epoch!==item.target.keyEpoch||kind==='project'&&!scopes.some(s=>s.scope==='project'&&s.scopeId===id&&s.keyEpoch===head.key_epoch&&s.mode==='content'&&s.permissions.includes('read_project')&&s.permissions.includes('plan_projects')))throw upgradeChanged();
    }
  });
  const current=new Map((await readCurrentUpgradeRecords(application,principal.workspaceId)).map(row=>[upgradeRecordKey(row.reference),row.reference]));
  for(const item of items){
    const source=(await application.query(`SELECT source_reference FROM app.encrypted_upgrade_sources
      WHERE workspace_id=$1 AND migration_id=$2 AND record_type=$3 AND record_id=$4`,[principal.workspaceId,proof.migrationId,item.source.kind,item.source.id])).rows[0];
    const identity=['workspace','profile','role'].includes(item.source.kind);
    if(!source||!same(current.get(upgradeRecordKey(item.source)),item.source)||
      (!identity&&!same(source.source_reference,item.source)))throw upgradeChanged();
  }
  return {proof,items};
}

/** Native record changes, their history and this migration progress are one tx. */
export async function recordUpgradeBatch(application:pg.PoolClient,principal:Pick<SessionPrincipal,'workspaceId'|'accountId'|'dataGeneration'>,operationId:string,
  payload:unknown,proof:UpgradeProof,items:UpgradeItem[],now:Date):Promise<UpgradeReceipt> {
  const prior=(await application.query('SELECT DISTINCT record_type,record_id FROM app.encrypted_upgrade_items WHERE workspace_id=$1 AND migration_id=$2',[principal.workspaceId,proof.migrationId])).rows;
  const completed=new Set(prior.map(r=>`${r.record_type}:${r.record_id}`));for(const item of items)completed.add(upgradeRecordKey(item.target));
  const receipt=upgradeReceipt.parse({version:1,workspaceId:principal.workspaceId,migrationId:proof.migrationId,operationId,
    actorId:principal.accountId,dataGeneration:principal.dataGeneration,kind:'batch',requestHash:await digestObject(payload),
    manifestDigest:proof.manifestDigest,completedCount:completed.size,committedAt:now.toISOString()});
  await application.query(`INSERT INTO app.encrypted_upgrade_operations(workspace_id,migration_id,operation_id,actor_profile_id,data_generation,request_digest,signed_operation,receipt,created_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[principal.workspaceId,proof.migrationId,operationId,principal.accountId,principal.dataGeneration,receipt.requestHash,payload,receipt,now]);
  for(const item of items)await application.query(`INSERT INTO app.encrypted_upgrade_items(workspace_id,migration_id,record_type,record_id,operation_id,target_revision,target_digest,target_envelope,signed_item,created_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[principal.workspaceId,proof.migrationId,item.source.kind,item.source.id,operationId,item.target.revision,item.target.digest,item.envelope,
      {source:item.source,target:item.target,operationId},now]);
  return receipt;
}

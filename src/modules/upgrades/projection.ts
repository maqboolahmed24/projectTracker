import type pg from 'pg';
import { randomUUID } from 'node:crypto';
import { AppError } from '../../errors.js';
import { contentEnvelope,type ContentEnvelope } from '../../shared/contracts.js';
import { base64urlDecode,canonicalJson,digestObject,verifyObject } from '../../shared/crypto.js';
import { identityUpgradePayload } from '../../shared/encrypted-upgrades.js';
import { restoreStart,restoreVerification,restoreReconciledManifest } from '../../shared/restoration.js';
import { upgradeReceipt } from '../../shared/upgrade-api.js';
import { recordUpgradeBatch } from './ledger.js';
import { enqueueNotificationJob } from '../notifications/delivery.js';

export interface UpgradeAuthorityProjection {migration_id:string;state:'active'|'completed'|'aborted';data_generation:string;
  manifest_digest:string;signed_start:unknown;signed_finish:unknown;completed_at:Date|null;restored_generation?:string}
export async function readUpgradeAuthority(control:pg.PoolClient,workspaceId:string):Promise<UpgradeAuthorityProjection[]>{
  const rows=(await control.query<UpgradeAuthorityProjection>('SELECT * FROM security.encrypted_upgrades WHERE workspace_id=$1 ORDER BY created_at,migration_id',[workspaceId])).rows;
  // A generation mismatch is recoverable only after the Owner's exact restore
  // acknowledgement committed to the independent current security journal.
  const restored=(await control.query(`SELECT r.signed_start,r.verification,r.reconciled_manifest,r.manifest_digest,t.signed_transition,t.head,w.data_generation,w.active_upgrade_id
    FROM security.restorations r JOIN security.workspaces w USING(workspace_id)
    JOIN security.security_transitions t ON t.workspace_id=r.workspace_id AND t.operation_id=(r.verification->'body'->'binding'->>'operationId')::uuid
    WHERE r.workspace_id=$1 AND r.state='verified' AND NOT w.restore_quarantine AND w.content_maintenance AND w.active_upgrade_id IS NOT NULL
      AND r.signed_start->'body'->>'nextDataGeneration'=w.data_generation::text AND t.action='workspace.restore_verified'
      AND t.sequence<=w.security_version ORDER BY r.verified_at DESC LIMIT 1`,[workspaceId])).rows[0];
  if(restored){
    const ack=restoreVerification.parse(restored.verification),start=restoreStart.parse(restored.signed_start),manifest=restoreReconciledManifest.parse(restored.reconciled_manifest),b=ack.body.binding;
    if(b.workspaceId!==workspaceId||b.restoreId!==start.body.restoreId||b.restoreId!==manifest.body.restoreId||b.dataGeneration!==restored.data_generation||
      start.body.nextDataGeneration!==b.dataGeneration||manifest.body.source.dataGeneration!==b.dataGeneration||b.manifestDigest!==restored.manifest_digest||
      start.body.manifestDigest!==b.manifestDigest||manifest.body.manifestDigest!==b.manifestDigest||await digestObject(manifest)!==b.reconciledDigest||
      canonicalJson(ack)!==canonicalJson(restored.signed_transition)||await digestObject(ack)!==restored.head||
      !await verifyObject<import('../../shared/restoration.js').RestoreVerification['body']>(ack,base64urlDecode(b.signingPublicKey,32),ack.body.purpose))throw new AppError('SECURITY_FENCED','The upgrade restore acknowledgement is incomplete',503);
    const active=rows.find(row=>row.migration_id===restored.active_upgrade_id&&row.state==='active'&&row.data_generation===b.dataGeneration);
    if(active)active.restored_generation=b.dataGeneration;
  }
  return rows;
}
export interface IdentityUpgradeProjection {signed_operation:unknown;receipt:unknown;request_digest:string}
export async function readIdentityUpgradeOperations(control:pg.PoolClient,workspaceId:string):Promise<IdentityUpgradeProjection[]>{
  return (await control.query<IdentityUpgradeProjection>("SELECT signed_operation,receipt,request_digest FROM security.encrypted_upgrade_operations WHERE workspace_id=$1 AND kind='identity' ORDER BY created_at,operation_id",[workspaceId])).rows;
}
export async function projectIdentityUpgrades(application:pg.PoolClient,workspaceId:string,operations:IdentityUpgradeProjection[]):Promise<void>{
  for(const row of operations){
    const payload=identityUpgradePayload.parse(row.signed_operation),b=payload.mutation.body.binding,receipt=upgradeReceipt.parse(row.receipt);
    if(b.workspaceId!==workspaceId||await digestObject(payload)!==row.request_digest)throw new AppError('SECURITY_FENCED','Invalid retained identity upgrade',503);
    if((await application.query('SELECT 1 FROM app.encrypted_upgrade_operations WHERE workspace_id=$1 AND operation_id=$2',[workspaceId,b.operationId])).rowCount)continue;
    const now=new Date(receipt.committedAt);
    for(const item of payload.upgradeItems){
      if(item.target.kind==='workspace')await application.query('UPDATE app.workspaces SET encrypted_envelope=$2,revision=revision+1,updated_at=$3 WHERE workspace_id=$1',[workspaceId,item.envelope,now]);
      await application.query(`INSERT INTO app.record_versions(workspace_id,id,record_type,record_id,record_revision,actor_profile_id,operation_id,schema_version,key_epoch,encrypted_envelope,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,2,$8,$9,$10)`,[workspaceId,randomUUID(),item.target.kind,item.target.id,item.target.revision,b.accountId,b.operationId,item.target.keyEpoch,item.envelope,now]);
      await application.query(`INSERT INTO app.audit_events(workspace_id,id,actor_profile_id,operation_id,action,record_type,record_id,key_epoch,encrypted_envelope,created_at)
        VALUES($1,$2,$3,$4,'identity.upgrade_content',$5,$6,$7,$8,$9)`,[workspaceId,randomUUID(),b.accountId,b.operationId,item.target.kind,item.target.id,item.target.keyEpoch,
          {mutation:payload.mutation,before:item.sourceEnvelope,after:item.envelope},now]);
    }
    const recorded=await recordUpgradeBatch(application,{workspaceId,accountId:b.accountId,dataGeneration:b.dataGeneration},b.operationId,payload,payload.mutation.body.upgrade,payload.upgradeItems,now);
    if(canonicalJson(recorded)!==canonicalJson(receipt))throw new AppError('SECURITY_FENCED','Identity upgrade receipt disagrees with projected progress',503);
    const outboxId=randomUUID();
    await application.query(`INSERT INTO app.outbox(workspace_id,id,data_generation,operation_id,event_type,deduplication_key,encrypted_envelope,created_at,updated_at)
      VALUES($1,$2,$3,$4,'identity.content_upgraded',$5,$6,$7,$7)`,[workspaceId,outboxId,b.dataGeneration,b.operationId,`upgrade:${b.operationId}`,{mutation:payload.mutation},now]);
    await enqueueNotificationJob(application,{workspaceId,outboxId,dataGeneration:b.dataGeneration,operationId:b.operationId,events:[]},now);
  }
}
/** A security projection may replay an old encrypted label. Follow only an exact
 * immutable migration source, never a revision guess that could undo recovery. */
export async function currentIdentityRepresentation(application:pg.PoolClient,workspaceId:string,kind:'workspace'|'profile'|'role',id:string,
  incoming:unknown):Promise<ContentEnvelope|null>{
  const parsed=contentEnvelope.safeParse(incoming);if(!parsed.success)return null;
  const hash=await digestObject(parsed.data),row=(await application.query(`SELECT i.target_envelope FROM app.encrypted_upgrade_items i
    JOIN app.encrypted_upgrades u USING(workspace_id,migration_id)
    WHERE i.workspace_id=$1 AND i.record_type=$2 AND i.record_id=$3 AND i.signed_item->'source'->>'digest'=$4
      AND u.state IN('active','completed') ORDER BY i.target_revision DESC,i.created_at DESC LIMIT 1`,[workspaceId,kind,id,hash])).rows[0];
  return row?contentEnvelope.parse(row.target_envelope):parsed.data;
}
/** The authority decision already committed; apply it before opening the fence. */
export async function projectUpgradeAuthority(application:pg.PoolClient,workspaceId:string,authority:UpgradeAuthorityProjection[]):Promise<void>{
  for(const row of authority){
    const local=(await application.query('SELECT * FROM app.encrypted_upgrades WHERE workspace_id=$1 AND migration_id=$2 FOR UPDATE',[workspaceId,row.migration_id])).rows[0];
    if(!local||local.manifest_digest!==row.manifest_digest||
      canonicalJson(local.signed_start)!==canonicalJson(row.signed_start))throw new AppError('SECURITY_FENCED','The encrypted upgrade projection is incomplete',503);
    if(local.data_generation!==row.data_generation){
      if(row.state!=='active'||local.state!=='active'||row.restored_generation!==row.data_generation||BigInt(local.data_generation)>=BigInt(row.data_generation))
        throw new AppError('SECURITY_FENCED','The encrypted upgrade generation is not authorized by restore verification',503);
      await application.query('UPDATE app.encrypted_upgrades SET data_generation=$3 WHERE workspace_id=$1 AND migration_id=$2',[workspaceId,row.migration_id,row.data_generation]);
    }
    if(local.state===row.state&&canonicalJson(local.signed_finish)===canonicalJson(row.signed_finish))continue;
    if(local.state==='completed'||local.state==='aborted')throw new AppError('SECURITY_FENCED','The encrypted upgrade projection cannot regress',503);
    await application.query('UPDATE app.encrypted_upgrades SET state=$3,signed_finish=$4,completed_at=$5 WHERE workspace_id=$1 AND migration_id=$2',
      [workspaceId,row.migration_id,row.state,row.signed_finish,row.completed_at]);
    if(row.state==='completed'){
      const owner=(await application.query("SELECT id FROM app.profiles WHERE workspace_id=$1 AND state='active' AND is_owner ORDER BY id LIMIT 1",[workspaceId])).rows[0];
      if(!owner)throw new AppError('SECURITY_FENCED','Summary invalidation requires a current Owner projection',503);
      await application.query("SELECT set_config('ukda.profile_id',$1,true)",[owner.id]);
      await application.query('DELETE FROM app.reporting_summaries WHERE workspace_id=$1',[workspaceId]);
      await application.query('DELETE FROM app.summaries WHERE workspace_id=$1',[workspaceId]);
      await application.query("SELECT set_config('ukda.profile_id','',true)");
    }
    await application.query('UPDATE app.workspaces SET revision=revision+1,updated_at=clock_timestamp() WHERE workspace_id=$1',[workspaceId]);
  }
}

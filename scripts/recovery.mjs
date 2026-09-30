import pg from 'pg';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { physicalFullBackups, assertNoPartialPurge, withPhysicalLock, repositoryInfo, backrest, isolatedRestore, execute, metrics as physicalMetrics } from './physical-backups.mjs';
import { BACKUP_MAX_AGE_MS, storeInfo, checkpointDue, checkpointHealth } from '../ops/recovery-policy.mjs';
import { RecoveryRecords, opaqueId, repositorySecret, CHECKPOINT_BYTES } from '../ops/recovery-records.mjs';
import { enforceBackupExpiry, retentionWindow } from '../ops/recovery-expiry.mjs';
import { recoveryDeployment } from '../ops/recovery-deployment.mjs';

const MAX_WORKSPACES=100,MAX_TICK_PURGES=20;
const DISPOSABLE=['notifications','notification_receipts','notification_preferences','inbox_operations','operation_receipts','outbox','summaries','reporting_preparations','reporting_summaries','export_sessions'];
export const RECOVERY_ARTIFACT_MAX_AGE_MS=24*60*60*1000;
const OWNED=/^ukda-recovery-(app|control)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
class RecoveryFailure extends Error{constructor(code){super(code);this.code=code;}}
const fail=code=>{throw new RecoveryFailure(code);};
async function stage(code,action){try{return await action();}catch(error){if(error instanceof RecoveryFailure)throw error;throw new RecoveryFailure(code);}}
const quote=name=>{if(!/^[a-z_][a-z0-9_]*$/.test(name))fail('INVALID_TABLE');return `"${name}"`;};

/** Operations use the same reviewed services as HTTP, loaded from the current
 * compiled release. This executable does not embed its own security reducer. */
export async function recoveryRuntime(env=process.env){
  const [{loadConfig},{createDatabases,transaction},{ServiceSecrets,loadIdentityConfig},{SessionService},{RestorationService},restoration,manifest,
    {EntitlementOperations},purge,{finalizeDeletionIfDue},crypto,{collectExpiredFileUploads}]=await Promise.all([
    import('../dist/src/config.js'),import('../dist/src/db.js'),import('../dist/src/modules/identity/secrets.js'),import('../dist/src/modules/identity/sessions.js'),
    import('../dist/src/modules/restoration/service.js'),import('../dist/src/shared/restoration.js'),import('../dist/src/modules/restoration/manifest.js'),
    import('../dist/src/modules/identity/entitlements.js'),import('../dist/src/modules/lifecycle/purge.js'),import('../dist/src/modules/lifecycle/deadline.js'),import('../dist/src/shared/crypto.js'),import('../dist/src/modules/files/maintenance.js')]);
  const config=loadConfig(env,{allowAdmin:true});
  if(!config.ADMIN_DATABASE_URL||!config.CONTROL_ADMIN_DATABASE_URL)fail('ADMIN_CONFIGURATION_REQUIRED');
  const actor={operatorId:opaqueId(env.UKDA_OPERATOR_ID)},databases=createDatabases(config),secrets=new ServiceSecrets(loadIdentityConfig(env));
  const adminOptions={max:2,connectionTimeoutMillis:5000,statement_timeout:600000,lock_timeout:30000,application_name:'ukda-recovery-maintenance'};
  const application=new pg.Pool({...adminOptions,connectionString:config.ADMIN_DATABASE_URL}),control=new pg.Pool({...adminOptions,connectionString:config.CONTROL_ADMIN_DATABASE_URL});
  for(const pool of [application,control])pool.on('error',()=>{});
  try{
    const sessions=new SessionService({databases,secrets,origin:config.APP_ORIGIN}),common={databases,secrets,sessions,origin:config.APP_ORIGIN};
    const deployment=recoveryDeployment(env);
    const records=new RecoveryRecords(deployment.recordsDirectory,await repositorySecret(`${deployment.directory}/app.conf`));
    const trusted={[secrets.keyId]:await new EntitlementOperations(databases,secrets).publicSigningKey()};
    return {databases,secrets,application,control,actor,records,transaction,collectExpiredFileUploads,...restoration,...manifest,...purge,...crypto,
      service:hooks=>new RestorationService({...common,...(hooks?{hooks}:{})}),finalize:id=>finalizeDeletionIfDue({databases,secrets,workspaceId:opaqueId(id)}),trusted,
      close:()=>Promise.all([databases.close(),application.end(),control.end()])};
  }catch(error){await Promise.all([databases.close(),application.end(),control.end()]);throw error;}
}

/** A named target is only usable once the segment containing it is archived. */
export async function archiveBoundary(pool){
  await pool.query('CHECKPOINT');
  const wal=(await pool.query('SELECT pg_walfile_name(pg_switch_wal()) AS wal')).rows[0]?.wal;
  if(!/^[A-F0-9]{24}$/.test(wal))fail('WAL_BOUNDARY_INVALID');
  for(let attempt=0;attempt<120;attempt++){
    const row=(await pool.query('SELECT last_archived_wal,last_archived_time,last_failed_time FROM pg_stat_archiver')).rows[0];
    if(row?.last_archived_wal>=wal&&(!row.last_failed_time||new Date(row.last_archived_time)>=new Date(row.last_failed_time)))return wal;
    await delay(1000);
  }fail('WAL_ARCHIVE_TIMEOUT');
}
async function capture(runtime,workspaceId,backups){
  const checkpointId=randomUUID(),target=`ukda_cp_${checkpointId.replaceAll('-','_')}`;
  const value=await runtime.service({checkpointCaptured:async manifest=>{
    if(manifest.body.workspaceId!==workspaceId||manifest.body.checkpointId!==checkpointId)fail('CHECKPOINT_BINDING_INVALID');
    await runtime.application.query('SELECT pg_create_restore_point($1)',[target]);
  }}).captureCheckpoint({workspaceId,checkpointId},runtime.actor);
  await archiveBoundary(runtime.application);
  const index={version:1,workspaceId,checkpointId,capturedAt:value.manifest.body.capturedAt,backupLabel:backups.app.label,controlBackupLabel:backups.control.label,walTarget:target};
  await runtime.records.save(index,{version:1,...value,physical:{app:backups.app,control:backups.control,target}});
  return index;
}
async function activeWorkspaces(runtime){
  const rows=(await runtime.control.query("SELECT workspace_id FROM security.workspaces WHERE lifecycle IN('active','pending_deletion') AND NOT restore_quarantine AND (delete_after IS NULL OR delete_after>clock_timestamp()) ORDER BY workspace_id LIMIT $1",[MAX_WORKSPACES+1])).rows;
  if(rows.length>MAX_WORKSPACES)fail('WORKSPACE_BATCH_LIMIT');return rows.map(r=>r.workspace_id);
}
export function chooseFullBackups(inventories,now=Date.now()){
  const backups={};
  for(const store of ['app','control']){
    const full=inventories[store]?.backup?.filter(b=>b.type==='full'&&Number.isFinite(b.timestamp?.start)&&Number.isFinite(b.timestamp?.stop)&&
      b.timestamp.start<=b.timestamp.stop&&b.timestamp.stop*1000<=now).sort((a,b)=>b.timestamp.stop-a.timestamp.stop)[0];
    if(!full||now-full.timestamp.stop*1000>=BACKUP_MAX_AGE_MS)return null;
    backups[store]={label:full.label,start:full.timestamp.start,stop:full.timestamp.stop,archive:full.archive};
  }return backups;
}
async function captureAll(runtime,ids,control){
  await expiry(runtime);await assertNoPartialPurge(control);
  const inventories={app:await repositoryInfo('app').catch(()=>null),control:await repositoryInfo('control').catch(()=>null)},
    backups=chooseFullBackups(inventories)??await physicalFullBackups(control),checkpoints=[];
  for(const id of ids)checkpoints.push(await capture(runtime,opaqueId(id),backups));
  return {backups,checkpoints};
}
async function verifyStored(runtime,workspaceId,checkpointId){
  const {index,value}=await runtime.records.read(workspaceId,checkpointId),manifest=runtime.restoreCheckpointManifest.parse(value.manifest);
  await runtime.verifyRestoreServiceObject(manifest,runtime.trusted);
  if(value.version!==1||manifest.body.workspaceId!==workspaceId||manifest.body.checkpointId!==checkpointId||manifest.body.capturedAt!==index.capturedAt||
    value.physical?.app?.label!==index.backupLabel||value.physical?.control?.label!==index.controlBackupLabel||value.physical?.target!==index.walTarget)fail('CHECKPOINT_BINDING_INVALID');
  if(!Array.isArray(value.keyObjects)||value.keyObjects.length!==manifest.body.inventory.keyObjects.length)fail('CHECKPOINT_KEYS_INVALID');
  const refs=[];for(const key of value.keyObjects){if(!key||await runtime.digestObject(key.value)!==key.digest)fail('CHECKPOINT_KEYS_INVALID');refs.push({id:key.id,kind:key.kind,digest:key.digest});}
  refs.sort((a,b)=>a.id.localeCompare(b.id));if(runtime.canonicalJson(refs)!==runtime.canonicalJson(manifest.body.inventory.keyObjects))fail('CHECKPOINT_KEYS_INVALID');
  return {index,manifest}; // Captured key objects are verification-only; never insert old control data.
}
export async function verifyRestoreRows(runtime,manifest,table,rows){
  if(!runtime.RESTORE_TABLES.includes(table)||!Array.isArray(rows)||rows.length>runtime.RESTORE_MAX_OBJECTS||rows.some(r=>!r||r.workspace_id!==manifest.body.workspaceId))fail('RESTORE_SOURCE_INVALID');
  const expected=manifest.body.inventory.tables.find(r=>r.table===table),digest=await runtime.digestObject(rows.map(r=>runtime.canonicalRestoreRow(table,r)).map(runtime.canonicalJson).sort());
  if(!expected||expected.count!==rows.length||expected.digest!==digest)fail('RESTORE_MANIFEST_MISMATCH');
}
/** Re-read a paused, owned isolated database in small pages. Private binary
 * chunks remain inside that recoverable artifact until installation commits. */
async function* isolatedTablePages(runtime,artifact,workspaceId,table){
  if(!OWNED.test(artifact.name)||!runtime.RESTORE_TABLES.includes(table))fail('RESTORE_SOURCE_INVALID');
  for(let offset=0;offset<=runtime.RESTORE_MAX_OBJECTS;offset+=16){
    const source=await execute(['exec','-i','--user','postgres',artifact.name,'psql','-X','-U',storeInfo('app').user,'-d',storeInfo('app').database,'-At','-v','ON_ERROR_STOP=1'],
      {input:`SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM (SELECT * FROM app.${quote(table)} WHERE workspace_id='${opaqueId(workspaceId)}'::uuid ORDER BY ctid LIMIT 16 OFFSET ${offset}) t;`});
    const rows=JSON.parse(source);if(!Array.isArray(rows)||rows.length>16||rows.some(r=>!r||r.workspace_id!==workspaceId))fail('RESTORE_SOURCE_INVALID');yield rows;if(rows.length<16)return;
  }fail('RESTORE_SIZE_LIMIT');
}
async function isolatedRows(runtime,artifact,manifest){
  const tables=new Map();let count=0,bytes=0,binaryBytes=0;
  for(const expected of manifest.body.inventory.tables){const table=expected.table,canonical=[];let columns=null,rowCount=0;
    for await(const rows of isolatedTablePages(runtime,artifact,manifest.body.workspaceId,table))for(const row of rows){
      const keys=Object.keys(row).sort();if(columns&&columns.join()!==keys.join())fail('RESTORE_SCHEMA_MISMATCH');columns=keys;
      const canonicalRow=runtime.canonicalRestoreRow(table,row),encoded=runtime.canonicalJson(canonicalRow);bytes+=Buffer.byteLength(encoded);if(bytes>(runtime.RESTORE_ROW_MAX_BYTES??CHECKPOINT_BYTES))fail('RESTORE_SIZE_LIMIT');
      if(table==='file_chunks'){binaryBytes+=canonicalRow.cipher_bytes_length;if(binaryBytes>(runtime.RESTORE_BINARY_MAX_BYTES??0))fail('RESTORE_SIZE_LIMIT');}
      canonical.push(encoded);rowCount++;count++;if(count>runtime.RESTORE_MAX_OBJECTS)fail('RESTORE_SIZE_LIMIT');
    }
    const digest=runtime.restoreTableDigest?runtime.restoreTableDigest(canonical):await runtime.digestObject(canonical.sort());if(rowCount!==expected.count||digest!==expected.digest)fail('RESTORE_MANIFEST_MISMATCH');
    tables.set(table,{kind:'isolated-table',artifact,workspaceId:manifest.body.workspaceId,rowCount,columns:columns??[],digest});
  }
  return tables;
}
export async function installRows(runtime,workspaceId,restoreId,tables){
  await runtime.transaction(runtime.application,async a=>{
    await a.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`ukda.workspace:${workspaceId}`]);
    const current=(await runtime.control.query('SELECT lifecycle,delete_after,restore_quarantine,active_restore_id FROM security.workspaces WHERE workspace_id=$1',[workspaceId])).rows[0];
    if(!current||!['active','pending_deletion'].includes(current.lifecycle)||current.delete_after&&new Date(current.delete_after)<=new Date()||!current.restore_quarantine||current.active_restore_id!==restoreId)fail('RESTORE_AUTHORITY_CHANGED');
    const workspace=(await a.query('SELECT fence_closed,restore_quarantine FROM app.workspaces WHERE workspace_id=$1 FOR UPDATE',[workspaceId])).rows[0];
    if(!workspace?.fence_closed||!workspace.restore_quarantine)fail('RESTORE_FENCE_REQUIRED');
    await a.query("SET LOCAL row_security=off; SET CONSTRAINTS ALL DEFERRED");
    // Reject a stale binary/schema pair before deleting any selected content.
    for(const [table,rows]of tables){
      if(!runtime.RESTORE_TABLES.includes(table))fail('INVALID_TABLE');
      const columns=(await a.query("SELECT attname FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped ORDER BY attname",[`app.${table}`])).rows.map(r=>r.attname);
      if(Array.isArray(rows)?rows.some(row=>Object.keys(row).sort().join()!==columns.join()):rows.kind!=='isolated-table'||rows.workspaceId!==workspaceId||rows.rowCount>runtime.RESTORE_MAX_OBJECTS||rows.rowCount&&rows.columns.join()!==columns.join())fail('RESTORE_SCHEMA_MISMATCH');
    }
    const changed=[...new Set([...DISPOSABLE,...(runtime.RESTORE_DISPOSABLE_FILE_TABLES??[]),...runtime.RESTORE_TABLES.filter(t=>t!=='workspaces')])];
    for(const table of changed)await a.query(`ALTER TABLE app.${quote(table)} DISABLE TRIGGER USER`);
    for(const table of changed)await a.query(`DELETE FROM app.${quote(table)} WHERE workspace_id=$1`,[workspaceId]);
    for(const [table,source]of tables){const canonical=[];let rowCount=0;
      const pages=Array.isArray(source)?(async function*(){yield source;})():isolatedTablePages(runtime,source.artifact,workspaceId,table);
      for await(const rows of pages)for(const row of rows){
        if(!Array.isArray(source)){if(Object.keys(row).sort().join()!==source.columns.join())fail('RESTORE_SCHEMA_MISMATCH');canonical.push(runtime.canonicalJson(runtime.canonicalRestoreRow(table,row)));rowCount++;}
        if(table==='workspaces')await a.query('UPDATE app.workspaces SET encrypted_envelope=$2,revision=$3 WHERE workspace_id=$1',[workspaceId,row.encrypted_envelope,row.revision]);
        else await a.query(`INSERT INTO app.${quote(table)} SELECT * FROM jsonb_populate_record(NULL::app.${quote(table)},$1::jsonb)`,[JSON.stringify(row)]);
      }
      if(!Array.isArray(source)&&(rowCount!==source.rowCount||(runtime.restoreTableDigest?runtime.restoreTableDigest(canonical):await runtime.digestObject(canonical.sort()))!==source.digest))fail('RESTORE_MANIFEST_MISMATCH');
    }
    // No session_replication_role bypass: database foreign keys remain deferred
    // and checked at commit. Only approved history/user triggers are disabled.
    await a.query('SET CONSTRAINTS ALL IMMEDIATE');
    for(const table of changed)await a.query(`ALTER TABLE app.${quote(table)} ENABLE TRIGGER USER`);
  });
}
async function removeArtifact(artifact,run=execute){
  if(!OWNED.test(artifact.name)||artifact.volume!==`${artifact.name}-data`)fail('ARTIFACT_OWNERSHIP_INVALID');
  const c=JSON.parse(await run(['inspect',artifact.name]))[0],v=JSON.parse(await run(['volume','inspect',artifact.volume]))[0];
  if(c.Name!==`/${artifact.name}`||c.Config?.Labels?.['ukda.recovery.drill']!=='true'||v.Name!==artifact.volume||v.Labels?.['ukda.recovery.drill']!=='true'||
    !c.Mounts.some(m=>m.Type==='volume'&&m.Name===artifact.volume&&m.Destination==='/var/lib/postgresql'))fail('ARTIFACT_OWNERSHIP_INVALID');
  await run(['rm','--force',artifact.name]);await run(['volume','rm',artifact.volume]);
}
/** Caller holds the global physical lock. Normal maintenance removes staging
 * copies after one day; deletion expiry/purge uses the default immediate sweep. */
export async function retireOwnedArtifacts({before=Date.now(),run=execute}={}){
  if(!Number.isFinite(before))fail('ARTIFACT_AGE_INVALID');
  const eligible=date=>{const time=Date.parse(date);if(!Number.isFinite(time))fail('ARTIFACT_AGE_INVALID');return time<=before;};
  const ids=(await run(['ps','-aq','--filter','label=ukda.recovery.drill=true'])).split(/\s+/).filter(Boolean);
  if(ids.length>200)fail('ARTIFACT_BATCH_LIMIT');let count=0;const protectedVolumes=new Set();
  for(const id of ids){const row=JSON.parse(await run(['inspect',id]))[0],name=row.Name?.replace(/^\//,'');
    if(!OWNED.test(name)||row.Config?.Labels?.['ukda.recovery.drill']!=='true')fail('ARTIFACT_OWNERSHIP_INVALID');
    const volume=`${name}-data`,v=JSON.parse(await run(['volume','inspect',volume]))[0];
    if(v.Name!==volume||v.Labels?.['ukda.recovery.drill']!=='true'||!row.Mounts.some(m=>m.Type==='volume'&&m.Name===volume&&m.Destination==='/var/lib/postgresql'))fail('ARTIFACT_OWNERSHIP_INVALID');
    if(!eligible(row.Created)||!eligible(v.CreatedAt)){protectedVolumes.add(volume);continue;}
    await removeArtifact({name,volume},run);count++;}
  // A process can die between volume creation and container creation/removal.
  const volumes=(await run(['volume','ls','-q','--filter','label=ukda.recovery.drill=true'])).split(/\s+/).filter(Boolean);
  if(volumes.length>200)fail('ARTIFACT_BATCH_LIMIT');
  for(const name of volumes){if(!name.endsWith('-data')||!OWNED.test(name.slice(0,-5)))fail('ARTIFACT_OWNERSHIP_INVALID');if(protectedVolumes.has(name))continue;
    const row=JSON.parse(await run(['volume','inspect',name]))[0];if(row.Name!==name||row.Labels?.['ukda.recovery.drill']!=='true')fail('ARTIFACT_OWNERSHIP_INVALID');
    if(!eligible(row.CreatedAt))continue;await run(['volume','rm',name]);count++;}
  return count;
}
async function restore(runtime,workspaceId,checkpointId){
  await runtime.finalize(workspaceId);const {index,manifest}=await verifyStored(runtime,workspaceId,checkpointId),service=runtime.service(),restoreId=randomUUID();
  await service.begin({workspaceId,restoreId,manifest},runtime.actor);
  let artifact;
  try{
    artifact=await isolatedRestore('app',index.backupLabel,index.walTarget);
    const tables=await isolatedRows(runtime,artifact,manifest);await installRows(runtime,workspaceId,restoreId,tables);
    const result=await service.reconcile({workspaceId,restoreId});
    return {workspaceId,checkpointId,restoreId,state:result.state,ownerVerificationRequired:true,missingRecords:result.missingRecords};
  }finally{
    // Global recovery lock is held. A failed isolatedRestore may not return its
    // handle, so sweep only verified owned artifacts as well. Never the primaries.
    if(artifact)await removeArtifact(artifact);await retireOwnedArtifacts();
  }
}
async function vacuumTables(pool,tables,schema,beforeStep){
  const seen=new Set();if(!Array.isArray(tables)||tables.length>200)fail('PURGE_TABLES_INVALID');
  for(const full of tables){if(seen.has(full))continue;seen.add(full);const parts=full.split('.');
    if(parts.length!==2||parts[0]!==schema&&full!=='graphile_worker._private_jobs'||schema==='security'&&parts[0]!=='security')fail('PURGE_TABLES_INVALID');
    const table=`${quote(parts[0])}.${quote(parts[1])}`;
    const exists=(await pool.query("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2 AND c.relkind='r'",parts)).rowCount;
    if(!exists)fail('PURGE_TABLES_INVALID');await beforeStep();await pool.query(`VACUUM (FULL, ANALYZE) ${table}`);
  }
}
async function purgeOne(runtime,workspaceId){
  await runtime.finalize(workspaceId);
  const tombstone=(await runtime.control.query("SELECT 1 FROM security.deletion_tombstones WHERE workspace_id=$1 AND entity_kind='workspace'",[workspaceId])).rowCount;
  if(!tombstone)fail('DELETION_TOMBSTONE_REQUIRED');
  const marker=(await runtime.control.query('SELECT live_payloads_purged_at FROM security.workspace_purges WHERE workspace_id=$1',[workspaceId])).rows[0];
  if(!marker)fail('PURGE_MARKER_REQUIRED');
  if(!marker.live_payloads_purged_at){
    const logical=await runtime.logicalPurgeWorkspace({databases:runtime.databases,application:runtime.application,control:runtime.control,workspaceId});
    await vacuumTables(runtime.application,logical.applicationTables,'app',()=>expiry(runtime));await vacuumTables(runtime.control,logical.controlTables,'security',()=>expiry(runtime));
    await archiveBoundary(runtime.application);await archiveBoundary(runtime.control);
    await runtime.records.removeWorkspace(workspaceId);await retireOwnedArtifacts();
    await runtime.completePhysicalPurge(runtime.control,workspaceId);
  }
  return {workspaceId,state:'physically_purged'};
}
async function expiry(runtime){
  await runtime.records.expire();
  const rows=(await runtime.control.query('SELECT workspace_id,live_payloads_purged_at,backup_expires_at FROM security.workspace_purges WHERE live_payloads_purged_at IS NOT NULL ORDER BY workspace_id')).rows;
  if(rows.length>20000)fail('RETENTION_BATCH_LIMIT');
  const purges=rows.map(r=>({livePayloadsPurgedAt:new Date(r.live_payloads_purged_at).toISOString(),backupExpiresAt:new Date(r.backup_expires_at).toISOString()})),results=[];
  const due=retentionWindow(purges).eligible;if(due)await retireOwnedArtifacts();
  let appInfo;
  for(const store of ['app','control']){
    // Never attempt a possibly slow backup in the removal phase. If repository
    // information is unavailable at cutoff, retire that exact stanza fail-closed.
    let current;try{current=await repositoryInfo(store);}catch{current=null;}
    const result=await enforceBackupExpiry({store,backups:current?.backup??[],purges,run:backrest,info:repositoryInfo});
    results.push({...result,requiresFull:!current||result.retired});
    if(store==='app'){if(result.retired)await runtime.records.expire(Date.now(),true);else if(current)appInfo={backup:current.backup.filter(b=>!result.expired.includes(b.label))};}
  }
  if(appInfo){const available=new Set(appInfo.backup.map(b=>b.label));
    for(const index of await runtime.records.list())if(!available.has(index.backupLabel)||rows.some(r=>r.workspace_id===index.workspaceId))await runtime.records.remove(index.workspaceId,index.checkpointId);}
  return results;
}
async function cleanFull(runtime,control){
  const row=(await runtime.control.query('SELECT max(live_payloads_purged_at) AS completed FROM security.workspace_purges')).rows[0];
  if(row?.completed){const ms=new Date(row.completed).getTime();await delay(Math.max(0,Math.ceil(ms/1000)*1000+1-Date.now()));}
  await expiry(runtime);return physicalFullBackups(control);
}
async function usableCheckpoints(runtime,ids,inventories){
  const labels={app:new Set(inventories.app?.backup?.map(b=>b.label)??[]),control:new Set(inventories.control?.backup?.map(b=>b.label)??[])},
    indexes=(await runtime.records.list()).sort((a,b)=>Date.parse(b.capturedAt)-Date.parse(a.capturedAt)),result=[];
  for(const id of ids){let attempts=0;
    for(const index of indexes){if(index.workspaceId!==id||!labels.app.has(index.backupLabel)||!labels.control.has(index.controlBackupLabel))continue;
      // Corrupt recent metadata cannot claim freshness or cause unbounded work.
      if(++attempts>64)break;
      try{const verified=await verifyStored(runtime,id,index.checkpointId);result.push(verified.index);break;}catch{}}
  }return result;
}
async function writeMetrics(runtime){
  const value=await physicalMetrics(); // Physical probes are not a composed Owner verification drill.
  const ids=await activeWorkspaces(runtime),inventories={app:await repositoryInfo('app'),control:await repositoryInfo('control')};
  value.contentCheckpoints=checkpointHealth(ids,await usableCheckpoints(runtime,ids,inventories));
  const previous=(await runtime.control.query('SELECT metrics FROM security.recovery_health WHERE id=true')).rows[0]?.metrics;
  for(const store of ['app','control']){const known=previous?.[store]?.lastSuccessfulDrillAt;
    if(typeof known==='string'&&Number.isFinite(Date.parse(known))&&Date.parse(known)<=Date.now())value[store].lastSuccessfulDrillAt=known;}
  await runtime.control.query('INSERT INTO security.recovery_health(id,measured_at,metrics) VALUES(true,clock_timestamp(),$1) ON CONFLICT(id) DO UPDATE SET measured_at=EXCLUDED.measured_at,metrics=EXCLUDED.metrics',[value]);return value;
}
async function tick(runtime,control){
  const due=(await runtime.control.query("SELECT workspace_id FROM security.workspaces WHERE lifecycle='pending_deletion' AND delete_after<=clock_timestamp() ORDER BY delete_after,workspace_id LIMIT $1",[MAX_TICK_PURGES])).rows;
  for(const row of due)await runtime.finalize(row.workspace_id);
  const candidates=await runtime.purgeCandidates(runtime.control);
  const purges=[];for(const row of candidates.slice(0,MAX_TICK_PURGES))purges.push(await purgeOne(runtime,row.workspace_id));
  const remaining=(await runtime.control.query("SELECT 1 FROM security.workspaces WHERE lifecycle='pending_deletion' AND delete_after<=clock_timestamp() LIMIT 1")).rowCount;
  if(remaining||(await runtime.purgeCandidates(runtime.control)).length)fail('DUE_DELETION_BATCH_REMAINS');
  const expiredUploads=(await runtime.application.query("SELECT workspace_id FROM app.file_versions WHERE state='staged' AND expires_at<=clock_timestamp() GROUP BY workspace_id ORDER BY min(expires_at) LIMIT 64")).rows;
  let removedUploads=0;for(const row of expiredUploads)removedUploads+=(await runtime.collectExpiredFileUploads(runtime.application,row.workspace_id)).removed;
  const retention=await expiry(runtime);
  const latestPurge=(await runtime.control.query('SELECT max(live_payloads_purged_at) AS completed FROM security.workspace_purges')).rows[0]?.completed;
  let requiresClean=purges.length>0||retention.some(r=>r.requiresFull);
  if(latestPurge&&!requiresClean)for(const store of ['app','control'])if(!(await repositoryInfo(store)).backup.some(b=>b.type==='full'&&b.timestamp.start*1000>=new Date(latestPurge).getTime()))requiresClean=true;
  if(requiresClean)await cleanFull(runtime,control);
  const inventories={app:await repositoryInfo('app'),control:await repositoryInfo('control')},ids=await activeWorkspaces(runtime),
    usable=await usableCheckpoints(runtime,ids,inventories),needs=ids.filter(id=>checkpointDue(usable.find(r=>r.workspaceId===id)??null));
  let checkpoints=[];
  // Five-minute named, signed recovery points reuse the daily physical bases.
  // A fresh full is needed only when either existing base has aged one day.
  if(needs.length||!chooseFullBackups(inventories)){
    const result=await captureAll(runtime,needs.length?needs:ids,control);checkpoints=result.checkpoints;
  }
  await writeMetrics(runtime);return {finalized:due.length,purged:purges.length,removedUploads,checkpoints};
}
function commandArguments(command,values){
  if(!['checkpoint','restore','purge','tick','daemon','metrics'].includes(command)||command==='checkpoint'&&values.length>1||command==='restore'&&values.length!==2||command==='purge'&&values.length!==1||['tick','daemon','metrics'].includes(command)&&values.length)fail('USAGE');
  values.forEach(opaqueId);
}
export async function recoveryCommand(runtime,command,values=[]){
  commandArguments(command,values);
  if(command==='metrics')return writeMetrics(runtime);
  if(command==='daemon')fail('USAGE');
  return withPhysicalLock(async control=>{
    try{
      // Both repositories are sanitized before any unrelated full backup, PITR,
      // purge vacuum, or checkpoint work can delay the hard retention cutoff.
      await expiry(runtime);
      await retireOwnedArtifacts({before:Date.now()-RECOVERY_ARTIFACT_MAX_AGE_MS});
      if(command==='checkpoint'){const ids=values.length?[values[0]]:await activeWorkspaces(runtime);for(const id of ids)await runtime.finalize(id);return await captureAll(runtime,ids,control);}
      if(command==='restore')return await restore(runtime,values[0],values[1]);
      if(command==='purge'){const result=await purgeOne(runtime,values[0]);await expiry(runtime);await cleanFull(runtime,control);await writeMetrics(runtime);return result;}
      return await tick(runtime,control);
    }finally{await expiry(runtime);}
  });
}
export async function recoveryMain(args){
  const [command,...values]=args;commandArguments(command,values);
  const runtime=await stage('RECOVERY_CONFIGURATION_INVALID',()=>recoveryRuntime());
  try{
    const run=()=>recoveryCommand(runtime,command==='daemon'?'tick':command,values);
    if(command!=='daemon')return await stage('RECOVERY_OPERATION_FAILED',run);
    let stopped=false;const stop=()=>{stopped=true;};process.once('SIGINT',stop);process.once('SIGTERM',stop);
    try{while(!stopped){try{const result=await run();process.stdout.write(JSON.stringify({at:new Date().toISOString(),...result})+'\n');}
      catch(error){process.stderr.write(JSON.stringify({at:new Date().toISOString(),error:error instanceof RecoveryFailure?error.code:'RECOVERY_TICK_FAILED'})+'\n');}
      if(!stopped)await delay(60000);}}
    finally{process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);}return {stopped:true};
  }finally{await runtime.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{process.stdout.write(JSON.stringify(await recoveryMain(process.argv.slice(2)),null,2)+'\n');}
  catch(error){process.stderr.write(JSON.stringify({error:error instanceof RecoveryFailure?error.code:'RECOVERY_OPERATION_FAILED'})+'\n');process.exitCode=1;}
}

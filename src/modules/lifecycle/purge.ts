import type pg from 'pg';
import type { Databases } from '../../db.js';
import { transaction } from '../../db.js';
import { identifier } from '../../shared/contracts.js';
import { withSecurityFence } from '../identity/projection.js';

/** Operational-only pools: the HTTP/queue runtime cannot execute the privileged
 * functions. Caller holds the common recovery:physical control-session lock. */
export async function logicalPurgeWorkspace(input:{databases:Databases;application:pg.Pool;control:pg.Pool;workspaceId:string}){
 const workspaceId=identifier.parse(input.workspaceId);
 const marker=(await input.control.query('SELECT * FROM security.workspace_purges WHERE workspace_id=$1',[workspaceId])).rows[0];
 const tombstone=(await input.control.query("SELECT 1 FROM security.deletion_tombstones WHERE workspace_id=$1 AND entity_kind='workspace'",[workspaceId])).rows[0];
 if(!marker||!tombstone)throw new Error('Authoritative deletion tombstone required');
 // Repeating after a partial two-store purge is safe. A later physical phase
 // may need to vacuum the same table set again; never report it as completed here.
 return withSecurityFence(input.databases,workspaceId,async()=>{
  const applicationTables=await transaction(input.application,async c=>{
   await c.query(`INSERT INTO app.lifecycle_tombstones(workspace_id,deleted_at,security_head,security_version)
    VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,[workspaceId,marker.deletion_deadline,marker.final_head,marker.final_security_version]);
   return (await c.query<{tables:string[]}>('SELECT app.purge_workspace_payloads($1) AS tables',[workspaceId])).rows[0]!.tables;
  });
  const controlTables=(await input.control.query<{tables:string[]}>('SELECT security.purge_workspace_payloads($1) AS tables',[workspaceId])).rows[0]!.tables;
  return {workspaceId,state:'logical_payloads_deleted' as const,applicationTables,controlTables,
   purgeDeadline:new Date(new Date(marker.deletion_deadline).getTime()+24*60*60*1000).toISOString()};
 });
}
export async function purgeCandidates(control:pg.Pool){return (await control.query(`SELECT workspace_id,deletion_deadline,logical_payloads_deleted_at,live_payloads_purged_at,backup_expires_at
 FROM security.workspace_purges WHERE live_payloads_purged_at IS NULL ORDER BY deletion_deadline,workspace_id`)).rows;}
export async function completePhysicalPurge(control:pg.Pool,workspaceId:string){
 await control.query('SELECT security.complete_physical_purge($1)',[identifier.parse(workspaceId)]);
 return (await control.query('SELECT workspace_id,logical_payloads_deleted_at,live_payloads_purged_at,backup_expires_at FROM security.workspace_purges WHERE workspace_id=$1',[workspaceId])).rows[0];
}

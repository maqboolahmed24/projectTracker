import type pg from 'pg';
import { transaction } from '../../db.js';
import { identifier } from '../../shared/contracts.js';

/** Privileged expiry collection, including projects with no surviving user grant.
 * Only the application's table owner can run this maintenance operation. It does
 * not bypass immutable ready-version triggers, alter security or delete history.
 */
export async function collectExpiredFileUploads(applicationAdmin:pg.Pool,workspaceId:string,now=new Date()):Promise<{removed:number;releasedBytes:number}> {
 identifier.parse(workspaceId);if(!Number.isFinite(now.getTime())||now.getTime()>Date.now()+30000)throw new Error('Invalid file maintenance time');
 return transaction(applicationAdmin,async a=>{
  const owner=(await a.query<{allowed:boolean}>("SELECT current_user::regrole=(SELECT relowner FROM pg_class WHERE oid='app.workspaces'::regclass) AS allowed")).rows[0]?.allowed;
  if(!owner)throw new Error('Privileged file maintenance identity required');
  await a.query("SELECT pg_advisory_xact_lock_shared(hashtextextended('ukda.workspace:' || $1,0))",[workspaceId]);
  await a.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.files.capacity',0))");
  const rows=(await a.query<{id:string;reserved_bytes:string;metadata_bytes:string}>(`SELECT v.id,r.reserved_bytes,
   (r.reserved_bytes-(v.manifest->'body'->>'cipherBytes')::bigint)::text AS metadata_bytes
   FROM app.file_upload_reservations r JOIN app.file_versions v ON v.workspace_id=r.workspace_id AND v.id=r.version_id
   WHERE r.workspace_id=$1 AND r.expires_at<=$2 AND v.state='staged' AND v.expires_at<=$2 ORDER BY v.id FOR UPDATE OF r,v`,[workspaceId,now])).rows;
  if(!rows.length)return {removed:0,releasedBytes:0};
  const reserved=rows.reduce((n,r)=>n+Number(r.reserved_bytes),0),metadata=rows.reduce((n,r)=>n+Number(r.metadata_bytes),0);
  await a.query("DELETE FROM app.file_versions WHERE workspace_id=$1 AND id=ANY($2::uuid[]) AND state='staged' AND expires_at<=$3",[workspaceId,rows.map(r=>r.id),now]);
  const updated=await a.query('UPDATE app.file_storage_usage SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes+$3,active_uploads=active_uploads-$4 WHERE workspace_id=$1',[workspaceId,reserved,metadata,rows.length]);
  if(updated.rowCount!==1)throw new Error('File quota maintenance mismatch');
  return {removed:rows.length,releasedBytes:reserved-metadata};
 });
}

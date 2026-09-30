import { randomUUID } from 'node:crypto';
import sodium from 'libsodium-wrappers';
import type pg from 'pg';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { assertAuthoritativeContentWrite, tenantTransaction } from '../../persistence.js';
import { base64urlDecode, base64urlEncode, digestObject, signObject, verifyObject } from '../../shared/crypto.js';
import { assertFileBindingCurrent, fileBeginRequest, fileBindingFromPlanning, fileCancelRequest, fileChunkDigest, fileChunkRequest,
  fileLinkRequest, fileListRequest, fileReadChunkRequest, fileReference, fileStatusRequest, fileVersionRequest, fileVersionsRequest,fileEditorPermitRequest,fileEditorPermit,
  FILE_CHUNK_OVERHEAD, FILE_CHUNK_PLAIN_BYTES, FILE_MAX_ACTIVE_UPLOADS, FILE_MAX_DOCUMENT_TASKS, FILE_MAX_PER_PROJECT,
  FILE_WORKSPACE_QUOTA_BYTES, verifyFileManifest,
  type FileContext, type FileEntry, type FileManifest, type FilePage, type FileQuota, type FileReceipt, type FileVersion,
  type FileVersionPage, type FileView,type FileEditorPermit } from '../../shared/files.js';
import {deliveryPairRequest,deliveryServiceCommandRequest,verifyOwnerFileObject} from '../../shared/file-delivery.js';
import type { PlanningContext, PlanningSecurityResolver } from '../../shared/planning-api.js';
import type { SessionPrincipal, SessionService } from '../identity/sessions.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { PlanningService } from '../work/planning.js';

interface Options {databases:Databases;sessions:SessionService;secrets:ServiceSecrets;origin:string;planning?:PlanningService;
 deploymentLimitBytes?:number;requestBudget?:(scope:{workspaceId:string;accountId:string})=>Promise<void>;
 hooks?:{beforeCommit?:()=>Promise<void>;afterCommit?:()=>Promise<void>}}
interface VersionRow {workspace_id:string;project_id:string;file_id:string;id:string;version:string;data_generation:string;
 author_profile_id:string;author_device_id:string;storage:'managed'|'external';state:'staged'|'ready'|'cancelled';
 reserved_bytes:string;manifest:FileManifest;created_at:Date;expires_at:Date;completed_at:Date|null}
interface UsageRow {used_bytes:string;reserved_bytes:string;active_uploads:number}
const invalid=()=>new AppError('FILES_INVALID','Invalid file operation',400);
const changed=()=>new AppError('FILES_CHANGED','The file or your access changed; refresh before continuing',409);
const forbidden=()=>new AppError('FILES_FORBIDDEN','Your current permissions do not allow this file action',403);
const missing=()=>new AppError('FILES_NOT_FOUND','File not available',404);
const unavailable=()=>new AppError('FILES_UNAVAILABLE','Files are temporarily unavailable; retain your upload',503);
function parse<T>(schema:z.ZodType<T>,input:unknown):T {const result=schema.safeParse(input);if(!result.success)throw invalid();return result.data;}
const ref=(v:{workspaceId:string;projectId:string;operationId:string})=>({workspaceId:v.workspaceId,projectId:v.projectId,operationId:v.operationId});

/** All operations retain the existing workspace fence and current approved-device project grant. */
export class FilesService {
 readonly #planning:PlanningService;readonly #deploymentLimit:number;
 constructor(readonly options:Options) {
  this.#planning=options.planning??new PlanningService(options);
  this.#deploymentLimit=options.deploymentLimitBytes??8*1024*1024*1024;
  if(!Number.isSafeInteger(this.#deploymentLimit)||this.#deploymentLimit<FILE_WORKSPACE_QUOTA_BYTES)throw new Error('Invalid file capacity configuration');
 }
 async #with<T>(cookie:string,csrf:string,reference:z.infer<typeof fileReference>,write:boolean,
  action:(a:pg.PoolClient,p:PlanningContext,principal:SessionPrincipal,now:Date,securityAt:PlanningSecurityResolver)=>Promise<T>):Promise<T> {
  try{return await this.#planning.withCurrentContext(cookie,csrf,ref(reference),async(a,p,principal,now,securityAt)=>{
   await this.options.requestBudget?.({workspaceId:principal.workspaceId,accountId:principal.accountId});
   if(write)await tenantTransaction(this.options.databases.control,reference.workspaceId,undefined,c=>
    assertAuthoritativeContentWrite(c,reference.workspaceId,[fileBindingFromPlanning(p.binding).writeSchema]));
   try{return await action(a,p,principal,now,securityAt);}catch(error){if(error instanceof AppError)throw error;throw unavailable();}
  },{write});}catch(error){if(error instanceof AppError)throw error;throw unavailable();}
 }
 #canManage(p:PlanningContext):boolean{return p.binding.permissions.includes('manage_tasks')||p.binding.permissions.includes('plan_projects');}
 #writeAllowed(p:PlanningContext,kind:'source'|'output',taskIds:string[]):void {
  if(p.graph.project.archived||['complete','cancelled'].includes(p.graph.project.state))throw new AppError('FILES_READ_ONLY','This project is closed for file changes',409);
  for(const id of taskIds){const task=p.graph.tasks.find(t=>t.id===id);if(!task||['done','cancelled','review'].includes(task.state))throw changed();}
  if(this.#canManage(p))return;
  if(kind!=='output'||!p.binding.permissions.includes('edit_assigned_tasks')||!taskIds.length||
  taskIds.some(id=>!p.graph.tasks.find(t=>t.id===id)?.assigneeIds.includes(p.binding.accountId)))throw forbidden();
 }
 async #affectedTasks(a:pg.PoolClient,r:{workspaceId:string;projectId:string},fileId:string,requested:string[]):Promise<string[]> {
  const rows=(await a.query<{task_id:string}>("SELECT task_id FROM app.task_file_links WHERE workspace_id=$1 AND project_id=$2 AND file_id=$3 AND mode='latest'",[r.workspaceId,r.projectId,fileId])).rows;
  return [...new Set([...requested,...rows.map(row=>row.task_id)])];
 }
 async #usage(a:pg.PoolClient,workspaceId:string):Promise<FileQuota> {
  const row=(await a.query<UsageRow>('SELECT used_bytes,reserved_bytes,active_uploads FROM app.file_storage_usage WHERE workspace_id=$1',[workspaceId])).rows[0];
  const total=Number((await a.query<{total:string}>('SELECT COALESCE(sum(used_bytes+reserved_bytes),0)::text AS total FROM app.file_storage_usage')).rows[0]!.total);
  return {limitBytes:FILE_WORKSPACE_QUOTA_BYTES,usedBytes:Number(row?.used_bytes??0),reservedBytes:Number(row?.reserved_bytes??0),activeUploads:row?.active_uploads??0,
   deploymentRemainingBytes:Math.max(0,this.#deploymentLimit-total)};
 }
 async #quotaLock(a:pg.PoolClient,workspaceId:string):Promise<void> {
  await a.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.files.capacity',0))");
  await a.query('INSERT INTO app.file_storage_usage(workspace_id) VALUES($1) ON CONFLICT DO NOTHING',[workspaceId]);
 }
 async #expire(a:pg.PoolClient,workspaceId:string,now:Date):Promise<void> {
  const expired=(await a.query<{version_id:string;reserved_bytes:string;metadata_bytes:string}>(`SELECT r.version_id,r.reserved_bytes,
   (r.reserved_bytes-(v.manifest->'body'->>'cipherBytes')::bigint)::text AS metadata_bytes FROM app.file_upload_reservations r
   JOIN app.file_versions v ON v.workspace_id=r.workspace_id AND v.id=r.version_id
   WHERE r.workspace_id=$1 AND r.expires_at<=$2 ORDER BY r.version_id FOR UPDATE OF r`,[workspaceId,now])).rows;
  if(!expired.length)return;
  const ids=expired.map(r=>r.version_id),size=expired.reduce((n,r)=>n+Number(r.reserved_bytes),0),retainedMetadata=expired.reduce((n,r)=>n+Number(r.metadata_bytes),0);
  // DELETE policy admits only expired staged versions; FK cascade removes their bytes.
  const removed=await a.query("DELETE FROM app.file_versions WHERE workspace_id=$1 AND id=ANY($2::uuid[]) AND state='staged' AND expires_at<=$3",[workspaceId,ids,now]);
  if(removed.rowCount!==expired.length)throw changed();
  await a.query('UPDATE app.file_storage_usage SET reserved_bytes=reserved_bytes-$2,active_uploads=active_uploads-$3,used_bytes=used_bytes+$4 WHERE workspace_id=$1',[workspaceId,size,expired.length,retainedMetadata]);
 }
 async context(cookie:string,csrf:string,input:unknown):Promise<FileContext> {
  const r=parse(fileReference,input);return this.#with(cookie,csrf,r,false,async(a,planning)=>({planning,binding:fileBindingFromPlanning(planning.binding),quota:await this.#usage(a,r.workspaceId)}));
 }
 async #receipt(a:pg.PoolClient,principal:SessionPrincipal,r:z.infer<typeof fileReference>,requestHash:string):Promise<FileReceipt|null> {
  const row=(await a.query<{project_id:string;data_generation:string;actor_profile_id:string;request_digest:string;receipt:FileReceipt}>('SELECT * FROM app.file_operations WHERE workspace_id=$1 AND operation_id=$2',[r.workspaceId,r.operationId])).rows[0];
  if(!row)return null;
  if(row.project_id!==r.projectId||row.data_generation!==principal.dataGeneration||row.actor_profile_id!==principal.accountId||row.request_digest!==requestHash)throw changed();return row.receipt;
 }
 async #record(a:pg.PoolClient,principal:SessionPrincipal,r:z.infer<typeof fileReference>,requestHash:string,payload:unknown,action:FileReceipt['action'],fileId:string,versionId:string|null,now:Date):Promise<FileView> {
  const receipt:FileReceipt={version:1,...r,dataGeneration:principal.dataGeneration,requestHash,action,fileId,versionId,committedAt:now.toISOString()};
  await a.query(`INSERT INTO app.file_operations(workspace_id,project_id,operation_id,data_generation,actor_profile_id,request_digest,payload,receipt,created_at)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[r.workspaceId,r.projectId,r.operationId,principal.dataGeneration,principal.accountId,requestHash,payload,receipt,now]);
  await a.query(`INSERT INTO app.operation_receipts(workspace_id,id,data_generation,operation_id,actor_profile_id,project_id,action,request_digest,encrypted_envelope,created_at)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[r.workspaceId,randomUUID(),principal.dataGeneration,r.operationId,principal.accountId,r.projectId,`files.${action}`,requestHash,{receipt},now]);
  await this.options.hooks?.beforeCommit?.();return {state:'completed',receipt};
 }
 async status(cookie:string,csrf:string,input:unknown):Promise<FileView> {
  const r=parse(fileStatusRequest,input);return this.#with(cookie,csrf,ref(r),false,async(a,_p,principal)=>{
   if(r.dataGeneration!==principal.dataGeneration)throw changed();const receipt=await this.#receipt(a,principal,r,r.requestHash);return {state:receipt?'completed':'absent',receipt};
  });
 }
 async begin(cookie:string,csrf:string,input:unknown):Promise<FileView> {
  const payload=parse(fileBeginRequest,input),m=payload.manifest.body,b=m.binding,r=ref(b),requestHash=await digestObject(payload);
  const view=await this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{
   const priorReceipt=await this.#receipt(a,principal,r,requestHash);if(priorReceipt)return {state:'completed' as const,receipt:priorReceipt};
   try{assertFileBindingCurrent(b,p,now);await verifyFileManifest(payload.manifest,securityAt);}catch{throw changed();}
   this.#writeAllowed(p,m.kind,await this.#affectedTasks(a,r,m.fileId,m.taskIds));
   await this.#quotaLock(a,r.workspaceId);await this.#expire(a,r.workspaceId,now);
   const quota=await this.#usage(a,r.workspaceId),reserved=m.cipherBytes+base64urlDecode(m.metadata.ciphertext).length+24;
   if(quota.usedBytes+quota.reservedBytes+reserved>quota.limitBytes)throw new AppError('FILES_QUOTA_EXCEEDED','Workspace file storage is full; keep this file on your shared drive',413);
   if(reserved>quota.deploymentRemainingBytes)throw new AppError('FILES_CAPACITY_EXCEEDED','Cloud file storage is full; keep this file on your shared drive',413);
   if(m.storage==='managed'&&quota.activeUploads>=FILE_MAX_ACTIVE_UPLOADS)throw new AppError('FILES_UPLOAD_BUSY','Other uploads are in progress; wait or cancel an unfinished upload',429);
   const current=(await a.query<{kind:string;latest_version_id:string|null}>('SELECT kind,latest_version_id FROM app.project_files WHERE workspace_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE',[r.workspaceId,r.projectId,m.fileId])).rows[0];
   if(current) {
    if(current.kind!==m.kind||current.latest_version_id!==m.priorVersionId||!m.priorVersionId)throw changed();
    const lineage=(await a.query<{maximum:string;staged:number}>('SELECT COALESCE(max(version),0)::text AS maximum,count(*) FILTER(WHERE state=\'staged\')::int AS staged FROM app.file_versions WHERE workspace_id=$1 AND project_id=$2 AND file_id=$3',[r.workspaceId,r.projectId,m.fileId])).rows[0]!;
    if(lineage.staged)throw new AppError('FILES_UPLOAD_BUSY','Finish or cancel this file’s current upload before adding another version',409);
    const previous=await this.#versionRow(a,r,m.priorVersionId);
    if(previous.state!=='ready'||String(BigInt(lineage.maximum)+1n)!==m.version||(!this.#canManage(p)&&previous.author_profile_id!==principal.accountId))throw changed();
   } else {
    if(m.version!=='1'||m.priorVersionId!==null)throw changed();
    const count=Number((await a.query<{n:string}>('SELECT count(*)::text AS n FROM app.project_files WHERE workspace_id=$1 AND project_id=$2',[r.workspaceId,r.projectId])).rows[0]!.n);
    if(count>=FILE_MAX_PER_PROJECT)throw new AppError('FILES_PROJECT_LIMIT','This project has reached its file limit',413);
    await a.query('INSERT INTO app.project_files(workspace_id,project_id,id,kind,created_at) VALUES($1,$2,$3,$4,$5)',[r.workspaceId,r.projectId,m.fileId,m.kind,now]);
   }
   const ready=m.storage==='external',expires=new Date(now.getTime()+2*60*60*1000);
   await a.query(`INSERT INTO app.file_versions(workspace_id,project_id,file_id,id,version,data_generation,author_profile_id,author_device_id,storage,state,reserved_bytes,manifest,created_at,expires_at,completed_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,[r.workspaceId,r.projectId,m.fileId,m.versionId,m.version,principal.dataGeneration,principal.accountId,principal.deviceId,m.storage,ready?'ready':'staged',reserved,payload.manifest,now,expires,ready?now:null]);
   if(ready) {
    await a.query('UPDATE app.file_storage_usage SET used_bytes=used_bytes+$2 WHERE workspace_id=$1',[r.workspaceId,reserved]);
    await a.query('UPDATE app.project_files SET latest_version_id=$4 WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[r.workspaceId,r.projectId,m.fileId,m.versionId]);
    await this.#links(a,p,m.fileId,m.taskIds,'latest',null,'link');
   }else {
    await a.query('INSERT INTO app.file_upload_reservations(workspace_id,project_id,version_id,reserved_bytes,expires_at) VALUES($1,$2,$3,$4,$5)',[r.workspaceId,r.projectId,m.versionId,reserved,expires]);
    await a.query('UPDATE app.file_storage_usage SET reserved_bytes=reserved_bytes+$2,active_uploads=active_uploads+1 WHERE workspace_id=$1',[r.workspaceId,reserved]);
   }
   return this.#record(a,principal,r,requestHash,payload,'begin',m.fileId,m.versionId,now);
  });await this.options.hooks?.afterCommit?.();return view;
 }
 async #versionRow(a:pg.PoolClient,r:{workspaceId:string;projectId:string},versionId:string):Promise<VersionRow> {
  const row=(await a.query<VersionRow>('SELECT * FROM app.file_versions WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[r.workspaceId,r.projectId,versionId])).rows[0];if(!row)throw missing();return row;
 }
 #uploadAuthor(row:VersionRow,principal:SessionPrincipal,now:Date,p:PlanningContext):void {
  if(row.data_generation!==principal.dataGeneration||row.author_profile_id!==principal.accountId||row.author_device_id!==principal.deviceId)throw forbidden();
  if(row.state!=='staged'||row.expires_at.getTime()<=now.getTime())throw changed();
  // A bounded upload may outlive its ten-minute preparation binding. Its signed
  // bytes remain valid only while every current security/key generation agrees.
  try {assertFileBindingCurrent({...row.manifest.body.binding,operationId:p.binding.operationId,
   issuedAt:p.binding.issuedAt,expiresAt:p.binding.expiresAt},p,now);}catch{throw changed();}
 }
 async chunk(cookie:string,csrf:string,input:unknown):Promise<{state:'received';index:number;digest:string}> {
  const r=parse(fileChunkRequest,input),bytes=base64urlDecode(r.bytes),hash=await fileChunkDigest(bytes);
  return this.#with(cookie,csrf,ref(r),true,async(a,p,principal,now)=>{
   const row=await this.#versionRow(a,r,r.versionId);this.#uploadAuthor(row,principal,now,p);this.#writeAllowed(p,row.manifest.body.kind,await this.#affectedTasks(a,r,row.file_id,row.manifest.body.taskIds));
   const m=row.manifest.body,expectedPlain=Math.min(FILE_CHUNK_PLAIN_BYTES,m.plainBytes-r.index*FILE_CHUNK_PLAIN_BYTES);
   if(m.chunkHashes[r.index]!==hash||bytes.length!==expectedPlain+FILE_CHUNK_OVERHEAD)throw invalid();
   const existing=(await a.query<{cipher_digest:string}>('SELECT cipher_digest FROM app.file_chunks WHERE workspace_id=$1 AND version_id=$2 AND chunk_index=$3',[r.workspaceId,r.versionId,r.index])).rows[0];
   if(existing&&existing.cipher_digest!==hash)throw changed();
   if(!existing)await a.query('INSERT INTO app.file_chunks(workspace_id,project_id,version_id,chunk_index,cipher_bytes,cipher_digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)',[r.workspaceId,r.projectId,r.versionId,r.index,Buffer.from(bytes),hash,now]);
   return {state:'received' as const,index:r.index,digest:hash};
  });
 }
 async complete(cookie:string,csrf:string,input:unknown):Promise<FileView> {
  const r=parse(fileVersionRequest,input),requestHash=await digestObject(r);
  const view=await this.#with(cookie,csrf,r,true,async(a,p,principal,now)=>{
   const receipt=await this.#receipt(a,principal,r,requestHash);if(receipt)return {state:'completed' as const,receipt};
   const row=await this.#versionRow(a,r,r.versionId);this.#uploadAuthor(row,principal,now,p);const m=row.manifest.body;this.#writeAllowed(p,m.kind,await this.#affectedTasks(a,r,row.file_id,m.taskIds));
   const chunks=(await a.query<{chunk_index:number;cipher_digest:string;n:string}>('SELECT chunk_index,cipher_digest,octet_length(cipher_bytes)::text AS n FROM app.file_chunks WHERE workspace_id=$1 AND version_id=$2 ORDER BY chunk_index',[r.workspaceId,r.versionId])).rows;
   if(chunks.length!==m.chunkHashes.length||chunks.some((c,i)=>c.chunk_index!==i||c.cipher_digest!==m.chunkHashes[i])||chunks.reduce((n,c)=>n+Number(c.n),0)!==m.cipherBytes)
    throw new AppError('FILES_UPLOAD_INCOMPLETE','Some file parts are missing; resume the upload before saving',409);
   for(const chunk of chunks){
    const bytes=(await a.query<{cipher_bytes:Buffer}>('SELECT cipher_bytes FROM app.file_chunks WHERE workspace_id=$1 AND version_id=$2 AND chunk_index=$3',[r.workspaceId,r.versionId,chunk.chunk_index])).rows[0]?.cipher_bytes;
    if(!bytes||await fileChunkDigest(bytes)!==m.chunkHashes[chunk.chunk_index])throw changed();
   }
   await this.#quotaLock(a,r.workspaceId);
   const head=(await a.query<{latest_version_id:string|null}>('SELECT latest_version_id FROM app.project_files WHERE workspace_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE',[r.workspaceId,r.projectId,row.file_id])).rows[0];
   if(!head||head.latest_version_id!==m.priorVersionId)throw changed();
   await a.query("UPDATE app.file_versions SET state='ready',completed_at=$3 WHERE workspace_id=$1 AND id=$2 AND state='staged'",[r.workspaceId,r.versionId,now]);
   await a.query('UPDATE app.project_files SET latest_version_id=$4 WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[r.workspaceId,r.projectId,row.file_id,r.versionId]);
   await a.query('DELETE FROM app.file_upload_reservations WHERE workspace_id=$1 AND version_id=$2',[r.workspaceId,r.versionId]);
   await a.query('UPDATE app.file_storage_usage SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes+$2,active_uploads=active_uploads-1 WHERE workspace_id=$1',[r.workspaceId,row.reserved_bytes]);
   await this.#links(a,p,row.file_id,m.taskIds,'latest',null,'link');
   return this.#record(a,principal,r,requestHash,r,'complete',row.file_id,r.versionId,now);
  });await this.options.hooks?.afterCommit?.();return view;
 }
 async cancel(cookie:string,csrf:string,input:unknown):Promise<FileView> {
  const r=parse(fileCancelRequest,input),requestHash=await digestObject({...r,action:'cancel'});
  const view=await this.#with(cookie,csrf,r,true,async(a,_p,principal,now)=>{
   const receipt=await this.#receipt(a,principal,r,requestHash);if(receipt)return {state:'completed' as const,receipt};
   const row=await this.#versionRow(a,r,r.versionId);if(row.author_profile_id!==principal.accountId||row.data_generation!==principal.dataGeneration||row.state!=='staged')throw changed();
   await this.#quotaLock(a,r.workspaceId);await a.query('DELETE FROM app.file_chunks WHERE workspace_id=$1 AND version_id=$2',[r.workspaceId,r.versionId]);
   await a.query("UPDATE app.file_versions SET state='cancelled',completed_at=$3 WHERE workspace_id=$1 AND id=$2",[r.workspaceId,r.versionId,now]);
   await a.query('DELETE FROM app.file_upload_reservations WHERE workspace_id=$1 AND version_id=$2',[r.workspaceId,r.versionId]);
   await a.query('UPDATE app.file_storage_usage SET reserved_bytes=reserved_bytes-$2,active_uploads=active_uploads-1,used_bytes=used_bytes+$3 WHERE workspace_id=$1',[r.workspaceId,row.reserved_bytes,Number(row.reserved_bytes)-row.manifest.body.cipherBytes]);
   return this.#record(a,principal,r,requestHash,{...r,action:'cancel'},'cancel',row.file_id,r.versionId,now);
  });await this.options.hooks?.afterCommit?.();return view;
 }
 async #links(a:pg.PoolClient,p:PlanningContext,fileId:string,taskIds:string[],mode:'latest'|'pinned',versionId:string|null,action:'link'|'unlink'):Promise<void> {
  const b=p.binding;if(!taskIds.length)return;
  const linked=(await a.query<{task_id:string}>('SELECT DISTINCT task_id FROM app.task_file_links WHERE workspace_id=$1 AND project_id=$2',[b.workspaceId,b.projectId])).rows.map(r=>r.task_id);
  if(action==='link'&&new Set([...linked,...taskIds]).size>FILE_MAX_DOCUMENT_TASKS)throw new AppError('FILES_TASK_LIMIT','This project has reached its document task limit',413);
  for(const taskId of taskIds) {
   if(action==='unlink')await a.query('DELETE FROM app.task_file_links WHERE workspace_id=$1 AND task_id=$2 AND file_id=$3',[b.workspaceId,taskId,fileId]);
   else await a.query(`INSERT INTO app.task_file_links(workspace_id,project_id,task_id,file_id,mode,version_id) VALUES($1,$2,$3,$4,$5,$6)
    ON CONFLICT(workspace_id,task_id,file_id) DO UPDATE SET mode=EXCLUDED.mode,version_id=EXCLUDED.version_id`,[b.workspaceId,b.projectId,taskId,fileId,mode,versionId]);
  }
 }
 async link(cookie:string,csrf:string,input:unknown):Promise<FileView> {
  const payload=parse(fileLinkRequest,input),body=payload.mutation.body,b=body.binding,r=ref(b),requestHash=await digestObject(payload);
  const view=await this.#with(cookie,csrf,r,true,async(a,p,principal,now)=>{
   const receipt=await this.#receipt(a,principal,r,requestHash);if(receipt)return {state:'completed' as const,receipt};
   try{assertFileBindingCurrent(b,p,now);if(!await verifyObject(payload.mutation,base64urlDecode(b.signingPublicKey),'ukda.file-links.v1'))throw invalid();}catch{throw changed();}
   const file=(await a.query<{kind:'source'|'output';latest_version_id:string|null}>('SELECT kind,latest_version_id FROM app.project_files WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[r.workspaceId,r.projectId,body.fileId])).rows[0];
   if(!file?.latest_version_id)throw missing();this.#writeAllowed(p,file.kind,body.taskIds);
   if(body.versionId){const version=await this.#versionRow(a,r,body.versionId);if(version.file_id!==body.fileId||version.state!=='ready')throw changed();}
   if(!this.#canManage(p)){const version=await this.#versionRow(a,r,file.latest_version_id);if(version.author_profile_id!==principal.accountId)throw forbidden();}
   await this.#links(a,p,body.fileId,body.taskIds,body.mode,body.versionId,body.action);
   return this.#record(a,principal,r,requestHash,payload,body.action,body.fileId,body.versionId,now);
  });await this.options.hooks?.afterCommit?.();return view;
 }
 async #version(a:pg.PoolClient,row:VersionRow,securityAt:PlanningSecurityResolver):Promise<FileVersion> {
  try{await verifyFileManifest(row.manifest,securityAt);}catch{throw changed();}
  const m=row.manifest.body;if(m.fileId!==row.file_id||m.versionId!==row.id||m.version!==row.version||m.binding.workspaceId!==row.workspace_id||m.binding.projectId!==row.project_id||m.binding.dataGeneration!==row.data_generation)throw changed();
  const received=(await a.query<{chunk_index:number}>('SELECT chunk_index FROM app.file_chunks WHERE workspace_id=$1 AND version_id=$2 ORDER BY chunk_index',[row.workspace_id,row.id])).rows;
  return {manifest:row.manifest,state:row.state,createdAt:row.created_at.toISOString(),completedAt:row.completed_at?.toISOString()??null,receivedIndexes:received.map(r=>r.chunk_index)};
 }
 async version(cookie:string,csrf:string,input:unknown):Promise<FileVersion> {
  const r=parse(fileVersionRequest,input);return this.#with(cookie,csrf,r,false,async(a,_p,_principal,_now,securityAt)=>this.#version(a,await this.#versionRow(a,r,r.versionId),securityAt));
 }
 async versions(cookie:string,csrf:string,input:unknown):Promise<FileVersionPage> {
  const r=parse(fileVersionsRequest,input);return this.#with(cookie,csrf,r,false,async(a,_p,_principal,_now,securityAt)=>{
   const rows=(await a.query<VersionRow>('SELECT * FROM app.file_versions WHERE workspace_id=$1 AND project_id=$2 AND file_id=$3 AND version>$4 ORDER BY version LIMIT $5',[r.workspaceId,r.projectId,r.fileId,r.afterVersion,r.limit+1])).rows;
   const selected=rows.slice(0,r.limit),versions:FileVersion[]=[];for(const row of selected)versions.push(await this.#version(a,row,securityAt));
   return {versions,nextVersion:rows.length>r.limit?selected.at(-1)!.version:null,complete:rows.length<=r.limit};
  });
 }
 async list(cookie:string,csrf:string,input:unknown):Promise<FilePage> {
  const r=parse(fileListRequest,input);return this.#with(cookie,csrf,r,false,async(a,p,_principal,_now,securityAt)=>{
   if(r.taskId&&!p.graph.tasks.some(t=>t.id===r.taskId))throw missing();
   const rows=(await a.query<{id:string;kind:'source'|'output';latest_version_id:string}>(`SELECT f.id,f.kind,f.latest_version_id FROM app.project_files f
    WHERE f.workspace_id=$1 AND f.project_id=$2 AND f.latest_version_id IS NOT NULL AND ($3::uuid IS NULL OR f.id>$3) AND ($4::text IS NULL OR f.kind=$4)
     AND ($5::uuid IS NULL OR EXISTS(SELECT 1 FROM app.task_file_links l WHERE l.workspace_id=f.workspace_id AND l.file_id=f.id AND l.task_id=$5)) ORDER BY f.id LIMIT $6`,
    [r.workspaceId,r.projectId,r.after??null,r.kind??null,r.taskId??null,r.limit+1])).rows;
   const selected=rows.slice(0,r.limit),entries:FileEntry[]=[];
   for(const row of selected){const version=await this.#version(a,await this.#versionRow(a,r,row.latest_version_id),securityAt);
    const links=(await a.query<{task_id:string;mode:'latest'|'pinned';version_id:string|null}>('SELECT task_id,mode,version_id FROM app.task_file_links WHERE workspace_id=$1 AND project_id=$2 AND file_id=$3 ORDER BY task_id',[r.workspaceId,r.projectId,row.id])).rows;
    entries.push({fileId:row.id,kind:row.kind,latestVersionId:row.latest_version_id,version,links:links.map(l=>({taskId:l.task_id,mode:l.mode,versionId:l.version_id}))});}
   return {entries,nextCursor:rows.length>r.limit?selected.at(-1)!.id:null,complete:rows.length<=r.limit,quota:await this.#usage(a,r.workspaceId)};
  });
 }
 async readChunk(cookie:string,csrf:string,input:unknown):Promise<{index:number;bytes:string;digest:string}> {
  const r=parse(fileReadChunkRequest,input);return this.#with(cookie,csrf,r,false,async(a,p,_principal,_now,securityAt)=>{
   if(r.purpose==='download'&&!p.binding.isOwner&&!(p.binding.permissions as readonly string[]).includes('download_files'))throw forbidden();
   const row=await this.#versionRow(a,r,r.versionId);if(row.state!=='ready'||row.storage!=='managed')throw missing();await this.#version(a,row,securityAt);
   const chunk=(await a.query<{cipher_bytes:Buffer;cipher_digest:string}>('SELECT cipher_bytes,cipher_digest FROM app.file_chunks WHERE workspace_id=$1 AND version_id=$2 AND chunk_index=$3',[r.workspaceId,r.versionId,r.index])).rows[0];
   if(!chunk)throw missing();if(chunk.cipher_digest!==row.manifest.body.chunkHashes[r.index]||await fileChunkDigest(chunk.cipher_bytes)!==chunk.cipher_digest)throw changed();
   return {index:r.index,bytes:base64urlEncode(chunk.cipher_bytes),digest:chunk.cipher_digest};
  });
 }
 async #editorService(a:pg.PoolClient,p:PlanningContext,serviceId:string,securityAt:PlanningSecurityResolver){
  const b=p.binding,row=(await a.query<{id:string;public_key:string;data_generation:string;state:'active'|'revoked';approved_pairing:z.infer<typeof deliveryPairRequest>}>("SELECT * FROM app.file_local_services WHERE workspace_id=$1 AND project_id=$2 AND id=$3 AND state='active' AND data_generation=$4",[b.workspaceId,b.projectId,serviceId,b.dataGeneration])).rows[0];
  if(!row)throw new AppError('FILES_EDITOR_UNAVAILABLE','Connect an approved local file service to open the editor',409);
  const pair=parse(deliveryPairRequest,row.approved_pairing);try{await verifyOwnerFileObject(pair.approval,securityAt,'ukda.file-service-pair.v1');
   if(pair.approval.body.serviceId!==row.id||pair.approval.body.publicKey!==row.public_key||pair.approval.body.binding.workspaceId!==b.workspaceId||pair.approval.body.binding.projectId!==b.projectId||pair.approval.body.binding.dataGeneration!==b.dataGeneration||
    !await verifyObject({body:pair.approval.body,signature:pair.proof},base64urlDecode(row.public_key),'ukda.file-service-pair.v1'))throw changed();
  }catch{throw changed();}
  // Mutable registry state cannot revive an immutable, signed revocation.
  const revoked=(await a.query<{payload:unknown}>(`SELECT payload FROM app.file_delivery_operations WHERE workspace_id=$1 AND project_id=$2 AND data_generation=$3
    AND receipt->>'action'='revoke_service' AND payload->'mutation'->'body'->>'serviceId'=$4`,[b.workspaceId,b.projectId,b.dataGeneration,serviceId])).rows;
  for(const operation of revoked){const command=parse(deliveryServiceCommandRequest,operation.payload);try{await verifyOwnerFileObject(command.mutation,securityAt,'ukda.file-service-revoke.v1');}catch{throw changed();}
   if(command.mutation.body.publicKey===row.public_key)throw new AppError('FILES_EDITOR_UNAVAILABLE','This local file service was disconnected',409);}
  return row;
 }
 async editorServices(cookie:string,csrf:string,input:unknown){const r=parse(fileReference,input);return this.#with(cookie,csrf,r,false,async(a,p,_principal,_now,securityAt)=>{
  const rows=(await a.query<{id:string}>('SELECT id FROM app.file_local_services WHERE workspace_id=$1 AND project_id=$2 AND state=\'active\' AND data_generation=$3 ORDER BY id LIMIT 101',[r.workspaceId,r.projectId,p.binding.dataGeneration])).rows;
  if(rows.length>100)throw new AppError('FILES_EDITOR_LIMIT','This project has reached its local service limit',413);
  const services=[];for(const row of rows){const service=await this.#editorService(a,p,row.id,securityAt);services.push({serviceId:service.id,publicKey:service.public_key,state:service.state,dataGeneration:service.data_generation,approval:service.approved_pairing});}return {services};
 });}
 async editorPermit(cookie:string,csrf:string,input:unknown):Promise<FileEditorPermit>{const r=parse(fileEditorPermitRequest,input);return this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{
  const row=await this.#versionRow(a,r,r.versionId);if(row.state!=='ready'||row.storage!=='managed')throw missing();await this.#version(a,row,securityAt);
  this.#writeAllowed(p,row.manifest.body.kind,await this.#affectedTasks(a,r,row.file_id,row.manifest.body.taskIds));
  const file=(await a.query<{latest_version_id:string|null}>('SELECT latest_version_id FROM app.project_files WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[r.workspaceId,r.projectId,row.file_id])).rows[0];if(file?.latest_version_id!==r.versionId)throw changed();
  await this.#editorService(a,p,r.serviceId,securityAt);const b=p.binding,body={purpose:'ukda.file-edit-permit.v1' as const,keyId:this.options.secrets.keyId,origin:this.options.origin,
   workspaceId:r.workspaceId,projectId:r.projectId,serviceId:r.serviceId,versionId:r.versionId,manifestDigest:await digestObject(row.manifest),accountId:principal.accountId,deviceId:principal.deviceId!,
   credentialGeneration:principal.credentialGeneration,sessionGeneration:principal.sessionGeneration,dataGeneration:principal.dataGeneration,permissionVersion:b.permissionVersion,keyEpoch:b.keyEpoch,
   issuedAt:now.toISOString(),expiresAt:new Date(now.getTime()+30000).toISOString(),permitId:randomUUID(),nonce:this.options.secrets.token()};
  await sodium.ready;const seed=this.options.secrets.digest('entitlement-signing-key',this.options.secrets.keyId),pair=sodium.crypto_sign_seed_keypair(seed);let permit:FileEditorPermit;
  try{permit=fileEditorPermit.parse(await signObject(body,pair.privateKey));}finally{seed.fill(0);pair.privateKey.fill(0);}
  await a.query('INSERT INTO app.file_editor_permits(workspace_id,project_id,id,version_id,service_id,actor_profile_id,device_id,signed_permit,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[r.workspaceId,r.projectId,body.permitId,r.versionId,r.serviceId,principal.accountId,principal.deviceId,permit,now,body.expiresAt]);return permit;
 });}
}

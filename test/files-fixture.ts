import {randomUUID} from 'node:crypto';
import type {TestContext} from 'node:test';
import {transaction} from '../src/db.js';
import {FilesService} from '../src/modules/files/service.js';
import {prepareFile} from '../src/client/files-crypto.js';
import {FILE_CHUNK_PLAIN_BYTES} from '../src/shared/files.js';
import {planningFixture} from './planning-fixture.js';
import {origin} from './password-change-fixture.js';
export async function fileServiceFixture(t:TestContext){
 let f:Awaited<ReturnType<typeof planningFixture>>;
 t.after(async()=>{if(f)await transaction(f.admin.application,async c=>{
  await c.query("SET LOCAL session_replication_role='replica'");
  for(const table of ['file_editor_permits','file_delivery_permits','file_service_pairings','file_local_services','file_delivery_operations','file_delivery_batches','file_approval_revocations','file_review_items','file_reviews','file_submissions','file_evidence_operations','file_chunks','file_upload_reservations','task_file_links','file_operations','file_versions','project_files','file_storage_usage'])
   await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`,[f.workspaceId]);
 });});
 f=await planningFixture(t);let hooks:NonNullable<ConstructorParameters<typeof FilesService>[0]['hooks']>={};
 const make=()=>new FilesService({...f,origin,planning:f.planning,hooks});let files=make();
 const reference=()=>({workspaceId:f.workspaceId,projectId:f.projectId,operationId:randomUUID()});
 async function prepared(kind:'source'|'output'='source',options:{taskIds?:string[];storage?:'managed'|'external';fileId?:string;version?:string;priorVersionId?:string|null;size?:number}={},auth=f.auth(),bundle=f.originalBundle){
  const context=await files.context(auth.cookieValue,auth.csrfToken,reference()),bytes=new Uint8Array(options.size??FILE_CHUNK_PLAIN_BYTES+7);bytes.fill(65);
  const result=await prepareFile({context:context.planning,history:await f.history(),accountId:context.binding.accountId,deviceId:context.binding.deviceId,binding:context.binding,
   fileId:options.fileId??randomUUID(),versionId:randomUUID(),version:options.version??'1',priorVersionId:options.priorVersionId??null,kind,storage:options.storage??'managed',
   taskIds:options.taskIds??[],file:new Blob([bytes]),metadata:{filename:'Private source.txt',mediaType:'text/plain',documentReference:randomUUID(),label:'Private label',
   ...(options.storage==='external'?{path:'/Volumes/Private organisation share/private source.txt'}:{})}},bundle);
  return {...result,bytes};
 }
 async function upload(p:Awaited<ReturnType<typeof prepared>>,auth=f.auth()){
  await files.begin(auth.cookieValue,auth.csrfToken,{manifest:p.manifest});
  for(let i=0;i<p.chunks.length;i++)await files.chunk(auth.cookieValue,auth.csrfToken,{...reference(),versionId:p.manifest.body.versionId,index:i,bytes:p.chunks[i]});
  if(p.chunks.length)await files.complete(auth.cookieValue,auth.csrfToken,{...reference(),versionId:p.manifest.body.versionId});return p;
 }
 return {...f,get files(){return files;},reference,prepared,upload,setFileHooks(next:typeof hooks={}){hooks=next;files=make();}};
}

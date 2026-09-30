import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {transaction} from '../src/db.js';
import {AppError} from '../src/errors.js';
import {base64urlDecode,base64urlEncode} from '../src/shared/crypto.js';
import {RESTORE_FILE_TABLES,RESTORE_DISPOSABLE_FILE_TABLES,RESTORE_LEGACY_TABLES,type RestoreCheckpointManifest} from '../src/shared/restoration.js';
import {signRestoreService} from '../src/modules/restoration/manifest.js';
import {digestObject} from '../src/shared/crypto.js';
import {FilesService} from '../src/modules/files/service.js';
import {prepareFile,readFiles,readFileBytes} from '../src/client/files-crypto.js';
import {readRestoration,prepareRestorationVerification} from '../src/client/restoration-crypto.js';
import {restorationFixture} from './restoration-fixture.js';
import {origin} from './password-change-fixture.js';

test('file restoration verifies all immutable ciphertext, retains readable versions and external metadata, and cancels old writes',async t=>{
 let f:Awaited<ReturnType<typeof restorationFixture>>;
 t.after(async()=>{if(f)await transaction(f.admin.application,async c=>{await c.query("SET LOCAL session_replication_role='replica'");
  for(const table of [...RESTORE_DISPOSABLE_FILE_TABLES,...RESTORE_FILE_TABLES])await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`,[f.workspaceId]);});});
 f=await restorationFixture(t);const files=new FilesService({...f,origin,planning:f.planning}),reference=()=>({workspaceId:f.workspaceId,projectId:f.projectId,operationId:randomUUID()});
 async function upload(size:number,prior?:Awaited<ReturnType<typeof prepareFile>>,external=false,finish=true){
  const auth=f.auth(),context=await files.context(auth.cookieValue,auth.csrfToken,reference()),bytes=new Uint8Array(size).fill(65+size%26),file=new Blob([bytes]);
  const prepared=await prepareFile({context:context.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId,binding:context.binding,
   fileId:prior?.manifest.body.fileId??randomUUID(),versionId:randomUUID(),version:prior?'2':'1',priorVersionId:prior?.manifest.body.versionId??null,
   kind:'source',storage:external?'external':'managed',taskIds:[],file,metadata:{filename:'Private document.txt',mediaType:'text/plain',documentReference:randomUUID(),label:'',
    ...(external?{path:'/Volumes/Organisation share/Private document.txt'}:{})}},f.originalBundle);
  await files.begin(auth.cookieValue,auth.csrfToken,{manifest:prepared.manifest});
  for(const [index,chunk]of prepared.chunks.entries())await files.chunk(auth.cookieValue,auth.csrfToken,{...reference(),versionId:prepared.manifest.body.versionId,index,bytes:chunk});
  if(!external&&finish)await files.complete(auth.cookieValue,auth.csrfToken,{...reference(),versionId:prepared.manifest.body.versionId});
  return {...prepared,bytes};
 }
 const first=await upload(100),second=await upload(200,first),external=await upload(80,undefined,true),pending=await upload(70,undefined,false,false);
 const checkpoint=await f.checkpoint();assert.equal(checkpoint.manifest.body.version,2);
 if(checkpoint.manifest.body.version!==2)assert.fail('Expected file-aware checkpoint');
 assert.equal(checkpoint.manifest.body.inventory.files.length,3);assert.equal(checkpoint.manifest.body.inventory.tables.find(t=>t.table==='file_chunks')!.count,3);
 assert.equal(checkpoint.manifest.body.inventory.files.find(v=>v.versionId===first.manifest.body.versionId)!.current,false);
 const restoreId=await f.begin(checkpoint.manifest);await f.install();await f.restoration.reconcile({workspaceId:f.workspaceId,restoreId});
 const auth=await f.restoreLogin(),context=await f.restoration.context(auth,{workspaceId:f.workspaceId,restoreId,operationId:randomUUID()}),history=await f.history();
 const input={context,history,accountId:f.accountId,deviceId:f.deviceId},report=await readRestoration(input,f.originalBundle);assert.equal(report.verifiedFileSamples,3);
 assert.equal(context.fileSamples!.find(s=>s.manifest.body.storage==='external')!.chunk,null);
 const changed=structuredClone(context),sample=changed.fileSamples!.find(s=>s.chunk!==null)!,bytes=base64urlDecode(sample.chunk!);bytes[30]=bytes[30]!^1;sample.chunk=base64urlEncode(bytes);
 await assert.rejects(prepareRestorationVerification({...input,context:changed},f.originalBundle));
 const proof=await prepareRestorationVerification(input,f.originalBundle);assert.equal(proof.body.purpose,'ukda.restore-verify.v2');assert.equal((await f.restoration.verify(auth,proof)).state,'completed');
 const restored=await files.context(auth.cookieValue,auth.csrfToken,reference()),readInput={context:restored.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId};
 assert.equal(restored.binding.dataGeneration,String(BigInt(first.manifest.body.binding.dataGeneration)+1n));
 for(const prepared of [first,second]){const version=await files.version(auth.cookieValue,auth.csrfToken,{...reference(),versionId:prepared.manifest.body.versionId});
  const chunk=await files.readChunk(auth.cookieValue,auth.csrfToken,{...reference(),versionId:prepared.manifest.body.versionId,index:0,purpose:'download'});
  assert.deepEqual(await readFileBytes({...readInput,manifest:version.manifest,chunks:[chunk.bytes]},f.originalBundle),prepared.bytes);}
 const [metadata]=await readFiles({...readInput,manifests:[external.manifest]},f.originalBundle);assert.equal(metadata!.metadata.path,'/Volumes/Organisation share/Private document.txt');
 await assert.rejects(files.readChunk(auth.cookieValue,auth.csrfToken,{...reference(),versionId:external.manifest.body.versionId,index:0,purpose:'download'}));
 await assert.rejects(files.begin(auth.cookieValue,auth.csrfToken,{manifest:pending.manifest}),e=>e instanceof AppError&&['FILES_CHANGED','STALE_GENERATION'].includes(e.code));
 const pendingRow=(await f.admin.application.query('SELECT state FROM app.file_versions WHERE workspace_id=$1 AND id=$2',[f.workspaceId,pending.manifest.body.versionId])).rows[0];assert.equal(pendingRow.state,'cancelled');
 const quota=(await f.admin.application.query('SELECT active_uploads,reserved_bytes FROM app.file_storage_usage WHERE workspace_id=$1',[f.workspaceId])).rows[0];assert.equal(quota.active_uploads,0);assert.equal(quota.reserved_bytes,'0');
 assert.equal((await f.admin.application.query('SELECT 1 FROM app.file_chunks WHERE workspace_id=$1 AND version_id=$2',[f.workspaceId,pending.manifest.body.versionId])).rowCount,0);
});

test('original version-1 signed recovery checkpoints retain their original catalogue and Owner acknowledgement',async t=>{
 const f=await restorationFixture(t),captured=await f.checkpoint(),body=captured.manifest.body;
 const inventory={tables:body.inventory.tables.filter(t=>(RESTORE_LEGACY_TABLES as readonly string[]).includes(t.table)),objects:body.inventory.objects,keyEpochs:body.inventory.keyEpochs,projectIds:body.inventory.projectIds,keyObjects:body.inventory.keyObjects};
 const checkpoint=await signRestoreService<Extract<RestoreCheckpointManifest['body'],{version:1}>>(f.secrets,{version:1,purpose:'ukda.content-checkpoint.v1',workspaceId:f.workspaceId,checkpointId:randomUUID(),capturedAt:body.capturedAt,source:body.source,inventory});
 await f.admin.control.query('INSERT INTO security.content_checkpoints(workspace_id,checkpoint_id,manifest_digest,manifest,created_at) VALUES($1,$2,$3,$4,$5)',[f.workspaceId,checkpoint.body.checkpointId,await digestObject(checkpoint),checkpoint,checkpoint.body.capturedAt]);
 const restoreId=await f.begin(checkpoint);await f.install();await f.restoration.reconcile({workspaceId:f.workspaceId,restoreId});const auth=await f.restoreLogin(),proof=await f.restoreProof(restoreId,auth);
 assert.equal(proof.body.purpose,'ukda.restore-verify.v1');assert.equal((await f.restoration.verify(auth,proof)).state,'completed');
});

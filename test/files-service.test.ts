import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import {fileServiceFixture as fixture} from './files-fixture.js';
import { AppError } from '../src/errors.js';
import { prepareFileLink, readFileBytes, readFiles } from '../src/client/files-crypto.js';
import { digestObject } from '../src/shared/crypto.js';
const code=(expected:string)=>(e:unknown)=>e instanceof AppError&&e.code===expected;
test('Files durable lifecycle: exact encrypted chunks, shared sources and immutable versions round-trip through current project access',async t=>{
 const f=await fixture(t),auth=f.auth(),taskIds=[randomUUID(),randomUUID()];
 for(const taskId of taskIds)await f.execute({action:'create_task',task:{id:taskId,phaseId:null,milestoneId:null,assigneeIds:[f.accountId],leadProfileId:null}},{content:{title:'Document work'}});
 const first=await f.upload(await f.prepared('source',{taskIds}));
 const page=await f.files.list(auth.cookieValue,auth.csrfToken,f.reference());assert.equal(page.entries.length,1);assert.equal(page.entries[0]!.links.length,2);
 const readContext=await f.files.context(auth.cookieValue,auth.csrfToken,f.reference()),chunks=[];
 for(let i=0;i<first.chunks.length;i++)chunks.push((await f.files.readChunk(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:first.manifest.body.versionId,index:i,purpose:'download'})).bytes);
 const decoded=await readFileBytes({context:readContext.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId,manifest:first.manifest,chunks},f.originalBundle);
 assert.deepEqual(decoded,first.bytes);const privateRows=await readFiles({context:readContext.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId,manifests:[first.manifest]},f.originalBundle);
 assert.equal(privateRows[0]!.metadata.filename,'Private source.txt');assert.equal('fileKey'in privateRows[0]!.metadata,false);
 const second=await f.upload(await f.prepared('source',{fileId:first.manifest.body.fileId,version:'2',priorVersionId:first.manifest.body.versionId}));
 assert.equal((await f.files.versions(auth.cookieValue,auth.csrfToken,{...f.reference(),fileId:first.manifest.body.fileId})).versions.length,2);
 assert.equal((await f.files.version(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:first.manifest.body.versionId})).manifest.body.version,'1');
 assert.equal((await f.files.list(auth.cookieValue,auth.csrfToken,f.reference())).entries[0]!.latestVersionId,second.manifest.body.versionId);
 const abandoned=await f.prepared('source',{fileId:first.manifest.body.fileId,version:'3',priorVersionId:second.manifest.body.versionId});await f.files.begin(auth.cookieValue,auth.csrfToken,{manifest:abandoned.manifest});
 await f.files.cancel(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:abandoned.manifest.body.versionId});
 const fourth=await f.upload(await f.prepared('source',{fileId:first.manifest.body.fileId,version:'4',priorVersionId:second.manifest.body.versionId}));assert.equal(fourth.manifest.body.priorVersionId,second.manifest.body.versionId);
 await assert.rejects(f.admin.application.query('UPDATE app.file_versions SET manifest=$3 WHERE workspace_id=$1 AND id=$2',[f.workspaceId,first.manifest.body.versionId,second.manifest]));
 assert.equal(JSON.stringify((await f.admin.application.query('SELECT manifest FROM app.file_versions WHERE workspace_id=$1',[f.workspaceId])).rows).includes('Private source.txt'),false);
});
test('Files interrupted upload: retry identity is generation-bound, partial chunks resume, cancel releases staged bytes and commit is atomic',async t=>{
 const f=await fixture(t),auth=f.auth(),p=await f.prepared(),begin={manifest:p.manifest};
 const initial=await f.files.begin(auth.cookieValue,auth.csrfToken,begin);assert.deepEqual(await f.files.begin(auth.cookieValue,auth.csrfToken,begin),initial);
 await f.files.chunk(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:p.manifest.body.versionId,index:0,bytes:p.chunks[0]});
 assert.deepEqual((await f.files.version(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:p.manifest.body.versionId})).receivedIndexes,[0]);
 const complete={...f.reference(),versionId:p.manifest.body.versionId};await assert.rejects(f.files.complete(auth.cookieValue,auth.csrfToken,complete),code('FILES_UPLOAD_INCOMPLETE'));
 const changed=structuredClone(begin);changed.manifest.body.metadata.nonce=p.manifest.body.metadata.ciphertext;
 await assert.rejects(f.files.begin(auth.cookieValue,auth.csrfToken,changed),code('FILES_INVALID'));
 for(let i=1;i<p.chunks.length;i++)await f.files.chunk(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:p.manifest.body.versionId,index:i,bytes:p.chunks[i]});
 f.setFileHooks({beforeCommit:async()=>{throw new Error('Injected commit failure');}});
 await assert.rejects(f.files.complete(auth.cookieValue,auth.csrfToken,complete),code('FILES_UNAVAILABLE'));f.setFileHooks();
 assert.equal((await f.files.version(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:p.manifest.body.versionId})).state,'staged');
 f.setFileHooks({afterCommit:async()=>{throw new Error('Lost response');}});await assert.rejects(f.files.complete(auth.cookieValue,auth.csrfToken,complete),/Lost response/);f.setFileHooks();
 const status=await f.files.status(auth.cookieValue,auth.csrfToken,{workspaceId:complete.workspaceId,projectId:complete.projectId,operationId:complete.operationId,dataGeneration:p.manifest.body.binding.dataGeneration,requestHash:await digestObject(complete)});
 assert.equal(status.state,'completed');assert.deepEqual(await f.files.complete(auth.cookieValue,auth.csrfToken,complete),status);
 const cancelled=await f.prepared();await f.files.begin(auth.cookieValue,auth.csrfToken,{manifest:cancelled.manifest});
 const before=(await f.files.context(auth.cookieValue,auth.csrfToken,f.reference())).quota;await f.files.cancel(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:cancelled.manifest.body.versionId});
 const after=(await f.files.context(auth.cookieValue,auth.csrfToken,f.reference())).quota;assert.equal(before.activeUploads,1);assert.equal(after.activeUploads,0);assert.equal(after.reservedBytes,0);assert.ok(after.usedBytes>p.manifest.body.cipherBytes);
});
test('Files external references stay encrypted, retain shared version identity and cannot be read as cloud bytes',async t=>{
 const f=await fixture(t),auth=f.auth(),p=await f.upload(await f.prepared('source',{storage:'external'}));
 assert.equal((await f.files.version(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:p.manifest.body.versionId})).state,'ready');
 await assert.rejects(f.files.readChunk(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:p.manifest.body.versionId,index:0,purpose:'download'}),code('FILES_NOT_FOUND'));
 assert.equal((await f.admin.application.query('SELECT 1 FROM app.file_chunks WHERE workspace_id=$1',[f.workspaceId])).rowCount,0);
 assert.equal(JSON.stringify((await f.admin.application.query('SELECT * FROM app.file_versions WHERE workspace_id=$1',[f.workspaceId])).rows).includes('/Volumes/'),false);
 const taskId=randomUUID();await f.execute({action:'create_task',task:{id:taskId,phaseId:null,milestoneId:null,assigneeIds:[f.accountId],leadProfileId:null}},{content:{title:'External document work'}});
 const context=await f.files.context(auth.cookieValue,auth.csrfToken,f.reference()),payload=await prepareFileLink({context:context.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId,
  binding:context.binding,fileId:p.manifest.body.fileId,taskIds:[taskId],mode:'pinned',versionId:p.manifest.body.versionId,action:'link'},f.originalBundle);
 await f.files.link(auth.cookieValue,auth.csrfToken,payload);assert.equal((await f.files.list(auth.cookieValue,auth.csrfToken,{...f.reference(),taskId})).entries[0]!.links[0]!.versionId,p.manifest.body.versionId);
});
test('Files admission enforces workspace quota, bounded concurrent reservations and current author access',async t=>{
 const f=await fixture(t),auth=f.auth(),pending=[];
 for(let i=0;i<4;i++){const p=await f.prepared();await f.files.begin(auth.cookieValue,auth.csrfToken,{manifest:p.manifest});pending.push(p);}
 const fifth=await f.prepared();await assert.rejects(f.files.begin(auth.cookieValue,auth.csrfToken,{manifest:fifth.manifest}),code('FILES_UPLOAD_BUSY'));
 await f.files.cancel(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:pending[0]!.manifest.body.versionId});
 await f.files.begin(auth.cookieValue,auth.csrfToken,{manifest:fifth.manifest});
 await f.admin.application.query('UPDATE app.file_storage_usage SET used_bytes=$2 WHERE workspace_id=$1',[f.workspaceId,2*1024**3]);
 const external=await f.prepared('source',{storage:'external'});await assert.rejects(f.files.begin(auth.cookieValue,auth.csrfToken,{manifest:external.manifest}),code('FILES_QUOTA_EXCEEDED'));
 const other=await fixture(t);await assert.rejects(f.files.list(other.auth().cookieValue,other.auth().csrfToken,f.reference()));
});

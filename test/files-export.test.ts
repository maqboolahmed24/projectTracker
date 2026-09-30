import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {unzipSync} from 'fflate';
import {fileServiceFixture} from './files-fixture.js';
import {origin} from './password-change-fixture.js';
import {transaction} from '../src/db.js';
import {ExportService} from '../src/modules/export/service.js';
import {prepareExport} from '../src/client/export-crypto.js';
import {createFileArchive} from '../src/client/files-archive.js';
import {readFileBytes,readFiles,FileClientError} from '../src/client/files-crypto.js';
import {AppError} from '../src/errors.js';
import type {ExportPage} from '../src/shared/export.js';
import type {FilesController} from '../src/client/files-controller.js';

test('File data exit includes immutable version metadata, privately packages authorised bytes, and never fetches external paths',async t=>{
 let f:Awaited<ReturnType<typeof fileServiceFixture>>;
 t.after(async()=>{if(f)await transaction(f.admin.application,async c=>{await c.query("SET LOCAL session_replication_role='replica'");await c.query('DELETE FROM app.export_sessions WHERE workspace_id=$1',[f.workspaceId]);});});
 f=await fileServiceFixture(t);const first=await f.upload(await f.prepared('source',{size:100})),second=await f.upload(await f.prepared('source',{size:150,fileId:first.manifest.body.fileId,version:'2',priorVersionId:first.manifest.body.versionId})),external=await f.upload(await f.prepared('source',{size:90,storage:'external'}));
 const service=new ExportService({...f,origin,planning:f.planning}),auth=f.auth(),start=await service.start(auth,{workspaceId:f.workspaceId,exportId:randomUUID(),acknowledgePlaintext:true}),pages:ExportPage[]=[];let after:string|null=null;
 for(let n=0;n<start.sources.length;n++){const p=await service.page(auth,{workspaceId:f.workspaceId,exportId:start.binding.exportId,manifestDigest:start.binding.manifestDigest,after});pages.push(p);after=p.nextCursor;}
 assert.equal(after,null);assert.equal(start.sources.filter(s=>s.kind==='file_versions').length,1);
 const delivery=await f.access.currentDelivery(auth.cookieValue,auth.csrfToken,{workspaceId:f.workspaceId}),prepared=await prepareExport({start,pages,history:await f.history(),materials:delivery.materials,accountId:f.accountId,deviceId:f.deviceId,acknowledgePlaintext:true},f.originalBundle),document=JSON.parse(prepared.json);
 assert.equal(document.fileVersions.length,3);assert.equal(document.fileVersions.find((v:{versionId:string})=>v.versionId===second.manifest.body.versionId).priorVersionId,first.manifest.body.versionId);
 assert.equal(document.fileVersions.find((v:{versionId:string})=>v.versionId===external.manifest.body.versionId).contents,'external-metadata-only');
 for(const word of ['fileKey','ciphertext','signingPrivateKey','recipientPrivateKey','nonce'])assert.equal(prepared.json.includes(`"${word}"`),false);
 await service.finalize(auth,prepared.finalize);
 const input=async()=>{const context=await f.files.context(auth.cookieValue,auth.csrfToken,f.reference());return {context:context.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId};};
 let byteReads=0;const api:Pick<FilesController,'context'|'version'|'bytes'>={context:async()=>f.files.context(auth.cookieValue,auth.csrfToken,f.reference()),version:async(_projectId,versionId)=>{
  const version=await f.files.version(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId}),[metadata]=await readFiles({...await input(),manifests:[version.manifest]},f.originalBundle);return {...version,metadata:metadata!.metadata};},bytes:async(_projectId,versionId)=>{
  byteReads++;const version=await f.files.version(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId}),chunks=[];
  for(let index=0;index<version.manifest.body.chunkHashes.length;index++)chunks.push((await f.files.readChunk(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId,index,purpose:'download'})).bytes);
  const read=await input(),[metadata]=await readFiles({...read,manifests:[version.manifest]},f.originalBundle);return {bytes:await readFileBytes({...read,manifest:version.manifest,chunks},f.originalBundle),metadata:metadata!.metadata};}};
 const archive=await createFileArchive(api,f.projectId,[first.manifest.body.versionId,second.manifest.body.versionId,external.manifest.body.versionId]),zip=unzipSync(new Uint8Array(await archive.blob.arrayBuffer())),manifest=JSON.parse(new TextDecoder().decode(zip['manifest.json']));
 assert.equal(byteReads,2);assert.equal(manifest.items.length,3);assert.equal(manifest.items.find((i:{versionId:string})=>i.versionId===external.manifest.body.versionId).contentsIncluded,false);
 assert.deepEqual(zip[`files/${first.manifest.body.versionId}/Private source.txt`],first.bytes);assert.deepEqual(zip[`files/${second.manifest.body.versionId}/Private source.txt`],second.bytes);assert.equal(Object.keys(zip).length,3);
 let contextReads=0;await assert.rejects(createFileArchive({...api,context:async()=>{const context=await api.context(f.projectId);return ++contextReads===1?context:{...context,binding:{...context.binding,securityHead:'f'.repeat(64)}};}},f.projectId,[first.manifest.body.versionId]),e=>e instanceof FileClientError&&e.code==='CONFLICT');
 await f.upload(await f.prepared('source',{size:80}));await assert.rejects(service.finalize(auth,prepared.finalize),e=>e instanceof AppError&&e.code==='EXPORT_CHANGED');
});

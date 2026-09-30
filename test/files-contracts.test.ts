import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import fastify from 'fastify';
import { registerFilesRoutes } from '../src/modules/files/routes.js';
import type { FilesService } from '../src/modules/files/service.js';
import { fileBinding, fileManifestBody, fileChunkDigest, FILE_CHUNK_PLAIN_BYTES, FILE_MAX_PLAIN_BYTES,
 FILE_EXTERNAL_MAX_BYTES, FILE_MAX_DOCUMENT_TASKS, FILE_WORKSPACE_QUOTA_BYTES } from '../src/shared/files.js';
import { base64urlEncode } from '../src/shared/crypto.js';
const origin='http://localhost:3400',id=()=>randomUUID(),binary=(n:number)=>base64urlEncode(new Uint8Array(n));
function manifest(){return {purpose:'ukda.file-version.v1' as const,binding:fileBinding.parse({version:1,workspaceId:id(),projectId:id(),operationId:id(),origin,
 accountId:id(),deviceId:id(),credentialGeneration:'1',sessionGeneration:'1',keyGeneration:'1',signingPublicKey:binary(32),permissionVersion:'1',
 keyEpoch:'1',securityVersion:'1',securityHead:'a'.repeat(64),dataGeneration:'1',writeSchema:1,issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+600000).toISOString()}),
 fileId:id(),versionId:id(),version:'1',priorVersionId:null,kind:'source' as const,storage:'managed' as const,plainBytes:1,cipherBytes:41,chunkHashes:['b'.repeat(64)],
 metadata:{nonce:binary(24),ciphertext:binary(16)},taskIds:[]};}
test('Document file limits cover encryption overhead, bounded external verification, immutable lineage and 512 tasks',()=>{
 assert.equal(FILE_MAX_DOCUMENT_TASKS,512);assert.equal(FILE_WORKSPACE_QUOTA_BYTES,2*1024**3);
 assert.equal(FILE_MAX_PLAIN_BYTES,25*1024**2);assert.equal(FILE_EXTERNAL_MAX_BYTES,2*1024**3);
 const body=manifest();assert.ok(fileManifestBody.safeParse(body).success);
 assert.equal(fileManifestBody.safeParse({...body,cipherBytes:1}).success,false);
 assert.equal(fileManifestBody.safeParse({...body,plainBytes:FILE_CHUNK_PLAIN_BYTES+1,cipherBytes:FILE_CHUNK_PLAIN_BYTES+41}).success,false);
 assert.equal(fileManifestBody.safeParse({...body,version:'2'}).success,false);
 assert.equal(fileManifestBody.safeParse({...body,storage:'external',plainBytes:FILE_EXTERNAL_MAX_BYTES,cipherBytes:0,chunkHashes:[]}).success,true);
 assert.equal(fileManifestBody.safeParse({...body,storage:'external',plainBytes:FILE_EXTERNAL_MAX_BYTES+1,cipherBytes:0,chunkHashes:[]}).success,false);
 assert.equal(fileManifestBody.safeParse({...body,filename:'unencrypted filename.pdf'}).success,false);
 assert.equal(fileManifestBody.safeParse({...body,taskIds:[id(),...Array.from({length:64},id)]}).success,false);
});
test('Chunk digests authenticate the exact packed bytes, including nonce',async()=>{
 const bytes=new Uint8Array(41);assert.equal(await fileChunkDigest(bytes),'9e1736c43d19118e6ce4302118af337109491ecc52757dfb949bad6a7940b0c2');
 const before=await fileChunkDigest(bytes);bytes[0]=1;assert.notEqual(await fileChunkDigest(bytes),before);
});
test('Files HTTP transport requires same origin, CSRF and session before using bounded encrypted routes',async()=>{
 const app=fastify({bodyLimit:1024*1024}),calls:unknown[]=[];
 app.setErrorHandler((e,_r,reply)=>{const error=e as {statusCode?:number;code?:string};return reply.code(error.statusCode??500).send({code:error.code??'unknown'});});
 registerFilesRoutes(app,{origin,files:{context:async(...args:unknown[])=>{calls.push(args);return {ok:true};}} as unknown as FilesService,budgets:{take:async()=>{}}});
 const payload={workspaceId:id(),projectId:id(),operationId:id()},headers={origin,'x-csrf-token':binary(32),cookie:`__Host-ukda_session=v1.${id()}.${id()}.${binary(32)}`};
 assert.equal((await app.inject({method:'POST',url:'/v1/files/context',payload})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:'/v1/files/context',payload,headers:{origin}})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:'/v1/files/context',payload,headers:{...headers,origin:'https://elsewhere.invalid'}})).statusCode,403);
 const accepted=await app.inject({method:'POST',url:'/v1/files/context',payload,headers});
 assert.equal(accepted.statusCode,200);assert.equal(accepted.headers['cache-control'],'no-store');assert.equal(calls.length,1);
 assert.equal((await app.inject({method:'POST',url:'/v1/files/context?workspace=other',payload,headers})).statusCode,400);
 assert.equal((await app.inject({method:'POST',url:'/v1/files/context',payload:{...payload,path:'/etc/passwd'},headers})).statusCode,400);
 await app.close();
});

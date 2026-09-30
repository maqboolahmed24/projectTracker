import assert from 'node:assert/strict';
import { createHash,createHmac,randomUUID } from 'node:crypto';
import { mkdtemp,mkdir,readFile,rm,symlink,writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test,{type TestContext} from 'node:test';
import sodium from 'libsodium-wrappers';
import {unzipSync,zipSync,strToU8} from 'fflate';
import { LocalFilesService } from '../src/local-files/service.js';
import { LocalOffice } from '../src/local-files/office.js';
import { docxFixture } from './file-preview-fixtures.js';
import { fileManifest,fileEditorPermit } from '../src/shared/files.js';
import { RootIO } from '../src/local-files/root-io.js';
import { base64urlEncode,canonicalJson,digestObject,generateSigningKeyPair,signObject,verifyObject } from '../src/shared/crypto.js';
import { deliveryBatch,deliveryMetadataContext,deliveryPermit } from '../src/shared/file-delivery.js';
import type { FileBinding } from '../src/shared/files.js';
const hash=(b:string)=>createHash('sha256').update(b).digest('hex');
const opaque=()=>({nonce:base64urlEncode(new Uint8Array(24)),ciphertext:base64urlEncode(new Uint8Array(16))});
async function fixture(t:TestContext){
 const dir=await mkdtemp(join(tmpdir(),'maqbool-local-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 const root=join(dir,'shared'),stateDirectory=join(dir,'state');await mkdir(root);await mkdir(join(root,'docs'));
 const server=await generateSigningKeyPair(),owner=await generateSigningKeyPair(),origin='https://example.test';
 let interrupted=false,hook:((stage:string,index:number)=>Promise<void>)|undefined;
 const options={root,stateDirectory,origin,trustedServiceKeys:{test:base64urlEncode(server.publicKey)},hook:async(stage:string,index:number)=>hook?.(stage,index)};
 let service=await LocalFilesService.open(options);
 const binding:FileBinding={version:1,workspaceId:randomUUID(),projectId:randomUUID(),operationId:randomUUID(),origin,accountId:randomUUID(),deviceId:randomUUID(),credentialGeneration:'1',sessionGeneration:'1',keyGeneration:'1',signingPublicKey:base64urlEncode(owner.publicKey),permissionVersion:'1',keyEpoch:'1',securityVersion:'1',securityHead:'a'.repeat(64),dataGeneration:'1',writeSchema:1,issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+60000).toISOString()};
 const approval=await signObject({purpose:'ukda.file-service-pair.v1',binding,serviceId:service.serviceId,publicKey:service.publicKey,pairingId:randomUUID(),nonce:base64urlEncode(new Uint8Array(32)),metadata:opaque()},owner.privateKey);
 const paired=await service.pair({code:service.setupCode(),approval});
 async function request(operation:'add'|'replace'|'move'|'rename'|'remove',destination:string,text:string,expected:string|null,fromPath?:string){
  await sodium.ready;const key=sodium.randombytes_buf(32),nonce=sodium.randombytes_buf(24);
  const body={purpose:'ukda.file-delivery.v1' as const,binding:{...binding,operationId:randomUUID()},batchId:randomUUID(),supersedes:null,items:[{operation,fileId:randomUUID(),versionId:randomUUID(),manifestDigest:'b'.repeat(64),approvalId:randomUUID()}],metadata:opaque(),details:opaque()};
  const details={version:1,label:'Issue one',rootLabel:'shared',items:[{destination,expectedOldSha256:expected,sha256:hash(text),plainBytes:Buffer.byteLength(text),filename:'file.txt',...(fromPath?{fromPath}:{})}]};
  body.details={nonce:base64urlEncode(nonce),ciphertext:base64urlEncode(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(canonicalJson(details),canonicalJson(deliveryMetadataContext(body,'details')),null,nonce,key))};
  const batch=deliveryBatch.parse(await signObject(body,owner.privateKey)),permit=deliveryPermit.parse(await signObject({purpose:'ukda.file-delivery-permit.v1',version:1,keyId:'test',origin,workspaceId:binding.workspaceId,projectId:binding.projectId,batchId:body.batchId,frozenDigest:await digestObject(batch),serviceId:service.serviceId,permitId:randomUUID(),nonce:base64urlEncode(new Uint8Array(32)),index:0,itemDigest:await digestObject(body.items[0]),securityHead:binding.securityHead,securityVersion:'1',dataGeneration:'1',issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+30000).toISOString()},server.privateKey));
  return {batch,permit,detailsKey:base64urlEncode(key),bytes:base64urlEncode(Buffer.from(text))};
 }
 return {root,dir,binding,paired,request,server,owner,get service(){return service;},interruptAt(stage:string){hook=async s=>{if(s===stage&&!interrupted){interrupted=true;throw new Error('Power interrupted');}};},async reopen(){service=await LocalFilesService.open(options);return service;}};
}
test('Local publication recovers a captured old file and verifies exact final bytes before receipt',async t=>{
 const f=await fixture(t);await writeFile(join(f.root,'docs','report.txt'),'old');
 const r=await f.request('replace','docs/report.txt','approved new',hash('old'));f.interruptAt('backed_up');
 await assert.rejects(f.service.apply(f.paired.token,r),/Power interrupted/);await f.reopen();
 const result=await f.service.apply(f.paired.token,r);assert.equal(result.state,'verified');assert.equal(await readFile(join(f.root,'docs','report.txt'),'utf8'),'approved new');
 const receipt=await f.service.finish(f.paired.token,r.batch.body.batchId,1);assert.ok(await verifyObject(receipt,Buffer.from(f.service.publicKey,'base64url'),'ukda.local-file-publication.v1'));
 assert.deepEqual(await f.service.finish(f.paired.token,r.batch.body.batchId,1),receipt);
});
test('Unexpected changes, missing published files, symlinks and escaped paths never count as a successful publication',async t=>{
 const f=await fixture(t);await writeFile(join(f.root,'docs','report.txt'),'someone changed this');
 const changed=await f.request('replace','docs/report.txt','new',hash('old'));await assert.rejects(f.service.apply(f.paired.token,changed));
 assert.equal(await readFile(join(f.root,'docs','report.txt'),'utf8'),'someone changed this');
 const add=await f.request('add','docs/new.txt','new',null);await f.service.apply(f.paired.token,add);await rm(join(f.root,'docs','new.txt'));
 await assert.rejects(f.service.finish(f.paired.token,add.batch.body.batchId,1));
 const outside=join(f.dir,'outside');await mkdir(outside);await symlink(outside,join(f.root,'shortcut'));
 const escaped=await f.request('add','shortcut/out.txt','new',null);await assert.rejects(f.service.apply(f.paired.token,escaped));
 const io=await RootIO.open(f.root);await assert.rejects(io.write(join(f.root,'shortcut','out.txt'),base64urlEncode(Buffer.from('bad'))));
 await assert.rejects(io.write(join(f.root,'..','outside','out.txt'),base64urlEncode(Buffer.from('bad'))));
 await assert.rejects(readFile(join(outside,'out.txt')));
});

test('Move, rename and remove preserve approved bytes and reject a changed source before completion',async t=>{
 const f=await fixture(t);await writeFile(join(f.root,'docs','draft.txt'),'approved');
 const move=await f.request('move','docs/moved.txt','approved',hash('approved'),'docs/draft.txt');
 await f.service.apply(f.paired.token,move);await assert.rejects(readFile(join(f.root,'docs','draft.txt')));
 await writeFile(join(f.root,'docs','draft.txt'),'new local work');
 await assert.rejects(f.service.finish(f.paired.token,move.batch.body.batchId,1),/CONFLICT/);
 assert.equal(await readFile(join(f.root,'docs','draft.txt'),'utf8'),'new local work');
 await rm(join(f.root,'docs','draft.txt'));await f.service.finish(f.paired.token,move.batch.body.batchId,1);
 const rename=await f.request('rename','docs/final.txt','approved',hash('approved'),'docs/moved.txt');
 await f.service.apply(f.paired.token,rename);await f.service.finish(f.paired.token,rename.batch.body.batchId,1);
 assert.equal(await readFile(join(f.root,'docs','final.txt'),'utf8'),'approved');
 const remove=await f.request('remove','docs/final.txt','approved',hash('approved'));await f.service.apply(f.paired.token,remove);
 await f.service.finish(f.paired.token,remove.batch.body.batchId,1);await assert.rejects(readFile(join(f.root,'docs','final.txt')));
 const forged=await f.request('add','docs/forged.txt','approved',null);forged.permit.body.projectId=randomUUID();
 await assert.rejects(f.service.apply(f.paired.token,forged),/FORBIDDEN/);await assert.rejects(readFile(join(f.root,'docs','forged.txt')));
 const expired=await f.request('add','docs/expired.txt','approved',null);expired.permit=deliveryPermit.parse(await signObject({...expired.permit.body,issuedAt:new Date(Date.now()-60000).toISOString(),expiresAt:new Date(Date.now()-30000).toISOString()},f.server.privateKey));
 await assert.rejects(f.service.apply(f.paired.token,expired),/EXPIRED/);
});

test('Local editing rejects replay, forged callbacks and remote downloads, and clears expired documents',async t=>{
 const f=await fixture(t),bytes=docxFixture(),versionId=randomUUID(),jwtSecret='synthetic-editor-test-secret-32-characters';let now=Date.now(),remoteFetches=0;
 const manifest=fileManifest.parse(await signObject({purpose:'ukda.file-version.v1',binding:f.binding,fileId:randomUUID(),versionId,version:'1',priorVersionId:null,kind:'source',storage:'managed',plainBytes:bytes.length,cipherBytes:bytes.length+40,chunkHashes:['a'.repeat(64)],metadata:opaque(),taskIds:[]},f.owner.privateKey));
 const permit=await signObject({purpose:'ukda.file-edit-permit.v1',keyId:'test',origin:f.binding.origin,workspaceId:f.binding.workspaceId,projectId:f.binding.projectId,serviceId:f.service.serviceId,versionId,manifestDigest:await digestObject(manifest),accountId:f.binding.accountId,deviceId:f.binding.deviceId,credentialGeneration:'1',sessionGeneration:'1',dataGeneration:'1',permissionVersion:'1',keyEpoch:'1',issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+30000).toISOString(),permitId:randomUUID(),nonce:base64urlEncode(new Uint8Array(32))},f.server.privateKey);
 const office=new LocalOffice({documentServer:'http://127.0.0.1:3420',callbackOrigin:'http://host.docker.internal:3412',publicOrigin:'https://localhost:3411',jwtSecret,now:()=>now,verifyPermit:p=>f.service.verifyEditorPermit(p),fetcher:async url=>{if(String(url).endsWith('/healthcheck'))return new Response('true');remoteFetches++;throw new Error('No private file may leave this computer');}});t.after(()=>office.clear());
 const input={permit:fileEditorPermit.parse(permit),manifest,filename:'local.docx',sha256:createHash('sha256').update(bytes).digest('hex'),bytes:base64urlEncode(bytes),theme:'light'};
 const external=zipSync({...unzipSync(bytes),'word/_rels/document.xml.rels':strToU8('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="image1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" TargetMode="External" Target="https://outside.example/private-image.png"/></Relationships>')});
 const badManifest=await signObject({...manifest.body,plainBytes:external.length,cipherBytes:external.length+40},f.owner.privateKey);
 const badPermit=await signObject({...permit.body,permitId:randomUUID(),manifestDigest:await digestObject(badManifest)},f.server.privateKey);
 await assert.rejects(office.start({...input,manifest:badManifest,permit:badPermit,bytes:base64urlEncode(external),sha256:createHash('sha256').update(external).digest('hex')}),/INVALID/);
 const opened=await office.start(input);await assert.rejects(office.start(input),/CONFLICT/);
 const config=opened.config as {document:{key:string;url:string}};const segments=new URL(config.document.url).pathname.split('/'),capability=segments[3]!;
 const callback={key:config.document.key,status:6,url:'https://outside.example/private.docx'};
 const signed=(payload:unknown)=>{const h=Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url'),b=Buffer.from(JSON.stringify(payload)).toString('base64url');return h+'.'+b+'.'+createHmac('sha256',jwtSecret).update(h+'.'+b).digest('base64url');};
 await assert.rejects(office.callback(opened.leaseId,capability,{...callback,token:'forged'}),/FORBIDDEN/);
 await assert.rejects(office.callback(opened.leaseId,capability,{...callback,token:signed(callback)}),/FORBIDDEN/);
 assert.equal(remoteFetches,0);const held=office.source(opened.leaseId,capability).bytes;assert.ok(held.some(b=>b!==0));
 now+=31*60000;office.sweep();assert.ok(held.every(b=>b===0));assert.throws(()=>office.snapshot(opened.leaseId,opened.token),/FORBIDDEN/);
});

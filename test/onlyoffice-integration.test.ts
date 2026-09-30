import assert from 'node:assert/strict';
import { createHash,randomUUID } from 'node:crypto';
import { mkdtemp,mkdir,rm,writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { chromium } from '@playwright/test';
import { zipSync,strToU8,unzipSync,strFromU8 } from 'fflate';
import sodium from 'libsodium-wrappers';
import { LocalFilesService } from '../src/local-files/service.js';
import { LocalOffice } from '../src/local-files/office.js';
import { startLocalHttp } from '../src/local-files/http.js';
import { DeliveryService } from '../src/modules/files/delivery-service.js';
import { prepareFile,readFileBytes } from '../src/client/files-crypto.js';
import { base64urlDecode,base64urlEncode,digestObject,signObject } from '../src/shared/crypto.js';
import { fileServiceFixture } from './files-fixture.js';
import { origin } from './password-change-fixture.js';
const docx=()=>zipSync({'[Content_Types].xml':strToU8('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'),
 '_rels/.rels':strToU8('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'),
 'word/document.xml':strToU8('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Document work acceptance</w:t></w:r></w:p><w:sectPr><w:pgSz w:w="12240" w:h="15840"/></w:sectPr></w:body></w:document>')});
test('ONLYOFFICE edits a real managed document and saves a new encrypted immutable version', {skip:process.env.ONLYOFFICE_INTEGRATION!=='1',timeout:150000},async t=>{
 const f=await fileServiceFixture(t),a=f.auth(),first=await f.files.context(a.cookieValue,a.csrfToken,f.reference()),bytes=docx(),fileId=randomUUID();
 const prepared=await prepareFile({context:first.planning,history:await f.history(),accountId:first.binding.accountId,deviceId:first.binding.deviceId,binding:first.binding,fileId,versionId:randomUUID(),version:'1',priorVersionId:null,kind:'source',storage:'managed',taskIds:[],file:new Blob([new Uint8Array(bytes)]),metadata:{filename:'Acceptance.docx',mediaType:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',documentReference:'DOC-001',label:''}},f.originalBundle);
 await f.upload({...prepared,bytes});
 const dir=await mkdtemp(join(tmpdir(),'maqbool-office-'));t.after(()=>rm(dir,{recursive:true,force:true}));await mkdir(join(dir,'share'));await sodium.ready;
 const serverKey=sodium.crypto_sign_seed_keypair(f.secrets.digest('entitlement-signing-key',f.secrets.keyId)),service=await LocalFilesService.open({root:join(dir,'share'),stateDirectory:join(dir,'state'),origin,trustedServiceKeys:{[f.secrets.keyId]:base64urlEncode(serverKey.publicKey)}});
 const delivery=new DeliveryService({...f,origin,planning:f.planning}),pair=await delivery.pairContext(a.cookieValue,a.csrfToken,{...f.reference(),serviceId:service.serviceId,publicKey:service.publicKey});
 const approval=await signObject({purpose:'ukda.file-service-pair.v1',binding:pair.binding,serviceId:service.serviceId,publicKey:service.publicKey,pairingId:pair.challenge.pairingId,nonce:pair.challenge.nonce,metadata:{nonce:base64urlEncode(new Uint8Array(24)),ciphertext:base64urlEncode(new Uint8Array(16))}},base64urlDecode(f.originalBundle.signingPrivateKey));
 const local=await service.pair({code:service.setupCode(),approval});await delivery.pair(a.cookieValue,a.csrfToken,{approval,proof:local.proof});
 const office=new LocalOffice({documentServer:'http://127.0.0.1:3420',callbackOrigin:'http://host.docker.internal:3412',publicOrigin:'http://localhost:3411',jwtSecret:process.env.JWT_SECRET??'',verifyPermit:p=>service.verifyEditorPermit(p)});
 const listener=await startLocalHttp({service,office,documentServer:'http://127.0.0.1:3420',origin,publicOrigin:'http://localhost:3411',port:3411});t.after(()=>listener.close());
 const permit=await f.files.editorPermit(a.cookieValue,a.csrfToken,{...f.reference(),versionId:prepared.manifest.body.versionId,serviceId:service.serviceId});
 const opened=await office.start({permit,manifest:prepared.manifest,filename:'Acceptance.docx',sha256:createHash('sha256').update(bytes).digest('hex'),bytes:base64urlEncode(bytes),theme:'light'});
 const browser=await chromium.launch({headless:true});t.after(()=>browser.close());const page=await browser.newPage({permissions:['local-network-access'],viewport:{width:1400,height:1000},ignoreHTTPSErrors:true});
 await page.route(origin+'/editor-acceptance',route=>route.fulfill({contentType:'text/html',body:`<!doctype html><html><body style="margin:0"><div id="editor"></div><script src="http://localhost:3411/office/web-apps/apps/api/documents/api.js"></script><script>window.ready=false;window.editor=new DocsAPI.DocEditor('editor',{...${JSON.stringify(opened.config)},height:'950px',events:{onDocumentReady:()=>window.ready=true,onError:e=>window.editorError=e}});</script></body></html>`}));
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));page.on('requestfailed',r=>errors.push(new URL(r.url()).pathname+': '+r.failure()?.errorText));page.on('response',r=>{if(r.status()>=400)errors.push(String(r.status())+' '+new URL(r.url()).pathname);});
 t.after(()=>{if(errors.length)t.diagnostic(errors.join(' | '));});
 await page.goto(origin+'/editor-acceptance');await page.waitForTimeout(8000);await page.screenshot({path:'.local/testing/office-acceptance.png'});await writeFile('.local/testing/office-diagnostics.json',JSON.stringify({frames:page.frames().map(f=>{try{const u=new URL(f.url());return u.origin+u.pathname;}catch{return f.url();}}),errors},null,2));await page.waitForFunction(()=>Boolean((window as unknown as {ready:boolean}).ready),{},{timeout:80000});
 const editor=page.frames().find(frame=>frame.url().includes('/documenteditor/'));assert.ok(editor,'Document editor iframe is present');
 const canvas=editor.locator('#id_main');await canvas.click({position:{x:560,y:230}});await page.keyboard.press('Control+End');await page.keyboard.press('Enter');await page.keyboard.type('Verified in Maqbool');await page.keyboard.press('Control+s');
 await page.waitForTimeout(1500);let snapshot=await office.forceSave(opened.leaseId,opened.token);
 for(let i=0;snapshot.state==='waiting'&&i<25;i++){await page.waitForTimeout(1000);snapshot=office.snapshot(opened.leaseId,opened.token);}
 assert.equal(snapshot.state,'ready',errors.join('\n'));assert.ok(snapshot.bytes);const edited=base64urlDecode(snapshot.bytes),document=strFromU8(unzipSync(edited)['word/document.xml']!);assert.match(document,/Verified in Maqbool/);
 const current=await f.files.context(a.cookieValue,a.csrfToken,f.reference()),next=await prepareFile({context:current.planning,history:await f.history(),accountId:current.binding.accountId,deviceId:current.binding.deviceId,binding:current.binding,fileId,versionId:randomUUID(),version:'2',priorVersionId:prepared.manifest.body.versionId,kind:'source',storage:'managed',taskIds:[],file:new Blob([new Uint8Array(edited)]),metadata:{filename:'Acceptance.docx',mediaType:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',documentReference:'DOC-001',label:''}},f.originalBundle);
 await f.upload({...next,bytes:new Uint8Array(edited)});const after=await f.files.context(a.cookieValue,a.csrfToken,f.reference());
 const decrypted=await readFileBytes({context:after.planning,history:await f.history(),accountId:after.binding.accountId,deviceId:after.binding.deviceId,manifest:next.manifest,chunks:next.chunks},f.originalBundle);assert.deepEqual(decrypted,edited);
 assert.notEqual(await digestObject(next.manifest),await digestObject(prepared.manifest));assert.equal((await f.files.version(a.cookieValue,a.csrfToken,{...f.reference(),versionId:prepared.manifest.body.versionId})).state,'ready');
 office.close(opened.leaseId,opened.token);decrypted.fill(0);edited.fill(0);
});

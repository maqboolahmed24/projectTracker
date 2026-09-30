import assert from 'node:assert/strict';
import test from 'node:test';
import {randomUUID} from 'node:crypto';
import {transaction} from '../src/db.js';
import {FilesService} from '../src/modules/files/service.js';
import {FileEvidenceService} from '../src/modules/files/evidence-service.js';
import {DeliveryService} from '../src/modules/files/delivery-service.js';
import {prepareFile,readFiles} from '../src/client/files-crypto.js';
import {prepareFileVerification,prepareSharedFileApproval} from '../src/client/file-evidence-crypto.js';
import {prepareDelivery,prepareDeliveryCommand,prepareDeliveryPair,prepareDeliveryPublish,preparePublicationMaterial,readDelivery} from '../src/client/files-delivery-crypto.js';
import {base64urlEncode,digestObject,generateSigningKeyPair,signObject} from '../src/shared/crypto.js';
import {publicationReceipt} from '../src/shared/file-delivery.js';
import {RESTORE_FILE_TABLES,RESTORE_DISPOSABLE_FILE_TABLES} from '../src/shared/restoration.js';
import {restorationFixture} from './restoration-fixture.js';
import {origin} from './password-change-fixture.js';

test('Recovery retains readable published delivery and exact approvals, but invalidates unfinished delivery and local write grants',async t=>{
 let f:Awaited<ReturnType<typeof restorationFixture>>;
 t.after(async()=>{if(f)await transaction(f.admin.application,async c=>{await c.query("SET LOCAL session_replication_role='replica'");for(const table of [...RESTORE_DISPOSABLE_FILE_TABLES,...RESTORE_FILE_TABLES])await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`,[f.workspaceId]);});});
 f=await restorationFixture(t);const files=new FilesService({...f,origin,planning:f.planning}),evidence=new FileEvidenceService({...f,origin,planning:f.planning}),delivery=new DeliveryService({...f,origin,planning:f.planning});let auth=f.auth();
 const reference=()=>({workspaceId:f.workspaceId,projectId:f.projectId,operationId:randomUUID()}),current=async()=>{const context=await files.context(auth.cookieValue,auth.csrfToken,reference());return {context,contextInput:{context:context.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId}};};
 const initial=await current(),source=await prepareFile({...initial.contextInput,binding:initial.context.binding,fileId:randomUUID(),versionId:randomUUID(),version:'1',priorVersionId:null,kind:'source',storage:'managed',taskIds:[],file:new Blob([new Uint8Array(100).fill(65)]),metadata:{filename:'Approved.txt',mediaType:'text/plain',documentReference:'RECOVERY-01',label:''}},f.originalBundle);
 await files.begin(auth.cookieValue,auth.csrfToken,{manifest:source.manifest});await files.chunk(auth.cookieValue,auth.csrfToken,{...reference(),versionId:source.manifest.body.versionId,index:0,bytes:source.chunks[0]});await files.complete(auth.cookieValue,auth.csrfToken,{...reference(),versionId:source.manifest.body.versionId});
 const ec=await evidence.context(auth.cookieValue,auth.csrfToken,{...reference(),versionId:source.manifest.body.versionId}),evidenceInput={context:ec.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId},proof=await prepareFileVerification({...evidenceInput,manifest:source.manifest,chunks:source.chunks},f.originalBundle),approvalId=randomUUID(),approval=await prepareSharedFileApproval({...evidenceInput,evidence:ec,approvalId,proofs:[proof]},f.originalBundle);
 await evidence.approveShared(auth.cookieValue,auth.csrfToken,approval);
 async function create(){const c=await current(),[file]=await readFiles({...c.contextInput,manifests:[source.manifest]},f.originalBundle),prepared=await prepareDelivery({...c.contextInput,binding:c.context.binding,batchId:randomUUID(),supersedes:null,manifests:[source.manifest],items:[{operation:'add',fileId:source.manifest.body.fileId,versionId:source.manifest.body.versionId,manifestDigest:await digestObject(source.manifest),approvalId}],details:{version:1,label:'Checked handover',rootLabel:'Approved folder',items:[{destination:'Approved.txt',expectedOldSha256:null,sha256:file!.metadata.sha256,plainBytes:100,filename:'Approved.txt'}]}},f.originalBundle);
  await delivery.create(auth.cookieValue,auth.csrfToken,prepared);return prepared.batch.body.batchId;}
 const publishedId=await create(),frozen=await delivery.get(auth.cookieValue,auth.csrfToken,{...reference(),batchId:publishedId}),confirmContext=await current(),confirmation=await prepareDeliveryCommand({...confirmContext.contextInput,binding:confirmContext.context.binding,record:frozen,manifests:[source.manifest],action:'confirm'},f.originalBundle);await delivery.command(auth.cookieValue,auth.csrfToken,confirmation,'confirm');
 const keys=await generateSigningKeyPair(),serviceId=randomUUID(),publicKey=base64urlEncode(keys.publicKey),pairContext=await delivery.pairContext(auth.cookieValue,auth.csrfToken,{...reference(),serviceId,publicKey}),pair=await prepareDeliveryPair({context:pairContext.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId,binding:pairContext.binding,challenge:pairContext.challenge,serviceId,publicKey,metadata:{version:1,label:'Recovery computer',rootLabel:'Approved folder',address:'https://localhost:3411'}},f.originalBundle);
 await delivery.pair(auth.cookieValue,auth.csrfToken,{...pair,proof:(await signObject(pair.approval.body,keys.privateKey)).signature});
 const startedAt=new Date().toISOString(),permit=await delivery.permit(auth.cookieValue,auth.csrfToken,{...reference(),batchId:publishedId,serviceId,index:0}),record=await delivery.get(auth.cookieValue,auth.csrfToken,{...reference(),batchId:publishedId}),service=(await delivery.services(auth.cookieValue,auth.csrfToken,reference())).services[0]!,pc=await current(),receipt=publicationReceipt.parse(await signObject({purpose:'ukda.local-file-publication.v1',workspaceId:f.workspaceId,projectId:f.projectId,serviceId,batchId:publishedId,frozenDigest:record.frozenDigest,permitIds:[permit.body.permitId],resultDigest:'a'.repeat(64),startedAt,completedAt:new Date().toISOString()},keys.privateKey)),publication=await prepareDeliveryPublish({...pc.contextInput,binding:pc.context.binding,record,manifests:[source.manifest],service,receipt},f.originalBundle);
 await delivery.publish(auth.cookieValue,auth.csrfToken,publication);const unfinishedId=await create(),checkpoint=await f.checkpoint(),restoreId=await f.begin(checkpoint.manifest);await f.install();await f.restoration.reconcile({workspaceId:f.workspaceId,restoreId});auth=await f.restoreLogin();assert.equal((await f.restoration.verify(auth,await f.restoreProof(restoreId,auth))).state,'completed');
 const restored=await current(),past=await delivery.get(auth.cookieValue,auth.csrfToken,{...reference(),batchId:publishedId}),oldService=(await delivery.services(auth.cookieValue,auth.csrfToken,reference())).services[0]!,read={...restored.contextInput,record:past,service:oldService,manifests:[source.manifest]};
 assert.equal(past.state,'published');assert.equal(oldService.state,'revoked');assert.equal((await readDelivery(read,f.originalBundle)).details.items[0]!.destination,'Approved.txt');
 assert.equal((await delivery.get(auth.cookieValue,auth.csrfToken,{...reference(),batchId:unfinishedId})).state,'cancelled');
 await assert.rejects(preparePublicationMaterial(read,f.originalBundle));await assert.rejects(delivery.permit(auth.cookieValue,auth.csrfToken,{...reference(),batchId:publishedId,serviceId,index:0}));await assert.rejects(delivery.publish(auth.cookieValue,auth.csrfToken,publication));
 const newId=await create();assert.equal((await delivery.get(auth.cookieValue,auth.csrfToken,{...reference(),batchId:newId})).batch.body.binding.dataGeneration,restored.context.binding.dataGeneration);
 keys.privateKey.fill(0);
});

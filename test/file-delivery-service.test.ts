import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {AppError} from '../src/errors.js';
import {DeliveryService} from '../src/modules/files/delivery-service.js';
import {FileEvidenceService as EvidenceService} from '../src/modules/files/evidence-service.js';
import {base64urlDecode,base64urlEncode,digestObject,generateSigningKeyPair,signObject,verifyObject} from '../src/shared/crypto.js';
import {deliveryBatch,deliveryCommandRequest,deliveryPairRequest,deliveryPublishRequest,deliveryServiceCommandRequest,publicationReceipt} from '../src/shared/file-delivery.js';
import {evidenceRevokeRequest,sharedFileApproval} from '../src/shared/file-evidence.js';
import {fileServiceFixture} from './files-fixture.js';
import {origin} from './password-change-fixture.js';
const code=(expected:string)=>(e:unknown)=>e instanceof AppError&&e.code===expected;
const opaque=()=>({nonce:base64urlEncode(new Uint8Array(24)),ciphertext:base64urlEncode(new Uint8Array(16))});
async function fixture(t:Parameters<typeof fileServiceFixture>[0]){
 const f=await fileServiceFixture(t),delivery=new DeliveryService({...f,origin,planning:f.planning}),evidence=new EvidenceService({...f,origin,planning:f.planning}),auth=f.auth(),key=base64urlDecode(f.originalBundle.signingPrivateKey);
 const source=await f.upload(await f.prepared()),versionId=source.manifest.body.versionId;
 const ec=await evidence.context(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId}),approvalId=randomUUID();
 const approval=sharedFileApproval.parse(await signObject({purpose:'ukda.shared-file-approval.v1',binding:ec.binding,approvalId,
  reference:{fileId:source.manifest.body.fileId,versionId,manifestDigest:await digestObject(source.manifest)},verification:opaque()},key));
 await evidence.approveShared(auth.cookieValue,auth.csrfToken,{approval});
 async function create(supersedes:string|null=null){const c=await delivery.context(auth.cookieValue,auth.csrfToken,f.reference()),batchId=randomUUID(),batch=deliveryBatch.parse(await signObject({purpose:'ukda.file-delivery.v1',binding:c.binding,batchId,supersedes,
  items:[{operation:'add',fileId:source.manifest.body.fileId,versionId,manifestDigest:await digestObject(source.manifest),approvalId}],metadata:opaque(),details:opaque()},key));
  const payload={batch},view=await delivery.create(auth.cookieValue,auth.csrfToken,payload);return {batch,batchId,payload,view,frozenDigest:await digestObject(batch)};}
 async function command(batch:Awaited<ReturnType<typeof create>>,action:'confirm'|'cancel'|'record_package'){
  const c=await delivery.context(auth.cookieValue,auth.csrfToken,f.reference()),payload=deliveryCommandRequest.parse({mutation:await signObject({purpose:'ukda.file-delivery-command.v1',binding:c.binding,batchId:batch.batchId,frozenDigest:batch.frozenDigest,action},key)});
  return {payload,view:await delivery.command(auth.cookieValue,auth.csrfToken,payload,action)};
 }
 async function pair(){const service=await generateSigningKeyPair(),serviceId=randomUUID(),publicKey=base64urlEncode(service.publicKey),c=await delivery.pairContext(auth.cookieValue,auth.csrfToken,{...f.reference(),serviceId,publicKey});
  const body={purpose:'ukda.file-service-pair.v1' as const,binding:c.binding,serviceId,publicKey,pairingId:c.challenge.pairingId,nonce:c.challenge.nonce,metadata:opaque()},approval=await signObject(body,key),proof=(await signObject(body,service.privateKey)).signature,
   payload=deliveryPairRequest.parse({approval,proof});await delivery.pair(auth.cookieValue,auth.csrfToken,payload);return {service,serviceId,publicKey,payload};
 }
 return {...f,delivery,evidence,auth,key,source,approvalId,create,command,pair};
}
test('Frozen delivery: only exact approved versions enter a batch; package downloads remain distinct from verified publication',async t=>{
 const f=await fixture(t),batch=await f.create(),a=f.auth;
 assert.equal(batch.view.state,'completed');assert.deepEqual(await f.delivery.create(a.cookieValue,a.csrfToken,batch.payload),batch.view);
 await assert.rejects(f.delivery.check(a.cookieValue,a.csrfToken,{...f.reference(),batchId:batch.batchId}),code('DELIVERY_CHANGED'));
 await f.command(batch,'confirm');await f.command(batch,'record_package');const record=await f.delivery.get(a.cookieValue,a.csrfToken,{...f.reference(),batchId:batch.batchId});
 assert.equal(record.state,'confirmed');assert.equal(record.packageDownloads,1);assert.equal(record.publication,null);
 const changed=structuredClone(batch.payload);changed.batch.body.items[0]!.versionId=randomUUID();await assert.rejects(f.delivery.create(a.cookieValue,a.csrfToken,changed));
 await assert.rejects(f.admin.application.query('UPDATE app.file_delivery_batches SET signed_batch=$3 WHERE workspace_id=$1 AND id=$2',[f.workspaceId,batch.batchId,changed.batch]));
 const newer=await f.create(batch.batchId);assert.equal((await f.delivery.get(a.cookieValue,a.csrfToken,{...f.reference(),batchId:batch.batchId})).state,'superseded');
 assert.equal((await f.delivery.get(a.cookieValue,a.csrfToken,{...f.reference(),batchId:newer.batchId})).state,'frozen');
});
test('Local publication: one-time possession pairing, short-lived signed permits and a service signature plus current Owner confirm publication',async t=>{
 const f=await fixture(t),a=f.auth,batch=await f.create();await f.command(batch,'confirm');const paired=await f.pair();
 assert.deepEqual((await f.delivery.services(a.cookieValue,a.csrfToken,f.reference())).services.map(s=>s.serviceId),[paired.serviceId]);
 assert.equal((await f.files.editorServices(a.cookieValue,a.csrfToken,f.reference())).services[0]!.publicKey,paired.publicKey);
 const edit=await f.files.editorPermit(a.cookieValue,a.csrfToken,{...f.reference(),versionId:f.source.manifest.body.versionId,serviceId:paired.serviceId});
 assert.equal(edit.body.purpose,'ukda.file-edit-permit.v1');assert.equal(Date.parse(edit.body.expiresAt)-Date.parse(edit.body.issuedAt),30000);
 const startedAt=new Date().toISOString(),permit=await f.delivery.permit(a.cookieValue,a.csrfToken,{...f.reference(),batchId:batch.batchId,serviceId:paired.serviceId,index:0});
 assert.equal(Date.parse(permit.body.expiresAt)-Date.parse(permit.body.issuedAt),30000);assert.equal(permit.body.itemDigest,await digestObject(batch.batch.body.items[0]));
 const ec=await f.files.context(a.cookieValue,a.csrfToken,f.reference());
 // API signing keys are distributed through the same trusted service identity.
 const seed=f.secrets.digest('entitlement-signing-key',f.secrets.keyId);assert.equal(seed.length,32);
 const receipt=publicationReceipt.parse(await signObject({purpose:'ukda.local-file-publication.v1',serviceId:paired.serviceId,workspaceId:f.workspaceId,projectId:f.projectId,
  batchId:batch.batchId,frozenDigest:batch.frozenDigest,permitIds:[permit.body.permitId],resultDigest:'a'.repeat(64),startedAt,completedAt:new Date().toISOString()},paired.service.privateKey));
 const c=await f.delivery.context(a.cookieValue,a.csrfToken,f.reference()),payload=deliveryPublishRequest.parse({mutation:await signObject({purpose:'ukda.file-delivery-published.v1',binding:c.binding,
  batchId:batch.batchId,frozenDigest:batch.frozenDigest,receipt},f.key)}),view=await f.delivery.publish(a.cookieValue,a.csrfToken,payload);
 assert.deepEqual(await f.delivery.publish(a.cookieValue,a.csrfToken,payload),view);assert.equal((await f.delivery.get(a.cookieValue,a.csrfToken,{...f.reference(),batchId:batch.batchId})).state,'published');
 assert.equal((await f.admin.application.query('SELECT used_at FROM app.file_delivery_permits WHERE workspace_id=$1 AND id=$2',[f.workspaceId,permit.body.permitId])).rows[0].used_at instanceof Date,true);
 assert.ok(ec.binding);assert.ok(await verifyObject(receipt,paired.service.publicKey,'ukda.local-file-publication.v1'));
});
test('Delivery grants stop after approval or local-service revocation and do not treat a forged service receipt as publication',async t=>{
 const f=await fixture(t),a=f.auth,batch=await f.create();await f.command(batch,'confirm');const paired=await f.pair();
 const startedAt=new Date().toISOString(),permit=await f.delivery.permit(a.cookieValue,a.csrfToken,{...f.reference(),batchId:batch.batchId,serviceId:paired.serviceId,index:0});
 const forgedReceipt=publicationReceipt.parse({body:{purpose:'ukda.local-file-publication.v1',serviceId:paired.serviceId,workspaceId:f.workspaceId,projectId:f.projectId,
  batchId:batch.batchId,frozenDigest:batch.frozenDigest,permitIds:[permit.body.permitId],resultDigest:'a'.repeat(64),startedAt,completedAt:new Date().toISOString()},signature:base64urlEncode(new Uint8Array(64))});
 const publicationContext=await f.delivery.context(a.cookieValue,a.csrfToken,f.reference()),forgedPublication=deliveryPublishRequest.parse({mutation:await signObject({purpose:'ukda.file-delivery-published.v1',binding:publicationContext.binding,batchId:batch.batchId,frozenDigest:batch.frozenDigest,receipt:forgedReceipt},f.key)});
 await assert.rejects(f.delivery.publish(a.cookieValue,a.csrfToken,forgedPublication),code('DELIVERY_CHANGED'));
 assert.equal((await f.delivery.get(a.cookieValue,a.csrfToken,{...f.reference(),batchId:batch.batchId})).state,'confirmed');
 assert.equal((await f.admin.application.query('SELECT used_at FROM app.file_delivery_permits WHERE workspace_id=$1 AND id=$2',[f.workspaceId,permit.body.permitId])).rows[0].used_at,null);
 const c=await f.delivery.context(a.cookieValue,a.csrfToken,f.reference()),revoke=deliveryServiceCommandRequest.parse({mutation:await signObject({purpose:'ukda.file-service-revoke.v1',binding:c.binding,serviceId:paired.serviceId,publicKey:paired.publicKey},f.key)});
 await f.delivery.revokeService(a.cookieValue,a.csrfToken,revoke);
 await assert.rejects(f.delivery.permit(a.cookieValue,a.csrfToken,{...f.reference(),batchId:batch.batchId,serviceId:paired.serviceId,index:0}),code('DELIVERY_SERVICE_UNAVAILABLE'));
 await assert.rejects(f.files.editorPermit(a.cookieValue,a.csrfToken,{...f.reference(),versionId:f.source.manifest.body.versionId,serviceId:paired.serviceId}),code('FILES_EDITOR_UNAVAILABLE'));
 await f.admin.application.query("UPDATE app.file_local_services SET state='active' WHERE workspace_id=$1 AND id=$2",[f.workspaceId,paired.serviceId]);
 await assert.rejects(f.delivery.permit(a.cookieValue,a.csrfToken,{...f.reference(),batchId:batch.batchId,serviceId:paired.serviceId,index:0}),code('DELIVERY_CHANGED'));
 await assert.rejects(f.files.editorPermit(a.cookieValue,a.csrfToken,{...f.reference(),versionId:f.source.manifest.body.versionId,serviceId:paired.serviceId}),code('FILES_EDITOR_UNAVAILABLE'));
 const other=await fileServiceFixture(t);await assert.rejects(f.delivery.get(other.auth().cookieValue,other.auth().csrfToken,{...f.reference(),batchId:batch.batchId}));
 const forged=structuredClone(batch.payload);forged.batch.signature=base64urlEncode(new Uint8Array(64));forged.batch.body.binding.operationId=randomUUID();
 await assert.rejects(f.delivery.create(a.cookieValue,a.csrfToken,forged),code('DELIVERY_CHANGED'));
 const evidence=await f.evidence.context(a.cookieValue,a.csrfToken,{...f.reference(),versionId:f.source.manifest.body.versionId}),revocation=evidenceRevokeRequest.parse({revocation:await signObject({purpose:'ukda.file-approval-revocation.v1',binding:evidence.binding,approvalId:f.approvalId,reason:opaque()},f.key)});
 await f.evidence.revoke(a.cookieValue,a.csrfToken,revocation);
 await assert.rejects(f.delivery.permit(a.cookieValue,a.csrfToken,{...f.reference(),batchId:batch.batchId,serviceId:paired.serviceId,index:0}),code('FILE_EVIDENCE_REQUIRED'));
});

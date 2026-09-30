import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {IDBFactory} from 'fake-indexeddb';
import sodium from 'libsodium-wrappers';
import {fileServiceFixture} from './files-fixture.js';
import {origin} from './password-change-fixture.js';
import {DeliveryService} from '../src/modules/files/delivery-service.js';
import {FileEvidenceService} from '../src/modules/files/evidence-service.js';
import {prepareFileVerification,prepareSharedFileApproval} from '../src/client/file-evidence-crypto.js';
import {readFiles} from '../src/client/files-crypto.js';
import {prepareDelivery,readDelivery,prepareDeliveryCommand,prepareDeliveryPair,preparePublicationMaterial,readDeliveryService} from '../src/client/files-delivery-crypto.js';
import {IndexedDeliveryStore} from '../src/client/files-delivery-store.js';
import {base64urlDecode,base64urlEncode,canonicalJson,digestObject,generateSigningKeyPair,signObject} from '../src/shared/crypto.js';
import {deliveryMetadataContext} from '../src/shared/file-delivery.js';

async function clientFixture(t:Parameters<typeof fileServiceFixture>[0]){
 const f=await fileServiceFixture(t),auth=f.auth(),delivery=new DeliveryService({...f,origin,planning:f.planning}),evidence=new FileEvidenceService({...f,origin,planning:f.planning}),source=await f.upload(await f.prepared());
 const c=await evidence.context(auth.cookieValue,auth.csrfToken,{...f.reference(),versionId:source.manifest.body.versionId}),input={context:c.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId};
 const proof=await prepareFileVerification({...input,manifest:source.manifest,chunks:source.chunks},f.originalBundle),approvalId=randomUUID(),approval=await prepareSharedFileApproval({...input,evidence:c,proofs:[proof],approvalId},f.originalBundle);
 await evidence.approveShared(auth.cookieValue,auth.csrfToken,approval);
 const current=await f.files.context(auth.cookieValue,auth.csrfToken,f.reference()),planningInput={context:current.planning,history:await f.history(),accountId:f.accountId,deviceId:f.deviceId};
 const [metadata]=await readFiles({...planningInput,manifests:[source.manifest]},f.originalBundle);assert.ok(metadata);
 const details={version:1 as const,label:'Checked delivery',rootLabel:'Shared project',items:[{destination:'Approved.txt',expectedOldSha256:null,sha256:metadata.metadata.sha256,plainBytes:source.manifest.body.plainBytes,filename:metadata.metadata.filename}]};
 const prepared={...planningInput,binding:current.binding,batchId:randomUUID(),supersedes:null,items:[{operation:'add' as const,fileId:source.manifest.body.fileId,versionId:source.manifest.body.versionId,manifestDigest:await digestObject(source.manifest),approvalId}],details,manifests:[source.manifest]};
 const payload=await prepareDelivery(prepared,f.originalBundle);await delivery.create(auth.cookieValue,auth.csrfToken,payload);
 const record=await delivery.get(auth.cookieValue,auth.csrfToken,{...f.reference(),batchId:prepared.batchId});
 return {...f,auth,delivery,source,planningInput,prepared,payload,record};
}
test('Delivery Worker preserves authenticated destinations, exact approved file bytes and separate package/publication authority',async t=>{
 const f=await clientFixture(t),read={...f.planningInput,record:f.record,manifests:[f.source.manifest]};
 assert.equal(JSON.stringify(f.payload).includes('Approved.txt'),false);assert.deepEqual((await readDelivery(read,f.originalBundle)).details,f.prepared.details);
 const modified=structuredClone(f.record);modified.batch.body.items[0]!.operation='replace';await assert.rejects(readDelivery({...read,record:modified},f.originalBundle));
 const altered=structuredClone(f.prepared);altered.details.items[0]!.sha256='f'.repeat(64);await assert.rejects(prepareDelivery(altered,f.originalBundle));
 for(const destination of ['../escape','/absolute','folder\\file','folder/../file','.maqbool-delivery/journal','folder//file']){
  await assert.rejects(prepareDelivery({...f.prepared,details:{...f.prepared.details,items:[{...f.prepared.details.items[0]!,destination}]}},f.originalBundle));
 }
 const context=await f.files.context(f.auth.cookieValue,f.auth.csrfToken,f.reference()),input={...f.planningInput,context:context.planning};
 const command=await prepareDeliveryCommand({...input,record:f.record,manifests:[f.source.manifest],binding:context.binding,action:'confirm'},f.originalBundle);
 await f.delivery.command(f.auth.cookieValue,f.auth.csrfToken,command,'confirm');
 const service=await generateSigningKeyPair(),serviceId=randomUUID(),publicKey=base64urlEncode(service.publicKey),pc=await f.delivery.pairContext(f.auth.cookieValue,f.auth.csrfToken,{...f.reference(),serviceId,publicKey});
 const pair=await prepareDeliveryPair({...input,context:pc.planning,binding:pc.binding,challenge:pc.challenge,serviceId,publicKey,metadata:{version:1,label:'Office computer',rootLabel:'Shared project',address:'https://localhost:3411'}},f.originalBundle),proof=(await signObject(pair.approval.body,service.privateKey)).signature;
 await f.delivery.pair(f.auth.cookieValue,f.auth.csrfToken,{...pair,proof});const paired=(await f.delivery.services(f.auth.cookieValue,f.auth.csrfToken,f.reference())).services[0]!;
 assert.equal((await readDeliveryService({...input,service:paired},f.originalBundle)).metadata.label,'Office computer');
 const record=await f.delivery.get(f.auth.cookieValue,f.auth.csrfToken,{...f.reference(),batchId:f.prepared.batchId}),material=await preparePublicationMaterial({...input,record,service:paired,manifests:[f.source.manifest]},f.originalBundle);
 assert.deepEqual(Object.keys(material),['detailsKey']);const key=base64urlDecode(material.detailsKey,32);await sodium.ready;
 const plain=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,base64urlDecode(record.batch.body.details.ciphertext),canonicalJson(deliveryMetadataContext(record.batch.body,'details')),base64urlDecode(record.batch.body.details.nonce),key);
 assert.deepEqual(JSON.parse(new TextDecoder().decode(plain)),f.prepared.details);key.fill(0);plain.fill(0);
});
test('Delivery drafts persist only exact signed ciphertext and stay origin/profile/device scoped across interrupted saves',async t=>{
 const f=await clientFixture(t),factory=new IDBFactory(),store=await IndexedDeliveryStore.open(origin,randomUUID(),factory);t.after(()=>store.close());
 const record={version:1 as const,origin,workspaceId:f.workspaceId,accountId:f.accountId,deviceId:f.deviceId,operationId:f.payload.batch.body.binding.operationId,action:'create' as const,payload:f.payload};
 await store.put(record);await store.put(record);assert.deepEqual(await store.get(f.workspaceId,record.operationId),record);
 assert.equal(JSON.stringify(await store.list(record)).includes('Approved.txt'),false);
 const changed=structuredClone(record);changed.payload.batch.body.details.ciphertext=base64urlEncode(new Uint8Array(17));await assert.rejects(store.put(changed));
 assert.equal((await store.list({...record,deviceId:randomUUID()})).length,0);await store.forgetDevice(record);assert.equal(await store.get(f.workspaceId,record.operationId),undefined);
});

import sodium from 'libsodium-wrappers';
import { z } from 'zod';
import { binary,digest } from '../shared/contracts.js';
import { base64urlDecode,base64urlEncode,canonicalJson,digestObject,signObject,verifyObject } from '../shared/crypto.js';
import { parseJsonStrict } from '../shared/json.js';
import { fileBinding,fileBindingFromPlanning,FILE_MAX_BATCH_BYTES,FILE_MAX_METADATA_BYTES,verifyFileManifest,type FileBinding,type FileManifest } from '../shared/files.js';
import { deliveryBatch,deliveryBatchBody,deliveryCommandRequest,deliveryMetadataContext,deliveryPairBody,deliveryPairChallenge,deliveryPairMetadataContext,
  deliveryPairRequest,deliveryPublishRequest,deliveryRecord,deliveryServiceCommandRequest,deliveryServiceRecord,publicationReceipt,verifyDeliveryBatch,verifyOwnerFileObject,
  type DeliveryBatch,type DeliveryRecord,type PublicationReceipt } from '../shared/file-delivery.js';
import { FileClientError,readFiles,type ReadableFileMetadata } from './files-crypto.js';
import { openVerifiedPlanning,planningSecurityResolver,type ReadPlanningInput } from './planning-crypto.js';
import type { DeviceBundle } from './device-store.js';
import { deliveryDetails,localRelativePath,type DeliveryDetails } from '../shared/local-files.js';

const utf8=new TextEncoder(),decode=new TextDecoder('utf-8',{fatal:true});
const safeText=(max:number)=>z.string().max(max).refine(v=>!/[\u0000-\u001f\u007f]/u.test(v));
/** Destinations are names beneath an explicitly chosen root; never executable paths. */
export const deliveryRelativePath=localRelativePath;
export const privateDeliveryDetails=deliveryDetails;
export type PrivateDeliveryDetails=DeliveryDetails;
export const privateDeliveryService=z.strictObject({version:z.literal(1),label:safeText(240).trim().min(1),rootLabel:safeText(240),address:z.string().url().max(2048).refine(value=>{
  const url=new URL(value);return !url.username&&!url.password&&!url.search&&!url.hash&&url.pathname==='/'&&
    (url.protocol==='https:'||url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname));
})});
export type PrivateDeliveryService=z.infer<typeof privateDeliveryService>;
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
function invalid():never{throw new FileClientError('INVALID_FILE');}
const placeholder=()=>({nonce:base64urlEncode(new Uint8Array(24)),ciphertext:base64urlEncode(new Uint8Array(16))});
async function opened(input:ReadPlanningInput,bundle:DeviceBundle,owner=true){
  const result=await openVerifiedPlanning({...input,historyPlaintext:false},bundle);
  if(owner&&!result.context.binding.isOwner)invalid();return result;
}
async function authority(input:ReadPlanningInput&{binding:FileBinding},bundle:DeviceBundle){
  const result=await opened(input,bundle),binding=fileBinding.parse(input.binding);
  if(!same(binding,fileBindingFromPlanning(result.context.binding))||Date.parse(binding.expiresAt)<=Date.now())invalid();
  return {...result,binding};
}
function scope(batch:DeliveryBatch,input:ReadPlanningInput){
  const a=batch.body.binding,b=input.context.binding;
  if(a.workspaceId!==b.workspaceId||a.projectId!==b.projectId||a.origin!==b.origin||BigInt(a.dataGeneration)>BigInt(b.dataGeneration))invalid();
}
async function seal(value:unknown,key:Uint8Array,aad:unknown){
  await sodium.ready;const plain=utf8.encode(canonicalJson(value));
  if(plain.length+16>FILE_MAX_METADATA_BYTES){plain.fill(0);throw new FileClientError('TOO_LARGE');}
  const nonce=sodium.randombytes_buf(24);
  try{return {nonce:base64urlEncode(nonce),ciphertext:base64urlEncode(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain,canonicalJson(aad),null,nonce,key))};}
  finally{plain.fill(0);}
}
async function decrypt(value:{nonce:string;ciphertext:string},key:Uint8Array,aad:unknown):Promise<unknown>{
  await sodium.ready;
  try{const plain=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,base64urlDecode(value.ciphertext),canonicalJson(aad),base64urlDecode(value.nonce,24),key);
    try{return parseJsonStrict(decode.decode(plain));}finally{plain.fill(0);}}
  catch{invalid();}
}
async function sign<T extends {purpose:string}>(body:T,bundle:DeviceBundle){
  const key=base64urlDecode(bundle.signingPrivateKey,64);try{return await signObject(body,key);}finally{key.fill(0);}
}
function validatePaths(batch:DeliveryBatch['body'],details:PrivateDeliveryDetails){
  if(batch.items.length!==details.items.length)invalid();const paths:string[]=[];
  for(let i=0;i<batch.items.length;i++){
    const publicItem=batch.items[i]!,privateItem=details.items[i]!,moving=['move','rename'].includes(publicItem.operation);
    if(moving!==(privateItem.fromPath!==undefined)||privateItem.destination===privateItem.fromPath||
      (publicItem.operation==='add')!==(privateItem.expectedOldSha256===null)||
      (moving||publicItem.operation==='remove')&&privateItem.expectedOldSha256!==privateItem.sha256)invalid();
    for(const path of [privateItem.destination,...(privateItem.fromPath?[privateItem.fromPath]:[])]){
      if(paths.some(other=>other===path||path.startsWith(`${other}/`)||other.startsWith(`${path}/`)))invalid();paths.push(path);
    }
  }
}
async function checkManifests(input:ReadPlanningInput,manifests:FileManifest[],batch:DeliveryBatch['body'],details:PrivateDeliveryDetails,bundle:DeviceBundle){
  validatePaths(batch,details);if(manifests.length!==batch.items.length)invalid();
  const metadata=await readFiles({...input,manifests},bundle);let managedBytes=0;
  for(let i=0;i<batch.items.length;i++){
    const item=batch.items[i]!,detail=details.items[i]!,manifest=manifests[i]!,body=manifest.body;
    const data:ReadableFileMetadata|undefined=metadata.find(row=>row.versionId===item.versionId)?.metadata;
    if(!data||body.fileId!==item.fileId||body.versionId!==item.versionId||await digestObject(manifest)!==item.manifestDigest||
      detail.sha256!==data.sha256||detail.plainBytes!==body.plainBytes||detail.filename!==data.filename||
      (body.storage==='external')!==(detail.externalPath!==undefined)||detail.externalPath!==data.path)invalid();
    if(body.storage==='managed'&&item.operation!=='remove')managedBytes+=body.plainBytes;
  }
  if(managedBytes>FILE_MAX_BATCH_BYTES)throw new FileClientError('TOO_LARGE');
}
export interface PrepareDeliveryInput extends ReadPlanningInput {binding:FileBinding;batchId:string;supersedes:string|null;
  items:DeliveryBatch['body']['items'];details:PrivateDeliveryDetails;manifests:FileManifest[]}
/** A random batch key opens only this exact frozen operation list, never project content keys. */
export async function prepareDelivery(input:PrepareDeliveryInput,bundle:DeviceBundle):Promise<{batch:DeliveryBatch}>{
  const auth=await authority(input,bundle),details=privateDeliveryDetails.parse(input.details),body=deliveryBatchBody.parse({purpose:'ukda.file-delivery.v1',binding:auth.binding,
    batchId:input.batchId,supersedes:input.supersedes,items:input.items,metadata:placeholder(),details:placeholder()});
  await checkManifests(input,input.manifests,body,details,bundle);
  const entry=auth.ring.find(k=>k.epoch===body.binding.keyEpoch);if(!entry)throw new FileClientError('INCOMPLETE_KEYS');
  await sodium.ready;const projectKey=base64urlDecode(entry.key,32),batchKey=sodium.randombytes_buf(32);
  try{body.metadata=await seal({version:1,key:base64urlEncode(batchKey)},projectKey,deliveryMetadataContext(body,'key'));
    body.details=await seal(details,batchKey,deliveryMetadataContext(body,'details'));return {batch:deliveryBatch.parse(await sign(body,bundle))};
  }finally{projectKey.fill(0);batchKey.fill(0);}
}
export interface ReadDeliveryInput extends ReadPlanningInput {record:DeliveryRecord;manifests:FileManifest[];service?:z.infer<typeof deliveryServiceRecord>}
async function batchMaterial(input:ReadDeliveryInput,bundle:DeviceBundle){
  const auth=await opened(input,bundle),record=deliveryRecord.parse(input.record),securityAt=planningSecurityResolver(input.history,auth.state),batch=await verifyDeliveryBatch(record.batch,securityAt);
  scope(batch,input);if(record.frozenDigest!==await digestObject(batch))invalid();
  if(record.confirmation){await verifyOwnerFileObject(record.confirmation,securityAt,'ukda.file-delivery-command.v1');
    if(record.confirmation.body.action!=='confirm'||record.confirmation.body.batchId!==batch.body.batchId||record.confirmation.body.frozenDigest!==record.frozenDigest)invalid();}
  if(['confirmed','published'].includes(record.state)&&!record.confirmation)invalid();
  if(record.publication){if(!input.service)invalid();await checkedService(input,input.service,bundle);
    const receipt=publicationReceipt.parse(record.publication),body=receipt.body;
    if(body.batchId!==batch.body.batchId||body.frozenDigest!==record.frozenDigest||body.serviceId!==input.service.serviceId||body.workspaceId!==batch.body.binding.workspaceId||body.projectId!==batch.body.binding.projectId||
      !await verifyObject(receipt,base64urlDecode(input.service.publicKey,32),'ukda.local-file-publication.v1'))invalid();}
  if(record.state==='published'&&!record.publication)invalid();
  const entry=auth.ring.find(k=>k.epoch===batch.body.binding.keyEpoch);if(!entry)throw new FileClientError('INCOMPLETE_KEYS');const projectKey=base64urlDecode(entry.key,32);
  let batchKey:Uint8Array|undefined;
  try{const wrapping=z.strictObject({version:z.literal(1),key:binary(32)}).parse(await decrypt(batch.body.metadata,projectKey,deliveryMetadataContext(batch.body,'key')));
    batchKey=base64urlDecode(wrapping.key,32);const details=privateDeliveryDetails.parse(await decrypt(batch.body.details,batchKey,deliveryMetadataContext(batch.body,'details')));
    await checkManifests(input,input.manifests,batch.body,details,bundle);return {auth,record,details,batchKey};
  }catch(error){batchKey?.fill(0);throw error;}finally{projectKey.fill(0);}
}
export async function readDelivery(input:ReadDeliveryInput,bundle:DeviceBundle):Promise<{details:PrivateDeliveryDetails;versions:{versionId:string;version:string;documentReference:string}[]}>{
  const material=await batchMaterial(input,bundle);
  try{const files=await readFiles({...input,manifests:input.manifests},bundle);return {details:material.details,versions:input.manifests.map(manifest=>{
    const data=files.find(file=>file.versionId===manifest.body.versionId);if(!data)invalid();return {versionId:manifest.body.versionId,version:manifest.body.version,documentReference:data.metadata.documentReference};})};
  }finally{material.batchKey.fill(0);}
}
export interface PrepareDeliveryCommandInput extends ReadDeliveryInput {binding:FileBinding;action:'confirm'|'cancel'|'record_package'}
export async function prepareDeliveryCommand(input:PrepareDeliveryCommandInput,bundle:DeviceBundle){
  const auth=await authority(input,bundle),material=await batchMaterial(input,bundle);material.batchKey.fill(0);
  if(material.record.batch.body.binding.dataGeneration!==auth.binding.dataGeneration||input.action==='confirm'&&material.record.state!=='frozen'||input.action==='cancel'&&!['frozen','confirmed'].includes(material.record.state)||input.action==='record_package'&&material.record.state!=='confirmed')invalid();
  const body=deliveryCommandRequest.shape.mutation.shape.body.parse({purpose:'ukda.file-delivery-command.v1',binding:auth.binding,batchId:material.record.batch.body.batchId,frozenDigest:material.record.frozenDigest,action:input.action});
  return deliveryCommandRequest.parse({mutation:await sign(body,bundle)});
}
export interface PrepareDeliveryPairInput extends ReadPlanningInput {binding:FileBinding;challenge:z.infer<typeof deliveryPairChallenge>;serviceId:string;publicKey:string;metadata:PrivateDeliveryService}
export async function prepareDeliveryPair(input:PrepareDeliveryPairInput,bundle:DeviceBundle):Promise<{approval:z.infer<typeof deliveryPairRequest>['approval']}>{
  const auth=await authority(input,bundle),challenge=deliveryPairChallenge.parse(input.challenge),metadata=privateDeliveryService.parse(input.metadata);
  if(Date.parse(challenge.expiresAt)<=Date.now()||Date.parse(challenge.issuedAt)>Date.now()+30000||Date.parse(challenge.expiresAt)-Date.parse(challenge.issuedAt)>600000)invalid();
  const body=deliveryPairBody.parse({purpose:'ukda.file-service-pair.v1',binding:auth.binding,serviceId:input.serviceId,publicKey:input.publicKey,pairingId:challenge.pairingId,nonce:challenge.nonce,metadata:placeholder()});
  const entry=auth.ring.find(k=>k.epoch===body.binding.keyEpoch);if(!entry)throw new FileClientError('INCOMPLETE_KEYS');const key=base64urlDecode(entry.key,32);
  try{body.metadata=await seal(metadata,key,deliveryPairMetadataContext(body));return {approval:await sign(body,bundle)};}finally{key.fill(0);}
}
export interface ReadDeliveryServiceInput extends ReadPlanningInput {service:z.infer<typeof deliveryServiceRecord>}
async function checkedService(input:ReadPlanningInput,service:z.infer<typeof deliveryServiceRecord>,bundle:DeviceBundle){
  const auth=await opened(input,bundle,false),record=deliveryServiceRecord.parse(service),approval=deliveryPairRequest.parse(record.approval),body=approval.approval.body;
  await verifyOwnerFileObject(approval.approval,planningSecurityResolver(input.history,auth.state),'ukda.file-service-pair.v1');
  if(body.binding.workspaceId!==auth.context.binding.workspaceId||body.binding.projectId!==auth.context.binding.projectId||body.serviceId!==record.serviceId||body.publicKey!==record.publicKey||
    body.binding.dataGeneration!==record.dataGeneration||!await verifyObject({body,signature:approval.proof},base64urlDecode(record.publicKey,32),'ukda.file-service-pair.v1'))invalid();
  return {auth,record,body};
}
export async function readDeliveryService(input:ReadDeliveryServiceInput,bundle:DeviceBundle):Promise<{metadata:PrivateDeliveryService}>{
  const {auth,body}=await checkedService(input,input.service,bundle),entry=auth.ring.find(k=>k.epoch===body.binding.keyEpoch);if(!entry)throw new FileClientError('INCOMPLETE_KEYS');const key=base64urlDecode(entry.key,32);
  try{return {metadata:privateDeliveryService.parse(await decrypt(body.metadata,key,deliveryPairMetadataContext(body)))};}finally{key.fill(0);}
}
export interface PrepareDeliveryServiceRevocationInput extends ReadDeliveryServiceInput {binding:FileBinding}
export async function prepareDeliveryServiceRevocation(input:PrepareDeliveryServiceRevocationInput,bundle:DeviceBundle){
  const auth=await authority(input,bundle),{record}=await checkedService(input,input.service,bundle);if(record.state!=='active'||record.dataGeneration!==auth.binding.dataGeneration)invalid();
  const body=deliveryServiceCommandRequest.shape.mutation.shape.body.parse({purpose:'ukda.file-service-revoke.v1',binding:auth.binding,serviceId:record.serviceId,publicKey:record.publicKey});
  return deliveryServiceCommandRequest.parse({mutation:await sign(body,bundle)});
}
export interface PrepareDeliveryPublishInput extends ReadDeliveryInput {binding:FileBinding;service:z.infer<typeof deliveryServiceRecord>;receipt:PublicationReceipt}
export async function prepareDeliveryPublish(input:PrepareDeliveryPublishInput,bundle:DeviceBundle){
  const auth=await authority(input,bundle),material=await batchMaterial(input,bundle);material.batchKey.fill(0);const {record}=await checkedService(input,input.service,bundle),receipt=publicationReceipt.parse(input.receipt),b=receipt.body;
  if(material.record.batch.body.binding.dataGeneration!==auth.binding.dataGeneration||material.record.state!=='confirmed'||record.state!=='active'||record.dataGeneration!==auth.binding.dataGeneration||b.serviceId!==record.serviceId||b.workspaceId!==auth.binding.workspaceId||b.projectId!==auth.binding.projectId||
    b.batchId!==material.record.batch.body.batchId||b.frozenDigest!==material.record.frozenDigest||b.permitIds.length!==material.record.batch.body.items.length||Date.parse(b.completedAt)>Date.now()+30000||Date.parse(b.completedAt)<Date.parse(b.startedAt)||
    !await verifyObject(receipt,base64urlDecode(record.publicKey,32),'ukda.local-file-publication.v1'))invalid();
  const body=deliveryPublishRequest.shape.mutation.shape.body.parse({purpose:'ukda.file-delivery-published.v1',binding:auth.binding,batchId:b.batchId,frozenDigest:b.frozenDigest,receipt});
  return deliveryPublishRequest.parse({mutation:await sign(body,bundle)});
}
export interface PreparePublicationMaterialInput extends ReadDeliveryInput {service:z.infer<typeof deliveryServiceRecord>}
/** Ephemeral grant: relay only to the authenticated, pinned local service and never save it in storage. */
export async function preparePublicationMaterial(input:PreparePublicationMaterialInput,bundle:DeviceBundle):Promise<{detailsKey:string}>{
  const material=await batchMaterial(input,bundle);
  try{const {record}=await checkedService(input,input.service,bundle);if(material.record.batch.body.binding.dataGeneration!==material.auth.context.binding.dataGeneration||material.record.state!=='confirmed'||record.state!=='active'||record.dataGeneration!==material.auth.context.binding.dataGeneration)invalid();
    return {detailsKey:base64urlEncode(material.batchKey)};
  }finally{material.batchKey.fill(0);}
}

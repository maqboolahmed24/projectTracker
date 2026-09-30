import sodium from 'libsodium-wrappers';
import { z } from 'zod';
import { binary,counter,digest,identifier,positiveCounter } from '../shared/contracts.js';
import { base64urlDecode,base64urlEncode,canonicalJson } from '../shared/crypto.js';
import { parseJsonStrict } from '../shared/json.js';
import { FILE_MAX_BATCH_ITEMS,FILE_MAX_BATCH_BYTES,FILE_EXTERNAL_MAX_BYTES,FILE_MAX_PLAIN_BYTES } from '../shared/files.js';
import { openVerifiedPlanning,type ReadPlanningInput } from './planning-crypto.js';
import type { DeviceBundle } from './device-store.js';
import { FileClientError } from './files-crypto.js';

const text=(max:number)=>z.string().max(max).refine(v=>!/[\u0000-\u001f\u007f]/u.test(v));
export const fileBulkItem=z.strictObject({id:identifier,taskId:identifier,createOperationId:identifier,uploadOperationId:identifier,submitOperationId:identifier,assignOperationId:identifier,
 fileId:identifier,versionId:identifier,existingFileId:identifier.nullable(),expectedVersionId:identifier.nullable(),documentReference:text(128).trim(),title:text(240).trim(),
 filename:text(240),plainBytes:z.number().int().nonnegative().max(FILE_EXTERNAL_MAX_BYTES),sha256:digest.nullable(),storage:z.enum(['managed','external']),path:text(4096),
 assigneeIds:z.array(identifier).max(32).refine(v=>new Set(v).size===v.length),leadProfileId:identifier.nullable(),reviewerProfileId:identifier.nullable(),phaseId:identifier.nullable(),
 state:z.enum(['ready','working','saved','error','skipped']),stage:z.enum(['pending','task_created','file_saved','submitted','assigned']),errorCode:text(64).nullable()});
export const fileBulkDraft=z.strictObject({version:z.literal(1),batchId:identifier,projectId:identifier,mode:z.enum(['register','assign','submit']),createdAt:z.iso.datetime(),label:text(240).min(1),revision:counter,
 items:z.array(fileBulkItem).min(1).max(FILE_MAX_BATCH_ITEMS)}).superRefine((v,c)=>{
 const fail=()=>c.addIssue({code:'custom',message:'Invalid bulk operation'}),active=v.items.filter(i=>i.state!=='skipped');
 if(new Set(v.items.map(i=>i.id)).size!==v.items.length||new Set(active.map(i=>i.taskId)).size!==active.length||
  v.mode==='register'&&new Set(active.map(i=>i.documentReference.toLowerCase())).size!==active.length||
  active.reduce((n,i)=>n+(i.storage==='managed'?i.plainBytes:0),0)>FILE_MAX_BATCH_BYTES)fail();
 for(const item of active){if(!item.documentReference||!item.title)fail();if(v.mode!=='assign'&&(!item.filename||!item.sha256||item.plainBytes<1||item.storage==='managed'&&item.plainBytes>FILE_MAX_PLAIN_BYTES||item.storage==='external'&&!item.path))fail();
  if(item.reviewerProfileId&&item.assigneeIds.includes(item.reviewerProfileId)||item.leadProfileId&&!item.assigneeIds.includes(item.leadProfileId))fail();}
});
export type FileBulkDraft=z.infer<typeof fileBulkDraft>;export type FileBulkItem=z.infer<typeof fileBulkItem>;
export const storedFileBulk=z.strictObject({version:z.literal(1),origin:z.string().url(),workspaceId:identifier,accountId:identifier,deviceId:identifier,projectId:identifier,batchId:identifier,
 dataGeneration:positiveCounter,keyEpoch:positiveCounter,revision:counter,nonce:binary(24),ciphertext:binary(16,1024*1024)});
export type StoredFileBulk=z.infer<typeof storedFileBulk>;
function context(record:Omit<StoredFileBulk,'nonce'|'ciphertext'>){return {...record,purpose:'ukda.file-bulk-private.v1'};}
export interface SealFileBulkInput extends ReadPlanningInput {draft:FileBulkDraft}
export interface OpenFileBulkInput extends ReadPlanningInput {record:StoredFileBulk}
export async function sealFileBulk(input:SealFileBulkInput,bundle:DeviceBundle):Promise<StoredFileBulk>{
 const opened=await openVerifiedPlanning({...input,historyPlaintext:false},bundle),draft=fileBulkDraft.parse(input.draft),b=opened.context.binding;
 if(draft.projectId!==b.projectId)throw new FileClientError('CONFLICT');const k=opened.ring.find(v=>v.epoch===b.keyEpoch);if(!k)throw new FileClientError('INCOMPLETE_KEYS');
 const header={version:1 as const,origin:b.origin,workspaceId:b.workspaceId,accountId:b.accountId,deviceId:b.deviceId,projectId:b.projectId,batchId:draft.batchId,dataGeneration:b.dataGeneration,keyEpoch:b.keyEpoch,revision:draft.revision},key=base64urlDecode(k.key,32),plain=new TextEncoder().encode(canonicalJson(draft));
 await sodium.ready;const nonce=sodium.randombytes_buf(24);try{if(plain.length+16>1024*1024)throw new FileClientError('TOO_LARGE');return storedFileBulk.parse({...header,nonce:base64urlEncode(nonce),ciphertext:base64urlEncode(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain,canonicalJson(context(header)),null,nonce,key))});}finally{plain.fill(0);key.fill(0);}
}
export async function openFileBulk(input:OpenFileBulkInput,bundle:DeviceBundle):Promise<FileBulkDraft>{
 const opened=await openVerifiedPlanning({...input,historyPlaintext:false},bundle),record=storedFileBulk.parse(input.record),b=opened.context.binding;
 if(record.origin!==b.origin||record.workspaceId!==b.workspaceId||record.projectId!==b.projectId||record.accountId!==b.accountId||record.deviceId!==b.deviceId||record.dataGeneration!==b.dataGeneration)throw new FileClientError('CONFLICT');
 const k=opened.ring.find(v=>v.epoch===record.keyEpoch);if(!k)throw new FileClientError('INCOMPLETE_KEYS');const key=base64urlDecode(k.key,32),{nonce,ciphertext,...header}=record;await sodium.ready;
 try{const plain=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,base64urlDecode(ciphertext),canonicalJson(context(header)),base64urlDecode(nonce,24),key);try{const draft=fileBulkDraft.parse(parseJsonStrict(new TextDecoder('utf-8',{fatal:true}).decode(plain)));if(draft.batchId!==record.batchId||draft.projectId!==record.projectId||draft.revision!==record.revision)throw new FileClientError('CONFLICT');return draft;}finally{plain.fill(0);}}finally{key.fill(0);}
}

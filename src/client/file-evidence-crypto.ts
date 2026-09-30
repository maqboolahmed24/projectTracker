import sodium from 'libsodium-wrappers';
import { z } from 'zod';
import { digest } from '../shared/contracts.js';
import { base64urlDecode,base64urlEncode,canonicalJson,digestObject,signObject,verifyObject } from '../shared/crypto.js';
import { fileBindingFromPlanning,verifyFileManifest,type FileManifest } from '../shared/files.js';
import { evidenceContext,fileVerification,fileSubmission,fileReview,sharedFileApproval,fileRevocation,fileEvidenceCipherContext,verifyFileEvidence,
 type EvidenceContext,type FileVerification,type FileSubmission,type FileReview,type SharedFileApproval,type FileRevocation } from '../shared/file-evidence.js';
import { parseJsonStrict } from '../shared/json.js';
import type { DeviceBundle } from './device-store.js';
import { openVerifiedPlanning,planningSecurityResolver,type ReadPlanningInput } from './planning-crypto.js';
import { FileClientError,readFiles,readFileBytes,hashSelectedFile } from './files-crypto.js';
const text=new TextEncoder(),decode=new TextDecoder('utf-8',{fatal:true}),same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
const hashProof=z.strictObject({sha256:digest,plainBytes:z.number().int().positive(),storage:z.enum(['managed','external']),locallyVerified:z.literal(true)});
const verificationSet=z.strictObject({sources:z.array(z.strictObject({fileId:z.string().uuid(),versionId:z.string().uuid(),manifestDigest:digest,...hashProof.shape})).max(64),outputs:z.array(z.strictObject({fileId:z.string().uuid(),versionId:z.string().uuid(),manifestDigest:digest,...hashProof.shape})).max(64)});
function invalid():never{throw new FileClientError('INVALID_FILE');}
async function opened(input:ReadPlanningInput,bundle:DeviceBundle){return openVerifiedPlanning({...input,historyPlaintext:false},bundle);}
async function seal(body:Parameters<typeof fileEvidenceCipherContext>[0],value:unknown,key:string){await sodium.ready;const raw=base64urlDecode(key,32),nonce=sodium.randombytes_buf(24),plain=text.encode(canonicalJson(value));
 try{return {nonce:base64urlEncode(nonce),ciphertext:base64urlEncode(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain,canonicalJson(fileEvidenceCipherContext(body)),null,nonce,raw))};}finally{raw.fill(0);plain.fill(0);}}
async function decrypt(body:Parameters<typeof fileEvidenceCipherContext>[0],value:{nonce:string;ciphertext:string},key:string):Promise<unknown>{await sodium.ready;const raw=base64urlDecode(key,32);
 try{const plain=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,base64urlDecode(value.ciphertext),canonicalJson(fileEvidenceCipherContext(body)),base64urlDecode(value.nonce,24),raw);try{return parseJsonStrict(decode.decode(plain));}finally{plain.fill(0);}}catch{invalid();}finally{raw.fill(0);}}
async function sign<T extends {purpose:string}>(body:T,bundle:DeviceBundle){const key=base64urlDecode(bundle.signingPrivateKey,64);try{return await signObject(body,key);}finally{key.fill(0);}}
const placeholder=()=>({nonce:base64urlEncode(new Uint8Array(24)),ciphertext:base64urlEncode(new Uint8Array(16))});
export interface PrepareFileVerificationInput extends ReadPlanningInput {manifest:FileManifest;chunks?:string[];file?:Blob}
/** Each proof requires actual bytes inside the worker, including external selections. */
export async function prepareFileVerification(input:PrepareFileVerificationInput,bundle:DeviceBundle):Promise<FileVerification>{
 const verified=await opened(input,bundle),manifest=await verifyFileManifest(input.manifest,planningSecurityResolver(input.history,verified.state)),binding=fileBindingFromPlanning(verified.context.binding),b=manifest.body;
 if(b.binding.projectId!==binding.projectId||b.binding.workspaceId!==binding.workspaceId)invalid();
 const [metadata]=await readFiles({...input,manifests:[manifest]},bundle);if(!metadata)invalid();
 if(b.storage==='managed'){if(input.file||!input.chunks)invalid();const bytes=await readFileBytes({...input,manifest,chunks:input.chunks},bundle);bytes.fill(0);}
 else if(!input.file||input.chunks||input.file.size!==b.plainBytes||await hashSelectedFile(input.file)!==metadata.metadata.sha256)throw new FileClientError('CHANGED_FILE');
 const ring=verified.ring.find(k=>k.epoch===binding.keyEpoch);if(!ring)throw new FileClientError('INCOMPLETE_KEYS');
 const body=fileVerification.shape.body.parse({purpose:'ukda.file-local-verification.v1',binding,reference:{fileId:b.fileId,versionId:b.versionId,manifestDigest:await digestObject(manifest)},verification:placeholder()});
 body.verification=await seal(body,{sha256:metadata.metadata.sha256,plainBytes:b.plainBytes,storage:b.storage,locallyVerified:true},ring.key);
 return fileVerification.parse(await sign(body,bundle));
}
export interface EvidenceCryptoInput extends ReadPlanningInput {evidence:EvidenceContext}
async function authority(input:EvidenceCryptoInput,bundle:DeviceBundle){const verified=await opened(input,bundle),e:EvidenceContext=evidenceContext.parse(input.evidence);
 if(!same(e.planning.binding,verified.context.binding)||!same(e.binding,fileBindingFromPlanning(verified.context.binding)))invalid();
 const key=verified.ring.find(k=>k.epoch===e.binding.keyEpoch)?.key;if(!key)throw new FileClientError('INCOMPLETE_KEYS');
 const securityAt=planningSecurityResolver(input.history,verified.state);return {verified,e,key,securityAt};}
async function proofSet(input:EvidenceCryptoInput,bundle:DeviceBundle,proofs:FileVerification[]){const auth=await authority(input,bundle),{e,key}=auth;
 if(proofs.length!==e.sources.length+e.outputs.length)invalid();const result:{sources:z.infer<typeof verificationSet>['sources'];outputs:z.infer<typeof verificationSet>['outputs']}={sources:[],outputs:[]};
 for(const kind of ['sources','outputs'] as const)for(const reference of e[kind]){
  const proof=fileVerification.parse(proofs.find(x=>x.body.reference.versionId===reference.versionId));
  if(!same(proof.body.binding,e.binding)||!same(proof.body.reference,reference)||!await verifyObject(proof,base64urlDecode(e.binding.signingPublicKey),'ukda.file-local-verification.v1'))invalid();
  const local=hashProof.parse(await decrypt(proof.body,proof.body.verification,key)),manifest=e.manifests.find(m=>m.body.versionId===reference.versionId);
  if(!manifest||await digestObject(await verifyFileManifest(manifest,auth.securityAt))!==reference.manifestDigest||local.plainBytes!==manifest.body.plainBytes||local.storage!==manifest.body.storage)invalid();
  const [data]=await readFiles({...input,manifests:[manifest]},bundle);if(!data||data.metadata.sha256!==local.sha256)invalid();result[kind].push({...reference,...local});
 }
 return {...auth,verification:verificationSet.parse(result)};
}
export async function readFileEvidence(input:EvidenceCryptoInput,bundle:DeviceBundle):Promise<{verified:true}>{const {e,key,securityAt,verified}=await authority(input,bundle);
 for(const manifest of e.manifests)await verifyFileManifest(manifest,securityAt);
 const scope=(b:{workspaceId:string;projectId:string;dataGeneration:string})=>{if(b.workspaceId!==e.binding.workspaceId||b.projectId!==e.binding.projectId||BigInt(b.dataGeneration)>BigInt(e.binding.dataGeneration))invalid();};
 if(e.submission){scope(e.submission.body.binding);if(e.submission.body.taskId!==e.taskId)invalid();}
 if(e.approval){scope(e.approval.body.binding);const b=e.approval.body;if(b.purpose==='ukda.file-review.v1'){if(!e.submission||b.submissionId!==e.submission.body.submissionId||b.submissionDigest!==await digestObject(e.submission)||b.taskId!==e.taskId)invalid();}else if(![...e.sources,...e.outputs].some(r=>same(r,b.reference)))invalid();}
 if(e.revocation){scope(e.revocation.body.binding);if(e.revocation.body.approvalId!==e.approval?.body.approvalId)invalid();}
 if(e.submission){await verifyFileEvidence(e.submission,securityAt);const k=verified.ring.find(x=>x.epoch===e.submission!.body.binding.keyEpoch)?.key;if(!k)invalid();verificationSet.parse(await decrypt(e.submission.body,e.submission.body.verification,k));}
 if(e.approval){await verifyFileEvidence(e.approval,securityAt,e.approval.body.purpose==='ukda.shared-file-approval.v1');const k=verified.ring.find(x=>x.epoch===e.approval!.body.binding.keyEpoch)?.key;if(!k)invalid();await decrypt(e.approval.body,e.approval.body.verification,k);}
 if(e.revocation){await verifyFileEvidence(e.revocation,securityAt,true);const k=verified.ring.find(x=>x.epoch===e.revocation!.body.binding.keyEpoch)?.key;if(!k)invalid();await decrypt(e.revocation.body,e.revocation.body.reason,k);}
 void key;return {verified:true};}
export interface PrepareFileSubmissionInput extends EvidenceCryptoInput {proofs:FileVerification[];submissionId:string}
export async function prepareFileSubmission(input:PrepareFileSubmissionInput,bundle:DeviceBundle):Promise<{submission:FileSubmission}>{const {e,key,verification}=await proofSet(input,bundle,input.proofs),task=e.planning.graph.tasks.find(t=>t.id===e.taskId);
 if(!task||e.planning.graph.version!==2||!e.planning.graph.project.reviewEnabled||!task.contentRevision||!e.outputs.length||!['todo','in_progress'].includes(task.state))invalid();
 const body=fileSubmission.shape.body.parse({purpose:'ukda.file-submission.v1',binding:e.binding,submissionId:input.submissionId,taskId:task.id,taskRevision:task.revision,
 taskContentRevision:task.contentRevision,reviewPolicyRevision:e.planning.graph.project.reviewPolicyRevision,sources:e.sources,outputs:e.outputs,verification:placeholder()});
 body.verification=await seal(body,verification,key);return {submission:fileSubmission.parse(await sign(body,bundle))};}
export interface PrepareFileReviewInput extends EvidenceCryptoInput {proofs:FileVerification[];approvalId:string}
export async function prepareFileReview(input:PrepareFileReviewInput,bundle:DeviceBundle):Promise<{review:FileReview}>{const {e,key,verification,securityAt,verified}=await proofSet(input,bundle,input.proofs),s=e.submission,t=e.planning.graph.tasks.find(t=>t.id===e.taskId);
 if(!s||!t||t.state!=='review'||t.reviewerProfileId!==e.binding.accountId||t.assigneeIds.includes(e.binding.accountId)||e.manifests.some(m=>m.body.kind==='output'&&m.body.binding.accountId===e.binding.accountId)||!same(s.body.sources,e.sources)||!same(s.body.outputs,e.outputs)||
 t.submittedRevision!==s.body.taskContentRevision||t.submittedPolicyRevision!==s.body.reviewPolicyRevision||t.contentRevision!==s.body.taskContentRevision)invalid();
 await verifyFileEvidence(s,securityAt);const k=verified.ring.find(x=>x.epoch===s.body.binding.keyEpoch)?.key;if(!k)invalid();if(!same(verificationSet.parse(await decrypt(s.body,s.body.verification,k)),verification))invalid();
 const body=fileReview.shape.body.parse({purpose:'ukda.file-review.v1',binding:e.binding,approvalId:input.approvalId,submissionId:s.body.submissionId,submissionDigest:await digestObject(s),taskId:t.id,
 taskContentRevision:s.body.taskContentRevision,reviewPolicyRevision:s.body.reviewPolicyRevision,reviewTaskRevision:t.revision,decision:'accept',verification:placeholder()});body.verification=await seal(body,verification,key);
 return {review:fileReview.parse(await sign(body,bundle))};}
export interface PrepareSharedFileApprovalInput extends EvidenceCryptoInput {proofs:FileVerification[];approvalId:string}
export async function prepareSharedFileApproval(input:PrepareSharedFileApprovalInput,bundle:DeviceBundle):Promise<{approval:SharedFileApproval}>{const {e,key,verification}=await proofSet(input,bundle,input.proofs);
 if(e.planning.binding.version===1||!e.planning.binding.isOwner||e.taskId!==null||e.sources.length!==1||e.outputs.length)invalid();
 const body=sharedFileApproval.shape.body.parse({purpose:'ukda.shared-file-approval.v1',binding:e.binding,approvalId:input.approvalId,reference:e.sources[0],verification:placeholder()});body.verification=await seal(body,verification.sources[0],key);
 return {approval:sharedFileApproval.parse(await sign(body,bundle))};}
export interface PrepareFileRevocationInput extends EvidenceCryptoInput {approvalId:string;reason:string}
export async function prepareFileRevocation(input:PrepareFileRevocationInput,bundle:DeviceBundle):Promise<{revocation:FileRevocation}>{const {e,key}=await authority(input,bundle);
 if(e.planning.binding.version===1||!e.planning.binding.isOwner||input.reason.length>2000||e.approval?.body.approvalId!==input.approvalId)invalid();
 const body=fileRevocation.shape.body.parse({purpose:'ukda.file-approval-revocation.v1',binding:e.binding,approvalId:input.approvalId,reason:placeholder()});body.reason=await seal(body,{reason:input.reason},key);
 return {revocation:fileRevocation.parse(await sign(body,bundle))};}

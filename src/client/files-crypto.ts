import sodium from 'libsodium-wrappers';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { z } from 'zod';
import { binary, digest, identifier, positiveCounter } from '../shared/contracts.js';
import { base64urlDecode, base64urlEncode, canonicalJson, signObject } from '../shared/crypto.js';
import { FILE_CHUNK_PLAIN_BYTES, FILE_EXTERNAL_MAX_BYTES, FILE_MAX_PLAIN_BYTES, FILE_SUPPORTED_EXTENSIONS,
  fileBinding, fileBindingFromPlanning, fileChunkDigest, fileManifest, verifyFileManifest,
  type FileBinding, type FileManifest, type FileManifestBody } from '../shared/files.js';
import type { DeviceBundle } from './device-store.js';
import { openVerifiedPlanning, planningSecurityResolver, type ReadPlanningInput } from './planning-crypto.js';
import { parseJsonStrict } from '../shared/json.js';
import { validateSelectedManagedFile, FileFormatError } from './file-formats.js';

const text = new TextEncoder(), decode = new TextDecoder('utf-8', { fatal:true });
const safeText = (max:number) => z.string().max(max).refine(v=>!/[\u0000-\u001f\u007f]/u.test(v));
export const privateFileMetadata = z.strictObject({
  filename:safeText(240).min(1).refine(v=>!/[\\/]/u.test(v)), mediaType:safeText(100),
  documentReference:safeText(128).trim().min(1), label:safeText(1000).default(''), sha256:digest,
  path:safeText(4096).min(1).refine(v=>!/:\/\/[^/]*@/u.test(v)).optional(), fileKey:binary(32).optional(),
});
export type PrivateFileMetadata=z.infer<typeof privateFileMetadata>;
export type ReadableFileMetadata=Omit<PrivateFileMetadata,'fileKey'>;
export class FileClientError extends Error {
  constructor(readonly code:'INVALID_FILE'|'TOO_LARGE'|'UNSUPPORTED_FORMAT'|'CHANGED_FILE'|'INCOMPLETE_KEYS'|'CANCELLED'|'CONFLICT'|'STORAGE') {
    super(`File operation failed (${code})`);this.name='FileClientError';
  }
}
function invalid():never {throw new FileClientError('INVALID_FILE');}
function same(a:unknown,b:unknown){return canonicalJson(a)===canonicalJson(b);}
function metadataContext(body:FileManifestBody) {const {metadata:_metadata,...rest}=body;return {...rest,purpose:'ukda.file-metadata.v1'};}
export function fileChunkContext(body:Pick<FileManifestBody,'binding'|'fileId'|'versionId'>,index:number) {
  return {purpose:'ukda.file-chunk.v1',workspaceId:body.binding.workspaceId,projectId:body.binding.projectId,
    fileId:body.fileId,versionId:body.versionId,keyEpoch:body.binding.keyEpoch,index};
}
/** Local selection is read incrementally; no document or hash goes to the server. */
export async function hashSelectedFile(file:Blob):Promise<string> {
  if(file.size<1||file.size>FILE_EXTERNAL_MAX_BYTES)throw new FileClientError('TOO_LARGE');
  const state=sha256.create();
  for(let offset=0;offset<file.size;offset+=FILE_CHUNK_PLAIN_BYTES){
    const bytes=new Uint8Array(await file.slice(offset,offset+FILE_CHUNK_PLAIN_BYTES).arrayBuffer());
    try{state.update(bytes);}finally{bytes.fill(0);}
  }
  return bytesToHex(state.digest());
}
export async function encryptFileChunk(bytes:Uint8Array,key:Uint8Array,context:ReturnType<typeof fileChunkContext>):Promise<Uint8Array> {
  if(bytes.length<1||bytes.length>FILE_CHUNK_PLAIN_BYTES||key.length!==32)invalid();
  await sodium.ready;const nonce=sodium.randombytes_buf(24),cipher=sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes,canonicalJson(context),null,nonce,key);
  const packed=new Uint8Array(nonce.length+cipher.length);packed.set(nonce);packed.set(cipher,nonce.length);return packed;
}
export async function decryptFileChunk(packed:Uint8Array,key:Uint8Array,context:ReturnType<typeof fileChunkContext>):Promise<Uint8Array> {
  if(packed.length<41||packed.length>FILE_CHUNK_PLAIN_BYTES+40||key.length!==32)invalid();
  await sodium.ready;try{return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,packed.subarray(24),canonicalJson(context),packed.subarray(0,24),key);}
  catch{invalid();}
}
export interface PrepareFileInput extends ReadPlanningInput {
  binding:FileBinding;fileId:string;versionId:string;version:string;priorVersionId:string|null;
  kind:'source'|'output';storage:'managed'|'external';taskIds:string[];file:Blob;
  metadata:Omit<PrivateFileMetadata,'sha256'|'fileKey'>;
}
export interface PreparedFile {manifest:FileManifest;chunks:string[]}
/** Worker-only encryption: content keys never leave the authenticated worker. */
export async function prepareFile(input:PrepareFileInput,bundle:DeviceBundle):Promise<PreparedFile> {
  const opened=await openVerifiedPlanning({...input,historyPlaintext:false},bundle),binding=fileBinding.parse(input.binding);
  if(!same(binding,fileBindingFromPlanning(opened.context.binding))||Date.parse(binding.expiresAt)<=Date.now())invalid();
  identifier.parse(input.fileId);identifier.parse(input.versionId);positiveCounter.parse(input.version);
  const max=input.storage==='managed'?FILE_MAX_PLAIN_BYTES:FILE_EXTERNAL_MAX_BYTES;
  if(input.file.size<1||input.file.size>max)throw new FileClientError('TOO_LARGE');
  if(input.storage==='managed'&&!FILE_SUPPORTED_EXTENSIONS.includes(input.metadata.filename.split('.').at(-1)?.toLowerCase() as typeof FILE_SUPPORTED_EXTENSIONS[number]))
    throw new FileClientError('UNSUPPORTED_FORMAT');
  if((input.storage==='external')!==(input.metadata.path!==undefined))invalid();
  if(input.storage==='managed')try{await validateSelectedManagedFile(input.file,input.metadata.filename);}catch(error){
    if(error instanceof FileFormatError)throw new FileClientError(error.code==='TOO_LARGE'?'TOO_LARGE':'UNSUPPORTED_FORMAT');throw error;
  }
  const ring=opened.ring.find(k=>k.epoch===binding.keyEpoch);if(!ring)throw new FileClientError('INCOMPLETE_KEYS');
  const projectKey=base64urlDecode(ring.key,32),signer=base64urlDecode(bundle.signingPrivateKey,64);
  await sodium.ready;const key=sodium.randombytes_buf(32),chunks:string[]=[],hashes:string[]=[],hash=sha256.create();
  try{
    for(let offset=0,index=0;offset<input.file.size;offset+=FILE_CHUNK_PLAIN_BYTES,index++){
      const bytes=new Uint8Array(await input.file.slice(offset,offset+FILE_CHUNK_PLAIN_BYTES).arrayBuffer());
      try{
        hash.update(bytes);
        if(input.storage==='managed'){
          const packed=await encryptFileChunk(bytes,key,fileChunkContext({binding,fileId:input.fileId,versionId:input.versionId},index));
          hashes.push(await fileChunkDigest(packed));chunks.push(base64urlEncode(packed));packed.fill(0);
        }
      }finally{bytes.fill(0);}
    }
    const metadata=privateFileMetadata.parse({...input.metadata,sha256:bytesToHex(hash.digest()),
      ...(input.storage==='managed'?{fileKey:base64urlEncode(key)}:{})});
    const body:FileManifestBody={purpose:'ukda.file-version.v1',binding,fileId:input.fileId,versionId:input.versionId,version:input.version,
      priorVersionId:input.priorVersionId,kind:input.kind,storage:input.storage,plainBytes:input.file.size,
      cipherBytes:input.storage==='managed'?input.file.size+chunks.length*40:0,chunkHashes:hashes,taskIds:input.taskIds,
      metadata:{nonce:base64urlEncode(new Uint8Array(24)),ciphertext:base64urlEncode(new Uint8Array(16))}};
    const nonce=sodium.randombytes_buf(24),cipher=sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(text.encode(canonicalJson(metadata)),canonicalJson(metadataContext(body)),null,nonce,projectKey);
    body.metadata={nonce:base64urlEncode(nonce),ciphertext:base64urlEncode(cipher)};
    return {manifest:fileManifest.parse(await signObject(body,signer)),chunks};
  }finally{key.fill(0);projectKey.fill(0);signer.fill(0);}
}
export interface ReadFilesInput extends ReadPlanningInput {manifests:FileManifest[]}
/** Worker-internal: callers must authenticate the manifest and current project access before supplying its verified key ring. */
export async function readFileMetadataWithKeyRing(manifest:FileManifest,ring:{epoch:string;key:string}[]):Promise<PrivateFileMetadata>{
  const entry=ring.find(k=>k.epoch===manifest.body.binding.keyEpoch);if(!entry)throw new FileClientError('INCOMPLETE_KEYS');
  const key=base64urlDecode(entry.key,32);await sodium.ready;
  try{
    const raw=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,base64urlDecode(manifest.body.metadata.ciphertext),canonicalJson(metadataContext(manifest.body)),base64urlDecode(manifest.body.metadata.nonce,24),key);
    try{
      const metadata=privateFileMetadata.parse(parseJsonStrict(decode.decode(raw)));
      if((manifest.body.storage==='managed')!==(metadata.fileKey!==undefined)||(manifest.body.storage==='external')!==(metadata.path!==undefined))invalid();
      return metadata;
    }finally{raw.fill(0);}
  }catch(error){if(error instanceof FileClientError)throw error;invalid();}finally{key.fill(0);}
}
export async function readFiles(input:ReadFilesInput,bundle:DeviceBundle):Promise<{versionId:string;metadata:ReadableFileMetadata}[]>{
  if(input.manifests.length>100)invalid();const opened=await openVerifiedPlanning({...input,historyPlaintext:false},bundle),resolve=planningSecurityResolver(input.history,opened.state),result=[];
  for(const value of input.manifests){
    const manifest=await verifyFileManifest(value,resolve);
    if(manifest.body.binding.workspaceId!==opened.state.workspaceId||manifest.body.binding.projectId!==opened.context.binding.projectId)invalid();
    const {fileKey:_key,...metadata}=await readFileMetadataWithKeyRing(manifest,opened.ring);result.push({versionId:manifest.body.versionId,metadata});
  }
  return result;
}
export interface ReadFileBytesInput extends ReadPlanningInput {manifest:FileManifest;chunks:string[]}
export async function readFileBytes(input:ReadFileBytesInput,bundle:DeviceBundle):Promise<Uint8Array>{
  const opened=await openVerifiedPlanning({...input,historyPlaintext:false},bundle),manifest=await verifyFileManifest(input.manifest,planningSecurityResolver(input.history,opened.state)),body=manifest.body;
  if(body.binding.workspaceId!==opened.state.workspaceId||body.binding.projectId!==opened.context.binding.projectId||body.storage!=='managed'||input.chunks.length!==body.chunkHashes.length)invalid();
  const metadata=await readFileMetadataWithKeyRing(manifest,opened.ring);if(!metadata.fileKey)invalid();const key=base64urlDecode(metadata.fileKey,32),output=new Uint8Array(body.plainBytes);
  const hash=sha256.create();
  try{
    for(let index=0,offset=0;index<input.chunks.length;index++){
      const packed=base64urlDecode(input.chunks[index]!);if(await fileChunkDigest(packed)!==body.chunkHashes[index])invalid();
      const plain=await decryptFileChunk(packed,key,fileChunkContext(body,index));
      try{
        if(plain.length!==Math.min(FILE_CHUNK_PLAIN_BYTES,body.plainBytes-offset))invalid();output.set(plain,offset);offset+=plain.length;hash.update(plain);
      }finally{plain.fill(0);packed.fill(0);}
    }
    if(bytesToHex(hash.digest())!==metadata.sha256)invalid();return output;
  }catch(error){output.fill(0);throw error;}finally{key.fill(0);}
}
export interface PrepareFileLinkInput extends ReadPlanningInput {binding:FileBinding;fileId:string;taskIds:string[];mode:'latest'|'pinned';versionId:string|null;action:'link'|'unlink'}
export async function prepareFileLink(input:PrepareFileLinkInput,bundle:DeviceBundle){
  const opened=await openVerifiedPlanning({...input,historyPlaintext:false},bundle);if(!same(input.binding,fileBindingFromPlanning(opened.context.binding)))invalid();
  const {fileLinkBody,fileLinkRequest}=await import('../shared/files.js'),body=fileLinkBody.parse({purpose:'ukda.file-links.v1',binding:input.binding,
    fileId:input.fileId,taskIds:input.taskIds,mode:input.mode,versionId:input.versionId,action:input.action});
  const key=base64urlDecode(bundle.signingPrivateKey,64);try{return fileLinkRequest.parse({mutation:await signObject(body,key)});}finally{key.fill(0);}
}

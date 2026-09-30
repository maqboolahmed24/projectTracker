import sodium from 'libsodium-wrappers';
import { privateFileMetadata,decryptFileChunk,fileChunkContext } from './files-crypto.js';
import { verifyFileManifest,fileChunkDigest } from '../shared/files.js';
import { planningSecurityResolver } from './planning-crypto.js';
import { parseJsonStrict } from '../shared/json.js';
import { base64urlDecode,canonicalJson,digestObject,signObject } from '../shared/crypto.js';
import { restoreContext,restoreVerification,verifyRestoreServiceObject,verifyRestoreOwner,validateRestoreVerification,
  type RestoreContext,type RestoreVerification,type RestoreMissingRecord } from '../shared/restoration.js';
import { verifySecurityHistory,type SecurityHistoryInput } from '../shared/security-history.js';
import type { DeviceBundle } from './device-store.js';
import { readOwnerCustodyKeyMaterial } from './pairing.js';
import { decryptHistoricalContent } from './upgrade-content-crypto.js';
export interface VerifyRestorationInput {context:RestoreContext;history:SecurityHistoryInput;accountId:string;deviceId:string}
export interface ReadableRestoration {workspaceId:string;restoreId:string;recoveredAt:string;dataGeneration:string;verifiedSamples:number;verifiedEpochs:number;verifiedFileSamples:number;
  missingRecords:RestoreMissingRecord[];contentAfterCheckpoint:'unverified_or_missing'}
export class RestorationClientError extends Error {constructor(readonly code:'INVALID_RESTORE'|'INCOMPLETE_KEYS'|'EXPIRED'){super(`Restoration failed (${code})`);this.name='RestorationClientError';}}
function invalid():never{throw new RestorationClientError('INVALID_RESTORE');}
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
async function opened(value:VerifyRestorationInput,bundle:DeviceBundle){
  const input=structuredClone(value),context=restoreContext.parse(input.context),b=context.binding,state=await verifySecurityHistory(input.history);verifyRestoreOwner(b,state);
  if(b.accountId!==input.accountId||b.deviceId!==input.deviceId||b.signingPublicKey!==bundle.signingPublicKey||state.devices[b.deviceId]?.recipientPublicKey!==bundle.recipientPublicKey)invalid();
  if(Date.parse(b.expiresAt)<=Date.now()||Date.parse(b.issuedAt)>Date.now()+30000)throw new RestorationClientError('EXPIRED');
  const checkpoint=context.checkpoint,reconciled=context.reconciled,keys=input.history.trustedServiceKeys??{};
  await verifyRestoreServiceObject(checkpoint,keys);await verifyRestoreServiceObject(reconciled,keys);
  if(checkpoint.body.version!==reconciled.body.version||checkpoint.body.workspaceId!==b.workspaceId||reconciled.body.workspaceId!==b.workspaceId||reconciled.body.restoreId!==b.restoreId||
    await digestObject(checkpoint)!==b.manifestDigest||await digestObject(reconciled)!==b.reconciledDigest||reconciled.body.manifestDigest!==b.manifestDigest||
    reconciled.body.source.dataGeneration!==state.dataGeneration||reconciled.body.source.writeSchema!==(state.writeSchema??1))invalid();
  for(const source of [checkpoint.body.source,reconciled.body.source]){
    const length=Number(BigInt(source.securityVersion)-1n);if(!Number.isSafeInteger(length)||length<0||length>input.history.transitions.length)invalid();
    const {pin:_pin,...base}=input.history;await verifySecurityHistory({...base,transitions:input.history.transitions.slice(0,length),expected:{securityHead:source.securityHead,securityVersion:source.securityVersion}});
  }
  if(new Set(reconciled.body.objects.map(r=>r.digest)).size!==reconciled.body.objects.length||new Set(reconciled.body.samples).size!==reconciled.body.samples.length)invalid();
  const computedEpochs=[...new Map(reconciled.body.objects.map(r=>{const h=r.header;return [`${h.scope}:${h.scopeId}:${h.keyEpoch}`,{scope:h.scope,scopeId:h.scopeId,keyEpoch:h.keyEpoch}] as const;}))].sort(([a],[b])=>a.localeCompare(b)).map(([,value])=>value);
  if(reconciled.body.version===2){const epochs=new Map(computedEpochs.map(e=>[`${e.scope}:${e.scopeId}:${e.keyEpoch}`,e]));for(const f of reconciled.body.files)epochs.set(`project:${f.projectId}:${f.keyEpoch}`,{scope:'project',scopeId:f.projectId,keyEpoch:f.keyEpoch});computedEpochs.splice(0,computedEpochs.length,...[...epochs].sort(([a],[b])=>a.localeCompare(b)).map(([,e])=>e));}
  if(!same(computedEpochs,reconciled.body.keyEpochs))invalid();
  const expectedSamples=new Map<string,string>();for(const r of [...reconciled.body.objects].sort((a,b)=>a.digest.localeCompare(b.digest))){const h=r.header,k=`${h.scope}:${h.scopeId}:${h.keyEpoch}:${r.current?'current':'historical'}`;if(!expectedSamples.has(k))expectedSamples.set(k,r.digest);}
  if(!same([...expectedSamples.values()].sort(),reconciled.body.samples))invalid();
  const custody=await readOwnerCustodyKeyMaterial({accountId:b.accountId,deviceId:b.deviceId,history:state,materials:context.materials},bundle);
  for(const required of reconciled.body.keyEpochs){
    const ring=required.scope==='workspace'?custody.manifest.workspaceKeys:custody.manifest.projectKeys.find(p=>p.projectId===required.scopeId)?.keys;
    if(!ring?.some(key=>key.epoch===required.keyEpoch))throw new RestorationClientError('INCOMPLETE_KEYS');
    if(required.scope==='project')for(const scopes of [state.profiles[b.accountId]!.scopes,state.devices[b.deviceId]!.scopes])
      if(!scopes.some(s=>s.scope==='project'&&s.scopeId===required.scopeId&&s.keyEpoch===state.scopeHeads[`project:${required.scopeId}`]?.keyEpoch&&s.permissions.includes('read_project')&&(s.expiresAt===null||Date.parse(s.expiresAt)>Date.parse(b.issuedAt))))invalid();
  }
  const actual=[];for(const envelope of context.samples){const hash=await digestObject(envelope),ref=reconciled.body.objects.find(r=>r.digest===hash);if(!ref||!same(ref.header,envelope.header))invalid();actual.push(hash);
    const ring=envelope.header.scope==='workspace'?custody.manifest.workspaceKeys:custody.manifest.projectKeys.find(p=>p.projectId===envelope.header.scopeId)?.keys;
    if(!ring)throw new RestorationClientError('INCOMPLETE_KEYS');await decryptHistoricalContent(input.history,envelope,ring);
  }
  if(!same(actual,reconciled.body.samples))invalid();
  const actualFiles:string[]=[];if(reconciled.body.version===2){
    const expected=new Map<string,string>();for(const f of [...reconciled.body.files].sort((a,b)=>a.manifestDigest.localeCompare(b.manifestDigest))){const k=`${f.projectId}:${f.keyEpoch}:${f.storage}:${f.current?'current':'historical'}`;if(!expected.has(k))expected.set(k,f.manifestDigest);}
    if(!same([...expected.values()].sort(),reconciled.body.fileSamples)||!context.fileSamples)invalid();
    for(const sample of context.fileSamples){const manifest=await verifyFileManifest(sample.manifest,planningSecurityResolver(input.history,state)),hash=await digestObject(manifest),ref=reconciled.body.files.find(f=>f.manifestDigest===hash);if(!ref||ref.fileId!==manifest.body.fileId||ref.versionId!==manifest.body.versionId||ref.projectId!==manifest.body.binding.projectId||ref.keyEpoch!==manifest.body.binding.keyEpoch||ref.storage!==manifest.body.storage||ref.plainBytes!==manifest.body.plainBytes)invalid();
      const key=custody.manifest.projectKeys.find(p=>p.projectId===ref.projectId)?.keys.find(k=>k.epoch===ref.keyEpoch);if(!key)throw new RestorationClientError('INCOMPLETE_KEYS');await sodium.ready;const rawKey=base64urlDecode(key.key,32),{metadata,...body}=manifest.body;
      try{const plain=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,base64urlDecode(metadata.ciphertext),canonicalJson({...body,purpose:'ukda.file-metadata.v1'}),base64urlDecode(metadata.nonce,24),rawKey);
        try{const file=privateFileMetadata.parse(parseJsonStrict(new TextDecoder('utf-8',{fatal:true}).decode(plain)));
          if(ref.storage==='managed'){if(!file.fileKey||!sample.chunk)invalid();const packed=base64urlDecode(sample.chunk),fileKey=base64urlDecode(file.fileKey,32);try{if(await fileChunkDigest(packed)!==manifest.body.chunkHashes[0])invalid();const bytes=await decryptFileChunk(packed,fileKey,fileChunkContext(manifest.body,0));bytes.fill(0);}finally{fileKey.fill(0);packed.fill(0);}}
          else if(file.fileKey||!file.path||sample.chunk!==null)invalid();
        }finally{plain.fill(0);}
      }catch{invalid();}finally{rawKey.fill(0);}actualFiles.push(hash);
    }
    if(!same(actualFiles,reconciled.body.fileSamples))invalid();
  }else if(context.fileSamples?.length)invalid();

  const readable:ReadableRestoration={workspaceId:b.workspaceId,restoreId:b.restoreId,recoveredAt:checkpoint.body.capturedAt,dataGeneration:b.dataGeneration,
    verifiedSamples:actual.length,verifiedFileSamples:actualFiles.length,verifiedEpochs:computedEpochs.length,missingRecords:reconciled.body.missingRecords,contentAfterCheckpoint:'unverified_or_missing'};
  return {context,state,readable};
}
/** Keys and decrypted samples remain inside the Worker; only opaque counts and
 * missing-record references are returned for explicit user acknowledgement. */
export async function readRestoration(input:VerifyRestorationInput,bundle:DeviceBundle):Promise<ReadableRestoration>{return (await opened(input,bundle)).readable;}
export async function prepareRestorationVerification(input:VerifyRestorationInput,bundle:DeviceBundle):Promise<RestoreVerification>{
  const {context,state}=await opened(input,bundle),signing=base64urlDecode(bundle.signingPrivateKey,64);
  try{return validateRestoreVerification(restoreVerification.parse(await signObject({...(context.reconciled.body.version===2?{version:2 as const,purpose:'ukda.restore-verify.v2' as const,verifiedFileSamples:context.reconciled.body.fileSamples}:{version:1 as const,purpose:'ukda.restore-verify.v1' as const}),binding:context.binding,
    verifiedSamples:context.reconciled.body.samples,verifiedKeyEpochs:context.reconciled.body.keyEpochs,missingContentAcknowledged:true as const},signing)),context,state);}finally{signing.fill(0);}
}

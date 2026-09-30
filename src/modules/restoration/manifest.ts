import type pg from 'pg';
import { createHash } from 'node:crypto';
import sodium from 'libsodium-wrappers';
import { AppError } from '../../errors.js';
import { contentEnvelope,type ContentEnvelope } from '../../shared/contracts.js';
import { base64urlEncode,canonicalJson,digestObject,signObject,type SignedObject } from '../../shared/crypto.js';
import { RESTORE_TABLES,RESTORE_MAX_OBJECTS,RESTORE_ROW_MAX_BYTES,RESTORE_BINARY_MAX_BYTES,type RestoreInventory } from '../../shared/restoration.js';
import type { PairingMaterial } from '../../shared/pairing.js';
import { fileManifest,verifyFileManifest,type FileManifest } from '../../shared/files.js';
import type { PlanningSecurityResolver } from '../../shared/planning-api.js';
import type { ServiceSecrets } from '../identity/secrets.js';
export { RESTORE_TABLES } from '../../shared/restoration.js';
/** The source security vector is signed separately. Never copy old security or
 * fence state over current authority when installing an application checkpoint. */
export function canonicalRestoreRow(table:typeof RESTORE_TABLES[number],row:Record<string,unknown>):Record<string,unknown>{
  if(table==='file_chunks'){const {cipher_bytes,...rest}=row;if(cipher_bytes===undefined)return rest;
    if(typeof cipher_bytes!=='string'||!/^\\x[a-f0-9]+$/.test(cipher_bytes)||cipher_bytes.length%2!==0)throw new Error('Invalid recovery chunk');
    const bytes=Buffer.from(cipher_bytes.slice(2),'hex'),hash=createHash('sha256').update(bytes).digest('hex');if(hash!==row.cipher_digest)throw new Error('Changed recovery chunk');
    return {...rest,cipher_bytes_digest:hash,cipher_bytes_length:bytes.length};}
  if(table==='workspaces')return {workspace_id:row.workspace_id,encrypted_envelope:row.encrypted_envelope,revision:row.revision};
  return row;
}
export async function signRestoreService<T extends {purpose:string;serviceKeyId:string;servicePublicKey:string}>(secrets:ServiceSecrets,body:Omit<T,'serviceKeyId'|'servicePublicKey'>):Promise<SignedObject<T>>{
  await sodium.ready;const seed=secrets.digest('entitlement-signing-key',secrets.keyId),pair=sodium.crypto_sign_seed_keypair(seed);
  try{return await signObject({...body,serviceKeyId:secrets.keyId,servicePublicKey:base64urlEncode(pair.publicKey)} as T,pair.privateKey);}
  finally{seed.fill(0);pair.privateKey.fill(0);}
}
export async function checkpointKeyObjects(control:pg.PoolClient,workspaceId:string):Promise<PairingMaterial[]>{
  const rows=(await control.query("SELECT object_id,object_hash,object_kind,versioned_object FROM security.staged_objects WHERE workspace_id=$1 AND state='committed' AND object_kind IN('key_envelope','custody_manifest') ORDER BY object_id",[workspaceId])).rows;
  if(rows.length>RESTORE_MAX_OBJECTS)throw new AppError('RESTORE_TOO_LARGE','Recovery inventory exceeds this release limit',413);
  return Promise.all(rows.map(async row=>{if(await digestObject(row.versioned_object)!==row.object_hash)throw new AppError('RESTORE_INCOMPLETE','A required encrypted key object is missing or changed',409);
    return {id:row.object_id as string,digest:row.object_hash as string,kind:row.object_kind as string,value:row.versioned_object};}));
}
/** Original v1 table digests, computed incrementally instead of serialising a giant array. */
export function restoreTableDigest(canonicalRows:string[]):string{const hash=createHash('sha256');hash.update('[');for(const [i,row]of canonicalRows.sort().entries()){if(i)hash.update(',');hash.update(canonicalJson(row));}hash.update(']');return hash.digest('hex');}
const currentTables=new Set(['workspaces','profiles','roles','teams','projects','project_phases','milestones','tasks','blockers','comments','updates']);
/** Metadata-only operational inventory; never returned by ordinary content APIs. */
export async function readRestoreInventory(application:pg.PoolClient,workspaceId:string,keyObjects:PairingMaterial[]=[],selectedTables:readonly string[]=RESTORE_TABLES,securityAt?:PlanningSecurityResolver):Promise<{inventory:RestoreInventory;envelopes:Map<string,ContentEnvelope>}>{
  const owner=(await application.query("SELECT id FROM app.profiles WHERE workspace_id=$1 AND state='active' AND is_owner ORDER BY id LIMIT 1",[workspaceId])).rows[0];
  if(!owner)throw new AppError('RESTORE_INCOMPLETE','Checkpoint has no application identity projection',409);
  await application.query("SELECT set_config('ukda.profile_id',$1,true)",[owner.id]);
  const tables:RestoreInventory['tables']=[],objects=new Map<string,RestoreInventory['objects'][number]>(),envelopes=new Map<string,ContentEnvelope>();
  let projectIds:string[]=[],total=0,totalBytes=0,binaryBytes=0;const files:NonNullable<Extract<RestoreInventory,{files:unknown}>['files']>=[],fileManifests=new Map<string,FileManifest>(),chunks=new Map<string,{index:number;digest:string;bytes:number}[]>();
  const latest=new Set((selectedTables.includes('project_files')?(await application.query<{latest_version_id:string|null}>('SELECT latest_version_id FROM app.project_files WHERE workspace_id=$1',[workspaceId])).rows:[]).flatMap(r=>r.latest_version_id?[r.latest_version_id]:[]));
  async function visit(value:unknown,current:boolean,depth=0):Promise<void>{
    if(depth>40)throw new AppError('RESTORE_INCOMPLETE','Encrypted object nesting exceeds the recovery limit',409);
    if(!value||typeof value!=='object')return;
    const parsed=contentEnvelope.safeParse(value);
    if(parsed.success){const envelope=parsed.data;if(envelope.header.workspaceId!==workspaceId)throw new AppError('RESTORE_INCOMPLETE','Cross-workspace encrypted object',409);
      const hash=await digestObject(envelope);objects.set(hash,{digest:hash,header:envelope.header,current:current||objects.get(hash)?.current===true});envelopes.set(hash,envelope);return;}
    for(const child of Object.values(value))await visit(child,current,depth+1);
  }
  for(const table of [...selectedTables].sort()){
    if(!RESTORE_TABLES.includes(table as typeof RESTORE_TABLES[number]))throw new AppError('RESTORE_INCOMPLETE','Unknown recovery table',409);
    const canonical:string[]=[];let offset=0;
    for(let page=0;page<=RESTORE_MAX_OBJECTS;page++){
      const expression=table==='file_chunks'?"(to_jsonb(t)-'cipher_bytes') || jsonb_build_object('cipher_bytes_digest',encode(sha256(cipher_bytes),'hex'),'cipher_bytes_length',octet_length(cipher_bytes))":"to_jsonb(t)";
      const rows=(await application.query(`SELECT ${expression} AS value FROM app.${table} t WHERE workspace_id=$1 LIMIT 64 OFFSET $2`,[workspaceId,offset])).rows.map(r=>r.value as Record<string,unknown>);
      total+=rows.length;offset+=rows.length;if(total>RESTORE_MAX_OBJECTS)throw new AppError('RESTORE_TOO_LARGE','Complete recovery inventory exceeds this release limit',413);
      for(const row of rows){const encoded=canonicalJson(canonicalRestoreRow(table as typeof RESTORE_TABLES[number],row));totalBytes+=Buffer.byteLength(encoded);if(totalBytes>RESTORE_ROW_MAX_BYTES)throw new AppError('RESTORE_TOO_LARGE','Recovery metadata exceeds this release limit',413);canonical.push(encoded);
        if(table==='projects')projectIds.push(String(row.id));
        if(table==='file_versions'){let m=fileManifest.parse(row.manifest);if(securityAt)m=await verifyFileManifest(m,securityAt);if(m.body.binding.workspaceId!==workspaceId||m.body.binding.projectId!==row.project_id||m.body.fileId!==row.file_id||m.body.versionId!==row.id||m.body.binding.dataGeneration!==String(row.data_generation))throw new AppError('RESTORE_INCOMPLETE','Invalid retained file version',409);
          fileManifests.set(m.body.versionId,m);if(row.state==='ready')files.push({fileId:m.body.fileId,versionId:m.body.versionId,projectId:m.body.binding.projectId,keyEpoch:m.body.binding.keyEpoch,manifestDigest:await digestObject(m),storage:m.body.storage,plainBytes:m.body.plainBytes,current:latest.has(m.body.versionId)});
        }
        if(table==='file_chunks'){if(row.cipher_bytes_digest!==row.cipher_digest)throw new AppError('RESTORE_INCOMPLETE','Retained file bytes changed',409);binaryBytes+=Number(row.cipher_bytes_length);if(binaryBytes>RESTORE_BINARY_MAX_BYTES)throw new AppError('RESTORE_TOO_LARGE','Retained file bytes exceed the recovery limit',413);const id=String(row.version_id),values=chunks.get(id)??[];values.push({index:Number(row.chunk_index),digest:String(row.cipher_bytes_digest),bytes:Number(row.cipher_bytes_length)});chunks.set(id,values);}
        await visit(row.encrypted_envelope,currentTables.has(table));for(const [key,value]of Object.entries(row))if(key!=='encrypted_envelope')await visit(value,false);
      }
      if(rows.length<64)break;
    }
    tables.push({table,count:offset,digest:restoreTableDigest(canonical)});
  }
  for(const file of files){const manifest=fileManifests.get(file.versionId)!.body,values=(chunks.get(file.versionId)??[]).sort((a,b)=>a.index-b.index);if(values.length!==manifest.chunkHashes.length||values.some((v,i)=>v.index!==i||v.digest!==manifest.chunkHashes[i])||values.reduce((n,v)=>n+v.bytes,0)!==manifest.cipherBytes)throw new AppError('RESTORE_INCOMPLETE','Retained file bytes are incomplete',409);}
  projectIds.sort();files.sort((a,b)=>a.manifestDigest.localeCompare(b.manifestDigest));
  const refs=[...objects.values()].sort((a,b)=>a.digest.localeCompare(b.digest));if(refs.length>RESTORE_MAX_OBJECTS)throw new AppError('RESTORE_TOO_LARGE','Encrypted object inventory exceeds this release limit',413);
  const epochs=new Map(refs.map(ref=>{const h=ref.header;return [`${h.scope}:${h.scopeId}:${h.keyEpoch}`,{scope:h.scope,scopeId:h.scopeId,keyEpoch:h.keyEpoch}] as const;}));
  for(const file of files)epochs.set(`project:${file.projectId}:${file.keyEpoch}`,{scope:'project',scopeId:file.projectId,keyEpoch:file.keyEpoch});
  return {inventory:{tables,...(selectedTables.includes('file_versions')?{files}:{}),objects:refs,keyEpochs:[...epochs].sort(([a],[b])=>a.localeCompare(b)).map(([,v])=>v),projectIds,
    keyObjects:keyObjects.map(({id,digest,kind})=>({id,digest,kind})).sort((a,b)=>a.id.localeCompare(b.id))},envelopes};
}
/** At least one current and one historical object per retained key epoch, when
 * each class exists. Selection is reproducible and bound by the signed manifest. */
export function restoreSamples(objects:RestoreInventory['objects']):string[]{
  const selected=new Map<string,string>();for(const ref of objects){const h=ref.header,key=`${h.scope}:${h.scopeId}:${h.keyEpoch}:${ref.current?'current':'historical'}`;
    if(!selected.has(key))selected.set(key,ref.digest);}
  const result=[...selected.values()].sort();if(!result.length||result.length>512)throw new AppError('RESTORE_TOO_LARGE','Representative verification sample exceeds this release limit',413);return result;
}

export function restoreFileSamples(files:Extract<RestoreInventory,{files:unknown}>['files']):string[]{const selected=new Map<string,string>();for(const f of files){const key=`${f.projectId}:${f.keyEpoch}:${f.storage}:${f.current?'current':'historical'}`;if(!selected.has(key))selected.set(key,f.manifestDigest);}const hashes=[...selected.values()].sort();if(hashes.length>32)throw new AppError('RESTORE_TOO_LARGE','File recovery sample exceeds this release limit',413);return hashes;}

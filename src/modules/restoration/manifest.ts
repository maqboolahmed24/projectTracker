import type pg from 'pg';
import sodium from 'libsodium-wrappers';
import { AppError } from '../../errors.js';
import { contentEnvelope,type ContentEnvelope } from '../../shared/contracts.js';
import { base64urlEncode,canonicalJson,digestObject,signObject,type SignedObject } from '../../shared/crypto.js';
import { RESTORE_TABLES,RESTORE_MAX_OBJECTS,type RestoreInventory } from '../../shared/restoration.js';
import type { PairingMaterial } from '../../shared/pairing.js';
import type { ServiceSecrets } from '../identity/secrets.js';
export { RESTORE_TABLES } from '../../shared/restoration.js';
/** The source security vector is signed separately. Never copy old security or
 * fence state over current authority when installing an application checkpoint. */
export function canonicalRestoreRow(table:typeof RESTORE_TABLES[number],row:Record<string,unknown>):Record<string,unknown>{
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
const currentTables=new Set(['workspaces','profiles','roles','teams','projects','project_phases','milestones','tasks','blockers','comments','updates']);
/** Metadata-only operational inventory; never returned by ordinary content APIs. */
export async function readRestoreInventory(application:pg.PoolClient,workspaceId:string,keyObjects:PairingMaterial[]=[]):Promise<{inventory:RestoreInventory;envelopes:Map<string,ContentEnvelope>}>{
  const owner=(await application.query("SELECT id FROM app.profiles WHERE workspace_id=$1 AND state='active' AND is_owner ORDER BY id LIMIT 1",[workspaceId])).rows[0];
  if(!owner)throw new AppError('RESTORE_INCOMPLETE','Checkpoint has no application identity projection',409);
  await application.query("SELECT set_config('ukda.profile_id',$1,true)",[owner.id]);
  const tables:RestoreInventory['tables']=[],objects=new Map<string,RestoreInventory['objects'][number]>(),envelopes=new Map<string,ContentEnvelope>();
  let projectIds:string[]=[],total=0;
  async function visit(value:unknown,current:boolean,depth=0):Promise<void>{
    if(depth>40)throw new AppError('RESTORE_INCOMPLETE','Encrypted object nesting exceeds the recovery limit',409);
    if(!value||typeof value!=='object')return;
    const parsed=contentEnvelope.safeParse(value);
    if(parsed.success){const envelope=parsed.data;if(envelope.header.workspaceId!==workspaceId)throw new AppError('RESTORE_INCOMPLETE','Cross-workspace encrypted object',409);
      const hash=await digestObject(envelope);objects.set(hash,{digest:hash,header:envelope.header,current:current||objects.get(hash)?.current===true});envelopes.set(hash,envelope);return;}
    for(const child of Object.values(value))await visit(child,current,depth+1);
  }
  for(const table of [...RESTORE_TABLES].sort()){
    const rows=(await application.query(`SELECT to_jsonb(t) AS value FROM app.${table} t WHERE workspace_id=$1 LIMIT $2`,[workspaceId,RESTORE_MAX_OBJECTS+1])).rows.map(r=>r.value as Record<string,unknown>);
    total+=rows.length;if(total>RESTORE_MAX_OBJECTS)throw new AppError('RESTORE_TOO_LARGE','Complete recovery inventory exceeds this release limit',413);
    if(table==='projects')projectIds=rows.map(r=>String(r.id)).sort();
    const canonical=rows.map(row=>canonicalRestoreRow(table,row)).map(canonicalJson).sort();
    tables.push({table,count:rows.length,digest:await digestObject(canonical)});
    for(const row of rows){await visit(row.encrypted_envelope,currentTables.has(table));for(const [key,value]of Object.entries(row))if(key!=='encrypted_envelope')await visit(value,false);}
  }
  const refs=[...objects.values()].sort((a,b)=>a.digest.localeCompare(b.digest));if(refs.length>RESTORE_MAX_OBJECTS)throw new AppError('RESTORE_TOO_LARGE','Encrypted object inventory exceeds this release limit',413);
  const epochs=new Map(refs.map(ref=>{const h=ref.header;return [`${h.scope}:${h.scopeId}:${h.keyEpoch}`,{scope:h.scope,scopeId:h.scopeId,keyEpoch:h.keyEpoch}] as const;}));
  return {inventory:{tables,objects:refs,keyEpochs:[...epochs].sort(([a],[b])=>a.localeCompare(b)).map(([,v])=>v),projectIds,
    keyObjects:keyObjects.map(({id,digest,kind})=>({id,digest,kind})).sort((a,b)=>a.id.localeCompare(b.id))},envelopes};
}
/** At least one current and one historical object per retained key epoch, when
 * each class exists. Selection is reproducible and bound by the signed manifest. */
export function restoreSamples(objects:RestoreInventory['objects']):string[]{
  const selected=new Map<string,string>();for(const ref of objects){const h=ref.header,key=`${h.scope}:${h.scopeId}:${h.keyEpoch}:${ref.current?'current':'historical'}`;
    if(!selected.has(key))selected.set(key,ref.digest);}
  const result=[...selected.values()].sort();if(!result.length||result.length>512)throw new AppError('RESTORE_TOO_LARGE','Representative verification sample exceeds this release limit',413);return result;
}

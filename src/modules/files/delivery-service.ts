import { randomUUID } from 'node:crypto';
import sodium from 'libsodium-wrappers';
import type pg from 'pg';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { assertAuthoritativeContentWrite,tenantTransaction } from '../../persistence.js';
import { base64urlDecode,base64urlEncode,digestObject,signObject,verifyObject } from '../../shared/crypto.js';
import { assertFileBindingCurrent,fileBindingFromPlanning,fileReference,FILE_MAX_BATCH_BYTES } from '../../shared/files.js';
import { deliveryBatchRequest,deliveryCommandRequest,deliveryCreateRequest,deliveryListRequest,deliveryPairContextRequest,deliveryPairRequest,
 deliveryPermit,deliveryPermitRequest,deliveryPublishRequest,deliveryRecord,deliveryServiceCommandRequest,deliveryStatusRequest,verifyDeliveryBatch,verifyOwnerFileObject,
 DELIVERY_PERMIT_TTL_MS,type DeliveryPermit,type DeliveryReceipt,type DeliveryRecord,type DeliveryView } from '../../shared/file-delivery.js';
import type { PlanningContext,PlanningSecurityResolver } from '../../shared/planning-api.js';
import type { SessionPrincipal,SessionService } from '../identity/sessions.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { PlanningService } from '../work/planning.js';
import { assertDeliveryEvidence } from './evidence-service.js';
interface Options {databases:Databases;sessions:SessionService;secrets:ServiceSecrets;origin:string;planning?:PlanningService;
 requestBudget?:(scope:{workspaceId:string;accountId:string})=>Promise<void>}
interface Row {id:string;data_generation:string;signed_batch:DeliveryRecord['batch'];frozen_digest:string;state:DeliveryRecord['state'];
 confirmation:DeliveryRecord['confirmation'];publication:DeliveryRecord['publication'];package_downloads:number;created_at:Date}
const changed=()=>new AppError('DELIVERY_CHANGED','The delivery or its approval changed; review it before continuing',409);
const invalid=()=>new AppError('DELIVERY_INVALID','Invalid delivery operation',400);
const forbidden=()=>new AppError('DELIVERY_FORBIDDEN','An active Owner must authorise this delivery action',403);
const unavailable=()=>new AppError('DELIVERY_UNAVAILABLE','Delivery is temporarily unavailable; retain the prepared batch',503);
const ref=(v:{workspaceId:string;projectId:string;operationId:string})=>({workspaceId:v.workspaceId,projectId:v.projectId,operationId:v.operationId});
function parse<T>(schema:z.ZodType<T>,v:unknown):T {const r=schema.safeParse(v);if(!r.success)throw invalid();return r.data;}
export class DeliveryService {
 readonly #planning:PlanningService;
 constructor(readonly options:Options){this.#planning=options.planning??new PlanningService(options);}
 async #with<T>(cookie:string,csrf:string,r:z.infer<typeof fileReference>,write:boolean,
  action:(a:pg.PoolClient,p:PlanningContext,principal:SessionPrincipal,now:Date,securityAt:PlanningSecurityResolver)=>Promise<T>):Promise<T> {
  try{return await this.#planning.withCurrentContext(cookie,csrf,ref(r),async(a,p,principal,now,securityAt)=>{
   if(!p.binding.isOwner)throw forbidden();await this.options.requestBudget?.({workspaceId:principal.workspaceId,accountId:principal.accountId});
   if(write)await tenantTransaction(this.options.databases.control,r.workspaceId,undefined,c=>assertAuthoritativeContentWrite(c,r.workspaceId,[fileBindingFromPlanning(p.binding).writeSchema]));
   try{return await action(a,p,principal,now,securityAt);}catch(error){if(error instanceof AppError)throw error;throw unavailable();}
  },{write});}catch(error){if(error instanceof AppError)throw error;throw unavailable();}
 }
 async #row(a:pg.PoolClient,r:{workspaceId:string;projectId:string},batchId:string):Promise<Row> {
  const row=(await a.query<Row>('SELECT * FROM app.file_delivery_batches WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[r.workspaceId,r.projectId,batchId])).rows[0];
  if(!row)throw new AppError('DELIVERY_NOT_FOUND','Delivery not available',404);return row;
 }
 async #read(a:pg.PoolClient,row:Row,securityAt:PlanningSecurityResolver):Promise<DeliveryRecord> {
  try{await verifyDeliveryBatch(row.signed_batch,securityAt);if(await digestObject(row.signed_batch)!==row.frozen_digest)throw changed();
   if(row.confirmation){await verifyOwnerFileObject(row.confirmation,securityAt,'ukda.file-delivery-command.v1');
    if(row.confirmation.body.action!=='confirm'||row.confirmation.body.batchId!==row.id||row.confirmation.body.frozenDigest!==row.frozen_digest)throw changed();}
   if(['confirmed','published'].includes(row.state)&&!row.confirmation)throw changed();
   if(row.publication){
    const b=row.signed_batch.body.binding,operation=(await a.query<{payload:unknown}>(`SELECT payload FROM app.file_delivery_operations WHERE workspace_id=$1 AND project_id=$2
     AND receipt->>'action'='publish' AND receipt->>'batchId'=$3 ORDER BY created_at DESC LIMIT 1`,[b.workspaceId,b.projectId,row.id])).rows[0];
    if(!operation)throw changed();const payload=deliveryPublishRequest.parse(operation.payload);await verifyOwnerFileObject(payload.mutation,securityAt,'ukda.file-delivery-published.v1');
    if(await digestObject(payload.mutation.body.receipt)!==await digestObject(row.publication)||payload.mutation.body.frozenDigest!==row.frozen_digest)throw changed();
    const service=(await a.query<{approved_pairing:z.infer<typeof deliveryPairRequest>;public_key:string}>('SELECT approved_pairing,public_key FROM app.file_local_services WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[b.workspaceId,b.projectId,row.publication.body.serviceId])).rows[0];
    if(!service)throw changed();await verifyOwnerFileObject(service.approved_pairing.approval,securityAt,'ukda.file-service-pair.v1');
    if(!await verifyObject({body:service.approved_pairing.approval.body,signature:service.approved_pairing.proof},base64urlDecode(service.public_key),'ukda.file-service-pair.v1')||
     !await verifyObject(row.publication,base64urlDecode(service.public_key),'ukda.local-file-publication.v1'))throw changed();
   }
   if(row.state==='published'&&!row.publication)throw changed();
  }catch{throw changed();}
  return deliveryRecord.parse({batch:row.signed_batch,frozenDigest:row.frozen_digest,state:row.state,createdAt:row.created_at.toISOString(),
   confirmation:row.confirmation,publication:row.publication,packageDownloads:row.package_downloads});
 }
 async #eligible(a:pg.PoolClient,p:PlanningContext,row:Pick<Row,'signed_batch'|'data_generation'>,securityAt:PlanningSecurityResolver):Promise<void> {
  if(row.data_generation!==p.binding.dataGeneration)throw changed();let bytes=0;
  for(const item of row.signed_batch.body.items){const approved=await assertDeliveryEvidence(a,p,item.versionId,securityAt);
   if(approved.fileId!==item.fileId||approved.manifestDigest!==item.manifestDigest||approved.approvalId!==item.approvalId)throw changed();
   const version=(await a.query<{manifest:{body:{plainBytes:number;storage:string}};state:string}>('SELECT manifest,state FROM app.file_versions WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[p.binding.workspaceId,p.binding.projectId,item.versionId])).rows[0];
   if(!version||version.state!=='ready')throw changed();if(version.manifest.body.storage==='managed'&&item.operation!=='remove')bytes+=version.manifest.body.plainBytes;
  }
  if(bytes>FILE_MAX_BATCH_BYTES)throw new AppError('DELIVERY_TOO_LARGE','This delivery exceeds 250 MiB; use smaller batches',413);
 }
 async #prior(a:pg.PoolClient,principal:SessionPrincipal,r:z.infer<typeof fileReference>,hash:string):Promise<DeliveryReceipt|null> {
  const row=(await a.query<{project_id:string;data_generation:string;actor_profile_id:string;request_digest:string;receipt:DeliveryReceipt}>('SELECT * FROM app.file_delivery_operations WHERE workspace_id=$1 AND operation_id=$2',[r.workspaceId,r.operationId])).rows[0];
  if(!row)return null;if(row.project_id!==r.projectId||row.data_generation!==principal.dataGeneration||row.actor_profile_id!==principal.accountId||row.request_digest!==hash)throw changed();return row.receipt;
 }
 async #record(a:pg.PoolClient,principal:SessionPrincipal,r:z.infer<typeof fileReference>,hash:string,payload:unknown,action:DeliveryReceipt['action'],batchId:string|null,frozenDigest:string|null,now:Date):Promise<DeliveryView> {
  const receipt:DeliveryReceipt={version:1,...r,dataGeneration:principal.dataGeneration,requestHash:hash,action,batchId,frozenDigest,committedAt:now.toISOString()};
  await a.query(`INSERT INTO app.file_delivery_operations(workspace_id,project_id,operation_id,data_generation,actor_profile_id,request_digest,payload,receipt,created_at)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[r.workspaceId,r.projectId,r.operationId,principal.dataGeneration,principal.accountId,hash,payload,receipt,now]);
  await a.query(`INSERT INTO app.operation_receipts(workspace_id,id,data_generation,operation_id,actor_profile_id,project_id,action,request_digest,encrypted_envelope,created_at)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[r.workspaceId,randomUUID(),principal.dataGeneration,r.operationId,principal.accountId,r.projectId,`files.delivery.${action}`,hash,{receipt},now]);return {state:'completed',receipt};
 }
 async context(cookie:string,csrf:string,input:unknown){const r=parse(fileReference,input);return this.#with(cookie,csrf,r,false,async(_a,p)=>({planning:p,binding:fileBindingFromPlanning(p.binding)}));}
 async create(cookie:string,csrf:string,input:unknown):Promise<DeliveryView> {
  const payload=parse(deliveryCreateRequest,input),b=payload.batch.body.binding,r=ref(b),hash=await digestObject(payload),frozenDigest=await digestObject(payload.batch);
  return this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{
   const prior=await this.#prior(a,principal,r,hash);if(prior)return {state:'completed',receipt:prior};
   try{assertFileBindingCurrent(b,p,now);await verifyDeliveryBatch(payload.batch,securityAt);}catch{throw changed();}
   await this.#eligible(a,p,{signed_batch:payload.batch,data_generation:principal.dataGeneration},securityAt);
   if(payload.batch.body.supersedes){const old=await this.#row(a,r,payload.batch.body.supersedes);if(['published','cancelled','superseded'].includes(old.state))throw changed();
    await a.query("UPDATE app.file_delivery_batches SET state='superseded' WHERE workspace_id=$1 AND id=$2",[r.workspaceId,old.id]);}
   await a.query(`INSERT INTO app.file_delivery_batches(workspace_id,project_id,id,data_generation,creator_profile_id,frozen_digest,signed_batch,state,created_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,'frozen',$8)`,[r.workspaceId,r.projectId,payload.batch.body.batchId,principal.dataGeneration,principal.accountId,frozenDigest,payload.batch,now]);
   return this.#record(a,principal,r,hash,payload,'create',payload.batch.body.batchId,frozenDigest,now);
  });
 }
 async command(cookie:string,csrf:string,input:unknown,expected:'confirm'|'cancel'|'record_package'):Promise<DeliveryView> {
  const payload=parse(deliveryCommandRequest,input),body=payload.mutation.body,b=body.binding,r=ref(b),hash=await digestObject(payload);if(body.action!==expected)throw invalid();
  return this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{
   const prior=await this.#prior(a,principal,r,hash);if(prior)return {state:'completed',receipt:prior};
   try{assertFileBindingCurrent(b,p,now);await verifyOwnerFileObject(payload.mutation,securityAt,'ukda.file-delivery-command.v1');}catch{throw changed();}
   const row=await this.#row(a,r,body.batchId);await this.#read(a,row,securityAt);if(row.frozen_digest!==body.frozenDigest)throw changed();
   if(expected==='cancel'){if(!['frozen','confirmed'].includes(row.state))throw changed();await a.query("UPDATE app.file_delivery_batches SET state='cancelled' WHERE workspace_id=$1 AND id=$2",[r.workspaceId,row.id]);}
   else {await this.#eligible(a,p,row,securityAt);
    if(expected==='confirm'){if(row.state!=='frozen')throw changed();await a.query("UPDATE app.file_delivery_batches SET state='confirmed',confirmation=$3 WHERE workspace_id=$1 AND id=$2",[r.workspaceId,row.id,payload.mutation]);}
    else {if(row.state!=='confirmed')throw changed();await a.query('UPDATE app.file_delivery_batches SET package_downloads=package_downloads+1 WHERE workspace_id=$1 AND id=$2',[r.workspaceId,row.id]);}}
   return this.#record(a,principal,r,hash,payload,expected,row.id,row.frozen_digest,now);
  });
 }
 async get(cookie:string,csrf:string,input:unknown):Promise<DeliveryRecord>{const r=parse(deliveryBatchRequest,input);return this.#with(cookie,csrf,r,false,async(a,_p,_principal,_now,securityAt)=>this.#read(a,await this.#row(a,r,r.batchId),securityAt));}
 async list(cookie:string,csrf:string,input:unknown){const r=parse(deliveryListRequest,input);return this.#with(cookie,csrf,r,false,async(a,_p,_principal,_now,securityAt)=>{
  const rows=(await a.query<Row>('SELECT * FROM app.file_delivery_batches WHERE workspace_id=$1 AND project_id=$2 AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4',[r.workspaceId,r.projectId,r.after??null,r.limit+1])).rows;
  const entries=[];for(const row of rows.slice(0,r.limit))entries.push(await this.#read(a,row,securityAt));return {entries,nextCursor:rows.length>r.limit?rows[r.limit-1]!.id:null,complete:rows.length<=r.limit};
 });}
 async check(cookie:string,csrf:string,input:unknown){const r=parse(deliveryBatchRequest,input);return this.#with(cookie,csrf,r,false,async(a,p,_principal,now,securityAt)=>{
  const row=await this.#row(a,r,r.batchId);await this.#read(a,row,securityAt);if(row.state!=='confirmed')throw changed();await this.#eligible(a,p,row,securityAt);
  return {batchId:row.id,frozenDigest:row.frozen_digest,state:'confirmed' as const,checkedAt:now.toISOString()};
 });}
 async pairContext(cookie:string,csrf:string,input:unknown){const r=parse(deliveryPairContextRequest,input);return this.#with(cookie,csrf,r,true,async(a,p,principal,now)=>{
  await a.query('DELETE FROM app.file_service_pairings WHERE workspace_id=$1 AND project_id=$2 AND expires_at<=$3',[r.workspaceId,r.projectId,now]);
  const active=Number((await a.query<{n:string}>('SELECT count(*)::text AS n FROM app.file_service_pairings WHERE workspace_id=$1 AND project_id=$2 AND account_id=$3 AND used_at IS NULL',[r.workspaceId,r.projectId,principal.accountId])).rows[0]!.n);
  if(active>=16)throw new AppError('RATE_LIMITED','Too many unfinished folder connections; wait for an earlier request to expire',429);
  const pairingId=randomUUID(),nonce=this.options.secrets.token(),expiresAt=new Date(now.getTime()+600000);
  await a.query(`INSERT INTO app.file_service_pairings(workspace_id,project_id,id,service_id,public_key,account_id,device_id,data_generation,nonce,expires_at,created_at)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[r.workspaceId,r.projectId,pairingId,r.serviceId,r.publicKey,principal.accountId,principal.deviceId,principal.dataGeneration,nonce,expiresAt,now]);
  return {planning:p,binding:fileBindingFromPlanning(p.binding),challenge:{pairingId,nonce,issuedAt:now.toISOString(),expiresAt:expiresAt.toISOString()}};
 });}
 async pair(cookie:string,csrf:string,input:unknown):Promise<DeliveryView>{const payload=parse(deliveryPairRequest,input),body=payload.approval.body,b=body.binding,r=ref(b),hash=await digestObject(payload);
  return this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{
   const prior=await this.#prior(a,principal,r,hash);if(prior)return {state:'completed',receipt:prior};
   try{assertFileBindingCurrent(b,p,now);await verifyOwnerFileObject(payload.approval,securityAt,'ukda.file-service-pair.v1');
    if(!await verifyObject({body,signature:payload.proof},base64urlDecode(body.publicKey),'ukda.file-service-pair.v1'))throw changed();}catch{throw changed();}
   const challenge=(await a.query<{service_id:string;public_key:string;account_id:string;device_id:string;data_generation:string;nonce:string;expires_at:Date;used_at:Date|null}>('SELECT * FROM app.file_service_pairings WHERE workspace_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE',[r.workspaceId,r.projectId,body.pairingId])).rows[0];
   if(!challenge||challenge.used_at||challenge.expires_at<=now||challenge.service_id!==body.serviceId||challenge.public_key!==body.publicKey||challenge.account_id!==principal.accountId||
    challenge.device_id!==principal.deviceId||challenge.data_generation!==principal.dataGeneration||challenge.nonce!==body.nonce)throw changed();
   const exists=(await a.query<{public_key:string;state:string}>('SELECT public_key,state FROM app.file_local_services WHERE workspace_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE',[r.workspaceId,r.projectId,body.serviceId])).rows[0];
   if(exists){if(exists.public_key!==body.publicKey||exists.state!=='active')throw changed();
    // A fresh local possession proof may renew a browser connection. The pinned
    // service identity stays fixed and previously revoked identities stay closed.
    await a.query('UPDATE app.file_local_services SET approved_pairing=$4,data_generation=$5 WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[r.workspaceId,r.projectId,body.serviceId,payload,principal.dataGeneration]);
   }else{const count=Number((await a.query<{n:string}>('SELECT count(*)::text AS n FROM app.file_local_services WHERE workspace_id=$1 AND project_id=$2',[r.workspaceId,r.projectId])).rows[0]!.n);
    if(count>=100)throw new AppError('DELIVERY_SERVICE_LIMIT','This project has reached its shared folder limit',413);
    await a.query("INSERT INTO app.file_local_services(workspace_id,project_id,id,public_key,data_generation,approved_pairing,state,created_at) VALUES($1,$2,$3,$4,$5,$6,'active',$7)",[r.workspaceId,r.projectId,body.serviceId,body.publicKey,principal.dataGeneration,payload,now]);
   }
   await a.query('UPDATE app.file_service_pairings SET used_at=$3 WHERE workspace_id=$1 AND id=$2',[r.workspaceId,body.pairingId,now]);
   return this.#record(a,principal,r,hash,payload,'pair',null,null,now);
  });
 }
 async #service(a:pg.PoolClient,p:PlanningContext,serviceId:string,securityAt:PlanningSecurityResolver){const b=p.binding,row=(await a.query<{public_key:string;approved_pairing:z.infer<typeof deliveryPairRequest>}>('SELECT public_key,approved_pairing FROM app.file_local_services WHERE workspace_id=$1 AND project_id=$2 AND id=$3 AND state=\'active\' AND data_generation=$4',[b.workspaceId,b.projectId,serviceId,b.dataGeneration])).rows[0];if(!row)throw new AppError('DELIVERY_SERVICE_UNAVAILABLE','Connect an approved local file service before publishing',409);
  try{const pair=deliveryPairRequest.parse(row.approved_pairing),body=pair.approval.body;await verifyOwnerFileObject(pair.approval,securityAt,'ukda.file-service-pair.v1');
   if(body.serviceId!==serviceId||body.publicKey!==row.public_key||body.binding.workspaceId!==b.workspaceId||body.binding.projectId!==b.projectId||body.binding.dataGeneration!==b.dataGeneration||
    !await verifyObject({body,signature:pair.proof},base64urlDecode(row.public_key,32),'ukda.file-service-pair.v1'))throw changed();
   const revocations=(await a.query<{payload:unknown}>(`SELECT payload FROM app.file_delivery_operations WHERE workspace_id=$1 AND project_id=$2 AND data_generation=$3
    AND receipt->>'action'='revoke_service' AND payload->'mutation'->'body'->>'serviceId'=$4`,[b.workspaceId,b.projectId,b.dataGeneration,serviceId])).rows;
   for(const operation of revocations){const revoked=deliveryServiceCommandRequest.parse(operation.payload);await verifyOwnerFileObject(revoked.mutation,securityAt,'ukda.file-service-revoke.v1');if(revoked.mutation.body.publicKey===row.public_key)throw changed();}
  }catch{throw changed();}return row;
 }
 async services(cookie:string,csrf:string,input:unknown){const r=parse(fileReference,input);return this.#with(cookie,csrf,r,false,async(a,_p,_principal,_now,securityAt)=>{
  const rows=(await a.query<{id:string;public_key:string;state:'active'|'revoked';data_generation:string;approved_pairing:z.infer<typeof deliveryPairRequest>}>('SELECT * FROM app.file_local_services WHERE workspace_id=$1 AND project_id=$2 ORDER BY id LIMIT 101',[r.workspaceId,r.projectId])).rows;
  if(rows.length>100)throw new AppError('DELIVERY_SERVICE_LIMIT','This project has reached its local service limit',413);
  for(const row of rows){const pair=deliveryPairRequest.parse(row.approved_pairing),body=pair.approval.body;await verifyOwnerFileObject(pair.approval,securityAt,'ukda.file-service-pair.v1');
   if(body.serviceId!==row.id||body.publicKey!==row.public_key||body.binding.workspaceId!==r.workspaceId||body.binding.projectId!==r.projectId||body.binding.dataGeneration!==row.data_generation||
    !await verifyObject({body,signature:pair.proof},base64urlDecode(row.public_key,32),'ukda.file-service-pair.v1'))throw changed();}
  return {services:rows.map(row=>({serviceId:row.id,publicKey:row.public_key,state:row.state,dataGeneration:row.data_generation,approval:row.approved_pairing}))};
 });}
 async revokeService(cookie:string,csrf:string,input:unknown):Promise<DeliveryView>{const payload=parse(deliveryServiceCommandRequest,input),body=payload.mutation.body,b=body.binding,r=ref(b),hash=await digestObject(payload);
  return this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{
   const prior=await this.#prior(a,principal,r,hash);if(prior)return {state:'completed',receipt:prior};
   try{assertFileBindingCurrent(b,p,now);await verifyOwnerFileObject(payload.mutation,securityAt,'ukda.file-service-revoke.v1');}catch{throw changed();}
   const service=await this.#service(a,p,body.serviceId,securityAt);if(service.public_key!==body.publicKey)throw changed();
   await a.query("UPDATE app.file_local_services SET state='revoked' WHERE workspace_id=$1 AND project_id=$2 AND id=$3",[r.workspaceId,r.projectId,body.serviceId]);
   return this.#record(a,principal,r,hash,payload,'revoke_service',null,null,now);
  });
 }
 async permit(cookie:string,csrf:string,input:unknown):Promise<DeliveryPermit>{const r=parse(deliveryPermitRequest,input);return this.#with(cookie,csrf,r,true,async(a,p,_principal,now,securityAt)=>{
  const row=await this.#row(a,r,r.batchId);await this.#read(a,row,securityAt);if(row.state!=='confirmed')throw changed();await this.#eligible(a,p,row,securityAt);await this.#service(a,p,r.serviceId,securityAt);
  const item=row.signed_batch.body.items[r.index];if(!item)throw invalid();const body={purpose:'ukda.file-delivery-permit.v1' as const,version:1 as const,keyId:this.options.secrets.keyId,origin:this.options.origin,
   workspaceId:r.workspaceId,projectId:r.projectId,batchId:r.batchId,frozenDigest:row.frozen_digest,serviceId:r.serviceId,permitId:randomUUID(),nonce:this.options.secrets.token(),index:r.index,
   itemDigest:await digestObject(item),securityHead:p.binding.securityHead,securityVersion:p.binding.securityVersion,dataGeneration:p.binding.dataGeneration,issuedAt:now.toISOString(),expiresAt:new Date(now.getTime()+DELIVERY_PERMIT_TTL_MS).toISOString()};
  await sodium.ready;const seed=this.options.secrets.digest('entitlement-signing-key',this.options.secrets.keyId),pair=sodium.crypto_sign_seed_keypair(seed);let permit:DeliveryPermit;
  try{permit=deliveryPermit.parse(await signObject(body,pair.privateKey));}finally{seed.fill(0);pair.privateKey.fill(0);}
  await a.query('INSERT INTO app.file_delivery_permits(workspace_id,project_id,id,batch_id,service_id,item_index,signed_permit,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[r.workspaceId,r.projectId,body.permitId,r.batchId,r.serviceId,r.index,permit,now,body.expiresAt]);return permit;
 });}
 async publish(cookie:string,csrf:string,input:unknown):Promise<DeliveryView>{const payload=parse(deliveryPublishRequest,input),body=payload.mutation.body,b=body.binding,r=ref(b),hash=await digestObject(payload);
  return this.#with(cookie,csrf,r,true,async(a,p,principal,now,securityAt)=>{
   const prior=await this.#prior(a,principal,r,hash);if(prior)return {state:'completed',receipt:prior};
   try{assertFileBindingCurrent(b,p,now);await verifyOwnerFileObject(payload.mutation,securityAt,'ukda.file-delivery-published.v1');}catch{throw changed();}
   const row=await this.#row(a,r,body.batchId);await this.#read(a,row,securityAt);if(row.state!=='confirmed'||row.frozen_digest!==body.frozenDigest)throw changed();await this.#eligible(a,p,row,securityAt);
   const service=await this.#service(a,p,body.receipt.body.serviceId,securityAt),receipt=body.receipt.body;
   if(receipt.workspaceId!==r.workspaceId||receipt.projectId!==r.projectId||receipt.batchId!==body.batchId||receipt.frozenDigest!==body.frozenDigest||
    !await verifyObject(body.receipt,base64urlDecode(service.public_key),'ukda.local-file-publication.v1')||Date.parse(receipt.completedAt)>now.getTime()+30000||
    Date.parse(receipt.completedAt)<Date.parse(receipt.startedAt)||receipt.permitIds.length!==row.signed_batch.body.items.length)throw changed();
   const permits=(await a.query<{id:string;item_index:number;signed_permit:DeliveryPermit;used_at:Date|null;issued_at:Date;expires_at:Date}>('SELECT * FROM app.file_delivery_permits WHERE workspace_id=$1 AND project_id=$2 AND batch_id=$3 AND service_id=$4 AND id=ANY($5::uuid[]) ORDER BY item_index FOR UPDATE',[r.workspaceId,r.projectId,row.id,receipt.serviceId,receipt.permitIds])).rows;
   if(permits.length!==receipt.permitIds.length||permits.some((permit,index)=>permit.item_index!==index||permit.used_at||permit.signed_permit.body.frozenDigest!==row.frozen_digest||
    permit.signed_permit.body.dataGeneration!==p.binding.dataGeneration||permit.issued_at.getTime()<Date.parse(receipt.startedAt)-30000||permit.expires_at.getTime()<Date.parse(receipt.startedAt)))throw changed();
   await a.query('UPDATE app.file_delivery_permits SET used_at=$3 WHERE workspace_id=$1 AND id=ANY($2::uuid[]) AND used_at IS NULL',[r.workspaceId,receipt.permitIds,now]);
   await a.query("UPDATE app.file_delivery_batches SET state='published',publication=$3 WHERE workspace_id=$1 AND id=$2",[r.workspaceId,row.id,body.receipt]);
   return this.#record(a,principal,r,hash,payload,'publish',row.id,row.frozen_digest,now);
  });
 }
 async status(cookie:string,csrf:string,input:unknown):Promise<DeliveryView>{const r=parse(deliveryStatusRequest,input);return this.#with(cookie,csrf,r,false,async(a,_p,principal)=>{
  if(r.dataGeneration!==principal.dataGeneration)throw changed();const receipt=await this.#prior(a,principal,r,r.requestHash);return {state:receipt?'completed':'absent',receipt};
 });}
}

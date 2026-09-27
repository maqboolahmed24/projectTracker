import type pg from 'pg';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { tenantTransaction } from '../../persistence.js';
import { base64urlEncode,canonicalJson,digestObject } from '../../shared/crypto.js';
import { contentEnvelope } from '../../shared/contracts.js';
import { DELETION_DELAY_MS,lifecycleContextRequest,lifecycleContext,lifecycleMutation,lifecycleReceipt,lifecycleStatusRequest,
  erasureList,validateLifecycleMutation,type LifecycleBinding,type LifecycleContext,type LifecycleMutation,type LifecycleReceipt,type LifecycleView } from '../../shared/lifecycle.js';
import { verifySecurityHistory,type SecurityHistoryInput } from '../../shared/security-history.js';
import { EntitlementOperations } from '../identity/entitlements.js';
import { projectAuthoritativeWorkspace,withSecurityFence } from '../identity/projection.js';
import { readCurrentDeviceProjectScopes } from '../work/planning.js';
import { SessionService,type SessionPrincipal } from '../identity/sessions.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { deletionElapsed,finalizeDeletionIfDue } from './deadline.js';

export interface LifecycleAuth {cookieValue:string;csrfToken:string}
interface Options {databases:Databases;sessions:SessionService;secrets:ServiceSecrets;origin:string;now?:()=>Date;
 hooks?:{beforeControlCommit?:(control:pg.PoolClient)=>Promise<void>;afterControlCommit?:()=>Promise<void>;afterCommit?:()=>Promise<void>}}
interface Authority {w:pg.QueryResultRow;p:SessionPrincipal;profile:pg.QueryResultRow;device:pg.QueryResultRow}
const denied=()=>new AppError('LIFECYCLE_FORBIDDEN','Current approved authority is required',403);
const changed=()=>new AppError('LIFECYCLE_CHANGED','Reload the current workspace state',409);
export class LifecycleService {
 readonly #now:()=>Date;
 constructor(readonly options:Options){this.#now=options.now??(()=>new Date());}
 async #authority(c:pg.PoolClient,auth:LifecycleAuth,workspaceId:string,recent=false):Promise<Authority>{
  // Security receipts must survive failover even when the connection defaults to local/off.
  await c.query("SET LOCAL synchronous_commit='on'");
  const w=(await c.query('SELECT * FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE',[workspaceId])).rows[0];
  if(!w||deletionElapsed(w,this.#now())||!['active','pending_deletion'].includes(w.lifecycle))throw denied();
  const p=await this.options.sessions.resolveCurrent(c,auth.cookieValue,{csrfToken:auth.csrfToken,approved:true,recent},this.#now());
  if(p.workspaceId!==workspaceId||!p.deviceId)throw denied();
  const profile=(await c.query("SELECT * FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 AND state='active'",[workspaceId,p.accountId])).rows[0];
  const device=(await c.query("SELECT * FROM security.devices WHERE workspace_id=$1 AND device_id=$2 AND profile_id=$3 AND state='active'",[workspaceId,p.deviceId,p.accountId])).rows[0];
  const scopes=await readCurrentDeviceProjectScopes(c,p,this.#now());
  if(!profile||!device||!scopes.some(s=>s.scope==='workspace'&&s.permissions.includes('read_project')&&(!profile.is_owner||s.mode==='custody'&&s.keyEpoch===w.custody_epoch)))throw denied();
  return {w,p,profile,device};
 }
 async #history(c:pg.PoolClient,p:SessionPrincipal){
  const genesis=(await c.query('SELECT o.versioned_object,o.object_hash FROM security.workspaces w JOIN security.staged_objects o ON o.workspace_id=w.workspace_id AND o.object_id=w.genesis_object_id WHERE w.workspace_id=$1',[p.workspaceId])).rows[0];
  if(!genesis||await digestObject(genesis.versioned_object)!==genesis.object_hash)throw changed();
  const transitions=(await c.query('SELECT signed_transition FROM security.security_transitions WHERE workspace_id=$1 AND sequence>1 ORDER BY sequence',[p.workspaceId])).rows.map(r=>r.signed_transition);
  const key=await new EntitlementOperations(this.options.databases,this.options.secrets).publicSigningKey();
  return verifySecurityHistory({workspaceId:p.workspaceId,origin:this.options.origin,genesisFingerprint:genesis.object_hash,genesis:genesis.versioned_object as SecurityHistoryInput['genesis'],
   transitions,expected:{securityHead:p.securityHead,securityVersion:p.securityVersion},trustedServiceKeys:{[this.options.secrets.keyId]:key}});
 }
 async #binding(c:pg.PoolClient,a:Authority,request:{workspaceId:string;operationId:string;action:LifecycleBinding['action']}):Promise<LifecycleContext>{
  const {w,p,device,profile}=a,state=await this.#history(c,p),now=this.#now();
  if(request.action!=='request_erasure'&&!profile.is_owner||w.restore_quarantine&&request.action==='request_deletion')throw denied();
  const workspace=request.action==='request_deletion'?(await c.query('SELECT versioned_object FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND state=\'committed\'',[p.workspaceId,state.workspaceContent!.objectId])).rows[0]?.versioned_object:null;
  if(request.action==='request_deletion'&&(!workspace||await digestObject(workspace)!==state.workspaceContent!.digest))throw changed();
  return lifecycleContext.parse({binding:{version:1,...request,origin:this.options.origin,accountId:p.accountId,deviceId:p.deviceId,isOwner:profile.is_owner,
   credentialGeneration:p.credentialGeneration,sessionGeneration:p.sessionGeneration,keyGeneration:device.key_generation,signingPublicKey:base64urlEncode(device.signing_public_key),
   securityHead:p.securityHead,securityVersion:p.securityVersion,nextSecurityVersion:String(BigInt(p.securityVersion)+1n),dataGeneration:p.dataGeneration,
   ownershipVersion:w.ownership_version,custodyEpoch:w.custody_epoch,workspaceDigest:profile.is_owner?state.workspaceContent!.digest:null,
   deletion:w.lifecycle==='pending_deletion'?{requestId:w.active_deletion_operation_id,requestedAt:new Date(w.deletion_requested_at).toISOString(),deleteAfter:new Date(w.delete_after).toISOString()}:null,
   issuedAt:now.toISOString(),expiresAt:new Date(now.getTime()+300000).toISOString()},workspace:workspace?contentEnvelope.parse(workspace):null});
 }
 async context(auth:LifecycleAuth,input:unknown):Promise<LifecycleContext>{
  const ref=parseInput(lifecycleContextRequest,input);
  await finalizeDeletionIfDue({...this.options,workspaceId:ref.workspaceId,now:this.#now()});
  return tenantTransaction(this.options.databases.control,ref.workspaceId,undefined,async c=>this.#binding(c,await this.#authority(c,auth,ref.workspaceId,ref.action!=='request_erasure'),ref));
 }
 async #prior(c:pg.PoolClient,p:SessionPrincipal,operationId:string,hash:string){
  const row=(await c.query("SELECT outcome,request_hash FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2 AND operation_kind LIKE 'lifecycle.%'",[p.workspaceId,operationId])).rows[0];
  if(!row)return null;const receipt=lifecycleReceipt.parse(row.outcome);
  if(receipt.actorId!==p.accountId||receipt.dataGeneration!==p.dataGeneration||row.request_hash!==hash)throw changed();
  return receipt;
 }
 async save(auth:LifecycleAuth,input:unknown):Promise<LifecycleView>{
  const signed=parseInput(lifecycleMutation,input),b=signed.body.binding,hash=await digestObject(signed);
  await finalizeDeletionIfDue({...this.options,workspaceId:b.workspaceId,now:this.#now()});
  const initial=await this.options.sessions.authenticate(auth.cookieValue,{csrfToken:auth.csrfToken,approved:true});
  if(initial.workspaceId!==b.workspaceId)throw denied();
  const result=await withSecurityFence(this.options.databases,b.workspaceId,async app=>{
   let receipt:LifecycleReceipt;
   try{receipt=await tenantTransaction(this.options.databases.control,b.workspaceId,undefined,async c=>{
    const a=await this.#authority(c,auth,b.workspaceId),prior=await this.#prior(c,a.p,b.operationId,hash);if(prior)return prior;
    if(b.action!=='request_erasure'&&this.#now().getTime()-a.p.authenticatedAt.getTime()>=300000)throw new AppError('REAUTH_REQUIRED','Confirm your password to continue',401);
    const current=await this.#binding(c,a,{workspaceId:b.workspaceId,operationId:b.operationId,action:b.action}),now=this.#now();
    if(Date.parse(b.expiresAt)<=now.getTime()||Date.parse(b.issuedAt)>now.getTime()+30000||canonicalJson(b)!==canonicalJson({...current.binding,issuedAt:b.issuedAt,expiresAt:b.expiresAt}))throw changed();
    await validateLifecycleMutation(signed,await this.#history(c,a.p));
    let deletion=b.deletion;
    if(b.action==='request_deletion'){
     if(a.w.lifecycle!=='active')throw changed();
     deletion={requestId:b.operationId,requestedAt:b.issuedAt,deleteAfter:new Date(Date.parse(b.issuedAt)+DELETION_DELAY_MS).toISOString()};
     await c.query("UPDATE security.workspaces SET lifecycle='pending_deletion',active_deletion_operation_id=$2,deletion_requested_at=$3,delete_after=$4 WHERE workspace_id=$1",[b.workspaceId,b.operationId,deletion.requestedAt,deletion.deleteAfter]);
    }else if(b.action==='cancel_deletion'){
     if(!deletion||a.w.lifecycle!=='pending_deletion'||now.getTime()>=Date.parse(deletion.deleteAfter))throw changed();
     await c.query("UPDATE security.workspaces SET lifecycle='active',active_deletion_operation_id=NULL,deletion_requested_at=NULL,delete_after=NULL WHERE workspace_id=$1",[b.workspaceId]);deletion=null;
    }else{
     if((await c.query("SELECT 1 FROM security.erasure_requests WHERE workspace_id=$1 AND profile_id=$2 AND state='requested'",[b.workspaceId,b.accountId])).rowCount)throw changed();
     await c.query("INSERT INTO security.erasure_requests(workspace_id,request_id,profile_id,signed_request,state,requested_at) VALUES($1,$2,$3,$4,'requested',$5)",[b.workspaceId,b.operationId,b.accountId,signed,now]);
    }
    const head=await digestObject(signed);
    await c.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition,created_at)
     VALUES($1,$2,$3,$4,$5,$6,'device',$7,$8,$9,$10)`,[b.workspaceId,b.nextSecurityVersion,b.operationId,b.securityHead,head,`lifecycle.${b.action}`,b.accountId,b.deviceId,signed,now]);
    await c.query('UPDATE security.workspaces SET security_head=$2,security_version=$3,updated_at=$4 WHERE workspace_id=$1',[b.workspaceId,head,b.nextSecurityVersion,now]);
    const committed=lifecycleReceipt.parse({version:1,workspaceId:b.workspaceId,operationId:b.operationId,actorId:b.accountId,dataGeneration:b.dataGeneration,requestHash:hash,
     securityHead:head,securityVersion:b.nextSecurityVersion,action:b.action,deletion,committedAt:now.toISOString(),transition:signed});
    await c.query(`INSERT INTO security.operation_receipts(workspace_id,operation_id,request_hash,operation_kind,security_version,outcome,created_at)
     VALUES($1,$2,$3,$4,$5,$6,$7)`,[b.workspaceId,b.operationId,hash,`lifecycle.${b.action}`,b.nextSecurityVersion,committed,now]);
    await this.options.hooks?.beforeControlCommit?.(c);
    // A cancellation prepared before the deadline must also commit before it.
    if(b.action==='cancel_deletion'&&this.#now().getTime()>=Date.parse(b.deletion!.deleteAfter))throw changed();
    return committed;
   });}catch(error){await projectAuthoritativeWorkspace(this.options.databases,b.workspaceId,app);return {error};}
   try{await this.options.hooks?.afterControlCommit?.();await projectAuthoritativeWorkspace(this.options.databases,b.workspaceId,app);return {view:{state:'completed' as const,receipt}};}
   catch{return {view:{state:'finishing' as const,receipt}};}
  },{enqueueActivationProjection:true});
  if('error'in result)throw result.error;await this.options.hooks?.afterCommit?.();return result.view;
 }
 async status(auth:LifecycleAuth,input:unknown):Promise<LifecycleView>{
  const ref=parseInput(lifecycleStatusRequest,input);
  await finalizeDeletionIfDue({...this.options,workspaceId:ref.workspaceId,now:this.#now()});
  const receipt=await tenantTransaction(this.options.databases.control,ref.workspaceId,undefined,async c=>{
   const a=await this.#authority(c,auth,ref.workspaceId);if(a.p.dataGeneration!==ref.dataGeneration)throw changed();return this.#prior(c,a.p,ref.operationId,ref.requestHash);});
  if(!receipt)return {state:'absent',receipt:null};
  try{await projectAuthoritativeWorkspace(this.options.databases,ref.workspaceId);return {state:'completed',receipt};}catch{return {state:'finishing',receipt};}
 }
 async erasures(auth:LifecycleAuth,workspaceId:string){
  await finalizeDeletionIfDue({...this.options,workspaceId,now:this.#now()});
  return tenantTransaction(this.options.databases.control,workspaceId,undefined,async c=>{
   const a=await this.#authority(c,auth,workspaceId),rows=(await c.query('SELECT * FROM security.erasure_requests WHERE workspace_id=$1 AND ($2 OR profile_id=$3) ORDER BY requested_at,request_id',[workspaceId,a.profile.is_owner,a.p.accountId])).rows;
   const owners=(await c.query("SELECT profile_id FROM security.profiles WHERE workspace_id=$1 AND state='active' AND is_owner",[workspaceId])).rows;
   return erasureList.parse({workspaceId,requests:rows.map(r=>({requestId:r.request_id,accountId:r.profile_id,state:r.state,requestedAt:r.requested_at.toISOString(),fulfilledAt:r.fulfilled_at?.toISOString()??null,
    needsSuccessor:r.state==='requested'&&owners.length===1&&owners[0]!.profile_id===r.profile_id}))});
  });
 }
}

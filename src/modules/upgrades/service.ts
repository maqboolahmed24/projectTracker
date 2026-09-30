import { planningWireValue } from '../../shared/planning-api.js';
import type pg from 'pg';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { dataTransaction,tenantTransaction } from '../../persistence.js';
import { base64urlEncode,canonicalJson,digestObject } from '../../shared/crypto.js';
import { upgradeRecordRef,identityUpgradePayload,identityUpgradeHistory,applyIdentityUpgradeHistory,type UpgradeRecordRef } from '../../shared/encrypted-upgrades.js';
import { upgradeBatch,upgradeContextRequest,upgradeContext,upgradeStart,upgradeFinish,upgradeStatusRequest,upgradeReceipt,
  validateUpgradeLifecycle,UPGRADE_MAX_CONTEXT_BYTES,type UpgradeLifecycleBinding,type UpgradeContext,type UpgradeStart,type UpgradeFinish,
  type UpgradeReceipt,type UpgradeView } from '../../shared/upgrade-api.js';
import { projectAuthoritativeWorkspace,withSecurityFence } from '../identity/projection.js';
import { SessionService,type SessionPrincipal } from '../identity/sessions.js';
import { EntitlementOperations } from '../identity/entitlements.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { verifySecurityHistory,type SecurityHistoryInput } from '../../shared/security-history.js';
import { readCurrentDeviceProjectScopes } from '../work/planning.js';
import { readCurrentUpgradeRecords,upgradeRecordKey,type CurrentUpgradeRecord } from './records.js';
import { assertCurrentUpgradeBatch,upgradeChanged,upgradeForbidden,upgradeRestricted } from './ledger.js';

export interface UpgradeAuth {cookieValue:string;csrfToken:string}
interface Options {databases:Databases;sessions:SessionService;secrets:ServiceSecrets;origin:string;now?:()=>Date;
  handlers:{planning:(auth:UpgradeAuth,payload:unknown)=>Promise<unknown>;team:(auth:UpgradeAuth,payload:unknown)=>Promise<unknown>;
    collaboration:(auth:UpgradeAuth,payload:unknown)=>Promise<unknown>};
  hooks?:{beforeControlCommit?:(control:pg.PoolClient)=>Promise<void>;afterControlCommit?:()=>Promise<void>;afterCommit?:()=>Promise<void>}}
interface Authority {principal:SessionPrincipal;workspace:pg.QueryResultRow;device:pg.QueryResultRow;workspaceKeyEpoch:string}
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
function parse<T>(schema:z.ZodType<T>,value:unknown):T{const result=schema.safeParse(value);if(!result.success)throw new AppError('UPGRADE_INVALID','Invalid encrypted upgrade request',400);return result.data;}
async function appTransaction<T>(client:pg.PoolClient,workspaceId:string,profileId:string,action:()=>Promise<T>):Promise<T>{
  await client.query('BEGIN');try{await client.query("SELECT set_config('ukda.workspace_id',$1,true),set_config('ukda.profile_id',$2,true)",[workspaceId,profileId]);
    const result=await action();await client.query('COMMIT');return result;
  }catch(error){await client.query('ROLLBACK');throw error;}
}

/** A finite Owner-operated upgrade. Business batches use their native signed
 * lineages; control decisions and recoverable app projection are separate commits. */
export class UpgradeService {
  readonly #now:()=>Date;
  readonly #trusted:Promise<Record<string,string>>;
  constructor(readonly options:Options){this.#now=options.now??(()=>new Date());if(new URL(options.origin).origin!==options.origin)throw new Error('Upgrade requires exact origin');
    this.#trusted=new EntitlementOperations(options.databases,options.secrets).publicSigningKey().then(key=>({[options.secrets.keyId]:key}));}
  async #history(control:pg.PoolClient,p:Authority){
    const genesis=(await control.query('SELECT o.versioned_object,o.object_hash FROM security.workspaces w JOIN security.staged_objects o ON o.workspace_id=w.workspace_id AND o.object_id=w.genesis_object_id WHERE w.workspace_id=$1',[p.principal.workspaceId])).rows[0];
    if(!genesis||await digestObject(genesis.versioned_object)!==genesis.object_hash)throw upgradeChanged();
    const transitions=(await control.query('SELECT signed_transition FROM security.security_transitions WHERE workspace_id=$1 AND sequence>1 ORDER BY sequence',[p.principal.workspaceId])).rows.map(r=>r.signed_transition);
    return verifySecurityHistory({workspaceId:p.principal.workspaceId,origin:this.options.origin,genesisFingerprint:genesis.object_hash,
      genesis:genesis.versioned_object as SecurityHistoryInput['genesis'],transitions,expected:{securityHead:p.principal.securityHead,securityVersion:p.principal.securityVersion},trustedServiceKeys:await this.#trusted});
  }
  async #authority(control:pg.PoolClient,auth:UpgradeAuth,workspaceId:string,now:Date,recent=false):Promise<Authority>{
    // Migration authority must not inherit a weaker runtime connection commit setting.
    await control.query("SET LOCAL synchronous_commit='on'");
    // Match enrolment's workspace-before-session lock order. This also fixes the
    // pending invitation source snapshot while a finite manifest is captured.
    const workspace=(await control.query('SELECT * FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE',[workspaceId])).rows[0];
    const principal=await this.options.sessions.resolveCurrent(control,auth.cookieValue,{csrfToken:auth.csrfToken,approved:true,recent},now);
    if(principal.workspaceId!==workspaceId||!principal.deviceId)throw upgradeForbidden();
    const profile=(await control.query("SELECT * FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 AND state='active' AND is_owner",[workspaceId,principal.accountId])).rows[0];
    const device=(await control.query("SELECT * FROM security.devices WHERE workspace_id=$1 AND device_id=$2 AND profile_id=$3 AND state='active' AND revoked_at IS NULL",[workspaceId,principal.deviceId,principal.accountId])).rows[0];
    if(!workspace||!profile||!device)throw upgradeForbidden();
    const scopes=await readCurrentDeviceProjectScopes(control,principal,now),heads=(await control.query('SELECT scope_kind,scope_id,key_epoch FROM security.scope_heads WHERE workspace_id=$1 ORDER BY scope_kind,scope_id',[workspaceId])).rows;
    if(!scopes.some(s=>s.scope==='workspace'&&s.scopeId===workspaceId&&s.mode==='custody'&&s.keyEpoch===workspace.custody_epoch&&s.permissions.includes('read_project')&&s.permissions.includes('plan_projects'))||
      heads.some(h=>h.scope_kind==='project'&&!scopes.some(s=>s.scope==='project'&&s.scopeId===h.scope_id&&s.mode==='content'&&s.keyEpoch===h.key_epoch&&s.permissions.includes('read_project')&&s.permissions.includes('plan_projects'))))throw upgradeForbidden();
    const workspaceKeyEpoch=heads.find(h=>h.scope_kind==='workspace'&&h.scope_id===workspaceId)?.key_epoch;if(!workspaceKeyEpoch)throw upgradeForbidden();
    return {principal,workspace,device,workspaceKeyEpoch};
  }
  #writable(p:Authority){const w=p.workspace;if(w.lifecycle!=='active'||w.licence_state!=='active'||w.restore_quarantine)throw upgradeRestricted();}
  async #binding(p:Authority,migrationId:string,operationId:string,manifest:UpgradeRecordRef[],completed:UpgradeRecordRef[],now:Date):Promise<UpgradeLifecycleBinding>{
    const s=p.principal,w=p.workspace;return {version:1,workspaceId:s.workspaceId,migrationId,operationId,origin:this.options.origin,
      accountId:s.accountId,deviceId:s.deviceId!,credentialGeneration:s.credentialGeneration,sessionGeneration:s.sessionGeneration,
      keyGeneration:p.device.key_generation,signingPublicKey:base64urlEncode(p.device.signing_public_key),securityVersion:s.securityVersion,nextSecurityVersion:String(BigInt(s.securityVersion)+1n),
      securityHead:s.securityHead,dataGeneration:s.dataGeneration,ownershipVersion:w.ownership_version,custodyEpoch:w.custody_epoch,
      workspaceKeyEpoch:p.workspaceKeyEpoch,writeSchema:w.write_schema,manifestDigest:await digestObject(manifest),manifestCount:manifest.length,
      completedDigest:await digestObject(completed),completedCount:completed.length,issuedAt:now.toISOString(),expiresAt:new Date(now.getTime()+600000).toISOString()};
  }
  async #checkBinding(p:Authority,b:UpgradeLifecycleBinding,manifest:UpgradeRecordRef[],completed:UpgradeRecordRef[],now:Date){
    const expected=await this.#binding(p,b.migrationId,b.operationId,manifest,completed,now);
    if(Date.parse(b.expiresAt)<=now.getTime()||Date.parse(b.issuedAt)>now.getTime()+30000||
      !same(b,{...expected,issuedAt:b.issuedAt,expiresAt:b.expiresAt}))throw upgradeChanged();
  }
  async #repair(workspaceId:string){
    const fenced=await tenantTransaction(this.options.databases.application,workspaceId,undefined,async a=>(await a.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1',[workspaceId])).rows[0]?.fence_closed);
    if(fenced)await projectAuthoritativeWorkspace(this.options.databases,workspaceId);
  }
  async #read<T>(auth:UpgradeAuth,workspaceId:string,action:(a:pg.PoolClient,c:pg.PoolClient,p:Authority,now:Date)=>Promise<T>):Promise<T>{
    const initial=await this.options.sessions.authenticate(auth.cookieValue,{csrfToken:auth.csrfToken,approved:true});
    if(initial.workspaceId!==workspaceId)throw upgradeForbidden();
    await this.#repair(workspaceId);
    return dataTransaction(this.options.databases,initial,a=>tenantTransaction(this.options.databases.control,workspaceId,undefined,async c=>{
      const now=this.#now(),p=await this.#authority(c,auth,workspaceId,now);
      if(p.principal.securityHead!==initial.securityHead||p.principal.dataGeneration!==initial.dataGeneration)throw upgradeChanged();
      return action(a,c,p,now);
    }));
  }
  async #completed(a:pg.PoolClient,workspaceId:string,migrationId:string):Promise<UpgradeRecordRef[]>{
    return (await a.query('SELECT DISTINCT ON(record_type,record_id) signed_item FROM app.encrypted_upgrade_items WHERE workspace_id=$1 AND migration_id=$2 ORDER BY record_type,record_id,target_revision DESC,created_at DESC,operation_id',[workspaceId,migrationId])).rows.map(row=>upgradeRecordRef.parse(row.signed_item.target));
  }
  async context(auth:UpgradeAuth,input:unknown):Promise<UpgradeContext>{const ref=parse(upgradeContextRequest,input);
    return this.#read(auth,ref.workspaceId,async(a,_c,p,now)=>{
      const migrationId=ref.migrationId??p.workspace.active_upgrade_id??ref.operationId;
      const row=(await a.query('SELECT * FROM app.encrypted_upgrades WHERE workspace_id=$1 AND migration_id=$2',[ref.workspaceId,migrationId])).rows[0];
      let records:CurrentUpgradeRecord[],manifest:UpgradeRecordRef[],completed:UpgradeRecordRef[]=[];
      if(row){
        if(row.state==='staged')throw upgradeChanged();
        if(row.data_generation!==p.principal.dataGeneration)throw upgradeChanged();
        manifest=z.array(upgradeRecordRef).parse(row.source_manifest);completed=await this.#completed(a,ref.workspaceId,migrationId);
        records=await readCurrentUpgradeRecords(a,ref.workspaceId,_c);
        if(!same(records.map(r=>upgradeRecordKey(r.reference)),manifest.map(upgradeRecordKey)))throw upgradeChanged();
      }else{
        if(p.workspace.active_upgrade_id||p.workspace.write_schema!==1||p.workspace.content_maintenance)throw upgradeChanged();
        records=await readCurrentUpgradeRecords(a,ref.workspaceId,_c);manifest=records.map(r=>r.reference);
        if(manifest.some(r=>r.schema!==1))throw upgradeChanged();
      }
      if(ref.after&&!records.some(r=>upgradeRecordKey(r.reference)===ref.after))throw upgradeChanged();
      const remaining=ref.after?records.filter(r=>upgradeRecordKey(r.reference)>ref.after!):records,selected=remaining.slice(0,32);
      const state:UpgradeContext['state']=row?.state==='completed'?'completed':row?.state==='aborted'?'aborted':
        p.workspace.lifecycle!=='active'||p.workspace.licence_state!=='active'||p.workspace.restore_quarantine?'paused':row?'active':'available';
      const result=parse(upgradeContext,{binding:await this.#binding(p,migrationId,ref.operationId,manifest,completed,now),state,manifest,completed,records:selected,
        nextCursor:remaining.length>selected.length?upgradeRecordKey(selected.at(-1)!.reference):null,start:row?.signed_start??null,finish:row?.signed_finish??null});
      if(Buffer.byteLength(canonicalJson(planningWireValue(result)))>UPGRADE_MAX_CONTEXT_BYTES)throw new AppError('UPGRADE_TOO_LARGE','Encrypted upgrade page exceeds this release limit',413);
      return result;
    });
  }
  async #receipt(client:pg.PoolClient,store:'app'|'security',p:Authority,migrationId:string,operationId:string,hash:string):Promise<UpgradeReceipt|null>{
    const row=(await client.query(`SELECT * FROM ${store}.encrypted_upgrade_operations WHERE workspace_id=$1 AND operation_id=$2`,[p.principal.workspaceId,operationId])).rows[0];
    if(!row)return null;if(row.migration_id!==migrationId||row.actor_profile_id!==p.principal.accountId||row.data_generation!==p.principal.dataGeneration||row.request_digest!==hash)throw upgradeChanged();
    return parse(upgradeReceipt,row.receipt);
  }
  async #decisionReceipt(c:pg.PoolClient,p:Authority,payload:UpgradeStart|UpgradeFinish,kind:'start'|'finish',now:Date):Promise<UpgradeReceipt>{
    const b=payload.body.binding,requestHash=await digestObject(payload),receipt=parse(upgradeReceipt,{version:1,workspaceId:b.workspaceId,migrationId:b.migrationId,operationId:b.operationId,
      actorId:p.principal.accountId,dataGeneration:b.dataGeneration,kind,requestHash,manifestDigest:b.manifestDigest,completedCount:b.completedCount,committedAt:now.toISOString()});
    await c.query(`INSERT INTO security.encrypted_upgrade_operations(workspace_id,migration_id,operation_id,actor_profile_id,data_generation,kind,request_digest,signed_operation,receipt,created_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[b.workspaceId,b.migrationId,b.operationId,p.principal.accountId,b.dataGeneration,kind,requestHash,payload,receipt,now]);return receipt;
  }
  async #decision(auth:UpgradeAuth,payload:UpgradeStart|UpgradeFinish,kind:'start'|'finish'):Promise<UpgradeView>{
    const b=payload.body.binding,initial=await this.options.sessions.authenticate(auth.cookieValue,{csrfToken:auth.csrfToken,approved:true,recent:true});
    if(initial.workspaceId!==b.workspaceId)throw upgradeForbidden();
    const result=await withSecurityFence(this.options.databases,b.workspaceId,async a=>{
      let receipt:UpgradeReceipt;
      try{receipt=await tenantTransaction(this.options.databases.control,b.workspaceId,undefined,async c=>{
        const now=this.#now(),p=await this.#authority(c,auth,b.workspaceId,now,true),prior=await this.#receipt(c,'security',p,b.migrationId,b.operationId,await digestObject(payload));
        if(prior)return prior;this.#writable(p);await validateUpgradeLifecycle(payload,kind);
        if(kind==='start'){
          const start=payload as UpgradeStart;if(p.workspace.write_schema!==1||p.workspace.active_upgrade_id||p.workspace.content_maintenance)throw upgradeChanged();
          await appTransaction(a,b.workspaceId,p.principal.accountId,async()=>{
            const records=await readCurrentUpgradeRecords(a,b.workspaceId,c),manifest=records.map(r=>r.reference);
            await this.#checkBinding(p,b,manifest,[],now);if(!same(manifest,start.body.manifest))throw upgradeChanged();
            const existing=(await a.query('SELECT signed_start FROM app.encrypted_upgrades WHERE workspace_id=$1 AND migration_id=$2',[b.workspaceId,b.migrationId])).rows[0];
            if(existing){if(!same(existing.signed_start,start))throw upgradeChanged();return;}
            await a.query(`INSERT INTO app.encrypted_upgrades(workspace_id,migration_id,source_schema,target_schema,transform_id,data_generation,state,manifest_digest,source_manifest,signed_start,created_at)
              VALUES($1,$2,1,2,'ukda.content-data.v2',$3,'staged',$4,$5,$6,$7)`,[b.workspaceId,b.migrationId,b.dataGeneration,b.manifestDigest,JSON.stringify(manifest),start,now]);
            for(const record of records)await a.query(`INSERT INTO app.encrypted_upgrade_sources(workspace_id,migration_id,record_type,record_id,project_id,source_revision,source_digest,source_reference,source_envelope)
              VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[b.workspaceId,b.migrationId,record.reference.kind,record.reference.id,record.reference.projectId,record.reference.revision,record.reference.digest,record.reference,record.envelope]);
          });
          await c.query(`INSERT INTO security.encrypted_upgrades(workspace_id,migration_id,source_schema,target_schema,transform_id,data_generation,state,manifest_digest,signed_start,created_at)
            VALUES($1,$2,1,2,'ukda.content-data.v2',$3,'active',$4,$5,$6)`,[b.workspaceId,b.migrationId,b.dataGeneration,b.manifestDigest,start,now]);
          await c.query('UPDATE security.workspaces SET content_maintenance=true,active_upgrade_id=$2,updated_at=$3 WHERE workspace_id=$1',[b.workspaceId,b.migrationId,now]);
        }else{
          const finish=payload as UpgradeFinish;if(!p.workspace.content_maintenance||p.workspace.active_upgrade_id!==b.migrationId||p.workspace.write_schema!==1)throw upgradeChanged();
          await appTransaction(a,b.workspaceId,p.principal.accountId,async()=>{
            const row=(await a.query('SELECT * FROM app.encrypted_upgrades WHERE workspace_id=$1 AND migration_id=$2',[b.workspaceId,b.migrationId])).rows[0];
            if(!row||row.state!=='active')throw upgradeChanged();const manifest=z.array(upgradeRecordRef).parse(row.source_manifest),completed=await this.#completed(a,b.workspaceId,b.migrationId);
            await this.#checkBinding(p,b,manifest,completed,now);const current=(await readCurrentUpgradeRecords(a,b.workspaceId)).map(r=>r.reference);
            if(!same(completed,finish.body.targets)||!same(current,completed)||completed.length!==manifest.length)throw upgradeChanged();
          });
          const updated=await c.query("UPDATE security.encrypted_upgrades SET state='completed',signed_finish=$3,completed_at=$4 WHERE workspace_id=$1 AND migration_id=$2 AND state='active'",[b.workspaceId,b.migrationId,finish,now]);
          if(updated.rowCount!==1)throw upgradeChanged();
          await c.query('UPDATE security.workspaces SET write_schema=2,content_maintenance=false,active_upgrade_id=NULL,updated_at=$3 WHERE workspace_id=$1 AND active_upgrade_id=$2',[b.workspaceId,b.migrationId,now]);
        }
        const head=await digestObject(payload);
        await c.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition,created_at)
          VALUES($1,$2,$3,$4,$5,$6,'device',$7,$8,$9,$10)`,[b.workspaceId,b.nextSecurityVersion,b.operationId,b.securityHead,head,`content.upgrade.${kind}`,b.accountId,b.deviceId,payload,now]);
        await c.query('UPDATE security.workspaces SET security_version=$2,security_head=$3,updated_at=$4 WHERE workspace_id=$1',[b.workspaceId,b.nextSecurityVersion,head,now]);
        const committed=await this.#decisionReceipt(c,p,payload,kind,now);await this.options.hooks?.beforeControlCommit?.(c);return committed;
      });}catch(error){await projectAuthoritativeWorkspace(this.options.databases,b.workspaceId,a);return {error};}
      try{await this.options.hooks?.afterControlCommit?.();await projectAuthoritativeWorkspace(this.options.databases,b.workspaceId,a);return {view:{state:'completed' as const,receipt}};}
      catch{return {view:{state:'finishing' as const,receipt}};}
    },{enqueueActivationProjection:true});
    if('error'in result)throw result.error;await this.options.hooks?.afterCommit?.();return result.view;
  }
  start(auth:UpgradeAuth,input:unknown){return this.#decision(auth,parse(upgradeStart,input),'start');}
  finish(auth:UpgradeAuth,input:unknown){return this.#decision(auth,parse(upgradeFinish,input),'finish');}
  async batch(auth:UpgradeAuth,input:unknown):Promise<UpgradeView>{
    const request=parse(upgradeBatch,input),p=request.payload as {mutation?:{body?:{binding?:{workspaceId?:string;operationId?:string};upgrade?:{migrationId?:string}}}};
    const b=p?.mutation?.body?.binding,proof=p?.mutation?.body?.upgrade;
    if(!b||b.workspaceId!==request.workspaceId||proof?.migrationId!==request.migrationId||!b.operationId)throw upgradeChanged();
    if(request.kind==='identity')return this.identity(auth,request.payload);
    await this.options.handlers[request.kind](auth,request.payload);
    await this.options.hooks?.afterCommit?.();
    return this.status(auth,{workspaceId:request.workspaceId,migrationId:request.migrationId,operationId:b.operationId,
      dataGeneration:(p.mutation!.body!.binding as {dataGeneration:string}).dataGeneration,requestHash:await digestObject(request.payload)});
  }
  async identity(auth:UpgradeAuth,input:unknown):Promise<UpgradeView>{
    const payload=parse(identityUpgradePayload,input),b=payload.mutation.body.binding,initial=await this.options.sessions.authenticate(auth.cookieValue,{csrfToken:auth.csrfToken,approved:true,recent:true});
    if(initial.workspaceId!==b.workspaceId)throw upgradeForbidden();
    const result=await withSecurityFence(this.options.databases,b.workspaceId,async a=>{
      let receipt:UpgradeReceipt;
      try{receipt=await tenantTransaction(this.options.databases.control,b.workspaceId,undefined,async c=>{
        const now=this.#now(),p=await this.#authority(c,auth,b.workspaceId,now,true),hash=await digestObject(payload),prior=await this.#receipt(c,'security',p,b.migrationId,b.operationId,hash);
        if(prior)return prior;this.#writable(p);
        const history=identityUpgradeHistory.parse({...payload.mutation,upgradeItems:payload.upgradeItems});
        await applyIdentityUpgradeHistory(history,await this.#history(c,p));
        if(Date.parse(b.expiresAt)<=now.getTime()||Date.parse(b.issuedAt)>now.getTime()+30000)throw upgradeChanged();
        let completedCount=0;
        await appTransaction(a,b.workspaceId,p.principal.accountId,async()=>{
          await assertCurrentUpgradeBatch(this.options.databases,a,p.principal,payload.mutation.body.upgrade,payload.upgradeItems,now);
          const completed=new Set((await this.#completed(a,b.workspaceId,b.migrationId)).map(upgradeRecordKey));
          for(const item of payload.upgradeItems)completed.add(upgradeRecordKey(item.target));completedCount=completed.size;
        });
        const head=await digestObject(history),objects=payload.mutation.body.objects;
        for(const object of objects){const item=payload.upgradeItems.find(item=>item.target.kind===object.kind&&item.target.id===object.recordId)!;
          await c.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version,created_at)
            VALUES($1,$2,$3,$4,$5,$6,'committed',$7,$8)`,[b.workspaceId,object.id,`encrypted_${object.kind}`,object.digest,item.envelope,b.operationId,b.nextSecurityVersion,now]);
          if(object.kind==='profile')await c.query('UPDATE security.profiles SET profile_object_id=$3,updated_at=$4 WHERE workspace_id=$1 AND profile_id=$2',[b.workspaceId,object.recordId,object.id,now]);
          if(object.kind==='role')await c.query('UPDATE security.roles SET revision=$3,definition_object_id=$4,encrypted_role_object_id=$5,security_version=$6 WHERE workspace_id=$1 AND role_id=$2',
            [b.workspaceId,object.recordId,item.target.revision,b.operationId,object.id,b.nextSecurityVersion]);
        }
        await c.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version,created_at)
          VALUES($1,$2,'signed_grant',$3,$4,$2,'committed',$5,$6)`,[b.workspaceId,b.operationId,head,history,b.nextSecurityVersion,now]);
        await c.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition,created_at)
          VALUES($1,$2,$3,$4,$5,'identity.upgrade_content','device',$6,$7,$8,$9)`,[b.workspaceId,b.nextSecurityVersion,b.operationId,b.securityHead,head,b.accountId,b.deviceId,history,now]);
        await c.query('UPDATE security.workspaces SET security_version=$2,security_head=$3,updated_at=$4 WHERE workspace_id=$1',[b.workspaceId,b.nextSecurityVersion,head,now]);
        const outcome=parse(upgradeReceipt,{version:1,workspaceId:b.workspaceId,migrationId:b.migrationId,operationId:b.operationId,actorId:b.accountId,dataGeneration:b.dataGeneration,
          kind:'batch',requestHash:hash,manifestDigest:payload.mutation.body.upgrade.manifestDigest,completedCount,committedAt:now.toISOString()});
        await c.query(`INSERT INTO security.encrypted_upgrade_operations(workspace_id,migration_id,operation_id,actor_profile_id,data_generation,kind,request_digest,signed_operation,receipt,created_at)
          VALUES($1,$2,$3,$4,$5,'identity',$6,$7,$8,$9)`,[b.workspaceId,b.migrationId,b.operationId,b.accountId,b.dataGeneration,hash,payload,outcome,now]);
        await this.options.hooks?.beforeControlCommit?.(c);return outcome;
      });}catch(error){await projectAuthoritativeWorkspace(this.options.databases,b.workspaceId,a);return {error};}
      try{await this.options.hooks?.afterControlCommit?.();await projectAuthoritativeWorkspace(this.options.databases,b.workspaceId,a);return {view:{state:'completed' as const,receipt}};}
      catch{return {view:{state:'finishing' as const,receipt}};}
    },{enqueueActivationProjection:true});
    if('error'in result)throw result.error;await this.options.hooks?.afterCommit?.();return result.view;
  }
  async status(auth:UpgradeAuth,input:unknown):Promise<UpgradeView>{const ref=parse(upgradeStatusRequest,input);
    return this.#read(auth,ref.workspaceId,async(a,c,p)=>{
      if(ref.dataGeneration!==p.principal.dataGeneration)throw upgradeChanged();
      const receipt=await this.#receipt(c,'security',p,ref.migrationId,ref.operationId,ref.requestHash)??await this.#receipt(a,'app',p,ref.migrationId,ref.operationId,ref.requestHash);
      return {state:receipt?'completed':'absent',receipt};
    });
  }
}

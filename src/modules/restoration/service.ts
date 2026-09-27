import type pg from 'pg';
import { z } from 'zod';
import { transaction,type Databases } from '../../db.js';
import { tenantTransaction } from '../../persistence.js';
import { AppError } from '../../errors.js';
import { identifier } from '../../shared/contracts.js';
import { base64urlEncode,canonicalJson,digestObject } from '../../shared/crypto.js';
import { restoreCheckpointManifest,restoreStart,restoreReconciledManifest,restoreContext,restoreContextRequest,restoreStatusRequest,restoreVerification,restoreReference,
  restoreView,verifyRestoreOwner,verifyRestoreServiceObject,validateRestoreVerification,RESTORE_MAX_BYTES,type RestoreCheckpointManifest,type RestoreContext,type RestoreBinding,type RestoreView,
  type RestoreMissingRecord,type RestoreStart,type RestoreReconciledManifest } from '../../shared/restoration.js';
import { verifySecurityHistory,type SecurityHistoryInput } from '../../shared/security-history.js';
import { EntitlementOperations,type OperationalActor } from '../identity/entitlements.js';
import { withSecurityFence,projectAuthoritativeWorkspace } from '../identity/projection.js';
import type { SessionService,SessionPrincipal } from '../identity/sessions.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { finalizeDeletionIfDue } from '../lifecycle/deadline.js';
import { checkpointKeyObjects,readRestoreInventory,restoreSamples,signRestoreService } from './manifest.js';
import { assertRestoredActiveUpgrade } from './upgrades.js';
export interface RestoreAuth {cookieValue:string;csrfToken:string}
interface Options {databases:Databases;secrets:ServiceSecrets;sessions:SessionService;origin:string;now?:()=>Date;beforeWorkspace?:(workspaceId:string)=>Promise<void>;
  hooks?:{beforeControlCommit?:(control:pg.PoolClient)=>Promise<void>;beforeProjection?:()=>Promise<void>;afterControlCommit?:()=>Promise<void>;checkpointCaptured?:(manifest:RestoreCheckpointManifest)=>Promise<void>}}
interface RestoreRow extends pg.QueryResultRow {workspace_id:string;restore_id:string;state:'quarantined'|'verified'|'aborted';manifest_digest:string;
  checkpoint_manifest:RestoreCheckpointManifest;signed_start:RestoreStart;verification:unknown;reconciled_manifest:RestoreReconciledManifest|null;missing_records:RestoreMissingRecord[];request_digest:string}
const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
const changed=()=>new AppError('RESTORE_CHANGED','Reload the current restore verification context',409);
const incomplete=()=>new AppError('RESTORE_INCOMPLETE','Restored content or its trusted manifests are incomplete; workspace remains quarantined',409);
const forbidden=()=>new AppError('RESTORE_FORBIDDEN','A current recently authenticated Owner and approved device are required',403);
function parse<T>(schema:z.ZodType<T>,value:unknown):T{const result=schema.safeParse(value);if(!result.success)throw new AppError('INVALID_REQUEST','Invalid restoration request',400);return result.data;}
async function appTx<T>(a:pg.PoolClient,workspaceId:string,action:()=>Promise<T>):Promise<T>{await a.query('BEGIN');try{await a.query("SELECT set_config('ukda.workspace_id',$1,true),set_config('ukda.profile_id','',true)",[workspaceId]);const value=await action();await a.query('COMMIT');return value;}catch(error){await a.query('ROLLBACK');throw error;}}
export class RestorationService {
  readonly #now:()=>Date;readonly #trusted:Promise<Record<string,string>>;
  constructor(readonly options:Options){this.#now=options.now??(()=>new Date());if(new URL(options.origin).origin!==options.origin)throw new Error('Restore requires exact origin');
    this.#trusted=new EntitlementOperations(options.databases,options.secrets).publicSigningKey().then(key=>({[options.secrets.keyId]:key}));}
  async #precheck(workspaceId:string){await finalizeDeletionIfDue({databases:this.options.databases,secrets:this.options.secrets,workspaceId,now:this.#now()});await this.options.beforeWorkspace?.(workspaceId);}
  #live(w:pg.QueryResultRow|undefined){if(!w||!['active','pending_deletion'].includes(w.lifecycle)||w.lifecycle==='pending_deletion'&&w.delete_after&&new Date(w.delete_after)<=this.#now())throw new AppError('NOT_FOUND','Workspace unavailable',404);return w;}
  async #authority(c:pg.PoolClient,workspaceId:string){
    // Restore generation and quarantine decisions require synchronous security durability.
    await c.query("SET LOCAL synchronous_commit='on'");
    return this.#live((await c.query('SELECT * FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE',[workspaceId])).rows[0]);}
  async #history(c:pg.PoolClient,w:pg.QueryResultRow){
    const genesis=(await c.query('SELECT versioned_object,object_hash FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND state=\'committed\'',[w.workspace_id,w.genesis_object_id])).rows[0];
    if(!genesis||await digestObject(genesis.versioned_object)!==genesis.object_hash)throw incomplete();
    const transitions=(await c.query('SELECT signed_transition FROM security.security_transitions WHERE workspace_id=$1 AND sequence>1 ORDER BY sequence',[w.workspace_id])).rows.map(r=>r.signed_transition);
    const input:SecurityHistoryInput={workspaceId:w.workspace_id,origin:this.options.origin,genesisFingerprint:genesis.object_hash,genesis:genesis.versioned_object,transitions,
      expected:{securityHead:w.security_head,securityVersion:w.security_version},trustedServiceKeys:await this.#trusted};
    return {input,state:await verifySecurityHistory(input)};
  }
  async captureCheckpoint(input:{workspaceId:string;checkpointId:string},actor:OperationalActor){
    const request=parse(z.strictObject({workspaceId:identifier,checkpointId:identifier}),input);parse(z.strictObject({operatorId:identifier}),actor);
    await this.#precheck(request.workspaceId);
    return withSecurityFence(this.options.databases,request.workspaceId,async a=>{
      const result=await tenantTransaction(this.options.databases.control,request.workspaceId,undefined,async c=>{
        const w=await this.#authority(c,request.workspaceId);if(w.restore_quarantine)throw incomplete();await this.#history(c,w);
        const keyObjects=await checkpointKeyObjects(c,request.workspaceId),captured=await appTx(a,request.workspaceId,()=>readRestoreInventory(a,request.workspaceId,keyObjects));
        const manifest=restoreCheckpointManifest.parse(await signRestoreService<RestoreCheckpointManifest['body']>(this.options.secrets,{version:1,purpose:'ukda.content-checkpoint.v1',
          ...request,capturedAt:this.#now().toISOString(),source:{securityHead:w.security_head,securityVersion:w.security_version,dataGeneration:w.data_generation,writeSchema:w.write_schema},inventory:captured.inventory}));
        await this.options.hooks?.checkpointCaptured?.(manifest);
        const hash=await digestObject(manifest),previous=(await c.query('SELECT manifest FROM security.content_checkpoints WHERE workspace_id=$1 AND checkpoint_id=$2',[request.workspaceId,request.checkpointId])).rows[0];
        if(previous){if(!same(previous.manifest,manifest))throw changed();}else await c.query('INSERT INTO security.content_checkpoints(workspace_id,checkpoint_id,manifest_digest,manifest,created_at) VALUES($1,$2,$3,$4,$5)',[request.workspaceId,request.checkpointId,hash,manifest,this.#now()]);
        return {manifest,keyObjects};
      });
      await projectAuthoritativeWorkspace(this.options.databases,request.workspaceId,a);return result;
    });
  }
  /** Operational-only. Must finish before the isolated checkpoint is installed. */
  async begin(input:{workspaceId:string;restoreId:string;manifest:RestoreCheckpointManifest},actor:OperationalActor):Promise<RestoreView>{
    const request=parse(restoreReference.extend({manifest:restoreCheckpointManifest}),input);parse(z.strictObject({operatorId:identifier}),actor);
    await this.#precheck(request.workspaceId);await verifyRestoreServiceObject(request.manifest,await this.#trusted);
    if(request.manifest.body.workspaceId!==request.workspaceId)throw changed();
    const requestDigest=await digestObject({...request,operatorId:actor.operatorId}),manifestDigest=await digestObject(request.manifest);
    return withSecurityFence(this.options.databases,request.workspaceId,async a=>{
      const row=await tenantTransaction(this.options.databases.control,request.workspaceId,undefined,async c=>{
        const w=await this.#authority(c,request.workspaceId),previous=(await c.query<RestoreRow>('SELECT * FROM security.restorations WHERE workspace_id=$1 AND restore_id=$2',[request.workspaceId,request.restoreId])).rows[0];
        if(previous){if(previous.request_digest!==requestDigest||previous.signed_start.body.nextDataGeneration!==w.data_generation)throw changed();return previous;}
        const current=await this.#history(c,w),checkpoint=(await c.query('SELECT manifest_digest FROM security.content_checkpoints WHERE workspace_id=$1 AND checkpoint_id=$2',[request.workspaceId,request.manifest.body.checkpointId])).rows[0];
        if(!checkpoint||checkpoint.manifest_digest!==manifestDigest||BigInt(request.manifest.body.source.securityVersion)>BigInt(w.security_version))throw incomplete();
        const anchor=(await c.query('SELECT head FROM security.security_transitions WHERE workspace_id=$1 AND sequence=$2',[request.workspaceId,request.manifest.body.source.securityVersion])).rows[0];
        if(anchor?.head!==request.manifest.body.source.securityHead)throw incomplete();
        const version=String(BigInt(w.security_version)+1n),generation=String(BigInt(w.data_generation)+1n),now=this.#now();
        const start=restoreStart.parse(await signRestoreService<RestoreStart['body']>(this.options.secrets,{version:1,purpose:'ukda.restore-start.v1',workspaceId:request.workspaceId,restoreId:request.restoreId,
          operationId:request.restoreId,operatorId:actor.operatorId,supersedesRestoreId:current.state.activeRestore?.restoreId??null,previousHead:w.security_head,securityVersion:version,dataGeneration:w.data_generation,
          nextDataGeneration:generation,manifestDigest,checkpointId:request.manifest.body.checkpointId,changedAt:now.toISOString()})),head=await digestObject(start);
        if(w.active_restore_id)await c.query("UPDATE security.restorations SET state='aborted' WHERE workspace_id=$1 AND restore_id=$2 AND state='quarantined'",[request.workspaceId,w.active_restore_id]);
        await c.query("INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition,created_at) VALUES($1,$2,$3,$4,$5,'workspace.restore','service',$6,$7)",[request.workspaceId,version,request.restoreId,w.security_head,head,start,now]);
        await c.query('UPDATE security.workspaces SET security_head=$2,security_version=$3,data_generation=$4,restore_quarantine=true,active_restore_id=$5,updated_at=$6 WHERE workspace_id=$1',[request.workspaceId,head,version,generation,request.restoreId,now]);
        await c.query('UPDATE security.sessions SET revoked_at=$2 WHERE workspace_id=$1 AND revoked_at IS NULL',[request.workspaceId,now]);
        await c.query("UPDATE security.ceremonies SET state='expired',staged_registration_record=NULL,server_state_ciphertext=NULL WHERE workspace_id=$1 AND state IN('issued','waiting_approval')",[request.workspaceId]);
        await c.query("UPDATE security.auth_attempts SET state='consumed',outcome='failed',consumed_at=$2,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND state='issued'",[request.workspaceId,now]);
        // Retire every pending JOIN profile; it has no current usable account to preserve.
        await c.query("UPDATE security.profiles SET state='removed',removed_at=$2,reset_generation=reset_generation+1 WHERE workspace_id=$1 AND state='pending'",[request.workspaceId,now]);
        const saved=(await c.query<RestoreRow>("INSERT INTO security.restorations(workspace_id,restore_id,manifest_digest,checkpoint_manifest,request_digest,signed_start,state,created_at) VALUES($1,$2,$3,$4,$5,$6,'quarantined',$7) RETURNING *",[request.workspaceId,request.restoreId,manifestDigest,request.manifest,requestDigest,start,now])).rows[0]!;
        await this.options.hooks?.beforeControlCommit?.(c);return saved;
      });
      await appTx(a,request.workspaceId,async()=>{await a.query('UPDATE app.workspaces SET fence_closed=true,restore_quarantine=true WHERE workspace_id=$1',[request.workspaceId]);});
      await this.options.hooks?.afterControlCommit?.();return this.#view(row);
    });
  }
  #view(row:RestoreRow):RestoreView{return restoreView.parse({state:row.state==='verified'?'completed':row.state==='aborted'?'aborted':row.reconciled_manifest?'ready_for_verification':'quarantined',
    workspaceId:row.workspace_id,restoreId:row.restore_id,dataGeneration:row.signed_start.body.nextDataGeneration,manifestDigest:row.manifest_digest,missingRecords:row.missing_records??[],verification:row.verification??null});}
  async reconcile(input:{workspaceId:string;restoreId:string}):Promise<RestoreView>{
    const ref=parse(restoreReference,input);await this.#precheck(ref.workspaceId);
    return withSecurityFence(this.options.databases,ref.workspaceId,async a=>{
      const initial=await tenantTransaction(this.options.databases.control,ref.workspaceId,undefined,async c=>{
        const w=await this.#authority(c,ref.workspaceId),row=(await c.query<RestoreRow>('SELECT * FROM security.restorations WHERE workspace_id=$1 AND restore_id=$2 FOR UPDATE',[ref.workspaceId,ref.restoreId])).rows[0];
        if(!row||row.state!=='quarantined'||w.active_restore_id!==ref.restoreId||!w.restore_quarantine)throw changed();await this.#history(c,w);
        const keyObjects=await checkpointKeyObjects(c,ref.workspaceId);
        for(const key of row.checkpoint_manifest.body.inventory.keyObjects)if(!keyObjects.some(r=>r.id===key.id&&r.digest===key.digest&&r.kind===key.kind))throw incomplete();
        if(!row.reconciled_manifest){
          const loaded=await appTx(a,ref.workspaceId,()=>readRestoreInventory(a,ref.workspaceId,keyObjects));
          const expected=row.checkpoint_manifest.body.inventory;
          if(!same(loaded.inventory.tables,expected.tables)||!same(loaded.inventory.objects,expected.objects)||!same(loaded.inventory.projectIds,expected.projectIds))throw incomplete();
        }
        const projects=(await c.query('SELECT project_id FROM security.project_creations WHERE workspace_id=$1 ORDER BY project_id',[ref.workspaceId])).rows.map(r=>r.project_id as string),
          absent=projects.filter(id=>!row.checkpoint_manifest.body.inventory.projectIds.includes(id));
        const missing:RestoreMissingRecord[]=[...absent.map(id=>({kind:'project' as const,id,reason:'after_checkpoint' as const,knownRevision:null})),
          {kind:'content_after_checkpoint',id:null,reason:'after_checkpoint',knownRevision:null}];
        await appTx(a,ref.workspaceId,async()=>{
          for(const id of absent)await a.query("INSERT INTO app.unrecovered_projects(workspace_id,project_id,restore_id,reason) VALUES($1,$2,$3,'after_checkpoint') ON CONFLICT(workspace_id,project_id) DO UPDATE SET restore_id=EXCLUDED.restore_id",[ref.workspaceId,id,ref.restoreId]);
          await a.query('DELETE FROM app.unrecovered_projects WHERE workspace_id=$1 AND NOT(project_id=ANY($2::uuid[]))',[ref.workspaceId,absent]);
        });
        return {row,keyObjects,missing};
      });
      await this.options.hooks?.beforeProjection?.();await projectAuthoritativeWorkspace(this.options.databases,ref.workspaceId,a);
      return tenantTransaction(this.options.databases.control,ref.workspaceId,undefined,async c=>{
        const w=await this.#authority(c,ref.workspaceId);if(w.active_restore_id!==ref.restoreId||!w.restore_quarantine)throw changed();const {state}=await this.#history(c,w);
        const captured=await appTx(a,ref.workspaceId,async()=>{
          const content=await readRestoreInventory(a,ref.workspaceId,initial.keyObjects);
          // Completed upgrades require their exact retained native lineage. Never
          // declare schema-1 source rows ready under current schema-2 authority.
          if(w.active_upgrade_id){if(!w.content_maintenance||w.write_schema!==1||state.activeUpgrade?.migrationId!==w.active_upgrade_id)throw incomplete();
            await assertRestoredActiveUpgrade(a,c,state);}
          else if(content.inventory.objects.some(r=>r.current&&r.header.schema!==w.write_schema))throw incomplete();
          const completed=(await c.query("SELECT migration_id,signed_finish FROM security.encrypted_upgrades WHERE workspace_id=$1 AND state='completed'",[ref.workspaceId])).rows;
          for(const migration of completed){const retained=(await a.query("SELECT signed_finish,state FROM app.encrypted_upgrades WHERE workspace_id=$1 AND migration_id=$2",[ref.workspaceId,migration.migration_id])).rows[0];
            if(!retained||retained.state!=='completed'||!same(retained.signed_finish,migration.signed_finish))throw incomplete();}
          const jobs=(await a.query('SELECT key FROM graphile_worker.jobs WHERE key LIKE $1',[`notification:${ref.workspaceId}:%`])).rows;
          for(const job of jobs)await a.query('SELECT graphile_worker.remove_job($1)',[job.key]);
          await a.query('DELETE FROM app.outbox WHERE workspace_id=$1',[ref.workspaceId]);
          await a.query('DELETE FROM app.reporting_summaries WHERE workspace_id=$1',[ref.workspaceId]);await a.query('DELETE FROM app.summaries WHERE workspace_id=$1',[ref.workspaceId]);
          await a.query('DELETE FROM app.reporting_preparations WHERE workspace_id=$1',[ref.workspaceId]);return content;
        });
        const manifest=restoreReconciledManifest.parse(await signRestoreService<RestoreReconciledManifest['body']>(this.options.secrets,{version:1,purpose:'ukda.restore-manifest.v1',...ref,
          manifestDigest:initial.row.manifest_digest,source:{securityHead:w.security_head,securityVersion:w.security_version,dataGeneration:w.data_generation,writeSchema:w.write_schema},
          reconciledAt:this.#now().toISOString(),objects:captured.inventory.objects,samples:restoreSamples(captured.inventory.objects),keyEpochs:captured.inventory.keyEpochs,missingRecords:initial.missing}));
        const row=(await c.query<RestoreRow>('UPDATE security.restorations SET reconciled_manifest=$3,missing_records=$4 WHERE workspace_id=$1 AND restore_id=$2 RETURNING *',[ref.workspaceId,ref.restoreId,manifest,JSON.stringify(initial.missing)])).rows[0]!;
        await appTx(a,ref.workspaceId,async()=>{await a.query("INSERT INTO app.restorations(workspace_id,restore_id,manifest_digest,checkpoint_manifest,state,missing_records,reconciled_manifest,created_at) VALUES($1,$2,$3,$4,'quarantined',$5,$6,$7) ON CONFLICT(workspace_id,restore_id) DO UPDATE SET reconciled_manifest=EXCLUDED.reconciled_manifest,missing_records=EXCLUDED.missing_records",[ref.workspaceId,ref.restoreId,row.manifest_digest,row.checkpoint_manifest,JSON.stringify(initial.missing),manifest,this.#now()]);});
        return this.#view(row);
      });
    });
  }
  async #owner(c:pg.PoolClient,auth:RestoreAuth,workspaceId:string){const w=await this.#authority(c,workspaceId),p=await this.options.sessions.resolveCurrent(c,auth.cookieValue,{csrfToken:auth.csrfToken,approved:true,recent:true},this.#now());
    if(p.workspaceId!==workspaceId||!p.deviceId)throw forbidden();const h=await this.#history(c,w),profile=h.state.profiles[p.accountId],device=h.state.devices[p.deviceId];
    if(!profile?.active||!profile.owner||!device?.active||device.accountId!==p.accountId)throw forbidden();return {w,p,...h};}
  async #context(a:pg.PoolClient,c:pg.PoolClient,auth:RestoreAuth,ref:z.infer<typeof restoreContextRequest>,times?:Pick<RestoreBinding,'issuedAt'|'expiresAt'>):Promise<RestoreContext>{
    const {w,p,state,input:history}=await this.#owner(c,auth,ref.workspaceId),row=(await c.query<RestoreRow>('SELECT * FROM security.restorations WHERE workspace_id=$1 AND restore_id=$2',[ref.workspaceId,ref.restoreId])).rows[0];
    if(!row||row.state!=='quarantined'||w.active_restore_id!==ref.restoreId||!w.restore_quarantine||!row.reconciled_manifest)throw changed();
    const d=state.devices[p.deviceId!]!,now=this.#now(),binding:RestoreBinding={version:1,...ref,origin:this.options.origin,accountId:p.accountId,deviceId:d.id,
      credentialGeneration:p.credentialGeneration,sessionGeneration:p.sessionGeneration,keyGeneration:d.keyGeneration,signingPublicKey:d.signingPublicKey,
      securityHead:w.security_head,securityVersion:w.security_version,nextSecurityVersion:String(BigInt(w.security_version)+1n),dataGeneration:w.data_generation,custodyEpoch:w.custody_epoch,
      manifestDigest:row.manifest_digest,reconciledDigest:await digestObject(row.reconciled_manifest),issuedAt:times?.issuedAt??now.toISOString(),expiresAt:times?.expiresAt??new Date(now.getTime()+600000).toISOString()};
    verifyRestoreOwner(binding,state);
    for(const projectId of new Set(row.reconciled_manifest.body.keyEpochs.filter(k=>k.scope==='project').map(k=>k.scopeId)))for(const scopes of [state.profiles[p.accountId]!.scopes,d.scopes])
      if(!scopes.some(s=>s.scope==='project'&&s.scopeId===projectId&&s.mode==='content'&&s.keyEpoch===state.scopeHeads[`project:${projectId}`]?.keyEpoch&&s.permissions.includes('read_project')&&(s.expiresAt===null||Date.parse(s.expiresAt)>now.getTime())))throw forbidden();
    if(row.reconciled_manifest.body.source.dataGeneration!==w.data_generation||row.reconciled_manifest.body.source.writeSchema!==w.write_schema)throw changed();
    const allKeys=await checkpointKeyObjects(c,ref.workspaceId),ids=new Set([state.custodyManifest.id,...d.scopes.flatMap(s=>s.manifests.map(m=>m.id))]);
    if(d.id===history.genesis.body.device.id)ids.add(history.genesis.body.deviceEnvelopeId);
    const materials=allKeys.filter(key=>ids.has(key.id)),loaded=await appTx(a,ref.workspaceId,()=>readRestoreInventory(a,ref.workspaceId));
    const samples=row.reconciled_manifest.body.samples.map(hash=>{const envelope=loaded.envelopes.get(hash);if(!envelope)throw incomplete();return envelope;});
    const result=restoreContext.parse({binding,checkpoint:row.checkpoint_manifest,reconciled:row.reconciled_manifest,samples,materials});
    if(Buffer.byteLength(canonicalJson(result))>RESTORE_MAX_BYTES)throw new AppError('RESTORE_TOO_LARGE','Restore verification exceeds this release limit',413);return result;
  }
  async #preflight(auth:RestoreAuth,ref:{workspaceId:string;restoreId:string},verification?:unknown){
    await tenantTransaction(this.options.databases.control,ref.workspaceId,undefined,async c=>{const {w}=await this.#owner(c,auth,ref.workspaceId),row=(await c.query<RestoreRow>('SELECT * FROM security.restorations WHERE workspace_id=$1 AND restore_id=$2',[ref.workspaceId,ref.restoreId])).rows[0];
      if(!row||row.signed_start.body.nextDataGeneration!==w.data_generation)throw changed();
      if(row.state==='verified'){if(!verification||!same(verification,row.verification))throw changed();}
      else if(row.state!=='quarantined'||!w.restore_quarantine||w.active_restore_id!==ref.restoreId)throw changed();});
  }
  async context(auth:RestoreAuth,input:unknown):Promise<RestoreContext>{const ref=parse(restoreContextRequest,input);await this.#precheck(ref.workspaceId);await this.#preflight(auth,ref);
    return withSecurityFence(this.options.databases,ref.workspaceId,a=>tenantTransaction(this.options.databases.control,ref.workspaceId,undefined,c=>this.#context(a,c,auth,ref)));}
  async verify(auth:RestoreAuth,input:unknown):Promise<RestoreView>{const payload=parse(restoreVerification,input),b=payload.body.binding;await this.#precheck(b.workspaceId);await this.#preflight(auth,b,payload);
    return withSecurityFence(this.options.databases,b.workspaceId,async a=>{
      const result=await tenantTransaction(this.options.databases.control,b.workspaceId,undefined,async c=>{
        const {w,state}=await this.#owner(c,auth,b.workspaceId),row=(await c.query<RestoreRow>('SELECT * FROM security.restorations WHERE workspace_id=$1 AND restore_id=$2 FOR UPDATE',[b.workspaceId,b.restoreId])).rows[0];
        if(row?.state==='verified'){if(!same(row.verification,payload)||b.dataGeneration!==w.data_generation)throw changed();return row;}
        const context=await this.#context(a,c,auth,{workspaceId:b.workspaceId,restoreId:b.restoreId,operationId:b.operationId},{issuedAt:b.issuedAt,expiresAt:b.expiresAt});
        if(Date.parse(b.expiresAt)<=this.#now().getTime()||Date.parse(b.issuedAt)>this.#now().getTime()+30000)throw changed();await validateRestoreVerification(payload,context,state);
        if(w.active_upgrade_id)await appTx(a,b.workspaceId,async()=>{
          await readRestoreInventory(a,b.workspaceId);await assertRestoredActiveUpgrade(a,c,state);
        });
        const head=await digestObject(payload),now=this.#now();
        await c.query("INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition,created_at) VALUES($1,$2,$3,$4,$5,'workspace.restore_verified','device',$6,$7,$8,$9)",[b.workspaceId,b.nextSecurityVersion,b.operationId,b.securityHead,head,b.accountId,b.deviceId,payload,now]);
        await c.query('UPDATE security.workspaces SET restore_quarantine=false,active_restore_id=NULL,security_head=$2,security_version=$3,updated_at=$4 WHERE workspace_id=$1',[b.workspaceId,head,b.nextSecurityVersion,now]);
        const saved=(await c.query<RestoreRow>("UPDATE security.restorations SET state='verified',verification=$3,verified_at=$4 WHERE workspace_id=$1 AND restore_id=$2 RETURNING *",[b.workspaceId,b.restoreId,payload,now])).rows[0]!;
        // The current Owner acknowledged the exact restored source/progress.
        // Rebind only the mutable ledger; old requests and receipts keep their
        // original generation and cannot become current requests by replay.
        if(w.active_upgrade_id){const rebound=await c.query("UPDATE security.encrypted_upgrades SET data_generation=$3 WHERE workspace_id=$1 AND migration_id=$2 AND state='active'",[b.workspaceId,w.active_upgrade_id,b.dataGeneration]);
          if(rebound.rowCount!==1)throw incomplete();}
        await this.options.hooks?.beforeControlCommit?.(c);return saved;
      });
      await this.options.hooks?.afterControlCommit?.();await this.options.hooks?.beforeProjection?.();await projectAuthoritativeWorkspace(this.options.databases,b.workspaceId,a);
      await appTx(a,b.workspaceId,async()=>{await a.query("UPDATE app.restorations SET state='verified',verified_at=$3 WHERE workspace_id=$1 AND restore_id=$2",[b.workspaceId,b.restoreId,this.#now()]);});return this.#view(result);
    });
  }
  async status(auth:RestoreAuth,input:unknown):Promise<RestoreView>{const ref=parse(restoreStatusRequest,input);await this.#precheck(ref.workspaceId);
    const row=await tenantTransaction(this.options.databases.control,ref.workspaceId,undefined,async c=>{const {w}=await this.#owner(c,auth,ref.workspaceId),r=(await c.query<RestoreRow>('SELECT * FROM security.restorations WHERE workspace_id=$1 AND restore_id=$2',[ref.workspaceId,ref.restoreId])).rows[0];
      if(!r||r.signed_start.body.nextDataGeneration!==w.data_generation)throw changed();if(ref.operationId&&r.verification&&(restoreVerification.parse(r.verification).body.binding.operationId!==ref.operationId||ref.requestHash&&await digestObject(r.verification)!==ref.requestHash))throw changed();return r;});
    if(row.state==='verified')await projectAuthoritativeWorkspace(this.options.databases,ref.workspaceId);return this.#view(row);
  }
}

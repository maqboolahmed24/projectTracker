import { randomUUID } from 'node:crypto';
import type { TestContext } from 'node:test';
import { transaction } from '../src/db.js';
import { UpgradeService,type UpgradeAuth } from '../src/modules/upgrades/service.js';
import { TeamService } from '../src/modules/work/teams.js';
import { prepareUpgradeStart,prepareIdentityUpgrade,prepareUpgradeFinish,type UpgradeNativeProof } from '../src/client/encrypted-upgrades-crypto.js';
import { preparePlanning } from '../src/client/planning-crypto.js';
import { prepareTeamUpgrade } from '../src/client/teams-crypto.js';
import { prepareCollaborationUpgrade } from '../src/client/collaboration-crypto.js';
import type { DeviceBundle } from '../src/client/device-store.js';
import type { UpgradeContext,UpgradeBatch } from '../src/shared/upgrade-api.js';
import { collaborationFixture } from './collaboration-fixture.js';
import { origin } from './password-change-fixture.js';

export async function encryptedUpgradesFixture(t:TestContext){
  let f:Awaited<ReturnType<typeof collaborationFixture>>;
  t.after(async()=>{if(f){
    await transaction(f.admin.application,async c=>{
      await c.query("SET LOCAL session_replication_role='replica'");
      for(const table of ['encrypted_upgrade_items','encrypted_upgrade_operations','encrypted_upgrade_sources','encrypted_upgrades','team_members','teams'])
        await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`,[f.workspaceId]);
    });
    await f.admin.control.query('DELETE FROM security.encrypted_upgrade_operations WHERE workspace_id=$1',[f.workspaceId]);
    await f.admin.control.query('DELETE FROM security.encrypted_upgrades WHERE workspace_id=$1',[f.workspaceId]);
  }});
  f=await collaborationFixture(t);
  const teams=new TeamService(f);
  let hooks:NonNullable<ConstructorParameters<typeof UpgradeService>[0]['hooks']>={};
  const make=()=>new UpgradeService({...f,origin,hooks,handlers:{planning:(a,p)=>f.planning.save(a.cookieValue,a.csrfToken,p),
    team:(a,p)=>teams.save(a,p),collaboration:(a,p)=>f.collaboration.save(a.cookieValue,a.csrfToken,p)}});
  let service=make();
  async function context(migrationId?:string,auth:UpgradeAuth=f.auth()){
    const operationId=randomUUID(),first=await service.context(auth,{workspaceId:f.workspaceId,operationId,...(migrationId?{migrationId}:{})}),records=[...first.records];
    let cursor=first.nextCursor;
    while(cursor){const page=await service.context(auth,{workspaceId:f.workspaceId,operationId,migrationId:first.binding.migrationId,after:cursor});records.push(...page.records);cursor=page.nextCursor;}
    return {context:first,records};
  }
  async function input(migrationId?:string,auth=f.auth(),bundle=f.originalBundle){
    const pages=await context(migrationId,auth),refreshed=await f.refresh(auth,bundle);
    return {...pages,history:refreshed.history,materials:refreshed.delivery.materials,
      accountId:pages.context.binding.accountId,deviceId:pages.context.binding.deviceId};
  }
  async function start(auth=f.auth(),bundle=f.originalBundle){
    const current=await input(undefined,auth,bundle),payload=await prepareUpgradeStart(current,bundle);
    return {payload,view:await service.start(auth,payload),migrationId:payload.body.binding.migrationId};
  }
  async function prepareBatch(migrationId:string,kind:UpgradeBatch['kind'],id?:string,auth=f.auth(),bundle:DeviceBundle=f.originalBundle):Promise<UpgradeBatch>{
    const current=await input(migrationId,auth,bundle),upgrade={migrationId,manifestDigest:current.context.binding.manifestDigest};
    let payload:unknown;
    if(kind==='identity')payload=await prepareIdentityUpgrade({...current,records:current.records.filter(r=>['workspace','profile','role'].includes(r.reference.kind)&&r.reference.schema===1).slice(0,32)},bundle);
    else if(kind==='planning'){
      const projectId=id??f.projectId,planning=await f.context(projectId,auth);
      payload=await preparePlanning({context:planning,history:current.history,accountId:current.accountId,deviceId:current.deviceId,
        command:{action:'upgrade_content',records:planning.records.filter(r=>r.envelope.header.schema===1).map(({kind,id})=>({kind,id}))},upgrade},bundle);
    }else if(kind==='team'){
      const team=await teams.context(auth,{workspaceId:f.workspaceId,teamId:id!,operationId:randomUUID(),action:'upgrade_content'});
      payload=await prepareTeamUpgrade({...current,...upgrade,context:team},bundle);
    }else{
      const record=current.records.find(r=>r.reference.id===id&&(r.reference.kind==='comment'||r.reference.kind==='update'))!;
      const entry=await f.collaboration.context(auth.cookieValue,auth.csrfToken,{workspaceId:f.workspaceId,projectId:record.reference.projectId!,operationId:randomUUID(),entryId:id!,kind:record.reference.kind});
      payload=await prepareCollaborationUpgrade({...current,...upgrade,context:entry},bundle);
    }
    return {workspaceId:f.workspaceId,migrationId,kind,payload};
  }
  async function finish(migrationId:string,auth=f.auth(),bundle=f.originalBundle){
    const current=await input(migrationId,auth,bundle),proofs:UpgradeNativeProof[]=[];
    for(const projectId of [...new Set(current.records.flatMap(r=>r.reference.projectId?[r.reference.projectId]:[]))])proofs.push({kind:'planning',context:await f.context(projectId,auth)});
    for(const record of current.records){const ref=record.reference;
      if(ref.kind==='team')proofs.push({kind:'team',context:await teams.context(auth,{workspaceId:f.workspaceId,teamId:ref.id,operationId:randomUUID(),action:'upgrade_content'})});
      if(ref.kind==='comment'||ref.kind==='update')proofs.push({kind:'collaboration',context:await f.collaboration.context(auth.cookieValue,auth.csrfToken,{workspaceId:f.workspaceId,projectId:ref.projectId!,operationId:randomUUID(),entryId:ref.id,kind:ref.kind})});
    }
    const payload=await prepareUpgradeFinish({...current,proofs},bundle);
    return {payload,view:await service.finish(auth,payload)};
  }
  async function allBatches(migrationId:string,auth=f.auth(),bundle=f.originalBundle){
    const rows=(await input(migrationId,auth,bundle)).records;
    for(const projectId of [...new Set(rows.flatMap(r=>['project','phase','milestone','task','blocker'].includes(r.reference.kind)?[r.reference.projectId!]:[]))]){
      if(rows.some(r=>r.reference.projectId===projectId&&['project','phase','milestone','task','blocker'].includes(r.reference.kind)&&r.reference.schema===1))await service.batch(auth,await prepareBatch(migrationId,'planning',projectId,auth,bundle));
    }
    for(const row of rows){const ref=row.reference;if(ref.schema!==1)continue;
      if(ref.kind==='team')await service.batch(auth,await prepareBatch(migrationId,'team',ref.id,auth,bundle));
      if(ref.kind==='comment'||ref.kind==='update')await service.batch(auth,await prepareBatch(migrationId,'collaboration',ref.id,auth,bundle));
    }
    if(rows.some(r=>['workspace','profile','role'].includes(r.reference.kind)&&r.reference.schema===1))await service.batch(auth,await prepareBatch(migrationId,'identity',undefined,auth,bundle));
  }
  return {...f,teams,upgradeContext:context,upgradeInput:input,startUpgrade:start,prepareUpgradeBatch:prepareBatch,finishUpgrade:finish,allUpgradeBatches:allBatches,
    get upgrades(){return service;},get planning(){return f.planning;},setUpgradeHooks(value:typeof hooks={}){hooks=value;service=make();}};
}

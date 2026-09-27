import { randomUUID } from 'node:crypto';
import type { TestContext } from 'node:test';
import { transaction } from '../src/db.js';
import { LifecycleService } from '../src/modules/lifecycle/service.js';
import { prepareLifecycle } from '../src/client/lifecycle-crypto.js';
import type { LifecycleBinding } from '../src/shared/lifecycle.js';
import { encryptedUpgradesFixture } from './encrypted-upgrades-fixture.js';
import { origin } from './password-change-fixture.js';
export async function lifecycleFixture(t:TestContext){
 let f:Awaited<ReturnType<typeof encryptedUpgradesFixture>>;
 t.after(async()=>{if(!f)return;
  for(const [pool,schema,tables] of [[f.admin.application,'app',['export_sessions','unrecovered_projects','restorations','lifecycle_tombstones']],
   [f.admin.control,'security',['content_checkpoints','restorations','erasure_requests','workspace_purges','retired_security_links','deletion_tombstones']]] as const)
   await transaction(pool,async c=>{await c.query("SET LOCAL session_replication_role='replica'");for(const table of tables)await c.query(`DELETE FROM ${schema}.${table} WHERE workspace_id=$1`,[f.workspaceId]);});
 });
 f=await encryptedUpgradesFixture(t);
 let hooks:NonNullable<ConstructorParameters<typeof LifecycleService>[0]['hooks']>={};
 const make=()=>new LifecycleService({...f,origin,hooks});let lifecycle=make();
 async function prepare(action:LifecycleBinding['action'],auth=f.auth(),bundle=f.originalBundle){
  const context=await lifecycle.context(auth,{workspaceId:f.workspaceId,operationId:randomUUID(),action}),current=await f.refresh(auth,bundle);
  return prepareLifecycle({context,history:current.history,materials:current.delivery.materials,accountId:context.binding.accountId,deviceId:context.binding.deviceId,
   ...(action==='request_deletion'?{confirmationName:'Password fixture workspace'}:{})},bundle);
 }
 return {...f,get lifecycle(){return lifecycle;},prepareLifecycle:prepare,setLifecycleHooks(value:typeof hooks={}){hooks=value;lifecycle=make();}};
}

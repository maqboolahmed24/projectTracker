import { randomUUID } from 'node:crypto';
import type { TestContext } from 'node:test';
import { transaction } from '../src/db.js';
import { ExportService, type ExportAuth } from '../src/modules/export/service.js';
import { prepareExport } from '../src/client/export-crypto.js';
import type { ExportPage } from '../src/shared/export.js';
import { collaborationFixture } from './collaboration-fixture.js';
import { origin } from './password-change-fixture.js';

export async function exportFixture(t:TestContext) {
  let f:Awaited<ReturnType<typeof collaborationFixture>>;
  t.after(async()=>{if(f)await transaction(f.admin.application,async c=>{await c.query("SET LOCAL session_replication_role='replica'");
    for(const table of ['export_sessions','team_members','teams'])await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`,[f.workspaceId]);});});
  f=await collaborationFixture(t);let hooks:NonNullable<ConstructorParameters<typeof ExportService>[0]['hooks']>={};
  const make=()=>new ExportService({...f,origin,planning:f.planning,collaboration:f.collaboration,hooks});let service=make();
  async function input(auth:ExportAuth=f.auth()) {
    const start=await service.start(auth,{workspaceId:f.workspaceId,exportId:randomUUID(),acknowledgePlaintext:true}),pages:ExportPage[]=[];let after:string|null=null;
    for(let n=0;n<start.sources.length;n++){const page=await service.page(auth,{workspaceId:f.workspaceId,exportId:start.binding.exportId,manifestDigest:start.binding.manifestDigest,after});pages.push(page);after=page.nextCursor;}
    if(after!==null)throw new Error('Incomplete fixture export');
    const principal=await f.sessions.authenticate(auth.cookieValue,{csrfToken:auth.csrfToken,approved:true}),delivery=await f.access.currentDelivery(auth.cookieValue,auth.csrfToken,{workspaceId:f.workspaceId});
    return {start,pages,history:await f.history(),materials:delivery.materials,accountId:principal.accountId,deviceId:principal.deviceId!,acknowledgePlaintext:true as const};
  }
  return {...f,get exports(){return service;},exportInput:input,
    exportDraft:async(auth=f.auth(),bundle=f.originalBundle)=>prepareExport(await input(auth),bundle),setExportHooks(value:typeof hooks={}){hooks=value;service=make();}};
}

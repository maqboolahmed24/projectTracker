import { randomUUID } from 'node:crypto';
import type { TestContext } from 'node:test';
import { transaction } from '../src/db.js';
import { CollaborationService } from '../src/modules/collaboration/service.js';
import { prepareCollaboration, readCollaboration } from '../src/client/collaboration-crypto.js';
import type { CollaborationCommand, CollaborationPayload } from '../src/shared/collaboration.js';
import { digestObject } from '../src/shared/crypto.js';
import { planningFixture } from './planning-fixture.js';
import { origin } from './password-change-fixture.js';

export async function collaborationFixture(t: TestContext) {
  let f: Awaited<ReturnType<typeof planningFixture>>;
  t.after(async () => { if (f) await transaction(f.admin.application,async (application) => {
    await application.query("SET LOCAL session_replication_role='replica'");
    await application.query('DELETE FROM app.collaboration_operations WHERE workspace_id=$1',[f.workspaceId]);
  }); });
  f = await planningFixture(t);
  let hooks: NonNullable<ConstructorParameters<typeof CollaborationService>[0]['hooks']> = {};
  const make = () => new CollaborationService({ ...f,origin,planning:f.planning,hooks }); let service = make();
  const ref = (kind:'comment'|'update',entryId:string=randomUUID(),operationId:string=randomUUID(),projectId:string=f.projectId) => ({ workspaceId:f.workspaceId,projectId,operationId,kind,entryId });
  const context = (value:ReturnType<typeof ref>,auth=f.auth()) => service.context(auth.cookieValue,auth.csrfToken,value);
  async function prepare(command:CollaborationCommand,options:{text?:string;reason?:string;projectId?:string}={},auth=f.auth(),bundle=f.originalBundle) {
    const current = await context(ref(command.action.endsWith('_comment')?'comment':'update',command.entryId,randomUUID(),options.projectId),auth);
    return prepareCollaboration({ context:current,history:await f.history(),accountId:current.binding.accountId,deviceId:current.binding.deviceId,command,
      ...(options.text!==undefined?{text:options.text}:{}),...(options.reason!==undefined?{reason:options.reason}:{}) },bundle);
  }
  const save = (payload:CollaborationPayload,auth=f.auth()) => service.save(auth.cookieValue,auth.csrfToken,payload);
  async function status(payload:CollaborationPayload,auth=f.auth()) { const b=payload.mutation.body.binding; return service.status(auth.cookieValue,auth.csrfToken,
    {workspaceId:b.workspaceId,projectId:b.projectId,operationId:b.operationId,dataGeneration:b.dataGeneration,requestHash:await digestObject(payload)}); }
  const list = (kind:'comment'|'update',options:{taskId?:string;phaseId?:string;limit?:number;anchor?:string;after?:string}={},auth=f.auth()) => service.list(auth.cookieValue,auth.csrfToken,
    {workspaceId:f.workspaceId,projectId:f.projectId,kind,...options});
  async function read(kind:'comment'|'update',auth=f.auth(),bundle=f.originalBundle) {
    const page=await list(kind,{},auth); return readCollaboration({context:page.planning,entries:page.entries,history:await f.history(),
      accountId:page.planning.binding.accountId,deviceId:page.planning.binding.deviceId},bundle);
  }
  async function createTask() { const taskId=randomUUID(); await f.execute({action:'create_task',task:{id:taskId,phaseId:null,milestoneId:null,assigneeIds:[f.accountId],leadProfileId:f.accountId}},
    {content:{title:'Private discussion task'}});return taskId; }
  return { ...f,ref,collaborationContext:context,prepareCollaboration:prepare,saveCollaboration:save,collaborationStatus:status,listCollaboration:list,readCollaboration:read,createTask,
    get planning(){return f.planning;},get collaboration(){return service;},setCollaborationHooks(value:typeof hooks={}){hooks=value;service=make();} };
}

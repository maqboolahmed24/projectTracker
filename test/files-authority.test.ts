import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {fileServiceFixture} from './files-fixture.js';
import {origin} from './password-change-fixture.js';
import {AppError} from '../src/errors.js';
import {RoleService} from '../src/modules/identity/roles.js';
import {prepareRoleChange} from '../src/client/roles-controller.js';
import {digestObject} from '../src/shared/crypto.js';

test('File downloads preserve legacy role limits and require an explicit signed capability; removal takes effect immediately',async t=>{
 const f=await fileServiceFixture(t),source=await f.upload(await f.prepared('source',{size:100})),member=await f.joined(),owner=f.auth(),roles=new RoleService({...f,origin}),roleId=randomUUID();
 const memberRole=(await f.admin.control.query("SELECT role_id FROM security.roles WHERE workspace_id=$1 AND template='member'",[f.workspaceId])).rows[0].role_id;
 await f.finalize(await f.draft('set_access',member.binding.accountId,{roleId:memberRole,projectIds:[f.projectId]}));let logged=await f.login(member.prepared,member.registered.exportKey);
 const chunk=()=>f.files.readChunk(logged.auth.cookieValue,logged.auth.csrfToken,{...f.reference(),versionId:source.manifest.body.versionId,index:0,purpose:'download'});
 assert.equal((await f.context(f.projectId,logged.auth)).binding.permissions.includes('download_files'),false);
 await assert.rejects(chunk(),e=>e instanceof AppError&&e.code==='FILES_FORBIDDEN');
 assert.equal((await f.files.readChunk(logged.auth.cookieValue,logged.auth.csrfToken,{...f.reference(),versionId:source.manifest.body.versionId,index:0,purpose:'preview'})).bytes,source.chunks[0]);
 async function role(action:'create'|'update',permissions:('read_project'|'download_files')[]){const request={workspaceId:f.workspaceId,operationId:randomUUID(),roleId,action},context=await roles.context(owner.cookieValue,owner.csrfToken,request),payload=await prepareRoleChange({request,context,history:await f.history(),displayName:'Document reader',permissions},f.originalBundle);
  assert.equal(payload.transition.body.role.permissionCatalogue,permissions.includes('download_files')?2:undefined);
 await roles.stage(owner.cookieValue,owner.csrfToken,payload);assert.equal((await roles.finalize(owner.cookieValue,owner.csrfToken,{workspaceId:f.workspaceId,operationId:request.operationId,requestHash:await digestObject(payload)})).state,'completed');}
 await role('create',['read_project','download_files']);await f.finalize(await f.draft('set_access',member.binding.accountId,{roleId,projectIds:[f.projectId]}));logged=await f.login(member.prepared,member.registered.exportKey);
 assert.equal((await chunk()).bytes,source.chunks[0]);await role('update',['read_project']);
 // Definitions keep assigned snapshots stable; applying the updated role removes access.
 assert.equal((await chunk()).bytes,source.chunks[0]);await f.finalize(await f.draft('set_access',member.binding.accountId,{roleId,projectIds:[f.projectId]}));
 await assert.rejects(chunk());logged=await f.login(member.prepared,member.registered.exportKey);await assert.rejects(chunk(),e=>e instanceof AppError&&e.code==='FILES_FORBIDDEN');
 assert.equal((await f.files.readChunk(owner.cookieValue,owner.csrfToken,{...f.reference(),versionId:source.manifest.body.versionId,index:0,purpose:'download'})).bytes,source.chunks[0]);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { RoleService } from '../src/modules/identity/roles.js';
import { prepareRoleChange } from '../src/client/roles-controller.js';
import { prepareJoinInvitation } from '../src/client/enrolment-controller.js';
import { encryptedUpgradesFixture } from './encrypted-upgrades-fixture.js';
import { origin } from './password-change-fixture.js';

test('CP11 invitations: a pending custom-role member completes after representation upgrades; genuine role edits remain different intent',async t=>{
  const f=await encryptedUpgradesFixture(t),roles=new RoleService({...f,origin}),roleId=randomUUID(),auth=f.auth();
  async function changeRole(action:'create'|'update',permissions:('read_project'|'comment')[]) {
    const request={workspaceId:f.workspaceId,operationId:randomUUID(),roleId,action},context=await roles.context(auth.cookieValue,auth.csrfToken,request),
      payload=await prepareRoleChange({request,context,history:await f.history(),displayName:'Private invitation role',permissions},f.originalBundle),
      staged=await roles.stage(auth.cookieValue,auth.csrfToken,payload);
    return roles.finalize(auth.cookieValue,auth.csrfToken,{workspaceId:f.workspaceId,operationId:request.operationId,requestHash:staged.requestHash!});
  }
  await changeRole('create',['read_project']);
  async function invite() {
    const request={workspaceId:f.workspaceId,accountId:randomUUID(),operationId:randomUUID(),kind:'join_member' as const,roleId,projectIds:[]},
      context=await f.enrolment.issuanceContext(auth.cookieValue,auth.csrfToken,request),
      payload=await prepareJoinInvitation({request,context,history:await f.history(),displayName:'Private pending custom-role person'},f.originalBundle);
    return {request,issued:await f.enrolment.issueJoin(auth.cookieValue,auth.csrfToken,payload)};
  }
  const accepted=await invite(),changed=await invite(),start=await f.startUpgrade();
  await f.allUpgradeBatches(start.migrationId);await f.finishUpgrade(start.migrationId);
  const current=(await f.refresh()).history;
  assert.ok(current.transitions.some(value=>JSON.stringify(value).includes('ukda.identity-content-upgrade.v1')));
  const begun=await f.begin(accepted.issued),prepared=await f.prepare(begun.ref,begun.binding);
  assert.equal(begun.binding.role.id,roleId);assert.equal(begun.binding.role.revision,'2');assert.equal(begun.binding.profile.revision,'2');
  const staged=await f.approve(begun.ref,prepared.prepared,prepared.registered.exportKey),
    finalized=await f.enrolment.finalize({...staged.publicRef,requestHash:staged.requestHash},auth);
  assert.equal(finalized.state,'completed');
  const joined=await f.login(prepared.prepared,prepared.registered.exportKey);
  assert.equal(joined.session.accountId,accepted.request.accountId);
  assert.equal((await f.admin.control.query('SELECT role_revision FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2',[f.workspaceId,accepted.request.accountId])).rows[0].role_revision,'2');
  // Restoring the same capability list does not erase real intervening role edits.
  await changeRole('update',['read_project','comment']);await changeRole('update',['read_project']);
  const denied=await f.begin(changed.issued),deniedDraft=await f.prepare(denied.ref,denied.binding);
  assert.equal(denied.binding.role.revision,'4');assert.deepEqual(denied.binding.role.permissions,['read_project']);
  await assert.rejects(f.approve(denied.ref,deniedDraft.prepared,deniedDraft.registered.exportKey),/INVALID_ENROLMENT/);
  assert.equal((await f.admin.control.query('SELECT state FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2',[f.workspaceId,changed.request.accountId])).rows[0].state,'pending');
});

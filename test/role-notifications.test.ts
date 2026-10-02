import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { prepareRoleChange } from '../src/client/roles-controller.js';
import { RoleService } from '../src/modules/identity/roles.js';
import { projectAuthoritativeWorkspace } from '../src/modules/identity/projection.js';
import { digestObject } from '../src/shared/crypto.js';
import type { Capability } from '../src/shared/permissions.js';
import { accessChangeFixture } from './access-change-fixture.js';
import { origin } from './password-change-fixture.js';

test('CP09: real role permission changes notify active affected people and every Owner once; label-only changes stay quiet', async t => {
  const f = await accessChangeFixture(t), roles = new RoleService({ ...f, origin }), roleId = randomUUID();
  async function change(action: 'create' | 'update', permissions: Capability[], displayName: string) {
    const request = { workspaceId: f.workspaceId, operationId: randomUUID(), roleId, action }, auth = f.auth(),
      context = await roles.context(auth.cookieValue, auth.csrfToken, request),
      payload = await prepareRoleChange({ request, context, history: await f.history(), permissions, displayName }, f.originalBundle);
    await roles.stage(auth.cookieValue, auth.csrfToken, payload);
    const final = { workspaceId: f.workspaceId, operationId: request.operationId, requestHash: await digestObject(payload) },
      completed = await roles.finalize(auth.cookieValue, auth.csrfToken, final);
    assert.equal(completed.state, 'completed');
    return { request, payload, final, completed };
  }
  const created = await change('create', ['read_project', 'comment'], 'Private original coordination role'),
    secondOwner = await f.joined('join_owner'), affected = await f.joined(), unrelated = await f.joined(), suspended = await f.joined();
  for (const person of [affected, suspended]) {
    assert.equal((await f.finalize(await f.draft('set_access', person.binding.accountId, { roleId, projectIds: [] }))).state, 'completed');
  }
  assert.equal((await f.finalize(await f.draft('suspend', suspended.binding.accountId))).state, 'completed');
  const permissions: Capability[] = ['read_project', 'comment', 'create_tasks'],
    updated = await change('update', permissions, 'Private updated coordination role');
  const rows = () => f.admin.application.query(`SELECT id,recipient_profile_id,event_id,event_type,record_id,project_id,encrypted_envelope
    FROM app.notifications WHERE workspace_id=$1 AND event_id=$2 ORDER BY recipient_profile_id`, [f.workspaceId, updated.request.operationId]);
  const initial = (await rows()).rows, expected = [f.accountId, secondOwner.binding.accountId, affected.binding.accountId].sort();
  assert.deepEqual(initial.map(row => row.recipient_profile_id), expected);
  assert.ok(initial.every(row => row.event_type === 'security.role_changed' && row.event_id === updated.request.operationId && row.record_id === roleId && row.project_id === null));
  assert.ok(initial.every(row => JSON.stringify(row.encrypted_envelope) === '{}'));
  assert.equal(initial.some(row => row.recipient_profile_id === unrelated.binding.accountId || row.recipient_profile_id === suspended.binding.accountId), false);
  const serialized = JSON.stringify(initial);
  for (const privateValue of ['Private original coordination role', 'Private updated coordination role', f.originalBundle.signingPrivateKey, f.originalBundle.recipientPrivateKey])
    assert.equal(serialized.includes(privateValue), false);
  const receipts = (await f.admin.application.query(`SELECT id,recipient_profile_id,event_id FROM app.notification_receipts
    WHERE workspace_id=$1 AND event_id=$2 ORDER BY recipient_profile_id`, [f.workspaceId, updated.request.operationId])).rows;
  assert.deepEqual(receipts, initial.map(({ id, recipient_profile_id, event_id }) => ({ id, recipient_profile_id, event_id })));

  const auth = f.auth();
  assert.deepEqual((await roles.finalize(auth.cookieValue, auth.csrfToken, updated.final)).receipt, updated.completed.receipt);
  assert.equal((await projectAuthoritativeWorkspace(f.databases, f.workspaceId)).state, 'ready');
  assert.deepEqual((await rows()).rows, initial, 'Replay and repeated projection preserve one notice per recipient');

  const renamed = await change('update', [...permissions].reverse(), 'Private label-only rename');
  assert.equal((await f.admin.application.query('SELECT id FROM app.notifications WHERE workspace_id=$1 AND event_id=ANY($2::uuid[])',
    [f.workspaceId, [created.request.operationId, renamed.request.operationId]])).rowCount, 0, 'Role creation and equivalent-permission rename are not access-change notices');
  assert.deepEqual((await rows()).rows, initial, 'Earlier role-change notices remain immutable');
});

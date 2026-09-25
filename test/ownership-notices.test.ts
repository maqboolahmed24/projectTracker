import test from 'node:test';
import assert from 'node:assert/strict';
import { AppError } from '../src/errors.js';
import { tenantTransaction } from '../src/persistence.js';
import { projectAuthoritativeWorkspace } from '../src/modules/identity/projection.js';
import { readOwnershipNotices } from '../src/modules/identity/ownership-notices.js';
import { accessChangeFixture } from './access-change-fixture.js';

test('CP06: ownership changes notify other Owners once, and failed notice projection preserves the old version', async (t) => {
  const f = await accessChangeFixture(t), second = await f.joined('join_owner');
  assert.equal((await f.admin.application.query('SELECT id FROM app.notifications WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  const third = await f.joined('join_owner');
  const added = (await f.admin.application.query('SELECT * FROM app.notifications WHERE workspace_id=$1', [f.workspaceId])).rows;
  assert.equal(added.length, 1); assert.equal(added[0].event_type, 'security.owner_added');
  assert.equal(added[0].event_id, third.binding.operationId); assert.equal(added[0].record_id, third.binding.accountId);
  assert.equal(added[0].recipient_profile_id, second.binding.accountId); assert.equal(added[0].project_id, null);
  assert.deepEqual(added[0].encrypted_envelope, {});

  const oldVersion = (await f.admin.application.query('SELECT security_version FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].security_version;
  const change = await f.draft('demote_owner', second.binding.accountId, { roleId: f.prepared.payload.genesis.body.roles.member, projectIds: [] });
  let rollback: { security_version: string; fence_closed: boolean; notices: number } | undefined;
  const connect = f.databases.application.connect;
  f.databases.application.connect = (async (...arguments_: unknown[]) => {
    const application = await Reflect.apply(connect, f.databases.application, arguments_), query = application.query;
    let interrupted = false;
    application.query = async (...args: unknown[]) => {
      if (typeof args[0] === 'string' && args[0].includes('INSERT INTO app.notifications')) {
        interrupted = true; throw new Error('Ownership notice insert interrupted');
      }
      const result = await Reflect.apply(query, application, args);
      if (args[0] === 'ROLLBACK' && interrupted && !rollback) {
        // Observe rollback while this finalization still holds its fence. A queued
        // worker is allowed to repair projection as soon as that fence is released.
        const pending = (await f.admin.application.query('SELECT security_version,fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0];
        const notices = (await f.admin.application.query('SELECT id FROM app.notifications WHERE workspace_id=$1 AND event_id=$2', [f.workspaceId, change.reference.operationId])).rowCount!;
        rollback = { ...pending, notices };
      }
      return result;
    };
    return application;
  }) as typeof f.databases.application.connect;
  let finishing: Awaited<ReturnType<typeof f.finalize>>;
  try { finishing = await f.finalize(change); }
  finally { f.databases.application.connect = connect; }
  assert.equal(finishing.state, 'finishing'); assert.ok(finishing.receipt);
  assert.deepEqual(rollback, { security_version: oldVersion, fence_closed: true, notices: 0 });
  const completed = await f.status(change); assert.equal(completed.state, 'completed'); assert.deepEqual(completed.receipt, finishing.receipt);
  assert.equal((await projectAuthoritativeWorkspace(f.databases, f.workspaceId)).state, 'ready');
  const notices = (await f.admin.application.query('SELECT * FROM app.notifications WHERE workspace_id=$1 AND event_id=$2', [f.workspaceId, change.reference.operationId])).rows;
  assert.equal(notices.length, 1); assert.equal(notices[0].event_type, 'security.owner_demoted');
  assert.equal(notices[0].recipient_profile_id, third.binding.accountId); assert.equal(notices[0].record_id, second.binding.accountId);
  assert.equal(notices[0].project_id, null); assert.deepEqual(notices[0].encrypted_envelope, {});
  for (const [accountId, expected] of [[f.accountId, 0], [second.binding.accountId, 0], [third.binding.accountId, 1]] as const) {
    await tenantTransaction(f.databases.application, f.workspaceId, accountId, async (application) => {
      assert.equal((await application.query('SELECT id FROM app.notifications WHERE workspace_id=$1 AND event_id=$2', [f.workspaceId, change.reference.operationId])).rowCount, expected);
    });
  }
  await tenantTransaction(f.databases.application, f.workspaceId, undefined, async (application) => {
    assert.equal((await application.query('SELECT id FROM app.notifications WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  });

  // A malformed committed row must stop projection, rather than manufacturing a
  // notice from an unsigned action column or mismatched target metadata.
  await tenantTransaction(f.databases.control, f.workspaceId, undefined, async (control) => {
    const original = control.query;
    control.query = (async (...args: unknown[]) => {
      const result = await Reflect.apply(original, control, args);
      if (typeof args[0] === 'string' && args[0].includes('FROM security.security_transitions')) {
        const row = result.rows.find((entry: { operation_id: string }) => entry.operation_id === change.reference.operationId);
        if (row) row.signed_transition.body.binding.targetAccountId = third.binding.accountId;
      }
      return result;
    }) as typeof control.query;
    try {
      await assert.rejects(readOwnershipNotices(control, f.workspaceId, oldVersion, change.context.binding.nextSecurityVersion),
        (error: unknown) => error instanceof AppError && error.code === 'SECURITY_FENCED');
    } finally { control.query = original; }
  });
});

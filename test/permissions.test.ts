import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { capabilities } from '../src/shared/contracts.js';
import { ACTION_POLICIES, BUILTIN_ROLE_PERMISSIONS, canPerform, customRolePermissions, decidePermission,
  type BuiltinRole, type PermissionAction, type PermissionRequest } from '../src/shared/permissions.js';

const workspaceId = randomUUID(), accountId = randomUUID(), otherAccountId = randomUUID(), projectId = randomUUID();
function request(role: BuiltinRole | 'custom', action: PermissionAction): PermissionRequest {
  return {
    actor: { workspaceId, accountId, active: true, isOwner: role === 'owner' }, action, target: { workspaceId, projectId },
    access: { workspaceId, projectId, accountId, state: 'active', keysReady: true,
      permissions: [...(role === 'custom' ? ['read_project', 'comment'] as const : BUILTIN_ROLE_PERMISSIONS[role])] },
    task: { workspaceId, projectId, assigneeIds: action === 'tasks.approve' ? [otherAccountId] : [accountId] },
    assignment: { assigneeIds: [accountId], eligibleAssigneeIds: [accountId, otherAccountId] },
  };
}

const reserved: PermissionAction[] = ['owners.manage', 'recovery.manage', 'profiles.manage', 'roles.manage', 'project_access.manage', 'projects.create'];
const memberActions: PermissionAction[] = ['projects.read', 'comments.create', 'updates.create', 'tasks.create', 'tasks.edit', 'tasks.start', 'tasks.request_completion'];

for (const role of ['owner', 'manager', 'member', 'viewer', 'custom'] as const) {
  test(`CP06: every fixed action follows the ${role} matrix in an active keyed project`, () => {
    for (const action of Object.keys(ACTION_POLICIES) as PermissionAction[]) {
      const expected = role === 'owner' || (role === 'manager' ? !reserved.includes(action) :
        role === 'member' ? memberActions.includes(action) : role === 'viewer' ? action === 'projects.read' :
          ['projects.read', 'comments.create', 'updates.create'].includes(action));
      assert.equal(canPerform(request(role, action)), expected, `${role}: ${action}`);
    }
  });
}

test('CP06: default role catalogues are fixed, custom roles require read and cannot encode reserved authority', () => {
  assert.deepEqual(BUILTIN_ROLE_PERMISSIONS.owner, capabilities);
  assert.deepEqual(BUILTIN_ROLE_PERMISSIONS.manager, capabilities);
  assert.deepEqual(BUILTIN_ROLE_PERMISSIONS.member, ['read_project', 'comment', 'create_tasks', 'edit_assigned_tasks']);
  assert.deepEqual(BUILTIN_ROLE_PERMISSIONS.viewer, ['read_project']);
  for (const invalid of [[], ['comment'], ['read_project', 'read_project'], ['read_project', 'manage_owners'],
    ['read_project', 'recovery'], ['read_project', 'create_projects'], ['read_project', '*'], ['read_project', 'owner']]) {
    assert.equal(customRolePermissions.safeParse(invalid).success, false);
  }
  for (const capability of capabilities) assert.equal(customRolePermissions.safeParse([...new Set(['read_project', capability])]).success, true);
  assert.throws(() => (BUILTIN_ROLE_PERMISSIONS.viewer as unknown as string[]).push('manage_tasks'), TypeError);
  for (const action of reserved) {
    const custom = request('custom', action); custom.access!.permissions = [...capabilities];
    assert.equal(canPerform(custom), false, `${action}: all checkboxes do not imply Owner`);
  }
});

test('CP06: every role needs current same-account/workspace/project keyed access for ordinary content', () => {
  for (const role of ['owner', 'manager', 'member', 'viewer', 'custom'] as const) {
    for (const variant of ['absent', 'pending', 'revoked', 'missing-keys', 'workspace', 'project', 'account'] as const) {
      const value = request(role, 'projects.read');
      if (variant === 'absent') delete value.access;
      else if (variant === 'pending' || variant === 'revoked') value.access!.state = variant;
      else if (variant === 'missing-keys') value.access!.keysReady = false;
      else if (variant === 'workspace') value.access!.workspaceId = randomUUID();
      else if (variant === 'project') value.access!.projectId = randomUUID();
      else value.access!.accountId = randomUUID();
      assert.equal(canPerform(value), false, `${role}: ${variant}`);
    }
  }
  const owner = request('owner', 'projects.create'); delete owner.access; delete owner.target.projectId;
  assert.equal(canPerform(owner), true, 'Reserved project creation precedes project key provisioning');
  owner.actor.active = false; assert.equal(canPerform(owner), false);
  for (const action of Object.keys(ACTION_POLICIES) as PermissionAction[]) {
    const crossWorkspace = request('owner', action); crossWorkspace.target.workspaceId = randomUUID();
    assert.equal(canPerform(crossWorkspace), false, action);
  }
});

test('CP06: Member task creation is self-assigned and assigned edits never authorize assignment changes', () => {
  const value = request('member', 'tasks.create');
  assert.equal(canPerform(value), true);
  for (const assigneeIds of [[], [otherAccountId], [accountId, otherAccountId]]) {
    value.assignment!.assigneeIds = assigneeIds;
    assert.equal(canPerform(value), false);
  }
  for (const action of ['tasks.edit', 'tasks.start', 'tasks.request_completion'] as const) {
    const assigned = request('member', action); assert.equal(canPerform(assigned), true);
    assigned.task!.assigneeIds = [otherAccountId]; assert.equal(canPerform(assigned), false);
  }
  assert.equal(canPerform(request('member', 'tasks.assign')), false);
  for (const role of ['owner', 'manager'] as const) {
    const managed = request(role, 'tasks.edit'); managed.task!.assigneeIds = [otherAccountId]; assert.equal(canPerform(managed), true);
    const unassigned = request(role, 'tasks.create'); unassigned.assignment!.assigneeIds = []; assert.equal(canPerform(unassigned), true);
  }
});

test('CP06: task assignment requires existing active project members and never creates access', () => {
  for (const role of ['owner', 'manager'] as const) for (const action of ['tasks.create', 'tasks.assign'] as const) {
    const value = request(role, action); value.assignment!.assigneeIds = [accountId, otherAccountId];
    assert.equal(canPerform(value), true);
    value.assignment!.eligibleAssigneeIds = [accountId];
    assert.deepEqual(decidePermission(value), { allowed: false, reason: 'assignee_ineligible' });
    delete value.assignment; assert.equal(canPerform(value), false);
  }
  const assignedWithoutAccess = request('member', 'tasks.edit'); delete assignedWithoutAccess.access;
  assert.equal(canPerform(assignedWithoutAccess), false);
  assert.equal(canPerform({ ...assignedWithoutAccess, teamMember: true }), false);
  const member = request('member', 'tasks.create'); member.assignment!.eligibleAssigneeIds = [];
  assert.equal(canPerform(member), false, 'The actor must also be an eligible active project member');
});

test('CP06: approval needs its explicit capability and rejects every assignee, including any Owner', () => {
  for (const role of ['owner', 'manager', 'member', 'custom'] as const) {
    const value = request(role, 'tasks.approve');
    if (role === 'member' || role === 'custom') {
      assert.equal(canPerform(value), false); value.access!.permissions.push('approve_tasks');
    }
    assert.equal(canPerform(value), true);
    value.task!.assigneeIds.push(accountId);
    assert.deepEqual(decidePermission(value), { allowed: false, reason: 'self_approval_forbidden' });
  }
  const manageOnly = request('custom', 'tasks.approve'); manageOnly.access!.permissions = ['read_project', 'manage_tasks'];
  assert.equal(canPerform(manageOnly), false, 'Manage/edit permissions cannot substitute for approval');
});

test('CP06: Viewer reads the entire joined ordinary project without task-by-task filters', () => {
  const value = request('viewer', 'projects.read'); value.task!.assigneeIds = [otherAccountId];
  assert.equal(canPerform(value), true);
  value.task!.assigneeIds = []; assert.equal(canPerform(value), true);
  delete value.task; assert.equal(canPerform(value), true);
  for (const action of Object.keys(ACTION_POLICIES) as PermissionAction[]) if (action !== 'projects.read') {
    assert.equal(canPerform(request('viewer', action)), false, action);
  }
});

test('CP06: malformed or incomplete authority fails closed without mutating its input', () => {
  const value = request('manager', 'tasks.edit'), snapshot = structuredClone(value);
  assert.equal(canPerform(value), true); assert.deepEqual(value, snapshot);
  for (const invalid of [null, {}, { ...value, action: 'tasks.supervise' }, { ...value, action: '__proto__' },
    { ...value, actor: { ...value.actor, role: 'Owner' } }, { ...value, access: { ...value.access, permissions: ['manage_tasks'] } },
    { ...value, actor: { ...value.actor, active: false } }, { ...value, task: { ...value.task, projectId: randomUUID() } }]) {
    assert.equal(canPerform(invalid), false);
  }
  delete value.task; assert.deepEqual(decidePermission(value), { allowed: false, reason: 'task_context_required' });
});

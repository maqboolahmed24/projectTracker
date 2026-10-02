import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { AppError } from '../src/errors.js';
import { RoleService } from '../src/modules/identity/roles.js';
import { prepareRoleChange } from '../src/client/roles-controller.js';
import type { PlanningIntent } from '../src/client/planning-crypto.js';
import type { DeviceBundle } from '../src/client/device-store.js';
import { base64urlDecode, digestObject, signObject } from '../src/shared/crypto.js';
import type { Capability } from '../src/shared/permissions.js';
import type { PlanningPayload } from '../src/shared/planning-api.js';
import { planningFixture } from './planning-fixture.js';
import { origin } from './password-change-fixture.js';

type Fixture = Awaited<ReturnType<typeof planningFixture>>;
type Auth = ReturnType<Fixture['auth']>;
const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;

async function memberWithRole(f: Fixture, permissions: Capability[]) {
  const member = await f.joined(), roles = new RoleService({ ...f, origin });
  const request = { workspaceId: f.workspaceId, operationId: randomUUID(), roleId: randomUUID(), action: 'create' as const };
  const auth = f.auth(), context = await roles.context(auth.cookieValue, auth.csrfToken, request);
  const payload = await prepareRoleChange({ request, context, history: await f.history(), displayName: 'Private minimal workflow role', permissions }, f.originalBundle);
  await roles.stage(auth.cookieValue, auth.csrfToken, payload);
  assert.equal((await roles.finalize(auth.cookieValue, auth.csrfToken, { workspaceId: f.workspaceId, operationId: request.operationId, requestHash: await digestObject(payload) })).state, 'completed');
  await f.finalize(await f.draft('set_access', member.binding.accountId, { roleId: request.roleId, projectIds: [f.projectId] }));
  return { member, accountId: member.binding.accountId, ...await f.login(member.prepared, member.registered.exportKey) };
}

async function executeAs(f: Fixture, command: PlanningIntent, auth: Auth, bundle: DeviceBundle,
  options: Parameters<Fixture['preparePlanning']>[1] = {}) {
  return f.save(await f.preparePlanning(command, options, auth, bundle), auth);
}

async function resign(payload: PlanningPayload, bundle: DeviceBundle) {
  payload.mutation = await signObject(payload.mutation.body, base64urlDecode(bundle.signingPrivateKey));
  return payload;
}

test('CP08 permissions: custom contributors prepare and execute assigned work but cannot acquire assignment or management authority', async (t) => {
  const f = await planningFixture(t), contributor = await memberWithRole(f, ['read_project', 'create_tasks', 'edit_assigned_tasks']);
  const taskId = randomUUID(), blockerId = randomUUID();
  const create: PlanningIntent = { action: 'create_task', task: { id: taskId, phaseId: null, milestoneId: null, assigneeIds: [contributor.accountId], leadProfileId: contributor.accountId } };
  const creation = await f.preparePlanning(create, { content: { title: 'Private custom-role task', description: '', acceptanceCriteria: '' } }, contributor.auth, contributor.bundle);
  const createBinding = creation.mutation.body.binding;
  if (createBinding.version !== 2) throw new Error('Expected the current task workflow protocol');
  const unauthorizedReviewer = structuredClone(creation);
  unauthorizedReviewer.mutation.body.command = { action: 'create_task', operationId: createBinding.operationId, expected: createBinding.before,
    task: { ...create.task, assigneeIds: [...create.task.assigneeIds], reviewerProfileId: f.accountId } };
  await assert.rejects(f.save(await resign(unauthorizedReviewer, contributor.bundle), contributor.auth), code('PLANNING_PERMISSION_DENIED'));
  await f.save(creation, contributor.auth);
  await assert.rejects(executeAs(f, { action: 'start_task', taskId }, contributor.auth, contributor.bundle), /parent_not_active/);
  const draft = await f.preparePlanning({ action: 'edit_task', taskId }, { content: { title: 'Private revised task', description: '', acceptanceCriteria: '' } }, contributor.auth, contributor.bundle);
  const forged = structuredClone(draft);
  const binding = draft.mutation.body.binding;
  if (binding.version !== 2) throw new Error('Expected the current task workflow protocol');
  forged.mutation.body.command = { action: 'assign_task', operationId: binding.operationId, expected: binding.before,
    taskId, assigneeIds: [contributor.accountId, f.accountId], leadProfileId: contributor.accountId, teamId: null };
  await assert.rejects(f.save(await resign(forged, contributor.bundle), contributor.auth), code('PLANNING_PERMISSION_DENIED'));
  await f.save(draft, contributor.auth);
  await f.execute({ action: 'start_project' });
  await executeAs(f, { action: 'start_task', taskId }, contributor.auth, contributor.bundle);
  await executeAs(f, { action: 'create_blocker', blocker: { id: blockerId, taskId, responsibleProfileId: contributor.accountId } }, contributor.auth, contributor.bundle,
    { content: { reason: 'Private dependency', nextAction: 'Obtain the missing input' } });
  await assert.rejects(executeAs(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true }, contributor.auth, contributor.bundle), /blocked_task/);
  await assert.rejects(executeAs(f, { action: 'edit_blocker', blockerId, responsibleProfileId: f.accountId }, contributor.auth, contributor.bundle,
    { content: { reason: 'Private dependency', nextAction: 'Attempt reassignment without permission' } }), /permission_denied/);
  await executeAs(f, { action: 'resolve_blocker', blockerId }, contributor.auth, contributor.bundle, { outcome: 'Required input received' });
  await executeAs(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true }, contributor.auth, contributor.bundle);
  await assert.rejects(executeAs(f, { action: 'reopen_task', taskId }, contributor.auth, contributor.bundle, { outcome: 'Attempt management action' }), /permission_denied/);
  const result = await f.read();
  assert.equal(result.graph.tasks[0]!.state, 'done');
  assert.deepEqual(result.graph.tasks[0]!.assigneeIds, [contributor.accountId]);
  assert.equal(result.graph.blockers![0]!.state, 'resolved');
  assert.equal(result.records.find((record) => record.id === taskId)!.content.title, 'Private revised task');
});

test('CP08 permissions: assigning the named custom reviewer invalidates Review and cannot turn a fresh signature into self-approval', async (t) => {
  const f = await planningFixture(t), reviewer = await memberWithRole(f, ['read_project', 'approve_tasks']), taskId = randomUUID();
  await f.execute({ action: 'start_project' });
  await f.execute({ action: 'create_task', task: { id: taskId, phaseId: null, milestoneId: null, assigneeIds: [f.accountId], leadProfileId: f.accountId } },
    { content: { title: 'Private reviewed task', description: '', acceptanceCriteria: 'Shared acceptance' } });
  await f.execute({ action: 'set_project_review', enabled: true, reviewers: [{ taskId, reviewerProfileId: reviewer.accountId }] }, { outcome: 'Require a separate reviewer' });
  await f.execute({ action: 'request_task_completion', taskId, acceptanceConfirmed: true });
  await assert.rejects(f.execute({ action: 'complete_project' }, { outcome: 'Pending review cannot close the project' }), /unfinished_tasks/);
  const submitted = (await f.context()).graph.tasks[0]!;
  const originalCiphertext = (await f.context()).records.find((record) => record.id === taskId)!.envelope;
  const approval = await f.preparePlanning({ action: 'approve_task', taskId, submittedRevision: submitted.submittedRevision!, submittedPolicyRevision: submitted.submittedPolicyRevision! }, {}, reviewer.auth, reviewer.bundle);
  await f.execute({ action: 'assign_task', taskId, assigneeIds: [f.accountId, reviewer.accountId], leadProfileId: f.accountId, teamId: null });
  const after = await f.context();
  assert.equal(after.graph.tasks[0]!.state, 'in_progress');
  assert.equal(after.graph.tasks[0]!.reviewerProfileId, null);
  assert.equal(after.graph.tasks[0]!.submittedRevision, null);
  assert.deepEqual(after.records.find((record) => record.id === taskId)!.envelope, originalCiphertext);
  await assert.rejects(f.save(approval, reviewer.auth), code('PLANNING_CHANGED'));
  const current = await f.context(f.projectId, reviewer.auth), freshSelfApproval = structuredClone(approval);
  if (current.binding.version !== 2) throw new Error('Expected the current task workflow protocol');
  freshSelfApproval.mutation.body.binding = current.binding;
  freshSelfApproval.mutation.body.command = { action: 'approve_task', taskId, operationId: current.binding.operationId, expected: current.binding.before,
    submittedRevision: submitted.submittedRevision!, submittedPolicyRevision: submitted.submittedPolicyRevision! };
  freshSelfApproval.mutation.body.nextVersion = String(BigInt(current.binding.beforeVersion) + 1n);
  await assert.rejects(f.save(await resign(freshSelfApproval, reviewer.bundle), reviewer.auth), code('PLANNING_PERMISSION_DENIED'));
  await f.execute({ action: 'assign_task', taskId, assigneeIds: [f.accountId], leadProfileId: f.accountId, teamId: null });
  await f.execute({ action: 'select_task_reviewer', taskId, reviewerProfileId: reviewer.accountId });
  await f.execute({ action: 'request_task_completion', taskId, acceptanceConfirmed: true });
  const fresh = (await f.context()).graph.tasks[0]!;
  await executeAs(f, { action: 'approve_task', taskId, submittedRevision: fresh.submittedRevision!, submittedPolicyRevision: fresh.submittedPolicyRevision! }, reviewer.auth, reviewer.bundle);
  assert.equal((await f.context()).graph.tasks[0]!.state, 'done');
});

test('CP08 closure: restoring cancelled work reopens accepted wave milestones after explicit parent reopening without rewriting old closing snapshots', async (t) => {
  const f = await planningFixture(t), phaseId = randomUUID(), milestoneId = randomUUID(), taskId = randomUUID();
  await f.execute({ action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: null } }, { content: { name: 'Private iterative wave' } });
  await f.execute({ action: 'create_milestone', milestone: { id: milestoneId, phaseId, ownerProfileId: null } }, { content: { name: 'Private iterative acceptance' } });
  await f.execute({ action: 'create_task', task: { id: taskId, phaseId, milestoneId, assigneeIds: [], leadProfileId: null } },
    { content: { title: 'Private restored work', description: '', acceptanceCriteria: '' } });
  await f.execute({ action: 'cancel_task', taskId }, { outcome: 'Explicitly remove unfinished scope' });
  await f.execute({ action: 'start_project' });
  await f.execute({ action: 'start_phase', phaseId });
  await f.execute({ action: 'accept_milestone', milestoneId }, { outcome: 'Accept the remaining scope' });
  await f.execute({ action: 'complete_phase', phaseId }, { outcome: 'Initial wave outcome' });
  await f.execute({ action: 'complete_project' }, { outcome: 'Initial project outcome' });
  const closed = await f.read();
  await f.execute({ action: 'archive_project' });
  await assert.rejects(f.execute({ action: 'restore_task', taskId }, { outcome: 'Cannot change archived work' }), /scope_read_only/);
  await f.execute({ action: 'unarchive_project' });
  await f.execute({ action: 'reopen_project' });
  await assert.rejects(f.execute({ action: 'restore_task', taskId }, { outcome: 'Containing wave is still terminal' }), /scope_read_only/);
  await f.execute({ action: 'reopen_phase', phaseId });
  await f.execute({ action: 'restore_task', taskId }, { outcome: 'Bring this scope into the next iteration' });
  const restored = await f.read();
  assert.equal(restored.graph.tasks[0]!.state, 'todo');
  assert.equal(restored.graph.milestones[0]!.state, 'open');
  assert.deepEqual(restored.graph.snapshots, closed.graph.snapshots);
  await assert.rejects(f.execute({ action: 'complete_phase', phaseId }, { outcome: 'Unfinished restored work' }), /unfinished_tasks/);
  await f.execute({ action: 'request_task_completion', taskId, acceptanceConfirmed: true });
  await assert.rejects(f.execute({ action: 'complete_phase', phaseId }, { outcome: 'Manual acceptance still required' }), /unaccepted_milestones/);
  await f.execute({ action: 'accept_milestone', milestoneId }, { outcome: 'Restored delivery accepted' });
  await f.execute({ action: 'complete_phase', phaseId }, { outcome: 'Revised wave outcome' });
  await f.execute({ action: 'complete_project' }, { outcome: 'Revised project outcome' });
  const final = await f.read();
  assert.equal(final.graph.project.state, 'complete');
  assert.deepEqual(final.graph.snapshots.slice(0, closed.graph.snapshots.length), closed.graph.snapshots);
  assert.equal(final.graph.snapshots.length, closed.graph.snapshots.length + 3);
});

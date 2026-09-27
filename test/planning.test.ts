import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { planningAuthority, planningCommand, type PlanningBinding } from '../src/shared/planning-api.js';
import { capabilities } from '../src/shared/contracts.js';
import { assertTaskPlanningLink, assertTaskPlanningScope, evaluatePlanning, PlanningError, planningRevisionSnapshot,
  reopenMilestoneForUnfinishedWork, type PlanningAuthority, type PlanningCommand, type PlanningEnvelopeReference,
  type PlanningMilestone, type PlanningPhase, type PlanningState, type PlanningTask } from '../src/shared/planning.js';

type Action = PlanningCommand extends infer C ? C extends PlanningCommand ? Omit<C, 'operationId' | 'expected'> : never : never;
const outcome = (): PlanningEnvelopeReference => ({ recordId: randomUUID(), revision: '1', digest: 'a'.repeat(64) });
function fixture() {
  const workspaceId = randomUUID(), accountId = randomUUID(), projectId = randomUUID();
  const state: PlanningState = { project: { workspaceId, id: projectId, revision: '1', state: 'planned', archived: false,
    phaseLabel: 'wave', managerProfileId: null, teamId: null }, phases: [], milestones: [], tasks: [], snapshots: [], movements: [] };
  const authority: PlanningAuthority = { actor: { workspaceId, accountId, active: true, isOwner: false },
    access: { workspaceId, projectId, accountId, state: 'active', keysReady: true, permissions: [...capabilities] } };
  const phase = (overrides: Partial<PlanningPhase> = {}): PlanningPhase => ({ workspaceId, projectId, id: randomUUID(), revision: '1',
    state: 'planned', archived: false, displayOrder: 0, leadProfileId: null, ...overrides });
  const milestone = (overrides: Partial<PlanningMilestone> = {}): PlanningMilestone => ({ workspaceId, projectId, id: randomUUID(), revision: '1',
    state: 'open', phaseId: null, ownerProfileId: null, ...overrides });
  const task = (overrides: Partial<PlanningTask> = {}): PlanningTask => ({ workspaceId, projectId, id: randomUUID(), revision: '1',
    state: 'todo', phaseId: null, milestoneId: null, assigneeIds: [accountId, randomUUID()], leadProfileId: accountId, ...overrides });
  const apply = (current: PlanningState, action: Action, auth = authority) => evaluatePlanning(current,
    { ...action, operationId: randomUUID(), expected: planningRevisionSnapshot(current) } as PlanningCommand, auth);
  return { workspaceId, accountId, projectId, state, authority, phase, milestone, task, apply };
}
const rejects = (code: PlanningError['code'], fn: () => unknown) => assert.throws(fn,
  (error) => error instanceof PlanningError && error.code === code, code);
function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { Object.freeze(value); for (const child of Object.values(value)) freeze(child); }
  return value;
}

test('CP07: minimal project planning stays manual, waves overlap, and designation grants no authority', () => {
  const f = fixture();
  const first = f.phase(), second = f.phase({ displayOrder: 1, leadProfileId: f.accountId });
  let current = f.apply(freeze(f.state), { action: 'edit_project', patch: { phaseLabel: 'phase', managerProfileId: f.accountId, teamId: randomUUID() } }).state;
  for (const phase of [first, second]) current = f.apply(current, { action: 'create_phase', phase: {
    id: phase.id, displayOrder: phase.displayOrder, leadProfileId: phase.leadProfileId } }).state;
  assert.equal(current.project.state, 'planned'); assert.equal(current.phases[0]!.state, 'planned');
  rejects('parent_not_active', () => f.apply(current, { action: 'start_phase', phaseId: first.id }));
  current = f.apply(current, { action: 'start_project' }).state;
  current = f.apply(current, { action: 'start_phase', phaseId: second.id }).state;
  current = f.apply(current, { action: 'start_phase', phaseId: first.id }).state;
  assert.deepEqual(current.phases.map((phase) => phase.state), ['active', 'active']);
  assert.equal(current.project.phaseLabel, 'phase');
  assert.equal(f.state.project.state, 'planned');
  const viewer = structuredClone(f.authority); viewer.access!.permissions = ['read_project'];
  rejects('permission_denied', () => f.apply(current, { action: 'edit_phase', phaseId: second.id, patch: { displayOrder: 0 } }, viewer));
  assertTaskPlanningScope(current, null, true);
  const planned = { ...current, phases: current.phases.map((row) => ({ ...row, state: 'planned' as const })) };
  assertTaskPlanningScope(planned, first.id);
  rejects('parent_not_active', () => assertTaskPlanningScope(planned, first.id, true));
});

test('CP07: exact child revision snapshots reject stale rows, insertions, deletions and duplicate references', () => {
  const f = fixture(); const phase = f.phase(), milestone = f.milestone(), task = f.task();
  const current = { ...f.state, phases: [phase], milestones: [milestone], tasks: [task] };
  const command: PlanningCommand = { action: 'start_project', operationId: randomUUID(), expected: planningRevisionSnapshot(current) };
  for (const variant of [
    { ...current, project: { ...current.project, revision: '2' } },
    { ...current, phases: [{ ...phase, revision: '2' }] },
    { ...current, milestones: [{ ...milestone, revision: '2' }] },
    { ...current, tasks: [{ ...task, revision: '2' }] },
    { ...current, phases: [phase, f.phase()] }, { ...current, tasks: [] },
  ]) rejects('revision_conflict', () => evaluatePlanning(variant, command, f.authority));
  const duplicate = structuredClone(command); duplicate.expected.tasks = [{ id: task.id, revision: '1' }, { id: task.id, revision: '1' }];
  rejects('revision_conflict', () => evaluatePlanning(current, duplicate, f.authority));
  const reversed = { ...current, phases: [phase, f.phase()] };
  const expected = planningRevisionSnapshot(reversed); expected.phases = [...expected.phases].reverse();
  assert.equal(evaluatePlanning(reversed, { ...command, expected }, f.authority).state.project.state, 'active');
});

test('CP07: manual empty milestone acceptance requires active parents and an opaque recorded outcome', () => {
  const f = fixture(), phase = f.phase();
  let current = { ...f.state, phases: [phase] } as PlanningState;
  const milestone = f.milestone({ phaseId: phase.id });
  current = f.apply(current, { action: 'create_milestone', milestone: { id: milestone.id, phaseId: phase.id, ownerProfileId: null } }).state;
  rejects('parent_not_active', () => f.apply(current, { action: 'accept_milestone', milestoneId: milestone.id, outcome: outcome() }));
  current = f.apply(current, { action: 'start_project' }).state;
  rejects('parent_not_active', () => f.apply(current, { action: 'accept_milestone', milestoneId: milestone.id, outcome: outcome() }));
  current = f.apply(current, { action: 'start_phase', phaseId: phase.id }).state;
  rejects('outcome_required', () => f.apply(current, { action: 'accept_milestone', milestoneId: milestone.id,
    outcome: { recordId: randomUUID(), revision: '1', digest: '' } }));
  const result = f.apply(freeze(current), { action: 'accept_milestone', milestoneId: milestone.id, outcome: outcome() });
  assert.equal(result.state.milestones[0]!.state, 'accepted'); assert.equal(result.snapshot!.tasks.length, 0);
  assert.equal(result.snapshot!.kind, 'milestone'); assert.equal(result.snapshot!.action, 'accept');
  assert.equal(result.state.phases[0]!.state, 'active');
  rejects('invalid_transition', () => f.apply(result.state, { action: 'accept_milestone', milestoneId: milestone.id, outcome: outcome() }));
});

test('CP07: pending review and all unfinished task states block manual acceptance and closure', () => {
  const f = fixture(), phase = f.phase({ state: 'active' }), milestone = f.milestone({ phaseId: phase.id });
  for (const taskState of ['todo', 'in_progress', 'review'] as const) {
    const task = f.task({ state: taskState, phaseId: phase.id, milestoneId: milestone.id });
    const current = { ...f.state, project: { ...f.state.project, state: 'active' as const }, phases: [phase], milestones: [milestone], tasks: [task] };
    rejects('unfinished_tasks', () => f.apply(current, { action: 'accept_milestone', milestoneId: milestone.id, outcome: outcome() }));
    rejects('unfinished_tasks', () => f.apply(current, { action: 'complete_phase', phaseId: phase.id, outcome: outcome() }));
    rejects('unfinished_tasks', () => f.apply(current, { action: 'complete_project', outcome: outcome() }));
  }
  let current: PlanningState = { ...f.state, project: { ...f.state.project, state: 'active' }, phases: [phase], milestones: [milestone],
    tasks: [f.task({ state: 'done', phaseId: phase.id, milestoneId: milestone.id }), f.task({ state: 'cancelled', phaseId: phase.id })] };
  rejects('unaccepted_milestones', () => f.apply(current, { action: 'complete_phase', phaseId: phase.id, outcome: outcome() }));
  current = f.apply(current, { action: 'accept_milestone', milestoneId: milestone.id, outcome: outcome() }).state;
  rejects('incomplete_phases', () => f.apply(current, { action: 'complete_project', outcome: outcome() }));
  current = f.apply(current, { action: 'complete_phase', phaseId: phase.id, outcome: outcome() }).state;
  assert.equal(current.project.state, 'active', 'closing a phase never implicitly closes the project');
  const extra = f.task(); current = { ...current, tasks: [...current.tasks, extra] };
  rejects('unfinished_tasks', () => f.apply(current, { action: 'complete_project', outcome: outcome() }));
  current = { ...current, tasks: current.tasks.map((task) => task.id === extra.id ? { ...task, state: 'done' } : task) };
  const result = f.apply(current, { action: 'complete_project', outcome: outcome() });
  assert.equal(result.state.project.state, 'complete'); assert.equal(result.snapshot!.tasks.length, 3);
  assert.equal(result.state.snapshots.length, 3);
});

test('CP07: cross-project and wrong-wave links fail while project milestones may span several waves', () => {
  const f = fixture(), first = f.phase(), second = f.phase(), milestone = f.milestone({ phaseId: first.id });
  const current = { ...f.state, phases: [first, second], milestones: [milestone] };
  rejects('invalid_link', () => assertTaskPlanningLink(current, f.task({ projectId: randomUUID() })));
  rejects('invalid_link', () => assertTaskPlanningLink(current, f.task({ workspaceId: randomUUID() })));
  rejects('invalid_link', () => assertTaskPlanningLink(current, f.task({ phaseId: second.id, milestoneId: milestone.id })));
  rejects('invalid_link', () => assertTaskPlanningLink(current, f.task({ phaseId: randomUUID() })));
  const projectMilestone = { ...milestone, phaseId: null };
  for (const phaseId of [null, first.id, second.id]) assertTaskPlanningLink({ ...current, milestones: [projectMilestone] },
    f.task({ phaseId, milestoneId: milestone.id }));
  const withTasks = { ...current, tasks: [f.task({ phaseId: first.id, milestoneId: milestone.id })] };
  rejects('invalid_link', () => f.apply(withTasks, { action: 'edit_milestone', milestoneId: milestone.id, patch: { phaseId: second.id } }));
  assert.equal(withTasks.milestones[0]!.phaseId, first.id);
});

test('CP07: carry-forward preserves shared identity, assignments and history and reopens accepted destination atomically', () => {
  const f = fixture(), from = f.phase({ state: 'active' }), to = f.phase(), oldMilestone = f.milestone({ phaseId: from.id }), destination = f.milestone();
  const task = f.task({ phaseId: from.id, milestoneId: oldMilestone.id });
  let current: PlanningState = { ...f.state, project: { ...f.state.project, state: 'active' }, phases: [from, to], milestones: [oldMilestone, destination], tasks: [task] };
  current = f.apply(current, { action: 'accept_milestone', milestoneId: destination.id, outcome: outcome() }).state;
  const previousSnapshot = structuredClone(current.snapshots[0]);
  rejects('invalid_link', () => f.apply(current, { action: 'carry_task', taskId: task.id, phaseId: to.id, milestoneId: oldMilestone.id, outcome: outcome() }));
  const result = f.apply(freeze(current), { action: 'carry_task', taskId: task.id, phaseId: to.id, milestoneId: destination.id, outcome: outcome() });
  assert.equal(result.state.tasks[0]!.id, task.id); assert.deepEqual(result.state.tasks[0]!.assigneeIds, task.assigneeIds);
  assert.equal(result.state.tasks[0]!.leadProfileId, task.leadProfileId); assert.equal(result.state.tasks[0]!.revision, '2');
  assert.equal(result.state.milestones.find((row) => row.id === destination.id)!.state, 'open');
  assert.deepEqual(result.state.snapshots[0], previousSnapshot);
  assert.equal(result.state.movements[0]!.fromPhaseId, from.id); assert.equal(result.state.movements[0]!.toPhaseId, to.id);
  let closed = f.apply(result.state, { action: 'cancel_milestone', milestoneId: oldMilestone.id, outcome: outcome() }).state;
  const closedResult = f.apply(closed, { action: 'complete_phase', phaseId: from.id, outcome: outcome() });
  assert.equal(closedResult.snapshot!.tasks.length, 0); assert.equal(closedResult.snapshot!.carriedWork[0]!.taskId, task.id);
  closed = f.apply(closedResult.state, { action: 'reopen_phase', phaseId: from.id }).state;
  assert.deepEqual(closed.snapshots.at(-1), closedResult.snapshot);
});

test('CP07: task moves require manage_tasks even for assignees and planners; phase leads grant no access', () => {
  const f = fixture(), first = f.phase({ leadProfileId: f.accountId }), second = f.phase(), task = f.task({ phaseId: first.id });
  const current = { ...f.state, phases: [first, second], tasks: [task] };
  for (const permissions of [['read_project', 'edit_assigned_tasks'], ['read_project', 'plan_projects']] as const) {
    const authority = structuredClone(f.authority); authority.access!.permissions = [...permissions];
    rejects('permission_denied', () => f.apply(current, { action: 'carry_task', taskId: task.id, phaseId: second.id, milestoneId: null, outcome: outcome() }, authority));
  }
  const manager = structuredClone(f.authority); manager.access!.permissions = ['read_project', 'manage_tasks'];
  assert.equal(f.apply(current, { action: 'carry_task', taskId: task.id, phaseId: second.id, milestoneId: null, outcome: outcome() }, manager).state.tasks[0]!.phaseId, second.id);
  manager.access!.state = 'revoked';
  rejects('permission_denied', () => f.apply(current, { action: 'carry_task', taskId: task.id, phaseId: second.id, milestoneId: null, outcome: outcome() }, manager));
});

test('CP07: wave cancellation requires one explicit resolution per unfinished task and open milestone', () => {
  const f = fixture(), first = f.phase(), second = f.phase(), milestone = f.milestone({ phaseId: first.id });
  const task = f.task({ phaseId: first.id, milestoneId: milestone.id }), done = f.task({ state: 'done', phaseId: first.id });
  const current = { ...f.state, phases: [first, second], milestones: [milestone], tasks: [task, done] };
  const reason = outcome();
  const command: Action = { action: 'cancel_phase', phaseId: first.id, outcome: reason, tasks: [], milestones: [] };
  rejects('resolution_required', () => f.apply(current, command));
  rejects('resolution_required', () => f.apply(current, { ...command, tasks: [{ taskId: task.id, action: 'cancel' }] }));
  rejects('resolution_required', () => f.apply(current, { ...command,
    tasks: [{ taskId: task.id, action: 'cancel' }, { taskId: task.id, action: 'cancel' }], milestones: [{ milestoneId: milestone.id, action: 'cancel' }] }));
  rejects('resolution_required', () => f.apply(current, { ...command,
    tasks: [{ taskId: task.id, action: 'cancel' }, { taskId: done.id, action: 'cancel' }], milestones: [{ milestoneId: milestone.id, action: 'cancel' }] }));
  const result = f.apply(freeze(current), { ...command,
    tasks: [{ taskId: task.id, action: 'move', phaseId: second.id, milestoneId: milestone.id }],
    milestones: [{ milestoneId: milestone.id, action: 'move', phaseId: second.id }] });
  assert.equal(result.state.phases[0]!.state, 'cancelled'); assert.equal(result.state.phases[1]!.state, 'planned');
  assert.equal(result.state.tasks[0]!.phaseId, second.id); assert.equal(result.state.tasks[1]!.state, 'done');
  assert.equal(result.state.milestones[0]!.phaseId, second.id); assert.equal(result.snapshot!.carriedWork.length, 1);
  assert.deepEqual(current.tasks[0], task);
});

test('CP07: cancellation cascades use plan_projects, while any unpermitted or incompatible move rejects the entire operation', () => {
  const f = fixture(), first = f.phase(), second = f.phase(), milestone = f.milestone({ phaseId: first.id });
  const task = f.task({ phaseId: first.id, milestoneId: milestone.id });
  const current = { ...f.state, phases: [first, second], milestones: [milestone], tasks: [task] };
  const planner = structuredClone(f.authority); planner.access!.permissions = ['read_project', 'plan_projects'];
  const before = structuredClone(current);
  rejects('permission_denied', () => f.apply(current, { action: 'cancel_phase', phaseId: first.id, outcome: outcome(),
    tasks: [{ taskId: task.id, action: 'move', phaseId: second.id, milestoneId: null }], milestones: [{ milestoneId: milestone.id, action: 'cancel' }] }, planner));
  assert.deepEqual(current, before);
  rejects('invalid_link', () => f.apply(current, { action: 'cancel_phase', phaseId: first.id, outcome: outcome(),
    tasks: [{ taskId: task.id, action: 'cancel' }], milestones: [{ milestoneId: milestone.id, action: 'move', phaseId: second.id }] }));
  assert.deepEqual(current, before);
  const result = f.apply(current, { action: 'cancel_phase', phaseId: first.id, outcome: outcome(),
    tasks: [{ taskId: task.id, action: 'cancel' }], milestones: [{ milestoneId: milestone.id, action: 'cancel' }] }, planner);
  assert.equal(result.state.tasks[0]!.state, 'cancelled'); assert.equal(result.state.milestones[0]!.state, 'cancelled');
  const reopened = f.apply(result.state, { action: 'reopen_phase', phaseId: first.id }, planner).state;
  assert.equal(reopened.tasks[0]!.state, 'cancelled'); assert.equal(reopened.milestones[0]!.state, 'cancelled');
  assert.deepEqual(reopened.snapshots, result.state.snapshots);
});

test('CP07: project cancellation includes unscheduled work and retains completed children and snapshots after reopening', () => {
  const f = fixture(), phase = f.phase(), completePhase = f.phase({ state: 'complete' });
  const current = { ...f.state, phases: [phase, completePhase], milestones: [f.milestone(), f.milestone({ state: 'accepted' })],
    tasks: [f.task({ state: 'review' }), f.task({ state: 'done', phaseId: completePhase.id }), f.task({ phaseId: phase.id })] };
  const planner = structuredClone(f.authority); planner.access!.permissions = ['read_project', 'plan_projects'];
  const result = f.apply(freeze(current), { action: 'cancel_project', outcome: outcome() }, planner);
  assert.deepEqual(result.state.tasks.map((row) => row.state), ['cancelled', 'done', 'cancelled']);
  assert.deepEqual(result.state.phases.map((row) => row.state), ['cancelled', 'complete']);
  assert.deepEqual(result.state.milestones.map((row) => row.state), ['cancelled', 'accepted']);
  const reopened = f.apply(result.state, { action: 'reopen_project' }, planner).state;
  assert.equal(reopened.project.state, 'active'); assert.deepEqual(reopened.tasks, result.state.tasks);
  assert.deepEqual(reopened.phases, result.state.phases); assert.deepEqual(reopened.snapshots, result.state.snapshots);
});

test('CP07: terminal and archived parents require explicit unarchive/reopen before edits, without losing prior closure', () => {
  const f = fixture(), phase = f.phase({ state: 'active' });
  let current: PlanningState = { ...f.state, project: { ...f.state.project, state: 'active' }, phases: [phase] };
  rejects('invalid_transition', () => f.apply(current, { action: 'archive_project' }));
  rejects('invalid_transition', () => f.apply(current, { action: 'archive_phase', phaseId: phase.id }));
  current = f.apply(current, { action: 'complete_phase', phaseId: phase.id, outcome: outcome() }).state;
  current = f.apply(current, { action: 'archive_phase', phaseId: phase.id }).state;
  rejects('scope_read_only', () => f.apply(current, { action: 'reopen_phase', phaseId: phase.id }));
  rejects('scope_read_only', () => f.apply(current, { action: 'edit_phase', phaseId: phase.id, patch: { displayOrder: 1 } }));
  current = f.apply(current, { action: 'complete_project', outcome: outcome() }).state;
  rejects('scope_read_only', () => f.apply(current, { action: 'unarchive_phase', phaseId: phase.id }));
  current = f.apply(current, { action: 'archive_project' }).state;
  const snapshots = structuredClone(current.snapshots);
  rejects('scope_read_only', () => f.apply(current, { action: 'reopen_project' }));
  rejects('scope_read_only', () => f.apply(current, { action: 'edit_project', patch: {} }));
  rejects('scope_read_only', () => assertTaskPlanningScope(current, null));
  current = f.apply(current, { action: 'unarchive_project' }).state;
  rejects('scope_read_only', () => f.apply(current, { action: 'edit_project', patch: {} }));
  current = f.apply(current, { action: 'reopen_project' }).state;
  current = f.apply(current, { action: 'unarchive_phase', phaseId: phase.id }).state;
  current = f.apply(current, { action: 'reopen_phase', phaseId: phase.id }).state;
  current = f.apply(current, { action: 'edit_phase', phaseId: phase.id, patch: { displayOrder: 4 } }).state;
  assert.deepEqual(current.snapshots, snapshots);
  const next = f.apply(current, { action: 'complete_phase', phaseId: phase.id, outcome: outcome() });
  assert.equal(next.state.snapshots.length, snapshots.length + 1); assert.deepEqual(next.state.snapshots.slice(0, -1), snapshots);
});

test('CP07: CP08 unfinished-work hook reopens acceptance atomically while retaining history and rejecting terminal parents', () => {
  const f = fixture(), milestone = f.milestone();
  let current: PlanningState = { ...f.state, project: { ...f.state.project, state: 'active' }, milestones: [milestone] };
  current = f.apply(current, { action: 'accept_milestone', milestoneId: milestone.id, outcome: outcome() }).state;
  for (const taskState of ['todo', 'in_progress', 'review'] as const) {
    const task = f.task({ state: taskState, milestoneId: milestone.id });
    const result = reopenMilestoneForUnfinishedWork(freeze(current), task);
    assert.equal(result.milestones[0]!.state, 'open'); assert.equal(result.milestones[0]!.revision, '3');
    assert.deepEqual(result.snapshots, current.snapshots); assert.equal(current.milestones[0]!.state, 'accepted');
  }
  for (const taskState of ['done', 'cancelled'] as const) assert.equal(reopenMilestoneForUnfinishedWork(current,
    f.task({ state: taskState, milestoneId: milestone.id })), current);
  rejects('scope_read_only', () => reopenMilestoneForUnfinishedWork({ ...current, project: { ...current.project, state: 'complete' } },
    f.task({ milestoneId: milestone.id })));
  rejects('scope_read_only', () => reopenMilestoneForUnfinishedWork({ ...current, milestones: [{ ...milestone, state: 'cancelled' }] },
    f.task({ milestoneId: milestone.id })));
});

test('CP07: operation replay cannot append duplicate closure history and guards reject envelope/plaintext substitutions', () => {
  const f = fixture(); const current: PlanningState = { ...f.state, project: { ...f.state.project, state: 'active' } };
  const command: PlanningCommand = { operationId: randomUUID(), expected: planningRevisionSnapshot(current), action: 'complete_project', outcome: outcome() };
  const first = evaluatePlanning(current, command, f.authority);
  rejects('operation_reused', () => evaluatePlanning(first.state, { ...command, expected: planningRevisionSnapshot(first.state) }, f.authority));
  rejects('outcome_required', () => f.apply(current, { action: 'complete_project', outcome: 'Everything is done' as unknown as PlanningEnvelopeReference }));
  const withPlaintext = { ...outcome(), text: 'unnecessary server plaintext' };
  rejects('outcome_required', () => f.apply(current, { action: 'complete_project', outcome: withPlaintext }));
  rejects('invalid_context', () => f.apply(current, { action: 'edit_project', patch: { state: 'complete' } as never }));
});


test('CP07: task preparation is Todo-only with fixed creation/assignment grants and atomic milestone reopening', () => {
  const f = fixture(), member = randomUUID(), milestone = f.milestone();
  let current: PlanningState = { ...f.state, project: { ...f.state.project, state: 'active' }, milestones: [milestone] };
  current = f.apply(current, { action: 'accept_milestone', milestoneId: milestone.id, outcome: outcome() }).state;
  const authority = { ...f.authority, eligibleAssigneeIds: [f.accountId, member] };
  const command: Action = { action: 'create_task', task: { id: randomUUID(), phaseId: null, milestoneId: milestone.id, assigneeIds: [f.accountId, member], leadProfileId: member } };
  const created = f.apply(current, command, authority);
  assert.equal(created.state.tasks[0]!.state, 'todo'); assert.equal(created.state.tasks[0]!.revision, '1');
  assert.equal(created.state.milestones[0]!.state, 'open'); assert.deepEqual(created.state.snapshots, current.snapshots);
  const self = structuredClone(authority); self.access!.permissions = ['read_project', 'create_tasks'];
  rejects('permission_denied', () => f.apply(current, command, self));
  const selfTask = { ...command, task: { ...command.task, assigneeIds: [f.accountId], leadProfileId: null } };
  assert.equal(f.apply(current, selfTask, self).state.tasks.length, 1);
  rejects('permission_denied', () => f.apply(current, { ...selfTask, task: { ...selfTask.task, assigneeIds: [] } }, self));
  rejects('permission_denied', () => f.apply(current, { ...command, task: { ...command.task, assigneeIds: [randomUUID()], leadProfileId: null } }, authority));
  rejects('invalid_context', () => f.apply(current, { ...command, task: { ...command.task, leadProfileId: randomUUID() } }, authority));
  assert.equal(planningCommand.safeParse({ ...command, operationId: randomUUID(), expected: planningRevisionSnapshot(current), task: { ...command.task, state: 'done' } }).success, false);
  assert.equal(planningCommand.safeParse({ action: 'edit_project', operationId: randomUUID(), expected: planningRevisionSnapshot(current), patch: { managerProfileId: undefined } }).success, false);
});

test('CP07: ordinary planning enforces a read-only Owner device capability intersection', () => {
  const f = fixture();
  const authority = planningAuthority({ workspaceId: f.workspaceId, projectId: f.projectId, accountId: f.accountId, isOwner: true,
    permissions: ['read_project'], eligibleAssigneeIds: [f.accountId] } as PlanningBinding);
  rejects('permission_denied', () => f.apply(f.state, { action: 'start_project' }, authority));
  rejects('permission_denied', () => f.apply(f.state, { action: 'create_task', task: { id: randomUUID(), phaseId: null, milestoneId: null, assigneeIds: [f.accountId], leadProfileId: null } }, authority));
});

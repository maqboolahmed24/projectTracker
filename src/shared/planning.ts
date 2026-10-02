import { z } from 'zod';
import { digest, identifier, positiveCounter } from './contracts.js';
import { decidePermission, type PermissionAction, type PermissionRequest } from './permissions.js';

export type PlanningLifecycle = 'planned' | 'active' | 'complete' | 'cancelled';
export type PlanningTaskState = 'todo' | 'in_progress' | 'review' | 'done' | 'cancelled';
export const planningEnvelopeReference = z.strictObject({ recordId: identifier, revision: positiveCounter, digest });
export type PlanningEnvelopeReference = z.infer<typeof planningEnvelopeReference>;
interface Revisioned { workspaceId: string; id: string; revision: string }
interface ProjectChild extends Revisioned { projectId: string }
export interface PlanningProject extends Revisioned {
  reviewEnabled?: boolean; reviewPolicyRevision?: string;
  state: PlanningLifecycle; archived: boolean; phaseLabel: 'phase' | 'wave'; managerProfileId: string | null; teamId: string | null;
}
/** Names, objectives, dates and completion criteria remain in the encrypted content envelope. */
export interface PlanningPhase extends ProjectChild {
  state: PlanningLifecycle; archived: boolean; displayOrder: number; leadProfileId: string | null;
}
export interface PlanningMilestone extends ProjectChild {
  state: 'open' | 'accepted' | 'cancelled'; phaseId: string | null; ownerProfileId: string | null;
}
/** Only the task metadata needed by planning; CP08 owns task execution and content edits. */
export interface PlanningTask extends ProjectChild {
  state: PlanningTaskState; phaseId: string | null; milestoneId: string | null;
  assigneeIds: readonly string[]; leadProfileId: string | null;
  contentRevision?: string; teamId?: string | null; reviewerProfileId?: string | null;
  submittedRevision?: string | null; submittedPolicyRevision?: string | null; approvalOperationId?: string | null;
}
export interface PlanningBlocker extends ProjectChild {
  taskId: string; contentRevision: string; state: 'open' | 'resolved'; responsibleProfileId: string | null;
  createdBy: string; createdAt: string; resolvedBy: string | null; resolvedAt: string | null;
}
export interface PlanningRevisionSnapshot {
  blockers?: readonly { id: string; revision: string }[];
  projectRevision: string;
  phases: readonly { id: string; revision: string }[];
  milestones: readonly { id: string; revision: string }[];
  tasks: readonly { id: string; revision: string }[];
}
export interface PlanningMovement {
  operationId: string; taskId: string; taskRevision: string;
  fromPhaseId: string | null; toPhaseId: string | null;
  fromMilestoneId: string | null; toMilestoneId: string | null;
  reason: PlanningEnvelopeReference;
}
export interface PlanningClosingSnapshot {
  operationId: string; kind: 'project' | 'phase' | 'milestone'; recordId: string;
  action: 'complete' | 'accept' | 'cancel'; outcome: PlanningEnvelopeReference;
  project: PlanningProject; phases: readonly PlanningPhase[]; milestones: readonly PlanningMilestone[];
  tasks: readonly PlanningTask[]; carriedWork: readonly PlanningMovement[]; blockers?: readonly PlanningBlocker[];
}
export interface PlanningState {
  version?: 2; blockers?: readonly PlanningBlocker[];
  project: PlanningProject;
  phases: readonly PlanningPhase[]; milestones: readonly PlanningMilestone[]; tasks: readonly PlanningTask[];
  snapshots: readonly PlanningClosingSnapshot[]; movements: readonly PlanningMovement[];
}
export interface PlanningAuthority { actor: PermissionRequest['actor']; access: PermissionRequest['access']; eligibleAssigneeIds?: readonly string[]; eligibleReviewerIds?: readonly string[]; isOwner?: boolean; now?: string }
type CommandBase = { operationId: string; expected: PlanningRevisionSnapshot };
export type TaskCancellationResolution = { taskId: string; action: 'cancel' } |
  { taskId: string; action: 'move'; phaseId: string | null; milestoneId: string | null };
export type MilestoneCancellationResolution = { milestoneId: string; action: 'cancel' } |
  { milestoneId: string; action: 'move'; phaseId: string | null };
export type LegacyPlanningCommand = CommandBase & (
  | { action: 'edit_project'; patch: Partial<Pick<PlanningProject, 'phaseLabel' | 'managerProfileId' | 'teamId'>> }
  | { action: 'start_project' | 'reopen_project' | 'archive_project' | 'unarchive_project' }
  | { action: 'complete_project' | 'cancel_project'; outcome: PlanningEnvelopeReference }
  | { action: 'create_phase'; phase: Omit<PlanningPhase, 'workspaceId' | 'projectId' | 'revision' | 'state' | 'archived'> }
  | { action: 'edit_phase'; phaseId: string; patch: Partial<Pick<PlanningPhase, 'displayOrder' | 'leadProfileId'>> }
  | { action: 'start_phase' | 'reopen_phase' | 'archive_phase' | 'unarchive_phase'; phaseId: string }
  | { action: 'complete_phase'; phaseId: string; outcome: PlanningEnvelopeReference }
  | { action: 'cancel_phase'; phaseId: string; outcome: PlanningEnvelopeReference;
      tasks: readonly TaskCancellationResolution[]; milestones: readonly MilestoneCancellationResolution[] }
  | { action: 'create_milestone'; milestone: Omit<PlanningMilestone, 'workspaceId' | 'projectId' | 'revision' | 'state'> }
  | { action: 'edit_milestone'; milestoneId: string; patch: Partial<Pick<PlanningMilestone, 'phaseId' | 'ownerProfileId'>> }
  | { action: 'accept_milestone' | 'cancel_milestone'; milestoneId: string; outcome: PlanningEnvelopeReference }
  | { action: 'reopen_milestone'; milestoneId: string }
  | { action: 'create_task'; task: Pick<PlanningTask, 'id' | 'phaseId' | 'milestoneId' | 'assigneeIds' | 'leadProfileId'> }
  | { action: 'carry_task'; taskId: string; phaseId: string | null; milestoneId: string | null; outcome: PlanningEnvelopeReference }
);
export type TaskWorkflowCommand = CommandBase & (
  | { action: 'edit_task' | 'start_task' | 'set_task_todo'; taskId: string }
  | { action: 'assign_task'; taskId: string; assigneeIds: readonly string[]; leadProfileId: string | null; teamId: string | null }
  | { action: 'request_task_completion'; taskId: string; acceptanceConfirmed: true }
  | { action: 'select_task_reviewer'; taskId: string; reviewerProfileId: string | null }
  | { action: 'approve_task'; taskId: string; submittedRevision: string; submittedPolicyRevision: string }
  | { action: 'reject_task' | 'cancel_task' | 'reopen_task' | 'restore_task'; taskId: string; outcome: PlanningEnvelopeReference }
  | { action: 'set_project_review'; enabled: boolean; reviewers: readonly { taskId: string; reviewerProfileId: string }[]; outcome: PlanningEnvelopeReference }
  | { action: 'create_blocker'; blocker: { id: string; taskId: string; responsibleProfileId: string } }
  | { action: 'edit_blocker'; blockerId: string; responsibleProfileId: string }
  | { action: 'resolve_blocker' | 'reopen_blocker'; blockerId: string; outcome: PlanningEnvelopeReference }
);
export type PlanningCommand = Exclude<LegacyPlanningCommand, { action: 'create_task' }> |
  (CommandBase & { action: 'create_task'; task: Pick<PlanningTask, 'id' | 'phaseId' | 'milestoneId' | 'assigneeIds' | 'leadProfileId'> & { teamId?: string | null; reviewerProfileId?: string | null } }) | TaskWorkflowCommand |
  (CommandBase & { action: 'upgrade_content'; records: readonly { kind: 'project' | 'phase' | 'milestone' | 'task' | 'blocker'; id: string }[] });
export type PlanningFailure = 'invalid_context' | 'permission_denied' | 'revision_conflict' | 'not_found' |
  'scope_read_only' | 'invalid_transition' | 'parent_not_active' | 'unfinished_tasks' | 'unaccepted_milestones' |
  'incomplete_phases' | 'invalid_link' | 'resolution_required' | 'outcome_required' | 'operation_reused' | 'blocked_task' | 'reviewer_required' | 'stale_approval';
export class PlanningError extends Error {
  constructor(readonly code: PlanningFailure) { super(code); this.name = 'PlanningError'; }
}
function fail(code: PlanningFailure): never { throw new PlanningError(code); }
const terminal = (state: PlanningLifecycle) => state === 'complete' || state === 'cancelled';
const unfinished = (task: PlanningTask) => task.state !== 'done' && task.state !== 'cancelled';
const increment = (revision: string) => {
  const value = (BigInt(revision) + 1n).toString();
  if (!positiveCounter.safeParse(value).success) fail('invalid_context');
  return value;
};
const copy = <T>(value: T): T => structuredClone(value);
const sorted = <T extends { id: string }>(values: readonly T[]) => [...values].sort((a, b) => a.id.localeCompare(b.id));

/** Callers must load the complete child sets under their business transaction/lock. */
export function planningRevisionSnapshot(state: PlanningState): PlanningRevisionSnapshot {
  const refs = (rows: readonly ProjectChild[]) => sorted(rows).map(({ id, revision }) => ({ id, revision }));
  return { projectRevision: state.project.revision, phases: refs(state.phases), milestones: refs(state.milestones), tasks: refs(state.tasks), ...(state.version === 2 ? { blockers: refs(state.blockers ?? []) } : {}) };
}
function assertExpected(state: PlanningState, expected: PlanningRevisionSnapshot): void {
  if (!expected || expected.projectRevision !== state.project.revision) fail('revision_conflict');
  const actual = planningRevisionSnapshot(state);
  for (const key of ['phases', 'milestones', 'tasks'] as const) {
    const rows = expected[key];
    if (!Array.isArray(rows) || rows.length !== actual[key].length || new Set(rows.map((r) => r.id)).size !== rows.length) fail('revision_conflict');
    const ordered = sorted(rows);
    if (ordered.some((row, index) => row.id !== actual[key][index]!.id || row.revision !== actual[key][index]!.revision)) fail('revision_conflict');
  }
  if (state.version === 2) {
    if (!expected.blockers || JSON.stringify(sorted(expected.blockers)) !== JSON.stringify(actual.blockers)) fail('revision_conflict');
  }
}
function phaseOf(state: PlanningState, id: string): PlanningPhase {
  return state.phases.find((phase) => phase.id === id) ?? fail('not_found');
}
function milestoneOf(state: PlanningState, id: string): PlanningMilestone {
  return state.milestones.find((milestone) => milestone.id === id) ?? fail('not_found');
}
function taskOf(state: PlanningState, id: string): PlanningTask {
  return state.tasks.find((task) => task.id === id) ?? fail('not_found');
}
function editable(record: { state: PlanningLifecycle; archived: boolean }): void {
  if (record.archived || terminal(record.state)) fail('scope_read_only');
}
/** Gate CP08 preparation versus execution; parent transitions are always explicit. */
export function assertTaskPlanningScope(state: PlanningState, phaseId: string | null, execution = false): void {
  editable(state.project);
  const phase = phaseId === null ? undefined : phaseOf(state, phaseId);
  if (phase) editable(phase);
  if (execution && (state.project.state !== 'active' || (phase && phase.state !== 'active'))) fail('parent_not_active');
}
export function assertTaskPlanningLink(state: PlanningState, task: Pick<PlanningTask, 'workspaceId' | 'projectId' | 'phaseId' | 'milestoneId'>): void {
  if (task.workspaceId !== state.project.workspaceId || task.projectId !== state.project.id) fail('invalid_link');
  if (task.phaseId !== null && !state.phases.some((phase) => phase.id === task.phaseId)) fail('invalid_link');
  if (task.milestoneId !== null) {
    const milestone = state.milestones.find((item) => item.id === task.milestoneId);
    if (!milestone || (milestone.phaseId !== null && milestone.phaseId !== task.phaseId)) fail('invalid_link');
  }
}
function assertGraph(state: PlanningState): void {
  const project = state.project;
  if (!identifier.safeParse(project.id).success || !identifier.safeParse(project.workspaceId).success ||
    !positiveCounter.safeParse(project.revision).success || !['planned', 'active', 'complete', 'cancelled'].includes(project.state) ||
    (project.archived && !terminal(project.state)) || !['phase', 'wave'].includes(project.phaseLabel)) fail('invalid_context');
  const ids = new Set<string>([project.id]);
  for (const row of [...state.phases, ...state.milestones, ...state.tasks]) {
    if (!identifier.safeParse(row.id).success || ids.has(row.id) || !positiveCounter.safeParse(row.revision).success ||
      row.workspaceId !== project.workspaceId || row.projectId !== project.id) fail('invalid_context');
    ids.add(row.id);
  }
  for (const phase of state.phases) if (!['planned', 'active', 'complete', 'cancelled'].includes(phase.state) ||
    (phase.archived && !terminal(phase.state)) || !Number.isSafeInteger(phase.displayOrder) || phase.displayOrder < 0) fail('invalid_context');
  for (const milestone of state.milestones) {
    if (!['open', 'accepted', 'cancelled'].includes(milestone.state) ||
      (milestone.phaseId !== null && !state.phases.some((phase) => phase.id === milestone.phaseId))) fail('invalid_link');
  }
  for (const task of state.tasks) {
    if (!['todo', 'in_progress', 'review', 'done', 'cancelled'].includes(task.state) ||
      new Set(task.assigneeIds).size !== task.assigneeIds.length ||
      (task.leadProfileId !== null && !task.assigneeIds.includes(task.leadProfileId))) fail('invalid_context');
    assertTaskPlanningLink(state, task);
  }
}
const actionPolicy: Record<LegacyPlanningCommand['action'], PermissionAction> = {
  edit_project: 'projects.plan', start_project: 'projects.plan', reopen_project: 'projects.reopen',
  archive_project: 'projects.archive', unarchive_project: 'projects.unarchive', complete_project: 'projects.close', cancel_project: 'projects.cancel',
  create_phase: 'waves.plan', edit_phase: 'waves.plan', start_phase: 'waves.start', reopen_phase: 'waves.plan',
  archive_phase: 'waves.plan', unarchive_phase: 'waves.plan', complete_phase: 'waves.close', cancel_phase: 'waves.plan',
  create_milestone: 'projects.plan', edit_milestone: 'projects.plan', accept_milestone: 'milestones.accept',
  cancel_milestone: 'projects.plan', reopen_milestone: 'projects.plan', create_task: 'tasks.create', carry_task: 'tasks.edit',
};
function permission(state: PlanningState, authority: PlanningAuthority, action: PermissionAction, task?: PlanningTask, assignment?: PermissionRequest['assignment']): void {
  const request: PermissionRequest = { actor: authority.actor, action,
    target: { workspaceId: state.project.workspaceId, projectId: state.project.id },
    ...(authority.access ? { access: authority.access } : {}),
    ...(task ? { task: { workspaceId: task.workspaceId, projectId: task.projectId, assigneeIds: [...task.assigneeIds] } } : {}), ...(assignment ? { assignment } : {}) };
  if (!decidePermission(request).allowed) fail('permission_denied');
}
function manageTask(state: PlanningState, authority: PlanningAuthority, task: PlanningTask): void {
  // This fixed policy requires manage_tasks; assigned-work permission must never authorize a move.
  permission(state, authority, 'tasks.reopen', task);
}
function outcome(value: PlanningEnvelopeReference): PlanningEnvelopeReference {
  const parsed = planningEnvelopeReference.safeParse(value);
  if (!parsed.success) fail('outcome_required');
  return parsed.data;
}
function checkComplete(tasks: readonly PlanningTask[], milestones: readonly PlanningMilestone[]): void {
  if (tasks.some(unfinished)) fail('unfinished_tasks');
  if (milestones.some((milestone) => milestone.state === 'open')) fail('unaccepted_milestones');
}
function assertNewId(state: PlanningState, id: string): void {
  if (!identifier.safeParse(id).success || [state.project, ...state.phases, ...state.milestones, ...state.tasks].some((row) => row.id === id)) fail('invalid_context');
}
function assertOptionalId(value: string | null): void {
  if (value !== null && !identifier.safeParse(value).success) fail('invalid_context');
}
function targetMilestone(state: PlanningState, phaseId: string | null, milestoneId: string | null): void {
  assertTaskPlanningScope(state, phaseId);
  assertTaskPlanningLink(state, { workspaceId: state.project.workspaceId, projectId: state.project.id, phaseId, milestoneId });
  if (milestoneId !== null && milestoneOf(state, milestoneId).state === 'cancelled') fail('scope_read_only');
}

/**
 * CP08 calls this after its own permission/state/revision checks, in the SAME atomic
 * transaction as adding, restoring, reopening or moving the unfinished task. It
 * changes only current acceptance, preserving all immutable closing snapshots.
 */
export function reopenMilestoneForUnfinishedWork(state: PlanningState, task: PlanningTask): PlanningState {
  assertTaskPlanningScope(state, task.phaseId);
  assertTaskPlanningLink(state, task);
  if (!unfinished(task) || task.milestoneId === null) return state;
  const milestone = milestoneOf(state, task.milestoneId);
  if (milestone.state === 'cancelled') fail('scope_read_only');
  if (milestone.state !== 'accepted') return state;
  return { ...state, milestones: state.milestones.map((row) => row.id === milestone.id ? { ...row, state: 'open', revision: increment(row.revision) } : row) };
}
export interface PlanningResult {
  state: PlanningState;
  changed: { project: boolean; phaseIds: string[]; milestoneIds: string[]; taskIds: string[]; blockerIds?: string[] };
  events: { action: string; recordId: string }[];
  snapshot?: PlanningClosingSnapshot;
}

/**
 * Pure metadata policy. The server separately authenticates current authority,
 * validates signed encrypted envelopes/references and commits ALL returned rows,
 * history and outbox events atomically. Outcome text is validated only by clients.
 * A full, locked child set is mandatory: filtered/paginated data is not sufficient.
 */
function evaluateLegacyPlanning(input: PlanningState, command: LegacyPlanningCommand, authority: PlanningAuthority): PlanningResult {
  assertGraph(input);
  if (!identifier.safeParse(command.operationId).success || !Object.hasOwn(actionPolicy, command.action)) fail('invalid_context');
  assertExpected(input, command.expected);
  if (input.snapshots.some((row) => row.operationId === command.operationId) || input.movements.some((row) => row.operationId === command.operationId)) fail('operation_reused');
  const record = command.action === 'carry_task' ? taskOf(input, command.taskId) : undefined;
  permission(input, authority, actionPolicy[command.action], record, command.action === 'create_task' ? { assigneeIds: [...command.task.assigneeIds], eligibleAssigneeIds: [...(authority.eligibleAssigneeIds ?? [])] } : undefined);
  let state: PlanningState = copy(input);
  const events: PlanningResult['events'] = [];
  const touched = { project: false, phaseIds: new Set<string>(), milestoneIds: new Set<string>(), taskIds: new Set<string>() };
  const project = () => { if (!touched.project) { state.project.revision = increment(state.project.revision); touched.project = true; } return state.project; };
  const phase = (id: string) => { const row = phaseOf(state, id); if (!touched.phaseIds.has(id)) { row.revision = increment(row.revision); touched.phaseIds.add(id); } return row; };
  const milestone = (id: string) => { const row = milestoneOf(state, id); if (!touched.milestoneIds.has(id)) { row.revision = increment(row.revision); touched.milestoneIds.add(id); } return row; };
  const task = (id: string) => { const row = taskOf(state, id); if (!touched.taskIds.has(id)) { row.revision = increment(row.revision); touched.taskIds.add(id); } return row; };
  let closing: { kind: PlanningClosingSnapshot['kind']; recordId: string; action: PlanningClosingSnapshot['action']; outcome: PlanningEnvelopeReference } | undefined;
  const close = (kind: PlanningClosingSnapshot['kind'], recordId: string, action: PlanningClosingSnapshot['action'], value: PlanningEnvelopeReference) => {
    closing = { kind, recordId, action, outcome: outcome(value) };
  };
  const reopenFor = (row: PlanningTask) => {
    if (unfinished(row) && row.milestoneId !== null && milestoneOf(state, row.milestoneId).state === 'accepted') {
      milestone(row.milestoneId).state = 'open'; events.push({ action: 'milestone_reopened_for_work', recordId: row.milestoneId });
    }
  };
  const move = (id: string, phaseId: string | null, milestoneId: string | null, reason: PlanningEnvelopeReference) => {
    const prior = taskOf(state, id);
    manageTask(state, authority, prior);
    assertTaskPlanningScope(state, prior.phaseId);
    if (!unfinished(prior)) fail('invalid_transition');
    targetMilestone(state, phaseId, milestoneId);
    if (prior.phaseId === phaseId && prior.milestoneId === milestoneId) fail('invalid_transition');
    const movement: PlanningMovement = { operationId: command.operationId, taskId: id, taskRevision: increment(prior.revision),
      fromPhaseId: prior.phaseId, toPhaseId: phaseId, fromMilestoneId: prior.milestoneId, toMilestoneId: milestoneId, reason: outcome(reason) };
    const row = task(id); row.phaseId = phaseId; row.milestoneId = milestoneId;
    state = { ...state, movements: [...state.movements, movement] }; reopenFor(row);
    events.push({ action: 'task_carried_forward', recordId: id });
  };
  switch (command.action) {
    case 'edit_project': {
      editable(state.project);
      if (Object.keys(command.patch).some((key) => !['phaseLabel', 'managerProfileId', 'teamId'].includes(key))) fail('invalid_context');
      if (command.patch.phaseLabel !== undefined && !['phase', 'wave'].includes(command.patch.phaseLabel)) fail('invalid_context');
      if (command.patch.managerProfileId !== undefined) assertOptionalId(command.patch.managerProfileId);
      if (command.patch.teamId !== undefined) assertOptionalId(command.patch.teamId);
      Object.assign(project(), command.patch); break;
    }
    case 'start_project': editable(state.project); if (state.project.state !== 'planned') fail('invalid_transition'); project().state = 'active'; break;
    case 'reopen_project':
      if (state.project.archived) fail('scope_read_only');
      if (!terminal(state.project.state)) fail('invalid_transition');
      project().state = 'active'; break;
    case 'archive_project': case 'unarchive_project':
      if (!terminal(state.project.state) || state.project.archived === (command.action === 'archive_project')) fail('invalid_transition');
      project().archived = command.action === 'archive_project'; break;
    case 'complete_project':
      assertTaskPlanningScope(state, null, true); checkComplete(state.tasks, state.milestones);
      if (state.phases.some((row) => row.state !== 'complete' && row.state !== 'cancelled')) fail('incomplete_phases');
      project().state = 'complete'; close('project', state.project.id, 'complete', command.outcome); break;
    case 'cancel_project':
      editable(state.project);
      for (const row of state.tasks) if (unfinished(row)) task(row.id).state = 'cancelled';
      for (const row of state.milestones) if (row.state === 'open') milestone(row.id).state = 'cancelled';
      for (const row of state.phases) if (!terminal(row.state)) phase(row.id).state = 'cancelled';
      project().state = 'cancelled'; close('project', state.project.id, 'cancel', command.outcome); break;
    case 'create_phase': {
      editable(state.project); assertNewId(state, command.phase.id);
      assertOptionalId(command.phase.leadProfileId);
      if (Object.keys(command.phase).some((key) => !['id', 'displayOrder', 'leadProfileId'].includes(key))) fail('invalid_context');
      const row: PlanningPhase = { ...command.phase, workspaceId: state.project.workspaceId, projectId: state.project.id, revision: '1', state: 'planned', archived: false };
      state = { ...state, phases: [...state.phases, row] }; touched.phaseIds.add(row.id); break;
    }
    case 'edit_phase': {
      editable(state.project); editable(phaseOf(state, command.phaseId));
      if (Object.keys(command.patch).some((key) => !['displayOrder', 'leadProfileId'].includes(key))) fail('invalid_context');
      if (command.patch.leadProfileId !== undefined) assertOptionalId(command.patch.leadProfileId);
      Object.assign(phase(command.phaseId), command.patch); break;
    }
    case 'start_phase':
      assertTaskPlanningScope(state, command.phaseId);
      if (state.project.state !== 'active') fail('parent_not_active');
      if (phaseOf(state, command.phaseId).state !== 'planned') fail('invalid_transition');
      phase(command.phaseId).state = 'active'; break;
    case 'reopen_phase':
      editable(state.project);
      if (phaseOf(state, command.phaseId).archived) fail('scope_read_only');
      if (!terminal(phaseOf(state, command.phaseId).state)) fail('invalid_transition');
      phase(command.phaseId).state = 'active'; break;
    case 'archive_phase': case 'unarchive_phase': {
      editable(state.project); const row = phaseOf(state, command.phaseId);
      if (!terminal(row.state) || row.archived === (command.action === 'archive_phase')) fail('invalid_transition');
      phase(row.id).archived = command.action === 'archive_phase'; break;
    }
    case 'complete_phase': {
      assertTaskPlanningScope(state, command.phaseId, true);
      checkComplete(state.tasks.filter((row) => row.phaseId === command.phaseId), state.milestones.filter((row) => row.phaseId === command.phaseId));
      phase(command.phaseId).state = 'complete'; close('phase', command.phaseId, 'complete', command.outcome); break;
    }
    case 'cancel_phase': {
      assertTaskPlanningScope(state, command.phaseId);
      const tasks = state.tasks.filter((row) => row.phaseId === command.phaseId && unfinished(row));
      const milestones = state.milestones.filter((row) => row.phaseId === command.phaseId && row.state === 'open');
      const exact = (expected: readonly string[], actual: readonly string[]) => expected.length === actual.length &&
        new Set(actual).size === actual.length && expected.every((id) => actual.includes(id));
      if (!exact(tasks.map((row) => row.id), command.tasks.map((row) => row.taskId)) ||
        !exact(milestones.map((row) => row.id), command.milestones.map((row) => row.milestoneId))) fail('resolution_required');
      // Apply explicit milestone destinations first so task destinations can be validated against the final scope.
      for (const resolution of command.milestones) {
        if (resolution.action === 'cancel') milestone(resolution.milestoneId).state = 'cancelled';
        else if (resolution.action === 'move') {
          if (resolution.phaseId === command.phaseId) fail('invalid_transition');
          assertTaskPlanningScope(state, resolution.phaseId); milestone(resolution.milestoneId).phaseId = resolution.phaseId;
        } else fail('resolution_required');
      }
      for (const resolution of command.tasks) {
        if (resolution.action === 'cancel') task(resolution.taskId).state = 'cancelled';
        else if (resolution.action === 'move') {
          if (resolution.phaseId === command.phaseId) fail('invalid_transition');
          move(resolution.taskId, resolution.phaseId, resolution.milestoneId, command.outcome);
        } else fail('resolution_required');
      }
      phase(command.phaseId).state = 'cancelled'; close('phase', command.phaseId, 'cancel', command.outcome); break;
    }
    case 'create_milestone': {
      assertTaskPlanningScope(state, command.milestone.phaseId); assertNewId(state, command.milestone.id);
      assertOptionalId(command.milestone.ownerProfileId);
      if (Object.keys(command.milestone).some((key) => !['id', 'phaseId', 'ownerProfileId'].includes(key))) fail('invalid_context');
      const row: PlanningMilestone = { ...command.milestone, workspaceId: state.project.workspaceId, projectId: state.project.id, revision: '1', state: 'open' };
      state = { ...state, milestones: [...state.milestones, row] }; touched.milestoneIds.add(row.id); break;
    }
    case 'edit_milestone': {
      const row = milestoneOf(state, command.milestoneId); assertTaskPlanningScope(state, row.phaseId);
      if (row.state !== 'open') fail('scope_read_only');
      if (Object.keys(command.patch).some((key) => !['phaseId', 'ownerProfileId'].includes(key))) fail('invalid_context');
      if (command.patch.ownerProfileId !== undefined) assertOptionalId(command.patch.ownerProfileId);
      if (command.patch.phaseId !== undefined) assertTaskPlanningScope(state, command.patch.phaseId);
      Object.assign(milestone(row.id), command.patch); break;
    }
    case 'accept_milestone': {
      const row = milestoneOf(state, command.milestoneId); assertTaskPlanningScope(state, row.phaseId, true);
      if (row.state !== 'open') fail('invalid_transition');
      if (state.tasks.some((task) => task.milestoneId === row.id && unfinished(task))) fail('unfinished_tasks');
      milestone(row.id).state = 'accepted'; close('milestone', row.id, 'accept', command.outcome); break;
    }
    case 'cancel_milestone': {
      const row = milestoneOf(state, command.milestoneId); assertTaskPlanningScope(state, row.phaseId);
      if (row.state !== 'open') fail('invalid_transition');
      milestone(row.id).state = 'cancelled'; close('milestone', row.id, 'cancel', command.outcome); break;
    }
    case 'reopen_milestone': {
      const row = milestoneOf(state, command.milestoneId); assertTaskPlanningScope(state, row.phaseId);
      if (row.state === 'open') fail('invalid_transition');
      milestone(row.id).state = 'open'; break;
    }
    case 'create_task': {
      assertNewId(state, command.task.id); targetMilestone(state, command.task.phaseId, command.task.milestoneId);
      if (Object.keys(command.task).some((key) => !['id','phaseId','milestoneId','assigneeIds','leadProfileId'].includes(key))) fail('invalid_context');
      const row: PlanningTask = { ...command.task, workspaceId: state.project.workspaceId, projectId: state.project.id, revision: '1', state: 'todo' };
      state = { ...state, tasks: [...state.tasks, row] }; touched.taskIds.add(row.id); reopenFor(row); break;
    }
    case 'carry_task': move(command.taskId, command.phaseId, command.milestoneId, command.outcome); break;
    default: fail('invalid_context');
  }
  assertGraph(state);
  let snapshot: PlanningClosingSnapshot | undefined;
  if (closing) {
    const { kind, recordId } = closing;
    const tasks = state.tasks.filter((row) => kind === 'project' || (kind === 'phase' ? row.phaseId === recordId : row.milestoneId === recordId));
    snapshot = copy({ operationId: command.operationId, ...closing, project: state.project,
      phases: kind === 'project' ? sorted(state.phases) : kind === 'phase' ? [phaseOf(state, recordId)] : [],
      milestones: sorted(state.milestones.filter((row) => kind === 'project' || (kind === 'phase' ? row.phaseId === recordId : row.id === recordId))),
      tasks: sorted(tasks), carriedWork: state.movements.filter((row) => kind === 'project' ||
        (kind === 'phase' ? row.fromPhaseId === recordId : row.fromMilestoneId === recordId)) });
    state = { ...state, snapshots: [...state.snapshots, snapshot] };
  }
  const targetId = 'phaseId' in command && command.action !== 'carry_task' ? command.phaseId :
    'milestoneId' in command && command.action !== 'carry_task' ? command.milestoneId :
      command.action === 'carry_task' ? command.taskId : command.action === 'create_phase' ? command.phase.id :
        command.action === 'create_milestone' ? command.milestone.id : command.action === 'create_task' ? command.task.id : state.project.id;
  events.push({ action: command.action, recordId: targetId });
  return { state, changed: { project: touched.project, phaseIds: [...touched.phaseIds].sort(),
    milestoneIds: [...touched.milestoneIds].sort(), taskIds: [...touched.taskIds].sort() }, events, ...(snapshot ? { snapshot } : {}) };
}

/** Explicit protocol boundary. Never call this while replaying a v1 operation. */
export function upgradePlanningGraph(input: PlanningState): PlanningState {
  if (input.version === 2) return copy(input);
  return { ...copy(input), version: 2, blockers: [],
    project: { ...input.project, reviewEnabled: false, reviewPolicyRevision: '1' },
    tasks: input.tasks.map((t) => ({ ...t, contentRevision: t.revision, teamId: null, reviewerProfileId: null,
      submittedRevision: null, submittedPolicyRevision: null, approvalOperationId: null })) };
}
export function planningTaskBlocked(state: PlanningState, taskId: string): boolean {
  const task = taskOf(state, taskId);
  return task.state !== 'cancelled' && (state.blockers ?? []).some((b) => b.taskId === taskId && b.state === 'open');
}
function clearApproval(task: PlanningTask): void {
  task.submittedRevision = null; task.submittedPolicyRevision = null; task.approvalOperationId = null;
}
function validReviewer(authority: PlanningAuthority, task: PlanningTask, reviewer: string | null): void {
  if (reviewer !== null && (!(authority.eligibleReviewerIds ?? []).includes(reviewer) || task.assigneeIds.includes(reviewer))) fail('reviewer_required');
}
function assertWorkflowGraph(state: PlanningState): void {
  assertGraph(state);
  if (state.version !== 2 || typeof state.project.reviewEnabled !== 'boolean' || !positiveCounter.safeParse(state.project.reviewPolicyRevision).success || !state.blockers) fail('invalid_context');
  for (const t of state.tasks) {
    if (!positiveCounter.safeParse(t.contentRevision).success || BigInt(t.contentRevision!) > BigInt(t.revision) ||
      [t.teamId,t.reviewerProfileId,t.submittedRevision,t.submittedPolicyRevision,t.approvalOperationId].some((v) => v === undefined) ||
      (t.reviewerProfileId !== null && t.assigneeIds.includes(t.reviewerProfileId!)) ||
      ((t.submittedRevision === null) !== (t.submittedPolicyRevision === null))) fail('invalid_context');
  }
  const ids = new Set([state.project.id, ...state.phases.map((p) => p.id), ...state.milestones.map((m) => m.id), ...state.tasks.map((t) => t.id)]);
  for (const b of state.blockers) {
    if (ids.has(b.id) || !identifier.safeParse(b.id).success || !positiveCounter.safeParse(b.revision).success || !positiveCounter.safeParse(b.contentRevision).success || BigInt(b.contentRevision) > BigInt(b.revision) ||
      b.workspaceId !== state.project.workspaceId || b.projectId !== state.project.id || !state.tasks.some((t) => t.id === b.taskId) ||
      (b.state === 'open' ? b.resolvedAt !== null || b.resolvedBy !== null : b.state !== 'resolved' || b.resolvedAt === null || b.resolvedBy === null)) fail('invalid_context');
    ids.add(b.id);
  }
}
/** Historical responsibility may be retained on terminal records; a reopening makes it current again. */
function normalizeReopenedDesignations(before: PlanningState, after: PlanningState, changed: PlanningResult['changed'], authority: PlanningAuthority): void {
  const eligible = new Set(authority.eligibleAssigneeIds ?? []);
  for (const id of changed.phaseIds) {
    const previous = before.phases.find((p) => p.id === id), current = after.phases.find((p) => p.id === id)!;
    if (previous && terminal(previous.state) && !terminal(current.state) && current.leadProfileId && !eligible.has(current.leadProfileId)) current.leadProfileId = null;
  }
  for (const id of changed.milestoneIds) {
    const previous = before.milestones.find((m) => m.id === id), current = after.milestones.find((m) => m.id === id)!;
    if (previous && previous.state !== 'open' && current.state === 'open' && current.ownerProfileId && !eligible.has(current.ownerProfileId)) current.ownerProfileId = null;
  }
}
/** Versioned dispatcher preserves all legacy transition/hash behavior. */
export function evaluatePlanning(input: PlanningState, command: PlanningCommand, authority: PlanningAuthority): PlanningResult {
  if (input.version !== 2) return evaluateLegacyPlanning(input, command as LegacyPlanningCommand, authority);
  authority = { ...authority, isOwner: authority.isOwner ?? authority.actor.isOwner, actor: { ...authority.actor, isOwner: false } };
  assertWorkflowGraph(input); assertExpected(input, command.expected);
  if (!identifier.safeParse(command.operationId).success) fail('invalid_context');
  if (command.action === 'upgrade_content') {
    if (!authority.isOwner || !command.records.length || command.records.length > 32 ||
      new Set(command.records.map(record => `${record.kind}:${record.id}`)).size !== command.records.length) fail('permission_denied');
    permission(input, authority, 'projects.plan');
    return applyPlanningUpgrade(input, command.records);
  }
  if (Object.hasOwn(actionPolicy, command.action)) {
    // Reuse the original lifecycle policy, then attach v2 task state only at this boundary.
    const legacy = command.action === 'create_task' ? { ...command, task: { id: command.task.id, phaseId: command.task.phaseId,
      milestoneId: command.task.milestoneId, assigneeIds: command.task.assigneeIds, leadProfileId: command.task.leadProfileId } } : command;
    const result = evaluateLegacyPlanning(input, legacy as LegacyPlanningCommand, authority);
    if (command.action === 'create_task') {
      const row = result.state.tasks.find((t) => t.id === command.task.id)!;
      row.contentRevision = '1'; row.teamId = command.task.teamId ?? null; row.reviewerProfileId = command.task.reviewerProfileId ?? null;
      clearApproval(row); validReviewer(authority, row, row.reviewerProfileId);
      if (row.reviewerProfileId !== null) permission(result.state,authority,'tasks.select_reviewer',row);
    }
    for (const id of result.changed.taskIds) {
      const row = result.state.tasks.find((t) => t.id === id)!;
      if (row.state === 'cancelled') clearApproval(row);
    }
    normalizeReopenedDesignations(input,result.state,result.changed,authority);
    // A snapshot created in this operation must contain the final v2 cancellation markers.
    if (result.snapshot) {
      result.snapshot.blockers = copy((result.state.blockers ?? []).filter((b) => result.snapshot!.tasks.some((t) => t.id === b.taskId)));
      result.snapshot.phases = result.snapshot.phases.map((p) => copy(result.state.phases.find((r) => r.id === p.id)!));
      result.snapshot.milestones = result.snapshot.milestones.map((m) => copy(result.state.milestones.find((r) => r.id === m.id)!));
      result.snapshot.tasks = result.snapshot.tasks.map((t) => copy(result.state.tasks.find((r) => r.id === t.id)!));
    }
    assertWorkflowGraph(result.state); return result;
  }
  let state = copy(input);
  const changed: PlanningResult['changed'] = { project: false, phaseIds: [], milestoneIds: [], taskIds: [], blockerIds: [] };
  const touchTask = (id: string) => { const row = taskOf(state,id); if (!changed.taskIds.includes(id)) { row.revision = increment(row.revision); changed.taskIds.push(id); } return row; };
  const touchBlocker = (id: string) => { const row = state.blockers!.find((b) => b.id === id) ?? fail('not_found'); if (!changed.blockerIds!.includes(id)) { row.revision = increment(row.revision); changed.blockerIds!.push(id); } return row; };
  const reopenAcceptance = (row: PlanningTask) => { const after = reopenMilestoneForUnfinishedWork(state,row); if (after !== state) { changed.milestoneIds.push(row.milestoneId!); state = after; } };
  const invalidate = (row: PlanningTask) => { if (row.state === 'review') row.state = 'in_progress'; clearApproval(row); };
  const task = 'taskId' in command ? taskOf(state, command.taskId) : undefined;
  const live = (row: PlanningTask, execution = false) => { assertTaskPlanningScope(state,row.phaseId,execution); if (!unfinished(row)) fail('scope_read_only'); };
  const reason = () => { if (!('outcome' in command)) fail('outcome_required'); outcome(command.outcome); };
  let recordId = task?.id ?? state.project.id;
  switch (command.action) {
    case 'edit_task':
      live(task!); permission(state,authority,'tasks.edit',task); { const row = touchTask(task!.id); row.contentRevision = increment(row.contentRevision!); invalidate(row); } break;
    case 'assign_task': {
      live(task!); permission(state,authority,'tasks.assign',task,{ assigneeIds: [...command.assigneeIds], eligibleAssigneeIds: [...(authority.eligibleAssigneeIds ?? [])] });
      if (new Set(command.assigneeIds).size !== command.assigneeIds.length || (command.leadProfileId !== null && !command.assigneeIds.includes(command.leadProfileId))) fail('invalid_context');
      assertOptionalId(command.teamId);
      const row = touchTask(task!.id); row.assigneeIds = [...command.assigneeIds]; row.leadProfileId = command.leadProfileId; row.teamId = command.teamId;
      if (row.reviewerProfileId && row.assigneeIds.includes(row.reviewerProfileId)) row.reviewerProfileId = null;
      invalidate(row); break;
    }
    case 'start_task': case 'set_task_todo':
      live(task!,true); permission(state,authority,'tasks.start',task);
      if (task!.state !== (command.action === 'start_task' ? 'todo' : 'in_progress')) fail('invalid_transition');
      touchTask(task!.id).state = command.action === 'start_task' ? 'in_progress' : 'todo'; break;
    case 'request_task_completion': {
      live(task!,true); permission(state,authority,'tasks.request_completion',task);
      if (!['todo','in_progress'].includes(task!.state) || command.acceptanceConfirmed !== true) fail('invalid_transition');
      if (planningTaskBlocked(state,task!.id)) fail('blocked_task');
      if (state.project.reviewEnabled) {
        if (!task!.reviewerProfileId) fail('reviewer_required'); validReviewer(authority,task!,task!.reviewerProfileId);
      }
      const row = touchTask(task!.id); clearApproval(row);
      row.state = state.project.reviewEnabled ? 'review' : 'done';
      if (state.project.reviewEnabled) { row.submittedRevision = row.contentRevision!; row.submittedPolicyRevision = state.project.reviewPolicyRevision!; }
      break;
    }
    case 'select_task_reviewer': {
      live(task!);
      // An eligible Owner may explicitly replace the reviewer, but still needs this device's approval capability.
      if (authority.isOwner && command.reviewerProfileId === authority.actor.accountId) permission(state,authority,'tasks.approve',task);
      else permission(state,authority,'tasks.select_reviewer',task);
      validReviewer(authority,task!,command.reviewerProfileId); touchTask(task!.id).reviewerProfileId = command.reviewerProfileId; break;
    }
    case 'approve_task': case 'reject_task': {
      live(task!,true); permission(state,authority,'tasks.approve',task);
      if (!state.project.reviewEnabled || task!.state !== 'review' || task!.reviewerProfileId !== authority.actor.accountId) fail('reviewer_required');
      validReviewer(authority,task!,task!.reviewerProfileId);
      if (task!.submittedRevision !== task!.contentRevision || task!.submittedPolicyRevision !== state.project.reviewPolicyRevision) fail('stale_approval');
      if (command.action === 'approve_task') {
        if (command.submittedRevision !== task!.submittedRevision || command.submittedPolicyRevision !== task!.submittedPolicyRevision) fail('stale_approval');
        if (planningTaskBlocked(state,task!.id)) fail('blocked_task');
        const row = touchTask(task!.id); row.state = 'done'; row.approvalOperationId = command.operationId;
      } else { reason(); const row = touchTask(task!.id); row.state = 'in_progress'; clearApproval(row); }
      break;
    }
    case 'cancel_task': case 'reopen_task': case 'restore_task': {
      assertTaskPlanningScope(state,task!.phaseId); permission(state,authority,command.action === 'cancel_task' ? 'tasks.cancel' : command.action === 'reopen_task' ? 'tasks.reopen' : 'tasks.restore',task); reason();
      if (command.action === 'cancel_task' ? task!.state === 'cancelled' : task!.state !== (command.action === 'reopen_task' ? 'done' : 'cancelled')) fail('invalid_transition');
      if (command.action === 'reopen_task') assertTaskPlanningScope(state,task!.phaseId,true);
      const row = touchTask(task!.id); row.state = command.action === 'cancel_task' ? 'cancelled' : command.action === 'reopen_task' ? 'in_progress' : 'todo'; clearApproval(row);
      if (unfinished(row)) {
        if (row.reviewerProfileId && (!(authority.eligibleReviewerIds ?? []).includes(row.reviewerProfileId) || row.assigneeIds.includes(row.reviewerProfileId))) row.reviewerProfileId = null;
        reopenAcceptance(row);
      } break;
    }
    case 'set_project_review': {
      editable(state.project); if (!authority.isOwner) fail('permission_denied'); permission(state,authority,'projects.plan'); reason();
      if (command.enabled === state.project.reviewEnabled) fail('invalid_transition');
      const pending = state.tasks.filter(unfinished);
      if (command.enabled ? command.reviewers.length !== pending.length || new Set(command.reviewers.map((r) => r.taskId)).size !== pending.length || pending.some((t) => !command.reviewers.some((r) => r.taskId === t.id)) : command.reviewers.length !== 0) fail('resolution_required');
      for (const selection of command.reviewers) validReviewer(authority,taskOf(state,selection.taskId),selection.reviewerProfileId);
      state.project.reviewEnabled = command.enabled; state.project.reviewPolicyRevision = increment(state.project.reviewPolicyRevision!); state.project.revision = increment(state.project.revision); changed.project = true;
      for (const t of pending) {
        const selection = command.reviewers.find((r) => r.taskId === t.id);
        if (selection || t.state === 'review') { const row = touchTask(t.id); if (selection) row.reviewerProfileId = selection.reviewerProfileId; invalidate(row); }
      }
      break;
    }
    case 'create_blocker': case 'edit_blocker': case 'resolve_blocker': case 'reopen_blocker': {
      const existing = command.action === 'create_blocker' ? undefined : state.blockers!.find((b) => b.id === command.blockerId) ?? fail('not_found');
      const target = taskOf(state, command.action === 'create_blocker' ? command.blocker.taskId : existing!.taskId);
      assertTaskPlanningScope(state,target.phaseId); permission(state,authority,'tasks.edit',target);
      if (target.state === 'cancelled' || (target.state === 'done' && (command.action === 'create_blocker' || command.action === 'reopen_blocker'))) fail('scope_read_only');
      const responsible = command.action === 'create_blocker' ? command.blocker.responsibleProfileId : command.action === 'edit_blocker' ? command.responsibleProfileId : undefined;
      if (responsible !== undefined) {
        if (!(authority.eligibleAssigneeIds ?? []).includes(responsible)) fail('permission_denied');
        if (responsible !== authority.actor.accountId && responsible !== existing?.responsibleProfileId && !authority.access?.permissions.includes('manage_tasks')) fail('permission_denied');
      }
      if (command.action === 'create_blocker') {
        assertNewId(state,command.blocker.id); if (state.blockers!.some((b) => b.id === command.blocker.id) || !authority.now || !Number.isFinite(Date.parse(authority.now))) fail('invalid_context');
        const row: PlanningBlocker = { id: command.blocker.id, workspaceId: state.project.workspaceId, projectId: state.project.id, taskId: target.id, revision: '1', contentRevision: '1', state: 'open', responsibleProfileId: responsible!, createdBy: authority.actor.accountId, createdAt: authority.now, resolvedBy: null, resolvedAt: null };
        state.blockers = [...state.blockers!,row]; changed.blockerIds!.push(row.id); recordId = row.id;
      } else {
        const row = touchBlocker(existing!.id); recordId = row.id;
        if (command.action === 'edit_blocker') { row.responsibleProfileId = responsible!; row.contentRevision = increment(row.contentRevision); }
        else { reason(); if (row.state !== (command.action === 'resolve_blocker' ? 'open' : 'resolved')) fail('invalid_transition');
          if (!authority.now || !Number.isFinite(Date.parse(authority.now))) fail('invalid_context');
          row.state = command.action === 'resolve_blocker' ? 'resolved' : 'open'; row.resolvedBy = row.state === 'resolved' ? authority.actor.accountId : null; row.resolvedAt = row.state === 'resolved' ? authority.now : null; }
      }
      break;
    }
    default: fail('invalid_context');
  }
  normalizeReopenedDesignations(input,state,changed,authority);
  assertWorkflowGraph(state);
  return { state, changed: { ...changed, taskIds: changed.taskIds.sort(), milestoneIds: changed.milestoneIds.sort(), blockerIds: changed.blockerIds!.sort() }, events: [{ action: command.action, recordId }] };
}

/** Representation-only revisions preserve all workflow intent, approvals and closing snapshots. */
export function applyPlanningUpgrade(input: PlanningState,
  records: readonly { kind: 'project' | 'phase' | 'milestone' | 'task' | 'blocker'; id: string }[]): PlanningResult {
  assertWorkflowGraph(input);
  if (!records.length || records.length > 32 || new Set(records.map(row => `${row.kind}:${row.id}`)).size !== records.length) fail('invalid_context');
  const state = copy(input), changed: PlanningResult['changed'] = { project: false, phaseIds: [], milestoneIds: [], taskIds: [], blockerIds: [] };
  for (const record of records) {
    const row = record.kind === 'project' ? state.project.id === record.id ? state.project : undefined :
      record.kind === 'phase' ? state.phases.find(row => row.id === record.id) :
      record.kind === 'milestone' ? state.milestones.find(row => row.id === record.id) :
      record.kind === 'task' ? state.tasks.find(row => row.id === record.id) : state.blockers?.find(row => row.id === record.id);
    if (!row) fail('not_found');
    row.revision = increment(row.revision);
    if (record.kind === 'project') changed.project = true;
    else if (record.kind === 'phase') changed.phaseIds.push(record.id);
    else if (record.kind === 'milestone') changed.milestoneIds.push(record.id);
    else if (record.kind === 'task') changed.taskIds.push(record.id);
    else changed.blockerIds!.push(record.id);
  }
  changed.phaseIds.sort(); changed.milestoneIds.sort(); changed.taskIds.sort(); changed.blockerIds!.sort();
  return { state, changed, events: records.map(record => ({ action: 'upgrade_content', recordId: record.id })) };
}

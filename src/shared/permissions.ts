import { z } from 'zod';
import { capabilities, identifier } from './contracts.js';

export type Capability = (typeof capabilities)[number];

/** Role labels supply defaults, never ownership or project membership. */
export const BUILTIN_ROLE_PERMISSIONS = Object.freeze({
  owner: Object.freeze([...capabilities]),
  manager: Object.freeze([...capabilities]),
  member: Object.freeze(['read_project', 'comment', 'create_tasks', 'edit_assigned_tasks'] as const),
  viewer: Object.freeze(['read_project'] as const),
});
export type BuiltinRole = keyof typeof BUILTIN_ROLE_PERMISSIONS;

/** Reserved ownership/access actions are deliberately absent from the checkbox catalogue. */
export const customRolePermissions = z.array(z.enum(capabilities)).min(1).max(capabilities.length)
  .refine((values) => new Set(values).size === values.length && values.includes('read_project'));

type ActionPolicy =
  | { kind: 'owner' }
  | { kind: 'capability'; capability: Capability; task?: true }
  | { kind: 'create' | 'assignment' | 'assigned_work' | 'approval' };

/** Fixed business actions; workflow state/revision checks remain a separate mandatory gate. */
export const ACTION_POLICIES = {
  'owners.manage': { kind: 'owner' },
  'recovery.manage': { kind: 'owner' },
  'profiles.manage': { kind: 'owner' },
  'roles.manage': { kind: 'owner' },
  'project_access.manage': { kind: 'owner' },
  'projects.create': { kind: 'owner' },
  'projects.read': { kind: 'capability', capability: 'read_project' },
  'comments.create': { kind: 'capability', capability: 'comment', task: true },
  'updates.create': { kind: 'capability', capability: 'comment' },
  'tasks.create': { kind: 'create' },
  'tasks.edit': { kind: 'assigned_work' },
  'tasks.assign': { kind: 'assignment' },
  'tasks.start': { kind: 'assigned_work' },
  'tasks.request_completion': { kind: 'assigned_work' },
  'tasks.approve': { kind: 'approval' },
  'tasks.cancel': { kind: 'capability', capability: 'manage_tasks', task: true },
  'tasks.reopen': { kind: 'capability', capability: 'manage_tasks', task: true },
  'tasks.restore': { kind: 'capability', capability: 'manage_tasks', task: true },
  'tasks.select_reviewer': { kind: 'capability', capability: 'manage_tasks', task: true },
  'comments.moderate': { kind: 'capability', capability: 'manage_tasks', task: true },
  'projects.plan': { kind: 'capability', capability: 'plan_projects' },
  'waves.plan': { kind: 'capability', capability: 'plan_projects' },
  'waves.start': { kind: 'capability', capability: 'plan_projects' },
  'waves.review': { kind: 'capability', capability: 'plan_projects' },
  'waves.close': { kind: 'capability', capability: 'plan_projects' },
  'milestones.accept': { kind: 'capability', capability: 'plan_projects' },
  'projects.cancel': { kind: 'capability', capability: 'plan_projects' },
  'projects.reopen': { kind: 'capability', capability: 'plan_projects' },
  'projects.close': { kind: 'capability', capability: 'plan_projects' },
  'projects.archive': { kind: 'capability', capability: 'plan_projects' },
  'projects.unarchive': { kind: 'capability', capability: 'plan_projects' },
  'updates.moderate': { kind: 'capability', capability: 'plan_projects' },
} as const satisfies Record<string, ActionPolicy>;
export type PermissionAction = keyof typeof ACTION_POLICIES;
for (const policy of Object.values(ACTION_POLICIES)) Object.freeze(policy);
Object.freeze(ACTION_POLICIES);

const uniqueIds = z.array(identifier).refine((values) => new Set(values).size === values.length);
const permissionRequest = z.strictObject({
  actor: z.strictObject({ workspaceId: identifier, accountId: identifier, active: z.boolean(), isOwner: z.boolean() }),
  action: z.custom<PermissionAction>((value) => typeof value === 'string' && Object.hasOwn(ACTION_POLICIES, value)),
  target: z.strictObject({ workspaceId: identifier, projectId: identifier.optional() }),
  access: z.strictObject({ workspaceId: identifier, projectId: identifier, accountId: identifier,
    state: z.enum(['pending', 'active', 'revoked']), keysReady: z.boolean(), permissions: customRolePermissions }).optional(),
  task: z.strictObject({ workspaceId: identifier, projectId: identifier, assigneeIds: uniqueIds }).optional(),
  assignment: z.strictObject({ assigneeIds: uniqueIds, eligibleAssigneeIds: uniqueIds }).optional(),
});
export type PermissionRequest = z.infer<typeof permissionRequest>;
export type PermissionDenial = 'invalid_context' | 'inactive_profile' | 'wrong_workspace' | 'owner_required' |
  'project_access_required' | 'capability_required' | 'task_context_required' | 'assignment_context_required' |
  'assignee_ineligible' | 'self_assignment_required' | 'assignee_required' | 'self_approval_forbidden';
export type PermissionDecision = { allowed: true } | { allowed: false; reason: PermissionDenial };
const allow = (): PermissionDecision => ({ allowed: true });
const deny = (reason: PermissionDenial): PermissionDecision => ({ allowed: false, reason });

/**
 * Pure policy over current, trusted authority and record metadata. Callers must resolve
 * these values from the locked/current security state, never a request's role or flags.
 * Session/device/generation, workspace restrictions, record existence, task workflow,
 * named-reviewer/revision and cryptographic signature checks are separate required gates.
 * `tasks.edit` never authorizes changing assignees: every such change also requires
 * `tasks.assign`. Team membership is intentionally not an authorization input.
 */
export function decidePermission(input: unknown): PermissionDecision {
  const parsed = permissionRequest.safeParse(input);
  if (!parsed.success) return deny('invalid_context');
  const { actor, action, target, access, task, assignment } = parsed.data;
  if (!actor.active) return deny('inactive_profile');
  if (actor.workspaceId !== target.workspaceId) return deny('wrong_workspace');
  const policy: ActionPolicy = ACTION_POLICIES[action];
  if (policy.kind === 'owner') return actor.isOwner ? allow() : deny('owner_required');
  if (!target.projectId || !access || access.workspaceId !== target.workspaceId || access.projectId !== target.projectId ||
    access.accountId !== actor.accountId || access.state !== 'active' || !access.keysReady || !access.permissions.includes('read_project')) {
    return deny('project_access_required');
  }
  if (task && (task.workspaceId !== target.workspaceId || task.projectId !== target.projectId)) return deny('invalid_context');
  const permissions: readonly Capability[] = actor.isOwner ? BUILTIN_ROLE_PERMISSIONS.owner : access.permissions;
  const has = (capability: Capability) => permissions.includes(capability);
  const needsTask = policy.kind === 'assigned_work' || policy.kind === 'assignment' || policy.kind === 'approval' ||
    (policy.kind === 'capability' && policy.task);
  if (needsTask && !task) return deny('task_context_required');
  if (policy.kind === 'capability') return has(policy.capability) ? allow() : deny('capability_required');
  if (policy.kind === 'approval') {
    if (!has('approve_tasks')) return deny('capability_required');
    return task!.assigneeIds.includes(actor.accountId) ? deny('self_approval_forbidden') : allow();
  }
  if (policy.kind === 'assigned_work') {
    if (has('manage_tasks')) return allow();
    if (!has('edit_assigned_tasks')) return deny('capability_required');
    return task!.assigneeIds.includes(actor.accountId) ? allow() : deny('assignee_required');
  }
  if (!has(policy.kind === 'create' ? 'create_tasks' : 'manage_tasks')) return deny('capability_required');
  if (!assignment) return deny('assignment_context_required');
  if (assignment.assigneeIds.some((id) => !assignment.eligibleAssigneeIds.includes(id))) return deny('assignee_ineligible');
  if (policy.kind === 'create' && !has('manage_tasks') &&
    (assignment.assigneeIds.length !== 1 || assignment.assigneeIds[0] !== actor.accountId)) return deny('self_assignment_required');
  return allow();
}

export function canPerform(input: unknown): boolean { return decidePermission(input).allowed; }

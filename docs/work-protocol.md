# Projects, teams and planning

Checkpoints 7–9 are verified; consult [planning evidence](checkpoint-07-evidence.md) and [task workflow evidence](checkpoint-08-evidence.md) for executed checks. See [collaboration and Inbox](collaboration-protocol.md) for comments, moderation, notifications and retained team/audit history. This is a browser library and API, without product screens. Follow the [authentication setup](authentication-protocol.md) and use `openClient()` so that logout and Forget hooks cover every controller.

## Create and organise work

After an Owner has signed in and unlocked an approved device:

```js
const created = await client.projectCreation.create({ name: 'Client portal' });
if (created.state !== 'completed') throw new Error('Project projection is finishing; retain its operation ID and resume it later.');
const projectId = created.projectId;

const team = await client.teams.create({ name: 'Delivery', memberIds: [] });
await client.planning.execute({
  projectId,
  command: { action: 'edit_project', patch: { teamId: team.teamId } },
});

const phaseId = crypto.randomUUID();
await client.planning.execute({
  projectId,
  command: { action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: null } },
  content: { name: 'Pilot', objective: 'Validate the first delivery', completionCriteria: 'Pilot accepted' },
});
await client.planning.execute({ projectId, command: { action: 'start_project' } });
await client.planning.execute({ projectId, command: { action: 'start_phase', phaseId } });
const view = await client.planning.read(projectId);
```

The first project needs only a name and starts Planned. Creation provisions encrypted access for all active Owners before the project becomes available. Team membership is organisational and grants no project access; use the [access controller](access-change-protocol.md) to give a person an explicit project role. Planning changes require the applicable fixed permissions and current device scope. Naming a manager, lead or milestone owner grants no extra permissions.

Project content accepts `name`, optional `description`, `startDate` and `dueDate`. Wave content accepts `name`, `objective`, `completionCriteria` and optional `startDate`/`dueDate`. Milestone content accepts `name` and an optional `dueDate`. Prepared task content accepts `title`, `description`, optional `dueDate` and `acceptanceCriteria`. Dates are calendar dates (`YYYY-MM-DD`); a start date cannot follow its due date. An edit's supplied `content` replaces that record's private content, so retain fields that should remain. Omit `content` to preserve it. Waves can overlap and start manually. `phaseLabel` changes the project's display term between `phase` and `wave`.

Use `create_milestone` with `{ milestone: { id, phaseId: null, ownerProfileId: null } }` for a project milestone, or supply a wave ID. `accept_milestone`, `complete_phase` and `complete_project` require a nonempty `outcome` string beside `command`. These actions check their full child state, including unfinished work outside waves and outstanding milestone acceptance. Closure writes an encrypted Update and preserves a closing snapshot. An empty milestone can be accepted as a manual checkpoint.

Cancellation requires an outcome and explicit dispositions for unfinished work. `cancel_phase` takes complete `tasks` and `milestones` resolution lists; `cancel_project` applies the documented project cascade. `carry_task` moves the same task and explicitly resolves its destination wave/milestone. A minimal `create_task` command can prepare Todo work with explicit assignees and an optional lead so planning and cancellation can operate on real tasks. Task execution, review and blockers are described below. Use the exported `PlanningIntent` type for action fields.

Only terminal projects/waves can be archived. Explicitly unarchive and reopen them before further business edits. Reopening a cancelled parent leaves its cancelled children unchanged. Old outcomes, movements and snapshots remain history.

## Shared tasks, review and blockers

This checkpoint 8 API is verified; see [its evidence record](checkpoint-08-evidence.md) for results and limits.

`client.planning.createTask({ projectId, title })` prepares one Todo task. For an actor with `manage_tasks`, omitted assignees means unassigned; other eligible creators default to themselves. Supply `assigneeIds` for shared work. Optional fields include `description`, `acceptanceCriteria`, `startDate`, `dueDate`, `priority` (`low`, `normal`, `high`), `phaseId`, `milestoneId`, `teamId`, `leadProfileId` and `reviewerProfileId`. The helper returns `taskId` and the ordinary operation receipt.

Use the same `planning.execute()` method for subsequent actions:

```js
const task = await client.planning.createTask({ projectId, title: 'Test the pilot together', assigneeIds: [developerId, testerId] });
await client.planning.execute({ projectId, command: { action: 'start_task', taskId: task.taskId } });
await client.planning.execute({ projectId, command: {
  action: 'request_task_completion', taskId: task.taskId, acceptanceConfirmed: true,
} });
```

Execution requires an Active project and containing wave. `edit_task` replaces the supplied private task content; preserve fields that should remain. `assign_task` supplies the full `assigneeIds` list, an explicit `leadProfileId` (or `null`) and `teamId` (or `null`). The lead must remain an assignee. These actions require the corresponding fixed permissions; an assignment never grants project access. One shared task has one status and acceptance record.

Review starts disabled. An Owner uses `set_project_review` with `enabled`, a complete `reviewers` list of `{ taskId, reviewerProfileId }` for unfinished tasks when enabling, and an `outcome` explaining the policy change. When disabling, supply an empty list; pending Review work returns to In progress. With review enabled, completion requests submit the current content revision to the named reviewer. The eligible non-assignee uses `approve_task` with `taskId`, `submittedRevision` and `submittedPolicyRevision` from the current verified task, or `reject_task` with an `outcome`. Replacing an unavailable reviewer uses `select_task_reviewer`; a missing reviewer is represented by `reviewerProfileId: null`.

Task content and assignment edits invalidate pending review. `cancel_task`, `reopen_task` and `restore_task` require an `outcome`; Done work must be reopened and Cancelled work restored before material edits. Reopening/restoration also reopens an Accepted linked milestone atomically. Prior approvals and closing snapshots remain history.

`create_blocker` takes `{ blocker: { id, taskId, responsibleProfileId } }` and private `content: { reason, nextAction }`. `edit_blocker` takes `blockerId`, `responsibleProfileId` and replacement private content. `resolve_blocker` and `reopen_blocker` take `blockerId` plus an `outcome`. Assigned editors initially make themselves responsible; task managers may select another active project member. The graph retains creator/resolver identities and times. Any Open blocker prevents completion; cancelled tasks retain their blockers as inactive history and restoration reactivates still-Open blockers.

Planning protocol v2 preserves original v1 signed history. Task and blocker content revisions are separate from metadata revisions: status, approval, responsibility cleanup and other metadata operations retain the original content envelope. Only explicit content edits replace it. This prevents an approval from silently substituting different private task text.

## HTTP and verification

All mutation/controller transports use exact-origin POST requests, approved session cookies and CSRF tokens. Bodies contain ciphertext and signed metadata, never private names, dates, outcomes, passwords or keys. The server validates authority, complete source revisions and lifecycle rules and commits the records, immutable versions, audit, outbox and receipt together. The browser separately verifies signed security and planning history, decrypts under the appropriate retained key epoch and pins the highest observed project head.

| Prefix | Operations |
| --- | --- |
| `/v1/work/projects/create/` | `context`, `stage`, `finalize`, `status`, `history` |
| `/v1/work/teams/` | `context`, `save`, `status`, `list`, `history` |
| `/v1/work/planning/` | `context`, `snapshot`, `save`, `status`, `history` |

Generic encrypted GET reads under `/v1/workspaces/:workspaceId/projects` recheck the session, workspace fence, person access and current device scope on every request and page. They return encrypted records; use the planning controller when a verified complete project graph is needed.

Project lists and `/v1/workspaces/:workspaceId/projects/:projectId/records/phases` exclude archived rows by default. Use `?includeArchived=true` to include archived history; `includeArchived=false` explicitly selects the default. Filtering happens before `limit` and `after` pagination. This option is accepted only on these two list routes, and other values are rejected. Direct project detail reads and the planning controller's complete graph/history remain available for archived scopes under the same access checks.

## Interrupted work and current limits

Pass an explicit `operationId` when a caller needs to retain it before a request. Each controller saves an immutable encrypted draft before sending a write. After an uncertain reply, sign in to the same device and call the corresponding `resume(operationId)`; use `pending()` to discover retained drafts. Do not generate a replacement operation until the earlier result is resolved. A stale uncommitted binding requires reloading current state and making an explicit new attempt. There is no automatic retry loop.

Currently, logout aborts active requests and clears usable local keys; encrypted drafts remain available for recovery. Checkpoint 11 must remove pending encrypted requests on successful logout, as required by the architecture. Forget removes the selected device's local drafts. Current permissions always govern delivery, history and receipt access. A lost device's recovery follows the identity protocols.

The initial planning protocol rejects, rather than truncates, a graph exceeding 2,000 current records, 512 planning operations or its 16 MiB complete context limit. Planning POST bodies are also capped at 16 MiB. There is no unbounded history compaction or automatic scheduling. Calculations/live refresh, retry/upgrade completion, backups/export and production release gates remain tracked in checkpoints 10–13.

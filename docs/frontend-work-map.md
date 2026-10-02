# Frontend work-domain map

Source audit, 27 September 2026. This describes the current implementation, not new UI promises. Primary sources are `src/client/runtime.ts`, the controllers and shared contracts cited below, and the actual browser journeys. The initial audit was read-only. A subsequent narrow extension exposes already-verified planning authority; its source tests are noted below. No database tests were run during the audit.

## Integration boundary and gaps to close

Use the browser runtime returned by `openClient()` from `src/client/index.ts`. The runtime already handles authenticated same-origin requests, secure Worker operations, verified reads, durable encrypted write requests, and authentication cleanup. UI modules must not directly encrypt data, construct signed payloads, or persist decrypted records. Keep private names, task text, dates, outcomes, and decrypted search results in memory, clear on authentication changes, and render as text.

The following gaps matter for a complete customer-facing application:

1. **No decrypted project-directory controller.** `GET /v1/workspaces/:workspaceId/projects` exists and pages encrypted database records, with `includeArchived=true|false`. It is appropriate for ID discovery only. The UI needs an adapter that pages this route and calls `planning.read(id)` before displaying names or business metadata. It must handle removed access, partial loading, paging, empty results, and current authentication changes. The route defaults to 50, caps at 100, and orders opaque IDs. Never infer project names or complete counts from an unfinished first page.
2. **No people directory.** The new `profiles.current()` returns only the signed, decrypted current profile. Shared task selectors, leads, reviewers, comments, teams, and history need readable names for other currently visible people. Existing generic work routes do not supply profile labels. A verified, permission-scoped directory extension is needed; raw account IDs must not become the permanent customer UI.
3. **Verified presentation authority is now exposed.** The narrow `ReadablePlanning.authority` extension returns `accountId`, `isOwner`, `permissions`, `eligibleAssigneeIds`, and `eligibleReviewerIds`, copied only after the current planning context has been verified. Older v1 contexts have an empty reviewer list. Source tests check exact authority and reject modified permissions, ownership, assignee and reviewer lists. Do not trust locally guessed role names or raw server metadata. `accessChanges.refreshKeys()` returns only `{complete:true,scopeCount,securityHead,securityVersion,custodyEpoch,ownershipVersion}`, not usable directory or permission details.
4. **No search controller/server plaintext search.** Implement local search over the verified, decrypted visible records loaded by the UI. State its scope clearly; do not promise a complete workspace result before all visible projects load. Include a route to open each result. Clear the index on sign-out, workspace change, or access invalidation. Comments can be searched only after their relevant feeds have loaded.
5. **Live refresh is reporting-specific.** `reporting.watch()` refreshes progress, not the separately rendered planning graph or comment feed. A UI refresh coordinator must reread current planning, discussions, project directory and Inbox on relevant notices/focus/explicit refresh. It must not overwrite an open edit form. The existing `HttpLiveSource`/`LiveRefreshController` implementation can be reused internally, with bounded refreshes and cleanup.
6. **No team delete/archive operation.** Current team API supports create/edit/list/history only. Offer those; do not render dead delete/archive controls.
7. **No task deletion, drag-and-drop generic status setter, comment editing/unhide, attachments, mentions, email, or recurrence.** Work transitions are explicit actions. These features should not be fabricated in the UI. Task cancellation and restoration are implemented; project and wave archive/unarchive are implemented.
8. **No workspace renaming or multi-workspace server list in this domain.** Workspace selection must come from identity/remembered profiles and a verified workspace reader being audited separately.

The docs `work-protocol.md`, `collaboration-protocol.md`, and `reporting-protocol.md` contain historical checkpoint prose/examples. Current source supersedes examples that omit required `reviewed` pins or say reporting/Inbox retries are memory-only. Current reporting/Inbox request stores are durable and confirmed sign-out clears pending business writes.

## Shared write contract

Every business form should create an explicit `operationId = crypto.randomUUID()` before invoking a write, retain it in component state while the outcome is unknown, disable double submission, and present success only after a verified completed result. Controllers persist exact encrypted requests before transmitting.

- `controller.pending()` discovers retained operations, while `controller.resume(operationId)` resolves the exact prior request. Several stores keep completed operation records as well; a pending list is not necessarily a list of unsaved work. Resolve before labeling an operation as failed.
- An uncertain reply becomes **“Checking your save”**, with an explicit **Check again** action. Do not create a second write with a new ID until the prior result is resolved.
- Every existing-target planning write needs the `pin` from the user's reviewed `planning.read(projectId)`: `planning.execute({projectId, reviewed: view.pin, command, content?, outcome?, operationId})`.
- A changed record throws `WriteConflict` with `operationId`, freshly verified `current`, and in-memory `unsaved` input. Show **“This changed while you were editing”**, allow reviewing current content and reapplying with a **new** operation ID and the new pin. Do not silently merge or overwrite.
- Creation actions (`create_phase`, `create_milestone`, `create_task`, `create_blocker`) do not need an existing-target reviewed pin, but still enforce current scope rules.
- `OFFLINE` blocks saves before a request is queued. Keep input in memory, show **“You're offline. Reconnect to save.”**, and offer manual retry. No background write loop or durable plaintext draft is implemented.
- Map `AUTH_REQUIRED` to sign-in; `RESTRICTED` to a customer-readable read-only workspace message; `UPDATE_REQUIRED` to app update/resume workflow; `NOT_FOUND` to unavailable content with navigation back; `CANCELLED` from navigation/auth cleanup should not produce alarming errors. Never expose raw server messages, cryptography terminology, request IDs, or stack traces in normal customer flows.
- Controllers cancel on authentication clear. Confirmed logout clears pending business requests and usable private state; a failed sign-out keeps encrypted requests available for later resolution. `openClient().close()` signs out, so do not call it merely when switching React routes.

## Project discovery and project creation

Raw discovery route:

```ts
GET /v1/workspaces/:workspaceId/projects?limit=50&after=<id>&includeArchived=false
// {records: encrypted DB rows[], nextCursor: string|null,
//  dataGeneration: string, securityHead: string}
```

Direct detail and child transport routes also exist, but return encrypted records:

```ts
GET /v1/workspaces/:workspaceId/projects/:projectId
GET /v1/workspaces/:workspaceId/projects/:projectId/records/:kind
// kind = phases|milestones|tasks|blockers|comments|updates
```

Only project lists and phase lists accept `includeArchived`. Comments/updates omit hidden entries. Each route rechecks current person and device access. The complete planning controller remains readable for an archived project.

```ts
const made = await client.projectCreation.create({name, projectId?, operationId?});
// {operationId, projectId, state:'completed'|'finishing', receipt}
await client.projectCreation.resume(operationId); // same result shape
await client.projectCreation.pending();
```

Only active Owners may create projects. A name is the only required input; result starts Planned and provisions all active Owners before the project becomes available. Ordinary members receive no automatic project access. If `finishing`, stay on a finishing screen with a bounded/manual check; do not open a presumed ready project or recreate it. Transport is `/v1/work/projects/create/{context,stage,finalize,status,history}`.

The project UI journey is: empty Projects view → **New project** → name → verified creation → project Overview → optional description, dates, responsible person and team → add waves/milestones/tasks → **Start project** → active delivery → completion/cancellation summary → archive → Archived filter → unarchive → reopen if further work is needed.

## Verified project view

```ts
const view = await client.planning.read(projectId);
// ReadablePlanning:
// {graph, records, pin, outcomes, audits, authority}
```

`graph` contains `project`, `phases[]`, `milestones[]`, `tasks[]`, optional `blockers[]`, `snapshots[]`, and `movements[]`. Join each business record to `records` by `kind` and `id`. A record is `{kind,id,revision,contentRevision?,envelopeRevision?,content:Record<string,unknown>}`.

- Project: `{workspaceId,id,revision,state,archived,phaseLabel:'phase'|'wave',managerProfileId,teamId,reviewEnabled?,reviewPolicyRevision?}`.
- Wave: `{workspaceId,projectId,id,revision,state,archived,displayOrder,leadProfileId}`.
- Milestone: `{workspaceId,projectId,id,revision,state:'open'|'accepted'|'cancelled',phaseId,ownerProfileId}`.
- Task: `{workspaceId,projectId,id,revision,state:'todo'|'in_progress'|'review'|'done'|'cancelled',phaseId,milestoneId,assigneeIds[],leadProfileId,contentRevision?,teamId?,reviewerProfileId?,submittedRevision?,submittedPolicyRevision?,approvalOperationId?}`.
- Blocker: `{workspaceId,projectId,id,revision,taskId,contentRevision,state:'open'|'resolved',responsibleProfileId,createdBy,createdAt,resolvedBy,resolvedAt}`.
- Project/wave state is `planned|active|complete|cancelled`.
- `outcomes` are `{id,text}[]`. `audits` include actor, signed date, action, changed before/after private content, optional closing snapshot content and original closing settings. The new `audit.outcome: string | null` is matched to that audit’s already verified mutation outcome ID, so reasons remain attached to the correct action. Show readable activity descriptions, never raw JSON.
- `pin = {workspaceId,projectId,dataGeneration,version,head}` is internal state for safe edits, never customer copy.

Private forms accept these fields. An edit's `content` **replaces** that record's complete private content; merge unchanged fields from the reviewed record before submitting:

| Record | Content fields |
| --- | --- |
| Project | `name`, optional `description`, `startDate`, `dueDate` |
| Wave | `name`, `objective`, `completionCriteria`, optional `startDate`, `dueDate` |
| Milestone | `name`, optional `dueDate` |
| Task | `title`, `description`, `acceptanceCriteria`, optional `startDate`, `dueDate`, `priority:'low'|'normal'|'high'` |
| Blocker | required `reason`, required `nextAction` |

Names/titles are trimmed, 1–240 characters; long text fields max 20,000. Dates are `YYYY-MM-DD`, and start must not follow due. An absent date should remain absent rather than an empty string. Shared tasks count once. Naming a manager, lead, reviewer, responsible person or team does not confer project access.

## Planning action inventory

All rows use `client.planning.execute({projectId, reviewed: view.pin, command, content?, outcome?, operationId})`; creations may omit `reviewed`. Returns `{state:'completed',operationId,projectId,receipt}`. Commands below exclude internal `expected`/operation fields that the controller constructs.

| Customer action | Command and companion fields |
| --- | --- |
| Edit project | `{action:'edit_project',patch:{phaseLabel?,managerProfileId?,teamId?}}`; complete project `content` if editing it |
| Start/reopen/archive/unarchive project | `{action:'start_project'|'reopen_project'|'archive_project'|'unarchive_project'}` |
| Complete/cancel project | `{action:'complete_project'|'cancel_project'}` plus required `outcome` |
| Add wave | `{action:'create_phase',phase:{id,displayOrder,leadProfileId}}` plus wave `content` |
| Edit wave | `{action:'edit_phase',phaseId,patch:{displayOrder?,leadProfileId?}}` plus optional complete `content` |
| Start/reopen/archive/unarchive wave | `{action:'start_phase'|'reopen_phase'|'archive_phase'|'unarchive_phase',phaseId}` |
| Complete wave | `{action:'complete_phase',phaseId}` plus `outcome` |
| Cancel wave | `{action:'cancel_phase',phaseId,tasks:[{taskId,action:'cancel'} or {taskId,action:'move',phaseId,milestoneId}],milestones:[{milestoneId,action:'cancel'} or {milestoneId,action:'move',phaseId}]}` plus `outcome`; lists must completely resolve unfinished children |
| Add milestone | `{action:'create_milestone',milestone:{id,phaseId,ownerProfileId}}` plus milestone `content` |
| Edit milestone | `{action:'edit_milestone',milestoneId,patch:{phaseId?,ownerProfileId?}}` plus optional complete `content` |
| Accept/cancel milestone | `{action:'accept_milestone'|'cancel_milestone',milestoneId}` plus `outcome` |
| Reopen milestone | `{action:'reopen_milestone',milestoneId}` |
| Move shared task | `{action:'carry_task',taskId,phaseId,milestoneId}` plus required `outcome` |

Project cancellation uses the defined cascade; phase cancellation requires explicit complete dispositions. Show what will be cancelled/moved before confirmation. Completion checks unfinished work (including work outside waves) and unaccepted milestones. An empty milestone may be manually accepted. Waves can overlap and are started manually. Only terminal project/wave scopes can be archived; unarchive then reopen before business editing. Reopening a cancelled parent does not automatically restore children. Old closures and outcomes remain readable history.

## Task delivery, shared assignment, review and blockers

```ts
const created = await client.planning.createTask({
  projectId, title, taskId?, operationId?, description?, acceptanceCriteria?,
  startDate?, dueDate?, priority?, assigneeIds?, leadProfileId?,
  phaseId?, milestoneId?, teamId?, reviewerProfileId?
});
// {state:'completed',operationId,projectId,taskId,receipt}
```

Managers can create unassigned or multi-assignee tasks; absent assignees means unassigned. Eligible ordinary creators default to themselves and may create only self-assigned tasks. Lead must be among assignees. One shared task has one status, discussion and acceptance outcome.

| Customer action | Planning command and companion fields |
| --- | --- |
| Edit task | `{action:'edit_task',taskId}` with complete task `content` |
| Change assignees | `{action:'assign_task',taskId,assigneeIds,leadProfileId,teamId}`; complete intended arrays/nulls |
| Start / move back to To do | `{action:'start_task'|'set_task_todo',taskId}` |
| Finish / send for review | `{action:'request_task_completion',taskId,acceptanceConfirmed:true}` |
| Choose reviewer | `{action:'select_task_reviewer',taskId,reviewerProfileId}` |
| Approve | `{action:'approve_task',taskId,submittedRevision,submittedPolicyRevision}` from the exact reviewed task |
| Request changes / cancel / reopen / restore | `{action:'reject_task'|'cancel_task'|'reopen_task'|'restore_task',taskId}` plus `outcome` |
| Turn project review on/off | `{action:'set_project_review',enabled,reviewers:[{taskId,reviewerProfileId}]}` plus policy-change `outcome` |
| Add blocker | `{action:'create_blocker',blocker:{id,taskId,responsibleProfileId}}` plus blocker `content` |
| Edit blocker | `{action:'edit_blocker',blockerId,responsibleProfileId}` plus complete blocker `content` |
| Resolve/reopen blocker | `{action:'resolve_blocker'|'reopen_blocker',blockerId}` plus `outcome` |

The task flow is To do → In progress → Done (review off) or In review → Approved/Done or Request changes/In progress (review on). Execution needs an Active project and containing wave. A To do task may be prepared under planned parents, but cannot be started until parents are active. Any open blocker prevents completion. Present a link to each blocking item and a path to resolve it.

Project review starts off. Only an Owner changes it. Enabling must supply an eligible independent reviewer for every unfinished task; disabling supplies an empty reviewer list and returns pending review to In progress. An assignee cannot approve their own shared task. Task content/assignment edits invalidate submitted review. Missing reviewer is an explicit state with a select-reviewer path. Reopening a Done task or restoring a Cancelled task requires a reason and reopens any previously accepted linked milestone. Cancelled task blockers remain history and become relevant again on restoration.

The frontend should use the verified current permissions plus actual task/lifecycle gates. Fixed permissions are `read_project`, `comment`, `create_tasks`, `edit_assigned_tasks`, `manage_tasks`, `approve_tasks`, `plan_projects`. Default roles: Owner and Manager all seven; Member read/comment/create/self-assigned-edit; Viewer read only. Owner-only project creation/access/role/people management remains separate even though Manager has all business permissions. `src/shared/permissions.ts` exposes the tested pure `decidePermission` policy; it does not replace lifecycle checks or server enforcement.

## Comments, updates and activity

```ts
await client.collaboration.postComment({projectId,taskId,text,entryId?,operationId?});
await client.collaboration.postUpdate({projectId,phaseId?,text,entryId?,operationId?});
// both -> {state:'completed',operationId,projectId,entryId,kind,receipt}
const page = await client.collaboration.read({projectId,kind:'comment'|'update',
  taskId?,phaseId?,includeHidden?,after?,anchor?,limit?});
// {records:ReadableCollaborationEntry[],anchor,nextCursor,complete}
const entry = await client.collaboration.history({projectId,entryId,kind});
await client.collaboration.hide({projectId,entryId,kind,reason,
  reviewed:{revision:entry.pin.revision,head:entry.pin.head},operationId?});
```

A readable entry includes private `text`, `pin`, `moderation:{actorId,at,reason}|null` and metadata such as `entryId`, project/task/phase references, author and creation time, hidden state and revision. Display verified text using normal text rendering, not HTML. Corrections are new posts. There is no edit or unhide action.

Maintain the page `anchor` while following `nextCursor`. A changed feed means refresh from page one rather than combining inconsistent pages. Independent post IDs let simultaneous comments coexist. Moving a task retains its comments. Posting requires comment permission and an editable parent; terminal task/wave/project or archived scope rejects new posts. Moderation remains available in closed/archived scopes to task managers (comments) or planners (updates). Hiding retains the original and reason in authorised history. Transport: `/v1/collaboration/{context,save,status,list,history}`.

## Inbox

```ts
const page = await client.inbox.list({after?,limit?,unreadOnly?});
// {records:[{id,revision,readAt,createdAt,eventType,projectId,recordId,unavailable}],
//  nextCursor,dataGeneration,securityHead,securityVersion}
const notice = await client.inbox.resolve(notificationId); // same notice shape
await client.inbox.setRead([{id,expectedRevision}], true /* or false */, operationId?);
const p = await client.inbox.preference(projectId); // {projectId,muted,revision}
await client.inbox.setProjectMuted(projectId, true /* or false */, p.revision, operationId?);
```

Inbox rows carry opaque references, never decrypted message previews. Resolve current access, then load content through verified planning/discussion readers before displaying a title or navigating. Inaccessible items return `unavailable:true`, generic event text, and null content references; offer marking read and returning to Inbox. Avoid a broken link. Access/recovery/ownership notices lead to appropriate account settings, and ordinary project notices to project/task detail. Muting silences ordinary project notices while important access notices remain. No email controls.

List pages default 50, maximum 100. `setRead` accepts 1–100 exact record revisions. Read/mute conflicts need reload. Transport: `/v1/inbox/{context,save,status,list,resolve,preference}`. Worker delivery can lag behind a successful business write; do not make the saved task appear failed because its notice is not yet present.

## Teams

```ts
await client.teams.create({name,description?,memberIds?,operationId?,teamId?});
await client.teams.edit({teamId,expectedRevision,name,description?,memberIds?,operationId?});
// -> {operationId,teamId,state:'completed',receipt}
const page = await client.teams.list({after?,limit?});
// {records:[{teamId,revision,name,description,memberIds}],nextCursor,
//  securityHead,securityVersion,dataGeneration}
const history = await client.teams.history(teamId);
// {workspaceId,teamId,anchor,records:[{revision,operationId,actorId,deviceId,
// action,signedAt,serverRecordedAt,before,after}]}
```

Only active Owners create/edit teams. Current approved workspace readers can list them. Editing supplies the expected reviewed revision and complete intended membership/content. Teams organise people; adding a person does not grant project access. Team history preserves membership and content before/after; older changes may have `signedAt:null`, so use the recorded timestamp honestly. Transport: `/v1/work/teams/{context,save,status,list,history}`.

## Progress and reporting

```ts
const scope = {kind:'project',projectId};
const calculated = await client.reporting.calculate(scope);
const cached = await client.reporting.read(scope);
await client.reporting.publish(scope,operationId?);
const settings = await client.reporting.settings();
await client.reporting.setTimezone(timezone,settings.pin,operationId?);
const watcher = client.reporting.watch(scope,state => render(state));
watcher.setVisible(boolean); watcher.refocus(); watcher.relevantWrite(); watcher.stop();
```

Scopes: `{kind:'project',projectId}`, `{kind:'phase'|'milestone',projectId,id}`, `{kind:'filtered',projectId,taskIds}`, `{kind:'visible_projects',projectIds}`, `{kind:'team',teamId,projectIds}`. Multi-project requests max 16 explicitly visible projects. Never silently truncate or include hidden counts.

`ReadableReporting = {status:'current'|'last-calculated'|'missing',scope,asOfUtc,timezone,localDate,nextMidnightUtc,components:[{projectId,result}],aggregate,planningPins,settingsPin}`.

Each result includes `progress:{taskCount,nonCancelledTaskCount,doneTaskCount,unfinishedTaskCount,cancelledTaskCount,percentage,emptyLabel}`, `awaitingAcceptance`, `lifecycle`, `archived`, `health`, `reasons`, `signals` (overdue, missing dates, blocked tasks/open blockers), inherited `deadlines`, blocker ages/missing responsible people, `nextMilestone`, original closing snapshot/settings, and warnings for dates outside parent boundaries.

Map health to natural copy: `on_track` → On track, `at_risk` → Needs attention, `delayed` → Behind schedule, `not_enough_information` → More information needed, `terminal` → use the actual Complete/Cancelled state. No work planned is not 0% failed work; percentage can be null. Shared tasks are counted once, cancelled work excluded from denominator, and incomplete work cannot round to 100%. Completion awaits milestone acceptance independently of task percentage.

All permitted readers calculate locally. Publishing requires planner permission in every selected project; normal customers need not see a technical Publish cache action. Owners alone change workspace timezone, using the reviewed settings pin. Do not shift entered dates when timezone changes.

`ReportingLiveState` extends `{status:'unavailable'|'last-known'|'current',value,asOfUtc,reason}` with `currentHealth` and `lastCalculated`. Current `value` exists only for current results. Render last-known status honestly while disconnected, with refresh/reconnect path. `watch` consumes authenticated metadata-only SSE, stops hidden refresh, invalidates on relevant local writes/focus/midnight, and has a 60-second fallback. It does not establish that a separately loaded task list is fresh.

Transport: `/v1/reporting/{settings,settings/context,settings/save,settings/status,context,publish,status,read}` and POST `/v1/work/live`.

## Closed-loop screen inventory

- Home: current visible work summary, My tasks, tasks awaiting the current person's review, blocker attention, next milestones; genuine empty/loading/access/error states and links to each item.
- Projects: active/planned/complete filters, Archived filter, search, create (Owner), project cards → overview; pagination and partial-load messages.
- Navigation has exactly four primary items: Home, Projects, My work, Inbox. Teams, people and permissions live in workspace settings.
- Project tabs are Overview, Work, Timeline, Updates. Work shows a task list grouped by wave, milestone, team or status; a board is future work. Timeline shows only wave date ranges and milestone markers. Activity and project settings are secondary detail views. Each state transition uses its defined action and returns to a refreshed project.
- Wave: objective, dates, completion criteria, task list, milestone list, updates, Start/Complete/Cancel; cancellation resolves every unfinished child; archive/reopen history is reachable.
- Task detail: title, description, acceptance criteria, assignees/lead, reviewer, team, dates/priority, wave/milestone, progress actions, blockers, discussion, activity; closes back to its originating list. Terminal states show reason/history and only valid reopen/restore actions.
- Review: exact submitted task, acceptance confirmation, Approve/Request changes; reviewer unavailable path; invalidated review refreshes instead of retaining stale approval controls.
- Milestone: linked tasks, due date, responsible person, Open/Accept/Cancel/Reopen, outcome history; automatic reopen reflected after reopened/moved work.
- Inbox: all/unread, mark read/unread, load more, current-reference resolution, accessible destination, generic unavailable receipt; project mute in its notification settings.
- Teams: list → create/edit (Owner) → member selection → save → readable history, plus projects/tasks explicitly designated to that team.
- Search: local verified scope, keyboard navigation, clear query, empty result explanation, each result opens real content.
- Pending saves: retained request review and explicit check; success navigates to the actual result; stale state offers review/reapply; sign-out behavior clear.
- All screens: light/dark tokens, keyboard focus, reduced-motion behavior, accessible labels, helpful empty states, no raw technical/debug/status vocabulary, no fake counts/charts/success notifications, and no decorative controls without a working action.

## Existing browser evidence to preserve while adding UI

These files contain actual backend-bound browser/Worker journeys, not UI screens. Use them as API examples, and add real product-screen tests for the new frontend without removing them:

- `test/browser/project-create.spec.ts`: both Owners gain access, ordinary member does not, interrupted finalisation resumes exactly once, restricted workspace denies writes.
- `test/browser/planning.spec.ts`: completion snapshots, archive/reopen, uncertain saves, stale drafts, shared task carry and phase cancellation.
- `test/browser/task-workflow.spec.ts`: title-only defaults, shared assignment, parent gates, multiple blockers, independent review/rejection/resubmission, approval invalidation.
- `test/browser/collaboration.spec.ts`: concurrent comments, moved tasks, scoped moderation, archive history, interrupted post recovery.
- `test/browser/reporting.spec.ts` and `progress.spec.ts`: shared work counted once, private calculations, SSE, hidden results, dates and timezone boundaries.
- `test/browser/teams.spec.ts`: team create/edit/read/history, privacy and no automatic access grant.
- `test/browser/retry.spec.ts`: two assignees' conflicting edits, durable reporting/Inbox retries, successful vs failed sign-out cleanup.
- `test/browser/core-journey.spec.ts`: iterative delivery through device approval, member reset, Owner recovery and removal.

Complete graph limits remain explicit: 2,000 current records, 512 planning operations, 16 MiB planning context. The UI must show a plain, useful limit message and path back, never silently clip work or spin indefinitely.


## Implemented product screens and bounded extensions

The work area is implemented in `frontend/work/index.tsx`, `project.tsx`, `task.tsx`, `forms.tsx`, `discussion.tsx`, and `shared.tsx`. It consumes the shared verified directory and planning graphs, keeps decrypted presentation data in memory, and uses existing controllers for all reads and writes. Four primary destinations and four project tabs follow the architecture. No email, board, upload, connector, recurring-work, or customer-worker features are introduced.

- Planning authority is exposed only after verification, including eligible shared assignees and independent reviewers. Forms hold their reviewed planning pin until the user explicitly acknowledges conflicting current content. Unsaved input stays present.
- Exact unknown saves resume their original encrypted operation. A `finishing` project remains on an explicit **Check progress** path; it never closes or announces completion until its verified result says completed. Completion callbacks remain attached to retries, so comments, moderation, Inbox flags and mute preferences refresh correctly.
- Optional `collaboration.read({..., includeHidden: true})` is a bounded, current-authorized history listing. It uses the same project read authorization as existing individual history reads; hidden originals and moderation remain verified. The page anchor binds the flag. Ordinary feed behavior is unchanged. Existing 100-entry page, 10,000-entry feed, and encrypted byte limits remain enforced. The frontend presents **Include hidden history** and a clear return to the ordinary feed.
- Comments and updates refresh on focus and a visible 60-second fallback. Scope changes discard out-of-date asynchronous responses. Planning graphs refresh through the shared shell and project lifecycle; reporting uses the actual reporting watcher and exposes last-known status honestly.
- Verified read-only workspace states disable ordinary work writes. Owner recovery, restoration, maintenance and deletion controls remain in the separately scoped settings area.
- Activity exposes readable action labels, private changes and exact outcome reasons, including blockers attached to a task. Neither internal IDs nor raw objects are product content.

Source verification: backend TypeScript and web TypeScript completed successfully. Nine planning/workflow client tests passed, including forged-authority rejection and reason association. Four collaboration client tests passed, including explicit retained history and rejection of hidden entries injected into an ordinary feed. Logs are `test-results/frontend-work-source-build.log`, `frontend-work-typecheck.log`, `frontend-work-authority-tests.log`, and `frontend-work-collaboration-tests.log`.

`test/frontend/work.spec.ts` adds actual product-screen journeys: project/wave/task/blocker lifecycle, dropped comment response and exact retry, hidden history after reload, milestone acceptance, update posting, completion/archive/unarchive/reopen, real progress, shared assignees, independent review/rejection/resubmission, and Inbox navigation/read flags/mute. It uses real UI invitations and a fixture-scoped call to the production notification delivery job, not fabricated notifications. Browser and database-backed test execution is centrally serialized; source construction alone is not passing browser evidence.

## Delivered work UI and current browser evidence

The customer frontend now connects the verified directory, planning, collaboration, reporting and Inbox controllers through Home, Projects, My work and Inbox. Project views expose Overview, Work, Timeline and Updates; lifecycle actions, shared assignees, independent review, blockers, milestones, retained history and exact retry flows use the existing controller contracts. My work filters are part of the browser route, so Back restores both the visible tasks and selected tab.

The initial Chromium integration run is retained in `test-results/frontend-work-chromium-initial.log` and `test-results/frontend-work-chromium-initial-results.json`. Its complete project lifecycle passed, including a confirmed project save whose next refresh loses its reply, exact comment retry without duplication, blocker resolution, hidden history, wave and milestone completion, archive/unarchive, reload and calculated progress. The three-person journey reached shared task completion through rejection and resubmission, and verified the My work Back behavior. It then exposed an Inbox read-filter race: a delayed mark-read callback refreshed the previously selected All filter after the person selected Unread.

The Inbox read path now uses the current filter and rejects superseded read responses. The regression test deliberately delays the real mark-read reply until after the filter switch. The release run below verifies this repair; the initial failure remains preserved and is not counted as a pass. The initial TLS harness reached the real API directly; final browser evidence must include the packaged frontend proxy before release.

The first proxy-inclusive matrix, retained as `test-results/frontend-work-final-results.json` and `frontend-work-final.log`, produced one pass, three failures and two intentional skips. Chromium's core project journey and dark palette assertions passed. The shared journey proved the Inbox filter repair, then exposed an inverted individual read/unread target. Firefox and WebKit completed the work mutations and history, but their final overview calculation remained blank.

A bounded Firefox diagnostic established that the reporting calculation itself succeeded while its value was discarded after a failed live connection (`frontend-work-report-diagnostic.log`). A separate two-engine request comparison passed both cases and proved that the page's `no-referrer` policy caused `ORIGIN_REJECTED`, while `strict-origin` reached the ordinary strict request validation (`frontend-live-origin-diagnostic-results.json`). The live transport now uses the same explicit referrer policy as authenticated requests; Origin and CSRF checks remain unchanged. Individual Inbox actions now request the opposite read state. Overview now presents an explicit Refresh progress action after a failed calculation. The release verification below now confirms these repairs.

Five settled safe screenshots are retained in `test-results/frontend-review/work-final/`. Desktop Work and Overview were visually inspected in light and dark modes, as was Work at a 390-pixel viewport. The charcoal canvas and surfaces match their exact computed-color assertions, and mobile tasks use the compact row layout without the prior excessive vertical stacking. The final release run replaced these screenshots after the small neutral overlay cleanup.

## Final work release verification

The final packaged image `sha256:8662e0ab1d3d40942670663a0c0eaef66aa282c549fc9a1f71e0c802caa1f543` passed all four executed Work cases on 27 September 2026. Every browser request used the packaged Next proxy and the real fixture API/database. No browser retries were enabled. The two non-Chromium three-person cases are explicit intentional skips, not passes.

| Journey | Browser | Result | Duration |
| --- | --- | --- | --- |
| Project lifecycle, waves, tasks, blockers, history, milestones, archive, reload and report retry | Chromium | Passed | 54.1 seconds |
| Two shared assignees, independent review, Inbox, browser Back and persistence | Chromium | Passed | 69.4 seconds |
| Project lifecycle, waves, tasks, blockers, history, milestones, archive, reload and report retry | Firefox | Passed | 58.1 seconds |
| Project lifecycle, waves, tasks, blockers, history, milestones, archive, reload and report retry | WebKit | Passed | 55.0 seconds |

The core cases prove the explicit recovery path after a real report request is held unavailable: Refresh progress becomes visible, the person retries, the real verified calculation returns 100%, and the unavailable notice clears. The shared journey proves that a delayed mark-read acknowledgement cannot restore the wrong filter, that an individual read item can be marked unread, and that two assignees work on the same task while an independent reviewer requests changes and approves the resubmission. It also checks Inbox links, notification preferences and a subsequent sign-in. Earlier failures are retained as diagnostic history.

Authoritative evidence is `test-results/frontend-work-release-repair-results.json` with its matching `.log`. The four distinct passed cases, two explicit skips, image identity, source hashes and screenshot hashes are indexed in `test-results/frontend-work-release-index.json`. All five final-image screenshots in `test-results/frontend-review/work-final/` were visually inspected: desktop Work and Overview in light/dark, plus compact Work at 390 pixels. Exact dark canvas/sidebar color assertions also passed. Fixture servers were closed and ports 3555/3556 released after the run.

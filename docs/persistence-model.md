# Application persistence contract

The application schema is defined by [001_core.sql](../migrations/application/001_core.sql). It stores permitted relationship/status metadata and encrypted business envelopes. It is not the authoritative identity/security control store, an authentication implementation, or proof that an encrypted payload is valid.

## Context and database roles

The migration runner applies the SQL as a separate migration role, then explicitly grants the limited runtime role schema usage, required table operations, and helper-function execution. PUBLIC has no schema, table, sequence, or function privileges. Runtime roles must not own schema objects, be members of the migration role, disable triggers, or have BYPASSRLS/superuser privileges.

Every tenant-owned table created by this migration enables and forces RLS. The trusted server opens a transaction and uses transaction-local `ukda.workspace_id` and `ukda.profile_id` settings only after verifying current identity, authority, and the protected-data fence. SQL clients must never derive these settings directly from unverified request headers or body values. Missing or empty workspace context matches no tenant. A malformed UUID context fails rather than falling back to another scope.

`app.current_workspace_id()` and `app.current_profile_id()` return the current UUID contexts. `app.can_read_project(project_id)` requires an Active profile, Active project-access projection, and a scoped role containing `read_project` in the current workspace. Owners also require provisioned access and that read capability; their `is_owner` flag is not a SQL project-visibility bypass. Project access represents completed permission/key provisioning; APIs separately check each action's fixed permission. Profiles, grants, roles, teams, workspace state, and internal outbox records use workspace-only policies so the helper does not recursively query its own project policy.

Business project tables use workspace plus project-access policies. Receipts are additionally actor-scoped, preferences are recipient/project-scoped, and notifications are recipient-scoped. Notification rows contain opaque metadata only; fetching referenced content still requires current project access. A generic access-removal notice remains readable without the removed project's content.

Deferred constraint triggers execute as the migration role with a fixed `pg_catalog` search path and qualified table names. A migration-role-only SELECT policy, still workspace-bound, lets these integrity checks find assignments and tasks after access is removed in the same transaction. It does not grant ordinary runtime INSERT/UPDATE/DELETE privileges or Owner-profile access to unprovisioned projects. Trigger functions cannot be called as ordinary data-returning functions.

## Columns and table ownership

Entity identifiers are UUIDs. Tenant identity is always `workspace_id`; foreign keys include it and include `project_id` when the referenced record must belong to the same project. Relationship tables use composite keys. Mutable `revision` and epoch/generation counters are positive PostgreSQL bigint values; the security projection alone permits version zero before activation. Serialize counters as decimal strings at API boundaries rather than JavaScript numbers. Revisions and timestamps are updated by explicit server operations, not by arbitrary ciphertext contents.

Encrypted content records use `encrypted_envelope jsonb`, checked to be an object. Most have `schema_version`, `key_epoch`, `revision`, `created_at`, and `updated_at`. Names, titles, display labels, descriptions, due/start/end dates, objectives, acceptance conditions, comment/update text, blocker reason/next action, moderation reason, and sensitive audit values remain inside the envelope. SQL does not inspect those facts or verify ciphertext/signatures. Later security/domain modules must validate the signed envelope and authorised transition before persistence.

| Table | Identity and main metadata |
| --- | --- |
| `workspaces` | `workspace_id` PK; `security_head`, `security_version`, `data_generation`, `write_schema`, `fence_closed` (true by default); projected `lifecycle`, `licence_state`, `content_maintenance`, `restore_quarantine`; encrypted workspace content |
| `profiles` | `(workspace_id,id)`; `state` pending/active/suspended/removed, `is_owner`; encrypted display/profile content; no passwords or device private keys |
| `roles` | `(workspace_id,id)`; public `template` owner/manager/member/viewer/custom, fixed `permissions text[]`; encrypted custom label; template alone grants no Owner authority |
| `teams` | `(workspace_id,id)`; encrypted team content |
| `team_members` | `(workspace_id,team_id,profile_id)`; membership does not create project access |
| `projects` | `(workspace_id,id)`; `state` planned/active/complete/cancelled, `archived`, `phase_label` phase/wave, optional `manager_profile_id`, `team_id` |
| `project_access` | `(workspace_id,project_id,profile_id)`; required `role_id`, `state` pending/active/revoked, revision/times; Owners also receive an explicit Owner-template grant |
| `project_phases` | `(workspace_id,id)` and unique `(workspace_id,project_id,id)`; project, planned/active/complete/cancelled `state`, `archived`, `display_order`, optional `lead_profile_id` |
| `milestones` | `(workspace_id,id)` and unique project key; optional `phase_id`, `owner_profile_id`; `state` open/accepted/cancelled |
| `tasks` | `(workspace_id,id)` and unique project key; optional `phase_id`, `milestone_id`, `team_id`, `lead_profile_id`, `reviewer_profile_id`, `submitted_revision`; `state` todo/in_progress/review/done/cancelled |
| `task_assignments` | `(workspace_id,task_id,member_id)`; `project_id`, `assigned_by`, `assigned_at`, revision; `member_id` references a profile |
| `blockers` | `(workspace_id,id)`; project/task, optional `responsible_profile_id`, `created_by`, optional `resolved_by`/`resolved_at`, open/resolved `state`; reason/next action/outcome encrypted |
| `comments` | `(workspace_id,id)`; project/task, `author_profile_id`, `hidden`, moderation actor/time; original and correction bodies are separate records |
| `updates` | `(workspace_id,id)`; project, optional phase, author/moderation metadata; encrypted plain-text update |
| `record_versions` | `(workspace_id,id)` plus unique `(workspace_id,record_type,record_id,record_revision)`; optional project, actor, operation, immutable encrypted historical envelope |
| `audit_events` | `(workspace_id,id)`; optional project/actor/record, operation, static action/type identifiers, immutable encrypted business evidence |
| `notifications` | `(workspace_id,id)` plus recipient/event uniqueness; recipient, optional project/record, event type, `read_at`; no plaintext content payload |
| `notification_preferences` | `(workspace_id,id)` plus profile/project uniqueness; `muted`, revision/times |
| `summaries` | `(workspace_id,id)`; project, scope kind/id/fingerprint, permission/source revisions, calculation version/actor/time/completeness, encrypted source/timezone/filter/provenance detail |
| `operation_receipts` | `(workspace_id,id)` plus `(workspace_id,data_generation,operation_id)` uniqueness; actor, optional project, static action, request digest, immutable encrypted result |
| `outbox` | `(workspace_id,id)` plus generation/deduplication uniqueness; operation, optional project, event type, pending/processing/complete/failed state, attempts, limit, available time, encrypted payload |

Stored shared summaries are project-scoped. Team and cross-project views can combine authorised project inputs locally; no broader persisted summary may be used to bypass individual project access. Scope fingerprints include filters and authorisation scope; the complete signed source manifest remains in the encrypted envelope. The API must validate actual referenced scope identifiers rather than treating generic UUID/type pairs as foreign keys.

Workspace restriction fields are projections for the fence comparison; authoritative control-store state decides whether an operation is currently allowed. Lifecycle values are pending_activation/active/pending_deletion/deleted, with pending_activation the default. Licence values are active/restricted/revoked, with active the default. Before activation, `security_version` is zero, `security_head` is sixty-four zeroes, and the fence remains closed; heads must be sixty-four lowercase hexadecimal characters. These fields must never independently re-enable a restricted, quarantined, deleted, or unprojected workspace.

## Deferred structural invariants

- A task has one project, at most one current phase and milestone, and one assignment per member. Its optional lead references one of those assignments through a deferred composite FK.
- Assignments reference the same task/project/workspace, an existing profile and scoped access row, and an assigning profile in that workspace. Deferred triggers require the final assigned profile and grant to be Active and the granted role to contain `read_project`.
- Profile-state, project-access, and role-permission changes also validate outstanding assignments. Revocation therefore clears affected assignments/lead in the same transaction; an archived scope is not an exception to this structural integrity requirement.
- A milestone belongs to its project and optionally one phase. If that phase is set, all tasks linked to the milestone must be in that phase. Both task edits and milestone edits validate the final transaction state.
- Deferred FKs permit atomic carry-forward, milestone moves, lead replacement, assignment cleanup, and access changes without an invalid intermediate statement becoming the final stored state. Use `SET CONSTRAINTS ALL IMMEDIATE` in a test/transaction when checking its final invariants before commit.
- Project creation can provision Active access rows before inserting the project in the same deferred-FK transaction, after the security operation has prepared the required envelopes. This gives the subsequent project insert its scoped RLS permission. No partially committed grant/project is permitted.
- Archive checks allow only complete/cancelled projects/phases. Further lifecycle/approval/blocker/business checks belong to the domain operation and signed-transition validation; the database cannot infer encrypted acceptance criteria.

Constraint-trigger violations use SQLSTATE `23514`; ordinary foreign-key/uniqueness failures retain PostgreSQL's standard codes. Messages are static and do not interpolate project content. APIs map them to the agreed safe error format.

## History, receipts, and retention

`record_versions`, `audit_events`, and `operation_receipts` reject UPDATE and DELETE with SQLSTATE `55000`. The normal runtime must have no TRUNCATE or trigger-management grant. Corrections append new evidence; newer mutable business versions do not rewrite original signed ciphertext.

An authorised whole-workspace purge is a later operational mechanism, not a runtime workaround. It must enforce the authoritative deletion tombstone/fence, use the separately privileged maintenance identity, remove dependent records atomically, and explicitly manage the immutable-history triggers under that privilege. Do not add a client-settable context flag that disables immutability. Preserved backups and irreversible tombstones follow checkpoint 12.

Business writes commit changed records, record versions, audit entries, receipt, and outbox entries in the same application-database transaction. Stable generation-bound receipt/outbox identities support retries; checkpoint 11 implements their full behaviour. The separate security-control commit/projection protocol is not replaced by this transaction.

## Verification boundary

This schema implements structural checks and RLS, not signed-grant verification, password authentication, role-authorised HTTP mutation routes, business-state automation, or the security-control fence protocol. Checkpoint 2 integration tests must use the real limited runtime identity and separate workspace/profile contexts, test missing context and unprovisioned Owner visibility, exercise deferred constraint failures and valid atomic moves/removals, and verify immutable history. Later checkpoints test the relevant domain/security operations against these same boundaries.

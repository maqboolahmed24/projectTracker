# First-release implementation evidence register

Created 24 September 2026. This register maps the thirteen ordered checkpoints to the agreed architecture and to evidence required before a checkpoint can be accepted. **No checkpoint or check is marked complete by creating this document.**

## Authority and scope

- Implementation order: [architecture/checklist.md](../architecture/checklist.md).
- Requirement authority: [architecture/archtecture.md](../architecture/archtecture.md).
- Reviewed decisions and acceptance scenarios: [architecture/architecture-review.md](../architecture/architecture-review.md), findings F01–F12.
- Architecture SHA-256 when this register was created: `d91263471492e97e793e826503be92bac03d2df3236eb9d1f2529350136399cf`.
- Architecture review SHA-256: `0ca1a540b1dedc214898b2e4b5e1e4a3975ed59024fb934e4c4237e692abcbdd`.

Frontend screens, layouts, styling, and interaction presentation are excluded from this implementation task. Browser-side cryptography, password/key handling, IndexedDB storage, approved-device protocols, local calculations, and their supported-browser tests remain required. API and domain outcomes must make the agreed future interface possible without implementing that interface now.

Do not introduce email, GitHub, AI, customer-operated workers/connectors, attachments, boards, channels, mentions, automatic dependencies, task-private sharing, or advanced planning. Hosted workers and the authoritative security control store are part of the current release. Search is local to authorised records. Reporting is client-calculated; due indicators do not require a hosted reminder scheduler.

An architecture decision is not implementation evidence. Passing unit tests is not an independent security review, a restore drill, a production deployment, or permission to claim those outcomes. Keep unanswered implementation findings visible; do not weaken a requirement to mark its check complete.

## Recording evidence

Use the stable check IDs below in test names, reports, and review notes. For every checkpoint, record:

1. Implementation references: repository paths and commit/revision.
2. Verification: exact command or drill procedure, relevant test IDs, timestamp, environment, and supported-browser versions where applicable.
3. Results: success and failure-path outcomes, report/log locations, and known limitations. Sanitize evidence; never record real credentials, recovery phrases, keys, or decrypted customer content.
4. Acceptance: reviewer, date, and unresolved findings. Independent review must identify the actual independent reviewer and review artifact.

A placeholder or an unexecuted test does not pass a check. Complete a checkpoint only when its required evidence is recorded and material failures are resolved. Cross-references avoid duplicate ownership: checkpoint 5 defines security durability; checkpoint 12 demonstrates that restore preserves it.

| Checkpoint | Architecture references | Review findings | Status |
| --- | --- | --- | --- |
| 01 Foundation | Sections 1, 3, 9, 10, 11 | F01; delivery gates | Verified — see CP01 report |
| 02 Persistence and isolation | Sections 4, 8 tenant isolation, 9 transactions | F04, F10 | Verified — see CP02 report |
| 03 Licence activation | Section 8 first-owner setup and licence policy | F01, F06 | Verified — see CP03 report |
| 04 Authentication and devices | Section 8 login/sessions; section 9 device contract | F02, F03, F05 | Verified — see CP04 report |
| 05 Encryption and recovery | Sections 8–9 security; section 10 security state | F03, F05, F11 | Verified — see CP05 report |
| 06 Profiles and access | Section 8 Owners, invitations, roles, access | F03, F04, F05 | In progress — see CP06 report |
| 07 Projects and closure | Sections 2 and 4 | F07, F08 | Not assessed |
| 08 Shared tasks and blockers | Section 4 task workflow; section 6 blockers | F07, F08, F09 | Not assessed |
| 09 Collaboration and audit | Section 2 interaction defaults; section 10 jobs/audit | F04, F10 | Not assessed |
| 10 Reporting and live updates | Sections 2 and 6 | F09 | Not assessed |
| 11 Concurrency and upgrades | Sections 9–10 transactions, editing, schemas | F10 | Not assessed |
| 12 Restore and data exit | Section 10 export, deletion, recovery | F11, F12 | Not assessed |
| 13 End-to-end and release | Section 9 release checks; review delivery gates | F01–F12 | Not assessed |

## 01. Backend foundation, environments, configuration, and deployment setup

**Required implementation:** hosted TypeScript modular monolith, application API, hosted background worker, PostgreSQL-backed persistence/jobs, and separate authoritative security state. Keep domain calculations reusable by authorised clients. Separate staging/production configuration and secrets; customers install no service.

Required success checks:

- [x] **CP01-S1:** A clean checkout installs from the lockfile, validates configuration, builds, and starts the API/worker using documented supported runtime versions and commands.
- [x] **CP01-S2:** Module boundaries match identity/access, projects/work, collaboration, health, and notifications/audit. Future modules do not become startup or core-work dependencies.
- [x] **CP01-S3:** Baseline readiness distinguishes API process, application/control database connectivity, and real worker execution. Logging/health interfaces expose only permitted metadata. Security projection/fence metrics are verified in checkpoint 5, durable queue-age/failure metrics in checkpoint 11, and backup/drill freshness in checkpoint 12; checkpoint 13 verifies them together. An unimplemented metric is never presented as a healthy zero.
- [x] **CP01-S4:** Deployment/configuration evidence identifies staging versus production resources, secret injection, restricted database identities, and the release artifact. Deployment setup is distinguished from an actually executed production deployment.

Required failure checks:

- [x] **CP01-F1:** Missing/invalid required configuration fails startup clearly without exposing secrets or silently weakening authentication/encryption.
- [x] **CP01-F2:** Database, security-store, and worker failures report the correct unavailable/degraded state; protected operations fail closed when authoritative security state cannot be honoured.
- [x] **CP01-F3:** Synthetic credential/content values do not appear in logs, error reports, server caches, or telemetry; no outbound email/connector/AI dependency is invoked.

Evidence: [Checkpoint 1 executed report](checkpoint-01-evidence.md). Eight tests passed; all four local containers healthy; no outstanding foundation findings.

## 02. Database models, migrations, tenant isolation, and API conventions

**Required implementation:** tenant-aware records and relationships, encrypted payloads plus permitted metadata, explicit API operations, revisioned records, restricted database roles, and RLS as defence in depth. Provider-readable storage must not contain private project plaintext or content keys.

Required success checks:

- [x] **CP02-S1:** Migrations create the required workspace/profile/team/project/wave/milestone/task/assignment/blocker/comment/update/audit records and the metadata needed for grants, revisions, events, and receipts.
- [x] **CP02-S2:** Constraints enforce workspace/project relationships, one assignment per task/member, an assignee-only task lead, and task/milestone phase compatibility. A task belongs to one project and at most one current wave.
- [x] **CP02-S3:** APIs validate input and return consistent machine-readable permission, validation, revision-conflict, restricted-mode, and unsupported-schema outcomes. Display names are labels, not credential identifiers.
- [x] **CP02-S4:** Application identities operate with the documented minimum privileges; security-control authority is separated from ordinary business-data projection and content ciphertext.

Required failure checks:

- [x] **CP02-F1:** Two-workspace fixtures reject cross-tenant reads, writes, foreign references, notifications, summaries, and cache reuse through APIs and database enforcement.
- [x] **CP02-F2:** Duplicate assignments, wrong-project milestones, a lead outside current assignees, invalid identifiers/envelopes, and unauthorised project membership are rejected without partial records.
- [x] **CP02-F3:** RLS tests run as the actual application role rather than a table owner/superuser; privileged operational access still cannot decrypt synthetic project content without client keys.

Evidence: [Checkpoint 2 executed report](checkpoint-02-evidence.md). Full suite: 27 passed, zero failed/skipped; both migrations replay cleanly; all local containers healthy.

## 03. Licence activation, interrupted setup, and entitlement handling

**Required implementation:** one non-expiring entitlement activates one workspace and first Owner. Additional Owners/devices consume no activation. Available → Reserved → Activated, with revoked/legacy-restricted handling, fixed sixty-minute reservations, protected resume credentials, and durable idempotent finalisation.

Required success checks:

- [x] **CP03-S1:** Activation commits entitlement consumption, workspace identity, first-Owner authentication/device/recovery references, staged envelopes, and receipt in one security-control transaction; data access waits for the fenced application projection.
- [x] **CP03-S2:** The protected attempt resumes within its reservation; identical finalisation returns the same account/workspace. Successful resume credentials expire after twenty-four hours without becoming login credentials.
- [x] **CP03-S3:** Existing workspace data access does not depend on the preactivation licence lookup. A lookup outage produces a retryable new-setup failure. The licence action guard permits existing authentication/replacement-device approval, read/recovery/revocation, export, and deletion while blocking ordinary writes/access expansion; current data reads/writes enforce the projected restriction.
- [x] **CP03-S4:** Consumption permanently binds the entitlement to its original workspace. Restriction/reinstatement, including a retired-workspace marker, cannot make it redeemable again or create another workspace/account through activation.

Required failure checks:

- [x] **CP03-F1:** Concurrent activation, an expired reservation/generation, and another browser holding only the licence cannot duplicate ownership or take over/resume someone else's attempt.
- [x] **CP03-F2:** Interrupt each setup boundary, lose the local draft, lose the success response, or fail the application projection. The documented resume/recovery path works without consuming an unused licence permanently or granting premature access.
- [x] **CP03-F3:** Different payloads under one operation ID fail; post-commit key loss uses Owner recovery, never another activation. Restoring an entitlement does not clear unrelated maintenance/deletion restrictions.

Evidence: [Checkpoint 3 executed report](checkpoint-03-evidence.md). Final suite: 91 passed, zero failed/skipped; migrations replay cleanly; API/worker images built and all four local services healthy. The report records the source digest, image digests, interruption outcomes and later-checkpoint boundaries.

Dependency ownership: CP03-S3/S4 verify the entitlement layer here. Their complete user journeys remain mandatory in the checkpoints that implement those operations: authentication/replacement devices in CP04-S1, recovery in CP05-S5, additional Owners in CP06-S6, and export/deletion in checkpoint 12. Those checks must exercise restricted licences where allowed and confirm the original workspace/entitlement remains unchanged. Checkpoint 13 verifies the combined journey. This mapping avoids requiring unfinished later modules to pass before their implementation turn; it does not remove those release requirements or claim they already work.

## 04. Authentication, sessions, logout, and device approval

**Required implementation:** reviewed OPAQUE integration, remembered opaque account references, approved-device proof, restricted new-device sessions, and local encrypted device bundles. No username/password discovery across accounts and no conventional password-login fallback.

Required success checks:

- [x] **CP04-S1:** Returning approved devices authenticate, locally unlock, and pass a fresh signed device challenge. New/cleared devices authenticate into a restricted state and obtain verified approval before fetching content-key envelopes.
- [x] **CP04-S2:** Password policy requires at least fifteen characters, accepts at least sixty-four, supports paste/password managers, and checks compromised/common values locally. Client/server use the selected OPAQUE configuration consistently and preserve server setup across deployments.
- [x] **CP04-S3:** Sessions use Secure/HttpOnly/SameSite=Lax cookies, CSRF protection, thirty-minute idle and twelve-hour absolute expiry, and rotation after authentication/privilege changes. Privileged operations enforce authentication within five minutes.
- [x] **CP04-S4:** Logout revokes the session and clears usable keys/plaintext/caches/pending requests; the remembered card is non-secret. Forget-device also removes encrypted local bundles and remembered references.
- [x] **CP04-S5:** Password change stages and verifies the replacement local wrapper, preserves the current healthy signer, revokes other devices/sessions, and requires those devices to pair again using the new password.

Required failure checks:

- [x] **CP04-F1:** Wrong password, expired/replayed two-minute challenges, revoked devices, cleared storage, CSRF, and absent current grants cannot obtain protected data. Account/source/workspace throttles and generic credential failures are exercised.
- [x] **CP04-F2:** A valid password or personal sign-in reference alone cannot bypass device approval; temporary-key input cannot be mistaken for a password through unrelated verifier searches.
- [x] **CP04-F3:** Interrupt password change before/after local staging and authoritative commit, then lose the response or restart the browser. At least the specified matching-generation login/recovery route survives; both wrappers are not discarded speculatively.

Evidence: [Checkpoint 4 verification report](checkpoint-04-evidence.md). Final checks: 165 backend tests and 18 real-browser tests passed. Login, sessions, pairing (including restricted entitlements), password interruption recovery and local cleanup are verified; the updated local API and worker are healthy. Later recovery/enrolment and final release gates remain separate requirements.

## 05. Encryption, key management, password recovery, and security records

**Required implementation:** the architecture's exact pinned crypto dependencies and versioned composition, per-device local keys, independent Owner recovery phrases, scoped custody, authenticated pairing, and durable security-control transitions. Preserve the declared hosted-client/device threat boundary.

Required success checks:

- [x] **CP05-S1:** Lock and verify the selected libsodium/OPAQUE/BIP39 versions. Encoding vectors cover JCS UTF-8, base64url, decimal-string counters, purpose/version context, AEAD headers, ciphertext digests, and Ed25519 signatures.
- [x] **CP05-S2:** Random project keys/nonces, separate signing/recipient keys, purpose-separated HKDF, OPAQUE client export-key wrapping, and signed sealed-box recipient envelopes round-trip across supported browser/runtime implementations.
- [x] **CP05-S3:** Device private bundles stay encrypted in local IndexedDB and are never uploaded/escrowed. Twenty-four-word Owner recovery uses independent random entropy, proof/recipient derivations, verified replacement kits, and no ordinary-member phrase/custody grant.
- [x] **CP05-S4:** Pairing verifies the full transcript fingerprint/QR through a trusted channel and binds genesis, current security head, both public-key sets, profile, scope, credential generation, ceremony, and expiry. Short JOIN/RESET codes do not encrypt permanent keys.
- [x] **CP05-S5:** Member reset, Owner phrase recovery, and Owner-assisted recovery restore only current eligible scopes and preserve records/history. Retired signing keys remain verifiable historically but cannot author new accepted writes.
- [x] **CP05-S6:** Security transitions stage/read-back encrypted objects, fence/drain data operations, commit authority and receipts durably in the control store, then project idempotently. Current custody retains historical key epochs needed by retained live/archived/audit/backup ciphertext.

Required failure checks:

- [x] **CP05-F1:** Tamper with ciphertext/header/signature/recipient/scope/version/algorithm, duplicate fields, or security generations; replay old heads/transcripts/grants. Reject each without releasing keys or accepting altered content.
- [x] **CP05-F2:** Replace or expire reset/recovery ceremonies; remove the approving Owner; lose a pending local bundle; interrupt before/after control commit and during projection. Prior working credentials remain until the documented commit, and stale ceremonies cannot finish.
- [x] **CP05-F3:** Resetting a suspended/revoked member cannot restore lost permissions. Removing an Owner or rotating a phrase prevents future service access through old authority while preserving authorised historical decryption.
- [x] **CP05-F4:** Provider database/log/backup access has no plaintext customer keys/content. Loss of every current Owner's usable device/recovery material cannot be bypassed by support promotion or a provider-issued replacement key.

Evidence: [Checkpoint 5 verification report](checkpoint-05-evidence.md). Combined checks: 205 backend tests and 30 real-browser tests passed; rebuilt local API and worker are healthy. Enrolment/removal commands (CP06), archived/audit/backup lifecycle integration (CP07/09/12), branded-browser coverage and independent release review (CP13) retain their mandatory end-to-end requirements.

## 06. Profiles, multiple equal Owners, roles, permissions, and access removal

**Required implementation:** Owner/Manager/Member/Viewer templates and scoped custom roles from the fixed capability catalogue. Ownership/recovery authority is reserved. Profiles are workspace-scoped; each Owner has equal authority and independent credentials/recovery material.

Required success checks:

- [x] **CP06-S1:** One-profile JOIN invitations expire after one hour; RESET keys after fifteen minutes. Keys are random, protected by keyed verification digests, revocable, generation-bound, and consumed once. Replacement cancels earlier incomplete setup.
- [ ] **CP06-S2:** Pending enrolment/promotion becomes active only after verified device setup, required key delivery, current authority checks, and, for Owners, recovery-kit/custody completion. Another active Owner can take over a member ceremony after identity verification.
- [ ] **CP06-S3:** Every matrix action is exercised for each default role and a minimal custom role. Members create self-assigned tasks; only Owners create projects/manage access. A Viewer sees the whole ordinary content of a joined project, not selected private tasks.
- [ ] **CP06-S4:** Pending access becomes Active only after permission and current/historical project-key envelopes are ready. Team membership/task assignment cannot create project access.
- [ ] **CP06-S5:** Revocation immediately fences service access and future grants, removes current assignments/leads/blocker responsibility, flags unassigned work, and rotates the future content epoch. Archived scopes preserve historical attribution.
- [ ] **CP06-S6:** Add/promote/demote/remove/recover Owners without founder privilege; retain at least one fully active Owner. Pending Owners do not count, and a former Owner's phrase cannot restore ownership.

Required failure checks:

- [ ] **CP06-F1:** Concurrent Owner removals cannot remove the last Owner; stale ownership/custody versions fail. Partial promotion/invitation grants no privileged capability.
- [ ] **CP06-F2:** Custom roles cannot obtain ownership/recovery through checkboxes, grant project access through assignment, or access another workspace. Removed users cannot retrieve protected cached/streamed data or notification details in later batches.
- [ ] **CP06-F3:** Code reuse, replaced invitations, incomplete ceremony takeover by a removed Owner, or authority changes before finalisation cannot activate a profile or silently change its current role.

Evidence — **checkpoint in progress**: [checkpoint 6 verification record](checkpoint-06-evidence.md). Current slices cover the fixed permission policy, authoritative membership/role/scope migrations, access projection and relationship cleanup with unassigned-work notices, real JOIN/equal-Owner/promotion journeys, and encrypted custom-role definitions with signed-history verification. The latest frozen snapshot passed 294 backend and 39 browser tests and runs in healthy local API/worker containers. CP06-S1 is verified by the JOIN/RESET replacement, redemption, revocation and expiry checks together with the keyed-digest/random-code implementations. Role assignment/access changes, suspension/demotion/removal with key rotation and concurrent last-Owner tests remain required. Checkpoint 6 stays unchecked in the project checklist.

## 07. Projects, teams, phases/waves, milestones, and closure

**Required implementation:** name-only Planned project creation, optional waves/milestones, project-local links, manual lifecycle transitions, explicit acceptance, and reversible terminal archiving. Phase/Wave is one concept with a configurable display label.

Required success checks:

- [ ] **CP07-S1:** An Owner creates a Planned project and provisions keys to active Owners before availability; optional Manager/team/dates/waves/milestones do not block simple projects.
- [ ] **CP07-S2:** Waves may overlap, have explicit order/objective/dates/lead, and start manually. Unscheduled tasks remain part of the project. A milestone may span its project or belong to one wave; tasks linked to a wave milestone share that wave.
- [ ] **CP07-S3:** Milestone acceptance requires all non-cancelled linked tasks Done and a recorded outcome; an empty milestone can be a manual checkpoint. Wave/project completion checks all required child states and records its outcome/snapshot.
- [ ] **CP07-S4:** Carry-forward keeps task identity, assignments, activity, and origin/destination history; resolve incompatible milestone links. Cancellation handles unfinished work explicitly and commits its permitted cascade atomically.
- [ ] **CP07-S5:** Reopen/unarchive terminal parents before business edits. Adding/restoring/reopening unfinished work reopens an Accepted milestone atomically. Earlier closing snapshots remain unchanged.

Required failure checks:

- [ ] **CP07-F1:** Completion fails for unfinished unscheduled tasks, unaccepted milestones, or outstanding review. A fully Done task list cannot bypass manual acceptance/closure.
- [ ] **CP07-F2:** Reject cross-project/wrong-wave links, partially permitted cancellation/moves, or writes into terminal/archived scopes, except documented security cleanup/moderation.
- [ ] **CP07-F3:** Archiving non-terminal work is rejected; cancellation/reopening does not silently restore cancelled children, erase history, or invent automatic scheduling/dependency gates.

Evidence — implementation references: _pending_; lifecycle/atomicity reports: _pending_; environment/revision/date: _pending_; reviewer/findings: _pending_.

## 08. Shared tasks, assignments, approvals, blockers, and lifecycle rules

**Required implementation:** one shared task with multiple assignees, optional assignee lead, To do/In progress/Done, optional single-reviewer Review, explicit Cancelled/restore/reopen actions, and task-linked Open/Resolved blockers.

Required success checks:

- [ ] **CP08-S1:** Two or more assignees share one status, description, dates, comments, acceptance, and activity stream; removing the lead clears/replaces its designation without duplicating work.
- [ ] **CP08-S2:** Preparation and administrative cancellation work in Planned scopes; execution/completion requires Active containing scopes. Fixed permissions apply equally to custom roles.
- [ ] **CP08-S3:** Review is off initially. When enabled, one named eligible non-assignee approves the submitted revision; rejection returns In progress with a reason. Missing reviewers are explicit; an eligible other Owner may replace them.
- [ ] **CP08-S4:** Material edits invalidate pending approval. Done work is reopened before such edits; Cancelled work is restored first. Disabling review is Owner-authorised/audited and returns pending Review work to In progress.
- [ ] **CP08-S5:** Blockers have reason, responsible member, next action, state, and actor/time history. Assigned editors can manage blockers on assigned work; managers may set another active responsible person. Resolution/reopening records reasons/outcomes.

Required failure checks:

- [ ] **CP08-F1:** An assignee/Owner cannot self-approve, a removed/newly assigned reviewer cannot approve, and old revision proofs cannot complete changed work. No approval bypass exists through ordinary edit signatures.
- [ ] **CP08-F2:** An Open blocker prevents Done; resolving only one of several leaves Blocked. Done tasks must reopen before an Open blocker is introduced.
- [ ] **CP08-F3:** Comment/read-only actors cannot alter blockers or assignments. Cancellation excludes its inactive blockers from live health; restoring work reactivates still-Open blockers. Access removal never silently resolves a blocker.

Evidence — implementation references: _pending_; workflow/permission reports: _pending_; environment/revision/date: _pending_; reviewer/findings: _pending_.

## 09. Comments, updates, in-app notifications, and audit history

**Required implementation:** encrypted append-only plain-text task comments and project/wave updates, scoped moderation, event-only in-app Inbox, read/unread/project mute, and authenticated audit history. No email/scheduled reminder/chat system.

Required success checks:

- [ ] **CP09-S1:** `comment` permits a new entry in an editable authorised scope. Corrections are new entries; moderation requires `manage_tasks`, records a reason, and retains the encrypted original in authorised history.
- [ ] **CP09-S2:** Assignment changes and task comments/status changes notify affected assignees; reviews notify the reviewer; access/recovery/ownership events reach affected people/Owners. Ordinary self-notifications are excluded; security notices ignore project mute.
- [ ] **CP09-S3:** Events/recipients are deduplicated. Payloads contain opaque references; details are fetched/decrypted only under current access. Removed access yields a generic content-free notice.
- [ ] **CP09-S4:** Record changes, audit, and required durable job creation share the business transaction. Historical signing keys verify actor/action/time and encrypted before/after evidence.

Required failure checks:

- [ ] **CP09-F1:** Duplicate delivery/replay produces one logical notification per recipient. Worker failure delays delivery without repeating or rolling back the already committed business action.
- [ ] **CP09-F2:** Revoked/project-muted users, stale cache scopes, and cross-tenant recipients do not receive forbidden details. A comment-only custom role cannot moderate.
- [ ] **CP09-F3:** Plaintext project names/comments, secrets, and recovery material do not enter hosted notification payloads, jobs, or logs. No external delivery is attempted.

Evidence — implementation references: _pending_; event/audit reports: _pending_; environment/revision/date: _pending_; reviewer/findings: _pending_.

## 10. Progress calculations, deadlines, project health, and live updates

**Required implementation:** shared client domain calculation version `progress-health-v1`, date-only reporting, scoped summary provenance, and SSE invalidation with visible-page refresh fallback. No forecasts/weights/workload/baseline calculations.

Required success checks:

- [ ] **CP10-S1:** Distinct Done/non-cancelled task counts apply consistently to project/wave/milestone/filter scopes. Count shared tasks once; round to whole percentages capped at 99 while unfinished work remains. Zero denominator displays a dash with the agreed no-work label.
- [ ] **CP10-S2:** Europe/London defaults, Owner timezone changes, UTC events, calendar-date deadlines, next-local-midnight overdue boundaries, and labelled task/milestone/wave deadline inheritance produce deterministic results.
- [ ] **CP10-S3:** Health requires complete/current/decrypted/verified input, then applies Delayed → At risk → Not enough information → On track. Cancelled work is excluded; outstanding acceptance counts as unfinished. Terminal scopes retain lifecycle/closing outcomes.
- [ ] **CP10-S4:** Next milestone selection includes overdue Open milestones, effective dates, deterministic ties, then undated items. Blocker age uses elapsed UTC periods, with no configurable age trigger.
- [ ] **CP10-S5:** Summaries bind exact permission/filter scope, source manifest/checkpoint, key epoch, calculation version, timezone, server as-of time, completeness, and device signature. Only Owners/scoped planners publish shared summaries; other readers calculate locally.
- [ ] **CP10-S6:** Relevant writes/open/refocus/local-midnight invalidate calculations; SSE and sixty-second visible-page fallback refresh data. Offline values are last-known, and cross-project totals cover only visible projects.

Required failure checks:

- [ ] **CP10-F1:** Test daylight-saving boundaries, due today, all-cancelled/empty scopes, 199 of 200 tasks, shared assignments, 100%-Done milestones awaiting late acceptance, and multiple blockers.
- [ ] **CP10-F2:** Missing/decryption-invalid pages, unknown current checkpoints, stale summaries, mid-read access changes, and narrower/broader scope substitution cannot produce an accepted current or unauthorised aggregate.
- [ ] **CP10-F3:** Identical fixtures/checkpoints/settings/as-of times yield identical outputs across supported clients; cancelled overdue tasks/waves do not keep current projects Delayed.

Evidence — implementation references: _pending_; deterministic fixtures/reports: _pending_; browser/environment/revision/date: _pending_; reviewer/findings: _pending_.

## 11. Concurrent edits, retry handling, background jobs, and encrypted upgrades

**Required implementation:** online-only submissions, expected record revisions, stable operation identities, atomic multi-record business actions, bounded job retries, and resumable Owner-operated encrypted migrations with preserved signed history.

Required success checks:

- [ ] **CP11-S1:** Two edits of one revision yield one commit and one explicit conflict. API/domain conflict data permits the future interface to retain unsaved input and deliberately reapply against the current revision; no implicit merge/resubmission occurs.
- [ ] **CP11-S2:** Same operation ID plus identical request returns the committed result once. Lost acknowledgements resolve through receipts before retrying the exact ciphertext. New content uses a new operation/nonce; current access and deletion tombstones override old receipts.
- [ ] **CP11-S3:** Append-only posts have independent stable IDs. Multi-record moves/closure/cancellation validate permissions/revisions/checkpoints and commit all records/audit/receipts/jobs together.
- [ ] **CP11-S4:** Jobs recheck scope, use stable deduplication, bounded exponential backoff with jitter, a failed state after ten attempts, and same-identity operator replay.
- [ ] **CP11-S5:** Schema/envelope 1 and historical decoders are explicit. Owner-run upgrades pause content writes, preserve history, migrate current records with revision/epoch checks, record resumable progress, and invalidate summaries on finalisation.
- [ ] **CP11-S6:** Another current Owner can resume. Recovery/revocation remain available; stale authority/keys invalidate batches. Licence/deletion restrictions pause migration, final deletion aborts it, and completion cannot clear another workspace restriction.

Required failure checks:

- [ ] **CP11-F1:** Different payload bytes under an existing operation ID, stale expected revisions, revoked scopes, wrong schema/epoch, and obsolete data generations fail without partial side effects.
- [ ] **CP11-F2:** Simulate disconnect before send/after commit, lost acknowledgement, duplicate job execution, concurrent comments, and partial multi-record failure. No duplicate business effect or silent overwrite occurs.
- [ ] **CP11-F3:** Old tabs cannot overwrite upgraded schemas or drop unknown fields. Interrupt migration, remove its Owner, rotate keys, request deletion, and restrict the licence; history remains verifiable and the specified resume/fail-closed route holds.

Evidence — implementation references: _pending_; concurrency/fault-injection reports: _pending_; environment/revision/date: _pending_; reviewer/findings: _pending_.

## 12. Backups, restoration, export, retention, and deletion

**Required implementation:** encrypted content checkpoints/recovery records, independently durable current security authority, quarantined restore, consistent Owner-only client JSON data exit, profile removal, and deadline-enforced whole-workspace deletion.

Required success checks:

- [ ] **CP12-S1:** Daily content checkpoints and continuous recovery records have thirty-day retention and include referenced encrypted objects/key manifests. Record measured progress toward fifteen-minute content-loss and eight-hour service-restore targets; do not report targets as achieved without drills.
- [ ] **CP12-S2:** Restore quarantines content, obtains latest acknowledged security authority, reconciles grants/credentials/custody/licence/deletion state forward, invalidates sessions/temporary ceremonies, increments data generation, and discards obsolete jobs.
- [ ] **CP12-S3:** A currently authorised Owner uses the restricted recovery route to verify current and historical ciphertext/key coverage before normal service returns. Restoration preserves later revocations despite older business content.
- [ ] **CP12-S4:** A recently authenticated Owner exports a consistent client-decrypted UTF-8 JSON schema-1 snapshot with source revisions/manifest/completeness and the specified ordinary business records/history. The export is plainly identified as plaintext data exit, not a restorable/key backup.
- [ ] **CP12-S5:** Profile removal clears credentials/access/current responsibility, uses Former member for the current label, and preserves shared/historical contributions. The last Owner activates a successor or follows whole-workspace deletion.
- [ ] **CP12-S6:** Any Owner requests deletion; any current Owner cancels before its 168-hour UTC deadline. Pending deletion allows the specified read/export/recovery/security routes and blocks ordinary writes/access expansion.
- [ ] **CP12-S7:** Final deletion enforces its deadline despite worker delay/requester departure, records an irreversible tombstone, and denies ordinary access/recovery. Live payloads purge within twenty-four hours; backups expire within thirty days after purge. Only minimal opaque tombstones/retired IDs/consumed-entitlement markers remain permanently.

Required failure checks:

- [ ] **CP12-F1:** Restore snapshots from before member reset/removal, Owner removal, phrase rotation, and deletion. Old authority/phrases/requests cannot regain access; currently permitted users can recover retained history.
- [ ] **CP12-F2:** Missing trusted current security head, missing required key/object manifests, failed security projection, or failed Owner verification leaves the workspace quarantined; no snapshot-only Owner or provider workaround opens it.
- [ ] **CP12-F3:** Revoke export authority mid-generation or invalidate its source snapshot: abort/restart rather than mislabel incomplete data as complete. Passwords, private keys, envelopes, recovery/security records, and unrelated restricted content never appear in export.
- [ ] **CP12-F4:** Owner A requests deletion/Owner B cancels; cancel races the deadline; requester leaves; deletion worker is delayed; old jobs/receipts retry; old snapshots restore; the consumed licence is reused. None bypasses final deletion or revives retired identities/entitlements.
- [ ] **CP12-F5:** Migration completion, restore, or deletion cancellation cannot remove another remaining licence/maintenance restriction. No new backup extends deleted payload retention beyond the documented limit.

Evidence — implementation references: _pending_; restore/export/purge drill artifacts and measured timings: _pending_; environment/revision/date: _pending_; reviewer/findings: _pending_.

## 13. End-to-end testing, independent security review, and production release

**Required implementation:** an integrated first-release backend and browser protocol/domain libraries, demonstrated fault handling, independent review of the composed security implementation, and evidenced release readiness. No frontend delivery is implied by this checkpoint.

Required success checks:

- [ ] **CP13-S1:** Run first Owner → equal second Owner → invited member → shared encrypted task → logout/login → new-device approval → member reset → Owner recovery/removal, retaining authorised history throughout.
- [ ] **CP13-S2:** Run a repository-free iterative project with optional waves/milestones, two-assignee tasks, optional review, blockers, comments, notifications, carry-forward, closure/reopen/archive, deterministic reporting, export, and cancellation of a deletion request.
- [ ] **CP13-S3:** Repeat protocol/crypto/local-storage/calculation journeys on current and previous stable desktop Chrome, Edge, Firefox, and Safari with supported WebAssembly/WebCrypto/IndexedDB. Record tested versions and unavailable environments honestly.
- [ ] **CP13-S4:** Record actual independent security review of the composed authentication/pairing/recovery/custody implementation, resolve material findings, and retain reviewer/report identifiers. Dependency selection/audits do not substitute for this evidence.
- [ ] **CP13-S5:** Record all prior checkpoint evidence, staging results, restore/deletion drill measurements, operational runbooks, release artifact/configuration review, and the status of production deployment. Distinguish release readiness from deployment actually performed.

Required failure checks:

- [ ] **CP13-F1:** Integrated tests combine tenant/role denial, stale approvals, concurrent Owner removal, revoked devices, lost security-commit responses, migration interruption, restore after revocation, and deletion deadline enforcement; isolated unit success is insufficient.
- [ ] **CP13-F2:** Unsupported capabilities fail explicitly without weaker crypto, fallback authentication, secret leakage, or a provider decryption route. Future feature outages/configuration absence cannot block core work.
- [ ] **CP13-F3:** No security-review/production-ready claim is made while material findings, required supported-browser evidence, or recovery/deletion acceptance evidence remain missing.

Evidence — implementation references: _pending_; integrated test/drill reports: _pending_; independent reviewer/report: _pending_; browser/environment/revision/date: _pending_; release reviewer/findings/deployment record: _pending_.

## Evidence summary

Checkpoints 1–5 are verified against their linked reports. Checkpoint 6 is in progress; checkpoints 7–13 remain unverified. Append evidence as work proceeds in order, and update the [working checklist](../architecture/checklist.md) only when the corresponding acceptance requirements are verified. Regression evidence for an implementation slice does not complete an entire checkpoint.

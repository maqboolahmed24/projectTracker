# Checkpoint 9 - collaboration, Inbox and audit

Status: verified on 26 September 2026. Checkpoints 1–9 are complete; checkpoints 10–13 remain required.

## Scope and acceptance

| Check | Required verification |
| --- | --- |
| CP09-S1 | Independent encrypted plain-text task comments and project/wave updates; corrections append; task moderation uses manage_tasks and update moderation uses plan_projects; reason and original remain readable in authorised history, including archived scopes. |
| CP09-S2 | Assignment, comment and task-state events reach affected assignees; Review reaches the named reviewer; access, recovery and ownership notices reach affected active profiles and Owners. Ordinary self-notices are excluded; security notices ignore mute. |
| CP09-S3 | Stable event/recipient identities deduplicate delivery; Inbox read/unread and project mute work; detail references require current person/device access; revoked project details become content-free generic receipts. |
| CP09-S4 | Entry/change, audit, immutable versions, receipt, outbox and Graphile job commit atomically; historical keys verify actor, time and encrypted before/after evidence. |
| CP09-F1 | Duplicate execution and a lost reply produce one logical effect; delivery interruption rolls back only delivery and preserves committed work. |
| CP09-F2 | Comment-only roles cannot moderate; removed, muted, foreign-tenant or device-restricted recipients cannot fetch forbidden details. |
| CP09-F3 | Jobs and notices contain only permitted opaque metadata; client text, passwords, keys and recovery material never enter them; no external delivery exists. |

Checkpoint 7/8 integration: comments stay on one task through carry-forward; hiding a planning outcome retains its original ciphertext and signed closing history. Existing task identity, approval and blocker behavior must continue to pass.

## Verified implementation

- Shared collaboration contracts and historical verification: `src/shared/collaboration.ts`. Independent post IDs do not compare or advance the planning head; hide operations compare the individual entry revision. Current parent state and authority are rechecked at commit.
- Collaboration service/transport: `src/modules/collaboration/service.ts`, `routes.ts`; client crypto/controller/store and Worker/runtime integration under `src/client/collaboration-*`.
- Notification events and worker: `src/modules/notifications/delivery.ts`, planning transaction integration, `src/worker.ts`. Event recipients derive from the committed graph, and delivery rechecks the security fence, recipient access and mute settings.
- Personal Inbox: signed bounded read/mute changes, revision conflicts and immutable receipts in `src/shared/inbox.ts`, `src/modules/notifications/inbox.ts`, `inbox-routes.ts`, and client Inbox files. Detail rows keep their existing project RLS. Separate receipts contain no project/content reference and permit generic unavailable notices.
- Security notices: `src/modules/identity/ownership-notices.ts` and projection integration include active affected profiles and Owners; custom-role permission changes count as access changes.
- Migrations `005_collaboration.sql` and `006_notifications.sql` applied successfully after stopping the API and worker. `test-results/checkpoint-09-migrations.log` records two application migrations applied and eight control migrations unchanged. Their immutable SHA-256 values are `e7c240ab852c38e12c1238605b366e4da358058c999c7239aa51eae29e6b36f9` and `51e73db5cde0e98d51d9a9814ad61289e6bb977865629da2c09255cd3adea085`, respectively. The local API and worker now use the rebuilt checkpoint 9 production source.

## Acceptance evidence map

| Check | Evidence in the executed focused suites |
| --- | --- |
| CP09-S1 | `collaboration.test.ts`, `collaboration-client.test.ts`, `collaboration-service.test.ts` and the three-engine collaboration browser journeys verify independent encrypted posts, appended corrections, distinct moderation capabilities, retained originals/reasons, archived moderation and unchanged closing outcomes. The carry journey preserves one task/comment identity across waves. |
| CP09-S2 | `notifications.test.ts` verifies recipients derived from before/after tasks, the named reviewer, self-exclusion, mute and delivery by the real worker; browser collaboration verifies actual comment delivery. `ownership-notices.test.ts`, `access-change.test.ts` and `role-notifications.test.ts` verify active affected people/Owners, role permission changes, deduplication and rollback. Recovery projection remains covered by the related backend/browser journeys. |
| CP09-S3 | `notifications.test.ts` verifies signed read/unread/mute revisions, exact retries, generic receipts after lost person scope, foreign-user/tenant rejection and strict HTTP boundaries. `work-read.test.ts` uses an actually signed expiring device-only lease to verify generic receipts and denied preference/receipt replay while the person's unrestricted device retains access. |
| CP09-S4 | The collaboration service's injected pre-commit failure rolls back records, immutable versions, audit, receipt, outbox and durable job. Shared/client verifiers check historical authority and signed actor/time/action. `teams.test.ts`, `teams-client.test.ts` and browser teams verify the bounded historical revision chain, encrypted before/after content, new signed time and explicit legacy timestamp provenance; `planning-client.test.ts` verifies readable signed audit attribution. |
| CP09-F1 | Service and browser lost-reply journeys recover the exact operation once. Notification delivery failure rolls back only delivery, preserves committed work, and deduplicates replay. The hosted-worker test completes actual queued delivery and shuts down cleanly. |
| CP09-F2 | Comment-only actors cannot moderate; revoked authors and foreign tenants cannot fetch protected entries. Notification tests cover mute/person revocation, and the device lease journey covers narrower device access and replay. Client generation checks and authentication lifecycle hooks reject stale scope. |
| CP09-F3 | Tests inspect uploaded encrypted posts, queued job fields and notification rows for private fixture values. Jobs contain only workspace/outbox/generation IDs; notice rows contain opaque references and empty private envelopes. Route failures and worker logs are sanitised; this implementation has no external delivery producer. |

## Final verification

Combined passing evidence covers **444 backend checks and 93 browser checks**, with no unresolved failures. The browser set has 31 cases each in Chromium 153.0.8010.12, Firefox 155.0 and WebKit 26.6. These are bundled-engine results, not the checkpoint 13 branded-browser release gate.

`test-results/checkpoint-09-final-coverage.json` records every passing case, report hash, runtime image, browser version and source association. The final source snapshot contains 238 files with SHA-256 `c1b7edacad140312a47f71ccadebc1b0b8cd092a44118d68fe4178ba94b1cd98` (`checkpoint-09-browser-repaired-candidate-snapshot.json`).

| Evidence | Result |
| --- | --- |
| Shared-contract first run | 13/13 passed; included again in the integrated focused set. |
| Focused backend coverage | All 82 distinct cases passed across the initial run and bounded repairs. |
| Remaining backend suites | 362/362 passed in 123.9 seconds; none skipped. |
| Focused browser coverage | All 15 distinct cases passed after the moderation fixture repair. |
| Remaining browser suites | 78/78 passed in 6.3 minutes. |
| Compilation and browser bundle | Passed; the last build is `checkpoint-09-browser-fixture-repair-1-build.log`. |
| Migrations | Two new application migrations applied; replay reported six application and eight control migrations unchanged. |
| Local runtime | API, worker and both databases healthy; API liveness/readiness and worker readiness returned 200. |

Runtime API image: `sha256:edac426b35439603b47e85e69e10108d9b660cd6663a713c0faa09f0d5c5b74f`. Worker image: `sha256:10782ce2ddb9085e06d07285c0af9a804531ca35acd713df3eb4af17a63932b7`. The only edits after image build were test assertions/setup in `test/teams.test.ts` and `test/browser/collaboration.spec.ts`; production files match the final snapshot. Native tests used Node 24.19.0; compilation/runtime images use Node 24.20.0.

### Bounded repairs

The first compilation needed explicit TypeScript narrowing/default-parameter types; the team-history addition needed explicit v1/v2 union typing. Each passed after one focused repair, with validation unchanged.

The initial focused run passed 79/82 cases. Test repairs replaced canonicalisation of PostgreSQL Date values with ordinary serialisation for the plaintext check, parsed decrypted team content before comparing object prototypes, and removed notification preferences during fixture cleanup. Cleanup had left a fixture authentication Worker alive; that completed child was terminated after inspection, the exact failed fixture workspace was removed, and the entire notification suite subsequently passed and exited cleanly. The team-history case needed a second assertion repair to expect an RLS-hidden receipt as `{receipt:null}`. Its remaining stale-anchor and signed-suspension checks then passed. No production authorisation rule was relaxed.

The initial browser moderation journey used a session revoked by its preceding role change. One repair asserts that rejection and signs the member back into the same approved device at session generation 2, then executes the unchanged moderation/archive/outcome-history journey. All three engines passed. No failing check exceeded the three-repair limit.

Preserved reports include `checkpoint-09-focused-initial.log`, `checkpoint-09-fixture-repair-1-tests.log`, `checkpoint-09-team-repair-2-tests.log`, `checkpoint-09-remaining-backend.log`, `checkpoint-09-browser-focused-initial.json`, `checkpoint-09-browser-fixture-repair-1.json` and `checkpoint-09-browser-remaining.json`. The combined report validates their replacement coverage; an interrupted or failing report alone is not acceptance evidence.

## Limits and later checkpoints

Returned entry signatures and retained per-entry pins authenticate content/history and reject known rollback. Independent signatures cannot prove that a server disclosed an unseen post. Bounded feed snapshots detect changes during pagination and report continuation/loading explicitly; they do not prove an unseen complete feed.

Ordinary notifications begin with newly committed events; older outboxes have notification_version 0 and retain their history without inventing recipients. Security projection remains independently idempotent. Graphile durable job state records failed attempts. Matching outbox failure metrics, jittered backoff, operator replay and successful-logout removal of pending encrypted drafts remain checkpoint 11 obligations. Inbox preference drafts are ephemeral non-secret metadata; committed receipts/settings can be reloaded.

New team changes sign their time. Earlier v1 histories retain their exact signatures and explicitly server-recorded timestamp; no signed timestamp is fabricated. Team history is bounded to 512 revisions and 8 MiB and rejects incomplete chains.

Checkpoint 10 owns progress/health calculations and live refresh, checkpoint 12 owns backup/export/deletion, and checkpoint 13 owns combined release journeys, independent security review and release readiness. Frontend screens, email, scheduled reminders, threaded chat, mentions, external delivery and customer-operated workers remain outside current scope. See [the collaboration protocol](collaboration-protocol.md) for the working headless APIs.

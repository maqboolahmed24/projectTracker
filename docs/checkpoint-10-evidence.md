# Checkpoint 10 - reporting, deadlines and live updates

Status: verified on 27 September 2026. Checkpoints 1–10 are complete; checkpoints
11–13 remain required. Final evidence covers 479 backend and 102 browser checks,
with no unresolved failures, and a healthy matching local API/worker runtime.

## Implementation and acceptance map

| Check | Implementation and executed evidence |
| --- | --- |
| CP10-S1 | `src/shared/progress.ts` and `test/progress.test.ts` calculate distinct Done/non-cancelled task counts for project, wave, milestone and filter scopes, including tasks outside waves, two-assignee work, the 99% cap and zero-denominator labels. The reporting browser journey exercises shared tasks through the real controllers. |
| CP10-S2 | `progressClock` uses calendar dates and the next local midnight. Domain/browser fixtures cover London DST and inherited deadlines. Signed Owner timezone settings preserve entered dates; `closing-settings-service.test.ts` verifies old closures retain their original authenticated timezone after later settings changes. Unstamped legacy closures remain explicitly unrecorded. |
| CP10-S3 | Complete/current/verified/decrypted input is required. Domain checks prove Delayed → At risk → Not enough information → On track, missing-date counts, cancelled exclusions and outstanding milestone acceptance. Terminal scopes retain their matching immutable closing snapshot and settings proof. |
| CP10-S4 | Domain and browser fixtures verify effectively dated Open milestones, overdue inclusion, creation-order/ID ties and undated-last order. Blocker ages use whole elapsed UTC days. |
| CP10-S5 | `reporting-crypto.ts`, `reporting-settings-crypto.ts` and the reporting service bind scope, visible-project permissions, source manifests, key epochs, settings, server UTC, completeness and signatures. Components use their own project keys. Readers calculate locally; only authorised planners/Owners publish. Client/service tests reject tampering, even signed false counts, stale checkpoints and substituted scopes. |
| CP10-S6 | `live-controller.ts`, live service/routes and real browser tests verify metadata-only SSE, current access per batch, open/write/refocus/midnight invalidation, visible sixty-second fallback, hidden/disconnected last-known values and exact lost-reply recovery. Cross-project/team totals explicitly identify visible projects. |
| CP10-F1 | Domain fixtures cover 199 of 200, Review, shared assignments, empty/all-cancelled scopes, DST, due today, late milestone acceptance and multiple blockers. |
| CP10-F2 | Client tests reject missing records and invalid scope/content; services reject stale source vectors/settings and mid-read content edits. The signed mid-read revocation test commits actual access removal between source read and final validation, proves denial and zero preparations, then proves fresh login still cannot read that project. SSE also rechecks revocation before subsequent batches. |
| CP10-F3 | Fixed fixtures produce identical complete canonical outputs and digests in Node, Chromium, Firefox and WebKit across DST and deadline boundaries. Domain checks exclude cancelled overdue work from current delay. |

Implementation files are the shared progress/reporting/closing-settings/live contracts,
client reporting/settings/refresh modules, work reporting/live services and routes,
and the planning closure proof integration. See [reporting protocol](reporting-protocol.md)
for headless APIs and scope bounds.

## Backend results

**479 distinct backend cases passed: 444 existing cases plus 35 checkpoint 10 cases.**
No backend failures remain unresolved. `test-results/checkpoint-10-backend-coverage.json`
records passing case identities, report hashes, bounded repair coverage and the one
renamed live-controller case without counting it twice.

- `checkpoint-10-integration-initial-tests.log`: 31/34 passed before repairs.
- `checkpoint-10-session-lock-repair-1-tests.log`: settings and summary journeys passed;
  the closure journey reached a final test-object comparison failure.
- `checkpoint-10-live-worker-repair-1-tests.log`: closure and seven live-client checks passed.
- `checkpoint-10-live-fetch-repair-2-tests.log`: both affected HTTP tests passed; the new
  revocation test identified an incorrect fixture assumption about retained access rows.
- `checkpoint-10-revocation-fixture-repair-1-tests.log`: the complete new revocation case passed.
- `checkpoint-10-remaining-backend.log`: 444/444 passed, none skipped, in 265.5 seconds.
  The exact file list is retained in `checkpoint-10-remaining-backend-files.json`.

## Browser results

All nine new checkpoint 10 cases have passed across the three bundled engines:

- The full reporting journey passed in each engine in
  `checkpoint-10-browser-focused-initial.json`.
- Fixed calculation fixtures passed in each engine in
  `checkpoint-10-browser-live-worker-repair-1.json`.
- Live reporting, hidden/refocused states and exact lost-publish recovery passed
  in each engine in `checkpoint-10-browser-live-fetch-repair-2.json`.

All 93 baseline cases passed across the baseline run and one isolated environment
retry. The baseline run passed 92 cases in 8.5 minutes; its first Chromium
comment/Inbox case ran while the hosted worker was still stopped. After starting
the rebuilt worker, the same test passed in 11 seconds, without a source change.
Reports are `checkpoint-10-browser-remaining.json` and
`checkpoint-10-browser-worker-environment-repair-1.json`.

`checkpoint-10-final-coverage.json` maps all 102 distinct browser cases and all
479 backend cases to retained report hashes and the final source/runtime. There
are 34 cases each in Chromium 153.0.8010.12, Firefox 155.0 and WebKit 26.6. These
bundled-engine results do not substitute for checkpoint 13's branded-browser gate.

## Bounded repairs and retained diagnostics

The initial targeted TypeScript command needed `--ignoreConfig`; it had run no tests.
Two live fixtures used noncanonical base64url tokens; one fixture repair retained
strict validation and passed. The integrated compiler needed one explicit union/
array typing repair. New migration SQL has not been edited after application.

Timezone saves originally opened a second session transaction while holding its
row lock. Reusing the held control connection fixed the lock and retained recent
authentication. The final closure comparison then required strict schema parsing
of a safely decoded null-prototype object. The revocation fixture expected a row
to disappear; it now asserts the retained `revoked` state, with denial and zero
preparation checks unchanged. Each of those fixture failures took one repair.

Live refresh initially cancelled the shared crypto Worker. Repair one retained
results only for the current generation without aborting that Worker; explicit
authentication clearing still cancels work. The browser remained unavailable.
Safe diagnostics proved calculation succeeded but the event request failed before
networking. An isolated native browser fetch produced `Illegal invocation`:
`HttpLiveSource` had supplied the wrong receiver. Repair two uses `globalThis`, as
existing API transports do, and the HTTP test asserts it. All live browser cases
then passed. The two repairs remain below the three-attempt limit.

Diagnostics: `checkpoint-10-live-diagnostic-chromium.json` and
`checkpoint-10-live-fetch-receiver-diagnostic.log`. An initial diagnostic command
incorrectly loaded admin environment values and failed before fixture setup; the
corrected command produced the described evidence. Configuration guards were not relaxed.

## Source, migrations and local runtime

The final candidate contains 263 files, SHA-256
`b738829223cec089ad39aabd1c83bb88b48d91c3eb9b83c06127438437d83d14`.
`checkpoint-10-final-candidate-snapshot.json` records each file digest. Both TypeScript
and browser builds passed; the last TypeScript build includes the revocation fixture repair.

Application migration `007_reporting.sql` is applied and immutable, SHA-256
`f9aebbfe62e3550aabb17b35b475144049f60ede7ae21887994b6cecea15ce89`.
Replay retained all seven application and eight control migrations unchanged
(`checkpoint-10-migration-replay.log`).

The API, worker and both PostgreSQL stores are running and healthy. API liveness,
API readiness and worker readiness all returned 200; see `checkpoint-10-runtime.json`.

- API image: `sha256:99fdaad0fc3a44c6de2dcd801d524b73ee6d2597534f13bae00d55a82f600524`.
- Worker image: `sha256:f438ad5ac601cbe85c20dace387d7667e4fa556bb5c7e961e817dca446a29db8`.

Native tests use Node 24.19.0; Docker compilation and runtime use Node 24.20.0.
Frontend screens and future integrations remain outside scope. Checkpoint 11 still
owns durable reporting drafts, successful-signout cleanup, job retries and upgrades;
checkpoint 12 owns export/backup/deletion, and checkpoint 13 owns integrated release gates.

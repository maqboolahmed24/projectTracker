# Checkpoint 12 — recovery, data exit and deletion

Verified on 27 September 2026: **552 distinct Node cases and 120 browser cases pass**, together with the operational drills below. Matching local API, queue worker, both databases, synchronous replica and recovery operator are running; queue and recovery health pass. Checkpoint 13 remains required. This report does not claim production readiness.

## Acceptance map

| Check | Implementation and executed evidence |
| --- | --- |
| CP12-S1 | `compose.recovery.yaml`, `physical-backups.mjs` and `recovery.mjs` provide independent encrypted repositories, continuous WAL, daily full backups and five-minute signed checkpoints with encrypted key/object sidecars. The actual schedule drill verifies cadence, reuse of daily bases, authenticated fallback and replacement of corrupted evidence. Actual physical/replica/composed drills measure the local recovery path. Recovery health distinguishes checkpoint age from WAL age and missing evidence. |
| CP12-S2 | `RestorationService` and the production CLI quarantine first, increment the generation, invalidate sessions/ceremonies, verify the exact recovered inventory, preserve current control authority and discard obsolete jobs. No control snapshot is installed as current authority. Native cases and the composed PITR drill verify this behavior. |
| CP12-S3 | Restricted Owner verification decrypts representative current/historical samples using current wrapped keys; only its signed acknowledgement opens normal access. Real Worker tests pass in all three bundled engines. The composed drill verifies five samples after actual resets/removals and current phrase recovery inside quarantine. |
| CP12-S4 | Export service/controller/Worker produce consistent schema-1 UTF-8 JSON with ordinary records, revisions, source manifest and readable history. Seven native/client cases and three browser cases verify plaintext acknowledgement, excluded security objects, complete scope and final authority. |
| CP12-S5 | Signed profile erasure requests, last-Owner successor requirement and access removal preserve shared/history data. Existing removal regressions and the new erasure/export cases verify cleared access/current responsibilities and the Former member label. |
| CP12-S6 | Signed name-confirmed requests use an exact 168-hour UTC deadline, notify all Owners and permit cancellation by any current Owner before that deadline. Native tests cover restrictions, interruption and the exact deadline race; real Worker browser cases cover confirmation, lost replies and equal-Owner cancellation. |
| CP12-S7 | Delayed-worker guards and an irreversible finalizer prevent expired access/recovery. Privileged purge deletes tenant payloads without bypassing FK integrity, then compacts physical tables and confirms WAL archival before recording completion. The actual composed purge and actual isolated repository-expiry drill verify deletion and bounded protected-backup lifetime. |
| CP12-F1 | Native and composed physical cases restore older content after member RESET, member removal, Owner removal and phrase rotation. Current credentials/keys persist, retired credentials/phrases fail, and an old checkpoint cannot reopen a deleted workspace. |
| CP12-F2 | Missing/changed encrypted objects or key manifests, invalid current history, incompatible schemas and failed projections/proofs leave quarantine closed. Only the current Owner route can acknowledge locally verified content; no operator decryption route exists. |
| CP12-F3 | Export revocation, changed source revisions, missing/duplicated objects and a failed final gate abort without producing a claimed-complete file. Private keys, credentials, security/recovery records and envelopes are excluded. |
| CP12-F4 | Lifecycle, job and composed cases cover equal-Owner cancellation, deadline races, requester departure, delayed finalization, old receipt/job replay, old snapshot restore and consumed-licence reuse. None revives deleted authority. |
| CP12-F5 | Cancellation and restore clear only their own restriction. Tests retain licence restriction and active content maintenance, including a partial upgrade resuming in the new generation. Hard expiry runs before replacement backups and can retire a contaminated repository when no clean base exists. |

## Operational drill measurements

| Executed drill | Result and scope |
| --- | --- |
| Physical backup plus named WAL replay | Both stores recovered the selected probe while the live primaries retained later values; 8,371 ms total. `checkpoint-12-physical-drill-4a7fff20-a6bf-4a44-b8b1-91f54b7f06ea.json`. |
| Synchronous security replica failure | Original write waited in `SyncRep`, did not acknowledge without its standby, and completed/replayed after that same replica returned. Wrong repository key was rejected. `checkpoint-12-replication-drill-repair-1.log`. |
| Composed recovery and purge | Selected point age 3,348 ms; 9,502 ms from restore start through current Owner verification; 22,774 ms for physical purge. Actual later RESET/removals/phrase rotation survived. `checkpoint-12-composed-drill-cc8c3d9a-132f-4587-9282-9f7d05572749.json`. |
| Actual repository expiry/retirement | 11,728 ms. Removed old full, retained/restored clean full, removed backup/archive payloads before stanza recreation, preserved running fixture data, and made a new encrypted full. `checkpoint-12-retention-drill-39e6f1fa-9b00-4cfc-9643-a768c3014625.json`. |
| Actual checkpoint scheduler | 14,682 ms wall time with Date-only scheduling advance of 300,001 ms. Immediate tick made no duplicate, due tick reused both daily bases, corrupted latest evidence fell back to an authenticated older point and was replaced. `checkpoint-12-schedule-drill-4b47cacb-14b1-4b38-948e-8dffc390ef86.json`. |

All report paths above are under `test-results/`. The deadline/retention/scheduling clocks are accelerated explicitly where indicated; database writes, encryption, archival, recovery, VACUUM and pgBackRest commands are real. The local repositories and standby share one computer. Small fixture timings demonstrate this local path, not a production guarantee or independent-host disaster resilience.

## Verification and review

Focused evidence includes 20 operational policy/record cases, four recovery-health cases, seven native/client export cases, seven native restore cases, six lifecycle/purge cases, two job deadline cases and nine browser executions. Counts across broader reports overlap; do not sum them as unique coverage.

The bounded operational review found delayed hard expiry, unbounded retained drill copies and the daily-only signed-manifest recovery gap. Each is repaired with focused and real operational evidence. A separate CP12 acceptance audit found no further material blocker after those repairs; it identified broad regression and matching runtime evidence as remaining gates. This is implementation/operational review, not checkpoint 13's independent composed security review.

Repair history, initial failures and immutable migration hashes are retained in [checkpoint-12-progress.md](checkpoint-12-progress.md). Runbooks and explicit drill commands are in [backup-operations.md](backup-operations.md).

## Final source and runtime

`test-results/checkpoint-12-final-coverage.json` maps each passing case to its retained report and records report hashes. Backend regression initially passed 551/552; the fixture-only repair passed the complete eight-case fence suite. Browser regression passed 119/120; its single missing-worker failure passed after the matching worker started. All 120 distinct cases are accounted for: 40 each in bundled Chromium **153.0.8010.12**, Firefox **155.0** and WebKit **26.6**. These do not substitute for checkpoint 13's branded-browser matrix.

The final candidate contains 359 source/configuration/test files, SHA-256 `62b204c112aabc855ea5e9885ef519e514708b2d4da800c4797e572594df1e10`. `checkpoint-12-final-candidate-snapshot.json` records each file and compiled hash. Since the broad regression candidate, only the repaired fence fixture and recovery CLI one-shot lifetime changed. The actual CLI initially closed its pools before the returned command promise settled; adding `await` inside its `try/finally` fixed that failure. The real one-shot tick then passed, and the daemon has completed multiple observed ticks. Its operational implementation and prior drill paths remain unchanged.

The running API and worker each match all **162 compiled application files**, aggregate SHA-256 `b765a4215d34a556a60443369e7afd9b7cb19fefbff9bbbb9c88dea9c3985eb2`. Migration replay applied zero changes across ten application and twelve control migrations.

- API image: `sha256:33358933421aaddad2bac4691a5036081a458e809a2c33960bd00e84cb609abd`.
- Worker image: `sha256:a005675d517cb6256f81695fcb3f3303dbb75590776161127d4b2ac8d65a2d54`.
- Recovery PostgreSQL image: `sha256:1a30455fe99f7830216c54d795ea8b9dd7ff88845336e0fa59e2b4633670c13d`.

At capture, API and worker liveness/readiness returned 200, queue health reported zero pending/failed supported jobs, and recovery health returned 200 with fresh backups/WAL, a durable synchronous standby and the recorded completed Owner drill. No active customer workspace existed at that moment: checkpoint coverage was explicitly zero eligible workspaces with a **null** age, not an invented zero-age recovery point. Actual nonempty coverage and corrupt-checkpoint behavior are proven by the separate scheduler drill. Runtime details are in `checkpoint-12-final-runtime.json`.

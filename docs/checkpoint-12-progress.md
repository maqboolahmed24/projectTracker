# Checkpoint 12 verification history

Checkpoint 12 is **verified**. Its final acceptance map, coverage and runtime association are in [checkpoint-12-evidence.md](checkpoint-12-evidence.md). This history retains initial failures and the bounded repairs. The previous goal turn only supplied goal wording; this continuation re-read authoritative state and completed checkpoint 12.

## Verified infrastructure, 27 September 2026

- PostgreSQL 18.6 and pinned pgBackRest 2.59.1 run in the local recovery Compose profile. Application and control stores have separate AES-256-CBC encrypted repositories and separate repository credentials. Repository credentials are outside the databases, backup volumes, source control and Docker build context.
- WAL archiving is enabled, with a sixty-second archive timeout. Daily scheduling and signed per-workspace checkpoint integration are still being implemented; the existence of the physical backup command does not claim the complete daily workflow.
- Initial full backups succeeded: application `20260927-004252F`, control `20260927-004254F`. Evidence: `test-results/checkpoint-12-physical-backup-initial.json`.
- The physical drill replayed both backups through later WAL to a named recovery point in new network-isolated containers. Restored rows matched the selected point; live primary rows retained later changes. Total elapsed time: **8,371 ms**; individual replay/start checks: **2,349 ms** application and **2,200 ms** control. These small local probe measurements do not establish production RPO/RTO or the composed Owner recovery matrix. Evidence: `checkpoint-12-physical-drill-4a7fff20-a6bf-4a44-b8b1-91f54b7f06ea.json`.
- The security replica reports `synchronous_commit=on`, one synchronous streaming standby and zero replay lag at capture. An actual replica outage left a write waiting in PostgreSQL `SyncRep`; it acknowledged only after the same replica returned. A deliberately wrong repository key failed `pgbackrest check`. Evidence: `checkpoint-12-replication-drill-repair-1.log`.
- Four focused recovery-policy tests passed: independent encrypted configuration, deletion deadlines overriding retention, missing/failed metric handling, and authenticated checkpoint-envelope tamper/identity/key rejection. Evidence: `checkpoint-12-recovery-policy-initial.log`.

The local volumes all share one computer. They demonstrate protocols and failure handling, not independent-host durability. The two isolated drill containers are stopped, with retained volumes available for inspection; neither replaced a live database.

## Repair accounting

The initial wrong-key drill expected `pgbackrest info` to return a nonzero exit status. It returns repository status inside its output instead. Repair 1 tried to parse that output, but wrong-key error bytes made the emitted JSON invalid. Repair 2 switched the check to the command's authoritative failure exit status, `pgbackrest check`, which passed. No backup key or customer plaintext was printed.

The next assertion exposed a separate drill issue: PostgreSQL's implicit commit waited for the synchronous replica beyond the statement timeout. The live process was inspected and the same replica restarted to release it; the write was not repeated. Replication-drill repair 1 now observes the real `SyncRep` wait, restarts the replica, and awaits that original write. It passed. No synchronous durability setting was weakened.

The initial combined TypeScript build found export/restoration type errors and one lifecycle fixture call mismatch. Build repair 1 passed. The first functional run passed 16/20 cases. Functional repair 1 passed 19/20; the remaining purge failure is described below. Tests do not yet prove the complete operational checkpoint.

## Functional verification

- All seven export client/service cases passed: complete ordinary data and history, exclusion of security objects, explicit plaintext acknowledgement, consistency invalidation, mid-export Owner revocation, and final authority checks. Chromium export also passed through the real Worker.
- All seven native restoration cases passed, including actual member RESET, Owner phrase rotation/recovery, member and Owner removal, later password change, missing content/keys, interrupted projection, licence/maintenance preservation, schema downgrade denial, and a partial upgrade resuming after restoration. These fixtures install selected captured rows; physical PITR is separately verified and the composed operational drill remains required.
- Five lifecycle cases passed, including equal-Owner cancellation, exact 168-hour deadlines, interrupted responses/projection, requester removal, profile erasure, and cancellation crossing the exact deadline while finalization wins.
- Two recovery-health cases passed. Eight initial operational-record cases passed, but review found that their mocked expiry checks did not cover delayed expiry or old retained drill volumes; the new repairs require stronger evidence.
- Both job/deletion deadline checks passed after fixture repair 1 supplied the required request timestamp. Delayed finalization cannot make obsolete jobs replayable or recreate inbox payloads.
- Chromium lifecycle passed. Chromium restoration initially failed because its fixture never installed the captured checkpoint; it now installs that exact snapshot and passes strict verification, lost acknowledgement recovery and ordinary access reopening. Production manifest validation was not relaxed.

Retained reports: `checkpoint-12-focused-repair-1.log`, `checkpoint-12-job-deadline-repair-1.log`, `checkpoint-12-browser-initial.json`, `checkpoint-12-browser-restore-repair-1.json`, and `checkpoint-12-recovery-records-initial.log` under `test-results/`.

### Remaining repairs and review findings

Purge repair 1 flushed deferred constraints before re-enabling user triggers. The next run reached the control-store purge and found immediate child/parent FK ordering (`grants` referencing `devices`). Repair 2 adds a new migration that deletes immediate FK children first while preserving all integrity checks. Its expanded purge case passed, including actual joined-member dependencies, active upgrade data, zero remaining tenant payloads and re-enabled immutable-history triggers. No applied migration was edited. Evidence: `checkpoint-12-purge-repair-2.log`.

Operational review found two retention gaps: a replacement full backup could delay hard expiry, and standalone drill volumes lacked routine age cleanup. Repair 1 now runs expiry before backup work with a one-day margin, never attempts a replacement before sanitizing both stores, and age-limits only verified-owned artifacts. Twenty focused operational policy/records cases passed, including the later RPO additions (`checkpoint-12-ops-final.log`).

The restore API uses exact signed named checkpoints. Capturing them only daily would leave up to 24 hours of unrecoverable later content despite continuous WAL. It now captures them every five minutes, reusing a daily full backup, and separately measures authenticated checkpoint coverage/age. Four health cases passed; fresh WAL cannot mask a stale/missing usable manifest. The actual scheduler drill passed: `checkpoint-12-schedule-drill-4b47cacb-14b1-4b38-948e-8dffc390ef86.json` records 14,682 ms wall time, a Date-only five-minute advance, unchanged daily full labels, rejection of a corrupted latest checkpoint, authenticated older fallback and replacement.

## Composed operational evidence

The actual checkpoint → named-WAL PITR → current-authority reconciliation → Owner local verification → final deletion → physical purge drill passed. Evidence: `checkpoint-12-composed-drill-cc8c3d9a-132f-4587-9282-9f7d05572749.json`. It used the production CLI dispatch and real repositories/databases with fixture service/customer keys. The selected point was **3,348 ms** old at simulated failure; restore through Owner verification took **9,502 ms**; physical purge took **22,774 ms**. Five current/historical ciphertext samples verified locally. Later member RESET, member removal, Owner removal and phrase rotation remained authoritative; current phrase recovery worked in quarantine. An old snapshot after deletion and reuse of the consumed licence both failed. Its deletion-deadline clock was explicitly advanced; these local measurements do not establish production recovery guarantees.

The initial composed drill reached PITR but failed reading the recovered rows because `docker exec` omitted `-i` for stdin-fed SQL. Repair 1 added that flag; the complete drill then passed. No manifest or authority check was weakened.

The isolated real pgBackRest retention drill passed in **11,728 ms** (`checkpoint-12-retention-drill-39e6f1fa-9b00-4cfc-9643-a768c3014625.json`). It proved encrypted/wrong-key behavior, expiration of a contaminated full while preserving and restoring a clean full, deletion of both backup and archive payloads before stanza recreation, survival of the running fixture database, and a successful new encrypted full. All throwaway resources were removed. Policy time was accelerated explicitly. Two earlier fixture setup failures (version-command stanza option and restore-directory ownership) were repaired separately; neither changed production retention rules.

All three new browser journeys now pass on each bundled engine: Chromium, Firefox and WebKit, **nine cases** total. Evidence combines the initial Chromium export/lifecycle results, the repaired Chromium restore result and `checkpoint-12-browser-firefox-webkit.json`. This is not checkpoint 13's branded current/previous stable browser matrix.

## Applied migrations

Migration application succeeded and these files are now immutable:

- Application 009: `2ff1bd57374d61b628f6b6871c28a935accf8dd50095d786fc7a9488f538619b`.
- Control 010: `10ee53e06b4bba4351a6705d774f817747b250eeb7a5804859efa21c10459681`.
- Application 010: `da8c4d04c854e83d134d71728d5ac722ea7054969c0189f56eb286ebc45b4c3f`.
- Control 011: `5beea9a26030011a554c2c85c841959633e5e55d86c2484f4353e305b95bdfef`.
- Control 012: `2803abdf9f588c2a49d799fbb9f7bf66f49bea461a380efca360d02eaa3cd239`.

Evidence: `test-results/checkpoint-12-migrate-initial.log`, `checkpoint-12-migrate-repair-1.log` and `checkpoint-12-purge-migrate-repair-2.log`. SQL repairs require a new migration.

## Remaining acceptance work

Backend regression ran **552 cases: 551 passed and one legacy fixture failed**. It fabricated deletion directly from pending activation/security version zero, which production never does: unactivated reservations are removed, while the signed finalizer increments committed authority. Fixture repair 1 preserves the pending assertions and uses a separate activated fixture for deleted-state/head/generation/tombstone assertions. All eight security-fence cases then passed. This gives **552 distinct passing backend cases**, without rerunning unaffected successes. Reports: `checkpoint-12-backend-regression.log` and `checkpoint-12-fence-fixture-repair-1.log`. Production code and constraints were unchanged by this repair.

The 120-case browser regression passed 119 cases. Its first Chromium notification case failed because the live queue worker had deliberately been stopped for earlier recovery work; no fixture-owned worker is started by that suite. The matching rebuilt worker started, Firefox and WebKit passed, and the affected Chromium case passed its focused rerun. All **120 distinct browser cases** are verified.

The final real CLI invocation exposed a one-shot resource-lifetime error: returning its promise without awaiting it ran `finally` and closed pools too early. Repair 1 adds the required await. The real tick passed and multiple daemon ticks were observed. Matching API/worker application hashes, unchanged migration replay, healthy databases/replica, zero supported queued/failed jobs and healthy recovery monitoring complete the runtime evidence. Checkpoint 12 is checked; checkpoint 13 remains open.

Operational design references: [pgBackRest retention configuration](https://pgbackrest.org/configuration.html#section-repository/option-repo-retention-full-type), [PostgreSQL physical recovery](https://www.postgresql.org/docs/18/continuous-archiving.html), and [durable synchronous replication](https://www.postgresql.org/docs/18/warm-standby.html#SYNCHRONOUS-REPLICATION).

# Checkpoint 11 verification history

Checkpoint 11 is **complete**. The final acceptance record is [checkpoint-11-evidence.md](checkpoint-11-evidence.md). Checkpoints 12–13 remain open. This file retains the chronological verification and repair history; pending statements below describe the state at those earlier runs.

## Queue and receipt slice — 27 September 2026

Six distinct focused tests passed against local PostgreSQL, Node 24.19.0, and Graphile Worker 0.18.0. The listed new files were transpiled with esbuild and tested against the previously verified CP10 compiled dependencies. The full CP11 TypeScript build, browser journeys, encrypted upgrades, and composed regression checks remain pending.

- `test/jobs.test.ts`: bounded jitter and sanitised stored errors; a real job failing ten times, retained failed state without an eleventh automatic attempt, same-identity operator replay, outbox reconciliation, and duplicate delivery; denial of replay for obsolete generations, deletion, unknown tasks, and malformed IDs.
- `test/receipts.test.ts`: strict authenticated HTTP, actor/workspace binding, logout/login lookup without the local request, current scope denial; actual committed receipts for all nine supported business kinds, with deletion overriding every kind.
- `test/worker.test.ts`: real queue deduplication under restricted database credentials and readiness/queue metrics returning unavailable on a real connection outage.

The source, compiled runtime, and report hashes are retained in `test-results/checkpoint-11-queue-receipts-snapshot.json`. Reports:

| Report | Result and repair history |
| --- | --- |
| `checkpoint-11-jobs-initial.log` | Jitter test passed. Failure mirroring timed out; deletion fixture omitted the required deletion timestamp. |
| `checkpoint-11-queue-diagnostic.log` | Direct persisted failure reconciliation passed. Inspection showed Graphile's completion event can precede batched failure persistence. |
| `checkpoint-11-jobs-repair-1.log` | Real ten-attempt/replay test passed after polling exact pending failure IDs. Deletion denial checks ran, but fixture cleanup used a pool already closed by an earlier teardown hook. |
| `checkpoint-11-jobs-fixture-repair-2.log` | Operator-denial test and teardown passed after cleanup was registered before fixture shutdown. |
| `checkpoint-11-receipts-initial.log` | Both receipt integration tests passed on their first run. |
| `checkpoint-11-worker-metrics.log` | Updated real queue/outage test passed on its first run. |

No unresolved failure in this slice exceeded the three-repair limit. A preliminary diagnostic invoked through Node's `--input-type=module` could not launch the fixture Worker because that flag is inherited; rerunning the same diagnostic from a saved module resolved that diagnostic environment issue.

Implementation: `src/jobs.ts`, `src/worker.ts`, `scripts/jobs.ts`, `src/shared/receipts.ts`, and `src/modules/work/{receipts,receipt-routes}.ts`. Operator instructions are in [job-operations.md](job-operations.md). Receipt acknowledgements do not advance security pins or install keys. Exact retained requests continue to use the original signed-payload verification paths.

## Combined candidate — initial verification

The combined TypeScript build passed (`checkpoint-11-build-repair-2.log`). Application migration 008 and control migration 009 applied successfully; replay applied zero migrations (`checkpoint-11-migrations.log`, `checkpoint-11-migration-replay.log`). Neither applied migration may be edited.

The first focused compiled run completed with **21 passed, 5 failed, 26 total** (`checkpoint-11-focused-initial.log`). Passing cases include historical decoding, strict schema rejection, signed identity lifecycle verification, actual Owner removal/key rotation/takeover, licence/deletion/restore restrictions, final deletion overriding retained receipts, job retries/replay, receipt lookup, retained conflict input, durable reporting/Inbox requests, and native team/collaboration history checks.

The five failures remain acceptance failures until rerun:

- The complete native upgrade found that pending profiles committed in the control store were absent from the starting application inventory. Start projection then introduced the missing record. Repair 1 includes authoritative pending ciphertext in a coherently locked source manifest.
- Fault-injection rollback did not fire because the fixture captured an old planning service instance. Repair 1 uses its live service getter.
- The unknown-schema test tried to regress authoritative schema 99 to 1; the monotone security trigger correctly rejected that cleanup. Repair 1 removes the invalid reset.
- Both planning upgrade cases leaked an extra caller `manifest` field into a strict signed proof. Repair 1 selects the declared proof fields, retaining independent authenticated manifest checks.

A bounded read-only agent audit also identified pending custom-role invitation compatibility after a representation-only migration and stale stored schema-version metadata. Fixes and focused regression assertions are prepared; they are not yet verified. This checkpoint review is not the independent composed security review required by checkpoint 13.

## Focused repairs verified

`checkpoint-11-focused-repair-1-build.log` and `checkpoint-11-browser-build.log` both passed. The six focused backend cases passed in 18 seconds (`checkpoint-11-focused-repair-1.log`): all five initial failures plus the new custom-role enrolment case. The native lineage case checks current and retained schema metadata and preserves exact historical rows. Every initial runtime failure was resolved on its first focused repair.

All nine new browser cases passed: three each in Chromium, Firefox, and WebKit. Retained reports are `checkpoint-11-browser-initial.json` and `checkpoint-11-browser-additional-engines.json`, with matching `.log` files. They exercise explicit conflict reapplication, offline denial, durable lost acknowledgements, failed and confirmed signout, and complete Owner takeover of an interrupted upgrade after page reload. These are bundled-engine checks, not the branded-browser release matrix required by checkpoint 13.

The tested candidate is recorded in `checkpoint-11-candidate-snapshot.json`: 301 source/configuration/test files, source SHA-256 `789dc8cb8b523245a3e798ba91057d5ec2b6c7c28428ac1576e98c21e9dc69a5`, with 1,182 compiled/browser file hashes. The shared protocol changes require baseline regression checks, which are still in progress. The headless operation sequence is documented in [encrypted upgrades](encrypted-upgrades.md).

## Pending acceptance work

The broad backend run (`checkpoint-11-backend-regression.log`) completed with 499 passing cases, one assertion failure, and two timed-out cases. The assertion identified loss of the independent original-head pin comparison in collaboration history; repair 1 restores it while preserving intermediate upgrade lineage checks. The two timeouts identified Forget waiting for a held pairing/password transport response. Repair 1 makes their local network continuations abort-aware while retaining cleanup drains and the original late-response tests. The deadlocked pairing child was explicitly terminated after its recorded 120-second test timeout so the rest of the suite could finish. Password timeout completed without manual termination.

All **47 affected cases passed** after those first repairs (`checkpoint-11-regression-repair-1.log`), including the entire interrupted pairing file and the original held-response checks. `checkpoint-11-backend-coverage.json` records **506 distinct passing backend cases**, report hashes, and the four source/test files changed since the broad run. TypeScript/browser rebuilds passed. The updated API and worker started healthy; `checkpoint-11-runtime.json` records actual readiness and queue metrics, not assumed zeros.

That runtime inspection exposed a separate real defect: 555 old scheduled `request_budget_cleanup` jobs failed because strict empty-payload validation rejected Graphile's native `_cron` metadata. Every retained error in that cohort identifies `_cron` (`checkpoint-11-cron-diagnostic.json`); raw errors and payloads were not printed. A strict native-metadata validation repair and a real-worker regression test are prepared. The current browser regression run uses its frozen candidate and running worker; test/build/replay of this additional repair waits for that run to finish. No other failed job has been deleted or replayed.

Build and test the focused repairs and additional audit fixes; run the browser retry and upgrade journeys and relevant regression checks. Then verify all CP11 success/failure criteria before checking off checkpoint 11. The local API and worker containers were stopped before this work; database containers remain running. Rebuild and restart services after a verified combined candidate is available.

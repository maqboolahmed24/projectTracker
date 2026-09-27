# Checkpoint 11 — reliable edits, jobs and encrypted upgrades

Verified on 27 September 2026: **507 distinct backend cases and 111 browser cases passed**, with no unresolved checkpoint failures. The matching local API, worker and both databases are healthy. Checkpoints 12–13 remain required.

## Acceptance map

| Check | Implementation and executed evidence |
| --- | --- |
| CP11-S1 | Planning edits bind an explicitly reviewed pin. `planning-client.test.ts` and `browser/retry.spec.ts` prove one committed revision, retained unsaved input on conflict, deliberate reapplication with a new operation, and no automatic reconnect submission. |
| CP11-S2 | Durable signed-request stores and current-access receipt lookup retain exact ciphertext across reload and lost replies. `receipts.test.ts` covers all nine business kinds, actor/tenant/scope/generation checks and deletion overriding receipts. Browser retry tests verify failed signout preserves requests and confirmed signout clears them without deleting device wrappers or trust pins. |
| CP11-S3 | `planning-service.test.ts`, `task-workflow-service.test.ts` and `collaboration-service.test.ts` exercise atomic moves, cancellation/review cascades, records/history/audit/receipts/jobs rollback, and two independently identified concurrent posts. |
| CP11-S4 | `jobs.test.ts` exercises a real ten-attempt queue, bounded jitter/backoff, sanitised failure storage, duplicate delivery, retained-identity replay, and obsolete/deleted-job denial. `notifications.test.ts` verifies current recipient scopes. `worker.test.ts` verifies real readiness/queue outage behaviour. `worker-cron.test.ts` verifies native scheduler metadata and expiry-only cleanup. |
| CP11-S5 | Explicit historical decoders and the typed schema-1-to-2 transform preserve exact original signed history. Schema, crypto, planning and native service upgrade tests prove current revision/epoch validation, immutable snapshots, preserved review intent, finite batches and summary invalidation. The browser journey completes all native lineages through actual Worker cryptography. |
| CP11-S6 | Upgrade restriction tests remove the initiating Owner, rotate keys, reject prepared stale batches, and finish under another current Owner. They exercise licence/deletion/restore guards and terminal tombstones. `recovery.test.ts` completes member RESET while maintenance and other restrictions remain set. |
| CP11-F1 | Planning, receipt, schema and upgrade tests reject changed request bytes, stale revisions/authority, revoked scopes, wrong schemas/epochs and obsolete generations without partial commits. |
| CP11-F2 | Browser tests inject failure before forwarding and response loss after commit. Service tests cover concurrent comments and partial multi-record rollback; worker tests cover duplicate execution. Pairing/password tests retain their original held-response assertions and prove Forget cannot wait indefinitely or recreate erased local material. |
| CP11-F3 | Unknown formats fail closed; old writers cannot replace schema-2 records. Upgrade tests preserve verifiable history through interruption, Owner removal, key rotation and independent restrictions. Custom-role invitation tests distinguish representation-only upgrades from genuine role-definition changes. |

Deletion/restore restrictions are tested through explicitly labelled fenced authority fixtures here; checkpoint 12 still owns their user-facing producers and drills. Owner phrase recovery is separately verified; completed RESET supplies the composed maintenance recovery check. No checkpoint-13 independent security-review or branded-browser claim is implied.

## Retained verification

`test-results/checkpoint-11-final-coverage.json` links source/runtime and report hashes. The backend coverage register maps every distinct passing case to its report; the browser register records 37 cases each in Chromium 153.0.8010.12, Firefox 155.0 and WebKit 26.6. These are bundled engines.

- The first focused run passed 21/26. All five failures plus the new enrolment regression passed after repair 1.
- The broad backend run passed 499 cases and exposed one collaboration-pin assertion failure plus two cancellation timeouts. Its interrupted pairing child was explicitly terminated after the recorded timeout; the complete affected files subsequently passed. The 47-case repair run includes every previously unreachable pairing case.
- All nine new browser cases passed; the later 105-case regression also passed. Six unchanged retry cases retain their earlier result, giving 111 distinct cases.
- The real-worker cron case passed after its first repair. An operational replay then completed all 555 scheduler-origin cleanup jobs diagnosed with rejected `_cron` metadata, retaining their IDs. The replay helper initially stopped before mutation because PostgreSQL microsecond precision exceeded the diagnostic's millisecond timestamp; matching the recorded timestamp precision resolved that bounded diagnostic failure.

Detailed early queue/build failures and repair history remain in [checkpoint-11-progress.md](checkpoint-11-progress.md). No unresolved failure exceeded the three-repair limit. Successful unaffected tests were retained; reruns covered the changed code and its dependants.

## Source and local runtime

The final candidate has 302 source/configuration/test files, SHA-256 `600fa5c294533af3b0246420fff7d003d70d8098f50fbdcf21bd76abafb1e378`. `checkpoint-11-final-candidate-snapshot.json` records individual source and compiled hashes. The final worker-only repair changed no browser code; its earlier candidate is retained separately.

TypeScript/browser builds passed. Migration replay applied zero changes across eight application and nine control migrations. Application migration 008 and control migration 009 remain immutable, with hashes recorded in the candidate manifest.

`checkpoint-11-final-runtime.json` records HTTP 200 API liveness/readiness and worker readiness/queue metrics. Supported jobs report zero failed jobs and one pending earlier cleanup retry at capture time; it retains the normal backoff schedule. This is an actual metric, not a claim of an empty queue.

- API image: `sha256:99ea54b8187f097661b9d87b9ecea86be4cb85b17082312fb149c9ab85ed8784`.
- Worker image: `sha256:a4a6c720246212e11b6812dd184a67b784742b8db780b96389e0303baa438161`.

Operation instructions: [encrypted upgrades and request recovery](encrypted-upgrades.md), [hosted job inspection and replay](job-operations.md). Setup remains in [README.md](../README.md). Independent composed security review, restore/deletion drills, the branded-browser matrix and production release gates remain open under checkpoints 12–13.

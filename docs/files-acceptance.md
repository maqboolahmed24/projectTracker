# Project files acceptance evidence

These measurements were taken on 29–30 September 2026 with Node 24.19.0 on the development Mac. Database tests used separate PostgreSQL application and control stores on ports 56432 and 56433, configured by `.local/testing/project-files.runtime.env`. They did not use the existing local workspace or cloud data. Times and memory below describe this machine and workload; they are not latency or memory guarantees for other environments.

## Planning history for 512 complete task lifecycles

`RUN_PLANNING_CAPACITY=1 node --env-file=.local/testing/project-files.runtime.env --test dist/test/planning-capacity.test.js` passed in 81.5 seconds. The fixture generated genuine schema-2 signed history for 512 tasks, two Owners, independent reviews and 16 corrections. All 512 tasks exercised the planning lifecycle. This case measures transport and client verification; it does not create 512 uploaded documents in the database.

| Measurement | Result |
| --- | ---: |
| Signed operations | 2,115 |
| Bounded history pages | 34 |
| Largest page | 4,262,943 bytes |
| Complete assembled history | 125,346,708 bytes |
| Initial context frame | 1,022,125 bytes |
| Fixture creation | 44.716 s |
| History assembly | 5.605 s |
| First client verification | 25.505 s |
| Verification with the bounded cache | 2.045 s |
| Reopen and verify | 3.627 s |
| Peak process resident memory | 1,092 MiB |
| Heap at measurement | 416 MiB |

Revision-reference sharing reduced the earlier peak from 1,534 MiB to 1,092 MiB without changing signed bytes. These figures include the Node fixture and client in one process. They do not establish browser memory use. History pages retain the 64-operation and 16 MiB wire limits; assembled verification retains finite 8,192-operation and 384 MiB limits.

## Real database with 512 registered document tasks

`RUN_FILES_CAPACITY=1 node --env-file=.local/testing/project-files.runtime.env --test dist/test/files-capacity.test.js` passed in 121.4 seconds. It registered 512 genuinely signed document tasks with stable document references, two contributors and one independent reviewer. Every task received a pinned link to one real encrypted shared source through eight bounded 64-item link requests. A simulated lost acknowledgement retried the exact existing request successfully.

Two representative tasks then exercised actual encrypted uploads, byte verification, submissions, independent file reviews and planning approvals. One used a managed output and one used an external reference. A correction reopened the first task, rejected its old delivery evidence and approved a new immutable output version. Downloaded managed bytes matched their originals. The recovery checkpoint contained every ready version and verified the real stored ciphertext inventory.

| Measurement | Result |
| --- | ---: |
| Registered document tasks / source links | 512 / 512 |
| Representative tasks completing exact file review | 2 |
| Corrections | 1 |
| Planning operations / assembled bytes | 521 / 19,394,726 |
| Ready managed versions / external references | 3 / 1 |
| Retained binary bytes / chunks | 1,311,076 / 8 |
| Accounted storage / outstanding reservation | 1,312,336 bytes / 0 |
| Signed task fixture creation | 7.998 s |
| Link and read workload | 29.771 s |
| Representative workflow | 83.577 s |
| Peak process resident memory | 784 MiB |
| Heap at measurement | 166 MiB |

Task creation in this case was fixture-seeded through genuine signed records. Only two representative document tasks completed the full file workflow. The separate planning case covers all 512 task lifecycles. Neither measurement claims 512 separate uploaded and independently reviewed outputs, physical shared-drive publication, an actual backup/WAL restoration drill, browser memory measurements or a production cloud load test.

## Focused recovery, export and review checks

`node --env-file=.local/testing/project-files.runtime.env --test dist/test/files-restoration.test.js dist/test/files-export.test.js dist/test/file-evidence.test.js` passed all four cases in 3.6 seconds:

- File-aware recovery hashed all immutable ciphertext, retained readable current and historical versions, kept external references as metadata, rejected a tampered verification sample, advanced the data generation and cancelled old incomplete writes and reservations.
- An actual signed version-1 checkpoint retained its original table catalogue and version-1 Owner acknowledgement through reconciliation and completion.
- Workspace JSON included private immutable version metadata. A bounded private ZIP contained authorised managed bytes and its manifest; external paths were never fetched. Access-fence changes and an export snapshot changed before finalisation were rejected.
- Exact review required actual bytes, denied self-review and missing file evidence, preserved idempotent receipts, rejected delivery before planning approval and after revocation or reopening, and required explicit Owner approval for a shared external source.

The seven existing restoration-service cases and seven existing export client/service cases also passed after these changes. The 13 recovery-records checks passed, including retention and the paginated snapshot installer. Browser, local-service publication and editor acceptance are tracked separately from the measurements in this document.

## Bulk assignment, submission and acknowledged evidence

`node --env-file=.local/testing/project-files.runtime.env --test dist/test/files-bulk-controller.test.js dist/test/file-evidence.test.js` passed both cases in 9.1 seconds. The bulk case uses the actual `FileBulkController`, `FilesController`, `PlanningController` and `FileEvidenceController`, real cryptography, IndexedDB stores and their HTTP transports dispatched directly to the production services on isolated PostgreSQL. It does not fake business state or completed receipts.

- Explicit assignment mappings were applied to two tasks. The first successful item stayed saved when the second lost its committed acknowledgement; a deliberate retry recovered the second without another signed assignment. A third item with the wrong document reference failed closed and left its task unchanged.
- Two explicitly mapped outputs were uploaded and submitted. A committed submission lost its acknowledgement, leaving that item resumable while preserving the first successful item. Retrying recovered the exact saved submission and planning transition; the database contained exactly two submissions and two completion requests.
- Acknowledged evidence uses a bounded displayed-context checkpoint. A concurrent assignment change rejected the stale acknowledgement before any new retry record or signature; a fresh unchanged acknowledgement succeeded despite new read-request timestamps.
- An Owner who authored an output but was not an assignee still failed both client and server independent-review checks. The existing exact-evidence case additionally denied an assignee's self-review.
- Completed encrypted evidence receipts survived a store reopen, disappeared from the pending list and supported stable-operation retries. Reusing their operation ID for a different action, task or project failed. Explicitly forgetting the device removed those receipts.

An additional focused regression run reported by the integration agent passed 23 existing authentication-controller, authentication-retention, planning-service, isolation, legacy and paged-history cases in 52.1 seconds. The application TypeScript build and `git diff --check` passed after these changes.

## Frontend file journey

The final production browser bundle, frontend TypeScript check, application TypeScript check and Next.js production build passed. The following final journey passed in Chromium (28.2 seconds) and WebKit (24.6 seconds), two cases in 55.3 seconds:

```sh
TMPDIR=/tmp node --env-file=.local/testing/project-files.runtime.env node_modules/@playwright/test/cli.js test test/frontend/files.spec.ts --config playwright.frontend.config.ts --project chromium --project webkit
```

The browser used the actual authenticated file, planning, evidence and delivery service fixture on the separate PostgreSQL stores. It created and deleted synthetic records only. Assertions covered:

- A committed upload with a lost chunk acknowledgement resumed without sending that chunk twice.
- Adding a second immutable version preserved the first version's original bytes. Preview, Versions and Linked work kept the same dialog position and dimensions, with less than two pixels of allowed measurement variation.
- An external reference clearly excluded contents from cloud backups. Choosing different bytes failed the check; choosing the actual matching file enabled its preview without offering a cloud download.
- A two-document registration batch used explicit document references and assignments. One committed completion lost its acknowledgement; the other item remained saved. A deliberate retry finished the interrupted item without another upload or task creation, and left no pending upload record.
- The private archive contained the selected managed file's current bytes and external reference metadata, with no external file contents.
- Light and dark Files and preview views rendered without page errors. Dark canvas matched `#101113`; a 390-pixel viewport had no horizontal page overflow. The registered tasks were present in the real Work view.

Final screenshots were inspected under `test-results/frontend-artifacts/files-project-files-preser-5bc1e--and-export-honest-contents-chromium/` and the equivalent `-webkit/` directory. Both contain `files-light.png`, `files-dark.png`, `file-preview-light.png`, `file-preview-dark.png` and `files-mobile-dark.png`. Chromium also records the compact registration mapping and interrupted-result dialogs. These are disposable test outputs, not checked-in product assets.

Before the final Files-only pass, the existing remembered-profile sign-in/logout/Forget journey and the existing waves/tasks/comments/completion/archive journey also passed in Chromium (9.5 and 39.8 seconds). Exact submission/acceptance concurrency and bulk assignment/submission are covered by the actual-controller cases above. Preview-format, local publication and actual ONLYOFFICE edit/save checks have separate acceptance evidence; this Files journey does not claim those interactions.

The installed Firefox engine failed before page launch with a temporary-profile folder error on this Mac, including with `TMPDIR=/tmp`. Firefox browser acceptance is therefore unverified. No browser security setting was disabled to bypass this environment failure. The final frontend is frozen after these focused checks.

## Cloud release

The reviewed application was deployed on 30 September 2026. Live encrypted upload/version download, external-reference, companion-download integrity and signed checkpoint inventory checks pass. See the [cloud release record](files-cloud-release.md) for exact images, storage admission, evidence and the separately tracked full CI result. These production smoke checks do not establish a 512-task cloud load capacity.

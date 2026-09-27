# Checkpoint 8 — shared task execution, review and blockers

Status: verified on 26 September 2026. Checkpoints 1–8 are complete. The final acceptance mapping and combined test evidence appear below; later collaboration, reporting and release gates remain required.

## Required behaviour and verification scope

Use the existing project planning transaction and signed history. One task retains one identity, shared private content and lifecycle regardless of its number of assignees. Comments and notification delivery remain checkpoint 9 dependencies; they must reference this same task identity.

| Acceptance | Required evidence |
| --- | --- |
| CP08-S1 | Create shared work, edit one common description/date/acceptance record, change assignments with explicit lead clearance/replacement, and preserve attribution for surviving assignments. Title-only creation remains possible under authenticated role defaults. |
| CP08-S2 | Real task execution/completion rejects Planned or terminal/archived containing scopes; preparation and cancellation work in Planned scopes. Custom-role capability tests and restricted Owner-device checks use current signed authority. |
| CP08-S3 | Review starts disabled. Enabling supplies eligible non-assignee reviewers for unfinished work. Submit/reject/resubmit/approve records submitted content and policy revisions. Missing reviewers lose authority immediately; a separately eligible Owner can replace one explicitly. |
| CP08-S4 | Content and assignment edits invalidate pending review. Done/Cancelled work needs explicit reopen/restore; both reopen Accepted milestones atomically. Owner-only review disable records a reason and returns pending Review tasks to In progress. Previous approvals and snapshots remain history. |
| CP08-S5 | Multiple task blockers retain encrypted reason/next action, eligible responsibility and actor/time history. Resolution needs an outcome; reopening needs a reason. Assigned editors and managers have the specified distinct responsibility permissions. |
| CP08-F1 | Deny self-approval, stale content/task/policy revisions, removed/newly assigned reviewers and hidden ciphertext substitution during approval. Metadata changes reuse exact task content ciphertext. |
| CP08-F2 | Any Open blocker prevents completion; resolving only one of several leaves the task blocked. Done tasks must reopen before introducing an Open blocker. |
| CP08-F3 | Read/comment-only actors cannot change assignments or blockers. Cancelled tasks retain inactive blockers; restoration reactivates Open blockers. Access removal clears responsibility without resolving the blocker, including archived scopes. |

Checkpoint 7 integration obligations: exercise actual Done/Review task producers against milestone/wave/project closure guards; task reopening/restoration must reopen Accepted milestones in the same transaction and preserve earlier closing snapshots.

## Compatibility evidence prepared

`test/fixtures/planning-v1.json` captures six signed operations and two closing snapshots from the verified checkpoint 7 production modules (source SHA256 `4af6dfa04fbfbb9c41c96cde80b77d47a42352965fabb5b92000304a218e0d66`). It includes task creation, acceptance reopening, cancellation and project reopening. All data is synthetic; the fixture contains public signatures and ciphertext, with no private keys, phrases or passwords. `test/planning-legacy.test.ts` requires the extended verifier to retain its original graph, operation digests and snapshot bytes and reject retroactive workflow defaults. Both compatibility checks passed against the integrated checkpoint 8 implementation.

The version extension must preserve original v1 operations and receipts, reject obsolete first writes, and separate task metadata revisions from content-envelope revisions. Existing applied migrations remain immutable; any required schema change belongs in a new migration.

## Executed results

The saved legacy fixture verifies against the frozen CP07 modules; its six signed operations and two snapshots retain their exact digests, while injected workflow defaults and a changed snapshot are rejected. Report: `test-results/checkpoint-08-legacy-fixture-baseline.log`. This establishes the fixture baseline, not compatibility with the still-unverified CP08 implementation.

Application migration `004_task_workflow.sql` was applied with both API and worker stopped cleanly: application 1 applied / 3 unchanged; control 0 applied / 8 unchanged. SHA256: `5fffc511081342d01a3ee425067207cf8e8e67a6ce8f1940c5a3c6f5d64a35ef`. Reports: `test-results/checkpoint-08-stop.log` and `test-results/checkpoint-08-migrations.log`. The migration adds project review policy, independent task/blocker content revisions and current approval/submission references. The applied file is immutable. The matching services were subsequently built, restarted and verified healthy.

Implementation and focused verification are complete as recorded below. No production-release or independent-security-review claim is made by this checkpoint.

The first integrated build found two v1/v2 narrowing errors in the new permission tests; production sources compiled. Focused type repair 1 passed the build (`test-results/checkpoint-08-initial-build.log`, `test-results/checkpoint-08-build-repair-1.log`). Static review then found and closed a reviewer-selection gap on task creation: selecting an eligible reviewer also requires `manage_tasks`, just as replacing a reviewer does. Both pure-domain and valid-signer service rejection checks were added before the initial workflow test run. Current blocker responsibility cleanup now includes Open and Resolved blockers while preserving creator/resolver attribution. The corresponding domain, client and service checks passed.

The initial integrated candidate contains 214 files, SHA256 `8d7e97e891e544eb5d0972234e3b16229fe4ab7b74db723dd2bae7bc7d32dd0b` (`test-results/checkpoint-08-initial-candidate-snapshot.json`). It builds successfully (`test-results/checkpoint-08-workflow-build.log`); an additional readonly-array typing error in the newly added reviewer-creation test was fixed before this build. The browser bundle also builds successfully.

The first focused run passed **65 of 68** checks, with zero cancelled/skipped, in 83.464 seconds. Report: `test-results/checkpoint-08-initial-focused.log`, SHA256 `07e6b42efeb9c16175153e264dba745ad05a0602e193bd80e1e83514f1873a0b`. Passing evidence includes the original signed v1 fixture, all sixteen new domain checks, all three new client checks, real custom-role denial and reviewer reassignment, task restoration through reopened parents, assignment-removal review invalidation, lost reviewer cleanup, exact retained ciphertext, archived responsibility cleanup and previous planning/read regressions. Three service journeys fail with `INCOMPLETE_KEYS` after adding another Owner to an existing project. Diagnosis found that `test/access-change-fixture.ts` sealed the original genesis custody-manifest reference into a new Owner delivery even after project creation had replaced that manifest. Production enrolment resolves current verified material. Focused repair attempt 1 replaces this test-only construction with the production approval helper, and moves browser Owner enrolment after project creation to verify that order through the real client. No acceptance is claimed until repaired tests pass.

The initial browser run passed **21 of 21** checks (seven each on bundled Chromium, Firefox and WebKit), with no retries, in 3.5 minutes. Reports: `test-results/checkpoint-08-initial-browser.log` and `test-results/checkpoint-08-initial-browser.json`; JSON SHA256 `0c5716d1f8fb73582423ee8571a38496a87becc27f4515bf9ac70a146029134c`. It covers shared-task execution, blockers, independent review, lost-response receipt recovery and checkpoint 7 closure regressions. The reordered Owner-enrolment journey passed in the later focused run below. This is bundled-engine evidence, not checkpoint 13's branded-browser release matrix.

Focused fixture repair 1 is verified: all **nine workflow service tests passed**, including the three previously failing Owner journeys. Report `test-results/checkpoint-08-fixture-repair-1-service.log`, SHA256 `33af2cfcdeb74493c98cd81c65dd2d329227cc1a052e9d05e33eaa036d1e58c6`, duration 40.002 seconds. No production validation was relaxed. A type error in the extracted history helper was corrected by accepting only the fixture fields it actually reads; the subsequent build passed (`checkpoint-08-fixture-repair-1-typefix-build.log`).

The service review journey now also produces Review through the real command, then sends validly signed milestone/wave/project closure attempts. Each rejects with `PLANNING_UNFINISHED_TASKS` and leaves graph, history and checkpoint unchanged. Approval still leaves the milestone Open; explicit acceptance and each closure remain required. This closes the checkpoint 7 integration evidence obligation.

The browser journey with project creation **before** second-Owner enrolment passed on all three bundled engines (3/3, 58.7 seconds). Report `test-results/checkpoint-08-owner-after-project-browser.json`, SHA256 `98cab4ed4981ef4452b2d8d579ba55bc1584b44caecdbc67932d7de2ba016415`. Existing review, rejection, material-edit, policy-disable and reviewer-removal assertions remain intact.

The repaired candidate has 214 files, source SHA256 `3dae74461a6be2714d23a5416a545258e0906d340c0e2d63b15a0262b6acc770` (`test-results/checkpoint-08-repaired-candidate-snapshot.json`). Its production source matches the initial candidate; only the enrolment fixture and two workflow tests changed. Remaining backend regressions include all users of the changed fixture; unchanged domain/client/legacy tests retain their earlier passing evidence. Remaining browser tests exclude the already-passed planning/workflow journeys. The full selected file list, logs and reports are recorded under `test-results/checkpoint-08-remaining-*`. Those runs passed, and local runtime health is verified below.

## Final verification and acceptance

The combined evidence covers **410 distinct backend tests and 84 distinct real-browser tests**, all with a passing result and no unresolved failure. This is a union of focused and remaining runs, not a claim of one repeated full run. The three initial failures were repaired once and passed; unchanged successful tests were not rerun. The final regression run passed 360/360 in 189.663 seconds, and remaining browser checks passed 63/63 in 3.2 minutes. Coverage is 28 scenarios per bundled engine. `test-results/checkpoint-08-final-coverage.json` verifies unique case counts, report hashes and the unchanged repaired source fingerprint.

Executed commands use native Node 24.19.0 on macOS arm64; compilation uses the locked Docker Node 24.20.0 image. The focused service command is `node --env-file-if-exists=.env --test --test-concurrency=1 dist/test/task-workflow-service.test.js`. The remaining backend command uses the same flags and the exact selected paths in `checkpoint-08-remaining-backend-files.json`. Playwright runs the planning/workflow files first, the changed independent-review case second, and the remaining 63 cases with those previous cases excluded. All use one worker and zero retries. The bundle was built before testing.

| Check | Verified evidence |
| --- | --- |
| CP08-S1 | Domain shared-assignment case; service attribution preservation; browser title-only defaults, shared edits and lead changes; private dates/acceptance round-trip in client checks. One task ID persists. |
| CP08-S2 | Domain lifecycle/capability cases; service valid-signer execution denial; real custom contributor and restricted-device checks; browser parent lifecycle gates. |
| CP08-S3 | Client, service and three-engine review journeys: default off, eligible named non-assignee, reject/resubmit/approve, exact submitted revisions, reviewer loss and explicit other-Owner replacement. |
| CP08-S4 | Material-edit invalidation, explicit Done reopen/Cancelled restore, atomic milestone reopening, retained old snapshots, and injected all-or-nothing review-policy cascade checks. |
| CP08-S5 | Domain/client/service/browser multiple blockers, encrypted reason/next action, actor/time attribution, responsibility permissions, resolution and reopen outcomes. |
| CP08-F1 | Valid-signer service self/stale/revoked-reviewer failures and ciphertext-substitution rejection; client re-signed same-revision alternate ciphertext also rejected in live validation and historical replay. |
| CP08-F2 | Multiple Open blockers, partial resolution, completion denial and explicit reopen before adding blockers; browser confirms one shared blocked task. |
| CP08-F3 | Custom read/comment actors cannot manage blockers/assignments; cancellation/restoration retain blocker state; security cleanup clears current responsibility without erasing actors or resolving blockers, including closed/archived work. |
| CP07 dependency | Real Done and Review producers against all closure levels; manual acceptance still required; task reopen/restore reopens acceptance while old closing snapshots remain unchanged. |

API/worker image builds and startup passed. API live/ready and worker ready each returned HTTP 200; all four containers are healthy. Proof: `test-results/checkpoint-08-final-runtime.json`. API image: `sha256:5013fc6bf6e5cb53b92f9eee956d23b160f26535fa417358e31858e2ae91684d`; worker image: `sha256:3a818d568da2c2add473c6b018b06932cd7d36f8a1ccb63055ed346933608f05`. Bundled versions: Chromium 153.0.8010.12, Firefox 155.0, WebKit 26.6. Applied migrations 003/004 and control 008 retain their recorded hashes.

Accepted by the implementing agent after a separate read-only domain-agent audit found no remaining essential CP08 implementation gap; its requested service closure evidence was added and passed. This internal audit is not the independent security review required at CP13.

## Remaining ownership and limits

CP09 must implement shared task comments/activity, moderation and notification delivery using these same task IDs, preserving them during carry-forward. CP10 must calculate Blocked/health from the verified Open blockers of non-cancelled work. CP11–13 retain their concurrency, upgrades, recovery/data-exit and release requirements. The current 2,000-record/512-operation/16 MiB planning bounds reject oversized projects explicitly. Frontend screens, email and other future features remain outside scope.

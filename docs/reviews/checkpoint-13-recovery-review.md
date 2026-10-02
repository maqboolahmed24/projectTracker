# Checkpoint 13 independent automated recovery and release review

Review ID: **CP13-RECOVERY-AUTO-2026-09-27**  
Reviewer: **OpenAI Codex, independent subagent `/root/independent_recovery_review`**  
Review date: **27 September 2026**  
Working tree baseline: Git HEAD `bb76a955eaf9983996967b282c1b0f3a8f8e72e0`, with substantial existing uncommitted and untracked checkpoint work. HEAD alone does not identify the reviewed candidate; the SHA-256 inventory below does.

This is a fresh, independent automated source review by a separate agent from the implementation lead. It is not an external audit, human review, certification, penetration test, or production approval. During the independent review phase, the reviewer did not implement the candidate, change application code, run tests or drills, query or mutate live databases, or change running processes. Only this report was written in that phase. Subsequent remediation requested by the implementation lead is recorded separately below and is not independent verification of the repair. The implementation lead retains responsibility for integrated verification.

## Result

**One material finding remains open at this review snapshot: CP13-R1.** No additional material security/privacy/retention defect was identified in the inspected paths. That statement is limited to this review; it is not evidence that uninspected paths or deployed infrastructure are secure.

### CP13-R1 - Security decisions inherit a weaker connection commit setting

**Severity:** P1, acknowledged security-state durability.  
**Status:** Open; communicated to the implementation lead during review.  
**Evidence type:** Static control-flow/configuration finding, checked against PostgreSQL 18 documentation; no fault reproduction was run by this reviewer.

The following authority-writing transactions call `tenantTransaction` without establishing `SET LOCAL synchronous_commit='on'`:

- `src/modules/lifecycle/service.ts:76`: deletion request, deletion cancellation, and profile-erasure request transitions and receipts.
- `src/modules/restoration/service.ts:69`: restore start, including quarantine, data-generation increment, and session/ceremony invalidation.
- `src/modules/restoration/service.ts:179`: current Owner restore verification and quarantine release.
- `src/modules/upgrades/service.ts:136` and `:194`: migration start/finish and identity-content migration decisions.

`tenantTransaction` in `src/persistence.ts` establishes tenant context only; `transaction` in `src/db.ts` does not strengthen commit durability. `loadConfig` accepts PostgreSQL URLs without constraining connection options, and the pool passes the URL through. A runtime role, database default, or connection option can therefore select `synchronous_commit=local` or `off`. A configured synchronous standby alone does not force these transactions to wait for it.

For a concrete failure sequence, give the runtime control connection the `local` setting, interrupt the synchronous standby, and submit an otherwise valid deletion request. This path can commit and return a receipt without durable standby acknowledgement. Loss of the primary before replication catches up can then lose the acknowledged deletion intent. The same missing guarantee affects restore generation/session invalidation and migration decisions. This is a deployment/configuration-dependent failure, not an assertion that the currently running local connection uses a weaker setting, nor an unauthenticated remote exploit.

The existing `RecoveryService.#transaction` explicitly sets synchronous commit at `src/modules/identity/recovery.ts:60`, and the deletion finalizer does so at `src/modules/lifecycle/deadline.ts:23`. Those protections do not cover the separate transactions above.

The health path does not exclude this condition: `scripts/physical-backups.mjs:117` reads `current_setting('synchronous_commit')` in the privileged local `psql` session selected by `sql()`, not in the runtime control connection. A runtime-role override can differ while `src/recovery-health.ts` still interprets the recorded administrator value as durable.

PostgreSQL documents that `local` waits only for local WAL flush, `off` can report success before crash safety, and the setting in effect at commit determines the transaction's behavior. The finding follows from those documented semantics and the inspected code. [PostgreSQL 18 WAL settings](https://www.postgresql.org/docs/18/runtime-config-wal.html#GUC-SYNCHRONOUS-COMMIT).

**Required closure:** Explicitly enforce synchronous durable commit for these current-security mutations, preferably through one auditable control-transaction boundary, and verify the effective setting on the actual runtime transaction. Retain focused evidence that a weaker incoming session setting cannot cause the new paths to acknowledge while the required standby is unavailable. Do not treat a healthy administrator-session metric alone as proof. A deployed synchronous standby and appropriate failure domains remain operational prerequisites even after the code is repaired.

## Composed-path observations

The inspected restore flow obtains authority from the current control store and does not install an old control snapshot. `begin` binds the checkpoint to a current journal ancestor and starts a new data generation. The installation CLI allowlists application tables, verifies the signed inventory and recovered rows, preserves the workspace authority columns, and installs under the workspace lock and quarantine checks. Reconciliation projects current roles, grants, profiles, scope epochs and restrictions; later missing projects are recorded rather than recreated from security metadata.

Current Owner verification is separate from operational restore authority. It requires a current approved, recently authenticated Owner session, signed current-head proof, current custody and project scope checks. The client verifies the service signatures and historical head anchors, confirms retained key epochs, and decrypts representative current/historical ciphertext before signing. A failed check leaves quarantine in place. The active-upgrade route verifies original sources and retained progress before allowing generation rebinding. These observations do not cure CP13-R1's persistence gap.

Export uses an Owner/recent-authentication gate, repeated current authority/source-manifest checks, a fixed business-data serialization allowlist in the client Worker, and a final current authority check. It labels the result as plaintext data exit. The inspected serializer does not include authentication records, private keys, recovery material, key envelopes, or raw security transitions. Revocation cannot recall plaintext already delivered to an authorized client, consistent with the architecture.

Deletion deadline checks appear in normal data transactions, recovery, export, restore, notification delivery and job replay. The irreversible finalizer revokes authority and records the tombstone under the fence. The reviewed latest purge migrations retain opaque tombstones/hash links and consumed entitlement state while deleting workspace payloads; their privileged invoker checks prevent the runtime role from acquiring purge power merely through function execution grants. The physical purge sequence compacts the affected relations, confirms archival, removes owned isolated artifacts and sidecars, then records completion.

The recovery CLI serializes physical operations, runs expiry before work and in its final cleanup, uses backup start times to classify contamination, and can retire a repository without waiting for a replacement backup. Sidecar files use private ownership/mode checks, authenticated encryption, bounded sizes and explicit identifier validation. Subprocess execution avoids shell interpolation and suppresses child error output. Hosted job errors are sanitized before Graphile persists them, and replay/delivery recheck current deletion/generation/access state. These are source observations; this review did not re-execute the recorded retention or purge drills.

## Release configuration boundary

The Docker source uses a non-root runtime user; the local Compose runtime declares read-only filesystems and reduced privileges. The Docker ignore file excludes environment secrets, local recovery storage and test output. Runtime configuration rejects administrator URL fields, requires distinct application/control database identities and an HTTPS application origin in production, and rejects the published local fixture passwords. API logging omits request bodies, cookie values and raw database exceptions; job error handling uses fixed categories.

These controls are not a reviewed production deployment. The Compose files explicitly describe local development and one-host recovery infrastructure. The deployment runbook still requires separate environment resources/secrets, restricted database roles, private networking with verified transport, a protected HTTPS gateway, independently durable control replication and operational secret backup. Those properties are not all enforced by `loadConfig` and were not independently checked in a deployed environment here. No production artifact digest, gateway configuration, runtime database role/transport configuration, production secret injection or independent-host failover was inspected. `docs/deployment.md` states that no production environment has been deployed.

## Evidence and limitations

The architecture's recovery/privacy/security-mutation rules and the checkpoint 12/13 acceptance requirements were used as the review contract. The reviewer read the checkpoint 12 evidence report and operational runbooks as prior evidence, not as substitutes for source inspection. Its local drill measurements and stated single-host limits are not new measurements from this review.

This review focused on restoration, export, lifecycle/purge, retained backup expiry, queue replay/delivery, encrypted-upgrade interaction, forward access projection, logging, and release configuration source. Identity recovery was examined at the current-authority/binding, material-delivery and commit boundaries; this is not a second full audit of every authentication or pairing ceremony. Architectural and evidence-register review focused on the sections relevant to these boundaries.

There was no exhaustive cryptographic proof, dependency/CVE audit, adversarial fuzzing, new browser execution, new integrated test run, load/capacity test, disk forensic examination or production operations assessment. Required supported-browser and end-to-end evidence remains the implementation lead's separate checkpoint 13 work. Changes after the hashes below require review of their deltas and new verification evidence. Closing CP13-R1 cannot by itself establish production readiness.

## Exact reviewed-file hashes

SHA-256 values identify the source bytes inspected, including uncommitted/untracked files. The main inventory was captured at `2026-09-27T01:48:18.644225+00:00`; the three latest purge repair migrations and access projection were captured immediately afterward as supplemental review scope. Relevant routines were inspected within the listed files; listing a file is not a claim of exhaustive formal verification of every function.

| File | SHA-256 |
| --- | --- |
| `architecture/archtecture.md` | `d91263471492e97e793e826503be92bac03d2df3236eb9d1f2529350136399cf` |
| `docs/implementation-evidence.md` | `c5eb26e87d199b0b4c7b7a342776fcb436f83ba64b81577d2d883215939386cb` |
| `docs/checkpoint-12-evidence.md` | `d86852953216cb8781936dfcb3e228e6267ad81c2edf0f85ffae2c742189d3b8` |
| `docs/backup-operations.md` | `36c3145f6149fe5fcdddcad251cd781fe1e8d97d6819faedd76cf4f2c805504d` |
| `docs/deployment.md` | `9b1e6ecccb84ec3e24a1a76a91d930455b2c0217c69bb227649db975b71d15b6` |
| `docs/job-operations.md` | `59468037e3c6f663311779944b2921a97de60c2913cab020a640d455beeeb093` |
| `docs/identity-operations.md` | `b41d1ef5e9497e88a3689dbbe4eee9604ffcc9f5e254242cbe1ac72b143e2042` |
| `docs/security-control-model.md` | `a797ea6b11e617d4f51808cc0896737a42cc1791230a80010ee75a87835e93ba` |
| `src/config.ts` | `4ca579a93e86c534440b753f37dcc4b2429a62e462b62c696b4d661f3f66aad5` |
| `src/db.ts` | `299bbb2bce9c5ef2c05b18e02cc9f3ae975915ea91ef763b2e2a1fdeae2cae99` |
| `src/persistence.ts` | `57fdf2f30e8966c44d338d4b83e2c6f946238913238bb22d11457606335d8ce5` |
| `src/app.ts` | `fb38a2282024a3951d5257261533658de0393fa948097eac49911ad9d0d57b3f` |
| `src/worker.ts` | `397ede2865aced108217bcdeb0c88b6b31bb1401c7dae50c257bfb642a5f7d89` |
| `src/jobs.ts` | `daf751c1369d869af4babe6d09282545db6e1eb454ff75834d425f142a357bd5` |
| `src/recovery-health.ts` | `0a736e2e8c7c94db28f57fd0f8bf3b046ebcf0be025a3b01bd6666dd8ca1f5c6` |
| `src/modules/restoration/service.ts` | `9d7e6eba36d8cb9dcad4d49d66489489d0d28f763e7407e54fa0fe0fcf1dd3d8` |
| `src/modules/restoration/manifest.ts` | `55deb54527f7431f83cd6720e86950aeb8080134a8ff9f390ce5fb3753e36cc6` |
| `src/modules/restoration/upgrades.ts` | `a6a182e085365fc1743b45785f675e4016318370a3079097b1e82129ed968ae5` |
| `src/modules/restoration/routes.ts` | `02c8dc65dbf2b831eaa593582952c41737fa1335fd025a4b0be54eca3283c53b` |
| `src/modules/export/service.ts` | `d819d0592199422e5db40009c2345f1bd5ff34f7f176d317542f0e27a87269b8` |
| `src/modules/export/routes.ts` | `f65872a7b51d62c72addbda539ad0f6c9fe525a6551803bfb0f71ae3a57b09e5` |
| `src/client/export-controller.ts` | `8d35863e99ad275ab5f7ad706bec6b44f2200de430b056425fa25752b75437da` |
| `src/client/export-crypto.ts` | `a8e7c0be76e68b97fd5e8edc1b07405c8a889ce0c2d53ee2f663c8a3ad73efd2` |
| `src/shared/export.ts` | `21866f232d3bec694530553f04b60c250f9b4782966a67a8a0f549c88e5d3060` |
| `src/modules/lifecycle/service.ts` | `2f68970b02a4b36250043ffcb7084fbbd72920a7c531d288974ea8dfc39eb55d` |
| `src/modules/lifecycle/deadline.ts` | `3d5128864aa6aac1d84408e7edb74c9b3afd48c6940a23955d078340d4498909` |
| `src/modules/lifecycle/purge.ts` | `609e9a9c54cb37a6446e8bd9da0028c65599866abbf1e09821f62a9d9e970c86` |
| `src/modules/lifecycle/routes.ts` | `9f133db3df06a16ce39d3d667cbee0eb47a39b2e80e24a1da0e7625aabad1b3a` |
| `src/modules/upgrades/service.ts` | `1c377641cf83e4bde5fa67bec4ac043d305ade98ef0b76be5a94174f49b0e8ed` |
| `src/modules/upgrades/projection.ts` | `6b2356cc385570985e522bb31a7a7e055b383552afb0d22e4e7fbf598d3cfa25` |
| `src/modules/upgrades/ledger.ts` | `2c226ee9a3f3890022932aeb95fe97cb60163b7ce3b87ab36d85b7a1561ef0f7` |
| `src/modules/identity/projection.ts` | `3e3f0252bec38293b3bb7d1c0ac14bf78d52c8c3931e71a497e0fdeca0840ec6` |
| `src/modules/identity/recovery.ts` | `93ddb1ad3de90a980f9ff0327f01c8931b15137953675abed5072228b1d9df94` |
| `src/modules/identity/secrets.ts` | `96fbbd14c6041849f72a8e76598dd7ad7da4c148678d2fb8047ac6d3b427b598` |
| `src/modules/notifications/delivery.ts` | `a28b62d4d7e2bed15550802727e7340d99d61a306981a2d8acb8a3ca2cfabb2b` |
| `src/shared/restoration.ts` | `efb6ba30ccd822d2c2ce7e5947f00c6880e547d49fa4f97249b8ad2b0684b637` |
| `src/client/restoration-crypto.ts` | `39635684bcf62382e94c76ba1055dad2279ebdcbe2eec123b9dc9f73e5ed67e9` |
| `scripts/recovery.mjs` | `95f146f5e1be3187e20f3e1187292a3cb14d6f3719bd19dc9897b50f69fc1383` |
| `scripts/physical-backups.mjs` | `092c8732f34d194f2dd9c229a11d7161eff2bdc4b49d8491e92d0481389e2d52` |
| `ops/recovery-policy.mjs` | `38f72074b1bdcbab77c0f9107484153a3c05d74682dcf484bac208f8c9f02e62` |
| `ops/recovery-records.mjs` | `18a0d020d161ae926e13a5586eac88e8b3c94d89a1389f5efc07c02e65294d0b` |
| `ops/recovery-expiry.mjs` | `79f330953b5a194a3d04c81892ead6c295a3dc111251f98c1d19967b7264682c` |
| `migrations/control/010_recovery_lifecycle.sql` | `10ee53e06b4bba4351a6705d774f817747b250eeb7a5804859efa21c10459681` |
| `migrations/application/009_recovery_lifecycle.sql` | `2ff1bd57374d61b628f6b6871c28a935accf8dd50095d786fc7a9488f538619b` |
| `Dockerfile` | `a79ecd3ee11b33d99bbed5b7a24b2f99ca002025ab658c0fe351eaafe742cfaa` |
| `.dockerignore` | `54ad062f5e03f57734d4c2e27dd51f16425dea520f890f38002b4ebd9f7b0f37` |
| `compose.yaml` | `4aa19660553d92a4ee10b5b1872f7185a21effe341f92d7771ff3ae76cf1d46e` |
| `compose.recovery.yaml` | `66bfe94b5c45d72386f52a2c15b985475a4b576867ec0e07f973088f0291e8c9` |
| `ops/postgres/entrypoint.sh` | `e329450b483aebd2ec931fc4609d5bab1536bd29bb35f7f7dc3c62dd1fffa737` |
| `ops/postgres/standby.sh` | `bd4bede36b9f1ccd65dd6c6cd36e6c59cfd799d2dbf78fd8f9ff63d438c91568` |
| `package.json` | `33a8edbe03c0c311d8ea2ec0fbdff0872ac6ebf0cb843b96ee1d39278aa7fb0a` |
| `migrations/application/010_purge_deferred_events.sql` | `da8c4d04c854e83d134d71728d5ac722ea7054969c0189f56eb286ebc45b4c3f` |
| `migrations/control/011_purge_deferred_events.sql` | `5beea9a26030011a554c2c85c841959633e5e55d86c2484f4353e305b95bdfef` |
| `migrations/control/012_purge_child_dependencies.sql` | `2803abdf9f588c2a49d799fbb9f7bf66f49bea461a380efca360d02eaa3cd239` |
| `src/modules/identity/access-projection.ts` | `d8f3a488ffdcf8afa611f67480580d75be33464fc2212018aaaa96612f27f4e8` |

## Subsequent remediation - separate from the independent review snapshot

At the implementation lead's explicit request after this report was saved, the same agent implemented a proposed CP13-R1 repair. Each of the lifecycle, restoration and encrypted-upgrade service authority boundaries now sets transaction-local synchronous commit to `on`. Existing precommit test hooks receive the current transaction client so the new regression can measure the actual effective PostgreSQL setting rather than inspect source text.

`test/control-durability.test.ts` defines two composed regressions, one starting with runtime connection options `off` and one with `local`. Each exercises deletion request/cancellation, upgrade start/identity/finish, and restore begin/current Owner verification, checks `SHOW synchronous_commit` in those committing transactions, and checks that the connection default is restored afterward. The tests modify only the fixture's connection configuration; they do not change database role settings or running service processes.

**Focused remediation validation passed subsequently.** Initial local compile attempts could not find `npm` and then lacked TypeScript 7's macOS ARM64 native package; neither was a successful type check. The implementation lead subsequently compiled with the matching Linux Docker environment and ran `test/control-durability.test.ts`: both `off` and `local` cases passed, measuring `on` at all seven committing mutation boundaries in each case (14 observations). The retained `test-results/checkpoint-13-focused-integration.log` records those two passes alongside 14 other passes and an initial failure in the new composed journey; that log is not represented as an all-pass run.

The implementation lead also authorized this agent to implement and validate `test/core-failure-journey.test.ts`. Two test-integration defects were corrected without changing application behavior: the restoration fixture's object spread had captured a stale upgrade service rather than forwarding its getter, so installed interruption hooks were bypassed; and the client ordinary-write preparation intentionally returns `PlanningClientError('INVALID_PLANNING')`, rather than the server's `AppError('WORKSPACE_RESTRICTED')`. The final test checks both exact errors by also submitting an ordinary draft signed before maintenance began. The lost-acknowledgement assertion was retained.

Under an exclusive native-test slot authorized by the implementation lead, this agent then compiled the full TypeScript project using `docker run --rm --platform linux/amd64 -v /Users/maqbool/Documents/ChatGPT/UKDA:/work -w /work node:24.20.0-bookworm-slim npm run build` and ran only `node --env-file-if-exists=.env --test --test-concurrency=1 dist/test/core-failure-journey.test.js` with the bundled Node 24.19.0. Compilation and the complete journey passed (1 test, 0 failures; approximately 4.95 seconds for the journey). Logs are retained as `test-results/checkpoint-13-failure-journey-client-repair-build.log` and `test-results/checkpoint-13-failure-journey-client-repair.log`.

That journey composes tenant denial, lost upgrade acknowledgement with exact receipt retry, partial native migration, competing Owner removals, rejection of stale migration drafts, restoration of older content under current revocations, current Owner verification and upgrade completion, denial at the deletion deadline before worker finalization, obsolete job delivery, idempotent final deletion, and refusal to restore or recover the deleted workspace. It uses actual services and fixture-owned database rows. It does not replace the separate physical backup/WAL recovery drills or establish production failover durability. The PostgreSQL client deprecation warning remains visible in the successful log and was not treated as a failure or hidden.

This is implementation and regression validation by the same agent who authored CP13-R1, with central durability execution by the implementation lead. It is **not an independent re-review or external certification**. The original finding remains open in its immutable as-reviewed snapshot above; subsequent evidence establishes the stated repair and focused checks, not blanket release approval. No migration or live service process configuration was changed by this agent.

Proposed-fix hashes captured at `2026-09-27T01:54:06.058591+00:00` (distinct from the as-reviewed hashes above):

| File | SHA-256 |
| --- | --- |
| `src/modules/lifecycle/service.ts` | `482dc066086708ae9fd13cc7f78278b0c4160c2fe668ca81b51a272fd45e75ae` |
| `src/modules/restoration/service.ts` | `3bb87ec39f78c03c1d4d7e84bb2005af6988ea75539acd5732d60494050a0e19` |
| `src/modules/upgrades/service.ts` | `93241d9e6195e686964e4e68b523b204ec1269ded044f3656a6853e478979016` |
| `test/control-durability.test.ts` | `b637228443871bd8fb78e7cd639a89b379a7e27a174dce9e6bda0e5f07aea0d0` |

Validated source/evidence snapshot captured at `2026-09-27T02:06:15.229490+00:00`. The four proposed-fix source hashes immediately above remain unchanged; the additional files are:

| File | SHA-256 |
| --- | --- |
| `test/core-failure-journey.test.ts` | `bee1f25d8a67ad50e8359ba5ac0f22147ca34dcee7c00946498349e3ac6c8ac7` |
| `test/restoration-fixture.ts` | `f9d5780b3302b074e172647bb9403af230ebe57cb0cbe50e70098d131c48f29b` |
| `test-results/checkpoint-13-focused-integration.log` | `7cad398a4363be6c9cd1552645279e4db400a7c0e7e9b33b2d31c77c8d888813` |
| `test-results/checkpoint-13-failure-journey-client-repair-build.log` | `b262fac68a580cab71bfbac6ad26352b73cfa9c6d73b7bbcf2eaff57e0f602b6` |
| `test-results/checkpoint-13-failure-journey-client-repair.log` | `134201337b32314c896e789b0b117a0fefaf8a65f638361927a32fdf1be9f266` |

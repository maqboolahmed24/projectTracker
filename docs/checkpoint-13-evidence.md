# Checkpoint 13 - integrated starter release evidence

**Status: verified.** All checkpoint 13 acceptance checks pass for the agreed local starter delivery. Core success/failure journeys, independent automated review repairs, all eight branded browser releases and final runtime verification have retained evidence. `architecture/checklist.md` marks all thirteen checkpoints complete. Production deployment has not been performed; frontend screens and future features remain excluded.

## Acceptance evidence

| Requirement | Executed evidence and limits |
| --- | --- |
| CP13-S1 | `core-journey.spec.ts` passed on bundled Chromium and all four current/previous Chrome/Edge releases (`checkpoint-13-branded-core-journeys.json`): real first-Owner fixture activation, equal second Owner and member enrolment, encrypted shared work, logout/login, another approved device with a lost commit response, Owner-issued member reset, Owner phrase recovery and removal. The surviving Owner exports retained history. Initial activation is a real Node protocol fixture, not a frontend screen. |
| CP13-S2 | The same workspace delivers one two-assignee task through two waves, a milestone, blocker resolution, comments, real queued notices, independent task review and stale-approval denial, carry-forward, closure/archive/reopen, equal calculated results with separately labelled observation times, plaintext export, and equal-Owner cancellation of deletion. No repository/email/connector service participates. |
| CP13-S3 | Chrome/Edge current and previous protocol/capability suites **28/28**, official Firefox current and previous **8/8**, native Safari current and previous **8/8**. Exact versions are below. Every required branded release was actually executed; bundled-engine passes are separate evidence. |
| CP13-S4 | Three fresh automated source reviews are retained with as-reviewed hashes and explicit scope limits. The custody substitution, logout-draft loss and weaker transaction durability findings are repaired and tested. Independent peer follow-up covers both custody and durability repairs. This is not a human/external certification. |
| CP13-S5 | Prior [checkpoint evidence](implementation-evidence.md), [physical recovery measurements](checkpoint-12-evidence.md), [backup runbook](backup-operations.md), [job operations](job-operations.md) and [upgrade protocol](encrypted-upgrades.md) remain applicable. Final candidate images match all 162 compiled source files; runtime, queue, recovery and replica health pass, migrations replay unchanged, and aggregate regression evidence is retained. Release configuration and limitations are recorded below. Production is not deployed. |
| CP13-F1 | `core-failure-journey.test.ts` passed in 4,945 ms: actual foreign-tenant denial, lost upgrade acknowledgement/one receipt, partial migration, competing mutual Owner removal with one survivor, stale/revoked migration attempts, restore from before removal under current authority, retained history and migration continuation, exact deadline denial, idempotent deletion and refusal of old restore/recovery/receipt paths. It composes with the browser journey’s role/stale-review/lost-pairing/reset failures. Fixture row installation is distinguished from checkpoint 12’s actual physical PITR drills. |
| CP13-F2 | Actual dedicated-Worker capability checks reject missing WebAssembly/WebCrypto/IndexedDB with `UNSUPPORTED` before any authentication request: **9/9** bundled-engine cases plus corresponding Chrome/Edge branded cases. Existing core journeys run without future-feature configuration or dependencies. |
| CP13-F3 | The parent checklist remained open until review repairs, recovery/deletion evidence, all required browser releases and final runtime checks passed. Failed diagnostic runs are retained and distinguished from passing evidence. Production deployment and external human certification are not claimed. |

## Independent review reports

- [Authentication](reviews/checkpoint-13-auth-review.md), `CP13-AUTH-REVIEW-2026-09-27`: repaired encrypted-draft retention, reproduced failure followed by a passing composed runtime/IndexedDB test; independently re-reviewed custody repair.
- [Authority](reviews/checkpoint-13-authority-review.md), `UKDA-CP13-AUTH-20260927-01`: repaired selection of attacker-chosen custody material, ordinary/revoked signer confidentiality regressions **2/2**; independently re-reviewed all durability authority-writing branches.
- [Recovery/release](reviews/checkpoint-13-recovery-review.md), `CP13-RECOVERY-AUTO-2026-09-27`: transaction-local synchronous commit repaired; **2/2** real database tests verify fourteen precommit settings across lifecycle/upgrade/restore with weak connection defaults and restoration of those defaults afterward.

Reviewers used fresh contexts and initially performed source review only. Subsequent fixes by the same reviewer are separated from original findings and peer follow-up. Exact hashes and limitations stay in each report. Library selection and the runtime dependency audit do not replace the composed reviews.

## Branded-browser results

| Browser release | Actual version | Evidence |
| --- | --- | --- |
| Chrome current | 154.0.8037.57 | Installed official Chrome, isolated Playwright profile; seven checks passed. |
| Chrome previous | 153.0.8010.52 | Official Chrome for Testing stable-branch artifact; seven checks passed. The distribution’s ad-hoc signature limitation is retained in provisioning notes; no OS-security bypass was performed. |
| Edge current | 154.0.4258.37 | Official package SHA-256 matched Microsoft metadata; extracted bundle signature verified; seven checks passed. |
| Edge previous | 153.0.4234.48 | Official package SHA-256 matched Microsoft metadata; extracted bundle signature verified; seven checks passed. |
| Firefox current | 156.0.1 | Official Mozilla checksum/signature verified; four unchanged specifications passed through GeckoDriver/BiDi. |
| Firefox previous | 155.0.1 | Official Mozilla checksum/signature verified; four unchanged specifications passed through GeckoDriver/BiDi. |
| Safari current | 27.0 | Four unchanged specifications passed on native Safari through Apple's WebDriver, first execution, after the authorised official Safari-only update. Native driver version is 21625.1.29.18.28; macOS remains 26.6.2. |
| Safari previous | 26.6.2 | Four unchanged specifications passed on native Safari through Apple's WebDriver, first execution, before the update. Remote Automation was enabled through Safari's native authorization dialog. |

Protocol checks exercise real OPAQUE registration/login and device signing inside the dedicated Worker, lock after logout, encrypted IndexedDB reload/Forget, frozen Node-generated content/recipient/recovery vectors and identical canonical progress results across London DST/deadline inputs. Chrome/Edge additionally exercise missing-capability failure. These protocol checks use no application database; database-backed journeys are identified separately.

Retained reports under `test-results/`: `checkpoint-13-chrome-edge-protocol.json`, `checkpoint-13-branded-core-journeys.json`, `checkpoint-13-firefox-branded-final.json`, `checkpoint-13-safari-26.6.2-final.json`, `checkpoint-13-safari-27.0-final.json`, vendor/provisioning records, and initial diagnostic failures. [Firefox runner instructions](branded-firefox-verification.md) explain the transport adapter and exact unchanged specifications. Its initial classic-WebDriver realm caused strict context checks to reject sandbox-created objects; evaluation now uses the browser’s default realm through BiDi. No application validation or CSP was relaxed. [Safari instructions](branded-safari-verification.md) record both native runs and preservation of previous-version evidence before updating. Both Safari bundle signatures verified; no Safari runner repair was needed.

The branded core journeys passed **4/4** in 3.5 minutes. They exercise the real databases, HTTP, browser Workers, IndexedDB and queue worker; their initial activation fixture uses Node. Firefox's four protocol specifications do not claim the broader database-backed core journey.

## Backend regression and candidate

The complete Node run passed **552/558**. Six worker-sensitive fixture cases then passed **6/6** unchanged with the separately running queue worker stopped. Combined, this verifies **558 distinct Node cases**, with no unresolved failure. The first run is retained as a failed run; the focused rerun and explanation are retained separately. `test-results/checkpoint-13-final-coverage.json` maps each passing case to its report and records browser, runtime, candidate and review report hashes. Prior checkpoint browser coverage remains retained separately; overlapping reports are not added as unique tests.

`checkpoint-13-candidate-snapshot.json` records 366 source/configuration/test files, SHA-256 `85c7ff21de9672a244db8a0f61d24089aba653012d4caac50e87dd99aa42e179`, and 162 compiled source files, SHA-256 `8ccd7ed003d6dfde2805c5c4ea09368ae8ac40f22c12c1058a3df057374b69fa`. All source hashes were rechecked unchanged after the branded core journeys. TypeScript and browser builds passed. Every compiled source file in both running API and worker images matches the candidate individually and in aggregate.

`checkpoint-13-final-runtime.json` records HTTP 200 API/worker liveness and readiness, queue health with zero pending/failed jobs, healthy recovery with fresh backup/WAL/Owner-drill evidence, and a streaming synchronous replica with zero replay lag at capture. Both runtime database roles lack superuser and RLS-bypass privileges and use `synchronous_commit=on`. Migration replay applied zero changes across ten application and twelve control migrations. There are zero active customer workspaces at capture, so checkpoint age is explicitly **null**; nonempty checkpoint coverage is demonstrated separately by checkpoint 12's scheduler drill. The supervised recovery daemon is running and four successful ticks were recorded.

The matching API image is `sha256:11bbef7095944c221bfd594f8387417774a69c9a8d81eb671e608ba3767e51e1`; the worker is `sha256:ecec24b25d2f6006a9c81b9b35dec0701d259b5de963fdd6c1b39d4257275190`. The first runtime verifier included source maps beyond the candidate's JavaScript scope; its failed report is retained. Correcting that comparison scope verified all 162 expected files without changing code or runtime. Three exhausted, unlocked jobs from disposable local fixtures were removed by their exact recorded IDs after proving their referenced workspaces absent; before/after evidence is retained.

After the host slept during Safari installation, `checkpoint-13-post-wake-health.json` reconfirmed API/worker readiness, empty queue, fresh recovery metrics, a live operator and zero replica replay lag at 11:02 UTC. The existing operator resumed normally; no restart, repeated drill or code change was needed.

## Release and limitations

The runtime dependency audit (`npm audit --omit=dev`) reported **zero known vulnerabilities** across 122 production dependency entries on the captured date. This is a registry result, not proof that the dependencies have no vulnerabilities.

The Docker runtime uses the unprivileged `node` identity; local Compose drops capabilities, uses read-only service filesystems and binds API/database ports to loopback. `.dockerignore` excludes private environment files, local browser/backup artifacts and test reports. The API receives identity secrets at runtime; the queue worker does not receive `.env.identity`. Local Compose credentials and its HTTP origin are development settings, not a production configuration. Production still requires HTTPS, private networking, independent backup/replica failure domains and externally managed operational secrets.

Frontend screens, email, customer-operated workers/connectors and other architecture future work remain outside this delivery. Local backups and the synchronous replica share one host; measured recovery times are local fixture evidence, not production disaster-resilience guarantees. Setup remains in [README](../README.md); protocol libraries and controllers are exercised through the test harness until a frontend is implemented.

Repair and execution history, including failed harness runs, is retained in [checkpoint-13 progress](checkpoint-13-progress.md). No required acceptance gate was waived. This completes the agreed implementation goal; further frontend or production deployment work requires its own scope.

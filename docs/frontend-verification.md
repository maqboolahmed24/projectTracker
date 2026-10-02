# Product frontend verification

This report covers the new product screens and their connection to the existing UKDA backend. It is separate from the earlier thirteen-checkpoint browser-library baseline and the avatar extension. The frontend is complete for the agreed local starter and runs at `http://localhost:3400`. The final release has 40 distinct passing product browser cases, 64 focused Node checks and healthy matching application services. This is a working local product, not a public production deployment.

Subsequent approval and Settings corrections are recorded in [frontend-approval-fix.md](frontend-approval-fix.md). The original release evidence below is retained as a historical baseline; the follow-up report identifies the changed frontend build and its focused verification.

The later stable-dialog and editing-popup correction is documented in [frontend-modal-fix.md](frontend-modal-fix.md). Its verification status is recorded separately and does not replace or extend the historical pass counts below.

The new-device visual code comparison is documented in [frontend-device-comparison.md](frontend-device-comparison.md), with separate component, pairing-journey and deployment evidence.

The Inbox row and remembered sign-in avatar fixes are documented in [frontend-inbox-avatar-fix.md](frontend-inbox-avatar-fix.md), with isolated browser and local-cache regression checks.

One-link invitation and new-device approval, automatic request discovery, and bounded progress updates are documented in [frontend-one-link-access.md](frontend-one-link-access.md). Its release record distinguishes isolated browser journeys from synthetic lifecycle checks.

Distinct work-status colours and their visual/contrast checks are documented in [frontend-status-colours.md](frontend-status-colours.md).

## Requirements and implementation

| Requirement | Delivered implementation and evidence |
| --- | --- |
| Understand and use the real backend | Domain audits in `frontend-identity-map.md`, `frontend-work-map.md` and `frontend-settings-map.md`; screens use the existing browser controllers and verified Worker reads. Only narrow directory, authority, hidden-history and pending-invitation read gaps were added. |
| Google Stitch, highest connector model | `design/README.md` records project 2504438657315916160, a shared design system and five saved reference screens. Generation and corrective edits used `GEMINI_3_8_FLASH`, the highest model exposed by the installed connector. |
| Consistent light and dark design | One shared React component library and `web/globals.css`, locally bundled Inter and Lucide, system/light/dark preference, responsive navigation and dialogs. Dark mode uses the launch canvas `#101113` and neutral charcoal surfaces. Generated HTML is retained as provenance, not shipped as independent inconsistent pages. |
| Existing animated startup | The original `brand/ukda-launch` artwork assembles at the centre, then uniformly shrinks into the measured page logo over 720 ms while the page appears. The destination is hidden during transfer and restored on every exit; reduced motion uses a short fade. The launch has a finite watchdog. |
| Customer-facing language | Normal screens use project, wave, task, invitation, recovery kit and security-check language. Error mapping avoids raw transport messages, stack traces and internal identifiers. |
| Complete account journeys | Activation with avatar and recovery-kit confirmation, remembered password-only sign-in, logout, local Forget, password change, member invitation/reset, equal Owner setup, Owner phrase recovery, new-device approval and interrupted setup continuation. |
| Collaborative project work | Projects, phases/waves, shared tasks, assignees/leads/reviewers, blockers, acceptance, discussion and retained history, milestones, updates, reporting, timeline, completion/cancellation, archive/unarchive and explicit reopen. |
| Work discovery and notifications | Home, Projects, My work, Inbox, verified in-memory search, permission-aware controls, live/focus refresh and links back to the relevant task or project. |
| Workspace controls | People/access, roles, teams/history, timezone, profile/security information, export acknowledgement, deletion/cancellation, erasure requests, interrupted-save checks, bounded workspace updates and restored-workspace review. |
| Deferred features clearly unavailable | Eleven muted cards, disabled controls, and the exact message “Not available in this build.” Categories include email, boards, attachments, threads/mentions, dependencies, forecasts/workload/weighted progress, risk register, connectors and AI. |
| Actual application integration | Next public shell, private client-side views after unlock, production same-origin API proxy, Docker frontend alongside matching API and worker, preserved canonical browser origin and existing database volumes. |

## Focused backend and transport checks

64 distinct passing cases are recorded in `test-results/frontend-unit-evidence.json`:

- 9 directory and handoff checks: signed labels, exact current authority, altered/duplicate data rejection, logout fencing and strict private-link validation.
- 35 affected enrolment, collaboration, planning and workflow cases, including the narrow frontend read extensions.
- 7 session and read-budget checks: passive refresh does not consume the password-guess budget, and limits remain enforced.
- 3 proxy checks: cookie/Origin/CSRF preservation, excluded untrusted headers, allowed larger planning/update bodies, bounded rejection, cancellation and non-sensitive failure responses.
- 10 live-refresh checks: stale-response fencing, hidden/stopped views, bounded fallback, independent report reads after stream loss, retained queued invalidations and strict metadata-only events. Three regressions cover the final disconnect repair.

The proxy unit tests use a controlled upstream response; the product browser suite additionally exercises the actual Next proxy and real database-backed fixture API. Earlier nine-case planning and four-case collaboration runs overlap the 35-case group and are not counted twice. The complete historical backend suite was not rerun merely for the new screens.

## Browser, visual and runtime evidence

The final aggregate is `test-results/frontend-browser-evidence.json`. Every indexed pass was checked against its original Playwright report; results are deduplicated by journey and browser, not added across repeated repair runs.

| Product journeys | Chromium | Firefox | WebKit | Distinct passes |
| --- | ---: | ---: | ---: | ---: |
| Account setup, recovery, invitations, equal Owners, private links and idle lock | 6 | 6 | 6 | 18 |
| Measured launch handoff, mobile appearance/reduced motion and invalid-link recovery | 3 | 3 | 3 | 9 |
| Roles, teams, people, data controls and workspace updates | 3 | 3 | 3 | 9 |
| Project/wave/task lifecycle, history, archive and progress retry | 1 | 1 | 1 | 3 |
| Two assignees, independent review, Inbox, mute and persistence | 1 | - | - | 1 |
| **Total** | **14** | **13** | **13** | **40** |

The three-person case intentionally runs only in Chromium; its Firefox and WebKit entries are two explicit skips, not passes. Core work and account journeys run in every engine. The two supplementary live-Origin diagnostic cases are excluded from the product total.

Domain evidence indexes are `frontend-identity-public-evidence.json` (27), `frontend-settings-evidence.json` (9) and `frontend-work-release-index.json` (4), all under `test-results/`. The last public and Work runs use the final packaged image `sha256:8662e0ab1d3d40942670663a0c0eaef66aa282c549fc9a1f71e0c802caa1f543`. Earlier successful unaffected account/Settings cases remain associated with their actual prior build and report; this record does not imply every case was rerun in one final command.

The serial suite uses a temporary HTTPS entry point, the actual Next same-origin proxy, real database-backed fixtures, cryptography, Worker execution, sessions and cookies. Initial failures are retained in their diagnostic reports. Repairs include setup Authorization forwarding, saved appearance, completed update display, an Inbox filter race and read/unread inversion, strict-origin live requests in Firefox/WebKit, and retaining a verified HTTP report after its live connection disconnects. The final project test deliberately fails a report read, uses the visible **Refresh progress** control and requires the actual verified 100% result.

The launch tests sample actual animation frames. All engines verify the centred start, uniform shrink/travel, page reveal, hidden destination during transfer, final centre alignment within two pixels, restored visibility/inert state and usable setup. Mobile tests verify the neutral `#101113` canvas, reduced motion, keyboard switching and saved appearance. Inspected screenshots in `test-results/frontend-review/` cover desktop entry, mobile entry, Home and final light/dark project views; `work-final/` contains the final settled project and compact mobile-task captures.

Automatic screenshots, videos and traces are disabled because recovery words and invitation capabilities appear during setup. Selected screenshots contain only disposable fixture content. Five orphan fixtures from earlier interrupted diagnostic runs were identified by exact IDs, the `browser-http-test` licence identity and signed test origins, then removed using the fixture cleanup procedure. `frontend-orphan-fixture-cleanup.json` records that bounded cleanup and preservation of the new real activation licence. Later final runs cleaned their own fixtures. No customer workspace was deleted.

### Running local release

`test-results/frontend-runtime-evidence.json` records six healthy services: frontend, API, worker, both database primaries and the synchronous replica. Eight HTTP checks pass through the actual local frontend/API; worker readiness, queue and recovery endpoints return 200. The queue has zero pending and failed jobs. The recovery operator is running again, a normal tick succeeds, and replication reports zero replay lag. Test servers and the temporary preview container are stopped.

`frontend-compiled-parity.json` verifies all 168 compiled backend/library source files against both deployed API and worker images. `frontend-asset-parity.json` verifies all 66 packaged browser and brand assets against the current source/build. `frontend-release-source.json` records 213 source/configuration hashes and the deployed frontend image. `frontend-final-release-build.log`, `frontend-final-notice-build.log` and `frontend-live-repair-tests.log` record successful production builds, TypeScript checks and the final focused live regressions. The automated source review and repaired findings are in `docs/reviews/frontend-security-review.md`.

The app was opened and visually checked in the Codex browser at its preserved canonical address, `http://localhost:3400`. A fresh activation key is stored only in `.local/activation-key.json`, an ignored file with mode 0600. Choose **Create a workspace** and copy its `licenceKey` value; the Owner chooses their own name/password and saves their own recovery kit. No account or password was pre-created on the user's behalf.

## Limits

The local product is not a public production deployment. Local HTTP cookie support is verified for Chromium and Firefox; Safari requires an HTTPS canonical address. WebKit over HTTPS is a separate test environment and is not a claim that native Safari was retested for these new screens. Existing workspace origins must not be silently changed.

Private content and usable keys stay in the browser controllers/Worker. Remembered profile labels are intentional local sign-in conveniences. A normal browser application still relies on the integrity of the code delivered to it; automated source review is not an external human audit or a promise against a compromised application distribution.

The first release has explicit backend limits and intentionally excludes the disabled future features. See `frontend-operations.md` for startup, testing and HTTPS deployment instructions.

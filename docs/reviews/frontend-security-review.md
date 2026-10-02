# Focused frontend security and completion review

> Historical review: identifiers, temporary paths and file hashes below record the reviewed version. They are retained as evidence, not current product branding. Current launch integration lives in `brand/maqbool-launch/`; see [compatibility identifiers](../compatibility-identifiers.md).

Review closed: 2026-09-27 12:29 UTC.

Reviewer: Codex automated agent `/root/independent_recovery_review`. This is a focused source review within the same implementation team, not an external audit, human review, penetration test, or certification. The reviewer inspected root-owned application, proxy and directory changes independently, but also implemented the Settings UI, deployment integration and the budget fixes below. Review of those owned changes is self-review. The identity reviewer separately identified the missing new-device entry point.

## Scope and method

Inspected the React shell and authentication lifecycle, shared runtime/UI, Next same-origin proxy and CSP, public application configuration, verified directory delivery/decryption, and Settings retry/completion behavior. Traced relevant existing authentication, session, budget and controller contracts. Checked the 30-minute idle requirement in `architecture/archtecture.md` and read retained central test logs. This pass did not run browsers, mutate fixture databases, restart services or rebuild containers. The root agent owns integrated execution and release evidence.

The final source snapshot is recorded below. Existing baseline security evidence is not relabelled as frontend coverage.

## Concrete findings and disposition

### F1 - Passive refresh exhausted the shared password-attempt source budget

**Observed:** Next forwards API requests from one server address while Fastify deliberately uses `trustProxy: false`. `/v1/auth/session` previously charged the same `authentication-source` allowance of 60 requests per ten minutes as password authentication. Three tabs polling every 30 seconds could exhaust that shared allowance without a password attempt and prevent subsequent login or privileged reauthentication.

**Fixed:** The exact-origin, cross-site and no-query checks run before counters. Session polling now uses `session-refresh-source` at 3,000 requests per ten minutes before authentication, followed by `session-refresh-session` at 600 requests per ten minutes keyed only by the authenticated workspace/session pair. Unauthenticated traffic remains bounded at the source. Existing password source/account/workspace limits and `trustProxy: false` remain unchanged; no untrusted forwarding header is accepted as identity. The source ceiling accommodates approximately 150 otherwise-idle 30-second polling tabs, with actual available capacity reduced by other refresh calls; it is a bound, not an unlimited scale guarantee.

**Validation:** `test-results/frontend-session-read-budgets-repair.log` records all seven authentication/access route cases passing. The new case makes 65 valid session requests, proves the password bucket is untouched, and checks exact session/source/password boundaries plus wrong-origin, query, malformed body and missing-cookie denial. It uses real durable counters and a deliberately labelled fake session authentication boundary; existing service tests cover actual authentication authority. The initial `frontend-session-read-budgets.log` is retained: six passed and one failed because the test seeded zero into a positive counter. The repair seeds one; no production limit was weakened.

### F2 - Passive traffic bypassed the intended user-idle lock

**Observed:** Application session and project refreshes renewed the server's idle expiry even without human interaction. A visible unattended tab could stay locally unlocked until the 12-hour absolute expiry instead of locking after 30 minutes without activity. A first UI fix tied the timer to the signed-in presentation; a handoff could then hide that presentation while retaining an unlocked Worker and stop the timer.

**Fixed in the final shell:** `idleSession` is bound to the authenticated session ID. Entering the workspace establishes it; `auth.onClear` removes it. Opening a handoff does not change it, so the same activity deadline continues through the Gateway. The effect depends on the client, session ID and stable notifier, not `signedIn` or route state. Only trusted pointer/key input renews activity. Input, visibility and focus handlers check the elapsed deadline before renewal, and an expiry calls `invalidateSession()`. That existing method synchronously clears local Worker and presentation state before awaiting server revocation and preserves uncertain saved requests. Re-entering the same session does not replace the timer; a newly authenticated session legitimately establishes a new timer.

**Validation:** Reviewed the final effect and `AuthController.invalidateSession`/`performLogout` source paths, including the handoff route and clear callback. The retained `frontend-idle-accessibility-build.log` confirms a successful frontend build of an earlier idle-fix iteration. It is not evidence of the final session-bound behavior. A browser time-advance/visibility/handoff assertion has not been executed in this review; that validation remains with central frontend testing.

### F3 - Key/directory reads consumed access-change mutation capacity

**Observed:** The root agent identified that `/v1/auth/access-change/delivery` used the narrow mutation source/workspace classification even though current delivery is a read and its resolved service quotas already use the history/read classification. Directory and project refreshes could spend mutation capacity and block legitimate access changes.

**Fixed:** Delivery uses the existing read classification: source 1,200 and workspace 4,000 per ten minutes. Context/stage/finalize/status mutation classification is unchanged, and the service still resolves current session authority and eligible grants.

**Validation:** The new real-counter route case in `test/access-change-routes.test.ts` proves delivery charges only read buckets, remains usable after the unchanged mutation source allowance is exhausted, and stops at the read allowance. It passed in the seven-case repaired log above.

## Settings and entry completion review

- Saved operation stores may retain completed records. The UI therefore exposes a manual **Check interrupted saves** flow and says an attempt may already be saved; it does not label every retained record unfinished.
- Resume success is announced only for `state === 'completed'`, or for the reporting controller's verified completed receipt return contract. `finishing` remains informational; an unconfirmed state does not produce a completion claim. Reload errors occur after result handling and do not mislabel a committed mutation as an unsaved change.
- Secure confirmation retains one operation identity and locks the reviewed fields after reauthentication. A synchronous in-flight guard prevents same-frame duplicate submits. Password state is cleared before mutation and on authentication clear. Private link state clears with the mounted session UI.
- The identity reviewer found that a new device had no customer control to obtain the already-supported `signin` handoff. Account Settings now provides **Use another device** with a private versioned link/file, followed by the existing password and separate approval journey. No raw account/workspace identifier is rendered as a field or prompt. That new entry control has source verification only at this snapshot.

The Settings Chromium journeys in `test/frontend/settings.spec.ts` are authored but pending the centrally allocated database slot. Their presence is not a passing result.

## Boundaries checked

The directory controller verifies signed history, current actor/device generations and exact current head, requests only authorized delivery, decrypts through the Worker and performs a final current-head delivery check before returning private presentation data. Restore quarantine returns signed status metadata without requesting private directory content. The server selects current signed workspace/profile references; a removed actor is denied and unrelated non-Owner ciphertext is filtered.

The Next API route is a same-origin transport to a fixed configured backend. It limits request body size, passes only selected headers, streams responses, disables fetch caching and returns a generic transport error. It does not decrypt application content. Public bootstrap exposes only the service's public verification key. React receives private data in memory; the inspected shell has no private server-rendered payload or plaintext local-storage cache. Shared error presentation uses fixed customer-facing messages, and avatar SVG is displayed in an image data URL rather than injected as document HTML. CSP uses nonce-bearing scripts and a same-origin connection/Worker boundary. No additional concrete private-data disclosure was found in these inspected paths.

`test-results/frontend-directory-handoff-tests-repair.log` records nine passing tests: signed labels, logout/authority fencing, removed-actor denial, exact secure-origin handoffs, query-secret/duplicate/oversized input rejection, and recovery-kit origin/account binding. `test-results/frontend-affected-backend-tests.log` records 35 passing cases including the Owner invitation reader's current-generation, paging, expiry and stale-authority assertions. These references support those bounded behaviors, not a blanket frontend release claim.

## Remaining material issues and limits

No unresolved material implementation defect was identified in this focused snapshot after the fixes above. Final idle/handoff behavior, the new-device entry control and the full Settings journeys still require central browser execution. Runtime image parity, complete multi-browser coverage, penetration testing, external deployment/proxy scale, and an exhaustive baseline audit are outside this review. Later source changes require comparing against this snapshot before reusing the conclusion.

## Reviewed source snapshot

SHA-256 of exact file bytes at report close. Paths are relative to the repository root.

| File | SHA-256 |
| --- | --- |
| `frontend/app.tsx` | `c2d7f33b9df2d1911d3d02a98839bdb6f704e04d1647f4fcde600aa7c60788c9` |
| `frontend/shared/runtime.ts` | `6e07855691082aa223790666cd707ad6ccc61d138b52851a7bc0622724eac2aa` |
| `frontend/shared/ui.tsx` | `77d4531c5ec5b0ac98cf0f14df76b87a0e9e37867490f94f69ba4ddd492b6c24` |
| `frontend/shared/errors.ts` | `2a378235fefbdc79fd7bcedfd3b0ab025c1771996640a613072f7f1320cc81bd` |
| `web/proxy.ts` | `55dd041286009f31960e426897370b97a2180553cb2fad59c39f294c990dea5e` |
| `web/app/v1/[...path]/route.ts` | `f1096c4bbedfe3254372e1ae9791c864e09c73da537e5f61bb1eb3998f79c8f7` |
| `web/next.config.mjs` | `c01e5f5341ff2f60f70cf5e8cbcbb39c52698b92dbc192dee613c46776153862` |
| `src/app.ts` | `59d4fb7ea98d8c3920c6ed4ad34f9fd30256523c9a58a427069bce2809ba5aa8` |
| `src/server.ts` | `2c5c664d8fd941a6d50ec7f74bfc71a868d297247ab1251964dd6aae68ec42ee` |
| `src/client/directory-controller.ts` | `4de7447178c48e51c80ef5909ce7a0ba6ad9bc9d3438b89357b06dc977a568d9` |
| `src/client/directory-crypto.ts` | `d434a4a146962e2468b5db09e171c2df2727f9b94fa88563b0ffabc3757f1f4f` |
| `src/client/auth-controller.ts` | `b77ef739843d7fc6b8f06e320f8a85a87315b7f8389d7e63459f450e55243ad3` |
| `src/modules/identity/sessions.ts` | `dad696e1a598a41fdbe46b35bec2e0cd556f2817563ccf1cf41aab185e21a13f` |
| `src/modules/identity/access-change.ts` | `fac82603d4a4a7dde224132616d0cf3ce45666425a30e871417f543beb53cced` |
| `src/modules/identity/access-change-routes.ts` | `03fe6c7541841b86742944974d577cec7eb40def656e24ed3bc33d640acc1460` |
| `src/modules/identity/auth-routes.ts` | `8b55d1f07e1288269e16678ccdab12ed08c2eb7ece43e5b72f6b0174368b73ec` |
| `frontend/settings/common.tsx` | `1844fc34f35a5f49287bf0133978d904b1e9798e2409bd7298755ca8f1e19a80` |
| `frontend/settings/index.tsx` | `11587200828471560166c2b5e08701294d4339e7db1bd13f4a217d8a78b5bc8b` |
| `frontend/settings/people.tsx` | `d19f65ec269d252de1e26cf702a07e43f4bc21ef2c1247fee10a039981970288` |
| `frontend/settings/roles-teams.tsx` | `1b53803399e4a8d5fc6a81762449257d7f58f6531c2a068afd37eafe6cb9f420` |
| `frontend/settings/data.tsx` | `7fbb835fec1984b16c5c513ab202bfb14a4684fdbfab4d1b03e7edbe57306116` |
| `test/auth-routes.test.ts` | `29286a307dacb5066d9130c105e29acebe91545611e4bc734d9c9238d684f5b8` |
| `test/access-change-routes.test.ts` | `39637d3a50731cbc8f6abd30f339d3bdd79c779a6ef284d07743805d73540def` |
| `test/frontend-directory.test.ts` | `a667fdba6305c0079148ea2de030a18ae70d4bf2ec0aefec50ed783c7f71f8c6` |
| `test/frontend-handoff.test.ts` | `3536e4494831905ebe8c0bfd5c7daaac74f2da068f081179542d28cc48497b36` |
| `test/frontend/settings.spec.ts` | `d3565cee61827998bfcbe4e9403f94acfc2c10753e56f3aa5a18aa4130e1b7f4` |
| `Dockerfile.frontend` | `e2141474ef49833adf7f2d6b3c6208a6675b0d64894260bfba1e7eefa64ea618` |

## Subsequent Settings Chromium run

After the snapshot above, the root allocated the browser/database slot. `test-results/frontend-settings-initial.log` and `test-results/frontend-settings-initial-results.json` retain the two-journey result: one passed and one failed. The complete invitation revoke/export acknowledgement/interrupted deletion/cancellation journey passed. The other completed role lost-acknowledgement recovery, edits/retirement and team creation/edit/history, then failed when the test selected the already-current `Europe/London` timezone; the UI correctly kept **Review change** disabled. Activation source explicitly initializes that timezone. The test now asserts the initial timezone and reviews a real change to `America/New_York`. Product source was unchanged by this repair; its rerun is pending allocation. This test-only repair postdates the test-file hash in the snapshot.

## Release follow-up review

The `/root/settings_release` agent re-read the current application/identity lifecycle, idle session handling, proxy, deployment configuration and Settings completion paths on 2026-09-27. This is a source review and self-review of Settings changes within the same implementation team; it does not extend the initial snapshot hashes to later files.

**F4 - A saved Settings change could be described as failed when only its view refresh failed.** The workspace-update and person-access callbacks awaited directory/project refresh inside the mutation callback. The controllers had already confirmed the change, but a subsequent read error reached the mutation error display. The retained operation identity prevented an automatic duplicate write; the customer-facing result was nevertheless inaccurate.

**Fixed:** Those refreshes run through `SecureConfirm.onDone` after the mutation has returned. A failed post-completion refresh closes the completed confirmation and explicitly says the action finished but the latest view could not be loaded. A `finishing` result instead closes with its existing continuation notice and skips callbacks that assume completion. Reviewed-field locking and exact-operation retries are retained. The new workspace-update UI case deliberately interrupts only the presentation directory request after a real update start, then checks bounded Continue/Finish progress and persisted completion. It is authored but not yet executed at this follow-up source snapshot.

No additional material defect was identified in the re-read application/proxy/deployment paths. The documented canonical-origin requirement, internal versus host port separation, retained recovery overlay, unprivileged standalone runtime, and distinction between local HTTP Chromium/Firefox support and Safari HTTPS support match the inspected configuration. Runtime parity and final browser execution remain the parent task's release gates.

**F5 - The frontend transport clipped valid larger backend payloads.** The root agent found that the original universal 1 MiB body limit was smaller than the existing signed planning/restoration and update API allowances. The route now derives the planning, restoration and update limits from their shared protocol constants, uses the reporting route's 2 MiB allowance, and retains 1 MiB for other paths. Next's transport allowance is 24 MiB, the largest supported protocol envelope. Both declared and streamed body sizes are bounded; the backend retains its own per-route size/schema enforcement. The reviewer inspected that change and `test/frontend-proxy.test.ts`. `test-results/frontend-proxy-tests.log` records three passing pure transport cases covering selected authentication headers and separate cookies, allowed larger requests and oversized-body denial, cancellation forwarding and a non-sensitive upstream failure response. These tests use a deliberately mocked upstream transport; the final UI matrix is configured to traverse the actual Next proxy.

**F6 - First-Owner activation lost its temporary setup authorization in the proxy.** The identity matrix through the actual Next proxy exposed that the header allowlist omitted the activation controller's `Authorization: Setup …` credential. The previous pure header test incorrectly expected all authorization headers to be omitted, so its green result did not verify the activation protocol. The root added `authorization` to the selected request headers and corrected that test. It is forwarded only to the server-configured upstream, with redirects still disabled; the existing backend validates the setup capability and exact origin. The reviewer traced the controller's temporary header and the updated proxy source. Real activation/recovery is being rerun across Chromium, Firefox and WebKit; the prior fixture-direct activation result is not a substitute for those runs.

**F7 - Completed workspace updates showed a read error after a fresh login.** The new real-UI update journey completed all explicit steps and confirmed the result, then reloaded. The screen called `upgrades.progress(undefined)` after the verified directory had already cleared the active update ID and advanced the write schema. The existing API correctly rejected a new prior-schema update context. The UI now derives the up-to-date state from the signed directory's current write schema matching the highest supported entry in the existing content schema registry, with no active upgrade. It requests update progress only when there is an available or active update and reloads that reader when the verified schema or active ID changes. No receipt is fabricated and no backend contract is weakened. The existing browser case asserts completion both before and after reload; its repaired run remains pending at this edit.

**F8 - A saved appearance could be overwritten by the initial system preference effect.** The real mobile test selected light appearance while the device preferred dark, then reloaded. The initial system-theme effect could overwrite the saved appearance, while the next effect only reapplied system mode. The root changed the effect to apply the current selected theme every time, so a restored explicit preference wins. The test verifies keyboard switching, persisted appearance after reload, reduced motion and narrow layout. The user's subsequent dark-surface instruction is implemented with neutral `#101113` canvas and neutral charcoal surface tokens matching the launch screen; the updated mobile test also asserts the computed canvas colour. This is a functional/visual finding, not a cryptographic security claim.

## Verified release follow-up results

The pending browser statements above describe their earlier snapshots. The following subsequent evidence resolves those specific gaps:

- `test-results/frontend-identity-public-evidence.json` identifies 24 distinct passing identity/public engine cases and their underlying chronological reports. The repaired idle/handoff case verifies the 30-minute lock through a newly opened private link; the new-device case exercises the Settings entry control and independent approval on another browser. Member join/reset and independent equal-Owner recovery setup are included. These use real backend fixtures and the Next API proxy.
- `test-results/frontend-activation-proxy-repair-results.json` and its `.log` record fresh first-Owner activation and phrase recovery passing on Chromium, Firefox and WebKit through the corrected packaged proxy. They resolve F6 without relying on the old fixture-direct activation result.
- `test-results/frontend-settings-matrix-results.json` records six passing Settings cases and three failures that exposed F7. Both broad baseline journeys passed on all engines: role lost-acknowledgement recovery, reviewed edits/retirement, team history, timezone, all eleven visibly unavailable future cards, private invitation revocation, export acknowledgement, wrong-name deletion refusal, exact interrupted deletion continuation and cancellation.
- `test-results/frontend-settings-appearance-repair-results.json` and its `.log` record all six targeted repair cases passing against packaged image `b03add1ce8b5fd42d0ed6ea22ac441b05a246a5c90c285c8fb57b776fe1f054a`: the complete update/failed-refresh/reload journey plus the mobile appearance journey on each engine. The update case proves a real completed save closes with the explicit failed-view-refresh notice, then bounded customer controls complete the update once and preserve its verified completion after reload. The appearance case proves the neutral dark canvas, keyboard switching, reduced motion, narrow layout and saved preference after reload.
- `test-results/frontend-settings-evidence.json` deduplicates the two Settings reports into **nine distinct passing Settings cases**. The three public appearance cases are listed separately and must not be counted again as Settings cases.

All Settings fixture workspaces were cleaned before releasing the shared test slot. Automatic traces, videos and failure screenshots are disabled because account journeys display recovery secrets. The tests use bundled Chromium, Firefox and WebKit; this is not a native Safari release certification. Work-area final browser verification and final deployed-image parity remain with the parent task and its `docs/frontend-verification.md` evidence. Later requested launch-motion changes require their own source and browser check; these results do not pre-verify those changes.

## Launch handoff source review

The final requested launch handoff was reviewed after its source freeze. `mountUKDALaunch` measures the assembled mark and an actually visible destination logo, uses uniform scaling and centre alignment, and fades the separate backdrop while the mark travels. It hides only that destination during handoff. Cleanup restores its original visibility, cancels animations, clears timers/listeners, removes the host and restores the application's prior inert state. The existing finite watchdog covers resource loading and exit; missing destinations and reduced motion take the bounded fade path. Resize/scroll during a measured handoff settles directly rather than using stale coordinates. The app passes a fixed logo selector. Only the trusted bundled mark is inserted into the shadow DOM; no customer content or secrets enter that markup.

No additional material source issue was identified in that delta. The new geometry case is authored in `test/frontend/public.spec.ts` and its engine execution remains with the identity release agent. The nine passing Settings cases above predate this decorative delta and do not claim to prove its motion. The parent release record will include that final public matrix and the Work matrix separately.

## Final reviewed source snapshot

Snapshot: 2026-09-27 13:08 UTC. The original snapshot above remains historical. These hashes identify the later reviewed sources; they are not an external audit, whole-repository certification or a claim that every line has exhaustive test coverage. No unresolved material finding remains in the bounded reviewed implementation. Final launch browser checks, Work checks and deployed-image parity remain separate release evidence.

| File | SHA-256 |
| --- | --- |
| `frontend/app.tsx` | `d7f04f5d52462b7599e01a7ece40807550cfe4dbb9893cede6e420b173089ddf` |
| `frontend/shared/runtime.ts` | `6e07855691082aa223790666cd707ad6ccc61d138b52851a7bc0622724eac2aa` |
| `frontend/shared/ui.tsx` | `77d4531c5ec5b0ac98cf0f14df76b87a0e9e37867490f94f69ba4ddd492b6c24` |
| `frontend/shared/errors.ts` | `2a378235fefbdc79fd7bcedfd3b0ab025c1771996640a613072f7f1320cc81bd` |
| `web/proxy.ts` | `55dd041286009f31960e426897370b97a2180553cb2fad59c39f294c990dea5e` |
| `web/app/v1/[...path]/route.ts` | `ba01f728187469b76bd66acd9020ac5a63890839c643e8282f20077814f6eee8` |
| `web/next.config.mjs` | `c464cbc4abd2c02f214998ab19a04905561d08f91e191dc55fb1b4269866bd2f` |
| `src/app.ts` | `59d4fb7ea98d8c3920c6ed4ad34f9fd30256523c9a58a427069bce2809ba5aa8` |
| `src/server.ts` | `2c5c664d8fd941a6d50ec7f74bfc71a868d297247ab1251964dd6aae68ec42ee` |
| `src/client/directory-controller.ts` | `4de7447178c48e51c80ef5909ce7a0ba6ad9bc9d3438b89357b06dc977a568d9` |
| `src/client/directory-crypto.ts` | `d434a4a146962e2468b5db09e171c2df2727f9b94fa88563b0ffabc3757f1f4f` |
| `src/client/auth-controller.ts` | `b77ef739843d7fc6b8f06e320f8a85a87315b7f8389d7e63459f450e55243ad3` |
| `src/modules/identity/sessions.ts` | `dad696e1a598a41fdbe46b35bec2e0cd556f2817563ccf1cf41aab185e21a13f` |
| `src/modules/identity/access-change.ts` | `fac82603d4a4a7dde224132616d0cf3ce45666425a30e871417f543beb53cced` |
| `src/modules/identity/access-change-routes.ts` | `03fe6c7541841b86742944974d577cec7eb40def656e24ed3bc33d640acc1460` |
| `src/modules/identity/auth-routes.ts` | `8b55d1f07e1288269e16678ccdab12ed08c2eb7ece43e5b72f6b0174368b73ec` |
| `frontend/settings/common.tsx` | `41e92c1922c3bb51d59021da7b3be09ca377cd592861dfa2a3e678103b79bc48` |
| `frontend/settings/index.tsx` | `d4baea66a9a2853dcac6942d17b5f0c6523267b8ae09c4b04d5e22a9d79ecfc0` |
| `frontend/settings/people.tsx` | `57001e196c57f1bebb7e1b815c875d4348f4992cbc011f4189fe1745fd0e80aa` |
| `frontend/settings/roles-teams.tsx` | `1b53803399e4a8d5fc6a81762449257d7f58f6531c2a068afd37eafe6cb9f420` |
| `frontend/settings/data.tsx` | `5404485db742fc8dc85240b92f833ec9db256d271a34536f4f9061aea0bb7f00` |
| `test/auth-routes.test.ts` | `29286a307dacb5066d9130c105e29acebe91545611e4bc734d9c9238d684f5b8` |
| `test/access-change-routes.test.ts` | `39637d3a50731cbc8f6abd30f339d3bdd79c779a6ef284d07743805d73540def` |
| `test/frontend-directory.test.ts` | `a667fdba6305c0079148ea2de030a18ae70d4bf2ec0aefec50ed783c7f71f8c6` |
| `test/frontend-handoff.test.ts` | `3536e4494831905ebe8c0bfd5c7daaac74f2da068f081179542d28cc48497b36` |
| `test/frontend/settings.spec.ts` | `f54e14f28ca193a257a2ea0cd15256ab405f3ee3be98d310c0f05a6dd9c35672` |
| `Dockerfile.frontend` | `e2141474ef49833adf7f2d6b3c6208a6675b0d64894260bfba1e7eefa64ea618` |
| `frontend/identity/IdentityGateway.tsx` | `8232003176977ad0880901e0e669ad0db7faf484e00e78df503dbb9cdec7b70c` |
| `frontend/identity/IdentityApprovals.tsx` | `a402afa31c3ad5e33906a36f31c1eed970050768dbcebb7deda2b45908f1efee` |
| `frontend/identity/components.tsx` | `34dc29eee3ae4960c8eaeec423d7fc3b1b9bd2ac74d3c378a54e023f3bf1adcd` |
| `frontend/identity/handoff.ts` | `7779dcc9663d307dc46ec3a8d5f24b24d613c1efdf5c7fe90f81b3b7636e4ec5` |
| `brand/ukda-launch/ukda-launch.js` | `6c3715c39cd029356605464aa3a7cf05554d4afc5f6b350157b7dedfbc08fe6a` |
| `brand/ukda-launch/ukda-launch.css` | `83d654b4497d7cf05b4d78d66dbef1e019c476de95ac2eca13731751a37a2702` |
| `web/globals.css` | `4350b688edf3fd34a70f6d2bae6c6cb3254aa5cfc936d3e0e4614962c0796d66` |
| `test/frontend/public.spec.ts` | `eba43a3b3a7ae6f9f4c6d2df6e3da6522ba23d57460f70e7f83e2cfb4476ff95` |
| `test/frontend-proxy.test.ts` | `243e8fa4a6d8edc25b72b743a630875f15f781e6193f5fa4ecb799fc8b01fe22` |
| `compose.yaml` | `9800da54c5f9aefaecbed9aa392079506d304c56178e21d7d38b0df6a99b14eb` |
| `compose.recovery.yaml` | `66bfe94b5c45d72386f52a2c15b985475a4b576867ec0e07f973088f0291e8c9` |
| `docs/frontend-operations.md` | `18723618cef77532c0a89de51cd4900b0e0e02bf353336a391f7a468a250dd7b` |

## Final Work repair review

This addendum reviews the bounded Work repairs after the preceding snapshot. The reviewer also implemented the disconnect bookkeeping and its three regression tests; that portion is a same-team self-review.

**F9 - Live requests inherited a browser policy that rejected their origin.** `test-results/frontend-work-report-diagnostic.log` records a successful reporting calculation alongside live-request 403 responses and a blank overview. The retained two-engine comparison in `test-results/frontend-live-origin-diagnostic-results.json` passed both cases: `no-referrer` produced `ORIGIN_REJECTED`, while `strict-origin` reached ordinary strict request validation (`INVALID_REQUEST` for the deliberately incomplete request). `HttpLiveSource` now explicitly uses `strict-origin`, matching the existing authenticated HTTP transport. Same-origin credentials, header-based CSRF, redirect rejection and server origin enforcement are preserved. This diagnostic establishes the policy difference; it does not substitute for the final authenticated Work journeys.

**F10 - A live disconnect discarded a successful independent report read.** Disconnect handling previously advanced the report generation and cleared queued refresh work. An initial HTTP calculation that completed afterward was discarded, leaving no value until the 60-second fallback. The controller now records disconnects separately: an already-running successful read is retained as last-known, while changed-event/write generations, hidden views and stopped controllers still reject superseded results. A queued refresh survives, and a later successful independent read may become current. The existing fallback cadence remains unchanged; no retry loop is introduced. Overview also presents **Refresh progress** after an unavailable read, using the existing coalesced refresh. The notice requires a non-current result as well as a disconnected reason, so it clears when a later read succeeds.

**F11 - Individual Inbox actions requested the current read state.** The row control now sends the opposite state (`!row.readAt`) through the existing verified mutation and refresh path, matching its **Mark read** / **Mark unread** label.

`test-results/frontend-live-repair-tests.log` records successful backend TypeScript compilation, frontend type checking and **10 passing live-client tests**. The three added cases prove retention of an initial result as last-known without early reconnection, preservation of a queued changed-event read while rejecting its superseded result, and rejection of disconnected in-flight results after hiding or stopping. Existing cases retain the 60-second fallback, clock, coalescing and strict SSE parsing coverage. The Work browser test now forces a reporting-read outage until the customer selects **Refresh progress**, then requires the real 100% result and removal of the retry notice; its final execution is pending at this addendum.

The additional `web/globals.css` delta replaces five remaining green-tinted literals with neutral colours: the modal and sidebar scrims, two small identity shadows, and avatar-picker text. The principal neutral surfaces and compact mobile task layout predate this delta. No behaviour changed, and no further material source issue was identified in this bounded repair review. Packaged image `8662e0ab1d3d40942670663a0c0eaef66aa282c549fc9a1f71e0c802caa1f543` is undergoing the final Work browser run; its outcome and runtime parity belong to the parent's `docs/frontend-verification.md` release record.

### Repair source snapshot

Snapshot: 2026-09-27 13:26 UTC. The earlier tables remain historical. All previously listed file hashes still match except `web/globals.css`, replaced below; the remaining entries identify the newly reviewed Work repair sources and tests. The Origin diagnostic is retained evidence, not shipped application code.

| File | SHA-256 |
| --- | --- |
| `web/globals.css` | `87f7cf37dae959bc6ba2b4ccd3ab0b114c2f86c47cadc3c11c70d1bd91276efd` |
| `frontend/work/index.tsx` | `74577920650a1110b45c07f09d3d477e06c94af99ecb42c8ddf6e19800ced627` |
| `frontend/work/shared.tsx` | `1116498bf0a5a8bd818318e9018cdd0e0fa3543ea4c32611c5eb152b8044e647` |
| `frontend/work/project.tsx` | `ad7f29dbec8ba04254c9fd283996eb303ba3253b3b5a297fc5ee43e0a93b69e8` |
| `src/client/live-controller.ts` | `5b0e53e9a053fe4a89b0d37cab225d1f4da06ef6c532e5b149b0e66dadd2f76d` |
| `test/live-client.test.ts` | `54f11398ca92b98bb91e103ae3d68f76b36dc2c05aeae78516f418840dc7908c` |
| `test/frontend/work.spec.ts` | `8a15887ab0f0bdce361d80961b7aa451ba3183b24bc9717dfe99cb5e4032d4e9` |
| `test-results/frontend-live-origin-diagnostic.spec.ts` | `65ceeaa66eaff6a2ff6ee58e45a434868da2c7fcd12118319bec4eff9d3d7ebe` |


## Final release closure

The parent release subsequently verified all pending product gates. `docs/frontend-verification.md` links the 40 distinct passing browser cases (with two intentional cross-engine skips for the three-person case), final public launch and Work reports, 64 focused Node checks, source/image parity and healthy local services. Both final public and Work reports identify deployed frontend image `8662e0ab1d3d40942670663a0c0eaef66aa282c549fc9a1f71e0c802caa1f543`. Earlier pending statements above remain historical snapshots. No product source changed after the final browser runs. This closure records implementation-team verification, not an external audit.

# Checkpoint 4 — authentication, sessions and device approval

Status: verified on 25 September 2026 (Europe/London). This checkpoint supplies the backend and browser protocol library without frontend screens. It is not a production-release or independent security-audit claim.

## Implemented behaviour

- Real OPAQUE login and reauthentication use persistent deployment setup, generic failed credentials, encrypted single-use two-minute proof state, current generation checks and cookie rotation. There is no password-based account discovery or conventional login fallback.
- Session cookies are host-only Secure/HttpOnly/SameSite=Lax. CSRF and exact-origin checks protect authenticated mutations. Thirty-minute idle, twelve-hour absolute and five-minute recent-authentication deadlines are enforced independently.
- Password authentication alone creates a restricted session. A returning approved device locally unwraps its exact credential-generation bundle and signs a fresh server challenge before protected access. Missing local keys require pairing.
- New-device pairing compares the full transcript fingerprint, verifies pinned signed history and both confirmations, stages immutable encrypted approvals, commits one signed grant and receipt, and requires fresh device proof before private delivery. The recipient verifies and decrypts every required scope before reporting content readiness. Restricted licences preserve replacement devices within existing scopes.
- Password change stages and reads back a new encrypted wrapper while retaining the old generation. Its fenced commit preserves the current signer, advances credentials, revokes other devices and all sessions, and produces a durable receipt. Restart recovery selects only the generation authenticated by the new password before receipt-based promotion.
- Logout clears worker keys, registered plaintext caches and pending operations before attempting server revocation. Forget additionally removes the selected remembered card and encrypted device/draft copies across stores. Cancellation checks prevent delayed pairing/password/activation responses from recreating forgotten copies. Corrupt ciphertext cannot block identity-based draft deletion.
- `openClient` installs the runtime lifecycle hooks and seeds the first independently verified genesis pin from activation. Names are explicit local remembered metadata. Signed history uses anchored complete-record pages and separately bounded authenticated read budgets.

Implementation: `src/modules/identity/{authentication,sessions,auth-routes,pairing,password-change,security-routes,security-history,authentication-cleanup}.ts`, `src/client/{auth-controller,auth-worker,auth-worker-client,remembered-profiles,pairing,password-change,runtime}.ts`, shared authentication/pairing/password/history schemas, migration `005_authentication.sql`, and API/worker wiring. Activation draft cleanup and verified-receipt hooks are integrated. Usage is documented in [authentication protocol](authentication-protocol.md).

## Acceptance evidence

| Check | Executed evidence |
| --- | --- |
| CP04-S1 | Authentication/session/controller tests distinguish password proof, current-device proof and private-key delivery. Pairing service/client tests verify scoped authority and immutable receipts. Two isolated real browser contexts pair, lose an approval response, recover it, decrypt delivery and resume after reload, with both active and actually revoked/restricted entitlements. |
| CP04-S2 | OPAQUE policy tests require 15 characters, accept long Unicode values without trimming/normalization, and reject the pinned common values locally. Real worker/browser registration and login use the same pinned Argon2id profile. Identity-provisioning tests verify private persistent setup and refuse accidental replacement; the local deployment reuses its existing identity file. Paste/password-manager presentation remains a frontend responsibility; the library imposes no such input restriction. |
| CP04-S3 | Session tests cover cookie attributes, CSRF, separate idle/absolute/recent deadlines, cookie rotation, current grants and reauthentication preserving the absolute limit. Real HTTPS browsers verify cookie attributes and protected access. |
| CP04-S4 | Worker, remembered-profile and controller tests verify usable-key clearing, pending-request cancellation, failed-network logout, late responses, all-hook cleanup and device-scoped erasure. Activation/password/pairing tests verify duplicate draft erasure, malformed ciphertext and delayed replies. Real browsers verify retained cards/wrappers on logout and removal on Forget. |
| CP04-S5 | Thirteen password-change tests verify staged/read-back wrappers, preserved signer/recovery authority, credential/session increments, other-device revocation, atomic commit, projection repair, receipt replay and local cleanup. Browser response-loss/reload tests successfully authenticate the new generation and promote the matching wrapper. |
| CP04-F1 | Tests reject wrong/unknown/inactive accounts, expired/replayed two-minute proofs, revoked devices, stale generations, changed grants, missing wrappers, CSRF and cross-origin requests. Real persisted source/account/workspace rate boundaries and generic/log-safe errors are exercised. |
| CP04-F2 | Restricted sessions and opaque sign-in references cannot fetch protected content or private delivery before approved-device proof. Login has one explicitly selected account and only OPAQUE packet handling; it never dispatches input through invitation/reset or unrelated password verifiers. Later invitation/reset interfaces retain their own checkpoint requirements. |
| CP04-F3 | Tests interrupt before draft persistence, between duplicate local writes, before authority commit, after commit, during projection and after a lost reply. A real browser reload proves new-password/exact-generation recovery; old and pending wrappers are not discarded speculatively. |

Additional checks cover finite grant expiry, Owner-versus-member approver authority, current-head conflicts, trusted operational entitlement signatures, rollback pins, complete history pagination, immutable anchors/cursors, per-page authentication and failed/oversized history records. History reads are capped at 1,200/source, 1,000/account and 4,000/workspace requests per ten minutes, separately from login/mutation budgets. Ordinary pages target 512 KiB/128 complete records; a single record is at most 1 MiB, with a 3 MiB response ceiling. Extreme histories can still return a finite rate-limit/error; no truncated history is silently accepted.

The hosted five-minute cleanup job deletes at most 1,000 expired authentication attempts each run. Two-minute proof expiry is enforced even when physical cleanup is delayed. The worker requires no identity secret.

## Final verification snapshot

Retention note: a later browser run removed the raw checkpoint-4 files from Playwright's default output directory. Its cleanup directory has been corrected. The [checkpoint 5 combined verification](checkpoint-05-evidence.md) freshly reruns all preceding cases and retains current logs; the counts and hashes below describe the original historical run, not currently available raw artifacts.

Environment: macOS arm64, native Node 24.19.0 tests, Node 24.20.0 container builds, PostgreSQL 18 application/control stores and restricted runtime roles. IndexedDB unit tests use `fake-indexeddb`; the browser suite separately uses native browser storage and actual WebAssembly/WebCrypto/module workers through local HTTPS.

Commands, using standard equivalents of the installed runtime paths:

```sh
npm run build
npm run build:browser
node node_modules/playwright/cli.js test
node --env-file=.env --test --test-concurrency=1 dist/test/*.test.js
node --env-file=.env --env-file=.env.admin dist/scripts/migrate.js
docker compose --profile app build api worker
docker compose --profile app up -d --wait api worker
```

- **Backend: 165 passed, zero failed/cancelled/skipped; 55.75 seconds.** Local report `test-results/checkpoint-04.log`, SHA-256 `bb707d254769b305c66abc12305199e2c93a7bc1ce6b829ff65f04a9e39b7a7a`.
- **Browser: 18 passed, zero failed/skipped/flaky; 35.51 seconds.** Six journeys in each of Chromium 153.0.8010.12, Firefox 155.0 and WebKit 26.6. Report `test-results/checkpoint-04-browser.json`, SHA-256 `a52b0569f8b9b9bd4cfe82e98522efe9a8745ccea9abc3f25db84e7a61842691`. Traces, screenshots and video are disabled; only public runtime/timing evidence is attached.
- **Source:** 93 `.ts`/`.sql` files in `src`, `scripts`, `migrations`, `test`; SHA-256 `cac8c6f76dddcec187dd629a5a208b44a2cd07c58826b3713686dfae9371274a`, using sorted relative path + NUL + bytes + NUL. The workspace remains uncommitted.
- Migration replay: application `0 applied, 1 unchanged`; control `0 applied, 5 unchanged`.
- Final API image manifest-list digest: `sha256:1582f45ea68dad37fcc4703205fba41b71e5c035ef58df9d983091e01c81d021`.
- Final worker image manifest-list digest: `sha256:60a0b28aad3206090fe7a3d5018df7ea9bf9025b18f762b5b0a82a3fced48ab8`.
- All four UKDA containers are healthy. API liveness/readiness and worker readiness return 200. Deployed session/history routes reject absent credentials with 401 `AUTH_REQUIRED`; a foreign origin receives 403. Worker runs as UID 1000, without admin credentials, identity secrets or an identity file.

The reports above are the final evidence. An earlier full run overlapped a compiler writing `dist` and returned one worker `INTERNAL` error; it is retained as `checkpoint-04-preacceptance.log` and excluded from acceptance. The isolated affected test and a clean complete run then passed. No source changes were needed for that error. Browser evidence remains applicable: the final intervening edits only corrected two strict test-reference fixture inputs.

Integration repaired and verified actual `fetch` receiver/referrer behavior, the activation journal's `{genesis,recoveryProof}` representation, dedicated history budgets, restricted-entitlement delivery and delayed-response cleanup. No unresolved checkpoint-4 failure remains.

## Later checkpoints and limitations

The small local common-password list is not a comprehensive breach database. Applications must register their own rendered plaintext/caches/input cleanup; the library cannot erase arbitrary external copies or reliably zero JavaScript strings. Public workspace rollback pins deliberately survive device Forget. Forgotten local keys are not reconstructed from the server.

This checkpoint does not implement member/Owner enrolment, password reset or Owner recovery, business workflows, retention/purge/export or final release. Those remain checkpoints 5–13. Expired pairing authorization is enforced now; later retention work must physically prune abandoned ceremony/device/object rows without removing required history. Enrolment/recovery/access transitions must extend the fail-closed client history verifier when implemented.

Bundled-engine evidence does not prove current/previous branded Chrome, Edge, Firefox and Safari compatibility. That matrix, the complete combined journey, independent review of the composed security implementation and production release remain explicit checkpoint-13 gates. No external independent review or production-readiness claim is made here.

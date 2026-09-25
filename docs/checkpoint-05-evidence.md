# Checkpoint 5 — encryption and account recovery

Status: verified on 25 September 2026 (Europe/London). This checkpoint implements the security backend and browser protocol library without frontend screens. It does not establish production readiness or complete checkpoints 6–13.

## Implemented behavior

Owner phrase recovery and Owner-assisted member/Owner resets replace authentication and device authority on the existing account. They preserve current eligible permissions and retained ciphertext. Each Owner receives an independent replacement phrase; members receive no phrase or custody grant. Reset codes are randomly generated 60-bit references with a fifteen-minute expiry, replacement/revocation, one recipient capability and safe identical-redemption retries. The short code never encrypts permanent keys.

The client verifies the complete fingerprint and signed history, stages and reads back an encrypted local device wrapper, proves the replacement password and new Owner phrase, and persists the exact encrypted approval before sending it. The service checks current authority, reads staged encrypted objects back, fences application operations, commits credentials/grants/revocations and a receipt durably, then projects the new head. Ambiguous responses reuse the same operation and receipt. Current login and fresh replacement-device proof precede private delivery; an Owner also decrypts the actual new recovery envelope with the new phrase before the controller reports content readiness.

Recovery history derives authority from signed genesis and supported transitions. Retired keys remain available for historical verification, but cannot authorize new transitions. Same-transaction history reads retain current authority locks through bounded anchored paging. Origin, strict-body, CSRF, current identity/device and durable source/account/workspace/operation limits guard the HTTP boundary. A separate two-connection counter pool prevents identity-pool starvation while keeping rejected-attempt counters committed.

Implementation references: `src/shared/recovery.ts`, `src/shared/security-history.ts`, `src/modules/identity/{recovery,recovery-routes,security-history,budgets}.ts`, `src/client/recovery-controller.ts`, Worker/client/runtime integration, and the API bootstrap. Existing schemas support these transitions; no new migration was needed. See [recovery protocol](recovery-protocol.md) for actual usage, paths, lifetimes, quotas and interruption handling.

## Requirement evidence

| Check | Executed evidence |
| --- | --- |
| CP05-S1 | `crypto-compatibility.test.ts` verifies manifest/installed/lock versions and integrity, frozen JCS UTF-8/base64url/counter/AEAD/digest/signature vectors, native Node Ed25519 verification and native HKDF reference output. The public fixture uses test-only keys and a counter beyond JavaScript's safe-integer range. |
| CP05-S2 | Crypto/activation/Worker tests and real Chromium/Firefox/WebKit runs exercise random keys/nonces, separate signing/recipient keys, scoped HKDF, OPAQUE export wrapping, signed sealed boxes and compatible decryption. The frozen Node-generated vector verifies in all three engines. |
| CP05-S3 | Recovery draft, strict contract, Worker and IndexedDB tests reject plaintext private fields and unverified word confirmations. Real browser flows persist only encrypted local wrappers through reload, then verify new device and phrase delivery. Member service recovery produces no recovery authority or Owner grant. Provider-row scans reject old/new plaintext secrets. |
| CP05-S4 | Pairing and recovery client/contract/browser checks bind the full transcript and reject wrong fingerprints, altered keys/scopes/generations/expiry. Owner approval and recipient confirmation are both required. RESET is an online ceremony reference, independent of encryption keys. JOIN enrolment remains checkpoint 6's integration responsibility. |
| CP05-S5 | Eleven recovery-service tests exercise phrase, member and other-Owner recovery; preserve account identity and encrypted records; exclude revoked project access; and restore both current and historical project epochs. Eleven client tests include a second phrase recovery using the new phrase while decrypting original custody signed by a retired device. Real browser journeys cover active/restricted licences, reloads, old-password rejection and two-browser Owner approval. |
| CP05-S6 | Service tests interrupt before/after authority commit and during projection, verify immutable staged/read-back encrypted approvals, stable receipts, old-authority retirement and idempotent projection repair. Existing persistence tests verify fences/draining/control-head checks. Current and retained project epochs decrypt after reset; no revoked-project envelope is restored. Full archive/audit/backup lifecycle integration is owned by checkpoints 7, 9 and 12. |
| CP05-F1 | Crypto, recovery contract/history/client and HTTP tests alter ciphertext, headers, algorithms, signatures, recipients, scopes, manifests, counters and heads; reject unknown/private/duplicate JSON fields; and refuse stale/replayed proofs or confirmations without releasing valid replacement access. |
| CP05-F2 | Tests cover replacement/revocation/expiry, another recipient capability, stale head, removed approver, corrupt/missing local drafts, late responses after Forget, interrupted commits and projection. Failed phrase challenges are consumed; expired unproved challenges stop occupying the pending-attempt limit after two minutes. Old credentials remain usable before commit. |
| CP05-F3 | Suspended targets cannot recover; revoked project grants remain revoked and absent from replacement delivery. Historical key epochs remain usable where current access permits. Old phrase proof and retired signing authority fail after rotation, including a subsequent recovery. Profile/Owner-removal lifecycle commands and their signed journal transitions remain checkpoint 6. |
| CP05-F4 | After both staging and commit, the real recovery fixture scans its provider-visible ceremony, staged-object, receipt, profile and application ciphertext rows for old/new passwords, phrases, export keys, device/recovery private keys, custody/content keys and known plaintext labels. None appears. Adapter tests verify sanitized logs/errors. Wrong/retired phrase and missing Owner/device authority cannot complete recovery; there is no support key or provider promotion route. Actual backup/restore media are checked in checkpoint 12. |

Member and additional-Owner service fixtures explicitly seed existing authorized profiles because enrolment is checkpoint 6. They prove recovery behavior, not a completed invitation/ownership lifecycle. Checkpoint 6 must prove those identities through real signed enrolment and removal, and checkpoint 13 must run the combined journey. Device removal must preserve person-level membership scope independently from device grants, so an active member can recover after losing the last device. These dependencies do not remove any later acceptance criterion.

## Final verification snapshot

Environment: macOS arm64; Node 24.19.0 tests; Node 24.20.0 container compilation; PostgreSQL 18 application/control stores with restricted runtime roles; Playwright 1.63.0. Browser crypto uses real HTTPS module Workers, WebAssembly, WebCrypto and IndexedDB.

- **Backend: 205 passed, 0 failed/cancelled/skipped; 71.91 seconds.** Report `test-results/checkpoint-05.log`; SHA-256 `915e5b574972ef84a48a94570cc6896a09d290aa5ecc86d8f3b6b01f749e0e1f`.
- **Browser: 30 passed, 0 failed/skipped/flaky; 57.04 seconds.** Ten journeys per engine: Chromium 153.0.8010.12, Firefox 155.0, WebKit 26.6. Report `test-results/checkpoint-05-browser.json`; SHA-256 `8baf25d4f1509593041d24fefa610bc668bf5eec8f4046af6c1d39f7544f0290`.
- **Source:** 106 `.ts`/`.sql` files under `src`, `scripts`, `migrations`, `test`; sorted relative path + NUL + bytes + NUL SHA-256 `695d3ed752b60fe19eaf962abf510d3018e11c799506b2e9f702c8892d0e9303`. The worktree is uncommitted.
- API image ID: `sha256:63a06e30eb886e17c30597bc902763d6a4b0af70d35e1f14fa8b447c9f6d007b`.
- Worker image ID: `sha256:17598faeefb3e757f811facb6f50281dcf31df732558f71da82349ce6390a0f7`.
- Both rebuilt local services and both databases are healthy. API live/ready and worker ready return 200. Deployed recovery rejects absent Owner credentials with 401 `AUTH_REQUIRED` and foreign Origin with 403 `ORIGIN_REJECTED`.

Executed commands used the installed native Node path and the Node container where necessary; standard equivalents:

```sh
npm run build
npm run build:browser
node --env-file=.env --test --test-concurrency=1 dist/test/*.test.js
node node_modules/playwright/cli.js test
docker compose --profile app build api worker
docker compose --profile app up -d --wait api worker
```

The combined run includes all preceding checkpoint tests plus the recovery additions, including the actual-target quota and exhausted-authority-pool regression. Focused runs first verified the new cryptographic, service, client and browser paths. Fixture-only assertion repairs used canonical equality for normalized JSON and fixed expiry timestamps; no repeated successful test loop was used to claim a pass.

An initial browser run exposed Playwright's default deletion of `test-results`, removing prior raw reports (including checkpoint 4's recorded logs). Its artifact directory is now `test-results/playwright-artifacts`; retained reports are outside that directory. The current combined reports above freshly verify the previous cases and supersede the missing raw files. Earlier recorded counts/hashes remain historical notes, not recreated artifacts.

Internal review by `/root/choose_security_libraries` found the expired-challenge capacity issue and the missing target-account quota coverage; both are fixed and tested. Server/client integration review found and addressed the separate-counter-pool requirement. These agent reviews are implementation checks, not the independent composed-system release review required at checkpoint 13.

## Remaining project work

Checkpoints 6–13 remain open. Bundled-engine results do not satisfy the current/previous branded Chrome/Edge/Firefox/Safari release matrix. Additional-Owner/member enrolment, role/access removal and custody rotation, business workflows, backup durability/restore, deletion/export and final independent review retain their explicit gates. Ordinary Owners are trusted content custodians. Client replacement or a compromised device can observe plaintext in use; no protection beyond the architecture's stated threat boundary is claimed.

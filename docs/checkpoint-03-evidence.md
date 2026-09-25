# Checkpoint 3 — licence activation and entitlement handling

Status: verified. Recorded 24 September 2026 in the local UKDA workspace. The original architecture remains the product authority; the evidence register assigns later authentication/recovery/Owner/deletion journeys to their implementing checkpoints without removing them from release acceptance.

## Implemented behaviour

- One non-expiring entitlement reserves one workspace and first Owner for sixty minutes. The server stores keyed verification values, not plaintext activation or resume keys. Competing browsers cannot inspect or take over an attempt using only its licence.
- Real OPAQUE registration and password-possession proof precede activation. The browser creates its independent 24-word recovery material and separate device keys, signs encrypted records and custody envelopes, and verifies an encrypted IndexedDB read-back before requesting finalisation.
- Activation atomically commits the consumed entitlement, workspace, Owner authentication record, approved device, recovery references, grants, immutable staged ciphertext and operation receipt in the security control store. The application fence closes and drains reads before authority changes; a durable hosted-worker job and protected status request repair interrupted projection.
- A saved setup operation survives reloads and lost responses. Draft replacement is generation-bound and idempotent; it cannot delete an active or newer local device candidate. Identical finalisation returns the original account/workspace. Setup resumption expires twenty-four hours after commit and never creates a login session.
- Operational revoke, legacy expiry, and reinstatement produce signed, immutable, idempotent receipts. Consumed/retired markers never become redeemable. Changes preserve identity, keys, maintenance, deletion and restore restrictions. Current protected reads remain possible under licence restriction; ordinary writes are denied.
- The API enforces origin, strict request schemas and persisted source/attempt/licence budgets. Errors and logs exclude secrets. Private operational provisioning files survive restart and are not embedded in images. The worker needs neither OPAQUE setup nor the service master key.

Implementation: `src/modules/identity/{activation,licences,entitlements,projection,opaque,secrets,budgets,routes}.ts`, `src/client/{activation,activation-controller,device-store,recovery,opaque}.ts`, `src/shared/{activation,crypto}.ts`, control migrations 002–004, `scripts/{setup-identity,licence}.ts`, API and worker wiring. The source tree is not yet committed; the source and local container artifact digests below identify this verification.

## Acceptance evidence

| Check | Evidence |
| --- | --- |
| CP03-S1 | `activation-flow.test.ts` uses real registration/proof, verifies all committed control records and exactly one Owner, and decrypts database read-back locally. `security-fence.test.ts` verifies reader draining and a durable closed fence. The worker repair test completes a failed projection without a browser retry. |
| CP03-S2 | `licence-reservations.test.ts` checks protected replay, fixed expiry, competing claims, draft generations, the 24-hour receipt window and consumed-key rejection. Controller and actual HTTP tests lose responses, reopen local stores, and promote only the saved matching device. |
| CP03-S3 | `entitlements.test.ts` covers the complete licence action allowlist, current data read/write gates, and a scoped licence lookup failure that leaves protected data reads usable. HTTP setup lookup failure returns a sanitised retryable 503. A security-control-store outage remains a separate fail-closed condition. |
| CP03-S4 | Entitlement tests preserve the original workspace and all profile/device/recovery/key rows through restriction and restoration. Deleted and fully purged workspace fixtures retain a consumed marker and cannot redeem the old licence or recreate either workspace projection. |
| CP03-F1 | Concurrent reservations/finalisations, licence-only takeover, invalid capabilities, old generations, expiry, wrong passwords and consumed proof replay fail without a second Owner. |
| CP03-F2 | Controller tests interrupt reservation, local staging, proof start/finish, draft replacement and the final reply. Database tests interrupt before authority commit and after commit/before projection. IndexedDB transaction-abort checks retain prior active/candidate state. Post-commit replacement is rejected; ordinary recovery remains checkpoint 5. |
| CP03-F3 | Changed hashes, signatures, ciphertext and context are rejected. Old entitlement-operation replay returns its original receipt without reapplying the old restriction after reinstatement. Reinstatement cannot clear independent workspace guards or reactivate deleted authority. |

Supporting checks include canonical encoding, signed/AEAD/recipient contexts, HKDF purpose separation, OPAQUE export-key stability and wrong-identity rejection, encrypted local storage, CLI private permissions, rollback on output-write failure, retention of the only key file after an ambiguous COMMIT, and real operational CLI replay.

## Executed verification

Environment: macOS arm64 host, native Node 24.19.0 test runtime, Node 24.20.0 Debian container builds, two PostgreSQL 18 stores with restricted runtime roles, Graphile Worker 0.18.0. Browser storage tests use `fake-indexeddb` 6.2.5; no browser-engine result is implied.

Commands (standard equivalents of the bundled-runtime paths used locally):

```sh
npm run build
node --env-file=.env --test --test-concurrency=1 dist/test/*.test.js
node --env-file=.env --env-file=.env.admin dist/scripts/migrate.js
docker compose --profile app build api worker
docker compose --profile app up -d --wait api worker
```

Final suite result: **91 passed, zero failed/cancelled/skipped, 14.99 seconds**. Full local output: `test-results/checkpoint-03.log` (ignored runtime evidence), SHA-256 `098fae7f2a24517666aee8f307ee0d7337136823eece1f0bb54e523cdab25849`. This includes the final local-staging interruption and explicit transport expiry/rate/unavailability checks.

Verified source digest: `f8281c49696dcacdcc4b7225c630bed6385e0b6cb82417b61b5bc62c0b37fac5` across 53 `.ts`/`.sql` files in `src`, `scripts`, `migrations`, and `test`; SHA-256 over lexically sorted relative path + NUL + file bytes + NUL.

Built local image manifest-list digests:

- API: `sha256:ebfa7d423184cf2c83f79a06d558103dfb8602cb1891fa08e34f3d86de76bbb3`.
- Worker: `sha256:c9c8d4a9a6fd44403c68fa883c29184488b5ada7052c51a582c7f7b98bc9faca`.

Migration replay reported application `0 applied, 1 unchanged`; control `0 applied, 4 unchanged`. Both containers ran as UID 1000; neither had admin credentials. API identity configuration was present via private environment injection, absent from the image filesystem; the worker had no identity secrets. Local API liveness/readiness and worker readiness returned 200. The deployed activation route rejected a malformed licence with 409 `LICENCE_UNAVAILABLE`.

## Remaining release work

Checkpoint 4 must implement normal login, sessions, approved/new-device journeys, password change, logout and real browser support. Checkpoints 5–6 must complete normal recovery, current-head trust, access management and equal-Owner journeys. Checkpoint 12 owns actual deletion/purge/export and restore drills, and checkpoint 13 owns combined end-to-end evidence, independent security review and production release gates. Their entitlement-preservation/restricted-mode cases remain mandatory. This checkpoint is not an independent security audit or a production-readiness claim.

Review: Codex integration with bounded module work by the security, client-flow and OPAQUE/provisioning agents. No external independent reviewer or production deployment is claimed. The recovery-context integration defect and actionable transport-error defect discovered during implementation were corrected and covered by focused checks; no unresolved checkpoint-3 blocker is recorded.

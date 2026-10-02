# Checkpoint 13 authentication, pairing and account-recovery review

> Historical review: identifiers, temporary paths and file hashes below record the reviewed version. They are retained as evidence, not current product branding. Current launch integration lives in `brand/maqbool-launch/`; see [compatibility identifiers](../compatibility-identifiers.md).

Report ID: **CP13-AUTH-REVIEW-2026-09-27**. Reviewer: **Codex independent automated review agent `/root/independent_auth_review`**. Review date: **27 September 2026**. This was a fresh source review delegated separately from the coordinating implementation agent. It is not a human audit, external certification, penetration test or proof of production readiness. Other automated reviewers were consulted on the shared custody-material finding; that collaboration is identified below. Subsequent implementation work by this same reviewer is recorded separately from the original independent findings.

## Result at initial review

Two findings require disposition: the shared material-authentication issue **CP13-AUTHORITY-01 (High, conditional)** and **CP13-AUTH-01 (Medium/P2, interrupted-workflow availability)**. No additional material OPAQUE authentication bypass, password-to-approved-device bypass, reset-to-ownership escalation, phrase-to-device-signature substitution or cross-account credential mutation was identified by this static pass. This is bounded negative evidence, not a claim that no vulnerability exists. CP13-S4 and release readiness must not be marked complete on this report alone while findings or required integrated/browser evidence remain open.

### CP13-AUTHORITY-01 — unanchored custody material can be re-encrypted as an approved delivery

Status at initial review: **open; shared finding owned by `/root/independent_authority_review`**. See that review's report and regression evidence for the authoritative disposition. This reviewer first raised the source-anchoring concern and independently traced the pairing/recovery consumers; the other reviewer established an additional confidentiality sink and owns the repair.

In the reviewed `src/client/pairing.ts`, `signer()` (lines 134–138) accepts a retained device by account, ID and key generation, including a retired or ordinary member's key. `scopePayload()` (153–179) verifies that the supplied material set contains the expected source digests, but then independently opens other recipient-matching envelopes. A custody payload is preferred over the content-key merge, and its manifest can be chosen from supplied material without requiring equality with `state.custodyManifest`. `openCustodyManifest()` verifies the chosen manifest's signature/context but does not establish its authorization in the signed history. A genuine required source can therefore be included while the actual selected keys come from an additional, attacker-created object.

Exploit prerequisites: control of the material response/storage presented to an honest client **and** possession of a current or retained historical workspace device signing private key. The attacker can seal an envelope to the victim's public recipient key, sign a fake same-epoch custody manifest containing attacker-known content keys, and include the genuine expected source alongside it. This is not an attack available from a password, short RESET code, public signing keys, or read-only database access alone.

The auth consumers are concrete: `preparePairingApproval()` (257–272) re-seals `scopePayload()`'s result to the new device and signs the approved grant; `prepareOwnerRecoveryApproval()` in `src/client/recovery-controller.ts` (159–167) uses `readDeviceScopeKeyMaterial()` and signs the replacement recovery delivery. Those callers perform strong transcript/current-authority checks, but those checks do not authenticate the separately selected plaintext key source. The other reviewer additionally traced new profile encryption in enrolment as a confidentiality sink. This reviewer did not execute an exploit and does not claim runtime reproduction of that sink.

Required repair: select key envelopes and custody manifests only through exact references authenticated by the replayed history/current scope; retain legitimate historical keys without treating historical signer presence as permission to create a new authority object. Exercise forged extra material with a genuine expected source present, retired/ordinary signer cases, and legitimate activation/pairing/recovery deliveries.

### CP13-AUTH-01 — confirmed logout removes security-operation resume drafts

Status at initial review: **open; repair authorized after the independent review**. Severity: **Medium/P2 availability and recovery-contract failure**, not a confidentiality leak or destruction of every local key.

`src/client/runtime.ts` (119–127) registers an `auth.onSignedOut` callback that invokes `forgetDevice()` for activation, pairing, recovery, enrolment and password-change controllers. `AuthController.performLogout()` (`src/client/auth-controller.ts`, 256–270) invokes this callback after confirmed explicit sign-out. Runtime `close()` also calls logout. The security controllers' `forgetDevice()` methods remove the matching operation records, including saved exact approvals, resume capabilities and encrypted wrapper copies. For example, `IndexedPasswordChangeStore.forgetDevice()` (`src/client/password-change.ts`, 172–190) deletes the saved draft by binding identity, and `IndexedRecoveryStore.forgetDevice()` (`src/client/recovery-controller.ts`, 362–370) deletes matching recovery metadata.

Concrete trigger: an approved device has a prepared password-change or security-approval draft; the user explicitly logs out or closes the runtime before resuming that operation, including after an uncertain result. The composed client deletes the saved draft, so its documented `resume(operationId)`/operation discovery path can no longer read the saved capability and exact request. An already prepared password-change candidate remains in the separate device store and matching-generation login can still work. A restricted recipient with no device identity may also retain its draft because it does not match the signed-out device. These limits are why the finding is not described as inevitable total account loss.

The behavior contradicts the encrypted-draft retention rules in `docs/authentication-protocol.md` and `docs/recovery-protocol.md`, and weakens the interruption handling required by architecture section 9 and CP04-F3/CP13-F1. Keep ordinary pending business-request cleanup on confirmed sign-out, but preserve these security-operation drafts until explicit Forget or an authoritative cancellation/completion cleanup policy. Existing explicit `onForget` hooks should retain their deletion behavior.

## Examined security properties

- **OPAQUE and sessions:** the selected account reference determines one record; unknown/inactive accounts use the OPAQUE fake-record path; client export material alone derives the local wrapper key; the shared OPAQUE session key is not an application session credential. Two-minute stored proof state is context-protected and consumed on rejected protocol finishes. Current credential/session/data generations are checked before session issue. Password success gives restricted authority; approved-device elevation requires a signed fresh challenge with current grants. Reauthentication preserves the absolute session deadline.
- **HTTP boundary:** examined exact-origin/no-query checks, strict schemas and duplicate-key rejection, cookie attributes, CSRF on authenticated mutations, durable source/account/workspace/code quotas, bounded errors, no-store responses and logging that avoids request bodies and raw URLs. No new secret-bearing endpoint field was found.
- **Password change:** the new OPAQUE record, configuration and wrapper digest are bound to the current device signature; the candidate is staged/read back before finalization. A control commit advances credential/session generations, revokes other devices and all sessions, preserves the current signer and Owner phrase authority, and returns a durable receipt. The client checks the saved exact payload before wrapper promotion.
- **Pairing:** the full transcript binds genesis/head, both device key sets, account, generations, scopes, expiry and wrapper digest. Existing approvers require an independent pin; recipients pin only after the full-fingerprint confirmation. The service rechecks its snapshot and personal/device scope intersection before stage/commit and delivery. The separate material-selection finding above remains material despite these checks.
- **Phrase/reset recovery:** phrase keys derive from 256-bit BIP39 entropy with distinct proof/recipient HKDF purposes; phrase proofs are separate from device signing. Reset codes are 60-bit online capabilities with a 15-minute ceremony, one resume holder, replacement-generation invalidation and current Owner authorization. Recipient capabilities cannot request Owner custody material for an assisted reset. Recovery targets an active existing profile, keeps current role/scopes, replaces devices and sessions, and rotates personal Owner recovery authority. Delivery checks the replacement device, current scopes and new phrase custody envelope before reporting readiness.
- **Client trust and storage:** verified signed history is replayed from pinned genesis and monotone head; unknown transitions fail closed. Local wrappers authenticate context and validate private/public key consistency. Logout clears worker access and uses epoch/cancellation guards; Forget is a separate erasure operation. The runtime draft-deletion finding above is an integration defect not visible from isolated controller `clear()` tests.

## Method and limits

The initial pass used read-only file inspection/search and manual data-flow reasoning; it did not run tests, query or mutate databases, restart services, issue credentials, or exercise a browser. The reviewed authority/history excerpts cover the auth/pairing/password/recovery branches and pin behavior; other lifecycle, role, content, restore and deployment implementations have separate reviewers. OPAQUE's installed API/preset documentation and exact direct dependency versions were inspected, but the library's WASM/cryptographic internals, transitive supply chain and latest vulnerability feeds were not independently audited. No production TLS/proxy, real-device timing/rate-limit calibration, all-supported-browser matrix, crash/restore drill or human fingerprint/phrase interface was verified here. Frontend and future features are excluded by task scope.

The documented compromised-device/maliciously replaced-client boundary remains: a worker cannot protect plaintext from arbitrary same-origin code or a compromised device; JS strings cannot be reliably wiped; an already authorized recipient's copied historical keys cannot be revoked. The material-selection finding is narrower and actionable because it concerns honest client processing of tampered hosted material, not malicious replacement of the client.

The checkout contains substantial pre-existing uncommitted implementation work. The Git HEAD below identifies only the base; SHA-256 values identify the actual inspected files. Full-file hashes do not imply every line in broad support files was exhaustively audited. Later changed hashes require focused re-review.

## Initial examined-file snapshot

Captured UTC: `2026-09-27T01:52:56.799430+00:00`. Base Git HEAD: `bb76a955eaf9983996967b282c1b0f3a8f8e72e0`.

| Examined file | SHA-256 |
| --- | --- |
| `architecture/archtecture.md` | `d91263471492e97e793e826503be92bac03d2df3236eb9d1f2529350136399cf` |
| `docs/implementation-evidence.md` | `c5eb26e87d199b0b4c7b7a342776fcb436f83ba64b81577d2d883215939386cb` |
| `docs/authentication-protocol.md` | `8618bc23b652cb523d03bd48cf7812d555000672518563ddf8c4c48045bb83a6` |
| `docs/recovery-protocol.md` | `92035dfa8050203ab57bf767a481c88a3f372a1f725061e871727827e9409d86` |
| `docs/enrolment-protocol.md` | `3d946fdc130a403d5db741aa2e4c10ae3e31abfc6a9f27d0397830b30afd13bb` |
| `package.json` | `33a8edbe03c0c311d8ea2ec0fbdff0872ac6ebf0cb843b96ee1d39278aa7fb0a` |
| `src/app.ts` | `fb38a2282024a3951d5257261533658de0393fa948097eac49911ad9d0d57b3f` |
| `src/http.ts` | `85210e8e3d8171c9a1645528662a685ad6a38d7e7e2e138f58490bddc5efa1f2` |
| `src/modules/identity/authentication.ts` | `b7cdaf7a1568871cb444c5e47f8712bce58b6e2e51482cf6dbc215d0e5b85d1d` |
| `src/modules/identity/auth-routes.ts` | `52cb7203dda3f73e8d6b071ae031bd5d92487054e7a6a093f585035a82864405` |
| `src/modules/identity/opaque.ts` | `794b0203ef1e3c4de3c8b56fe9e5c3c708e6919b32fa3117b7d49a6c0052fa9d` |
| `src/modules/identity/sessions.ts` | `dad696e1a598a41fdbe46b35bec2e0cd556f2817563ccf1cf41aab185e21a13f` |
| `src/modules/identity/security-routes.ts` | `a09cfcbf0ac8f25bcf7ca39e13ee69fa195081fc73089fae17a784be2a33a29b` |
| `src/modules/identity/pairing.ts` | `56ae1d3811825d4ae95d8413887a68f11f00006fe34777a466b4e340f17b0627` |
| `src/modules/identity/password-change.ts` | `4a7a5fc2295f82247152c3797805cebd6fe243516c0572bd4003997e37780e0a` |
| `src/modules/identity/recovery.ts` | `93ddb1ad3de90a980f9ff0327f01c8931b15137953675abed5072228b1d9df94` |
| `src/modules/identity/recovery-routes.ts` | `de964a3a786fb99cd2ab72ededa750c8cc5ee08147ff6c9d9e0bd0b41c764b9f` |
| `src/modules/identity/personal-scopes.ts` | `7ad77d088fbc11df054a3f3bf66ec2c59a90ccdd87b3ff4178be19db6dbdec08` |
| `src/modules/identity/security-history.ts` | `25091e1a7e26ad0fd7b4f9dc2bf71918aea856645e19a5aaa46f37e6396eaa1e` |
| `src/modules/identity/budgets.ts` | `e00fabf962b39d7bfde5b4422c43b3c2a6b64ee56915040533043c772a9d0b6d` |
| `src/modules/identity/secrets.ts` | `96fbbd14c6041849f72a8e76598dd7ad7da4c148678d2fb8047ac6d3b427b598` |
| `src/client/auth-controller.ts` | `b77ef739843d7fc6b8f06e320f8a85a87315b7f8389d7e63459f450e55243ad3` |
| `src/client/auth-worker.ts` | `8913ba3136e09541f345c3f87c8831cee0fafab95f8fb0712acad480daf668dc` |
| `src/client/auth-worker-client.ts` | `ba57a8b9d920c2d523bf447fffc0ede0de056ffb3fa30d9fc171299208f0a7b4` |
| `src/client/opaque.ts` | `851f3fb4e07fc3a7a70d66c4924048cf67d85e61103c6f45a3e578e0736e9bbe` |
| `src/client/device-store.ts` | `4636a6f4d559ac4f162a29cf99a97185fa8ca01f48d3d6b2a35a415d7ee8b94a` |
| `src/client/pairing.ts` | `300a480153563f99aeb914e0fae9ad6fa16e46129c5b97f32dfde6cb36b327fc` |
| `src/client/password-change.ts` | `521f05d7e798e30ce11f3ca6058ea87f660ae45c80d48f9e9221b43458addaa6` |
| `src/client/recovery.ts` | `98f27881dc06c95c9c79e325ecdfefbc6dc8232989082d535e92055738411f41` |
| `src/client/recovery-controller.ts` | `fc4b300145c7f0557049fd94f2db9a1adc6322509843b06174c75517f98c3863` |
| `src/client/runtime.ts` | `628ebbfcd70df631b91c2eb24538ab555bf8c99798dd64fee39b923bad1d90a6` |
| `src/shared/auth.ts` | `89c773d2213b9dba14ffb5010db5ea1d970a0e4f0015617adf2d3db558446a20` |
| `src/shared/pairing.ts` | `aedcfc0283e4364f8dad23385139851bcf462409ff69556dcd9532deb203a0d3` |
| `src/shared/password-change.ts` | `88dfbc164ad10809efdb95c458a8f2699029c770b7d26e65cd7c2e1225224f01` |
| `src/shared/recovery.ts` | `139a9fa48f256a6042c5384dd1416f825b9cc442a8f24a9b0af337f4876896d5` |
| `src/shared/crypto.ts` | `c56d8de1eadc450411711f3f0fd839eda225c55f0e81f7f913abce8acdcb063e` |
| `src/shared/security-history.ts` | `9806df56959fce51e2ee45239fd73ad0014a06902506ed4fbd46dfb221a6504a` |
| `src/shared/json.ts` | `70c33af0087e8a04fff078edaea999befe9ca0f92d0a08f39ca9fafee8460c76` |
| `node_modules/@serenity-kit/opaque/README.md` | `ca85b27183ff01d369ec87b0b929d9b638cb164e873340ecec94c2ec746fcf64` |
| `node_modules/@serenity-kit/opaque/index.d.ts` | `beda412319a379722e07eb30b2d4c4e84c82c92f8596aff327da3535204442f0` |

## Authorized follow-up: CP13-AUTH-01 repair

After saving the independent findings, the coordinating agent authorized this reviewer to implement the bounded retention fix. `src/client/runtime.ts` now keeps activation, pairing, recovery, enrolment and password-change controllers out of confirmed-sign-out draft deletion. Their registered `onClear` handlers still abort work/clear usable keys, and their `onForget` handlers still erase drafts on explicit Forget. Ordinary pending business-request cleanup remains in the existing sign-out callback.

A new pure composition regression, `test/runtime-auth-retention.test.ts`, uses the real `openClient()` wiring and IndexedDB stores, real signed/encrypted active and pending device wrappers, and mocked HTTP authentication/Worker initialization. The test failed before the repair because the saved password-change draft became `undefined` after successful logout. After repair it passed **1/1**, checking exact saved capability/draft preservation after logout and runtime close/reopen, retention of active/pending wrappers and the remembered card, then deletion of all those matching local copies on explicit Forget.

Execution: native Node **v24.19.0**, direct TypeScript execution with `--experimental-transform-types` and a temporary relative `.js`→`.ts` resolution hook, `--test --test-concurrency=1 test/runtime-auth-retention.test.ts`. No application/control database, browser, running API, shared `dist/` build or real credentials were touched. This is a focused regression, not whole-checkpoint acceptance. CP13-AUTH-01 is **repaired and locally verified**; central type-check/build and integrated regression remain the coordinator's responsibility.

Post-repair SHA-256 snapshot:

| File | SHA-256 |
| --- | --- |
| `src/client/runtime.ts` | `25346ce6723d24d12ebb900b4ec983d97dac71a02d265ccff1a20540ebdf47f4` |
| `test/runtime-auth-retention.test.ts` | `0aa14a06b6266d44b9d8d19f34167f61d92a3a726552843eca6a908556deac50` |

## Independent follow-up: CP13-AUTHORITY-01 repair

The authority reviewer authored the material-selection repair; this reviewer independently inspected its source and ran its focused adversarial regression. `openCustodyManifest` now requires the exact current signed history manifest ID/digest and epoch. Scope-key selection only opens the exact envelopes referenced by the active device's current personal scope (or the signed genesis anchor), validates the active holder's keys/generation, preserves content/custody distinctions, and checks effective read access/expiry and current scope epochs. An unrelated signed envelope included alongside the genuine delivery cannot supply the selected key.

The initial re-review caught a legitimate revocation-fixture failure: passing a full custody-manifest state reference, including `revision`, violated the strict payload schema. The author corrected this to the exact `{ id, digest }` wire reference. The rerun then passed **2/2**, covering injected keys signed by an ordinary device and by a subsequently revoked device while retaining genuine source delivery. Both cases exercise the concrete new-invitation encryption sink. This independently confirms closure of the reported injected-material attack under those fixtures; it is not full acceptance of every legitimate pairing/recovery transition.

Execution: native Node **v24.19.0**, `--experimental-transform-types --import /tmp/ukda-cp13-auth-typescript-loader.mjs --test --test-concurrency=1 test/pairing-material-authority.test.ts`. The temporary loader only resolves missing relative `.js` imports to TypeScript source. No application/control database, browser, running API or shared `dist/` build was touched. CP13-AUTHORITY-01 is **repaired and independently locally verified**; central compilation and integrated journeys remain the coordinator's responsibility.

Re-review SHA-256 snapshot captured UTC: `2026-09-27T01:59:37.316363+00:00`.

| File | SHA-256 |
| --- | --- |
| `src/client/pairing.ts` | `7173a332c0d074e5389b7fbb928f128ef9e8d4d916bf85c70edaed6675bc5e8a` |
| `src/shared/security-history.ts` | `9806df56959fce51e2ee45239fd73ad0014a06902506ed4fbd46dfb221a6504a` |
| `test/pairing-material-authority.test.ts` | `99ed529c57be4fb7df0384e8edabeb1ac6a660a6735fbc1416e41abe88005dac` |

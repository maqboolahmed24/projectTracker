# Checkpoint 13 authority review

Report ID: **UKDA-CP13-AUTH-20260927-01**  
Reviewer: **Codex automated reviewer, agent `/root/independent_authority_review`**  
Review type: **Fresh, independent automated static review of the composed implementation.** This is not a human review, external audit, penetration test, or dependency audit. The reviewer did not implement the reviewed flows during this review.  
Date: **2026-09-27**  
Base Git commit: `bb76a955eaf9983996967b282c1b0f3a8f8e72e0`; the review includes the current modified and untracked implementation, not only that commit.

## Result

**One material finding: CP13-AUTHORITY-01 (High).** The key-material resolver can use ciphertext outside the current signed authority to select an attacker-chosen encryption key. This blocked release at initial review. A focused repair and pure verification are recorded below; the composed integration gate remains with the coordinator. No other material authority finding was identified in this bounded review.

The report addresses the authority portion of CP13-S4. It does not itself complete CP13-S1/S2/F1 integrated execution, CP13-S3 supported-browser evidence, or CP13-S5 production/release evidence. CP13-F3 still requires those separate gates and resolution of any findings from the other composed reviews.

## Scope and method

Read the architecture's equal-Owner, custody, signed-transition, fixed-permission, tenant-isolation, concurrency and restore-fence requirements, together with the checkpoint 13 acceptance criteria. Followed the current implementation across client preparation and decryption, shared deterministic validators/history replay, server staging/finalisation, security authority and application projection. Inspected relevant source sections and SQL constraints/policies rather than treating file presence or dependency choice as implementation evidence.

Threat cases considered were an ordinary member requesting ownership, a pending/promoted profile claiming authority early, an Owner departing with stale custody, two Owners concurrently attempting removal, a server substituting a key recipient or older signed head, an expired or revoked device recovering current envelopes, cross-workspace object identifiers, project access outside the device's delivery subset, and stale/self task approval. The exact file digests below identify the reviewed bytes; a file appearing there does not claim exhaustive line-by-line review of unrelated functionality in that file.

The initial review performed no tests, database mutations, network attacks, live process changes, or implementation edits. Existing test claims in checkpoint evidence were read as supplied claims and were not independently rerun during the initial review. The final key-material lead was shared by automated peer `/root/independent_auth_review` and independently traced to the concrete encryption sink below. Any subsequent repair and pure regression execution is recorded separately; the as-reviewed hashes remain unchanged.

## Material finding: CP13-AUTHORITY-01

**Severity: High. Status at initial review: open; source-confirmed, runtime reproduction pending.**

**Conditions.** An attacker can tamper with the hosted key-material response and possesses any current or historical workspace device signing private key, including an ordinary member or retired device. The victim's client code, current signed history, local pin, device private key and OPAQUE authentication remain uncompromised. A malicious member alone, with no response/storage tampering route, is not shown to exploit the honest API by this review.

**Evidence and mechanism.** `src/client/pairing.ts:134–148` accepts any matching historical device as the signer of a custody manifest; it does not establish that signed history authorised that ciphertext. At `:155`, `scopePayload` only checks that genuine source objects are present. At `:159–179`, it then opens all matching recipient envelopes, including ones outside those sources, and prefers any matching-epoch custody payload/manifest before the genuine content payloads. This disconnect lets an injected envelope and manifest select attacker-chosen workspace/project keys while genuine signed objects remain as unused decoys. A signature by a known historical device proves authorship, not current authority to supply custody.

**Concrete confidentiality path.** The attacker seals a forged workspace custody payload to the victim Owner's public device recipient key and signs it with the attacker's known historical device signer. Its encrypted, attacker-signed manifest has the current custody epoch and an attacker-chosen current workspace content key. Preserve the genuine required source material, but omit the genuine Owner recipient envelope where it is not a required source, or place the forged custody first. `prepareJoinInvitation` in `src/client/enrolment-controller.ts:68–86` obtains that ring through `readDeviceScopeKeyMaterial` and encrypts the new profile name and invitation intent under the attacker-known key. Its same-key readback succeeds. The hosting attacker can decrypt that uploaded ciphertext. `preparePairingApproval` at `src/client/pairing.ts:257–272` also re-seals the selected material and signs a new grant, potentially laundering the untrusted source through valid current Owner authority.

**Further affected use.** Planning's `projectRing` (`src/client/planning-crypto.ts:78–106`) uses the same resolver. A removed project member who knows retained historical keys can provide those correct historical keys plus an attacker-chosen newly rotated current key; a project whose stored content has not yet been rewritten to the fresh epoch can pass old-record decryption and encrypt its next protected content under the substituted key. This secondary path is a source-level consequence requiring a focused regression fixture, not a claimed executed exploit. Callers in access rotation and project creation compare the returned manifest to `state.custodyManifest` and reject this particular fake manifest, but those local guards do not protect all other callers.

**Required repair.** Resolve each accepted device envelope through the exact digest/identity recorded by the device's relevant current signed scope, and establish a current signed custody-manifest reference before opening or delegating custody-derived keys. Retain explicit verified-genesis handling and historical keys without treating any historical signer as fresh authority. Reject or ignore unrelated injected materials before key selection. Add a pure regression with an intact signed history/source plus a same-epoch malicious custody envelope/manifest signed by an ordinary or revoked device, and verify the legitimate workflow remains usable. Record subsequent repair hashes and test evidence separately from the manifest below.

## Composed checks and evidence

| Threat or invariant | Source-level evidence and conclusion |
| --- | --- |
| Equal active Owners; no custom-role promotion | `src/shared/permissions.ts` keeps ownership/access administration outside the capability catalogue. `verifyEnrolmentBindingAgainstHistory` in `src/shared/security-history.ts` requires a current active Owner/device and the built-in Owner template for Owner enrolment. `src/modules/identity/enrolment.ts` rechecks current Owner authority and the target's state, invitation generation, complete binding and live scopes before finalisation. No special first-Owner authority was found in these paths. |
| Owner activation requires device, new recovery proof and all deliveries | `validateEnrolmentTransition` in `src/shared/enrolment.ts` binds recipient and authorizer confirmations, the new recovery confirmation, exact transcript digest, and one delivery per required device/scope plus recovery custody. `src/client/enrolment-crypto.ts` verifies the complete fingerprint and recovery-kit answers before generating proofs; the controller verifies signed history. Finalisation commits Owner role, recovery authority, grants, security head and receipt in one control transaction. |
| Last Owner and concurrent mutual removal | `deriveAccessPlan` in `src/shared/access-change.ts` requires another active Owner with current custody and active recovery authority before an Owner departure. The binding includes security head/version, ownership version, custody epoch and prior target generations. `AccessChangeService.#tx/#check/finalize` locks the workspace and rebuilds the exact plan at commit. After one removal commits, the other prepared binding cannot match current authority. |
| Removed custody cannot decrypt later epochs | The access plan identifies removed scopes, advances their content epochs, rotates custody for departure/scope removal, and enumerates remaining device/recovery recipients. `prepareAccessChange` in `src/client/access-change-crypto.ts` replays history before opening keys, preserves retained keyrings, generates fresh rotation keys, and seals to the exact derived recipients. Server validation verifies descriptor hashes, signed envelope headers and the derived plan before atomically revoking target sessions/ceremonies/recovery authority and replacing grants. This cannot erase keys or plaintext already copied, as the architecture explicitly states. |
| New projects remain recoverable by all active Owners | `deriveScopeProvisionPlan` in `src/shared/scope-provision.ts` includes every active Owner, requires a current recovery recipient for each, and derives custody recipients from current authority. The project client verifies this plan before generating keys and encrypted project content; the server validates the signed plan. |
| Signed history and rollback pins | `verifySecurityHistory` verifies the independently supplied genesis fingerprint, previous-head/next-version chain, authorised signer and exact expected final head; it rejects an omitted or conflicting pinned prefix. `IndexedPairingStore.recordVerifiedHistory` performs a transactional current-pin comparison and rejects a concurrent regression/fork. Current access-change controllers require an existing pin and matching current/anchor head. Historical verification deliberately removes the current pin only when replaying a bounded prefix of the already supplied history. |
| Current person and device grants both constrain access | `readPersonalScopes` and `intersectDeviceScopes` require committed manifests/grants, current key epochs, unexpired read permission and the person/device intersection. `SessionService` rechecks profile, session/credential/data generations and current device workspace grant. Current server envelope delivery applies the same scope checks; ordinary members receive only their device's key envelopes. Client material selection has the independent defect CP13-AUTHORITY-01 above. The selected work-read routes reauthenticate under the shared fence and filter by current device project scopes. |
| No ordinary edit signature substitutes for approval | `verifyPlanningBinding` derives permissions from current signed person/device scopes. `evaluatePlanning` requires the named eligible reviewer, `approve_tasks`, non-assignee status, the submitted content and policy revisions, active containing scopes and no open blocker. Material content/assignment edits invalidate review; the server rebuilds the complete binding and graph under the project lock before save. `verifyPlanningContext` replays signed commands and authenticated ciphertext digests, so the client does not accept an arbitrary server-supplied Done graph. |
| Cross-workspace and cross-project substitution | Reviewed service queries bind workspace/profile/project identifiers explicitly. Signed bindings and envelope headers contain workspace, scope, recipient and security context. The reviewed migrations use tenant-inclusive foreign keys and force RLS; application project policies include current workspace/profile and active project read grants. These are additional layers to API/device checks, not substitutes for them. |
| Security commit/projection failure is fail-closed | `withSecurityFence` obtains the exclusive application workspace lock and durably closes its fence before the separate control mutation. `dataTransaction` holds the matching shared lock and compares projected/current heads, versions and data generations before returning data. Failed projection leaves the fence closed; signed operation receipts distinguish committed security work from an incomplete application projection. |

## Limits and residual release gates

This was a bounded static authority review. Authentication/OPAQUE internals, pairing transport and reset/recovery ceremonies beyond their authority/history interfaces, cryptographic primitives, restore/deletion operations, worker deployment, rate limits, operational key management and browser-specific runtime behavior require their own evidence. No independent assurance is made about deployed PostgreSQL privileges, synchronous replica durability, production configuration, or a malicious client distribution. The reviewed permission and custody design intentionally trusts active Owners with ordinary workspace content.

No initial-review test result or previous checkpoint pass count is added by this report; any subsequent repair validation must be identified as such. The integration coordinator must retain its actual test and drill results, supported-browser versions/unavailable environments, other reviewer reports, and production status separately. Changes to a reviewed file after the recorded digest require a targeted follow-up review of the changed security behavior.

## Exact reviewed-file SHA-256 manifest

Snapshot captured at **2026-09-27T01:48:45.632138+00:00**. Digests are of complete file bytes, even when the review concentrated on the relevant sections.

| File | SHA-256 |
| --- | --- |
| `architecture/archtecture.md` | `d91263471492e97e793e826503be92bac03d2df3236eb9d1f2529350136399cf` |
| `docs/implementation-evidence.md` | `c5eb26e87d199b0b4c7b7a342776fcb436f83ba64b81577d2d883215939386cb` |
| `src/shared/access-change.ts` | `ca0fb16f60316f92039b38b2f5ace027dd4d151e3d1fdb4b1ee8f6d139ddb4d1` |
| `src/shared/security-history.ts` | `a06ff706a202c90f64f0c8445228bea0ef9d85a319c418f0a5f267b717346c1d` |
| `src/shared/enrolment.ts` | `d9fbd68e75f2ae6336a0bc6e60f86f2e22ce2856b189de9ea9806e8cfeac84f9` |
| `src/shared/permissions.ts` | `5547e95c0e5d7c42cc829d21eb0e58c4371174000525ac31c28aa45ed9735705` |
| `src/shared/roles.ts` | `eb99647363de1cf59248eb39106833c45f5e11d24fcce1d5d9c5ff837775a3f4` |
| `src/shared/scope-provision.ts` | `9c905c6d375b8eae27230bba57a473fea77c2456e14cfd5bfb6f10cc3783f79d` |
| `src/shared/planning-api.ts` | `f33f840f6d40e7736f32a45cdf9d4ded6193fdf5d84e3803512cc6c73fce99d7` |
| `src/shared/planning.ts` | `5bb1c5ad78002a28aa95f1ee84b8d899e3fa0caf3965dcd2a15e924679df1f66` |
| `src/client/access-change-crypto.ts` | `f83140aa29d19a600e0f5fc5facdadec3b610f2bed234c72a309d9478a9a1715` |
| `src/client/access-change-controller.ts` | `438b7b3e1a81988dce86997d987930c4a77e80f7b72a8ab06fb1382a4d6e8f84` |
| `src/client/enrolment-crypto.ts` | `f2c87523fe39b884b8224e14ce5fed38986bc7888049d720414751a73cfda3c8` |
| `src/client/enrolment-controller.ts` | `baae477ff87f77f08719827631de9089f33585a8551487cba5810c66cc2a45a1` |
| `src/client/pairing.ts` | `b853252a1e8eb46d42f560cb42ad11eb34e0b93521c4fd8eb7c95923b6677043` |
| `src/client/project-create-controller.ts` | `56e425f0236ef77f03d193469383161d799fdffb3ac02df07c7b4812341f106d` |
| `src/client/project-create-crypto.ts` | `400337ef2402d978e80947dc8d0b64fb3d8ae9af846a93292dc8905ca0ef7f43` |
| `src/client/planning-crypto.ts` | `50115796c09339aa997b4670ddb35a5a0e4c45dc47d9d0273b28912666e77f84` |
| `src/client/security-history-resolver.ts` | `5e657c72b9e44f81c44df66d9160d593a274b95724a57f28547e16355a8e4d62` |
| `src/modules/identity/access-change.ts` | `ee1a9d900e685298d14250bdef72e08113344026a66f029863ea8c84b509c42f` |
| `src/modules/identity/access-projection.ts` | `d8f3a488ffdcf8afa611f67480580d75be33464fc2212018aaaa96612f27f4e8` |
| `src/modules/identity/enrolment.ts` | `56b4e39a80a2887b92f0983a705fe1ec9ca30a5af13a0f33c3591a1f8c6da24e` |
| `src/modules/identity/personal-scopes.ts` | `7ad77d088fbc11df054a3f3bf66ec2c59a90ccdd87b3ff4178be19db6dbdec08` |
| `src/modules/identity/projection.ts` | `3e3f0252bec38293b3bb7d1c0ac14bf78d52c8c3931e71a497e0fdeca0840ec6` |
| `src/modules/identity/roles.ts` | `661c6eb2965f30f3a822642107f40c624f70469693f944b4cc56b96f2bcef1d7` |
| `src/modules/identity/security-history.ts` | `25091e1a7e26ad0fd7b4f9dc2bf71918aea856645e19a5aaa46f37e6396eaa1e` |
| `src/modules/identity/sessions.ts` | `dad696e1a598a41fdbe46b35bec2e0cd556f2817563ccf1cf41aab185e21a13f` |
| `src/modules/work/device-scopes.ts` | `6ecdf7febece69be61aee9338f96243ba0041e988389e951998e6695e81838d5` |
| `src/modules/work/routes.ts` | `70a39ed3061430b8a1830ddfbee7ecbf856ba223ff891e4aaa1e6436d06a86ee` |
| `src/modules/work/planning.ts` | `bbeb118a1cde429227f07d8b8ee02afa8717e06b428f796545f164d632ce2939` |
| `src/modules/work/project-create.ts` | `a652401ea8a1ed639d2b08b6605d0648c9f9219393623156a1dbdb47cc5bd3a1` |
| `src/persistence.ts` | `57fdf2f30e8966c44d338d4b83e2c6f946238913238bb22d11457606335d8ce5` |
| `migrations/application/001_core.sql` | `a11d0a0206d0d02a57c7c3840d8c6439ae67d382ceadd6efeb3a0c3515ac74c9` |
| `migrations/application/002_identity_access.sql` | `62c50a5cf6c6a0dea65b749e9a7740835955a093a3c56922d9ba423dbf021116` |
| `migrations/control/001_security.sql` | `99573d4aae2b5c8224192beb45c7e925d25582bf6a50ddba81137efd757ea6b3` |
| `migrations/control/006_identity_access.sql` | `f85611ac3960b0e2f4ebb19700cf258e7705832601af5ff177db8affc9c54ddc` |


## Repair and supplemental verification

Status at this appendix: **CP13-AUTHORITY-01 repaired; focused attack regressions passed; coordinator integration pending.** The same automated reviewer authored the repair after the coordinator explicitly authorised implementation changes. This repair is therefore not claimed as an independent implementation audit; automated peer `/root/independent_auth_review` separately reviewed the anchoring approach. The initial-review SHA-256 manifest above remains unchanged.

The repair in `src/client/pairing.ts` resolves selected envelopes only through the holder's current signed device scope and matching current personal scope, rejects unrelated ciphertext as a key source, separates custody from ordinary content deliveries, and requires the exact current signed custody-manifest ID/digest/epoch. `src/shared/security-history.ts` retains the initial device-envelope ID/digest from the authenticated genesis so first-Owner delivery remains explicitly anchored. Existing historical signers still verify previously authorised envelopes; signer history alone cannot authorise an injected envelope.

The new `test/pairing-material-authority.test.ts` exercises both an active ordinary member and a revoked member signing an injected current-epoch custody envelope and manifest, with genuine required source bytes left intact. It verifies that legitimate source keys prevail, an actual newly encrypted invitation can be decrypted with the real key and cannot be decrypted with the attacker's key, and a genuine manifest plus only injected recipient material fails closed.

Validation performed after authorisation:

- Direct source execution with `/Users/maqbool/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node --experimental-transform-types --import /tmp/ukda-cp13-authority-resolve.mjs --test test/pairing-material-authority.test.ts`: **2 passed, 0 failed**. The temporary hook only maps absent relative `.js` imports to existing `.ts` source files in this workspace.
- Automated peer `/root/independent_auth_review` independently reread the repaired scope and manifest anchoring and reran the same attack regression through its own temporary source-resolution hook on Node v24.19.0: **2 passed, 0 failed**. The peer reported that the exact current-manifest and authorised envelope-source restrictions address the identified injection. This is independent automated re-review, not a human or external audit.
- The same native Node source runner with `--test-concurrency=1` over `access-change-client`, `enrolment-controller`, `project-create-client`, `recovery-client`, and `pairing-client`: **28 passed, 11 failed**. All 11 failures were the `pairing-client` fixture's worker startup reporting `AuthWorkerError(UNSUPPORTED)` before protocol assertions; that compiled-worker test requires the normal built execution path. No production-code change was made for this runner limitation. The 28 passing checks include equal-Owner project creation, historical key retention after Owner removal, promotion, reset/phrase delivery, and a second phrase recovery after retirement of the original signing device.
- One compile diagnostic in the repair was corrected by narrowing the `scopeMatches` helper's structural parameter type. One runtime fixture failure was corrected by returning only `{id,digest}` for the initial manifest reference, excluding the state's `revision` field from a strict recipient payload. The focused tests above are after those corrections.
- No database or browser test was run by this reviewer. Final TypeScript compilation, compiled worker regression, integrated backend/browser journeys and production evidence belong to the coordinator's retained execution record.

Repaired-source digest snapshot at 2026-09-27T01:58:51.098358+00:00:

| File | SHA-256 |
| --- | --- |
| `src/client/pairing.ts` | `7173a332c0d074e5389b7fbb928f128ef9e8d4d916bf85c70edaed6675bc5e8a` |
| `src/shared/security-history.ts` | `9806df56959fce51e2ee45239fd73ad0014a06902506ed4fbd46dfb221a6504a` |
| `test/pairing-material-authority.test.ts` | `99ed529c57be4fb7df0384e8edabeb1ac6a660a6735fbc1416e41abe88005dac` |

## Independent durability repair follow-up — 2026-09-27

Reviewer: automated Codex agent `/root/independent_authority_review`, independent of the agent that authored CP13-R1 and its repair. Review timestamp: **2026-09-27 02:09:09 UTC**. This read-only follow-up examined only the durability repair and committing authority branches in the three services below, with their transaction wrapper and retained focused-test evidence. It is not a human/external audit, a new test execution, or release approval.

**Conclusion: CP13-R1's missing transaction-local durability enforcement is repaired in the reviewed source. No uncovered control-authority write branch was found in these three services.** Each helper executes `SET LOCAL synchronous_commit='on'` on the same control client subsequently committed by `tenantTransaction` / `transaction`; the wrapper begins before invoking the helper and commits only after its callback returns. There is no intervening reset or control-client commit in these service paths. Separate application transactions use a different client and do not clear the control setting.

| Service | Committing branches checked |
| --- | --- |
| `src/modules/lifecycle/service.ts` | `#authority` at line 27 sets durability before `save` reaches deletion request, cancellation, or erasure-request writes at lines 85–103. All three branches and their security transition, workspace head and receipt share that transaction. An exact receipt retry also passes through the helper. |
| `src/modules/restoration/service.ts` | `#authority` at line 36 covers checkpoint capture at lines 52–59, restore begin and supersession/session/ceremony/profile invalidation at lines 72–92, and the separate reconciliation update transaction at lines 124–147. `#owner` invokes it for verification before lines 191–199, including the active-upgrade generation rebinding branch. Retry returns and all control transaction entry points were checked. |
| `src/modules/upgrades/service.ts` | `#authority` at line 48 covers both start/finish decisions at lines 138–172 and every profile/role/receipt/history write in identity batches at lines 196–225. The private decision-receipt helper is called inside the already-covered transaction. Nonidentity batch handlers delegate application content writes; they are not additional control-authority writes in this file. |

The coordinator's `test-results/checkpoint-13-focused-integration.log` records **both durability tests passing**. Reading `test/control-durability.test.ts` confirms seven actual precommit client observations for each incoming connection setting (`off` and `local`), for **14 observations of `on`**, plus checks that the session baseline is restored afterward. Checkpoint capture, reconciliation and erasure-request coverage above is static evidence, not claimed among those 14 observations. The retained log also contains an unrelated initial composed-journey failure and is not an all-pass suite. This follow-up ran no tests, changed no service/test/recovery-report source, and mutated no database or live process.

The repair requires the intended PostgreSQL synchronous replication configuration to deliver standby durability. Neither the source inspection nor the focused setting test establishes standby availability, independent failure domains, or production failover behavior; those operational requirements from CP13-R1 remain separate.

Exact follow-up SHA-256 snapshot (complete file bytes):

| File | SHA-256 |
| --- | --- |
| `src/modules/lifecycle/service.ts` | `482dc066086708ae9fd13cc7f78278b0c4160c2fe668ca81b51a272fd45e75ae` |
| `src/modules/restoration/service.ts` | `3bb87ec39f78c03c1d4d7e84bb2005af6988ea75539acd5732d60494050a0e19` |
| `src/modules/upgrades/service.ts` | `93241d9e6195e686964e4e68b523b204ec1269ded044f3656a6853e478979016` |
| `src/db.ts` | `299bbb2bce9c5ef2c05b18e02cc9f3ae975915ea91ef763b2e2a1fdeae2cae99` |
| `src/persistence.ts` | `57fdf2f30e8966c44d338d4b83e2c6f946238913238bb22d11457606335d8ce5` |
| `test/control-durability.test.ts` | `b637228443871bd8fb78e7cd639a89b379a7e27a174dce9e6bda0e5f07aea0d0` |
| `test-results/checkpoint-13-focused-integration.log` | `7cad398a4363be6c9cd1552645279e4db400a7c0e7e9b33b2d31c77c8d888813` |

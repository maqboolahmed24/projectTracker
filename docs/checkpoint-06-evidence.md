# Checkpoint 6 — profiles, Owners and permissions

Status: in progress. Checkpoint 5 is verified; checkpoint 6 remains unchecked.

Implementation includes the fixed permission matrix, authoritative identity/access schema and projection, verified client/server JOIN and promotion journeys, encrypted custom role definitions, and unassigned-work removal notices. The remaining acceptance work includes role assignment/access changes, suspension/demotion/removal and key rotation, concurrent last-Owner protection, and their client/server journeys.

Implemented first slice: `src/shared/permissions.ts` supplies immutable builtin defaults, validated custom capabilities and a reusable action policy. Current active ownership is required for administration; every content action requires exact active keyed project access. Members create tasks assigned only to themselves, assignment changes require management authority and eligible members, and assignees cannot approve their own task even when they are Owners. Projection imports/re-exports the unchanged role defaults.

Verification on 25 September 2026: TypeScript build passed; **19 focused tests passed, zero failed/skipped** (12 permission tests plus 7 activation/projection regression tests; 3.36 seconds). Report: `test-results/checkpoint-06-permissions.log`. Domain HTTP handlers do not yet consume the new policy; this is not completion of CP06-S3 or the checkpoint. The concrete remaining schema, enrolment and transition plan is in [checkpoint 6 design](checkpoint-06-design.md).

The next slice adds these concrete changes:

- Control migration `006_identity_access.sql` separates personal membership from devices, stores signed role revisions and ordinary-content scope heads, and records the current custody-manifest pointer. Legacy bootstrap uses only unambiguous committed epoch-one genesis material; it never invents membership from a device grant. SHA256: `f85611ac3960b0e2f4ebb19700cf258e7705832601af5ff177db8affc9c54ddc`.
- Application migration `002_identity_access.sql` projects effective grant permissions/expiry and scope epochs. Project RLS has no Owner bypass. Project notifications require current project access; inactive recipients cannot read workspace notices. SHA256: `62c50a5cf6c6a0dea65b749e9a7740835955a093a3c56922d9ba423dbf021116`.
- Activation writes personal Owner authority, genesis-derived roles and initial scope pointers. `access-projection.ts` copies all roles/access/epochs in the fenced application transaction, clears invalid live responsibilities and assignments, and preserves ciphertext, historical record epochs and authorship. Uncommitted key material keeps the workspace fenced. This is projection of an already validated authority change; it is not yet an Owner-removal API or a key-rotation protocol.
- `shared/enrolment.ts` binds JOIN/member/Owner/promotion signatures, private name proposals, exact key deliveries, immutable approval attempts and stable receipts. `client/enrolment-crypto.ts` handles encrypted local name/device drafts, full fingerprint confirmations, takeover re-sealing and promotion without replacing the existing password/device wrapper. The caller must independently verify the current authority binding; a matching server claim alone is insufficient.

Both migrations applied successfully and replayed with zero pending files. The seven new database tests passed, including rollback-only legacy migration replay; all seven projection/fence tests passed after correcting the synthetic fixture's custody epoch. All twelve enrolment contract checks passed. Broader integrated verification is recorded below when completed; these focused results do not complete CP06.

Implementation constraints carried forward from verified recovery:

- A person's workspace membership and recoverable content scope must survive revocation of their last device. Device grants alone must not define membership.
- An Owner's workspace authority does not bypass missing project keys or the existing project-access RLS. Owner setup/promotion must deliver ordinary project history and materialize access; future project creation must grant all active Owners.
- Roles use the existing seven-capability catalogue. Owner and recovery authority are separate from role checkboxes. Task assignments and teams never create project access.
- Existing-member promotion retains the account, working password and healthy current device; new personal phrase/custody authority is verified before ownership commits.
- Owner removal/demotion prepares replacement custody and future content-key epochs first, then commits revocation atomically under the workspace fence. Historical keys and attribution remain verifiable. At least one fully active Owner must survive every individual removal/suspension/demotion.
- Enrolment, access and ownership changes must extend the signed-history verifier. Recovery, pairing, snapshots and later business operations must use the same authoritative scope and generation model.

## Integrated regression evidence, 25 September 2026

Personal scope adapters now derive eligibility from durable person-level membership/Owner/project grants, intersect pairing with the approving device's exact current scope, and recheck permissions, expiry, committed material and explicit epochs for sessions and deliveries. Recovery preserves the person's membership when replacing devices. Regressions cover recovery after loss of the last device, immediate membership revocation, and narrowed pairing rights.

Signed-history verification now accepts validated JOIN/member/Owner and promotion transitions. It checks the trusted role registry, fresh identities, current active Owner authority, exact scope sources, independent new recovery authority, and preservation of existing credentials/profile/devices during promotion. These contracts do not yet constitute an exposed enrolment service.

The frozen source snapshot in `test-results/checkpoint-06-snapshot.json` contains 118 TypeScript/SQL files with SHA256 `79439eb53983b25627daee59303ed9f326cee6414afc378609ab521e946e4bcc`. TypeScript and browser builds succeeded. On that snapshot:

- **254 backend tests passed**, zero failed/skipped, in 75.824 seconds (`test-results/checkpoint-06-backend.log`, SHA256 `5e319f7d8efbddc0b2d425732aeba2b1d0387a215636a0bfb4c6bc369524334b`).
- **30 existing browser tests passed**, zero failed/skipped, across Chromium, Firefox and WebKit in 59.3 seconds (`test-results/checkpoint-06-browser.json`, SHA256 `40c0afe33d82ffb2e91e4622c2d28ce65b01e75b3d94fd988557245b99619316`). These cover the existing activation/authentication/recovery journeys; they do not prove a CP06 JOIN browser journey.
- API and worker images rebuilt successfully and were restarted. Both databases, API and worker report healthy; API live/ready and worker ready probes succeeded.
- Running API image: `sha256:ba0cd0f99aea5d1e130e58b8a8952c6f7cf45124a6b3a9972ce21bb171b466b1`; worker image: `sha256:5312a48bf82582345c0b977a84ce874e6702cf6c962dd093492517541736a6fe`.

Subsequent JOIN service/controller work is outside this verified snapshot until separately recorded. No checkpoint-6 acceptance criterion is claimed complete by this progress record. End-to-end business actions, notification visibility and archive/backup integration remain mandatory in their owning later checkpoints as well as the final combined journey.

## Enrolment and promotion verification, 25 September 2026

The implemented [enrolment protocol](enrolment-protocol.md) now connects real OPAQUE registration/proof, encrypted local device storage, signed history, the control database, fenced application projection and headless browser controllers. It supports one-profile JOIN replacement/revocation, independent equal-Owner setup, password-preserving member promotion, scoped delivery, takeover and durable lost-response recovery.

The frozen snapshot `test-results/checkpoint-06-enrolment-snapshot.json` covers 136 source/configuration files with SHA256 `95793277edb2c75d1ed4ae6fcc78237b33cc433bd369fca3fdf48e4d385b0bbd`. TypeScript and browser builds passed. Verification on that snapshot:

- **274 backend tests passed**, zero failed/skipped, in 90.974 seconds. Report: `test-results/checkpoint-06-enrolment-backend.log`; SHA256 `c7f8d2f8dd0c876a2f564e61a419a64ab259de3ee4586d12f6b0c2d9e2e01233`.
- **36 browser tests passed**, zero failed/skipped, across Chromium, Firefox and WebKit. Report: `test-results/checkpoint-06-enrolment-browser.json`; SHA256 `18f82642ef5364eea83898a3f1f70129f025b0a1f2b98137d5917dce9bbc2a6f`. This includes member JOIN after a lost commit reply/reload, promotion without replacing the password/device, independent second-Owner setup, staged approval takeover, and subsequent pairing/reset by the original Owner without relogging.
- A database journey pairs two actual devices, promotes the member, independently decrypts current custody on both devices, verifies unchanged credentials/device identities and replays the complete signed journal.
- Failure checks reject substituted invitation roles, retired public-key reuse, expired device delivery, code replacement/reuse, stale takeover confirmations, wrong password proofs, restricted access expansion and premature authority. Projection failure preserves the fence and resolves through the committed receipt.
- Rebuilt API and worker were restarted; both databases and both services are healthy. API live/ready and worker ready probes succeeded. API image: `sha256:ad7db3fd9163e64cfad489fdb1c73d7413e4b73ce3e9b6144638afc7310b03fe`; worker image: `sha256:f410be14e13a1ac241d292bcf59a5ab41e8da974a78210d6e97e0be11007f0d9`.

One expanded browser scenario exposed an overly strict cached ownership-version check after adding an Owner. The focused repair permits a monotone version only after verifying current history, unchanged credentials/device/custody and the operation's current authority. Pairing and reset approvals use the same guard; delivery retains exact generation/head checks. The repaired scenario and full suite passed. There is no unresolved failure in this snapshot.

This evidence does not complete checkpoint 6: signed role/access changes, suspension/demotion/removal with rotation, cleanup notifications and concurrent last-Owner enforcement are still required. The bundled-engine browser tests also do not replace checkpoint 13's supported-browser release matrix or independent security review.

CP06-S1 is now verified: `test/enrolment.test.ts` exercises concurrent finalization to one receipt, invitation replacement, single-holder redemption, revocation and expiry after 3,600,001 ms. `test/recovery.test.ts` exercises RESET replacement, same-holder retry, another-holder rejection, revocation, expiry after 900,001 ms and replacement invalidation of staged recovery. The corresponding shared code generators use cryptographic random bytes, and services retain purpose/workspace-bound keyed digests, recheck the profile's invitation/reset generation and reject completed/revoked/expired setup. These tests passed in the 274-test report above. Other CP06 criteria remain open.

## Removal projection notices

Access projection now captures unfinished tasks whose last eligible assignee is being removed and inserts `security.work_unassigned` notices for the remaining project Manager and active Owners with project access. Notices contain opaque task references, never decrypted content. Security notices bypass project mute and are deduplicated by security version, task and recipient. Already unassigned tasks, completed/cancelled tasks and tasks retaining another assignee do not generate these notices. Existing RLS hides project notices after recipient access ends.

The scoped TypeScript build and all **8 security-fence tests passed** (zero failed/skipped, 1.384 seconds), including a real application-transaction interruption at the notification write: assignments and notifications both roll back, the workspace remains fenced, and a subsequent projection completes cleanup and sends exactly one notice per recipient. This tests projection of synthetic committed authority, not an implemented removal command or cryptographic key rotation.

Evidence: `test-results/checkpoint-06-cleanup.log`, SHA256 `5e31921990ef3fd2de9d445b45826a3f94bccfcc1e70055a5d5b90b4dc93ef88`. Source SHA256: `src/modules/identity/access-projection.ts` = `9e6ba8115b4ab7c62e354103a6154c98aedaf64ee2d8fa72aa7514c5aee94d72`; `test/security-fence.test.ts` = `4cbb7322b4be3aec89dc4df8ff3135c18bf266d3deed184dbe4f8bc9c1ca8bd8`. This addition is outside the earlier enrolment image snapshot until the next integrated rebuild.

## Custom roles and integrated regression, 25 September 2026

The [role protocol](roles-protocol.md) implements Owner-only create/update/retire/list, encrypted labels, immutable staged payloads, fenced commit, durable receipts and interrupted browser recovery. Builtin definitions remain immutable, and the seven-capability catalogue contains no ownership or recovery authority. Editing defaults preserves existing personal/project role revisions and effective permissions. Retirement rejects current references, including expired assignments that have not been explicitly revoked, and pending invitations. Signed history now derives those role links explicitly and rejects retired roles during enrolment.

The new tests cover real custom-role member JOIN, restricted-entitlement reads/replay, denied member administration, cross-origin/CSRF/body validation, durable quota keys, ciphertext tampering, stale authority, unchanged project permission snapshots, and interruption before/after commit. Client tests cover encrypted label round trips, exact list verification, persistent ciphertext read-back, lost replies, logout/Forget and strict history request bodies. Browser tests exercise lost staging and commit replies across reload, paginated decrypted listing, edit/retirement, builtin rejection, custom-role JOIN and in-use retirement refusal. Captured upload bodies contain no role labels.

A bounded peer review found and corrected one retirement mismatch between expired database grants and retained signed assignment links. The first browser run found extra edit-context fields in a history request; the transport now sends only its public reference/cursor, with a dedicated regression. Test-only repairs corrected an expiry timestamp violating database integrity and the simulated HTTP response's missing URL. All affected checks subsequently passed; no unresolved failure remains in this slice. This peer review is not checkpoint 13's independent release security audit.

The final source snapshot `test-results/checkpoint-06-roles-snapshot.json` covers 145 source/configuration files with SHA256 `c17bf97984a03088873a2e7835f77d2b1dcf42fc98658e3880b383ca01b4b12a`. TypeScript and browser builds passed. On that frozen snapshot:

- **294 backend tests passed**, zero failed/skipped, in 100.272 seconds. Report: `test-results/checkpoint-06-roles-backend.log`; SHA256 `4899ba3af27a705e32b15117a4d745579921e3906bbb8561c1681f9bbcf026f2`.
- **39 browser tests passed**, zero failed/skipped/flaky, across Chromium, Firefox and WebKit in 111.477 seconds. Report: `test-results/checkpoint-06-roles-browser.json`; SHA256 `2abfb0984662fa7c4f908e5bbdb8bf951540d3921565ce56cb3db61898de68b0`.
- API and worker images rebuilt and restarted successfully. Both databases, API and worker are healthy; API live/ready and worker ready probes succeeded.
- API image: `sha256:586ff1acb90b45cbdbc3298b8ef3a9dcaa76b75714789672a2e22186dfd41550`. Worker image: `sha256:9d680303b041ea99c36ba13222d9f266a0d51f35886fba8b334854b9fb63469c`. These images include both custom roles and the removal-projection notices above.

Checkpoint 6 remains unchecked. Definition management does not yet provide role reassignment or expanded/revoked project membership. Suspension, Owner demotion/removal, custody/content rotation and concurrent last-Owner enforcement remain required before accepting the checkpoint. Later business APIs and the complete release journey remain required by checkpoints 7–13.

## Current profile role migration, 25 September 2026

Control migration `007_profile_roles.sql` adds a profile's current role, role revision and immutable signed assignment reference. The three fields must be present together and references stay within the workspace. Existing assignments are backfilled from committed genesis/enrolment/promotion records matched to the security journal; a newer promotion supersedes the original member role. Staged objects and unjournalled objects cannot establish an assignment. Existing signed objects and transition bytes remain unchanged.

The migration applied successfully to the local control store; all six preceding control migrations were unchanged. Its SHA256 is `56b76cc7bdba5c714e52ac7d90ecefd93bef5de939f47b7b46f745addaac7bfd`. An isolated TypeScript build and **9 database checks passed**, zero failed/skipped, in 0.563 seconds. Report: `test-results/checkpoint-06-role-migrations.log`, SHA256 `a09a29b7a0aa33b89d4bd6917a6bc42b9b07003fc0d03a07962a8997823d20cb`. These checks cover the backfill, complete references, tenant boundaries and retained role references for suspension, together with the preceding identity-access migration checks.

Activation/enrolment assignment writes, retirement lookup changes and access-change protocol integration are being connected separately. The nine database checks do not prove those service journeys or complete checkpoint 6; the last fully verified running image remains the custom-role snapshot above.

# Checkpoint 06 implementation plan

Status: checkpoint 6 is in progress. This is the original implementation plan, so descriptions of existing gaps below describe the starting state. Membership/projection, enrolment/promotion and custom role definitions have since been implemented; see [enrolment protocol](enrolment-protocol.md), [role protocol](roles-protocol.md) and [verification evidence](checkpoint-06-evidence.md) for current scope. Assignment/access mutation and removal/rotation remain unfinished. This plan does **not** assert completion or independent release audit.

## Existing authority and gaps

The control store already owns profiles, device grants, recovery authorities, ceremonies, immutable encrypted objects, signed transitions, and operation receipts. The application store already has roles, project access, assignments, leads, blocker responsibility, and tenant/project RLS. Extend those records rather than creating a second membership service.

Current `projectAuthoritativeWorkspace` copies only workspace restrictions, profile state/ciphertext, and missing builtin roles. It does not yet project authoritative role definitions, project grants, key epochs, or access-removal effects. Its application transaction uses an empty profile context, which is sufficient for its current workspace-scoped tables but cannot mutate project-scoped records under existing RLS.

A member's current workspace key entitlement is inferred from device grants. This must change: revoking the last device must revoke that device's future access without destroying an active person's workspace membership or recovery eligibility. Owner authority is likewise personal; legacy Owner grants should not remain tied to the activating device.

## Minimal control-store changes

All new tenant tables use composite workspace keys, tenant-aware foreign keys, and the existing FORCE RLS tenant policy. All signed definitions/encrypted objects remain immutable in `security.staged_objects`; current-state rows point at them. Do not put labels, key material, invitation codes, or phrases in plaintext metadata.

| Record | Proposed delta and invariant |
| --- | --- |
| `security.grants` | Add `grant_kind='membership'`, constrained to workspace scope with `device_id IS NULL`. One active workspace membership grant per profile. Keep person-level project grants as existing `grant_kind='project', device_id IS NULL`; device/project delivery grants remain device-bound. Add explicit positive `key_epoch`, so content epochs are not inferred from the encryption epoch of a custody-wrapped manifest. Add nullable `role_id` and `role_revision` for person-level project grants, with a tenant FK to authoritative roles. Current grant generation plus its signed object binds the exact permission snapshot. |
| `security.roles` | `(workspace_id, role_id)` PK; `template` in Owner/Manager/Member/Viewer/custom; positive `revision`; state active/retired; fixed-catalogue `permissions`; `definition_object_id` pointing to the signed definition; `encrypted_role_object_id` for a custom name; `security_version`. Builtin names may remain localized public templates with no encrypted label object. Ownership is not a capability or assignable custom role bit. A project assignment cannot make `profiles.is_owner` true. |
| `security.scope_heads` | `(workspace_id, scope_kind, scope_id)` PK, with workspace scope ID equal to workspace ID; positive ordinary-content `key_epoch`; `recovery_manifest_object_id` for the current custody-protected scope keyring; `security_version`. Project IDs are opaque security-scope identities; application project creation is a separate projection/domain step. Keyrings retain every historical epoch needed by retained ciphertext. |
| `security.workspaces` | Add `current_custody_manifest_object_id` beside existing `custody_epoch`. Custody-key epoch and ordinary-content epochs are separate counters: rewrapping a project keyring under new custody must not pretend the project content epoch changed. |
| `security.staged_objects` | Add encrypted role-definition object kind. Reuse existing signed-grant, key-envelope, and custody-manifest kinds for signed definitions and encrypted keyrings; no new mutable blob store. |
| `security.ceremonies` | Existing invitation and owner-promotion kinds, staged OPAQUE record, generations, public state, verifiers, and encrypted proof state suffice. Invitation payloads explicitly distinguish member/Owner enrolment. Reuse staging/receipt machinery, not a parallel login credential table. |

A workspace membership grant authorizes the person's ordinary workspace key scope. Its recovery-manifest reference is ciphertext under current Owner custody; it is not a member recovery phrase or a key that unlocks every project. Only approved device grants deliver plaintext key material after local decryption. Person-level project grants remain the authoritative project eligibility; a device can only receive subsets already granted to its person.

The grant's explicit `key_epoch` identifies the material delivered by that scope: an Owner workspace grant or device delivery uses the current `custody_epoch`; ordinary member workspace and all project grants use their current ordinary-content `scope_heads.key_epoch`. Scope heads always describe ordinary content, even when their keyring ciphertext is encrypted under a different custody epoch.

On migration/bootstrap, derive initial Owner scope heads and builtin role definitions from the existing signed genesis and committed manifests. Normalize legacy `grant_kind='owner'` rows to person-level `device_id=NULL`. New member enrolment writes the independent workspace membership from its signed enrolment transition. Do not manufacture unsigned memberships from arbitrary device grants. Existing CP05 seeded member fixtures must be updated to seed the new invariant explicitly; they were not production enrolment paths.

## Application projection and authorization

- Project authoritative roles by revision, including retirements; stop treating builtin insertion as the complete role projection.
- Project each person's pending/active/revoked project grant into `app.project_access`. Add the authoritative grant ID, grant generation, effective permission snapshot, and role revision. Use that permission snapshot for `can_read_project` and policy evaluation. Editing a role definition alone must not silently expand an old grant.
- Project `security.scope_heads` into a small `app.scope_heads` mirror. Protected writes compare the requested key epoch with this current write epoch. Existing `projects.key_epoch`, profile/task record epochs, and ciphertext headers describe the epoch that encrypted that record; do not update them merely because future writes rotate to a new epoch.
- Keep explicit keyed project access for Owners. New Owner activation/promotion must install person-level Owner access to **every existing ordinary project**, together with current/historical key availability. Checkpoint 07 project creation must install access for every active Owner before making the project available. `app.can_read_project` must retain its current absence of an Owner bypass.
- A new/expanded grant stays Pending until both its signed permission snapshot and required encrypted key delivery objects are committed. Team membership and assignment never supply missing access. Role edits use the same signed, fenced grant-change operation for affected assignments; a definition update cannot grant access outside its listed scopes.

Projection must synchronize all these rows in its existing single application transaction, then reread the same control head before reopening the fence. It must not reopen after copying profiles but before copying revocations or epochs.

For project-scoped cleanup, first project active access for all remaining Owners, then use a retained, fully active Owner's explicit project access as the internal projection transaction's profile context. This is a trusted projection of an already committed signed control transition, never a browser-supplied identity or a new user session. Do not disable RLS or grant the HTTP role a general bypass. If no valid remaining Owner/access projection exists, leave the fence closed.

Within that transaction, apply access removal to live metadata: clear a departing member's task lead before deleting that member's assignments; clear phase leads and blocker responsibility; clear Manager/milestone responsibility where applicable; revoke the projected grant/profile state; and queue deduplicated notification/outbox references for newly unassigned work and other Owners. Preserve historical authorship, record versions, comments, and audit entries. Do not rewrite encrypted task bodies or invent signatures for them. The signed removal transition and deterministic cleanup rule authorize these live relationship changes; later task writes still require a fresh security head. Newly unassigned work can be derived from active tasks with no remaining assignments rather than adding a second assignment-state model.

## Commit ordering and concurrency

1. A recently authenticated approved Owner starts a stable operation against the exact security head, ownership version, affected grant/role generations, scope epochs, and custody epoch. Check licence policy: invitations/promotions/expanded access require active entitlement; revocation remains permitted when restricted.
2. The client prepares signed authority changes, encrypted labels/profile data where needed, and exact recipient/keyring manifests. Enrolment requires OPAQUE new-password proof, local encrypted device-bundle read-back, trusted full-transcript comparison, and recipient/Owner confirmations. Owner enrolment/promotion additionally proves a distinct verified personal recovery kit and access to current custody. A promotion of an existing member retains the account and password unless a separate recovery operation is requested.
3. Stage immutable objects and verify their stored hashes/read-back. For removal or demotion, prepare the next custody epoch before an Owner loses custody; reseal its manifest for every remaining Owner's current recovery authenticator and eligible approved devices. Rotate every ordinary-content scope from which access is removed and prepare replacement envelopes for the remaining eligible people/devices. A demoted Owner retains only explicitly selected ordinary-member scopes. Never deliver the new custody key to that former Owner.
4. Acquire the existing application security fence and drain data operations. In the separate control transaction, lock the workspace row **FOR UPDATE first**; lock/recheck actor, target, operation, and relevant grants in stable ID order. Recheck recent actor authentication, active Owner status, exact signed head/versions/epochs, pending expiry/generation, all required immutable object digests, and current eligible recipient set.
5. For removal, suspension, demotion, or deletion of an Owner, count **fully active** remaining Owners after the proposed change while holding that workspace lock. A pending Owner does not count. Require at least one, increment ownership version, and commit new custody/content epochs, current keyring pointers, role/membership changes, revocation of affected sessions/devices/grants/recovery authenticators/temporary ceremonies, signed transition, and durable receipt in the same control transaction. Concurrent requests serialize and must recheck the actor: one Owner cannot finish removing the other after losing authority themselves.
6. Project the full committed snapshot and deterministic relationship cleanup, then open the fence only at that head. Lost responses resolve the same receipt. A failure before control commit leaves the existing authority intact; a failure afterward remains fenced/Finishing until idempotent projection succeeds. Do not promise one transaction across databases.

Simple device removal is distinct: revoke that device's grants/sessions and future signing authority, retaining the person's active workspace/project memberships and historical public keys. Replacement pairing/recovery then derives scopes from the surviving person grants. Revoking a person's project or workspace membership removes eligibility; recovery must not recreate it.

## Required changes to existing code

| Area | Required adaptation |
| --- | --- |
| Activation | Write initial scope heads/current custody pointer and signed builtin role definitions; make Owner grant personal. Keep genesis as the trust root and make any initial derived rows match it exactly. |
| Pairing | Derive eligible workspace/project scopes from personal membership/Owner/project grants, then intersect an approving same-account device's current scopes. Read explicit grant/key-scope epochs; never infer person membership from whichever device still exists. |
| Recovery | Derive ordinary workspace eligibility from membership and project eligibility from person grants. Replace device deliveries without revoking those person grants. Owner recovery changes personal recovery authority; it does not remove Owner status or alter unrelated people. Verify current custody/scope pointers and preserve historical keyring entries. |
| Sessions and delivery | An approved session still needs a current device grant plus active person/scope authority. Device grant existence cannot outlive person revocation. Restricted sessions never become content-ready through a membership row alone. |
| Signed history/client verifier | Add exact enrolment, promotion, role/access change, revocation, and rotation transition schemas. Derive personal memberships separately from device state. Verify recipient sets, permission snapshots, key/custody epochs, last-Owner result, and all mandatory object hashes. Unknown or incomplete transitions remain rejected. |
| Projection/policies | Synchronize roles, effective access, scope heads, and cleanup before fence opening. Keep explicit Owner project access; use the fixed policy catalogue for actions, with ownership administration reserved outside it. |

Implementation order: migrations and current-state projection contract; personal-scope adapters with last-device recovery regression; signed enrolment/promotion; roles and scoped grant changes; signed revocation/custody rotation plus cleanup; full CP06 permission matrix and concurrent last-Owner tests. Checkpoint 07/08 domain endpoints should consume the same policy/epoch contracts when introduced, rather than being implemented early solely for a policy test.

## Enrolment and promotion protocol

This eight-part proposal extends the plan above. Checkpoint 06 remains open: the first policy/projection slice has passed its 19 checks (12 permissions and 7 activation/projection), but this protocol is not yet an implemented or verified enrolment journey.

### 1. Boundary and reuse

Add `src/shared/enrolment.ts`, a headless controller/store/transport in `src/client/enrolment.ts`, and an identity `EnrolmentService`. Reuse OPAQUE worker calls, `IndexedDeviceStore`, signed-history paging and pins, `RecipientHeader`/`ContentEnvelope` v1, recovery-phrase helpers, and pairing's internal custody/content readers. Do not extend `RecoveryBinding`: replacing credentials and revoking devices are recovery semantics, not promotion semantics.

Use the explicit purposes `ukda.enrolment-transcript.v1`, `ukda.enrolment-confirmation.v1`, `ukda.profile-enrolment.v1`, and `ukda.owner-promotion.v1`.

### 2. Authority binding

The operation discriminant is `join_member`, `join_owner`, or `promote_owner`. Bind:

- Exact origin, workspace/account IDs, stable operation ID, `approvalAttemptId`, and `attemptGeneration`.
- JOIN invitation generation; pending-profile revision and profile-object reference; selected role ID/revision/permission snapshot; and exact intended personal project access.
- Current and resulting credential, session, recovery, and ownership generations; current/next security version, current security head, custody epoch, data generation, and genesis fingerprint.
- Approving Owner account/device identities, complete public keys, and credential/session generations; for promotion, the target's current approved devices.
- Exact current workspace/project scope epochs, source manifests, permissions, expiry, and the operation's issue/expiry times.

JOIN moves credential generation from 0 to 1, creates a new device with key generation 1, and starts session generation 1. Ordinary member recovery generation remains 0. Owner JOIN adds independent recovery generation 1 and advances ownership version.

Promotion preserves the current OPAQUE record, credential generation, and every healthy approved target device. It advances session, recovery, and ownership versions while retaining the current custody epoch. Every retained target device receives the required Owner custody and ordinary-project envelopes. No behaviour depends on who first activated the workspace.

### 3. Draft, approval, and receipt

The transcript binds the authority snapshot, joining/current target devices, optional new recovery public authority, local wrapper digest, JOIN-only OPAQUE configuration and registration-record hash, and JOIN setup-name ciphertext digest.

The draft adds the JOIN registration record (otherwise null), a nullable target confirmation until explicit full-fingerprint verification, and a mandatory new-recovery confirmation for Owner flows. The target signs with the new joining device or existing promotion device. The new phrase's signing key signs only its recovery-kit confirmation. The approving current Owner signs the final transition and each recipient envelope.

Approval contains the immutable signed transition, exact recipient deliveries, and the JOIN final encrypted-profile envelope. Promotion does not rewrite the profile or password. The transition binds every ciphertext ID, revision, and digest; the resulting scopes/role; and the preserved-device set. The receipt binds stable operation and approval attempt, target, resulting generations/head, request hash, and local wrapper hash. The server combines the staged OPAQUE record internally; the approving Owner does not receive it.

### 4. Private name handling without a hash cycle

At invitation creation, the Owner encrypts the pending name under the current workspace content key. The joining person confirms or edits their name locally.

Persist only a local name wrapper encrypted with a fresh XChaCha nonce and a purpose-separated key derived from the OPAQUE export key: `ukda.setup-name-wrap.v1`, bound to workspace/account/operation. Versioned authenticated context includes origin and credential generation. Never persist the export key.

For the current approval attempt, the joining device seals `{version:1, mode:'setup_name', profileId, displayName}` to the approving Owner's X25519 key and signs it. A separately purposed `labelContextDigest` covers the binding, target/recovery identity, OPAQUE configuration, registration-record digest, and device-wrapper digest. This digest enters the name packet's authenticated header. The final transcript then includes the resulting packet digest; the name packet does not depend on the final transcript digest, avoiding a circular hash.

The Owner validates context and signed history, opens the proposal, and encrypts canonical `{displayName}` as an ordinary signed profile `ContentEnvelope` under the current workspace key. The final transition binds the profile ID, revision, and ciphertext digest. The server protocol and logs receive no plaintext name. Promotion preserves the existing encrypted label and has no setup-name packet.

### 5. JOIN sequence

1. A recently authenticated approved Owner issues or replaces one named pending-profile invitation with exact selected role/scopes. JOIN has twelve random readable symbols (60 bits), expires one hour from issue including the approval steps, stores a keyed verification digest, and permits one successful redemption. Replacement/revocation cancels the previous incomplete setup.
2. Before redemption, the recipient persists a random private resume capability. `begin(workspace, code, resumeToken)` resolves one pending profile; the same holder may retry a lost response. The Owner receives the public operation reference, never the private resume token.
3. Owner claim freezes the current binding and approval attempt. The recipient registers OPAQUE, generates a local device and, for an Owner, an independent phrase, confirms saved words, and stages the encrypted device bundle/name wrapper. Verify IndexedDB read-back before publishing the draft and prove the staged password through real OPAQUE.
4. Both parties compare the complete final transcript SHA256 fingerprint/QR through a trusted channel and sign. The target pins the verified genesis and head. The Owner reads current custody/key material, seals exact selected-scope deliveries plus Owner recovery custody where required, encrypts the final profile name, and persists the exact approval before staging it.
5. The server validates and reads back all ciphertext. The fenced final transaction rechecks current Owner authority, profile/invitation/attempt generations, expiry, role/scope permissions, security/ownership/custody heads, and the target proof. Activate the profile, credential, personal/device/project grants, optional Owner/recovery authority, immutable transition/receipt, and consumed invitation together.
6. Projection finishes before ordinary access. The recipient then completes normal password login, device proof, current signed-history verification, and delivery decryption. A new Owner must also decrypt the actual new phrase custody envelope before reporting content-ready.

### 6. Promotion sequence

A current Owner starts promotion of an existing active non-Owner. The target claims it through a recently authenticated approved personal session and confirms their existing password through reauthentication. There is no JOIN key or replacement OPAQUE record.

The target keeps the current device and private bundle, verifies local read-back, creates and verifies an independent phrase, and confirms the complete transcript. The Owner signs custody/project deliveries to every retained approved target device and the recovery recipient.

Commit Owner readiness/authority and grants together. Incrementing session generation revokes old sessions; the same password and current device work on the following login. Do not change credential generation, replace the active device wrapper under a new operation, or revoke healthy devices accidentally. Until this commit, the pending promotion retains ordinary membership only.

### 7. Interrupted work and approval takeover

Persist only public signed data, ciphertext, and the random capability, with monotonic trust pins and compare-and-swap local revisions. Logout clears usable worker state. Forget removes the matching encrypted drafts and invalidates late callbacks. Missing pre-commit device material cancels the operation; a lost committed response resumes its matching durable receipt and cannot create a duplicate Owner.

Another active Owner may take over unfinished JOIN after verifying the person, including after approval ciphertext has been staged. Increment `attemptGeneration`, allocate a new `approvalAttemptId`, and retire the previous staged attempt. Clear target, Owner, and new-phrase confirmations and password-proof freshness, but retain the target device, OPAQUE registration draft, and local encrypted bundle. Re-seal the setup name to the new Owner, regenerate the complete transcript, and collect fresh confirmations; the person may need to re-enter the saved phrase.

Store each immutable approval grant under its **approval attempt ID**, not the stable operation ID. The final durable receipt remains keyed by the stable operation ID. Old-attempt finalization and takeover serialize under the same workspace/ceremony locks and fence; only one may win. Never overwrite an immutable staged object or extend the original invitation expiry.

Changed role/scope/head/custody state requires a fresh binding and approval. Licence restriction or pending deletion blocks uncommitted enrolment/promotion, while a previously committed receipt, login, and eligible delivery remain resumable.

### 8. Minimal integration work

Signed history must distinguish personal membership/project rights from device deliveries and verify new-profile creation or promotion against the preceding trusted state. Projection must install selected roles, explicit project access, and the encrypted profile envelope before reopening the fence.

Promotion needs a small worker/local-store bridge to verify the existing active wrapper again after reauthentication without persisting the export key. Use an ephemeral export-key callback or retain the verified wrapper digest in the worker at unlock and compare the exact IndexedDB read-back.

This implementation adds no email, external connectors, UI screens, or early checkpoint 07/08 endpoint work. Those later endpoints will consume the same committed access and policy contracts.

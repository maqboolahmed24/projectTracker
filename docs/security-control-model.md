# Security control model

Checkpoint 2 supplies structural tables, tenant isolation, and persistence constraints. It does not implement login, licence redemption, signature verification, key sharing, or recovery. Those remain the subsequent ordered checkpoints. The initial migration is [001_security.sql](../migrations/control/001_security.sql), in the **security control database**, using schema `security`.

## Store and runtime boundary

The control database is authoritative for identities, credentials, public authorisations, security generations, licence consumption, signed transitions, and security receipts. The application database holds business records and a security projection. There are no foreign keys across databases and no claim of a cross-store transaction.

The request-serving database role must not own tables, be a superuser, or have `BYPASSRLS`. All tenant tables have `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`; both reads and writes require their `workspace_id` to equal the transaction-local `ukda.workspace_id` setting. Missing or empty context denies access. Invalid UUID context fails instead of widening access. The backend derives context from a validated operation or account session, never an unchecked client header. Connection pools must use `SET LOCAL` inside an explicit transaction; session-persistent tenant settings are forbidden.

`licences` and `activation_attempts` are global **service-only** tables. Their lookup happens before a tenant account exists, so they deliberately have no tenant RLS policy. The restricted backend role may access them; end users have neither database credentials nor a generic table API. Checkpoint 3 must require the correct licence/resume verifier, attempt identity, expiry, and reservation generation before revealing state or committing an activation. All application routes remain separate from these backend privileges. Narrow database functions may be added later if useful; they are not a prerequisite of this schema.

## Workspace guard contract

| Column | Type/default | Meaning |
| --- | --- | --- |
| `workspace_id` | UUID primary key | Immutable tenant identity. |
| `licence_id` | UUID, unique FK | One entitlement binding per workspace. |
| `security_head` | Lowercase 64-character hex, initially all zeroes | Current authoritative transition hash. |
| `security_version` | BIGINT, initially 0 | Current transition sequence. |
| `data_generation` | BIGINT, initially 1 | Content-restore generation; stale requests do not replay across it. |
| `ownership_version` | BIGINT, initially 0 | Concurrent Owner-change fence. |
| `custody_epoch` | BIGINT, initially 0 | Current shared Owner recovery custody epoch. |
| `lifecycle` | `pending_activation` initially | Then `active`, `pending_deletion`, or `deleted`. Pending activation grants no access. |
| `licence_state` | `active` initially | `active`, `restricted`, or `revoked`; distinct from entitlement reservation state. |
| `content_maintenance` | BOOLEAN false | Ordinary content-write pause. |
| `restore_quarantine` | BOOLEAN false | Ordinary data-access quarantine. |
| `write_schema` | Positive INT, initially 1 | Required write schema. |

The additional fields are genesis-object reference and activation/deletion/creation timestamps. A pending workspace row permits tenant-scoped cryptographic object staging before activation; it is not an activated workspace or a consumed licence. Deleting abandoned drafts never reuses an activated workspace identity or a consumed entitlement.

The application projection is fenced before authority changes. Protected reads/writes hold the application shared workspace lock, check the authoritative control head and current permissions, and reject a mismatch. The mutation path exclusively fences/drains application access, commits the signed transition and control state/receipt together, then idempotently projects that head. A projection failure leaves the fence closed. The approved restore-verification route is the narrowly scoped exception already specified in the architecture.

## Table contract

| Table | Primary key | Essential content and constraints |
| --- | --- | --- |
| `licences` | `licence_id` | 32-byte keyed verifier plus key ID; state; reservation generation; immutable consumed workspace/time. No plaintext licence. Unique verifier and consumed workspace binding. |
| `activation_attempts` | `activation_id` | Unique operation ID, licence FK, intended workspace UUID, reservation generation, resume verifier, expiry, versioned public staging state, request hash, completion receipt. One reserved attempt per licence. |
| `workspaces` | `workspace_id` | Authoritative guard contract above; current identity/head/counters cannot regress. |
| `staged_objects` | `(workspace_id, object_id)` | Immutable versioned encrypted/signed JSON object, kind, canonical hash, staging operation, lifecycle, optional expiry and committing transition. Genesis, encrypted profile, key-envelope, custody-manifest, and signed-grant objects. |
| `profiles` | `(workspace_id, profile_id)` | Pending/active/suspended/removed state; Owner flag/readiness timestamp; encrypted-profile object; current OPAQUE record/config/setup/identifiers; credential/session/invitation/reset/recovery generations. No plaintext display name or password. |
| `devices` | `(workspace_id, device_id)` | Profile FK; immutable public Ed25519/X25519 keys and key generation; pending/active/revoked state and approval transition/time. Public history remains; private bundles never enter this table. |
| `recovery_authorities` | `(workspace_id, profile_id, generation)` | Public proof/recipient keys, verified-kit time, custody-envelope reference, epoch and revocation state. At most one active generation per profile. |
| `grants` | `(workspace_id, grant_id)` | Target profile/device, kind, workspace/project scope, generation, fixed-catalogue permissions, signed-grant and key-manifest references, active/revoked state and transition version. |
| `ceremonies` | `(workspace_id, ceremony_id)` | Invitation/reset/pairing/promotion/login/recovery/password-change/challenge type; target and approving identities; expected generations/head/epoch; token verifier when applicable; transcript hash; expiry; public state and optional encrypted server protocol state. |
| `sessions` | `(workspace_id, session_id)` | Token and CSRF digests, target profile/device, restricted access level, credential/session/data generation snapshots, authentication and idle/absolute expiry times. No bearer token. |
| `security_transitions` | `(workspace_id, sequence)` | Unique operation ID/hash, previous head, action, opaque actor references, versioned signed transition. Append-only updates are rejected. |
| `operation_receipts` | `(workspace_id, operation_id)` | Immutable exact-request hash, operation kind, committing security version, safe structured result. Links to both the transition sequence and operation ID. |
| `deletion_tombstones` | `(workspace_id, entity_kind, entity_id)` | Permanent opaque workspace/profile retirement marker, deletion time and security version. No content, display label, secret, or workspace FK. Updates/deletes are rejected. |

Every tenant relationship uses composite workspace-aware foreign keys. A session, grant, or ceremony referencing a device also references its profile, preventing a same-workspace device from being attributed to another account. Historical transition actors deliberately remain opaque references rather than foreign keys that would block profile-data erasure; the signed history must retain the public authorisation needed for verification.

`licences.activated_workspace_id` and `activation_attempts.workspace_id` deliberately are not workspace foreign keys. The first is an irreversible consumed-entitlement marker that must survive workspace purge; the second can exist before a tenant draft and is deleted during the defined retention procedure. An active workspace has its normal FK to the licence.

Project scope IDs in control grants refer to the same opaque project identity used by the application database. Their tenant/existence consistency is checked by the fenced operation and projection contract, not an impossible cross-database foreign key. Checkpoint 6 can add role templates/versioned definitions; the initial grants already constrain effective permission names to the fixed catalogue.

## Sensitive data and versioned objects

The following never belong in any server table: plaintext passwords, Owner phrases/entropy, OPAQUE client export keys, client ephemeral private state, device private bundles, plaintext project keys, and decrypted project content. Local wrapping and recovery derivation remain client responsibilities.

An OPAQUE registration record is permitted sensitive authentication material, not a conventional password hash or a plaintext password. It remains in the security store with the matching server setup/configuration IDs and bound public identifiers. `serverSetup` itself stays in the server operational secrets manager. A server-side ephemeral OPAQUE login state may be stored only in `server_state_ciphertext`, protected with a separately versioned operational key and strict short expiry. It must not be placed in `public_state` or returned to the client.

JSONB is used for explicitly versioned public, signed, and encrypted structures. Checkpoint 5 validates exact schemas, canonical bytes/hashes, signatures, algorithm identifiers, recipient/scope context, nonce rules, and crypto generations before inserting objects. Reject duplicate JSON properties at the API boundary before PostgreSQL JSONB discards them. A JSON object constraint alone does not establish encryption or signature validity.

Object content/hash/identity cannot be rewritten after staging. A committed object cannot return to staged state. Rewrapping creates a new object and atomically changes the authorised reference; retained ciphertext and public history keep their earlier references. Stale/expired uncommitted staging cleanup and controlled deletion/purge are implemented at their respective checkpoints.

## What SQL enforces now

- Tenant RLS and compound tenant/device/profile foreign keys.
- UUID identity, supported state values, positive/monotone generation counters, hash/key/digest shape, and basic timestamp ordering.
- One reserved licence attempt, one live invitation/reset per target, and one active Owner recovery generation.
- Irreversible consumed-licence identity and retired workspace/profile markers.
- Immutable transition/receipt updates, object payloads, device keys, and recovery public-key generations.
- Only fixed-catalogue project permissions; Owner authority is not a custom permission string.

Partial unique indexes deliberately do not use the current time. Expiry must be checked at every operation and the prior row marked expired/cancelled before replacing it in the same transaction. No scheduled cleanup job is relied upon to prevent an expired key from working.

## Enforcement added in subsequent checkpoints

| Checkpoint | Work on this foundation |
| --- | --- |
| 3 | Licence/resume digest verification, 60-minute reservation and 24-hour completed-resume limits, atomic activation payload validation and generation/head commit. |
| 4 | OPAQUE route flow, confidential ephemeral state, device challenge proof, session rotation/expiry/revocation, constant-scope identity lookup and throttles. Unknown-account dummy login must not create a real profile or valid session. |
| 5 | Canonical crypto formats/signature validation, custody manifest membership, complete staging receipts, current signer authority, recovery/key-rotation routines and historical decryptability. |
| 6 | Owner activation/readiness, per-workspace locked last-active-Owner invariant, role definitions and permission updates, scope removal, ownership concurrency. Profile removal is a soft retirement with credential/label erasure, preserving required public verification history. |
| 11 | Fence/projection reconciliation, exact-operation receipts, schema migration state and authority/version checks. |
| 12 | Independently durable control recovery, restore generation changes, deletion deadlines, protected purge and retained tombstones. Never purge required public or encrypted history while its workspace still retains that content. |

These semantic checks are not claimed to exist merely because a column or state value exists. In particular, SQL has no cryptographic verifier at this checkpoint and does not yet count fully active Owners. All production operations must go through the authorised backend transaction handlers; direct database privileges are not an end-user API.

## Checkpoint 2 acceptance suggestions

1. Apply migrations on empty control and application databases using the migration role; replay runner reports the migration already applied.
2. With the runtime role and no tenant setting, tenant reads return no rows and tenant inserts fail. Scope A cannot read/update scope B or use B's profile/object through an A foreign key.
3. Within one workspace, a session/grant/ceremony cannot name a device belonging to another profile.
4. Duplicate active reservations, live reset keys, or active recovery generations are rejected.
5. Partial OPAQUE configuration, invalid digest/public-key sizes, malformed heads, and invalid state/timestamp combinations fail.
6. Consumed licence bindings, committed encrypted payloads, retired device public keys, immutable receipts, and decreasing control generations cannot be rewritten.
7. Verify the runtime role has neither table ownership nor `BYPASSRLS`; verify no API exposes global entitlement tables before checkpoint 3's authorised handlers exist.

The root migration runner owns privilege grants and integration evidence. This migration intentionally creates no login endpoint, security-definer bypass, runtime secret, or placeholder decryption capability.

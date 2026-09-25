# Profile enrolment and Owner promotion

This document describes the implemented headless protocol. Checkpoint 6 remains in progress: role assignment/access mutation and Owner removal/rotation are separate, unfinished requirements. Custom role definitions are described in the [role protocol](roles-protocol.md). No frontend screens or email invitation system are included.

## Client entry points

`openClient()` exposes `enrolments` alongside authentication, pairing and recovery. The controller uses the authentication Worker, encrypted local device storage, an origin-bound enrolment store, and verified workspace history pins. Runtime shutdown/Forget clears associated local state.

- An unlocked, recently authenticated Owner calls `issueJoin({ accountId, operationId, kind, roleId, projectIds, displayName })`. Names are encrypted and signed inside the Worker. `kind` is `join_member` or `join_owner`; equal Owners receive all ordinary projects.
- The recipient calls `beginJoin({ workspaceId, code, genesisFingerprint })`. The trust fingerprint must come from the Owner through a trusted channel, or an existing local pin. The code alone is not a workspace trust root.
- An Owner calls `claim(publicReference)`. The recipient calls `prepare(localId, password, confirmation, displayName, ownerKit?)`, compares the full fingerprint and calls `confirmRecipient`. Additional Owners must verify a new personal recovery kit.
- The Owner independently compares the same fingerprint and calls `approve`. After `resume`, the recipient logs in using the saved device and calls `resume` again to verify/decrypt current delivery. Owner delivery also verifies the personal phrase. A successful HTTP commit alone is not content readiness.
- To promote an existing member, an Owner calls `beginPromotion`; the member calls `claimPromotion`, then the Owner claims the ceremony. `preparePromotion` uses fresh password authentication to read back the existing wrapper and verify a new Owner kit. Approval preserves the password record, encrypted profile and healthy device identities, while replacing grants and invalidating old sessions.

Progress exposes a stable local ID, public operation reference, state, device ID and full transcript fingerprint. Local operation records hold public protocol data, encrypted wrappers and random resume capabilities. They do not hold raw JOIN codes, names, passwords, export keys or recovery phrases. A verified decrypted name may be retained in the existing local remembered-profile card for one-field login.

## HTTP boundary

Routes are POSTs under `/v1/auth/enrolment/`. Strict JSON schemas reject unknown fields, query credentials and duplicate keys. Requests require the exact configured origin. Authenticated actions use the existing HttpOnly session cookie and CSRF header; target setup actions use a separately scoped random resume capability.

| Routes | Purpose |
| --- | --- |
| `join/context`, `join/history` | Authorized current context, encrypted key material and anchored history needed to encrypt an invitation locally |
| `join/issue`, `join/revoke`, `join/begin` | Issue/replace/revoke a one-profile invitation and redeem it for resumable setup |
| `promotion/begin`, `promotion/claim`, `promotion/stage` | Authorize and prepare password-preserving member promotion |
| `claim`, `inspect`, `status`, `cancel` | Approval ownership, bounded state reads, interrupted completion and cancellation |
| `registration`, `proof/start`, `proof/finish` | OPAQUE registration and possession proof for the exact JOIN draft |
| `unlock/start`, `unlock/finish` | Unlock an existing encrypted local draft after takeover without approving the replacement attempt |
| `confirm`, `materials`, `stage`, `finalize` | Fingerprint confirmations, authorized material, immutable approval staging and fenced commit |
| `history`, `delivery` | Anchored, reauthorized history and current authenticated recipient delivery |

JOIN uses twelve random symbols from a 32-symbol alphabet and expires one hour after issuance, including approval. Only keyed verification digests are stored. A code binds one pending profile and one resume holder. Replacement revokes the earlier incomplete operation. Request budgets cover source, workspace, code/operation and the resolved target account. Resume capability after a committed result lasts 24 hours; it cannot authenticate a normal application session.

## Authority and interruption rules

The encrypted pending profile contains the original signed invitation intent: target, operation, kind, full selected role, and selected projects (or all ordinary projects for an Owner). Before signing approval or preparing deliveries, the Worker verifies its exact ciphertext reference, decrypts it using the retained workspace epoch, verifies the original issuer against historical signed authority, and compares that intent with the claimed binding. A server substitution of another valid role is rejected.

The final transcript binds the current head, generations, custody/content epochs, current authorizer, immutable approval attempt, device/recovery public keys, profile and exact deliveries. Public keys reused from retained or retired history are rejected before key envelopes are prepared. Promotion excludes expired devices and preserves each remaining device's own generation.

Takeover creates a new approval-attempt ID and discards the old attempt's confirmations, proof freshness and approval hash. The stable operation, retained password registration and encrypted local device/name draft survive. The recipient unlocks the retained draft, reseals the name for the new Owner, verifies a new fingerprint and proves the new attempt. Delayed old-attempt messages cannot cancel or reactivate the replacement attempt.

Finalization closes the application fence, locks and rechecks current control authority, commits the signed transition/grants/profile/recovery authority/receipt, and projects the resulting snapshot before reopening access. A failure before commit retains pending authority; a lost reply after commit resolves the same durable receipt. Projection failure reports Finishing and remains recoverable through status/background projection. Retries do not create another account or grant.

Delivery rechecks current personal and device scope, expiry and epochs. Multi-device promotion delivers only the requesting device's envelopes plus that account's recovery envelope. Revoked rights cannot be recreated from an old receipt. New enrolment/promotion requires active entitlement; receipt recovery and existing authorized delivery remain available under restriction.

Verification results and outstanding checkpoint requirements are tracked in [checkpoint 6 evidence](checkpoint-06-evidence.md).

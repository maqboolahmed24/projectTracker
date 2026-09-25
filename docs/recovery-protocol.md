# Account recovery

This document describes the implemented recovery API and headless browser library. It covers an Owner's recovery phrase and Owner-assisted password reset for an existing member or Owner. It does not supply frontend screens or create a new profile. Check [implementation evidence](implementation-evidence.md#05-encryption-key-management-password-recovery-and-security-records) for acceptance status; the protocol description is not a production-readiness claim.

## Browser setup and trust

Use `openClient` as described in [authentication](authentication-protocol.md#setup-and-browser-entry). It creates `client.recoveries`, its IndexedDB store and its logout/Forget hooks alongside authentication, pairing and password change. The same-origin module worker performs recovery cryptography. Ship `trustedServiceKeys` independently through reviewed deployment configuration; a public key received inside an untrusted security transition cannot become its own trust anchor.

An Owner's saved recovery kit contains the 24-word phrase plus the application's exact origin, workspace ID, account ID and genesis fingerprint. The phrase has independent 256-bit random entropy; it is not derived from the password or a wallet seed. Separate, context-bound proof and recipient keys are derived locally. Ordinary members have no personal recovery phrase or Owner custody grant.

Recovery verifies signed history against the saved kit or an independent existing workspace pin. Owner approvers require an existing pin. A fresh reset recipient pins the history only after confirming the full transcript fingerprint through the trusted Owner channel. Recovery retains retired public verification keys for old ciphertext and signed history; their presence does not restore current signing or recovery authority.

The full fingerprint is the 64-character hexadecimal transcript digest. It binds origin, workspace/genesis, current security head, target account and role, exact current and next generations, authorizer, replacement device/recovery keys, scope permissions and expiry, OPAQUE configuration/record hash and local-wrapper hash. Compare the complete value through an independently trusted channel. Do not substitute the short RESET key, a shortened display code, or an unchecked fingerprint copied from the same server. QR presentation is a frontend responsibility; it must not disclose the recipient's resume capability.

## Recover with the current Owner phrase

The consumer supplies the saved kit identity and asks for the phrase only when needed:

```js
import { openClient, recovery } from '/client.js';

const client = await openClient({ trustedServiceKeys });
const started = await client.recoveries.beginPhrase(savedKitIdentity);
const localId = started.localId;
await client.recoveries.provePhrase(localId, oldPhrase);

const newPhrase = await recovery.newOwnerPhrase();
const positions = await recovery.recoveryChallenge(); // Three zero-based positions.
// Display/save the new kit, then collect the user's answers at those positions.
const prepared = await client.recoveries.prepare(
  localId, newPassword, passwordConfirmation,
  { phrase: newPhrase, positions, answers: userEnteredAnswers },
);

await client.recoveries.confirmRecipient(localId, confirmedFullFingerprint);
await client.recoveries.approvePhrase(localId, confirmedFullFingerprint, oldPhrase);
```

The example's kit, inputs, trusted configuration and confirmation values come from the consumer's interface. `prepared.fingerprint` is the complete fingerprint to display and verify in the saved-kit context. Do not generate the answers automatically from the phrase in a production interface. Store the replacement phrase with the same origin/workspace/account/genesis identity; the library does not persist or later redisplay it.

The initial phrase challenge lasts two minutes. The worker matches the saved kit, derives the current phrase keys, signs the exact challenge and verifies current signed history. The new password then completes OPAQUE registration and proof. The worker generates fresh replacement device keys, verifies three words from the new Owner phrase, and prepares a locally encrypted wrapper. The controller saves, reads back and unwraps that exact wrapper before it can authorize commit.

For phrase recovery, the replacement device signs the new encrypted recipient envelopes, while the **current** recovery proof key signs the complete authorization transition. A phrase key is never treated as an approved device signer. Both the replacement device and new recovery key must prove possession. The server receives public proofs, an OPAQUE record and encrypted envelopes, not either phrase, the password, export key or device private bundle.

## Owner-assisted reset

A current Owner uses an approved, unlocked device with password authentication within five minutes. The target must be an existing active profile. An equal Owner can help another Owner; reset never promotes an ordinary member.

1. The Owner calls `owner.recoveries.issueReset(targetAccountId)`. Show the returned `code` once and deliver it privately. It has the form `RESET-XXXX-XXXX-XXXX`: twelve readable base32 characters, 60 random bits, fifteen-minute expiry and one recipient. Issuing a replacement invalidates the previous reset generation. `revokeReset(workspaceId, resetId)` explicitly cancels a pending reset.
2. The recipient calls `recipient.recoveries.beginReset(workspaceId, code)`. No username or reset ID is required. The controller saves a random resume capability before the request; its returned `localId` identifies the local draft. The returned public `operation` contains only `workspaceId` and `operationId`; share this with the Owner. The server operation ID equals the issued reset ID.
3. The Owner calls `owner.recoveries.claim(operation)`. Current Owner/device authority and history are checked before fixing the binding. The recipient calls `prepare(localId, newPassword, confirmation, newOwnerKit?)`. Supply a newly generated, word-confirmed kit only when recovering an Owner; omit it for a member.
4. Compare the full fingerprint through the trusted channel. The recipient calls `confirmRecipient(localId, fingerprint)`. The Owner calls `approve(operation, fingerprint)`, which independently verifies history and scopes, encrypts the authorized key material, signs the transition and persists the exact approval before sending it.
5. The recipient follows the postcommit steps below. A short key or successful password proof alone cannot fetch custody material or complete recovery without the current Owner's authorization.

Owner-side requests use the public operation reference plus the Owner session and CSRF token. They never require the recipient's resume token or private OPAQUE export key. The approving Owner device signs the new envelopes and final transition; the recipient and new Owner recovery key, when applicable, sign their own possession confirmations.

Claiming with another eligible Owner invalidates the previous unfinished binding, proof and confirmations. Before a signed approval is staged, the recipient can prepare again against the new binding; the controller discards only the stale uncommitted candidate. Once approval is staged, start a replacement reset instead of changing the immutable operation. Revocation, loss of approval authority or changes to the bound security head prevent a stale commit. None of these precommit events changes the target's working password.

## Commit, sign in and verify the replacement kit

The server reads back the staged signed encrypted objects, fences and drains application writes, then commits credentials, authority and a receipt atomically in the security-control database. Recovery increments credential/session/device generations, revokes the target's old devices and sessions, and invalidates old ceremonies. Owner recovery also rotates that Owner's personal phrase authority. Existing ownership and current eligible scope permissions/expiry are preserved. Archived or historical ciphertext keeps the key epochs needed for authorized decryption; revoked projects do not return through reset.

The receipt is stable across retries. Application projection is repaired idempotently by the worker or a status retry; a committed operation can report `finishing` while this work remains. Recovery does not remove licence restrictions, content maintenance or restore quarantine.

```js
let progress = await client.recoveries.resume(localId);
if (progress.access === 'login_required') {
  const reference = {
    workspaceId: progress.operation.workspaceId,
    accountId: targetAccountId,
    deviceId: progress.deviceId,
  };
  await client.auth.login(reference, newPassword);
  progress = await client.recoveries.resume(localId, newPhrase); // Omit phrase for a member.
  if (progress.access === 'content_ready') {
    await client.remembered.remember({ ...reference, displayName: userEnteredName });
  }
}
```

Do not show content merely because an HTTP commit succeeded. `resume` first matches the signed receipt to the saved draft and promotes only its exact encrypted wrapper. Ordinary OPAQUE login and a fresh device proof are then required. Delivery checks the current signed history, active recipient device, exact scopes and every expected encrypted object. For an Owner, `resume(localId, newPhrase)` additionally derives the **new** phrase keys and decrypts the newly committed recovery custody envelope. A missing phrase returns `recovery_kit_required`; incomplete key material returns `incomplete_keys`. Only `content_ready` confirms these checks. The old phrase cannot satisfy the new-kit readback.

Remembered display names are not saved automatically by recovery or login. Save the chosen name explicitly as above. A UI must keep its own input and rendered-plaintext cleanup registered with `auth.onClear`.

## Interrupted work, logout and Forget

Discover saved operations with `await client.recoveries.operations.list()`. Keep the original `localId`; a reset's local ID can differ from its server operation ID. Pending drafts contain public protocol material, the bounded resume capability and encrypted local wrappers/approvals, but no phrase, password or plaintext private bundle.

| Interruption or action | Behaviour |
| --- | --- |
| Reset redemption response lost | Retry `beginReset` with the same code and `localId`; the saved capability selects the same recipient. A different capability cannot take over. |
| Reload after draft preparation | Resume the saved operation. `prepare` or `confirmRecipient` can take the new password again to refresh OPAQUE proof and unwrap the existing candidate. A phrase approval can also take that password as its fourth argument. |
| Stage or final response lost | `approve`/`approvePhrase` checks status and reuses the exact saved signed encrypted approval. `resume` accepts the one matching receipt; do not generate another device for an ambiguous operation. |
| Confirmed precommit cancellation/expiry | `cancel(localId)` verifies authoritative state before removing the uncommitted wrapper and draft. Metadata-only capability lookup permits cancellation even if the encrypted draft is corrupt. A committed receipt is retained and resumed. |
| Commit or projection uncertain | Retain the draft. `finishing`, timeout or resume-capability expiry is not evidence of rollback. The precommit capability expires with the fifteen-minute ceremony; successful commit renews it for twenty-four hours. |
| Logout/close | Clears ephemeral export keys and worker secrets, aborts work, and prevents late responses from restoring access. Encrypted drafts remain available for retry. |
| Forget a device | Drains tracked recovery work and deletes matching draft copies by origin/workspace/account/device metadata, including corrupt encrypted copies. Runtime hooks also remove that device's active/pending wrappers and remembered card. Unrelated drafts and public workspace pins remain. |

An unredeemed local draft has no device identity yet, so device Forget does not match it. A known pending server operation can be cancelled explicitly. Losing the only pending wrapper after commit is not repaired by a receipt or support-issued key; use another current authorized recovery method. Explicit Forget is local erasure, not server account deletion or device revocation.

## HTTP contracts and limits

All routes are `POST /v1/auth/recovery/<path>` with strict JSON, exact configured `Origin`, no query parameters and no cacheable responses. Unknown/private fields and duplicate JSON keys are rejected. Owner operations and current-history reads require the session cookie and `X-CSRF-Token`. Delivery requires the current approved replacement-device cookie and exact Origin; its read route does not enforce CSRF, although the browser transport sends it. Explicit recipient-capability requests remain usable when the browser also carries a cookie revoked by the recovery commit. No recovery endpoint returns a session cookie; sign in normally after commit.

| Paths | Authority and purpose |
| --- | --- |
| `reset/issue`, `reset/revoke` | Recent approved Owner; issue/replace or revoke the target's short code. |
| `reset/begin`, `phrase/begin`, `phrase/prove` | Redeem the code with a saved capability, or prove the current Owner phrase against a bound challenge. |
| `claim` | Public operation reference and recent approved Owner. |
| `registration`, `proof/start`, `proof/finish` | Recipient capability; stage/prove the replacement OPAQUE record. |
| `inspect`, `confirm`, `materials`, `stage`, `finalize`, `status` | Explicit recipient capability or public reference plus authorized Owner, with action-specific proof and current-authority checks. A reset recipient's capability does not authorize custody material. |
| `cancel` | Recipient capability; cancel an uncommitted operation. |
| `history` | Anchored, bounded transcript history under the operation authority; current-history mode requires a current session and CSRF even if a capability is supplied. |
| `delivery` | Operation ID plus the current approved replacement-device session and exact Origin. |

`src/shared/recovery.ts` defines versioned strict payloads; `HttpRecoveryTransport` and `RecoveryController` implement them. Phrase and replacement-password proof attempts last two minutes. Password proof must remain fresh within five minutes at approval/commit. At most five pending phrase attempts occupy a target's allowance; unproved two-minute-expired challenges stop occupying it.

Durable counters use separate ten-minute windows:

| Quota layer | Ordinary recovery | History paging |
| --- | --- | --- |
| Before target lookup | Source 120; supplied workspace 480; operation/code reference 120. Initial requests carrying an account ID also have an account limit of 15. | Source 1,200; supplied workspace 4,000; operation 1,000. |
| After server-side target lookup | Actual target account 120 and workspace 480, shared across operations and including delivery. | Actual target account 1,000 and workspace 4,000. |

The target identity comes from the server-resolved operation/session, not an account label supplied to evade limits. A resolved operation can consume its target quota before final capability verification. Separate counter transactions preserve rejected attempts; a small dedicated connection pool avoids waiting for a free authority-pool connection while a recovery transaction holds one. Persisted buckets contain keyed digests and bounded counters/timestamps, not source addresses, account labels, codes or capabilities. Operational failures return bounded generic errors without database details.

## Privacy and remaining boundaries

Provider storage holds ciphertext, public keys/signatures, opaque IDs and required authority/routing metadata, OPAQUE records, keyed capability/code verifiers and encrypted short-lived OPAQUE server state. The password-encrypted device wrapper stays in local IndexedDB; only its digest is sent. Short RESET codes authorize a bounded setup ceremony and never encrypt permanent keys. No provider or support replacement key can reconstruct customer private keys or a lost Owner phrase.

Logout and Forget cannot erase arbitrary copies made by the consuming UI, browser extensions or other same-origin code. JavaScript strings cannot be reliably zeroed. The hosted-client/device threat boundary remains as described in the architecture: a compromised device or maliciously replaced client can observe material while it is in use. Normal recovery does not implement backup restoration, workspace deletion, profile enrolment or Owner-removal lifecycle; those retain their separate acceptance requirements. There is no email recovery in this scope.

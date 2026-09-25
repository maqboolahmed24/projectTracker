# Authentication and device approval

This document describes the checkpoint 4 API and browser library. The presentation layer is not implemented. Consult [checkpoint 4 evidence](checkpoint-04-evidence.md) for executed checks and remaining acceptance gates; implementation alone is not a production-readiness claim.

## Setup and browser entry

Follow the [README](../README.md) to start both PostgreSQL stores, apply migrations, provision identity once, and run the API and hosted worker. Preserve `.env.identity` across restarts: its OPAQUE setup and service verification key are operational secrets, not customer content keys. See [identity operations](identity-operations.md) for provisioning and licence commands.

Run `npm run build:browser`. Serve the complete `dist/browser/` output, including its module chunks and `auth-worker.js`, from the same HTTPS origin as the API. The API does not serve a product frontend. Set `APP_ORIGIN` to this exact origin; only exact loopback hosts permit HTTP during development. A client requires a same-origin module Worker, WebAssembly, WebCrypto and IndexedDB. Initialization fails if these are unavailable; there is no weaker login fallback.

Use the composition helper instead of constructing independent controllers without their cleanup hooks:

```js
import { openClient } from '/client.js'; // URL where dist/browser/client.js is served

const client = await openClient({
  // Trusted public configuration shipped with the reviewed client deployment.
  trustedServiceKeys: deploymentPublicConfig.entitlementSigningKeys,
});

const detachApplicationCleanup = client.auth.onClear(() => {
  plaintextRecords.clear();
  clearPasswordInputs();
  cancelApplicationRequests();
});
```

The named application callbacks/configuration in this example are supplied by the presentation layer. Cleanup callbacks must be synchronous and idempotent. Their exceptions are reported after the other cleanup handlers run. Do not save passwords, phrases, OPAQUE export keys, decrypted records or private device keys in browser storage. Ordinary login, device proof, pairing cryptography and password-change key handling use the dedicated worker; terminating it also stops in-flight cryptographic work.

`trustedServiceKeys` maps an operational signing key ID to its base64url public key. A trusted deployment process obtains this public value from `EntitlementOperations.publicSigningKey()` and uses the corresponding `ServiceSecrets.keyId`. Ship it through reviewed deployment configuration, independently of the history being verified. Never copy a purported trust key from a received transition. This configuration is needed when history contains real entitlement changes, including pairing while a licence is restricted. It contains no operational private key.

## Remembered name and password login

A sign-in reference contains opaque `workspaceId` and `accountId` values; a remembered device also has `deviceId`. It is not a credential. The selected reference determines which OPAQUE record is used. The service does not search accounts using the entered password or a display name, and temporary enrolment/reset keys do not enter this login endpoint.

After activation, take these three IDs from its verified receipt. Activation creates no session. `openClient` seeds the verified genesis pin through its activation callback, but neither activation nor ordinary login automatically saves the user's display name. The consumer must do so explicitly:

```js
const reference = {
  workspaceId: activationReceipt.workspaceId,
  accountId: activationReceipt.accountId,
  deviceId: activationReceipt.deviceId,
};

const state = await client.auth.login(reference, enteredPassword);
if (state.localAccess === 'unlocked') {
  await client.remembered.remember({ ...reference, displayName: userEnteredName });
}

// After logout/restart, display the chosen local card's name and one password field.
const cards = await client.remembered.list();
// Pass only the three IDs from the selected card to auth.login, not the entire card.
```

The local card contains the origin, opaque reference and display name, with no password or bearer token. Treat its name as visible local-device metadata. The consumer renders it as text and offers explicit Forget. The client password policy requires 15–1,024 Unicode code points, preserves the entered value without trimming or normalizing, and checks a small pinned local common-password list. The list is not a comprehensive breach feed. A future interface must allow paste and password managers; there is no password-input widget in this library.

OPAQUE success first produces a **restricted** session. A returning device must additionally unwrap the exact current credential-generation candidate and sign a fresh two-minute device challenge. Only an active device with current grants can receive an approved session. A missing local wrapper leaves `localAccess: 'pairing_required'`; password possession cannot substitute for device approval. An existing server cookie after reload does not reconstruct local keys: `auth.refresh()` checks public session state, while ordinary password login unlocks the device.

The cookie is `__Host-ukda_session`, Secure, HttpOnly, SameSite=Lax, Path `/`, with no Domain. Sessions expire after 30 minutes idle or 12 hours absolute. Password login, device elevation and reauthentication rotate the cookie. `auth.reauthenticate(password)` requires the current approved device, refreshes recent-password authority, and preserves the absolute deadline. Privileged actions require password authentication within five minutes. Every protected lookup checks current account/device/grant and credential/session/data generations.

## HTTP boundary

All operations below are `POST` with strict JSON, no query parameters and the exact configured `Origin`. Browser transports use same-origin requests, disallow redirects and disable caching. Session-changing authenticated requests carry `X-CSRF-Token`; cookies are set only in HTTP headers and are omitted from JSON results. Login failures for nonexistent, inactive and incorrect accounts remain generic. Two-minute OPAQUE proof attempts are single-use, including failed finishes, and shared source/account/workspace budgets limit requests.

| Path under `/v1/auth/` | Purpose |
| --- | --- |
| `login/start`, `login/finish` | Opaque account reference and OPAQUE packets; issue a restricted session. |
| `session` | Read current public authority and session state. |
| `device-challenge/start`, `device-challenge/finish` | Prove a current local device and rotate into an approved session. |
| `reauth/start`, `reauth/finish` | Fresh OPAQUE proof bound to the existing approved session. |
| `logout` | Revoke the session and its pending device challenges; expire the cookie. |
| `pairing/begin`, `inspect`, `claim`, `confirm`, `history`, `materials`, `stage`, `commit`, `delivery` | Establish, verify and complete approval of another device. |
| `password-change/begin`, `registration`, `proof/start`, `proof/finish`, `finalize`, `status`, `cancel` | Replace the password using a staged local wrapper and durable receipt. |

Owner phrase recovery and Owner-assisted short RESET keys have a separate [recovery protocol](recovery-protocol.md), exposed through `openClient().recoveries`. Recovery commits revoke the target's sessions and require ordinary login, replacement-device proof and verified encrypted delivery before content is ready.

Use the exported transports and schemas for packet details. Plaintext passwords and private device wrappers are not request fields. Password-change `status` uses its operation-bound resume capability and reveals only bounded public state/receipt; it neither logs in nor releases keys. A repeated identical `finalize` can find the committed receipt before rejecting the old revoked session. A first commit still requires current approved/recent authentication and CSRF. Keep the same operation ID and capability after an uncertain response.

## Pair another device

The new browser first calls `auth.login({ workspaceId, accountId }, password)` and remains restricted. An already approved device of the same account, or an active Owner authorized to approve that existing account, completes the approval. This does not invite a new profile or expand existing access. A pending pairing expires after ten minutes.

The controller sequence uses the same operation ID on both devices:

1. Recipient calls `pairing.begin()` and retains the returned operation ID. It generates, stages, reads back and locally verifies an encrypted candidate before starting the server ceremony.
2. Approver calls `pairing.claim(operationId)`. The approver must already have an independent workspace genesis/highest-head pin. Initial activation seeds it automatically through `openClient`.
3. Compare the **full transcript fingerprint** through a trusted channel on both devices. Supply that exact value to `confirmRecipient(operationId, fullFingerprint)` and `confirmApprover(operationId, fullFingerprint)`. A shortened code or an unchecked value fetched from the same server is insufficient.
4. Approver calls `pairing.approve(operationId)`. The controller saves the exact signed encrypted approval before staging it, so retries reuse the same object. It verifies the durable signed receipt and current history.
5. Recipient calls `pairing.resumeRecipient(operationId, userEnteredName)`. It verifies the receipt and history, promotes only its matching candidate, proves the device with a fresh challenge, then fetches and decrypts the scoped delivery. Only `state: 'content_ready'` means every expected delivery was verified. When a name is supplied, this path explicitly saves the remembered card.

The fingerprint binds origin, workspace, account, both device keys, current authority and scopes. The client replays signed genesis and supported security transitions, verifies signatures against authority derived from earlier records, and checks a monotone local pin. Unknown transitions, untrusted service signers, rollback, stale authority, altered manifests and expanded scopes fail closed. Workspace pins are public security metadata and survive device Forget.

After a reload, sign in again and discover saved operations with `client.pairing.store.list()`. Resume the original operation instead of generating new key material. `approve()` resolves an ambiguous commit; `resumeRecipient()` retries receipt promotion and delivery. Missing delivery remains explicitly incomplete, preserving the encrypted candidate for a retry. Authentication alone must not be displayed as complete pairing.

## Change a known password

Password change starts from an approved, unlocked device with recent authentication:

```js
await client.auth.reauthenticate(currentPassword);
const change = await client.passwordChanges.begin(reference.workspaceId);
const operationId = change.binding.operationId;
await client.passwordChanges.prepare(operationId, newPassword, confirmation);
await client.passwordChanges.complete(operationId, newPassword);

// Completion revokes every session, including this one.
const signedIn = await client.auth.login(reference, newPassword);
await client.passwordChanges.resume(operationId, signedIn.session);
```

The worker preserves the current device's signing and recipient keys, wraps them under the new OPAQUE export key, and signs the exact replacement binding. The client persists the encrypted draft before staging the candidate, reads it back and unwraps it before authorizing commit. The server verifies new-password proof and advances credential/session generations through a signed, fenced control transaction. Other devices and all sessions are revoked; the current signer and existing Owner recovery authority remain intact. Other devices must use the new password and pair again.

The ceremony lasts fifteen minutes; its proof lasts two minutes. The status capability initially lasts twenty-four hours from ceremony creation, renewed to twenty-four hours from successful commit. A committed password change may temporarily return `finishing` while its application projection is fenced; the worker or status retry repairs that projection. Neither projection delay nor a lost response means that the old password remains current.

| Interruption | Recovery |
| --- | --- |
| Before the encrypted draft persists | The old password/wrapper remains usable. Prepare again within the ceremony. |
| After draft save, before candidate staging | The saved exact draft can stage again; do not generate a different replacement for an ambiguous operation. |
| Before control commit | Authenticate with the old password and resume the same operation if still valid. |
| Commit response lost or browser restarted | Call `passwordChanges.resume(operationId)` for public status. If committed, log in with the new password; login selects the exact authenticated generation even if the active pointer is still old. Then call `resume(operationId, signedIn.session)` to promote that matching candidate. |
| Projection incomplete | Retain both wrappers; retry status until the committed projection is usable. |
| Confirmed precommit cancellation/expiry | `cancel(operationId)` discards only the uncommitted candidate after authoritative confirmation. It refuses a committed receipt. |

Keep the public operation ID for this recovery flow. It can also be rediscovered through the exported `IndexedPasswordChangeStore.list()` using the default store; close that extra handle after reading. A receipt alone does not unlock keys or justify speculative promotion after restart. Never discard both credential generations because a response was uncertain. Status-capability expiry is not evidence of rollback; use normal current-password login and retain recovery material.

## Logout, Forget and local state

```js
await client.auth.logout();          // Immediate local lock, then server revocation.
await client.auth.forget(reference); // Explicit local erasure for this one device.
await client.close();                // Logout and close worker/store handles.
detachApplicationCleanup();          // Detach the application cleanup callback.
```

These calls illustrate separate actions; a screen does not need to call all three on every logout. `close()` is idempotent. Await failures and communicate incomplete server revocation or local cleanup instead of displaying unconditional success.

| Local state | Logout | Forget this device |
| --- | --- | --- |
| Usable worker keys, ephemeral OPAQUE state and registered plaintext caches | Cleared; active authentication, pairing, password-change and recovery work is cancelled. | Cleared. |
| Remembered name/reference | Retained. | Exact selected card removed. |
| Active and pending encrypted device generations | Retained for later password login/recovery. | All matching generations removed. |
| Activation, pairing, password-change and recovery draft copies for that device | Retained as encrypted recovery material. | Matching copies removed through the runtime's registered hooks. |
| Workspace genesis/highest-head pins | Retained. | Retained; these public pins prevent rollback and contain no device secret. |

Logout clears local access before waiting on the network. It waits for tracked authentication responses and revokes the latest resulting cookie, preventing a late login response from restoring the browser session. Controller cancellation/epoch checks prevent late pairing or password-change responses from recreating forgotten state; activation additionally tracks forgotten device identities. Draft-store cleanup uses identity metadata rather than requiring intact ciphertext. The separate IndexedDB databases cannot participate in one atomic transaction: every registered Forget hook runs even if another fails, and repeated Forget can finish a partial cleanup. Forget is local erasure, not a server-side account or device-revocation command.

The presentation layer still owns its password input values, rendered plaintext, application request lifecycles and caches. Register them with `onClear`; the library cannot erase arbitrary external copies. JavaScript strings cannot be reliably zeroed, and compromised same-origin code or a maliciously replaced hosted client remains within the architecture's explicit threat limitations.

## Remaining boundaries

This checkpoint supplies authentication primitives and browser composition. The subsequent [recovery implementation](recovery-protocol.md) adds temporary reset-key and Owner phrase-recovery journeys. Frontend screens, member/Owner enrolment, complete application content caching and workspace deletion retain their separate acceptance requirements. Bundled Chromium/Firefox/WebKit checks do not establish the full current/previous branded Chrome, Edge, Firefox and Safari release matrix. Independent review of the composed protocol and implementation remains a release requirement; the selected upstream libraries do not certify this application.

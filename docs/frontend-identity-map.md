# Frontend identity integration map

Audited 27 September 2026 against the current controllers, shared contracts, protocol documents and real browser journeys. This is implementation guidance for the presentation layer. UI wording should use names such as “Set up your workspace”, “Recovery words”, “Approve this device”, “Security check” and “Continue setup”; the internal names below must not become customer-facing jargon.

## Runtime boundary

Use `openClient({ origin?: string, trustedServiceKeys?: Record<string, string> })` from the existing browser bundle. `ClientRuntime` exposes `auth`, `activation`, `passwordChanges`, `pairing`, `recoveries`, `enrolments`, `roles`, `accessChanges`, `profiles`, the work controllers, `remembered`, and `close()`.

The same-origin module Worker, WebAssembly, WebCrypto and IndexedDB are required. Serve the full browser build, including its Worker and chunks. Keep deployment-provided public service verification keys separate from untrusted history. Existing controllers own signing, verification, encrypted IndexedDB drafts, scoped cookies, CSRF and interruption handling; do not replace them with raw login fetches or client-invented credentials.

Register synchronous, idempotent `client.auth.onClear(() => ...)` cleanup for React/UI data, passwords, recovery phrases, clipboard previews, decrypted names and work content. Every render/loading continuation needs a generation or cancellation check so a late response cannot repopulate a signed-out interface. Theme and reduced-motion preferences may persist separately; secrets and decrypted application records must not enter localStorage/sessionStorage or analytics.

`client.close()` signs out and closes stores/Worker. Do not call it as a transient screen effect or on ordinary route changes. A single runtime should live for the app's lifetime. Full page reload leaves the browser locked: an existing cookie alone does not reconstruct in-memory keys.

## Core values and return shapes

```ts
type LoginReference = {
  workspaceId: string;
  accountId: string;
  deviceId?: string;
};
type RememberedReference = Required<LoginReference>;
type AuthState = {
  session: {
    sessionId: string; workspaceId: string; accountId: string;
    deviceId: string | null;
    accessLevel: 'restricted' | 'device_approved';
    credentialGeneration: string; sessionGeneration: string;
    dataGeneration: string; csrfToken: string;
    authenticatedAt: string; idleExpiresAt: string; absoluteExpiresAt: string;
  };
  localAccess: 'pairing_required' | 'unlocked';
};
type PublicOperation = { workspaceId: string; operationId: string };
type CeremonyProgress = {
  localId: string; operation: PublicOperation | null;
  state: string; fingerprint: string | null; deviceId: string | null;
};
type CeremonyResume = CeremonyProgress & {
  access: 'pending' | 'login_required' | 'recovery_kit_required'
    | 'content_ready' | 'incomplete_keys';
};
type OwnerKitInput = {
  phrase: string; positions: number[]; answers: string[];
};
```

Identifiers are opaque UUIDs, not labels. Account roles are not included in `AuthState`; get permissions/ownership from verified work/history context. Do not infer Owner authority from activation origin, a recovery phrase being present, an avatar, or a remembered card.

`CeremonyProgress` intentionally omits account ID and Owner/member kind. For an existing enrolment/recovery, read the matching local `operations.get('recipient', localId)` or `operations.list()` metadata to route the appropriate UI. Keep only the necessary metadata in UI state, not the full record's resume capability. Never render or share that capability.

## Entry and returning login

| Call | Result/use |
| --- | --- |
| `client.remembered.list()` | `{ version: 1, origin, workspaceId, accountId, deviceId, displayName }[]`; local cards only, not a server directory. |
| `client.auth.login(reference, password)` | `Promise<AuthState>`; pass only IDs, never the whole remembered card. |
| `client.auth.current()` | Current `AuthState | undefined`, synchronous. |
| `client.auth.refresh()` | Session fields plus `securityHead` and `securityVersion`; does not unlock a new runtime. |
| `client.auth.reauthenticate(password)` | Refreshes recent-password authority for an already approved, unlocked device. |
| `client.remembered.remember({workspaceId, accountId, deviceId, displayName})` | Saves one local name card. Does not save the avatar or a secret. |
| `client.auth.logout()` | Locks synchronously, then confirms server sign-out. A network failure is reported even though local plaintext is cleared. |
| `client.auth.forget({workspaceId, accountId, deviceId})` | Signs out and erases matching local device/card/pending data through runtime hooks. Does not remove the person or revoke a remote device. |

Entry should show remembered names with one password field, a “Use another profile” action, “Set up a workspace”, “Use an invitation” and “Recover access”. No email or username field is necessary. A fresh browser nevertheless needs a workspace/account reference delivered from an already trusted person/device or saved recovery kit. The backend cannot identify an account by trying the entered password. Provide a private sign-in handoff/QR containing the public reference; do not fake a name search.

On successful login:

1. `localAccess === 'unlocked'`: fetch `profiles.current()`, populate the app, and update the remembered display name using the authenticated profile.
2. `localAccess === 'pairing_required'`: show device approval, with a return-to-login option. Password possession alone cannot open project content.
3. A current cookie after reload can help select the matching remembered card, but the user must enter the password again to unlock. Never render protected screens simply from `refresh()`.

New passwords are 15–1,024 Unicode code points, checked by `password.validateNewPassword(value)`. Preserve the exact value: do not trim, normalize, prohibit paste, or disable password managers. Existing password login permits shorter historical passwords. Use separate `new-password` and `current-password` autocomplete as appropriate, password visibility toggles, inline confirmation errors and accessible length help. Never expose raw crypto errors or stack traces.

Sessions expire after 30 minutes idle and 12 hours absolute. Privileged actions require password authentication within five minutes; show one reauthentication sheet and retry the user's same action with its original operation identity.

## First Owner: licence to usable workspace

```ts
const operationId = await client.activation.create();
const reservation = await client.activation.reserve(operationId, licenceKey);
const phrase = await recovery.newOwnerPhrase();
const positions = await recovery.recoveryChallenge();
const kit = await client.activation.prepare(operationId, {
  password, confirmation, phrase,
  challengePositions: positions,
  challengeAnswers: userEnteredAnswers,
  displayName, workspaceName, avatar,
});
const result = await client.activation.activate(operationId, password);
```

`reserve` returns `{ activationId, operationId, workspaceId, accountId, reservationGeneration, draftGeneration, expiresAt, resumeExpiresAt, state, receipt?, configuration? }`. Its state is `reserved | completed | finishing_setup | expired | cancelled`. Licence reservation lasts 60 minutes.

`prepare` returns the downloadable recovery kit **only in memory**:

```ts
{
  version: 1, language: 'english', application: origin,
  workspaceId, accountId, genesisFingerprint, phrase
}
```

Display the 24 words, let the user save/print the full kit and independently type the three requested words. `recoveryChallenge()` returns zero-based positions; UI labels are positions plus one. Do not generate the answers from the phrase or mark the backup confirmed just because a download started. The full kit contains the account/workspace identity needed if all remembered cards are lost.

`activate` returns `{ state: 'completed' | 'finishing_setup', receipt }`; the verified receipt contains `{ workspaceId, accountId, deviceId, credentialGeneration: '1', operationId, dataGeneration: '1', securityVersion: '1', securityHead, genesisFingerprint, completedAt }`. Setup creates **no session**. After a completed result, call `auth.login` with receipt IDs and then `remembered.remember` with the entered name. The runtime seeds the workspace trust pin automatically after receipt verification.

Keep a “Finishing setup” state while projection completes; expose “Check again” and return later. Retry the saved operation with `activation.resume(operationId, password?)`, whose extra states are `password_required | prepare_required | reserve_required | expired | cancelled`. Do not redeem the licence again after an uncertain final response. `replaceDraft(operationId)` is the explicit action for changing an uncommitted prepared signup; it requires a new phrase/word confirmation cycle.

Discovery gap: `activation` does not publicly expose its store. The exported `IndexedActivationStore.open()` has `list()` returning `{operationId, origin, state}[]`; a small presentation adapter may open/list/close it. Do not access TypeScript-private fields or put setup capabilities into URLs. The completed-result resume capability lasts 24 hours; after that use ordinary login/recovery, not another activation.

## Avatar and own profile

`GET /v1/avatars/catalog` is public and returns `{version: 1, defaultSelection, colours: [{id,label,hex}], shapes: [{id,label,svg}], ...sourceMetadata}`. It has 20 shapes and 12 colours. Fetch the complete fixed catalogue, validate/use only allowlisted IDs, and display SVG through isolated image URLs, replacing `currentColor` with the selected catalogue hex. Do not inject SVG strings into page DOM or load external avatar services.

`AvatarSelection = { shapeId: 'shape-01' ... 'shape-20', colourId: 'coral' | 'amber' | 'gold' | 'lime' | 'teal' | 'mint' | 'sky' | 'blue' | 'indigo' | 'violet' | 'rose' | 'slate' }`. The default is shape-01/teal. Signup explicitly passes the choice. `client.profiles.current()` returns `{workspaceId, accountId, revision, displayName, avatar}` after current authenticated verification. It reads the caller only. There is no avatar edit API after signup, no image upload, and no public avatar/name directory. Do not render an enabled “Edit avatar” control without implementing a proper encrypted profile mutation.

## Invite a member or another equal Owner

Owner calls:

```ts
client.enrolments.issueJoin({
  kind: 'join_member' | 'join_owner', roleId, projectIds, displayName,
  accountId?: string, operationId?: string,
});
client.enrolments.revokeJoin({workspaceId, operationId});
client.enrolments.claim({workspaceId, operationId});
client.enrolments.approve({workspaceId, operationId}, confirmedFullFingerprint);
```

`issueJoin` returns `{workspaceId, accountId, operationId, invitationGeneration, code, expiresAt}`. The code is `JOIN-XXXX-XXXX-XXXX`, valid for one hour including approval. Members receive explicit projects and selected role. Additional Owners use the Owner role and receive all ordinary projects. Copy/share privately; there is no email invitation service. A replacement invitation must retain the intended account ID and use the appropriate fresh operation; do not create an accidental duplicate person.

Recipient calls:

```ts
const begun = await client.enrolments.beginJoin({
  workspaceId, code, genesisFingerprint, // fingerprint optional only with existing pin
}, localId?);
// Owner claims begun.operation before preparation.
const prepared = await client.enrolments.prepare(
  begun.localId, password, confirmation, displayName,
  ownerKitOrUndefined, avatar,
);
await client.enrolments.confirmRecipient(
  begun.localId, independentlyConfirmedFullFingerprint, passwordIfReloaded?,
);
```

`beginJoin`, `claim`, `prepare`, `confirmRecipient`, `approve` and `cancel(localId)` return `CeremonyProgress`; `resume(localId, newOwnerPhrase?)` returns `CeremonyResume`.

Provide the workspace fingerprint from the inviting Owner through a trusted private handoff, alongside the workspace ID and code. The code alone cannot establish trust. An invitation handoff can hide IDs inside a validated fragment/share package while displaying useful names. Avoid query parameters or third-party link shorteners carrying codes. The later full 64-hex security comparison is distinct from this initial workspace fingerprint. Both parties must independently compare the full value through a trusted channel; the UI may group it and provide QR/clipboard, but must not silently call confirmation with its own server response.

Members need name, avatar and password. Additional Owners need the same independent 24-word backup and word checks as the first Owner. Once approved, call `resume`, then `auth.login` using account ID from the local operation record and returned device ID, then `resume` again (passing the new phrase for an Owner). Enter the app only after `access === 'content_ready'`. The enrolment controller automatically remembers the verified decrypted name on successful delivery.

State routing:

| State/access | User path |
| --- | --- |
| `issued`, `waiting_approval`, `starting` | Waiting for an Owner; show share request, expiry and explicit check again. |
| `verifying` | Complete personal setup and comparison. |
| `confirmed` | Waiting for the Owner's final approval; retain same local operation. |
| `finishing` | Finishing setup; check existing status. |
| `login_required` | Enter chosen password; then verify existing delivery. |
| `recovery_kit_required` | Ask for newly saved Owner phrase; never substitute old phrase. |
| `incomplete_keys` | Keep setup pending; retry delivery or seek current Owner help; no blank app pretending success. |
| `content_ready` | Fetch own profile and open workspace. |
| `expired`, `revoked`, `cancelled` | Explain and return to invitation entry/contact Owner. Preserve any committed-result recovery. |

Local discovery: `enrolments.operations.list()` returns `{role, localId, workspaceId, accountId, operationId, state}[]`; `.get('recipient'|'owner', localId)` provides saved typed state for the route. Owner takeover invalidates old confirmations and produces a new fingerprint. Re-run `prepare` on the same recipient draft/password; its retained encrypted name/avatar choice survives. Do not make a new member for a network timeout. `cancel(localId)` verifies final status before discarding an uncommitted candidate.

## Promote a member to equal Owner

1. Owner: `enrolments.beginPromotion(accountId, operationId?)` → `EnrolmentView`.
2. Existing member: `enrolments.claimPromotion({workspaceId,operationId}, currentPassword, localId?)` → progress.
3. Owner: `enrolments.claim(reference)`.
4. Member creates/backs up a new personal phrase and manually verifies three words; `enrolments.preparePromotion(localId, currentPassword, ownerKit)` → progress.
5. Recipient `confirmRecipient` and Owner `approve` after full independent comparison.
6. Recipient `resume`, logs in again using the existing password/device, then `resume(localId,newPhrase)` until content ready.

Promotion retains the password, avatar/name and healthy device identities, but replaces grants and invalidates old sessions. Treat every Owner equally; the licence activator has no special ongoing privileges. Owner permissions are not a toggle that may skip the member's recovery setup.

## New browser/device approval

Recipient first logs in using `{workspaceId,accountId}` and password, yielding restricted access. `client.pairing.begin(operationId?)` → `{operationId,state,deviceId,fingerprint}`. Share only the public request reference. Current approved device/eligible Owner calls `pairing.claim(operationId)` to fix the comparison. Then:

```ts
await recipient.pairing.confirmRecipient(operationId, confirmedFingerprint);
await approver.pairing.confirmApprover(operationId, confirmedFingerprint);
await approver.pairing.approve(operationId); // PairingReceipt
await recipient.pairing.resumeRecipient(operationId, displayName?);
```

`resumeRecipient` returns `state: 'content_ready'` only after verified delivery and session elevation. Otherwise states are `waiting_approver | verifying | confirmed | completed | expired | cancelled`. After reload, log in again first, then resume the existing operation. `pairing.store.list()` returns `{role,operationId,workspaceId,accountId,deviceId,completed}[]`. A completed receipt alone is not a content-ready screen.

No dedicated pairing cancel controller/endpoint is exposed. A UI “Back” may leave the request pending until its expiry, but must not claim it revoked server approval. Pairing has a single active controller operation; disable duplicate submits.

## Password change while signed in

1. Ask for current password and `auth.reauthenticate(currentPassword)`.
2. `passwordChanges.begin(workspaceId, operationId?)` → status.
3. `passwordChanges.prepare(operationId,newPassword,confirmation)` → void.
4. `passwordChanges.complete(operationId,newPassword)` → `{state:'completed'|'finishing',receipt}`; local auth clears on completion/uncertain commit.
5. Log in with the new password and same account/device. Then `passwordChanges.resume(operationId, auth.current()!.session)` to resolve/confirm the receipt.

`resume(operationId, authenticated?)` returns `{state:'issued'|'completed'|'finishing'|'cancelled'|'expired'|'revoked',binding,receipt?}`. `cancel(operationId)` is only for confirmed precommit cancellation. The invoking device remains, other devices/sessions are revoked. Keep an interrupted-operation route; do not replace a draft because a response was lost. Discovery is through exported `IndexedPasswordChangeStore.open().list()` (returns operation/workspace/origin), because the controller has no public store property.

## Recover access with Owner words

Accept a saved kit file/local paste and the old phrase. Kit identity is **exactly** `{origin,workspaceId,accountId,genesisFingerprint}`; map activation kit's `application` to `origin`. Validate the origin against the current app and reject unrelated files. Do not upload the kit or phrase. Then:

```ts
const begun = await client.recoveries.beginPhrase(kitIdentity, localId?);
await client.recoveries.provePhrase(begun.localId, oldPhrase);
const prepared = await client.recoveries.prepare(
  begun.localId, newPassword, confirmation,
  {phrase:newPhrase, positions, answers:userEnteredAnswers},
);
await client.recoveries.confirmRecipient(begun.localId, confirmedFingerprint, newPasswordIfReloaded?);
await client.recoveries.approvePhrase(begun.localId, confirmedFingerprint, oldPhrase, newPasswordIfReloaded?);
```

The old phrase establishes trust through the saved kit; no other Owner is needed. Generate and independently verify a **new** personal phrase before commit; the old recovery phrase becomes unusable afterward. All old devices/sessions are revoked. Persist the replacement full kit outside browser storage, never only the words. The first phrase challenge expires after two minutes, so avoid doing long backup/reading steps between beginning and proving it.

After commit: `recoveries.resume(localId)` → `login_required`; log in with replacement password/device, then `resume(localId,newPhrase)` → `content_ready`. Fetch `profiles.current()` and explicitly remember the verified name; recovery does not automatically save a name card. Keep the new phrase in memory only as long as this verified readback needs it, clearing on logout/navigation.

## Owner-assisted forgotten-password reset

Owner: `recoveries.issueReset(accountId, resetId?)` → `{workspaceId,accountId,resetId,code,resetGeneration,expiresAt}`. Code format `RESET-XXXX-XXXX-XXXX`, one recipient, expires after 15 minutes. Issuing a replacement rotates the reset generation. `recoveries.revokeReset(workspaceId,resetId)` cancels a pending reset.

Recipient: `recoveries.beginReset(workspaceId,code,localId?)` → progress. Share returned public operation with Owner. Owner: `recoveries.claim(operation)` → progress. Recipient: `recoveries.prepare(localId,newPassword,confirmation,newOwnerKit?)`. Supply a new kit only for an Owner, never give ordinary members recovery words. Recipient confirms the full fingerprint; Owner calls `recoveries.approve(operation,confirmedFingerprint)`. Complete with the same resume/login/verified-delivery sequence above.

`recoveries.operations.list()` exposes saved `{role,localId,workspaceId,accountId,operationId,state}` summaries; `operations.get('recipient',localId)` gives Owner/member kind from `view.binding.role` when claimed. After reset begin the view account ID is already saved, so do not ask the recipient to type technical identifiers. A different eligible Owner can take over before immutable approval staging. Once staged, use a replacement reset rather than mutating the approved operation. `recoveries.cancel(localId)` verifies authoritative cancellation and preserves committed receipts.

## Complete UI states and safe wording

| Internal result/error | Customer-facing meaning and actionable exit |
| --- | --- |
| `AUTHENTICATION`, `PROOF_REQUIRED` during password entry | “That password didn't work. Please try again.”; keep recovery link. |
| `AUTH_REQUIRED` | “Please sign in to continue.”; clear protected content and preserve non-secret route intent. |
| `REAUTH_REQUIRED` | “Confirm your password to continue.”; retry same intended action once authenticated. |
| `PASSWORD_CONFIRMATION`, new-password validation | Specific inline field help; keep entered non-secret form values. |
| `RATE_LIMITED` | “Too many attempts. Please wait a little and try again.”; no automatic retry loop. |
| `TRANSPORT`, offline, `UNAVAILABLE` | “We couldn't connect. Your progress is saved on this device.” only where a draft is actually saved; provide retry/back. |
| `CONFLICT`, stale operation | Reload/check saved status; explain changed access or an Owner takeover; never silently regenerate a request. |
| `EXPIRED`, revoked invitation/reset | “This invitation has expired” / “This key is no longer valid”; request a fresh key from Owner. |
| `FORBIDDEN` | “You don't have access to this action.”; route back to allowed content. |
| `LOCAL_DEVICE_UNAVAILABLE`, missing local wrapper | “This device needs approval.”; pairing/recovery options. |
| `STORAGE`, `UNAVAILABLE` opening runtime | “This browser couldn't save your secure sign-in. Enable site storage or try another supported browser.”; retry without weakening security. |
| `TRUST_REQUIRED`, mismatch, invalid receipt/content | “We couldn't verify this request. Nothing has been approved.”; stop and compare a fresh trusted handoff; no “continue anyway”. |
| `INCOMPLETE_KEYS` | “Your access is still being prepared.”; bounded check/retry/contact Owner, not an empty-success workspace. |
| `CANCELLED` from navigation/logout | Usually no toast; prevent a late result reopening the previous screen. |
| `LOCAL_CLEANUP`, failed server logout | Local screen stays locked; state whether retrying sign-out is needed. Never claim all remote sessions revoked. |

Loading states must have a meaningful label and stable layout, errors an adjacent retry/back action, and waiting states an expiry/check-again/cancel-or-leave path. Disable buttons while their mutation runs. Use bounded polling only while a waiting screen is visible; stop on terminal states, route change, auth clear and offline. Never use an endless “retry until success” effect. Provide a global pending setup entry sourced from saved operation summaries after reload.

## Integration gaps to resolve explicitly

1. Fresh-browser reference handoff, invitation trust package and recovery-kit import/download are presentation work. They are necessary for one-password login without a public account directory. Use strict, versioned parsing, fragment or local file handling, and no secret in query strings or logs.
2. Owner pending approvals are not a server-listed inbox in these identity controllers. Owner operations created/claimed on this browser can be listed locally, while other-device requests need the shared public request link/QR. Do not show an empty local list as proof that the workspace has no pending requests.
3. Activation/password-change saved-operation discovery needs a small exported-store adapter, or a narrowly added controller listing method. Pairing/enrolment/recovery already expose stores.
4. `EnrolmentProgress`/`RecoveryProgress` omit account ID, kind, expiry and display labels. Read bounded local metadata or add safe progress helpers. Never expose full internal records in debug UI.
5. The existing self-profile endpoint cannot fill a People directory. Authenticated roster labels require a verified encrypted directory read through real authorized data, not UUID text or demo names. Coordinate with the work/administration integration before rendering member selection.
6. No standalone “revoke this one remote device” API, recovery-word redisplay, profile/avatar editing, or email recovery was found. Omit such promises unless proper backend changes are explicitly implemented; password reset/change, profile access controls and local Forget have different effects.
7. Two actors cannot be simulated by changing account IDs inside one shared-cookie browser runtime. End-to-end approval testing needs independent browser contexts (as the existing browser tests use).
8. Existing docs include historical checkpoint-in-progress phrasing. Current source and tested journeys are the authoritative implemented contract; do not present old document caveats as product copy.

## Existing evidence and acceptance targets

`test/browser/enrolment.spec.ts` exercises member JOIN through a lost final response/reload, password-preserving promotion, equal Owner signup, Owner takeover, pairing, RESET and retained avatar choices. `test/browser/authentication.spec.ts` covers actual Worker/login/password changes. `test/browser/recovery.spec.ts` covers phrase and Owner-assisted reset. `test/browser/authentication-fixture.ts` is a harness only, never a product shortcut.

The frontend must itself verify at least: fresh activation with independently typed backup words; returning remembered-name login; expired/wrong input and storage/connection errors; real member and Owner invitation approval across independent contexts; device approval; Owner phrase recovery and member reset; interrupted setup resumed after reload; password change followed by login; logout clearing all plaintext; explicit Forget; keyboard/focus/screen-reader behavior; reduced motion; light/dark/mobile layouts. Tests should interact with actual customer controls and use real backend fixtures, not bypass production flows with direct fixture state injection for the journey under test.

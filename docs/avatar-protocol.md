# Illustrated profile avatars

Signup supports a choice of **20 illustrated shapes × 12 colours = 240 combinations**. The artwork is a locally bundled adaptation of [DiceBear Critters](https://www.dicebear.com/styles/critters/), released under CC0 1.0. The [asset notice](../assets/avatars/NOTICE.md) retains the licence, pinned source and modifications; [preview.png](../assets/avatars/preview.png) shows every design and colour. No avatar service, photo upload, arbitrary URL or customer-supplied SVG is involved.

This is the backend and browser protocol implementation. There is no signup screen or visual selector yet.

## Catalogue before signup

`GET /v1/avatars/catalog` requires no account, licence or database query. It returns catalogue `version: 1`, `defaultSelection`, twelve `colours` (`id`, `label`, `hex`), and twenty `shapes` (`id`, `label`, `svg`), with source/licence information. The full catalogue is the same for every caller, supports ETag/304 caching, and accepts no query parameters. Sending a selected shape in an image URL is unnecessary.

Templates use `currentColor` for the chosen shell/accessory colour, with fixed ink and highlights. A future frontend can replace `currentColor` with the selected catalogue hex and display the resulting SVG as an image. Use isolated images rather than injecting markup into the page; local clipping IDs can otherwise collide when the same shape is embedded repeatedly. Do not accept arbitrary SVG, CSS colours or remote image URLs. All assets are hash checked on API startup and included in the runtime image.

`avatarSelection`, `avatarShapeIds`, `avatarColourIds`, `avatarColours`, `DEFAULT_AVATAR` and `resolveAvatarSelection` are exported from the browser library. The selection is exactly:

```ts
const avatar = { shapeId: 'shape-07', colourId: 'sky' } as const;
```

IDs are allowlisted. Additional fields, unknown IDs, raw hex colours and null selections fail validation. Published IDs keep their existing design and colour meaning. New artwork versions must not overwrite those meanings.

## Signup and persistence

First Owner activation accepts the optional `avatar` alongside its existing name/password/recovery inputs:

```ts
await client.activation.prepare(operationId, {
  password, confirmation: password, phrase,
  challengePositions, challengeAnswers, displayName, workspaceName,
  avatar,
});
```

Invited members and additional Owners choose for themselves during preparation. The existing fifth argument remains the additional Owner's recovery kit; the sixth is the avatar:

```ts
await client.enrolments.prepare(localId, password, password, displayName, undefined, avatar);
await client.enrolments.prepare(localId, password, password, displayName, ownerRecoveryKit, avatar);
```

Selection is optional for compatibility with existing callers. A new selector can start with `DEFAULT_AVATAR` (`shape-01`, `teal`) and pass the chosen pair explicitly. Existing callers that omit it retain their exact former encrypted content shape.

The two IDs live inside the encrypted profile alongside the display name. JOIN additionally carries them inside its sealed setup packet and encrypted local retry wrapper. They are never added to public security history, database metadata or plaintext persisted setup drafts. Owner approval, reloads, lost responses and approval takeover preserve the staged choice. A retry resumes the existing encrypted draft; it does not replace its avatar from newly supplied arguments. Initial activation uses the existing draft replacement ceremony if a prepared signup must be changed.

Password changes, device pairing, recovery and member-to-Owner promotion retain the profile. The avatar is not a credential, authority marker or unique user identifier. This change adds no profile-editing action after signup; that is separate from the requested signup selection.

## Read and export

After an approved login, `await client.profiles.current()` returns the caller's `workspaceId`, `accountId`, current `revision`, `displayName` and resolved `avatar`. Its Worker verifies the current signed profile reference, digest, revision, actor/device and historical upgrade lineage before decrypting. The controller checks current authority again before releasing the result and cancels reads on logout. Profile plaintext is returned in memory. After an authenticated, verified read, the application may save the current profile’s display name and optional validated catalogue selection in its local remembered-profile card so sign-in shows the same avatar. This convenience metadata is scoped to the browser origin, workspace, account and device; Forget removes it. Backend profile records remain encrypted, and sign-in does not fetch personal profile data before authentication.

This reuses the authenticated `POST /v1/auth/access-change/delivery` request with `{ workspaceId, includeProfile: true }`. It returns only the caller's encrypted profile and eligible key material. The caller cannot supply another account ID. Existing delivery requests remain key-only. Password-only, revoked and ineligible devices cannot retrieve the profile. There is no public member directory.

Old profiles without a selection display the default through the read result only. Readers and encrypted upgrades never insert that default into signed historical content. Owner data-exit export includes an explicit avatar when present and preserves absence in legacy content. Profile removal continues to replace the current label with `Former member` and removes the current avatar with it; historical encrypted contributions keep the architecture's existing retention rules.

No SQL migration, new third-party runtime dependency or photo storage is required. Deploy matching API, worker and browser-library builds; older clients with strict name-only profile parsing cannot consume avatar-bearing profiles. The original thirteen-checkpoint reports remain historical evidence; avatar-specific verification is recorded in [avatar verification](avatar-verification.md).

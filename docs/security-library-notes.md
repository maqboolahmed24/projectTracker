# Security library integration notes

Original dependency research, checked 24 September 2026. At the time of that research, no application authentication code or runtime/browser interoperability checks had been implemented. Findings come from the published npm tarballs, declarations, generated JavaScript, and upstream source. They support checkpoints 4–5; they do not change the agreed checkpoint order or establish audited application security.

Implementation update: all three selected libraries are now installed and pinned. Activation, authentication, device approval and password changes are verified through checkpoint 4. Checkpoint 5 recovery integration is in progress; see the [checkpoint 4 evidence](checkpoint-04-evidence.md) and [checkpoint 5 evidence](checkpoint-05-evidence.md) for current runtime and browser results. These implementation checks do not substitute for the independent review required before release.

## Confirmed package baseline

| Package | Published version | Relevant packaging |
| --- | --- | --- |
| `@serenity-kit/opaque` | `1.1.0` | CommonJS `cjs/index.js`; browser/ESM `esm/index.js`; bundled WASM; bundled `index.d.ts`; no runtime dependency. |
| `libsodium-wrappers` | `0.8.4` | Conditional ESM/CommonJS exports and bundled declarations; runtime dependency `libsodium: ^0.8.0`, so lock the transitive version. |
| `@scure/bip39` | `2.4.0` | ESM; bundled declarations; exact runtime dependency `@noble/hashes: 2.4.0`. |

Registry records: [OPAQUE 1.1.0](https://registry.npmjs.org/@serenity-kit/opaque/1.1.0), [libsodium wrappers 0.8.4](https://registry.npmjs.org/libsodium-wrappers/0.8.4), [BIP39 2.4.0](https://registry.npmjs.org/@scure/bip39/2.4.0). The records' `dist.integrity` values should be captured by the package lock. OPAQUE's matching upstream release tag resolves to commit `ca1cb22f03b9e456159ce367e2975124f87f5ad8`.

## Corrections that matter before implementation

1. Await both libraries' readiness before crypto calls: `await opaque.ready` and `await sodium.ready`.
2. OPAQUE's `keyStretching` option belongs on **client `finishRegistration` and `finishLogin`**. The published README incorrectly names the start calls. The shipped TypeScript declarations and Rust implementation agree on the finish calls. There is no server `keyStretching` argument; preserve a versioned public client-configuration ID alongside each credential registration.
3. Use `import sodium from 'libsodium-wrappers'` for ESM. Version 0.8.4 populates `crypto_*` operations on the default object after readiness. Its named ESM exports contain readiness and utility functions, not the crypto operations. Do not use namespace imports or named `crypto_*` imports in ESM.
4. OPAQUE protocol strings, states, keys, and public keys use **base64url without padding**. Decode `exportKey` to bytes before WebCrypto HKDF. Never derive wrapping keys from the ASCII encoding or the shared `sessionKey`.
5. The exact English wordlist import is `@scure/bip39/wordlists/english.js`. Explicitly request 256 bits or encode 32 random bytes; the mnemonic generation default is 128 bits/12 words.

## OPAQUE call sequence and ownership of data

Import with `import * as opaque from '@serenity-kit/opaque'` and await readiness in each client/server runtime. These are API call shapes, not application endpoint implementations.

### Registration

1. Client: `opaque.client.startRegistration({ password })` returns `clientRegistrationState` and `registrationRequest`. Only the request crosses the network.
2. Server: `opaque.server.createRegistrationResponse({ serverSetup, userIdentifier, registrationRequest })` returns `registrationResponse`.
3. Client: `opaque.client.finishRegistration({ password, clientRegistrationState, registrationResponse, identifiers, keyStretching })` returns `registrationRecord`, `exportKey`, and `serverStaticPublicKey`.
4. Client checks the configured server public key, derives its local wrapping key from decoded export material, stages/verifies its local encrypted device bundle, and submits only the registration record plus authorised setup metadata.
5. Server activates that record only through the architecture's authorised, generation-checked security transaction. OPAQUE registration does not itself authorise an invitation, licence, reset, or owner grant.

### Login

1. Client: `opaque.client.startLogin({ password })` returns `clientLoginState` and `startLoginRequest`.
2. Server: `opaque.server.startLogin({ serverSetup, userIdentifier, registrationRecord, startLoginRequest, identifiers })` returns `serverLoginState` and `loginResponse`. Look up the registration record on the server; never accept it from the requester.
3. Client: `opaque.client.finishLogin({ password, clientLoginState, loginResponse, identifiers, keyStretching })` returns a result or `undefined`. A result contains `finishLoginRequest`, `sessionKey`, `exportKey`, and `serverStaticPublicKey`. Malformed inputs can also throw.
4. Server: `opaque.server.finishLogin({ serverLoginState, finishLoginRequest, identifiers })` verifies the final message and returns its own `sessionKey`; it can throw on failure. A client-provided session key is not proof of login.
5. Only after server finalisation, current generation checks, and the architecture's separate approved-device challenge may the application issue the appropriate session/access. Match the login-state account, ceremony, registration generation, and expiry again at completion, so a reset between login start and finish invalidates the old attempt.

Use identical custom identifiers in client registration finish, both login finish calls, and server login start. Recommended values are an immutable workspace/account reference for `identifiers.client` and a fixed deployment authentication identity for `identifiers.server`. `userIdentifier` is the immutable workspace-scoped credential identity; it is neither a display name nor a request-controlled identity switch. Persist the identity policy with the credential, and never silently change it on deployment or domain changes.

### Secret/state handling

| Value | Where it belongs |
| --- | --- |
| Password, client ephemeral state, `exportKey` | Client memory only during the operation. No API, telemetry, persistence, or server log. |
| Encrypted device private bundle | Client IndexedDB only, as required by the architecture. |
| `serverSetup` | Long-lived server operational secret, backed up separately with an explicit setup ID. Generate once, not on each process boot. |
| `registrationRecord` | Security control store, bound to workspace/account and credential generation. Treat as sensitive authentication material. |
| `serverLoginState` | Short-lived server-only state, bound to the account/generation/ceremony; consume once. Return an opaque flow identifier to the browser, never this state. |
| `sessionKey` | Ephemeral protocol material available to both peers; never a private-content wrapping secret. |
| `serverStaticPublicKey` | Public verification value, pinned through trusted deployment configuration; distinct from the workspace genesis identity. |

`server.startLogin` accepts `registrationRecord: null` or `undefined` for the protocol's fake-record path. Still give generic failures and apply uniform bounded processing/rate limits. Do not expose raw library exceptions. Replacing `serverSetup` invalidates existing password files; secret rotation therefore needs an explicit credential migration/recovery plan, not a restart-generated value.

The documented `exportKey` stability applies to repeated login under the stored registration. Treat a replacement registration, including password change/reset, as a new generation with new export material and perform the required local bundle rewrap. The application must never assume the same password implies the same export key after re-registration.

## Password hardening and browser runtime

Use the explicit initial profile `keyStretching: 'memory-constrained'` consistently for client registration/login finish. In this release it selects Argon2id with memory 65,536 KiB, three iterations, and parallelism four. Record a profile/version ID with the credential and benchmark the supported browsers before pilot. `rfc-recommended` selects approximately 2 GiB, one iteration, and parallelism four; do not accidentally select it for the default browser journey. Avoid silently downgrading an existing record's profile.

OPAQUE packages WASM bytes inside its JavaScript; the published package has no separate `.wasm` asset to deploy. Initialization is asynchronous; the subsequent expensive finish calls are synchronous. Run client password work in a dedicated bundled worker so the UI remains responsive. Review the production CSP with the real bundles: WASM compilation needs the appropriate `wasm-unsafe-eval` permission, not an indiscriminate relaxation to `unsafe-eval`. Check same-origin worker and chunk loading under the deployed policy.

The sodium ESM bundle explicitly requires `globalThis.crypto.getRandomValues` and describes Node 19+ support. Node 24 meets that stated prerequisite, but actual Node and browser startup/round trips still need the checkpoint tests. Keep server secrets out of client-exposed environment variables and client module graphs.

Primary source: [OPAQUE tagged Rust implementation](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/src/lib.rs), [OPAQUE upstream documentation](https://github.com/serenity-kit/opaque#advanced-usage), and [CSP Level 3](https://www.w3.org/TR/CSP3/).

## Sodium calls needed by the architecture

After `await sodium.ready`, use byte inputs/outputs and canonical encoding at the application boundary:

| Purpose | API shape |
| --- | --- |
| Random bytes | `sodium.randombytes_buf(length)` |
| Ed25519 device signer | `sodium.crypto_sign_keypair()` |
| Deterministic recovery signer | `sodium.crypto_sign_seed_keypair(seed32)` |
| X25519 device recipient | `sodium.crypto_box_keypair()` |
| Deterministic recovery recipient | `sodium.crypto_box_seed_keypair(seed32)` |
| Record encrypt | `sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce24, key32)` |
| Record decrypt | `sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce24, key32)` |
| Signature | `sodium.crypto_sign_detached(message, signingPrivateKey)` |
| Verify | `sodium.crypto_sign_verify_detached(signature, message, signingPublicKey)` |
| Recipient envelope | `sodium.crypto_box_seal(payload, recipientPublicKey)` |
| Open envelope | `sodium.crypto_box_seal_open(ciphertext, recipientPublicKey, recipientPrivateKey)` |
| Base64url | `sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING)` and matching `from_base64` variant |

`crypto_box_seed_keypair` is the library's deterministic box keypair construction; do not assume its returned private key equals the 32-byte input seed. Use the returned pair consistently. Sealed boxes do not authenticate senders: retain the architecture's signed outer envelope and context binding. Authentication/decryption failures must become controlled rejection paths. Use `memzero` for mutable byte buffers where practical, while recognising that JavaScript strings and copied runtime memory cannot be guaranteed erased.

These APIs are in the standard wrapper; no sumo dependency or `@types/libsodium-wrappers` package is needed for 0.8.4. Verify the actually locked transitive libsodium build's exported operations during checkpoint 4.

## Recovery phrase calls

Use `generateMnemonic(wordlist, 256)` or `entropyToMnemonic(sodium.randombytes_buf(32), wordlist)`. Validate with `validateMnemonic`, then recover entropy with `mnemonicToEntropy`. Require the decoded entropy to be exactly 32 bytes for this application's 24-word kits. Validation alone also accepts valid shorter mnemonics.

Never use `mnemonicToSeed`, `mnemonicToSeedSync`, or `mnemonicToSeedWebcrypto` for this application's recovery design. Those are wallet-style PBKDF2 seed APIs; the architecture deliberately derives separately labelled application keys from the original entropy. Keep kit language and format version explicit. [BIP39 upstream API documentation](https://github.com/paulmillr/scure-bip39).

## Checkpoint 4–5 evidence to collect

- Exact-version Node and production-browser imports, readiness, worker operation, CSP, and standard sodium symbols.
- Registration/login export-key equality, server/client session-key equality, and pinned server-key verification.
- Wrong password, custom-identifier mismatch, missing account, expired/replayed login state, and reset during an in-progress login all reject correctly.
- New registration/password change updates export material and follows the staged local rewrap/commit-receipt contract.
- Canonical AEAD/signature vectors; tampered ciphertext, wrong context/recipient, and malformed base64 fail.
- Independent 24-word phrases round-trip to 32-byte entropy; wrong checksum and valid-but-shorter phrases reject.
- Logs and transport contain no password, export key, client private state, phrase, or plaintext project content.

No package/API selection blocker was found. These are concrete integration requirements and validation gates, not evidence that the eventual application is already secure.

# Licence activation protocol

Checkpoint 3 implements setup through an HTTP API and a browser library. It does not create a login session or frontend screen. Subsequent password login and approved-device proof belong to checkpoint 4.

## Run locally

Follow the README to start both databases, apply migrations, generate `.env.identity` once, and start the API and worker. Issue a key with `npm run licence -- issue --output .local/activation-key.json`. Only the private output file contains the plaintext licence key. The hosted API has no licence-issuance endpoint.

Use HTTPS in deployment. The browser transport allows plain HTTP only on exact loopback hosts for local development. Production server configuration requires HTTPS. The application origin must match `APP_ORIGIN`; the stable OPAQUE server identity comes from `.env.identity` and must survive restarts.

## Client sequence

Use `HttpActivationTransport`, `IndexedActivationStore`, `IndexedDeviceStore`, and `ActivationController` from `src/client/`. These are browser modules; the IndexedDB factory can be supplied for tests. Password work should run in a dedicated browser worker; this document does not claim that a browser interface or worker host is already implemented.

1. Open the two local stores and construct the controller for the configured origin. `create()` saves a random operation ID and 256-bit setup resume capability before the first network request.
2. `reserve(operationId, licenceKey)` reserves one entitlement for sixty minutes. A retry uses the same operation and capability. The response identifies the pending workspace and Owner; neither name nor password is an account identifier.
3. Generate a phrase using `newOwnerPhrase()`. Arrange a local save/print of the recovery material and confirm the selected words using `recoveryChallenge()`. Pass the phrase, matching answers, names, and password confirmation to `prepare()`. The recovery kit returned by this call includes the application origin, account reference, and genesis fingerprint; retain it outside this browser.
4. Preparation registers OPAQUE, generates independent signing and recipient device keys, encrypts the workspace/profile/custody records, and produces signed recipient envelopes. It saves an encrypted local device wrapper, reads it back, and unwraps it locally before finalisation. Only the client OPAQUE export key wraps that private bundle.
5. `activate(operationId, password)` proves possession of the registered password, uploads the signed encrypted setup payload, and finalises the same request hash. The server commits licence consumption, first-Owner identity, device/recovery/grant references, staged ciphertext, and the receipt in one control transaction.
6. The application projection remains fenced until it matches the committed security head. A successful reply is `completed`; an interrupted projection is `finishing_setup`. The durable worker job and protected status lookup can repair that projection. The controller promotes the matching local device candidate only after validating the receipt against its saved genesis and device context.

Names, passwords, phrases, content keys, private device keys, local wrappers, and OPAQUE export keys are never part of an upload. The pending local setup store holds public/encrypted draft data and the short-lived setup capability; it does not hold a plaintext password or recovery phrase. This capability provides setup authority only, not customer-data access.

## HTTP operations

All routes use `POST`, strict JSON, `Origin: <APP_ORIGIN>`, and no query parameters. Protected setup routes also require `Authorization: Setup <resumeToken>`. Responses and errors have `Cache-Control: no-store`; setup never sets an authentication cookie.

| Route | JSON body |
| --- | --- |
| `/v1/activation/reserve` | `licenceKey`, `operationId`, `resumeToken` |
| `/v1/activation/:activationId/status` | `{}` |
| `/v1/activation/:activationId/registration` | `draftGeneration`, `registrationRequest` |
| `/v1/activation/:activationId/proof/start` | `draftGeneration`, `payload`, `startLoginRequest` |
| `/v1/activation/:activationId/proof/finish` | `draftGeneration`, `proofId`, `finishLoginRequest` |
| `/v1/activation/:activationId/finalize` | `draftGeneration`, `requestHash` |
| `/v1/activation/:activationId/replace-draft` | `expectedDraftGeneration`, `operationId` for this replacement |

The signed payload and cryptographic contexts are defined in `src/shared/activation.ts`. Initial encrypted records refer to security version zero and the zero head; their signed manifest determines the immutable genesis fingerprint without a circular hash. The committed activation is security version one. Subsequent normal writes must use current authority, not bootstrap authority.

The password proof expires after two minutes and is consumed on use, including an invalid attempt. Finalisation requires successful verification within five minutes and a still-valid reservation. A different payload hash requires explicit draft replacement. The identical finalisation returns the original receipt.

Rate budgets are shared across API instances: 120 requests per source and per activation attempt per ten minutes, plus 20 reservation requests per licence per ten minutes. Storage contains keyed digests and counter times, not raw IP addresses or keys. The worker prunes expired counters in bounded batches every five minutes. Reverse-proxy source handling needs an explicit deployment configuration; the server does not trust caller-supplied forwarding headers.

## Interruption outcomes

| Interruption | Required next action |
| --- | --- |
| Lost reservation response | Retry the original operation and locally saved capability. |
| Reload with a saved draft | Discover the pending local operation and call `resume()`; re-enter the password if setup is uncommitted. |
| Lost pre-commit draft but retained capability | Confirm server status, explicitly replace the pending draft, and repeat recovery-kit verification. The replacement invalidates earlier proof material. |
| Lost capability before commit | Wait for the fixed reservation expiry; the licence alone cannot inspect or take over the attempt. |
| Lost final response | Read protected status and validate the original receipt; do not generate another Owner. |
| Projection interruption | Keep setup in `finishing_setup`; the worker or status lookup repairs the same workspace. |
| Lost usable local keys after commit | Use ordinary Owner recovery; activation cannot reset the account. |
| More than twenty-four hours after commit | The setup capability expires. Use normal login/recovery; the licence remains consumed. |

Licence restriction preserves identity and keys. Operational revoke/legacy-expire/reinstate commands change the licence guard only. They do not clear deletion, maintenance, or restore restrictions, and cannot grant ownership. The reusable action policy allows existing authentication, approved replacement within existing scopes, reads, recovery, password change, revocation, export, and deletion; access expansion and ordinary writes are denied while restricted. Each later endpoint must additionally enforce current identity, device and scope authority.

## Verification boundaries

PostgreSQL tests exercise real OPAQUE, client cryptography, transactions, receipts, fences, and worker jobs. IndexedDB unit/integration tests currently use `fake-indexeddb`; they do not prove a supported browser matrix. Browser-engine compatibility, ordinary login/recovery, multiple-Owner journeys, deletion/purge, and final independent security review remain owned by their later checkpoints. The hosted-client and compromised-device threat boundaries in the architecture still apply.

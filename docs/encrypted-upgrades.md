# Encrypted content upgrades

The headless browser client exposes `client.upgrades`. A currently approved Owner operates the upgrade; decryption, transformation, fresh encryption, and signed-history verification run in the authentication Worker. The server retains ciphertext, signed references, progress, and receipts. This does not change the hosted-client/device threat boundary documented in the architecture.

The first transform changes content schema 1 into the explicit typed schema-2 wrapper. Envelope version 1 remains supported. Historical ciphertext, signatures, closing snapshots, and task review intent remain unchanged. Unknown formats fail with `UPDATE_REQUIRED` rather than dropping fields. There is no downgrade operation.

## Explicit operation sequence

After normal Owner authentication and local unlock:

```ts
const started = await client.upgrades.start();
const migrationId = started.migrationId;
const progress = await client.upgrades.progress(migrationId);
// Each explicit invocation processes at most one native batch.
const batch = await client.upgrades.advance(migrationId);
// Call advance again when requested, until it returns ready_to_finish.
// Then explicitly finalise the fully verified current inventory:
const finished = await client.upgrades.finish(migrationId);
```

`advance` processes up to 32 compatible identity or planning records, or one team/discussion record. It does not schedule an automatic loop. The complete manifest is bounded to 20,000 current encrypted records. `progress` reports the persisted completed and total counts. `finish` independently checks the target inventory, its native signed histories, and plaintext equivalence before signing completion; it rejects unfinished work.

Starting pauses ordinary content writes. Existing reads and permitted security/recovery operations remain available. A different current Owner can use the same migration ID to continue. Removed Owners, revoked devices, stale key epochs, and obsolete data generations cannot continue with retained requests. Licence restrictions and pending deletion pause migration; final deletion overrides receipts and aborts access. Finishing clears only this content-maintenance restriction.

## Interrupted requests

Each mutation stores its exact signed ciphertext request locally before submission. The following calls support explicit recovery:

```ts
const pendingIds = await client.upgrades.pending();
const result = await client.upgrades.resume(pendingIds[0]);
```

Resume looks up the actor-bound receipt first. A committed request is verified against signed current history before its local pending copy is removed. An absent, unexpired request may be resent byte for byte; no fresh nonce or replacement payload is invented under the same operation ID. A `finishing` response keeps the pending request for later explicit resume while control-state projection is repaired.

`discard(operationId)` removes a local pending request only after the server confirms no receipt under current authority. An expired or conflicting request requires fresh review and a new operation ID. Reloads, failed signout, automatic session invalidation, and reconnects do not silently resend or erase pending work. Confirmed explicit signout clears that identity's business requests while retaining encrypted device wrappers and trust pins.

The HTTP endpoints are `POST /v1/upgrades/context`, `/start`, `/batch`, `/finish`, and `/status`. They use the existing authenticated cookie, exact Origin, CSRF, current authority, and workspace-fence rules. General business receipt discovery is available through `client.receipts.lookup`; acknowledgements alone never install keys or advance trust pins. See [job operations](job-operations.md) for bounded background retries and operator replay.

Verification and remaining release boundaries are recorded in [checkpoint 11 evidence](checkpoint-11-evidence.md).

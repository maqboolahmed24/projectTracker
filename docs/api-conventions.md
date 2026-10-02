# API and persistence conventions

The API uses `/v1`, opaque lowercase UUID references, and positive decimal strings for persistent revisions and security/data/key generations. A display name is encrypted content, never a credential identifier. Timestamps describing server events use UTC; private planned dates remain in encrypted records.

## Request validation and errors

JSON bodies are bounded to 1 MiB, with a maximum nesting depth of 64. Duplicate object keys, prototype-poisoning keys, malformed Unicode, non-finite numbers, unsupported algorithms and unknown envelope fields are rejected. Binary fields use canonical unpadded base64url. The initial content schema and envelope version are 1. `src/shared/contracts.ts` defines the wire format; `src/http.ts` checks structure and expected record context. Structural validation does not verify a signature or authorize a write: the security and domain operations must perform those checks before persistence.

Errors contain `{ "error": { "code", "message", "requestId" } }`. Request IDs are server-generated. Error messages contain no request values, underlying SQL, credentials or ciphertext contents.

| Code | HTTP status | Meaning |
| --- | --- | --- |
| `INVALID_REQUEST` / `INVALID_ENVELOPE_CONTEXT` | 400 | Malformed input or a record/context mismatch |
| `INVALID_RELATIONSHIP` | 400 | Database relation or integrity rule rejected the operation |
| `AUTH_REQUIRED` | 401 | An authenticated, approved-device session is required |
| `FORBIDDEN` | 403 | Current permissions do not allow the action |
| `NOT_FOUND` | 404 | Record unavailable in the caller's scope; no existence disclosure |
| `REVISION_CONFLICT` / `RECORD_CONFLICT` | 409 | Review the current record before a deliberate new operation |
| `STALE_GENERATION` / `SECURITY_STATE_CHANGED` | 409 | Refresh current authority/data state |
| `UNSUPPORTED_SCHEMA` | 409 | Update the client before writing |
| `RETRY_REQUIRED` | 409 | Retry the same operation bytes and identity |
| `WORKSPACE_RESTRICTED` | 423 | Writes are restricted by the current workspace mode |
| `SECURITY_FENCED` / `SECURITY_UNAVAILABLE` / `RESTORE_QUARANTINE` | 503 | Protected access is unavailable until trusted state is ready |

## Protected access

Only authentication middleware supplies a `DataPrincipal`. Request headers and bodies cannot select a database identity or assert a profile. The route workspace must match that authenticated principal. Until checkpoint 4 provides the actual authentication middleware, deployed protected routes return `AUTH_REQUIRED`; there is no development login bypass. Integration tests supply an explicit test-only authentication dependency to exercise persistence in isolation.

`dataTransaction` sets transaction-local workspace/profile context, holds the shared workspace advisory lock through the data operation, checks the application fence and latest control-store authority, and rejects stale projections or generations. Control-store failure denies protected reads. Security transitions must acquire the matching exclusive workspace lock before committing authority changes; the transition implementation and interruption tests belong to checkpoint 5.

PostgreSQL composite keys enforce tenant relationships. FORCE RLS protects data in depth using the runtime role. Workspace context cannot survive commit/rollback into another pooled request. Project content also requires active provisioned project access; task assignments and team memberships cannot grant it. A provider operator may inspect ciphertext with privileged database access but receives no client decryption key.

The read routes expose bounded pages of encrypted records, opaque relationships and allowed operational metadata. They use deterministic UUID cursors (maximum 100 records/page); each page is a new authorized transaction. A paginated read is not a consistent export or summary snapshot: later explicit snapshot protocols must validate completeness and revisions. API responses use `Cache-Control: no-store`; no shared content cache exists. Any future cache must include workspace, profile, data generation and current security head/version, as demonstrated by `scopedCacheKey`.

Mutations are explicit domain operations, not generic SQL/table endpoints. They will use expected revisions and stable operation IDs, record changes/audit/outbox/receipts in one application transaction, and return the prior result for an identical authorized retry. Those domain writes are implemented in their ordered checkpoints; a read transport is not a claim that the workflow is complete.

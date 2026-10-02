# Profile access and removal protocol

Checkpoint 6 supplies an Owner-authorized access-change service and headless browser controller. Its verification is recorded in [checkpoint 6 evidence](checkpoint-06-evidence.md); the existence of these endpoints alone does not complete the checkpoint.

## Supported operations

An approved Owner authenticated within the last five minutes can use `runtime.accessChanges`:

| Method | Result |
| --- | --- |
| `setAccess({accountId, roleId, projectIds, operationId?})` | Replace an active ordinary profile's current role and explicit project selection. |
| `demoteOwner({accountId, roleId, projectIds, operationId?})` | Convert an Owner to an ordinary profile, retaining only the selected ordinary access. |
| `suspend({accountId, operationId?})` | Suspend access, revoke sessions/devices and remove current responsibilities. |
| `reactivateMember({accountId, roleId, projectIds, operationId?})` | Reactivate a suspended person as an ordinary member. The password is retained; a new device approval is required. |
| `remove({accountId, operationId?})` | Permanently remove an active or suspended profile, clear its password registration and replace its current encrypted name with “Former member.” |
| `resume(operationId)` | Resolve an interrupted operation from its saved immutable draft and durable receipt. |
| `refreshKeys()` | Verify current signed history and decrypt the caller's currently authorized key delivery. |

Suspending or demoting an Owner retires their personal recovery authority. Reactivation cannot restore ownership: subsequent promotion requires the normal independent Owner setup and a fresh recovery phrase. Pending Owners never satisfy the last-active-Owner rule. The original licence activator has no special exception.

## Preparation and commit

The `/v1/auth/access-change/` routes expose `context`, `stage`, `finalize`, `status`, `history`, `delivery`, and `delivery/history`. Requests use strict schemas, origin checks and separate source/workspace/account/operation quotas. Normal administration and delivery require current approved sessions and CSRF verification.

The client and service independently replay the signed journal from the pinned genesis. They derive the same exact role snapshots, remaining scopes, device and recovery recipients, and required key epochs. The binding includes the current security head, account/device generations, ownership/custody versions, target state and a ten-minute preparation deadline. Unknown recipients, stale authority or incomplete ciphertext delivery cannot activate the change.

The Worker retains every historical ordinary key, generates fresh keys for scopes losing readers, and seals replacement material for eligible remaining recipients. An Owner departure or any content-key rotation also advances custody, delivering the new custody manifest separately to remaining Owner devices and personal recovery authorities. The departing Owner receives no new custody key. An ordinary demotion preserves the working password and healthy device identity but revokes the old session.

Before uploading, the browser persists and reads back the exact signed ciphertext draft. Finalization closes the application security fence, locks current workspace authority, rechecks it, and commits the journal, objects, role/access changes, revocations, key epochs and receipt together. Application projection updates access and cleans up assignments, leads and blocker responsibility before reopening the fence. Interrupted projection reports `finishing` and retains the committed receipt for recovery.

Another Owner can take over a pending intended change by preparing it under a fresh operation. After that commits, the original staged operation has a stale head and cannot apply. Immutable drafts are never silently rewritten to change their signer or scope.

## Lost replies and self-removal

Each draft contains a random 32-byte receipt capability; only its workspace/operation-bound hash is signed and sent to the service. A saved capability can retrieve that operation's bounded status and receipt after the acting Owner removes themselves or loses their session. It cannot retrieve history, content or keys, and it cannot authorize the first commit without an approved Owner session.

Remaining users refresh keys through authenticated delivery plus independently verified history. The Worker checks current personal and device scopes and unchanged credential/session/data generations before accepting newer public custody and security versions. Suspended or removed users cannot refresh keys. Retrying an interrupted operation reuses its original operation ID and ciphertext; controllers do not retry indefinitely.

## Scope boundaries

Role definitions and current assignments are separate: editing a custom role does not silently change an existing assignment. Current profile assignments refer to signed committed objects; project grants retain their role revision and effective permissions. Team membership and task assignment never grant project access.

Signed project-scope provisioning is a shared security primitive used by checkpoint-6 fixtures. Project creation and its business lifecycle belong to checkpoint 7. Checkpoints 7–12 must exercise their domain actions through the same permission, epoch, fence and revocation rules, and checkpoint 13 must verify the combined journey and independent release review.

Revocation prevents future service access and protects later ciphertext versions. Previously copied ciphertext, historical keys or plaintext cannot be erased from another person's possession. Owners remain trusted custodians of ordinary workspace content.

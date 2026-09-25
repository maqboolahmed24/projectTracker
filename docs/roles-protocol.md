# Custom role definitions

Checkpoint 6 is in progress. This protocol adds custom role definitions to the headless client; the integrated verification results are recorded in [checkpoint 6 evidence](checkpoint-06-evidence.md). Role assignment changes, suspension and access removal with key rotation remain separate required work.

## Client entry points

An unlocked Owner uses `openClient().roles`. Mutations require recent authentication through the existing authentication controller.

```js
const created = await client.roles.create({
  displayName: 'Client commenter',
  permissions: ['read_project', 'comment'],
});
const page = await client.roles.list({ limit: 50 });
await client.roles.update({
  roleId: created.roleId,
  displayName: 'Client reviewer',
  permissions: ['read_project', 'comment', 'approve_tasks'],
});
await client.roles.retire({ roleId: created.roleId });
```

The fixed catalogue is `read_project`, `comment`, `create_tasks`, `edit_assigned_tasks`, `manage_tasks`, `approve_tasks` and `plan_projects`. Every custom role requires `read_project`. Ownership and recovery authority are not checkboxes. Owner, Manager, Member and Viewer definitions are immutable templates.

Creating or editing a definition does not modify existing permission grants. Each active person/project assignment retains its signed role revision and permission snapshot until a separate signed access change is completed. Retirement requires the role to be unused by active people, project grants and pending invitations. A retired identity cannot be resurrected by replay or reused as a new role.

## Encryption and authority

Names are encrypted and signed inside the authentication Worker using the current ordinary workspace key. The API receives encrypted labels, public role permissions and signed authority metadata. List responses contain ciphertext; the Worker checks the exact role registry against independently pinned security history before decrypting names. Historical labels retain their original authenticated signer.

A change binds the workspace, origin, operation and role IDs, previous and next role revisions, current security head, data generation, ownership/custody/content epochs, and the approving Owner's exact account, device and credential/session generations. Its lifetime is ten minutes. Both client and service recheck current authority; builtins, unknown permissions and altered ciphertext fail closed.

## HTTP and interruption handling

Authenticated POST routes under `/v1/auth/roles/` are `context`, `stage`, `finalize`, `status`, `history` and `list`. They use the existing Secure session cookie, CSRF protection, exact-origin enforcement, strict schemas and durable request budgets.

Before staging, the client persists and reads back the exact signed ciphertext payload in origin-bound IndexedDB. It stores no raw role name, password or content key. The service stages immutable objects and reads back their hashes. Finalization closes the application fence, locks/rechecks current control authority, commits the role definition with its signed transition and durable receipt, then projects that state before reopening access.

Keep the operation ID returned by a successful operation, or supply one when creating a change. After an ambiguous network failure, discover locally retained IDs with `roles.pending()` and call `roles.resume(operationId)` after unlocking. Resume sends the same payload and resolves the existing receipt; it never silently replaces the name or permissions. A committed operation can report `finishing` until projection is repaired. A definitely expired or stale uncommitted operation needs a newly prepared operation. There is no automatic unbounded retry loop.

Restricted entitlement blocks new definition writes. Current authorized listing and recovery of committed results remain available. Logout cancels active work and clears usable keys; Forget removes matching locally retained role operations too. Security-removal commands and business APIs must continue to enforce their own current access and key-epoch checks.

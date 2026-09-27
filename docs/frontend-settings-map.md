# Frontend settings, people and administration map

Read-only audit of the existing implementation, 27 September 2026. This is a frontend integration map, not a new security certification. Source and existing browser scenarios were inspected; this audit did not run tests, modify source or operate the database. Paths below are repository-relative. The later frontend implementation and new directory reader are separate from this snapshot.

## Release and integration boundary

`architecture/archtecture.md` sections 2, 8, 10 and 11 are authoritative for the product scope; `architecture/checklist.md` records the completed backend delivery and explicitly excludes screens/styling. Settings contain people, teams, permissions and integrations. First release includes equal Owners, custom roles, private invitation/reset handoffs, individual recovery phrases, in-app notices, Owner export and workspace deletion. Email invitations/reset/delivery, GitHub, AI, customer-operated connectors/workers, imports and per-project exports are future work. They must not appear as functioning controls. Use accessible labelled inputs, keyboard operation, visible focus, text status and restrained colour.

`openClient()` in `src/client/runtime.ts` returns `auth`, `activation`, `passwordChanges`, `pairing`, `recoveries`, `enrolments`, `roles`, `accessChanges`, `projectCreation`, `teams`, `planning`, `collaboration`, `inbox`, `reporting`, `receipts`, `upgrades`, `exports`, `restoration`, `lifecycle`, `profiles`, `remembered`, and `close`. Use these composed controllers rather than reproducing signing, encryption, storage or HTTP transactions in React. Independently configured service public keys remain part of deployment trust.

`auth.current()` is `{session,localAccess:'pairing_required'|'unlocked'}`. The session contains workspace/account/device references, access level (`restricted` or `device_approved`), decimal-string credential/session/data generations, CSRF token and authenticated/expiry timestamps. It does **not** contain Owner status, workspace name or lifecycle. `auth.onClear` must clear rendered plaintext, passwords, phrase inputs and temporary export/link material. IDs are internal lookup/select values, never customer-facing names. `remembered.list()` is this browser's remembered identities, not a workspace roster. Forget removes local material; it is not remote device revocation.

## Existing controller surface

### Profile and avatars

`profiles.current()` returns `{workspaceId,accountId,revision,displayName,avatar:{shapeId,colourId}}` for the signed-in profile. The worker verifies the exact signed profile object, digest, revision and authority, and delivery is checked again after decryption. It uses `POST /v1/auth/access-change/delivery` with `includeProfile:true`; this only supplies the caller's profile. Do not use it for arbitrary people or use export as a roster workaround.

`GET /v1/avatars/catalog` is public and returns version 1, default selection, 20 shapes `{id,label,svg}`, 12 colours `{id,label,hex}`, and licence information: 240 selections. Assets are pinned local SVGs; there is no upload/remote-image API. Legacy profiles receive a display default without rewriting their signed history. Enrolment accepts the selection; there is no profile/name/avatar edit controller after enrolment in this snapshot.

### Roles and permissions

`roles.list({afterRoleId?,limit?})` returns `{roles,nextRoleId}`. Each readable role is `{id,template:'owner'|'manager'|'member'|'viewer'|'custom',revision,state:'active'|'retired',permissions,displayName}`. Listing and editing require current Owner authority and approved unlocked device context.

| Action | Exact controller call |
| --- | --- |
| Create custom role | `roles.create({displayName,permissions,roleId?,operationId?})` |
| Edit custom role | `roles.update({roleId,expectedRevision,displayName,permissions,operationId?})` |
| Retire custom role | `roles.retire({roleId,expectedRevision,operationId?})` |
| Find/resume local operation | `roles.pending()`; `roles.resume(operationId)` |

The response is `{operationId,roleId,state:'completed'|'finishing',receipt}`. HTTP routes are `POST /v1/auth/roles/{context,stage,finalize,status,history,list}`. Source signatures require `expectedRevision`; older prose examples may omit it.

Fixed permissions are `read_project`, `comment`, `create_tasks`, `edit_assigned_tasks`, `manage_tasks`, `approve_tasks`, `plan_projects`. Custom roles require `read_project`. Owner and Manager defaults have all seven, Member has the first four, Viewer only read. **Ownership is separate authority**, not an editable permission. Built-ins are immutable. Updating a role definition does not silently change existing grant revision snapshots: an Owner explicitly reapplies access. Retirement fails while active grants or invitations use the role.

### People, equal Owners and access

`accessChanges.refreshKeys()` returns only `{complete:true,scopeCount,securityHead,securityVersion,custodyEpoch,ownershipVersion}`; it is not a people reader.

| Action | Exact controller call |
| --- | --- |
| Set member role/project grants | `setAccess({accountId,roleId,projectIds,operationId?})` |
| Demote an Owner | `demoteOwner({accountId,roleId,projectIds,operationId?})` |
| Reactivate suspended member | `reactivateMember({accountId,roleId,projectIds,operationId?})` |
| Suspend / remove | `suspend({accountId,operationId?})`; `remove({accountId,operationId?})` |
| Resume | `pending()`; `resume(operationId)` |

These are methods on `accessChanges`. Result: `{operationId,targetAccountId,state:'completed'|'finishing',receipt,access:'ready'|'revoked'}`. HTTP: `POST /v1/auth/access-change/{context,stage,finalize,status,history,delivery,delivery/history}`. Actions require current approved Owner and recent authentication (five minutes). The first licence activator has no extra privilege. Last active Owner protection is enforced on the server; UI can explain a required successor but cannot replace enforcement.

Suspension removes sessions/devices and current responsibilities. Reactivation returns a member requiring new device approval, not restored ownership. Demotion retires Owner recovery, preserves the password/healthy device material and invalidates old sessions. Removal permanently revokes account access, clears current responsibility and uses “Former member”; shared/historical content remains. Self-removal and lost final acknowledgement resolve through the stored exact operation; `access:'revoked'` must return to sign-in. Restrictive security actions remain available during maintenance/pending deletion; expansion is blocked. Team membership or task assignment never grants access.

### Invitations and promotion

`enrolments.issueJoin({kind:'join_member'|'join_owner',roleId,projectIds,displayName,accountId?,operationId?})` returns `{workspaceId,accountId,operationId,invitationGeneration,code,expiresAt}`. `revokeJoin({workspaceId,operationId})` revokes it. Invitation code is twelve base32 symbols in `JOIN-XXXX-XXXX-XXXX` presentation, valid one hour including approval. No email is sent. Keep the returned code/link only in the issuing screen; do not log or store it as a general preference.

`beginPromotion(accountId,operationId?)` starts member-to-equal-Owner promotion. Recipient `claimPromotion(reference,password,localId?)`, `preparePromotion(localId,password,newOwnerKit)`, explicit full-fingerprint confirmation and Owner approval establish the new individual recovery authority. A role dropdown cannot promote someone. Promotion preserves the existing profile/avatar/password and healthy devices while invalidating prior sessions.

Recipient join flow is `beginJoin({workspaceId,code,genesisFingerprint?},localId?)`, `prepare(localId,password,confirmation,displayName,newOwnerKit?,avatar?)`, `confirmRecipient(localId,fullFingerprint,password?)`, then `resume(localId,newOwnerPhrase?)`. Approver flow is `claim(reference)`, explicit comparison, `approve(reference,fullFingerprint)`. `cancel(localId)` is recipient cancellation. New Owner kit is `{phrase,positions,answers}`; answers come from the human. A missing genesis fingerprint is acceptable only when an existing trusted pin supplies it.

Progress is `{localId,operation:{workspaceId,operationId}|null,state,fingerprint:string|null,deviceId:string|null}`. Resume adds `access:'pending'|'login_required'|'recovery_kit_required'|'content_ready'|'incomplete_keys'`. Public server states: issued, waiting_approval, verifying, confirmed, completed, finishing, cancelled, revoked, expired. After commit, sign in and prove the device; content is ready only after verified delivery. A second Owner can take over approval, which resets the attempt and requires a fresh full fingerprint check. Local exact encrypted drafts survive interruption; postcommit resume is bounded (24 hours).

`enrolments.operations.list()` exposes local metadata `{role,localId,workspaceId,accountId|null,operationId|null,state}`. It is not a server-wide pending-invitation directory. Routes are under `POST /v1/auth/enrolment/`: join context/history/issue/revoke/begin, promotion begin/claim/stage, claim, inspect, registration, proof start/finish, unlock start/finish, confirm, materials, stage, finalize, status, cancel, delivery, history. Controllers select the appropriate authenticated or recipient-capability flow.

### Password, devices and recovery

| Journey | Existing surface and required behaviour |
| --- | --- |
| Recent authentication | `auth.reauthenticate(password)`; clear password immediately after attempt |
| Password change | `passwordChanges.begin(workspaceId,operationId?)`, `prepare(operationId,newPassword,confirmation)`, `complete(operationId,newPassword)`, `resume(operationId,authenticated?)`, `cancel(operationId)` |
| Approve another browser | `pairing.begin(operationId?)`, `confirmRecipient(operationId,fullFingerprint)`, approver `claim`, `confirmApprover`, `approve`, recipient `resumeRecipient(operationId,displayName?)` |
| Owner-assisted reset | `recoveries.issueReset(accountId,resetId?)` returns `{workspaceId,accountId,resetId,code,resetGeneration,expiresAt}`; `revokeReset(workspaceId,resetId)` |
| Reset recipient | `beginReset(workspaceId,code,localId?)`, `prepare(localId,password,confirmation,newOwnerKit?)`, explicit recipient/Owner confirmation, `resume(localId,newOwnerPhrase?)` |
| Owner phrase recovery | `beginPhrase(kitIdentity,localId?)`, `provePhrase(localId,phrase)`, prepare new password/new kit, confirm, `approvePhrase(localId,fullFingerprint,oldPhrase,password?)`, resume |

Password result is `{state:'completed'|'finishing',receipt}`. Status is `{state:'issued'|'completed'|'finishing'|'cancelled'|'expired'|'revoked',binding,resumeExpiresAt,requestHash?,receipt?}`. Success invalidates the session: prompt sign-in with the new password. The password store has a list method but the controller does not expose a pending-list wrapper in this snapshot.

Reset code is `RESET-XXXX-XXXX-XXXX`, fifteen minutes, one recipient. Owner reset requires recent authentication, can target an equal Owner and does not promote members. Owner phrase is 24 words, independent of password; `recovery.newOwnerPhrase()` and `recovery.recoveryChallenge()` generate it and the three-word human verification challenge. Recovery kit identity is origin/workspace/account/genesis fingerprint. Never insert expected challenge answers automatically. Full ceremony fingerprint is 64 hex characters; do not substitute the short invite/reset code. Recovery rotates personal phrase and revokes old devices. It does not bypass current removal, deletion or ownership.

`recoveries.operations.list()` and `pairing.store.list()` expose local pending metadata. Pairing states add `content_ready` after delivery. There is no customer device-name/last-seen list, revoke-one-device, remote-session list or sign-out-all controller in this snapshot. Forget is strictly local. The current phrase cannot be redisplayed; it exists only when generated or supplied by the user. No independent “show current kit” or “rotate phrase” settings action exists.

### Teams

`teams.list({after?,limit?})` returns `{records:[{teamId,revision,name,description,memberIds}],nextCursor,securityHead,securityVersion,dataGeneration}`. `create({name,description?,memberIds?,operationId?,teamId?})`; `edit({teamId,expectedRevision,name,description?,memberIds?,operationId?})`. Create/edit are Owner actions. Preserve the displayed description and member set when editing; optional defaults must not accidentally clear them. Result is `{operationId,teamId,state:'completed',receipt}`. `pending()` and `resume(operationId)` recover exact saved drafts.

`history(teamId)` returns `{workspaceId,teamId,anchor,records}`. Each readable change contains revision, operation/actor/device references, action create/update/upgrade_content, signedAt (nullable), serverRecordedAt, before (nullable) and after `{name,description,memberIds}`. Resolve IDs through authorised directory labels. History is bounded to 512 revisions. HTTP: `POST /v1/work/teams/{context,save,status,list,history}`. No team delete/archive exists. Teams group people; membership never grants project access.

### Workspace timezone

`reporting.settings()` returns `{workspaceId,timezone:string|null,revision,head,pin}`. The pin is `{workspaceId,revision,head,initialDigest,dataGeneration}`. Read, display, and preserve that exact pin for `setTimezone(timezone,pin,operationId?)`. Do not manufacture a pin or auto-submit the browser zone. Missing review produces `REVIEW_REQUIRED`; stale review gives `WriteConflict` with current settings and the unsaved choice. An initial null requires explicit selection. Existing closing snapshots retain their timezone.

HTTP: `POST /v1/reporting/settings`, `/settings/context`, `/settings/save`; controller `resume(operationId)` and `pending()` use the reporting status machinery. IANA zone names are required.

### Export, erasure and workspace deletion

`exports.generate({acknowledgePlaintext:true,exportId?})` returns `{filename,mimeType:'application/json;charset=utf-8',json,receipt}`. Present `exports.notice`, require explicit plaintext acknowledgement and recent Owner authentication. Download only a completely successful result, revoke the Blob URL and discard JSON on completion/sign-out. HTTP: `POST /v1/export/{start,page,finalize}`. The final authority/completeness check aborts after revocation or inconsistent records. Export includes ordinary readable data/history, not credentials, key material or a restorable backup. Owner export remains available during pending deletion.

`lifecycle.requestDeletion(confirmationName,operationId?)`, `cancelDeletion(operationId?)`, `requestErasure(operationId?)`, `erasures()`, `pending()`, `resume(operationId)` use `POST /v1/lifecycle/{context,save,status,erasures}`. View is `{state:'absent'|'finishing'|'completed',receipt:null|receipt}`; receipt includes action, committedAt and `deletion:{requestId,requestedAt,deleteAfter}|null` plus verified security references.

The workspace confirmation name is compared locally with verified encrypted content, never sent in plaintext. Any equal active Owner may request or cancel before the deadline. Pending deletion is 168 hours in UTC, ordinary content read-only; read/export/recovery/revocation remain available. Cancellation preserves any other restriction. At the deadline it is irreversible even if a worker is late. Live purge is within 24 hours of deadline; protected backups expire within 30 days after live purge; exported copies cannot be recalled.

`erasures()` returns `{workspaceId,requests:[{requestId,accountId,state:'requested'|'fulfilled',requestedAt,fulfilledAt:null|string,needsSuccessor}]}`. Owners see all; a member sees their own. This is a request, not automatic account removal. An Owner fulfils through signed removal; the last Owner first needs a successor or whole-workspace deletion. Shared content/historical embedded names are not rewritten.

### Encrypted upgrades, restoration and interruptions

`upgrades.progress(migrationId?)` returns `{state:'available'|'active'|'paused'|'completed'|'aborted',migrationId,completed,total,writeSchema}`. `start(operationId?)`, `advance(migrationId,operationId?)`, `finish(migrationId,operationId?)`, `pending()`, `resume(operationId)`, `discard(operationId)` are the actual operations. Advance performs one bounded batch and may return `ready_to_finish`. Operation result `state:'completed'|'finishing'` describes that operation, not the overall upgrade. HTTP: `POST /v1/upgrades/{context,start,batch,finish,status}`.

Show scope, completed/total, paused reason and explicit Continue. Do not run an unlimited background loop. Ordinary writes remain paused until verified finish and any other restrictions clear. Another current Owner can continue using fresh authority. Stale batches require review; discard only applies to an absent local draft, never undoing an acknowledged commit. Pending deletion/licence restriction pauses; deletion aborts.

`restoration.inspect(restoreId)` returns `{workspaceId,restoreId,recoveredAt,dataGeneration,verifiedSamples,verifiedEpochs,missingRecords,contentAfterCheckpoint:'unverified_or_missing'}`. `verify(restoreId,true,operationId?)` requires explicit acknowledgement of missing later content. `pending()` and `resume(operationId)` handle interruptions. HTTP: `POST /v1/restoration/{context,verify,status}`. Operator initiates restoration; settings only lets a currently authorised Owner inspect/verify a quarantined restore. Do not provide backup operation controls or revive authority from a restored snapshot. Missing content must be shown before reopening.

Across controllers, persisted exact signed/encrypted drafts resolve lost replies without creating duplicate operations. Do not automatically rebase conflicts or queue writes offline. `WriteError` codes are OFFLINE, CONFLICT, REVIEW_REQUIRED, UPDATE_REQUIRED, RESTRICTED, RETRY_REQUIRED and STORAGE. `WriteConflict` includes operationId, current verified data and unsaved input; keep plaintext unsaved input only in memory. Explain a fresh review and preserve entered text where permitted. Security ceremonies retain their drafts over logout; business-operation stores are cleared by the runtime's sign-out/Forget lifecycle. Display pending work before issuing a replacement mutation.

## Missing read composition and smallest extensions

1. **Verified workspace and people directory.** Required for workspace name, own Owner status, people labels/avatars/status/role revisions/project grants and named task/team choices. Security history already verifies current profiles, devices, roles, licence, lifecycle, deletion, write schema and active upgrade/restore, but no composed readable overview exists. Add a worker-verified authorised reader joining exact signed encrypted profile/workspace references with current authority, and recheck delivery before exposing plaintext. Restrict ordinary-member visibility to the chosen authorised people policy; do not simply return every encrypted profile. Root owns this extension.
2. **Server pending enrolment list.** Local stores cannot discover ceremonies issued by another Owner/browser. Smallest design: authenticated `POST /v1/auth/enrolment/list {workspaceId,after?,limit<=50}`, current approved active Owner guard, bounded stable pagination over existing `security.ceremonies` of kind invitation/owner_promotion joined to current profile/invitation generation. Return only operationId, accountId, kind, state, expiresAt, issuerAccountId and current authorizerAccountId if needed. Honour current authority, generation and elapsed expiry in the read. Do not return `public_state` wholesale, code digests, raw code, capability, staged records or resume token. Customer label comes from verified directory. Existing claim/status/approve/revoke endpoints remain authoritative. No new table is required just for this directory.
3. **Restriction and restore discovery.** The directory should include verified lifecycle, deletion deadline, licence state, write schema, active upgrade ID and active restore ID. A historic local receipt is not current authority. Quarantined Owners need a narrow authenticated way to discover their current restore ID without normal content access.
4. **Password-change pending wrapper.** Existing local store supports listing; expose a narrow controller wrapper if the password panel must rediscover pending changes after reload. Do not persist the password or copy private drafts into UI storage.
5. **Absent mutations, not hidden HTTP APIs.** Profile/name/avatar editing, remote device revocation/list, team deletion/archive, redisplay of an existing phrase, and workspace renaming are not implemented. Avoid controls that imply these succeed. Future integration categories must be clearly unavailable. Implementation scope decisions belong to the main task; this map does not introduce substitute unsafe actions.

## Required customer journeys and existing scenario evidence

These are existing source scenarios inspected, not tests executed during this audit:

| Journey | Existing browser source |
| --- | --- |
| Login, logout, Forget, lost password-change reply and reload | `test/browser/authentication.spec.ts` |
| Named member invite, Owner promotion, interrupted join, equal-Owner takeover | `test/browser/enrolment.spec.ts` |
| Owner reset with explicit comparison and replacement recovery kit | `test/browser/recovery.spec.ts` |
| Custom role create/edit/retire, grant snapshots, interrupted writes | `test/browser/roles.spec.ts` |
| Revoke project access, suspend/reactivate, demotion, self-removal lost reply | `test/browser/access-change.spec.ts` |
| Team create/edit/list/history, lost save and local resume | `test/browser/teams.spec.ts` |
| Explicit timezone review and client reporting | `test/browser/reporting.spec.ts` |
| Plaintext export acknowledgement and final current-authority gate | `test/browser/export.spec.ts` |
| Wrong-name deletion refusal, lost reply, reload, equal-Owner cancellation, reads/export before deadline | `test/browser/lifecycle.spec.ts` |
| Quarantined restore proof and lost acknowledgement | `test/browser/restoration.spec.ts` |
| Interrupted upgrade and continuation by another Owner | `test/browser/upgrades.spec.ts` |
| Composed release workflow | `test/browser/core-journey.spec.ts` |

Browser fixtures inject trusted setup/test material; production UI must use normal activation, login, pairing and human confirmation paths. Backend state enforcement remains authoritative when a screen's directory data becomes stale. The frontend should offer permission-appropriate actions, refresh after security changes, show finishing/resume distinctly from success, and never translate an arbitrary exception into a successful save.

## Subsequent implementation handoff

After the read-only snapshot above, the parent task authorised the minimal pending-enrolment reader and settings implementation. `POST /v1/auth/enrolment/list` and `enrolments.listInvitations({after?,limit?})` now return `{workspaceId,observedAt,invitations,nextCursor}`. Each invitation is exactly `{operationId,accountId,kind,state,expiresAt,issuerAccountId,authorizerAccountId}`. Only live issued/waiting ceremonies in the target's current invitation/credential generation are returned. Every page requires same-origin/CSRF, current approved active Owner, recent authentication and current personal/device scope coverage; restore quarantine is denied. Server query and strict response omit all secret, staged and raw-code fields. Ordinary expiry drops a request from the next list. The list is discovery metadata; the existing approval controllers still verify and recheck current signed authority.

Focused service and route scenarios were added to `test/enrolment.test.ts` and `test/enrolment-routes.test.ts` with the `frontend:` prefix. They cover paging, sanitisation, replacement/revocation/expiry, generation mismatch, foreign tenant, non-Owner, stale authentication and strict origin/CSRF/input boundaries. Execution and integration validation belong to the parent task and were pending at this handoff.

`frontend/settings/index.tsx` exports `SettingsArea({section?})` and `RestorePanel({restoreId,onDone?})`. Settings integrate the shared app directory/context, identity approval/password components, roles, people/access, teams/history, timezone, export, lifecycle, saved-operation continuation and explicit bounded upgrades. Quarantine renders only recovery review/continuation. Reviewed dialog fields are frozen after the first authenticated mutation attempt so a retry cannot display new inputs while submitting an old saved draft. Unsupported edit mutations are omitted; future integration categories remain explicitly unavailable. No database service was operated during this work, and no migration was added for these screens.

## Product verification follow-up

The later frontend test pass used the packaged Next application and its real same-origin proxy with isolated database-backed fixtures. `test-results/frontend-settings-evidence.json` records nine distinct passing customer journeys across Chromium, Firefox and WebKit, with the full reports retained alongside it. These cover interrupted role/deletion saves, reviewed permissions and timezone, teams/history, invitation revocation, export acknowledgement, explicit update continuation/finish and verified completion after reload. A separate identity matrix covers the new-device link, password change, member reset and equal-Owner setup.

Post-save view refresh errors are separated from confirmed mutation results. A completed confirmation closes with a clear refresh notice when only its follow-up read fails; a finishing result directs the person to continue the original saved attempt. A finished content update is recognised after reload from the current signed directory schema and absence of an active update, avoiding an invalid request to start a prior-format update. These fixes and their retained diagnostic failures are recorded in `docs/reviews/frontend-security-review.md`.

Integrations show eleven muted, disabled feature cards, each explicitly stating **Not available in this build.** These include email, GitHub, AI, boards, attachments, mentions/channels, dependencies/scheduling, risk register, forecasts/workload (including weighted progress and comparisons), external connectors and customer-hosted processing. They are placeholders, not enabled integrations or external communications.

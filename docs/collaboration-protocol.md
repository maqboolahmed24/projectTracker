# Comments, updates and Inbox

Checkpoint 9 is verified; see [its evidence record](checkpoint-09-evidence.md). These APIs are part of the headless browser runtime returned by `openClient()`. The hosted worker must run for ordinary notification delivery. No email service is required.

## Discussion and retained history

```js
const comment = await client.collaboration.postComment({ projectId, taskId, text: 'Ready for review.' });
await client.collaboration.postUpdate({ projectId, text: 'The pilot is underway.' });
await client.collaboration.postUpdate({ projectId, phaseId, text: 'The first wave is underway.' });
const page = await client.collaboration.read({ projectId, kind: 'comment', taskId });
```

Text is plain text encrypted in the browser. Corrections are new entries. Independent post IDs allow concurrent comments without consuming the planning revision. Task comments remain attached to the same task when it moves to another wave. A feed has bounded pages; follow its continuation and snapshot anchor, and refresh if the feed changes during pagination.

Posting requires `comment` and an editable parent scope. A task in Done or Cancelled, a terminal wave/project, and an archived scope reject new posts. Moderation remains possible in terminal and archived scopes:

```js
await client.collaboration.hide({ projectId, kind: 'comment', entryId: comment.entryId, reason: 'Duplicate entry.' });
const retained = await client.collaboration.history({ projectId, kind: 'comment', entryId: comment.entryId });
```

Task-comment moderation requires `manage_tasks`; project/wave-update moderation requires `plan_projects`. Hiding retains the signed original and encrypted reason in authorised history. It does not erase previously delivered data or remove a planning outcome from its closing snapshot. There is no edit or unhide action. Every history request rechecks current person and device access.

After a lost post reply, use `pending()` and `resume(operationId)` to resolve its existing receipt. Do not create a new operation until the previous outcome is known. Encrypted collaboration drafts use the same device-scoped storage and Forget behaviour as planning.

## Business audit history

`client.teams.history(teamId)` reads and verifies the retained team revision chain, including the actor, action, membership and decrypted before/after content. New team changes sign their time. Earlier v1 changes remain verifiable and report `signedAt: null` beside their explicitly server-recorded timestamp; they do not acquire a fabricated historical signature. Team history is bounded and rejects an incomplete or changed chain.

Planning's readable audits include the actor, device, action and signed time from each verified mutation, alongside the decrypted audit values. Historical keys verify earlier changes even when that signer is no longer allowed to write. Current authority still controls whether the caller can retrieve the history.

## Personal Inbox

```js
const inbox = await client.inbox.list({ unreadOnly: true, limit: 50 });
if (inbox.records.length) {
  const notice = inbox.records[0];
  await client.inbox.setRead([{ id: notice.id, expectedRevision: notice.revision }], true);
  const current = await client.inbox.resolve(notice.id);
}
const preference = await client.inbox.preference(projectId);
await client.inbox.setProjectMuted(projectId, true, preference.revision);
```

Assignments, comments and task-state changes notify affected assignees; Review notifies its named reviewer. Ordinary self-notices are excluded. Access, recovery and ownership notices reach affected active people and active Owners even when a project is muted. Permission changes to a custom role count as access changes.

Notices contain only opaque references. Fetch and decrypt their referenced content using the appropriate current-access controller. If person or device project access has ended, the Inbox returns `content.unavailable` with no project or record reference. This generic personal receipt can still be marked read. The Inbox controller does not persist notice details or decrypted content.

Read flags and mute changes use signed revision checks and exact operation receipts. A conflict requires reloading the current setting. `resume(operationId)` resolves an uncertain preference write while its in-memory draft is available; after a reload, fetch the current settings. Inbox preferences contain no private business content.

## Transport and worker

Exact-origin POST routes under `/v1/collaboration/` provide `context`, `save`, `status`, `list` and `history`. `/v1/inbox/` provides `context`, `save`, `status`, `list`, `resolve` and `preference`. All require an approved session and CSRF token; responses are not cacheable.

Business changes, immutable history, receipts, outbox descriptors and notification jobs commit together. Delivery failures delay the notice without rerunning the business action. Jobs recheck current recipient access and mute state, and stable event/recipient identities prevent duplicate delivery. Ordinary notification delivery starts with this implementation's new events; older outboxes do not invent historical recipients.

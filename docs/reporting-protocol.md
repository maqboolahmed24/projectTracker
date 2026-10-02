# Progress, reporting and live refresh

Checkpoint 10 is verified. See [its verification record](checkpoint-10-evidence.md)
for executed checks and remaining release gates. This module provides a headless browser API;
it does not add frontend screens.

After opening the existing client runtime and unlocking an approved profile:

```ts
const scope = { kind: 'project' as const, projectId };
const report = await client.reporting.calculate(scope);
const receipt = await client.reporting.publish(scope); // Owner/scoped planner
const cached = await client.reporting.read(scope);

const watch = client.reporting.watch(scope, state => {
  // state.value is present only when current. Last-known results are separately
  // labelled in state.lastCalculated; currentHealth then reports insufficient information.
  renderReportingState(state);
});
watch.stop(); // Also detached when the authenticated runtime clears.
```

Scopes support a project, phase, milestone, explicitly filtered task IDs, or an
explicit list of visible projects. A team scope combines team-designated tasks
only in its supplied visible project list. Project IDs and filter IDs are
canonicalised. An inaccessible project makes the request fail; no hidden project
count is returned. The starter supports at most 16 selected projects per request,
within the existing complete-project record/history limits and a 32 MiB response
budget. It does not silently truncate an aggregate.

All readers can calculate locally. Publishing requires current `plan_projects`
permission in every selected project. Each project component is encrypted with
that project's content key. The signed summary binds the exact scope, visible
permission vector, complete source manifest, security/data generations, key
epochs, settings revision, calculation version and server calculation time.
Readers independently recalculate a cache before accepting it as current.

`calculate` requires complete, verified and decrypted source data. `read` returns
`current`, `last-calculated`, or `missing`; stale cached values are historical
results, not current health. The live wrapper marks disconnected values as
last-known and current health as `not_enough_information`.

An Owner changes the workspace timezone with:

```ts
await client.reporting.setTimezone('Europe/London');
```

The initial timezone is verified from the signed, encrypted activation record.
Missing historical values remain unrecorded. Later changes form a signed Owner
history and preserve every entered date. New closing operations retain an
authenticated settings stamp alongside their signed mutation and encrypted audit.
Their original timezone does not change when current settings change. Legacy
snapshot graph bytes and signatures are preserved.

Live updates use `POST /v1/work/live`, a cookie-authenticated SSE stream with CSRF
in a header. Every batch rechecks current session/device scope. Frames contain
only a metadata fingerprint and observation time, and cannot prove a report is
current. Streams expire after five minutes; visible views use a sixty-second
refresh/reconnect fallback. Local planning/settings writes, refocus and the next
workspace midnight also invalidate the current calculation. Hidden views stop
refreshing. Stream credentials never appear in URLs.

Reporting request drafts currently live in memory. `pending()` lists their IDs;
`resume(operationId)` checks the exact receipt before retransmitting the same
signed payload. These drafts and plaintext reports are cleared when authentication
clears. Reload does not retain reporting drafts. The broader durable retry and
upgrade acceptance work remains in checkpoint 11.

The first release has task-count progress, deadlines, blockers, health signals
and next milestones. It does not include weighted progress, forecasts, email,
scheduled reminders, AI, external connectors or customer-operated workers.

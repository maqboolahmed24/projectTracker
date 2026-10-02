# Hosted job operations

Run these commands from the configured application directory with its restricted runtime database credentials:

```sh
npm run jobs -- metrics
npm run jobs -- failed
npm run jobs -- failed <last-job-id>
npm run jobs -- replay <job-id>
```

`failed` returns at most 50 failed jobs, an optional next-page cursor, their opaque workspace/generation references, attempts, and safe timestamps. It never returns payloads, content names, credentials, or raw exceptions. `replay` accepts only a failed, unlocked, recognised hosted job and resets its attempt budget to ten while retaining its original physical ID, deduplication key, and payload. A concurrent replay cannot reset a running job. Deleted workspaces and obsolete data generations cannot be replayed. Delivery still rechecks current recipients and permissions before any effect.

Notification delivery, activation projection, and request-budget cleanup use ten automatic attempts. On each retryable failure, the task waits a random 0–1,000 milliseconds before emitting the fixed error `JOB_RETRYABLE`. Graphile then persists its native delay of `exp(min(attempt, 10))` seconds. The random wait varies the next retry time; the exponential part is capped at about 6.12 hours. Attempt ten remains failed until an operator deliberately replays it. The completed business transaction is never repeated by notification retries.

Scheduled cleanup accepts Graphile's `_cron` timestamp/backfill metadata; manual cleanup uses an empty payload. Both prune only expired request budgets and authentication attempts. Unknown payload fields and malformed scheduler metadata fail validation and are recorded through the same sanitised job-error path.

Graphile's persisted queue state is authoritative for execution. Notification failure state is also mirrored to the application's outbox. The installed 0.18 implementation emits its completion event before batched failure SQL necessarily finishes, so the worker polls only those exact pending failure IDs once per second until persisted. Startup repairs missed mirrors after a process interruption. Replay and mirroring share a per-job lock, and replay resets the outbox and queue in one application transaction. The implementation uses Graphile's public jobs view and administration functions; it does not mutate private queue tables.

The worker's internal `GET /health/queue` endpoint reports pending count, failed count, and the oldest pending age. A running final attempt counts as pending. A database failure returns HTTP 503 with `status: unavailable`, never a false zero. This port is not published by the local Compose configuration. `/health/ready` separately reports worker/database readiness.

Replay a failed job only after addressing its operational cause. These tools do not release active worker locks or override scope checks. For database or queue outages, restore connectivity before retrying the same operation.

Reference: [Graphile retry backoff](https://worker.graphile.org/docs/exponential-backoff), [public administration functions](https://worker.graphile.org/docs/admin-functions), and [jobs view](https://worker.graphile.org/docs/jobs-view). The installed package's event ordering and zero-attempt SQL behaviour are covered by the focused CP11 queue tests.

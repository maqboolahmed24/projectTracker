# Recovery operations

Checkpoint 12 is verified. Physical PITR, current-authority reconciliation, Owner verification, physical purge, replication failure, real repository expiry, scheduling, regressions and the matching local runtime passed. Measurements and limits are in [checkpoint-12-evidence.md](checkpoint-12-evidence.md); checkpoint 13 remains required.

## Local infrastructure

Use Node 24.19–24.x, Docker Compose, the installed locked dependencies and the built application. Work from the repository root. Keep `.env`, `.env.admin` and `.env.identity` separate: the recovery operator loads all three; API and queue workers never load admin database credentials. Set a stable UUID as `UKDA_OPERATOR_ID` in `.env.admin` for operator attribution. The example contains a public development identifier.

```sh
docker build -t ukda-postgres-recovery:18-2.59.1 ops/postgres
npm run backup:setup
npm run backup:physical -- backup
npm run backup:physical -- verify
npm run backup:physical -- metrics
```

Setup preserves existing database volumes, creates separate private repository credentials under `.local/recovery`, enables continuous WAL archiving and seeds a separate security replica. It enables synchronous acknowledgement after the standby is streaming. A replica outage blocks security commits; do not disable that protection to make a health check green. A failed seed is retained for inspection, not automatically erased and retried.

Once enabled, always include the recovery overlay when operating this local stack:

```sh
docker compose -f compose.yaml -f compose.recovery.yaml --profile app up -d --build --wait
docker compose -f compose.yaml -f compose.recovery.yaml --profile app stop api worker
```

Do not subsequently start the primary databases with the base Compose file alone: that configuration does not mount the repositories or run the archiver. Keep the original volumes when stopping services. Never use `down --volumes` for retained work.

These repositories and the synchronous replica reside on one development computer. Production requires independent storage/failure domains and its own verified provisioning; local Docker evidence is not a claim of disaster durability.

## Checkpoints and restoration

The operational entry point is `npm run recovery -- <command>`. It uses the same signed restore service as the application, with separate maintenance credentials. Run one supervised operator daemon alongside the API and hosted queue worker:

```sh
npm run recovery -- daemon
```

Each tick is bounded. It enforces retention before backup work, finalizes due deletions and completes their purge, refreshes full backups daily, and captures signed content checkpoints every five minutes against an existing usable full backup. A failed or incomplete capture is never advertised as usable. `npm run recovery -- tick` performs one explicit tick. Read `/health/recovery` on the internal queue-worker listener for measured backup age, WAL lag, oldest usable active-workspace checkpoint age, synchronous replica state and last completed restore drill. Missing or stale evidence returns 503; fresh WAL alone or a physical probe does not prove the complete Owner recovery path.

For an explicit checkpoint or workspace restore, replace the arguments with the printed opaque identifiers:

```sh
npm run recovery -- checkpoint WORKSPACE_UUID
npm run recovery -- restore WORKSPACE_UUID CHECKPOINT_UUID
```

A usable full application backup precedes each captured named WAL point; frequent checkpoints reuse that daily base. The manifest is captured while that workspace's write fence is held; it includes the selected encrypted objects and key-envelope inventory. Its WAL boundary must be archived before the encrypted sidecar is published under `.local/recovery-records`. Preserve both these records and the matching physical repository, along with their separately protected operational secrets. This starter operator supports at most 100 active workspaces per tick and a bounded 2,000,000-file sidecar inventory; exceeding a bound reports a failure instead of silently skipping data. This is not a throughput guarantee for 100 busy workspaces.

Restore creates an isolated, network-disabled database, verifies the signed inventory and installs only the selected workspace's allowlisted application rows. Current security authority is never replaced by an older control backup. The workspace remains quarantined until a current approved Owner authenticates, calls `client.restoration.inspect(restoreId)`, reviews missing content and explicitly calls `client.restoration.verify(restoreId, true)`. Its Worker decrypts the selected current and historical samples. A missing key, unsupported schema, stale authority or failed proof keeps quarantine closed. The operator cannot mint Owner authority or decryption keys.

On a command failure, inspect its stage, current restore record and retained process/container state before retrying. A lost response may have committed a signed transition. Never substitute an old Owner or an old control snapshot to reopen service.

## Deletion and retention

The signed deletion request uses its recorded server-issued `requestedAt` and returns the exact `deleteAfter`, 168 hours later in UTC. The context is accepted for at most five minutes; `committedAt` separately records acceptance. Any current Owner may cancel before the deadline. At and after the deadline, protected routes deny access even if the operator tick was delayed.

`npm run recovery -- purge WORKSPACE_UUID` requires the existing irreversible tombstone. It deletes logical payloads using privileged database functions, compacts the affected physical tables, confirms an archived WAL boundary, removes retained workspace sidecars and owned isolated recovery artifacts, then records physical completion. An interrupted purge blocks subsequent ordinary backup creation until resumed. The final phase creates clean full backups; this does not rewrite shared work in other workspaces.

Daily backups normally retain thirty days of recovery history. Deletion expiry is a hard boundary: old sets containing deleted payloads must expire by thirty days after physical purge. Removal starts with a one-day safety margin and never waits for a replacement full backup. The operator checks backup **start** times, so an overlapping backup is treated as contaminated. If no clean full exists, it retires the affected repository stanza, preserves the live database, and reports degraded recovery until a new clean backup succeeds. Both stores are sanitized before replacement backups start. Live data and current security tombstones are independent of backup-set expiration. Customer-created plaintext exports cannot be recalled.

Ordinary ticks remove only verified-owned isolated restore containers and volumes older than 24 hours. Purge and completed composed restores remove those owned copies immediately; failed standalone drills are retained only for bounded inspection. Sidecars expire conservatively before the 30-day boundary. Never place unrelated containers or volumes under the operator's reserved `ukda-recovery-*` names/labels.

## Reproducible local drills

Run these explicit operational drills with the recovery stack available and the application built. They use fixture data; keep the normal API/queue worker stopped while running them. Use `UKDA_DOCKER=/absolute/path/to/docker` if Docker is not on the executable path.

```sh
node --env-file-if-exists=.env --env-file-if-exists=.env.admin scripts/drill-physical-recovery.mjs
node --env-file-if-exists=.env --env-file-if-exists=.env.admin scripts/drill-recovery-failures.mjs
node --env-file-if-exists=.env --test scripts/drill-composed-recovery.mjs
node --env-file-if-exists=.env --test scripts/drill-checkpoint-schedule.mjs
node scripts/drill-retention-recovery.mjs
```

The composed drill uses the production checkpoint/restore/purge commands with fixture service keys and real databases, encrypted repositories, WAL replay and Owner crypto. Its deletion deadline clock is advanced explicitly; it does not pretend to wait seven days. The isolated retention drill likewise accelerates only policy time and executes real pgBackRest expiration/retirement against newly created throwaway resources. The replication-failure drill deliberately interrupts the local security replica and verifies that an acknowledged write cannot bypass synchronous durability. JSON evidence is stored under `test-results/`; these small local measurements do not establish production RPO/RTO or independent-host durability.

Keep `.env.identity`, repository credentials and deployment configuration in a separately protected operational backup. Neither the repositories nor these service secrets can replace an Owner's customer-side key/recovery material.

The database procedures follow [PostgreSQL physical recovery](https://www.postgresql.org/docs/18/continuous-archiving.html), [synchronous replication](https://www.postgresql.org/docs/18/warm-standby.html#SYNCHRONOUS-REPLICATION) and [pgBackRest retention](https://pgbackrest.org/configuration.html#section-repository/option-repo-retention-full-type). Product acceptance is based on the repository's recorded drills, not the target recovery times alone.

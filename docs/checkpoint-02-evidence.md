# Checkpoint 2 — verified persistence and API conventions

Verified 2026-09-24T22:09:41.076022+00:00 in the local macOS arm64 workspace with PostgreSQL 18 in Docker, bundled Node 24.19.0 for tests and Node 24.20.0 for container builds.

Source-set SHA-256: `24f9a5e6031350bfb67df41abf6d6f3945500780aa00f10874ff4a3e8227aeef`. Input: sorted TypeScript files under `src`, `scripts`, `test`; SQL files under `migrations`; `package.json` and `package-lock.json`, with each UTF-8 path and file separated by NUL bytes. Working files remain uncommitted.

## Implementation

- `migrations/application/001_core.sql`: 21 application tables, encrypted content columns, composite tenant/project relationships, FORCE RLS, provisioned project-read policy, assignment/lead/phase integrity, immutable history and receipts.
- `migrations/control/001_security.sql`: separate authoritative security schema, 11 tenant tables with FORCE RLS and two explicitly service-only preactivation tables, security identities/generations, public grants, protected verifiers, sessions, immutable staged objects and tombstones. These tables do not themselves implement authentication/recovery.
- `src/migrations.ts`, `scripts/migrate.ts`: privileged migration execution, checksum/history ledger, one locked transaction per store, safe replay, minimum runtime grants and sanitized failures. No cross-database transaction is claimed.
- `src/persistence.ts`: transaction-local tenant/profile binding, shared workspace lock, fence/current-head/current-generation checks, restricted-write guard and scoped cache identity. No shared response cache is enabled.
- `src/shared/json.ts`, `src/shared/contracts.ts`, `src/http.ts`: bounded duplicate-rejecting JSON, canonical identifiers/counters/base64url, versioned encrypted-envelope shape/context checks and consistent API failures.
- `src/modules/work/routes.ts`: bounded encrypted project/record reads. Production requires authentication and currently returns 401 until checkpoint 4 implements that middleware; tests inject an explicit fixture-only identity dependency. No plaintext or unauthenticated write endpoint exists.
- `docs/persistence-model.md`, `docs/security-control-model.md`, `docs/api-conventions.md` document the contracts and later-checkpoint responsibilities. README/CI include both migration commands and keep admin secrets out of runtime configuration.

## Executed verification

1. `docker run --rm --platform linux/amd64 -v /Users/maqbool/Documents/ChatGPT/UKDA:/work -w /work node:24.20.0-bookworm-slim npm run build` — passed.
2. `/Users/maqbool/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node --env-file=.env --env-file=.env.admin dist/scripts/migrate.js` — both stores applied successfully; final replay reported **0 applied, 1 unchanged** for each store.
3. `/Users/maqbool/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node --env-file=.env --test --test-concurrency=1 dist/test/*.test.js` — **27 passed, 0 failed, 0 skipped**, final runtime 2.32 seconds. Includes the eight foundation checks, five API-contract checks, five migration checks, five application persistence checks and four control-store checks.
4. `docker compose --profile app up -d --build --wait` — all four services healthy. API image manifest `sha256:b7adde8c0520725465b8a6055f004d28c58801e1f6c6d631760b359288515282`; worker `sha256:14716432b1ecfe623848490b7e7c43fb401cef3e45425f8d2cccf9d973e218fe`.
5. Live container HTTP probes: API/worker readiness 200; valid protected route without a session 401 `AUTH_REQUIRED`; malformed workspace identifier 400 `INVALID_REQUEST`.

## Acceptance coverage

| Criteria | Authoritative tests/evidence |
| --- | --- |
| CP02-S1/S4 | Real migrations, table catalogs, restricted-role and separate-store integration tests; documented schema and privilege contracts |
| CP02-S2/F2 | Duplicate/cross-workspace/non-member assignments, missing lead membership, incompatible project/milestone/wave links and role revocation rejected at transaction end; deliberate atomic wave move succeeds; immutable history remains intact |
| CP02-S3 | Actual injected HTTP responses for permission/revision/restriction/schema/database errors; malformed identifiers, duplicate fields, envelope mismatch and malformed counters reject safely |
| CP02-F1/F3 | Actual limited application/control roles, two-workspace fixtures, absent-context denial, pool-context reset, tenant-scoped notifications/summaries, project read APIs, unprovisioned Owner/team non-bypass, authority mismatch/outage and distinct cache identities |
| Private data boundary | Real libsodium XChaCha20-Poly1305 fixture: privileged application rows contain ciphertext, not the known private value or client-held key; only correct client key decrypts. This verifies storage separation, not the full composed crypto protocol. |

The shared envelope and production crypto/authentication protocols remain checkpoints 3–6. Notification/summary write and delivery routes remain checkpoints 9–10; CP2 verifies their underlying persistence scopes, not those future feature journeys.

## Focused repairs and review

- Pre-migration review added explicit `read_project` checks and assignment revalidation on role changes; no released migration history was edited.
- Independent development review by the `review_security_flows` agent caught a malformed-counter exception. Guarded BigInt conversion and HTTP regression checks now return 400 instead of 500. One focused repair, passed.
- The combined suite exposed a worker-test race with the live hosted worker. The test now observes completion of its unique job in the shared queue rather than requiring one worker's private event. One focused repair; deduplication, execution, role and outage checks pass.
- Read-only API reviews found no remaining checkpoint-2 blockers. These development reviews do not replace the composed-system independent security gate in checkpoint 13.

No production deployment, finished login, signature verification, Owner recovery, workflow completion, backup durability or pilot readiness is claimed at this checkpoint.

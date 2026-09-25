# Checkpoint 1 — verified foundation

Verified 2026-09-24T21:50:43.028188+00:00 in the local macOS arm64 workspace with Docker Desktop, PostgreSQL 18, and Node 24.19.0 (host tests) / 24.20.0 (container build).

Source-set SHA-256: `a0b745bbf4be3693be8cc49932c57823e9cc42ac256a080705d0eeb6ae49f3ae` (ordered paths: `package.json`, `package-lock.json`, `Dockerfile`, `compose.yaml`, `src/config.ts`, `src/app.ts`, `src/db.ts`, `src/worker.ts`, `scripts/worker-migrate.ts`, `test/foundation.test.ts`, `test/foundation-db.test.ts`, `test/worker.test.ts`). These are currently uncommitted working files.

## Implemented and verified

- Separate application/control databases; restricted non-owner runtime identities, no superuser, role/database creation, schema creation, or RLS bypass.
- TypeScript modular API foundation, safe configuration errors, separate admin-only migration environment, health endpoints, correlation IDs, bounded requests, and sanitized logs/errors.
- Real Graphile Worker queue with schema bootstrap, deduplication and execution; worker readiness depends on queue polling and database connectivity.
- Container build, non-root runtime, read-only filesystem, loopback-only development endpoints, isolated configuration, and a CI workflow. Module ownership and later-stage monitoring responsibilities are documented.

## Executed evidence

1. `docker run --rm --platform linux/amd64 -v /Users/maqbool/Documents/ChatGPT/UKDA:/work -w /work node:24.20.0-bookworm-slim npm run build` — passed.
2. `/Users/maqbool/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node --env-file=.env --test --test-concurrency=1 dist/test/*.test.js` — **8 passed, 0 failed, 0 skipped**. Tests cover both real database roles, dependency outages, unsafe configuration, malformed/oversized requests, secret-bearing synthetic errors/logs, real job deduplication/execution and a private worker TCP outage.
3. `docker compose --profile app up -d --build --wait` — API, worker, application DB and control DB all healthy. Build uses `npm ci` with the lockfile. API image manifest: `sha256:b0e0f5124538f01f2e9f7e43aa5eea5aca59d69840b96868c84b2d3829d50767`; worker: `sha256:ad14bceb2c060959ef61ee8ef61859a42340ae77095afd7944cdc3b14a96e223`.
4. Live container probes — API and worker readiness HTTP 200; both UID 1000; neither has admin connection settings. API contains no `.env`; attempted application-directory write rejected with `EROFS`.
5. Read-only foundation review by the `review_product_flows` agent — no remaining checkpoint-1 blockers. This is development review, not the independent composed-security review required by checkpoint 13.

## Boundaries

This verifies deployment setup and foundation only. The CI workflow has not run remotely, and no staging/production deployment is claimed. Authentication, tenant-aware domain operations, security transitions, later metrics, backups and browser crypto are implemented and accepted in later checkpoints. No protected domain route is available yet. Email, AI and connector dependencies are absent.

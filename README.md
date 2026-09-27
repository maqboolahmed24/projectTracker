# Maqbool project workspace

Implementation of the architecture in `architecture/archtecture.md`, with backend services, browser cryptography/controllers and a Next.js product frontend. Email and the deferred integrations remain outside this build. Progress is tracked in `architecture/checklist.md`, with acceptance evidence in `docs/implementation-evidence.md`.

The product is branded **Maqbool**. Existing `ukda` protocol, storage, package and deployment identifiers remain stable so the rename preserves existing workspaces, remembered profiles and integrations.

## Local development

Requires Node.js 24.19 or later in the Node 24 line, npm, and Docker Compose.

The commands below initialize a fresh installation. For an existing recovery-enabled installation, include `-f compose.yaml -f compose.recovery.yaml` in every Compose command; starting the database services with the base file alone disables their recovery configuration.

```sh
cp .env.example .env
cp .env.admin.example .env.admin
docker compose up -d --wait app-db control-db
npm ci
npm run build
npm run identity:setup
npm run migrate
npm run worker:migrate
npm run check
npm test
npm start
```

The API listens on `http://localhost:3400`. `GET /health/live` checks the process; `GET /health/ready` checks both databases. A database outage returns readiness 503 without exposing connection details. Local database credentials are development-only and services bind to loopback. To open the product frontend, follow [frontend build and operation](docs/frontend-operations.md); its default published port is 3000 and it proxies `/v1/*` to the API on the same browser origin. Choose the canonical `APP_ORIGIN` before activating a workspace. Existing workspaces must keep their original origin.

Keep migration credentials in `.env.admin` only. The API rejects an environment containing admin database URLs. `npm run migrate` and `npm run worker:migrate` are separate privileged setup commands; the running API/worker use limited database roles. Run `PORT=3401 npm run worker` in a second terminal for hosted jobs.

`identity:setup` creates `.env.identity` once, with private file permissions. Keep this file across restarts and deployments; never regenerate it to reset accounts. It holds the OPAQUE server setup and operational verification secret, and contains no customer content keys. The API, operational licence CLI and recovery operator load it; the projection worker does not need it.

Issue a development activation key into a private, ignored directory:

```sh
mkdir -p .local
npm run licence -- issue --output .local/activation-key.json
```

The key is written only to that file. See [identity operations](docs/identity-operations.md) for interruption handling and entitlement restrictions. Activation APIs and the browser controller are documented in [activation protocol](docs/activation-protocol.md); the frontend uses these controllers for setup.

The browser client library is built with `npm run build:browser`. See [authentication protocol](docs/authentication-protocol.md) for `openClient`, remembered profiles, device approval, password changes, and local cleanup; [recovery protocol](docs/recovery-protocol.md) for Owner phrases and short RESET keys; [enrolment protocol](docs/enrolment-protocol.md) for member/Owner JOIN, member promotion and interrupted approval; [role definitions](docs/roles-protocol.md) for encrypted custom role names and fixed permissions; [access changes](docs/access-change-protocol.md) for reassignment, suspension, Owner demotion/removal and key refresh; and [projects and planning](docs/work-protocol.md) for the work controllers, plus [collaboration and Inbox](docs/collaboration-protocol.md) for encrypted discussion, notifications and retained history; and [reporting and live refresh](docs/reporting-protocol.md) for progress, deadlines, health, signed summaries and timezone settings. Serve its output from the configured application origin over HTTPS; the browser tests provide a local HTTPS harness.

[Illustrated avatar selection](docs/avatar-protocol.md) adds 20 locally bundled CC0 designs and 12 colours to signup, with encrypted profile storage and authenticated `client.profiles.current()` retrieval. The public catalogue is `GET /v1/avatars/catalog`; [preview the collection](assets/avatars/preview.png). The product signup screens use this same catalogue.

To run the API in its container:

```sh
docker compose --profile app up -d --build --wait
```

Stop this project's application services with `docker compose --profile app --profile frontend stop api worker frontend`. Retain both Compose files for recovery-enabled installations. Do not use `down --volumes` when preserving local data.

The frontend has its own `Dockerfile.frontend` and Compose `frontend` profile; enable both `--profile app --profile frontend` after configuring the published ports and canonical origin. For recovery-enabled installations retain `-f compose.yaml -f compose.recovery.yaml`. The [frontend runbook](docs/frontend-operations.md) includes both fresh-install and existing-origin examples, standalone asset layout and validation checks. The API/worker Dockerfile and database volumes are unchanged by the frontend service.

For an update, stop every API and worker using these databases before applying migrations, then build and start both services from the same source revision. Confirm readiness before accepting traffic. Mixed-version security projection is unsupported in this first release: an older worker can advance the projection without performing newer side effects. Run integration tests against isolated databases or a worker built from the source being tested. Upgrading a pre-release database that was already processed by older projection code may require explicit reconciliation; restarting alone does not replay previously projected events.

Encrypted migrations and explicit request recovery are documented in [encrypted upgrades](docs/encrypted-upgrades.md); hosted queue inspection and failed-job replay are in [job operations](docs/job-operations.md).

The [recovery operator and local recovery profile](docs/backup-operations.md) provide encrypted physical backups, continuous WAL, five-minute signed checkpoints and a synchronous security replica. Once enabled, include `-f compose.yaml -f compose.recovery.yaml` in Compose commands so the primary databases retain their archivers. Its integration tests and operational drills pass; see [checkpoint 12 evidence](docs/checkpoint-12-evidence.md) and the verified [final release evidence](docs/checkpoint-13-evidence.md).

## Validation

`npm run check` checks backend/library TypeScript; `npm run check:frontend` checks the React/Next application. `npm run build:frontend` creates the browser library and production frontend. `npm test` compiles and runs the focused Node test suite. CI runs the backend commands with both isolated PostgreSQL stores. Security-sensitive request bodies, query values, cookies, and database error details are excluded from logs.

For backend integration tests, use local test databases with the separately running queue worker and recovery operator stopped. Tests that need a worker start their own controlled instance; another worker can consume a deliberately held job or repair an intentionally interrupted projection before its assertion. When using the local recovery Compose profile, stop its queue worker with `docker compose -f compose.yaml -f compose.recovery.yaml stop worker` before `npm test`.

For browser verification, start and migrate the same two local test databases and run a hosted queue worker built from the matching source; notification tests require real queued delivery. Start it with `docker compose -f compose.yaml -f compose.recovery.yaml --profile app up -d --no-deps worker`, then run `npm run browser:install` and `npm run test:browser`. Keep the recovery operator stopped while fixture workspaces use their temporary test service keys. The tests use an ephemeral local HTTPS certificate and isolated fixtures; ports 3555 and 3556 must be free. They exercise actual WebAssembly/WebCrypto/IndexedDB and browser cookies without product screens. Bundled Chromium, Firefox and WebKit evidence is separate from the final current/previous branded-browser release gate.

Checkpoint 13's [integrated evidence](docs/checkpoint-13-evidence.md) records the working core journeys, independent automated security reviews and passing results on current/previous Chrome, Edge, Firefox and Safari. Official [Firefox](docs/branded-firefox-verification.md) and native [Safari](docs/branded-safari-verification.md) have separate runner instructions; locally provisioned Chrome/Edge use `playwright.branded.config.ts`.

## Current state

All thirteen implementation checkpoints are complete for the agreed local starter: backend services and browser protocol/domain libraries. The checkpoint 13 baseline evidence covers 558 distinct passing Node cases, the integrated core and failure journeys, all eight required branded browser releases, independent automated security reviews with repaired findings, and healthy matching local services. That baseline predates the new product screens. The product frontend now has separate [verification evidence](docs/frontend-verification.md): 40 distinct passing product browser cases, 64 focused Node checks, inspected responsive light/dark screens, the measured centre-to-corner startup transition, and matching healthy local services. These UI results are separate from the older controller/browser baseline. Email and future integrations remain visibly unavailable in this build.

The subsequent avatar extension has separate [verification evidence](docs/avatar-verification.md): 82 distinct focused Node cases, six browser journeys, inspected local artwork, and matching healthy runtime services. The full baseline suite was not rerun for this extension.

The application is deployed at **[Maqbool on Azure](https://maqbool.denmarkeast.cloudapp.azure.com)**, with HTTPS, private database access, separate operational secrets, and a second host for encrypted backups and synchronous security replication. See the [cloud evidence](docs/cloud-deployment-evidence.md) and [operating guide](docs/cloud-operations.md). It uses finite Azure for Students credit with the spending limit enabled; it is not permanent free hosting. Existing local workspace data remains local pending the activation/migration decision. Automated security review is not an external human audit or certification.

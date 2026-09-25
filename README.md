# UKDA project workspace

Starter implementation of the architecture in `architecture/archtecture.md`. The visual frontend and deferred integrations are outside this build. Progress is tracked in `architecture/checklist.md`, with acceptance evidence in `docs/implementation-evidence.md`.

## Local development

Requires Node.js 24.19 or later in the Node 24 line, npm, and Docker Compose.

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

The API listens on `http://localhost:3400`. `GET /health/live` checks the process; `GET /health/ready` checks both databases. A database outage returns readiness 503 without exposing connection details. Local database credentials are development-only and services bind to loopback.

Keep migration credentials in `.env.admin` only. The API rejects an environment containing admin database URLs. `npm run migrate` and `npm run worker:migrate` are separate privileged setup commands; the running API/worker use limited database roles. Run `PORT=3401 npm run worker` in a second terminal for hosted jobs.

`identity:setup` creates `.env.identity` once, with private file permissions. Keep this file across restarts and deployments; never regenerate it to reset accounts. It holds the OPAQUE server setup and operational verification secret, and contains no customer content keys. Only the API and operational licence CLI load it; the projection worker does not need it.

Issue a development activation key into a private, ignored directory:

```sh
mkdir -p .local
npm run licence -- issue --output .local/activation-key.json
```

The key is written only to that file. See [identity operations](docs/identity-operations.md) for interruption handling and entitlement restrictions. Activation APIs and the browser controller are documented in [activation protocol](docs/activation-protocol.md); they implement setup without frontend screens.

The browser client library is built with `npm run build:browser`. See [authentication protocol](docs/authentication-protocol.md) for `openClient`, remembered profiles, device approval, password changes, and local cleanup; [recovery protocol](docs/recovery-protocol.md) for Owner phrases and short RESET keys; [enrolment protocol](docs/enrolment-protocol.md) for member/Owner JOIN, member promotion and interrupted approval; [role definitions](docs/roles-protocol.md) for encrypted custom role names and fixed permissions; and [access changes](docs/access-change-protocol.md) for reassignment, suspension, Owner demotion/removal and key refresh. Serve its output from the configured application origin over HTTPS; the browser tests provide a local HTTPS harness.

To run the API in its container:

```sh
docker compose --profile app up -d --build --wait
```

Stop this project's services with `docker compose --profile app down`. Omit `--volumes` to preserve local data.

For an update, stop every API and worker using these databases before applying migrations, then build and start both services from the same source revision. Confirm readiness before accepting traffic. Mixed-version security projection is unsupported in this first release: an older worker can advance the projection without performing newer side effects. Run integration tests against isolated databases or a worker built from the source being tested. Upgrading a pre-release database that was already processed by older projection code may require explicit reconciliation; restarting alone does not replay previously projected events.

## Validation

`npm run check` checks TypeScript. `npm test` compiles and runs the focused Node test suite. CI runs the same commands with both isolated PostgreSQL stores. Security-sensitive request bodies, query values, cookies, and database error details are excluded from logs.

For browser verification, start and migrate the same two local test databases, then run `npm run browser:install` and `npm run test:browser`. The tests use an ephemeral local HTTPS certificate and isolated fixtures; ports 3555 and 3556 must be free. They exercise actual WebAssembly/WebCrypto/IndexedDB and browser cookies without product screens. Bundled Chromium, Firefox and WebKit evidence is separate from the final current/previous branded-browser release gate.

## Current state

Implementation is in progress. This foundation is not yet a complete application or a production release. Each checkpoint remains unchecked until its own implementation and acceptance checks pass. Deployment requires HTTPS, private database networking, distinct operational secrets, independent security-store durability, and the later documented release gates.

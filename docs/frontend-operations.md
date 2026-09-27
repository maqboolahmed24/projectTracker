# Frontend build and operation

Local `http://localhost` cookie support was verified with Chromium and Firefox. Use HTTPS for Safari and hosted installations; the WebKit browser test rejects the required Secure session cookie at this local HTTP address. The frontend checks cookie support before setup and explains an unsupported local address without consuming an activation key. Authentication cookie protections are unchanged.

The Next.js frontend serves the application, local fonts, brand assets and browser cryptography library. `/v1/*` requests pass through its same-origin streaming proxy to the API. The browser never connects directly to the internal Compose API address. Private keys and decrypted content stay in the browser controllers and Worker.

`Dockerfile.frontend` builds the browser library and Next application together, then runs the generated standalone server as the unprivileged `node` user. The runtime copies the traced production dependency closure plus `web/.next/static` and `web/public` beside `web/server.cjs`. Next generates this bootstrap as `web/server.js`; the container renames it to `.cjs` so the repository’s ESM package type cannot reinterpret its CommonJS code. Development dependencies, database credentials, `.env.identity` and migration tools are not supplied to the frontend runtime. The existing `Dockerfile` continues to build the API and projection worker.

## Origin and ports

The API still listens on **3400 inside Compose**. The frontend still listens on **3000 inside its container**. These internal ports are independent of the browser origin and published host ports.

| Setting | Meaning |
| --- | --- |
| `APP_ORIGIN` | Exact browser origin, including scheme and non-default port; the same value must be used by API, worker and operational identity/recovery tools |
| `UKDA_FRONTEND_PORT` | Local published frontend port; defaults to 3000 |
| `UKDA_API_PORT` | Local diagnostic API port; defaults to 3400 |
| `UKDA_API_ORIGIN` | Frontend server's internal upstream; Compose sets `http://api:3400` |

**Keep an existing workspace's origin unchanged.** It is bound into signed workspace history, recovery kits and device storage. Switching `localhost` to `127.0.0.1`, changing a port or changing the scheme creates a different origin; changing an environment variable is not a migration. The new Compose variables do not edit `.env`, credentials, workspace records or existing volumes.

For a fresh local installation with no activated workspace, set these non-secret values in `.env` before issuing/using an activation key:

```dotenv
APP_ORIGIN=http://localhost:3000
UKDA_FRONTEND_PORT=3000
UKDA_API_PORT=3400
```

For an existing workspace whose canonical browser origin is `http://localhost:3400`, serve the frontend on that same port and move only the API's host diagnostic port:

```dotenv
APP_ORIGIN=http://localhost:3400
UKDA_FRONTEND_PORT=3400
UKDA_API_PORT=3402
```

The API container still uses internal port 3400. Do not attempt to bind both frontend and API to the same host port. The `.env.example` backend default remains 3400; choose the appropriate explicit configuration above before enabling the frontend. The development Compose file uses local-only database credentials and binds published ports to loopback.

## Build and start

Complete the existing one-time identity, migration and worker bootstrap from the README first. Keep the operational identity file and database volumes. Do not rerun identity setup to reset existing accounts.

For an installation that already uses the recovery profile, **retain both Compose files in every command**, including frontend commands:

```sh
docker compose -f compose.yaml -f compose.recovery.yaml --profile app --profile frontend build api worker frontend
docker compose -f compose.yaml -f compose.recovery.yaml --profile app --profile frontend up -d --no-deps --wait api worker frontend
```

The second command assumes the existing database and synchronous replica services are already healthy. It updates only API, worker and frontend. Do not recreate primaries without the recovery overlay. For a fresh installation without the recovery profile, use the same two commands with `-f compose.recovery.yaml` omitted; start its database services first as documented in the README. The existing `--profile app` alone continues to select API and worker. The frontend additionally uses `--profile frontend`.

Stop the API and worker before a required schema migration, apply migrations with the separate admin environment, then start all three application services from the same reviewed source. Do not mix an older worker with a newer security API. Frontend deployment itself does not introduce a migration or database initialization step.

Read-only configuration validation is:

```sh
docker compose -f compose.yaml -f compose.recovery.yaml --profile app --profile frontend config --quiet
```

Avoid printing expanded Compose configuration because it may contain operational secrets loaded for the API. Never use `down --volumes` when retaining local data.

## Validation after startup

Use the configured frontend origin in the browser. Verify:

- The sign-in/setup screen loads, its local fonts and launch assets load, and `/client/client.js` plus `/client/auth-worker.js` are same-origin resources.
- `GET /v1/application` succeeds through the frontend and contains public verification configuration only. The frontend health check uses this route, so it checks both the standalone server and API proxy. It does not replace the API's database readiness check.
- `GET /v1/avatars/catalog` succeeds through the frontend. Authentication and mutations preserve the browser `Origin`, cookies and CSRF headers through the proxy; there is no cross-origin browser API configuration.
- API `/health/live` and `/health/ready` remain available at its separate diagnostic host port or from the Compose network. Worker readiness remains internal on port 3401. Queue, recovery freshness and synchronous-replica checks remain in the existing operational runbooks.
- An authorised user can open and decrypt a project, navigate settings and receive live updates without exposing plaintext in server logs.

Retain the build and verification output for the source revision deployed. Existing checkpoint/browser-library evidence predates the new product screens and does not itself verify the new frontend. The central frontend task owns the new screen/browser results.

## Product browser checks

With migrated local test databases and installed Playwright browsers, run `npm run test:frontend`. Stop this project's separately running queue worker and recovery operator first; the serial fixtures control notification delivery and use temporary service identities. The suite starts a temporary HTTPS entry point on 3555, a fixture API on 3556 and the built Next frontend on 3557. All browser requests pass through Next, including its real same-origin API proxy. Ports must be free. Never run this fixture suite against production data.

The proxy preserves the API's larger planning, restoration and workspace-update request limits. It carries the temporary setup Authorization header, cookies and CSRF headers to its fixed API upstream, streams responses, and lets the API enforce its route-specific authorization and schemas. It does not trust a browser-supplied forwarding address.

Recovery words and temporary invitation codes are deliberately excluded from automatic traces, videos and failure screenshots. Selected screenshots show only disposable fixture project content. Restore the regular worker and recovery operator when verification ends.

## Development and production

For local development, run API and worker as documented in the README. Set their `APP_ORIGIN` to the frontend browser origin before creating workspaces, then run:

```sh
npm run check:frontend
npm run dev:frontend
```

The frontend defaults to port 3000 and its local proxy defaults to `http://127.0.0.1:3400`. A standalone production build outside Docker uses `npm run build:frontend` followed by `npm run start:frontend`; the custom container instead invokes its generated bootstrap as `web/server.cjs` directly.

For production, use an HTTPS canonical application origin from the outset. Put the frontend behind the HTTPS entry point, keep API and database services on private networks, set the API to its production configuration, and supply separately managed secrets only to services that need them. Preserve streaming responses for in-app live updates and avoid proxy buffering/caching on `/v1/*`. The local Compose file is not a production database/security configuration; independent backup and replica failure domains remain required. The frontend does not need customer-operated workers or connectors.

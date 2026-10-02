# Deployment setup

## Local development

`compose.yaml` defines an isolated `ukda` project with two PostgreSQL services. Both expose only loopback ports. The `app` profile adds the API and hosted worker. The published database passwords are only local-development fixtures. Named volumes preserve data between normal stops; deleting volumes destroys that local data.

The API and worker receive only `DATABASE_URL` and `CONTROL_DATABASE_URL`, using non-owner roles that cannot bypass RLS or create schema objects. Privileged migration URLs belong in `.env.admin`, which is loaded only by explicit setup commands. The runtime rejects admin URLs accidentally supplied in its environment.

## Staging and production

Create separate databases, storage, deployment credentials, domain names, and operational secrets for each environment. Never copy customer ciphertext or credentials into staging as test fixtures. Build the same reviewed Docker artifact for both environments; the runtime runs as the image's non-root `node` user with a read-only filesystem.

Supply these runtime settings from the deployment's secret/configuration mechanism:

| Setting | Requirement |
| --- | --- |
| `NODE_ENV` | `production` in both staging and production deployments |
| `HOST`, `PORT` | Internal listener behind the deployment gateway |
| `APP_ORIGIN` | Exact HTTPS origin, without a path or query |
| `DATABASE_URL` | Limited application database role; private networking and verified transport |
| `CONTROL_DATABASE_URL` | Limited security control role in its separately protected store |
| `LOG_LEVEL` | `info` by default; no request/response payload logging |

Run migrations as a separate privileged release job. Do not put administrator URLs in the API image, worker image, runtime environment, or frontend bundles. The API must not be exposed directly as a public HTTP origin: terminate HTTPS at the deployment gateway and restrict its internal listener. No proxy-provided user identity or forwarded header is trusted by default.

The local Compose file is not a production topology. Independent security-store replication/durability, backup retention, encrypted-object storage when needed, secret backup, and restore drills are release requirements covered by later checkpoints. Deployment is not considered completed merely because the container builds.

## Health and shutdown

- `/health/live` reports process availability.
- `/health/ready` reports dependency readiness without connection strings or exception details.
- A database outage leaves liveness available but readiness unavailable.
- Send `SIGTERM` for a graceful shutdown; remove an unready process from traffic before replacement.
- Logs include generated request IDs, method, route template, and response status. They exclude URL parameters, query strings, request/response bodies, cookies, and underlying database errors.

Security-projection/fence metrics are delivered in checkpoint 5, durable queue metrics in checkpoint 11, and backup/restore metrics in checkpoint 12. Their absence is not represented as successful measurements. The final release checkpoint verifies all operational signals together.

## Release status

No production environment has been deployed. Follow the evidence register and complete the final security, workflow, recovery, and supported-browser gates before a real-user release.

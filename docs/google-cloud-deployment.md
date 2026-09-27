# Google Cloud deployment readiness

Maqbool's current local installation is working. A Google Cloud deployment has **not** been provisioned or verified. Trial eligibility and an approved billing arrangement must be established before creating resources; this preparation does not authorize paid usage.

## Compatible hosting path

Use Compute Engine for the existing container-based application and PostgreSQL services. Serve the Next.js frontend through one permanent HTTPS address. Keep the API, database listeners, worker health endpoints and operational tools private. Vercel is not required.

The complete application includes:

- Frontend and API containers built from the same reviewed source revision.
- An always-running queue worker and supervised recovery operator.
- Separate application and security-control PostgreSQL 18 stores, with limited runtime roles and separate privileged migration credentials.
- A synchronous security-control replica in a separate failure domain.
- Independently durable encrypted backup repositories, continuous WAL archiving, protected operational secrets and a tested restoration procedure.

The existing Compose configuration is explicitly for local development. A cloud deployment must replace its public development passwords, set `NODE_ENV=production`, supply a stable HTTPS `APP_ORIGIN`, restrict network access, and provide independent storage and replica provisioning. Do not expose the unmodified local Compose stack to the internet.

Cloud SQL is not a configuration-only replacement today. The recovery scripts invoke PostgreSQL and pgBackRest through Docker Compose, inspect local named-volume mounts, and launch isolated restore containers. Cloud SQL would require a supported recovery/restore adapter and new verification evidence before deployment.

## Existing accounts and data

The current workspace origin is part of its signed security history, recovery material and browser device storage. Copying the databases and changing `APP_ORIGIN` does not migrate an activated workspace. The application currently has no supported origin-migration or full export/import workflow.

A fresh cloud workspace can be activated at the permanent HTTPS origin while the local workspace remains available. Moving existing accounts and project history requires a separately designed, Owner-authorized migration. Never rewrite signed origins directly or regenerate the local installation's operational identity.

## Provisioning and release sequence

1. Confirm eligible trial credit or a separately authorized billing plan. Do not upgrade billing under a trial-only instruction. Google's [trial terms](https://docs.cloud.google.com/free/docs/free-cloud-features) describe eligibility, the credit limit and expiry.
2. Decide whether to start a fresh cloud workspace or first implement migration of existing data, and select the permanent HTTPS address before activating any cloud workspace.
3. Prepare cloud-specific provisioning, network restrictions, independent replica/storage, secret delivery and a cost estimate. Budget alerts are notifications, not a guarantee that resources cannot incur charges.
4. Build the frontend, API and worker from a pinned Git revision. Supply fresh cloud operational identity and non-development credentials through protected configuration; exclude them from Git and image layers.
5. Run migrations with the separate migration credentials, bootstrap the worker schema, configure the replica and encrypted repositories, and start the API, worker, frontend and recovery operator.
6. Verify HTTPS, readiness, queue processing, replica durability, backup/WAL freshness and a full restore drill. Verify real Owner/member setup, project access and new-device approval at the final origin.
7. Record the deployed revision, image digests, public URL, verification evidence and rollback procedure. Report the application as live only after these checks pass.

See [frontend operations](frontend-operations.md), [deployment requirements](deployment.md) and [backup operations](backup-operations.md) for the current implementation's requirements and limitations.

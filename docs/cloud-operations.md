# Azure operating guide

The cloud product is served at **[https://maqbool.denmarkeast.cloudapp.azure.com](https://maqbool.denmarkeast.cloudapp.azure.com)**. Keep this origin unchanged: workspace identity is bound to it. This guide describes the deployed Azure topology and maintenance commands; it does not certify uncompleted recovery or application tests.

## Deployment and cost boundary

| Host | Region / zone | Size | Purpose |
| --- | --- | --- | --- |
| Primary, `10.42.0.4` | Denmark East / 1 | `Standard_B2als_v2`, 4 GiB RAM | Caddy, frontend, API, worker, application and current control databases, recovery operator |
| Standby, `10.42.0.5` | Denmark East / 2 | `Standard_B2ats_v2`, 1 GiB RAM | Synchronous control replica and private NFS backup storage |

Both machines run Ubuntu 24.04 on x64. The primary also has a 2 GiB build swap file. These are small, burstable machines; this is a starter deployment, with no measured capacity promise or automatic failover. Separate availability zones protect against some host/zone failures. Both machines still share the region, subscription and administrator, so they do not protect against every disaster or exhausted credit.

The subscription is **Azure for Students, spending limit On**. This is a finite, credit-funded deployment, not a permanently free hosting service. Azure currently advertises $100 of student credit usable within 12 months, subject to eligibility and renewal. Check this subscription's actual remaining credit and expiry in the Azure portal; the deployment date does not restart its credit term. [Azure for Students](https://azure.microsoft.com/en-us/free/students/)

Keep the spending limit enabled. Do not upgrade to pay-as-you-go, remove the limit, or purchase a paid Marketplace/support service under the zero-cash requirement. The limit stops ordinary credit-backed resources when credit runs out; some separately billed services are exceptions. Availability can end before the credit expiry date if usage consumes the balance. [Azure spending limit](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/spending-limit)

Review usage and projected exhaustion at least weekly and after changes. Include both VMs, managed disks, public IPs and network transfer; do not assume every resource is covered by a free allowance. Before the balance or term ends, preserve recovery material outside this subscription and either renew eligible student benefits or stop the deployment. A guest shutdown does not deallocate a VM. Azure deallocation stops compute billing, but retained disks and other resources can still consume credit. [Azure VM billing states](https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing)

## Files, images and access

| Location | Contents |
| --- | --- |
| `/opt/maqbool/release` | Reviewed application release and operational scripts |
| `/opt/maqbool/release/ops/cloud/compose.primary.yaml` | Primary stack, fixed project `ukda-cloud-primary` |
| `/opt/maqbool/release/ops/cloud/compose.standby.yaml` | Standby stack, fixed project `ukda-cloud-standby` |
| `/opt/maqbool/secrets` | External configuration, database credentials, identity settings, backup encryption configuration and private TLS material; root-restricted |
| `/opt/maqbool/secrets/cloud.env` | Host-specific Compose settings and immutable image references |
| `/opt/maqbool/secrets/operator.env` | Primary maintenance identity and privileged database settings |
| `/opt/maqbool/recovery-records` | Primary's mounted NFS checkpoint records, backed by standby storage |
| `/srv/maqbool-backups/{app,control,records}` | Standby's encrypted repositories and encrypted checkpoint sidecars |

The primary's backup repositories use NFS-backed Docker named volumes; its live databases use separate local Docker volumes. The replica has its own local volume on the standby. Backup encryption secrets are held separately from repositories. The `records` export preserves root ownership and is restricted to `10.42.0.4/32`; only the `app` and `control` exports use `root_squash` with UID/GID 999. Keep NFS private and preserve these permissions.

API, frontend, database/recovery, operator and Caddy images are pinned to full immutable SHA-256 image IDs or registry digests in the external configuration. All manifests use `pull_policy: never`. Retain each reviewed image/archive, checksum, source revision and matching configuration before replacing it. A mutable tag is insufficient for rollback. The operator is a distinct image with Docker tooling; do not substitute the API image.

Use the existing ignored local SSH key/configuration and trusted `known_hosts` file under `.local/azure-deploy`; never commit or paste them into a report. SSH is key-only, root login is disabled, and operations run through `sudo`. Use strict host-key checking and the approved current host address. Azure network rules also restrict administrator access; a changed client address requires an intentional rule update, not opening SSH to everyone. Do not print resolved Compose environments or private files. The Docker socket grants full host control and belongs only to the maintenance operator.

## Inspect and restart

Run primary commands over SSH **on the primary host**. These shell functions keep the cloud project separate from local development:

```sh
maqbool_primary() {
  sudo docker compose --env-file /opt/maqbool/secrets/cloud.env \
    -f /opt/maqbool/release/ops/cloud/compose.primary.yaml \
    --profile application "$@"
}
maqbool_primary ps
maqbool_primary images
maqbool_primary logs --tail 80 api worker frontend gateway
sudo systemctl status maqbool-recovery --no-pager
sudo journalctl -u maqbool-recovery -n 80 --no-pager
curl --fail --silent --show-error http://127.0.0.1:3401/health/recovery
```

The recovery service is installed/enabled after deployment drills. A missing unit during commissioning is not proof of protection. Recovery health can return 503 when measurements or the complete Owner restore drill are missing/stale; a healthy web page or a successful full backup alone does not establish recovery readiness.

For an application-only restart with unchanged files/images:

```sh
maqbool_primary restart api worker frontend gateway
maqbool_primary ps
curl --fail --silent --show-error --output /dev/null \
  https://maqbool.denmarkeast.cloudapp.azure.com/
```

`restart` does not apply a changed image, environment or Compose file. For a reviewed application update, stop API/worker before any required migration, use matching API/worker releases, then apply the new pinned configuration with `maqbool_primary up -d --no-deps --wait api worker frontend gateway`. Follow the release's migration procedure and verify readiness before resuming customer work. Do not rebuild or migrate during an ordinary restart.

On the **standby host**, use its own configuration and manifest:

```sh
maqbool_standby() {
  sudo docker compose --env-file /opt/maqbool/secrets/cloud.env \
    -f /opt/maqbool/release/ops/cloud/compose.standby.yaml "$@"
}
maqbool_standby ps
maqbool_standby logs --tail 80 control-replica
sudo systemctl status nfs-server --no-pager
sudo exportfs -v
```

A standby restart intentionally interrupts synchronous security writes. Keep both hosts running during normal use; never disable synchronous commits to restore apparent availability. For a planned whole-stack outage, stop the primary's recovery operator and application writers first. On return, make standby NFS available, start the existing primary databases, then the existing standby replica; verify it is streaming synchronously before starting application writers and the recovery operator. Do not initialize, reseed or delete existing volumes as a restart procedure.

The checkpoint mount is deliberately deferred at boot. Before starting the recovery operator, use the installed primary helper if needed:

```sh
sudo /usr/local/sbin/maqbool-mount-recovery-records
findmnt /opt/maqbool/recovery-records
sudo systemctl start maqbool-recovery
```

The mount must resolve to `10.42.0.5:/srv/maqbool-backups/records`, with root-owned `0700` records directory. A hard NFS mount can block during a standby outage. Restore connectivity; never substitute a local directory or weaken it to a soft mount.

## Backup, checkpoint and restore

The supervised operator schedules daily full backups, continuous WAL coverage and five-minute signed checkpoints for active workspaces. Check its service and `/health/recovery` regularly. Preserve **both** physical repositories, encrypted checkpoint records and the separately protected operational secrets. Customer-side Owner recovery material is also required; a server operator cannot recreate it.

Run explicit maintenance one operation at a time, with the daemon stopped to avoid competing work. The following primary-host shell helper uses the same restricted mounts as the service. It extracts only the immutable, non-secret operator image setting; it does not execute `cloud.env` as shell code or print its contents:

```sh
maqbool_operator_image="$(sudo sed -n 's/^UKDA_OPERATOR_IMAGE=//p' /opt/maqbool/secrets/cloud.env)"
maqbool_operator() {
  printf '%s\n' "$maqbool_operator_image" |
    grep -Ex '(sha256:[0-9a-f]{64}|[^[:space:]]+@sha256:[0-9a-f]{64})' >/dev/null || return 1
  sudo mountpoint -q /opt/maqbool/recovery-records || return 1
  sudo docker run --rm --init --pull never --network host --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop ALL \
    --security-opt no-new-privileges:true --pids-limit 256 \
    --log-driver local --log-opt max-size=10m --log-opt max-file=3 \
    --env-file /opt/maqbool/secrets/cloud.env \
    --env-file /opt/maqbool/secrets/operator.env \
    --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
    --mount type=bind,src=/opt/maqbool/secrets,dst=/opt/maqbool/secrets,readonly \
    --mount type=bind,src=/opt/maqbool/release/ops/cloud,dst=/opt/maqbool/release/ops/cloud,readonly \
    --mount type=bind,src=/opt/maqbool/recovery-records,dst=/opt/maqbool/recovery-records \
    "$maqbool_operator_image" node "$@"
}
sudo systemctl stop maqbool-recovery
```

Choose the required operation below; these are separate examples, not a sequence to paste blindly. Replace UUID placeholders with the intended workspace and a recorded usable checkpoint. Keep returned identifiers in the private operation record.

```sh
# Create and verify encrypted full backups for both stores.
maqbool_operator scripts/physical-backups.mjs backup
maqbool_operator scripts/physical-backups.mjs verify

# Capture a signed workspace checkpoint and retain its returned checkpoint ID.
maqbool_operator scripts/recovery.mjs checkpoint WORKSPACE_UUID

# Restore this workspace to that checkpoint: this changes live workspace content.
maqbool_operator scripts/recovery.mjs restore WORKSPACE_UUID CHECKPOINT_UUID
```

Restore first reconstructs a separate, network-disabled database and verifies the signed inventory, then installs the selected workspace's allowed application rows under current security authority. It does **not** roll back the current control database. The restored workspace stays quarantined until a current approved Owner signs in, reviews the restore and completes its verification. A physical restore alone is not a finished customer recovery. See [recovery operations](backup-operations.md) for the protocol and failure handling.

On interruption or failure, inspect the reported stage and retained operation state before retrying. Do not delete partial seeds, clear quarantine or overwrite the primaries. After completing or safely resolving the maintenance operation, resume protection and inspect health:

```sh
sudo systemctl start maqbool-recovery
sudo systemctl status maqbool-recovery --no-pager
curl --fail --silent --show-error http://127.0.0.1:3401/health/recovery
```

## Preservation and rollback

Never use `docker compose down -v`, `docker volume prune`, delete the VM/resource group/disks, or replace the current control database to undo an application release. Do not regenerate identity setup or backup encryption configuration. Retain Caddy's data volume, database volumes, standby volume and NFS repositories across updates.

Before an update, record current image pins and source revision, secure a separate configuration/secret backup, and verify a current full backup and workspace checkpoint. An application rollback may restore previously reviewed image pins only when they remain compatible with the current schema and security projection. Stop API/worker together; do not run mixed releases. If a migration is incompatible, use the release's forward repair or reviewed restore procedure. An old control backup must never become current authority.

Before credit exhaustion or a planned shutdown, copy encrypted repositories and checkpoint sidecars to an independently controlled destination while preserving ownership and integrity, and protect operational secrets separately. Verify that preserved material can be recovered before deleting any Azure resource. Both current backup storage and the replica are inside the same student subscription; neither survives arbitrary subscription/resource deletion by design.

## Certificates and expiry

Caddy manages the public HTTPS certificate automatically. Keep DNS pointing to the primary, inbound ports 80/443 available, outbound certificate-authority access working, and its `/data` volume intact. Inspect gateway logs when issuance or renewal fails; do not bypass certificate verification. [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https)

The private database server certificates have a **365-day lifetime** (expire 27 September 2027); the private CA has a **1,095-day lifetime** (expires 26 September 2029). They need operator renewal. Inspect their actual `notAfter` dates with `openssl x509 -in CERTIFICATE_PATH -noout -dates`; use the public certificate paths referenced by `UKDA_DATABASE_CA_FILE`, `UKDA_APP_TLS_CERT_FILE` and `UKDA_CONTROL_TLS_CERT_FILE` in the protected configuration. Start renewal at least 30 days before the earliest expiry. This guide does not install a renewal reminder or service.

Renew in a maintenance window: securely prepare new certificates and private keys, retain the required names/IPs (`app-db`, `control-db`, `127.0.0.1` and the primary replication address as applicable), verify their chain and validity, and update the configured files on both hosts. A CA rotation must update trust for API, worker, operator and standby as well as both server certificates; use a reviewed overlapping-trust rollout or stop writers until all clients have the new trust. Keep `verify-full` enabled throughout.

Recreate the affected containers after replacing file-backed secrets so new bind mounts and trust files are used, and restart the operator with the renewed CA. The database entrypoint copies private server keys to `/var/lib/postgresql/tls`, outside `PGDATA`; these keys are not part of the PostgreSQL physical backup. Verify database readiness, actual synchronous replication, backups and HTTPS before reopening normal operation. Keep the old private material securely until rollback is no longer needed, then retire it according to the secret policy.

## Evidence boundary

The [cloud deployment evidence](cloud-deployment-evidence.md) records the actual HTTPS, encrypted backup, two-store isolated restore, synchronous outage and current-Owner verification results, plus the real application journey. Host bootstrap checks confirmed Docker/Compose, key-only SSH, primary swap, NFSv4 exports and ownership. The first cloud-init run recorded a missing `/run/sshd` error; repaired bootstrap scripts completed successfully, and that original cloud-init status remains as historical evidence.

The broader [local implementation evidence](implementation-evidence.md) and [frontend evidence](frontend-verification.md) are separate from this deployment's acceptance. Keep the cloud release record current when images, configuration or verification results change.

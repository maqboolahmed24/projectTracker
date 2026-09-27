# Fresh Azure host preparation

Use `cloud-init.primary.yaml` only for a fresh Ubuntu 24.04 amd64 primary at `10.42.0.4`, and `cloud-init.standby.yaml` only for its fresh standby at `10.42.0.5`. Supply the administrator SSH public key through Azure. These files contain no passwords, application secrets, SSH keys or database data. They do not provision VMs, disks, containers or databases.

Ubuntu supplies [docker.io](https://packages.ubuntu.com/noble/docker.io), [Docker Compose v2](https://packages.ubuntu.com/search?keywords=docker-compose), and [the NFS packages](https://packages.ubuntu.com/noble-updates/nfs-kernel-server). The explicitly enabled `noble-updates` archive currently supplies Compose 2.40.3; the bootstrap rejects Compose below 2.30 or a missing `--no-env-resolution` option. Docker Buildx is included for native x64 image builds. No administrator is added to the Docker group: use `sudo docker`.

Both hosts disable root/password/interactive SSH login, preserve Azure's key-authenticated administrator, and set Docker's local log driver to three files of at most 10 MiB per container. Package installation precedes bootstrap. The NFS export file is deferred until after package installation; the standby creates its directories before explicitly restarting NFS.

The standby exports only these paths to primary `10.42.0.4/32`, synchronously over NFSv4 TCP on its private address:

| Path | Owner/mode | Root mapping |
| --- | --- | --- |
| `/srv/maqbool-backups/app` | `999:999`, `0700` | `root_squash,anonuid=999,anongid=999` |
| `/srv/maqbool-backups/control` | `999:999`, `0700` | `root_squash,anonuid=999,anongid=999` |
| `/srv/maqbool-backups/records` | `root:root`, `0700` | `no_root_squash` only for this export |

The recovery operator requires records to retain its root UID. App/control repositories do not receive this exception. Verify the pinned PostgreSQL recovery image uses UID/GID 999 before use. Restrict standby TCP 2049 to the primary private `/32` in the Azure NSG; no public NFS ingress is needed. This configuration does not create firewall rules or encrypted NFS transport.

After `sudo cloud-init status --wait --long` succeeds on both hosts, inspect `sudo exportfs -v` and `/proc/fs/nfsd/versions` on the standby. On the primary, explicitly run `sudo /usr/local/sbin/maqbool-mount-recovery-records` only once exports and routing are ready. This installs the reviewed fstab fragment and starts the mount with a 30-second initial mount limit. It refuses conflicting mounts/fstab entries or a nonempty underlying directory. The `hard,_netdev,noauto,nofail` configuration does not attempt NFS during initial provisioning or ordinary boot. The recovery operator's later explicit mount dependency can start it; hard-mounted I/O waits during an outage, so never replace it with a local directory or a soft mount.

The primary optionally creates `/swapfile.maqbool-build`, a new 2 GiB file on an ext4/XFS root filesystem only when at least 4 GiB is free. Existing paths, symlinks, swap areas and database files are untouched. The new file is mode `0600`, published without overwriting another file, activated and added to fstab. An unsupported filesystem or insufficient free space skips this optional step. No disk is formatted, repartitioned or resized.

Local checks cover YAML parsing and embedded Bash syntax only. Cloud-init execution, SSH access, installed package versions, NFS UID mapping, service startup and mount behavior still require verification on the fresh Azure hosts before following the deployment release sequence in `README.md`.

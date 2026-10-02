# Azure deployment evidence - 27 September 2026

Public origin: **https://maqbool.denmarkeast.cloudapp.azure.com**. The frontend, API, worker and databases run on Azure. The GitHub source is [projectTracker](https://github.com/maqboolahmed24/projectTracker). This record distinguishes cloud checks from the earlier local/browser release evidence.

## Infrastructure and spending boundary

Azure for Students is enabled with **spending limit On**; no paid upgrade was enabled. The two Denmark East VMs use availability zones 1 and 2. This consumes finite student credit and is not permanent free hosting. The subscription can stop providing the service when credit or eligibility expires. See the [operating guide](cloud-operations.md) for preservation and shutdown procedures.

The primary runs the application and current databases. The second host runs the synchronous security replica and private NFS storage for encrypted backups and checkpoint records. These hosts have separate failure domains within one region/subscription; this is not automatic failover or protection against subscription deletion.

Existing local containers, accounts and project data were left intact. No local workspace was copied or rebound to the cloud origin. Customer activation or a supported migration remains a separate handoff decision.

## Artifact identity

All application images are Linux/amd64 and were explicitly loaded before Compose startup. Local image IDs below are Docker-inspected immutable IDs, not interchangeable registry manifest digests.

| Component | Immutable artifact |
| --- | --- |
| API and worker | `sha256:ca06e0fefe451a3f4adf6cdbfc08ad64c24e3718ea0e6d96ab8f276dbd3cb721` |
| Frontend | `sha256:6d82ec60262beacb1ab19354fdd95b0bd7e2aeb8def952fa5f915297218aeb09` |
| PostgreSQL 18 / pgBackRest | `sha256:53a56c16d2ad3379df99fdd92d4943723f82927a0ad30132f4d9a30cdd9ccdf4` |
| Recovery operator | `sha256:ef8c2e1c958c834a0e10d6e473d45a081fd3d6ed90088f4772d99f31e04811c5` |
| HTTPS gateway | `caddy@sha256:0c994536bddb66445885237f1a5dcc1916bccea922661c76b4e9fc24061f9b52` |

The application source is the published `0a94d52cb0cd653c77b61cbe44803de793bcfa90` release. Subsequent changes concern deployment, startup and operating documentation. The recovery image includes the protected runtime-password copy fix. Reviewed cloud manifests and validation scripts are mounted from the host release into the operator. Private configuration, CA signing material and database/backup secrets are excluded from Git.

## Verified on the actual cloud hosts

- HTTPS returned 200 with successful certificate validation; HTTP redirected to HTTPS. The branded welcome screen rendered in the browser. HSTS, CSP and no-store response headers were present.
- API, worker, frontend and both primary databases passed their health checks. Ten application migrations and twelve control migrations applied; worker bootstrap completed.
- Database readiness authenticates the restricted application role over verified TLS. Plaintext TCP authentication was rejected. Public connection probes could not reach database, worker or NFS ports.
- The security replica was streaming synchronously over TLS from the expected private peer. During a controlled 3.679-second replica outage, a fixture write waited at PostgreSQL `SyncRep` without acknowledgement. Restart allowed the commit, and its row was read on the standby. The probe table and restart timer were removed.
- Encrypted full backups completed for both stores and pgBackRest verification passed. Isolated named-point restores of both stores recovered the selected earlier fixture marker while each current primary retained the later marker. Restore containers had no network and read-only repository mounts; both were stopped after inspection. This physical drill completed in 43.667 seconds for tiny fixtures, not a production RTO guarantee.
- NFS checkpoint records passed ownership, restrictive-mode and file/directory fsync checks. Private database certificates expire on 27 September 2027; their CA expires on 26 September 2029.
- Twenty-seven focused recovery tests passed after deployment fixes. The preceding published revision `e6632b3` passed [GitHub CI](https://github.com/maqboolahmed24/projectTracker/actions/runs/36353251270).

Startup validation exposed and repaired two configuration issues before customer use: the restricted-role secret needed a PostgreSQL-owned copy before initialization dropped privileges, and comma-separated tmpfs options needed quoted YAML strings. The existing fresh cloud volumes were preserved; only the missing runtime roles/grants and TLS rejection rules were explicitly completed. Readiness and resolved-configuration guards now detect these failure modes.

## Application and recovery acceptance

The bounded API journey passed with **135 real HTTPS requests**. It covered Owner activation, password and signed-device authentication, encrypted project creation/editing, approved member enrolment, a task shared by two assignees, encrypted comments and background inbox notifications/read state, task completion/cancellation, project completion/archive, logout and reauthentication.

The same run captured a signed encrypted checkpoint, made a later edit, restored only its fixture workspace, rejected old sessions and denied ordinary work during quarantine. The current Owner decrypted three samples across two key epochs and signed verification. Both collaborators then read the selected earlier task content. Current people/device authority was preserved, data generation advanced, and the saved verification receipt matched the complete signed proof. This completed at **2026-09-27T22:21:05.492Z**. The combined physical and Owner drill evidence was checked against the stored verified restoration before recording that actual completion time in recovery health.

The recovery supervisor is installed, enabled and active. Its first tick completed, covered all three disposable workspaces with current checkpoints, and reported `/health/recovery` **HTTP 200, healthy**, with a durable synchronous replica and zero replay lag. The cloud journey uses the production client crypto and HTTP transports; it is API-level evidence, not a new execution of the full browser/IndexedDB suite.

The [earlier composed recovery evidence](checkpoint-12-evidence.md) covers reset/removal/phrase-rotation and deletion scenarios. Those results are separate from the cloud checks and must not be presented as a fresh cloud execution of that complete matrix. The [frontend verification](frontend-verification.md) is likewise separate from this deployment's browser welcome-screen inspection.

Detailed fixture identifiers and operation outputs stay in the ignored local deployment evidence directory. Fixtures contain generated test data only. Real customer activation has not been performed by the agent, and customer passwords or Owner phrases are not part of this release record.

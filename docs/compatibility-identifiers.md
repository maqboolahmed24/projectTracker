# Maqbool compatibility identifiers

The product, package and current launch component are named **Maqbool**. The
launch component lives in `brand/maqbool-launch/` and exports
`mountMaqboolLaunch`. Its source ZIP uses the same directory and filenames.

Some technical identifiers retain the earlier `ukda` prefix. These are existing
data formats or deployment contracts, not a second product name. Renaming them
as text would break existing accounts, encrypted work, backups or deployments.
Keep their exact values when following operational instructions.

| Retained identifiers | Why the existing values matter |
| --- | --- |
| `ukda.hkdf.v1`, `ukda.device-wrap.v1`, `ukda.content.v1`, `ukda.recipient.v1` and other versioned cryptographic purposes | Key derivation, authenticated encryption and signed messages depend on the exact bytes. Changing a prefix does not migrate the encrypted data or signatures. |
| `ukda.opaque.ristretto255.argon2id-m64-t3-p4.v1` and `ukda:<workspace>:<account>` | Existing password registrations are bound to this configuration and account identity. |
| `ukda-recovery-v1`, `ukda.checkpoint.v1`, `ukda.content-data.v2` | Recovery-key derivation, checkpoint authentication and encrypted-content transforms must remain readable across releases. |
| `ukda-device-v1`, `ukda-remembered-profiles-v1`, `ukda-activation-v1` and other IndexedDB store names | Browsers already store approved-device material, remembered profiles and pending operations under these names. Opening new names would leave that state behind. |
| `ukda.appearance`, `ukda.ui.completed-setup.v1` | These browser preferences preserve the chosen appearance and completed-setup state. |
| `__Host-ukda_session` | The frontend proxy, server and browsers agree on the existing secure session-cookie name. Its security attributes are unchanged. |
| `ukda.workspace_id`, `ukda.profile_id`, `ukda.workspace:`, `ukda.job:` | SQL tenant policies and coordinated transaction locks use these names. Inconsistent substitutions could deny access or stop different processes from sharing the same lock. |
| `ukda_migrations`, `ukda:sql-migrations:v1` and existing migration files | The ledger, lock and checksums protect the database migration history. Previously applied migrations must not be rewritten to rebrand them. |
| `ukda`, `ukda-cloud-primary`, `ukda-cloud-standby`, database/role names and recovery labels | Existing Compose services, persistent volumes, database accounts, replication and restore tooling refer to these deployed names. Changing a project name can create a separate empty stack. |
| `UKDA_API_ORIGIN`, `UKDA_FRONTEND_PORT`, `UKDA_API_PORT`, `UKDA_OPERATOR_ID` and other `UKDA_*` environment settings | Existing deployment manifests, protected configuration and operator commands use these setting names. Maqbool product branding does not imply renamed configuration keys. |
| Versioned service-token contexts and notification identifiers | Persisted tokens and deterministic event identities must continue matching their original values. |

Changing one of these contracts requires an explicit, versioned migration with
compatibility tests, a rollback path and retained access to existing encrypted
data. This branding change performs no such migration and does not rename the
running cloud infrastructure.

## Historical records and third-party attribution

The design archive contains original Google Stitch responses and generated
screens. Historical security reviews retain the original report identifiers,
reviewed paths and hashes. Those records are not rewritten to claim a newly
named file had the same historical bytes. The current launch integration uses
the Maqbool paths documented above.

The current launch mark is original Maqbool artwork. Its
[artwork provenance](../brand/maqbool-launch/assets/SOURCE.md) documents the
replacement. Earlier Git revisions retain the previous artwork's UK Data Service
attribution and original source URLs; those records must not be re-labelled as
original Maqbool work. Third-party attribution is historical evidence, not
current product branding.

Older Git commits also retain their historical names. This update changes the
current source tree without rewriting commit history or invalidating existing
clones and references.

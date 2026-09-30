# Assisted UI cloud release

The updated frontend is live at [Maqbool](https://maqbool.denmarkeast.cloudapp.azure.com/), tracked in [pull request #2](https://github.com/maqboolahmed24/projectTracker/pull/2), stacked on the project-files branch.

## Deployed version

- Frontend source: `f227ddd0dd46077fe9d4dc053ad391ca589c1487`.
- Frontend image: `sha256:c3beb2fc7af52f1f765ff61b7f5da38450ff6ed4233360b8dee70984ce9a99ad`.
- Source archive SHA-256: `3668852a20f10cde51d7b02b0bee3834cf9fca1d32e58154a281b32dddcd2109`.
- Container started **30 September 2026 at 01:25:10 UTC**; healthy service snapshot at **01:25:16 UTC**.
- Staged frontend source and private cutover evidence: `/opt/maqbool/releases/assisted-ui-f227ddd0dd46`.

Only the frontend image pin and container were replaced. The release tool compared backend, protocol, dependencies, migrations, operational scripts and Dockerfiles byte for byte before cutover. API, worker, gateway and both database container IDs, image IDs and start times were unchanged afterward. Recovery supervision remained active and healthy, and its process/start identity was unchanged.

The backend/operations source link remains `/opt/maqbool/release` → `/opt/maqbool/releases/files-7a04aa6`. Backend source is `7a04aa63fb9d25908146a0dfb7b2cdff6139eb80`; this separate frontend revision must not be mistaken for a backend migration. No new cloud resource, licence, workspace, storage allowance or paid service was created.

## Verification

[Local acceptance](assisted-ui-acceptance.md) records 21 distinct passing browser cases across Chromium/WebKit, one intentional WebKit exclusion, TypeScript and production builds. Full repository CI was still in progress when documented; no successful conclusion is assumed.

Public HTTPS checks returned success for the home page, application endpoint, companion guide, companion download metadata and current initial/dynamic assets: **13 requests** total. The deployed UI JavaScript and CSS hashes match the running container. The JavaScript contains the reviewed preview expansion, priority choices, search and access-refresh behavior:

- `/_next/static/chunks/489.599d1b54f0520e37.js`: SHA-256 `987ab1af153102feef6c96ef7ee74164ffbc841d8daa40c7be15f46f9af32a12`.
- `/_next/static/css/98bc6044d3758d99.css`: SHA-256 `0ce64fc7462044e0849ca75d47e45d6a6662b8debc013a0e5a141fb9dbdc1d3f`.

The live welcome screen was reloaded and visually inspected in the in-app browser after the startup animation. It rendered successfully with no captured console warnings or errors. This is public-page evidence, not a signed-in production workflow test. Existing synthetic activation fixtures retained no approved-device credentials/password, so authenticated verification used the isolated real backend without consuming activation keys or changing customer access.

The existing Mac companion remains 39,564,449 bytes, with ZIP SHA-256 `6e50440f8ffe56284f01128929adca1cf5df59c248c178b58879c4e4bba089db`. Its staged checksum and served content length match the previous release.

## Rollback and evidence

The previous frontend image is `sha256:a30a86d960a1b1e69b4d081e693212bf8146574e463aecd8c9edea8907295c42`. Rollback replaces only `UKDA_FRONTEND_IMAGE` in the protected environment and recreates only the frontend using the existing Compose profile with `--no-deps --wait`. Do not reset databases, change the backend source link or restore the entire environment over unrelated later changes.

Private before/after snapshots are under the staged release's `release-evidence` directory. Local nonsecret public asset checks are retained at `.local/azure-deploy/assisted-ui-public-evidence.json`. Test-selector and documentation followups do not change this deployed runtime.

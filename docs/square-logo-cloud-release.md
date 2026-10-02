# Square logo cloud release — 2 October 2026

The original square line logo is live in the workspace startup, identity screens, navigation and favicon, and on the public landing page. The startup drawing sequence and centre-to-corner transition are preserved.

## Deployed versions

- Workspace: [Maqbool](https://maqbool.denmarkeast.cloudapp.azure.com/), deployed at **03:29 BST** (02:29 UTC).
- Source: [`3738417c3d4856fd48e4d80f36ad56304823abfb`](https://github.com/maqboolahmed24/projectTracker/commit/3738417c3d4856fd48e4d80f36ad56304823abfb), based on production source `5efc69342587840fd142c2fabc415066c4c4e09d`.
- Frontend image: `sha256:695830cc3a092e7e17de7f425edd52aa8034543532313d60806cbfe46b4a5ba0`.
- Frontend source directory: `/opt/maqbool/releases/square-logo-3738417c3d48`.
- Landing page: [Maqbool introduction](https://maqbool.denmarkeast.cloudapp.azure.com/landing/), updated at **03:30 BST** (02:30 UTC).
- Landing target: `releases/85459fd411b3/site`; only `assets/maqbool-mark.svg` changed from `releases/1df048c25f23/site`.
- Canonical SVG SHA-256: `c919189a60b81853db7efbff209b85f60455f514c3d05a1edc22b74e083f1930`.

This release patches the current production frontend, preserving its newer task ordering, workspace updates and project-card interactions. Only the frontend image pin/container and the landing-page symlink changed. Backend, worker, gateway, databases, recovery supervisor, operational configuration outside the frontend pin, and the backend source link were verified unchanged. No database migration or new cloud resource was needed.

## Verification

Frontend TypeScript and the production container build passed. The candidate homepage and API proxy passed before cutover. All 27 public JavaScript/CSS asset hashes matched the built image; four public routes responded successfully; the served brand modules and SVG matched the reviewed source. The companion archive remained byte-identical (`6e50440f8ffe56284f01128929adca1cf5df59c248c178b58879c4e4bba089db`). All ten landing files matched the new manifest, with the guidebook and other nine files unchanged.

Live Chromium checks passed in light, dark and reduced-motion modes, with no captured page errors. The logo contains sixteen square segments. Normal motion retains sixteen 1180 ms reveals, sixteen 1520 ms slides, the 720 ms corner handoff and 580 ms backdrop fade. Reduced motion uses the existing short fades. The loading overlay is removed, the application becomes interactive, and the settled logo is visible. The landing feature explorer still opens within the same viewport.

Checks used public screens and health endpoints; no customer workspace content or account was changed.

## Rollback and evidence

The previous frontend image remains available as `sha256:79a14080131bf9aba321df3f644e1da51819ea43eb085e77bc3fb08e7656ba46`. Its guarded rollback changes only the expected frontend pin and recreates that container:

```sh
sudo /opt/maqbool/releases/square-logo-3738417c3d48/square-logo-rollback.sh \
  3738417c3d4856fd48e4d80f36ad56304823abfb
```

The separately guarded landing rollback restores its preceding static target:

```sh
sudo /opt/maqbool/landing/releases/85459fd411b3/evidence/rollback.sh
```

Frontend receipts are under the source directory's root-restricted `release-evidence/` folder. Landing receipts and the static deployment script are under `/opt/maqbool/landing/releases/85459fd411b3/evidence/`. Local scripts, hash checks, browser screenshots and results are retained in the ignored `.local/azure-deploy/` directory. Never commit private deployment configuration or credentials.

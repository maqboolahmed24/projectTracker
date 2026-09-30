# Task completion fix — 30 September 2026

Tasks with linked files previously sent “Mark complete” to Files and evidence without showing all the steps needed to finish. They now offer **Prepare file review**, with actionable review setup, output and reviewer requirements. Ordinary tasks retain the confirmation before completing.

File-presence checks refresh when returning to Details and offer a retry on failure. Evidence refreshes after file-link or project-planning changes, including blocker resolution. Older asynchronous reads cannot replace a newer review context. Programmatic tab changes move keyboard focus to the destination tab.

The existing rules remain in place: linked files need outputs and an independent exact-version review; blockers, read-only access and project/wave state prevent submission or acceptance. Review setup reuses the existing Owner workflow for all unfinished tasks.

## Verification

- Main and frontend TypeScript checks and production frontend build passed.
- Six browser journeys passed across Chromium and WebKit: failed file-check recovery and persisted ordinary completion; source-only prerequisites, review setup, output upload, blocker resolution and independent approval; full project lifecycle regression.
- The blocker journey reproduced a stale planning-context failure before the final fix and passed afterwards.
- Results: `test-results/task-completion-results.json`; screenshots: `test-results/task-completion-final-artifacts/` (local, ignored).

Authenticated journeys used the isolated test backend and real encrypted client operations. Production verification checked public rendering, served assets and service health; it did not modify customer tasks or accounts.

## Live release

- URL: https://maqbool.denmarkeast.cloudapp.azure.com/
- Runtime source: `93b5c2f903a9b57f96de2db129d692f1c1885e5f`.
- Frontend image: `sha256:cc43078043addfde57dafde00d1a350d0aa047b5a5ee518059f672f98c9c05f1`.
- Healthy after rollout at 2026-09-30 01:49 UTC; 13 public HTTPS checks passed, including exact served asset hashes and all four new action/guidance labels. Live welcome screen rendered with no captured console errors.
- Only the frontend container changed. API, worker, gateway, databases, recovery process, other image pins and backend release symlink were verified unchanged. No migrations or new cloud resources.
- Prior frontend image remains available: `sha256:c3beb2fc7af52f1f765ff61b7f5da38450ff6ed4233360b8dee70984ce9a99ad`.
- Private before/after evidence: `/opt/maqbool/releases/task-completion-93b5c2f903a9/release-evidence/`.

For rollback, restore only `UKDA_FRONTEND_IMAGE` to the prior image and recreate only the frontend using the existing compose configuration with `--no-deps --wait`. Preserve all other configuration and services.

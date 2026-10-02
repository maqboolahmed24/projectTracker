# Approval and Settings layout correction

The received approval request previously rendered as a full-width card before the entire Settings layout. It stretched its actions across the page, displaced the navigation and heading, and duplicated the approval form embedded in Account settings.

Incoming links, **Review approval** in People, and **Review access requests** in Account and People now open the same native dialog. It is bounded to 620 pixels, fits narrow screens, supports keyboard dismissal, and preserves the underlying request when closed. Completed approvals remain visible until dismissed.

The correction also:

- Resets the dialog when reopening the same invitation, and fixes the initial saved-request load racing the incoming request selection.
- Disables switching requests while a check is running and clears passwords and errors when returning to the request list.
- Places interrupted-save recovery after the Settings content so each page begins with its own heading.
- Uses the current person's already verified directory profile for the Account card. This removes a redundant profile read that could overlap with approval password confirmation. The directory verifies the same signed profile content and authority before displaying it.

## Verification

All tests used separate temporary application and control databases, real controllers, cryptography, API and the packaged Next frontend. Customer data and requests were not used as test fixtures.

- `test-results/frontend-approval-workflows.json`: 15 passes across Chromium, Firefox and WebKit for approval layout, invitation and password recovery, second-Owner setup, new-device approval, and interrupted Settings saves.
- `test-results/frontend-approval-final.json`: six passes on the final build, repeating the layout regression with the verified Profile card and checking activation, chosen avatar and Owner recovery in all three engines.
- Production builds and frontend TypeScript checks pass. The final build log is `test-results/frontend-approval-final-build.log`.

The two runs represent 18 distinct journey/browser combinations; three layout cases were repeated after the Profile card adjustment. This is focused follow-up verification, not a rerun of the entire original release suite.

Layout checks cover 1440, 390 and 320-pixel viewports in light and dark mode, with no horizontal overflow. They verify a single modal, Settings heading order, disabled navigation during an in-flight claim, dismissal without an approval or revocation, and reopening the same request. Selected waiting-state screenshots and measured geometry are in `test-results/frontend-review/approval-layout/`; they contain disposable fixture content and no passwords, private links, recovery words or security comparison codes.

Only the frontend is updated at the existing `http://localhost:3400` address. The browser needs a refresh to load the correction. Backend services, database volumes, workspace origin and pending requests are preserved. Release image, source hashes and health checks are recorded in `test-results/frontend-approval-release.json`. Test database isolation and cleanup are recorded separately in `frontend-ui-isolation.json` and `frontend-ui-isolation-cleanup.json` under `test-results/`.

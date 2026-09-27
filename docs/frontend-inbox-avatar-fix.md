# Inbox rows and remembered avatars

The Inbox row had child styles but no parent layout. Its content touched the card edge and the read/unread action dropped underneath at desktop widths. Rows now have consistent padding, a flexible text column, a separate action column and dividers. Long text wraps without pushing controls outside the card. On small screens, the action sits below the text with matching indentation. Refresh and pagination controls sit together below the list.

The sign-in screen used the default avatar because remembered profiles stored the name and device reference without the chosen avatar. The fix saves a validated avatar selection alongside the local remembered name after a verified profile read, and uses it on both the remembered-profile card and password screen. The encrypted profile remains the source of truth; no public profile lookup or avatar-bearing link is added.

Older remembered cards remain compatible. Their avatar is refreshed after an approved sign-in. Forgetting a device removes its remembered details, including the avatar.

Focused verification and deployment receipts for this change are recorded separately from the earlier product and device-approval releases.

- Eight pure local-cache tests passed, covering old cards, avatar validation, isolation, name-only updates, Forget cleanup and stale-session guards. TypeScript validation also passed. See `test-results/frontend-avatar-local-cache-unit.log`.
- Twenty-four actual Inbox component cases passed across Chromium, Firefox and Playwright WebKit, in both themes at 1440, 701, 700 and 320 pixels. These use in-memory fixture data without an API or database. See `test-results/frontend-inbox-layout.json`.
- Three complete activation/recovery journeys passed against isolated databases, verifying the exact chosen avatar on both entry screens through theme changes, reload, logout and recovery. See `test-results/frontend-avatar-e2e.json`.
- The real three-person collaboration/Inbox journey passed in Chromium, including comment notifications, opening the related task and read/unread behavior. See `test-results/frontend-inbox-e2e.json`.

The production build passed and the tested frontend image `sha256:d5e48bff2b6f4c88d4e072d9c1795f4da91666438235c29f58a34da431260578` is deployed at the existing `http://localhost:3400` address. All six services are healthy, with unchanged API, worker and database container identities. Image/source verification is in `test-results/frontend-inbox-avatar-verification.json`; deployment checks are in `test-results/frontend-inbox-avatar-release.json`.

The disposable test databases and preview were removed after verifying they contained no workspaces or active sessions. Cleanup is recorded in `test-results/frontend-avatar-isolation-cleanup.json`. The real workspace was not used as test data. Reloading the app while signed in refreshes older remembered avatar details for the next sign-in.

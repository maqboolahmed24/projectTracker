# Stable dialogs and editing popups

This follow-up addresses task and wave windows changing size when switching tabs, and editing controls appearing inside the page instead of a popup. It follows the earlier [approval and Settings correction](frontend-approval-fix.md). It changes frontend presentation and interaction; backend commands, status rules, permissions, encryption and database schemas remain unchanged.

## Cause and correction

Task and wave dialogs previously sized themselves from their current content. A long Details view and a short Discussion or Activity view therefore produced different dialog heights and positions. Headers and navigation also shared the scrolling content. Some controls, including Project options, password changes and reporting timezone edits, were intentionally rendered as inline panels. They expanded the page when the user expected a focused popup.

The shared `Modal` now renders its native dialog through a portal directly under the document body, outside the page layout. A detail layout provides a consistent frame; the title, close control, tab navigation and optional footer stay outside one scrollable content region. Compact confirmations retain a content-sized layout. Invitation and person-management forms use a separate stable form layout so choosing a different role or action does not resize the window.

## Expected behavior

- **Task details:** Details, Discussion and Activity use the same frame at a given viewport. Long content scrolls inside the window, while the title, close button and tabs remain available. Selecting another tab starts its content at the top.
- **Waves and phases:** Work, Updates and History follow the same behavior. The Work tab contains the objective, dates, lead, completion criteria, actions, tasks and milestones. Milestone details and Project activity also use the detail frame.
- **Responsive layout:** Detail dialogs are bounded to 860 pixels wide and 760 pixels high on larger screens, with viewport margins. On phones they use nearly the available height. Titles wrap; metadata uses a responsive grid; assignee avatars and discussion actions fit narrow screens. Table wrappers establish a positioning context so visually hidden accessibility labels remain inside their horizontal scroll container instead of widening the page. Tables still scroll horizontally when needed. Both themes retain the existing neutral palette.
- **Project options:** A modal replaces the inline options card. Edit details, Task review, View activity, Complete project and Cancel project close it before opening their next dialog. Start, reopen, archive and notification changes keep it open so their result or retry controls remain visible. Manage access closes it before navigating to People.
- **Password changes:** Account settings shows a summary and **Change password** button. The popup contains the existing password-change flow, with one heading. Its authentication-clear and automatic sign-in sequence is preserved.
- **Reporting timezone:** Workspace settings shows the current value and **Change timezone** button. The selector and password confirmation share one dialog. The reviewed settings are captured when it opens; after an authenticated attempt, fields lock so retrying resumes the same operation. Owner and workspace restrictions still apply.

## Keyboard access and retained work

Task and wave navigation uses linked `tablist`, `tab` and `tabpanel` elements. Left/Right arrows and Home/End select and focus tabs. Inactive panels are hidden; Discussion and Updates mount on their first visit and stay mounted while that detail window remains open, preserving unsent drafts when switching tabs. Draft retention is limited to that open window, not browser reloads or reopening a closed task.

Each task, wave and milestone detail is keyed by its project and record identity so switching records does not reuse another record's local state. Nested editors keep their parent dialog open and return focus to the initiating control when dismissed. Native modal behavior confines interaction to the top dialog; Escape and the close control dismiss it. The page remains scroll-locked until the last dialog closes. The content region is labelled, keyboard-focusable and has a visible focus outline, allowing keyboard scrolling of long content.

## Test isolation and coverage

The focused browser tests use the real client controllers, cryptography, Worker, API, database writes and packaged Next frontend. They do not use the customer's workspace or requests as fixtures. A private runner, `.local/run-modal-frontend.mjs`, checks both runtime and administrative connections against separately named temporary application and control databases before starting Playwright. It also validates the isolated HTTPS origin. Connection credentials remain in ignored local configuration, not this report.

`test/frontend/modal-layout.spec.ts` covers task and wave geometry across tabs, retained drafts, internal scrolling, keyboard navigation, nested-editor dismissal, Project options remaining outside page flow, password and timezone cancellation, and stable person-management forms. Measurements include desktop and 390/320-pixel phone widths in light and dark themes. Existing work, account and Settings journeys have been updated to enter the new popups and remain available as workflow regressions.

Automatic screenshots, videos and traces remain disabled. Selected visual captures are limited to disposable fixture content and empty credential forms. The intended measurement and screenshot directory is `test-results/frontend-review/modal-layout/`; database isolation is recorded separately in `test-results/frontend-modal-isolation.json`.

A separate narrow-screen diagnosis is recorded in `test-results/frontend-modal-overflow-diagnosis.json`. In Chromium, a disposable People table using the actual stylesheet and local font reproduced a 378-pixel document at a 320-pixel viewport. Absolutely positioned `.sr-only` labels extended beyond the unpositioned table wrapper. Giving `.table-wrap` `position: relative` reduced the document width to 320 pixels while retaining the table's 391-pixel internal scroll width. This isolated geometry check did not use customer data, a fixture or a network route; it is diagnostic evidence, separate from the pending final browser suite.

## Verification and release — 27 September 2026

The final image passed **9 browser cases, with no failures, skips or retries**, in Chromium, Firefox and Playwright WebKit. Each browser ran the task/wave layout journey, the account/timezone/person popup journey, and the existing Settings save/retry workflow. These are browser-engine checks, not a claim of a new branded Safari release run. Results: `test-results/frontend-modal-final.json` and `test-results/frontend-modal-final.log`.

The preceding broader run also exercised access approvals, remembered sign-in/password changes, project completion/archive, and the shared-task review/Inbox journey. It recorded 16 passes, 3 failures and 2 intentional skips (the three-person shared-task journey runs in Chromium only). The failures exposed the narrow People table overflow in Chromium/WebKit and a WebKit test assumption that clicking a button necessarily focuses it. The table fix was added; nested focus restoration now explicitly opens the editor with keyboard Enter and checks both Escape and Cancel. All affected layout and Settings cases were then rerun successfully on the final image. The earlier report remains available as `test-results/frontend-modal-workflows.json`; it is not represented as a fully passing final-image run.

Measurements wait for the dialog's own finite entry animation before comparing geometry, retain the 1-pixel tolerance, and cover actual PageDown scrolling as well as programmatic boundary checks. Desktop/mobile light/dark captures were visually inspected, including task Details and Discussion, wave Work, and narrow account/person forms. Geometry files and selected images are under `test-results/frontend-review/modal-layout/`. Frontend TypeScript checks and the production Docker build passed; build output is in `test-results/frontend-modal-build.log`.

The tested image `sha256:d609675dcc87fa8fe864e09a02561771d2d020bded7150094875f491a6113174` is deployed at `http://localhost:3400`. Only the frontend container was replaced. The API, worker, application/control databases and control replica retained their container IDs and images, and all six services were healthy after deployment. Public page, application, startup-brand and client-bundle checks returned 200, as did worker readiness, queue and recovery checks. `test-results/frontend-modal-release.json` records these checks and the source hashes.

The disposable preview container has been removed. Final database cleanup is recorded separately in `test-results/frontend-modal-isolation-cleanup.json`; no customer workspace was used as a fixture.

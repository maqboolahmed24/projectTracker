# Assisted UI acceptance

This bounded pass makes Maqbool clearer without replacing its identity, lifecycle rules or permissions. The existing geometric logo and startup handoff, charcoal dark theme and real workspace data remain in use. Google Stitch supplied six reviewed light/dark references; see [design provenance](../design/assisted-ui/README.md).

## Delivered behavior

- Planned project cards and headers expose **Start project** to people who can plan that project. Existing planning receipts and interrupted-save recovery handle the action. Cards retain a separate **Open project** control.
- Home shows actual personal assignments and reviews. Review links open the review view. Project, wave and task guidance explains the immediate prerequisite, responsibility or read-only state and exposes only permitted actions.
- Priority exposes Low, Normal and High as native, keyboard-accessible radio choices instead of a dropdown in task creation and editing. Selection persists through the real backend.
- Successful access approval refreshes project eligibility along with the people directory, so newly joined teammates can be assigned immediately. A refresh failure preserves the completed approval and shows a reload notice.
- Work search icons stay inside their fields and adjacent filters stay together. Long names wrap, task dialogs retain their frame across tabs, and opening/closing a task retains the underlying project scroll position.
- Global search uses an honest icon button with a labeled, focused search dialog. Both Ctrl+K and Command+K open it. Search trims whitespace and opens actual tasks or waves, including return navigation from a wave into its milestone.
- File previews have expand/restore controls. Expanded geometry remains stable across tabs; Escape first restores the window and then dismisses it. Small-screen file actions wrap without overlapping the size/source summary.
- Busy buttons keep their size, avatars derive their image from the current selection, breadcrumbs name the current project/section, help offers real next steps, and obsolete future-feature cards no longer occupy Settings. Legacy settings links retain a way back.

## Release gates

The production frontend build, main TypeScript build and both TypeScript checks pass. The accepted browser evidence contains **21 distinct passing journey/engine combinations across 11 journeys**, plus one existing intentional WebKit skip. These are targeted runs, not a claim that one uninterrupted run passed 22 tests.

| Journey | Chromium | WebKit |
| --- | --- | --- |
| Project cards: direct start, lost reply recovery, read-only access | Pass | Pass |
| Assisted task steps, prerequisites, wave search and navigation | Pass | Pass |
| Files: versions, external references, exports and preview expansion | Pass | Pass |
| Task tabs, internal scrolling and nested editing | Pass | Pass |
| Account, timezone and person dialogs | Pass | Pass |
| Priority: pointer/keyboard selection and saved values | Pass | Pass |
| Roles, teams, timezone and legacy settings links | Pass | Pass |
| Invitation revocation, export acknowledgement and deletion cancellation | Pass | Pass |
| Completed workspace update followed by a failed refresh | Pass | Pass |
| Two assignees, independent review and Inbox navigation | Pass | Intentionally excluded |
| Project lifecycle through completion, archive and reopening | Pass | Pass |

The three-person journey is explicitly limited to Chromium by the existing test; the core work journey runs in both engines. These checks use real isolated PostgreSQL-backed fixtures, not a separate mock frontend. Geometry and screenshots cover light/dark desktop layouts, the wide Work toolbar, phone layouts, and dialogs down to 320px. Priority was checked at 390px; file expansion at desktop and 390px.

Retained local evidence is in `test-results/assisted-ui-base-results.json`, `assisted-ui-controls-results.json` and `assisted-ui-work-results.json`, with screenshots under `frontend-artifacts`, `assisted-ui-final-artifacts`, `assisted-ui-work-final-artifacts` and `frontend-review/modal-layout`. The deduplicated accepted passes are 6 + 13 + 2. The final lifecycle rerun passed both engines in 99 seconds. Early tests found the native-dialog autofocus bug and stale member eligibility, both corrected; old keyboard-tab and newly duplicated project-action selectors were corrected before passing reruns. Interrupted runs are not counted as passes.

A full repository CI run on runtime commit `f227ddd0dd46077fe9d4dc053ad391ca589c1487` is [run 36654470585](https://github.com/maqboolahmed24/projectTracker/actions/runs/36654470585). It was still running when the release record was written; it is not represented here as passed. This UI change does not modify backend protocol, migrations, dependencies or storage limits. The preceding backend/files release has its own completed full-CI evidence.

See [cloud release](assisted-ui-cloud-release.md) for the deployed frontend, service preservation and public verification. Authenticated workflows were verified against the real local test backend; no customer account was used for a production sign-in test.

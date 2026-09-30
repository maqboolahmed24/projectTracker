# Assisted UI acceptance

This bounded pass makes Maqbool clearer without replacing its identity, lifecycle rules or permissions. The existing geometric logo and startup handoff, charcoal dark theme and real workspace data remain in use. Google Stitch supplied six reviewed light/dark references; see [design provenance](../design/assisted-ui/README.md).

## Delivered behavior

- Planned project cards and headers expose **Start project** to people who can plan that project. Existing planning receipts and interrupted-save recovery handle the action. Cards retain a separate **Open project** control.
- Home shows actual personal assignments and reviews. Review links open the review view. Project, wave and task guidance explains the immediate prerequisite, responsibility or read-only state and exposes only permitted actions.
- Work search icons stay inside their fields and adjacent filters stay together. Long names wrap, task dialogs retain their frame across tabs, and opening/closing a task retains the underlying project scroll position.
- Global search uses an honest icon button with a labeled, focused search dialog. Both Ctrl+K and Command+K open it. Search trims whitespace and opens actual tasks or waves, including return navigation from a wave into its milestone.
- File previews have expand/restore controls. Expanded geometry remains stable across tabs; Escape first restores the window and then dismisses it. Small-screen file actions wrap without overlapping the size/source summary.
- Busy buttons keep their size, avatars derive their image from the current selection, breadcrumbs name the current project/section, help offers real next steps, and obsolete future-feature cards no longer occupy Settings. Legacy settings links retain a way back.

## Release gates

Production frontend build and main TypeScript build pass. Browser verification is in progress; final results and deployment evidence are recorded after completion. The initial browser pass found and corrected native-dialog autofocus; no initial partial run is claimed as the final gate.

The focused browser gate uses real isolated PostgreSQL-backed fixtures in Chromium and WebKit. It exercises direct project start and a lost committed reply; Owner/member/read-only controls; wave/task start; reviewer versus assignee guidance; global search/keyboard focus; modal and toolbar geometry; file versions/expansion; settings and nested dialogs; shared discussion/review/Inbox; light/dark desktop and mobile layouts. It does not establish testing on every physical browser/device.

No database, backend protocol, package dependency, deployment topology or storage limit is changed by this UI pass.

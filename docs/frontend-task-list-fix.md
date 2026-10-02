# Consistent task rows

The task list previously distributed every child with `justify-content: space-between`. Optional Blocked and High labels changed the number of children, shifting titles, statuses, dates and assignees from row to row. A `:last-child` border rule also removed every divider because each button was the only child of its list-item wrapper.

Task rows now use shared grid columns for the icon, flexible title, status/date/assignee group and opening arrow. Optional indicators stay with the title. Each row retains its native button and task-opening callback. Separators belong to sibling list items; group names and counts have explicit spacing. Three assignee avatars are visible before the existing overflow count, while the full set of names remains available to assistive technology.

A container query switches the row to a compact layout below 640 pixels, including narrow Overview cards on large screens. Titles and optional details wrap; the metadata stays visible below. The change applies wherever the shared TaskList is used: project work, waves, milestones, My work, Home and search results. Backend state, permissions and task actions are unchanged.

## Verification

Production build and TypeScript checks passed. **54 standalone visual cases passed** across Chromium, Firefox and Playwright WebKit: nine viewport/container combinations per engine in both light and dark themes, including 320/390-pixel phones, a narrow desktop card, the 639/640-pixel layout boundary and wide desktop rows. Geometry checks confirmed aligned status/date/assignee columns, separators, consistent simple-row heights and no horizontal clipping. Keyboard Enter and Space invoked the existing task-opening callback.

The actual TaskList component was bundled with disposable presentation data and the real shared UI components, using an isolated context and in-memory avatar response. This is a component layout check, not a new end-to-end backend test. No API, database or real workspace was accessed. The screenshots were visually inspected for desktop light, phone dark and narrow desktop layouts.

`test-results/frontend-task-list-layout.json` contains the measurements and hashes of the component and stylesheet tested; captures are in `test-results/frontend-review/task-list-layout/`. The build log is `test-results/frontend-task-rows-build.log`. Frontend release and runtime health checks are recorded in `test-results/frontend-task-rows-release.json`.

The tested frontend image `sha256:3080be72047231b0166cccc0595343c519c00e10874fbe4a98eea015834f42dc` is deployed at `http://localhost:3400`. All six application services were healthy, public routes/assets and worker checks returned 200, and backend container IDs/images were unchanged.

# Assisted UI: Google Stitch references

Reviewed on 30 September 2026 for the goal of making Maqbool more helpful, personal and polished while retaining its minimal interface. The actual source UI was inspected first: `frontend/work/index.tsx`, `project.tsx`, `task.tsx`, `web/globals.css` and the earlier accepted Files design notes.

The existing private Google Stitch project **5855422246659088288**, “Maqbool · Essential document work”, and shared design **assets/12527623825984102001**, version 2, were retrieved and verified before generation. All three calls explicitly used **GEMINI_3_8_FLASH**, the highest model exposed by the installed connector. Each brief requested paired light/dark screens. All calls completed on their first attempt and returned six complete screens. No further regeneration was needed. Only synthetic Studio North, Alex and Sam records were supplied.

The exact briefs, generation parameters, structured connector responses, source project/design metadata, downloaded HTML references and returned screenshots are in this directory. `screens.json` is the compact index. The connector reports 2560×2048 screen metadata but its returned screenshot URLs delivered 512×410 previews; all six previews and corresponding HTML were inspected. These are reviewed visual references, not functioning application code or proof of product behavior.

| Workflow | Light screen | Dark screen |
|---|---|---|
| Personal Home and actionable project cards | 3ea97a1a007c465b988c8fe911d4783f | 749844013cc84298bbcb41f8a9c1b3d8 |
| Planned project and contextual next step | 5ae82be4d6ab4fdca2517e9ff9f3a202 | 111eada64944490592781f96553ef287 |
| Task detail with an actionable prerequisite | 98b7b68036ff48bc9713513d22ac259e | 0dfae2251a3e48b09b0db3a4c29aae6b |

## Guidance accepted for implementation

- Home keeps the real first-name greeting and replaces generic encouragement with an accurate, concise summary of personal assignments and reviews. Compact navigable counts can replace large status cards. A review action must open the review destination, not the general assigned-work list.
- Project cards are semantic articles with a clear Open project control and a separate footer. A planned project offers **Start project** directly to eligible planners; it must not require finding Project options. Do not nest one button inside another. Align card content and footers while allowing long names to wrap.
- Planned projects say that work has not started and show truthful prepared-task counts. Active projects show actual progress and **Open work**. Completed projects offer **View project**. An archive label requires actual archived state. Loading, unavailable reporting, no tasks and zero progress are distinct states.
- Project and task screens explain the immediate prerequisite in one slim next-action region. Planned project → start project; active project with no tasks → add first task; work in a planned wave → start that wave where permitted. Starting a project does not silently start its waves. The chosen phase/wave label is used consistently.
- If the user lacks permission, explain who can take the next step and retain a useful navigation path. Archived, terminal and read-only work must not offer a misleading mutation. Reuse actual planning permissions, controllers, pending feedback and recovery handling.
- Task guidance reflects actual assignment, blockers, reviewer, files and lifecycle state. A reviewer sees the existing eligible review action; an assignee waiting for review sees the actual reviewer. No status control may bypass completion criteria or independent review.
- Keep the existing 860×760 desktop task-dialog footprint and bounded mobile geometry, fixed header/tabs and one scrolling body. Metadata labels sit above values with consistent gaps. Discussion empty states should lead to the existing composer, without resizing the dialog.
- Preserve the real colorful geometric logo, startup animation/handoff, bundled profile avatars, sidebar navigation and local typeface. Dark surfaces remain charcoal: canvas `#101113`, surface `#191b1f`, controls `#23252a`, dividers `#32363d`; light canvas remains `#f7f8f7`. Retain shared readable controls, focus visibility and reduced-motion behavior.

## Generated details deliberately rejected

The generated prose claims exact branding preservation, but the HTML substitutes a four-square logo. Keep the real logo. Do not copy the static unread count, online-presence dot, sample names/dates, fake attachment counts, or placeholder links. The generated Start button uses a timer and anchor navigation; real success must come from the existing authenticated planning action.

The Home result labels a merely completed project “Archived record”; completion and archive are separate. The project overview adds effort estimates, disabled task checkboxes, “Project ready to launch”, “Scheduled for project launch”, inconsistent phase/wave names, a relocated navigation bar and duplicate More/options controls. None is required or authoritative. Keep the existing shell and use the actual state without implying automatic phase activation.

The task result contradicts its “Unscheduled work” subtitle with “Wave 1 · First essentials” metadata and adds invented Files/Discussion counts, a document reference and a review-policy paragraph. Use actual loaded values, show review requirements only when enabled and relevant, and omit the verbose “You have permission” sentence. Do not copy generated blanket text-selection disabling, static dialog divs, inaccessible placeholder tabs or overly small typography.

Runtime verification belongs to the implementation acceptance: permission-aware start actions, successful state changes, recovery/error feedback, correct review routing, personal empty states, light/dark consistency, mobile overflow, keyboard focus and stable dialog dimensions. Generated screens alone do not establish those outcomes.

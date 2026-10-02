# Consistent detail fields

Task, phase and milestone details now share a semantic description list. Each label sits above its value, with consistent spacing, readable text and room for long names. Assignee avatars and their Change action form a wrapping group. The layout uses two columns on wider screens and one column at phone widths of 520 pixels or less.

Priority and phase labels use explicit display text, so their casing does not depend on CSS. Description-list markup also keeps labels and values separate if a stylesheet has not loaded. Existing permissions, task actions and backend behaviour are unchanged.

The screenshot showed inline labels and values without the spacing or capitalization already present in the freshly served stylesheet. An older mounted page may have contributed; refreshing after this update loads the current component and stylesheet together.

Verification and release evidence is recorded in `test-results/frontend-detail-spacing-*`. Visual checks use disposable presentation data without accessing workspace data.

The production build and TypeScript check passed. All 48 component layout cases passed across Chromium, Firefox and WebKit, in light and dark modes at 1440, 560, 390 and 320 pixels. Checks covered long labels and names, multiple assignees, action-button containment, the assignment popup, stable task-tab dimensions, and description-list readability without styles. Desktop and phone screenshots were visually reviewed.

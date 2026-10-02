# Consistent dropdown arrows

All product dropdowns use the shared native Select component. Browser-rendered arrows sat too close to the right border, while the compact toolbar padding overrode the original select padding.

The shared stylesheet now supplies one 16-pixel chevron, vertically centred with a 14-pixel right inset and 44 pixels of reserved text space. The rule also wins over compact toolbar padding. Light and dark themes use their existing muted icon colours. Narrow filters wrap with a 140-pixel minimum width. Native selection, field labels, focus and disabled semantics remain intact; forced-colors mode restores the system arrow.

The production build and TypeScript checks passed. Fourteen standalone checks passed using the actual Select/Field components: Chromium, Firefox and Playwright WebKit at desktop/phone sizes in both themes, plus Chromium forced-colors checks. The checks cover arrow placement, text padding, stable dimensions, keyboard selection and disabled controls. Desktop and phone screenshots were visually reviewed. No API or database fixtures were needed for this CSS change.

Evidence is in `test-results/frontend-select-layout.json`, with screenshots under `test-results/frontend-review/select-layout/`. The frontend image is `sha256:07dea04f901acceb0c895f38660609307f76cb20647c2f428b9879c432bc1245`; deployment health and unchanged backend container identities are recorded in `test-results/frontend-select-release.json`.

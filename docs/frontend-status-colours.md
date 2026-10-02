# Distinct work status colours

Task status badges previously reused green for both In progress and Done. The shared work-status mapping now uses grey for To do, blue for In progress, purple for In review, green for Done and red for Cancelled. Blocked remains amber. Project and wave badges use the same meanings: Planned is grey, Active blue and Complete green. Open is grey; Accepted and Resolved are green.

The shared Badge component adds blue and purple tones with separate light/dark foreground and background colours. Neutral badge text is slightly darker in the light theme for readability. Text labels, badge dimensions and spacing remain unchanged, and the surrounding dark theme stays charcoal.

Verification is recorded in `test-results/frontend-status-colours.json`; the production build is `test-results/frontend-status-colours-build.log`. These are presentation-only checks using real shared components and synthetic data, without an API or database fixture. Source/image and deployment receipts are recorded separately in `frontend-status-colours-source.json` and `frontend-status-colours-release.json` under `test-results/`.

Twelve shared-badge cases passed across Chromium, Firefox and Playwright WebKit in both themes at desktop/phone widths, plus four representative TaskList cases in Chromium. The lowest measured label/background contrast is 4.90:1. The five task statuses have distinct colour pairs; labels, dimensions, wrapping and neutral fallback remain intact.

# Project-files implementation checkpoints

Authoritative scope: [goal.md](goal.md). Started 29 September 2026.

Completion requires working implementation and current evidence for every item.

- [x] 1. Bounded verified planning history for a full 512-task lifecycle
- [x] 2. Explicit download permission; existing grants and client-only privacy preserved
- [x] 3. Durable chunked encryption, enforced upload/storage/capacity limits and recovery
- [x] 4. Separate sources/outputs, immutable versions and same-project shared links
- [x] 5. Encrypted external references with locally verified bytes and honest warnings
- [x] 6. Local PDF/image/text/CSV/DOCX/XLSX/RTF/PPTX previews and safe fallback
- [x] 7. Confirmed bulk registration/assignment/submission and per-item safe retry
- [x] 8. Exact-version review and eligible independent reviewer; normal reopen rules
- [x] 9. Frozen Owner-confirmed delivery packages and manifests
- [x] 10. Optional paired Mac local publisher, rooted paths, conflict journal, recovery and real ONLYOFFICE editing
- [x] 11. File export, backup, restore, retention and deletion integration
- [ ] 12. Extensive Google Stitch frontend, all product states, measured acceptance and release

## Current decisions

- Preserve the original seven-capability genesis/built-in role catalogue. Add download_files only to the extended permission catalogue; explicit signed custom-role permissionCatalogue=2 and reapplied grants supply access. Active Owners retain reserved workspace authority.
- Store opaque encrypted chunks in PostgreSQL to reuse durable WAL and physical backups. Binary bytes remain separate from encrypted task envelopes; filenames, hashes and external paths remain encrypted.
- Retain 25 MiB upload, 2 GiB workspace, 64-item/250 MiB batch, 2 browser /4 workspace concurrent upload limits, 512 document tasks and 2 GiB external verification limits.
- Stitch uses GEMINI_3_8_FLASH, the highest model exposed by the connector, and the existing design system. Dark canvas remains #101113.
- No customer data copied into design prompts or tests. No deployment until acceptance gates pass.

## Acceptance status (30 September 2026)

All implementation gates pass: 512-task lifecycle and document database workloads, explicit download authority, managed/external files and previews, bulk registration/assignment/submission recovery, exact review acknowledgements, current-authority restoration and delivery, real rooted local publication, and actual ONLYOFFICE edit/save. Final Files journeys pass in Chromium and WebKit, with stable light/dark/mobile layouts. Existing account/task browser journeys and 23 focused headless regressions also pass. Firefox's installed test engine fails before page launch; no Firefox acceptance claim is made. Release verification remains before checkpoint 12 is complete.

Evidence: docs/files-acceptance.md, docs/local-files-operations.md and docs/files-design.md. These distinguish measured local capacity, browser checks and cloud verification.

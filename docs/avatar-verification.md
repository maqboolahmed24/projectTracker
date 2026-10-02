# Avatar backend verification

**Status: complete for the requested backend scope.** The local starter now supports signup selection from 20 illustrated shapes and 12 independent colours (240 combinations), encrypted profile persistence, and authenticated current-profile retrieval. Frontend screens remain future work.

## Requirements and evidence

| Requirement | Verified result |
| --- | --- |
| Attractive, reusable illustrations | Twenty distinct DiceBear Critters designs are bundled locally under CC0 1.0. The pinned upstream source, full licence, attribution, deterministic generator and hashes are retained in [the asset directory](../assets/avatars/README.md). The [preview](../assets/avatars/preview.png) was visually inspected at full and small profile sizes; all 20 SVGs also passed XML and static-content validation. |
| Independent shape and colour | Strict allowlisted selection accepts exactly `shapeId` and `colourId`. Twenty shapes and twelve palette entries produce 240 distinct rendered combinations. Unknown IDs, arbitrary colours, extra fields and image-upload input are rejected. |
| Available during signup | Public `GET /v1/avatars/catalog` returns the complete fixed catalogue without authentication or database access. Tests verify cache headers, ETag/304, rejection of query parameters and absence of an upload route. Serving the full catalogue avoids a separate request identifying a user's selected shape. |
| First Owner, member and additional Owner selection | Activation and JOIN accept the optional selection inside existing encrypted profile/setup content. Tests cover real OPAQUE activation, encrypted IndexedDB drafts, lost responses, reloads and approval takeover. The selection is absent from public metadata and plaintext persisted setup drafts. |
| Safe retrieval and retention | `client.profiles.current()` authenticates the current profile reference and authority before returning the caller's decrypted name and selection. Tests reject substituted ciphertext, duplicated material, foreign identity, locked/old sessions, password-only sessions, revoked devices and reads interrupted by logout. Browser journeys retain selections through promotion and member password recovery. |
| Existing profiles and data exit | Missing legacy selections receive a display-only default. Tests verify that encrypted representation upgrades and Owner exports preserve an explicit selection and do not insert defaults into historical profiles. Existing callers may continue to omit the new field. |
| Local runtime | The actual unauthenticated catalogue returned HTTP 200 with 20 shapes and 12 colours. Every served SVG and palette entry matched the host manifest. Both rebuilt containers matched all 166 locally compiled source files, and their bundled assets matched the same manifest. API/worker readiness, queue, recovery and synchronous replica checks passed. |

The [protocol document](avatar-protocol.md) contains the API and client call examples. This extension adds no SQL migration, third-party runtime dependency, photo storage or remote avatar request.

## Executed checks

There is passing evidence for **82 distinct focused Node cases**. The initial [run](../test-results/avatar-focused-tests.log) passed 77 of 82. Five new-test failures were repaired in test code only: four assertions needed to compare exact canonical JSON because the existing strict decoder creates null-prototype objects, and one additional-Owner fixture needed its recovery phrase. The [focused rerun](../test-results/avatar-focused-repair-1.log) passed all five. [Repair details](../test-results/avatar-signup-repair-1.md) retain the original diagnosis. No production parser, cryptography or authority rule was weakened to pass these tests.

The focused suite covers avatar catalogue/activation/profile delivery plus the affected activation, enrolment, access-change, export, encrypted-upgrade, content-schema, runtime-retention and foundation paths. This is not a rerun of the entire checkpoint 13 regression suite.

There is passing evidence for **six distinct browser journeys**: two database-backed enrolment journeys on each of bundled Chromium, Firefox and WebKit. The [initial run](../test-results/avatar-browser-results.json) passed the first journey on all three engines. The second journey reached its final new assertion but queried a page that the existing test had reassigned to a subsequently revoked device. The assertion now reads the recovered member's current profile and explicitly checks that the old device is denied. The [focused rerun](../test-results/avatar-browser-repair-1-results.json) passed that journey on all three engines. This repair changed only the test. These executions use real HTTP, browser Workers, WebAssembly and IndexedDB; they do not implement product screens.

TypeScript compilation, browser-library bundling and both runtime image builds passed. Initial TypeScript diagnostics were repaired by narrowing the nullable current device ID and giving an activation test fixture its declared input type. Logs are retained as `avatar-build.log`, `avatar-build-repair.log`, `avatar-test-repair-build.log`, `avatar-browser-final-build.log` and `avatar-runtime-build.log` under `test-results`. `git diff --check` passes.

An independent automated source review found no concrete material issue within the avatar changes it examined: encrypted selection, validation, retry preservation, profile authority anchors, authentication boundaries, export/legacy behaviour and asset hashes. It did not run tests or constitute an external human audit. Its reported 18-file review aggregate was `714710f5f4e1737cca42522e626745fcafd45bee9b5197d68c81e1f5797d3f75`; subsequent coordinator changes included the device-ID type narrowing and test repairs described above.

## Runtime and delivery boundary

The [runtime capture](../test-results/avatar-runtime-verification.json), taken on 27 September 2026, records matching API and worker code, all five local services healthy, HTTP 200 liveness/readiness, no pending or failed queue jobs, healthy recovery, and a streaming synchronous replica with zero replay lag. The asset manifest SHA-256 is `59ab4da04b815a8e9eb955d93c712cb066d813d555bf5893a78d0acb07d82b4c`; the 166-file compiled-source aggregate is `0ab34fa5d77c8da9bb6505e568ab7e5da0f4e5c38f6f5742558db92808ff2c91`.

All fixture workspaces were removed before restarting the existing recovery operator. Its one-shot tick passed, and the detached local daemon was independently observed running with two successful ticks. Its PID and append-only log paths are recorded in the runtime report. This is a local process, not a newly installed operating-system service. Zero active workspaces at capture means checkpoint age is null; this extension does not claim a new nonempty recovery drill.

The [coverage manifest](../test-results/avatar-final-evidence.json) maps passing cases to their reports and records evidence and implementation hashes. Original failed diagnostic reports remain available; there are no unresolved failures from these focused checks.

The original [thirteen-checkpoint evidence](checkpoint-13-evidence.md), including native Safari 26.6.2 and 27.0, remains historical baseline evidence. Those branded browser tests and the complete baseline regression suite were not repeated for this avatar extension. The current extension has the focused browser and backend coverage above.

No production deployment or frontend selector was added. Remembered-profile cards still retain their existing name-only metadata; post-signup avatar editing is outside this request. Deploy matching API, worker and browser-library versions because older clients with strict name-only profile parsing cannot read avatar-bearing profiles.

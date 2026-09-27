# UKDA frontend design

Google Stitch project: `2504438657315916160` — **UKDA — Complete product · Light & Dark**.
Shared design system: `assets/18248857475683212615` — **UKDA · Quiet clarity**.

All generation and corrective edits used **GEMINI_3_8_FLASH**, the highest model exposed by the installed Stitch connector at implementation time. Its other exposed option was GEMINI_3_5_FLASH_LITE. The saved screen metadata and original generated HTML in `stitch/` provide provenance; these references are not shipped as application pages.

The reference set covers the light workspace, dark project work, first Owner setup, remembered sign-in, and dark People settings. A corrective pass removed technical labels that Stitch invented. The implemented screens share one React component library and one stylesheet, so unrelated generated details do not create inconsistent controls or navigation.

The application follows the architecture's four main destinations: Home, Projects, My work and Inbox. Settings contains people, teams, permissions, account security and data controls. Projects use Overview, Work, Timeline and Updates. The current list view is functional; deferred features are visibly disabled and labelled “Not available in this build.”

## Visual decisions

- Inter is bundled locally. No remote font, avatar or image requests are needed.
- Light: warm grey canvas, white surfaces and restrained forest green. Dark: the startup animation's exact neutral background, `#101113`, with charcoal surfaces and soft mint action accents. This follows the user's refinement to remove the original dark-green surfaces.
- Shared 8px control and 12px card corners; generous spacing, quiet borders and limited shadows.
- Existing `brand/ukda-launch` animation opens the app, then its assembled symbol shrinks and travels into the page's measured corner logo as the background reveals the content. The 720ms handoff keeps the mark's proportions and temporarily hides the destination to avoid a duplicate. Reduced motion uses a short fade; errors, a missing destination, resized layouts and the hard deadline always release the page. Its symbol is reused throughout.
- Native focus-trapped dialogs, visible keyboard focus, a skip link, responsive navigation and system/light/dark appearance are shared across journeys.
- Private names, records and search results are loaded after sign-in and retained in browser memory. Public server rendering contains only the application shell.

The functional application, rather than unreviewed generated HTML, is the final design deliverable. Illustrations come from the existing bundled avatar catalogue and brand; Lucide provides consistent interface icons.

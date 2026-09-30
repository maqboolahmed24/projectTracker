# Files and document work: Stitch design provenance

The user rejected the original document-work design set as too busy. It is retained only as superseded provenance under `design/files/`; it is not the accepted visual reference.

The replacement private Google Stitch project is **5855422246659088288**, “Maqbool · Essential document work”, using shared design `assets/12527623825984102001`. Every generation explicitly requested **GEMINI_3_8_FLASH**, the highest model exposed by the installed connector. No unexposed Pro model was assumed. Only synthetic Studio North sample records were supplied.

## Replacement set

Eight separate paired light/dark workflow briefs were submitted once. Seven returned fourteen screens; the Add files request returned “The service is currently unavailable.” That request was not regenerated. Bounded later screen-list checks found no missing Add files result. The working upload dialog follows the same restrained system as the returned file and bulk dialogs.

Full prompts, exact tool responses, project/design metadata, screenshots, downloaded HTML references and the compact index are saved in [design/files/slim](../design/files/slim/). All fourteen returned screenshots were visually inspected. Individual screen retrieval also confirmed results that the connector’s project listing had not yet included. Generated HTML is a design reference; application components use the existing shell, shared controls and real authenticated controllers.

| Workflow | Light screen | Dark screen |
|---|---|---|
| Project Files | 8b8b0f2c95cc48989fea4d652ffb3147 | e4c286f979594eb181923f2424fa1c06 |
| Bulk registration, assignment and output submission | 19223da7a8a142eb9c465844952f2460 | 7dfb8df2234f415a91410e25173dd41f |
| Task evidence and independent review | 6ef1af9bd1724866a51a65475c715eb0 | d42cc19e304647a5bd0ac10301b778bd |
| Preview, version history and optional Office editing | 9a7c207b5bab439da20530e369613e23 | da9b799c70c24a43a67d280ca2f71a6c |
| Frozen Owner delivery | 4bd21983f3cb466a83a5e1b008610bb8 | 1329e3e8b67046e284875f35500daaec |
| Optional shared-folder companion | 96cff09796234383a0d75f4cd9054bd9 | 5be39bcd51254e1691aa547bf6f04016 |
| Storage, file export and recovery | f1393c5af4694cdd8ac572739240fb97 | 51eb9334329a4eea8947b2ca857a110b |

The briefs describe normal, empty, loading, progress, quota, oversized-file, invalid-input, interruption, duplicate-mapping, permission, changed-external-file, stale-review, unavailable-editor, offline-companion, local-conflict, export and recovery behaviour. Each returned image depicts one coherent normal state, rather than a collage of every error at once. Conditional states are implemented only when needed.

## Translation into the real product

- Preserve the actual startup mark, its animated handoff and the real bundled logo. Reuse the current sidebar, local Inter font, Lucide icons, profile avatars and account/security flows.
- Keep one primary action per screen. Files has Add files, a quiet More menu, search and filters, one aligned table and a small storage footer. Delivery has New delivery and one batch list. Setup, bulk work, file history and unfinished attempts open in dialogs.
- Remove large introductory cards, redundant statistics, duplicate storage panels, decorative illustrations, persistent warning banners and unnecessary explanatory sections. Important warnings appear only during the relevant action.
- Use light canvas `#f7f8f7` with white surfaces and `#176b50` actions. Dark canvas is the startup `#101113`, with `#191b1f` surfaces, `#23252a` subtle areas, `#32363d` borders and `#9cd7b9` actions. Never use dark-green panels.
- Table columns stay aligned regardless of optional data. Text and references wrap safely. Keep native selects’ inset chevrons and shared focus styling.
- Use stable dialog dimensions with fixed header, tabs and footer; only the body scrolls. Preview, Versions, Linked work and task tabs retain their geometry. Respect reduced-motion preferences.
- Separate Sources and Outputs, and Uploaded files and Shared-drive references. Use simple numbered versions. Review evidence opens the exact submitted version; newer work never replaces it silently.
- Keep the external warning honest: **Stored outside Maqbool. File contents are not included in cloud backups. Other people need access to this drive.** A user must choose the actual file for any content check; a typed path alone is not verification.
- Keep optional editing basic: an organisation-controlled ONLYOFFICE editor, explicit Save new version, dirty-close confirmation, stale-version protection and a workable fallback. **After editing on your computer, upload the updated file. Changes do not sync automatically.** Local-network permission guidance and companion-download/setup links appear only when needed.
- Owner confirmation freezes a delivery. Downloading a package and successful publication are separate states. Publication succeeds only after verified written files.

## Deliberately rejected generated details

Stitch does not know the backend. The following generated details were reviewed and excluded or corrected:

- Substitute logos, a new navigation taxonomy, stock branding and excessively small generated typography. Retain the real product and readable shared type scale.
- “Auto matched” bulk wording and matching by filename. Registration creates a distinct task for each explicit document reference; submissions explicitly select the task. No inferred match is silently accepted.
- A generated existing-task dropdown in Register documents. Register creates new document tasks; Assign and Submit operate on existing tasks.
- An invented 2 GiB export package limit. Managed uploads are 25 MiB per file; bulk uploads and file packages are capped at 64 items and 250 MiB; local checks may accept external files up to 2 GiB. Workspace managed storage is 2 GiB.
- Technical JSON/schema/security footers, opaque identifiers, hashes and implementation terms. Customer controls describe files, versions, access, storage and outcomes.
- Persistent shared-folder connection controls on the Delivery list. Place setup under More, with concise fields and contextual guidance in its own dialog.
- Fake backup completion dates, retention promises, automatic external-drive synchronisation or claims that external contents are backed up.
- Combined confirmation/publication actions or replacement of changed local files without review. Keep explicit destination checks, independent Owner confirmation and recoverable conflicts.

The acceptance deliverable is the working product with focused browser verification, not unreviewed generated HTML.

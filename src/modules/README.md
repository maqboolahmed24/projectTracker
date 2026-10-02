# Backend module boundaries

Feature modules are added in checklist order. The API and hosted worker use the same module operations; neither directly edits another module's records.

| Module | Owns |
| --- | --- |
| `identity` | Licence activation, accounts, OPAQUE sessions, devices, owner custody, security transitions, profiles, permissions and scoped grants |
| `work` | Projects, teams, waves, milestones, tasks, assignments, review and blocker transitions |
| `collaboration` | Comments, updates and moderation |
| `reporting` | Summary persistence/provenance; reusable plaintext calculations run in the authorised client |
| `notifications` | Metadata-only event delivery, read state and mute settings |
| `operations` | Fences, jobs, migration orchestration, restore, data exit and deletion |

`src/app.ts` assembles HTTP routes and shared error/logging policy. `src/db.ts` owns database pools and transaction helpers. Client cryptography and plaintext domain logic will live under `src/client` and `src/shared`; these must not import server credentials, database code or worker modules. Feature acceptance tests enforce these boundaries as the corresponding checkpoints are implemented.

GitHub, AI, email and customer-operated connectors have no module or runtime dependency in this release.

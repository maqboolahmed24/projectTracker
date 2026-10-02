# Punctuation cleanup release - 2 October 2026

Project-owned editable text now uses colons, periods, commas or plain hyphens in place of em dashes. This includes interface copy, browser titles, project documentation, editable design references, the product guide and the Mac companion README. Customer-entered content, historical screenshots and third-party package bytes were preserved.

## Published versions

- Workspace: [Maqbool](https://maqbool.denmarkeast.cloudapp.azure.com/), deployed at **03:56 BST** (02:56 UTC).
- Production source: [`9907ccb3c0562dcbff5450fbbf521d753d63f3a6`](https://github.com/maqboolahmed24/projectTracker/commit/9907ccb3c0562dcbff5450fbbf521d753d63f3a6), applied to the existing production source lineage.
- Frontend image: `sha256:9c1f5fb7c57b065ce20a49fab87bc043a889294abd908d7b8e79b726b852317d`.
- Source directory: `/opt/maqbool/releases/punctuation-9907ccb3c056`.
- Public repository cleanup: [PR #7](https://github.com/maqboolahmed24/projectTracker/pull/7), merged as `c47aa70ca3873c03705f99f4fbe7bd30c593d8a1` after both CI runs, dependency review and CodeQL checks passed.
- Landing target: `releases/dab7d3510a49/site`, published at **03:51 BST** (02:51 UTC). Only `index.html` and the product guide changed from `releases/85459fd411b3/site`.
- Full static release identity: `dab7d3510a49687b78887443f95449e752b7944da904806e49ff34bd7c87d3ef`.
- Guide: 142 pages, 38,771,074 bytes, SHA-256 `214aeb3e039fe9dd9febab8958f497139b8dd6f5ca5ca6fd5cdce54006e0a368`.
- Mac companion: 39,562,800 bytes, SHA-256 `0d5f19216a3aabb8c2f08df22096d128d29d31b956c589ae10471df789f66932`. Only the README content changed; executable contents and modes are identical.

The cloud patch changes six runtime source files through exact punctuation replacements. The square logo and startup animation remain byte-identical. The API, worker, gateway, both databases, recovery supervisor, backend release link and configuration outside the frontend image pin were verified unchanged. No migration or new cloud resource was needed.

## Verification

The frontend typecheck, JSON validation, production build and candidate homepage/API proxy passed. A scan of 773 tracked UTF-8 files in the cloud release found no literal or encoded em dashes. Public verification matched all 27 Next JavaScript/CSS assets, the preview worker, four public routes, the companion download and brand assets to the reviewed build. Existing task ordering, workspace updates and project-card behavior markers remain present.

The rebuilt guide has no em dashes in extractable text, metadata or bookmarks; the cover and changed text pages were visually checked. Original screenshot images are retained as historical evidence. All ten landing files matched the new static manifest, including the other eight byte-identical files. Independent HTTPS checks verified the full PDF hash and HTTP 206 byte ranges. Live landing browser checks verified the same-viewport feature explorer, rendered guide, Open PDF fallback, download link and close/focus behavior, with no page errors.

Live app checks passed in light and dark modes: the colon title is correct, the startup overlay completes, the square logo settles in the corner, the application becomes interactive, and public Join/Back navigation works. No browser errors were captured and no customer account or workspace was changed.

## Rollback and evidence

The preceding compatible frontend remains available as `sha256:695830cc3a092e7e17de7f425edd52aa8034543532313d60806cbfe46b4a5ba0`. Its guarded rollback changes only the expected frontend pin and container:

```sh
sudo /opt/maqbool/releases/punctuation-9907ccb3c056/punctuation-rollback.sh \
  9907ccb3c0562dcbff5450fbbf521d753d63f3a6
```

The independent static rollback restores the preceding landing target without restarting services:

```sh
sudo python3 /opt/maqbool/landing/releases/dab7d3510a49/evidence/deploy.py \
  --rollback dab7d3510a49687b78887443f95449e752b7944da904806e49ff34bd7c87d3ef
```

Root-restricted server receipts are under the frontend source directory's `release-evidence/` folder and the landing release's `evidence/` folder. Local verification, browser evidence, source hashes and rollback rehearsals are retained in ignored `.local/azure-deploy/punctuation-*` files. Primary working-copy text backups are in `.local/typography-cleanup-2026-10-02/`. The static manifest includes local guide source hashes because the guide is maintained separately from the production application source snapshot.

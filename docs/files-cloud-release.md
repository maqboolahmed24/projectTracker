# Project files cloud release

Production cutover completed on **30 September 2026, approximately 00:34 UTC**, at [Maqbool](https://maqbool.denmarkeast.cloudapp.azure.com/). The change is tracked in [pull request #1](https://github.com/maqboolahmed24/projectTracker/pull/1).

## Deployed version

The deployed application code is `7a04aa63fb9d25908146a0dfb7b2cdff6139eb80`. Subsequent commit `e4e48550f2f1d0fea5b58ba3d7c7a5fdc1a18caf` corrects an outdated test assertion only; it does not change the deployed runtime.

| Component | Pinned image digest |
| --- | --- |
| API and worker | `sha256:f597c8f0cdf7ebf5a46220f0790597fa9b55a1064614f24e45a10fc16fbf86b7` |
| Frontend | `sha256:a30a86d960a1b1e69b4d081e693212bf8146574e463aecd8c9edea8907295c42` |
| Recovery operator | `sha256:969e4589d9635240dbb58a6c86c8e43a59c7f5303b9f7d4501ee2b31c04f02a8` |

Application migrations **011–016** and control migration **013** were applied additively, with existing migration checksums unchanged. The live deployment admits up to **2 GiB of managed file storage globally**, **2 GiB per workspace** and **25 MiB per managed file**. No additional cloud resources were created.

## Cutover checks

All application containers were healthy. Recovery supervision was active and synchronous replica replay lag was zero at the check. The home page and companion setup guide returned HTTP 200. The deployed welcome screen was also reloaded and visually checked in the in-app browser, with no recorded console warnings or errors.

The live Mac companion download was **39,564,449 bytes**, with SHA-256 `6e50440f8ffe56284f01128929adca1cf5df59c248c178b58879c4e4bba089db`, matching the locally built ZIP.

The production API smoke passed **46 real HTTPS requests** using a dedicated synthetic workspace: fresh Owner activation, password/device proof, project creation and start, two managed immutable versions uploaded and downloaded, local decryption matching the original bytes, an idempotent repeated completion receipt and one metadata-only external reference. Final usage was **1,027 accounted bytes**, with zero active uploads or reservations. Fixture identifiers and private evidence are excluded from this record.

The first smoke helper incorrectly treated a begin-operation receipt as completed upload evidence. The application correctly refused replacement before chunks and completion. The helper was corrected and a fresh dedicated fixture passed; no runtime change was required.

## Release verification

- **Full CI: passed.** [Run 36650941907](https://github.com/maqboolahmed24/projectTracker/actions/runs/36650941907), on exact commit `e4e48550f2f1d0fea5b58ba3d7c7a5fdc1a18caf`, completed at 00:45:54 UTC: 647 tests, 644 passed, zero failed or cancelled, three skipped, in 667.2 seconds. Dependencies, build, migrations, worker bootstrap, TypeScript, tests and cleanup all passed. The initial run's sole failure was the outdated cached-tampering assertion; the correction verifies both warm and cold rejection and changes no runtime behavior. Capacity and real-editor opt-in acceptance were run separately as documented.
- **Live checkpoint inventory: passed.** A signed version-2 checkpoint captured at 00:38:25 UTC contains both managed versions, their two encrypted chunks and the external metadata version. Its service signature, digest and encrypted sidecar match the physical backup/WAL bindings. Recovery health at 00:38:28 UTC covered all six active workspaces, with zero synchronous replica replay lag and no archive failures. This verifies capture and inventory; it is not a new destructive restore of a production workspace. Actual file restoration acceptance is recorded in the isolated database evidence.

## Preservation and operating references

Previous source is preserved at `/opt/maqbool/release-before-files-7a04aa6`, together with a configuration backup. Existing database volumes were retained. Because these are additive migrations, recovery uses forward repair; do not reset volumes or assume the previous runtime can safely operate the new schema.

See [file acceptance evidence](files-acceptance.md) for isolated database, capacity, bulk and frontend checks; [file storage](project-files-storage.md) for format/preview bounds, storage and recovery behaviour; [local companion and editor operations](local-files-operations.md) for the Apple silicon Mac package, notarization status, optional Docker/ONLYOFFICE setup and local acceptance limits; and [Stitch design provenance](files-design.md) for the reviewed light/dark designs. General cloud operation remains documented in [cloud operations](cloud-operations.md).

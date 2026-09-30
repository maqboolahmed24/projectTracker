## Goal

Extend the existing **Maqbool application** with a complete, production-usable document-work workflow for document-heavy projects, while preserving the existing account, project, encryption, recovery and task systems.keep the developmetn simple, dont try to fall in to any itteration loop, or infinite developeing loop, keep it clear and best . do focused tests, i dont want super sophisticated codign for now, but a design which can be sacled in futire, but a good product for initial launch.

The implementation should support up to **512 document tasks per project**, encrypted managed files and immutable versions, shared attachments linked to multiple tasks, external file references, safe previews, bulk registration and submission, exact-version review, and Owner-controlled delivery.&#x20;

Users (who have permission to write)must be able to perform document work either directly inside Maqbool using the integrated ONLYOFFICE (in the frotn end keep only essential features form the onlyofice, which is basic necessary, donot try to make ti super heavy)(install this library pleae and other opensource for viewign too)editor for supported managed office documents, or externally using their preferred desktop tools (if performed using externally, give clear message that after editing updadet he file int eh platform, as sync not happenign automatically). In-platform editing must remain optional: Maqbool should continue to manage the files, immutable versions, evidence, review and delivery regardless of where editing occurs.



Implement secure binary file storage separately from task envelopes, enforce storage and upload limits on both client and server, preserve encrypted filenames and metadata, and introduce an explicit `download_files` permission without silently expanding existing roles. A project must provide **Files** and **Files and evidence**, with sources and outputs represented separately. Multiple tasks may reference one shared file and version history, while review evidence always pins exact immutable versions.

Support **Keep file on your shared drive** for files that should remain external. Store only an encrypted reference, size and verified hash. Users explicitly select external files when verification is required; the cloud must never treat stored paths as server-accessible locations or claim to back up external file contents.

Provide lightweight, secure previews for common files. Use local previewing for PDF, images and bounded text/CSV, and evaluate and integrate appropriate maintained **open-source preview tools** for DOCX, XLSX, RTF and PPTX. Unsupported or unsafe files must fall back cleanly to authorised download or external work. Do not send private documents to third-party conversion services.

Add bounded bulk workflows for registering documents, assigning work and submitting outputs. Use stable document references and explicit mappings rather than relying only on filenames. Preserve successful items when part of a bulk operation fails, and make retries idempotent.

Extend the existing review system so a submission binds the exact task revision, source versions, output versions and verified hashes. Reviewers must be eligible, separate from the task’s assignees and unable to approve their own submitted output. Only reviewed document outputs become eligible for official delivery.

Owners must be able to create a **frozen delivery batch** containing exact approved versions, destination paths and file operations. Any material change requires fresh Owner confirmation. Provide a downloadable package and manifest, but distinguish downloading that package from successful publication to official local storage.

Introduce the **Local File Service** as an optional organisation-controlled companion, initially for the supported Mac environment. It may write only inside an explicitly selected root, must verify expected existing files before replacement, journal operations durably, recover safely after interruptions and never silently overwrite unexpected local changes. The main cloud workflow must remain usable when the Local File Service is unavailable.

Extend backups, restores, exports, retention and deletion to cover managed file bytes, versions and manifests while clearly identifying external references as metadata-only. Restore operations must respect current authority and must never revive revoked access.



Complete the customer-facing frontend using the application's existing design system. When implementing the frontend, use the already-connected **Google Stitch** capability extensively page for page if needed to design and refine the required screens and states, prompting it with enough product context to produce coherent (becase stich doesnot have any direct access to the soruce file, it only product what is been promtped), usable interfaces. Cover normal, empty, loading, progress, conflict, quota, permission, offline/service-unavailable and recovery states. and also if needed and better update teh surrounding design appropretly too pleaes, i want the superior wuality design, well thohut both everytihgn like colours animations, illustraiton colours and thign liek that, i wan the minimustic design, premium finishign. if requrie to make it looks unified design, adjust the other design elements, you have the full createive control, i want the best lookign UI, like google/apple/microsoft level quality,, you have to put all your efforts in teh forntend, all your power to make it looks intentioanly god, minimustics, and carefully creaftd, be carefull not to leak the developmetn terminologies int eh fonrt end, i want the all elements and typology in teh front end clearly user friendly and profesisonally&#x20;





Before completion, test a realistic **512-task document project** with representative uploads, shared attachments, multiple contributors, corrections, reviews, external references, interrupted bulk operations, delivery conflicts and recovery. Measure actual capacity, storage growth, memory usage, timings, supported formats and browser behaviour, and verify existing core account and task workflows still work.



**Do not expand indefinitely.** Finish when this defined workflow works end-to-end, all required acceptance checks pass, and failures necessary for those checks have been fixed. Features such as , automatic external-drive synchronisation, broader connectors, email, cross-project sharing and stronger private file boundaries remain future work.,





while accepting the work form stich, it might irrelavant, noisy, mismatch in desing, so you need to be supe rcarefull when accepting its work, i want he final design to be minimul, less noisy, clean user friendly and sleek pleae, use appropret eanimation, illustration wherever needed, not forced, i didnt like the design stich genete for the new one, so i deleted the project, pleaes regenerate more better slim and apporpte design, the other one was too much and so much unnseassary thigns,&#x20;



please use the best model presneti in the stich&#x20;
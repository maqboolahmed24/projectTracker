# Public repository protection

Recorded on 2 October 2026 for [maqboolahmed24/projectTracker](https://github.com/maqboolahmed24/projectTracker). The repository remains public and forkable. All enabled repository controls use features available for a public repository; no paid security subscription was purchased.

## GitHub settings verified

- `main` requires a pull request, successful up-to-date CI and resolved review conversations. The rules also apply to administrators. Force pushes and branch deletion are blocked.
- The only account with repository write access at verification was `maqboolahmed24`. Required approving reviews are zero because a sole maintainer cannot approve their own pull request. External contributors have no write access; their pull requests need a maintainer to merge them. Before granting another person write access, require independent code-owner approval.
- Secret scanning and push protection are enabled. No open secret-scanning alerts were returned during verification. Extra non-provider patterns and validity checks were not enabled and are not claimed as protection.
- Dependabot vulnerability alerts and automated security-fix pull requests are enabled. No dependency alerts were returned during verification. Scheduled version updates are configured separately in `.github/dependabot.yml`; they are not automatically merged.
- Private vulnerability reporting is enabled through the repository's Security tab.
- GitHub Actions defaults to read-only permissions and cannot approve pull requests. Actions must be pinned to complete commit hashes. Only GitHub-owned remote actions are allowed; individual jobs grant additional permissions only where needed for security results.
- Every external contributor requires maintainer approval before fork workflows run. Workflows use hosted runners, do not execute untrusted pull requests through `pull_request_target`, and do not receive deployment credentials.
- No repository Actions secrets, deploy keys or webhooks were present at verification.

CODEOWNERS names the maintainer. CodeQL scans JavaScript/TypeScript and workflow definitions; dependency review checks newly introduced vulnerable dependencies. Their workflow checks supplement the application CI. Review security alerts as well as the job result: a completed scan does not itself mean that it found no vulnerabilities.

## Source audit and naming

A bounded audit inspected 2,238 reachable Git blobs for common credential and private-key patterns, plus extracted text from eight historical PDFs. No live credential was confirmed. Credential-like findings were local development credentials, examples or test fixtures. Image-only documents and screenshots were not OCR-audited. An advisory query for 317 locked package names returned no advisories at the time of review. These observations are not a guarantee that no secret or vulnerability exists.

Private configuration, operational keys, local credentials, backups and database dumps are excluded from Git and build contexts. Examples must contain only public placeholders. If a real credential is ever published, revoke or rotate it first; later deletion and history rewriting cannot revoke copies already obtained by others.

Current product branding, package metadata and launch filenames use Maqbool. Versioned cryptographic and storage identifiers remain unchanged for [compatibility](compatibility-identifiers.md). Historical records retain their original provenance. No Git history was rewritten.

Original project work is licensed under [AGPL-3.0-only](../LICENSE), with [third-party notices](../THIRD_PARTY_NOTICES.md). The new square line logo replaces the earlier adapted artwork while retaining the startup animation's sequencing and handoff.

## Account and deployment boundaries

Repository controls do not establish the owner's account security. Use a passkey or two-factor authentication and retain recovery codes privately. The authenticated API did not expose the account's two-factor status, so this audit does not claim it was enabled.

Repository protection also does not replace deployment security, backups, credential rotation or application authorization checks. Follow the [cloud operating guide](cloud-operations.md) for those controls. This repository update does not rotate operational secrets, alter encrypted customer data or change the running cloud stack.

# Security policy

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/maqboolahmed24/projectTracker/security/advisories/new). Do not publish exploit details in issues, discussions, pull requests, or screenshots before a fix is available.

Include the affected commit or release, the impact, and minimal reproduction steps using a local instance and invented data. Share only the information needed to understand the issue. Never send real passwords, recovery phrases, activation keys, private keys, session tokens, or customer files.

The maintainer will review the report privately and coordinate a fix and disclosure with the reporter. This is a community project without a guaranteed response time or a paid bug bounty.

## Supported code

Security fixes target the latest `main` branch. Older commits and forks do not receive a separate security maintenance guarantee. Self-hosted operators are responsible for applying updates, rotating exposed credentials, and protecting their deployment and backups.

## Responsible testing

Test only systems and data you own or have explicit permission to assess. This policy does not authorize testing the hosted service, accessing someone else's workspace, denial of service, or destructive actions. Use a local instance for reproduction.

If you discover a leaked credential, report where it appeared without copying it into a public report. The credential must be revoked or rotated; deleting it from a later commit does not remove it from existing copies or Git history.

## Repository safeguards

The repository includes dependency updates, dependency review, source and workflow scanning, pinned workflow actions, and owner review rules. These controls reduce risk; they do not establish that the software or a deployment is free of vulnerabilities. See [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change.

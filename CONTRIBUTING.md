# Contributing to Maqbool

Contributions are welcome through pull requests. For security issues, follow [SECURITY.md](SECURITY.md) and use private reporting.

## Make a focused change

1. Fork the repository and create a branch from the latest `main`.
2. Follow the setup instructions in [README.md](README.md) and use a disposable local workspace with invented data.
3. Keep the change small and explain the user problem it solves. Update documentation when behavior changes.
4. Run the relevant checks below, then open a pull request with the results and any remaining limitations.

The maintainer reviews contributions before merging. Automated dependency updates also require review; they are not automatically merged.

The repository currently has one maintainer with write access. Pull requests and passing required checks are enforced on `main`, including for the administrator. The required approval count is zero because a sole maintainer cannot approve their own pull request. Before granting another person write access, require at least one independent Code Owner approval and dismiss stale approvals when new commits are added. Keep write access limited to trusted maintainers.

## Checks

- Use the Node.js version required by `package.json` and install from the lockfile with `npm ci`.
- Run `npm run check` for TypeScript changes and `npm test` with the disposable databases configured as described in the README.
- For the web interface, run `npm run check:frontend` and the relevant browser checks. Include redacted screenshots for visible changes.
- Keep lockfiles in sync with dependency changes. Explain why a new dependency is needed and review its provenance and license.
- GitHub CI runs the backend checks. Dependency Review checks newly introduced dependencies for high or critical known vulnerabilities. CodeQL scans source and workflow files; review its findings as well as the job result.

Run only the checks relevant to your change; describe any that could not be run. A passing automated check does not replace reviewing authentication, permissions, encryption, and data handling changes.

## Keep private data out of Git

Never commit real environment files, recovery phrases, activation keys, passwords, tokens, private keys, database exports, backups, or personal workspace content. Use placeholders in examples. Review `git diff --cached` before committing. Ignored files can still be force-added, and ignore rules do not remove existing Git history.

Do not add credentials to workflow logs or grant pull requests access to deployment secrets. Actions must use full commit SHA references, minimal token permissions, and GitHub-hosted runners. Do not introduce privileged `pull_request_target` jobs that execute contributor code.

## Licensing and attribution

By submitting original code, you agree that it may be distributed under this project's [AGPL-3.0-only license](LICENSE). Retain existing copyright and license notices. Submit only material you are authorized to contribute.

Third-party components and assets retain their own terms. Do not assume that a project logo, illustration, font, avatar, or other bundled asset is covered by the source-code license; follow the repository's third-party notices and supply attribution and provenance for new assets. This contribution process does not transfer ownership of your work or grant trademark rights.

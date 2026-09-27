# One-link invitations and device approval

Member and additional-Owner invitations now need one shared invitation link. Opening it makes the request available in **Access requests** inside the Owner's existing UKDA session. The Owner explicitly starts the security check, the recipient supplies their details, and both compare the complete code. Either person can compare first. After both confirmations, approval and entry continue automatically.

New browsers use the existing private sign-in link and password. Their request appears on an eligible approved device or with an eligible Owner. No return approval link or repeated progress button is required in the normal journey. A direct-link fallback remains under a collapsed help disclosure.

The sidebar request button appears only when discovery finds pending requests, with a count badge. It reads **Access requests** for Owners and **My device requests** for members. When the refreshed count reaches zero, the button disappears. A permanent entry remains in **Settings → Your account** (also available at `/settings/security`), so people can start waiting for a request or reopen the list even when the sidebar is empty. Member descriptions refer only to approving their own devices.

## Boundaries

- Discovery returns only request identifiers, status, expiry and approving-account/device references. It does not return invitation codes, resume capabilities, fingerprints, credentials, keys or decrypted profiles.
- Every discovery request checks current authority. Members see their own eligible device requests; eligible Owners can help other accounts in their workspace.
- Opening, listing and polling never claim a request. Starting the security check is an explicit password-confirmed action.
- The complete 64-character transcript fingerprint, current authority checks, expiry, encrypted key delivery and both signed confirmations remain unchanged. A comparison is not replaced by a short locator code.
- An approval continuation is bound to the selected request, complete fingerprint, binding and current authenticated session. Changing the request, closing the view, signing out, a polling error or a timeout discards the pending local approval intent.
- Status reads have separate bounded request budgets. Polling is serial, backs off, and pauses after ten minutes or repeated failures. Manual actions wait for an in-flight read. Focus or navigation can restart paused sidebar discovery; unattended discovery does not restart forever.
- Passwords and recovery words used to finish a new invitation remain in memory only. A reload may require the chosen password again. New Owners still save and confirm their individual recovery kit.
- Member password recovery and Owner promotion retain their existing confirmation controls. Device restart creates a fresh operation and keys; it does not inherit an earlier approval.

No schema migration or workspace-origin change is required. A different physical device still needs access to the installation's existing canonical address; this change does not migrate localhost-bound workspaces.

## Verification

Build and release evidence is recorded under `test-results/frontend-one-link-*` and `test-results/api-one-link-build.log`. Browser journeys use separate disposable databases and the candidate frontend image. Production workspace data is not used for tests.

The final candidate passed 17 browser cases: invitation and device approval in both confirmation orders across Chromium, Firefox and WebKit, Owner activation/recovery, recipient cancellation, and approval-window layout. Additional checks covered 15 approval-state regressions, two polling lifecycle cases, five client/route cases, and three database-backed discovery cases. The disposable test databases and preview were removed after verification.

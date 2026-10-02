# New-device code comparison

New-device approval now asks the user to compare the full code displayed independently on each device and select **The codes match**. The code remains all 64 characters, arranged as eight groups in a two-column monospace layout in both themes. There is no field to copy the local code back into.

**The codes don’t match** submits nothing. It shows instructions to stop and check the request, removes the approval action, and offers **Compare again**. Changing the request or code resets that local mismatch state. Busy actions are disabled; malformed codes cannot be confirmed. The new-device screen hides comparison controls once it knows the request has expired or ended.

Either device may confirm first. When the approving device goes first, it keeps the code visible and waits for confirmation on the new device. **Finish approval** rechecks the existing signed confirmation and only proceeds once both devices have confirmed. After the new device confirms, its code also remains visible for comparison on the approving device.

This is an explicit visual trust check. Users must compare every group with the other device, or with the Owner through a trusted conversation; clicking the button without comparing does not independently verify the other screen. No code is shortened, automatically accepted, or scanned. The existing full transcript validation, expiry checks, signatures, history verification and encrypted key delivery remain unchanged. Invitation, password-reset, promotion and recovery-kit comparison screens retain their existing behaviour.

## Verification

Evidence for this change is recorded separately from the original product release:

- `test-results/frontend-device-comparison-ui.json`: standalone actual-component interaction and layout checks using synthetic codes, without an API or database.
- `test-results/frontend-device-comparison-e2e.json`: both approval orders in two independent browser contexts against temporary application/control databases and the production frontend image.
- `test-results/frontend-device-comparison-build.log`: production compilation and TypeScript validation.
- `test-results/frontend-device-comparison-source.json`: tested candidate image and relevant source hashes.
- `test-results/frontend-device-comparison-release.json`: deployed frontend, health checks and unchanged backend container identities.

The browser checks use Chromium, Firefox and Playwright WebKit. They do not imply a native Safari retest or change the local application's canonical address.

All six end-to-end journeys passed, including both confirmation orders, stopping on a mismatch and remembered sign-in afterward. A final wording-only correction removed advice to go back and immediately create another request, because going back resumes the pending one. That exact sentence deletion is verified against the end-to-end source hashes; the final component checks and production build cover the corrected wording. The separate journey and release image identities are retained in the evidence.

All twelve final component cases passed across desktop/320-pixel widths and light/dark themes. The frontend is deployed at the preserved `http://localhost:3400` origin as `sha256:a20f54565a0e093d753958893de358715194bafcdf15eca934ef8a452b66ec48`. All six services are healthy; the API, worker and database container identities are unchanged. The two temporary test databases and preview container were removed after verifying zero remaining test workspaces and active sessions; cleanup is recorded in `test-results/frontend-device-isolation-cleanup.json`.

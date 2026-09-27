# Official Firefox verification

`scripts/run-branded-webdriver.mjs` runs the existing four protocol/crypto/storage/calculation specifications against official desktop Firefox using Mozilla GeckoDriver, W3C WebDriver navigation and WebDriver BiDi evaluation in the default page realm. The adapter changes registration and the browser-control surface only; assertions remain in `test/browser/{crypto,auth-worker,crypto-compatibility,progress}.spec.ts`. Playwright supplies assertions, not a browser binary or transport. BiDi evaluation keeps constructed inputs in the normal page realm; classic Marionette execute-script sandbox objects would correctly fail the client’s strict plain-object crypto validation. The runner does not weaken that validation or CSP.

The checks cover secure-context/WebAssembly/WebCrypto/IndexedDB capabilities; encrypted device storage across reload and explicit Forget; real OPAQUE registration/login in the dedicated module Worker, device proof and lock after logout; frozen crypto/recipient/recovery derivation vectors; and canonical Node/browser calculation agreement across London daylight-saving and due-date boundaries. They do not run the database-backed account/session, enrolment, recovery, or combined application journeys. Those have separate integration evidence.

## Provisioned versions

On 2026-09-27, [Mozilla current-version metadata](https://product-details.mozilla.org/1.0/firefox_versions.json) identified `156.0.1`; [stability history](https://product-details.mozilla.org/1.0/firefox_history_stability_releases.json) identified `155.0.1` as the latest patch in the previous major. Official macOS universal DMGs were extracted under `.local/branded-browsers/firefox-VERSION/Firefox.app`. Each DMG matched its release's Mozilla `SHA256SUMS`, and both extracted app bundles passed `codesign --verify --deep --strict` with Mozilla Corporation signatures and stapled notarization tickets.

[Mozilla GeckoDriver 0.37.1](https://github.com/mozilla/geckodriver/releases/tag/v0.37.1) macOS ARM64 was extracted to `.local/branded-browsers/geckodriver-0.37.1`. Its archive matched the official GitHub release asset digest. Provisioning metadata and exact hashes are saved to `test-results/checkpoint-13-firefox-provisioning.json`. Download/signature verification is not execution evidence.

## Run

Use native Node 24 with the existing dependencies and a centrally rebuilt `dist/browser`. Coordinate exclusive use of the HTTPS harness on loopback port 3555 before running:

```sh
node --experimental-transform-types scripts/run-branded-webdriver.mjs --version 156.0.1 --version 155.0.1 --start-server
```

Omit `--start-server` only when intentionally reusing the existing test harness. `--list` imports and lists the four specifications without starting a browser, server or driver. No application database is needed. Each browser uses GeckoDriver's generated disposable profile under `.local/branded-browsers/profiles`; no installed application, global browser preference, or existing user profile is changed. The HTTPS test certificate is accepted only in that automation session.

The runner requires the actual returned browser version to equal the requested release, saves capabilities/timings/results plus exact specification and browser-bundle SHA-256 hashes to `test-results/branded-firefox-results.json`, and returns a failing exit code for any failed check. Driver logs/profile directories remain local for diagnosis. Run results and environment limitations must be reported separately from bundled-engine results and from provisioning.

## Checkpoint 13 run evidence

The coordinated final run on 2026-09-27 passed **8/8**, four unchanged specifications in each actual branded version **156.0.1** and **155.0.1**, with process exit code 0. Native Node was `v24.19.0` on macOS ARM64. Both sessions' returned browser versions exactly matched the requested official builds. The report records full capabilities, source/bundle hashes, timings and public runtime attachments.

Retained report: `test-results/checkpoint-13-firefox-branded-final.json`, SHA-256 `829b13be0ce62ddd8243dc1d8040c049d59d50476fa805502ad1fc96fae96a06`. Log: `test-results/checkpoint-13-firefox-branded-final.log`. Provisioning evidence: `test-results/checkpoint-13-firefox-provisioning.json`.

Initial execution failed all eight cases due to the adapter's classic WebDriver sandbox realm; a single-version diagnostic run exposed the concrete `INVALID_CONTEXT`/canonical-data prototype failures after correcting error reporting. Switching the adapter to default-page-realm BiDi execution then passed both versions. Initial and diagnostic JSON reports/logs remain retained as `checkpoint-13-firefox-branded-initial.json`/`checkpoint-13-firefox-branded.log` and `checkpoint-13-firefox-branded-diagnostic.{json,log}`. No application implementation, crypto validator or CSP change was made for these runner failures. These Firefox results address only the four stated compatibility categories; the complete supported-browser matrix and combined application journeys require their own evidence.

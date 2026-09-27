# Native Safari verification

The shared `scripts/run-branded-webdriver.mjs` supports installed Safari through Apple's `/usr/bin/safaridriver`. It reuses the same four unchanged protocol/crypto/local-storage/calculation specifications as the [official Firefox runner](branded-firefox-verification.md). Playwright supplies assertions only. Safari uses classic W3C WebDriver script execution; Firefox retains its default-page-realm BiDi path.

[Apple documents](https://developer.apple.com/documentation/safari-developer-tools/webdriver) that Safari confines WebDriver execution to isolated automation windows with a clean session, separate from normal browsing data/settings. The native `safaridriver(1)` manual documents `acceptInsecureCerts` and the macOS/browser-version selection capabilities used here. HTTPS certificate acceptance is confined to the automation session. The runner does not enable Remote Automation, install updates or change Safari preferences.

## Ordered verification

Verify the current installed version before an update replaces it. The expected previous version in this environment is **26.6.2**; the coordinator identified a separate **27.0** Safari update. Once Remote Automation has been enabled and exclusive use of HTTPS harness port 3555 is available:

```sh
node --experimental-transform-types scripts/run-branded-webdriver.mjs --browser safari --version 26.6.2 --start-server
```

Preserve `test-results/branded-safari-results.json` and the command log with version-specific names before updating Safari. Then run the same command with the exact installed new version. The runner accepts one Safari version per invocation and verifies the returned actual version equals that value. It records capability/build information, source and browser-bundle hashes, timings and all four test results. `--list` checks discovery without launching Safari, GeckoDriver or the HTTPS harness.

The driver, automation session and owned harness are closed in cleanup. Safari manages its own isolated automation data; `.local/branded-browsers/profiles/safari-VERSION-*` contains the runner's diagnostic log, not a replacement Safari user profile. An environment blocked by Remote Automation remains untested until actual execution succeeds. Bundled WebKit results do not substitute for these native Safari tests.

## Safari 26.6.2 result before update

On 2026-09-27 at 02:24 UTC, the first native run passed **4/4**, process exit code **0**, before any Safari update. Returned capabilities confirmed `browserName: Safari`, `browserVersion: 26.6.2`, `platformName: macOS`, and platform build `25G83`. The real Worker OPAQUE registration/login measurements were **156/133 ms**. No runner or application repair was needed for this execution.

Evidence preserved before update: `test-results/checkpoint-13-safari-26.6.2-final.json` (SHA-256 `feccc75fe0877bbf1dd01f42d0d58da3b760bbcc8101c4d886e39015067c1b21`) and `test-results/checkpoint-13-safari-26.6.2-final.log`. The report records specification and browser-bundle hashes; executed runner SHA-256 was `2b04b0d27231b1f75cbc6193708af1982f5bb138d3aa49c1fe0e8e7524911806`. This is native Safari evidence for the four stated compatibility categories, separate from bundled WebKit and database-backed application journeys.

## Safari 27.0 result after update

After the coordinator completed the authorized standalone Safari update, the first native Safari **27.0** run passed **4/4**, process exit code **0**. Actual session creation confirmed Remote Automation remained usable. Returned capabilities identified `browserName: Safari`, `browserVersion: 27.0`, `platformName: macOS`, and platform build `25G83`. The previous **26.6.2** results above were already preserved before the update. No runner or application repair was needed.

Evidence: `test-results/checkpoint-13-safari-27.0-final.json` (SHA-256 `9477ba70cc5fb59adf6b83c631ad8cfa058aaea57b22031ed156eaf7962891d0`) and `test-results/checkpoint-13-safari-27.0-final.log`. The report records the observed UTC time, exact specification/browser-bundle hashes, returned capabilities and Worker timing measurements. Both Safari versions therefore have **8/8** passing native protocol/crypto/local-storage/calculation checks in total; no bundled WebKit result is substituted.

The coordinator reported that the host slept during the Safari installation, which completed after wake with `softwareupdate` exit code 0. The installed native bundle/driver identified Safari 27.0; no operating-system upgrade or reinstall was performed. This runner performed only the post-update compatibility test.

import { defineConfig } from '@playwright/test';
import { resolve } from 'node:path';

// These binaries are provisioned explicitly from the vendor artifacts recorded in
// test-results/checkpoint-13-browser-vendor-metadata.json. Playwright uses temporary
// browser profiles and isolated contexts; no installed user profile is selected.
const localBrowser = (path: string) => resolve('.local/branded-browsers', path);

export default defineConfig({
  testDir: './test/browser', testMatch: '**/*.spec.ts', fullyParallel: false, workers: 1,
  retries: 0, timeout: 30000, expect: { timeout: 10000 },
  outputDir: 'test-results/playwright-branded-artifacts',
  reporter: [['list'], ['json', { outputFile: 'test-results/browser-branded-results.json' }]],
  use: { baseURL: 'https://127.0.0.1:3555', ignoreHTTPSErrors: true, trace: 'off', screenshot: 'off', video: 'off' },
  projects: [
    { name: 'chrome-current-154.0.8037.57', use: { browserName: 'chromium', launchOptions: {
      executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    } } },
    { name: 'chrome-for-testing-previous-153.0.8010.52', use: { browserName: 'chromium', launchOptions: {
      executablePath: localBrowser('chrome-153.0.8010.52/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'),
    } } },
    { name: 'edge-current-154.0.4258.37', use: { browserName: 'chromium', launchOptions: {
      executablePath: localBrowser('edge-154.0.4258.37/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'),
    } } },
    { name: 'edge-previous-153.0.4234.48', use: { browserName: 'chromium', launchOptions: {
      executablePath: localBrowser('edge-153.0.4234.48/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'),
    } } },
  ],
  webServer: { command: `"${process.execPath}" test/browser/server.mjs`, url: 'https://127.0.0.1:3555',
    ignoreHTTPSErrors: true, reuseExistingServer: false, timeout: 15000, gracefulShutdown: { signal: 'SIGTERM', timeout: 3000 } },
});

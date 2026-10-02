import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './test/browser', testMatch: '**/*.spec.ts', fullyParallel: false, workers: 1,
  retries: 0, timeout: 30000, expect: { timeout: 10000 },
  // Playwright clears this directory before each run. Keep retained evidence outside it.
  outputDir: 'test-results/playwright-artifacts',
  reporter: [['list'], ['json', { outputFile: 'test-results/browser-results.json' }]],
  use: { baseURL: 'https://127.0.0.1:3555', ignoreHTTPSErrors: true, trace: 'off', screenshot: 'off', video: 'off' },
  // Bundled-engine evidence is recorded separately from the current/previous branded-browser release matrix.
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } }, { name: 'webkit', use: { browserName: 'webkit' } }],
  webServer: { command: `"${process.execPath}" test/browser/server.mjs`, url: 'https://127.0.0.1:3555',
    ignoreHTTPSErrors: true, reuseExistingServer: false, timeout: 15000, gracefulShutdown: { signal: 'SIGTERM', timeout: 3000 } },
});

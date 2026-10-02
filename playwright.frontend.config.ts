import { defineConfig } from '@playwright/test';

// A failing setup test can still display private recovery words. Omit automatic
// DOM dumps as well as visual/trace recordings; test diagnostics remain available.
process.env.PLAYWRIGHT_NO_COPY_PROMPT = '1';

export default defineConfig({
  testDir: './test/frontend', testMatch: '**/*.spec.ts', fullyParallel: false, workers: 1,
  retries: 0, timeout: 180_000, expect: { timeout: 20_000 },
  outputDir: 'test-results/frontend-artifacts',
  reporter: [['list'], ['json', { outputFile: 'test-results/frontend-results.json' }]],
  // Recovery words and invitation capabilities appear during these journeys.
  // Retained recordings must not accidentally collect their plaintext.
  use: { baseURL: 'https://127.0.0.1:3555', ignoreHTTPSErrors: true, actionTimeout: 20_000, navigationTimeout: 30_000,
    trace: 'off', screenshot: 'off', video: 'off' },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
  webServer: { command: `"${process.execPath}" test/frontend/server.mjs`, url: 'https://127.0.0.1:3555',
    ignoreHTTPSErrors: true, reuseExistingServer: false, timeout: 30_000,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 5000 } },
});

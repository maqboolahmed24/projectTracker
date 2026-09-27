import { defineConfig } from '@playwright/test';
import base from './playwright.config.js';

// Explicit opt-in keeps installed branded Chrome evidence separate from bundled engines.
// Playwright creates disposable profiles; it never reuses the user's Chrome profile.
export default defineConfig(base, {
  projects: [{ name: 'chrome-installed', use: { browserName: 'chromium', channel: 'chrome' } }],
});

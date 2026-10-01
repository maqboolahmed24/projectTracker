import { expect, test, type Page, type TestInfo } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { authenticationFixture, password } from '../browser/authentication-fixture.js';
import { navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

const contentPanel = (page: Page) => page.locator('.settings-panel').filter({
  has: page.getByRole('heading', { name: 'Content update', exact: true }),
});

async function confirmUpdate(page: Page, label: 'Start update' | 'Continue update') {
  const dialog = page.getByRole('dialog', { name: `${label === 'Start update' ? 'Start' : 'Continue'} workspace update?`, exact: true });
  await expect(dialog.getByRole('button', { name: label, exact: true })).toBeDisabled();
  await dialog.getByLabel(/^Confirm your password/).fill(password);
  await dialog.getByRole('button', { name: label, exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

async function reviewScreenshot(page: Page, testInfo: TestInfo, state: string) {
  // Capture only the seeded workspace, after password entry has unmounted.
  await expect(page.getByRole('dialog')).toHaveCount(0);
  const directory = `test-results/frontend-review/workspace-update/${testInfo.project.name}`;
  await mkdir(directory, { recursive: true });
  await page.locator('.main-content').screenshot({ path: `${directory}/${state}.png`, animations: 'disabled' });
}

// Hold only real server responses. The normal form, password confirmation,
// encrypted Worker, controller and database all remain in the exercised flow.
// No request bodies, password dialogs, traces or private recovery words are retained.
test('workspace update pauses after the current batch and resumes with one confirmation', async ({ page }, testInfo) => {
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page), batchReply = gate();
  let starts = 0, batches = 0, finishes = 0, heldBatch = false;
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    await navigate(page, '/settings/maintenance');
    const content = contentPanel(page);
    await expect(content.getByText('Update available', { exact: true })).toBeVisible();
    await page.setViewportSize({ width: 1440, height: 1000 });
    await reviewScreenshot(page, testInfo, 'ready-desktop');
    await page.route('**/v1/upgrades/start', async route => { starts++; await route.continue(); });
    await page.route('**/v1/upgrades/batch', async route => {
      batches++;
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      if (!heldBatch) {
        heldBatch = true;
        await batchReply.promise;
      }
      await route.fulfill({ response });
    });
    await page.route('**/v1/upgrades/finish', async route => { finishes++; await route.continue(); });

    await content.getByRole('button', { name: 'Start update', exact: true }).click();
    await confirmUpdate(page, 'Start update');
    await expect.poll(() => heldBatch, { timeout: 60_000 }).toBe(true);
    await reviewScreenshot(page, testInfo, 'running-desktop');
    await page.setViewportSize({ width: 390, height: 844 });
    await reviewScreenshot(page, testInfo, 'running-mobile');
    await page.setViewportSize({ width: 1440, height: 1000 });
    await content.getByRole('button', { name: 'Pause after this step', exact: true }).click();
    await expect(content.getByRole('button', { name: 'Pausing…', exact: true })).toBeDisabled();
    // The in-flight step is still held; pausing must not expose another run yet.
    await expect(content.getByRole('button', { name: 'Continue update', exact: true })).toHaveCount(0);
    batchReply.release();
    await expect(content.getByRole('button', { name: 'Continue update', exact: true })).toBeEnabled();
    await expect(content.getByText('Progress saved', { exact: true })).toBeVisible();
    await reviewScreenshot(page, testInfo, 'paused-desktop');
    expect(starts).toBe(1); expect(batches).toBe(1); expect(finishes).toBe(0);
    // Verify an actual quiet interval after the pause, not just the first paint.
    await page.waitForTimeout(500);
    expect(starts).toBe(1); expect(batches).toBe(1); expect(finishes).toBe(0);

    await content.getByRole('button', { name: 'Continue update', exact: true }).click();
    await confirmUpdate(page, 'Continue update');
    await expect(content.getByText('Up to date', { exact: true })).toBeVisible({ timeout: 90_000 });
    await reviewScreenshot(page, testInfo, 'complete-desktop');
    await page.setViewportSize({ width: 390, height: 844 });
    await reviewScreenshot(page, testInfo, 'complete-mobile');
    await expect(content.getByRole('button', { name: 'Continue update', exact: true })).toHaveCount(0);
    await expect(content.getByRole('button', { name: 'Start update', exact: true })).toHaveCount(0);
    expect(starts).toBe(1); expect(finishes).toBe(1); expect(errors).toEqual([]);
  } finally {
    batchReply.release();
    await page.close(); await fixture.close();
  }
});

test('pausing during the final request still displays its verified completion', async ({ page }) => {
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page), finishReply = gate();
  let starts = 0, finishes = 0, finishHeld = false, finishReleased = false, obsoleteContextReads = 0;
  page.on('request', request => {
    if (finishReleased && request.method() === 'POST' && request.url().endsWith('/v1/upgrades/context')) obsoleteContextReads++;
  });
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    await navigate(page, '/settings/maintenance');
    const content = contentPanel(page);
    await expect(content.getByText('Update available', { exact: true })).toBeVisible();
    await page.route('**/v1/upgrades/start', async route => { starts++; await route.continue(); });
    await page.route('**/v1/upgrades/finish', async route => {
      finishes++;
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      expect((await response.json() as { state: string }).state).toBe('completed');
      finishHeld = true;
      await finishReply.promise;
      finishReleased = true;
      await route.fulfill({ response });
    });

    await content.getByRole('button', { name: 'Start update', exact: true }).click();
    await confirmUpdate(page, 'Start update');
    await expect.poll(() => finishHeld, { timeout: 90_000 }).toBe(true);
    await expect(content.getByText('Finishing up', { exact: true })).toBeVisible();
    await content.getByRole('button', { name: 'Pause after this step', exact: true }).click();
    await expect(content.getByRole('button', { name: 'Pausing…', exact: true })).toBeDisabled();
    finishReply.release();

    await expect(content.getByText('Up to date', { exact: true })).toBeVisible({ timeout: 30_000 });
    await expect(content.getByRole('button', { name: 'Continue update', exact: true })).toHaveCount(0);
    await expect(content.getByRole('alert')).toHaveCount(0);
    expect(starts).toBe(1); expect(finishes).toBe(1); expect(obsoleteContextReads).toBe(0);
    // A fresh signed-in session independently confirms the persisted schema.
    await page.reload(); await signIn(page);
    await navigate(page, '/settings/maintenance');
    await expect(contentPanel(page).getByText('Up to date', { exact: true })).toBeVisible();
    expect(starts).toBe(1); expect(finishes).toBe(1); expect(obsoleteContextReads).toBe(0);
    expect(errors).toEqual([]);
  } finally {
    finishReply.release();
    await page.close(); await fixture.close();
  }
});

import { expect, test, type Page } from '@playwright/test';
import { authenticationFixture } from '../browser/authentication-fixture.js';
import { navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

async function createPlannedProject(page: Page, name: string) {
  await navigate(page, '/projects');
  await page.getByRole('button', { name: 'New project', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'A fresh start', exact: true });
  await dialog.getByLabel('Project name', { exact: true }).fill(name);
  await dialog.getByRole('button', { name: 'Create project', exact: true }).click();
  await expect.poll(async () => {
    const check = dialog.getByRole('button', { name: 'Check progress', exact: true });
    if (await check.isVisible() && await check.isEnabled()) await check.click();
    return page.getByRole('heading', { name, exact: true, level: 1 }).isVisible();
  }, { timeout: 20_000 }).toBe(true);
  return new URL(page.url()).pathname.split('/')[2]!;
}

test('project cards start work directly, recover a lost reply and stay useful when read-only', async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  const name = 'A thoughtful launch for our shared workspace and the next people joining our team';
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    const projectId = await createPlannedProject(page, name);
    await navigate(page, '/projects');
    const card = page.getByRole('article', { name, exact: true });
    await expect(card).toContainText('No tasks yet');
    await expect(card.getByRole('button', { name: 'Start project', exact: true })).toBeEnabled();
    await expect(card.locator('button button')).toHaveCount(0);
    await card.getByRole('heading', { name, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/projects/${projectId}/overview$`));
    await navigate(page, '/');
    // The empty card padding is a target too, including on Home.
    await card.click({ position: { x: 12, y: 12 } });
    await expect(page).toHaveURL(new RegExp(`/projects/${projectId}/overview$`));
    await navigate(page, '/projects');

    let committedStarts = 0;
    await page.route('**/v1/work/planning/save', async route => {
      const response = await route.fetch(); expect(response.status()).toBe(200);
      committedStarts++; await route.abort('failed'); // Real write; only its reply is lost.
    }, { times: 1 });
    await card.getByRole('button', { name: 'Start project', exact: true }).click();
    await expect(card.getByRole('alert')).toBeVisible();
    await expect(card.getByRole('button', { name: 'Start project', exact: true })).toBeDisabled();
    await card.getByRole('button', { name: /Try again/ }).click();
    await expect(card.locator('.badge').filter({ hasText: /^Active$/ })).toBeVisible();
    await expect(card.getByRole('button', { name: 'Start project', exact: true })).toHaveCount(0);
    await expect(page).toHaveURL(/\/projects$/);
    expect(committedStarts).toBe(1);
    await expect(card.getByRole('button', { name: 'Open project', exact: true })).toBeFocused();
    await card.getByRole('button', { name: 'Open project', exact: true }).press('Enter');
    await expect(page).toHaveURL(new RegExp(`/projects/${projectId}/overview$`));
    await expect(page.locator('.page-header')).toContainText('Active');

    const plannedName = 'Next shared project';
    await createPlannedProject(page, plannedName);
    await navigate(page, '/projects');
    await page.getByLabel('Project status', { exact: true }).selectOption('complete');
    await expect(page.getByRole('heading', { name: 'No projects in this view', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Show current projects', exact: true }).click();
    await expect(page.getByRole('article', { name: plannedName, exact: true })).toBeVisible();
    await page.getByLabel('Search visible projects and tasks', { exact: true }).fill('no such project');
    await expect(page.getByRole('heading', { name: 'No matching projects', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Clear filters', exact: true }).click();
    await expect(card).toBeVisible();

    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.evaluate(async () => { await document.fonts.ready; });
    for (const theme of ['light', 'dark']) {
      if (await page.locator('html').getAttribute('data-theme') !== theme) await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
      await page.screenshot({ path: testInfo.outputPath(`assisted-projects-${theme}.png`), fullPage: true, animations: 'disabled' });
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await expect(card.getByRole('button', { name: 'Open project', exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath('assisted-projects-mobile-dark.png'), fullPage: true, animations: 'disabled' });
    await page.setViewportSize({ width: 1440, height: 1000 });
    await navigate(page, '/');
    await expect(page.getByRole('navigation', { name: 'Your work summary' })).toBeVisible();
    await page.getByRole('navigation', { name: 'Your work summary' }).getByRole('button', { name: /For your review/ }).click();
    await expect(page.getByRole('button', { name: 'For my review', exact: true })).toHaveAttribute('aria-current', 'page');
    await page.getByLabel('Filter by project', { exact: true }).selectOption(projectId);
    await expect(page.getByRole('button', { name: 'Show all my work', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Show all my work', exact: true }).click();
    await expect(page.getByLabel('Filter by project', { exact: true })).toHaveValue('');

    // A real control-plane revocation makes the existing workspace read-only;
    // it must not leave a tempting Start action in a planned project card.
    await fixture.restrictLicence();
    await page.reload(); await signIn(page);
    await navigate(page, '/projects');
    const readonly = page.getByRole('article', { name: plannedName, exact: true });
    await expect(readonly).toContainText('This workspace is read-only');
    await expect(readonly.getByRole('button', { name: 'Start project', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'New project', exact: true })).toHaveCount(0);
    await readonly.getByRole('button', { name: 'Open project', exact: true }).click();
    await expect(page.getByRole('heading', { name: plannedName, exact: true, level: 1 })).toBeVisible();
    expect(errors).toEqual([]);
  } finally { await fixture.close(); }
});

import { expect, test, type Locator } from '@playwright/test';
import { authenticationFixture } from '../browser/authentication-fixture.js';
import { navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

async function oneRow(group: Locator) {
  const positions = await group.locator('.choice-option').evaluateAll(options => options.map(option => {
    const { top, bottom, left, right } = option.getBoundingClientRect();
    return { top, bottom, left, right, fits: option.scrollWidth <= option.clientWidth };
  }));
  expect(positions).toHaveLength(3);
  for (const position of positions) {
    expect(Math.abs(position.top - positions[0]!.top)).toBeLessThan(1);
    expect(Math.abs(position.bottom - positions[0]!.bottom)).toBeLessThan(1);
    expect(position.fits).toBe(true);
  }
  expect(positions[1]!.left).toBeGreaterThan(positions[0]!.right);
  expect(positions[2]!.left).toBeGreaterThan(positions[1]!.right);
}

async function closeDialog(dialog: Locator) {
  await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

test('priority choices stay visible and save pointer and keyboard changes to the real task', async ({ page }, testInfo) => {
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  const projectName = 'Simple choices', taskName = 'Set a clear priority';
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await seedRememberedOwner(page, fixture); await signIn(page);
    if (await page.locator('html').getAttribute('data-theme') !== 'light') await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
    await page.getByRole('button', { name: 'New project', exact: true }).click();
    let dialog = page.getByRole('dialog', { name: 'A fresh start', exact: true });
    await dialog.getByLabel('Project name', { exact: true }).fill(projectName);
    await dialog.getByRole('button', { name: 'Create project', exact: true }).click();
    await expect.poll(async () => {
      const check = dialog.getByRole('button', { name: 'Check progress', exact: true });
      if (await check.isVisible() && await check.isEnabled()) await check.click();
      return page.getByRole('heading', { name: projectName, exact: true, level: 1 }).isVisible();
    }, { timeout: 20_000 }).toBe(true);
    const projectId = new URL(page.url()).pathname.split('/')[2]!;
    await page.locator('.page-header').getByRole('button', { name: 'Add task', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Add a task', exact: true });
    await dialog.getByLabel('Task name', { exact: true }).fill(taskName);
    let priority = dialog.getByRole('radiogroup', { name: 'Priority', exact: true });
    await expect(priority.getByRole('radio')).toHaveCount(3);
    await expect(priority.getByRole('radio', { name: 'Normal', exact: true })).toBeChecked();
    await expect(dialog.getByRole('combobox', { name: 'Priority', exact: true })).toHaveCount(0);
    await priority.getByRole('radio', { name: 'High', exact: true }).click();
    await expect(priority.getByRole('radio', { name: 'High', exact: true })).toBeChecked();
    await oneRow(priority);
    await priority.screenshot({ path: testInfo.outputPath('priority-light.png'), animations: 'disabled' });
    await dialog.getByRole('button', { name: 'Add task', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await navigate(page, `/projects/${projectId}/work`);
    await page.locator('.task-row').filter({ hasText: taskName }).click();
    const taskId = new URL(page.url()).searchParams.get('task')!;
    const task = page.getByRole('dialog', { name: taskName, exact: true });
    await expect(task.locator('.detail-item').filter({ has: page.locator('.detail-label', { hasText: /^Priority$/ }) })).toContainText('High');
    await task.getByRole('button', { name: 'Edit task', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Edit task', exact: true });
    priority = dialog.getByRole('radiogroup', { name: 'Priority', exact: true });
    const high = priority.getByRole('radio', { name: 'High', exact: true }), normal = priority.getByRole('radio', { name: 'Normal', exact: true }), low = priority.getByRole('radio', { name: 'Low', exact: true });
    await expect(high).toBeChecked();
    await high.focus();
    await page.keyboard.press('ArrowLeft');
    await expect(normal).toBeChecked();
    await expect(normal).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(low).toBeChecked();
    await expect(low).toBeFocused();
    await dialog.getByRole('button', { name: 'Save changes', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(task.locator('.detail-item').filter({ has: page.locator('.detail-label', { hasText: /^Priority$/ }) })).toContainText('Low');
    await closeDialog(task);
    await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
    await page.reload(); await signIn(page);
    await navigate(page, `/projects/${projectId}/work?task=${taskId}`);
    await task.getByRole('button', { name: 'Edit task', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Edit task', exact: true });
    priority = dialog.getByRole('radiogroup', { name: 'Priority', exact: true });
    await expect(priority.getByRole('radio', { name: 'Low', exact: true })).toBeChecked();
    await expect(page.locator('html')).toHaveCSS('background-color', 'rgb(16, 17, 19)');
    await priority.screenshot({ path: testInfo.outputPath('priority-dark.png'), animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 844 });
    await oneRow(priority);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await priority.screenshot({ path: testInfo.outputPath('priority-mobile-dark.png'), animations: 'disabled' });
    await closeDialog(dialog);
    expect(errors).toEqual([]);
  } finally { await page.close(); await fixture.close(); }
});

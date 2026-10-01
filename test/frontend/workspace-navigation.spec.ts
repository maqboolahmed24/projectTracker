import { expect, test, type Page } from '@playwright/test';
import { authenticationFixture } from '../browser/authentication-fixture.js';
import { navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

async function expectPageFits(page: Page) {
  const measure = () => page.evaluate(() => ({
    viewport: innerWidth, document: document.documentElement.scrollWidth,
    overflow: Array.from(document.querySelectorAll('body *')).flatMap(element => {
      const rect = element.getBoundingClientRect(), style = getComputedStyle(element);
      if (!rect.width || rect.right <= innerWidth + 1 || style.visibility === 'hidden') return [];
      return [{ tag: element.tagName, classes: element.className, x: rect.x, width: rect.width, right: rect.right,
        client: element.clientWidth, scroll: element.scrollWidth, overflowX: style.overflowX, minWidth: style.minWidth,
        parent: element.parentElement?.className }];
    }).slice(0, 30),
  }));
  let geometry = await measure();
  const initial = geometry;
  try {
    await expect.poll(async () => {
      geometry = await measure();
      return geometry.document - geometry.viewport;
    }, { message: 'The workspace should fit after its responsive layout commits', timeout: 5000 }).toBeLessThanOrEqual(1);
  } catch (error) {
    await test.info().attach('workspace-overflow-geometry', { body: JSON.stringify(geometry, null, 2), contentType: 'application/json' });
    throw error;
  }
  if (initial.document > initial.viewport + 1) await test.info().attach('responsive-layout-settled', {
    body: JSON.stringify({ initial, settled: geometry }, null, 2), contentType: 'application/json',
  });
}

test('workspace navigation keeps mobile focus contained and remains reachable in short windows', async ({ page }) => {
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  try {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await seedRememberedOwner(page, fixture); await signIn(page);
    const sidebar = page.locator('#workspace-navigation');
    const trigger = page.locator('button[aria-controls="workspace-navigation"]');
    const main = page.locator('#main-content');

    for (const width of [390, 320]) {
      await page.setViewportSize({ width, height: 844 });
      await expect(trigger).toBeVisible();
      await expect(sidebar).toHaveAttribute('inert', '');
      await expect(sidebar).toHaveAttribute('aria-hidden', 'true');
      await expect(trigger).toHaveAttribute('aria-expanded', 'false');
      await expectPageFits(page);
      await trigger.focus();
      // Tab through the real document: translated navigation must never receive focus.
      for (let index = 0; index < 16; index++) {
        await page.keyboard.press('Tab');
        expect(await sidebar.evaluate(element => element.contains(document.activeElement))).toBe(false);
      }

      await trigger.focus(); await page.keyboard.press('Enter');
      const drawer = page.getByRole('dialog', { name: 'Workspace navigation', exact: true });
      await expect(drawer).toBeVisible();
      await expect(drawer).toHaveAttribute('aria-modal', 'true');
      await expect(trigger).toHaveAttribute('aria-expanded', 'true');
      await expect(page.locator('.workspace')).toHaveAttribute('inert', '');
      expect(await page.evaluate(() => document.documentElement.style.overflow)).toBe('hidden');
      await expect(drawer.locator('[aria-current="page"]')).toBeFocused({ timeout: 5000 });
      const beforeScroll = await page.evaluate(() => scrollY);
      await page.mouse.move(width - 12, 600); await page.mouse.wheel(0, 400);
      expect(await page.evaluate(() => scrollY)).toBe(beforeScroll);
      await drawer.locator('.wordmark').focus();
      await page.keyboard.press('Shift+Tab');
      await expect(drawer.getByRole('button', { name: 'Change appearance', exact: true })).toBeFocused();
      await page.keyboard.press('Tab');
      await expect(drawer.locator('.wordmark')).toBeFocused();
      await expectPageFits(page);
      await page.keyboard.press('Escape');
      await expect(drawer).toHaveCount(0);
      await expect(trigger).toBeFocused();
      await expect(page.locator('.workspace')).not.toHaveAttribute('inert', '');
      expect(await page.evaluate(() => document.documentElement.style.overflow)).not.toBe('hidden');
    }

    await trigger.press('Enter');
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Projects', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/projects$/);
    await expect(sidebar).toHaveAttribute('inert', '');
    await expect(main).toBeFocused();
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Drawer controls can open native dialogs without leaving a hidden scroll lock.
    await trigger.click();
    await sidebar.locator('.workspace-switch').click();
    const workspaceDialog = page.getByRole('dialog');
    await expect(workspaceDialog).toHaveCount(1);
    await expect(workspaceDialog.getByRole('button', { name: 'Workspace settings' })).toBeVisible();
    await workspaceDialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
    expect(await page.evaluate(() => document.documentElement.style.overflow)).not.toBe('hidden');
    await expectPageFits(page);

    await trigger.click();
    await page.setViewportSize({ width: 1280, height: 400 });
    await expect(sidebar).not.toHaveAttribute('inert', '');
    await expect(sidebar).not.toHaveAttribute('role', 'dialog');
    await expect(sidebar).not.toHaveClass(/sidebar-open/);
    await expect(main).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.style.overflow)).not.toBe('hidden');
    const profile = sidebar.locator('.profile-link');
    await profile.focus();
    await expect(profile).toBeInViewport();
    await profile.press('Enter');
    await expect(page.getByRole('heading', { name: 'Your account', exact: true })).toBeVisible();
    await expect(main).toBeFocused();
    await expectPageFits(page);
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(trigger).toHaveAttribute('aria-expanded', 'false');
    await expect(sidebar).toHaveAttribute('inert', '');
    await navigate(page, '/settings/roles');
    await expect(page.getByRole('heading', { name: 'Roles & permissions', exact: true })).toBeVisible();
    const settingsNav = page.getByRole('navigation', { name: 'Settings sections' });
    const activeIsVisible = () => settingsNav.evaluate(element => {
      const active = element.querySelector<HTMLElement>('[aria-current="page"]')!;
      const row = element.getBoundingClientRect(), item = active.getBoundingClientRect();
      return item.left >= row.left - 1 && item.right <= row.right + 1;
    });
    await expect.poll(activeIsVisible).toBe(true);
    await expectPageFits(page);
    // A responsive resize reveals the selected section without scrolling the page.
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.evaluate(() => scrollTo(0, 0));
    await page.setViewportSize({ width: 320, height: 844 });
    await expect.poll(activeIsVisible).toBe(true);
    expect(await page.evaluate(() => scrollY)).toBe(0);
    await expectPageFits(page);
    expect(errors).toEqual([]);
  } finally { await fixture.close(); }
});

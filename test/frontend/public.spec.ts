import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { publicFrontendFixture } from './public-fixture.js';
import { trackBrowserErrors } from './helpers.js';

test('the assembled startup mark moves into the page logo as the workspace entry appears', async ({ page }, testInfo) => {
  const fixture = await publicFrontendFixture(), errors = trackBrowserErrors(page);
  try {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'no-preference' });
    await page.addInitScript(() => {
      const samples: Array<{ phase: string; x: number; y: number; width: number; height: number; backdrop: number; hidden: boolean; inert: boolean }> = [];
      Object.defineProperty(window, '__maqboolLaunchGeometry', { value: samples });
      const deadline = performance.now() + 12_000;
      let seen = false;
      const sample = () => {
        const host = document.querySelector<HTMLElement>('[data-maqbool-launch]');
        const stage = host?.shadowRoot?.querySelector<HTMLElement>('.maqbool-launch-stage');
        if (host && stage && !host.hidden) {
          seen = true;
          const box = stage.getBoundingClientRect(), logo = document.querySelector<HTMLElement>('.identity-brand img');
          const backdrop = host.shadowRoot?.querySelector<HTMLElement>('.maqbool-launch-backdrop');
          samples.push({ phase: host.dataset.phase ?? '', x: box.x, y: box.y, width: box.width, height: box.height,
            backdrop: backdrop ? Number(getComputedStyle(backdrop).opacity) : 1,
            hidden: !!logo && getComputedStyle(logo).visibility === 'hidden',
            inert: !!document.querySelector<HTMLElement>('#maqbool-root')?.inert });
        }
        if ((!seen || host) && performance.now() < deadline) requestAnimationFrame(sample);
      };
      requestAnimationFrame(sample);
    });
    await page.goto('/');
    const launch = page.locator('[data-maqbool-launch]');
    await expect(launch).toBeVisible();
    await expect(launch).toHaveCount(0, { timeout: 12_000 });
    const geometry = await page.evaluate(() => {
      const samples = (window as unknown as { __maqboolLaunchGeometry: Array<{ phase: string; x: number; y: number; width: number; height: number; backdrop: number; hidden: boolean; inert: boolean }> }).__maqboolLaunchGeometry;
      const logo = document.querySelector<HTMLElement>('.identity-brand img')!, box = logo.getBoundingClientRect();
      return { samples, destination: { x: box.x, y: box.y, width: box.width, height: box.height }, inlineVisibility: logo.style.visibility };
    });
    const opening = geometry.samples.find(sample => sample.phase === 'opening')!;
    expect(opening).toBeTruthy();
    expect(opening.width).toBeGreaterThan(100);
    expect(Math.abs(opening.x + opening.width / 2 - 640)).toBeLessThan(1);
    expect(Math.abs(opening.y + opening.height / 2 - 400)).toBeLessThan(1);
    const moving = geometry.samples.filter(sample => sample.phase === 'handoff');
    expect(moving.length).toBeGreaterThan(2);
    expect(moving.every(sample => sample.hidden && sample.inert)).toBe(true);
    expect(moving.some(sample => sample.width < opening.width * .9 && sample.width > geometry.destination.width * 1.2)).toBe(true);
    expect(moving.some(sample => sample.backdrop > 0 && sample.backdrop < .9)).toBe(true);
    const final = moving.at(-1)!, destination = geometry.destination;
    expect(Math.abs(final.x + final.width / 2 - (destination.x + destination.width / 2))).toBeLessThan(2);
    expect(Math.abs(final.y + final.height / 2 - (destination.y + destination.height / 2))).toBeLessThan(2);
    expect(Math.abs(final.width / final.height - opening.width / opening.height)).toBeLessThan(.001);
    expect(geometry.inlineVisibility).toBe('');
    await expect(page.locator('.identity-brand img')).toBeVisible();
    expect(await page.locator('#maqbool-root').evaluate(element => (element as HTMLElement).inert)).toBe(false);
    await mkdir('test-results/frontend-review', { recursive: true });
    await page.screenshot({ path: `test-results/frontend-review/entry-desktop-${testInfo.project.name}.png`, fullPage: true, animations: 'disabled' });
    await page.getByRole('button', { name: 'Create a workspace', exact: true }).click();
    await expect(page.getByLabel('Activation key', { exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  } finally { await fixture.close(); }
});

test('mobile entry follows system appearance, supports reduced motion, and has usable light and dark layouts', async ({ page }, testInfo) => {
  const fixture = await publicFrontendFixture(), errors = trackBrowserErrors(page);
  try {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Great work starts here.' })).toBeVisible();
    await expect(page.locator('[data-maqbool-launch]')).toHaveCount(0, { timeout: 12_000 });
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.locator('html')).toHaveCSS('background-color', 'rgb(16, 17, 19)');
    await expect(page.getByRole('button', { name: 'Use light appearance' })).toBeVisible();
    await expect(page.locator('.identity-brand')).toContainText('Maqbool');
    expect(await page.locator('.identity-brand').evaluate(element => { const box = element.getBoundingClientRect(); return box.height > 0 && box.width > 0 && box.top >= 0; })).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect(await page.locator('#maqbool-root').evaluate(element => (element as HTMLElement).inert)).toBe(false);
    await mkdir('test-results/frontend-review', { recursive: true });
    await page.screenshot({ path: `test-results/frontend-review/entry-mobile-dark-${testInfo.project.name}.png`, fullPage: true, animations: 'disabled' });
    await page.getByRole('button', { name: 'Use light appearance' }).focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await page.screenshot({ path: `test-results/frontend-review/entry-mobile-light-${testInfo.project.name}.png`, fullPage: true, animations: 'disabled' });
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Great work starts here.' })).toBeVisible();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    expect(errors).toEqual([]);
  } finally { await fixture.close(); }
});

test('invalid private links stay on the entry screen with a clear way back', async ({ page }) => {
  const fixture = await publicFrontendFixture(), errors = trackBrowserErrors(page);
  try {
    await page.goto('/');
    const join = page.getByRole('button', { name: 'Join a workspace', exact: true });
    await expect(join).toBeVisible();
    await expect(page.locator('[data-maqbool-launch]')).toHaveCount(0, { timeout: 12_000 });
    await join.focus(); await page.keyboard.press('Enter');
    await page.getByLabel('Private link', { exact: true }).fill('https://another-workspace.example/#access=invalid');
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await expect(page.locator('.identity-notice[role="alert"]')).toContainText('This link is not valid for this workspace.');
    await page.getByRole('button', { name: 'Back', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Great work starts here.' })).toBeVisible();
    // A newly opened link in this same document must be consumed, validated and
    // removed from the address even though the application is already mounted.
    await page.evaluate(() => { location.hash = '#access=invalid'; });
    await expect(page.locator('.identity-notice[role="alert"]')).toContainText('This link is not valid for this workspace.');
    expect(new URL(page.url()).hash).toBe('');
    await page.getByRole('button', { name: 'Create a workspace', exact: true }).click();
    await expect(page.getByLabel('Activation key', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Back', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Join a workspace', exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  } finally { await fixture.close(); }
});

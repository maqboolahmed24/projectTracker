import { expect, test, type Locator, type Page } from '@playwright/test';
import { authenticationFixture } from '../browser/authentication-fixture.js';
import { joinViaInvitation, navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

async function closeDialog(dialog: Locator) {
  await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
  await expect(dialog).toHaveCount(0);
}
async function fresh(page: Page) {
  await page.evaluate(() => dispatchEvent(new Event('focus')));
}

test('assisted task steps explain real gates, start the right scope and keep read-only members informed', async ({ page, browser }, testInfo) => {
  test.setTimeout(240_000);
  const fixture = await authenticationFixture();
  const memberContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const member = await memberContext.newPage();
  const errors = [trackBrowserErrors(page), trackBrowserErrors(member)];
  const name = 'A clear next step', waveName = 'First shared step', taskName = 'Prepare a friendly welcome';
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    if (await page.locator('html').getAttribute('data-theme') !== 'light') await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
    await page.getByRole('button', { name: 'New project', exact: true }).click();
    let dialog = page.getByRole('dialog', { name: 'A fresh start', exact: true });
    await dialog.getByLabel('Project name', { exact: true }).fill(name);
    await dialog.getByRole('button', { name: 'Create project', exact: true }).click();
    await expect.poll(async () => {
      const check = dialog.getByRole('button', { name: 'Check progress', exact: true });
      if (await check.isVisible() && await check.isEnabled()) await check.click();
      return page.getByRole('heading', { name, exact: true, level: 1 }).isVisible();
    }, { timeout: 20_000 }).toBe(true);
    const projectId = new URL(page.url()).pathname.split('/')[2]!;
    await expect(page.locator('.page-header').getByRole('button', { name: 'Start project', exact: true })).toBeVisible();
    await navigate(page, `/projects/${projectId}/work`);
    // An empty project offers one clear start; no duplicate empty task group.
    await expect(page.getByRole('heading', { name: 'Every project starts with one task', exact: true })).toBeVisible();
    await expect(page.locator('.task-group')).toHaveCount(0);
    await page.getByRole('button', { name: 'Add wave', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Add wave', exact: true });
    await dialog.getByLabel('Name', { exact: true }).fill(waveName);
    await dialog.getByRole('button', { name: 'Add wave', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await page.locator('.page-header').getByRole('button', { name: 'Add task', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Add a task', exact: true });
    await dialog.getByLabel('Task name', { exact: true }).fill(taskName);
    await dialog.getByLabel('What does done look like?', { exact: true }).fill('The team can take its first step without guessing.');
    await dialog.getByLabel('Wave', { exact: true }).selectOption({ label: waveName });
    await dialog.getByRole('checkbox', { name: 'Browser owner', exact: true }).check();
    await dialog.getByLabel('Task lead', { exact: true }).selectOption({ label: 'Browser owner' });
    await dialog.getByRole('button', { name: 'Add task', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await page.locator('.task-row').filter({ hasText: taskName }).click();
    const taskId = new URL(page.url()).searchParams.get('task')!;
    let task = page.getByRole('dialog', { name: taskName, exact: true });
    await expect(task.locator('.work-guidance')).toContainText('Start the project to begin');
    await expect(task.getByRole('button', { name: 'Start task', exact: true })).toHaveCount(0);
    await closeDialog(task);

    // Search trims surrounding spaces and opens the actual named wave.
    const searchTrigger = page.locator('.topbar').getByRole('button', { name: 'Find your work', exact: true });
    await expect(searchTrigger).toHaveClass('icon-button');
    await expect(searchTrigger).toHaveText('');
    await expect(searchTrigger.locator('svg')).toHaveCount(1);
    await expect(searchTrigger.locator('input, span, kbd')).toHaveCount(0);
    await expect(searchTrigger).toHaveAttribute('title', 'Find your work (⌘K / Ctrl+K)');
    await expect(searchTrigger).toHaveAttribute('aria-haspopup', 'dialog');
    await expect(searchTrigger).toHaveAttribute('aria-expanded', 'false');
    await searchTrigger.click();
    const search = page.getByRole('dialog', { name: 'Find your work', exact: true });
    const searchInput = search.getByRole('textbox', { name: 'Search your work', exact: true });
    await expect(searchInput).toBeFocused();
    await expect(searchTrigger).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('Escape');
    await expect(search).toHaveCount(0);
    await expect(searchTrigger).toHaveAttribute('aria-expanded', 'false');
    // Use actual keyboard events; both advertised platform shortcuts reopen it.
    await page.keyboard.press('Control+k');
    await expect(searchInput).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(search).toHaveCount(0);
    await page.keyboard.press('Meta+k');
    await expect(searchInput).toBeFocused();
    await searchInput.fill(`  ${waveName}  `);
    await search.locator('.search-results > button').filter({ hasText: waveName }).click();
    const wave = page.getByRole('dialog', { name: waveName, exact: true });
    await expect(wave).toBeVisible();
    expect(new URL(page.url()).searchParams.get('phase')).toMatch(/^[0-9a-f-]{36}$/);
    await wave.getByRole('button', { name: 'Add milestone', exact: true }).click();
    const milestoneName = 'A shared checkpoint';
    const addMilestone = page.getByRole('dialog', { name: 'Add milestone', exact: true });
    await addMilestone.getByLabel('Name', { exact: true }).fill(milestoneName);
    await addMilestone.getByRole('button', { name: 'Save milestone', exact: true }).click();
    await expect(addMilestone).toHaveCount(0);
    await wave.locator('.milestone-row').filter({ hasText: milestoneName }).click();
    const milestone = page.getByRole('dialog', { name: milestoneName, exact: true });
    await expect(milestone).toBeVisible();
    await expect(wave).toHaveCount(0);
    expect(new URL(page.url()).searchParams.has('phase')).toBe(false);
    await closeDialog(milestone);
    // Moving to a milestone must not leave a stale wave query that prevents
    // the same search result from reopening its actual detail dialog.
    await searchTrigger.click();
    await searchInput.fill(waveName);
    await search.locator('.search-results > button').filter({ hasText: waveName }).click();
    await expect(wave).toBeVisible();
    expect(new URL(page.url()).searchParams.get('phase')).toMatch(/^[0-9a-f-]{36}$/);
    await closeDialog(wave);
    expect(new URL(page.url()).searchParams.has('phase')).toBe(false);

    // The search icon sits inside its input and wide screens retain compact gaps.
    await page.setViewportSize({ width: 2000, height: 1000 });
    const geometry = await page.locator('.work-toolbar').evaluate(toolbar => {
      const rect = (element: Element) => { const value = element.getBoundingClientRect(); return { x: value.x, y: value.y, width: value.width, height: value.height }; };
      return { input: rect(toolbar.querySelector('.search-field input')!), icon: rect(toolbar.querySelector('.search-field > svg')!),
        controls: Array.from(toolbar.querySelectorAll(':scope > .search-field, :scope > select')).map(rect) };
    });
    expect(geometry.icon.x).toBeGreaterThan(geometry.input.x);
    expect(geometry.icon.x + geometry.icon.width).toBeLessThan(geometry.input.x + geometry.input.width);
    expect(Math.abs(geometry.icon.y + geometry.icon.height / 2 - geometry.input.y - geometry.input.height / 2)).toBeLessThan(2);
    expect(geometry.controls).toHaveLength(4);
    for (let index = 1; index < geometry.controls.length; index++) {
      const before = geometry.controls[index - 1]!, next = geometry.controls[index]!;
      expect(Math.abs(next.y - before.y)).toBeLessThan(2);
      expect(next.x - before.x - before.width).toBeGreaterThanOrEqual(8);
      expect(next.x - before.x - before.width).toBeLessThanOrEqual(24);
    }
    await page.screenshot({ path: testInfo.outputPath('assisted-work-wide-toolbar.png'), fullPage: true, animations: 'disabled' });

    // Opening and dismissing a task leaves the underlying Work page in place.
    await page.setViewportSize({ width: 1440, height: 560 });
    const row = page.locator('.task-row').filter({ hasText: taskName });
    await row.scrollIntoViewIfNeeded();
    await page.evaluate(() => scrollBy(0, 35));
    const beforeOpen = await page.evaluate(() => scrollY);
    expect(beforeOpen).toBeGreaterThan(0);
    await row.click();
    await expect(task).toBeVisible();
    expect(Math.abs(await page.evaluate(() => scrollY) - beforeOpen)).toBeLessThanOrEqual(1);
    await closeDialog(task);
    expect(Math.abs(await page.evaluate(() => scrollY) - beforeOpen)).toBeLessThanOrEqual(1);
    await page.setViewportSize({ width: 1440, height: 1000 });

    await joinViaInvitation(page, member, { name: 'Casey Guest', password: 'Quiet gardens welcome a new day 826', role: 'Member', projectNames: [name] });
    await navigate(member, `/projects/${projectId}/work?task=${taskId}`);
    const memberTask = member.getByRole('dialog', { name: taskName, exact: true });
    await expect(memberTask.locator('.work-guidance')).toContainText('A project manager needs to start this project');
    await expect(memberTask.getByRole('button', { name: 'Start project', exact: true })).toHaveCount(0);
    await expect(memberTask.getByRole('button', { name: 'Start task', exact: true })).toHaveCount(0);

    // Starting from the project header is discoverable, without Project options.
    await navigate(page, `/projects/${projectId}/overview`);
    await page.locator('.page-header').getByRole('button', { name: 'Start project', exact: true }).click();
    await expect(page.locator('.page-header')).toContainText('Active');
    await expect(page.locator('.page-header').getByRole('button', { name: 'Start project', exact: true })).toHaveCount(0);
    await fresh(member);
    await expect(memberTask.locator('.work-guidance')).toContainText(`A project manager needs to start “${waveName}”`);
    await expect(memberTask.getByRole('button', { name: 'Start wave', exact: true })).toHaveCount(0);
    await navigate(page, `/projects/${projectId}/work?task=${taskId}`);
    task = page.getByRole('dialog', { name: taskName, exact: true });
    await expect(task.locator('.work-guidance')).toContainText('Start the wave to begin');
    await task.getByRole('button', { name: 'Start wave', exact: true }).click();
    await expect(task.getByRole('button', { name: 'Start task', exact: true })).toBeEnabled();
    await task.getByRole('button', { name: 'Start task', exact: true }).click();
    await expect(task.locator('.task-subtitle')).toContainText('In progress');
    await expect(task.locator('.work-guidance')).toContainText('Keep the work moving');
    await fresh(member);
    await expect(memberTask.locator('.work-guidance')).toContainText('You’re following this task');
    for (const action of ['Start task', 'Mark complete', 'Edit task', 'Change assignees']) {
      await expect(memberTask.getByRole('button', { name: action, exact: true })).toHaveCount(0);
    }
    // Switching content never changes the detail dialog frame.
    await page.setViewportSize({ width: 1440, height: 1000 });
    const bounds = await task.boundingBox();
    expect(bounds).not.toBeNull();
    for (const tab of ['Discussion', 'Activity', 'Details']) {
      await task.getByRole('tab', { name: tab, exact: true }).click();
      const changed = await task.boundingBox();
      expect(changed?.width).toBe(bounds?.width);
      expect(changed?.height).toBe(bounds?.height);
    }
    await page.evaluate(async () => { await document.fonts.ready; });
    await page.screenshot({ path: testInfo.outputPath('assisted-task-light.png'), fullPage: true, animations: 'disabled' });
    await closeDialog(task);
    if (await page.locator('html').getAttribute('data-theme') !== 'dark') await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
    await navigate(page, `/projects/${projectId}/work?task=${taskId}`);
    await expect(page.locator('html')).toHaveCSS('background-color', 'rgb(16, 17, 19)');
    await page.screenshot({ path: testInfo.outputPath('assisted-task-dark.png'), fullPage: true, animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath('assisted-task-mobile-dark.png'), fullPage: true, animations: 'disabled' });
    await closeDialog(task);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.getByLabel('Search project tasks', { exact: true }).fill('Nothing matches this');
    await expect(page.locator('.work-filter-summary')).toContainText('0 tasks match your filters');
    await expect(page.getByRole('button', { name: 'Clear filters', exact: true })).toHaveCount(1);
    await page.getByRole('button', { name: 'Clear filters', exact: true }).click();
    await expect(page.locator('.task-row').filter({ hasText: taskName })).toBeVisible();

    // This is a real entitlement change, not a mocked authority object.
    await fixture.restrictLicence();
    await page.reload(); await signIn(page);
    await navigate(page, `/projects/${projectId}/work?task=${taskId}`);
    task = page.getByRole('dialog', { name: taskName, exact: true });
    await expect(task.locator('.work-guidance')).toContainText('Your workspace is read only');
    for (const action of ['Start task', 'Mark complete', 'Edit task', 'Add blocker', 'Change assignees', 'Move to To do']) {
      await expect(task.getByRole('button', { name: action, exact: true })).toHaveCount(0);
    }
    expect(errors.flat()).toEqual([]);
  } finally { await memberContext.close(); await page.close(); await fixture.close(); }
});

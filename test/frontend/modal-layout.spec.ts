import { expect, test, type Locator, type Page } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { authenticationFixture } from '../browser/authentication-fixture.js';
import { navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

async function modalGeometry(dialog: Locator) {
  const geometry = await dialog.evaluate(async element => {
    // Modal entry transforms affect getBoundingClientRect without changing the
    // CSS frame. Measure after its own finite animation ends; never wait on child
    // spinners, inject timing delays or widen the geometry tolerance.
    const entryAnimations = element.getAnimations().filter(animation => Number.isFinite(animation.effect?.getComputedTiming().endTime));
    const entryTransform = getComputedStyle(element).transform;
    await Promise.all(entryAnimations.map(animation => animation.finished.catch(() => undefined)));
    const box = element.getBoundingClientRect(), body = element.querySelector<HTMLElement>('.modal-body')!;
    const header = element.querySelector<HTMLElement>('.modal-header')!.getBoundingClientRect();
    // Failure diagnostics contain only layout metadata: never text, input values,
    // IDs, attributes containing private links, or the page's fragment/query.
    const layout = (node: Element) => {
      const rect = node.getBoundingClientRect(), style = getComputedStyle(node);
      return { tag: node.tagName.toLowerCase(), classes: node.getAttribute('class') ?? '',
        x: rect.x, y: rect.y, width: rect.width, height: rect.height, right: rect.right,
        clientWidth: node.clientWidth, scrollWidth: node.scrollWidth, position: style.position,
        overflowX: style.overflowX, display: style.display, minWidth: style.minWidth, maxWidth: style.maxWidth };
    };
    const overflow = document.documentElement.scrollWidth > innerWidth + 1 ? Array.from(document.querySelectorAll('body *'))
      .filter(node => { const rect = node.getBoundingClientRect(); return rect.width > 0 && rect.right > innerWidth + 1; })
      .slice(0, 100).map(node => {
        const ancestors = []; let parent = node.parentElement;
        for (let depth = 0; parent && depth < 8; depth++, parent = parent.parentElement) ancestors.push(layout(parent));
        return { ...layout(node), ancestors };
      }) : [];
    return { x: box.x, y: box.y, width: box.width, height: box.height, right: box.right, bottom: box.bottom,
      viewportWidth: innerWidth, viewportHeight: innerHeight, documentWidth: document.documentElement.scrollWidth,
      dialogClientWidth: element.clientWidth, dialogScrollWidth: element.scrollWidth, dialogScrollTop: element.scrollTop,
      bodyClientWidth: body.clientWidth, bodyScrollWidth: body.scrollWidth, bodyClientHeight: body.clientHeight,
      bodyScrollHeight: body.scrollHeight, bodyScrollTop: body.scrollTop, headerY: header.y, pageScrollY: scrollY,
      bodyPortal: element.parentElement === document.body, nativeModal: element.matches(':modal'),
      entryAnimationsWaited: entryAnimations.length, entryTransform, settledTransform: getComputedStyle(element).transform,
      pathname: location.pathname, overflow };
  });
  if (geometry.documentWidth > geometry.viewportWidth + 1) {
    await mkdir('test-results/frontend-review/modal-layout', { recursive: true });
    await writeFile(`test-results/frontend-review/modal-layout/overflow-${test.info().project.name}.json`, JSON.stringify(geometry, null, 2) + '\n');
  }
  return geometry;
}

function expectWithinViewport(geometry: Awaited<ReturnType<typeof modalGeometry>>) {
  expect(geometry.bodyPortal).toBe(true);
  expect(geometry.nativeModal).toBe(true);
  expect(geometry.width).toBeGreaterThan(250);
  expect(geometry.height).toBeGreaterThan(200);
  expect(geometry.x).toBeGreaterThanOrEqual(0);
  expect(geometry.y).toBeGreaterThanOrEqual(0);
  expect(geometry.right).toBeLessThanOrEqual(geometry.viewportWidth + 1);
  expect(geometry.bottom).toBeLessThanOrEqual(geometry.viewportHeight + 1);
  expect(geometry.documentWidth).toBeLessThanOrEqual(geometry.viewportWidth + 1);
  expect(geometry.dialogScrollWidth).toBeLessThanOrEqual(geometry.dialogClientWidth + 1);
  expect(geometry.bodyScrollWidth).toBeLessThanOrEqual(geometry.bodyClientWidth + 1);
}

async function createLayoutTask(page: Page) {
  const projectName = 'A thoughtful first week', taskName = 'Prepare the first-day guide with practical examples, welcoming introductions and clear next steps for everyone joining the team';
  await page.getByRole('button', { name: 'New project', exact: true }).click();
  const create = page.getByRole('dialog', { name: 'A fresh start', exact: true });
  await create.getByLabel('Project name', { exact: true }).fill(projectName);
  await create.getByRole('button', { name: 'Create project', exact: true }).click();
  await expect.poll(async () => {
    const check = create.getByRole('button', { name: 'Check progress', exact: true });
    if (await check.isVisible() && await check.isEnabled()) await check.click();
    return page.getByRole('heading', { name: projectName, exact: true, level: 1 }).isVisible();
  }, { timeout: 20_000 }).toBe(true);
  const projectId = new URL(page.url()).pathname.split('/')[2];
  if (!projectId) throw new Error('The created project was not opened');
  const options = page.getByRole('button', { name: 'Project options', exact: true });
  const headingBefore = await page.locator('.page-header').boundingBox();
  await options.click();
  const menu = page.getByRole('dialog', { name: 'Project options', exact: true });
  await expect(menu).toBeVisible();
  const headingDuring = await page.locator('.page-header').boundingBox();
  expect(headingDuring).toEqual(headingBefore);
  await menu.getByRole('button', { name: 'Start project', exact: true }).click();
  await expect(page.locator('.page-header')).toContainText('Active');
  await menu.getByRole('button', { name: 'Close dialog', exact: true }).click();
  await expect(menu).toHaveCount(0);
  await navigate(page, `/projects/${projectId}/work`);
  await page.getByRole('button', { name: 'Add task', exact: true }).click();
  const editor = page.getByRole('dialog', { name: 'Add a task', exact: true });
  await editor.getByLabel('Task name', { exact: true }).fill(taskName);
  const description = Array.from({ length: 16 }, (_, index) => `Step ${index + 1}: Explain one part of the first day in clear, welcoming language. Include a useful example and give the new teammate room to ask questions.`).join('\n\n');
  await editor.getByLabel('Description', { exact: true }).fill(description);
  await editor.getByLabel('What does done look like?', { exact: true }).fill('The guide is complete, clear and ready for the team to review.');
  await editor.getByRole('checkbox', { name: 'Browser owner', exact: true }).check();
  await editor.getByLabel('Task lead', { exact: true }).selectOption({ label: 'Browser owner' });
  await editor.getByRole('button', { name: 'Add task', exact: true }).click();
  await expect(editor).toHaveCount(0);
  await page.locator('.task-row').filter({ hasText: taskName }).click();
  const task = page.getByRole('dialog', { name: taskName, exact: true });
  await task.getByRole('button', { name: 'Start task', exact: true }).click();
  await expect(task.locator('.task-subtitle')).toContainText('In progress');
  await task.getByRole('tab', { name: 'Discussion', exact: true }).click();
  const comment = 'The first draft is ready for a careful read. We can make the examples clearer together.';
  await task.getByLabel('Add to the conversation', { exact: true }).fill(comment);
  await task.getByRole('button', { name: 'Post comment', exact: true }).click();
  await expect(task.locator('.discussion-entry').filter({ hasText: comment })).toHaveCount(1);
  const draft = 'A thought to finish before sending: add one helpful example for the team.';
  await task.getByLabel('Add to the conversation', { exact: true }).fill(draft);
  await task.getByRole('tab', { name: 'Details', exact: true }).click();
  return { task, taskName, projectId, description, draft };
}

test('task tabs keep a stable frame, scroll inside it and return from nested editing', async ({ page }, testInfo) => {
  test.setTimeout(240_000);
  // Execute via .local/run-modal-frontend.mjs, which verifies both isolated
  // databases before allowing this real API/Worker/browser fixture to run.
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
    await seedRememberedOwner(page, fixture); await signIn(page);
    const { task, taskName, description, draft } = await createLayoutTask(page);
    const measurements: unknown[] = [];
    await mkdir('test-results/frontend-review/modal-layout', { recursive: true });
    for (const width of [1440, 390, 320]) {
      await page.setViewportSize({ width, height: width === 1440 ? 1000 : 844 });
      for (const theme of ['light', 'dark'] as const) {
        await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        let first: Awaited<ReturnType<typeof modalGeometry>> | undefined;
        for (const tab of ['Details', 'Discussion', 'Activity']) {
          await task.getByRole('tab', { name: tab, exact: true }).click();
          await expect(task.getByRole('tab', { name: tab, exact: true })).toHaveAttribute('aria-selected', 'true');
          if (tab === 'Activity') await expect(task.locator('.activity-list')).toBeVisible();
          if (tab === 'Discussion') {
            await expect(task.locator('.discussion-entry')).toHaveCount(1);
            await expect(task.getByLabel('Add to the conversation', { exact: true })).toHaveValue(draft);
          }
          const geometry = await modalGeometry(task);
          expectWithinViewport(geometry);
          if (!first) first = geometry;
          else for (const dimension of ['x', 'y', 'width', 'height'] as const) expect(Math.abs(geometry[dimension] - first[dimension])).toBeLessThanOrEqual(1);
          measurements.push({ requestedWidth: width, theme, tab, ...geometry });
          const close = await task.getByRole('button', { name: 'Close dialog', exact: true }).boundingBox();
          if (!close) throw new Error('The task close control could not be measured');
          expect(close.x).toBeGreaterThanOrEqual(geometry.x);
          expect(close.x + close.width).toBeLessThanOrEqual(geometry.right);
          if (tab === 'Details') {
            expect(geometry.bodyScrollHeight).toBeGreaterThan(geometry.bodyClientHeight + 100);
            if (width === 1440 && theme === 'light') {
              const body = task.locator('.modal-body');
              await body.focus();
              await page.keyboard.press('PageDown');
              await expect.poll(() => body.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
              const keyboardScrolled = await modalGeometry(task);
              expect(keyboardScrolled.dialogScrollTop).toBe(0);
              expect(Math.abs(keyboardScrolled.headerY - geometry.headerY)).toBeLessThanOrEqual(1);
              expect(keyboardScrolled.pageScrollY).toBe(geometry.pageScrollY);
              await body.evaluate(element => { element.scrollTop = 0; });
            }
            await task.locator('.modal-body').evaluate(element => { element.scrollTop = element.scrollHeight; });
            const scrolled = await modalGeometry(task);
            expect(scrolled.bodyScrollTop).toBeGreaterThan(100);
            expect(scrolled.dialogScrollTop).toBe(0);
            expect(Math.abs(scrolled.headerY - geometry.headerY)).toBeLessThanOrEqual(1);
            expect(scrolled.pageScrollY).toBe(geometry.pageScrollY);
            await expect(task.getByRole('button', { name: 'Close dialog', exact: true })).toBeVisible();
            await task.locator('.modal-body').evaluate(element => { element.scrollTop = 0; });
          }
          if (testInfo.project.name === 'chromium') await page.screenshot({ path: `test-results/frontend-review/modal-layout/task-${tab.toLowerCase()}-${width}-${theme}.png`, animations: 'disabled' });
        }
      }
    }
    await writeFile(`test-results/frontend-review/modal-layout/task-geometry-${testInfo.project.name}.json`, JSON.stringify(measurements, null, 2) + '\n');

    await task.getByRole('tab', { name: 'Details', exact: true }).focus();
    await page.keyboard.press('ArrowRight');
    await expect(task.getByRole('tab', { name: 'Discussion', exact: true })).toHaveAttribute('aria-selected', 'true');
    await expect(task.getByRole('tab', { name: 'Discussion', exact: true })).toBeFocused();
    await expect(task.getByLabel('Add to the conversation', { exact: true })).toHaveValue(draft);
    await page.keyboard.press('End');
    await expect(task.getByRole('tab', { name: 'Activity', exact: true })).toHaveAttribute('aria-selected', 'true');
    await expect(task.getByRole('tab', { name: 'Activity', exact: true })).toBeFocused();
    await page.keyboard.press('Home');
    await expect(task.getByRole('tab', { name: 'Details', exact: true })).toHaveAttribute('aria-selected', 'true');

    for (const width of [1440, 320]) {
      await page.setViewportSize({ width, height: 1000 });
      await task.getByRole('tab', { name: 'Details', exact: true }).click();
      for (const dismissal of ['Escape', 'Cancel'] as const) {
        const before = await modalGeometry(task);
        // WebKit pointer activation does not necessarily focus a button. Open
        // from keyboard focus so restoring that focus has the same contract in
        // every engine, while retaining both Escape and Cancel dismissal paths.
        const edit = task.getByRole('button', { name: 'Edit task', exact: true });
        await edit.focus();
        await expect(edit).toBeFocused();
        await page.keyboard.press('Enter');
        const editor = page.getByRole('dialog', { name: 'Edit task', exact: true });
        await expect(editor).toBeVisible();
        await expect(page.locator('dialog[open]')).toHaveCount(2);
        expectWithinViewport(await modalGeometry(editor));
        await expect(editor.getByLabel('Task name', { exact: true })).toHaveValue(taskName);
        await expect(editor.getByLabel('Description', { exact: true })).toHaveValue(description);
        await editor.getByLabel('Task name', { exact: true }).fill('An unsaved change');
        if (dismissal === 'Escape') await page.keyboard.press('Escape');
        else await editor.getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(editor).toHaveCount(0);
        await expect(page.locator('dialog[open]')).toHaveCount(1);
        await expect(task).toBeVisible();
        await expect(task.getByRole('tab', { name: 'Details', exact: true })).toHaveAttribute('aria-selected', 'true');
        await expect(task.getByRole('button', { name: 'Edit task', exact: true })).toBeFocused();
        const after = await modalGeometry(task);
        for (const dimension of ['x', 'y', 'width', 'height'] as const) expect(Math.abs(after[dimension] - before[dimension])).toBeLessThanOrEqual(1);
      }
    }
    await task.getByRole('button', { name: 'Close dialog', exact: true }).click();
    await expect(page.locator('dialog[open]')).toHaveCount(0);
    await expect(page.locator('.task-row').filter({ hasText: taskName })).toBeVisible();

    await page.setViewportSize({ width: 1440, height: 1000 });
    const waveName = 'Pilot the welcome experience';
    await page.getByRole('button', { name: 'Add wave', exact: true }).click();
    const waveEditor = page.getByRole('dialog', { name: 'Add wave', exact: true });
    await waveEditor.getByLabel('Name', { exact: true }).fill(waveName);
    await waveEditor.getByLabel('Objective', { exact: true }).fill(Array.from({ length: 14 }, (_, index) => `Learning ${index + 1}: Introduce the guide to a small group, listen carefully to their questions, and improve the examples before the next group joins.`).join('\n\n'));
    await waveEditor.getByLabel('Completion criteria', { exact: true }).fill('Everyone in the pilot can find the right next step and share feedback.');
    await waveEditor.getByRole('button', { name: 'Add wave', exact: true }).click();
    await expect(waveEditor).toHaveCount(0);
    await page.getByRole('button', { name: waveName, exact: true }).click();
    const wave = page.getByRole('dialog', { name: waveName, exact: true });
    await wave.getByRole('button', { name: 'Start wave', exact: true }).click();
    await expect(wave.getByRole('button', { name: 'Complete wave', exact: true })).toBeEnabled();
    await wave.getByRole('tab', { name: 'Updates', exact: true }).click();
    const updateDraft = 'Draft for the pilot team: we have one more example to discuss before sharing this update.';
    await wave.getByLabel('Share an update', { exact: true }).fill(updateDraft);
    await wave.getByRole('tab', { name: 'Work', exact: true }).click();
    const waveMeasurements: unknown[] = [];
    for (const width of [1440, 320]) {
      await page.setViewportSize({ width, height: width === 1440 ? 1000 : 844 });
      for (const theme of ['light', 'dark'] as const) {
        await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        let first: Awaited<ReturnType<typeof modalGeometry>> | undefined;
        for (const tab of ['Work', 'Updates', 'History']) {
          await wave.getByRole('tab', { name: tab, exact: true }).click();
          await expect(wave.getByRole('tab', { name: tab, exact: true })).toHaveAttribute('aria-selected', 'true');
          if (tab === 'Updates') await expect(wave.getByLabel('Share an update', { exact: true })).toHaveValue(updateDraft);
          if (tab === 'History') await expect(wave.locator('.activity-list')).toBeVisible();
          const geometry = await modalGeometry(wave);
          expectWithinViewport(geometry);
          if (!first) first = geometry;
          else for (const dimension of ['x', 'y', 'width', 'height'] as const) expect(Math.abs(geometry[dimension] - first[dimension])).toBeLessThanOrEqual(1);
          waveMeasurements.push({ requestedWidth: width, theme, tab, ...geometry });
          if (tab === 'Work') {
            expect(geometry.bodyScrollHeight).toBeGreaterThan(geometry.bodyClientHeight + 100);
            await wave.locator('.modal-body').evaluate(element => { element.scrollTop = element.scrollHeight; });
            const scrolled = await modalGeometry(wave);
            expect(scrolled.bodyScrollTop).toBeGreaterThan(100);
            expect(scrolled.dialogScrollTop).toBe(0);
            expect(Math.abs(scrolled.headerY - geometry.headerY)).toBeLessThanOrEqual(1);
            expect(scrolled.pageScrollY).toBe(geometry.pageScrollY);
            await expect(wave.getByRole('tab', { name: 'Updates', exact: true })).toBeVisible();
            await wave.locator('.modal-body').evaluate(element => { element.scrollTop = 0; });
          }
          if (testInfo.project.name === 'chromium') await page.screenshot({ path: `test-results/frontend-review/modal-layout/wave-${tab.toLowerCase()}-${width}-${theme}.png`, animations: 'disabled' });
        }
      }
    }
    await writeFile(`test-results/frontend-review/modal-layout/wave-geometry-${testInfo.project.name}.json`, JSON.stringify(waveMeasurements, null, 2) + '\n');
    await wave.getByRole('button', { name: 'Close dialog', exact: true }).click();
    await expect(page.locator('dialog[open]')).toHaveCount(0);
    expect(errors).toEqual([]);
  } finally { await page.close(); await fixture.close(); }
});

test('account, timezone and person settings stay in bounded dialogs and cancel without changes', async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page), writes: string[] = [];
  page.on('request', request => {
    if (request.method() === 'POST' && /\/v1\/(auth\/password-change|auth\/access-change\/(begin|stage|finalize)|reporting\/save)/.test(new URL(request.url()).pathname)) writes.push(new URL(request.url()).pathname);
  });
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
    await seedRememberedOwner(page, fixture); await signIn(page);
    const measurements: unknown[] = [];
    await mkdir('test-results/frontend-review/modal-layout', { recursive: true });
    for (const width of [1440, 390, 320]) {
      await page.setViewportSize({ width, height: width === 1440 ? 1000 : 844 });
      for (const theme of ['light', 'dark'] as const) {
        await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        await navigate(page, '/settings/account');
        await expect(page.locator('.settings-content input[type="password"]')).toHaveCount(0);
        await page.getByRole('button', { name: 'Change password', exact: true }).click();
        let dialog = page.getByRole('dialog', { name: 'Change your password', exact: true });
        await expect(dialog).toBeVisible();
        await expect(page.locator('dialog[open]')).toHaveCount(1);
        await expect(dialog.getByLabel('Current password', { exact: true })).toHaveValue('');
        await expect(dialog.getByLabel(/^New password/)).toHaveValue('');
        const passwordGeometry = await modalGeometry(dialog);
        expectWithinViewport(passwordGeometry);
        measurements.push({ requestedWidth: width, theme, dialog: 'password', ...passwordGeometry });
        if (testInfo.project.name === 'chromium') await page.screenshot({ path: `test-results/frontend-review/modal-layout/password-${width}-${theme}.png`, animations: 'disabled' });
        await dialog.getByLabel('Current password', { exact: true }).fill('An unsaved test entry');
        await page.keyboard.press('Escape');
        await expect(page.locator('dialog[open]')).toHaveCount(0);
        await expect(page.locator('.settings-content input[type="password"]')).toHaveCount(0);

        await navigate(page, '/settings/workspace');
        const timezone = page.locator('.settings-panel').filter({ has: page.getByRole('heading', { name: 'Reporting timezone', exact: true }) });
        await expect(timezone).toContainText('Europe/London');
        await expect(timezone.getByLabel('Timezone', { exact: true })).toHaveCount(0);
        await timezone.getByRole('button', { name: 'Change timezone', exact: true }).click();
        dialog = page.getByRole('dialog', { name: 'Change reporting timezone?', exact: true });
        await expect(dialog).toBeVisible();
        await expect(page.locator('dialog[open]')).toHaveCount(1);
        await expect(dialog.getByLabel('Timezone', { exact: true })).toHaveValue('Europe/London');
        await expect(dialog.getByLabel(/^Confirm your password/)).toHaveValue('');
        const timezoneGeometry = await modalGeometry(dialog);
        expectWithinViewport(timezoneGeometry);
        measurements.push({ requestedWidth: width, theme, dialog: 'timezone', ...timezoneGeometry });
        if (testInfo.project.name === 'chromium') await page.screenshot({ path: `test-results/frontend-review/modal-layout/timezone-${width}-${theme}.png`, animations: 'disabled' });
        await dialog.getByLabel('Timezone', { exact: true }).selectOption('America/New_York');
        await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(dialog).toHaveCount(0);
        await expect(timezone).toContainText('Europe/London');
        await expect(timezone.getByLabel('Timezone', { exact: true })).toHaveCount(0);

        await navigate(page, '/settings/people');
        await page.getByRole('button', { name: 'Manage Browser owner', exact: true }).click();
        dialog = page.getByRole('dialog', { name: 'Browser owner', exact: true });
        await expect(dialog).toBeVisible();
        let initialPerson: Awaited<ReturnType<typeof modalGeometry>> | undefined;
        for (const action of ['access', 'suspend', 'remove']) {
          await dialog.getByLabel('Action', { exact: true }).selectOption(action);
          await expect(dialog).toContainText('Invite and activate another Owner before changing the last Owner’s access.');
          const personGeometry = await modalGeometry(dialog);
          expectWithinViewport(personGeometry);
          if (!initialPerson) initialPerson = personGeometry;
          else for (const dimension of ['x', 'y', 'width', 'height'] as const) expect(Math.abs(personGeometry[dimension] - initialPerson[dimension])).toBeLessThanOrEqual(1);
          measurements.push({ requestedWidth: width, theme, dialog: 'person', action, ...personGeometry });
        }
        if (testInfo.project.name === 'chromium') await page.screenshot({ path: `test-results/frontend-review/modal-layout/person-${width}-${theme}.png`, animations: 'disabled' });
        await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(dialog).toHaveCount(0);
      }
    }
    await writeFile(`test-results/frontend-review/modal-layout/settings-geometry-${testInfo.project.name}.json`, JSON.stringify(measurements, null, 2) + '\n');
    expect(writes).toEqual([]);
    expect(errors).toEqual([]);
  } finally { await page.close(); await fixture.close(); }
});

import { expect, test, type Locator, type Page, type TestInfo } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { authenticationFixture, password } from '../browser/authentication-fixture.js';
import { navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

const projectName = 'A thoughtful welcome for every new teammate';
const phaseName = 'Prepare a clear and welcoming first experience';
const taskNames = ['Write the welcome guide with practical examples for the whole team', 'Review the first-day checklist and make the next steps clear'] as const;

async function closeDialog(dialog: Locator) {
  await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

async function createWork(page: Page) {
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
  expect(projectId).toMatch(/^[0-9a-f-]{36}$/);
  await page.getByRole('button', { name: 'Project options', exact: true }).click();
  await page.getByRole('button', { name: 'Edit details', exact: true }).click();
  dialog = page.getByRole('dialog', { name: 'Project details', exact: true });
  await expect(dialog.getByLabel('Organise work into', { exact: true })).toHaveCount(0);
  await dialog.getByLabel('Description', { exact: true }).fill('A shared place to turn the small details of joining a team into a clear, useful and welcoming experience.');
  await dialog.getByLabel('Start date', { exact: true }).fill('2026-10-01');
  await dialog.getByLabel('Due date', { exact: true }).fill('2026-11-15');
  await dialog.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await page.locator('.page-header').getByRole('button', { name: 'Start project', exact: true }).click();
  await expect(page.locator('.page-header')).toContainText('Active');

  await navigate(page, `/projects/${projectId}/work`);
  for (const [name, dated] of [[phaseName, true], ['Listen, improve and share what we learn', false]] as const) {
    await page.getByRole('button', { name: 'Add phase', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Add phase', exact: true });
    await dialog.getByLabel('Name', { exact: true }).fill(name);
    await dialog.getByLabel('Objective', { exact: true }).fill('Give the team useful context, a clear first step and enough space to share thoughtful feedback.');
    if (dated) {
      await dialog.getByLabel('Start date', { exact: true }).fill('2026-10-01');
      await dialog.getByLabel('Due date', { exact: true }).fill('2026-10-20');
    }
    await dialog.getByRole('button', { name: 'Add phase', exact: true }).click();
    await expect(dialog).toHaveCount(0);
  }
  await page.getByRole('button', { name: phaseName, exact: true }).click();
  const phase = page.getByRole('dialog', { name: phaseName, exact: true });
  await phase.getByRole('button', { name: 'Start phase', exact: true }).click();
  await expect(phase.getByRole('button', { name: 'Complete phase', exact: true })).toBeVisible();
  await closeDialog(phase);

  for (const [index, name] of taskNames.entries()) {
    await page.locator('.page-header').getByRole('button', { name: 'Add task', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Add a task', exact: true });
    await dialog.getByLabel('Task name', { exact: true }).fill(name);
    await dialog.getByLabel('Description', { exact: true }).fill('Make the first step easy to understand. Include one useful example, explain where to ask questions and leave a clear next action.');
    await dialog.getByLabel('What does done look like?', { exact: true }).fill('The team can use the guide without needing an extra explanation.');
    await dialog.getByLabel('Phase', { exact: true }).selectOption({ label: phaseName });
    await dialog.getByRole('checkbox', { name: 'Browser owner', exact: true }).check();
    await dialog.getByLabel('Task lead', { exact: true }).selectOption({ label: 'Browser owner' });
    await dialog.getByLabel('Due date', { exact: true }).fill(index ? '2026-10-20' : '2026-10-12');
    if (!index) await dialog.getByRole('radio', { name: 'High', exact: true }).check();
    await dialog.getByRole('button', { name: 'Add task', exact: true }).click();
    await expect(dialog).toHaveCount(0);
  }
  await expect(page.locator('.task-row')).toHaveCount(2);
  await page.locator('.task-row').filter({ hasText: taskNames[0] }).click();
  const task = page.getByRole('dialog', { name: taskNames[0], exact: true });
  const taskId = new URL(page.url()).searchParams.get('task')!;
  await task.getByRole('button', { name: 'Start task', exact: true }).click();
  await expect(task.locator('.task-subtitle')).toContainText('In progress');
  await task.getByRole('tab', { name: 'Discussion', exact: true }).click();
  await task.getByLabel('Add to the conversation', { exact: true }).fill('The outline is ready. The next step is to check that the examples answer the questions a new teammate would ask.');
  await task.getByRole('button', { name: 'Post comment', exact: true }).click();
  await expect(task.locator('.discussion-entry')).toHaveCount(1);
  await closeDialog(task);
  return { projectId, taskId };
}

async function createTeam(page: Page) {
  await navigate(page, '/settings/teams');
  await page.getByRole('button', { name: 'Create team', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Create a team', exact: true });
  await dialog.getByLabel('Team name', { exact: true }).fill('Welcome experience and shared delivery');
  await dialog.getByLabel(/^Description/).fill('A small team making everyday collaboration feel clear and considered.');
  await dialog.getByRole('checkbox', { name: /Browser owner/ }).check();
  await dialog.getByLabel(/^Confirm your password/).fill(password);
  await dialog.getByRole('button', { name: 'Create team', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.locator('.settings-team-card')).toHaveCount(1);
}

async function measurePage(page: Page) {
  return page.evaluate(() => {
    const visible = (element: Element) => element.getClientRects().length > 0 && getComputedStyle(element).visibility !== 'hidden';
    const box = (element: Element) => {
      const bounds = element.getBoundingClientRect();
      return { left: bounds.left, right: bounds.right, top: bounds.top, bottom: bounds.bottom, width: bounds.width, height: bounds.height };
    };
    const main = document.querySelector('#main-content')!;
    const header = main.querySelector('.page-header')!;
    const heading = header.querySelector('h1')!;
    const controls = Array.from(main.querySelectorAll('.page-actions .button,.files-heading .button,.work-group-actions .button'))
      .filter(visible).map(element => ({ label: element.textContent?.trim(), ...box(element), scrollWidth: element.scrollWidth, clientWidth: element.clientWidth, scrollHeight: element.scrollHeight, clientHeight: element.clientHeight }));
    const overflow = document.documentElement.scrollWidth > innerWidth + 1
      ? Array.from(main.querySelectorAll('*')).filter(visible).filter(element => box(element).right > innerWidth + 1).slice(0, 12).map(element => ({ tag: element.tagName, className: element.className, ...box(element) }))
      : [];
    return { width: innerWidth, documentWidth: document.documentElement.scrollWidth, header: box(header), heading: box(heading), controls, overflow };
  });
}

type View = { key: string; path: string; heading: string | RegExp; ready: (page: Page) => Promise<void> };

async function capture(page: Page, testInfo: TestInfo, view: View, width: number, theme: string, evidence: unknown[]) {
  await navigate(page, view.path);
  await expect(page.getByRole('heading', { level: 1, name: view.heading, exact: typeof view.heading === 'string' })).toBeVisible();
  await view.ready(page);
  await expect(page.locator('.settings-loading')).toHaveCount(0);
  if (view.key === 'overview') {
    await expect(page.getByRole('button', { name: 'Refresh progress', exact: true })).toHaveCount(0);
    await expect(page.locator('.metric-health')).not.toContainText('Last known');
  }
  await page.evaluate(async () => { await document.fonts.ready; scrollTo({ top: 0, behavior: 'instant' }); });
  const dismiss = page.getByRole('button', { name: 'Dismiss notification', exact: true });
  while (await dismiss.count()) await dismiss.first().click();
  await expect(page.locator('dialog[open]')).toHaveCount(0);
  await expect(page.locator('input[type=password]:visible')).toHaveCount(0);
  const geometry = await measurePage(page);
  evidence.push({ view: view.key, theme, ...geometry });
  const note = `${view.key} at ${width}px in ${theme}`;
  expect(geometry.documentWidth, note).toBeLessThanOrEqual(geometry.width + 1);
  expect(geometry.header.left, note).toBeGreaterThanOrEqual(0);
  expect(geometry.header.right, note).toBeLessThanOrEqual(width + 1);
  expect(geometry.heading.width, note).toBeGreaterThan(80);
  for (const control of geometry.controls) {
    expect(control.left, `${note}: ${control.label}`).toBeGreaterThanOrEqual(0);
    expect(control.right, `${note}: ${control.label}`).toBeLessThanOrEqual(width + 1);
    expect(control.height, `${note}: ${control.label}`).toBeGreaterThanOrEqual(30);
    expect(control.scrollWidth, `${note}: ${control.label}`).toBeLessThanOrEqual(control.clientWidth + 1);
    expect(control.scrollHeight, `${note}: ${control.label}`).toBeLessThanOrEqual(control.clientHeight + 1);
  }
  if (view.key === 'timeline') {
    const rows = await page.locator('.timeline-row').evaluateAll(elements => elements.map(element => {
      const row = element.getBoundingClientRect(), title = element.children[0]!.getBoundingClientRect();
      const track = element.querySelector('.timeline-track')!.getBoundingClientRect();
      const status = element.querySelector('.badge')!.getBoundingClientRect();
      return { rowLeft: row.left, rowRight: row.right, titleRight: title.right, titleBottom: title.bottom,
        trackLeft: track.left, trackRight: track.right, trackTop: track.top, statusLeft: status.left, statusRight: status.right };
    }));
    for (const row of rows) {
      expect(row.trackLeft, note).toBeGreaterThanOrEqual(row.rowLeft);
      expect(row.trackRight, note).toBeLessThanOrEqual(row.rowRight + 1);
      expect(row.statusRight, note).toBeLessThanOrEqual(row.rowRight + 1);
      if (width <= 700) expect(row.trackTop, note).toBeGreaterThanOrEqual(row.titleBottom);
      else {
        expect(row.trackLeft, note).toBeGreaterThan(row.titleRight);
        expect(row.statusLeft, note).toBeGreaterThan(row.trackRight);
      }
    }
    evidence.push({ view: view.key, theme, width, timelineRows: rows });
  }
  if (view.key === 'work' || view.key === 'my-work') {
    const titles = await page.locator('.task-row-title').evaluateAll(elements => elements.map(element => {
      const rect = element.getBoundingClientRect(); return { left: rect.left, right: rect.right };
    }));
    expect(titles).toHaveLength(2);
    expect(Math.abs(titles[0]!.left - titles[1]!.left), note).toBeLessThanOrEqual(1);
    for (const title of titles) expect(title.right, note).toBeLessThanOrEqual(width + 1);
  }
  await page.screenshot({ path: testInfo.outputPath(`workspace-${view.key}-${width}-${theme}.png`), fullPage: true, animations: 'disabled' });
}

test('workspace polish keeps real work and settings clear across desktop, tablet, mobile and both themes', async ({ page }, testInfo) => {
  test.setTimeout(360_000);
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page), evidence: unknown[] = [];
  const observedLabels = new Map<string, string>();
  const reads: Promise<void>[] = [];
  page.on('response', response => {
    if (!response.ok() || !response.url().endsWith('/v1/work/planning/context')) return;
    reads.push(response.json().then((body: { context?: { graph?: { project?: { id: string; phaseLabel: string } } }; graph?: { project?: { id: string; phaseLabel: string } } }) => {
      const project = (body.context ?? body).graph?.project;
      if (project) observedLabels.set(project.id, project.phaseLabel);
    }).catch(() => {}));
  });
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
    await seedRememberedOwner(page, fixture); await signIn(page);
    const { projectId, taskId } = await createWork(page);
    await expect.poll(() => observedLabels.get(projectId)).toBe('wave');
    // The real signed graph still uses its legacy value. Every rendered control
    // must use Phase without rewriting the graph or user-authored project text.
    await expect(page.getByRole('button', { name: 'Add phase', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Add wave', exact: true })).toHaveCount(0);
    await expect(page.getByLabel('Group tasks', { exact: true }).locator('option[value="wave"]')).toHaveText('By phase');
    await createTeam(page);
    await fixture.deliverFrontendNotifications();

    const views: View[] = [
      { key: 'home', path: '/', heading: /^Good (morning|afternoon|evening), Browser\.$/, ready: async p => { await expect(p.locator('.project-card')).toHaveCount(1); } },
      { key: 'projects', path: '/projects', heading: 'Projects', ready: async p => { await expect(p.locator('.project-card')).toHaveCount(1); } },
      { key: 'work', path: `/projects/${projectId}/work`, heading: projectName, ready: async p => { await expect(p.locator('.task-row')).toHaveCount(2); } },
      { key: 'overview', path: `/projects/${projectId}/overview`, heading: projectName, ready: async p => { await expect(p.locator('.metric').filter({ hasText: 'PROGRESS' })).toContainText('0%'); await expect(p.locator('.wave-card')).toHaveCount(2); } },
      { key: 'timeline', path: `/projects/${projectId}/timeline`, heading: projectName, ready: async p => { await expect(p.locator('.timeline-row')).toHaveCount(2); await expect(p.locator('.timeline-unscheduled')).toHaveText('Dates not set'); } },
      { key: 'files', path: `/projects/${projectId}/files`, heading: projectName, ready: async p => { await expect(p.getByRole('heading', { name: 'Your project files start here', exact: true })).toBeVisible(); } },
      { key: 'my-work', path: '/my-work', heading: 'My work', ready: async p => { await expect(p.locator('.task-row')).toHaveCount(2); } },
      { key: 'inbox', path: '/inbox', heading: 'Inbox', ready: async p => { await expect(p.locator('.loading-row')).toHaveCount(0); await expect(p.getByRole('button', { name: 'Refresh Inbox', exact: true })).toBeEnabled(); } },
      { key: 'workspace', path: '/settings/workspace', heading: 'Workspace', ready: async p => { await expect(p.getByLabel('Workspace name', { exact: true })).toHaveValue('Browser workspace'); } },
      { key: 'people', path: '/settings/people', heading: 'People', ready: async p => { await expect(p.getByRole('button', { name: 'Manage Browser owner', exact: true })).toBeVisible(); } },
      { key: 'teams', path: '/settings/teams', heading: 'Teams', ready: async p => { await expect(p.locator('.settings-team-card')).toHaveCount(1); } },
      { key: 'roles', path: '/settings/roles', heading: 'Roles & permissions', ready: async p => { await expect(p.locator('.settings-role-card').filter({ has: p.getByRole('heading', { name: 'Owner', exact: true }) })).toBeVisible(); } },
      { key: 'account', path: '/settings/account', heading: 'Your account', ready: async p => { await expect(p.locator('.settings-profile')).toContainText('Browser owner'); } },
    ];
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: width === 1440 ? 1000 : 844 });
      for (const theme of ['light', 'dark'] as const) {
        await navigate(page, '/settings/workspace');
        await page.getByLabel('Colour theme', { exact: true }).selectOption(theme);
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        for (const view of views) await capture(page, testInfo, view, width, theme, evidence);

        await navigate(page, `/projects/${projectId}/work?task=${taskId}`);
        const task = page.getByRole('dialog', { name: taskNames[0], exact: true });
        await expect(task).toBeVisible();
        for (const tab of ['Details', 'Discussion']) {
          await task.getByRole('tab', { name: tab, exact: true }).click();
          if (tab === 'Discussion') await expect(task.locator('.discussion-entry')).toHaveCount(1);
          expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
          const bounds = await task.boundingBox();
          expect(bounds).not.toBeNull();
          expect(bounds!.x).toBeGreaterThanOrEqual(0);
          expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width + 1);
          await page.screenshot({ path: testInfo.outputPath(`workspace-task-${tab.toLowerCase()}-${width}-${theme}.png`), animations: 'disabled' });
        }
        await closeDialog(task);
      }
    }
    await page.setViewportSize({ width: 1024, height: 900 });
    for (const theme of ['light', 'dark'] as const) {
      await navigate(page, '/settings/workspace');
      await page.getByLabel('Colour theme', { exact: true }).selectOption(theme);
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      for (const view of views.filter(view => view.path.startsWith('/settings/'))) await capture(page, testInfo, view, 1024, theme, evidence);
    }
    await Promise.all(reads);
    expect(observedLabels.get(projectId)).toBe('wave');
    expect(errors).toEqual([]);
  } finally {
    await mkdir(testInfo.outputDir, { recursive: true });
    await writeFile(testInfo.outputPath('workspace-geometry.json'), JSON.stringify(evidence, null, 2) + '\n');
    await page.close(); await fixture.close();
  }
});

import { expect, test, type Locator, type Page, type TestInfo } from '@playwright/test';
import { authenticationFixture } from '../browser/authentication-fixture.js';
import { joinViaInvitation, navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

async function projectOptions(page: Page) {
  const dialog = page.getByRole('dialog', { name: 'Project options', exact: true });
  if (!await dialog.isVisible()) await page.getByRole('button', { name: 'Project options', exact: true }).click();
  await expect(dialog).toBeVisible();
}

async function createProject(page: Page, name: string, loseFirstRefresh = false) {
  await page.getByRole('button', { name: 'New project', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'A fresh start', exact: true });
  await dialog.getByLabel('Project name', { exact: true }).fill(name);
  if (loseFirstRefresh) await page.route('**/v1/work/planning/context', async route => {
    // Project creation does not read planning. This is the subsequent screen
    // refresh, after its verified completion, and must never reopen creation.
    const response = await route.fetch(); expect(response.status()).toBe(200); await route.abort('failed');
  }, { times: 1 });
  await dialog.getByRole('button', { name: 'Create project', exact: true }).click();
  // Projection can still be finishing after its durable receipt. Follow the
  // product's explicit check, with a bounded deadline rather than re-creating.
  await expect.poll(async () => {
    const check = dialog.getByRole('button', { name: 'Check progress', exact: true });
    if (await check.isVisible() && await check.isEnabled()) await check.click();
    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    if (loseFirstRefresh && await refresh.isVisible()) {
      await expect(dialog).toHaveCount(0);
      await refresh.click();
    }
    return page.getByRole('heading', { name, exact: true, level: 1 }).isVisible();
  }, { timeout: 20_000 }).toBe(true);
  const id = new URL(page.url()).pathname.split('/')[2];
  expect(id).toMatch(/^[0-9a-f-]{36}$/);
  await page.locator('.page-header').getByRole('button', { name: 'Start project', exact: true }).click();
  await expect(page.locator('.page-header')).toContainText('Active');
  return id!;
}

async function finishOutcome(page: Page, title: string, reason: string) {
  const dialog = page.getByRole('dialog', { name: title, exact: true });
  await dialog.getByLabel('Outcome or reason', { exact: true }).fill(reason);
  await dialog.getByRole('button', { name: title, exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

async function closeDialog(dialog: Locator) {
  await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

async function freshProjects(page: Page) {
  // Returning to the app refreshes the current authorized planning graph.
  await page.evaluate(() => dispatchEvent(new Event('focus')));
}

async function captureProject(page: Page, projectId: string, testInfo: TestInfo) {
  if (testInfo.project.name !== 'chromium') return;
  const options = page.getByRole('dialog', { name: 'Project options', exact: true });
  if (await options.isVisible()) await closeDialog(options);
  const notifications = page.getByRole('button', { name: 'Dismiss notification', exact: true });
  for (let remaining = await notifications.count(); remaining > 0; remaining--) {
    if (await notifications.first().isVisible()) await notifications.first().click();
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
  if (await page.locator('html').getAttribute('data-theme') === 'dark') await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
  for (const theme of ['light', 'dark'] as const) {
    if (await page.locator('html').getAttribute('data-theme') !== theme) await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
    if (theme === 'dark') {
      await expect(page.locator('html')).toHaveCSS('background-color', 'rgb(16, 17, 19)');
      await expect(page.locator('.sidebar')).toHaveCSS('background-color', 'rgb(25, 27, 31)');
    }
    for (const tab of ['work', 'overview']) {
      await navigate(page, `/projects/${projectId}/${tab}`);
      await expect(page.getByRole('heading', { name: 'A calmer launch', level: 1, exact: true })).toBeVisible();
      if (tab === 'overview') await expect(page.locator('.metric').filter({ hasText: 'PROGRESS' })).toContainText('0%');
      await page.evaluate(async () => { await document.fonts.ready; });
      await page.screenshot({ path: testInfo.outputPath(`project-${tab}-${theme}.png`), fullPage: true, animations: 'disabled' });
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await navigate(page, `/projects/${projectId}/work`);
  await page.screenshot({ path: testInfo.outputPath('project-work-mobile-dark.png'), fullPage: true, animations: 'disabled' });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
}

test('a project moves through waves, shared work history, completion and archive without a dead end', async ({ page }, testInfo) => {
  test.setTimeout(240_000);
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  const projectName = 'A calmer launch', waveName = 'Pilot with the team', taskName = 'Prepare the welcome guide';
  const comment = 'The outline is ready for a first look.', hiddenReason = 'A newer note supersedes this first outline.';
  const writes: string[] = [];
  page.on('request', request => {
    if (/\/v1\/(work\/planning|collaboration)\/save$/.test(new URL(request.url()).pathname)) writes.push(request.postData() ?? '');
  });
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    const projectId = await createProject(page, projectName, true);
    await projectOptions(page);
    await page.getByRole('button', { name: 'Edit details', exact: true }).click();
    let dialog = page.getByRole('dialog', { name: 'Project details', exact: true });
    await dialog.getByLabel('Description', { exact: true }).fill('A thoughtful first release for our team.');
    await dialog.getByLabel('Start date', { exact: true }).fill('2026-10-01');
    await dialog.getByLabel('Due date', { exact: true }).fill('2026-11-14');
    await dialog.getByLabel('Project lead', { exact: true }).selectOption({ label: 'Browser owner' });
    await dialog.getByRole('button', { name: 'Save changes', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await page.getByRole('navigation', { name: 'Project navigation' }).getByRole('button', { name: 'Work', exact: true }).click();
    await page.getByRole('button', { name: 'Add wave', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Add wave', exact: true });
    await dialog.getByLabel('Name', { exact: true }).fill(waveName);
    await dialog.getByLabel('Objective', { exact: true }).fill('Learn from one small launch.');
    await dialog.getByLabel('Start date', { exact: true }).fill('2026-10-01');
    await dialog.getByLabel('Due date', { exact: true }).fill('2026-10-14');
    await dialog.getByLabel('Completion criteria', { exact: true }).fill('The guide is ready and the team can begin.');
    await dialog.getByRole('button', { name: 'Add wave', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await page.getByRole('button', { name: waveName, exact: true }).click();
    const wave = page.getByRole('dialog', { name: waveName, exact: true });
    await wave.getByRole('button', { name: 'Start wave', exact: true }).click();
    await expect(wave.getByRole('button', { name: 'Complete wave', exact: true })).toBeEnabled();
    await wave.getByRole('button', { name: 'Add task', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Add a task', exact: true });
    await dialog.getByLabel('Task name', { exact: true }).fill(taskName);
    await dialog.getByLabel('Description', { exact: true }).fill('Write a short guide that helps everyone take their first step.');
    await dialog.getByLabel('What does done look like?', { exact: true }).fill('The guide is clear and ready to share.');
    await dialog.getByRole('checkbox', { name: 'Browser owner', exact: true }).check();
    await dialog.getByLabel('Task lead', { exact: true }).selectOption({ label: 'Browser owner' });
    await dialog.getByLabel('Due date', { exact: true }).fill('2026-10-12');
    await dialog.getByRole('button', { name: 'Add task', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(wave.getByRole('button', { name: 'Complete wave', exact: true })).toBeDisabled();
    await wave.locator('.task-row').filter({ hasText: taskName }).click();
    const task = page.getByRole('dialog', { name: taskName, exact: true });
    const taskId = new URL(page.url()).searchParams.get('task');
    expect(taskId).toMatch(/^[0-9a-f-]{36}$/);
    await task.getByRole('button', { name: 'Start task', exact: true }).click();
    await expect(task.locator('.task-subtitle')).toContainText('In progress');
    await task.getByRole('button', { name: 'Add blocker', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'What is in the way?', exact: true });
    await dialog.getByLabel('What is blocking progress?', { exact: true }).fill('We need the final welcome message.');
    await dialog.getByLabel('Next action', { exact: true }).fill('Agree the message together.');
    await dialog.getByRole('button', { name: 'Save blocker', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(task.getByRole('button', { name: 'Mark complete', exact: true })).toBeDisabled();
    await closeDialog(task);
    await captureProject(page, projectId, testInfo);
    await navigate(page, `/projects/${projectId}/work?task=${taskId}`);
    await task.getByRole('button', { name: 'Resolve', exact: true }).click();
    await finishOutcome(page, 'Resolve blocker', 'The welcome message is agreed.');
    await expect(task.getByRole('button', { name: 'Mark complete', exact: true })).toBeEnabled();
    await task.getByRole('tab', { name: 'Discussion', exact: true }).click();
    // Commit a real comment and lose only its HTTP reply. The existing operation
    // must finish through the retry button without posting a second comment.
    let commentSaves = 0;
    page.on('request', request => { if (request.url().endsWith('/v1/collaboration/save')) commentSaves++; });
    await page.route('**/v1/collaboration/save', async route => {
      const response = await route.fetch(); expect(response.status()).toBe(200); await route.abort('failed');
    }, { times: 1 });
    await task.getByLabel('Add to the conversation', { exact: true }).fill(comment);
    await task.getByRole('button', { name: 'Post comment', exact: true }).click();
    await task.getByRole('button', { name: 'Try again', exact: false }).click();
    await expect(task.locator('.discussion-entry').filter({ hasText: comment })).toHaveCount(1);
    await expect(task.getByLabel('Add to the conversation', { exact: true })).toHaveValue('');
    expect(commentSaves).toBe(1);
    await task.locator('.discussion-entry').filter({ hasText: comment }).getByRole('button', { name: 'Hide', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Hide this entry?', exact: true });
    await dialog.getByLabel('Reason', { exact: true }).fill(hiddenReason);
    await dialog.getByRole('button', { name: 'Hide entry', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(task.locator('.discussion-entry')).toHaveCount(0);
    await task.getByRole('checkbox', { name: 'Include hidden history', exact: true }).check();
    await expect(task.locator('.discussion-entry')).toContainText(comment);
    await expect(task.locator('.discussion-entry')).toContainText(hiddenReason);
    await task.getByRole('tab', { name: 'Details', exact: true }).click();
    await task.getByRole('button', { name: 'Mark complete', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Ready to mark complete?', exact: true });
    await expect(dialog.getByRole('button', { name: 'Mark complete', exact: true })).toBeDisabled();
    await dialog.getByRole('checkbox', { name: 'The work meets its acceptance criteria.', exact: true }).check();
    await dialog.getByRole('button', { name: 'Mark complete', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(task.locator('.task-subtitle')).toContainText('Done');
    await task.getByRole('tab', { name: 'Activity', exact: true }).click();
    await expect(task.locator('.activity-list')).toContainText('The welcome message is agreed.');
    await closeDialog(task);
    await page.getByRole('button', { name: waveName, exact: true }).click();
    await wave.getByRole('button', { name: 'Complete wave', exact: true }).click();
    await finishOutcome(page, 'Complete wave', 'Our pilot is ready. Keep the next wave just as focused.');
    await expect(wave.getByRole('button', { name: 'Reopen wave', exact: true })).toBeVisible();
    await closeDialog(wave);
    await page.getByRole('button', { name: 'Add milestone', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Add milestone', exact: true });
    await dialog.getByLabel('Name', { exact: true }).fill('Ready to welcome everyone');
    await dialog.getByLabel('Due date', { exact: true }).fill('2026-10-15');
    await dialog.getByRole('button', { name: 'Save milestone', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await page.getByRole('navigation', { name: 'Project navigation' }).getByRole('button', { name: 'Timeline', exact: true }).click();
    await expect(page.locator('.timeline-row').filter({ hasText: waveName })).toContainText('Complete');
    await expect(page.locator('.timeline-bar')).toBeVisible();
    await page.locator('.milestone-row').filter({ hasText: 'Ready to welcome everyone' }).click();
    const milestone = page.getByRole('dialog', { name: 'Ready to welcome everyone', exact: true });
    await milestone.getByRole('button', { name: 'Accept milestone', exact: true }).click();
    await finishOutcome(page, 'Accept milestone', 'The team is ready for the next step.');
    await expect(milestone.getByRole('button', { name: 'Reopen milestone', exact: true })).toBeVisible();
    await closeDialog(milestone);
    await page.getByRole('navigation', { name: 'Project navigation' }).getByRole('button', { name: 'Updates', exact: true }).click();
    await page.getByLabel('Share an update', { exact: true }).fill('Our first launch is complete. Thank you, everyone.');
    await page.getByRole('button', { name: 'Share update', exact: true }).click();
    await expect(page.locator('.discussion-feed')).toContainText('Our first launch is complete. Thank you, everyone.');
    await projectOptions(page);
    await page.getByRole('button', { name: 'Complete project', exact: true }).click();
    await finishOutcome(page, 'Complete project', 'A small release with a clear path forward.');
    await projectOptions(page);
    await page.getByRole('button', { name: 'Archive project', exact: true }).click();
    await expect(page.getByRole('dialog', { name: 'Project options', exact: true }).getByRole('button', { name: 'Unarchive project', exact: true })).toBeVisible();
    await expect(page.getByLabel('Share an update', { exact: true })).toHaveCount(0);
    await closeDialog(page.getByRole('dialog', { name: 'Project options', exact: true }));
    await page.getByRole('button', { name: 'All projects', exact: false }).click();
    await page.getByLabel('Project status', { exact: true }).selectOption('archived');
    await expect(page.locator('.project-card').filter({ hasText: projectName })).toHaveCount(1);
    await page.locator('.project-card').filter({ hasText: projectName }).getByRole('button', { name: 'Open project', exact: true }).click();
    await projectOptions(page);
    await page.getByRole('dialog', { name: 'Project options', exact: true }).getByRole('button', { name: 'Unarchive project', exact: true }).click();
    await page.getByRole('dialog', { name: 'Project options', exact: true }).getByRole('button', { name: 'Reopen project', exact: true }).click();
    await expect(page.locator('.page-header')).toContainText('Active');
    await closeDialog(page.getByRole('dialog', { name: 'Project options', exact: true }));
    await navigate(page, '/my-work');
    await page.getByRole('checkbox', { name: 'Include finished tasks', exact: true }).check();
    await expect(page.locator('.task-row').filter({ hasText: taskName })).toHaveCount(1);
    // A failed overview calculation must offer a visible, bounded retry path.
    // Keep real report reads unavailable until the person explicitly retries.
    let reportingUnavailable = true;
    await page.route('**/v1/reporting/context', async route => {
      if (reportingUnavailable) await route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'REPORTING_UNAVAILABLE', message: 'Please try again shortly.' } }) });
      else await route.continue();
    });
    await page.reload();
    await signIn(page);
    await navigate(page, `/projects/${projectId}/work?task=${taskId}`);
    await expect(task.locator('.task-subtitle')).toContainText('Done');
    await task.getByRole('tab', { name: 'Discussion', exact: true }).click();
    await task.getByRole('checkbox', { name: 'Include hidden history', exact: true }).check();
    await expect(task.locator('.discussion-entry')).toContainText(hiddenReason);
    await closeDialog(task);
    await navigate(page, `/projects/${projectId}/overview`);
    const retryProgress = page.getByRole('button', { name: 'Refresh progress', exact: true });
    await expect(retryProgress).toBeVisible();
    reportingUnavailable = false;
    await retryProgress.click();
    await expect(page.locator('.metric').filter({ hasText: 'PROGRESS' })).toContainText('100%');
    await expect(retryProgress).toHaveCount(0);
    await navigate(page, '/');
    await page.getByRole('button', { name: 'Check interrupted saves', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Everything is accounted for', exact: true })).toBeVisible();
    expect(writes.length).toBeGreaterThan(8);
    for (const body of writes) for (const privateText of [taskName, comment, hiddenReason, 'The welcome message is agreed.']) expect(body.includes(privateText)).toBe(false);
    expect(errors).toEqual([]);
  } finally { await page.close(); await fixture.close(); }
});

test('two assignees share one task, an independent reviewer approves it, and Inbox leads back to the real work', async ({ page, browser }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'The full three-person journey runs in Chromium; the core work journey covers each engine.');
  test.setTimeout(300_000);
  const fixture = await authenticationFixture();
  const collaboratorContext = await browser.newContext({ ignoreHTTPSErrors: true }), reviewerContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const collaborator = await collaboratorContext.newPage(), reviewer = await reviewerContext.newPage();
  const errors = [page, collaborator, reviewer].map(trackBrowserErrors);
  const projectName = 'Our shared first step', taskName = 'Shape the first release together';
  const collaboratorName = 'Jordan Lee', reviewerName = 'Riley Chen';
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    const projectId = await createProject(page, projectName);
    await joinViaInvitation(page, collaborator, { name: collaboratorName, password: 'Evening gardens welcome quiet ideas 729', role: 'Manager', projectNames: [projectName] });
    await joinViaInvitation(page, reviewer, { name: reviewerName, password: 'River mornings carry new beginnings 418', role: 'Manager', projectNames: [projectName] });
    await navigate(page, `/projects/${projectId}/work`);
    await page.getByRole('button', { name: 'Add task', exact: true }).click();
    let dialog = page.getByRole('dialog', { name: 'Add a task', exact: true });
    await dialog.getByLabel('Task name', { exact: true }).fill(taskName);
    await dialog.getByLabel('What does done look like?', { exact: true }).fill('Both assignees are happy with the first draft.');
    await dialog.getByRole('checkbox', { name: 'Browser owner', exact: true }).check();
    await dialog.getByRole('checkbox', { name: collaboratorName, exact: true }).check();
    await dialog.getByLabel('Task lead', { exact: true }).selectOption({ label: collaboratorName });
    await dialog.getByRole('button', { name: 'Add task', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await projectOptions(page);
    await page.getByRole('button', { name: 'Task review: Off', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'Turn on task review', exact: true });
    await dialog.getByLabel(taskName, { exact: true }).selectOption({ label: reviewerName });
    await dialog.getByLabel('Reason for this change', { exact: true }).fill('A fresh pair of eyes before sharing.');
    await dialog.getByRole('button', { name: 'Enable review', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await navigate(page, '/my-work');
    await page.locator('.task-row').filter({ hasText: taskName }).click();
    const ownerTask = page.getByRole('dialog', { name: taskName, exact: true });
    const taskId = new URL(page.url()).searchParams.get('task');
    await expect(ownerTask.locator('.avatar-group')).toHaveAttribute('aria-label', /Browser owner/);
    await expect(ownerTask.locator('.avatar-group')).toHaveAttribute('aria-label', new RegExp(collaboratorName));
    await freshProjects(collaborator); await navigate(collaborator, '/my-work');
    await collaborator.locator('.task-row').filter({ hasText: taskName }).click();
    expect(new URL(collaborator.url()).searchParams.get('task')).toBe(taskId);
    const memberTask = collaborator.getByRole('dialog', { name: taskName, exact: true });
    await memberTask.getByRole('button', { name: 'Start task', exact: true }).click();
    await expect(memberTask.locator('.task-subtitle')).toContainText('In progress');
    await memberTask.getByRole('tab', { name: 'Discussion', exact: true }).click();
    await memberTask.getByLabel('Add to the conversation', { exact: true }).fill('The first draft is ready for us both.');
    await memberTask.getByRole('button', { name: 'Post comment', exact: true }).click();
    await expect(memberTask.locator('.discussion-feed')).toContainText('The first draft is ready for us both.');
    await ownerTask.getByRole('tab', { name: 'Discussion', exact: true }).click();
    await expect(ownerTask.locator('.discussion-feed')).toContainText('The first draft is ready for us both.');
    await ownerTask.getByLabel('Add to the conversation', { exact: true }).fill('Agreed. Let us get the final review.');
    await ownerTask.getByRole('button', { name: 'Post comment', exact: true }).click();
    await expect(ownerTask.locator('.discussion-feed')).toContainText('Agreed. Let us get the final review.');
    await fixture.deliverFrontendNotifications();
    await closeDialog(memberTask);
    await navigate(collaborator, '/inbox');
    const commentNotice = collaborator.locator('.inbox-row').filter({ hasText: 'A new comment was shared' });
    await expect(commentNotice).toHaveCount(1);
    await commentNotice.locator('.inbox-main').click();
    await expect(memberTask).toBeVisible();
    expect(new URL(collaborator.url()).searchParams.get('task')).toBe(taskId);
    await memberTask.getByRole('button', { name: 'Send for review', exact: true }).click();
    dialog = collaborator.getByRole('dialog', { name: 'Ready for review?', exact: true });
    await dialog.getByRole('checkbox', { name: 'The work meets its acceptance criteria.', exact: true }).check();
    await dialog.getByRole('button', { name: 'Send for review', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(memberTask.locator('.task-subtitle')).toContainText('In review');
    await expect(memberTask.getByRole('button', { name: 'Approve task', exact: true })).toHaveCount(0);
    // Assigned work awaiting someone else's review must never invite self-review.
    await closeDialog(memberTask);
    await navigate(collaborator, `/projects/${projectId}/overview`);
    await expect(collaborator.locator('.work-guidance')).toContainText('Waiting for review');
    await expect(collaborator.getByRole('button', { name: 'Review task', exact: true })).toHaveCount(0);
    await collaborator.locator('.work-guidance').getByRole('button', { name: 'Open task', exact: true }).click();
    await expect(memberTask).toBeVisible();
    await expect(memberTask.getByRole('button', { name: 'Approve task', exact: true })).toHaveCount(0);
    await fixture.deliverFrontendNotifications();
    await freshProjects(reviewer); await navigate(reviewer, `/projects/${projectId}/overview`);
    await expect(reviewer.locator('.work-guidance')).toContainText('Ready for your review');
    await expect(reviewer.locator('.work-guidance').getByRole('button', { name: 'Review task', exact: true })).toBeVisible();
    await navigate(reviewer, '/my-work?view=review');
    await expect(reviewer.locator('.task-row').filter({ hasText: taskName })).toHaveCount(1);
    await reviewer.getByRole('button', { name: 'Assigned to me', exact: true }).click();
    await expect(reviewer).toHaveURL(/\/my-work\?view=assigned$/);
    await expect(reviewer.locator('.task-row').filter({ hasText: taskName })).toHaveCount(0);
    await reviewer.goBack();
    await expect(reviewer).toHaveURL(/\/my-work\?view=review$/);
    await expect(reviewer.getByRole('button', { name: 'For my review', exact: true })).toHaveAttribute('aria-current', 'page');
    await expect(reviewer.locator('.task-row').filter({ hasText: taskName })).toHaveCount(1);
    await navigate(reviewer, '/inbox');
    const reviewNotice = reviewer.locator('.inbox-row').filter({ hasText: 'A task is ready for your review' });
    await expect(reviewNotice).toHaveCount(1);
    await reviewNotice.locator('.inbox-main').click();
    const reviewTask = reviewer.getByRole('dialog', { name: taskName, exact: true });
    await expect(reviewTask.getByRole('button', { name: 'Approve task', exact: true })).toBeEnabled();
    await reviewTask.getByRole('button', { name: 'Request changes', exact: true }).click();
    await finishOutcome(reviewer, 'Request changes', 'Please add one concrete example.');
    await expect(reviewTask.locator('.task-subtitle')).toContainText('In progress');
    await freshProjects(collaborator);
    await memberTask.getByRole('tab', { name: 'Activity', exact: true }).click();
    await expect(memberTask.locator('.activity-list')).toContainText('Please add one concrete example.');
    await memberTask.getByRole('tab', { name: 'Details', exact: true }).click();
    await memberTask.getByRole('button', { name: 'Edit task', exact: true }).click();
    dialog = collaborator.getByRole('dialog', { name: 'Edit task', exact: true });
    await dialog.getByLabel('Description', { exact: true }).fill('A concrete example: begin with one shared task and build from there.');
    await dialog.getByRole('button', { name: 'Save changes', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await memberTask.getByRole('button', { name: 'Send for review', exact: true }).click();
    dialog = collaborator.getByRole('dialog', { name: 'Ready for review?', exact: true });
    await dialog.getByRole('checkbox', { name: 'The work meets its acceptance criteria.', exact: true }).check();
    await dialog.getByRole('button', { name: 'Send for review', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await freshProjects(reviewer);
    await closeDialog(reviewTask);
    await navigate(reviewer, '/my-work?view=review');
    await reviewer.locator('.task-row').filter({ hasText: taskName }).click();
    await reviewTask.getByRole('button', { name: 'Approve task', exact: true }).click();
    await expect(reviewTask.locator('.task-subtitle')).toContainText('Done');
    await freshProjects(collaborator);
    await expect(memberTask.locator('.task-subtitle')).toContainText('Done');
    await fixture.deliverFrontendNotifications();
    await closeDialog(memberTask);
    await navigate(collaborator, '/inbox');
    await expect(collaborator.locator('.inbox-row').filter({ hasText: 'A task moved forward' }).first()).toBeVisible();
    // Finish a real write after the person changes the filter. Its follow-up
    // refresh must use the current view, never restore the earlier All results.
    let readCommitted = false;
    let releaseRead!: () => void;
    const readReply = new Promise<void>(resolve => { releaseRead = resolve; });
    await collaborator.route('**/v1/inbox/save', async route => {
      const response = await route.fetch(); expect(response.status()).toBe(200);
      readCommitted = true; await readReply; await route.fulfill({ response });
    }, { times: 1 });
    const markAll = collaborator.getByRole('button', { name: 'Mark visible as read', exact: true });
    await markAll.click();
    await expect.poll(() => readCommitted).toBe(true);
    await collaborator.getByRole('button', { name: 'Unread', exact: true }).click();
    releaseRead();
    await expect(markAll).toHaveAttribute('aria-busy', 'false');
    await expect(collaborator.getByRole('heading', { name: 'All caught up', exact: true })).toBeVisible();
    await collaborator.getByRole('button', { name: 'All updates', exact: true }).click();
    await collaborator.locator('.inbox-row').first().getByRole('button', { name: 'Mark unread', exact: true }).click();
    await expect(collaborator.locator('.inbox-row.is-unread')).toHaveCount(1);
    await navigate(collaborator, `/projects/${projectId}/overview`);
    await expect(collaborator.locator('.metric').filter({ hasText: 'PROGRESS' })).toContainText('100%');
    await projectOptions(collaborator);
    await collaborator.getByRole('button', { name: 'Mute notifications', exact: true }).click();
    await expect(collaborator.getByRole('button', { name: 'Resume notifications', exact: true })).toBeVisible();
    await collaborator.getByRole('button', { name: 'Resume notifications', exact: true }).click();
    await expect(collaborator.getByRole('button', { name: 'Mute notifications', exact: true })).toBeVisible();
    await closeDialog(collaborator.getByRole('dialog', { name: 'Project options', exact: true }));
    await collaborator.reload(); await signIn(collaborator, collaboratorName, 'Evening gardens welcome quiet ideas 729');
    await navigate(collaborator, `/projects/${projectId}/work?task=${taskId}`);
    await expect(memberTask.locator('.task-subtitle')).toContainText('Done');
    await memberTask.getByRole('tab', { name: 'Discussion', exact: true }).click();
    await expect(memberTask.locator('.discussion-entry')).toHaveCount(2);
    for (const browserErrors of errors) expect(browserErrors).toEqual([]);
  } finally { await page.close(); await collaboratorContext.close(); await reviewerContext.close(); await fixture.close(); }
});

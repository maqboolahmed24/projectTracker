import { expect, test, type Locator, type Page } from '@playwright/test';
import { authenticationFixture } from '../browser/authentication-fixture.js';
import { joinViaInvitation, navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

async function closeDialog(dialog: Locator) {
  await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

async function createActiveProject(page: Page, name: string) {
  await page.getByRole('button', { name: 'New project', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'A fresh start', exact: true });
  await dialog.getByLabel('Project name', { exact: true }).fill(name);
  await dialog.getByRole('button', { name: 'Create project', exact: true }).click();
  await expect.poll(async () => {
    const check = dialog.getByRole('button', { name: 'Check progress', exact: true });
    if (await check.isVisible() && await check.isEnabled()) await check.click();
    return page.getByRole('heading', { name, exact: true, level: 1 }).isVisible();
  }, { timeout: 25_000 }).toBe(true);
  const projectId = new URL(page.url()).pathname.split('/')[2]!;
  await page.locator('.page-header').getByRole('button', { name: 'Start project', exact: true }).click();
  await expect(page.locator('.page-header')).toContainText('Active');
  await navigate(page, `/projects/${projectId}/work`);
  return projectId;
}

async function addTask(page: Page, name: string) {
  await page.locator('.page-header').getByRole('button', { name: 'Add task', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Add a task', exact: true });
  await dialog.getByLabel('Task name', { exact: true }).fill(name);
  await dialog.getByLabel('What does done look like?', { exact: true }).fill('The work is ready for the team to use.');
  await dialog.getByRole('checkbox', { name: 'Browser owner', exact: true }).check();
  await dialog.getByRole('button', { name: 'Add task', exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

async function uploadTaskFile(page: Page, task: Locator, kind: 'source' | 'output', reference: string) {
  await task.getByRole('button', { name: kind === 'source' ? 'Add source' : 'Add output', exact: true }).click();
  const upload = page.getByRole('dialog', { name: 'Add files', exact: true });
  await upload.getByLabel('Choose files to upload', { exact: true }).setInputFiles({
    name: `${reference.toLowerCase()}.txt`, mimeType: 'text/plain', buffer: Buffer.from(`${kind === 'source' ? 'Original reference' : 'Finished work'} for the task.\n`),
  });
  await upload.getByLabel('Document reference', { exact: true }).fill(reference);
  await expect(upload.getByLabel('Purpose', { exact: true })).toHaveValue(kind);
  await upload.getByRole('button', { name: 'Save files', exact: true }).click();
  await expect(upload.locator('.is-saved')).toContainText('Saved');
  await upload.getByRole('button', { name: 'Done', exact: true }).click();
  await expect(upload).toHaveCount(0);
}

test('task completion retries a failed file check and still confirms ordinary work before marking it done', async ({ page }) => {
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  const taskName = 'Finish a simple task';
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    const projectId = await createActiveProject(page, 'Reliable completion');
    await addTask(page, taskName);
    // Fail only a read, without inventing file contents or changing real work.
    await page.route('**/v1/files/list', route => route.fulfill({
      status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'FILES_UNAVAILABLE' } }),
    }), { times: 1 });
    await page.locator('.task-row').filter({ hasText: taskName }).click();
    const taskId = new URL(page.url()).searchParams.get('task')!;
    const task = page.getByRole('dialog', { name: taskName, exact: true });
    await expect(task.getByRole('alert')).toBeVisible();
    await expect(task.getByRole('button', { name: 'Mark complete', exact: true })).not.toBeEnabled();
    await task.getByRole('button', { name: 'Check task files', exact: true }).click();
    await expect(task.getByRole('alert')).toHaveCount(0);
    await expect(task.getByRole('button', { name: 'Mark complete', exact: true })).toBeEnabled();
    await task.getByRole('button', { name: 'Mark complete', exact: true }).click();
    let confirm = page.getByRole('dialog', { name: 'Ready to mark complete?', exact: true });
    await expect(confirm.getByRole('button', { name: 'Mark complete', exact: true })).toBeDisabled();
    await confirm.getByRole('button', { name: 'Keep working', exact: true }).click();
    await expect(confirm).toHaveCount(0);
    await expect(task.locator('.task-subtitle')).toContainText('To do');
    await task.getByRole('button', { name: 'Mark complete', exact: true }).click();
    confirm = page.getByRole('dialog', { name: 'Ready to mark complete?', exact: true });
    await confirm.getByRole('checkbox', { name: 'The work meets its acceptance criteria.', exact: true }).check();
    await confirm.getByRole('button', { name: 'Mark complete', exact: true }).click();
    await expect(confirm).toHaveCount(0);
    await expect(task.locator('.task-subtitle')).toContainText('Done');
    // Reopen the saved task from a fresh authenticated page, not optimistic state.
    await page.reload(); await signIn(page);
    await navigate(page, `/projects/${projectId}/work?task=${taskId}`);
    await expect(task.locator('.task-subtitle')).toContainText('Done');
    expect(errors).toEqual([]);
  } finally { await fixture.close(); }
});

test('linked task files lead through visible prerequisites to independent exact-version review and completion', async ({ page, browser }, testInfo) => {
  test.setTimeout(240_000);
  const fixture = await authenticationFixture(), reviewerContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const reviewer = await reviewerContext.newPage(), errors = [trackBrowserErrors(page), trackBrowserErrors(reviewer)];
  const projectName = 'A complete document handoff', taskName = 'Finish the welcome document', otherTaskName = 'Check the launch plan', reviewerName = 'Casey Reviewer';
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    const projectId = await createActiveProject(page, projectName);
    await addTask(page, otherTaskName); await addTask(page, taskName);
    await page.locator('.task-row').filter({ hasText: taskName }).click();
    const taskId = new URL(page.url()).searchParams.get('task')!;
    const task = page.getByRole('dialog', { name: taskName, exact: true });
    await expect(task.getByRole('button', { name: 'Mark complete', exact: true })).toBeEnabled();
    await task.getByRole('tab', { name: 'Files and evidence', exact: true }).click();
    await uploadTaskFile(page, task, 'source', 'WELCOME-SOURCE');
    // Uploads do not change task revision: the open Details view must still
    // refresh its completion route when returning from Files and evidence.
    await task.getByRole('tab', { name: 'Details', exact: true }).click();
    await expect(task.getByRole('button', { name: 'Mark complete', exact: true })).toHaveCount(0);
    await task.getByRole('button', { name: 'Prepare file review', exact: true }).click();
    await expect(task.getByRole('tab', { name: 'Files and evidence', exact: true })).toBeFocused();
    const evidence = task.locator('.file-review-card');
    await expect(evidence.getByRole('heading', { name: 'Prepare this task for review', exact: true })).toBeVisible();
    await expect(evidence).toContainText('Add at least one finished output before sending this task for review.');
    await expect(evidence.getByRole('button', { name: 'Set up task review', exact: true })).toBeVisible();
    await expect(evidence.getByRole('button', { name: 'Submit exact versions for review', exact: true })).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath('completion-source-only-prerequisites.png'), animations: 'disabled' });
    await closeDialog(task);

    // Manager is an actual existing role with approval permission; this person
    // is neither assigned to the task nor the uploader of its output.
    await joinViaInvitation(page, reviewer, { name: reviewerName, password: 'A welcome document is ready 987', role: 'Manager', projectNames: [projectName] });
    await navigate(page, `/projects/${projectId}/work?task=${taskId}`);
    await task.getByRole('button', { name: 'Prepare file review', exact: true }).click();
    await evidence.getByRole('button', { name: 'Set up task review', exact: true }).click();
    const policy = page.getByRole('dialog', { name: 'Turn on task review', exact: true });
    await expect(policy.getByRole('button', { name: 'Enable review', exact: true })).toBeDisabled();
    await policy.getByLabel(taskName, { exact: true }).selectOption({ label: reviewerName });
    await expect(policy.getByRole('button', { name: 'Enable review', exact: true })).toBeDisabled();
    await policy.getByLabel(otherTaskName, { exact: true }).selectOption({ label: reviewerName });
    await policy.getByLabel('Reason for this change', { exact: true }).fill('The finished document needs an independent check.');
    await policy.getByRole('button', { name: 'Enable review', exact: true }).click();
    await expect(policy).toHaveCount(0);
    await expect(evidence.getByRole('button', { name: 'Set up task review', exact: true })).toHaveCount(0);
    await expect(evidence).toContainText('Add at least one finished output before sending this task for review.');
    await uploadTaskFile(page, task, 'output', 'WELCOME-OUTPUT');
    // Files must enforce the same blocker gate as Details, rather than offering
    // a submission that can only fail after the person has checked the files.
    await task.getByRole('tab', { name: 'Details', exact: true }).click();
    await task.getByRole('button', { name: 'Add blocker', exact: true }).click();
    const blocker = page.getByRole('dialog', { name: 'What is in the way?', exact: true });
    await blocker.getByLabel('What is blocking progress?', { exact: true }).fill('Confirm the final wording.');
    await blocker.getByLabel('Next action', { exact: true }).fill('Check the welcome message together.');
    await blocker.getByRole('button', { name: 'Save blocker', exact: true }).click();
    await expect(blocker).toHaveCount(0);
    await task.getByRole('tab', { name: 'Files and evidence', exact: true }).click();
    await expect(evidence).toContainText('Resolve this task’s open blockers before submitting or accepting its work.');
    const submit = evidence.getByRole('button', { name: 'Submit exact versions for review', exact: true });
    await expect(submit).toBeDisabled();
    await expect(evidence.getByRole('checkbox', { name: 'I have checked these versions and the task’s acceptance criteria.', exact: true })).toBeDisabled();
    await evidence.getByRole('button', { name: 'Back to task details', exact: true }).click();
    await task.getByRole('button', { name: 'Resolve', exact: true }).click();
    const resolution = page.getByRole('dialog', { name: 'Resolve blocker', exact: true });
    await resolution.getByLabel('Outcome or reason', { exact: true }).fill('The final message has been agreed.');
    await resolution.getByRole('button', { name: 'Resolve blocker', exact: true }).click();
    await expect(resolution).toHaveCount(0);
    await task.getByRole('button', { name: 'Prepare file review', exact: true }).click();
    await expect(submit).toBeDisabled();
    await evidence.getByRole('checkbox', { name: 'I have checked these versions and the task’s acceptance criteria.', exact: true }).check();
    await submit.click();
    await expect(task.locator('.task-subtitle')).toContainText('In review');
    await expect(evidence.getByRole('button', { name: 'Accept these versions', exact: true })).toHaveCount(0);
    await expect(evidence).toContainText(`${reviewerName} is reviewing this task.`);

    await reviewer.evaluate(() => dispatchEvent(new Event('focus')));
    await navigate(reviewer, `/projects/${projectId}/work?task=${taskId}`);
    const reviewTask = reviewer.getByRole('dialog', { name: taskName, exact: true });
    await expect(reviewTask.locator('.task-subtitle')).toContainText('In review');
    await reviewTask.getByRole('button', { name: 'Review exact file versions', exact: true }).click();
    const reviewEvidence = reviewTask.locator('.file-review-card');
    await expect(reviewEvidence.locator('.file-evidence-row')).toHaveCount(2);
    const accept = reviewEvidence.getByRole('button', { name: 'Accept these versions', exact: true });
    await expect(accept).toBeDisabled();
    await reviewEvidence.getByRole('checkbox', { name: 'I have reviewed these exact versions and the completed work.', exact: true }).check();
    await accept.click();
    await expect(reviewTask.locator('.task-subtitle')).toContainText('Done');
    await expect(reviewEvidence).toContainText('Accepted exact versions');
    await page.evaluate(() => dispatchEvent(new Event('focus')));
    await expect(task.locator('.task-subtitle')).toContainText('Done');
    await expect(evidence).toContainText('Accepted exact versions');
    expect(errors.flat()).toEqual([]);
  } finally { await reviewerContext.close(); await fixture.close(); }
});

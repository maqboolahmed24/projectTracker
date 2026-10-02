import { expect, test, type Page } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { createHandoffLink, parseHandoff } from '../../frontend/identity/handoff.js';
import { authenticationFixture, origin, password } from '../browser/authentication-fixture.js';
import { downloadLinkFile, navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

const approvalDialog = (page: Page) => page.getByRole('dialog', { name: 'Approve access', exact: true });
const interruptedPanel = (page: Page) => page.locator('.settings-panel').filter({ has: page.getByRole('heading', { name: 'Check interrupted saves', exact: true }) });
const settingsApprovalEntry = (page: Page) => page.locator('.settings-content').getByRole('button', { name: 'Review access requests', exact: true });
const waitingNotice = (page: Page) => approvalDialog(page).getByText('The other person can now set up their access. This screen will update when their security check is ready.', { exact: true });

async function expectSingleApproval(page: Page) {
  await expect(approvalDialog(page)).toBeVisible();
  await expect(page.locator('dialog[open]')).toHaveCount(1);
  await expect(page.locator('.identity-approvals')).toHaveCount(1);
  await expect(approvalDialog(page).locator('.identity-approvals')).toHaveCount(1);
  expect(await approvalDialog(page).evaluate(element => element.matches(':modal'))).toBe(true);
}

async function expectSettingsOrder(page: Page, title: string) {
  const header = page.locator('.settings-content .page-header').filter({ has: page.getByRole('heading', { name: title, exact: true }) });
  await expect(header).toBeVisible();
  const interrupted = interruptedPanel(page);
  await expect(interrupted).toBeVisible();
  const first = await header.boundingBox(), second = await interrupted.boundingBox();
  if (!first || !second) throw new Error('Settings headings could not be measured');
  expect(first.y + first.height).toBeLessThanOrEqual(second.y + 1);
}

test('access approval stays in one bounded dialog across handoffs, Settings entry points and repeated requests', async ({ page, browser }, testInfo) => {
  test.setTimeout(240_000);
  // The guarded .local/run-isolated-frontend.mjs launcher supplies separate
  // application/control stores. This fixture never represents a user's workspace.
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  const recipientContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const recipient = await recipientContext.newPage(), recipientErrors = trackBrowserErrors(recipient);
  const securityWrites: string[] = [];
  page.on('request', request => {
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'POST' && /^\/v1\/auth\/(enrolment|pairing|recovery)\/(claim|confirm|approve|stage|finalize|cancel|join\/revoke)$/.test(pathname)) securityWrites.push(pathname);
  });
  let releaseClaim: (() => void) | undefined;
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
    await seedRememberedOwner(page, fixture); await signIn(page);
    await navigate(page, '/settings/people');
    await expectSettingsOrder(page, 'People');
    await expect(page.locator('.identity-approvals')).toHaveCount(0);
    await page.getByRole('button', { name: 'Invite person', exact: true }).click();
    const invitationDialog = page.getByRole('dialog');
    await invitationDialog.getByLabel('Name', { exact: true }).fill('Approval layout colleague');
    await invitationDialog.getByRole('combobox', { name: /^Role/ }).selectOption({ label: 'Member' });
    await invitationDialog.getByLabel(/^Confirm your password/).fill(password);
    await invitationDialog.getByRole('button', { name: 'Create invitation', exact: true }).click();
    const privateLink = page.getByRole('dialog').getByLabel(/^Private link/);
    await privateLink.waitFor({ state: 'visible' });
    const invitation = await privateLink.inputValue();
    await page.getByRole('dialog').getByRole('button', { name: 'Done', exact: true }).click();

    await recipient.goto(invitation);
    await recipient.getByRole('heading', { name: 'An Owner will help you in', exact: true }).waitFor({ state: 'visible' });
    await recipient.locator('details').filter({ has: recipient.locator('summary').filter({ hasText: 'Can’t find the request?' }) }).locator('summary').click();
    const request = parseHandoff((await downloadLinkFile(recipient)).toString('utf8'), origin);
    if (request.kind !== 'approve') throw new Error('The recipient did not provide an approval request');
    const handoff = createHandoffLink({ kind: 'approve', workspaceId: request.workspaceId, operationId: request.operationId, ceremony: request.ceremony }, origin);
    // Same-document handoff preserves the real unlocked Worker and follows the
    // same URL event as opening a received link within the running application.
    await navigate(page, '/');
    await page.evaluate(hash => { location.hash = hash; }, new URL(handoff).hash);
    await expectSingleApproval(page);
    await expect(page).toHaveURL(/\/settings\/security$/);
    expect(new URL(page.url()).hash).toBe('');
    await approvalDialog(page).getByLabel('Confirm your password', { exact: true }).fill(password);

    let claimResponseReached = false;
    const claimGate = new Promise<void>(resolve => { releaseClaim = resolve; });
    await page.route('**/v1/auth/enrolment/claim', async route => {
      const response = await route.fetch();
      if (response.status() !== 200) throw new Error('The real claim endpoint did not accept the request');
      claimResponseReached = true;
      await claimGate;
      await route.fulfill({ response });
    }, { times: 1 });
    await approvalDialog(page).getByRole('button', { name: 'Start security check', exact: true }).click();
    await expect.poll(() => claimResponseReached).toBe(true);
    await expect(approvalDialog(page).getByRole('button', { name: 'Back to requests', exact: true })).toBeDisabled();
    releaseClaim?.();
    await expect(waitingNotice(page)).toBeVisible();
    await expect(approvalDialog(page).getByRole('button', { name: 'Back to requests', exact: true })).toBeEnabled();
    // Password confirmation must not leave a racing, redundant profile read
    // displaying an error behind the approval dialog.
    await expect(page.locator('.settings-profile')).toContainText('Browser owner');
    await expect(page.locator('.settings-content [role="alert"]')).toHaveCount(0);
    expect(securityWrites).toEqual(['/v1/auth/enrolment/claim']);

    const measurements: unknown[] = [];
    await mkdir('test-results/frontend-review/approval-layout', { recursive: true });
    for (const width of [1440, 390, 320]) {
      await page.setViewportSize({ width, height: width === 1440 ? 1000 : 844 });
      for (const theme of ['light', 'dark'] as const) {
        await page.emulateMedia({ colorScheme: theme });
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        await expectSingleApproval(page);
        await expect(waitingNotice(page)).toBeVisible();
        // Saved images contain only a disposable owner's waiting screen. Never
        // capture passwords, private links, recovery words or comparison codes.
        await expect(approvalDialog(page).locator('input, textarea, .identity-fingerprint')).toHaveCount(0);
        const geometry = await approvalDialog(page).evaluate(element => {
          const box = element.getBoundingClientRect();
          return { x: box.x, y: box.y, width: box.width, height: box.height, right: box.right, bottom: box.bottom,
            viewportWidth: innerWidth, viewportHeight: innerHeight, documentWidth: document.documentElement.scrollWidth,
            dialogWidth: element.clientWidth, dialogScrollWidth: element.scrollWidth };
        });
        expect(geometry.width).toBeLessThanOrEqual(620.5);
        expect(geometry.width).toBeGreaterThan(250);
        expect(geometry.x).toBeGreaterThanOrEqual(0);
        expect(geometry.y).toBeGreaterThanOrEqual(0);
        expect(geometry.right).toBeLessThanOrEqual(geometry.viewportWidth + 1);
        expect(geometry.bottom).toBeLessThanOrEqual(geometry.viewportHeight + 1);
        expect(geometry.documentWidth).toBeLessThanOrEqual(geometry.viewportWidth + 1);
        expect(geometry.dialogScrollWidth).toBeLessThanOrEqual(geometry.dialogWidth + 1);
        measurements.push({ requestedWidth: width, theme, ...geometry });
        await page.screenshot({ path: `test-results/frontend-review/approval-layout/waiting-${width}-${theme}-${testInfo.project.name}.png`, animations: 'disabled' });
      }
    }
    await writeFile(`test-results/frontend-review/approval-layout/geometry-${testInfo.project.name}.json`, JSON.stringify(measurements, null, 2) + '\n');

    await page.keyboard.press('Escape');
    await expect(page.locator('dialog[open], .identity-approvals')).toHaveCount(0);
    expect(securityWrites).toEqual(['/v1/auth/enrolment/claim']);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await expectSettingsOrder(page, 'Your account');
    await settingsApprovalEntry(page).click();
    await expectSingleApproval(page);
    await expect(approvalDialog(page).getByRole('heading', { name: 'Access requests', exact: true })).toBeVisible();
    await approvalDialog(page).getByRole('button', { name: /^Workspace invitation(?: · Approval layout colleague)?$/ }).click();
    await expect(approvalDialog(page).getByLabel('Confirm your password', { exact: true })).toHaveValue('');
    await approvalDialog(page).getByRole('button', { name: 'Close dialog', exact: true }).click();
    await expect(page.locator('dialog[open], .identity-approvals')).toHaveCount(0);
    expect(securityWrites).toEqual(['/v1/auth/enrolment/claim']);

    await navigate(page, '/settings/people');
    await expectSettingsOrder(page, 'People');
    await settingsApprovalEntry(page).click();
    await expectSingleApproval(page);
    await expect(approvalDialog(page).getByRole('heading', { name: 'Access requests', exact: true })).toBeVisible();
    await approvalDialog(page).getByRole('button', { name: 'Close dialog', exact: true }).click();
    const invitations = page.locator('.settings-panel').filter({ has: page.getByRole('heading', { name: 'Pending invitations', exact: true }) });
    for (const dismissal of ['Escape', 'close'] as const) {
      await invitations.getByRole('button', { name: 'Review approval', exact: true }).click();
      await expectSingleApproval(page);
      await expect(approvalDialog(page).getByRole('heading', { name: 'Workspace invitation', exact: true })).toBeVisible();
      await expect(approvalDialog(page).getByLabel('Confirm your password', { exact: true })).toHaveValue('');
      await expect(approvalDialog(page).getByRole('button', { name: 'Start security check', exact: true })).toBeDisabled();
      if (dismissal === 'Escape') {
        await approvalDialog(page).getByLabel('Confirm your password', { exact: true }).fill(password);
        await approvalDialog(page).getByRole('button', { name: 'Back to requests', exact: true }).click();
        await expect(approvalDialog(page).getByLabel('Private approval link', { exact: true })).toHaveValue('');
        await expect(approvalDialog(page).locator('input[type="password"]')).toHaveCount(0);
        await page.keyboard.press('Escape');
      }
      else await approvalDialog(page).getByRole('button', { name: 'Close dialog', exact: true }).click();
      await expect(page.locator('dialog[open], .identity-approvals')).toHaveCount(0);
    }
    expect(securityWrites).toEqual(['/v1/auth/enrolment/claim']);
    expect(errors).toEqual([]); expect(recipientErrors).toEqual([]);
  } finally {
    releaseClaim?.();
    await recipientContext.close(); await page.close(); await fixture.close();
  }
});

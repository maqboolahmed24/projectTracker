import { expect, test, type Page } from '@playwright/test';
import { authenticationFixture, password } from '../browser/authentication-fixture.js';
import { navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

const panel = (page: Page, title: string) => page.locator('.settings-panel').filter({ has: page.getByRole('heading', { name: title, exact: true }) });
async function confirmDialog(page: Page, label: string) {
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel(/^Confirm your password/).fill(password);
  await dialog.getByRole('button', { name: label, exact: true }).click();
}

// These tests drive the product controls. Fixture setup installs an existing
// approved device; it does not replace any form, API, Worker or database write.
test('settings: interrupted role save, reviewed edits, teams, timezone and recoverable legacy settings links', async ({ page }) => {
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page), bodies: string[] = [];
  const initialRole = 'Private delivery coordinators', finalRole = 'Private delivery reviewers', initialTeam = 'Private launch team', finalTeam = 'Private release team';
  page.on('request', request => { if (request.method() === 'POST') bodies.push(request.postData() ?? ''); });
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    await navigate(page, '/settings/roles'); await expect(page.getByRole('heading', { name: 'Roles & permissions', exact: true })).toBeVisible();
    let commitReached = false;
    await page.route('**/v1/auth/roles/finalize', async route => {
      const response = await route.fetch(); expect(response.status()).toBe(200); commitReached = true; await route.abort('failed');
    }, { times: 1 });
    await page.getByRole('button', { name: 'Create role', exact: true }).click();
    await page.getByRole('dialog').getByLabel('Role name', { exact: true }).fill(initialRole);
    await page.getByRole('dialog').getByRole('checkbox', { name: /^Comment and post updates/ }).check();
    await confirmDialog(page, 'Create role');
    await expect(page.getByRole('dialog').getByRole('alert')).toBeVisible(); expect(commitReached).toBe(true);
    await expect(page.getByRole('dialog').getByLabel('Role name', { exact: true })).toBeDisabled();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    const interrupted = panel(page, 'Check interrupted saves');
    await interrupted.getByRole('button', { name: 'Check saved attempts', exact: true }).click();
    await expect(interrupted).toContainText('These attempts may already have completed');
    await interrupted.getByRole('button', { name: 'Check and finish', exact: true }).click();
    await confirmDialog(page, 'Check and finish');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByText('The saved change is complete.', { exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: initialRole, exact: true })).toHaveCount(1);
    const roleCard = () => page.locator('.settings-role-card').filter({ has: page.getByRole('heading', { name: initialRole, exact: true }) });
    await roleCard().getByRole('button', { name: 'Edit role', exact: true }).click();
    await page.getByRole('dialog').getByLabel('Role name', { exact: true }).fill(finalRole);
    await page.getByRole('dialog').getByRole('checkbox', { name: /^Comment and post updates/ }).uncheck();
    await expect(page.getByRole('dialog')).toContainText('Existing access keeps its current permissions');
    await confirmDialog(page, 'Save role'); await expect(page.getByRole('dialog')).toHaveCount(0);
    const updated = page.locator('.settings-role-card').filter({ has: page.getByRole('heading', { name: finalRole, exact: true }) });
    await updated.getByRole('button', { name: 'Retire', exact: true }).click(); await confirmDialog(page, 'Retire role');
    await expect(page.getByRole('dialog')).toHaveCount(0); await expect(updated).toContainText('Retired');
    const builtin = page.locator('.settings-role-card').filter({ has: page.getByRole('heading', { name: 'Owner', exact: true }) });
    await expect(builtin.getByRole('button', { name: 'Edit role', exact: true })).toHaveCount(0);

    await navigate(page, '/settings/teams'); await page.getByRole('button', { name: 'Create team', exact: true }).click();
    await page.getByRole('dialog').getByLabel('Team name', { exact: true }).fill(initialTeam);
    await page.getByRole('dialog').getByLabel(/^Description/).fill('Private team description');
    await page.getByRole('dialog').getByRole('checkbox', { name: /Browser owner/ }).check();
    await confirmDialog(page, 'Create team'); await expect(page.getByRole('dialog')).toHaveCount(0);
    let team = page.locator('.settings-team-card').filter({ has: page.getByRole('heading', { name: initialTeam, exact: true }) });
    await expect(team).toContainText('Browser owner'); await team.getByRole('button', { name: 'Edit team', exact: true }).click();
    await expect(page.getByRole('dialog').getByLabel(/^Description/)).toHaveValue('Private team description');
    await expect(page.getByRole('dialog').getByRole('checkbox', { name: /Browser owner/ })).toBeChecked();
    await page.getByRole('dialog').getByLabel('Team name', { exact: true }).fill(finalTeam);
    await confirmDialog(page, 'Save team'); await expect(page.getByRole('dialog')).toHaveCount(0);
    team = page.locator('.settings-team-card').filter({ has: page.getByRole('heading', { name: finalTeam, exact: true }) });
    await team.getByRole('button', { name: 'History', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(initialTeam); await expect(page.getByRole('dialog')).toContainText(finalTeam);
    await page.getByRole('dialog').getByRole('button', { name: 'Done', exact: true }).click();

    await navigate(page, '/settings/workspace');
    await expect(panel(page, 'Reporting timezone')).toContainText('Current timezone: Europe/London');
    await panel(page, 'Reporting timezone').getByRole('button', { name: 'Change timezone', exact: true }).click();
    await page.getByRole('dialog', { name: 'Change reporting timezone?', exact: true }).getByLabel('Timezone', { exact: true }).selectOption('America/New_York');
    await expect(page.getByRole('dialog')).toContainText('Change from Europe/London to America/New_York'); await confirmDialog(page, 'Save timezone');
    await expect(page.getByRole('dialog')).toHaveCount(0); await expect(panel(page, 'Reporting timezone')).toContainText('Current timezone: America/New_York');
    await page.getByLabel('Colour theme', { exact: true }).selectOption('dark');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await navigate(page, '/settings/integrations');
    await expect(page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: 'Integrations', exact: true })).toHaveCount(0);
    await expect(page.locator('.settings-role-card.settings-future')).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'Integrations are not available', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Back to workspace settings', exact: true }).click();
    await expect(page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: 'Workspace', exact: true })).toHaveAttribute('aria-current', 'page');
    await expect(panel(page, 'Reporting timezone')).toContainText('Current timezone: America/New_York');
    await navigate(page, '/settings/unknown-section');
    await expect(page.getByRole('heading', { name: 'Settings unavailable', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Back to workspace settings', exact: true }).click();
    await expect(page).toHaveURL(/\/settings\/workspace$/);
    for (const plaintext of [initialRole,finalRole,initialTeam,finalTeam,'Private team description',password]) expect(bodies.some(body => body.includes(plaintext))).toBe(false);
    expect(errors).toEqual([]);
  } finally { await page.close(); await fixture.close(); }
});

test('settings: private invitation revoke, plaintext export acknowledgement, interrupted deletion and cancellation', async ({ page }) => {
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page); let deletionSaves = 0;
  page.on('request', request => { if (request.method() === 'POST' && request.url().endsWith('/v1/lifecycle/save')) deletionSaves++; });
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    await navigate(page, '/settings/people'); await page.getByRole('button', { name: 'Invite person', exact: true }).click();
    await page.getByRole('dialog').getByLabel('Name', { exact: true }).fill('Private invited colleague');
    await page.getByRole('dialog').getByLabel('Role', { exact: true }).selectOption({ label: 'Member' });
    await confirmDialog(page, 'Create invitation');
    const privateLink = page.getByRole('dialog').getByLabel(/^Private link/); await expect(privateLink).toBeVisible();
    const invitation = new URL(await privateLink.inputValue()); expect(invitation.origin).toBe('https://127.0.0.1:3555'); expect(invitation.search).toBe(''); expect(invitation.hash.startsWith('#access=')).toBe(true);
    await page.getByRole('dialog').getByRole('button', { name: 'Done', exact: true }).click();
    const invitations = panel(page, 'Pending invitations'); await expect(invitations.getByRole('button', { name: 'Revoke', exact: true })).toHaveCount(1);
    await invitations.getByRole('button', { name: 'Revoke', exact: true }).click(); await confirmDialog(page, 'Revoke invitation');
    await expect(page.getByRole('dialog')).toHaveCount(0); await expect(invitations).toContainText('No invitations are waiting.');
    await expect(page.locator('body')).not.toContainText(fixture.workspaceId); await expect(page.locator('body')).not.toContainText(fixture.accountId);

    await navigate(page, '/settings/data'); await page.getByRole('button', { name: 'Export workspace', exact: true }).click();
    await page.getByRole('dialog').getByLabel(/^Confirm your password/).fill(password);
    await expect(page.getByRole('dialog').getByRole('button', { name: 'Download export', exact: true })).toBeDisabled();
    await page.getByRole('dialog').getByRole('checkbox', { name: /I understand this file is not encrypted/ }).check();
    const downloadEvent = page.waitForEvent('download'); await page.getByRole('dialog').getByRole('button', { name: 'Download export', exact: true }).click();
    const download = await downloadEvent, stream = await download.createReadStream(); if (!stream) throw new Error('Workspace export did not complete');
    const chunks: Buffer[] = []; for await (const chunk of stream) chunks.push(Buffer.from(chunk));
    const exported = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { complete: boolean };
    expect(exported.complete).toBe(true); expect(download.suggestedFilename()).toMatch(/\.json$/); await expect(page.getByRole('dialog')).toHaveCount(0);

    await page.getByRole('button', { name: 'Delete workspace', exact: true }).click();
    await page.getByRole('dialog').getByLabel(/^Type Browser workspace to confirm/).fill('Wrong name');
    await page.getByRole('dialog').getByLabel(/^Confirm your password/).fill(password);
    await expect(page.getByRole('dialog').getByRole('button', { name: 'Schedule deletion', exact: true })).toBeDisabled(); expect(deletionSaves).toBe(0);
    let committed = false;
    await page.route('**/v1/lifecycle/save', async route => { const response = await route.fetch(); expect(response.status()).toBe(200); committed = true; await route.abort('failed'); }, { times: 1 });
    await page.getByRole('dialog').getByLabel(/^Type Browser workspace to confirm/).fill('Browser workspace');
    await page.getByRole('dialog').getByRole('button', { name: 'Schedule deletion', exact: true }).click();
    await expect(page.getByRole('dialog').getByRole('alert')).toBeVisible(); expect(committed).toBe(true); expect(deletionSaves).toBe(1);
    await page.reload(); await signIn(page); await navigate(page, '/settings/data');
    const attempts = panel(page, 'Check interrupted saves'); await attempts.getByRole('button', { name: 'Check saved attempts', exact: true }).click();
    await attempts.getByRole('button', { name: 'Check and finish', exact: true }).click(); await confirmDialog(page, 'Check and finish');
    await expect(page.getByRole('dialog')).toHaveCount(0); expect(deletionSaves).toBe(1);
    await expect(page.getByRole('heading', { name: 'Workspace deletion scheduled', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Cancel deletion', exact: true }).click(); await confirmDialog(page, 'Keep workspace');
    await expect(page.getByRole('dialog')).toHaveCount(0); await expect(page.getByRole('heading', { name: 'Delete workspace', exact: true })).toBeVisible();
    expect(deletionSaves).toBe(2); expect(errors).toEqual([]);
  } finally { await page.close(); await fixture.close(); }
});

test('settings: completed update survives a failed refresh and finishes through bounded customer controls', async ({ page }) => {
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  let starts = 0, committed = false, refreshFailed = false;
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    await navigate(page, '/settings/maintenance');
    const content = panel(page, 'Content update');
    await expect(content.getByText('Update available', { exact: true })).toBeVisible();
    await page.route('**/v1/upgrades/start', async route => {
      starts++; const response = await route.fetch(); expect(response.status()).toBe(200);
      committed = true; await route.fulfill({ response });
    });
    await page.route('**/v1/auth/access-change/delivery', async route => {
      // Only the presentation directory read is interrupted. Controller receipt
      // and history verification still run against the real service first.
      const body = route.request().postDataJSON() as { includeDirectory?: boolean };
      if (committed && body.includeDirectory && !refreshFailed) { refreshFailed = true; await route.abort('failed'); }
      else await route.continue();
    });
    await content.getByRole('button', { name: 'Start update', exact: true }).click();
    await confirmDialog(page, 'Start update');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByText('The action finished, but the latest view could not be loaded. Refresh to see the result.', { exact: true })).toBeVisible();
    expect(committed).toBe(true); expect(refreshFailed).toBe(true); expect(starts).toBe(1);
    await expect(content.getByText('In progress', { exact: true })).toBeVisible();
    let previous = 0;
    // This fresh fixture contains only its initial identity records. Every
    // explicit step must advance verified progress; the loop is tightly bounded.
    for (let step = 0; step < 8; step++) {
      if (await content.getByRole('button', { name: 'Finish update', exact: true }).count()) break;
      const progress = content.getByRole('progressbar', { name: 'Workspace update progress' });
      previous = Number(await progress.getAttribute('value'));
      await content.getByRole('button', { name: 'Continue update', exact: true }).click();
      await confirmDialog(page, 'Continue update');
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect.poll(async () => Number(await progress.getAttribute('value'))).toBeGreaterThan(previous);
    }
    await expect(content.getByRole('button', { name: 'Finish update', exact: true })).toBeVisible();
    await content.getByRole('button', { name: 'Finish update', exact: true }).click();
    await confirmDialog(page, 'Finish update');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(content.getByText('Up to date', { exact: true })).toBeVisible();
    expect(starts).toBe(1);
    await page.reload(); await signIn(page); await navigate(page, '/settings/maintenance');
    await expect(panel(page, 'Content update').getByText('Up to date', { exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  } finally { await page.close(); await fixture.close(); }
});

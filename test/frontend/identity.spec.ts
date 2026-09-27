import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { authenticationFixture, password as originalPassword } from '../browser/authentication-fixture.js';
import { confirmRecoveryWords, downloadLinkFile, downloadRecoveryKit, finishAccessRequest, joinViaInvitation, navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';

test('a new Owner activates a workspace, saves their avatar, and recovers using their private kit', async ({ page }, testInfo) => {
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  const name = 'Alex Morgan', workspace = 'A little more focus', password = 'Quiet orchards gather afternoon light 739', replacement = 'Fresh rivers cross the valley gently 642';
  try {
    const licence = await fixture.issueFrontendLicence();
    await page.goto('/');
    await expect(page.locator('[data-ukda-launch]')).toBeVisible();
    await expect(page.locator('[data-ukda-launch]')).toHaveCount(0, { timeout: 12_000 });
    await expect(page.locator('.identity-brand')).toContainText('UKDA');
    await expect(page.locator('.identity-brand img')).toHaveAttribute('src', '/brand/assets/ukds-symbol.svg');
    await page.getByRole('button', { name: 'Use dark appearance' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await page.getByRole('button', { name: 'Use light appearance' }).click();
    await page.getByRole('button', { name: 'Create a workspace', exact: true }).click();
    await page.getByLabel('Activation key', { exact: true }).fill(licence);
    await page.getByRole('button', { name: 'Create my workspace', exact: true }).click();
    await page.getByLabel('Your name', { exact: true }).fill(name);
    await page.getByLabel('Workspace name', { exact: true }).fill(workspace);
    await page.getByRole('button', { name: 'Character 7', exact: true }).click();
    await page.getByRole('button', { name: 'Coral', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Character 7', exact: true })).toHaveAttribute('aria-pressed', 'true');
    const selectedAvatar = page.locator('.identity-avatar-preview img');
    await expect(selectedAvatar).toHaveAttribute('src', /%23e97667/i);
    const avatar = await selectedAvatar.getAttribute('src');
    const rememberedCard = () => page.getByRole('button', { name: new RegExp(`${name} Remembered on this device`) });
    const signInWithChosenAvatar = async (credential: string, checkAppearanceAndReload = false) => {
      await expect(rememberedCard().locator('img')).toHaveAttribute('src', avatar!);
      if (checkAppearanceAndReload) {
        for (const theme of ['dark', 'light']) {
          await page.getByRole('button', { name: `Use ${theme} appearance`, exact: true }).click();
          await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
          await expect(rememberedCard().locator('img')).toHaveAttribute('src', avatar!);
        }
        await page.reload();
        await expect(rememberedCard().locator('img')).toHaveAttribute('src', avatar!);
      }
      await rememberedCard().click();
      await expect(page.locator('.identity-login-profile img')).toHaveAttribute('src', avatar!);
      if (checkAppearanceAndReload) {
        for (const theme of ['dark', 'light']) {
          await page.getByRole('button', { name: `Use ${theme} appearance`, exact: true }).click();
          await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
          await expect(page.locator('.identity-login-profile img')).toHaveAttribute('src', avatar!);
        }
        // Reload returns to the remembered card; selecting it must retain the same picture.
        await page.reload();
        await expect(rememberedCard().locator('img')).toHaveAttribute('src', avatar!);
        await rememberedCard().click();
        await expect(page.locator('.identity-login-profile img')).toHaveAttribute('src', avatar!);
      }
      await page.getByLabel('Password', { exact: true }).fill(credential);
      await page.getByRole('button', { name: 'Open my workspace', exact: true }).click();
      await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
      await expect(page.locator('.sidebar-profile img')).toHaveAttribute('src', avatar!);
    };
    await page.getByLabel(/^Create a password/).fill(password);
    await page.getByLabel(/^Confirm password/).fill(password);
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    const phrase = await confirmRecoveryWords(page);
    const kit = await downloadRecoveryKit(page);
    const saved = JSON.parse(kit.toString('utf8')) as { phrase: string };
    if (saved.phrase !== phrase) throw new Error('The downloaded kit does not match the words confirmed during setup');
    await page.getByRole('checkbox', { name: 'I have saved my recovery kit somewhere safe.' }).check();
    await page.getByRole('button', { name: 'Open my workspace', exact: true }).click();
    await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    await expect(page.locator('.workspace-switch')).toContainText(workspace);
    await mkdir('test-results/frontend-review', { recursive: true });
    await page.screenshot({ path: `test-results/frontend-review/home-light-${testInfo.project.name}.png`, fullPage: true, animations: 'disabled' });
    await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await page.screenshot({ path: `test-results/frontend-review/home-dark-${testInfo.project.name}.png`, fullPage: true, animations: 'disabled' });
    await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
    await navigate(page, '/settings/account');
    await expect(page.locator('.settings-profile img')).toHaveAttribute('src', avatar!);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await signInWithChosenAvatar(password, true);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(rememberedCard().locator('img')).toHaveAttribute('src', avatar!);
    await page.getByRole('button', { name: 'Need help getting back in?', exact: true }).click();
    await page.getByLabel('Your saved recovery kit', { exact: true }).setInputFiles({ name: 'workspace-recovery-kit.json', mimeType: 'application/json', buffer: kit });
    await page.getByRole('button', { name: 'Recover my account', exact: true }).click();
    await page.getByLabel(/^Create a password/).fill(replacement);
    await page.getByLabel(/^Confirm password/).fill(replacement);
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    const newPhrase = await confirmRecoveryWords(page);
    const newKit = await downloadRecoveryKit(page);
    if (newPhrase === phrase || JSON.parse(newKit.toString('utf8')).phrase !== newPhrase) throw new Error('Recovery did not create and save a fresh kit');
    await page.getByRole('checkbox', { name: 'I’ve saved my new kit safely.' }).check();
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await page.getByRole('checkbox', { name: 'I’m recovering my account on this device.' }).check();
    await page.getByRole('button', { name: 'Confirm and continue', exact: true }).click();
    await page.getByRole('button', { name: 'Continue to my workspace', exact: true }).click();
    await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    await navigate(page, '/settings/account');
    await expect(page.locator('.settings-profile img')).toHaveAttribute('src', avatar!);
    await expect(page.locator('.settings-profile')).toContainText(name);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await signInWithChosenAvatar(replacement);
    const browserStorage = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
    for (const secret of [password, replacement, phrase, newPhrase, licence]) if (browserStorage.includes(secret)) throw new Error('A credential was stored as plaintext in Web Storage');
    expect(errors).toEqual([]);
    await testInfo.attach('remembered-avatar-checks', { contentType: 'application/json', body: JSON.stringify({
      chosenAvatar: 'Character 7, Coral', rememberedCard: true, passwordScreen: true, lightAndDark: true,
      retainedAfterReload: true, retainedAfterLoginAndLogout: true, retainedAfterRecovery: true,
    }) });
  } finally { await fixture.close(); }
});

test('remembered sign-in, password change, logout and forgetting a device form a complete journey', async ({ page, context }) => {
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page), replacement = 'Calm mountains welcome another morning 812';
  try {
    await seedRememberedOwner(page, fixture);
    await signIn(page);
    const cookie = (await context.cookies()).find(entry => entry.name === '__Host-ukda_session');
    expect(cookie ? { secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite } : null).toEqual({ secure: true, httpOnly: true, sameSite: 'Lax' });
    await navigate(page, '/settings/account');
    await page.getByRole('button', { name: 'Change password', exact: true }).click();
    await expect(page.getByRole('dialog', { name: 'Change your password', exact: true })).toBeVisible();
    await page.getByLabel('Current password', { exact: true }).fill(originalPassword);
    await page.getByLabel(/^New password/).fill(replacement);
    await page.getByLabel(/^Confirm new password/).fill(replacement);
    const relogin = page.waitForResponse(response => response.url().endsWith('/v1/auth/login/finish') && response.request().method() === 'POST' && response.ok());
    await page.getByRole('button', { name: 'Update password', exact: true }).click();
    await relogin;
    await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    await expect(page.locator('.settings-profile')).toContainText('Browser owner');
    // Reaching the remounted account screen proves the auth-clear event did not
    // leave a successfully changed password stranded at the entry screen.
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await signIn(page, 'Browser owner', replacement);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('button', { name: /Browser owner Remembered on this device/ }).click();
    await page.getByRole('button', { name: 'Forget this device', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Forget this device', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Create a workspace', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: /Browser owner Remembered on this device/ })).toHaveCount(0);
    expect((await context.cookies()).some(entry => entry.name === '__Host-ukda_session')).toBe(false);
    expect(errors).toEqual([]);
  } finally { await fixture.close(); }
});

test('an invited member joins and later resets their password through explicit Owner approval', async ({ page, browser }) => {
  const fixture = await authenticationFixture(), memberContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const member = await memberContext.newPage(), errors = trackBrowserErrors(page), memberErrors = trackBrowserErrors(member);
  const name = 'Sam Taylor', password = 'Small steps make a wonderful journey 987';
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    await joinViaInvitation(page, member, { name, password });
    expect(new URL(member.url()).hash).toBe('');
    await navigate(member, '/settings/account');
    await expect(member.getByRole('heading', { name: 'Recovery kit', exact: true })).toHaveCount(0);
    await expect(member.locator('.settings-profile')).toContainText(name);
    await member.getByRole('button', { name: 'Sign out', exact: true }).click();
    await signIn(member, name, password);
    await member.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('button', { name: 'Refresh people', exact: true }).click();
    await page.getByRole('button', { name: `Manage ${name}`, exact: true }).click();
    let dialog = page.getByRole('dialog');
    await dialog.getByRole('combobox', { name: /^Action/ }).selectOption({ label: 'Help with sign-in' });
    await dialog.getByLabel(/^Confirm your password/).fill(originalPassword);
    await dialog.getByRole('button', { name: 'Create recovery link', exact: true }).click();
    dialog = page.getByRole('dialog');
    await expect(dialog.getByLabel(/^Private link/)).toBeVisible();
    const resetLink = await dialog.getByLabel(/^Private link/).inputValue();
    await dialog.getByRole('button', { name: 'Done', exact: true }).click();
    const replacement = 'Gentle breezes cross the island together 235';
    await finishAccessRequest(page, member, resetLink, { name, password: replacement, reset: true });
    await member.getByRole('button', { name: 'Sign out', exact: true }).click();
    await signIn(member, name, replacement);
    expect(errors).toEqual([]); expect(memberErrors).toEqual([]);
  } finally { await memberContext.close(); await fixture.close(); }
});

test('a second Owner completes their own recovery kit and gains equal workspace access', async ({ page, browser }) => {
  const fixture = await authenticationFixture(), ownerContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const secondOwner = await ownerContext.newPage(), errors = trackBrowserErrors(secondOwner);
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    const kit = await joinViaInvitation(page, secondOwner, { name: 'Jordan Lee', password: 'Quiet gardens welcome everyone together 475', role: 'Owner' });
    if (!kit) throw new Error('The second Owner did not save a personal recovery kit');
    await navigate(secondOwner, '/settings/account');
    await expect(secondOwner.getByRole('heading', { name: 'Recovery kit', exact: true })).toBeVisible();
    await expect(secondOwner.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: 'Roles & permissions', exact: true })).toBeVisible();
    await navigate(secondOwner, '/settings/people');
    await expect(secondOwner.getByRole('button', { name: 'Invite person', exact: true })).toBeEnabled();
    await expect(secondOwner.locator('tbody tr').filter({ hasText: 'Browser owner' })).toContainText('Owner');
    await expect(secondOwner.locator('tbody tr').filter({ hasText: 'Jordan Lee' })).toContainText('Owner');
    expect(errors).toEqual([]);
  } finally { await ownerContext.close(); await fixture.close(); }
});

for (const approvalOrder of ['recipient first', 'approver first'] as const) test(`one shared invitation completes without a return link or manual refresh (${approvalOrder})`, async ({ page, browser }, testInfo) => {
  const fixture = await authenticationFixture(), memberContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const member = await memberContext.newPage(), errors = trackBrowserErrors(page), memberErrors = trackBrowserErrors(member);
  const name = 'Sam Taylor', password = 'Small steps make a wonderful journey 987';
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    const role = approvalOrder === 'approver first' ? 'Owner' : 'Member';
    const kit = await joinViaInvitation(page, member, { name, password, role, approvalOrder, checkMismatch: true });
    if (role === 'Owner' && !kit) throw new Error('The invited Owner must save a recovery kit before approval');
    await member.getByRole('button', { name: 'Sign out', exact: true }).click();
    await signIn(member, name, password);
    expect(errors).toEqual([]); expect(memberErrors).toEqual([]);
    await testInfo.attach('one-link-invitation-checks', { contentType: 'application/json', body: JSON.stringify({
      approvalOrder, role, ownerRecoveryKitSaved: role === 'Owner', sharedLinks: 1, returnLinkUsed: false, manualRefreshUsed: false, fullCodesEqual: true,
      codeCharacters: 64, mismatchSentConfirmations: false, rememberedSignInSucceeded: true,
    }) });
  } finally { await memberContext.close(); await fixture.close(); }
});

test('an idle session locks on schedule even after a new private link opens the entry screen', async ({ page, context }) => {
  const fixture = await authenticationFixture();
  try {
    await page.clock.install();
    await seedRememberedOwner(page, fixture); await signIn(page);
    await page.clock.fastForward(29 * 60 * 1000);
    await page.evaluate(() => { location.hash = '#access=invalid'; });
    await expect(page.locator('.identity-notice[role="alert"]')).toContainText('This link is not valid for this workspace.');
    await page.clock.fastForward(2 * 60 * 1000);
    await expect(page.getByRole('navigation', { name: 'Main navigation' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Browser owner Remembered on this device/ })).toBeVisible();
    await expect(page.locator('.workspace-switch')).toHaveCount(0);
    await expect(page.locator('.sidebar-profile')).toHaveCount(0);
    expect(await page.locator('input[type="password"]').count()).toBe(0);
    await expect.poll(async () => (await context.cookies()).some(cookie => cookie.name === '__Host-ukda_session')).toBe(false);
  } finally { await fixture.close(); }
});

for (const approvalOrder of ['recipient first', 'approver first'] as const) test(`a private sign-in link lets an existing person approve a second browser without account recovery (${approvalOrder})`, async ({ page, browser }, testInfo) => {
  const fixture = await authenticationFixture(), newContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const secondDevice = await newContext.newPage(), errors = trackBrowserErrors(secondDevice), existingErrors = trackBrowserErrors(page);
  const confirmations = { existing: 0, newDevice: 0 };
  for (const [device, side] of [[page, 'existing'], [secondDevice, 'newDevice']] as const) {
    device.on('request', request => {
      if (request.method() === 'POST' && request.url().endsWith('/v1/auth/pairing/confirm')) confirmations[side]++;
    });
  }
  try {
    await seedRememberedOwner(page, fixture); await signIn(page); await navigate(page, '/settings/account');
    await page.getByRole('button', { name: 'Create sign-in link', exact: true }).click();
    const signInFile = await downloadLinkFile(page);
    await page.getByRole('dialog').getByRole('button', { name: 'Done', exact: true }).click();
    await secondDevice.goto('https://127.0.0.1:3555/');
    await secondDevice.getByRole('button', { name: 'Join a workspace', exact: true }).click();
    await secondDevice.getByLabel('Or choose a link file', { exact: true }).setInputFiles({ name: 'workspace-private-link.json', mimeType: 'application/json', buffer: signInFile });
    await secondDevice.getByLabel('Password', { exact: true }).fill(originalPassword);
    await secondDevice.getByRole('button', { name: 'Open my workspace', exact: true }).click();
    await expect(secondDevice.getByRole('heading', { name: 'Let’s welcome this device.' })).toBeVisible();
    await page.locator('.sidebar').getByRole('button', { name: 'Review access requests', exact: true }).click();
    const approval = page.getByRole('dialog', { name: 'Approve access', exact: true });
    await approval.getByRole('button', { name: /^Device approval/ }).click();
    await page.getByLabel('Confirm your password', { exact: true }).fill(originalPassword);
    await page.getByRole('button', { name: 'Start security check', exact: true }).click();
    await expect(page.getByLabel('Your complete security check', { exact: true })).toBeVisible();
    await expect(secondDevice.getByLabel('Your complete security check', { exact: true })).toBeVisible();
    const existingCheck = await page.getByLabel('Your complete security check', { exact: true }).textContent();
    const newCheck = await secondDevice.getByLabel('Your complete security check', { exact: true }).textContent();
    if (!existingCheck || !/^[0-9a-f]{64}$/.test(existingCheck.replace(/\s/g, '')) || existingCheck !== newCheck) {
      throw new Error('The two devices did not show the same complete security check');
    }
    for (const device of [secondDevice, page]) {
      await expect(device.locator('.identity-comparison input')).toHaveCount(0);
      await device.getByRole('button', { name: 'The codes don’t match', exact: true }).click();
      await expect(device.getByRole('button', { name: 'Compare again', exact: true })).toBeVisible();
      await expect(device.getByRole('button', { name: 'The codes match', exact: true })).toHaveCount(0);
      // Mismatch is a local stop; neither device must submit a signed confirmation.
      expect(confirmations).toEqual({ existing: 0, newDevice: 0 });
      await device.getByRole('button', { name: 'Compare again', exact: true }).click();
      await expect(device.getByRole('button', { name: 'The codes match', exact: true })).toBeEnabled();
      expect(confirmations).toEqual({ existing: 0, newDevice: 0 });
    }
    const confirmDevice = async (device: typeof page) => {
      const response = device.waitForResponse(result => result.url().endsWith('/v1/auth/pairing/confirm') && result.request().method() === 'POST' && result.ok());
      await device.getByRole('button', { name: 'The codes match', exact: true }).click();
      await response;
    };
    if (approvalOrder === 'approver first') {
      await page.getByRole('button', { name: 'The codes match', exact: true }).click();
      await expect(page.getByText('Your check is complete. Waiting for the other person to compare the codes.', { exact: true })).toBeVisible();
      await expect(page.getByLabel('Your complete security check', { exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Access approved', exact: true })).toHaveCount(0);
      expect(confirmations.newDevice).toBe(0);
    }
    await confirmDevice(secondDevice);
    if (approvalOrder === 'recipient first') await confirmDevice(page);
    await expect(page.getByRole('heading', { name: 'Access approved', exact: true })).toBeVisible();
    await expect(secondDevice.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    await expect(secondDevice.locator('.sidebar-profile')).toContainText('Browser owner');
    expect(confirmations.existing).toBeGreaterThan(0); expect(confirmations.newDevice).toBe(1);
    const expectedConfirmations = { ...confirmations };
    await page.getByRole('button', { name: 'Back to requests', exact: true }).click();
    await page.getByRole('dialog', { name: 'Approve access', exact: true }).getByRole('button', { name: 'Close dialog', exact: true }).click();
    await secondDevice.getByRole('button', { name: 'Sign out', exact: true }).click();
    await signIn(secondDevice);
    expect(confirmations).toEqual(expectedConfirmations);
    expect(errors).toEqual([]); expect(existingErrors).toEqual([]);
    await testInfo.attach('device-comparison-checks', { contentType: 'application/json', body: JSON.stringify({
      approvalOrder, sharedLinks: 1, returnLinkUsed: false, manualRefreshUsed: false, fullCodesEqual: true,
      codeCharacters: 64, manualInputRequired: false, mismatchSentConfirmations: false,
      confirmations, rememberedSignInSucceeded: true,
    }) });
  } finally { await newContext.close(); await fixture.close(); }
});

test('a recipient can cancel a one-link invitation without leaving an active approval', async ({ page, browser }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'Cancellation is checked once against the real API; both successful orders cover every engine.');
  const fixture = await authenticationFixture(), memberContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const member = await memberContext.newPage(), errors = trackBrowserErrors(member);
  let confirmations = 0;
  for (const device of [page, member]) device.on('request', request => {
    if (request.method() === 'POST' && request.url().endsWith('/v1/auth/enrolment/confirm')) confirmations++;
  });
  try {
    await seedRememberedOwner(page, fixture); await signIn(page); await navigate(page, '/settings/people');
    await page.getByRole('button', { name: 'Invite person', exact: true }).click();
    let dialog = page.getByRole('dialog');
    await dialog.getByLabel('Name', { exact: true }).fill('Sam Taylor');
    await dialog.getByLabel(/^Confirm your password/).fill(originalPassword);
    await dialog.getByRole('button', { name: 'Create invitation', exact: true }).click();
    dialog = page.getByRole('dialog');
    await expect(dialog.getByLabel(/^Private link/)).toBeVisible();
    const invitation = await dialog.getByLabel(/^Private link/).inputValue();
    await dialog.getByRole('button', { name: 'Done', exact: true }).click();
    await member.goto(invitation);
    await expect(member.getByRole('button', { name: 'Cancel this request', exact: true })).toBeVisible();
    await page.locator('.sidebar').getByRole('button', { name: 'Review access requests', exact: true }).click();
    const request = page.getByRole('dialog', { name: 'Approve access', exact: true }).getByRole('button', { name: /^Workspace invitation/ });
    await expect(request).toBeVisible();
    const cancelled = member.waitForResponse(response => response.url().endsWith('/v1/auth/enrolment/cancel') && response.request().method() === 'POST' && response.ok());
    await member.getByRole('button', { name: 'Cancel this request', exact: true }).click(); await cancelled;
    await expect(member.getByText('This request is no longer active. Ask an Owner for a fresh private link.', { exact: true })).toBeVisible();
    await expect(member.getByRole('button', { name: 'The codes match', exact: true })).toHaveCount(0);
    await expect(member.getByRole('navigation', { name: 'Main navigation' })).toHaveCount(0);
    await expect(request).toHaveCount(0);
    await member.getByRole('button', { name: 'Back to sign in', exact: true }).click();
    await expect(member.getByRole('button', { name: 'Create a workspace', exact: true })).toBeVisible();
    expect(confirmations).toBe(0); expect(errors).toEqual([]);
    await testInfo.attach('one-link-cancellation-checks', { contentType: 'application/json', body: JSON.stringify({
      cancelledByRecipient: true, approvalRemovedAutomatically: true, confirmations: 0, accessGranted: false, returnedToSignIn: true,
    }) });
  } finally { await memberContext.close(); await fixture.close(); }
});

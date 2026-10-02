import { expect, test, type Page, type Request } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import type * as Client from '../../src/client/index.js';
import type { authenticationFixture } from '../browser/authentication-fixture.js';
import { password as fixturePassword } from '../browser/authentication-fixture.js';

export type FrontendFixture = Awaited<ReturnType<typeof authenticationFixture>>;

/** Install only an existing verified device, its signed pin and remembered card.
 * Login itself always uses the product's actual password form and real API. */
export async function seedRememberedOwner(page: Page, fixture: FrontendFixture) {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Create a workspace', exact: true })).toBeVisible();
  await page.evaluate(async ({ reference, wrapper, operationId, genesis, receipt }) => {
    const url = '/client/client.js', library = await import(url) as typeof Client;
    const devices = await library.IndexedDeviceStore.open();
    try { await devices.stage(wrapper, operationId); await devices.commit(operationId, { ...reference, operationId, credentialGeneration: '1' }); }
    finally { devices.close(); }
    const pins = await library.IndexedPairingStore.open(location.origin);
    try { await library.seedActivationPin(pins, genesis, receipt); } finally { pins.close(); }
    const remembered = await library.RememberedProfiles.open(location.origin);
    try { await remembered.remember({ ...reference, displayName: 'Browser owner' }); } finally { remembered.close(); }
  }, { reference: { workspaceId: fixture.workspaceId, accountId: fixture.accountId, deviceId: fixture.deviceId }, wrapper: fixture.wrapper,
    operationId: fixture.operationId, genesis: fixture.genesis, receipt: fixture.receipt });
  await page.reload();
}

export async function signIn(page: Page, name = 'Browser owner', password = fixturePassword) {
  await page.getByRole('button', { name: new RegExp(`${name} Remembered on this device`) }).click();
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Open my workspace', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
  await expect(page.locator('.sidebar-profile')).toContainText(name);
}

/** Same-document navigation preserves the unlocked Worker, as product links do. */
export async function navigate(page: Page, path: string) {
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Expected a local product path');
  await page.evaluate(value => { history.pushState(null, '', value); dispatchEvent(new PopStateEvent('popstate')); }, path);
}

export function trackBrowserErrors(page: Page) {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  return errors;
}

/** Reads the words the UI asks the person to save, then answers its random check. */
export async function confirmRecoveryWords(page: Page) {
  await expect(page.getByRole('heading', { name: 'Your personal recovery words' })).toBeVisible();
  const words = await page.locator('.identity-recovery-words li').evaluateAll(nodes => nodes.map(node => node.childNodes[node.childNodes.length - 1]?.textContent ?? ''));
  expect(words).toHaveLength(24);
  await page.getByRole('checkbox', { name: 'I’ve written these words down somewhere safe.' }).check();
  await page.getByRole('button', { name: 'Check my backup' }).click();
  const fields = page.getByLabel(/^Word \d+$/);
  // Locator assertions can embed an accessibility snapshot in their errors.
  // Wait without that snapshot while recovery words may be on screen.
  await fields.nth(2).waitFor({ state: 'visible' });
  expect(await fields.count()).toBe(3);
  for (let index = 0; index < 3; index++) {
    const input = fields.nth(index), label = await input.evaluate(element => (element as HTMLInputElement).labels?.[0]?.textContent ?? '');
    const position = Number(label.match(/Word (\d+)/)?.[1]);
    expect(position).toBeGreaterThan(0); await input.fill(words[position - 1]!);
  }
  await page.getByRole('button', { name: 'Confirm backup', exact: true }).click();
  return words.join(' ');
}

export async function downloadRecoveryKit(page: Page) {
  const save = page.getByRole('button', { name: 'Save recovery kit', exact: true });
  await save.waitFor({ state: 'visible' });
  const download = page.waitForEvent('download');
  await save.click();
  const stream = await (await download).createReadStream();
  if (!stream) throw new Error('Recovery kit download did not complete');
  const chunks: Buffer[] = []; for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

export async function downloadLinkFile(page: Page) {
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Save link', exact: true }).click();
  const stream = await (await download).createReadStream();
  if (!stream) throw new Error('Private link download did not complete');
  const chunks: Buffer[] = []; for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

/** Share one invitation, then compare the actual codes displayed on both devices. */
export async function joinViaInvitation(ownerPage: Page, memberPage: Page, options: {
  name: string; password: string; role?: string; projectNames?: string[];
  approvalOrder?: 'recipient first' | 'approver first'; checkMismatch?: boolean;
}) {
  const invitation = await test.step('Owner creates a private invitation', async () => {
  await navigate(ownerPage, '/settings/people');
  await ownerPage.getByRole('button', { name: 'Invite person', exact: true }).click();
  let dialog = ownerPage.getByRole('dialog');
  await dialog.getByLabel('Name', { exact: true }).fill(options.name);
  await dialog.getByRole('combobox', { name: /^Role/ }).selectOption({ label: options.role ?? 'Member' });
  for (const projectName of options.projectNames ?? []) await dialog.getByRole('checkbox', { name: projectName, exact: true }).check();
  await dialog.getByLabel(/^Confirm your password/).fill(fixturePassword);
  await dialog.getByRole('button', { name: 'Create invitation', exact: true }).click();
  dialog = ownerPage.getByRole('dialog');
  const link = dialog.getByLabel(/^Private link/);
  await expect(link).toBeVisible(); const invitation = await link.inputValue();
  expect(new URL(invitation).search).toBe('');
  await dialog.getByRole('button', { name: 'Done', exact: true }).click();
  return invitation;
  }, { timeout: 30_000 });
  return finishAccessRequest(ownerPage, memberPage, invitation, { ...options, owner: options.role === 'Owner' });
}

export async function finishAccessRequest(ownerPage: Page, memberPage: Page, invitation: string, options: {
  name: string; password: string; owner?: boolean; reset?: boolean;
  approvalOrder?: 'recipient first' | 'approver first'; checkMismatch?: boolean;
}) {
  if (!options.reset) return finishOneLinkInvitation(ownerPage, memberPage, invitation, options);
  let recoveryKit: Buffer | null = null;
  const request = await test.step('Recipient opens the invitation and saves its approval request', async () => {
  await memberPage.goto(invitation);
  await expect(memberPage.getByRole('heading', { name: 'An Owner will help you in' })).toBeVisible();
  // A downloaded request is an alternative to clipboard permission. It carries
  // only the public request reference; the invitation capability is separate.
  return (await downloadLinkFile(memberPage)).toString('utf8');
  }, { timeout: 30_000 });
  await test.step('Owner starts the security check', async () => {
  await ownerPage.locator('.sidebar').getByRole('button', { name: 'Review access requests', exact: true }).click();
  await ownerPage.locator('summary').filter({ hasText: 'Use a private approval link' }).click();
  await ownerPage.getByLabel('Private approval link', { exact: true }).fill(request);
  await ownerPage.getByRole('button', { name: 'Review request', exact: true }).click();
  await ownerPage.getByLabel(/^Confirm your password/).fill(fixturePassword);
  await ownerPage.getByRole('button', { name: 'Start security check', exact: true }).click();
  await expect(ownerPage.getByRole('button', { name: 'Check their progress', exact: true })).toBeVisible();
  }, { timeout: 30_000 });
  await test.step('Recipient chooses their name and password', async () => {
  await memberPage.getByRole('button', { name: 'Check for approval', exact: true }).click();
  if (!options.reset) await memberPage.getByLabel('Your name', { exact: true }).fill(options.name);
  await memberPage.getByLabel(/^Create a password/).fill(options.password);
  await memberPage.getByLabel(/^Confirm password/).fill(options.password);
  await memberPage.getByRole('button', { name: 'Continue', exact: true }).click();
  if (options.owner) {
    await confirmRecoveryWords(memberPage); recoveryKit = await downloadRecoveryKit(memberPage);
    await memberPage.getByRole('checkbox', { name: 'I’ve saved my new kit safely.' }).check();
    await memberPage.getByRole('button', { name: 'Continue', exact: true }).click();
  }
  await expect(memberPage.getByLabel('Your complete security check', { exact: true })).toBeVisible();
  }, { timeout: 30_000 });
  await test.step('Both people compare and approve the full security check', async () => {
  await ownerPage.getByRole('button', { name: 'Check their progress', exact: true }).click();
  const ownerCheck = await ownerPage.getByLabel('Your complete security check', { exact: true }).textContent();
  const memberCheck = await memberPage.getByLabel('Your complete security check', { exact: true }).textContent();
  if (!ownerCheck || ownerCheck !== memberCheck) throw new Error('The two devices did not show the same security check');
  await memberPage.getByLabel(/^The check from the other person/).fill(ownerCheck);
  await memberPage.getByRole('button', { name: 'Confirm and continue', exact: true }).click();
  await expect(memberPage.getByText('Thanks. Your side is ready.', { exact: false })).toBeVisible();
  await ownerPage.getByLabel(/^The check from the other person/).fill(memberCheck);
  await ownerPage.getByRole('button', { name: 'Confirm and continue', exact: true }).click();
  await expect(ownerPage.getByRole('heading', { name: 'Access approved', exact: true })).toBeVisible();
  await memberPage.getByRole('button', { name: 'Check and continue', exact: true }).click();
  await expect(memberPage.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
  await expect(memberPage.locator('.sidebar-profile')).toContainText(options.name);
  await ownerPage.getByRole('button', { name: 'Back to requests', exact: true }).click();
  await ownerPage.getByRole('dialog', { name: 'Approve access', exact: true }).getByRole('button', { name: 'Close dialog', exact: true }).click();
  }, { timeout: 30_000 });
  return recoveryKit;
}

async function finishOneLinkInvitation(ownerPage: Page, memberPage: Page, invitation: string, options: {
  name: string; password: string; owner?: boolean;
  approvalOrder?: 'recipient first' | 'approver first'; checkMismatch?: boolean;
}) {
  let recoveryKit: Buffer | null = null;
  const confirmations = { owner: 0, recipient: 0 };
  const responses: { side: string; path: string; status: number }[] = [];
  for (const [device, side] of [[ownerPage, 'owner'], [memberPage, 'recipient']] as const) device.on('response', response => {
    const path = new URL(response.url()).pathname;
    if (path.startsWith('/v1/auth/') && responses.length < 150) responses.push({ side, path, status: response.status() });
  });
  const ownerRequest = (request: Request) => { if (request.method() === 'POST' && request.url().endsWith('/v1/auth/enrolment/confirm')) confirmations.owner++; };
  const recipientRequest = (request: Request) => { if (request.method() === 'POST' && request.url().endsWith('/v1/auth/enrolment/confirm')) confirmations.recipient++; };
  ownerPage.on('request', ownerRequest); memberPage.on('request', recipientRequest);
  try {
    await test.step('Recipient opens the only shared invitation', async () => {
      await memberPage.goto(invitation);
      await expect(memberPage.getByRole('button', { name: 'Cancel this request', exact: true })).toBeVisible();
      expect(new URL(memberPage.url()).hash).toBe('');
    }, { timeout: 30_000 });
    await test.step('Owner discovers the request without receiving a return link', async () => {
      await ownerPage.locator('.sidebar').getByRole('button', { name: 'Review access requests', exact: true }).click();
      const dialog = ownerPage.getByRole('dialog', { name: 'Approve access', exact: true });
      await dialog.getByRole('button', { name: /^Workspace invitation/ }).click();
      await dialog.getByLabel('Confirm your password', { exact: true }).fill(fixturePassword);
      await dialog.getByRole('button', { name: 'Start security check', exact: true }).click();
      // The recipient advances by itself once the Owner starts the check.
      try { await expect(memberPage.getByLabel('Your name', { exact: true })).toBeVisible(); }
      catch (error) {
        await mkdir('test-results/frontend-review/one-link', { recursive: true });
        await writeFile(`test-results/frontend-review/one-link/setup-${test.info().project.name}.json`, JSON.stringify({ responses,
          ownerNotices: await dialog.locator('.identity-notice').allTextContents(), recipientNotices: await memberPage.locator('.identity-notice').allTextContents(),
          ownerBusy: await dialog.locator('.identity-approvals').getAttribute('aria-busy'),
          ownerStartVisible: await dialog.getByRole('button', { name: 'Start security check', exact: true }).isVisible(),
          recipientHasSetup: await memberPage.getByLabel('Your name', { exact: true }).count(),
        }, null, 2) + '\n');
        throw error;
      }
    }, { timeout: 30_000 });
    await test.step('Recipient chooses their details and saves any required Owner kit', async () => {
      await memberPage.getByLabel('Your name', { exact: true }).fill(options.name);
      await memberPage.getByLabel(/^Create a password/).fill(options.password);
      await memberPage.getByLabel(/^Confirm password/).fill(options.password);
      await memberPage.getByRole('button', { name: 'Continue', exact: true }).click();
      if (options.owner) {
        await confirmRecoveryWords(memberPage); recoveryKit = await downloadRecoveryKit(memberPage);
        await expect(memberPage.getByRole('button', { name: 'The codes match', exact: true })).toHaveCount(0);
        await memberPage.getByRole('checkbox', { name: 'I’ve saved my new kit safely.' }).check();
        await memberPage.getByRole('button', { name: 'Continue', exact: true }).click();
      }
      await expect(memberPage.getByLabel('Your complete security check', { exact: true })).toBeVisible();
      await expect(ownerPage.getByLabel('Your complete security check', { exact: true })).toBeVisible();
    }, { timeout: 45_000 });
    await test.step('Both people compare the full code and access completes automatically', async () => {
      const ownerCode = await ownerPage.getByLabel('Your complete security check', { exact: true }).textContent();
      const memberCode = await memberPage.getByLabel('Your complete security check', { exact: true }).textContent();
      if (!ownerCode || !/^[0-9a-f]{64}$/.test(ownerCode.replace(/\s/g, '')) || ownerCode !== memberCode) throw new Error('Both people must see the same complete security check');
      for (const device of [memberPage, ownerPage]) {
        await expect(device.locator('.identity-comparison input')).toHaveCount(0);
        if (options.checkMismatch) {
          await device.getByRole('button', { name: 'The codes don’t match', exact: true }).click();
          await expect(device.getByRole('button', { name: 'Compare again', exact: true })).toBeVisible();
          await expect(device.getByRole('button', { name: 'The codes match', exact: true })).toHaveCount(0);
          expect(confirmations).toEqual({ owner: 0, recipient: 0 });
          await device.getByRole('button', { name: 'Compare again', exact: true }).click();
          await expect(device.getByRole('button', { name: 'The codes match', exact: true })).toBeEnabled();
          expect(confirmations).toEqual({ owner: 0, recipient: 0 });
        }
      }
      if (options.approvalOrder === 'approver first') {
        await ownerPage.getByRole('button', { name: 'The codes match', exact: true }).click();
        await expect(ownerPage.getByText('Your check is complete. Waiting for the other person to compare the codes.', { exact: true })).toBeVisible();
        await expect(memberPage.getByRole('navigation', { name: 'Main navigation' })).toHaveCount(0);
        await memberPage.getByRole('button', { name: 'The codes match', exact: true }).click();
      } else {
        const confirmed = memberPage.waitForResponse(response => response.url().endsWith('/v1/auth/enrolment/confirm') && response.request().method() === 'POST' && response.ok());
        await memberPage.getByRole('button', { name: 'The codes match', exact: true }).click(); await confirmed;
        await expect(memberPage.getByRole('navigation', { name: 'Main navigation' })).toHaveCount(0);
        await ownerPage.getByRole('button', { name: 'The codes match', exact: true }).click();
      }
      await expect(ownerPage.getByRole('heading', { name: 'Access approved', exact: true })).toBeVisible();
      await expect(memberPage.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
      await expect(memberPage.locator('.sidebar-profile')).toContainText(options.name);
      expect(confirmations.recipient).toBeGreaterThan(0);
      await ownerPage.getByRole('button', { name: 'Back to requests', exact: true }).click();
      await ownerPage.getByRole('dialog', { name: 'Approve access', exact: true }).getByRole('button', { name: 'Close dialog', exact: true }).click();
    }, { timeout: 45_000 });
    return recoveryKit;
  } finally { ownerPage.off('request', ownerRequest); memberPage.off('request', recipientRequest); }
}

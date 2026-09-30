import { expect, test, type Locator, type Page } from '@playwright/test';
import { unzipSync, strFromU8 } from 'fflate';
import { authenticationFixture } from '../browser/authentication-fixture.js';
import { navigate, seedRememberedOwner, signIn, trackBrowserErrors } from './helpers.js';
import type * as Client from '../../src/client/index.js';

async function close(dialog: Locator) {
  await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

async function createProject(page: Page, name: string) {
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
  await page.getByRole('button', { name: 'Project options', exact: true }).click();
  const options = page.getByRole('dialog', { name: 'Project options', exact: true });
  await options.getByRole('button', { name: 'Start project', exact: true }).click();
  await expect(page.locator('.page-header')).toContainText('Active');
  await close(options);
  await navigate(page, `/projects/${projectId}/files`);
  await expect(page.locator('.files-page')).toBeVisible();
  return projectId;
}

async function more(page: Page, action: string) {
  await page.locator('.files-more > summary').click();
  await page.locator('.files-more-menu').getByRole('button', { name: action, exact: true }).click();
}

async function sameGeometry(dialog: Locator, original: NonNullable<Awaited<ReturnType<Locator['boundingBox']>>>) {
  const current = await dialog.boundingBox();
  expect(current).not.toBeNull();
  for (const field of ['x', 'y', 'width', 'height'] as const) expect(Math.abs(current![field] - original[field])).toBeLessThan(2);
}

test('project files preserve exact versions, recover interrupted work, check external files and export honest contents', async ({ page }, info) => {
  test.setTimeout(240_000);
  const fixture = await authenticationFixture(), errors = trackBrowserErrors(page);
  const first = { name: 'welcome-guide.txt', mimeType: 'text/plain', buffer: Buffer.from('The first welcome guide.\nA clear beginning.') };
  const second = { ...first, buffer: Buffer.from('The revised welcome guide.\nA clearer beginning.') };
  const external = { name: 'shared-notes.txt', mimeType: 'text/plain', buffer: Buffer.from('Notes kept on the shared drive.') };
  try {
    await seedRememberedOwner(page, fixture); await signIn(page);
    const projectId = await createProject(page, 'A document launch');
    await page.getByRole('button', { name: 'Add files', exact: true }).first().click();
    let upload = page.getByRole('dialog', { name: 'Add files', exact: true });
    await upload.getByLabel('Choose files to upload', { exact: true }).setInputFiles(first);
    await upload.getByLabel('Document reference', { exact: true }).fill('DOC-001');
    let firstChunks = 0;
    const countFirst = (request: import('@playwright/test').Request) => { if (request.url().endsWith('/v1/files/chunk')) firstChunks++; };
    page.on('request', countFirst);
    await page.route('**/v1/files/chunk', async route => {
      const response = await route.fetch(); expect(response.status()).toBe(200); await route.abort('failed');
    }, { times: 1 });
    await upload.getByRole('button', { name: 'Save files', exact: true }).click();
    await expect(upload.getByRole('alert')).toBeVisible();
    await upload.getByRole('button', { name: 'Save files', exact: true }).click();
    await expect(upload.locator('.is-saved')).toContainText('Saved');
    expect(firstChunks).toBe(1);
    page.off('request', countFirst);
    await upload.getByRole('button', { name: 'Done', exact: true }).click();
    await expect(upload).toHaveCount(0);
    await expect(page.locator('.files-table tbody tr')).toHaveCount(1);
    await page.getByRole('button', { name: 'Open welcome-guide.txt', exact: true }).click();
    const detail = page.getByRole('dialog', { name: 'welcome-guide.txt', exact: true });
    await expect(detail.locator('.file-text-preview')).toContainText('The first welcome guide.');
    const geometry = (await detail.boundingBox())!;
    await detail.getByRole('button', { name: 'Expand window', exact: true }).click();
    const expandedGeometry = (await detail.boundingBox())!;
    expect(expandedGeometry.width).toBeGreaterThan(geometry.width + 100);
    expect(expandedGeometry.height).toBeGreaterThanOrEqual(geometry.height);
    await expect(detail.locator('.file-text-preview')).toContainText('The first welcome guide.');
    if (info.project.name === 'chromium') await page.screenshot({ path: info.outputPath('file-preview-expanded.png'), animations: 'disabled' });
    await detail.getByRole('tab', { name: 'Versions', exact: true }).click();
    await sameGeometry(detail, expandedGeometry);
    await detail.getByRole('tab', { name: 'Preview', exact: true }).click();
    await detail.getByRole('button', { name: 'Restore window size', exact: true }).click();
    await sameGeometry(detail, geometry);
    await detail.getByRole('button', { name: 'Expand window', exact: true }).click();
    await page.keyboard.press('Escape');
    await expect(detail).toBeVisible();
    await sameGeometry(detail, geometry);
    const viewport = page.viewportSize()!;
    await page.setViewportSize({ width: 390, height: 844 });
    await detail.getByRole('button', { name: 'Expand window', exact: true }).click();
    const mobileExpanded = (await detail.boundingBox())!;
    expect(mobileExpanded.width).toBeLessThanOrEqual(390);
    expect(mobileExpanded.height).toBeLessThanOrEqual(844);
    const closeControl = (await detail.getByRole('button', { name: 'Close dialog', exact: true }).boundingBox())!;
    expect(closeControl.x).toBeGreaterThanOrEqual(0);
    expect(closeControl.x + closeControl.width).toBeLessThanOrEqual(390);
    await expect(detail.locator('.file-text-preview')).toContainText('The first welcome guide.');
    const footerSummary = (await detail.locator('.file-footer-summary').boundingBox())!;
    const footerClose = (await detail.locator('.modal-footer').getByRole('button', { name: 'Close', exact: true }).boundingBox())!;
    expect(footerSummary.y + footerSummary.height).toBeLessThanOrEqual(footerClose.y);
    if (info.project.name === 'chromium') await page.screenshot({ path: info.outputPath('file-preview-expanded-mobile.png'), animations: 'disabled' });
    await detail.getByRole('button', { name: 'Restore window size', exact: true }).click();
    await page.setViewportSize(viewport);
    await sameGeometry(detail, geometry);
    await detail.getByRole('tab', { name: 'Versions', exact: true }).click();
    await expect(detail.locator('.file-version-row')).toHaveCount(1);
    await sameGeometry(detail, geometry);
    await detail.getByRole('tab', { name: 'Linked work', exact: true }).click();
    await expect(detail.getByText('A project reference', { exact: true })).toBeVisible();
    await sameGeometry(detail, geometry);
    await detail.getByRole('tab', { name: 'Preview', exact: true }).click();
    await sameGeometry(detail, geometry);
    await detail.getByRole('button', { name: 'Add version', exact: true }).click();
    upload = page.getByRole('dialog', { name: 'Add a new version', exact: true });
    await upload.getByLabel('Choose files to upload', { exact: true }).setInputFiles(second);
    await upload.getByRole('button', { name: 'Save new version', exact: true }).click();
    await expect(upload.locator('.is-saved')).toContainText('Saved');
    await upload.getByRole('button', { name: 'Done', exact: true }).click();
    await detail.getByRole('tab', { name: 'Versions', exact: true }).click();
    await expect(detail.locator('.file-version-row')).toHaveCount(2);
    await detail.locator('.file-version-row').filter({ hasText: 'Version 1' }).getByRole('button', { name: /Open version/ }).click();
    await expect(detail.locator('.file-text-preview')).toContainText('The first welcome guide.');
    await sameGeometry(detail, geometry);
    await close(detail);

    await more(page, 'Keep on shared drive');
    upload = page.getByRole('dialog', { name: 'Add files', exact: true });
    await upload.getByLabel('Choose shared-drive files to check', { exact: true }).setInputFiles(external);
    await upload.getByLabel('Document reference', { exact: true }).fill('DOC-002');
    await upload.getByLabel('Shared-drive location', { exact: true }).fill('/Volumes/Shared/Launch/shared-notes.txt');
    await expect(upload.getByText(/File contents are not included in cloud backups/)).toBeVisible();
    await upload.getByRole('button', { name: 'Save files', exact: true }).click();
    await expect(upload.locator('.is-saved')).toContainText('Saved');
    await upload.getByRole('button', { name: 'Done', exact: true }).click();
    await page.getByRole('button', { name: 'Open shared-notes.txt', exact: true }).click();
    const shared = page.getByRole('dialog', { name: 'shared-notes.txt', exact: true });
    await shared.getByLabel('Choose the external file to check', { exact: true }).setInputFiles({ ...external, buffer: Buffer.from('Different file bytes') });
    await expect(shared.getByRole('alert')).toBeVisible();
    await shared.getByLabel('Choose the external file to check', { exact: true }).setInputFiles(external);
    await expect(shared.getByText('Matches this version', { exact: true })).toBeVisible();
    await expect(shared.locator('.file-text-preview')).toContainText('Notes kept on the shared drive.');
    await expect(shared.getByRole('button', { name: /^Download v/ })).toHaveCount(0);
    await close(shared);

    await more(page, 'Register documents');
    const batch = page.getByRole('dialog', { name: 'Register documents', exact: true });
    await batch.getByLabel('Choose documents for this batch', { exact: true }).setInputFiles([
      { name: 'review-a.txt', mimeType: 'text/plain', buffer: Buffer.from('Source for document A') },
      { name: 'review-b.txt', mimeType: 'text/plain', buffer: Buffer.from('Source for document B') },
    ]);
    await batch.getByLabel('Document reference', { exact: true }).nth(0).fill('REG-A');
    await batch.getByLabel('Document reference', { exact: true }).nth(1).fill('REG-B');
    await batch.getByRole('checkbox', { name: 'Browser owner', exact: true }).check();
    if (info.project.name === 'chromium') await page.screenshot({ path: info.outputPath('register-match.png'), fullPage: true, animations: 'disabled' });
    await batch.getByRole('button', { name: 'Review batch', exact: false }).click();
    await batch.getByRole('checkbox', { name: 'I have checked the references, files and assignments in this batch.', exact: true }).check();
    let starts = 0, completions = 0;
    const observe = (request: import('@playwright/test').Request) => {
      if (request.url().endsWith('/v1/files/begin')) starts++;
      if (request.url().endsWith('/v1/files/complete')) completions++;
    };
    page.on('request', observe);
    await page.route('**/v1/files/complete', async route => {
      const response = await route.fetch(); expect(response.status()).toBe(200); await route.abort('failed');
    }, { times: 1 });
    await batch.getByRole('button', { name: 'Register documents', exact: true }).click();
    await expect(batch.getByRole('button', { name: 'Check and retry unfinished', exact: true })).toBeVisible();
    await expect(batch.locator('.file-bulk-result').filter({ hasText: 'review-b.txt' })).toContainText('Saved');
    if (info.project.name === 'chromium') await page.screenshot({ path: info.outputPath('register-interrupted.png'), fullPage: true, animations: 'disabled' });
    await batch.getByRole('button', { name: 'Check and retry unfinished', exact: true }).click();
    await expect(batch.getByRole('button', { name: 'Done', exact: true })).toBeVisible();
    expect(starts).toBe(2); expect(completions).toBe(2);
    page.off('request', observe);
    await batch.getByRole('button', { name: 'Done', exact: true }).click();
    await expect(batch).toHaveCount(0);
    await expect(page.locator('.files-table tbody tr')).toHaveCount(4);
    const pending = await page.evaluate(async scope => {
      const url = '/client/client.js', library = await import(url) as typeof Client, store = await library.IndexedFilesStore.open(location.origin);
      try { return (await store.list(scope)).length; } finally { store.close(); }
    }, { workspaceId: fixture.workspaceId, accountId: fixture.accountId, deviceId: fixture.deviceId });
    expect(pending).toBe(0);

    await more(page, 'Export files');
    const archive = page.getByRole('dialog', { name: 'Export files', exact: true });
    await archive.locator('.file-archive-row').filter({ hasText: 'welcome-guide.txt' }).getByRole('checkbox').check();
    await archive.locator('.file-archive-row').filter({ hasText: 'shared-notes.txt' }).getByRole('checkbox').check();
    await archive.getByRole('checkbox', { name: 'I understand that this package contains readable files and will keep it private.', exact: true }).check();
    const downloading = page.waitForEvent('download');
    await archive.getByRole('button', { name: 'Download selected files', exact: true }).click();
    const stream = await (await downloading).createReadStream();
    if (!stream) throw new Error('Expected the private file package');
    const chunks: Buffer[] = []; for await (const chunk of stream) chunks.push(Buffer.from(chunk));
    const contents = unzipSync(Buffer.concat(chunks)), names = Object.keys(contents);
    expect(names.filter(name => name.endsWith('welcome-guide.txt'))).toHaveLength(1);
    expect(strFromU8(contents[names.find(name => name.endsWith('welcome-guide.txt'))!]!)).toContain('The revised welcome guide.');
    expect(names.filter(name => name.endsWith('shared-notes.txt'))).toHaveLength(0);
    await expect(archive).toHaveCount(0);

    await page.setViewportSize({ width: 1440, height: 1000 });
    for (const theme of ['light', 'dark'] as const) {
      if (await page.locator('html').getAttribute('data-theme') !== theme) await page.getByRole('button', { name: 'Change appearance', exact: true }).click();
      if (theme === 'dark') await expect(page.locator('html')).toHaveCSS('background-color', 'rgb(16, 17, 19)');
      await page.screenshot({ path: info.outputPath(`files-${theme}.png`), fullPage: true, animations: 'disabled' });
      await page.getByRole('button', { name: 'Open welcome-guide.txt', exact: true }).click();
      await expect(detail.locator('.file-text-preview')).toContainText('The revised welcome guide.');
      await page.screenshot({ path: info.outputPath(`file-preview-${theme}.png`), fullPage: true, animations: 'disabled' });
      await close(detail);
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath('files-mobile-dark.png'), fullPage: true, animations: 'disabled' });
    await navigate(page, `/projects/${projectId}/work`);
    await expect(page.locator('.task-row')).toHaveCount(2);
    expect(errors).toEqual([]);
  } finally { await fixture.close(); }
});

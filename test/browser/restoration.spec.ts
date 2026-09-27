import { expect, test } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, password } from './authentication-fixture.js';
import { ownerPage } from './planning-helpers.js';

test('CP12: current Owner verifies quarantined ciphertext in a real Worker and resolves a lost acknowledgement', async ({ page }) => {
  test.setTimeout(90000);
  const f = await authenticationFixture();
  try {
    await ownerPage(page, f);
    const project = await page.evaluate(async () => {
      const c = window.clientRuntime, project = await c.projectCreation.create({ name: 'Private restore browser project' });
      const task = await c.planning.createTask({ projectId: project.projectId, title: 'Historical restore task' });
      await c.planning.execute({ projectId: project.projectId, reviewed: (await c.planning.read(project.projectId)).pin,
        command: { action: 'edit_task', taskId: task.taskId }, content: { title: 'Current restore task' } });
      return project;
    });
    // Install the exact captured fixture rows after quarantine begins. The
    // separate physical drill owns PITR; this case verifies the browser boundary.
    const restoreId = await f.quarantineCurrentCheckpoint();
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    await page.evaluate(async ({ workspaceId, accountId, deviceId, password, trustedServiceKeys }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, password, trustedServiceKeys: f.trustedServiceKeys });
    expect(await page.evaluate(async projectId => { try { await window.clientRuntime.planning.read(projectId); return false; } catch { return true; } }, project.projectId)).toBe(true);
    expect(await page.evaluate(async () => { try { await window.clientRuntime.accessChanges.refreshKeys(); return false; } catch { return true; } })).toBe(true);
    const inspected = await page.evaluate(restoreId => window.clientRuntime.restoration.inspect(restoreId), restoreId);
    expect(JSON.stringify(inspected)).not.toContain('Current restore task');
    expect(JSON.stringify(inspected)).not.toContain('Historical restore task');
    const operationId = randomUUID(), sent: string[] = [];
    page.on('request', request => { if (request.url().endsWith('/v1/restoration/verify')) sent.push(request.postData() ?? ''); });
    await page.route('**/v1/restoration/verify', async route => {
      const response = await route.fetch(); expect(response.status()).toBe(200); await route.abort('failed');
    }, { times: 1 });
    expect(await page.evaluate(async ({ restoreId, operationId }) => { try { await window.clientRuntime.restoration.verify(restoreId, true, operationId); return false; } catch { return true; } }, { restoreId, operationId })).toBe(true);
    expect(await page.evaluate(() => window.clientRuntime.restoration.pending())).toEqual([operationId]);
    await page.evaluate(operationId => window.clientRuntime.restoration.resume(operationId), operationId);
    expect(sent).toHaveLength(1); expect(sent[0]).not.toContain('restore task');
    expect(await page.evaluate(() => window.clientRuntime.restoration.pending())).toEqual([]);
    const reopened = await page.evaluate(projectId => window.clientRuntime.planning.read(projectId), project.projectId);
    expect(reopened.records.some(record => record.content.title === 'Current restore task')).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close())]); await f.close(); }
});

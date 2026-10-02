import { expect, test } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, password } from './authentication-fixture.js';
import { enrol, ownerPage } from './planning-helpers.js';

test('CP12: Owner confirms the name locally, resumes a lost deletion reply, and an equal Owner cancels', async ({ page, browser }) => {
  test.setTimeout(120000);
  const f = await authenticationFixture(), otherContext = await browser.newContext({ ignoreHTTPSErrors: true }), other = await otherContext.newPage();
  try {
    await ownerPage(page, f);
    const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private lifecycle project' }));
    await enrol(page, other, f, true);
    const sent: string[] = [];
    page.on('request', request => { if (request.url().endsWith('/v1/lifecycle/save')) sent.push(request.postData() ?? ''); });
    expect(await page.evaluate(async () => { try { await window.clientRuntime.lifecycle.requestDeletion('Wrong name'); return false; } catch { return true; } })).toBe(true);
    expect(sent).toHaveLength(0);
    const operationId = randomUUID();
    await page.route('**/v1/lifecycle/save', async route => {
      const response = await route.fetch(); expect(response.status()).toBe(200); await route.abort('failed');
    }, { times: 1 });
    expect(await page.evaluate(async operationId => {
      try { await window.clientRuntime.lifecycle.requestDeletion('Browser workspace', operationId); return false; } catch { return true; }
    }, operationId)).toBe(true);
    expect(await page.evaluate(() => window.clientRuntime.lifecycle.pending())).toEqual([operationId]);
    expect(sent).toHaveLength(1); expect(sent[0]).not.toContain('Browser workspace');
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const resumed = await page.evaluate(async ({ workspaceId, accountId, deviceId, password, trustedServiceKeys, operationId }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
      return window.clientRuntime.lifecycle.resume(operationId);
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, password, trustedServiceKeys: f.trustedServiceKeys, operationId });
    expect(resumed.state).toBe('completed');
    const deletion = resumed.receipt!.deletion!;
    expect(Date.parse(deletion.deleteAfter) - Date.parse(deletion.requestedAt)).toBe(168 * 60 * 60 * 1000);
    expect(sent).toHaveLength(1); expect(await page.evaluate(() => window.clientRuntime.lifecycle.pending())).toEqual([]);
    expect(await other.evaluate(async projectId => { try { await window.clientRuntime.planning.createTask({ projectId, title: 'Blocked while deleting' }); return false; } catch { return true; } }, project.projectId)).toBe(true);
    const exported = await other.evaluate(() => window.clientRuntime.exports.generate({ acknowledgePlaintext: true }));
    expect(JSON.parse(exported.json).complete).toBe(true);
    expect((await other.evaluate(() => window.clientRuntime.lifecycle.cancelDeletion())).state).toBe('completed');
    expect((await other.evaluate(projectId => window.clientRuntime.planning.createTask({ projectId, title: 'After cancellation' }), project.projectId)).taskId).toBeTruthy();
  } finally {
    await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), other.evaluate(() => window.clientRuntime?.close())]);
    await otherContext.close(); await f.close();
  }
});

import { expect, test, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, origin, password } from './authentication-fixture.js';
import type { ClientRuntime } from '../../src/client/runtime.js';

declare global { interface Window { clientRuntime: ClientRuntime } }
type Fixture = Awaited<ReturnType<typeof authenticationFixture>>;
async function ownerPage(page: Page, f: Fixture) {
  await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
  await page.evaluate(async ({ workspaceId, accountId, deviceId, wrapper, operationId, genesis, receipt, trustedServiceKeys, password }) => {
    const client = window.ukda, devices = await client.IndexedDeviceStore.open();
    await devices.stage(wrapper, operationId); await devices.commit(operationId, { workspaceId, accountId, deviceId, operationId, credentialGeneration: '1' }); devices.close();
    const pins = await client.IndexedPairingStore.open(location.origin); await client.seedActivationPin(pins, genesis, receipt); pins.close();
    window.clientRuntime = await client.openClient({ trustedServiceKeys }); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
  }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, wrapper: f.wrapper, operationId: f.operationId,
    genesis: f.genesis, receipt: f.receipt, trustedServiceKeys: f.trustedServiceKeys, password });
}
async function reopenOwner(page: Page, f: Fixture) {
  await page.reload(); await page.waitForFunction(() => !!window.ukda);
  await page.evaluate(async ({ workspaceId, accountId, deviceId, trustedServiceKeys, password }) => {
    window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
  }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, trustedServiceKeys: f.trustedServiceKeys, password });
}

test('CP06: encrypted custom roles survive lost replies, support edits/retirement, and enrol members with fixed grant snapshots', async ({ page, browser }) => {
  const f = await authenticationFixture(), roleId = randomUUID(), operationId = randomUUID(), privateLabel = 'Private research coordinators', updatedLabel = 'Private iteration reviewers';
  const recipientContext = await browser.newContext({ ignoreHTTPSErrors: true }), recipient = await recipientContext.newPage(), requests: string[] = [];
  page.on('request', (request) => { if (request.method() === 'POST') requests.push(request.postData() ?? ''); });
  try {
    await ownerPage(page, f);
    let stagedReplyLost = false;
    await page.route('**/v1/auth/roles/stage', async (route) => { const response = await route.fetch(); expect(response.status()).toBe(200); stagedReplyLost = true; await route.abort('failed'); }, { times: 1 });
    const failedStage = await page.evaluate(async ({ roleId, operationId, privateLabel }) => {
      try { await window.clientRuntime.roles.create({ roleId, operationId, displayName: privateLabel, permissions: ['read_project', 'comment'] }); return { failed: false, error: null }; }
      catch (error) { return { failed: true, error: error instanceof Error ? { name: error.name, message: error.message, stack: error.stack } : { message: String(error) } }; }
    }, { roleId, operationId, privateLabel });
    expect(failedStage.failed, JSON.stringify(failedStage.error)).toBe(true);
    expect(stagedReplyLost, JSON.stringify(failedStage.error)).toBe(true);
    await reopenOwner(page, f);
    let commitReplyLost = false;
    await page.route('**/v1/auth/roles/finalize', async (route) => { const response = await route.fetch(); expect(response.status()).toBe(200); commitReplyLost = true; await route.abort('failed'); }, { times: 1 });
    expect(await page.evaluate(async (operationId) => { try { await window.clientRuntime.roles.resume(operationId); return false; } catch { return true; } }, operationId)).toBe(true);
    expect(commitReplyLost).toBe(true); await reopenOwner(page, f);
    const resumed = await page.evaluate((operationId) => window.clientRuntime.roles.resume(operationId), operationId);
    expect(resumed.state).toBe('completed'); expect(resumed.receipt.roleRevision).toBe('1');
    const rows = await page.evaluate(async () => {
      const result = []; let afterRoleId: string | undefined;
      do { const page = await window.clientRuntime.roles.list({ limit: 2, ...(afterRoleId ? { afterRoleId } : {}) }); result.push(...page.roles); afterRoleId = page.nextRoleId ?? undefined; } while (afterRoleId);
      return result;
    });
    expect(rows).toHaveLength(5); expect(rows.find((role) => role.id === roleId)?.displayName).toBe(privateLabel);
    const updated = await page.evaluate(({ roleId, updatedLabel }) => window.clientRuntime.roles.update({ roleId, displayName: updatedLabel, permissions: ['read_project'] }), { roleId, updatedLabel });
    expect(updated.receipt.roleRevision).toBe('2');
    const retired = await page.evaluate((roleId) => window.clientRuntime.roles.retire({ roleId }), roleId);
    expect(retired.receipt.roleRevision).toBe('3');
    const retiredRow = await page.evaluate(async (roleId) => (await window.clientRuntime.roles.list()).roles.find((role) => role.id === roleId), roleId);
    expect(retiredRow).toMatchObject({ displayName: updatedLabel, state: 'retired', permissions: ['read_project'] });
    expect(await page.evaluate(async (roleId) => { try { await window.clientRuntime.roles.update({ roleId, displayName: 'Forbidden builtin', permissions: ['read_project'] }); return false; } catch { return true; } }, f.genesis.body.roles.viewer)).toBe(true);

    const joinedRole = await page.evaluate(() => window.clientRuntime.roles.create({ displayName: 'Private QA members', permissions: ['read_project', 'comment'] }));
    const accountId = randomUUID(), invitationId = randomUUID(), memberPassword = 'Custom role member password 514682';
    const invitation = await page.evaluate(({ roleId, accountId, operationId }) => window.clientRuntime.enrolments.issueJoin({
      kind: 'join_member', roleId, accountId, operationId, projectIds: [], displayName: 'Private pending QA profile' }),
    { roleId: joinedRole.roleId, accountId, operationId: invitationId });
    await recipient.goto(origin); await recipient.waitForFunction(() => !!window.ukda);
    const begun = await recipient.evaluate(async ({ workspaceId, code, genesisFingerprint, trustedServiceKeys }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); return window.clientRuntime.enrolments.beginJoin({ workspaceId, code, genesisFingerprint });
    }, { workspaceId: f.workspaceId, code: invitation.code, genesisFingerprint: f.receipt.genesisFingerprint, trustedServiceKeys: f.trustedServiceKeys });
    await page.evaluate((operation) => window.clientRuntime.enrolments.claim(operation!), begun.operation);
    const prepared = await recipient.evaluate(async ({ localId, password }) => {
      const prepared = await window.clientRuntime.enrolments.prepare(localId, password, password, 'Private QA member');
      await window.clientRuntime.enrolments.confirmRecipient(localId, prepared.fingerprint!); return prepared;
    }, { localId: begun.localId, password: memberPassword });
    await page.evaluate(({ operation, fingerprint }) => window.clientRuntime.enrolments.approve(operation!, fingerprint!), prepared);
    const joined = await recipient.evaluate(async ({ localId, workspaceId, accountId, password }) => {
      const pending = await window.clientRuntime.enrolments.resume(localId); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId: pending.deviceId! }, password);
      return window.clientRuntime.enrolments.resume(localId);
    }, { localId: begun.localId, workspaceId: f.workspaceId, accountId, password: memberPassword });
    expect(joined.access).toBe('content_ready');
    await page.evaluate((roleId) => window.clientRuntime.roles.update({ roleId, displayName: 'Private QA future members', permissions: ['read_project'] }), joinedRole.roleId);
    expect(await page.evaluate(async (roleId) => { try { await window.clientRuntime.roles.retire({ roleId }); return false; } catch { return true; } }, joinedRole.roleId)).toBe(true);
    expect(requests.some((body) => body.includes(privateLabel) || body.includes(updatedLabel) || body.includes('Private QA'))).toBe(false);
  } finally {
    await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), recipient.evaluate(() => window.clientRuntime?.close())]);
    await recipientContext.close(); await f.close();
  }
});

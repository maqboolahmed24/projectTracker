import { expect, test } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, origin, password } from './authentication-fixture.js';
import type { ClientRuntime } from '../../src/client/runtime.js';

declare global { interface Window { clientRuntime: ClientRuntime } }
const newPassword = 'A replacement recovery password 902435';

for (const restricted of [false, true]) test(`CP05: Owner phrase recovery survives reload and restores keys with ${restricted ? 'restricted' : 'active'} entitlement`, async ({ page }) => {
  const f = await authenticationFixture(restricted), operationId = randomUUID(); f.recoveryOperations.add(operationId);
  const kit = { origin, workspaceId: f.workspaceId, accountId: f.accountId, genesisFingerprint: f.receipt.genesisFingerprint };
  try {
    await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
    const prepared = await page.evaluate(async ({ kit, phrase, operationId, newPassword, trustedServiceKeys }) => {
      const client = window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      await client.recoveries.beginPhrase(kit, operationId);
      await client.recoveries.provePhrase(operationId, phrase);
      const newPhrase = await window.ukda.recovery.newOwnerPhrase(), positions = [2, 11, 21];
      const result = await client.recoveries.prepare(operationId, newPassword, newPassword,
        { phrase: newPhrase, positions, answers: positions.map((index) => newPhrase.split(' ')[index]!) });
      let mismatchRejected = false;
      try { await client.recoveries.confirmRecipient(operationId, '0'.repeat(64)); } catch { mismatchRejected = true; }
      return { ...result, newPhrase, mismatchRejected };
    }, { kit, phrase: f.phrase, operationId, newPassword, trustedServiceKeys: f.trustedServiceKeys });
    expect(prepared.mismatchRejected).toBe(true); expect(prepared.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    // The persisted draft contains only public protocol material and the encrypted local wrapper.
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const committed = await page.evaluate(async ({ operationId, fingerprint, phrase, newPassword, trustedServiceKeys }) => {
      const client = window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      await client.recoveries.confirmRecipient(operationId, fingerprint!, newPassword);
      await client.recoveries.approvePhrase(operationId, fingerprint!, phrase);
      return client.recoveries.resume(operationId);
    }, { operationId, fingerprint: prepared.fingerprint, phrase: f.phrase, newPassword, trustedServiceKeys: f.trustedServiceKeys });
    expect(committed.access).toBe('login_required'); expect(committed.deviceId).not.toBe(f.deviceId);
    // An HTTP completion reply is not sufficient to expose keys: login plus fresh device proof is required.
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const delivered = await page.evaluate(async ({ kit, operationId, newPassword, oldPassword, oldDeviceId, newPhrase, trustedServiceKeys }) => {
      const client = window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      let oldPasswordRejected = false;
      try { await client.auth.login({ workspaceId: kit.workspaceId, accountId: kit.accountId, deviceId: oldDeviceId }, oldPassword); }
      catch { oldPasswordRejected = true; }
      const pending = await client.recoveries.resume(operationId);
      const loggedIn = await client.auth.login({ workspaceId: kit.workspaceId, accountId: kit.accountId, deviceId: pending.deviceId! }, newPassword);
      const result = await client.recoveries.resume(operationId, newPhrase);
      return { access: result.access, approved: loggedIn.session.accessLevel, credentialGeneration: loggedIn.session.credentialGeneration,
        oldPasswordRejected, protectedStatus: (await fetch(`/v1/workspaces/${kit.workspaceId}/projects`)).status };
    }, { kit, operationId, newPassword, oldPassword: password, oldDeviceId: f.deviceId, newPhrase: prepared.newPhrase, trustedServiceKeys: f.trustedServiceKeys });
    expect(delivered).toEqual({ access: 'content_ready', approved: 'device_approved', credentialGeneration: '2', oldPasswordRejected: true, protectedStatus: 200 });
  } finally { await page.evaluate(() => window.clientRuntime?.close()).catch(() => {}); await f.close(); }
});

test('CP05: short RESET requires full Owner approval and a fresh replacement-phrase kit across two browsers', async ({ page, browser }) => {
  const f = await authenticationFixture(), resetId = randomUUID(); f.recoveryOperations.add(resetId);
  const recipientContext = await browser.newContext({ ignoreHTTPSErrors: true }), recipient = await recipientContext.newPage();
  try {
    await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
    const issued = await page.evaluate(async ({ workspaceId, accountId, deviceId, wrapper, operationId, genesis, receipt, resetId, password, trustedServiceKeys }) => {
      const c = window.ukda, devices = await c.IndexedDeviceStore.open();
      await devices.stage(wrapper, operationId); await devices.commit(operationId, { workspaceId, accountId, deviceId, operationId, credentialGeneration: '1' }); devices.close();
      const pins = await c.IndexedPairingStore.open(location.origin); await c.seedActivationPin(pins, genesis, receipt); pins.close();
      const client = window.clientRuntime = await c.openClient({ trustedServiceKeys });
      await client.auth.login({ workspaceId, accountId, deviceId }, password);
      return client.recoveries.issueReset(accountId, resetId);
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, wrapper: f.wrapper, operationId: f.operationId,
      genesis: f.genesis, receipt: f.receipt, resetId, password, trustedServiceKeys: f.trustedServiceKeys });
    await recipient.goto(origin); await recipient.waitForFunction(() => !!window.ukda);
    const begun = await recipient.evaluate(async ({ workspaceId, code, trustedServiceKeys }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      return window.clientRuntime.recoveries.beginReset(workspaceId, code);
    }, { workspaceId: f.workspaceId, code: issued.code, trustedServiceKeys: f.trustedServiceKeys });
    expect(begun.operation?.operationId).toBe(resetId);
    await page.evaluate((reference) => window.clientRuntime.recoveries.claim(reference!), begun.operation);
    const prepared = await recipient.evaluate(async ({ localId, newPassword }) => {
      const newPhrase = await window.ukda.recovery.newOwnerPhrase(), positions = [1, 10, 23];
      const prepared = await window.clientRuntime.recoveries.prepare(localId, newPassword, newPassword,
        { phrase: newPhrase, positions, answers: positions.map((index) => newPhrase.split(' ')[index]!) });
      await window.clientRuntime.recoveries.confirmRecipient(localId, prepared.fingerprint!);
      return { ...prepared, newPhrase };
    }, { localId: begun.localId, newPassword });
    await page.evaluate(({ operation, fingerprint }) => window.clientRuntime.recoveries.approve(operation!, fingerprint!), prepared);
    const result = await recipient.evaluate(async ({ localId, newPassword, newPhrase, workspaceId, accountId }) => {
      const client = window.clientRuntime, progress = await client.recoveries.resume(localId);
      await client.auth.login({ workspaceId, accountId, deviceId: progress.deviceId! }, newPassword);
      return client.recoveries.resume(localId, newPhrase);
    }, { localId: begun.localId, newPassword, newPhrase: prepared.newPhrase, workspaceId: f.workspaceId, accountId: f.accountId });
    expect(result.access).toBe('content_ready'); expect(result.deviceId).not.toBe(f.deviceId);
    expect(await page.evaluate(async (workspaceId) => (await fetch(`/v1/workspaces/${workspaceId}/projects`)).status, f.workspaceId)).toBe(401);
  } finally {
    await page.evaluate(() => window.clientRuntime?.close()).catch(() => {});
    await recipient.evaluate(() => window.clientRuntime?.close()).catch(() => {});
    await recipientContext.close(); await f.close();
  }
});

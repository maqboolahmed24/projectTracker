import { expect, test, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, origin, password } from './authentication-fixture.js';
import type { ClientRuntime } from '../../src/client/runtime.js';

declare global { interface Window { clientRuntime: ClientRuntime } }
type Fixture = Awaited<ReturnType<typeof authenticationFixture>>;
const otherPassword = 'A retained access password 539820';
async function ownerPage(page: Page, f: Fixture) {
  await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
  await page.evaluate(async ({ workspaceId, accountId, deviceId, wrapper, operationId, genesis, receipt, trustedServiceKeys, password }) => {
    const c = window.ukda, devices = await c.IndexedDeviceStore.open(); await devices.stage(wrapper, operationId);
    await devices.commit(operationId, { workspaceId, accountId, deviceId, operationId, credentialGeneration: '1' }); devices.close();
    const pins = await c.IndexedPairingStore.open(location.origin); await c.seedActivationPin(pins, genesis, receipt); pins.close();
    window.clientRuntime = await c.openClient({ trustedServiceKeys }); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
    await window.clientRuntime.accessChanges.refreshKeys();
  }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, wrapper: f.wrapper, operationId: f.operationId,
    genesis: f.genesis, receipt: f.receipt, trustedServiceKeys: f.trustedServiceKeys, password });
}
async function enrol(owner: Page, recipient: Page, f: Fixture, asOwner = false, projectIds: string[] = []) {
  const accountId = randomUUID(), operationId = randomUUID();
  const issued = await owner.evaluate(({ accountId, operationId, roleId, asOwner, projectIds }) => window.clientRuntime.enrolments.issueJoin({
    accountId, operationId, kind: asOwner ? 'join_owner' : 'join_member', roleId, projectIds, displayName: 'Private pending access profile' }),
  { accountId, operationId, roleId: asOwner ? f.genesis.body.roles.owner : f.genesis.body.roles.member, asOwner, projectIds });
  await recipient.goto(origin); await recipient.waitForFunction(() => !!window.ukda);
  const begun = await recipient.evaluate(async ({ workspaceId, code, genesisFingerprint, trustedServiceKeys }) => {
    window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); return window.clientRuntime.enrolments.beginJoin({ workspaceId, code, genesisFingerprint });
  }, { workspaceId: f.workspaceId, code: issued.code, genesisFingerprint: f.receipt.genesisFingerprint, trustedServiceKeys: f.trustedServiceKeys });
  await owner.evaluate((operation) => window.clientRuntime.enrolments.claim(operation!), begun.operation);
  const prepared = await recipient.evaluate(async ({ localId, password, asOwner }) => {
    const phrase = asOwner ? await window.ukda.recovery.newOwnerPhrase() : null, positions = [1, 11, 20];
    const result = await window.clientRuntime.enrolments.prepare(localId, password, password, 'Private confirmed access profile',
      phrase ? { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) } : undefined);
    await window.clientRuntime.enrolments.confirmRecipient(localId, result.fingerprint!); return { ...result, phrase };
  }, { localId: begun.localId, password: otherPassword, asOwner });
  await owner.evaluate(({ operation, fingerprint }) => window.clientRuntime.enrolments.approve(operation!, fingerprint!), prepared);
  const result = await recipient.evaluate(async ({ localId, workspaceId, accountId, password, phrase }) => {
    const pending = await window.clientRuntime.enrolments.resume(localId); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId: pending.deviceId! }, password);
    const result = await window.clientRuntime.enrolments.resume(localId, phrase ?? undefined); return { deviceId: result.deviceId!, access: result.access };
  }, { localId: begun.localId, workspaceId: f.workspaceId, accountId, password: otherPassword, phrase: prepared.phrase });
  expect(result.access).toBe('content_ready'); return { accountId, deviceId: result.deviceId, phrase: prepared.phrase };
}

test('CP06: explicit project removal rotates future keys, suspension blocks access, and ordinary reactivation needs fresh pairing', async ({ page, browser }) => {
  const f = await authenticationFixture(), context = await browser.newContext({ ignoreHTTPSErrors: true }), member = await context.newPage();
  try {
    // Signed scope provisioning is a CP06 security fixture; project-creation product flows remain CP07.
    const project = await f.provisionProject(); await ownerPage(page, f); const target = await enrol(page, member, f, false, [project.projectId]);
    expect((await member.evaluate(() => window.clientRuntime.accessChanges.refreshKeys())).scopeCount).toBe(2);
    const removed = await page.evaluate(({ accountId, roleId }) => window.clientRuntime.accessChanges.setAccess({ accountId, roleId, projectIds: [] }),
      { accountId: target.accountId, roleId: f.genesis.body.roles.member });
    expect(removed.state).toBe('completed'); expect(removed.receipt.transition.body.plan.rotations).toEqual([{ scope: 'project', scopeId: project.projectId, previousEpoch: '1', nextEpoch: '2' }]);
    const retained = await member.evaluate(async ({ workspaceId, accountId, deviceId, password, projectId }) => {
      let oldSessionRejected = false; try { await window.clientRuntime.auth.refresh(); } catch { oldSessionRejected = true; }
      const login = await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
      const current = await window.clientRuntime.accessChanges.refreshKeys(); const response = await fetch(`/v1/workspaces/${workspaceId}/projects/${projectId}`);
      return { oldSessionRejected, sessionGeneration: login.session.sessionGeneration, scopeCount: current.scopeCount, projectStatus: response.status };
    }, { workspaceId: f.workspaceId, ...target, password: otherPassword, projectId: project.projectId });
    expect(retained.oldSessionRejected).toBe(true); expect(retained.sessionGeneration).toBe('2'); expect(retained.scopeCount).toBe(1); expect([403, 404]).toContain(retained.projectStatus);
    const suspended = await page.evaluate((accountId) => window.clientRuntime.accessChanges.suspend({ accountId }), target.accountId);
    expect(suspended.receipt.transition.body.plan.rotations).toEqual([{ scope: 'workspace', scopeId: f.workspaceId, previousEpoch: '1', nextEpoch: '2' }]);
    expect(await member.evaluate(async ({ workspaceId, accountId, password }) => { try { await window.clientRuntime.auth.login({ workspaceId, accountId }, password); return false; } catch { return true; } },
      { workspaceId: f.workspaceId, accountId: target.accountId, password: otherPassword })).toBe(true);
    await page.evaluate(({ accountId, roleId }) => window.clientRuntime.accessChanges.reactivateMember({ accountId, roleId, projectIds: [] }),
      { accountId: target.accountId, roleId: f.genesis.body.roles.member });
    const pending = await member.evaluate(async ({ workspaceId, accountId, password }) => {
      const login = await window.clientRuntime.auth.login({ workspaceId, accountId }, password); const paired = await window.clientRuntime.pairing.begin();
      return { ...paired, access: login.session.accessLevel };
    }, { workspaceId: f.workspaceId, accountId: target.accountId, password: otherPassword });
    expect(pending.access).toBe('restricted');
    const claimed = await page.evaluate((operationId) => window.clientRuntime.pairing.claim(operationId), pending.operationId);
    await member.evaluate(({ operationId, fingerprint }) => window.clientRuntime.pairing.confirmRecipient(operationId, fingerprint!), claimed);
    await page.evaluate(async ({ operationId, fingerprint }) => { await window.clientRuntime.pairing.confirmApprover(operationId, fingerprint!); await window.clientRuntime.pairing.approve(operationId); }, claimed);
    expect((await member.evaluate((operationId) => window.clientRuntime.pairing.resumeRecipient(operationId), pending.operationId)).state).toBe('content_ready');
    expect((await member.evaluate(() => window.clientRuntime.accessChanges.refreshKeys())).scopeCount).toBe(1);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), member.evaluate(() => window.clientRuntime?.close())]); await context.close(); await f.close(); }
});

test('CP06: demoting an Owner preserves the password/device but invalidates its old recovery phrase and Owner authority', async ({ page, browser }) => {
  const f = await authenticationFixture(), context = await browser.newContext({ ignoreHTTPSErrors: true }), second = await context.newPage();
  try {
    await ownerPage(page, f); const target = await enrol(page, second, f, true);
    const result = await page.evaluate(({ accountId, roleId }) => window.clientRuntime.accessChanges.demoteOwner({ accountId, roleId, projectIds: [] }),
      { accountId: target.accountId, roleId: f.genesis.body.roles.member });
    expect(result.receipt.transition.body.plan.nextCustodyEpoch).toBe('2'); expect(result.receipt.transition.body.plan.rotations).toEqual([]);
    const member = await second.evaluate(async ({ workspaceId, accountId, deviceId, password }) => {
      const login = await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password); const keys = await window.clientRuntime.accessChanges.refreshKeys();
      let ownerRejected = false; try { await window.clientRuntime.roles.create({ displayName: 'Forbidden demoted role', permissions: ['read_project'] }); } catch { ownerRejected = true; }
      return { credentialGeneration: login.session.credentialGeneration, sessionGeneration: login.session.sessionGeneration, deviceId: login.session.deviceId, keys, ownerRejected };
    }, { workspaceId: f.workspaceId, ...target, password: otherPassword });
    expect(member).toMatchObject({ credentialGeneration: '1', sessionGeneration: '2', deviceId: target.deviceId, ownerRejected: true }); expect(member.keys.complete).toBe(true);
    const operationId = randomUUID(); f.recoveryOperations.add(operationId);
    expect(await second.evaluate(async ({ kit, operationId, phrase }) => {
      try { await window.clientRuntime.recoveries.beginPhrase(kit, operationId); await window.clientRuntime.recoveries.provePhrase(operationId, phrase!); return false; } catch { return true; }
    }, { kit: { origin, workspaceId: f.workspaceId, accountId: target.accountId, genesisFingerprint: f.receipt.genesisFingerprint }, operationId, phrase: target.phrase })).toBe(true);
    expect(await page.evaluate(async (accountId) => { try { await window.clientRuntime.accessChanges.remove({ accountId }); return false; } catch { return true; } }, f.accountId)).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), second.evaluate(() => window.clientRuntime?.close())]); await context.close(); await f.close(); }
});

test('CP06: self-removal survives a lost reply without an authenticated session and remaining Owner refreshes rotated custody', async ({ page, browser }) => {
  const f = await authenticationFixture(), context = await browser.newContext({ ignoreHTTPSErrors: true }), successor = await context.newPage(), operationId = randomUUID();
  try {
    await ownerPage(page, f); const target = await enrol(page, successor, f, true); let replyLost = false;
    await page.route('**/v1/auth/access-change/finalize', async (route) => { const response = await route.fetch(); expect(response.status()).toBe(200); replyLost = true; await route.abort('failed'); }, { times: 1 });
    const failed = await page.evaluate(async ({ accountId, operationId }) => { try { await window.clientRuntime.accessChanges.remove({ accountId, operationId }); return { failed: false }; }
      catch (error) { return { failed: true, error: error instanceof Error ? { name: error.name, message: error.message, stack: error.stack } : String(error) }; } }, { accountId: f.accountId, operationId });
    expect(failed.failed).toBe(true); expect(replyLost, JSON.stringify(failed.error)).toBe(true);
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const receipt = await page.evaluate(async ({ operationId, trustedServiceKeys }) => { window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      const result = await window.clientRuntime.accessChanges.resume(operationId); return { result, current: window.clientRuntime.auth.current() }; }, { operationId, trustedServiceKeys: f.trustedServiceKeys });
    expect(receipt.result.state).toBe('completed'); expect(receipt.result.access).toBe('revoked'); expect(receipt.current).toBeUndefined();
    const updated = await successor.evaluate(async () => { const refresh = await window.clientRuntime.accessChanges.refreshKeys();
      const role = await window.clientRuntime.roles.create({ displayName: 'Private successor role', permissions: ['read_project'] }); return { refresh, role }; });
    expect(updated.refresh.custodyEpoch).toBe('2'); expect(updated.role.state).toBe('completed');
    await successor.reload(); await successor.waitForFunction(() => !!window.ukda);
    const reloaded = await successor.evaluate(async ({ workspaceId, accountId, deviceId, password, trustedServiceKeys }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password); return window.clientRuntime.accessChanges.refreshKeys();
    }, { workspaceId: f.workspaceId, ...target, password: otherPassword, trustedServiceKeys: f.trustedServiceKeys });
    expect(reloaded.complete).toBe(true); expect(reloaded.custodyEpoch).toBe('2');
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), successor.evaluate(() => window.clientRuntime?.close())]); await context.close(); await f.close(); }
});

import { expect, test, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, origin, password } from './authentication-fixture.js';
import type { ClientRuntime } from '../../src/client/runtime.js';

declare global { interface Window { clientRuntime: ClientRuntime } }
type Fixture = Awaited<ReturnType<typeof authenticationFixture>>;
const otherPassword = 'A retained project password 539820';
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
    accountId, operationId, kind: asOwner ? 'join_owner' : 'join_member', roleId, projectIds, displayName: 'Private pending project profile' }),
  { accountId, operationId, roleId: asOwner ? f.genesis.body.roles.owner : f.genesis.body.roles.member, asOwner, projectIds });
  await recipient.goto(origin); await recipient.waitForFunction(() => !!window.ukda);
  const begun = await recipient.evaluate(async ({ workspaceId, code, genesisFingerprint, trustedServiceKeys }) => {
    window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); return window.clientRuntime.enrolments.beginJoin({ workspaceId, code, genesisFingerprint });
  }, { workspaceId: f.workspaceId, code: issued.code, genesisFingerprint: f.receipt.genesisFingerprint, trustedServiceKeys: f.trustedServiceKeys });
  await owner.evaluate((operation) => window.clientRuntime.enrolments.claim(operation!), begun.operation);
  const prepared = await recipient.evaluate(async ({ localId, password, asOwner }) => {
    const phrase = asOwner ? await window.ukda.recovery.newOwnerPhrase() : null, positions = [1, 11, 20];
    const result = await window.clientRuntime.enrolments.prepare(localId, password, password, 'Private confirmed project profile',
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

test('CP07: a name creates one Planned encrypted project with usable keys for both equal Owners and no automatic ordinary-member access', async ({ page, browser }) => {
  const f = await authenticationFixture(), otherContext = await browser.newContext({ ignoreHTTPSErrors: true }), second = await otherContext.newPage(),
    memberContext = await browser.newContext({ ignoreHTTPSErrors: true }), member = await memberContext.newPage();
  try {
    await ownerPage(page, f); await enrol(page, second, f, true); await enrol(page, member, f);
    const name = 'Private office relocation draft', uploads: string[] = [];
    page.on('request', (request) => { if (request.url().includes('/v1/work/projects/create/')) uploads.push(request.postData() ?? ''); });
    const created = await page.evaluate((name) => window.clientRuntime.projectCreation.create({ name }), name);
    expect(created.state).toBe('completed'); expect(created.receipt.projectId).toBe(created.projectId); expect(uploads.length).toBeGreaterThan(3);
    expect(uploads.every((value) => !value.includes(name))).toBe(true);
    const ownerView = await second.evaluate(async ({ workspaceId, projectId }) => {
      const keys = await window.clientRuntime.accessChanges.refreshKeys(), response = await fetch(`/v1/workspaces/${workspaceId}/projects/${projectId}`);
      return { keys, status: response.status, data: await response.json() };
    }, { workspaceId: f.workspaceId, projectId: created.projectId });
    expect(ownerView.keys.scopeCount).toBe(2); expect(ownerView.status).toBe(200);
    expect(ownerView.data.record).toMatchObject({ id: created.projectId, state: 'planned', archived: false, manager_profile_id: null, team_id: null, phase_label: 'wave', revision: '1' });
    expect(JSON.stringify(ownerView.data)).not.toContain(name);
    const memberView = await member.evaluate(async ({ workspaceId, projectId }) => ({ keys: await window.clientRuntime.accessChanges.refreshKeys(),
      status: (await fetch(`/v1/workspaces/${workspaceId}/projects/${projectId}`)).status }), { workspaceId: f.workspaceId, projectId: created.projectId });
    expect(memberView.keys.scopeCount).toBe(1); expect([403, 404]).toContain(memberView.status);
    const secondCreated = await second.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'A second Owner project' }));
    expect(secondCreated.state).toBe('completed'); expect(secondCreated.projectId).not.toBe(created.projectId);
    expect((await page.evaluate(() => window.clientRuntime.accessChanges.refreshKeys())).scopeCount).toBe(3);
  } finally {
    await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), second.evaluate(() => window.clientRuntime?.close()), member.evaluate(() => window.clientRuntime?.close())]);
    await otherContext.close(); await memberContext.close(); await f.close();
  }
});

test('CP07: a lost project finalization reply resumes after reload exactly once and Forget clears its encrypted draft', async ({ page }) => {
  const f = await authenticationFixture(), operationId = randomUUID(), projectId = randomUUID();
  try {
    await ownerPage(page, f); let replyLost = false;
    await page.route('**/v1/work/projects/create/finalize', async (route) => { const response = await route.fetch(); expect(response.status()).toBe(200); replyLost = true; await route.abort('failed'); }, { times: 1 });
    const failed = await page.evaluate(async ({ operationId, projectId }) => { try { await window.clientRuntime.projectCreation.create({ name: 'Private one-time project', operationId, projectId }); return false; } catch { return true; } }, { operationId, projectId });
    expect(failed).toBe(true); expect(replyLost).toBe(true);
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const resumed = await page.evaluate(async ({ workspaceId, accountId, deviceId, password, trustedServiceKeys, operationId }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
      const pending = await window.clientRuntime.projectCreation.pending(), result = await window.clientRuntime.projectCreation.resume(operationId),
        replay = await window.clientRuntime.projectCreation.resume(operationId), list = await (await fetch(`/v1/workspaces/${workspaceId}/projects`)).json();
      return { pending, result, replay, list };
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, password, trustedServiceKeys: f.trustedServiceKeys, operationId });
    expect(resumed.pending).toEqual([{ workspaceId: f.workspaceId, operationId, projectId }]); expect(resumed.result.state).toBe('completed');
    expect(resumed.result.receipt).toEqual(resumed.replay.receipt); expect(resumed.list.records.map((record: { id: string }) => record.id)).toEqual([projectId]);
    expect(await page.evaluate(async ({ workspaceId, accountId, deviceId, operationId }) => {
      await window.clientRuntime.auth.forget({ workspaceId, accountId, deviceId });
      const store = await window.ukda.IndexedProjectCreateStore.open(location.origin); try { return await store.get(workspaceId, operationId) === undefined; } finally { store.close(); }
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, operationId })).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close())]); await f.close(); }
});

test('CP07: a restricted licence cannot create a project or upload an encrypted creation draft', async ({ page }) => {
  const f = await authenticationFixture(true);
  try {
    await ownerPage(page, f); let stageRequests = 0; page.on('request', (request) => { if (request.url().endsWith('/v1/work/projects/create/stage')) stageRequests++; });
    const result = await page.evaluate(async (workspaceId) => {
      let rejected = false; try { await window.clientRuntime.projectCreation.create({ name: 'Restricted creation rejected' }); } catch { rejected = true; }
      return { rejected, projects: await (await fetch(`/v1/workspaces/${workspaceId}/projects`)).json(), pending: await window.clientRuntime.projectCreation.pending() };
    }, f.workspaceId);
    expect(result.rejected).toBe(true); expect(stageRequests).toBe(0); expect(result.pending).toEqual([]); expect(result.projects.records).toEqual([]);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close())]); await f.close(); }
});

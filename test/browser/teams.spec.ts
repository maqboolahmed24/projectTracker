import { expect, test, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, origin, password } from './authentication-fixture.js';
import type { ClientRuntime } from '../../src/client/runtime.js';

declare global { interface Window { clientRuntime: ClientRuntime } }
type Fixture = Awaited<ReturnType<typeof authenticationFixture>>;
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
test('CP07: a real Worker creates, edits and decrypts workspace teams without exposing names or granting project access', async ({ page }) => {
  const f = await authenticationFixture();
  try {
    await ownerPage(page, f); const privateName = 'Private delivery team', privateDescription = 'Private working agreement', uploads: string[] = [];
    page.on('request', (request) => { if (request.url().includes('/v1/work/teams/')) uploads.push(request.postData() ?? ''); });
    const result = await page.evaluate(async ({ accountId, name, description, workspaceId }) => {
      const created = await window.clientRuntime.teams.create({ name, memberIds: [accountId] });
      const initial = await window.clientRuntime.teams.list();
      const updated = await window.clientRuntime.teams.edit({ teamId: created.teamId, expectedRevision: initial.records.find(team=>team.teamId===created.teamId)!.revision, name: `${name} revised`, description, memberIds: [] });
      const final = await window.clientRuntime.teams.list();
      const history = await window.clientRuntime.teams.history(created.teamId);
      const projects = await (await fetch(`/v1/workspaces/${workspaceId}/projects`)).json();
      return { created, initial, updated, final, history, projects };
    }, { accountId: f.accountId, workspaceId: f.workspaceId, name: privateName, description: privateDescription });
    expect(result.created.state).toBe('completed'); expect(result.initial.records).toEqual([{ teamId: result.created.teamId, revision: '1', name: privateName, description: '', memberIds: [f.accountId] }]);
    expect(result.updated.receipt.revision).toBe('2'); expect(result.final.records).toEqual([{ teamId: result.created.teamId, revision: '2', name: `${privateName} revised`, description: privateDescription, memberIds: [] }]);
    expect(result.history.records.map((change) => change.revision)).toEqual(['1', '2']);
    expect(result.history.records[0]!.before).toBeNull();
    expect(result.history.records[1]!.before).toEqual({ name: privateName, description: '', memberIds: [f.accountId] });
    expect(result.history.records[1]!.after).toEqual({ name: `${privateName} revised`, description: privateDescription, memberIds: [] });
    for (const change of result.history.records) {
      expect(change.actorId).toBe(f.accountId); expect(change.deviceId).toBe(f.deviceId);
      expect(change.signedAt).toEqual(expect.any(String)); expect(change.serverRecordedAt).toEqual(expect.any(String));
    }
    expect(result.projects.records).toEqual([]); expect(uploads.length).toBeGreaterThan(4);
    expect(uploads.every((text) => !text.includes(privateName) && !text.includes(privateDescription))).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close())]); await f.close(); }
});

test('CP07: a lost team-save reply resumes after reload and Forget removes its encrypted operation', async ({ page }) => {
  const f = await authenticationFixture(), operationId = randomUUID(), teamId = randomUUID();
  try {
    await ownerPage(page, f); let lost = false;
    await page.route('**/v1/work/teams/save', async (route) => { const response = await route.fetch(); expect(response.status()).toBe(200); lost = true; await route.abort('failed'); }, { times: 1 });
    expect(await page.evaluate(async ({ operationId, teamId }) => { try { await window.clientRuntime.teams.create({ operationId, teamId, name: 'Private saved team' }); return false; } catch { return true; } }, { operationId, teamId })).toBe(true);
    expect(lost).toBe(true); await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const result = await page.evaluate(async ({ workspaceId, accountId, deviceId, password, trustedServiceKeys, operationId }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
      const pending = await window.clientRuntime.teams.pending(), resumed = await window.clientRuntime.teams.resume(operationId), replay = await window.clientRuntime.teams.resume(operationId), list = await window.clientRuntime.teams.list();
      await window.clientRuntime.auth.forget({ workspaceId, accountId, deviceId });
      const store = await window.ukda.IndexedTeamsStore.open(location.origin); const forgotten = await store.get(workspaceId, operationId) === undefined; store.close();
      return { pending, resumed, replay, list, forgotten };
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, password, trustedServiceKeys: f.trustedServiceKeys, operationId });
    expect(result.pending).toEqual([{ workspaceId: f.workspaceId, operationId, teamId }]); expect(result.resumed.receipt).toEqual(result.replay.receipt);
    expect(result.list.records).toEqual([{ teamId, revision: '1', name: 'Private saved team', description: '', memberIds: [] }]); expect(result.forgotten).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close())]); await f.close(); }
});

import { expect, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, origin, password } from './authentication-fixture.js';
import type { ClientRuntime } from '../../src/client/runtime.js';

declare global { interface Window { clientRuntime: ClientRuntime } }
type Fixture = Awaited<ReturnType<typeof authenticationFixture>>;
export const otherPassword = 'A retained project password 539820';
export async function ownerPage(page: Page, f: Fixture) {
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
export async function enrol(owner: Page, recipient: Page, f: Fixture, asOwner = false, projectIds: string[] = []) {
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



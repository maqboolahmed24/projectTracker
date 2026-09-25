import { expect, test, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, origin, password } from './authentication-fixture.js';
import type { ClientRuntime } from '../../src/client/runtime.js';

declare global { interface Window { clientRuntime: ClientRuntime } }
const memberPassword = 'An invited member password 519003';
type Fixture = Awaited<ReturnType<typeof authenticationFixture>>;

async function ownerPage(page: Page, f: Fixture) {
  await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
  await page.evaluate(async ({ workspaceId, accountId, deviceId, wrapper, operationId, genesis, receipt, trustedServiceKeys, password }) => {
    const c = window.ukda, devices = await c.IndexedDeviceStore.open();
    await devices.stage(wrapper, operationId);
    await devices.commit(operationId, { workspaceId, accountId, deviceId, operationId, credentialGeneration: '1' }); devices.close();
    const pins = await c.IndexedPairingStore.open(location.origin); await c.seedActivationPin(pins, genesis, receipt); pins.close();
    window.clientRuntime = await c.openClient({ trustedServiceKeys });
    await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
  }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, wrapper: f.wrapper, operationId: f.operationId,
    genesis: f.genesis, receipt: f.receipt, trustedServiceKeys: f.trustedServiceKeys, password });
}

test('CP06: member JOIN survives a lost commit reply and browser restart, then promotion retains its password and device', async ({ page, browser }) => {
  const f = await authenticationFixture(), accountId = randomUUID(), operationId = randomUUID();
  const recipientContext = await browser.newContext({ ignoreHTTPSErrors: true }), recipient = await recipientContext.newPage();
  try {
    await ownerPage(page, f);
    const issued = await page.evaluate(({ accountId, operationId, roleId }) => window.clientRuntime.enrolments.issueJoin({
      accountId, operationId, kind: 'join_member', roleId, projectIds: [], displayName: 'Invited member' }),
    { accountId, operationId, roleId: f.genesis.body.roles.member });
    await recipient.goto(origin); await recipient.waitForFunction(() => !!window.ukda);
    const begun = await recipient.evaluate(async ({ workspaceId, code, genesisFingerprint, trustedServiceKeys }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      return window.clientRuntime.enrolments.beginJoin({ workspaceId, code, genesisFingerprint });
    }, { workspaceId: f.workspaceId, code: issued.code, genesisFingerprint: f.receipt.genesisFingerprint, trustedServiceKeys: f.trustedServiceKeys });
    expect(begun.operation?.operationId).toBe(operationId);
    await page.evaluate((reference) => window.clientRuntime.enrolments.claim(reference!), begun.operation);
    const prepared = await recipient.evaluate(async ({ localId, password }) => {
      const client = window.clientRuntime;
      const prepared = await client.enrolments.prepare(localId, password, password, 'Confirmed member');
      let wrongFingerprintRejected = false;
      try { await client.enrolments.confirmRecipient(localId, '0'.repeat(64)); } catch { wrongFingerprintRejected = true; }
      await client.enrolments.confirmRecipient(localId, prepared.fingerprint!);
      return { ...prepared, wrongFingerprintRejected };
    }, { localId: begun.localId, password: memberPassword });
    expect(prepared.wrongFingerprintRejected).toBe(true);
    let lostResponse = false;
    await page.route('**/v1/auth/enrolment/finalize', async (route) => {
      const response = await route.fetch(); expect(response.status()).toBe(200);
      lostResponse = true; await route.abort('failed');
    }, { times: 1 });
    await page.evaluate(async ({ operation, fingerprint }) => {
      try { await window.clientRuntime.enrolments.approve(operation!, fingerprint!); } catch { /* server committed; target must recover durable receipt */ }
    }, prepared);
    expect(lostResponse).toBe(true);
    await recipient.reload(); await recipient.waitForFunction(() => !!window.ukda);
    const joined = await recipient.evaluate(async ({ localId, workspaceId, accountId, password, trustedServiceKeys }) => {
      const client = window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      const pending = await client.enrolments.resume(localId);
      const login = await client.auth.login({ workspaceId, accountId, deviceId: pending.deviceId! }, password);
      const delivered = await client.enrolments.resume(localId);
      return { ...delivered, initialAccess: pending.access, credentialGeneration: login.session.credentialGeneration,
        projectStatus: (await fetch(`/v1/workspaces/${workspaceId}/projects`)).status,
        remembered: await client.remembered.list() };
    }, { localId: begun.localId, workspaceId: f.workspaceId, accountId, password: memberPassword, trustedServiceKeys: f.trustedServiceKeys });
    expect(joined.initialAccess).toBe('login_required'); expect(joined.access).toBe('content_ready');
    expect(joined.credentialGeneration).toBe('1'); expect(joined.projectStatus).toBe(200);
    expect(joined.remembered).toEqual(expect.arrayContaining([expect.objectContaining({ accountId, displayName: 'Confirmed member' })]));

    const promotion = { workspaceId: f.workspaceId, operationId: randomUUID() };
    await page.evaluate(({ accountId, operationId }) => window.clientRuntime.enrolments.beginPromotion(accountId, operationId), { accountId, operationId: promotion.operationId });
    const target = await recipient.evaluate(({ reference, password }) => window.clientRuntime.enrolments.claimPromotion(reference, password), { reference: promotion, password: memberPassword });
    await page.evaluate((reference) => window.clientRuntime.enrolments.claim(reference), promotion);
    const preparedPromotion = await recipient.evaluate(async ({ localId, password }) => {
      const phrase = await window.ukda.recovery.newOwnerPhrase(), positions = [2, 12, 20];
      const prepared = await window.clientRuntime.enrolments.preparePromotion(localId, password,
        { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) });
      await window.clientRuntime.enrolments.confirmRecipient(localId, prepared.fingerprint!);
      return { ...prepared, phrase };
    }, { localId: target.localId, password: memberPassword });
    await page.evaluate(({ operation, fingerprint }) => window.clientRuntime.enrolments.approve(operation!, fingerprint!), preparedPromotion);
    const promoted = await recipient.evaluate(async ({ localId, phrase, workspaceId, accountId, password }) => {
      const client = window.clientRuntime, pending = await client.enrolments.resume(localId);
      const login = await client.auth.login({ workspaceId, accountId, deviceId: pending.deviceId! }, password);
      const result = await client.enrolments.resume(localId, phrase);
      return { ...result, credentialGeneration: login.session.credentialGeneration, sessionGeneration: login.session.sessionGeneration };
    }, { localId: target.localId, phrase: preparedPromotion.phrase, workspaceId: f.workspaceId, accountId, password: memberPassword });
    expect(promoted.access).toBe('content_ready'); expect(promoted.deviceId).toBe(joined.deviceId);
    expect(promoted.credentialGeneration).toBe('1'); expect(promoted.sessionGeneration).toBe('2');
    const newInvitation = await recipient.evaluate(({ roleId, accountId, operationId }) => window.clientRuntime.enrolments.issueJoin({
      accountId, operationId, kind: 'join_member', roleId, projectIds: [], displayName: 'Promoted Owner invitation' }),
    { roleId: f.genesis.body.roles.viewer, accountId: randomUUID(), operationId: randomUUID() });
    expect(newInvitation.code).toMatch(/^JOIN-/);
  } finally {
    await page.evaluate(() => window.clientRuntime?.close()).catch(() => {});
    await recipient.evaluate(() => window.clientRuntime?.close()).catch(() => {});
    await recipientContext.close(); await f.close();
  }
});

test('CP06: an equal Owner can invite and approve; another Owner can take over staged JOIN after recipient reload', async ({ page, browser }) => {
  test.setTimeout(45000);
  const f = await authenticationFixture(), accountId = randomUUID(), operationId = randomUUID();
  const secondContext = await browser.newContext({ ignoreHTTPSErrors: true }), second = await secondContext.newPage();
  const memberContext = await browser.newContext({ ignoreHTTPSErrors: true }), member = await memberContext.newPage();
  try {
    await ownerPage(page, f);
    const issued = await page.evaluate(({ accountId, operationId, roleId }) => window.clientRuntime.enrolments.issueJoin({
      accountId, operationId, kind: 'join_owner', roleId, projectIds: [], displayName: 'Equal second Owner' }),
    { accountId, operationId, roleId: f.genesis.body.roles.owner });
    await second.goto(origin); await second.waitForFunction(() => !!window.ukda);
    const begun = await second.evaluate(async ({ workspaceId, code, genesisFingerprint, trustedServiceKeys }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      return window.clientRuntime.enrolments.beginJoin({ workspaceId, code, genesisFingerprint });
    }, { workspaceId: f.workspaceId, code: issued.code, genesisFingerprint: f.receipt.genesisFingerprint, trustedServiceKeys: f.trustedServiceKeys });
    await page.evaluate((reference) => window.clientRuntime.enrolments.claim(reference!), begun.operation);
    const prepared = await second.evaluate(async ({ localId, password }) => {
      const phrase = await window.ukda.recovery.newOwnerPhrase(), positions = [1, 11, 22];
      const result = await window.clientRuntime.enrolments.prepare(localId, password, password, 'Equal second Owner',
        { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) });
      await window.clientRuntime.enrolments.confirmRecipient(localId, result.fingerprint!);
      return { ...result, phrase };
    }, { localId: begun.localId, password: memberPassword });
    expect(prepared.phrase).not.toBe(f.phrase);
    await page.evaluate(({ operation, fingerprint }) => window.clientRuntime.enrolments.approve(operation!, fingerprint!), prepared);
    const result = await second.evaluate(async ({ localId, workspaceId, accountId, password, phrase, roleId, newAccount, newOperation }) => {
      const client = window.clientRuntime, pending = await client.enrolments.resume(localId);
      await client.auth.login({ workspaceId, accountId, deviceId: pending.deviceId! }, password);
      const delivered = await client.enrolments.resume(localId, phrase);
      const invitation = await client.enrolments.issueJoin({ accountId: newAccount, operationId: newOperation, kind: 'join_member',
        roleId, projectIds: [], displayName: 'Second Owner invitation' });
      return { access: delivered.access, deviceId: delivered.deviceId, invitation };
    }, { localId: begun.localId, workspaceId: f.workspaceId, accountId, password: memberPassword, phrase: prepared.phrase,
      roleId: f.genesis.body.roles.member, newAccount: randomUUID(), newOperation: randomUUID() });
    expect(result.access).toBe('content_ready'); expect(result.deviceId).not.toBe(f.deviceId);
    expect(result.invitation.code).toMatch(/^JOIN-/); expect(result.invitation.workspaceId).toBe(f.workspaceId);
    await member.goto(origin); await member.waitForFunction(() => !!window.ukda);
    const pendingMember = await member.evaluate(async ({ workspaceId, code, genesisFingerprint, trustedServiceKeys }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      return window.clientRuntime.enrolments.beginJoin({ workspaceId, code, genesisFingerprint });
    }, { workspaceId: f.workspaceId, code: result.invitation.code, genesisFingerprint: f.receipt.genesisFingerprint,
      trustedServiceKeys: f.trustedServiceKeys });
    await second.evaluate((reference) => window.clientRuntime.enrolments.claim(reference!), pendingMember.operation);
    const firstDraft = await member.evaluate(async ({ localId, password }) => {
      const prepared = await window.clientRuntime.enrolments.prepare(localId, password, password, 'Takeover member');
      await window.clientRuntime.enrolments.confirmRecipient(localId, prepared.fingerprint!); return prepared;
    }, { localId: pendingMember.localId, password: memberPassword });
    // Staging succeeds, but this approver loses connectivity before commit.
    let staged = false;
    await second.route('**/v1/auth/enrolment/finalize', async (route) => { staged = true; await route.abort('failed'); }, { times: 1 });
    await second.evaluate(async ({ operation, fingerprint }) => {
      try { await window.clientRuntime.enrolments.approve(operation!, fingerprint!); } catch { /* another current Owner may take over */ }
    }, firstDraft);
    expect(staged).toBe(true);
    await member.reload(); await member.waitForFunction(() => !!window.ukda);
    await page.evaluate((reference) => window.clientRuntime.enrolments.claim(reference!), pendingMember.operation);
    const replacement = await member.evaluate(async ({ localId, password, trustedServiceKeys }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      const prepared = await window.clientRuntime.enrolments.prepare(localId, password, password, 'Takeover member');
      await window.clientRuntime.enrolments.confirmRecipient(localId, prepared.fingerprint!); return prepared;
    }, { localId: pendingMember.localId, password: memberPassword, trustedServiceKeys: f.trustedServiceKeys });
    expect(replacement.deviceId).toBe(firstDraft.deviceId); expect(replacement.fingerprint).not.toBe(firstDraft.fingerprint);
    await page.evaluate(({ operation, fingerprint }) => window.clientRuntime.enrolments.approve(operation!, fingerprint!), replacement);
    const completed = await member.evaluate(async ({ localId, workspaceId, accountId, password }) => {
      const client = window.clientRuntime, pending = await client.enrolments.resume(localId);
      await client.auth.login({ workspaceId, accountId, deviceId: pending.deviceId! }, password);
      return client.enrolments.resume(localId);
    }, { localId: pendingMember.localId, workspaceId: f.workspaceId, accountId: result.invitation.accountId, password: memberPassword });
    expect(completed.access).toBe('content_ready'); expect(completed.deviceId).toBe(firstDraft.deviceId);
    // The original Owner still has its original unlocked device context. It must
    // remain able to approve replacement devices and RESET after adding an Owner.
    const paired = await second.evaluate(async ({ workspaceId, accountId, password, trustedServiceKeys }) => {
      await window.clientRuntime.close();
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      await window.clientRuntime.auth.login({ workspaceId, accountId }, password);
      return window.clientRuntime.pairing.begin();
    }, { workspaceId: f.workspaceId, accountId: result.invitation.accountId, password: memberPassword, trustedServiceKeys: f.trustedServiceKeys });
    const pairClaim = await page.evaluate((operationId) => window.clientRuntime.pairing.claim(operationId), paired.operationId);
    await second.evaluate(({ operationId, fingerprint }) => window.clientRuntime.pairing.confirmRecipient(operationId, fingerprint!), pairClaim);
    await page.evaluate(async ({ operationId, fingerprint }) => {
      await window.clientRuntime.pairing.confirmApprover(operationId, fingerprint!);
      await window.clientRuntime.pairing.approve(operationId);
    }, pairClaim);
    expect((await second.evaluate((operationId) => window.clientRuntime.pairing.resumeRecipient(operationId), paired.operationId)).state).toBe('content_ready');
    const resetId = randomUUID(); f.recoveryOperations.add(resetId);
    const reset = await page.evaluate(({ accountId, resetId }) => window.clientRuntime.recoveries.issueReset(accountId, resetId),
      { accountId: result.invitation.accountId, resetId });
    const resetBegun = await member.evaluate(({ workspaceId, code }) => window.clientRuntime.recoveries.beginReset(workspaceId, code), reset);
    await page.evaluate((reference) => window.clientRuntime.recoveries.claim(reference!), resetBegun.operation);
    const resetPassword = `${memberPassword} replacement`;
    const resetPrepared = await member.evaluate(async ({ localId, password }) => {
      const prepared = await window.clientRuntime.recoveries.prepare(localId, password, password);
      await window.clientRuntime.recoveries.confirmRecipient(localId, prepared.fingerprint!); return prepared;
    }, { localId: resetBegun.localId, password: resetPassword });
    await page.evaluate(({ operation, fingerprint }) => window.clientRuntime.recoveries.approve(operation!, fingerprint!), resetPrepared);
    const recovered = await member.evaluate(async ({ localId, workspaceId, accountId, password }) => {
      const client = window.clientRuntime, pending = await client.recoveries.resume(localId);
      const loggedIn = await client.auth.login({ workspaceId, accountId, deviceId: pending.deviceId! }, password);
      const delivered = await client.recoveries.resume(localId);
      return { access: delivered.access, credentialGeneration: loggedIn.session.credentialGeneration };
    }, { localId: resetBegun.localId, workspaceId: f.workspaceId, accountId: result.invitation.accountId, password: resetPassword });
    expect(recovered).toEqual({ access: 'content_ready', credentialGeneration: '2' });
  } finally {
    await page.evaluate(() => window.clientRuntime?.close()).catch(() => {});
    await second.evaluate(() => window.clientRuntime?.close()).catch(() => {});
    await member.evaluate(() => window.clientRuntime?.close()).catch(() => {});
    await memberContext.close(); await secondContext.close(); await f.close();
  }
});

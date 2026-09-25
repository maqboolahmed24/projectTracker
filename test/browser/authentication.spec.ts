import { expect, test } from '@playwright/test';
import { randomUUID, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import pg from 'pg';
import * as opaqueLibrary from '@serenity-kit/opaque';
import { loadConfig } from '../../src/config.js';
import { createDatabases, transaction } from '../../src/db.js';
import { buildApp } from '../../src/app.js';
import { AppError } from '../../src/errors.js';
import { ServiceSecrets } from '../../src/modules/identity/secrets.js';
import { OpaqueService } from '../../src/modules/identity/opaque.js';
import { ActivationService } from '../../src/modules/identity/activation.js';
import { AuthenticationService } from '../../src/modules/identity/authentication.js';
import { SessionService, readSessionCookie } from '../../src/modules/identity/sessions.js';
import { RequestBudgets } from '../../src/modules/identity/budgets.js';
import { registerAuthenticationRoutes } from '../../src/modules/identity/auth-routes.js';
import { registerSecurityRoutes } from '../../src/modules/identity/security-routes.js';
import { PairingService } from '../../src/modules/identity/pairing.js';
import { PasswordChangeService } from '../../src/modules/identity/password-change.js';
import { EntitlementOperations } from '../../src/modules/identity/entitlements.js';
import { startRegistration, finishRegistration, startLogin, finishLogin } from '../../src/client/opaque.js';
import { prepareOwnerActivation } from '../../src/client/activation.js';
import { newOwnerPhrase } from '../../src/client/recovery.js';
import type { AuthController } from '../../src/client/auth-controller.js';
import type { IndexedDeviceStore } from '../../src/client/device-store.js';
import type { RememberedProfiles } from '../../src/client/remembered-profiles.js';
import type { PasswordChangeController, IndexedPasswordChangeStore } from '../../src/client/password-change.js';
import type * as Client from '../../src/client/index.js';
import type { ClientRuntime } from '../../src/client/runtime.js';

declare global { interface Window { ukda: typeof Client; journey: {
  auth: AuthController; devices: IndexedDeviceStore; remembered: RememberedProfiles; cleared: boolean;
} } }
declare global { interface Window { passwordJourney: { changes: IndexedPasswordChangeStore; controller: PasswordChangeController } } }
declare global { interface Window { clientRuntime: ClientRuntime } }
import { authenticationFixture as fixture, origin, password } from './authentication-fixture.js';


test('CP04: real browser cookies and controller enforce approved-device login, logout and forget', async ({ page, context }) => {
  const f = await fixture();
  try {
    await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
    const reference = { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId };
    await page.evaluate(async ({ reference, wrapper, operationId }) => {
      const client = window.ukda;
      const devices = await client.IndexedDeviceStore.open('browser-auth-device');
      await devices.stage(wrapper, operationId);
      await devices.commit(operationId, { ...reference, operationId, credentialGeneration: '1' });
      const remembered = await client.RememberedProfiles.open(location.origin, 'browser-auth-cards');
      await remembered.remember({ ...reference, displayName: 'Browser owner' });
      const auth = new client.AuthController(new client.HttpAuthTransport(location.origin), new client.AuthWorkerClient(), devices, remembered);
      window.journey = { auth, devices, remembered, cleared: false };
      auth.onClear(() => { window.journey.cleared = true; });
    }, { reference, wrapper: f.wrapper, operationId: f.operationId });
    const loggedIn = await page.evaluate(async ({ reference, password }) => {
      const state = await window.journey.auth.login(reference, password);
      return { access: state.session.accessLevel, local: state.localAccess, protectedStatus: (await fetch(`/v1/workspaces/${reference.workspaceId}/projects`)).status,
        scriptCanReadSession: document.cookie.includes('__Host-ukda_session') };
    }, { reference, password });
    expect(loggedIn).toEqual({ access: 'device_approved', local: 'unlocked', protectedStatus: 200, scriptCanReadSession: false });
    const cookie = (await context.cookies()).find((entry) => entry.name === '__Host-ukda_session');
    expect(cookie ? { secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite, path: cookie.path } : null)
      .toEqual({ secure: true, httpOnly: true, sameSite: 'Lax', path: '/' });
    const loggedOut = await page.evaluate(async (reference) => {
      window.journey.cleared = false;
      await window.journey.auth.logout();
      return { cleared: window.journey.cleared, current: window.journey.auth.current() === undefined,
        cards: (await window.journey.remembered.list()).length, wrapper: !!await window.journey.devices.getActive(reference.workspaceId, reference.accountId, reference.deviceId),
        protectedStatus: (await fetch(`/v1/workspaces/${reference.workspaceId}/projects`)).status };
    }, reference);
    expect(loggedOut).toEqual({ cleared: true, current: true, cards: 1, wrapper: true, protectedStatus: 401 });
    expect((await context.cookies()).some((entry) => entry.name === '__Host-ukda_session')).toBe(false);
    const forgotten = await page.evaluate(async (reference) => {
      await window.journey.auth.forget(reference);
      const result = { cards: (await window.journey.remembered.list()).length,
        wrapper: !!await window.journey.devices.getActive(reference.workspaceId, reference.accountId, reference.deviceId) };
      window.journey.auth.worker.close(); window.journey.devices.close(); window.journey.remembered.close();
      return result;
    }, reference);
    expect(forgotten).toEqual({ cards: 0, wrapper: false });
  } finally { await f.close(); }
});

test('CP04: password-change response loss survives a browser restart and preserves the current device', async ({ page }) => {
  const f = await fixture(), operationId = randomUUID();
  f.passwordOperations.add(operationId);
  const reference = { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId };
  const replacement = 'A new browser password after interruption 7402';
  try {
    await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
    const interrupted = await page.evaluate(async ({ reference, wrapper, activationOperation, operationId, password, replacement }) => {
      const client = window.ukda;
      const devices = await client.IndexedDeviceStore.open('browser-password-devices');
      await devices.stage(wrapper, activationOperation);
      await devices.commit(activationOperation, { ...reference, operationId: activationOperation, credentialGeneration: '1' });
      const remembered = await client.RememberedProfiles.open(location.origin, 'browser-password-cards');
      await remembered.remember({ ...reference, displayName: 'Browser owner' });
      const auth = new client.AuthController(new client.HttpAuthTransport(location.origin), new client.AuthWorkerClient(), devices, remembered);
      window.journey = { auth, devices, remembered, cleared: false };
      auth.onClear(() => { window.journey.cleared = true; });
      await auth.login(reference, password);
      const changes = await client.IndexedPasswordChangeStore.open('browser-password-changes');
      let loseResponse = true;
      const transport = new client.HttpPasswordChangeTransport({ origin: location.origin, csrfToken: () => auth.current()?.session.csrfToken,
        fetcher: async (...args) => {
          const response = await globalThis.fetch(...args);
          if (String(args[0]).endsWith('/finalize') && loseResponse) { loseResponse = false; await response.text(); throw new Error('Synthetic response loss'); }
          return response;
        } });
      const controller = new client.PasswordChangeController({ transport, changes, devices, worker: auth.worker });
      controller.attachAuthLifecycle(auth); window.passwordJourney = { changes, controller };
      await controller.begin(reference.workspaceId, operationId);
      await controller.prepare(operationId, replacement, replacement);
      window.journey.cleared = false;
      let failed = false;
      try { await controller.complete(operationId, replacement); } catch { failed = true; }
      const active = await devices.getActive(reference.workspaceId, reference.accountId, reference.deviceId);
      const staged = await devices.getStaged(operationId);
      return { failed, cleared: window.journey.cleared, loggedOut: auth.current() === undefined,
        activeGeneration: active?.header.credentialGeneration, pendingGeneration: staged?.header.credentialGeneration };
    }, { reference, wrapper: f.wrapper, activationOperation: f.operationId, operationId, password, replacement });
    expect(interrupted).toEqual({ failed: true, cleared: true, loggedOut: true, activeGeneration: '1', pendingGeneration: '2' });
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const recovered = await page.evaluate(async ({ reference, operationId, replacement }) => {
      const client = window.ukda;
      const devices = await client.IndexedDeviceStore.open('browser-password-devices');
      const remembered = await client.RememberedProfiles.open(location.origin, 'browser-password-cards');
      const auth = new client.AuthController(new client.HttpAuthTransport(location.origin), new client.AuthWorkerClient(), devices, remembered);
      const changes = await client.IndexedPasswordChangeStore.open('browser-password-changes');
      const controller = new client.PasswordChangeController({ changes, devices, worker: auth.worker,
        transport: new client.HttpPasswordChangeTransport({ origin: location.origin, csrfToken: () => auth.current()?.session.csrfToken }) });
      controller.attachAuthLifecycle(auth);
      const status = await controller.resume(operationId);
      const before = (await devices.getActive(reference.workspaceId, reference.accountId, reference.deviceId))?.header.credentialGeneration;
      const loggedIn = await auth.login(reference, replacement);
      await controller.resume(operationId, loggedIn.session);
      const active = (await devices.getActive(reference.workspaceId, reference.accountId, reference.deviceId))?.header.credentialGeneration;
      const protectedStatus = (await fetch(`/v1/workspaces/${reference.workspaceId}/projects`)).status;
      await auth.forget(reference);
      const forgotten = (await changes.get(operationId)) === undefined &&
        (await devices.getActive(reference.workspaceId, reference.accountId, reference.deviceId)) === undefined &&
        (await remembered.list()).length === 0;
      auth.worker.close(); devices.close(); remembered.close(); changes.close();
      return { state: status.state, before, active, access: loggedIn.session.accessLevel, generation: loggedIn.session.credentialGeneration,
        sameDevice: loggedIn.session.deviceId === reference.deviceId, protectedStatus, forgotten };
    }, { reference, operationId, replacement });
    expect(recovered).toEqual({ state: 'completed', before: '1', active: '2', access: 'device_approved', generation: '2',
      sameDevice: true, protectedStatus: 200, forgotten: true });
  } finally { await f.close(); }
});

for (const entitlement of ['active', 'restricted'] as const) test(`CP04: two isolated browser devices pair and recover a lost approval response with ${entitlement} entitlement`, async ({ page, browser }) => {
  const f = await fixture(entitlement === 'restricted');
  const second = await browser.newContext({ ignoreHTTPSErrors: true });
  const recipient = await second.newPage();
  const reference = { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId };
  try {
    await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
    await page.evaluate(async ({ reference, wrapper, operationId, genesis, receipt, password, trustedServiceKeys }) => {
      const devices = await window.ukda.IndexedDeviceStore.open();
      await devices.stage(wrapper, operationId);
      await devices.commit(operationId, { ...reference, operationId, credentialGeneration: '1' });
      devices.close();
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      await window.ukda.seedActivationPin(window.clientRuntime.pairing.store, genesis, receipt);
      await window.clientRuntime.auth.login(reference, password);
    }, { reference, wrapper: f.wrapper, operationId: f.operationId, genesis: f.genesis, receipt: f.receipt, password, trustedServiceKeys: f.trustedServiceKeys });
    await recipient.goto(origin); await recipient.waitForFunction(() => !!window.ukda);
    const started = await recipient.evaluate(async ({ workspaceId, accountId, password, trustedServiceKeys }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      const login = await window.clientRuntime.auth.login({ workspaceId, accountId }, password);
      const denied = (await fetch(`/v1/workspaces/${workspaceId}/projects`)).status;
      const pairing = await window.clientRuntime.pairing.begin();
      return { login: login.session.accessLevel, denied, pairing };
    }, { workspaceId: f.workspaceId, accountId: f.accountId, password, trustedServiceKeys: f.trustedServiceKeys });
    expect(started.login).toBe('restricted'); expect(started.denied).toBe(403);
    expect(started.pairing.state).toBe('waiting_approver');
    const operationId = started.pairing.operationId;
    const claimed = await page.evaluate((operationId) => window.clientRuntime.pairing.claim(operationId), operationId);
    expect(claimed.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    const wrongFingerprint = await recipient.evaluate(async (operationId) => {
      try { await window.clientRuntime.pairing.confirmRecipient(operationId, '0'.repeat(64)); return 'accepted'; }
      catch (error) { return (error as { code?: string }).code; }
    }, operationId);
    expect(wrongFingerprint).toBe('FINGERPRINT_MISMATCH');
    // The test driver acts as the independent full-fingerprint channel between the devices.
    await recipient.evaluate(({ operationId, fingerprint }) => window.clientRuntime.pairing.confirmRecipient(operationId, fingerprint),
      { operationId, fingerprint: claimed.fingerprint! });
    await page.evaluate(({ operationId, fingerprint }) => window.clientRuntime.pairing.confirmApprover(operationId, fingerprint),
      { operationId, fingerprint: claimed.fingerprint! });
    await page.route('**/v1/auth/pairing/commit', async (route) => {
      const committed = await route.fetch();
      expect(committed.status()).toBe(200);
      await route.abort('failed');
    }, { times: 1 });
    const ambiguous = await page.evaluate(async (operationId) => {
      try { await window.clientRuntime.pairing.approve(operationId); return false; } catch { return true; }
    }, operationId);
    expect(ambiguous).toBe(true);
    const receipt = await page.evaluate((operationId) => window.clientRuntime.pairing.approve(operationId), operationId);
    expect(receipt.deviceId).toBe(started.pairing.deviceId);
    const delivered = await recipient.evaluate(async (operationId) => {
      const ready = await window.clientRuntime.pairing.resumeRecipient(operationId, 'Browser owner on second device');
      const state = window.clientRuntime.auth.current()!;
      return { ready: ready.state, deviceId: ready.deviceId, access: state.session.accessLevel,
        protectedStatus: (await fetch(`/v1/workspaces/${state.session.workspaceId}/projects`)).status };
    }, operationId);
    expect(delivered).toEqual({ ready: 'content_ready', deviceId: started.pairing.deviceId, access: 'device_approved', protectedStatus: 200 });
    await recipient.reload(); await recipient.waitForFunction(() => !!window.ukda);
    const resumed = await recipient.evaluate(async ({ reference, operationId, password, trustedServiceKeys }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      await window.clientRuntime.auth.login(reference, password);
      return window.clientRuntime.pairing.resumeRecipient(operationId);
    }, { reference: { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: started.pairing.deviceId }, operationId, password, trustedServiceKeys: f.trustedServiceKeys });
    expect(resumed.state).toBe('content_ready');
  } finally {
    await page.evaluate(async () => { await window.clientRuntime?.close(); }).catch(() => {});
    await recipient.evaluate(async () => { await window.clientRuntime?.close(); }).catch(() => {});
    await second.close(); await f.close();
  }
});

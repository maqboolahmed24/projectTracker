import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as opaque from '@serenity-kit/opaque';
import { IDBFactory } from 'fake-indexeddb';
import { testAuthWorker } from './client-worker-driver.js';
import { AuthController, AuthClientError, HttpAuthTransport, type AuthTransport, type AuthSessionSnapshot } from '../src/client/auth-controller.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';
import { base64urlEncode, generateRecipientKeyPair, generateSigningKeyPair, randomKey, verifyObject } from '../src/shared/crypto.js';
import { IndexedDeviceStore, wrapDeviceBundle, unwrapDeviceBundle } from '../src/client/device-store.js';
import { RememberedProfiles } from '../src/client/remembered-profiles.js';
import type { AuthSessionResult, DeviceChallenge } from '../src/shared/auth.js';

const origin = 'https://ukda.example'; const password = 'Controller test password 91238725';
const code = (expected: AuthClientError['code']) => (error: unknown) => error instanceof AuthClientError && error.code === expected;
async function fixture() {
  const factory = new IDBFactory(); const devices = await IndexedDeviceStore.open(randomUUID(), factory);
  const remembered = await RememberedProfiles.open(origin, randomUUID(), factory); const worker = testAuthWorker(origin);
  const reference = { workspaceId: randomUUID(), accountId: randomUUID(), deviceId: randomUUID() };
  await opaque.ready;
  const opaqueServer = new OpaqueService({ serverSetup: opaque.server.createSetup(), setupId: 'auth-controller', serverIdentity: origin });
  const start = await worker.startRegistration(password);
  const registration = await opaqueServer.response(reference.workspaceId, reference.accountId, start.registrationRequest);
  let registered = await worker.finishRegistration({ password, clientRegistrationState: start.clientRegistrationState, ...registration });
  const signing = await generateSigningKeyPair(); const recipient = await generateRecipientKeyPair();
  const context = { ...reference, credentialGeneration: '1' };
  const wrapper = await wrapDeviceBundle(context, { signingPrivateKey: base64urlEncode(signing.privateKey), signingPublicKey: base64urlEncode(signing.publicKey),
    recipientPrivateKey: base64urlEncode(recipient.privateKey), recipientPublicKey: base64urlEncode(recipient.publicKey) }, registered.exportKey);
  const operationId = randomUUID(); await devices.stage(wrapper, operationId); await devices.commit(operationId, { ...context, operationId });
  await remembered.remember({ ...reference, displayName: 'Remembered controller profile' });
  signing.privateKey.fill(0); recipient.privateKey.fill(0);
  let generation = '1';
  let session: AuthSessionResult | undefined; let loginState: string | undefined; let loginId: string | undefined;
  let challenge: DeviceChallenge | undefined; let logoutCalls = 0; let failLogout = false; let holdSession: (() => Promise<void>) | undefined;
  const key = () => base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  function issue(approved = false, previous?: AuthSessionResult): AuthSessionResult {
    const now = new Date().toISOString();
    return { ...reference, sessionId: randomUUID(), deviceId: approved ? reference.deviceId : null, accessLevel: approved ? 'device_approved' : 'restricted',
      credentialGeneration: generation, sessionGeneration: generation, dataGeneration: '1', csrfToken: key(), authenticatedAt: previous?.authenticatedAt ?? now,
      idleExpiresAt: new Date(Date.now() + 1_800_000).toISOString(), absoluteExpiresAt: previous?.absoluteExpiresAt ?? new Date(Date.now() + 43_200_000).toISOString() };
  }
  const transport: AuthTransport = {
    origin,
    async loginStart(input) {
      assert.equal(input.workspaceId, reference.workspaceId); assert.equal(input.accountId, reference.accountId);
      const response = await opaqueServer.startLogin(reference.workspaceId, reference.accountId, registered.registrationRecord, input.startLoginRequest);
      loginState = response.serverLoginState; loginId = randomUUID();
      return { loginId, loginResponse: response.loginResponse, configuration: registration.configuration, expiresAt: new Date(Date.now() + 120_000).toISOString() };
    },
    async loginFinish(input) {
      assert.equal(input.loginId, loginId); assert.ok(loginState);
      await opaqueServer.finishLogin(reference.workspaceId, reference.accountId, loginState, input.finishLoginRequest);
      session = issue(); return session;
    },
    async session() {
      const snapshot = session ? { ...session, securityHead: 'a'.repeat(64), securityVersion: '1' } : undefined;
      await holdSession?.(); if (!snapshot) throw new AuthClientError('AUTH_REQUIRED'); return snapshot;
    },
    async challengeStart(csrf, deviceId) {
      assert.ok(session); assert.equal(csrf, session.csrfToken); assert.equal(deviceId, reference.deviceId);
      const issuedAt = Date.now();
      challenge = { version: 1, purpose: 'ukda.device-challenge.v1', origin, workspaceId: reference.workspaceId, accountId: reference.accountId,
        sessionId: session.sessionId, deviceId, keyGeneration: '1', credentialGeneration: generation, sessionGeneration: generation, dataGeneration: '1',
        securityVersion: '1', securityHead: 'a'.repeat(64), ownershipVersion: '1', custodyEpoch: '1', grantId: randomUUID(), grantGeneration: '1',
        signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey), ceremonyId: randomUUID(), nonce: key(),
        issuedAt: new Date(issuedAt).toISOString(), expiresAt: new Date(issuedAt + 120_000).toISOString() };
      return challenge;
    },
    async challengeFinish(csrf, proof) {
      assert.ok(session); assert.equal(csrf, session.csrfToken); assert.deepEqual(proof.body, challenge);
      assert.equal(await verifyObject(proof, signing.publicKey, 'ukda.device-challenge.v1'), true); session = issue(true, session); return session;
    },
    async reauthStart(csrf, request) { assert.equal(csrf, session?.csrfToken); return this.loginStart({ workspaceId: reference.workspaceId, accountId: reference.accountId, startLoginRequest: request }); },
    async reauthFinish(csrf, input) {
      assert.equal(csrf, session?.csrfToken); assert.ok(loginState); const previous = session!;
      await opaqueServer.finishLogin(reference.workspaceId, reference.accountId, loginState, input.finishLoginRequest);
      session = { ...issue(true, previous), authenticatedAt: new Date().toISOString() }; return session;
    },
    async logout(csrf) { logoutCalls++; assert.equal(csrf, session?.csrfToken); if (failLogout) throw new AuthClientError('UNAVAILABLE'); session = undefined; return { loggedOut: true }; },
  };
  const controller = new AuthController(transport, worker, devices, remembered);
  return { controller, worker, devices, remembered, reference, wrapper, operationId, transport,
    async passwordCommitWithoutLocalPromotion(nextPassword: string) {
      const bundle = await unwrapDeviceBundle(context, wrapper, registered.exportKey);
      const started = await worker.startRegistration(nextPassword);
      const response = await opaqueServer.response(reference.workspaceId, reference.accountId, started.registrationRequest);
      registered = await worker.finishRegistration({ password: nextPassword, clientRegistrationState: started.clientRegistrationState, ...response });
      generation = '2'; session = undefined;
      const candidateId = randomUUID(), candidate = await wrapDeviceBundle({ ...context, credentialGeneration: generation }, bundle, registered.exportKey);
      await devices.stage(candidate, candidateId); return { candidate, candidateId };
    },
    get logoutCalls() { return logoutCalls; }, set failLogout(value: boolean) { failLogout = value; },
    set holdSession(callback: typeof holdSession) { holdSession = callback; },
    close() { worker.close(); devices.close(); remembered.close(); } };
}

test('CP04: login separates password authentication from local device proof; logout retains cards and wipes caches', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const restricted = await f.controller.login({ workspaceId: f.reference.workspaceId, accountId: f.reference.accountId }, password);
  assert.equal(restricted.session.accessLevel, 'restricted'); assert.equal(restricted.localAccess, 'pairing_required');
  let leaked = false; await f.controller.withExportKey(async (key) => { leaked = typeof key !== 'string'; }); assert.equal(leaked, false);
  const approved = await f.controller.approveLocalDevice(f.reference.deviceId);
  assert.equal(approved.localAccess, 'unlocked'); assert.equal(approved.session.accessLevel, 'device_approved');
  await assert.rejects(f.controller.withExportKey(async () => {}), code('AUTH_REQUIRED'));
  const plaintext = new Uint8Array([3, 4, 5]); f.controller.onClear(() => plaintext.fill(0));
  await f.controller.logout(); assert.equal(f.logoutCalls, 1); assert.equal(f.controller.current(), undefined);
  assert.deepEqual(plaintext, new Uint8Array(3)); assert.equal((await f.remembered.list()).length, 1);
  assert.deepEqual(await f.devices.getStaged(f.operationId), f.wrapper);
  const loggedIn = await f.controller.login(f.reference, password); assert.equal(loggedIn.localAccess, 'unlocked');
  const deadline = loggedIn.session.absoluteExpiresAt;
  assert.equal((await f.controller.reauthenticate(password)).session.absoluteExpiresAt, deadline);
});

test('CP04: a missing local bundle remains restricted and is never reconstructed from server state', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  await f.devices.forget(f.reference.workspaceId, f.reference.accountId, f.reference.deviceId);
  const state = await f.controller.login(f.reference, password);
  assert.equal(state.localAccess, 'pairing_required'); assert.equal(state.session.accessLevel, 'restricted');
  assert.equal(await f.devices.getActive(f.reference.workspaceId, f.reference.accountId, f.reference.deviceId), undefined);
  await assert.rejects(f.controller.approveLocalDevice(f.reference.deviceId), code('LOCAL_DEVICE_UNAVAILABLE'));
});

test('CP06: promotion reauthentication exposes a transient export key only after proof and preserves the existing device wrapper', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  await f.controller.login(f.reference, password);
  let called = false;
  await assert.rejects(f.controller.reauthenticateWithExportKey('An incorrect password', async () => { called = true; }));
  assert.equal(called, false);
  const before = f.controller.current()!.session;
  const after = await f.controller.reauthenticateWithExportKey(password, async (exportKey, session) => {
    called = true;
    assert.equal(session.deviceId, f.reference.deviceId);
    const wrapper = await f.devices.getActive(f.reference.workspaceId, f.reference.accountId, f.reference.deviceId);
    assert.ok(wrapper);
    const bundle = await unwrapDeviceBundle({ ...f.reference, credentialGeneration: '1' }, wrapper, exportKey);
    assert.ok(bundle.signingPublicKey); assert.ok(bundle.recipientPublicKey);
  });
  assert.equal(called, true); assert.equal(after.session.credentialGeneration, before.credentialGeneration);
  assert.equal(after.session.absoluteExpiresAt, before.absoluteExpiresAt);
  assert.deepEqual(await f.devices.getActive(f.reference.workspaceId, f.reference.accountId, f.reference.deviceId), f.wrapper);
  await assert.rejects(f.controller.withExportKey(async () => {}), code('AUTH_REQUIRED'), 'Approved sessions do not retain the callback export key');
  const callbackFailure = new Error('Local promotion draft rejected');
  await assert.rejects(f.controller.reauthenticateWithExportKey(password, async () => { throw callbackFailure; }), (error) => error === callbackFailure);
  assert.equal(f.controller.current()?.localAccess, 'unlocked', 'A local draft failure does not undo successful server reauthentication');
  assert.deepEqual(await f.devices.getActive(f.reference.workspaceId, f.reference.accountId, f.reference.deviceId), f.wrapper);
});

test('CP04: failed server logout still clears local keys; explicit Forget removes card and encrypted wrappers', async (t) => {
  const f = await fixture(); t.after(() => f.close()); await f.controller.login(f.reference, password);
  let cleared = 0; f.controller.onClear(() => { cleared++; }); f.failLogout = true;
  await assert.rejects(f.controller.logout(), code('UNAVAILABLE'));
  assert.equal(f.controller.current(), undefined); assert.equal(cleared, 1);
  await assert.rejects(f.controller.withExportKey(async () => {}), code('AUTH_REQUIRED'));
  await assert.rejects(f.controller.forget(f.reference), code('UNAVAILABLE'));
  assert.equal((await f.remembered.list()).length, 0);
  assert.equal(await f.devices.getActive(f.reference.workspaceId, f.reference.accountId, f.reference.deviceId), undefined);
  f.failLogout = false; await f.controller.logout();
});

test('CP04: a late session response cannot restore local authenticated state after logout', async (t) => {
  const f = await fixture(); t.after(() => f.close()); await f.controller.login(f.reference, password);
  let release: (() => void) | undefined; let entered: (() => void) | undefined;
  const arrived = new Promise<void>((resolve) => { entered = resolve; });
  f.holdSession = () => new Promise<void>((resolve) => { release = resolve; entered!(); });
  const refreshing = f.controller.refresh(); const rejected = assert.rejects(refreshing, code('CANCELLED')); await arrived;
  const loggingOut = f.controller.logout(); f.holdSession = undefined; release!();
  await rejected; await loggingOut; assert.equal(f.controller.current(), undefined); assert.equal(f.logoutCalls, 1);
});

test('CP04: auth HTTP transport uses HttpOnly-cookie credentials and separate CSRF header without leaking errors', async () => {
  const requests: RequestInit[] = []; const csrf = base64urlEncode(await randomKey());
  const fetcher = (async (input: string | URL | Request, init?: RequestInit) => {
    requests.push(init!); const response = new Response(JSON.stringify({ loggedOut: true }), { headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: String(input) }); return response;
  }) as typeof fetch;
  const transport = new HttpAuthTransport(origin, fetcher); await transport.logout(csrf);
  assert.equal(requests[0]!.credentials, 'same-origin'); assert.equal(requests[0]!.redirect, 'error');
  assert.equal((requests[0]!.headers as Record<string, string>)['X-CSRF-Token'], csrf);
  assert.equal(String(requests[0]!.body).includes(csrf), false);
  const unavailable = new HttpAuthTransport(origin, (async (input) => {
    const response = new Response(JSON.stringify({ error: { code: 'AUTHENTICATION_UNAVAILABLE', message: 'private diagnostics' } }),
      { status: 503, headers: { 'content-type': 'application/json' } }); Object.defineProperty(response, 'url', { value: String(input) }); return response;
  }) as typeof fetch);
  await assert.rejects(unavailable.session(), (error: unknown) => error instanceof AuthClientError && error.code === 'UNAVAILABLE' && !error.message.includes('private'));
});


test('CP04: fresh password login proves an exact-generation staged wrapper without speculative promotion', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  const nextPassword = 'A replacement controller password 38172849';
  const pending = await f.passwordCommitWithoutLocalPromotion(nextPassword);
  const state = await f.controller.login(f.reference, nextPassword);
  assert.equal(state.localAccess, 'unlocked'); assert.equal(state.session.credentialGeneration, '2');
  assert.deepEqual(await f.devices.getActive(f.reference.workspaceId, f.reference.accountId, f.reference.deviceId), f.wrapper);
  assert.deepEqual(await f.devices.getStaged(pending.candidateId), pending.candidate);
});

test('CP04: Forget runs all encrypted-store cleanup hooks even when one cleanup fails', async (t) => {
  const f = await fixture(); t.after(() => f.close());
  let cleaned = false;
  f.controller.onForget(async () => { throw new Error('simulated blocked store'); });
  f.controller.onForget(async (reference) => { assert.deepEqual(reference, f.reference); cleaned = true; });
  await assert.rejects(f.controller.forget(f.reference), code('LOCAL_CLEANUP'));
  assert.equal(cleaned, true); assert.equal((await f.remembered.list()).length, 0);
  assert.equal(await f.devices.getStaged(f.operationId), undefined);
});

import { randomUUID } from 'node:crypto';
import { expect, test } from '@playwright/test';
import * as opaque from '@serenity-kit/opaque';
import { OpaqueService } from '../../src/modules/identity/opaque.js';
import type { AuthWorkerClient } from '../../src/client/auth-worker-client.js';
import type * as Client from '../../src/client/index.js';

declare global { interface Window { ukda: typeof Client; authTestWorker: AuthWorkerClient } }

test('CP04: a real HTTPS module worker authenticates with OPAQUE, signs locally, and forgets usable keys on logout', async ({ page, browser }, testInfo) => {
  await opaque.ready;
  const server = new OpaqueService({ serverSetup: opaque.server.createSetup(), setupId: 'browser-worker-test', serverIdentity: 'https://127.0.0.1:3555' });
  const workspaceId = randomUUID(), accountId = randomUUID();
  const password = 'An independent browser worker password 62485';
  await page.goto('/');
  await page.waitForFunction(() => !!window.ukda);
  const started = await page.evaluate(async (password) => {
    window.authTestWorker = new window.ukda.AuthWorkerClient();
    await window.authTestWorker.ready();
    return window.authTestWorker.startRegistration(password);
  }, password);
  const registrationResponse = await server.response(workspaceId, accountId, started.registrationRequest);
  const registration = await page.evaluate(async ({ password, started, registrationResponse }) => {
    const before = performance.now();
    const result = await window.authTestWorker.finishRegistration({ password, clientRegistrationState: started.clientRegistrationState,
      registrationResponse: registrationResponse.registrationResponse, configuration: registrationResponse.configuration });
    return { ...result, durationMs: Math.round(performance.now() - before) };
  }, { password, started, registrationResponse });
  const login = await page.evaluate((password) => window.authTestWorker.startLogin(password), password);
  const loginResponse = await server.startLogin(workspaceId, accountId, registration.registrationRecord, login.startLoginRequest);
  const finished = await page.evaluate(async ({ password, login, loginResponse, configuration, exportKey, workspaceId, accountId }) => {
    const before = performance.now();
    const result = await window.authTestWorker.finishLogin({ password, clientLoginState: login.clientLoginState,
      loginResponse: loginResponse.loginResponse, configuration });
    const durationMs = Math.round(performance.now() - before);
    const { cryptography: crypto, wrapDeviceBundle } = window.ukda;
    const signing = await crypto.generateSigningKeyPair(), recipient = await crypto.generateRecipientKeyPair();
    const context = { workspaceId, accountId, deviceId: globalThis.crypto.randomUUID(), credentialGeneration: '1' };
    const wrapper = await wrapDeviceBundle(context, { signingPublicKey: crypto.base64urlEncode(signing.publicKey),
      signingPrivateKey: crypto.base64urlEncode(signing.privateKey), recipientPublicKey: crypto.base64urlEncode(recipient.publicKey),
      recipientPrivateKey: crypto.base64urlEncode(recipient.privateKey) }, result.exportKey);
    const proofContext = { ...context, origin: location.origin, sessionId: globalThis.crypto.randomUUID(), keyGeneration: '1',
      sessionGeneration: '1', dataGeneration: '1', securityVersion: '1', securityHead: 'a'.repeat(64), ownershipVersion: '1',
      custodyEpoch: '1', grantId: globalThis.crypto.randomUUID(), grantGeneration: '1',
      signingPublicKey: crypto.base64urlEncode(signing.publicKey), recipientPublicKey: crypto.base64urlEncode(recipient.publicKey) };
    const challenge = { ...proofContext, version: 1 as const, purpose: 'ukda.device-challenge.v1' as const,
      ceremonyId: globalThis.crypto.randomUUID(), nonce: crypto.base64urlEncode(await crypto.randomKey()),
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() };
    signing.privateKey.fill(0); recipient.privateKey.fill(0);
    await window.authTestWorker.unlockDevice({ context, wrapper, exportKey: result.exportKey, proofContext });
    const proof = await window.authTestWorker.deviceProof(challenge);
    const verified = await crypto.verifyObject(proof, signing.publicKey, 'ukda.device-challenge.v1');
    window.authTestWorker.logout();
    let locked = false;
    try { await window.authTestWorker.deviceProof(challenge); } catch (error) { locked = (error as { code?: string }).code === 'LOCKED'; }
    window.authTestWorker.close();
    return { finishLoginRequest: result.finishLoginRequest, durationMs, sameExportKey: result.exportKey === exportKey,
      sessionKeyExposed: 'sessionKey' in result, verified, locked };
  }, { password, login, loginResponse: { loginResponse: loginResponse.loginResponse }, configuration: registrationResponse.configuration,
    exportKey: registration.exportKey, workspaceId, accountId });
  await server.finishLogin(workspaceId, accountId, loginResponse.serverLoginState, finished.finishLoginRequest);
  expect({ sameExportKey: finished.sameExportKey, sessionKeyExposed: finished.sessionKeyExposed, verified: finished.verified, locked: finished.locked })
    .toEqual({ sameExportKey: true, sessionKeyExposed: false, verified: true, locked: true });
  await testInfo.attach('runtime', { body: JSON.stringify({ engine: testInfo.project.name, version: browser.version(),
    registrationMs: registration.durationMs, loginMs: finished.durationMs }), contentType: 'application/json' });
});

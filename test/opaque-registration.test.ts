import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';
import * as opaque from '@serenity-kit/opaque';
import { ClientOpaqueError, finishLogin, finishRegistration, startLogin, startRegistration, validateNewPassword } from '../src/client/opaque.js';
import { AppError } from '../src/errors.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';

await opaque.ready;
const setup = opaque.server.createSetup();
const service = new OpaqueService({ serverSetup: setup, setupId: 'cp03-test-v1', serverIdentity: 'ukda:cp03-test' });
const password = 'Northern lamps above the quiet valley 47';

async function registration() {
  const workspaceId = randomUUID();
  const accountId = randomUUID();
  const started = await startRegistration(password);
  const response = await service.response(workspaceId, accountId, started.registrationRequest);
  const finished = await finishRegistration({ password, clientRegistrationState: started.clientRegistrationState,
    registrationResponse: response.registrationResponse, configuration: response.configuration });
  return { workspaceId, accountId, configuration: response.configuration, ...finished };
}

test('CP03: real OPAQUE registration and repeated login preserve the client export key', async () => {
  const registered = await registration();
  await service.validateRegistrationRecord(registered.workspaceId, registered.accountId, registered.registrationRecord);
  for (let attempt = 0; attempt < 2; attempt++) {
    const client = await startLogin(password);
    const server = await service.startLogin(registered.workspaceId, registered.accountId, registered.registrationRecord, client.startLoginRequest);
    const finished = await finishLogin({ password, clientLoginState: client.clientLoginState,
      loginResponse: server.loginResponse, configuration: registered.configuration });
    const verified = await service.finishLogin(registered.workspaceId, registered.accountId, server.serverLoginState, finished.finishLoginRequest);
    assert.equal(finished.exportKey, registered.exportKey);
    assert.equal(finished.sessionKey, verified.sessionKey);
    assert.notEqual(finished.exportKey, finished.sessionKey);
    assert.equal(finished.serverStaticPublicKey, registered.configuration.serverStaticPublicKey);
  }
  const restarted = new OpaqueService({ serverSetup: setup, setupId: 'cp03-test-v1', serverIdentity: 'ukda:cp03-test' });
  assert.deepEqual(await restarted.publicConfiguration(registered.workspaceId, registered.accountId), registered.configuration);
  assert.equal(JSON.stringify(service), '{}', 'private setup must not serialize');
  assert.equal(JSON.stringify(registered.configuration).includes(setup), false);
  assert.equal(registered.configuration.identifiers.client, `ukda:${registered.workspaceId}:${registered.accountId}`);
});

test('CP03: wrong password, account identity, and server identity cannot complete OPAQUE login', async () => {
  const registered = await registration();
  for (const scenario of ['password', 'account', 'server'] as const) {
    const suppliedPassword = scenario === 'password' ? 'Another unrelated test password 924' : password;
    const client = await startLogin(suppliedPassword);
    const server = await service.startLogin(registered.workspaceId, registered.accountId, registered.registrationRecord, client.startLoginRequest);
    const configuration = structuredClone(registered.configuration);
    if (scenario === 'account') configuration.identifiers.client = `ukda:${registered.workspaceId}:${randomUUID()}`;
    if (scenario === 'server') configuration.identifiers.server = 'ukda:different-deployment';
    await assert.rejects(finishLogin({ password: suppliedPassword, clientLoginState: client.clientLoginState,
      loginResponse: server.loginResponse, configuration }),
    (error: unknown) => error instanceof ClientOpaqueError && error.code === 'AUTHENTICATION');
  }
});

test('CP03: client checks the trusted server public-key pin and refuses profile downgrade', async () => {
  const registered = await registration();
  const client = await startLogin(password);
  const server = await service.startLogin(registered.workspaceId, registered.accountId, registered.registrationRecord, client.startLoginRequest);
  const configuration = { ...registered.configuration, serverStaticPublicKey: randomBytes(32).toString('base64url') };
  await assert.rejects(finishLogin({ password, clientLoginState: client.clientLoginState, loginResponse: server.loginResponse, configuration }),
    (error: unknown) => error instanceof ClientOpaqueError && error.code === 'SERVER_KEY');
  await assert.rejects(finishLogin({ password, clientLoginState: client.clientLoginState, loginResponse: server.loginResponse,
    configuration: { ...registered.configuration, configId: 'unsupported' as typeof registered.configuration.configId } }),
  (error: unknown) => error instanceof ClientOpaqueError && error.code === 'CONFIGURATION');
});

test('CP03: malformed registration/proof packets fail safely and unknown accounts use a fake record', async () => {
  const workspaceId = randomUUID();
  const accountId = randomUUID();
  for (const record of ['', 'not-a-record', 'AA', randomBytes(17).toString('base64url'), `${randomBytes(17).toString('base64url')}=`]) {
    await assert.rejects(service.validateRegistrationRecord(workspaceId, accountId, record),
      (error: unknown) => error instanceof AppError && error.code === 'INVALID_OPAQUE_RECORD' && !error.message.includes(record || 'private'));
  }
  await assert.rejects(service.response(workspaceId, accountId, 'synthetic-malformed-request'),
    (error: unknown) => error instanceof AppError && error.code === 'INVALID_OPAQUE_REQUEST');
  const started = await startLogin(password);
  const unknown = await service.startLogin(workspaceId, accountId, null, started.startLoginRequest);
  await assert.rejects(finishLogin({ password, clientLoginState: started.clientLoginState,
    loginResponse: unknown.loginResponse, configuration: await service.publicConfiguration(workspaceId, accountId) }),
  (error: unknown) => error instanceof ClientOpaqueError && error.code === 'AUTHENTICATION');
  await assert.rejects(service.finishLogin(workspaceId, accountId, unknown.serverLoginState, randomBytes(64).toString('base64url')),
    (error: unknown) => error instanceof AppError && error.code === 'AUTHENTICATION_FAILED');
});

test('CP03: new-password policy counts Unicode characters, preserves spaces, and applies a bounded local denylist', () => {
  for (const candidate of ['a'.repeat(14), 'a'.repeat(1025), 'passwordpassword', 'Correct Horse Battery Staple', `12345678901234\ud800`]) {
    assert.throws(() => validateNewPassword(candidate), (error: unknown) => error instanceof ClientOpaqueError && error.code === 'PASSWORD_POLICY');
  }
  for (const candidate of [' a phrase with spaces ', '界'.repeat(64), '🔑'.repeat(15), 'x'.repeat(1024)]) {
    assert.doesNotThrow(() => validateNewPassword(candidate));
  }
});

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import { Worker as ThreadWorker } from 'node:worker_threads';
import type { TestContext } from 'node:test';
import { IDBFactory } from 'fake-indexeddb';
import * as opaqueLibrary from '@serenity-kit/opaque';
import pg from 'pg';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { AuthWorkerClient, type AuthWorkerEndpoint } from '../src/client/auth-worker-client.js';
import { IndexedDeviceStore, unwrapDeviceBundle } from '../src/client/device-store.js';
import { finishLogin, finishRegistration, startLogin, startRegistration } from '../src/client/opaque.js';
import { IndexedPasswordChangeStore, PasswordChangeController, type PasswordChangeTransport } from '../src/client/password-change.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { loadConfig } from '../src/config.js';
import { createDatabases, transaction } from '../src/db.js';
import { ActivationService } from '../src/modules/identity/activation.js';
import { AuthenticationService } from '../src/modules/identity/authentication.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';
import { PasswordChangeService } from '../src/modules/identity/password-change.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { SessionService, type IssuedSession } from '../src/modules/identity/sessions.js';
import { digestObject } from '../src/shared/crypto.js';

export const oldPassword = 'Password change original fixture secret 756';
export const newPassword = 'Password change replacement fixture secret 982';
export const origin = 'http://localhost:3400';
type Hooks = NonNullable<ConstructorParameters<typeof PasswordChangeService>[0]['hooks']>;

export async function passwordFixture(t: TestContext) {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const applicationUrl = process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ?? local.ADMIN_DATABASE_URL;
  const controlUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(applicationUrl && controlUrl, 'Password-change tests require explicit fixture admin credentials');
  const admin = { application: new pg.Pool({ connectionString: applicationUrl }), control: new pg.Pool({ connectionString: controlUrl }) };
  const databases = createDatabases(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }));
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'cp04-change' });
  await opaqueLibrary.ready;
  const opaque = new OpaqueService({ serverSetup: opaqueLibrary.server.createSetup(), setupId: 'cp04-change', serverIdentity: origin });
  const sessions = new SessionService({ databases, secrets, origin });
  const authentication = new AuthenticationService({ databases, secrets, opaque, sessions, origin });
  const activation = new ActivationService({ databases, secrets, opaque, origin });
  const licence = await activation.reservations.issueLicence(), resumeToken = secrets.token();
  const reserved = await activation.reservations.reserve({ licenceKey: licence.licenceKey, resumeToken, operationId: randomUUID() });
  const workspaceId = reserved.workspaceId, accountId = reserved.accountId;
  const factory = new IDBFactory(), deviceStoreName = randomUUID(), changeStoreName = randomUUID();
  let devices = await IndexedDeviceStore.open(deviceStoreName, factory), changes = await IndexedPasswordChangeStore.open(changeStoreName, factory);
  const worker = new AuthWorkerClient({ origin, createWorker: () => {
    const thread = new ThreadWorker(new URL('./auth-worker-fixture.js', import.meta.url), { workerData: { origin } });
    const listeners = new Map<EventListener, (value: unknown) => void>();
    return {
      postMessage: (message) => thread.postMessage(message), terminate: () => { void thread.terminate(); },
      addEventListener(type, listener) { const fn = (value: unknown) => listener(type === 'message' ? new MessageEvent('message', { data: value }) : new Event(type)); listeners.set(listener, fn); thread.on(type, fn); },
      removeEventListener(type, listener) { const fn = listeners.get(listener); if (fn) thread.off(type, fn); listeners.delete(listener); },
    } satisfies AuthWorkerEndpoint;
  } });
  t.after(async () => {
    worker.close(); devices.close(); changes.close();
    try {
      await databases.application.query('SELECT graphile_worker.remove_job($1)', [`activation:${workspaceId}`]);
      await transaction(admin.application, async (client) => {
        await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.workspace:' || $1,0))", [workspaceId]);
        await client.query('DELETE FROM app.notifications WHERE workspace_id=$1', [workspaceId]);
        await client.query('DELETE FROM app.profiles WHERE workspace_id=$1', [workspaceId]);
        await client.query('DELETE FROM app.roles WHERE workspace_id=$1', [workspaceId]);
        await client.query('DELETE FROM app.workspaces WHERE workspace_id=$1', [workspaceId]);
      });
      await transaction(admin.control, async (client) => {
        await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
        await client.query('DELETE FROM security.auth_attempts WHERE workspace_id=$1', [workspaceId]);
        await client.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
        await client.query('DELETE FROM security.activation_attempts WHERE licence_id=$1', [licence.licenceId]);
        await client.query('DELETE FROM security.licences WHERE licence_id=$1', [licence.licenceId]);
      });
    } finally { await Promise.allSettled([databases.close(), admin.application.end(), admin.control.end()]); }
  });
  const started = await startRegistration(oldPassword);
  const registration = await activation.registration(reserved.activationId, resumeToken, { draftGeneration: '1', registrationRequest: started.registrationRequest });
  const registered = await finishRegistration({ password: oldPassword, clientRegistrationState: started.clientRegistrationState,
    registrationResponse: registration.registrationResponse, configuration: registration.configuration });
  const phrase = await newOwnerPhrase(), positions = [1, 9, 20];
  const prepared = await prepareOwnerActivation({ binding: { activationId: reserved.activationId, operationId: reserved.operationId, workspaceId, accountId,
    origin, reservationGeneration: '1', draftGeneration: '1' }, configuration: registration.configuration,
    registrationRecord: registered.registrationRecord, exportKey: registered.exportKey, phrase,
    challengePositions: positions, challengeAnswers: positions.map((position) => phrase.split(' ')[position]!), displayName: 'Password fixture Owner', workspaceName: 'Password fixture workspace' });
  const firstProof = await startLogin(oldPassword);
  const serverProof = await activation.startProof(reserved.activationId, resumeToken, { draftGeneration: '1', payload: prepared.payload, startLoginRequest: firstProof.startLoginRequest });
  const finished = await finishLogin({ password: oldPassword, clientLoginState: firstProof.clientLoginState, loginResponse: serverProof.loginResponse, configuration: serverProof.configuration });
  await activation.finishProof(reserved.activationId, resumeToken, { draftGeneration: '1', proofId: serverProof.proofId, finishLoginRequest: finished.finishLoginRequest });
  const activated = await activation.finalize(reserved.activationId, resumeToken, { draftGeneration: '1', requestHash: serverProof.requestHash });
  assert.equal(activated.state, 'completed');
  const deviceId = prepared.deviceWrapper.header.deviceId;
  const deviceContext = { workspaceId, accountId, deviceId, credentialGeneration: '1' };
  await devices.stage(prepared.deviceWrapper, reserved.operationId);
  await devices.commit(reserved.operationId, { ...deviceContext, operationId: reserved.operationId });
  const originalBundle = await unwrapDeviceBundle(deviceContext, prepared.deviceWrapper, registered.exportKey);
  let currentSession: IssuedSession;
  async function login(password: string) {
    const start = await worker.startLogin(password);
    const response = await authentication.startLogin({ workspaceId, accountId, startLoginRequest: start.startLoginRequest });
    const result = await worker.finishLogin({ password, clientLoginState: start.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration });
    const restricted = await authentication.finishLogin({ loginId: response.loginId, finishLoginRequest: result.finishLoginRequest });
    const challenge = await sessions.beginDeviceChallenge(restricted.cookieValue, restricted.csrfToken, deviceId);
    const { version: _version, purpose: _purpose, ceremonyId: _ceremony, nonce: _nonce, issuedAt: _issued, expiresAt: _expires, ...proofContext } = challenge;
    const context = { workspaceId, accountId, deviceId, credentialGeneration: restricted.credentialGeneration };
    const wrapper = await devices.get(context); assert.ok(wrapper, 'Current generation wrapper must survive a restart');
    await worker.unlockDevice({ context, wrapper, exportKey: result.exportKey, proofContext });
    const proof = await worker.deviceProof(challenge);
    currentSession = await sessions.completeDeviceChallenge(restricted.cookieValue, restricted.csrfToken, proof);
    return { session: currentSession, exportKey: result.exportKey };
  }
  await login(oldPassword);
  let clockOffset = 0;
  const now = () => new Date(Date.now() + clockOffset);
  let service = new PasswordChangeService({ databases, secrets, opaque, sessions, origin, now });
  const auth = () => ({ cookieValue: currentSession.cookieValue, csrfToken: currentSession.csrfToken });
  const transport: PasswordChangeTransport = {
    origin, begin: (input) => service.begin(input, auth()), status: (input) => service.status(input),
    registration: (input) => service.registration(input, auth()), startProof: (input) => service.startProof(input, auth()),
    finishProof: (input) => service.finishProof(input, auth()), finalize: (input) => service.finalize(input, auth()), cancel: (input) => service.cancel(input, auth()),
  };
  let controller = new PasswordChangeController({ transport, changes, devices, worker });
  async function draft() {
    const operationId = randomUUID();
    await controller.begin(workspaceId, operationId); await controller.prepare(operationId, newPassword, newPassword);
    return operationId;
  }
  async function stagedProof(operationId: string) {
    const pending = await changes.get(operationId); assert.ok(pending?.draft);
    const client = await worker.startLogin(newPassword);
    const proof = await service.startProof({ ...pending.reference, payload: pending.draft.payload, startLoginRequest: client.startLoginRequest }, auth());
    const finish = await worker.finishLogin({ password: newPassword, clientLoginState: client.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
    await worker.verifyPasswordChangeWrapper({ binding: pending.status!.binding, wrapper: (await devices.getStaged(operationId))!, exportKey: finish.exportKey });
    await service.finishProof({ ...pending.reference, proofId: proof.proofId, finishLoginRequest: finish.finishLoginRequest }, auth());
    return { ...pending.reference, requestHash: await digestObject(pending.draft.payload) };
  }
  return { admin, databases, secrets, opaque, sessions, authentication, activation, workspaceId, accountId, deviceId, deviceContext,
    originalBundle, phrase, registered, licence, reserved, prepared, worker, transport, auth, login, draft, stagedProof, factory, changeStoreName,
    get service() { return service; }, get controller() { return controller; }, get devices() { return devices; }, get changes() { return changes; },
    setHooks(hooks: Hooks = {}) { service = new PasswordChangeService({ databases, secrets, opaque, sessions, origin, hooks, now }); },
    advance(milliseconds: number) { clockOffset += milliseconds; },
    async reopen() { devices.close(); changes.close(); worker.logout(); devices = await IndexedDeviceStore.open(deviceStoreName, factory);
      changes = await IndexedPasswordChangeStore.open(changeStoreName, factory); controller = new PasswordChangeController({ transport, changes, devices, worker }); },
  };
}

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Writable } from 'node:stream';
import { createServer } from 'node:net';
import { parseEnv } from 'node:util';
import test from 'node:test';
import pg from 'pg';
import * as opaqueLibrary from '@serenity-kit/opaque';
import { IDBFactory } from 'fake-indexeddb';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createDatabases, transaction } from '../src/db.js';
import { startRegistration, startLogin, finishLogin } from '../src/client/opaque.js';
import { ActivationController, HttpActivationTransport, IndexedActivationStore } from '../src/client/activation-controller.js';
import { IndexedDeviceStore, unwrapDeviceBundle } from '../src/client/device-store.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { ActivationService } from '../src/modules/identity/activation.js';
import { RequestBudgets, pruneRequestBudgets } from '../src/modules/identity/budgets.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';
import { registerActivationRoutes } from '../src/modules/identity/routes.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { SessionService, readSessionCookie } from '../src/modules/identity/sessions.js';
import { AuthenticationService } from '../src/modules/identity/authentication.js';
import { registerAuthenticationRoutes } from '../src/modules/identity/auth-routes.js';
import { AppError } from '../src/errors.js';
import { base64urlDecode, signObject } from '../src/shared/crypto.js';

test('CP03: HTTP setup routes enforce origin, resume capability, strict bodies, and secret-free responses/logs', async (t) => {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'info' });
  const databases = createDatabases(config);
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const admin = new pg.Pool({ connectionString: process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL });
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'cp03-http-test' });
  await opaqueLibrary.ready;
  const opaque = new OpaqueService({ serverSetup: opaqueLibrary.server.createSetup(), setupId: 'cp03-http-v1', serverIdentity: config.APP_ORIGIN });
  const service = new ActivationService({ databases, secrets, opaque, origin: config.APP_ORIGIN });
  const budgets = new RequestBudgets(databases.control, secrets);
  const logs: string[] = [];
  const app = buildApp(config, databases, new Writable({ write(chunk, _encoding, done) { logs.push(String(chunk)); done(); } }));
  registerActivationRoutes(app, { origin: config.APP_ORIGIN, service, budgets });
  const issued = await service.reservations.issueLicence();
  let workspaceId: string | undefined;
  t.after(async () => {
    try {
      if (workspaceId) await admin.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
      await admin.query('DELETE FROM security.activation_attempts WHERE licence_id=$1', [issued.licenceId]);
      await admin.query('DELETE FROM security.licences WHERE licence_id=$1', [issued.licenceId]);
      // This test's HMAC key isolates its operational counters from every other fixture.
      await admin.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[
        secrets.digest('rate:activation-source', '127.0.0.1'), secrets.digest('rate:activation-licence', issued.licenceKey),
        ...(workspaceId ? [secrets.digest('rate:activation-attempt', activationId)] : []),
      ]]);
    } finally { await app.close(); await admin.end(); }
  });
  let activationId = '';
  const body = { licenceKey: issued.licenceKey, operationId: randomUUID(), resumeToken: secrets.token() };
  const reserve = async (headers: Record<string, string>, payload: unknown = body) => app.inject({ method: 'POST', url: '/v1/activation/reserve', headers, payload: payload as object });
  assert.equal((await reserve({})).statusCode, 403);
  assert.equal((await reserve({ origin: 'https://foreign.example' })).statusCode, 403);
  assert.equal((await reserve({ origin: config.APP_ORIGIN, 'sec-fetch-site': 'cross-site' })).statusCode, 403);
  const headers = { origin: config.APP_ORIGIN };
  assert.equal((await reserve(headers, { ...body, password: 'never-upload-password' })).statusCode, 400);
  const reserved = await reserve(headers);
  assert.equal(reserved.statusCode, 200, reserved.body);
  workspaceId = reserved.json().workspaceId;
  activationId = reserved.json().activationId;
  const path = `/v1/activation/${activationId}`;
  const auth = { ...headers, authorization: `Setup ${body.resumeToken}` };
  assert.equal((await app.inject({ method: 'POST', url: `${path}/status`, headers, payload: {} })).statusCode, 404);
  assert.equal((await app.inject({ method: 'POST', url: `${path}/status`, headers: { ...headers, authorization: `Setup ${secrets.token()}` }, payload: {} })).statusCode, 404);
  const status = await app.inject({ method: 'POST', url: `${path}/status`, headers: auth, payload: {} });
  assert.equal(status.statusCode, 200);
  assert.equal(status.json().configuration.identifiers.server, config.APP_ORIGIN);
  assert.equal(status.json().workspaceId, workspaceId);
  assert.equal(status.headers['cache-control'], 'no-store');
  assert.equal(status.headers['set-cookie'], undefined, 'Setup resumption must not create a login session');
  assert.equal((await app.inject({ method: 'POST', url: `${path}/status?token=${body.resumeToken}`, headers: auth, payload: {} })).statusCode, 400);
  const client = await startRegistration('HTTP registration private password 912');
  const registration = await app.inject({ method: 'POST', url: `${path}/registration`, headers: auth,
    payload: { draftGeneration: '1', registrationRequest: client.registrationRequest } });
  assert.equal(registration.statusCode, 200, registration.body);
  const replacement = await app.inject({ method: 'POST', url: `${path}/replace-draft`, headers: auth,
    payload: { expectedDraftGeneration: '1', operationId: randomUUID() } });
  assert.equal(replacement.json().draftGeneration, '2');
  assert.equal((await app.inject({ method: 'POST', url: `${path}/registration`, headers: auth,
    payload: { draftGeneration: '1', registrationRequest: client.registrationRequest } })).statusCode, 409);
  assert.equal((await app.inject({ method: 'POST', url: `${path}/finalize`, headers: auth,
    payload: { draftGeneration: '2', requestHash: 'a'.repeat(64) } })).statusCode, 409);
  const snapshot = `${logs.join('')} ${status.body} ${registration.body} ${replacement.body}`;
  for (const secret of [issued.licenceKey, body.resumeToken, 'never-upload-password', 'HTTP registration private password 912']) {
    assert.equal(snapshot.includes(secret), false, 'Setup credentials must not appear in logs or unrelated responses');
  }
  await admin.query(`UPDATE security.activation_attempts SET created_at=clock_timestamp()-interval '61 minutes',
    expires_at=clock_timestamp()-interval '1 minute',resume_expires_at=clock_timestamp()-interval '1 minute' WHERE activation_id=$1`, [activationId]);
  const expired = await app.inject({ method: 'POST', url: `${path}/status`, headers: auth, payload: {} });
  assert.equal(expired.statusCode, 410);
  assert.equal(expired.json().error.code, 'ACTIVATION_EXPIRED');
  // Licence lookup outage returns retryable setup failure, while liveness stays usable.
  service.reservations.reserve = async () => { throw new Error('postgres://internal-secret'); };
  const outage = await reserve(headers);
  assert.equal(outage.statusCode, 503);
  assert.equal(outage.body.includes('internal-secret'), false);
  assert.equal((await app.inject('/health/live')).statusCode, 200);
});

test('CP03: persisted request budgets serialize concurrent attempts, expire, and retain no raw source', async (t) => {
  assert.ok(process.env.CONTROL_DATABASE_URL);
  const pool = new pg.Pool({ connectionString: process.env.CONTROL_DATABASE_URL });
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'cp03-budget-test' });
  const budgets = new RequestBudgets(pool, secrets);
  const limit = { purpose: 'fixture', key: `source-${randomUUID()}`, limit: 3, windowMs: 1000 };
  const digest = secrets.digest('rate:fixture', limit.key);
  t.after(async () => { await pool.query('DELETE FROM security.request_budgets WHERE bucket_digest=$1', [digest]); await pool.end(); });
  const outcomes = await Promise.allSettled(Array.from({ length: 8 }, () => budgets.take([limit])));
  assert.equal(outcomes.filter((o) => o.status === 'fulfilled').length, 3);
  for (const result of outcomes) if (result.status === 'rejected') assert.equal(result.reason.code, 'RATE_LIMITED');
  const stored = (await pool.query('SELECT * FROM security.request_budgets WHERE bucket_digest=$1', [digest])).rows[0];
  assert.equal(stored.attempts, 4);
  assert.equal(JSON.stringify(stored).includes(limit.key), false);
  await pool.query("UPDATE security.request_budgets SET expires_at=clock_timestamp()-interval '1 second' WHERE bucket_digest=$1", [digest]);
  await budgets.take([limit]);
  assert.equal((await pool.query('SELECT attempts FROM security.request_budgets WHERE bucket_digest=$1', [digest])).rows[0].attempts, 1);
  await pool.query("UPDATE security.request_budgets SET expires_at=clock_timestamp()-interval '1 second' WHERE bucket_digest=$1", [digest]);
  await pruneRequestBudgets(pool);
  assert.equal((await pool.query('SELECT * FROM security.request_budgets WHERE bucket_digest=$1', [digest])).rowCount, 0);
});

test('CP04: real HTTP activation resumes and password login requires device proof before protected reads', async (t) => {
  const portReservation = createServer();
  await new Promise<void>((resolve) => portReservation.listen(0, '127.0.0.1', resolve));
  const address = portReservation.address();
  assert.ok(address && typeof address !== 'string');
  const port = address.port;
  await new Promise<void>((resolve, reject) => portReservation.close((error) => error ? reject(error) : resolve()));
  const origin = `http://127.0.0.1:${port}`;
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent', APP_ORIGIN: origin });
  const databases = createDatabases(config);
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const admin = {
    application: new pg.Pool({ connectionString: process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ?? local.ADMIN_DATABASE_URL }),
    control: new pg.Pool({ connectionString: process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL }),
  };
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'cp03-http-journey' });
  await opaqueLibrary.ready;
  const opaque = new OpaqueService({ serverSetup: opaqueLibrary.server.createSetup(), setupId: 'cp03-http-journey', serverIdentity: origin });
  const service = new ActivationService({ databases, secrets, opaque, origin });
  const sessions = new SessionService({ databases, secrets, origin });
  const authentication = new AuthenticationService({ databases, secrets, opaque, sessions, origin });
  const app = buildApp(config, databases, undefined, async (request) => {
    const cookie = readSessionCookie(request.headers.cookie);
    if (!cookie) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return sessions.authenticate(cookie, { approved: true });
  });
  registerActivationRoutes(app, { origin, service, budgets: new RequestBudgets(databases.control, secrets) });
  registerAuthenticationRoutes(app, { origin, authentication, sessions, budgets: new RequestBudgets(databases.control, secrets) });
  const issued = await service.reservations.issueLicence();
  const factory = new IDBFactory();
  let pending = await IndexedActivationStore.open('http-setup', factory);
  let devices = await IndexedDeviceStore.open('http-device', factory);
  let workspaceId: string | undefined;
  let activationId: string | undefined;
  t.after(async () => {
    pending.close(); devices.close();
    try {
      if (workspaceId) {
        await databases.application.query('SELECT graphile_worker.remove_job($1)', [`activation:${workspaceId}`]);
        await transaction(admin.application, async (client) => {
          await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
          await client.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.workspace:' || $1,0))", [workspaceId]);
          for (const table of ['profiles', 'roles', 'workspaces']) await client.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [workspaceId]);
        });
        await admin.control.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
      }
      await admin.control.query('DELETE FROM security.activation_attempts WHERE licence_id=$1', [issued.licenceId]);
      if (workspaceId) await admin.control.query('DELETE FROM security.auth_attempts WHERE workspace_id=$1', [workspaceId]);
      await admin.control.query('DELETE FROM security.licences WHERE licence_id=$1', [issued.licenceId]);
      await admin.control.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[
        secrets.digest('rate:activation-source', '127.0.0.1'), secrets.digest('rate:activation-licence', issued.licenceKey),
        ...(activationId ? [secrets.digest('rate:activation-attempt', activationId)] : []),
        secrets.digest('rate:authentication-source', '127.0.0.1'),
        ...(workspaceId && accountId ? [secrets.digest('rate:authentication-account', `${workspaceId}:${accountId}`),
          secrets.digest('rate:authentication-workspace', workspaceId)] : []),
      ]]);
    } finally { await app.close(); await Promise.all([admin.application.end(), admin.control.end()]); }
  });
  let accountId: string | undefined;
  await app.listen({ host: '127.0.0.1', port });
  const uploaded: string[] = [];
  let loseFinalResponse = true;
  const transport = new HttpActivationTransport(origin, async (request, options) => {
    uploaded.push(String(options?.body));
    // Browsers set Origin; this Node driver explicitly reproduces that browser header.
    const response = await fetch(request, { ...options, headers: { ...options?.headers, Origin: origin } });
    if (String(request).endsWith('/finalize') && loseFinalResponse) {
      loseFinalResponse = false;
      await response.text();
      throw new Error('Synthetic connection loss after successful response');
    }
    return response;
  });
  let controller = new ActivationController(transport, pending, devices);
  const operationId = await controller.create();
  const reserved = await controller.reserve(operationId, issued.licenceKey);
  workspaceId = reserved.workspaceId; activationId = reserved.activationId;
  accountId = reserved.accountId;
  const phrase = await newOwnerPhrase();
  const positions = [0, 9, 23];
  const password = 'Actual HTTP encrypted setup password 751';
  const displayName = 'Private HTTP journey owner';
  const recoveryKit = await controller.prepare(operationId, { password, confirmation: password, phrase,
    challengePositions: positions, challengeAnswers: positions.map((p) => phrase.split(' ')[p]!), displayName, workspaceName: 'Private HTTP workspace' });
  assert.equal(recoveryKit.phrase, phrase);
  await assert.rejects(controller.activate(operationId, password));
  const saved = await pending.get(operationId);
  assert.ok(saved?.draft);
  assert.equal(await devices.getActive(workspaceId, reserved.accountId, saved.draft.context.deviceId), undefined);
  pending.close(); devices.close();
  pending = await IndexedActivationStore.open('http-setup', factory);
  devices = await IndexedDeviceStore.open('http-device', factory);
  controller = new ActivationController(transport, pending, devices);
  const recovered = await controller.resume(operationId);
  assert.equal(recovered.state, 'completed');
  assert.ok(await devices.getActive(workspaceId, reserved.accountId, saved.draft.context.deviceId));
  const requestBodies = uploaded.join('\n');
  for (const secret of [password, phrase, displayName, 'Private HTTP workspace', saved.draft.wrapper.ciphertext]) assert.equal(requestBodies.includes(secret), false);
  const counts = (await admin.control.query('SELECT count(*) FROM security.profiles WHERE workspace_id=$1', [workspaceId])).rows[0];
  assert.equal(counts.count, '1', 'Response loss must not create another Owner');

  const post = async (path: string, body: unknown, cookie?: string, csrfToken?: string) => {
    const response = await fetch(`${origin}/v1/auth/${path}`, { method: 'POST', headers: {
      'Content-Type': 'application/json', Origin: origin, ...(cookie ? { Cookie: cookie } : {}),
      ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
    }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json(), cookieHeader: response.headers.get('set-cookie') };
  };
  const login = await startLogin(password);
  const started = await post('login/start', { workspaceId, accountId, startLoginRequest: login.startLoginRequest });
  assert.equal(started.status, 200);
  const finished = await finishLogin({ password, clientLoginState: login.clientLoginState,
    loginResponse: started.body.loginResponse, configuration: started.body.configuration });
  const loggedIn = await post('login/finish', { loginId: started.body.loginId, finishLoginRequest: finished.finishLoginRequest });
  assert.equal(loggedIn.status, 200);
  assert.equal(loggedIn.body.accessLevel, 'restricted');
  assert.ok(loggedIn.cookieHeader);
  for (const attribute of ['__Host-ukda_session=', 'Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/']) assert.ok(loggedIn.cookieHeader.includes(attribute));
  const restrictedCookie = loggedIn.cookieHeader.split(';')[0]!;
  assert.equal(JSON.stringify(loggedIn.body).includes(restrictedCookie.slice(restrictedCookie.indexOf('=') + 1)), false);
  const protectedURL = `${origin}/v1/workspaces/${workspaceId}/projects`;
  assert.equal((await fetch(protectedURL, { headers: { Cookie: restrictedCookie } })).status, 403);
  assert.equal((await post('device-challenge/start', { deviceId: saved.draft.context.deviceId }, restrictedCookie)).status, 403);
  const unknownDevice = await post('device-challenge/start', { deviceId: randomUUID() }, restrictedCookie, loggedIn.body.csrfToken);
  assert.equal(unknownDevice.status, 403);
  assert.equal(unknownDevice.body.error.code, 'DEVICE_APPROVAL_REQUIRED');
  const challenge = await post('device-challenge/start', { deviceId: saved.draft.context.deviceId }, restrictedCookie, loggedIn.body.csrfToken);
  assert.equal(challenge.status, 200);
  const bundle = await unwrapDeviceBundle(saved.draft.context, saved.draft.wrapper, finished.exportKey);
  const signingKey = base64urlDecode(bundle.signingPrivateKey);
  const proof = await signObject(challenge.body, signingKey);
  signingKey.fill(0);
  const approved = await post('device-challenge/finish', proof, restrictedCookie, loggedIn.body.csrfToken);
  assert.equal(approved.status, 200, JSON.stringify(approved.body));
  assert.equal(approved.body.accessLevel, 'device_approved');
  const approvedCookie = approved.cookieHeader!.split(';')[0]!;
  assert.notEqual(approvedCookie, restrictedCookie);
  assert.equal((await post('session', {}, restrictedCookie)).status, 401);
  const records = await fetch(protectedURL, { headers: { Cookie: approvedCookie } });
  assert.equal(records.status, 200);
  assert.deepEqual((await records.json()).records, []);
  assert.equal((await post('logout', {}, approvedCookie, secrets.token())).status, 403);
  const loggedOut = await post('logout', {}, approvedCookie, approved.body.csrfToken);
  assert.equal(loggedOut.status, 200);
  assert.match(loggedOut.cookieHeader!, /Max-Age=0/);
  assert.equal((await fetch(protectedURL, { headers: { Cookie: approvedCookie } })).status, 401);
});

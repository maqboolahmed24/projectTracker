import { expect } from '@playwright/test';
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
import { RequestBudgets, createRequestBudgetPool } from '../../src/modules/identity/budgets.js';
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

import { RecoveryService } from '../../src/modules/identity/recovery.js';
import { registerRecoveryRoutes, recoveryAccountBudget } from '../../src/modules/identity/recovery-routes.js';
import { EnrolmentService } from '../../src/modules/identity/enrolment.js';
import { registerEnrolmentRoutes, enrolmentAccountBudget } from '../../src/modules/identity/enrolment-routes.js';
import { RoleService } from '../../src/modules/identity/roles.js';
import { registerRoleRoutes, roleAccountBudget } from '../../src/modules/identity/roles-routes.js';
import { AccessChangeService } from '../../src/modules/identity/access-change.js';
import { registerAccessChangeRoutes, accessChangeAccountBudget } from '../../src/modules/identity/access-change-routes.js';
import type { RequestBudget } from '../../src/modules/identity/budgets.js';
import { unwrapDeviceBundle } from '../../src/client/device-store.js';
import { base64urlDecode, signObject } from '../../src/shared/crypto.js';
import { provisionProjectScope } from '../project-scope-fixture.js';

export const origin = 'https://127.0.0.1:3555';
export const password = 'A browser session fixture password 24794';

export async function authenticationFixture(restricted = false) {
  const local = parseEnv(await readFile('.env', 'utf8').catch(() => ''));
  const adminEnvironment = parseEnv(await readFile('.env.admin', 'utf8').catch(() => ''));
  const config = loadConfig({ ...local, ...process.env, NODE_ENV: 'test', APP_ORIGIN: origin, LOG_LEVEL: 'silent' });
  const databases = createDatabases(config);
  const admin = { application: new pg.Pool({ connectionString: process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ?? adminEnvironment.ADMIN_DATABASE_URL }),
    control: new pg.Pool({ connectionString: process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? adminEnvironment.CONTROL_ADMIN_DATABASE_URL }) };
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'browser-http-test' });
  await opaqueLibrary.ready;
  const opaque = new OpaqueService({ serverSetup: opaqueLibrary.server.createSetup(), setupId: 'browser-http-test', serverIdentity: origin });
  const activation = new ActivationService({ databases, secrets, opaque, origin });
  const sessions = new SessionService({ databases, secrets, origin });
  const authentication = new AuthenticationService({ databases, secrets, opaque, sessions, origin });
  const app = buildApp(config, databases, undefined, async (request) => {
    const cookie = readSessionCookie(request.headers.cookie);
    if (!cookie) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return sessions.authenticate(cookie, { approved: true });
  });
  const budgetPool = createRequestBudgetPool(config);
  app.addHook('onClose', async () => budgetPool.end());
  const realBudgets = new RequestBudgets(budgetPool, secrets), recordedCounters = new Map<string, Buffer>();
  const budgets = { async take(entries: readonly RequestBudget[]) {
    for (const entry of entries) { const digest = secrets.digest(`rate:${entry.purpose}`, entry.key); recordedCounters.set(digest.toString('hex'), digest); }
    await realBudgets.take(entries);
  } };
  registerAuthenticationRoutes(app, { origin, authentication, sessions, budgets });
  registerSecurityRoutes(app, { origin, databases, sessions, budgets, pairing: new PairingService({ databases, sessions, origin }),
    passwordChange: new PasswordChangeService({ databases, sessions, opaque, secrets, origin }) });
  registerRecoveryRoutes(app, { origin, budgets, recovery: new RecoveryService({ databases, sessions, opaque, secrets, origin,
    requestBudget: recoveryAccountBudget(budgets) }) });
  registerEnrolmentRoutes(app, { origin, budgets,
    enrolment: new EnrolmentService({ databases, sessions, opaque, secrets, origin,
      requestBudget: enrolmentAccountBudget(budgets) }) });
  registerRoleRoutes(app, { origin, budgets,
    roles: new RoleService({ databases, sessions, origin, requestBudget: roleAccountBudget(budgets) }) });
  registerAccessChangeRoutes(app, { origin, budgets,
    accessChanges: new AccessChangeService({ databases, sessions, secrets, origin,
      requestBudget: accessChangeAccountBudget(budgets) }) });
  const passwordOperations = new Set<string>();
  const recoveryOperations = new Set<string>();
  let workspaceId: string | undefined, accountId: string | undefined, licenceId: string | undefined;
  const close = async () => {
    try {
      if (workspaceId) {
        await databases.application.query('SELECT graphile_worker.remove_job($1)', [`activation:${workspaceId}`]);
        await transaction(admin.application, async (client) => {
          await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
          await client.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.workspace:' || $1,0))", [workspaceId]);
          for (const table of ['notifications', 'project_access', 'projects', 'profiles', 'roles', 'workspaces']) await client.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [workspaceId]);
        });
        await admin.control.query('DELETE FROM security.ceremonies WHERE workspace_id=$1', [workspaceId]);
        await admin.control.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
        await admin.control.query('DELETE FROM security.auth_attempts WHERE workspace_id=$1', [workspaceId]);
      }
      if (licenceId) {
        await admin.control.query('DELETE FROM security.entitlement_operations WHERE licence_id=$1', [licenceId]);
        await admin.control.query('DELETE FROM security.activation_attempts WHERE licence_id=$1', [licenceId]);
        await admin.control.query('DELETE FROM security.licences WHERE licence_id=$1', [licenceId]);
      }
      const digests = [secrets.digest('rate:authentication-source', '127.0.0.1'), secrets.digest('rate:history-source', '127.0.0.1'),
        secrets.digest('rate:recovery-source', '127.0.0.1'), secrets.digest('rate:recovery-history-source', '127.0.0.1'),
        ...(workspaceId && accountId ? [secrets.digest('rate:authentication-account', `${workspaceId}:${accountId}`), secrets.digest('rate:authentication-workspace', workspaceId),
          secrets.digest('rate:security-account', `${workspaceId}:${accountId}`), secrets.digest('rate:security-workspace', workspaceId),
          secrets.digest('rate:history-account', `${workspaceId}:${accountId}`), secrets.digest('rate:history-workspace', workspaceId),
          secrets.digest('rate:recovery-workspace', workspaceId), secrets.digest('rate:recovery-history-workspace', workspaceId),
          secrets.digest('rate:recovery-account', `${workspaceId}:${accountId}`),
          secrets.digest('rate:recovery-target-account', `${workspaceId}:${accountId}`), secrets.digest('rate:recovery-target-workspace', workspaceId),
          secrets.digest('rate:recovery-target-history-account', `${workspaceId}:${accountId}`), secrets.digest('rate:recovery-target-history-workspace', workspaceId),
          ...[...recoveryOperations].flatMap((id) => [secrets.digest('rate:recovery-operation', `${workspaceId}:${id}`), secrets.digest('rate:recovery-history-operation', `${workspaceId}:${id}`)]),
          ...[...passwordOperations].map((id) => secrets.digest('rate:password-change-operation', `${workspaceId}:${id}`))] : [])];
      await admin.control.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [[...digests, ...recordedCounters.values()]]);
    } finally { await app.close(); await Promise.all([admin.application.end(), admin.control.end()]); }
  };
  try {
    const issued = await activation.reservations.issueLicence(); licenceId = issued.licenceId;
    const resumeToken = secrets.token();
    const reserved = await activation.reservations.reserve({ licenceKey: issued.licenceKey, operationId: randomUUID(), resumeToken });
    workspaceId = reserved.workspaceId; accountId = reserved.accountId;
    const registrationStart = await startRegistration(password);
    const response = await activation.registration(reserved.activationId, resumeToken, { draftGeneration: '1', registrationRequest: registrationStart.registrationRequest });
    const registered = await finishRegistration({ password, clientRegistrationState: registrationStart.clientRegistrationState,
      registrationResponse: response.registrationResponse, configuration: response.configuration });
    const phrase = await newOwnerPhrase(), positions = [1, 10, 23];
    const prepared = await prepareOwnerActivation({ binding: { workspaceId, accountId, operationId: reserved.operationId,
      activationId: reserved.activationId, reservationGeneration: reserved.reservationGeneration, draftGeneration: reserved.draftGeneration, origin }, configuration: response.configuration,
      registrationRecord: registered.registrationRecord, exportKey: registered.exportKey, phrase, challengePositions: positions,
      challengeAnswers: positions.map((index) => phrase.split(' ')[index]!), displayName: 'Browser owner', workspaceName: 'Browser workspace' });
    const login = await startLogin(password);
    const proof = await activation.startProof(reserved.activationId, resumeToken, { draftGeneration: '1', payload: prepared.payload, startLoginRequest: login.startLoginRequest });
    const finish = await finishLogin({ password, clientLoginState: login.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
    await activation.finishProof(reserved.activationId, resumeToken, { draftGeneration: '1', proofId: proof.proofId, finishLoginRequest: finish.finishLoginRequest });
    const activated = await activation.finalize(reserved.activationId, resumeToken, { draftGeneration: '1', requestHash: proof.requestHash });
    const receipt = activated.receipt as Parameters<typeof Client.seedActivationPin>[2];
    expect(receipt).toMatchObject({ workspaceId, accountId, deviceId: prepared.payload.genesis.body.device.id,
      operationId: reserved.operationId, securityVersion: '1' });
    expect(receipt.genesisFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(receipt.securityHead).toBe(receipt.genesisFingerprint);
    const entitlements = new EntitlementOperations(databases, secrets);
    const trustedServiceKeys = { [secrets.keyId]: await entitlements.publicSigningKey() };
    const provisionProject = async (selected: { accountId: string; roleId: string }[] = []) => {
      const deviceId = prepared.payload.genesis.body.device.id;
      const start = await startLogin(password);
      const response = await authentication.startLogin({ workspaceId: reserved.workspaceId, accountId: reserved.accountId, startLoginRequest: start.startLoginRequest });
      const logged = await finishLogin({ password, clientLoginState: start.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration });
      const session = await authentication.finishLogin({ loginId: response.loginId, finishLoginRequest: logged.finishLoginRequest });
      const bundle = await unwrapDeviceBundle({ workspaceId: reserved.workspaceId, accountId: reserved.accountId, deviceId, credentialGeneration: session.credentialGeneration }, prepared.deviceWrapper, logged.exportKey);
      const challenge = await sessions.beginDeviceChallenge(session.cookieValue, session.csrfToken, deviceId);
      const approved = await sessions.completeDeviceChallenge(session.cookieValue, session.csrfToken, await signObject(challenge, base64urlDecode(bundle.signingPrivateKey)));
      return provisionProjectScope({ workspaceId: reserved.workspaceId, accountId: reserved.accountId, deviceId,
        originalBundle: bundle, databases, admin, secrets, sessions, auth: () => ({ cookieValue: approved.cookieValue, csrfToken: approved.csrfToken }), origin }, { selected });
    };
    if (restricted) await entitlements.change({ licenceId, operationId: randomUUID(), action: 'revoke' }, { operatorId: randomUUID() });
    await app.listen({ host: '127.0.0.1', port: 3556 });
    return { close, workspaceId, accountId, deviceId: prepared.payload.genesis.body.device.id, operationId: reserved.operationId, wrapper: prepared.deviceWrapper,
      genesis: prepared.payload.genesis, receipt, passwordOperations, recoveryOperations, trustedServiceKeys, phrase, provisionProject };
  } catch (error) { await close(); throw error; }
}

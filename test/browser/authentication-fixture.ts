import { deliverNotificationJob } from '../../src/modules/notifications/delivery.js';
import { ExportService } from '../../src/modules/export/service.js';
import { registerExportRoutes } from '../../src/modules/export/routes.js';
import { RestorationService } from '../../src/modules/restoration/service.js';
import { RESTORE_TABLES } from '../../src/modules/restoration/manifest.js';
import { registerRestorationRoutes } from '../../src/modules/restoration/routes.js';
import { finalizeDeletionIfDue } from '../../src/modules/lifecycle/deadline.js';
import { LifecycleService } from '../../src/modules/lifecycle/service.js';
import { registerLifecycleRoutes } from '../../src/modules/lifecycle/routes.js';
import { UpgradeService } from '../../src/modules/upgrades/service.js';
import { registerUpgradeRoutes } from '../../src/modules/upgrades/routes.js';
import { ReceiptService } from '../../src/modules/work/receipts.js';
import { registerReceiptRoutes } from '../../src/modules/work/receipt-routes.js';
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
import { registerActivationRoutes } from '../../src/modules/identity/routes.js';
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
import { ProjectCreateService } from '../../src/modules/work/project-create.js';
import { registerProjectCreateRoutes, projectCreateAccountBudget } from '../../src/modules/work/project-create-routes.js';
import { TeamService } from '../../src/modules/work/teams.js';
import { PlanningService } from '../../src/modules/work/planning.js';
import { registerPlanningRoutes, planningAccountBudget } from '../../src/modules/work/planning-routes.js';
import { CollaborationService } from '../../src/modules/collaboration/service.js';
import { registerCollaborationRoutes, collaborationAccountBudget } from '../../src/modules/collaboration/routes.js';
import { ReportingService } from '../../src/modules/work/reporting.js';
import { registerReportingRoutes } from '../../src/modules/work/reporting-routes.js';
import { LiveService } from '../../src/modules/work/live.js';
import { registerLiveRoutes } from '../../src/modules/work/live-routes.js';
import { InboxService } from '../../src/modules/notifications/inbox.js';
import { registerInboxRoutes } from '../../src/modules/notifications/inbox-routes.js';
import { registerTeamRoutes, teamAccountBudget } from '../../src/modules/work/team-routes.js';

export const origin = 'https://127.0.0.1:3555';
export const password = 'A browser session fixture password 24794';

export async function authenticationFixture(restricted = false, avatar?: Client.AvatarSelection) {
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
  registerActivationRoutes(app, { origin, service: activation, budgets });
  const entitlements = new EntitlementOperations(databases, secrets);
  const trustedServiceKeys = { [secrets.keyId]: await entitlements.publicSigningKey() };
  app.get('/v1/application', async () => ({ version: 1, trustedServiceKeys }));
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
  registerProjectCreateRoutes(app, { origin, budgets,
    projectCreation: new ProjectCreateService({ databases, sessions, secrets, origin,
      requestBudget: projectCreateAccountBudget(budgets) }) });
  registerLifecycleRoutes(app, { origin: origin, budgets, lifecycle: new LifecycleService({ databases, sessions, secrets, origin: origin }) });
  const teams = new TeamService({ databases, sessions, requestBudget: teamAccountBudget(budgets) });
  const planning = new PlanningService({ databases, sessions, secrets, origin: origin, requestBudget: planningAccountBudget(budgets) });
  const collaboration = new CollaborationService({ databases, sessions, secrets, origin: origin, planning, requestBudget: collaborationAccountBudget(budgets) });
  registerExportRoutes(app, { origin, budgets, exports: new ExportService({ databases, sessions, secrets, origin, planning, teams, collaboration }) });
  const restoration = new RestorationService({ databases, sessions, secrets, origin,
    beforeWorkspace: async workspaceId => { await finalizeDeletionIfDue({ databases, secrets, workspaceId }); } });
  registerRestorationRoutes(app, { origin, budgets, restoration });
  registerTeamRoutes(app, { origin: origin, budgets, teams });
  registerPlanningRoutes(app, { origin: origin, budgets, planning });
  registerCollaborationRoutes(app, { origin: origin, budgets, collaboration });
  registerUpgradeRoutes(app, { origin: origin, budgets, upgrades: new UpgradeService({ databases, sessions, secrets, origin: origin,
    handlers: { planning: (a,payload)=>planning.save(a.cookieValue,a.csrfToken,payload), team: (a,payload)=>teams.save(a,payload),
      collaboration: (a,payload)=>collaboration.save(a.cookieValue,a.csrfToken,payload) } }) });
  registerReceiptRoutes(app, { origin: origin, budgets, receipts: new ReceiptService({ databases, sessions,
    requestBudget: ({ workspaceId, accountId })=>budgets.take([{purpose:'receipts-account',key:`${workspaceId}:${accountId}`,limit:600,windowMs:600000}]) }) });
  registerInboxRoutes(app, { origin, budgets, inbox: new InboxService({ databases, sessions, origin }) });
  registerReportingRoutes(app, { origin, budgets, reporting: new ReportingService({ databases, sessions, secrets, origin }) });
  registerLiveRoutes(app, { origin, budgets, live: new LiveService({ databases, sessions }) });
  const passwordOperations = new Set<string>();
  const recoveryOperations = new Set<string>();
  // Product UI tests activate additional isolated workspaces through the real
  // HTTP routes. Track their issued licences so failed/resumed setups also clean up.
  const frontendLicences = new Set<string>();
  const issueFrontendLicence = async () => {
    const issued = await activation.reservations.issueLicence();
    frontendLicences.add(issued.licenceId);
    return issued.licenceKey;
  };
  let workspaceId: string | undefined, accountId: string | undefined, licenceId: string | undefined;
  const close = async () => {
    try {
      const cleanupWorkspaces = new Set(workspaceId ? [workspaceId] : []);
      if (frontendLicences.size) {
        const rows = await admin.control.query<{ workspace_id: string }>('SELECT workspace_id FROM security.activation_attempts WHERE licence_id=ANY($1::uuid[])', [[...frontendLicences]]);
        for (const row of rows.rows) cleanupWorkspaces.add(row.workspace_id);
      }
      for (const workspaceId of cleanupWorkspaces) {
        await databases.application.query('SELECT graphile_worker.remove_job($1)', [`activation:${workspaceId}`]);
        const jobs = (await databases.application.query<{ key: string }>('SELECT key FROM graphile_worker.jobs WHERE key LIKE $1', [`notification:${workspaceId}:%`])).rows;
        for (const job of jobs) await databases.application.query('SELECT graphile_worker.remove_job($1)', [job.key]);
        await transaction(admin.application, async (client) => {
          await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
          await client.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.workspace:' || $1,0))", [workspaceId]);
          // Fixture-only cleanup of immutable history for this disposable workspace.
          await client.query("SET LOCAL session_replication_role='replica'");
          for (const table of ['export_sessions','restorations','unrecovered_projects','lifecycle_tombstones','encrypted_upgrade_items','encrypted_upgrade_operations','encrypted_upgrade_sources','encrypted_upgrades','outbox', 'operation_receipts', 'audit_events', 'record_versions', 'comments', 'updates', 'blockers',
            'task_assignments', 'tasks', 'milestones', 'project_phases', 'notification_preferences', 'notification_receipts', 'notifications', 'inbox_operations', 'summaries',
            'reporting_operations', 'reporting_preparations', 'reporting_summaries', 'reporting_settings', 'collaboration_operations', 'planning_operations', 'project_planning_heads', 'project_access', 'projects', 'team_members', 'teams', 'profiles', 'roles', 'workspaces']) await client.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [workspaceId]);
        });
        await admin.control.query('DELETE FROM security.encrypted_upgrade_operations WHERE workspace_id=$1',[workspaceId]);
        await admin.control.query('DELETE FROM security.ceremonies WHERE workspace_id=$1', [workspaceId]);
        await admin.control.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
        await admin.control.query('DELETE FROM security.auth_attempts WHERE workspace_id=$1', [workspaceId]);
      }
      for (const ownedLicenceId of new Set([...(licenceId ? [licenceId] : []), ...frontendLicences])) {
        await admin.control.query('DELETE FROM security.entitlement_operations WHERE licence_id=$1', [ownedLicenceId]);
        await admin.control.query('DELETE FROM security.activation_attempts WHERE licence_id=$1', [ownedLicenceId]);
        await admin.control.query('DELETE FROM security.licences WHERE licence_id=$1', [ownedLicenceId]);
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
      challengeAnswers: positions.map((index) => phrase.split(' ')[index]!), displayName: 'Browser owner', workspaceName: 'Browser workspace', ...(avatar ? { avatar } : {}) });
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
    const quarantineCurrentCheckpoint = async () => {
      const checkpointId = randomUUID(), restoreId = randomUUID(), actor = { operatorId: randomUUID() };
      const snapshot = new Map<string, Record<string, unknown>[]>();
      const capture = new RestorationService({ ...restoration.options, hooks: { checkpointCaptured: async () => {
        // Capture under the same workspace fence as the signed inventory. The
        // subsequent authority projection can legitimately update row timestamps.
        for (const table of RESTORE_TABLES) snapshot.set(table, (await admin.application.query(`SELECT to_jsonb(t) AS row FROM app.${table} t WHERE workspace_id=$1`, [reserved.workspaceId])).rows.map(row => row.row));
      } } });
      const captured = await capture.captureCheckpoint({ workspaceId: reserved.workspaceId, checkpointId }, actor);
      await restoration.begin({ workspaceId: reserved.workspaceId, restoreId, manifest: captured.manifest }, actor);
      // Browser protocol fixture only; actual base-backup/WAL installation is
      // exercised separately. Never copy application authority over control.
      await transaction(admin.application, async client => {
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.workspace:' || $1,0))", [reserved.workspaceId]);
        await client.query("SET LOCAL session_replication_role='replica'");
        for (const table of ['notifications','notification_receipts','notification_preferences','inbox_operations','operation_receipts','outbox','summaries','reporting_preparations','reporting_summaries', ...RESTORE_TABLES.filter(table => table !== 'workspaces')])
          await client.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [reserved.workspaceId]);
        for (const table of RESTORE_TABLES) for (const row of snapshot.get(table) ?? []) {
          if (table === 'workspaces') await client.query('UPDATE app.workspaces SET encrypted_envelope=$2,revision=$3,fence_closed=true,restore_quarantine=true WHERE workspace_id=$1', [reserved.workspaceId, row.encrypted_envelope, row.revision]);
          else await client.query(`INSERT INTO app.${table} SELECT * FROM jsonb_populate_record(NULL::app.${table},$1::jsonb)`, [JSON.stringify(row)]);
        }
      });
      await restoration.reconcile({ workspaceId: reserved.workspaceId, restoreId });
      return restoreId;
    };
    // Exercise the production notification job for this isolated fixture only.
    // The global worker uses a different keyring and is deliberately not involved.
    const deliverFrontendNotifications = async () => {
      const pending = await transaction(databases.application, async client => {
        await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [reserved.workspaceId]);
        return (await client.query<{ id: string; data_generation: string }>(
          "SELECT id,data_generation FROM app.outbox WHERE workspace_id=$1 AND state='pending' AND notification_version=1 ORDER BY created_at,id LIMIT 1000",
          [reserved.workspaceId])).rows;
      });
      for (const row of pending) await deliverNotificationJob(databases, {
        workspaceId: reserved.workspaceId, outboxId: row.id, dataGeneration: row.data_generation,
      });
      return pending.length;
    };
    const restrictLicence = () => entitlements.change({ licenceId: issued.licenceId, operationId: randomUUID(), action: 'revoke' }, { operatorId: randomUUID() });
    if (restricted) await entitlements.change({ licenceId, operationId: randomUUID(), action: 'revoke' }, { operatorId: randomUUID() });
    await app.listen({ host: '127.0.0.1', port: 3556 });
    return { close, workspaceId, accountId, deviceId: prepared.payload.genesis.body.device.id, operationId: reserved.operationId, wrapper: prepared.deviceWrapper,
      genesis: prepared.payload.genesis, receipt, passwordOperations, recoveryOperations, trustedServiceKeys, phrase, provisionProject, restrictLicence, quarantineCurrentCheckpoint, issueFrontendLicence, deliverFrontendNotifications };
  } catch (error) { await close(); throw error; }
}

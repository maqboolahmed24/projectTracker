import { LifecycleService } from './modules/lifecycle/service.js';
import { registerLifecycleRoutes } from './modules/lifecycle/routes.js';
import { ExportService } from './modules/export/service.js';
import { registerExportRoutes } from './modules/export/routes.js';
import { RestorationService } from './modules/restoration/service.js';
import { registerRestorationRoutes } from './modules/restoration/routes.js';
import { finalizeDeletionIfDue } from './modules/lifecycle/deadline.js';
import { UpgradeService } from './modules/upgrades/service.js';
import { registerUpgradeRoutes } from './modules/upgrades/routes.js';
import { ReceiptService } from './modules/work/receipts.js';
import { registerReceiptRoutes } from './modules/work/receipt-routes.js';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { createDatabases } from './db.js';
import { ActivationService } from './modules/identity/activation.js';
import { RequestBudgets, createRequestBudgetPool } from './modules/identity/budgets.js';
import { OpaqueService } from './modules/identity/opaque.js';
import { registerActivationRoutes } from './modules/identity/routes.js';
import { loadIdentityConfig, ServiceSecrets } from './modules/identity/secrets.js';
import { randomUUID } from 'node:crypto';
import { EntitlementOperations } from './modules/identity/entitlements.js';
import { SessionService, readSessionCookie } from './modules/identity/sessions.js';
import { AuthenticationService } from './modules/identity/authentication.js';
import { registerAuthenticationRoutes } from './modules/identity/auth-routes.js';
import { AppError } from './errors.js';
import { PairingService } from './modules/identity/pairing.js';
import { PasswordChangeService } from './modules/identity/password-change.js';
import { registerSecurityRoutes } from './modules/identity/security-routes.js';
import { RecoveryService } from './modules/identity/recovery.js';
import { registerRecoveryRoutes, recoveryAccountBudget } from './modules/identity/recovery-routes.js';
import { EnrolmentService } from './modules/identity/enrolment.js';
import { registerEnrolmentRoutes, enrolmentAccountBudget } from './modules/identity/enrolment-routes.js';
import { RoleService } from './modules/identity/roles.js';
import { registerRoleRoutes, roleAccountBudget } from './modules/identity/roles-routes.js';
import { AccessChangeService } from './modules/identity/access-change.js';
import { registerAccessChangeRoutes, accessChangeAccountBudget } from './modules/identity/access-change-routes.js';
import { TeamService } from './modules/work/teams.js';
import { registerTeamRoutes, teamAccountBudget } from './modules/work/team-routes.js';
import { ProjectCreateService } from './modules/work/project-create.js';
import { registerProjectCreateRoutes, projectCreateAccountBudget } from './modules/work/project-create-routes.js';
import { PlanningService } from './modules/work/planning.js';
import { registerPlanningRoutes, planningAccountBudget } from './modules/work/planning-routes.js';
import { FilesService } from './modules/files/service.js';
import { registerFilesRoutes, filesAccountBudget } from './modules/files/routes.js';
import { FileEvidenceService } from './modules/files/evidence-service.js';
import { registerFileEvidenceRoutes } from './modules/files/evidence-routes.js';
import { DeliveryService } from './modules/files/delivery-service.js';
import { registerDeliveryRoutes } from './modules/files/delivery-routes.js';
import { CollaborationService } from './modules/collaboration/service.js';
import { registerCollaborationRoutes, collaborationAccountBudget } from './modules/collaboration/routes.js';
import { InboxService } from './modules/notifications/inbox.js';
import { registerInboxRoutes } from './modules/notifications/inbox-routes.js';
import { LiveService } from './modules/work/live.js';
import { registerLiveRoutes } from './modules/work/live-routes.js';
import { ReportingService } from './modules/work/reporting.js';
import { registerReportingRoutes } from './modules/work/reporting-routes.js';

try {
  const config = loadConfig();
  const identity = loadIdentityConfig();
  const secrets = new ServiceSecrets(identity);
  const opaque = new OpaqueService({ serverSetup: identity.OPAQUE_SERVER_SETUP, setupId: identity.OPAQUE_SETUP_ID, serverIdentity: identity.AUTH_SERVER_IDENTITY });
  // Parse persistent OPAQUE setup before listening, rather than failing the first user's setup.
  await opaque.publicConfiguration(randomUUID(), randomUUID());
  const databases = createDatabases(config);
  const sessions = new SessionService({ databases, secrets, origin: config.APP_ORIGIN });
  const authentication = new AuthenticationService({ databases, secrets, opaque, sessions, origin: config.APP_ORIGIN });
  const app = buildApp(config, databases, undefined, async (request) => {
    const cookie = readSessionCookie(request.headers.cookie);
    if (!cookie) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return sessions.authenticate(cookie, { approved: true });
  });
  const trustedServiceKeys = { [secrets.keyId]: await new EntitlementOperations(databases, secrets).publicSigningKey() };
  app.get('/v1/application', async () => ({ version: 1, trustedServiceKeys }));
  const activation = new ActivationService({ databases, secrets, opaque, origin: config.APP_ORIGIN });
  const budgetPool = createRequestBudgetPool(config);
  app.addHook('onClose', async () => budgetPool.end());
  const budgets = new RequestBudgets(budgetPool, secrets);
  registerActivationRoutes(app, { origin: config.APP_ORIGIN, service: activation, budgets });
  registerAuthenticationRoutes(app, { origin: config.APP_ORIGIN, authentication, sessions, budgets });
  registerSecurityRoutes(app, { origin: config.APP_ORIGIN, databases, sessions, budgets,
    pairing: new PairingService({ databases, sessions, origin: config.APP_ORIGIN }),
    passwordChange: new PasswordChangeService({ databases, sessions, opaque, secrets, origin: config.APP_ORIGIN }) });
  registerRecoveryRoutes(app, { origin: config.APP_ORIGIN, budgets,
    recovery: new RecoveryService({ databases, sessions, opaque, secrets, origin: config.APP_ORIGIN,
      requestBudget: recoveryAccountBudget(budgets) }) });
  registerEnrolmentRoutes(app, { origin: config.APP_ORIGIN, budgets,
    enrolment: new EnrolmentService({ databases, sessions, opaque, secrets, origin: config.APP_ORIGIN,
      requestBudget: enrolmentAccountBudget(budgets) }) });
  registerRoleRoutes(app, { origin: config.APP_ORIGIN, budgets,
    roles: new RoleService({ databases, sessions, origin: config.APP_ORIGIN, requestBudget: roleAccountBudget(budgets) }) });
  registerAccessChangeRoutes(app, { origin: config.APP_ORIGIN, budgets,
    accessChanges: new AccessChangeService({ databases, sessions, secrets, origin: config.APP_ORIGIN,
      requestBudget: accessChangeAccountBudget(budgets) }) });
  registerLifecycleRoutes(app, { origin: config.APP_ORIGIN, budgets, lifecycle: new LifecycleService({ databases, sessions, secrets, origin: config.APP_ORIGIN }) });
  const teams = new TeamService({ databases, sessions, requestBudget: teamAccountBudget(budgets) });
  const planning = new PlanningService({ databases, sessions, secrets, origin: config.APP_ORIGIN, requestBudget: planningAccountBudget(budgets) });
  const collaboration = new CollaborationService({ databases, sessions, secrets, origin: config.APP_ORIGIN, planning, requestBudget: collaborationAccountBudget(budgets) });
  registerExportRoutes(app, { origin: config.APP_ORIGIN, budgets, exports: new ExportService({ databases, sessions, secrets, origin: config.APP_ORIGIN, planning, teams, collaboration }) });
  registerRestorationRoutes(app, { origin: config.APP_ORIGIN, budgets, restoration: new RestorationService({ databases, sessions, secrets, origin: config.APP_ORIGIN,
    beforeWorkspace: async workspaceId => { await finalizeDeletionIfDue({ databases, secrets, workspaceId }); } }) });
  registerTeamRoutes(app, { origin: config.APP_ORIGIN, budgets, teams });
  registerProjectCreateRoutes(app, { origin: config.APP_ORIGIN, budgets,
    projectCreation: new ProjectCreateService({ databases, sessions, secrets, origin: config.APP_ORIGIN,
      requestBudget: projectCreateAccountBudget(budgets) }) });
  registerPlanningRoutes(app, { origin: config.APP_ORIGIN, budgets, planning });
  registerFilesRoutes(app, { origin: config.APP_ORIGIN, budgets,
    files: new FilesService({ databases, sessions, secrets, origin: config.APP_ORIGIN, planning, deploymentLimitBytes: config.FILE_STORAGE_LIMIT_BYTES, requestBudget: filesAccountBudget(budgets) }) });
  registerFileEvidenceRoutes(app, { origin: config.APP_ORIGIN, budgets,
    evidence: new FileEvidenceService({ databases, sessions, secrets, origin: config.APP_ORIGIN, planning }) });
  registerDeliveryRoutes(app, { origin: config.APP_ORIGIN, budgets,
    delivery: new DeliveryService({ databases, sessions, secrets, origin: config.APP_ORIGIN, planning }) });
  registerCollaborationRoutes(app, { origin: config.APP_ORIGIN, budgets, collaboration });
  registerUpgradeRoutes(app, { origin: config.APP_ORIGIN, budgets, upgrades: new UpgradeService({ databases, sessions, secrets, origin: config.APP_ORIGIN,
    handlers: { planning: (a,payload)=>planning.save(a.cookieValue,a.csrfToken,payload), team: (a,payload)=>teams.save(a,payload),
      collaboration: (a,payload)=>collaboration.save(a.cookieValue,a.csrfToken,payload) } }) });
  registerReceiptRoutes(app, { origin: config.APP_ORIGIN, budgets, receipts: new ReceiptService({ databases, sessions,
    requestBudget: ({ workspaceId, accountId })=>budgets.take([{purpose:'receipts-account',key:`${workspaceId}:${accountId}`,limit:600,windowMs:600000}]) }) });
  registerInboxRoutes(app, { origin: config.APP_ORIGIN, budgets,
    inbox: new InboxService({ databases, sessions, origin: config.APP_ORIGIN }) });
  registerLiveRoutes(app, { origin: config.APP_ORIGIN, budgets, live: new LiveService({ databases, sessions }) });
  registerReportingRoutes(app, { origin: config.APP_ORIGIN, budgets,
    reporting: new ReportingService({ databases, sessions, secrets, origin: config.APP_ORIGIN,
      requestBudget: ({ workspaceId, accountId }) => budgets.take([{ purpose: 'reporting-account', key: `${workspaceId}:${accountId}`, limit: 600, windowMs: 600000 }]) }) });
  let closing = false;
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => {
      if (closing) return;
      closing = true;
      void app.close().then(() => { process.exitCode = 0; });
    });
  }
  await app.listen({ host: config.HOST, port: config.PORT });
} catch (error) {
  // Configuration errors are sanitised; runtime errors must not expose connection details.
  const message = error instanceof Error && /configuration|APP_ORIGIN|Production|databases must/.test(error.message)
    ? error.message : 'API startup failed';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

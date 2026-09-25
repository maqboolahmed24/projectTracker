import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { createDatabases } from './db.js';
import { ActivationService } from './modules/identity/activation.js';
import { RequestBudgets, createRequestBudgetPool } from './modules/identity/budgets.js';
import { OpaqueService } from './modules/identity/opaque.js';
import { registerActivationRoutes } from './modules/identity/routes.js';
import { loadIdentityConfig, ServiceSecrets } from './modules/identity/secrets.js';
import { randomUUID } from 'node:crypto';
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

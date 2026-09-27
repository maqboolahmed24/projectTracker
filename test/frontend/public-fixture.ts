import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import { buildApp } from '../../src/app.js';
import { loadConfig } from '../../src/config.js';
import { createDatabases } from '../../src/db.js';
import { EntitlementOperations } from '../../src/modules/identity/entitlements.js';
import { ServiceSecrets } from '../../src/modules/identity/secrets.js';
import { origin } from '../browser/authentication-fixture.js';

/** Actual public application routes only. Pools are lazy and no DB query or
 * workspace mutation is performed by these entry-screen journeys. */
export async function publicFrontendFixture() {
  const local = parseEnv(await readFile('.env', 'utf8').catch(() => ''));
  const config = loadConfig({ ...local, ...process.env, NODE_ENV: 'test', APP_ORIGIN: origin, LOG_LEVEL: 'silent' });
  const databases = createDatabases(config), app = buildApp(config, databases);
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'frontend-public-test' });
  const trustedServiceKeys = { [secrets.keyId]: await new EntitlementOperations(databases, secrets).publicSigningKey() };
  app.get('/v1/application', async () => ({ version: 1, trustedServiceKeys }));
  try { await app.listen({ host: '127.0.0.1', port: 3556 }); }
  catch (error) { await app.close(); throw error; }
  return { close: () => app.close() };
}

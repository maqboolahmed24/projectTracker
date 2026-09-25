import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadConfig, type Config } from '../src/config.js';
import { migrateStore, MigrationError } from '../src/migrations.js';

/** Compiled entry point is dist/scripts/migrate.js; SQL is shipped at project root. */
export async function migrate(config: Config): Promise<void> {
  if (!config.ADMIN_DATABASE_URL || !config.CONTROL_ADMIN_DATABASE_URL) throw new MigrationError('CONFIGURATION');
  const stores = [
    { name: 'application', schema: 'app', adminUrl: config.ADMIN_DATABASE_URL, runtimeUrl: config.DATABASE_URL },
    { name: 'control', schema: 'security', adminUrl: config.CONTROL_ADMIN_DATABASE_URL, runtimeUrl: config.CONTROL_DATABASE_URL },
  ];
  for (const store of stores) {
    const result = await migrateStore({ ...store, directory: fileURLToPath(new URL(`../../migrations/${store.name}/`, import.meta.url)) });
    process.stdout.write(`${store.name}: ${result.applied.length} applied, ${result.unchanged.length} unchanged\n`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await migrate(loadConfig(process.env, { allowAdmin: true }));
  } catch (error) {
    const code = error instanceof MigrationError ? error.code : 'CONFIGURATION';
    process.stderr.write(`Migration failed (${code}); check migration history, credentials, and database availability\n`);
    process.exitCode = 1;
  }
}

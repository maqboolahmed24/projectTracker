import { z } from 'zod';

const postgresUrl = z.string().url().refine((value) => {
  const url = new URL(value);
  return ['postgres:', 'postgresql:'].includes(url.protocol) && url.pathname.length > 1;
}, 'must be a PostgreSQL connection URL with a database name');

const environment = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('127.0.0.1'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3400),
  APP_ORIGIN: z.string().url().default('http://localhost:3400'),
  DATABASE_URL: postgresUrl,
  CONTROL_DATABASE_URL: postgresUrl,
  ADMIN_DATABASE_URL: postgresUrl.optional(),
  CONTROL_ADMIN_DATABASE_URL: postgresUrl.optional(),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'silent']).default('info'),
});

export type Config = z.infer<typeof environment>;

/** Deliberately reports field names only, never connection URLs or secret values. */
export function loadConfig(input: NodeJS.ProcessEnv = process.env, options: { allowAdmin?: boolean } = {}): Config {
  if (!options.allowAdmin && (input.ADMIN_DATABASE_URL !== undefined || input.CONTROL_ADMIN_DATABASE_URL !== undefined)) {
    throw new Error('Runtime configuration must not include migration credentials');
  }
  const parsed = environment.safeParse(input);
  if (!parsed.success) {
    throw new Error(`Invalid configuration: ${[...new Set(parsed.error.issues.map((issue) => issue.path[0]))].join(', ')}`);
  }
  const config = parsed.data;
  const origin = new URL(config.APP_ORIGIN);
  if (origin.origin !== config.APP_ORIGIN || origin.username || origin.password) {
    throw new Error('APP_ORIGIN must be an origin without a path, credentials, or query');
  }
  const appDb = new URL(config.DATABASE_URL);
  const controlDb = new URL(config.CONTROL_DATABASE_URL);
  const databaseIdentity = (url: URL) => `${url.hostname.toLowerCase()}:${url.port || '5432'}/${decodeURIComponent(url.pathname.slice(1))}`;
  if (databaseIdentity(appDb) === databaseIdentity(controlDb)) {
    throw new Error('Application and security control databases must be separate');
  }
  if (config.NODE_ENV === 'production') {
    if (origin.protocol !== 'https:') throw new Error('Production APP_ORIGIN requires HTTPS');
    for (const url of [appDb, controlDb]) {
      if (!url.password || decodeURIComponent(url.password).includes('local_only')) {
        throw new Error('Production requires explicit non-development database credentials');
      }
    }
  }
  return config;
}

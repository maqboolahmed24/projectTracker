import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import pg from 'pg';

export type MigrationErrorCode = 'CONFIGURATION' | 'FILES' | 'IDENTITY' | 'HISTORY' | 'CHECKSUM' | 'DATABASE';

/** Only this safe code reaches CLI output; database errors can contain SQL and secrets. */
export class MigrationError extends Error {
  constructor(readonly code: MigrationErrorCode) {
    super(`Migration failed (${code})`);
    this.name = 'MigrationError';
  }
}

export interface MigrationOptions {
  adminUrl: string;
  runtimeUrl: string;
  directory: string;
  schema: string;
}

export interface MigrationResult {
  applied: string[];
  unchanged: string[];
}

interface Migration {
  name: string;
  version: bigint;
  checksum: string;
  sql: string;
}

function databaseIdentity(url: URL): string {
  return `${url.hostname.toLowerCase()}:${url.port || '5432'}/${decodeURIComponent(url.pathname.slice(1))}`;
}

function validateOptions(options: MigrationOptions): { runtimeRole: string; adminRole: string } {
  try {
    const admin = new URL(options.adminUrl);
    const runtime = new URL(options.runtimeUrl);
    const adminRole = decodeURIComponent(admin.username);
    const runtimeRole = decodeURIComponent(runtime.username);
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(options.schema) || options.schema.startsWith('pg_') ||
      ['public', 'information_schema', 'ukda_migrations'].includes(options.schema) ||
      ![admin, runtime].every((url) => ['postgres:', 'postgresql:'].includes(url.protocol) && url.pathname.length > 1) ||
      databaseIdentity(admin) !== databaseIdentity(runtime) || !adminRole || !runtimeRole || adminRole === runtimeRole) {
      throw new Error();
    }
    return { runtimeRole, adminRole };
  } catch {
    throw new MigrationError('CONFIGURATION');
  }
}

/** Files are trusted, reviewed deployment artifacts, never request-supplied SQL. */
async function readMigrations(directory: string): Promise<Migration[]> {
  try {
    const entries = await readdir(directory, { withFileTypes: true });
    const migrations: Migration[] = [];
    for (const entry of entries) {
      if (!entry.name.endsWith('.sql')) continue;
      const match = /^(\d{3,})_[a-z][a-z0-9_]*\.sql$/.exec(entry.name);
      if (!entry.isFile() || !match?.[1]) throw new Error();
      const version = BigInt(match[1]);
      if (version < 1n || version > 9223372036854775807n) throw new Error();
      const bytes = await readFile(join(directory, entry.name));
      if (bytes.length === 0) throw new Error();
      migrations.push({ name: entry.name, version, sql: bytes.toString('utf8'), checksum: createHash('sha256').update(bytes).digest('hex') });
    }
    migrations.sort((left, right) => left.version < right.version ? -1 : left.version > right.version ? 1 : 0);
    if (!migrations.length || migrations.some((migration, index) => index > 0 && migrations[index - 1]?.version === migration.version)) {
      throw new Error();
    }
    return migrations;
  } catch {
    throw new MigrationError('FILES');
  }
}

/**
 * All pending files, ledger rows, and grants commit together for one database.
 * SQL must not contain transaction-control statements; migrations own the transaction.
 * Application and control stores intentionally have independent transactions.
 */
export async function migrateStore(options: MigrationOptions): Promise<MigrationResult> {
  const { runtimeRole, adminRole } = validateOptions(options);
  const migrations = await readMigrations(options.directory);
  const admin = new pg.Client({ connectionString: options.adminUrl, connectionTimeoutMillis: 3000, application_name: 'ukda-migrations' });
  const runtime = new pg.Client({ connectionString: options.runtimeUrl, connectionTimeoutMillis: 3000, application_name: 'ukda-migration-identity-check' });
  // Client error events must never become an uncaught credential-bearing exception.
  admin.on('error', () => {});
  runtime.on('error', () => {});
  let transactionOpen = false;
  try {
    await admin.connect();
    await runtime.connect();
    const identity = await runtime.query<{
      role: string; restricted: boolean; can_assume_admin: boolean; can_create_schema: boolean;
    }>(`
      SELECT current_user AS role,
        NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR rolreplication) AS restricted,
        pg_has_role(current_user, $1, 'MEMBER') AS can_assume_admin,
        has_database_privilege(current_user, current_database(), 'CREATE') AS can_create_schema
      FROM pg_roles WHERE rolname = current_user
    `, [adminRole]);
    const actualAdmin = await admin.query<{ role: string }>('SELECT current_user AS role');
    const row = identity.rows[0];
    if (!row || row.role !== runtimeRole || !row.restricted || row.can_assume_admin || row.can_create_schema || actualAdmin.rows[0]?.role !== adminRole) {
      throw new MigrationError('IDENTITY');
    }
    await runtime.end();
    await admin.query('BEGIN');
    transactionOpen = true;
    await admin.query("SET LOCAL lock_timeout = '30s'; SET LOCAL statement_timeout = '120s'; SET LOCAL search_path = pg_catalog");
    // Database-local, transaction-scoped lock also covers first creation of the ledger.
    const lock = createHash('sha256').update('ukda:sql-migrations:v1').digest().readBigInt64BE();
    await admin.query('SELECT pg_advisory_xact_lock($1::bigint)', [lock.toString()]);
    await admin.query(`
      CREATE SCHEMA IF NOT EXISTS ukda_migrations;
      REVOKE ALL ON SCHEMA ukda_migrations FROM PUBLIC;
      CREATE TABLE IF NOT EXISTS ukda_migrations.applied (
        store_schema text NOT NULL,
        version bigint NOT NULL CHECK (version > 0),
        name text NOT NULL,
        checksum text NOT NULL CHECK (checksum ~ '^[a-f0-9]{64}$'),
        applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        PRIMARY KEY (store_schema, version),
        UNIQUE (store_schema, name)
      );
      REVOKE ALL ON ALL TABLES IN SCHEMA ukda_migrations FROM PUBLIC;
    `);
    const quotedRole = pg.escapeIdentifier(runtimeRole);
    await admin.query(`REVOKE ALL ON SCHEMA ukda_migrations FROM ${quotedRole}; REVOKE ALL ON ALL TABLES IN SCHEMA ukda_migrations FROM ${quotedRole}`);
    const history = await admin.query<{ name: string; version: string; checksum: string }>(
      'SELECT name, version::text, checksum FROM ukda_migrations.applied WHERE store_schema = $1 ORDER BY applied.version', [options.schema],
    );
    for (const [index, previous] of history.rows.entries()) {
      const current = migrations[index];
      if (!current || current.name !== previous.name || current.version !== BigInt(previous.version)) throw new MigrationError('HISTORY');
      if (current.checksum !== previous.checksum) throw new MigrationError('CHECKSUM');
    }
    const schema = pg.escapeIdentifier(options.schema);
    await admin.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
    // Runtime ownership would make a REVOKE ineffective: owners retain DDL rights.
    const ownership = await admin.query<{ unsafe: boolean }>(`
      SELECT EXISTS (
        SELECT 1 FROM pg_namespace WHERE nspname = $1 AND nspowner = $2::regrole
        UNION ALL
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relowner = $2::regrole
        UNION ALL
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = $1 AND p.proowner = $2::regrole
      ) AS unsafe
    `, [options.schema, runtimeRole]);
    if (ownership.rows[0]?.unsafe) throw new MigrationError('IDENTITY');
    const result: MigrationResult = { applied: [], unchanged: history.rows.map((previous) => previous.name) };
    for (const migration of migrations.slice(history.rows.length)) {
      await admin.query(migration.sql);
      await admin.query('INSERT INTO ukda_migrations.applied (store_schema, version, name, checksum) VALUES ($1, $2, $3, $4)',
        [options.schema, migration.version.toString(), migration.name, migration.checksum]);
      result.applied.push(migration.name);
    }
    // RLS policies stay under migration control. Global security tables are service-only;
    // these SQL grants do not create an HTTP endpoint or authorize an application user.
    await admin.query(`
      REVOKE ALL ON SCHEMA ${schema} FROM PUBLIC, ${quotedRole};
      REVOKE ALL ON ALL TABLES IN SCHEMA ${schema} FROM PUBLIC, ${quotedRole};
      REVOKE ALL ON ALL SEQUENCES IN SCHEMA ${schema} FROM PUBLIC, ${quotedRole};
      REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ${schema} FROM PUBLIC, ${quotedRole};
      GRANT USAGE ON SCHEMA ${schema} TO ${quotedRole};
      GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${schema} TO ${quotedRole};
      GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA ${schema} TO ${quotedRole};
      GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ${schema} TO ${quotedRole};
    `);
    await admin.query('COMMIT');
    transactionOpen = false;
    return result;
  } catch (error) {
    if (transactionOpen) await admin.query('ROLLBACK').catch(() => {});
    if (error instanceof MigrationError) throw error;
    throw new MigrationError('DATABASE');
  } finally {
    await Promise.allSettled([admin.end(), runtime.end()]);
  }
}

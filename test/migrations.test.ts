import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import { parseEnv } from 'node:util';
import pg from 'pg';
import { migrateStore, MigrationError, type MigrationOptions } from '../src/migrations.js';

async function fixture(t: TestContext): Promise<MigrationOptions & { admin: pg.Client; runtime: pg.Client }> {
  // Admin credentials are read by this fixture only, never added to process.env or API config.
  const localAdmin = process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ? undefined :
    parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const adminUrl = process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ?? localAdmin?.ADMIN_DATABASE_URL;
  const runtimeUrl = process.env.DATABASE_URL;
  assert.ok(adminUrl, 'Migration integration tests require explicit test admin credentials');
  assert.ok(runtimeUrl, 'Migration integration tests require DATABASE_URL');
  const schema = `test_migration_${randomUUID().replaceAll('-', '')}`;
  const directory = await mkdtemp(join(tmpdir(), 'ukda-migrations-'));
  const admin = new pg.Client({ connectionString: adminUrl });
  const runtime = new pg.Client({ connectionString: runtimeUrl });
  await Promise.all([admin.connect(), runtime.connect()]);
  t.after(async () => {
    try {
      // Only fixture-owned schema/history is removed; domain tables and queue data stay intact.
      await admin.query(`DROP SCHEMA IF EXISTS ${pg.escapeIdentifier(schema)} CASCADE`);
      if ((await admin.query("SELECT to_regclass('ukda_migrations.applied') AS ledger")).rows[0]?.ledger) {
        await admin.query('DELETE FROM ukda_migrations.applied WHERE store_schema = $1', [schema]);
      }
    } finally {
      await Promise.allSettled([admin.end(), runtime.end(), rm(directory, { recursive: true, force: true })]);
    }
  });
  return { adminUrl, runtimeUrl, schema, directory, admin, runtime };
}

function hasCode(code: string): (error: unknown) => boolean {
  return (error) => error instanceof MigrationError && error.code === code;
}

test('CP02: sorted SQL migrations replay once and give runtime DML without DDL, ledger, or PUBLIC access', async (t) => {
  const options = await fixture(t);
  const schema = pg.escapeIdentifier(options.schema);
  // Intentionally write in reverse order; the runner uses numeric versions.
  await writeFile(join(options.directory, '010_function.sql'), `
    CREATE FUNCTION ${schema}.answer() RETURNS integer LANGUAGE sql AS $$ SELECT 42 $$;
    INSERT INTO ${schema}.records (value) VALUES ('migration');
  `);
  await writeFile(join(options.directory, '002_table.sql'), `
    CREATE TABLE ${schema}.records (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, value text NOT NULL);
  `);
  const first = await migrateStore(options);
  assert.deepEqual(first, { applied: ['002_table.sql', '010_function.sql'], unchanged: [] });
  const second = await migrateStore(options);
  assert.deepEqual(second, { applied: [], unchanged: ['002_table.sql', '010_function.sql'] });
  assert.equal((await options.runtime.query(`SELECT count(*)::int AS count FROM ${schema}.records`)).rows[0]?.count, 1);
  const inserted = await options.runtime.query(`INSERT INTO ${schema}.records (value) VALUES ('runtime') RETURNING id`);
  await options.runtime.query(`UPDATE ${schema}.records SET value = 'changed' WHERE id = $1`, [inserted.rows[0]?.id]);
  await options.runtime.query(`DELETE FROM ${schema}.records WHERE id = $1`, [inserted.rows[0]?.id]);
  assert.equal((await options.runtime.query(`SELECT ${schema}.answer() AS answer`)).rows[0]?.answer, 42);
  for (const sql of [
    `CREATE TABLE ${schema}.forbidden (id integer)`,
    `ALTER TABLE ${schema}.records ADD COLUMN forbidden integer`,
    `TRUNCATE ${schema}.records`,
    `SELECT * FROM ukda_migrations.applied`,
    `UPDATE ukda_migrations.applied SET checksum = repeat('0', 64)`,
  ]) {
    await assert.rejects(options.runtime.query(sql), (error: unknown) => (error as { code?: string }).code === '42501');
  }
  const publicPermissions = await options.admin.query<{ count: number }>(`
    SELECT count(*)::int AS count FROM (
      SELECT a.grantee FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE n.nspname = $1
      UNION ALL
      SELECT a.grantee FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname = $1
      UNION ALL
      SELECT a.grantee FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE n.nspname = $1
    ) privileges WHERE grantee = 0
  `, [options.schema]);
  assert.equal(publicPermissions.rows[0]?.count, 0);
});

test('CP02: checksum drift and missing or inserted migration history fail closed', async (t) => {
  const options = await fixture(t);
  const original = `CREATE TABLE ${pg.escapeIdentifier(options.schema)}.records (id integer PRIMARY KEY);`;
  const file = join(options.directory, '002_original.sql');
  await writeFile(file, original);
  await migrateStore(options);
  await writeFile(file, `${original}\n-- changed after application`);
  await assert.rejects(migrateStore(options), hasCode('CHECKSUM'));
  await writeFile(file, original);
  await writeFile(join(options.directory, '001_inserted.sql'), 'SELECT 1;');
  await assert.rejects(migrateStore(options), hasCode('HISTORY'));
  await rm(join(options.directory, '001_inserted.sql'));
  await rm(file);
  await writeFile(join(options.directory, '003_later.sql'), 'SELECT 1;');
  await assert.rejects(migrateStore(options), hasCode('HISTORY'));
  assert.equal((await options.admin.query('SELECT count(*)::int AS count FROM ukda_migrations.applied WHERE store_schema = $1', [options.schema])).rows[0]?.count, 1);
});

test('CP02: a failed SQL file rolls back the entire pending store batch and ledger', async (t) => {
  const options = await fixture(t);
  const schema = pg.escapeIdentifier(options.schema);
  await writeFile(join(options.directory, '001_baseline.sql'), `CREATE TABLE ${schema}.baseline (id integer PRIMARY KEY);`);
  await migrateStore(options);
  await writeFile(join(options.directory, '002_pending.sql'), `CREATE TABLE ${schema}.pending (id integer); INSERT INTO ${schema}.baseline VALUES (1);`);
  const failedFile = join(options.directory, '003_failure.sql');
  await writeFile(failedFile, "DO $$ BEGIN RAISE EXCEPTION 'synthetic-secret-must-not-escape'; END $$;");
  await assert.rejects(migrateStore(options), (error: unknown) => {
    assert.ok(error instanceof MigrationError);
    assert.equal(error.code, 'DATABASE');
    assert.equal(String(error).includes('synthetic-secret'), false);
    return true;
  });
  assert.equal((await options.admin.query('SELECT to_regclass($1) AS relation', [`${options.schema}.pending`])).rows[0]?.relation, null);
  assert.equal((await options.runtime.query(`SELECT count(*)::int AS count FROM ${schema}.baseline`)).rows[0]?.count, 0);
  assert.equal((await options.admin.query('SELECT count(*)::int AS count FROM ukda_migrations.applied WHERE store_schema = $1', [options.schema])).rows[0]?.count, 1);
  await writeFile(failedFile, `INSERT INTO ${schema}.baseline VALUES (2);`);
  assert.deepEqual((await migrateStore(options)).applied, ['002_pending.sql', '003_failure.sql']);
});

test('CP02: concurrent migration runners serialize and publish a single application', async (t) => {
  const options = await fixture(t);
  await writeFile(join(options.directory, '001_table.sql'), `
    SELECT pg_sleep(0.05);
    CREATE TABLE ${pg.escapeIdentifier(options.schema)}.records (id integer PRIMARY KEY);
    INSERT INTO ${pg.escapeIdentifier(options.schema)}.records VALUES (1);
  `);
  const results = await Promise.all([migrateStore(options), migrateStore(options)]);
  assert.equal(results.flatMap((result) => result.applied).length, 1);
  assert.equal(results.flatMap((result) => result.unchanged).length, 1);
  assert.equal((await options.runtime.query(`SELECT count(*)::int AS count FROM ${pg.escapeIdentifier(options.schema)}.records`)).rows[0]?.count, 1);
});

test('CP02: migration admin must be a distinct identity in the runtime database', async (t) => {
  const options = await fixture(t);
  await writeFile(join(options.directory, '001_noop.sql'), 'SELECT 1;');
  await assert.rejects(migrateStore({ ...options, adminUrl: options.runtimeUrl }), hasCode('CONFIGURATION'));
  const otherDatabase = new URL(options.adminUrl);
  otherDatabase.pathname = '/different_database';
  await assert.rejects(migrateStore({ ...options, adminUrl: otherDatabase.href }), hasCode('CONFIGURATION'));
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { loadConfig } from '../src/config.js';
import { createDatabases } from '../src/db.js';
import { buildApp } from '../src/app.js';

function config() {
  return loadConfig({
    NODE_ENV: 'test', LOG_LEVEL: 'silent',
    DATABASE_URL: process.env.DATABASE_URL,
    CONTROL_DATABASE_URL: process.env.CONTROL_DATABASE_URL,
  });
}

test('CP01: both real PostgreSQL stores are reachable with restricted runtime identities', async (t) => {
  const databases = createDatabases(config());
  t.after(() => databases.close());
  await databases.ready();
  const identities: string[] = [];
  for (const pool of [databases.application, databases.control]) {
    const { rows } = await pool.query(`
      SELECT current_database() AS database, current_user AS role,
        rolsuper, rolcreatedb, rolcreaterole, rolbypassrls,
        has_schema_privilege(current_user, 'public', 'CREATE') AS can_create
      FROM pg_roles WHERE rolname = current_user
    `);
    const role = rows[0];
    assert.ok(role);
    for (const property of ['rolsuper', 'rolcreatedb', 'rolcreaterole', 'rolbypassrls', 'can_create']) {
      assert.equal(role[property], false, `${role.role} must not have ${property}`);
    }
    identities.push(role.database);
  }
  assert.notEqual(identities[0], identities[1]);
});

test('CP01: real database readiness and a failed control connection remain safe', async (t) => {
  const healthy = buildApp(config());
  t.after(() => healthy.close());
  assert.equal((await healthy.inject('/health/ready')).statusCode, 200);
  const failedConfig = { ...config(), CONTROL_DATABASE_URL: 'postgres://unused:synthetic-secret@127.0.0.1:1/unavailable' };
  const failed = buildApp(failedConfig);
  t.after(() => failed.close());
  assert.equal((await failed.inject('/health/live')).statusCode, 200);
  const response = await failed.inject('/health/ready');
  assert.equal(response.statusCode, 503);
  assert.equal(response.body.includes('synthetic-secret'), false);
  assert.deepEqual(response.json(), { status: 'unavailable' });
});

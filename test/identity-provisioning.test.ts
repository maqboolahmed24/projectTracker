import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, open, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseEnv, promisify } from 'node:util';
import * as opaque from '@serenity-kit/opaque';
import pg from 'pg';
import { issueLicenceToFile, licenceMain } from '../scripts/licence.js';
import { ProvisioningError, setupIdentity, setupIdentityMain } from '../scripts/setup-identity.js';
import { loadIdentityConfig, ServiceSecrets } from '../src/modules/identity/secrets.js';
import { canonicalJson } from '../src/shared/crypto.js';

const execute = promisify(execFile);
const code = (expected: string) => (error: unknown) => error instanceof ProvisioningError && error.code === expected;

async function directory(t: TestContext) {
  const path = await mkdtemp(join(tmpdir(), 'ukda-provisioning-'));
  t.after(() => rm(path, { recursive: true, force: true }));
  return path;
}

async function databaseFixture(t: TestContext) {
  const path = await directory(t);
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const adminUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(adminUrl && process.env.CONTROL_DATABASE_URL, 'Provisioning integration tests need explicit test control connections');
  const pool = new pg.Pool({ connectionString: process.env.CONTROL_DATABASE_URL });
  const admin = new pg.Pool({ connectionString: adminUrl });
  const keyId = `test-provision-${randomUUID().replaceAll('-', '')}`;
  await opaque.ready;
  const identity = { SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: keyId,
    OPAQUE_SERVER_SETUP: opaque.server.createSetup(), OPAQUE_SETUP_ID: 'test-v1', AUTH_SERVER_IDENTITY: 'ukda:provision-test' };
  const secrets = new ServiceSecrets(identity);
  t.after(async () => {
    try {
      await admin.query('DELETE FROM security.entitlement_operations WHERE licence_id IN (SELECT licence_id FROM security.licences WHERE verification_key_id=$1)', [keyId]);
      await admin.query('DELETE FROM security.licences WHERE verification_key_id=$1', [keyId]);
    }
    finally { await Promise.allSettled([pool.end(), admin.end()]); }
  });
  const rows = async () => (await admin.query('SELECT * FROM security.licences WHERE verification_key_id=$1', [keyId])).rows;
  return { path, pool, admin, secrets, rows, identity };
}

test('CP03: identity setup persists valid operational secrets privately and refuses replacement', async (t) => {
  const path = await directory(t);
  const outputPath = join(path, '.env.identity');
  await setupIdentity({ outputPath, origin: 'https://workspace.example.test' });
  const original = await readFile(outputPath, 'utf8');
  const config = loadIdentityConfig(parseEnv(original));
  assert.equal(config.AUTH_SERVER_IDENTITY, 'https://workspace.example.test');
  assert.equal(Buffer.from(config.SECURITY_MASTER_KEY, 'base64url').length, 32);
  await opaque.ready;
  assert.equal(Buffer.from(opaque.server.getPublicKey(config.OPAQUE_SERVER_SETUP), 'base64url').length, 32);
  assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
  await assert.rejects(setupIdentity({ outputPath, origin: 'https://different.example.test' }), code('OUTPUT_EXISTS'));
  assert.equal(await readFile(outputPath, 'utf8'), original);
});

test('CP03: setup CLI uses the configured origin without exposing generated keys or unsafe error details', async (t) => {
  const path = await directory(t);
  const outputPath = join(path, '.env.identity');
  const script = fileURLToPath(new URL('../scripts/setup-identity.js', import.meta.url));
  const success = await execute(process.execPath, [script, '--output', outputPath],
    { env: { ...process.env, APP_ORIGIN: 'https://origin.example.test' } });
  const config = loadIdentityConfig(parseEnv(await readFile(outputPath, 'utf8')));
  assert.equal(config.AUTH_SERVER_IDENTITY, 'https://origin.example.test');
  for (const secret of [config.SECURITY_MASTER_KEY, config.OPAQUE_SERVER_SETUP]) {
    assert.equal(`${success.stdout}${success.stderr}`.includes(secret), false);
  }
  const invalidOrigin = 'https://operator:synthetic-secret@invalid.example.test/private';
  await assert.rejects(execute(process.execPath, [script, '--output', join(path, 'invalid'), '--origin', invalidOrigin]), (error: unknown) => {
    const failure = error as { stdout: string; stderr: string; code: number };
    assert.equal(failure.code, 1);
    assert.match(failure.stderr, /CONFIGURATION/);
    assert.equal(`${failure.stdout}${failure.stderr}`.includes('synthetic-secret'), false);
    return true;
  });
  await assert.rejects(setupIdentityMain(['--output', join(path, 'production')],
    { NODE_ENV: 'production', APP_ORIGIN: 'http://localhost:3400' }), code('CONFIGURATION'));
  await assert.rejects(setupIdentityMain(['--unknown', 'synthetic-secret']), code('USAGE'));
});

test('CP03: licence issuance writes one exclusive private key file and stores only its digest', async (t) => {
  const f = await databaseFixture(t);
  const outputPath = join(f.path, 'licence.json');
  const issued = await issueLicenceToFile({ pool: f.pool, secrets: f.secrets, outputPath });
  const storedFile = JSON.parse(await readFile(outputPath, 'utf8')) as { licenceId: string; licenceKey: string };
  assert.equal(storedFile.licenceId, issued.licenceId);
  assert.match(storedFile.licenceKey, /^LIC-[A-Za-z0-9_-]{43}$/);
  assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
  const rows = await f.rows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.state, 'available');
  assert.equal(f.secrets.matches('licence', storedFile.licenceKey, rows[0]?.verification_digest), true);
  assert.equal(JSON.stringify(rows).includes(storedFile.licenceKey), false);
  const existing = await readFile(outputPath, 'utf8');
  await assert.rejects(issueLicenceToFile({ pool: f.pool, secrets: f.secrets, outputPath }), code('OUTPUT_EXISTS'));
  assert.equal(await readFile(outputPath, 'utf8'), existing);
  assert.equal((await f.rows()).length, 1);
});

test('CP03: a real output-write failure rolls back licence insertion and removes its partial file', async (t) => {
  const f = await databaseFixture(t);
  const probe = await open(join(f.path, 'prototype-probe'), 'wx', 0o600);
  const prototype: object = Object.getPrototypeOf(probe);
  await probe.close();
  const mocked = t.mock.method(prototype, 'writeFile' as never, async () => { throw new Error('synthetic-sensitive-write-error'); });
  const outputPath = join(f.path, 'failed-licence.json');
  try {
    await assert.rejects(issueLicenceToFile({ pool: f.pool, secrets: f.secrets, outputPath }), (error: unknown) => {
      assert.ok(code('OUTPUT_WRITE')(error));
      assert.equal(String(error).includes('synthetic-sensitive'), false);
      return true;
    });
  } finally { mocked.mock.restore(); }
  await assert.rejects(stat(outputPath), (error: unknown) => (error as { code?: string }).code === 'ENOENT');
  assert.equal((await f.rows()).length, 0);
});

test('CP03: a lost COMMIT acknowledgement retains the only key file for the committed licence', async (t) => {
  const f = await databaseFixture(t);
  const client = await f.pool.connect();
  const originalQuery = client.query;
  const query = t.mock.method(client, 'query', async (...args: unknown[]) => {
    const result: unknown = await Reflect.apply(originalQuery, client, args);
    if (args[0] === 'COMMIT') throw new Error('synthetic-lost-commit-response');
    return result;
  });
  const connect = t.mock.method(f.pool, 'connect', async () => client);
  const outputPath = join(f.path, 'uncertain-licence.json');
  try { await assert.rejects(issueLicenceToFile({ pool: f.pool, secrets: f.secrets, outputPath }), code('COMMIT_UNCERTAIN')); }
  finally { query.mock.restore(); connect.mock.restore(); }
  const retained = JSON.parse(await readFile(outputPath, 'utf8')) as { licenceId: string; licenceKey: string };
  const rows = await f.rows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.licence_id, retained.licenceId);
  assert.equal(f.secrets.matches('licence', retained.licenceKey, rows[0]?.verification_digest), true);
});

test('CP03: licence CLI refuses invalid configuration and leaves an existing output untouched', async (t) => {
  const path = await directory(t);
  const outputPath = join(path, 'existing-output');
  await writeFile(outputPath, 'preserve-existing-output', { mode: 0o600 });
  const script = fileURLToPath(new URL('../scripts/licence.js', import.meta.url));
  await assert.rejects(execute(process.execPath, [script, 'issue', '--output', outputPath],
    { env: { ...process.env, SECURITY_MASTER_KEY: 'synthetic-invalid-private-key' } }), (error: unknown) => {
    const failure = error as { stdout: string; stderr: string; code: number };
    assert.equal(failure.code, 1);
    assert.match(failure.stderr, /CONFIGURATION/);
    assert.equal(`${failure.stdout}${failure.stderr}`.includes('synthetic-invalid-private-key'), false);
    return true;
  });
  assert.equal(await readFile(outputPath, 'utf8'), 'preserve-existing-output');
  await assert.rejects(licenceMain(['revoke', '--licence-id', randomUUID(), '--operation-id', randomUUID(), '--operator-id', 'untrusted-operator']), code('USAGE'));
  await assert.rejects(licenceMain(['reinstate', '--licence-id', randomUUID(), '--operation-id', randomUUID()]), code('USAGE'));
});

test('CP03: operational entitlement CLI dispatches all actions and replays a stable operation once', async (t) => {
  const f = await databaseFixture(t);
  const outputPath = join(f.path, 'entitlement.json');
  const issued = await issueLicenceToFile({ pool: f.pool, secrets: f.secrets, outputPath });
  const file = JSON.parse(await readFile(outputPath, 'utf8')) as { licenceKey: string };
  const environment = { ...process.env, ...f.identity, NODE_ENV: 'test' };
  const operatorId = randomUUID();
  const revoke = ['revoke', '--licence-id', issued.licenceId, '--operation-id', randomUUID(), '--operator-id', operatorId];
  const first = await licenceMain(revoke, environment);
  assert.equal(first.kind, 'changed');
  if (first.kind !== 'changed') throw new Error('Expected entitlement result');
  assert.equal(first.result.receipt.entitlementState, 'revoked');
  assert.equal(first.result.receipt.workspaceId, null);
  assert.equal(canonicalJson(await licenceMain(revoke, environment)), canonicalJson(first));
  for (const [command, expected] of [['reinstate', 'available'], ['legacy-expire', 'legacy_expired']] as const) {
    const result = await licenceMain([command, '--licence-id', issued.licenceId, '--operation-id', randomUUID(), '--operator-id', operatorId], environment);
    assert.equal(result.kind, 'changed');
    if (result.kind === 'changed') assert.equal(result.result.receipt.entitlementState, expected);
  }
  assert.equal((await f.admin.query('SELECT count(*)::int AS count FROM security.entitlement_operations WHERE licence_id=$1', [issued.licenceId])).rows[0]?.count, 3);
  for (const secret of [file.licenceKey, f.identity.SECURITY_MASTER_KEY, f.identity.OPAQUE_SERVER_SETUP]) {
    assert.equal(JSON.stringify(first).includes(secret), false);
  }
});

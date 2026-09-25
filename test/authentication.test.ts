import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test, { type TestContext } from 'node:test';
import { parseEnv } from 'node:util';
import * as opaqueLibrary from '@serenity-kit/opaque';
import pg from 'pg';
import { ClientOpaqueError, finishLogin, finishRegistration, startLogin, startRegistration } from '../src/client/opaque.js';
import { loadConfig } from '../src/config.js';
import { createDatabases, transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { AuthenticationService, type LoginFinishInput } from '../src/modules/identity/authentication.js';
import { OpaqueService } from '../src/modules/identity/opaque.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { SessionService } from '../src/modules/identity/sessions.js';

const password = 'A quiet authentication test passphrase 761';
const origin = 'http://localhost:3400';
const failed = (error: unknown) => error instanceof AppError && error.code === 'AUTHENTICATION_FAILED' &&
  error.message === 'Authentication failed' && error.statusCode === 401;

async function fixture(t: TestContext) {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const adminUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(adminUrl, 'Authentication tests require explicit control fixture admin credentials');
  const admin = new pg.Pool({ connectionString: adminUrl });
  const databases = createDatabases(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }));
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'cp04-auth-test' });
  await opaqueLibrary.ready;
  const opaque = new OpaqueService({ serverSetup: opaqueLibrary.server.createSetup(), setupId: 'cp04-auth-v1', serverIdentity: 'ukda:cp04-auth-test' });
  let currentTime = new Date();
  const now = () => new Date(currentTime);
  const sessions = new SessionService({ databases, secrets, origin, now });
  const service = new AuthenticationService({ databases, secrets, opaque, sessions, origin, now });
  const workspaces: string[] = [];
  const licences: string[] = [];
  t.after(async () => {
    try {
      await transaction(admin, async (client) => {
        await client.query('DELETE FROM security.auth_attempts WHERE workspace_id = ANY($1::uuid[])', [workspaces]);
        for (const workspaceId of workspaces) {
          await client.query("SELECT set_config('ukda.workspace_id', $1, true)", [workspaceId]);
          await client.query('DELETE FROM security.workspaces WHERE workspace_id = $1', [workspaceId]);
        }
        await client.query('DELETE FROM security.licences WHERE licence_id = ANY($1::uuid[])', [licences]);
      });
    } finally { await Promise.allSettled([admin.end(), databases.close()]); }
  });
  async function addAccount() {
    const workspaceId = randomUUID(), accountId = randomUUID(), licenceId = randomUUID();
    workspaces.push(workspaceId); licences.push(licenceId);
    const registration = await startRegistration(password);
    const response = await opaque.response(workspaceId, accountId, registration.registrationRequest);
    const registered = await finishRegistration({ password, clientRegistrationState: registration.clientRegistrationState,
      registrationResponse: response.registrationResponse, configuration: response.configuration });
    await transaction(admin, async (client) => {
      await client.query("SELECT set_config('ukda.workspace_id', $1, true)", [workspaceId]);
      await client.query(`INSERT INTO security.licences
        (licence_id, verification_digest, verification_key_id, state, activated_workspace_id, activated_at)
        VALUES ($1,$2,'cp04-fixture','activated',$3,$4)`, [licenceId, randomBytes(32), workspaceId, now()]);
      await client.query(`INSERT INTO security.workspaces
        (workspace_id, licence_id, lifecycle, security_head, security_version, activated_at)
        VALUES ($1,$2,'active',repeat('a',64),1,$3)`, [workspaceId, licenceId, now()]);
      await client.query(`INSERT INTO security.security_transitions
        (workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition)
        VALUES ($1,1,$2,repeat('0',64),repeat('a',64),'fixture.authority','service','{}')`, [workspaceId, randomUUID()]);
      await client.query(`INSERT INTO security.profiles
        (workspace_id, profile_id, state, credential_generation, opaque_registration_record,
         opaque_setup_id, opaque_config_id, opaque_identifiers)
        VALUES ($1,$2,'active',1,$3,$4,$5,$6)`, [workspaceId, accountId, registered.registrationRecord,
        response.configuration.setupId, response.configuration.configId, response.configuration.identifiers]);
    });
    const sql = <T>(action: (client: pg.PoolClient) => Promise<T>) => transaction(admin, async (client) => {
      await client.query("SELECT set_config('ukda.workspace_id', $1, true)", [workspaceId]);
      return action(client);
    });
    async function proof() {
      const client = await startLogin(password);
      const started = await service.startLogin({ workspaceId, accountId, startLoginRequest: client.startLoginRequest });
      const finished = await finishLogin({ password, clientLoginState: client.clientLoginState,
        loginResponse: started.loginResponse, configuration: started.configuration });
      assert.equal(finished.exportKey, registered.exportKey);
      return { started, finished, input: { loginId: started.loginId, finishLoginRequest: finished.finishLoginRequest } };
    }
    async function approvedFixture() {
      // The device/grant is a pre-existing authority fixture; device proof has its own integration suite.
      const deviceId = randomUUID(), objectId = randomUUID(), grantId = randomUUID();
      await sql(async (client) => {
        await client.query(`INSERT INTO security.staged_objects
          (workspace_id, object_id, object_kind, object_hash, versioned_object, staged_operation_id, state, committed_security_version)
          VALUES ($1,$2,'signed_grant',$3,'{}',$4,'committed',1)`, [workspaceId, objectId, randomBytes(32).toString('hex'), randomUUID()]);
        await client.query(`INSERT INTO security.devices
          (workspace_id, device_id, profile_id, key_generation, signing_public_key, recipient_public_key,
           state, approval_security_version, approved_at)
          VALUES ($1,$2,$3,1,$4,$5,'active',1,$6)`, [workspaceId, deviceId, accountId, randomBytes(32), randomBytes(32), now()]);
        await client.query(`INSERT INTO security.grants
          (workspace_id, grant_id, profile_id, device_id, grant_kind, scope_kind, generation, state,
           signed_grant_object_id,key_manifest_object_id,permissions,key_epoch, security_version, activated_at)
          VALUES ($1,$2,$3,$4,'device','workspace',1,'active',$5,$5,ARRAY['read_project'],1,1,$6)`, [workspaceId, grantId, accountId, deviceId, objectId, now()]);
        await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,generation,state,
          signed_grant_object_id,key_manifest_object_id,permissions,key_epoch,security_version,activated_at)
          VALUES($1,$2,$3,'membership','workspace',1,'active',$4,$4,ARRAY['read_project'],1,1,$5)`, [workspaceId, randomUUID(), accountId, objectId, now()]);
        await client.query(`INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version)
          VALUES($1,'workspace',$1,1,$2,1)`, [workspaceId, objectId]);
      });
      const issued = await transaction(databases.control, (client) => sessions.issue(client,
        { workspaceId, profileId: accountId, credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1',
          accessLevel: 'device_approved', deviceId }, now()));
      return { issued, deviceId, grantId };
    }
    return { workspaceId, accountId, licenceId, registered, sql, proof, approvedFixture };
  }
  return { service, sessions, secrets, opaque, databases, admin, now, addAccount,
    unknownWorkspace: () => { const id = randomUUID(); workspaces.push(id); return id; },
    advance: (ms: number) => { currentTime = new Date(currentTime.getTime() + ms); } };
}

test('CP04: a real password proof issues only a restricted session and erases the single-use encrypted state', async (t) => {
  const f = await fixture(t), a = await f.addAccount();
  const proof = await a.proof();
  const pending = (await f.admin.query('SELECT * FROM security.auth_attempts WHERE login_id=$1', [proof.started.loginId])).rows[0];
  assert.equal(pending.state, 'issued');
  assert.match(pending.server_state_ciphertext, /^cp04-auth-test\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.equal(pending.expires_at.getTime() - pending.created_at.getTime(), 120000);
  const issued = await f.service.finishLogin(proof.input);
  assert.equal(issued.accessLevel, 'restricted'); assert.equal(issued.deviceId, null);
  assert.equal(issued.accountId, a.accountId); assert.equal(issued.workspaceId, a.workspaceId);
  assert.equal((await f.sessions.authenticate(issued.cookieValue)).accessLevel, 'restricted');
  await assert.rejects(f.sessions.authenticate(issued.cookieValue, { approved: true }));
  const consumed = (await f.admin.query('SELECT * FROM security.auth_attempts WHERE login_id=$1', [proof.started.loginId])).rows[0];
  assert.equal(consumed.state, 'consumed'); assert.equal(consumed.outcome, 'verified');
  assert.equal(consumed.server_state_ciphertext, null); assert.equal(consumed.server_state_key_id, null);
  const sessionRows = await a.sql((client) => client.query('SELECT * FROM security.sessions WHERE workspace_id=$1', [a.workspaceId]));
  const stored = JSON.stringify({ pending, consumed, sessions: sessionRows.rows });
  for (const secret of [password, a.registered.exportKey, proof.finished.sessionKey, issued.cookieValue, issued.csrfToken]) {
    assert.equal(stored.includes(secret), false, 'Provider state must contain verifiers, not plaintext client secrets or bearers');
  }
  assert.equal(JSON.stringify(f.service), '{}');
});

test('CP04: wrong passwords, unknown accounts and inactive profiles have the same packet shape and generic failed proof', async (t) => {
  const f = await fixture(t), a = await f.addAccount();
  let expectedLength: number | undefined;
  const cases = [
    { workspaceId: a.workspaceId, accountId: a.accountId, suppliedPassword: 'An incorrect authentication passphrase 162' },
    { workspaceId: a.workspaceId, accountId: randomUUID(), suppliedPassword: password },
    { workspaceId: f.unknownWorkspace(), accountId: randomUUID(), suppliedPassword: password },
    { workspaceId: a.workspaceId, accountId: a.accountId, suppliedPassword: password, inactive: true },
  ];
  for (const item of cases) {
    if (item.inactive) await a.sql((client) => client.query("UPDATE security.profiles SET state='suspended' WHERE workspace_id=$1 AND profile_id=$2", [a.workspaceId, a.accountId]));
    const client = await startLogin(item.suppliedPassword);
    const started = await f.service.startLogin({ workspaceId: item.workspaceId, accountId: item.accountId, startLoginRequest: client.startLoginRequest });
    assert.deepEqual(Object.keys(started).sort(), ['configuration', 'expiresAt', 'loginId', 'loginResponse']);
    expectedLength ??= started.loginResponse.length;
    assert.equal(started.loginResponse.length, expectedLength);
    await assert.rejects(finishLogin({ password: item.suppliedPassword, clientLoginState: client.clientLoginState,
      loginResponse: started.loginResponse, configuration: started.configuration }),
    (error: unknown) => error instanceof ClientOpaqueError && error.code === 'AUTHENTICATION');
    const input = { loginId: started.loginId, finishLoginRequest: randomBytes(64).toString('base64url') };
    await assert.rejects(f.service.finishLogin(input), failed);
    await assert.rejects(f.service.finishLogin(input), failed);
    const stored = (await f.admin.query('SELECT state,outcome,server_state_ciphertext FROM security.auth_attempts WHERE login_id=$1', [started.loginId])).rows[0];
    assert.deepEqual(stored, { state: 'consumed', outcome: 'failed', server_state_ciphertext: null });
  }
});

test('CP04: concurrent finish creates one session; expired and failed attempts cannot replay', async (t) => {
  const f = await fixture(t), a = await f.addAccount();
  const proof = await a.proof();
  const results = await Promise.allSettled([f.service.finishLogin(proof.input), f.service.finishLogin(proof.input)]);
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  const rejected = results.find((result) => result.status === 'rejected');
  assert.ok(rejected?.status === 'rejected' && failed(rejected.reason));
  assert.equal((await a.sql((client) => client.query('SELECT session_id FROM security.sessions WHERE workspace_id=$1', [a.workspaceId]))).rowCount, 1);
  const expiring = await a.proof();
  f.advance(120000);
  await assert.rejects(f.service.finishLogin(expiring.input), failed);
  await assert.rejects(f.service.finishLogin(expiring.input), failed);
  const unsuccessful = await a.proof();
  await assert.rejects(f.service.finishLogin({ ...unsuccessful.input, finishLoginRequest: randomBytes(64).toString('base64url') }), failed);
  await assert.rejects(f.service.finishLogin(unsuccessful.input), failed);
  const rows = (await f.admin.query('SELECT state,outcome,server_state_ciphertext FROM security.auth_attempts WHERE login_id=ANY($1::uuid[])',
    [[expiring.input.loginId, unsuccessful.input.loginId]])).rows;
  assert.ok(rows.every((row) => row.state === 'consumed' && row.outcome === 'failed' && row.server_state_ciphertext === null));
});

test('CP04: changed credential, session and data generations or removed authority invalidate an in-flight proof', async (t) => {
  const f = await fixture(t), a = await f.addAccount();
  const changes = [
    'UPDATE security.profiles SET credential_generation=credential_generation+1 WHERE workspace_id=$1',
    'UPDATE security.profiles SET session_generation=session_generation+1 WHERE workspace_id=$1',
    'UPDATE security.workspaces SET data_generation=data_generation+1 WHERE workspace_id=$1',
    "UPDATE security.profiles SET state='suspended' WHERE workspace_id=$1",
  ];
  for (const sql of changes) {
    const proof = await a.proof();
    await a.sql((client) => client.query(sql, [a.workspaceId]));
    await assert.rejects(f.service.finishLogin(proof.input), failed);
  }
  await a.sql((client) => client.query("UPDATE security.profiles SET state='active' WHERE workspace_id=$1", [a.workspaceId]));
  const quarantined = await a.proof();
  await a.sql((client) => client.query('UPDATE security.workspaces SET restore_quarantine=true WHERE workspace_id=$1', [a.workspaceId]));
  const restoreSession = await f.service.finishLogin(quarantined.input);
  assert.equal(restoreSession.accessLevel, 'restricted');
  await assert.rejects(f.sessions.authenticate(restoreSession.cookieValue, { approved: true }));
  await a.sql((client) => client.query('UPDATE security.workspaces SET restore_quarantine=false WHERE workspace_id=$1', [a.workspaceId]));
  const deleted = await a.proof();
  await a.sql((client) => client.query("UPDATE security.workspaces SET lifecycle='deleted',deleted_at=$2 WHERE workspace_id=$1", [a.workspaceId, f.now()]));
  await assert.rejects(f.service.finishLogin(deleted.input), failed);
});

test('CP04: restricted entitlements and pending deletion preserve password authentication', async (t) => {
  const f = await fixture(t), a = await f.addAccount();
  await a.sql(async (client) => {
    await client.query("UPDATE security.licences SET state='revoked' WHERE licence_id=$1", [a.licenceId]);
    await client.query(`UPDATE security.workspaces SET licence_state='restricted',lifecycle='pending_deletion',
      deletion_requested_at=$2,delete_after=$3 WHERE workspace_id=$1`, [a.workspaceId, f.now(), new Date(f.now().getTime() + 86400000)]);
  });
  const issued = await f.service.finishLogin((await a.proof()).input);
  assert.equal(issued.accessLevel, 'restricted');
  assert.equal((await f.sessions.authenticate(issued.cookieValue)).accountId, a.accountId);
});

test('CP04: successful account switching rotates and revokes the previous cookie across workspace boundaries', async (t) => {
  const f = await fixture(t), first = await f.addAccount(), second = await f.addAccount();
  const old = await f.service.finishLogin((await first.proof()).input);
  const next = await f.service.finishLogin((await second.proof()).input, { previousCookie: old.cookieValue });
  assert.notEqual(next.cookieValue, old.cookieValue);
  assert.equal(next.accountId, second.accountId); assert.equal(next.accessLevel, 'restricted');
  await assert.rejects(f.sessions.authenticate(old.cookieValue));
  assert.equal((await f.sessions.authenticate(next.cookieValue)).workspaceId, second.workspaceId);
  const replaced = await first.sql((client) => client.query('SELECT revoked_at FROM security.sessions WHERE workspace_id=$1 AND session_id=$2', [first.workspaceId, old.sessionId]));
  assert.ok(replaced.rows[0].revoked_at instanceof Date);
});

test('CP04: reauthentication binds current approved session, rotates it and preserves device and absolute expiry', async (t) => {
  const f = await fixture(t), a = await f.addAccount();
  const { issued: old, deviceId } = await a.approvedFixture();
  f.advance(6 * 60000);
  const client = await startLogin(password);
  const context = { cookieValue: old.cookieValue, csrfToken: old.csrfToken };
  const started = await f.service.startReauthentication({ startLoginRequest: client.startLoginRequest }, context);
  const finished = await finishLogin({ password, clientLoginState: client.clientLoginState, loginResponse: started.loginResponse, configuration: started.configuration });
  const input: LoginFinishInput = { loginId: started.loginId, finishLoginRequest: finished.finishLoginRequest };
  const fresh = await f.service.finishReauthentication(input, context);
  assert.equal(fresh.accessLevel, 'device_approved'); assert.equal(fresh.deviceId, deviceId);
  assert.equal(fresh.absoluteExpiresAt, old.absoluteExpiresAt);
  assert.equal(fresh.authenticatedAt, f.now().toISOString());
  assert.notEqual(fresh.cookieValue, old.cookieValue);
  await assert.rejects(f.sessions.authenticate(old.cookieValue));
  assert.equal((await f.sessions.authenticate(fresh.cookieValue, { approved: true, recent: true })).sessionId, fresh.sessionId);
  await assert.rejects(f.service.finishReauthentication(input, context), failed);
  const restricted = await f.service.finishLogin((await a.proof()).input);
  await assert.rejects(f.service.startReauthentication({ startLoginRequest: (await startLogin(password)).startLoginRequest },
    { cookieValue: restricted.cookieValue, csrfToken: restricted.csrfToken }));
});

test('CP04: reauthentication rejects another session and revoked approved-device authority', async (t) => {
  const f = await fixture(t), a = await f.addAccount();
  const { issued, grantId } = await a.approvedFixture();
  const context = { cookieValue: issued.cookieValue, csrfToken: issued.csrfToken };
  async function proof() {
    const client = await startLogin(password);
    const started = await f.service.startReauthentication({ startLoginRequest: client.startLoginRequest }, context);
    const finished = await finishLogin({ password, clientLoginState: client.clientLoginState, loginResponse: started.loginResponse, configuration: started.configuration });
    return { loginId: started.loginId, finishLoginRequest: finished.finishLoginRequest };
  }
  const substituted = await proof();
  const other = await f.service.finishLogin((await a.proof()).input);
  await assert.rejects(f.service.finishReauthentication(substituted, { cookieValue: other.cookieValue, csrfToken: other.csrfToken }), failed);
  await assert.rejects(f.service.finishReauthentication(substituted, context), failed);
  const revoked = await proof();
  await a.sql((client) => client.query("UPDATE security.grants SET state='revoked',revoked_at=$3 WHERE workspace_id=$1 AND grant_id=$2", [a.workspaceId, grantId, f.now()]));
  await assert.rejects(f.service.finishReauthentication(revoked, context), failed);
  await assert.rejects(f.service.finishReauthentication(revoked, context), failed);
});

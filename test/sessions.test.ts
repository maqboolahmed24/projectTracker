import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { createDatabases, transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { SessionService, buildSessionCookie, clearSessionCookie, readSessionCookie, SESSION_COOKIE_NAME, type SessionIssue } from '../src/modules/identity/sessions.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { deviceChallenge } from '../src/shared/auth.js';
import { generateSigningKeyPair, generateRecipientKeyPair, signObject } from '../src/shared/crypto.js';

const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;

async function fixture(t: TestContext) {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const applicationUrl = process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ?? local.ADMIN_DATABASE_URL;
  const controlUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(applicationUrl && controlUrl, 'Session integration tests require explicit fixture admin credentials');
  const db = createDatabases(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }));
  const admin = { application: new pg.Pool({ connectionString: applicationUrl }), control: new pg.Pool({ connectionString: controlUrl }) };
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'cp04-sessions' });
  let now = new Date();
  const workspaceId = randomUUID(), licenceId = randomUUID(), profileId = randomUUID(), otherProfileId = randomUUID();
  const deviceId = randomUUID(), pendingDeviceId = randomUUID(), otherDeviceId = randomUUID(), grantId = randomUUID(), objectId = randomUUID(), operationId = randomUUID();
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair(), otherSigning = await generateSigningKeyPair();
  const sessions = new SessionService({ databases: db, secrets, origin: 'https://sessions.example', now: () => new Date(now) });
  t.after(async () => {
    try {
      await admin.application.query('DELETE FROM app.workspaces WHERE workspace_id=$1', [workspaceId]);
      await admin.control.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
      await admin.control.query('DELETE FROM security.licences WHERE licence_id=$1', [licenceId]);
    } finally { await Promise.allSettled([db.close(), admin.application.end(), admin.control.end()]); }
  });
  await transaction(admin.control, async (client) => {
    await client.query("INSERT INTO security.licences(licence_id,verification_digest,verification_key_id) VALUES($1,$2,'fixture')", [licenceId, randomBytes(32)]);
    await client.query(`INSERT INTO security.workspaces(workspace_id,licence_id,lifecycle,security_head,security_version,ownership_version,custody_epoch,activated_at)
      VALUES($1,$2,'active',repeat('a',64),1,1,1,$3)`, [workspaceId, licenceId, now]);
    await client.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition)
      VALUES($1,1,$2,repeat('0',64),repeat('a',64),'fixture','service','{}')`, [workspaceId, operationId]);
    // The fixture represents already-validated committed grant authority. CP5 tests
    // signed grant creation; these tests exercise session and device proof enforcement.
    await client.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
      VALUES($1,$2,'signed_grant',repeat('b',64),'{"fixture":true}',$3,'committed',1)`, [workspaceId, objectId, operationId]);
    await client.query(`INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version)
      VALUES($1,'workspace',$1,1,$2,1)`, [workspaceId, objectId]);
    for (const id of [profileId, otherProfileId]) await client.query(`INSERT INTO security.profiles(workspace_id,profile_id,state,credential_generation,
      opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers) VALUES($1,$2,'active',1,'AA','fixture','fixture','{}')`, [workspaceId, id]);
    for (const [id, profile, state, publicKey] of [[deviceId, profileId, 'active', signing.publicKey], [pendingDeviceId, profileId, 'pending', signing.publicKey], [otherDeviceId, otherProfileId, 'active', otherSigning.publicKey]] as const) {
      await client.query(`INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approval_security_version,approved_at)
        VALUES($1,$2,$3,1,$4,$5,$6,$7,$8)`, [workspaceId, id, profile, publicKey, recipient.publicKey, state, state === 'active' ? '1' : null, state === 'active' ? now : null]);
    }
    for (const [id, device, profile] of [[grantId, deviceId, profileId], [randomUUID(), otherDeviceId, otherProfileId]] as const) {
      await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,generation,state,signed_grant_object_id,key_manifest_object_id,permissions,key_epoch,security_version,activated_at)
        VALUES($1,$2,$3,$4,'device','workspace',1,'active',$5,$5,ARRAY['read_project'],1,1,$6)`, [workspaceId, id, profile, device, objectId, now]);
      await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,generation,state,signed_grant_object_id,key_manifest_object_id,permissions,key_epoch,security_version,activated_at)
        VALUES($1,$2,$3,'membership','workspace',1,'active',$4,$4,ARRAY['read_project'],1,1,$5)`, [workspaceId, randomUUID(), profile, objectId, now]);
    }
  });
  await admin.application.query('INSERT INTO app.workspaces(workspace_id,fence_closed) VALUES($1,true)', [workspaceId]);
  const issue = (overrides: Partial<SessionIssue> = {}) => transaction(db.control, (client) => sessions.issue(client, {
    workspaceId, profileId, credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1', accessLevel: 'restricted', ...overrides,
  }));
  const ceremonyState = async (ceremonyId: string) => (await admin.control.query('SELECT state FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [workspaceId, ceremonyId])).rows[0]?.state as string;
  return { db, admin, secrets, sessions, workspaceId, profileId, otherProfileId, deviceId, pendingDeviceId, otherDeviceId, grantId,
    signing, otherSigning, issue, ceremonyState, now: () => new Date(now), advance: (milliseconds: number) => { now = new Date(now.getTime() + milliseconds); } };
}

test('CP04: session secrets stay in verifiers, cookies are host-only secure, and CSRF binds to its session', async (t) => {
  const f = await fixture(t), issued = await f.issue(), other = await f.issue();
  const stored = (await f.admin.control.query('SELECT * FROM security.sessions WHERE workspace_id=$1 AND session_id=$2', [f.workspaceId, issued.sessionId])).rows[0];
  assert.equal(stored.token_digest.length, 32); assert.equal(stored.csrf_digest.length, 32);
  for (const secret of [issued.cookieValue, issued.csrfToken]) assert.equal(JSON.stringify(stored).includes(secret), false);
  const principal = await f.sessions.authenticate(issued.cookieValue, { csrfToken: issued.csrfToken, recent: true });
  assert.equal(principal.profileId, f.profileId); assert.equal(principal.csrfToken, issued.csrfToken);
  await assert.rejects(f.sessions.authenticate(issued.cookieValue, { csrfToken: other.csrfToken }), code('CSRF_INVALID'));
  const cookie = buildSessionCookie(issued.cookieValue, new Date(issued.absoluteExpiresAt), f.now());
  for (const attribute of ['Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/']) assert.equal(cookie.includes(attribute), true);
  assert.equal(cookie.includes('Domain='), false); assert.ok(cookie.startsWith('__Host-ukda_session='));
  assert.equal(readSessionCookie(`${SESSION_COOKIE_NAME}=${issued.cookieValue}; other=x`), issued.cookieValue);
  assert.equal(readSessionCookie(`${SESSION_COOKIE_NAME}=${issued.cookieValue}; ${SESSION_COOKIE_NAME}=${other.cookieValue}`), undefined);
  assert.equal(readSessionCookie(`${SESSION_COOKIE_NAME}=invalid`), undefined);
  assert.ok(clearSessionCookie().includes('Max-Age=0'));
  const tampered = issued.cookieValue.split('.'); tampered[1] = randomUUID();
  await assert.rejects(f.sessions.authenticate(tampered.join('.')), code('AUTH_REQUIRED'));
  tampered[1] = f.workspaceId; tampered[2] = other.sessionId;
  await assert.rejects(f.sessions.authenticate(tampered.join('.')), code('AUTH_REQUIRED'));
});

test('CP06: revoking personal membership immediately rejects an otherwise active approved device/session', async (t) => {
  const f = await fixture(t), issued = await f.issue({ accessLevel: 'device_approved', deviceId: f.deviceId });
  assert.equal((await f.sessions.authenticate(issued.cookieValue, { approved: true })).deviceId, f.deviceId);
  await f.admin.control.query("UPDATE security.grants SET state='revoked',revoked_at=clock_timestamp() WHERE workspace_id=$1 AND profile_id=$2 AND grant_kind='membership'", [f.workspaceId, f.profileId]);
  assert.equal((await f.admin.control.query('SELECT state FROM security.devices WHERE workspace_id=$1 AND device_id=$2', [f.workspaceId, f.deviceId])).rows[0].state, 'active');
  assert.equal((await f.admin.control.query('SELECT state FROM security.grants WHERE workspace_id=$1 AND grant_id=$2', [f.workspaceId, f.grantId])).rows[0].state, 'active');
  await assert.rejects(f.sessions.authenticate(issued.cookieValue, { approved: true }), code('DEVICE_APPROVAL_REQUIRED'));
  await assert.rejects(f.issue({ accessLevel: 'device_approved', deviceId: f.deviceId }), code('DEVICE_APPROVAL_REQUIRED'));
});

test('CP04: idle, absolute and recent-authentication deadlines enforce their separate limits', async (t) => {
  const f = await fixture(t), issued = await f.issue();
  assert.equal(Date.parse(issued.idleExpiresAt) - Date.parse(issued.authenticatedAt), 30 * 60_000);
  assert.equal(Date.parse(issued.absoluteExpiresAt) - Date.parse(issued.authenticatedAt), 12 * 60 * 60_000);
  f.advance(5 * 60_000);
  await assert.rejects(f.sessions.authenticate(issued.cookieValue, { recent: true }), code('REAUTH_REQUIRED'));
  f.advance(24 * 60_000);
  const refreshed = await f.sessions.authenticate(issued.cookieValue);
  assert.equal(refreshed.idleExpiresAt.getTime() - f.now().getTime(), 30 * 60_000);
  f.advance(30 * 60_000);
  await assert.rejects(f.sessions.authenticate(issued.cookieValue), code('AUTH_REQUIRED'));
  const nearDeadline = await f.issue({ authenticatedAt: new Date(f.now().getTime() - (11 * 60 + 50) * 60_000), absoluteExpiresAt: new Date(f.now().getTime() + 10 * 60_000) });
  f.advance(9 * 60_000);
  const bounded = await f.sessions.authenticate(nearDeadline.cookieValue);
  assert.equal(bounded.idleExpiresAt.toISOString(), nearDeadline.absoluteExpiresAt);
  f.advance(60_000);
  await assert.rejects(f.sessions.authenticate(nearDeadline.cookieValue), code('AUTH_REQUIRED'));
});

test('CP04: authentication survives independent restrictions but rejects stale generations and inactive accounts', async (t) => {
  const f = await fixture(t), issued = await f.issue();
  await f.admin.control.query(`UPDATE security.workspaces SET licence_state='restricted',content_maintenance=true,restore_quarantine=true,
    lifecycle='pending_deletion',deletion_requested_at=now(),delete_after=now()+interval '7 days' WHERE workspace_id=$1`, [f.workspaceId]);
  assert.equal((await f.sessions.authenticate(issued.cookieValue)).accessLevel, 'restricted');
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.fence_closed, true);
  await f.admin.control.query('UPDATE security.profiles SET credential_generation=2 WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.profileId]);
  await assert.rejects(f.sessions.authenticate(issued.cookieValue), code('AUTH_REQUIRED'));
  const second = await f.issue({ credentialGeneration: '2' });
  await f.admin.control.query('UPDATE security.profiles SET session_generation=2 WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.profileId]);
  await assert.rejects(f.sessions.authenticate(second.cookieValue), code('AUTH_REQUIRED'));
  const third = await f.issue({ credentialGeneration: '2', sessionGeneration: '2' });
  await f.admin.control.query('UPDATE security.workspaces SET data_generation=2 WHERE workspace_id=$1', [f.workspaceId]);
  await assert.rejects(f.sessions.authenticate(third.cookieValue), code('AUTH_REQUIRED'));
  const fourth = await f.issue({ credentialGeneration: '2', sessionGeneration: '2', dataGeneration: '2' });
  await f.admin.control.query("UPDATE security.profiles SET state='suspended' WHERE workspace_id=$1 AND profile_id=$2", [f.workspaceId, f.profileId]);
  await assert.rejects(f.sessions.authenticate(fourth.cookieValue), code('AUTH_REQUIRED'));
  await assert.rejects(f.issue(), code('AUTH_REQUIRED'));
});

test('CP04: approved-device proof rotates sessions and preserves authentication time and absolute expiry', async (t) => {
  const f = await fixture(t), issued = await f.issue();
  await assert.rejects(f.sessions.authenticate(issued.cookieValue, { approved: true }), code('DEVICE_APPROVAL_REQUIRED'));
  for (const device of [f.pendingDeviceId, f.otherDeviceId, randomUUID()]) await assert.rejects(f.sessions.beginDeviceChallenge(issued.cookieValue, issued.csrfToken, device), code('DEVICE_APPROVAL_REQUIRED'));
  f.advance(60_000);
  const challenge = await f.sessions.beginDeviceChallenge(issued.cookieValue, issued.csrfToken, f.deviceId);
  assert.equal(deviceChallenge.safeParse(challenge).success, true);
  assert.equal(Date.parse(challenge.expiresAt) - Date.parse(challenge.issuedAt), 120_000);
  assert.equal(challenge.sessionId, issued.sessionId); assert.equal(challenge.origin, 'https://sessions.example');
  const proof = await signObject(challenge, f.signing.privateKey);
  const approved = await f.sessions.completeDeviceChallenge(issued.cookieValue, issued.csrfToken, proof);
  assert.equal(approved.accessLevel, 'device_approved'); assert.equal(approved.deviceId, f.deviceId);
  assert.notEqual(approved.cookieValue, issued.cookieValue); assert.notEqual(approved.csrfToken, issued.csrfToken);
  assert.equal(approved.authenticatedAt, issued.authenticatedAt); assert.equal(approved.absoluteExpiresAt, issued.absoluteExpiresAt);
  assert.equal((await f.sessions.authenticate(approved.cookieValue, { approved: true })).deviceId, f.deviceId);
  await assert.rejects(f.sessions.authenticate(issued.cookieValue), code('AUTH_REQUIRED'));
  await assert.rejects(f.sessions.completeDeviceChallenge(issued.cookieValue, issued.csrfToken, proof), code('DEVICE_PROOF_INVALID'));
  assert.equal(await f.ceremonyState(challenge.ceremonyId), 'completed');
  const sessions = (await f.admin.control.query('SELECT revoked_at FROM security.sessions WHERE workspace_id=$1', [f.workspaceId])).rows;
  assert.equal(sessions.length, 2); assert.equal(sessions.filter((row) => row.revoked_at === null).length, 1);
});

test('CP04: invalid, malformed and expired proofs are consumed; wrong CSRF or another session cannot burn them', async (t) => {
  const f = await fixture(t), issued = await f.issue(), other = await f.issue();
  let challenge = await f.sessions.beginDeviceChallenge(issued.cookieValue, issued.csrfToken, f.deviceId);
  const valid = await signObject(challenge, f.signing.privateKey);
  await assert.rejects(f.sessions.completeDeviceChallenge(issued.cookieValue, other.csrfToken, valid), code('CSRF_INVALID'));
  assert.equal(await f.ceremonyState(challenge.ceremonyId), 'issued');
  await assert.rejects(f.sessions.completeDeviceChallenge(other.cookieValue, other.csrfToken, valid), code('DEVICE_PROOF_INVALID'));
  assert.equal(await f.ceremonyState(challenge.ceremonyId), 'issued');
  await assert.rejects(f.sessions.completeDeviceChallenge(issued.cookieValue, issued.csrfToken, await signObject(challenge, f.otherSigning.privateKey)), code('DEVICE_PROOF_INVALID'));
  assert.equal(await f.ceremonyState(challenge.ceremonyId), 'cancelled');
  await assert.rejects(f.sessions.completeDeviceChallenge(issued.cookieValue, issued.csrfToken, valid), code('DEVICE_PROOF_INVALID'));
  challenge = await f.sessions.beginDeviceChallenge(issued.cookieValue, issued.csrfToken, f.deviceId);
  await assert.rejects(f.sessions.completeDeviceChallenge(issued.cookieValue, issued.csrfToken, { body: challenge, signature: 'bad' }), code('DEVICE_PROOF_INVALID'));
  assert.equal(await f.ceremonyState(challenge.ceremonyId), 'cancelled');
  challenge = await f.sessions.beginDeviceChallenge(issued.cookieValue, issued.csrfToken, f.deviceId);
  const expired = await signObject(challenge, f.signing.privateKey);
  f.advance(120_000);
  await assert.rejects(f.sessions.completeDeviceChallenge(issued.cookieValue, issued.csrfToken, expired), code('DEVICE_PROOF_INVALID'));
  assert.equal(await f.ceremonyState(challenge.ceremonyId), 'expired');
});

test('CP04: proof context and current head/grant changes reject stale or misdirected signatures', async (t) => {
  const f = await fixture(t), issued = await f.issue();
  let challenge = await f.sessions.beginDeviceChallenge(issued.cookieValue, issued.csrfToken, f.deviceId);
  await assert.rejects(f.sessions.completeDeviceChallenge(issued.cookieValue, issued.csrfToken,
    await signObject({ ...challenge, origin: 'https://other.example' }, f.signing.privateKey)), code('DEVICE_PROOF_INVALID'));
  assert.equal(await f.ceremonyState(challenge.ceremonyId), 'cancelled');
  challenge = await f.sessions.beginDeviceChallenge(issued.cookieValue, issued.csrfToken, f.deviceId);
  await f.admin.control.query("UPDATE security.workspaces SET security_version=2,security_head=repeat('c',64) WHERE workspace_id=$1", [f.workspaceId]);
  await assert.rejects(f.sessions.completeDeviceChallenge(issued.cookieValue, issued.csrfToken, await signObject(challenge, f.signing.privateKey)), code('DEVICE_PROOF_INVALID'));
  assert.equal(await f.ceremonyState(challenge.ceremonyId), 'cancelled');
  assert.equal((await f.sessions.authenticate(issued.cookieValue)).securityVersion, '2');
  challenge = await f.sessions.beginDeviceChallenge(issued.cookieValue, issued.csrfToken, f.deviceId);
  const approved = await f.sessions.completeDeviceChallenge(issued.cookieValue, issued.csrfToken, await signObject(challenge, f.signing.privateKey));
  await f.admin.control.query("UPDATE security.grants SET state='revoked',revoked_at=now() WHERE workspace_id=$1 AND grant_id=$2", [f.workspaceId, f.grantId]);
  await assert.rejects(f.sessions.authenticate(approved.cookieValue, { approved: true }), code('DEVICE_APPROVAL_REQUIRED'));
});

test('CP04: device revocation and logout invalidate sessions; transactional prior-cookie revocation is safe', async (t) => {
  const f = await fixture(t), approved = await f.issue({ accessLevel: 'device_approved', deviceId: f.deviceId });
  await f.admin.control.query("UPDATE security.devices SET state='revoked',revoked_at=now() WHERE workspace_id=$1 AND device_id=$2", [f.workspaceId, f.deviceId]);
  await assert.rejects(f.sessions.authenticate(approved.cookieValue), code('DEVICE_APPROVAL_REQUIRED'));
  const restricted = await f.issue();
  await assert.rejects(f.sessions.logout(restricted.cookieValue, approved.csrfToken), code('CSRF_INVALID'));
  await f.sessions.logout(restricted.cookieValue, restricted.csrfToken);
  await f.sessions.logout(restricted.cookieValue, restricted.csrfToken);
  await assert.rejects(f.sessions.authenticate(restricted.cookieValue), code('AUTH_REQUIRED'));
  const last = await f.issue({ profileId: f.otherProfileId });
  await transaction(f.db.control, async (client) => {
    assert.equal(await f.sessions.revokeCookie(client, 'bad'), false);
    assert.equal(await f.sessions.revokeCookie(client, last.cookieValue), true);
    const replacement = await f.sessions.issue(client, { workspaceId: f.workspaceId, profileId: f.profileId, credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1', accessLevel: 'restricted' });
    assert.equal(replacement.accountId, f.profileId);
  });
  await assert.rejects(f.sessions.authenticate(last.cookieValue), code('AUTH_REQUIRED'));
});

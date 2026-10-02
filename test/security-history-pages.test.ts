import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import pg from 'pg';
import Fastify from 'fastify';
import { registerSecurityRoutes } from '../src/modules/identity/security-routes.js';
import { RequestBudgets } from '../src/modules/identity/budgets.js';
import type { PairingService } from '../src/modules/identity/pairing.js';
import type { PasswordChangeService } from '../src/modules/identity/password-change.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import { loadConfig } from '../src/config.js';
import { createDatabases, transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { SessionService } from '../src/modules/identity/sessions.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { HISTORY_PAGE_BYTES, HISTORY_RECORD_BYTES, HISTORY_RESPONSE_BYTES, readPairingHistoryPage, type HistoryAnchor, type PairingHistoryRequest } from '../src/modules/identity/security-history.js';
import { base64urlEncode, canonicalJson, digestObject, generateRecipientKeyPair, generateSigningKeyPair, signObject } from '../src/shared/crypto.js';
import { pairingConfirmationFor, type PairingReceipt, type PairingTranscript } from '../src/shared/pairing.js';

const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;
async function fixture(t: TestContext) {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const controlUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(controlUrl, 'History page tests require explicit fixture admin credentials');
  const admin = new pg.Pool({ connectionString: controlUrl });
  const databases = createDatabases(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }));
  const workspaceId = randomUUID(), accountId = randomUUID(), deviceId = randomUUID(), licenceId = randomUUID(), genesisId = randomUUID(), grantId = randomUUID();
  const otherAccountId = randomUUID(), otherDeviceId = randomUUID(), otherGrantId = randomUUID();
  const origin = 'https://history-pages.example', signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'history-pages' });
  const sessions = new SessionService({ databases, secrets, origin });
  // These synthetic signed fixture records exercise transport boundaries and authority.
  // Full supported-transition cryptographic replay is independently tested in security-history.test.ts.
  const genesis = await signObject({ purpose: 'fixture.history-genesis', workspaceId }, signing.privateKey);
  const activationJournal = { genesis, recoveryProof: await signObject({ purpose: 'fixture.recovery-proof', workspaceId }, signing.privateKey) };
  const budgetDigests: Buffer[] = [];
  let anchor: HistoryAnchor = { securityHead: await digestObject(genesis), securityVersion: '1' };
  t.after(async () => {
    try {
      if (budgetDigests.length) await admin.query('DELETE FROM security.request_budgets WHERE bucket_digest=ANY($1::bytea[])', [budgetDigests]);
      await admin.query('DELETE FROM security.ceremonies WHERE workspace_id=$1', [workspaceId]);
      await admin.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
      await admin.query('DELETE FROM security.licences WHERE licence_id=$1', [licenceId]);
    } finally { await Promise.allSettled([databases.close(), admin.end()]); }
  });
  await transaction(admin, async (client) => {
    await client.query("INSERT INTO security.licences(licence_id,verification_digest,verification_key_id) VALUES($1,$2,'fixture')", [licenceId, randomBytes(32)]);
    await client.query("INSERT INTO security.workspaces(workspace_id,licence_id,lifecycle,security_head,security_version,ownership_version,custody_epoch,activated_at) VALUES($1,$2,'active',$3,1,1,1,now())", [workspaceId, licenceId, anchor.securityHead]);
    await client.query("INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition) VALUES($1,1,$2,repeat('0',64),$3,'fixture','service',$4)", [workspaceId, randomUUID(), anchor.securityHead, activationJournal]);
    await client.query("INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version) VALUES($1,$2,'genesis',$3,$4,$5,'committed',1)", [workspaceId, genesisId, anchor.securityHead, genesis, randomUUID()]);
    await client.query('UPDATE security.workspaces SET genesis_object_id=$2 WHERE workspace_id=$1', [workspaceId, genesisId]);
    await client.query(`INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version)
      VALUES($1,'workspace',$1,1,$2,1)`, [workspaceId, genesisId]);
    for (const [id, device, grant, owner] of [[accountId, deviceId, grantId, true], [otherAccountId, otherDeviceId, otherGrantId, false]] as const) {
      await client.query(`INSERT INTO security.profiles(workspace_id,profile_id,state,is_owner,owner_ready_at,credential_generation,opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers)
        VALUES($1,$2,'active',$3,$4,1,'AA','fixture','fixture','{}')`, [workspaceId, id, owner, owner ? new Date() : null]);
      await client.query(`INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approval_security_version,approved_at)
        VALUES($1,$2,$3,1,$4,$5,'active',1,now())`, [workspaceId, device, id, signing.publicKey, recipient.publicKey]);
      await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,generation,state,signed_grant_object_id,key_manifest_object_id,key_epoch,permissions,security_version,activated_at)
        VALUES($1,$2,$3,$4,'device','workspace',1,'active',$5,$5,1,ARRAY['read_project'],1,now())`, [workspaceId, grant, id, device, genesisId]);
      await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,generation,state,signed_grant_object_id,key_manifest_object_id,key_epoch,permissions,security_version,activated_at)
        VALUES($1,$2,$3,$4,'workspace',1,'active',$5,$5,1,ARRAY['read_project'],1,now())`, [workspaceId, randomUUID(), id, owner ? 'owner' : 'membership', genesisId]);
    }
  });
  const issue = (profileId = accountId, approved = false, id = deviceId) => transaction(databases.control, (client) => sessions.issue(client, {
    workspaceId, profileId, credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1', accessLevel: approved ? 'device_approved' : 'restricted', ...(approved ? { deviceId: id } : {}) }));
  const session = await issue(), owner = await issue(accountId, true), other = await issue(otherAccountId, true, otherDeviceId);
  const records: unknown[] = [];
  async function append(value?: unknown, operationId = randomUUID()) {
    const sequence = String(BigInt(anchor.securityVersion) + 1n);
    const record = value ?? await signObject({ purpose: 'fixture.history-transition', workspaceId, sequence, previousHead: anchor.securityHead }, signing.privateKey);
    const head = await digestObject(record);
    await transaction(admin, async (client) => {
      await client.query("INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition) VALUES($1,$2,$3,$4,$5,'fixture','service',$6)", [workspaceId, sequence, operationId, anchor.securityHead, head, record]);
      await client.query('UPDATE security.workspaces SET security_version=$2,security_head=$3 WHERE workspace_id=$1', [workspaceId, sequence, head]);
    });
    anchor = { securityVersion: sequence, securityHead: head }; records.push(record); return record;
  }
  async function ceremony(profileId = accountId) {
    const operationId = randomUUID(), signingNew = await generateSigningKeyPair(), recipientNew = await generateRecipientKeyPair();
    const transcript: PairingTranscript = { version: 1, purpose: 'ukda.device-pair-transcript.v1', origin, workspaceId, operationId, ceremonyId: operationId,
      accountId: profileId, device: { id: randomUUID(), keyGeneration: '1', signingPublicKey: base64urlEncode(signingNew.publicKey), recipientPublicKey: base64urlEncode(recipientNew.publicKey) },
      localBundleDigest: 'a'.repeat(64), approverAccountId: accountId,
      approverDevice: { id: deviceId, keyGeneration: '1', signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) },
      approverIsOwner: true, credentialGeneration: '1', sessionGeneration: '1', approverCredentialGeneration: '1', approverSessionGeneration: '1',
      dataGeneration: '1', ownershipVersion: '1', custodyEpoch: '1', genesisFingerprint: await digestObject(genesis), ...anchor,
      scopes: [{ scope: 'workspace', scopeId: workspaceId, mode: 'custody', keyEpoch: '1', expiresAt: null, permissions: [], sources: [{ grantId, generation: '1', manifestId: genesisId, manifestDigest: await digestObject(genesis) }] }],
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() };
    await admin.query(`INSERT INTO security.ceremonies(workspace_id,ceremony_id,profile_id,kind,generation,expected_credential_generation,expected_ownership_version,expected_security_version,expected_custody_epoch,public_state,expires_at)
      VALUES($1,$2,$3,'device_pair',1,1,1,$4,1,$5,now()+interval '10 minutes')`, [workspaceId, operationId, profileId, anchor.securityVersion, { transcript }]);
    async function commit() {
      const transcriptDigest = await digestObject(transcript), securityVersion = String(BigInt(anchor.securityVersion) + 1n);
      const grant = await signObject({ version: 1 as const, purpose: 'ukda.device-pair-grant.v1' as const, workspaceId, operationId, grantId: operationId,
        securityVersion, previousHead: anchor.securityHead, transcript, transcriptDigest,
        recipientConfirmation: await signObject(pairingConfirmationFor(transcript, transcriptDigest, 'recipient'), signingNew.privateKey),
        approverConfirmation: await signObject(pairingConfirmationFor(transcript, transcriptDigest, 'approver'), signing.privateKey),
        deliveries: [{ id: randomUUID(), scope: 'workspace' as const, scopeId: workspaceId, digest: 'b'.repeat(64) }] }, signing.privateKey);
      await append(grant, operationId);
      const receipt: PairingReceipt = { version: 1, workspaceId, operationId, accountId: profileId, deviceId: transcript.device.id, grantId: operationId,
        transcriptDigest, ...anchor, dataGeneration: '1', committedAt: new Date().toISOString(), grant };
      await admin.query("INSERT INTO security.operation_receipts(workspace_id,operation_id,request_hash,operation_kind,security_version,outcome) VALUES($1,$2,$3,'device_pair',$4,$5)", [workspaceId, operationId, await digestObject(receipt), anchor.securityVersion, receipt]);
      await admin.query("UPDATE security.ceremonies SET state='completed',completed_at=now() WHERE workspace_id=$1 AND ceremony_id=$2", [workspaceId, operationId]);
      return receipt;
    }
    return { operationId, transcript, commit };
  }
  const page = (request: Omit<PairingHistoryRequest, 'afterVersion'> & { afterVersion?: string }, cookie = session.cookieValue) => readPairingHistoryPage({ databases, sessions }, cookie, request);
  return { admin, databases, sessions, secrets, origin, budgetDigests, workspaceId, accountId, otherAccountId, genesis, records, append, ceremony, page, session, owner, other, grantId,
    anchor: () => ({ ...anchor }) };
}

test('CP04: history pages preserve complete byte-bounded records, exact order, genesis and final anchor', async (t) => {
  const f = await fixture(t);
  for (let index = 0; index < 7; index++) await f.append({ body: { purpose: 'fixture.bytes', index, payload: '🙂'.repeat(38_000) }, signature: randomBytes(64).toString('base64url') });
  const ceremony = await f.ceremony(), collected: unknown[] = [];
  let afterVersion = '0', bound: HistoryAnchor | undefined, pages = 0;
  do {
    const page = await f.page({ operationId: ceremony.operationId, mode: 'transcript', afterVersion, ...(bound ? { anchor: bound } : {}) });
    assert.ok(Buffer.byteLength(JSON.stringify(page), 'utf8') <= HISTORY_PAGE_BYTES);
    assert.equal(page.afterVersion, afterVersion); assert.deepEqual(page.anchor, f.anchor());
    assert.equal(page.genesis !== null, pages === 0); if (pages === 0) assert.equal(canonicalJson(page.genesis), canonicalJson(f.genesis));
    collected.push(...page.transitions); pages++; bound = page.anchor;
    if (page.nextAfterVersion === null) break;
    assert.equal(BigInt(page.nextAfterVersion), BigInt(afterVersion) + BigInt(page.transitions.length + (page.genesis === null ? 0 : 1)));
    afterVersion = page.nextAfterVersion;
  } while (pages < 10);
  assert.ok(pages >= 3); assert.equal(canonicalJson(collected), canonicalJson(f.records));
  assert.equal(BigInt(bound!.securityVersion), BigInt(collected.length + 1));
});

test('CP04: history current mode includes committed pairing and newer authority while anchored continuations never shift', async (t) => {
  const f = await fixture(t), ceremony = await f.ceremony();
  await assert.rejects(f.page({ operationId: ceremony.operationId, mode: 'current' }), code('PAIRING_INVALID'));
  const receipt = await ceremony.commit();
  for (let index = 0; index < 4; index++) await f.append({ body: { purpose: 'fixture.bytes', index, payload: 'a'.repeat(200_000) }, signature: randomBytes(64).toString('base64url') });
  const first = await f.page({ operationId: ceremony.operationId, mode: 'current' });
  assert.notEqual(first.anchor.securityHead, receipt.securityHead); assert.ok(first.nextAfterVersion);
  const frozen = first.anchor; await f.append();
  const second = await f.page({ operationId: ceremony.operationId, mode: 'current', anchor: frozen, afterVersion: first.nextAfterVersion! });
  assert.deepEqual(second.anchor, frozen); assert.deepEqual(second.current, f.anchor()); assert.notDeepEqual(second.current, second.anchor);
  const prefix = await f.page({ operationId: ceremony.operationId, mode: 'transcript' });
  assert.equal(prefix.anchor.securityVersion, '1'); assert.equal(prefix.transitions.length, 0); assert.equal(prefix.nextAfterVersion, null);
  await assert.rejects(f.page({ operationId: ceremony.operationId, mode: 'current', anchor: { securityVersion: '1', securityHead: await digestObject(f.genesis) } }), code('HISTORY_CURSOR_INVALID'));
  await assert.rejects(f.page({ operationId: ceremony.operationId, mode: 'current', anchor: { ...frozen, securityHead: 'c'.repeat(64) }, afterVersion: '1' }), code('HISTORY_CURSOR_INVALID'));
  await assert.rejects(f.page({ operationId: ceremony.operationId, mode: 'current', afterVersion: '1' }), code('INVALID_REQUEST'));
});

test('CP04: one large complete signed record uses explicit margin; oversized records fail closed', async (t) => {
  const f = await fixture(t);
  await f.append({ body: { purpose: 'fixture.large', payload: 'x'.repeat(700_000) }, signature: randomBytes(64).toString('base64url') });
  const good = await f.ceremony(), first = await f.page({ operationId: good.operationId, mode: 'transcript' });
  assert.equal(first.transitions.length, 0); assert.equal(first.nextAfterVersion, '1');
  const large = await f.page({ operationId: good.operationId, mode: 'transcript', anchor: first.anchor, afterVersion: '1' });
  const size = Buffer.byteLength(JSON.stringify(large), 'utf8');
  assert.ok(size > HISTORY_PAGE_BYTES && size < HISTORY_RESPONSE_BYTES); assert.equal(large.transitions.length, 1); assert.equal(large.genesis, null); assert.equal(large.nextAfterVersion, null);
  await f.append({ body: { purpose: 'fixture.oversized', payload: 'x'.repeat(HISTORY_RECORD_BYTES) }, signature: randomBytes(64).toString('base64url') });
  const bad = await f.ceremony();
  await assert.rejects(f.page({ operationId: bad.operationId, mode: 'transcript', anchor: f.anchor(), afterVersion: '2' }), code('SECURITY_FENCED'));
});

test('CP04: every history page rechecks account, Owner/device authorization, cookie generations and tenant scope', async (t) => {
  const f = await fixture(t), own = await f.ceremony(), other = await f.ceremony(f.otherAccountId);
  await f.page({ operationId: own.operationId, mode: 'transcript' });
  await assert.rejects(f.page({ operationId: own.operationId, mode: 'transcript' }, f.other.cookieValue), code('PAIRING_FORBIDDEN'));
  await assert.rejects(f.page({ operationId: other.operationId, mode: 'transcript' }), code('PAIRING_FORBIDDEN'));
  await f.page({ operationId: other.operationId, mode: 'transcript' }, f.owner.cookieValue);
  await f.admin.query("UPDATE security.grants SET state='revoked',revoked_at=now() WHERE workspace_id=$1 AND grant_id=$2", [f.workspaceId, f.grantId]);
  await assert.rejects(f.page({ operationId: other.operationId, mode: 'transcript' }, f.owner.cookieValue), code('DEVICE_APPROVAL_REQUIRED'));
  await f.admin.query('UPDATE security.profiles SET credential_generation=2 WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.accountId]);
  await assert.rejects(f.page({ operationId: own.operationId, mode: 'transcript' }), code('AUTH_REQUIRED'));
  await assert.rejects(f.page({ operationId: randomUUID(), mode: 'transcript' }, f.other.cookieValue), code('PAIRING_FORBIDDEN'));
});

test('CP04: authenticated HTTP history reads have finite dedicated budgets and do not exhaust login or mutation attempts', async (t) => {
  const f = await fixture(t), ceremony = await f.ceremony();
  const app = Fastify({ logger: false });
  const budgets = new RequestBudgets(f.databases.control, f.secrets);
  registerSecurityRoutes(app, { origin: f.origin, databases: f.databases, sessions: f.sessions, budgets,
    pairing: {} as PairingService, passwordChange: {} as PasswordChangeService });
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof AppError) return reply.code(error.statusCode).send({ error: { code: error.code } });
    return reply.code(500).send({ error: { code: 'INTERNAL_ERROR' } });
  });
  const source = '192.0.2.73', account = `${f.workspaceId}:${f.accountId}`;
  const keys = [['authentication-source', source], ['security-account', account], ['security-workspace', f.workspaceId],
    ['history-source', source], ['history-account', account], ['history-workspace', f.workspaceId]] as const;
  for (const [purpose, key] of keys) f.budgetDigests.push(f.secrets.digest(`rate:${purpose}`, key));
  async function attempts(purpose: string, key: string, count: number) {
    await f.admin.query(`INSERT INTO security.request_budgets(bucket_digest,window_started_at,attempts,expires_at)
      VALUES($1,clock_timestamp(),$2,clock_timestamp()+interval '10 minutes')
      ON CONFLICT(bucket_digest) DO UPDATE SET attempts=$2,expires_at=clock_timestamp()+interval '10 minutes'`, [f.secrets.digest(`rate:${purpose}`, key), count]);
  }
  const headers = { origin: f.origin, cookie: `${SESSION_COOKIE_NAME}=${f.session.cookieValue}`, 'content-type': 'application/json' };
  const request = () => app.inject({ method: 'POST', url: '/v1/auth/pairing/history', remoteAddress: source, headers,
    payload: { operationId: ceremony.operationId, mode: 'transcript' } });
  try {
    await attempts('authentication-source', source, 60); await attempts('security-account', account, 60); await attempts('security-workspace', f.workspaceId, 240);
    for (let index = 0; index < 65; index++) {
      const response = await request(); assert.equal(response.statusCode, 200, response.body);
      assert.equal(canonicalJson(response.json().genesis), canonicalJson(f.genesis), 'HTTP extracts genesis from the activation journal wrapper');
    }
    const mutation = await app.inject({ method: 'POST', url: '/v1/auth/pairing/begin', remoteAddress: source, headers, payload: {} });
    assert.equal(mutation.statusCode, 429, 'ordinary mutation retains its smaller attempt budget');
    const wrongOrigin = await app.inject({ method: 'POST', url: '/v1/auth/pairing/history', remoteAddress: source,
      headers: { ...headers, origin: 'https://other.example' }, payload: { operationId: ceremony.operationId, mode: 'transcript' } });
    assert.equal(wrongOrigin.statusCode, 403);
    const missingCookie = await app.inject({ method: 'POST', url: '/v1/auth/pairing/history', remoteAddress: source,
      headers: { origin: f.origin }, payload: { operationId: ceremony.operationId, mode: 'transcript' } });
    assert.equal(missingCookie.statusCode, 401);
    await attempts('history-account', account, 1000); assert.equal((await request()).statusCode, 429);
    await attempts('history-account', account, 1); await attempts('history-source', source, 1200); assert.equal((await request()).statusCode, 429);
    await attempts('history-source', source, 1); await attempts('history-workspace', f.workspaceId, 4000); assert.equal((await request()).statusCode, 429);
  } finally { await app.close(); }
});

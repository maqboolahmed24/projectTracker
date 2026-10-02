import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { transaction, createDatabases } from '../src/db.js';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { TeamService, type TeamAuth } from '../src/modules/work/teams.js';
import { registerTeamRoutes } from '../src/modules/work/team-routes.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import { base64urlDecode, canonicalJson, decryptContent, digestObject, encryptContent, signObject } from '../src/shared/crypto.js';
import { teamContent, teamHeader, teamMutationBody, teamPayload, teamBindingV1, validateTeamPayload, type TeamPayload, type TeamReceipt } from '../src/shared/teams.js';
import { accessChangeFixture } from './access-change-fixture.js';
import { origin } from './password-change-fixture.js';

const errorCode = (code: string) => (error: unknown) => error instanceof AppError && error.code === code;
async function fixture(t: TestContext) {
  let f: Awaited<ReturnType<typeof accessChangeFixture>>;
  t.after(async () => {
    if (f) await transaction(f.admin.application, async (c) => {
      // Delete only this disposable workspace's immutable test history.
      await c.query("SET LOCAL session_replication_role='replica'");
      for (const table of ['outbox', 'operation_receipts', 'audit_events', 'record_versions', 'team_members', 'teams']) {
        await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [f.workspaceId]);
      }
    });
  });
  f = await accessChangeFixture(t);
  const teams = new TeamService(f);
  async function prepare(input: { teamId?: string; operationId?: string; name?: string; memberIds?: string[]; action?: 'create' | 'update'; auth?: TeamAuth } = {}): Promise<TeamPayload> {
    const request = { workspaceId: f.workspaceId, teamId: input.teamId ?? randomUUID(), operationId: input.operationId ?? randomUUID(), action: input.action ?? 'create' };
    const context = await teams.context(input.auth ?? f.auth(), request), header = teamHeader(context.binding);
    const envelope = await encryptContent(header, teamContent.parse({ name: input.name ?? 'Private delivery team' }), f.workspaceKey, base64urlDecode(f.originalBundle.signingPrivateKey));
    const mutation = await signObject(teamMutationBody(context.binding, input.memberIds ?? [], await digestObject(envelope)), base64urlDecode(f.originalBundle.signingPrivateKey));
    return teamPayload.parse({ mutation, envelope });
  }
  return { ...f, teams, prepare };
}

test('CP07: encrypted teams share one retry receipt, preserve versions and never grant project access', async (t) => {
  const f = await fixture(t), member = await f.joined(), teamId = randomUUID();
  const before = (await f.admin.control.query('SELECT count(*) FROM security.grants WHERE workspace_id=$1', [f.workspaceId])).rows[0].count;
  const payload = await f.prepare({ teamId, memberIds: [member.binding.accountId] });
  const [one, two] = await Promise.all([f.teams.save(f.auth(), payload), f.teams.save(f.auth(), payload)]);
  assert.deepEqual(two, one); assert.equal(one.revision, '1');
  const differentEnvelope = await encryptContent(payload.envelope.header, { name: 'Different request under same operation' }, f.workspaceKey, base64urlDecode(f.originalBundle.signingPrivateKey));
  const differentMutation = await signObject({ ...payload.mutation.body, contentDigest: await digestObject(differentEnvelope) }, base64urlDecode(f.originalBundle.signingPrivateKey));
  await assert.rejects(f.teams.save(f.auth(), { mutation: differentMutation, envelope: differentEnvelope }), errorCode('REVISION_CONFLICT'));
  const reference = { workspaceId: f.workspaceId, teamId, operationId: one.operationId };
  assert.deepEqual((await f.teams.status(f.auth(), reference)).receipt, one);
  const list = await f.teams.list(member.auth, { workspaceId: f.workspaceId, limit: 1 });
  assert.equal(list.records.length, 1); assert.equal(list.nextCursor, null);
  assert.deepEqual(list.records[0]!.memberIds, [member.binding.accountId]);
  assert.equal(canonicalJson(await validateTeamPayload(list.records[0]!.signedChange)), canonicalJson(payload));
  assert.equal((await f.admin.control.query('SELECT count(*) FROM security.grants WHERE workspace_id=$1', [f.workspaceId])).rows[0].count, before);
  assert.equal((await f.admin.application.query('SELECT * FROM app.project_access WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  const next = await f.prepare({ teamId, action: 'update', name: 'Renamed private team', memberIds: [f.accountId, member.binding.accountId] });
  assert.equal((await f.teams.save(f.auth(), next)).revision, '2');
  const history = (await f.admin.application.query("SELECT encrypted_envelope FROM app.record_versions WHERE workspace_id=$1 AND record_type='team' ORDER BY record_revision", [f.workspaceId])).rows;
  assert.equal(history.length, 2);
  const old = history[0]!.encrypted_envelope as TeamPayload;
  assert.equal((await decryptContent(old.envelope, f.workspaceKey, base64urlDecode(f.originalBundle.signingPublicKey), old.envelope.header) as { name: string }).name, 'Private delivery team');
  assert.equal(JSON.stringify(history).includes('Private delivery team'), false);
  assert.equal((await f.admin.application.query('SELECT * FROM app.outbox WHERE workspace_id=$1', [f.workspaceId])).rowCount, 2);
});

test('CP07: team management rejects non-Owners, inactive/foreign members, tampering and stale revisions', async (t) => {
  const f = await fixture(t), member = await f.joined();
  await assert.rejects(f.prepare({ auth: member.auth }), errorCode('FORBIDDEN'));
  const invalid = await f.prepare({ memberIds: [randomUUID()] });
  await assert.rejects(f.teams.save(f.auth(), invalid), errorCode('MEMBER_INELIGIBLE'));
  const payload = await f.prepare(), tampered = structuredClone(payload);
  tampered.mutation.body.memberIds.push(member.binding.accountId);
  await assert.rejects(f.teams.save(f.auth(), tampered), errorCode('INVALID_REQUEST'));
  const receipt = await f.teams.save(f.auth(), payload), teamId = receipt.teamId;
  const first = await f.prepare({ teamId, action: 'update', name: 'First edit' }), second = await f.prepare({ teamId, action: 'update', name: 'Second edit' });
  const result = await Promise.allSettled([f.teams.save(f.auth(), first), f.teams.save(f.auth(), second)]);
  assert.equal(result.filter((r) => r.status === 'fulfilled').length, 1);
  const rejected = result.find((r) => r.status === 'rejected'); assert.ok(rejected && errorCode('REVISION_CONFLICT')(rejected.reason));
  await f.admin.control.query("UPDATE security.profiles SET state='suspended' WHERE workspace_id=$1 AND profile_id=$2", [f.workspaceId, member.binding.accountId]);
  await f.admin.application.query("UPDATE app.profiles SET state='suspended' WHERE workspace_id=$1 AND id=$2", [f.workspaceId, member.binding.accountId]);
  const inactive = await f.prepare({ memberIds: [member.binding.accountId] });
  await assert.rejects(f.teams.save(f.auth(), inactive), errorCode('MEMBER_INELIGIBLE'));
  await assert.rejects(f.teams.list(f.auth(), { workspaceId: randomUUID() }), errorCode('NOT_FOUND'));
});

test('CP07: team failure rolls back content, membership, audit, receipt and durable outbox together', async (t) => {
  const f = await fixture(t), payload = await f.prepare({ memberIds: [f.accountId] });
  const interrupted = new TeamService({ ...f, beforeCommit: async () => { throw new Error('Injected interruption'); } });
  await assert.rejects(interrupted.save(f.auth(), payload), /Injected interruption/);
  for (const table of ['teams', 'team_members', 'record_versions', 'audit_events', 'operation_receipts', 'outbox']) {
    assert.equal((await f.admin.application.query(`SELECT 1 FROM app.${table} WHERE workspace_id=$1`, [f.workspaceId])).rowCount, 0, table);
  }
  assert.equal((await f.teams.save(f.auth(), payload)).revision, '1');
  const modified = structuredClone(payload); modified.envelope.nonce = modified.envelope.nonce.split('').reverse().join('');
  await assert.rejects(f.teams.save(f.auth(), modified), errorCode('INVALID_REQUEST'));
});

test('CP07: team HTTP enforces origin, CSRF, strict bodies and permits reads/receipt retry in restricted mode', async (t) => {
  const f = await fixture(t), config = loadConfig({ ...process.env, APP_ORIGIN: origin, NODE_ENV: 'test', LOG_LEVEL: 'silent' });
  const app = buildApp(config, createDatabases(config)); t.after(() => app.close());
  registerTeamRoutes(app, { origin, teams: f.teams, budgets: { take: async () => {} } });
  const payload = await f.prepare(), headers = { origin, cookie: `${SESSION_COOKIE_NAME}=${f.auth().cookieValue}`, 'x-csrf-token': f.auth().csrfToken };
  const post = (path: string, body: unknown, custom = headers) => app.inject({ method: 'POST', url: `/v1/work/teams/${path}`, headers: custom, payload: body as object });
  assert.equal((await post('save', payload, { ...headers, origin: 'https://foreign.example' })).statusCode, 403);
  assert.equal((await post('save', payload, { ...headers, 'x-csrf-token': '' })).statusCode, 403);
  assert.equal((await post('list', { workspaceId: f.workspaceId, name: 'Unexpected plaintext' })).statusCode, 400);
  assert.equal((await post('list?secret=disallowed', { workspaceId: f.workspaceId })).statusCode, 400);
  const saved = await post('save', payload); assert.equal(saved.statusCode, 200);
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='restricted' WHERE workspace_id=$1", [f.workspaceId]);
  await f.admin.application.query("UPDATE app.workspaces SET licence_state='restricted' WHERE workspace_id=$1", [f.workspaceId]);
  assert.equal((await post('save', payload)).statusCode, 200);
  assert.equal((await post('list', { workspaceId: f.workspaceId })).statusCode, 200);
  const historyRef = { workspaceId: f.workspaceId, teamId: payload.envelope.header.recordId };
  const history = await post('history', historyRef); assert.equal(history.statusCode, 200); assert.equal(history.headers['cache-control'], 'no-store');
  assert.equal(history.json().records.length, 1);
  assert.equal((await post('history', { ...historyRef, afterRevision: '1' })).statusCode, 400);
  assert.equal((await post('history', { ...historyRef, limit: 101 })).statusCode, 400);
  assert.equal((await post('history', { ...historyRef, reason: 'Unexpected plaintext' })).statusCode, 400);
  assert.equal((await post('history?token=secret', historyRef)).statusCode, 400);
  assert.equal((await post('history', historyRef, { ...headers, origin: 'https://foreign.example' })).statusCode, 403);
  assert.equal((await post('history', historyRef, { ...headers, cookie: '' })).statusCode, 401);
  assert.equal((await post('history', { ...historyRef, workspaceId: randomUUID() })).statusCode, 404);
  assert.equal((await post('context', { workspaceId: f.workspaceId, teamId: randomUUID(), operationId: randomUUID(), action: 'create' })).statusCode, 423);
});


test('CP09: authorised team history pages retain signed actor/time and before/after evidence, reject stale anchors and revoked readers', async (t) => {
  const f = await fixture(t), member = await f.joined(), teamId = randomUUID(), reference = { workspaceId: f.workspaceId, teamId };
  const first = await f.prepare({ teamId, name: 'Private original', memberIds: [member.binding.accountId] });
  const receipt = await f.teams.save(f.auth(), first);
  const second = await f.prepare({ teamId, action: 'update', name: 'Private corrected', memberIds: [f.accountId] });
  await f.teams.save(f.auth(), second);
  const page1 = await f.teams.history(member.auth, { ...reference, limit: 1 });
  assert.equal(page1.complete, false); assert.equal(page1.nextRevision, '1'); assert.equal(page1.anchor.revision, '2');
  assert.deepEqual(page1.records[0]!.payload, first);
  const page2 = await f.teams.history(member.auth, { ...reference, limit: 1, afterRevision: page1.nextRevision, anchor: page1.anchor });
  assert.equal(page2.complete, true); assert.equal(page2.nextRevision, null); assert.deepEqual(page2.records[0]!.payload, second);
  for (const row of [...page1.records, ...page2.records]) {
    await validateTeamPayload(row.payload); const binding = row.payload.mutation.body.binding;
    assert.ok('version' in binding); assert.ok(Date.parse(binding.issuedAt) <= Date.parse(row.recordedAt));
    assert.equal(binding.authorizer.accountId, f.accountId);
  }
  assert.equal(second.mutation.body.binding.previousDigest, await digestObject(first.envelope));
  assert.deepEqual(second.mutation.body.binding.previousMemberIds, first.mutation.body.memberIds);
  const plaintext = async (p: TeamPayload) => decryptContent(p.envelope, f.workspaceKey, base64urlDecode(f.originalBundle.signingPublicKey), p.envelope.header);
  assert.deepEqual(teamContent.parse(await plaintext(first)), { name: 'Private original', description: '' });
  assert.deepEqual(teamContent.parse(await plaintext(second)), { name: 'Private corrected', description: '' });
  assert.equal(JSON.stringify(page1).includes('Private original'), false);
  assert.deepEqual(await f.teams.status(member.auth, { ...reference, operationId: receipt.operationId }), { receipt: null });
  const third = await f.prepare({ teamId, action: 'update', name: 'Private latest' }); await f.teams.save(f.auth(), third);
  await assert.rejects(f.teams.history(member.auth, { ...reference, afterRevision: '1', anchor: page1.anchor }), errorCode('REVISION_CONFLICT'));
  await f.finalize(await f.draft('suspend', member.binding.accountId));
  await assert.rejects(f.teams.history(member.auth, reference), (error: unknown) => error instanceof AppError && [401,403].includes(error.statusCode));
  assert.equal((await f.teams.history(f.auth(), reference)).records.length, 3);
});

test('CP09: exact legacy team signatures and receipts remain readable while new writes require bounded signed time', async (t) => {
  const f = await fixture(t), original = await f.prepare(), b = original.mutation.body.binding;
  assert.ok('version' in b);
  const { version: _version, issuedAt: _issuedAt, expiresAt: _expiresAt, ...legacyFields } = b;
  const legacyBinding = teamBindingV1.parse(legacyFields), legacy = teamPayload.parse({ envelope: original.envelope,
    mutation: await signObject(teamMutationBody(legacyBinding, [], await digestObject(original.envelope)), base64urlDecode(f.originalBundle.signingPrivateKey)) });
  await validateTeamPayload(legacy);
  await assert.rejects(f.teams.save(f.auth(), legacy), errorCode('REVISION_CONFLICT'));
  // A migrated CP07 record, not a new v1 write: preserve the historical bytes and its receipt exactly.
  const recordedAt = new Date('2025-01-01T00:00:00.000Z'), requestHash = await digestObject(legacy),
    receipt: TeamReceipt = { version: 1, workspaceId: f.workspaceId, operationId: b.operationId, teamId: b.teamId,
      actorId: f.accountId, revision: '1', dataGeneration: b.dataGeneration, requestHash };
  await transaction(f.admin.application, async (c) => {
    await c.query('INSERT INTO app.teams(workspace_id,id,revision,key_epoch,encrypted_envelope) VALUES($1,$2,1,$3,$4)', [f.workspaceId,b.teamId,b.keyEpoch,legacy.envelope]);
    await c.query(`INSERT INTO app.record_versions(workspace_id,id,record_type,record_id,record_revision,actor_profile_id,operation_id,key_epoch,encrypted_envelope,created_at)
      VALUES($1,$2,'team',$3,1,$4,$5,$6,$7,$8)`, [f.workspaceId,randomUUID(),b.teamId,f.accountId,b.operationId,b.keyEpoch,legacy,recordedAt]);
    await c.query(`INSERT INTO app.operation_receipts(workspace_id,id,data_generation,operation_id,actor_profile_id,action,request_digest,encrypted_envelope)
      VALUES($1,$2,$3,$4,$5,'teams.create',$6,$7)`, [f.workspaceId,randomUUID(),b.dataGeneration,b.operationId,f.accountId,requestHash,{receipt}]);
  });
  assert.deepEqual(await f.teams.save(f.auth(), legacy), receipt);
  const next = await f.prepare({ teamId:b.teamId,action:'update',name:'Modern signed update' }); await f.teams.save(f.auth(),next);
  const page = await f.teams.history(f.auth(),{workspaceId:f.workspaceId,teamId:b.teamId});
  assert.equal(page.records[0]!.recordedAt,recordedAt.toISOString()); assert.deepEqual(page.records[0]!.payload,legacy);
  assert.equal('issuedAt' in page.records[0]!.payload.mutation.body.binding,false);
  assert.equal('issuedAt' in page.records[1]!.payload.mutation.body.binding,true);
  const draft = await f.prepare(), binding = draft.mutation.body.binding; assert.ok('version' in binding);
  const redate = async (issuedAt:string,expiresAt:string) => teamPayload.parse({ envelope:draft.envelope,
    mutation:await signObject(teamMutationBody({...binding,issuedAt,expiresAt},[],await digestObject(draft.envelope)),base64urlDecode(f.originalBundle.signingPrivateKey)) });
  const timestamp = Date.now();
  await assert.rejects(f.teams.save(f.auth(),await redate(new Date(timestamp-700_000).toISOString(),new Date(timestamp-100_000).toISOString())),errorCode('REVISION_CONFLICT'));
  await assert.rejects(f.teams.save(f.auth(),await redate(new Date(timestamp+60_000).toISOString(),new Date(timestamp+600_000).toISOString())),errorCode('REVISION_CONFLICT'));
  const tampered = structuredClone(draft); if ('issuedAt' in tampered.mutation.body.binding) tampered.mutation.body.binding.issuedAt = new Date(0).toISOString();
  await assert.rejects(f.teams.save(f.auth(),tampered),errorCode('INVALID_REQUEST'));
  assert.equal((await f.teams.save(f.auth(),draft)).revision,'1');
});

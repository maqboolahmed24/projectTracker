import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomUUID } from 'node:crypto';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { readSessionCookie, SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import { tenantTransaction } from '../src/persistence.js';
import { readOwnerCustodyKeyMaterial } from '../src/client/pairing.js';
import { base64urlDecode, canonicalJson, decryptContent, encryptContent, type ContentHeader } from '../src/shared/crypto.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { accessChangeFixture } from './access-change-fixture.js';
import { provisionProjectScope } from './project-scope-fixture.js';

type Fixture = Awaited<ReturnType<typeof accessChangeFixture>>;
type Project = Awaited<ReturnType<typeof provisionProjectScope>>;

async function fixture(t: TestContext) {
  let f: Fixture | undefined, api: ReturnType<typeof buildApp> | undefined;
  // Register before the shared fixture's project/profile teardown. This setting
  // is local to the admin teardown transaction; runtime history stays immutable.
  t.after(async () => {
    await api?.close();
    if (!f) return;
    const current = f;
    await transaction(current.admin.application, async (c) => {
      await c.query("SET LOCAL session_replication_role='replica'");
      for (const table of ['record_versions', 'audit_events', 'comments', 'blockers', 'task_assignments', 'tasks', 'milestones', 'project_phases']) {
        await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [current.workspaceId]);
      }
    });
  });
  f = await accessChangeFixture(t);
  const current = f;
  api = buildApp(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }),
    { ...f.databases, close: async () => {} }, undefined, async (request) => {
      const cookie = readSessionCookie(request.headers.cookie);
      if (!cookie) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
      return current.sessions.authenticate(cookie, { approved: true });
    });
  const app = api;
  return { ...f, read: (url: string, cookieValue: string) => app.inject({ url, headers: { cookie: `${SESSION_COOKIE_NAME}=${cookieValue}` } }) };
}

async function encryptedRecord(f: Fixture, project: Project, recordType: ContentHeader['recordType'], recordId: string,
  plaintext: unknown, actor = { accountId: f.accountId, deviceId: f.deviceId, bundle: f.originalBundle }) {
  const history = await f.history();
  const header: ContentHeader = { ...f.prepared.payload.objects.profile.header,
    scope: 'project', scopeId: project.projectId, recordType, recordId, revision: '1', keyEpoch: '1',
    operationId: randomUUID(), action: 'fixture.seed', accountId: actor.accountId, deviceId: actor.deviceId,
    securityHead: history.expected.securityHead, securityVersion: history.expected.securityVersion };
  return encryptContent(header, plaintext, project.projectKey, base64urlDecode(actor.bundle.signingPrivateKey));
}

test('CP06: real removal cleans terminal archived responsibilities without rewriting closing history or attribution', async (t) => {
  const f = await fixture(t), member = await f.joined();
  const memberId = member.binding.accountId;
  const project = await provisionProjectScope(f, { selected: [{ accountId: memberId, roleId: f.prepared.payload.genesis.body.roles.member }] });
  const phaseId = randomUUID(), doneId = randomUUID(), cancelledId = randomUUID(), blockerId = randomUUID(), commentId = randomUUID();
  const actor = { accountId: memberId, deviceId: member.prepared.draft.transcript.device.id, bundle: member.bundle };
  // These are pre-existing CP07–09 lifecycle/history producer fixtures. This
  // test exercises the real CP06 removal, sessions, projection and ciphertext.
  const projectEnvelope = await encryptedRecord(f, project, 'project', project.projectId, { title: 'Private archived project', closingOutcome: 'Accepted delivery' });
  const phaseEnvelope = await encryptedRecord(f, project, 'phase', phaseId, { objective: 'Private closed wave', closingOutcome: 'Complete' });
  const taskEnvelope = await encryptedRecord(f, project, 'task', doneId, { title: 'Private completed work', assigneeIds: [memberId], leadProfileId: memberId }, actor);
  const cancelledEnvelope = await encryptedRecord(f, project, 'task', cancelledId, { title: 'Private cancelled work', cancellationReason: 'Scope ended' }, actor);
  const blockerEnvelope = await encryptedRecord(f, project, 'blocker', blockerId, { reason: 'Private unresolved dependency', nextAction: 'Await missing information' }, actor);
  const commentEnvelope = await encryptedRecord(f, project, 'comment', commentId, { body: 'Private historical contribution' }, actor);
  const approvalEnvelope = await encryptedRecord(f, project, 'audit', doneId, { approvedRevision: '1', approverProfileId: f.accountId, outcome: 'Accepted' });
  await tenantTransaction(f.databases.application, f.workspaceId, f.accountId, async (c) => {
    await c.query("UPDATE app.projects SET state='complete',archived=true,manager_profile_id=$3,encrypted_envelope=$4 WHERE workspace_id=$1 AND id=$2",
      [f.workspaceId, project.projectId, memberId, projectEnvelope]);
    await c.query(`INSERT INTO app.project_phases(workspace_id,id,project_id,state,archived,lead_profile_id,encrypted_envelope)
      VALUES($1,$2,$3,'complete',true,$4,$5)`, [f.workspaceId, phaseId, project.projectId, memberId, phaseEnvelope]);
    for (const [id, state, envelope] of [[doneId, 'done', taskEnvelope], [cancelledId, 'cancelled', cancelledEnvelope]] as const) {
      await c.query(`INSERT INTO app.tasks(workspace_id,id,project_id,phase_id,state,lead_profile_id,reviewer_profile_id,submitted_revision,encrypted_envelope)
        VALUES($1,$2,$3,$4,$5,$6,$7,1,$8)`, [f.workspaceId, id, project.projectId, phaseId, state, memberId, f.accountId, envelope]);
      await c.query(`INSERT INTO app.task_assignments(workspace_id,task_id,project_id,member_id,assigned_by)
        VALUES($1,$2,$3,$4,$5)`, [f.workspaceId, id, project.projectId, memberId, f.accountId]);
    }
    await c.query(`INSERT INTO app.blockers(workspace_id,id,project_id,task_id,responsible_profile_id,created_by,state,encrypted_envelope)
      VALUES($1,$2,$3,$4,$5,$5,'open',$6)`, [f.workspaceId, blockerId, project.projectId, cancelledId, memberId, blockerEnvelope]);
    await c.query(`INSERT INTO app.comments(workspace_id,id,project_id,task_id,author_profile_id,encrypted_envelope)
      VALUES($1,$2,$3,$4,$5,$6)`, [f.workspaceId, commentId, project.projectId, doneId, memberId, commentEnvelope]);
    for (const [recordType, recordId, envelope, actorId] of [
      ['project', project.projectId, projectEnvelope, f.accountId], ['phase', phaseId, phaseEnvelope, f.accountId],
      ['task', doneId, taskEnvelope, memberId],
    ] as const) await c.query(`INSERT INTO app.record_versions(workspace_id,id,project_id,record_type,record_id,record_revision,actor_profile_id,operation_id,encrypted_envelope)
      VALUES($1,$2,$3,$4,$5,1,$6,$7,$8)`, [f.workspaceId, randomUUID(), project.projectId, recordType, recordId, actorId, envelope.header.operationId, envelope]);
    await c.query(`INSERT INTO app.audit_events(workspace_id,id,project_id,record_type,record_id,action,actor_profile_id,operation_id,encrypted_envelope)
      VALUES($1,$2,$3,'task',$4,'task.approve',$5,$6,$7)`, [f.workspaceId, randomUUID(), project.projectId, doneId, f.accountId, approvalEnvelope.header.operationId, approvalEnvelope]);
  });
  const historicalRows = async () => ({
    versions: (await f.admin.application.query('SELECT * FROM app.record_versions WHERE workspace_id=$1 ORDER BY id', [f.workspaceId])).rows,
    audit: (await f.admin.application.query('SELECT * FROM app.audit_events WHERE workspace_id=$1 ORDER BY id', [f.workspaceId])).rows,
    comments: (await f.admin.application.query('SELECT * FROM app.comments WHERE workspace_id=$1 ORDER BY id', [f.workspaceId])).rows,
  });
  const before = await historicalRows();
  const removal = await f.draft('remove', memberId);
  assert.equal((await f.finalize(removal)).state, 'completed');
  await assert.rejects(f.sessions.authenticate(member.session.cookieValue));
  assert.deepEqual(await historicalRows(), before, 'Closing, assignment, approval and contribution bytes/actors remain unchanged');
  for (const [table, id, expectedEnvelope] of [['projects', project.projectId, projectEnvelope], ['project_phases', phaseId, phaseEnvelope]] as const) {
    const row = (await f.admin.application.query(`SELECT state,archived,revision,encrypted_envelope FROM app.${table} WHERE workspace_id=$1 AND id=$2`, [f.workspaceId, id])).rows[0];
    assert.equal(row.state, 'complete'); assert.equal(row.archived, true); assert.equal(row.revision, '1');
    assert.equal(canonicalJson(row.encrypted_envelope), canonicalJson(expectedEnvelope));
  }
  const tasks = (await f.admin.application.query('SELECT id,state,lead_profile_id,reviewer_profile_id,submitted_revision,revision,encrypted_envelope FROM app.tasks WHERE workspace_id=$1', [f.workspaceId])).rows;
  assert.equal(tasks.length, 2);
  for (const task of tasks) {
    assert.equal(task.state, task.id === doneId ? 'done' : 'cancelled'); assert.equal(task.lead_profile_id, null);
    assert.equal(task.reviewer_profile_id, f.accountId); assert.equal(task.submitted_revision, '1'); assert.equal(task.revision, '1');
    assert.equal(canonicalJson(task.encrypted_envelope), canonicalJson(task.id === doneId ? taskEnvelope : cancelledEnvelope));
  }
  assert.equal((await f.admin.application.query('SELECT * FROM app.task_assignments WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  const blocker = (await f.admin.application.query('SELECT * FROM app.blockers WHERE workspace_id=$1 AND id=$2', [f.workspaceId, blockerId])).rows[0];
  assert.equal(blocker.state, 'open'); assert.equal(blocker.responsible_profile_id, null); assert.equal(blocker.created_by, memberId);
  assert.equal(blocker.resolved_by, null); assert.equal(blocker.resolved_at, null); assert.equal(canonicalJson(blocker.encrypted_envelope), canonicalJson(blockerEnvelope));
  assert.equal((await f.admin.application.query('SELECT manager_profile_id FROM app.projects WHERE workspace_id=$1 AND id=$2', [f.workspaceId, project.projectId])).rows[0].manager_profile_id, null);
  const refreshed = await f.refresh(), state = await verifySecurityHistory(refreshed.history);
  const held = await readOwnerCustodyKeyMaterial({ accountId: f.accountId, deviceId: f.deviceId, history: state, materials: refreshed.delivery.materials }, f.originalBundle);
  const profile = (await f.admin.application.query('SELECT state,is_owner,key_epoch,encrypted_envelope FROM app.profiles WHERE workspace_id=$1 AND id=$2', [f.workspaceId, memberId])).rows[0];
  const currentKey = held.manifest.workspaceKeys.find((key) => key.epoch === profile.key_epoch)!;
  assert.equal(profile.state, 'removed'); assert.equal(profile.is_owner, false); assert.equal(profile.encrypted_envelope.header.recordId, memberId);
  assert.equal(canonicalJson(await decryptContent(profile.encrypted_envelope, base64urlDecode(currentKey.key), base64urlDecode(f.originalBundle.signingPublicKey), profile.encrypted_envelope.header)), canonicalJson({ displayName: 'Former member' }));
  const retainedKey = held.manifest.projectKeys.find((entry) => entry.projectId === project.projectId)!.keys.find((key) => key.epoch === '1')!;
  const historicTask = await decryptContent(taskEnvelope, base64urlDecode(retainedKey.key), base64urlDecode(member.bundle.signingPublicKey), taskEnvelope.header);
  assert.equal(canonicalJson(historicTask), canonicalJson({ title: 'Private completed work', assigneeIds: [memberId], leadProfileId: memberId }));
  assert.equal(canonicalJson(await decryptContent(commentEnvelope, base64urlDecode(retainedKey.key), base64urlDecode(member.bundle.signingPublicKey), commentEnvelope.header)), canonicalJson({ body: 'Private historical contribution' }));
  const denial = await f.read(`/v1/workspaces/${f.workspaceId}/projects/${project.projectId}/records/comments`, member.session.cookieValue);
  assert.equal(denial.statusCode, 401); assert.equal(denial.body.includes(commentEnvelope.ciphertext), false);
});

test('CP06: encrypted HTTP pagination rechecks real session and project revocation before every later page', async (t) => {
  const f = await fixture(t), member = await f.joined(), viewer = f.prepared.payload.genesis.body.roles.viewer;
  const memberId = member.binding.accountId;
  const project = await provisionProjectScope(f, { selected: [{ accountId: memberId, roleId: viewer }] });
  const taskIds = [randomUUID(), randomUUID(), randomUUID()].sort();
  const envelopes = await Promise.all(taskIds.map((id, index) => encryptedRecord(f, project, 'task', id, { title: `Private page task ${index}` })));
  await tenantTransaction(f.databases.application, f.workspaceId, f.accountId, async (c) => {
    for (let i = 0; i < taskIds.length; i++) await c.query(`INSERT INTO app.tasks(workspace_id,id,project_id,encrypted_envelope)
      VALUES($1,$2,$3,$4)`, [f.workspaceId, taskIds[i], project.projectId, envelopes[i]]);
  });
  const initial = await f.login(member.prepared, member.registered.exportKey);
  const path = `/v1/workspaces/${f.workspaceId}/projects/${project.projectId}/records/tasks`;
  const first = await f.read(`${path}?limit=1`, initial.session.cookieValue);
  assert.equal(first.statusCode, 200); assert.equal(first.headers['cache-control'], 'no-store');
  const page = first.json(); assert.equal(page.records.length, 1); assert.equal(page.records[0].id, taskIds[0]); assert.equal(page.nextCursor, taskIds[0]);
  assert.equal(canonicalJson(page.records[0].encrypted_envelope), canonicalJson(envelopes[0])); assert.equal(first.body.includes('Private page task'), false);
  const granted = (await f.admin.application.query('SELECT role_id,permissions FROM app.project_access WHERE workspace_id=$1 AND project_id=$2 AND profile_id=$3', [f.workspaceId, project.projectId, memberId])).rows[0];
  assert.equal(granted.role_id, viewer); assert.deepEqual(granted.permissions, ['read_project']);
  const change = await f.draft('set_access', memberId, { roleId: viewer, projectIds: [] });
  assert.equal((await f.finalize(change)).state, 'completed');
  const cursorPath = `${path}?limit=1&after=${page.nextCursor}`;
  const oldSession = await f.read(cursorPath, initial.session.cookieValue);
  assert.equal(oldSession.statusCode, 401);
  const current = await f.login(member.prepared, member.registered.exportKey);
  assert.equal(current.session.sessionGeneration, '2');
  const currentDelivery = await f.refresh(current.auth, current.bundle); assert.equal(currentDelivery.refreshed.scopeCount, 1);
  const freshSession = await f.read(cursorPath, current.session.cookieValue); assert.equal(freshSession.statusCode, 404);
  for (const response of [oldSession, freshSession]) {
    assert.equal(response.headers['cache-control'], 'no-store'); assert.equal(response.json().records, undefined);
    for (const envelope of envelopes) assert.equal(response.body.includes(envelope.ciphertext), false);
  }
  const remainingOwner = await f.read(cursorPath, f.auth().cookieValue);
  assert.equal(remainingOwner.statusCode, 200); assert.equal(remainingOwner.json().records[0].id, taskIds[1]);
  assert.equal(canonicalJson(remainingOwner.json().records[0].encrypted_envelope), canonicalJson(envelopes[1]));
  const state = await verifySecurityHistory(await f.history());
  assert.equal(state.profiles[memberId]!.role.id, viewer); assert.equal(state.profiles[memberId]!.scopes.some((scope) => scope.scopeId === project.projectId), false);
  assert.equal((await f.admin.application.query('SELECT state FROM app.project_access WHERE workspace_id=$1 AND project_id=$2 AND profile_id=$3', [f.workspaceId, project.projectId, memberId])).rows[0].state, 'revoked');
});

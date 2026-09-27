import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import { AppError } from '../src/errors.js';
import { transaction } from '../src/db.js';
import { ReceiptService } from '../src/modules/work/receipts.js';
import { registerReceiptRoutes } from '../src/modules/work/receipt-routes.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import { TeamService } from '../src/modules/work/teams.js';
import { RoleService } from '../src/modules/identity/roles.js';
import { InboxService } from '../src/modules/notifications/inbox.js';
import { CollaborationService } from '../src/modules/collaboration/service.js';
import { prepareTeamChange } from '../src/client/teams-crypto.js';
import { prepareRoleChange } from '../src/client/roles-controller.js';
import { prepareInbox } from '../src/client/inbox-crypto.js';
import { prepareCollaboration } from '../src/client/collaboration-crypto.js';
import { digestObject } from '../src/shared/crypto.js';
import { receiptLookupRequest, type ReceiptLookupRequest } from '../src/shared/receipts.js';
import { planningFixture } from './planning-fixture.js';
import { reportingFixture } from './reporting-fixture.js';
import { origin } from './password-change-fixture.js';

test('CP11 receipts: strict HTTP lookup survives logout/login and denies a different actor, workspace or revoked scope', async t => {
  const f = await planningFixture(t), member = await f.joined(), taskId = randomUUID();
  await f.finalize(await f.draft('set_access', member.binding.accountId, { roleId: f.prepared.payload.genesis.body.roles.member, projectIds: [f.projectId] }));
  const login = await f.login(member.prepared, member.registered.exportKey);
  await f.execute({ action: 'start_project' });
  await f.execute({ action: 'create_task', task: { id: taskId, phaseId: null, milestoneId: null, assigneeIds: [member.binding.accountId], leadProfileId: member.binding.accountId } }, { content: { title: 'Receipt fixture' } });
  const payload = await f.preparePlanning({ action: 'start_task', taskId }, {}, login.auth, login.bundle);
  const saved = await f.save(payload, login.auth), b = payload.mutation.body.binding;
  const reference = { kind: 'planning' as const, workspaceId: f.workspaceId, projectId: f.projectId, operationId: b.operationId };
  const budgets: unknown[] = [], receipts = new ReceiptService({ ...f, requestBudget: async entry => { budgets.push(entry); } }), app = Fastify({ logger: false });
  t.after(() => app.close());
  app.setErrorHandler((error, _request, reply) => reply.code(error instanceof AppError ? error.statusCode : 503).send({ code: error instanceof AppError ? error.code : 'UNAVAILABLE' }));
  registerReceiptRoutes(app, { origin, receipts, budgets: { async take(entries) { budgets.push(entries); } } });
  const headers = { origin, cookie: `${SESSION_COOKIE_NAME}=${login.auth.cookieValue}`, 'x-csrf-token': login.auth.csrfToken };
  const post = (body: object, custom = headers, url = '/v1/work/receipts') => app.inject({ method: 'POST', url, headers: custom, payload: body });
  assert.equal((await post(reference, { ...headers, origin: 'https://foreign.example' })).statusCode, 403);
  assert.equal(budgets.length, 0);
  assert.equal((await post(reference, { ...headers, cookie: '' })).statusCode, 401);
  assert.equal((await post(reference, { ...headers, 'x-csrf-token': '' })).statusCode, 403);
  assert.equal((await post({ ...reference, plaintext: 'forbidden' })).statusCode, 400);
  assert.equal((await post(reference, headers, '/v1/work/receipts?secret=forbidden')).statusCode, 400);
  const response = await post(reference);
  assert.equal(response.statusCode, 200); assert.equal(response.headers['cache-control'], 'no-store');
  assert.deepEqual(response.json(), { kind: 'planning', receipt: saved.receipt });
  assert.equal((await receipts.lookup(f.auth().cookieValue, f.auth().csrfToken, reference)).receipt, null, 'Owners cannot use another actor’s receipt identity');
  assert.equal((await receipts.lookup(login.auth.cookieValue, login.auth.csrfToken, { ...reference, operationId: randomUUID() })).receipt, null);
  await assert.rejects(receipts.lookup(login.auth.cookieValue, login.auth.csrfToken, { ...reference, workspaceId: randomUUID() }));
  await f.sessions.logout(login.auth.cookieValue, login.auth.csrfToken);
  assert.equal((await post(reference)).statusCode, 401);
  const resumed = await f.login(member.prepared, member.registered.exportKey);
  assert.deepEqual(await receipts.lookup(resumed.auth.cookieValue, resumed.auth.csrfToken, reference), { kind: 'planning', receipt: saved.receipt });
  await f.finalize(await f.draft('set_access', member.binding.accountId, { roleId: f.prepared.payload.genesis.body.roles.member, projectIds: [] }));
  const restricted = await f.login(member.prepared, member.registered.exportKey);
  await assert.rejects(receipts.lookup(restricted.auth.cookieValue, restricted.auth.csrfToken, reference));
  assert.equal(receiptLookupRequest.safeParse({ kind: 'team', workspaceId: f.workspaceId, operationId: randomUUID(), projectId: f.projectId }).success, false);
  assert.equal(receiptLookupRequest.safeParse({ kind: 'planning', workspaceId: f.workspaceId, operationId: randomUUID() }).success, false);
});

test('CP11 receipts: all business acknowledgement kinds resolve committed actor-bound records without retained request ciphertext', async t => {
  let f: Awaited<ReturnType<typeof reportingFixture>>;
  t.after(async () => { if (f) await transaction(f.admin.application, async c => {
    await c.query("SET LOCAL session_replication_role='replica'");
    for (const table of ['inbox_operations', 'notification_preferences', 'collaboration_operations', 'team_members', 'teams'])
      await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [f.workspaceId]);
  }); });
  f = await reportingFixture(t);
  const receipts = new ReceiptService(f), auth = f.auth(), refs: { reference: ReceiptLookupRequest; receipt: unknown }[] = [];
  const project = (await f.admin.control.query("SELECT operation_id,outcome FROM security.operation_receipts WHERE workspace_id=$1 AND operation_kind='project.create'", [f.workspaceId])).rows[0];
  refs.push({ reference: { kind: 'project', workspaceId: f.workspaceId, operationId: project.operation_id }, receipt: project.outcome });
  const member = await f.joined(), access = await f.draft('set_access', member.binding.accountId, { roleId: f.prepared.payload.genesis.body.roles.member, projectIds: [f.projectId] });
  const accessResult = await f.finalize(access);
  refs.push({ reference: { kind: 'access', ...access.reference }, receipt: accessResult.receipt });
  const roles = new RoleService({ ...f, origin }), roleRequest = { workspaceId: f.workspaceId, operationId: randomUUID(), roleId: randomUUID(), action: 'create' as const };
  const roleContext = await roles.context(auth.cookieValue, auth.csrfToken, roleRequest);
  const role = await prepareRoleChange({ request: roleRequest, context: roleContext, history: await f.history(), displayName: 'Receipt role', permissions: ['read_project'] }, f.originalBundle);
  await roles.stage(auth.cookieValue, auth.csrfToken, role);
  const roleResult = await roles.finalize(auth.cookieValue, auth.csrfToken, { workspaceId: f.workspaceId, operationId: roleRequest.operationId, requestHash: await digestObject(role) });
  refs.push({ reference: { kind: 'role', workspaceId: f.workspaceId, operationId: roleRequest.operationId }, receipt: roleResult.receipt });
  const teams = new TeamService(f), teamRequest = { workspaceId: f.workspaceId, operationId: randomUUID(), teamId: randomUUID(), action: 'create' as const };
  const team = await prepareTeamChange({ request: teamRequest, context: await teams.context(auth, teamRequest), history: await f.history(),
    accountId: f.accountId, deviceId: f.deviceId, materials: (await f.refresh()).delivery.materials, name: 'Receipt team', memberIds: [f.accountId] }, f.originalBundle);
  refs.push({ reference: { kind: 'team', workspaceId: f.workspaceId, operationId: teamRequest.operationId }, receipt: await teams.save(auth, team) });
  const setting = await f.settingDraft('Europe/London'), settingsResult = await f.reporting.saveSettings(auth, setting);
  refs.push({ reference: { kind: 'reporting-settings', workspaceId: f.workspaceId, operationId: setting.mutation.body.binding.operationId }, receipt: settingsResult.receipt });
  const summary = await f.summaryDraft(), summaryResult = await f.reporting.publish(auth, summary);
  refs.push({ reference: { kind: 'reporting-summary', workspaceId: f.workspaceId, operationId: summary.mutation.body.binding.operationId }, receipt: summaryResult.receipt });
  const inbox = new InboxService({ ...f, origin }), inboxRequest = { workspaceId: f.workspaceId, operationId: randomUUID() };
  const inboxDraft = await prepareInbox({ binding: (await inbox.context(auth.cookieValue, auth.csrfToken, inboxRequest)).binding,
    command: { action: 'set_project_muted', projectId: f.projectId, expectedRevision: '0', muted: true } }, f.originalBundle);
  refs.push({ reference: { kind: 'inbox', ...inboxRequest }, receipt: await inbox.save(auth.cookieValue, auth.csrfToken, inboxDraft) });
  const taskId = randomUUID(), task = await f.preparePlanning({ action: 'create_task', task: { id: taskId, phaseId: null, milestoneId: null, assigneeIds: [f.accountId], leadProfileId: f.accountId } }, { content: { title: 'Receipt task' } });
  const taskResult = await f.save(task);
  refs.push({ reference: { kind: 'planning', workspaceId: f.workspaceId, projectId: f.projectId, operationId: task.mutation.body.binding.operationId }, receipt: taskResult.receipt });
  const collaboration = new CollaborationService({ ...f, origin, planning: f.planning }), commentRequest = { workspaceId: f.workspaceId, projectId: f.projectId,
    operationId: randomUUID(), entryId: randomUUID(), kind: 'comment' as const };
  const context = await collaboration.context(auth.cookieValue, auth.csrfToken, commentRequest);
  const comment = await prepareCollaboration({ context, history: await f.history(), accountId: f.accountId, deviceId: f.deviceId,
    command: { action: 'post_comment', entryId: commentRequest.entryId, taskId }, text: 'Receipt comment' }, f.originalBundle);
  const commentResult = await collaboration.save(auth.cookieValue, auth.csrfToken, comment);
  refs.push({ reference: { kind: 'collaboration', workspaceId: f.workspaceId, projectId: f.projectId, operationId: commentRequest.operationId }, receipt: commentResult.receipt });
  assert.equal(refs.length, 9);
  for (const entry of refs) assert.deepEqual(await receipts.lookup(auth.cookieValue, auth.csrfToken, entry.reference), { kind: entry.reference.kind, receipt: entry.receipt }, entry.reference.kind);
  await f.admin.control.query("UPDATE security.workspaces SET lifecycle='deleted',deleted_at=clock_timestamp() WHERE workspace_id=$1", [f.workspaceId]);
  for (const entry of refs) await assert.rejects(receipts.lookup(auth.cookieValue, auth.csrfToken, entry.reference), `${entry.reference.kind} receipt must not outlive deletion`);
});

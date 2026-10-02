import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomUUID } from 'node:crypto';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { PairingService } from '../src/modules/identity/pairing.js';
import { InboxService } from '../src/modules/notifications/inbox.js';
import { readSessionCookie, SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import { startLogin, finishLogin } from '../src/client/opaque.js';
import { wrapDeviceBundle, type DeviceBundle } from '../src/client/device-store.js';
import { prepareInbox } from '../src/client/inbox-crypto.js';
import type { InboxCommand } from '../src/shared/inbox.js';
import { base64urlDecode, base64urlEncode, digestObject, encryptContent, generateRecipientKeyPair, generateSigningKeyPair, sealRecipient, signObject } from '../src/shared/crypto.js';
import { pairingConfirmationFor, pairingRecipientHeader, type PairingApproval } from '../src/shared/pairing.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { accessChangeFixture } from './access-change-fixture.js';
import { provisionProjectScope } from './project-scope-fixture.js';
import { origin, newPassword } from './password-change-fixture.js';

type Fixture = Awaited<ReturnType<typeof accessChangeFixture>>;
type Project = Awaited<ReturnType<typeof provisionProjectScope>>;
type Member = Awaited<ReturnType<Fixture['joined']>>;
async function fixture(t: TestContext) {
  let f: Fixture | undefined, api: ReturnType<typeof buildApp> | undefined;
  t.after(async () => {
    await api?.close(); if (!f) return;
    await transaction(f.admin.application, async (c) => {
      await c.query("SET LOCAL session_replication_role='replica'");
      for (const table of ['inbox_operations', 'notification_receipts', 'notification_preferences'])
        await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [f!.workspaceId]);
      for (const table of ['task_assignments', 'tasks', 'milestones', 'project_phases']) await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [f!.workspaceId]);
    });
  });
  f = await accessChangeFixture(t); const current = f;
  let omitDevice = false, afterAuthentication: (() => Promise<void>) | undefined;
  api = buildApp(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }), { ...f.databases, close: async () => {} }, undefined, async (request) => {
    const cookie = readSessionCookie(request.headers.cookie); if (!cookie) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    const principal = await current.sessions.authenticate(cookie, { approved: true });
    const next = afterAuthentication; afterAuthentication = undefined; if (next) await next();
    return omitDevice ? { ...principal, deviceId: null } : principal;
  });
  const app = api;
  return { ...f, read: (url: string, cookieValue?: string, extraHeaders: Record<string, string> = {}) => app.inject({ url,
    headers: { ...(cookieValue ? { cookie: `${SESSION_COOKIE_NAME}=${cookieValue}` } : {}), ...extraHeaders } }),
    missingDevice(value: boolean) { omitDevice = value; }, afterAuthentication(action: () => Promise<void>) { afterAuthentication = action; } };
}
async function restrictedSession(f: Fixture, accountId: string) {
  const login = await startLogin(newPassword), response = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId, startLoginRequest: login.startLoginRequest });
  const finish = await finishLogin({ password: newPassword, clientLoginState: login.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration });
  return f.authentication.finishLogin({ loginId: response.loginId, finishLoginRequest: finish.finishLoginRequest });
}
async function seedTasks(f: Fixture, project: Project) {
  const ids = [randomUUID(), randomUUID(), randomUUID()].sort(), head = (await f.history()).expected;
  for (const id of ids) {
    const envelope = await encryptContent({ ...f.prepared.payload.objects.profile.header, scope: 'project', scopeId: project.projectId,
      recordId: id, recordType: 'task', revision: '1', operationId: randomUUID(), action: 'fixture.seed', securityHead: head.securityHead, securityVersion: head.securityVersion },
    { title: 'Private task details' }, project.projectKey, base64urlDecode(f.originalBundle.signingPrivateKey));
    await f.admin.application.query('INSERT INTO app.tasks(workspace_id,project_id,id,encrypted_envelope) VALUES($1,$2,$3,$4)', [f.workspaceId, project.projectId, id, envelope]);
  }
  return ids;
}
/** Transport-only row fixtures: lifecycle commands and signed planning replay are tested separately. */
async function seedArchiveVisibility(f: Fixture, project: Project) {
  await f.admin.application.query("UPDATE app.projects SET state='complete',archived=true WHERE workspace_id=$1 AND id=$2", [f.workspaceId, project.projectId]);
  const ids = [randomUUID(), randomUUID(), randomUUID(), randomUUID()].sort(), head = (await f.history()).expected;
  for (const [index, id] of ids.entries()) {
    const archived = index % 2 === 0, state = index === 0 ? 'complete' : index === 2 ? 'cancelled' : 'planned';
    const envelope = await encryptContent({ ...f.prepared.payload.objects.profile.header, scope: 'project', scopeId: project.projectId,
      recordId: id, recordType: 'phase', revision: '1', operationId: randomUUID(), action: 'fixture.seed', securityHead: head.securityHead, securityVersion: head.securityVersion },
    { name: 'Private wave transport fixture' }, project.projectKey, base64urlDecode(f.originalBundle.signingPrivateKey));
    await f.admin.application.query('INSERT INTO app.project_phases(workspace_id,project_id,id,state,archived,encrypted_envelope) VALUES($1,$2,$3,$4,$5,$6)', [f.workspaceId, project.projectId, id, state, archived, envelope]);
  }
  return ids;
}
/** A genuine signed new-device grant, narrower than its person's enduring project grants. */
async function pairedLease(f: Fixture, member: Member, projects: Project[], excludedProject: string, leasedProject: string) {
  const accountId = member.binding.accountId, sourceDevice = member.prepared.draft.transcript.device.id;
  const pairing = new PairingService({ databases: f.databases, sessions: f.sessions, origin });
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair(), deviceId = randomUUID(), operationId = randomUUID();
  const bundle: DeviceBundle = { signingPrivateKey: base64urlEncode(signing.privateKey), signingPublicKey: base64urlEncode(signing.publicKey),
    recipientPrivateKey: base64urlEncode(recipient.privateKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
  const wrapper = await wrapDeviceBundle({ workspaceId: f.workspaceId, accountId, deviceId, credentialGeneration: '1' }, bundle, member.registered.exportKey);
  const restricted = await restrictedSession(f, accountId);
  await pairing.begin(restricted.cookieValue, restricted.csrfToken, { operationId, device: { id: deviceId, keyGeneration: '1',
    signingPublicKey: bundle.signingPublicKey, recipientPublicKey: bundle.recipientPublicKey }, localBundleDigest: await digestObject(wrapper) });
  const source = (await f.admin.control.query<{ grant_id: string; permissions: string[]; expires_at: Date | null }>(
    "SELECT grant_id,permissions,expires_at FROM security.grants WHERE workspace_id=$1 AND profile_id=$2 AND device_id=$3 AND scope_kind='project' AND state='active'", [f.workspaceId, accountId, sourceDevice])).rows;
  // Constrain the delegation inputs, then restore the original source grants.
  // The new device's narrower scope and expiry remain in its immutable signature.
  await f.admin.control.query("UPDATE security.grants SET permissions='{}' WHERE workspace_id=$1 AND device_id=$2 AND scope_id=$3 AND state='active'", [f.workspaceId, sourceDevice, excludedProject]);
  await f.admin.control.query("UPDATE security.grants SET expires_at=clock_timestamp()+interval '1 minute' WHERE workspace_id=$1 AND device_id=$2 AND scope_id=$3 AND state='active'", [f.workspaceId, sourceDevice, leasedProject]);
  const claimed = await pairing.claim(member.session.cookieValue, member.session.csrfToken, operationId), transcript = claimed.transcript!, transcriptDigest = claimed.transcriptDigest!;
  assert.equal(transcript.scopes.some((s) => s.scopeId === excludedProject), false);
  assert.ok(transcript.scopes.find((s) => s.scopeId === leasedProject)?.expiresAt);
  await pairing.confirm(restricted.cookieValue, restricted.csrfToken, await signObject(pairingConfirmationFor(transcript, transcriptDigest, 'recipient'), signing.privateKey));
  const confirmed = await pairing.confirm(member.session.cookieValue, member.session.csrfToken,
    await signObject(pairingConfirmationFor(transcript, transcriptDigest, 'approver'), base64urlDecode(member.bundle.signingPrivateKey)));
  const deliveries = await Promise.all(transcript.scopes.map(async (scope) => ({ id: randomUUID(), envelope: await sealRecipient(pairingRecipientHeader(transcript, transcriptDigest, scope),
    { version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch,
      keys: scope.scope === 'workspace' ? f.manifest.workspaceKeys : [{ epoch: '1', key: base64urlEncode(projects.find((project) => project.projectId === scope.scopeId)!.projectKey) }] },
    base64urlDecode(member.bundle.signingPrivateKey)) })));
  const approval: PairingApproval = { deliveries, grant: await signObject({ version: 1 as const, purpose: 'ukda.device-pair-grant.v1' as const,
    operationId, workspaceId: f.workspaceId, grantId: operationId, securityVersion: String(BigInt(transcript.securityVersion) + 1n), previousHead: transcript.securityHead,
    transcript, transcriptDigest, recipientConfirmation: confirmed.recipientConfirmation!, approverConfirmation: confirmed.approverConfirmation!,
    deliveries: await Promise.all(deliveries.map(async (d) => ({ id: d.id, scope: d.envelope.header.scope, scopeId: d.envelope.header.scopeId, digest: await digestObject(d.envelope) }))) }, base64urlDecode(member.bundle.signingPrivateKey)) };
  await pairing.stageApproval(member.session.cookieValue, member.session.csrfToken, approval);
  assert.equal((await pairing.commit(member.session.cookieValue, member.session.csrfToken, operationId)).projection.state, 'ready');
  for (const row of source) await f.admin.control.query('UPDATE security.grants SET permissions=$3,expires_at=$4 WHERE workspace_id=$1 AND grant_id=$2', [f.workspaceId, row.grant_id, row.permissions, row.expires_at]);
  const challenge = await f.sessions.beginDeviceChallenge(restricted.cookieValue, restricted.csrfToken, deviceId);
  const session = await f.sessions.completeDeviceChallenge(restricted.cookieValue, restricted.csrfToken, await signObject(challenge, signing.privateKey));
  // Verify this is a supported signed narrower lease, not just corrupted rows.
  const state = await verifySecurityHistory(await f.history());
  assert.equal(state.devices[deviceId]!.scopes.some((s) => s.scopeId === excludedProject), false);
  assert.equal(state.devices[deviceId]!.scopes.find((s) => s.scopeId === leasedProject)!.expiresAt, transcript.scopes.find((s) => s.scopeId === leasedProject)!.expiresAt);
  return { session, deviceId, transcript, bundle };
}

test('CP09 Inbox access boundary: an expired device-only project lease keeps generic receipts but rejects preference reads and replay', async t => {
  const f = await fixture(t), member = await f.joined(), projects: Project[] = [];
  for (let i = 0; i < 2; i++) projects.push(await provisionProjectScope(f, {
    selected: [{ accountId: member.binding.accountId, roleId: f.prepared.payload.genesis.body.roles.member }],
  }));
  const hidden = projects[0]!, leased = projects[1]!, paired = await pairedLease(f, member, projects, hidden.projectId, leased.projectId),
    inbox = new InboxService({ ...f, origin }), noticeId = randomUUID(), recordId = randomUUID(),
    cookie = paired.session.cookieValue, csrf = paired.session.csrfToken, reference = { workspaceId: f.workspaceId, notificationId: noticeId };
  // Metadata-only seed isolates the Inbox access boundary. Actual transactional
  // producers and worker delivery are covered in notifications.test.ts.
  await f.admin.application.query(`INSERT INTO app.notifications(workspace_id,id,recipient_profile_id,project_id,event_id,event_type,record_id)
    VALUES($1,$2,$3,$4,$5,'task.assignment',$6)`, [f.workspaceId, noticeId, member.binding.accountId, leased.projectId, randomUUID(), recordId]);
  assert.equal((await f.admin.application.query('SELECT id FROM app.notification_receipts WHERE workspace_id=$1 AND id=$2', [f.workspaceId, noticeId])).rowCount, 1);
  const prepare = async (command: InboxCommand) => {
    const context = await inbox.context(cookie, csrf, { workspaceId: f.workspaceId, operationId: randomUUID() });
    return prepareInbox({ binding: context.binding, command }, paired.bundle);
  };
  const initial = await inbox.resolve(cookie, csrf, reference);
  assert.equal(initial.projectId, leased.projectId); assert.equal(initial.recordId, recordId); assert.equal(initial.unavailable, false);
  const mute = await prepare({ action: 'set_project_muted', projectId: leased.projectId, expectedRevision: '0', muted: true }),
    muteReceipt = await inbox.save(cookie, csrf, mute),
    read = await prepare({ action: 'set_read', records: [{ id: noticeId, expectedRevision: initial.revision }], read: true }),
    readReceipt = await inbox.save(cookie, csrf, read);
  assert.deepEqual((await inbox.status(cookie, csrf, { workspaceId: f.workspaceId, operationId: mute.body.binding.operationId })).receipt, muteReceipt);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 120000 });
  try {
    assert.equal((await f.sessions.authenticate(cookie, { approved: true })).deviceId, paired.deviceId);
    const generic = await inbox.resolve(cookie, csrf, reference),
      listed = (await inbox.list(cookie, csrf, { workspaceId: f.workspaceId })).records.find(row => row.id === noticeId)!;
    assert.deepEqual(listed, generic);
    assert.equal(generic.unavailable, true); assert.equal(generic.eventType, 'content.unavailable');
    assert.equal(generic.projectId, null); assert.equal(generic.recordId, null); assert.ok(generic.readAt);
    const missing = (error: unknown) => error instanceof AppError && error.code === 'NOT_FOUND';
    await assert.rejects(inbox.preference(cookie, csrf, { workspaceId: f.workspaceId, projectId: leased.projectId }), missing);
    await assert.rejects(inbox.status(cookie, csrf, { workspaceId: f.workspaceId, operationId: mute.body.binding.operationId }), missing);
    await assert.rejects(inbox.save(cookie, csrf, mute), missing);
    assert.deepEqual(await inbox.save(cookie, csrf, read), readReceipt, 'Exact personal read receipt remains safe to replay without project details');
    const unread = await prepare({ action: 'set_read', records: [{ id: noticeId, expectedRevision: generic.revision }], read: false });
    await inbox.save(cookie, csrf, unread);
    const changed = await inbox.resolve(cookie, csrf, reference);
    assert.equal(changed.unavailable, true); assert.equal(changed.readAt, null); assert.equal(changed.revision, '3');
    const original = await inbox.resolve(member.session.cookieValue, member.session.csrfToken, reference);
    assert.equal(original.unavailable, false); assert.equal(original.projectId, leased.projectId); assert.equal(original.recordId, recordId);
    assert.equal(original.readAt, null, 'Read flags belong to the person while content access remains device-specific');
    assert.equal((await inbox.preference(member.session.cookieValue, member.session.csrfToken, { workspaceId: f.workspaceId, projectId: leased.projectId })).muted, true);
  } finally { t.mock.timers.reset(); }
});

test('CP07 reads: approved device scopes filter before pagination and expired project leases deny later pages despite live person/workspace access', async (t) => {
  const f = await fixture(t), member = await f.joined(), ids = [randomUUID(), randomUUID(), randomUUID()].sort(), projects: Project[] = [];
  for (const id of ids) projects.push(await provisionProjectScope(f, { projectId: id, selected: [{ accountId: member.binding.accountId, roleId: f.prepared.payload.genesis.body.roles.member }] }));
  const [hidden, leased, enduring] = projects as [Project, Project, Project], tasks = await seedTasks(f, leased);
  const paired = await pairedLease(f, member, projects, hidden.projectId, leased.projectId), cookie = paired.session.cookieValue;
  const listPath = `/v1/workspaces/${f.workspaceId}/projects`, detail = `${listPath}/${leased.projectId}`, records = `${detail}/records/tasks`;
  const first = await f.read(`${listPath}?limit=1`, cookie); assert.equal(first.statusCode, 200);
  assert.deepEqual(first.json().records.map((r: { id: string }) => r.id), [leased.projectId]); assert.equal(first.json().nextCursor, leased.projectId);
  const second = await f.read(`${listPath}?limit=1&after=${first.json().nextCursor}`, cookie);
  assert.deepEqual(second.json().records.map((r: { id: string }) => r.id), [enduring.projectId]); assert.equal(second.json().nextCursor, null);
  for (const path of [`${listPath}/${hidden.projectId}`, `${listPath}/${hidden.projectId}/records/tasks`]) assert.equal((await f.read(path, cookie)).statusCode, 404);
  assert.equal((await f.read(detail, cookie)).statusCode, 200);
  const taskPage = await f.read(`${records}?limit=1`, cookie); assert.equal(taskPage.statusCode, 200); assert.equal(taskPage.json().nextCursor, tasks[0]);
  const taskNext = await f.read(`${records}?limit=1&after=${tasks[0]}`, cookie); assert.equal(taskNext.json().records[0].id, tasks[1]);
  assert.equal(taskNext.json().nextCursor, tasks[1]); assert.equal(taskNext.body.includes('Private task details'), false);
  assert.equal((await f.read(listPath, member.session.cookieValue)).json().records.length, 3);
  assert.equal((await f.read(listPath, f.auth().cookieValue)).json().records.length, 3);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 120000 });
  try {
    assert.equal((await f.sessions.authenticate(cookie, { approved: true })).deviceId, paired.deviceId);
    assert.equal((await f.read(detail, cookie)).statusCode, 404);
    assert.equal((await f.read(`${records}?limit=1&after=${tasks[0]}`, cookie)).statusCode, 404);
    assert.deepEqual((await f.read(listPath, cookie)).json().records.map((r: { id: string }) => r.id), [enduring.projectId]);
    assert.equal((await f.read(`${listPath}?limit=1&after=${leased.projectId}`, cookie)).json().records[0].id, enduring.projectId);
    assert.equal((await f.read(detail, member.session.cookieValue)).statusCode, 200);
  } finally { t.mock.timers.reset(); }
});

test('CP07 reads: actual sessions enforce actor, tenant, device, fence, strict query and no-store checks', async (t) => {
  const f = await fixture(t), stranger = await f.joined(), project = await provisionProjectScope(f), other = await fixture(t), foreign = await provisionProjectScope(other);
  const listPath = `/v1/workspaces/${f.workspaceId}/projects`, detail = `${listPath}/${project.projectId}`, cookie = f.auth().cookieValue;
  const valid = await f.read(detail, cookie); assert.equal(valid.statusCode, 200); assert.equal(valid.headers['cache-control'], 'no-store');
  for (const [path, actor, status] of [[detail, undefined, 401], [detail, 'malformed', 401],
    [`/v1/workspaces/${other.workspaceId}/projects/${foreign.projectId}`, cookie, 404], [`${listPath}/${foreign.projectId}`, cookie, 404],
    [detail, stranger.session.cookieValue, 404], [`${listPath}?limit=1000`, cookie, 400], [`${listPath}?unknown=true`, cookie, 400],
    [`${listPath}?after=not-a-uuid`, cookie, 400], [`${detail}/records/unknown`, cookie, 400], [`${detail}/records/tasks?limit=0`, cookie, 400]] as const) {
    const response = await f.read(path, actor); assert.equal(response.statusCode, status, path); assert.equal(response.headers['cache-control'], 'no-store');
  }
  assert.equal((await f.read(detail, stranger.session.cookieValue, { 'x-profile-id': f.accountId, 'x-device-id': f.deviceId, 'x-workspace-id': f.workspaceId })).statusCode, 404);
  assert.deepEqual((await f.read(listPath, stranger.session.cookieValue)).json().records, []);
  const restricted = await restrictedSession(f, stranger.binding.accountId);
  assert.equal((await f.read(detail, restricted.cookieValue)).statusCode, 403);
  f.missingDevice(true); assert.equal((await f.read(detail, cookie)).statusCode, 403); f.missingDevice(false);
  await f.admin.application.query('UPDATE app.workspaces SET fence_closed=true WHERE workspace_id=$1', [f.workspaceId]);
  const fenced = await f.read(detail, cookie); assert.equal(fenced.statusCode, 503); assert.equal(fenced.json().error.code, 'SECURITY_FENCED');
  await f.admin.application.query('UPDATE app.workspaces SET fence_closed=false WHERE workspace_id=$1', [f.workspaceId]);
  f.afterAuthentication(() => f.sessions.logout(cookie, f.auth().csrfToken));
  assert.equal((await f.read(detail, cookie)).statusCode, 401);
});

test('CP07 reads: seeded archive rows are filtered before project/wave pagination, with explicit history access and strict opt-in', async (t) => {
  const f = await fixture(t), stranger = await f.joined(), ids = [randomUUID(), randomUUID(), randomUUID()].sort(), projects: Project[] = [];
  for (const id of ids) projects.push(await provisionProjectScope(f, { projectId: id }));
  const archived = projects[0]!, phaseIds = await seedArchiveVisibility(f, archived), cookie = f.auth().cookieValue;
  const listPath = `/v1/workspaces/${f.workspaceId}/projects`, detail = `${listPath}/${archived.projectId}`, phases = `${detail}/records/phases`;
  const page = async (path: string, expected: string[], nextCursor: string | null) => {
    const response = await f.read(path, cookie); assert.equal(response.statusCode, 200, path);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.deepEqual(response.json().records.map((r: { id: string }) => r.id), expected, path);
    assert.equal(response.json().nextCursor, nextCursor, path); return response;
  };
  await page(`${listPath}?limit=1`, [ids[1]!], ids[1]!);
  await page(`${listPath}?limit=1&after=${ids[1]}`, [ids[2]!], null);
  await page(`${listPath}?limit=1&after=${ids[0]}`, [ids[1]!], ids[1]!);
  await page(`${listPath}?includeArchived=false`, ids.slice(1), null);
  await page(`${listPath}?includeArchived=true&limit=1`, [ids[0]!], ids[0]!);
  await page(`${listPath}?includeArchived=true&limit=1&after=${ids[0]}`, [ids[1]!], ids[1]!);
  await page(`${listPath}?includeArchived=true`, ids, null);
  const historical = await f.read(detail, cookie); assert.equal(historical.statusCode, 200); assert.equal(historical.json().record.archived, true);
  await page(`${phases}?limit=1`, [phaseIds[1]!], phaseIds[1]!);
  await page(`${phases}?limit=1&after=${phaseIds[1]}`, [phaseIds[3]!], null);
  await page(`${phases}?limit=1&after=${phaseIds[2]}`, [phaseIds[3]!], null);
  await page(`${phases}?includeArchived=false`, [phaseIds[1]!, phaseIds[3]!], null);
  await page(`${phases}?includeArchived=true&limit=2`, phaseIds.slice(0, 2), phaseIds[1]!);
  await page(`${phases}?includeArchived=true&limit=2&after=${phaseIds[1]}`, phaseIds.slice(2), null);
  const allPhases = await page(`${phases}?includeArchived=true`, phaseIds, null);
  assert.equal(allPhases.body.includes('Private wave transport fixture'), false);
  for (const path of [`${listPath}?includeArchived=1`, `${listPath}?includeArchived=TRUE`, `${listPath}?includeArchived=true&includeArchived=false`,
    `${phases}?includeArchived=`, `${phases}?includeArchived=true&unknown=true`, `${detail}/records/tasks?includeArchived=true`]) {
    const response = await f.read(path, cookie); assert.equal(response.statusCode, 400, path); assert.equal(response.headers['cache-control'], 'no-store');
  }
  assert.deepEqual((await f.read(`${listPath}?includeArchived=true`, stranger.session.cookieValue)).json().records, []);
  assert.equal((await f.read(`${phases}?includeArchived=true`, stranger.session.cookieValue)).statusCode, 404);
});

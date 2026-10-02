import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test, { type TestContext } from 'node:test';
import { AppError } from '../src/errors.js';
import { transaction } from '../src/db.js';
import { ProjectCreateService } from '../src/modules/work/project-create.js';
import { prepareProjectCreate } from '../src/client/project-create-crypto.js';
import { readOwnerCustodyKeyMaterial } from '../src/client/pairing.js';
import { base64urlDecode, decryptContent, digestObject } from '../src/shared/crypto.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { validateProjectCreateReceiptForPayload } from '../src/shared/project-create.js';
import { accessChangeFixture } from './access-change-fixture.js';
import { origin } from './password-change-fixture.js';
const code = (expected: string) => (e: unknown) => e instanceof AppError && e.code === expected;

async function fixture(t: TestContext) {
  const f = await accessChangeFixture(t); let offset = 0;
  let hooks: NonNullable<ConstructorParameters<typeof ProjectCreateService>[0]['hooks']> = {};
  const make = () => new ProjectCreateService({ ...f, origin, now: () => new Date(Date.now() + offset), hooks });
  let service = make();
  async function prepare(name = 'Private delivery project', auth = f.auth(), bundle = f.originalBundle) {
    const request = { workspaceId: f.workspaceId, operationId: randomUUID(), projectId: randomUUID() };
    const context = await service.context(auth.cookieValue, auth.csrfToken, request);
    const payload = await prepareProjectCreate({ request, context, history: await f.history(), name }, bundle);
    const reference = { workspaceId: request.workspaceId, operationId: request.operationId };
    return { request, reference, context, payload, finalize: { ...reference, requestHash: await digestObject(payload) } };
  }
  async function stage(draft: Awaited<ReturnType<typeof prepare>>) { const a = f.auth(); return service.stage(a.cookieValue, a.csrfToken, draft.payload); }
  async function finalize(draft: Awaited<ReturnType<typeof prepare>>) { const a = f.auth(); return service.finalize(a.cookieValue, a.csrfToken, draft.finalize); }
  async function status(draft: Awaited<ReturnType<typeof prepare>>) { const a = f.auth(); return service.status(a.cookieValue, a.csrfToken, draft.reference); }
  return { ...f, prepare, stage, finalize, status, get projectCreation() { return service; },
    setHooks(value: typeof hooks = {}) { hooks = value; service = make(); }, advance(ms: number) { offset += ms; } };
}

test('CP07: name-only creation atomically exposes an encrypted Planned project and explicit keys to every active Owner', async (t) => {
  const f = await fixture(t), second = await f.joined('join_owner'), member = await f.joined();
  const draft = await f.prepare(), firstCustody = draft.context.binding.custodyEpoch;
  assert.equal(draft.context.plan.recipients.filter((r) => r.kind === 'recovery').length, 2);
  assert.equal(draft.context.plan.recipients.some((r) => r.accountId === member.binding.accountId), false);
  assert.equal((await f.status(draft)).state, 'absent'); assert.equal((await f.stage(draft)).state, 'staged');
  assert.equal((await f.admin.application.query('SELECT 1 FROM app.projects WHERE workspace_id=$1 AND id=$2', [f.workspaceId, draft.request.projectId])).rowCount, 0);
  const [a, b] = await Promise.all([f.finalize(draft), f.finalize(draft)]);
  assert.equal(a.state, 'completed'); assert.deepEqual(a, b); await validateProjectCreateReceiptForPayload(a.receipt, draft.payload);
  const project = (await f.admin.application.query('SELECT * FROM app.projects WHERE workspace_id=$1 AND id=$2', [f.workspaceId, draft.request.projectId])).rows[0];
  assert.equal(project.state, 'planned'); assert.equal(project.manager_profile_id, null); assert.equal(project.team_id, null); assert.equal(project.archived, false);
  assert.deepEqual(project.encrypted_envelope, draft.payload.project.envelope);
  assert.equal(JSON.stringify(project).includes('Private delivery project'), false);
  const access = (await f.admin.application.query("SELECT profile_id FROM app.project_access WHERE workspace_id=$1 AND project_id=$2 AND state='active' ORDER BY profile_id", [f.workspaceId, project.id])).rows.map((r) => r.profile_id);
  assert.deepEqual(access, [f.accountId, second.binding.accountId].sort());
  const secondKeys = await f.refresh(second.auth, second.bundle), state = await verifySecurityHistory(secondKeys.history);
  const held = await readOwnerCustodyKeyMaterial({ accountId: second.binding.accountId, deviceId: second.prepared.draft.transcript.device.id, history: state, materials: secondKeys.delivery.materials }, second.bundle);
  assert.equal(held.manifest.custodyEpoch, String(BigInt(firstCustody) + 1n));
  const key = held.manifest.projectKeys.find((p) => p.projectId === project.id)!.keys[0]!.key;
  assert.equal((await decryptContent(project.encrypted_envelope, base64urlDecode(key), base64urlDecode(f.originalBundle.signingPublicKey), project.encrypted_envelope.header) as { name: string }).name, 'Private delivery project');
  const next = await f.prepare('Second private project'); await f.stage(next); await f.finalize(next);
  const updated = await f.refresh(second.auth, second.bundle), updatedState = await verifySecurityHistory(updated.history);
  const retained = await readOwnerCustodyKeyMaterial({ accountId: second.binding.accountId, deviceId: second.prepared.draft.transcript.device.id, history: updatedState, materials: updated.delivery.materials }, second.bundle);
  assert.deepEqual(retained.manifest.projectKeys.find((p) => p.projectId === project.id)?.keys, [{ epoch: '1', key }]);
  assert.equal(retained.manifest.projectKeys.length, 2);
  assert.deepEqual((await f.status(draft)).receipt, a.receipt);
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.project_creations WHERE workspace_id=$1 AND operation_id=$2', [f.workspaceId, draft.request.operationId])).rowCount, 1);
});

test('CP07: unsigned/missing metadata, incomplete recipients, changed immutable drafts, and stale heads are rejected', async (t) => {
  const f = await fixture(t), draft = await f.prepare(), a = f.auth();
  const { project: _project, ...missing } = draft.payload;
  await assert.rejects(f.projectCreation.stage(a.cookieValue, a.csrfToken, missing), code('PROJECT_INVALID'));
  const incomplete = structuredClone(draft.payload); incomplete.deliveries.pop();
  await assert.rejects(f.projectCreation.stage(a.cookieValue, a.csrfToken, incomplete), code('PROJECT_INVALID'));
  const altered = structuredClone(draft.payload); altered.project.envelope.header.recordId = randomUUID();
  await assert.rejects(f.projectCreation.stage(a.cookieValue, a.csrfToken, altered), code('PROJECT_INVALID'));
  await f.stage(draft);
  const otherPayload = await prepareProjectCreate({ request: draft.request, context: draft.context, history: await f.history(), name: 'Changed private name' }, f.originalBundle);
  await assert.rejects(f.projectCreation.stage(a.cookieValue, a.csrfToken, otherPayload), code('PROJECT_CHANGED'));
  const winner = await f.prepare(); await f.stage(winner); await f.finalize(winner);
  await assert.rejects(f.finalize(draft), code('PROJECT_CHANGED'));
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.project_creations WHERE workspace_id=$1 AND project_id=$2', [f.workspaceId, draft.request.projectId])).rowCount, 0);
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].fence_closed, false);
});

test('CP07: preparation and first commit recheck Owner, entitlement, maintenance, live grants and expiry', async (t) => {
  const f = await fixture(t), member = await f.joined(), draft = await f.prepare(), a = f.auth();
  await assert.rejects(f.projectCreation.context(member.auth.cookieValue, member.auth.csrfToken, draft.request), code('PROJECT_FORBIDDEN'));
  await f.stage(draft);
  for (const field of ['content_maintenance', 'restore_quarantine']) {
    await f.admin.control.query(`UPDATE security.workspaces SET ${field}=true WHERE workspace_id=$1`, [f.workspaceId]);
    await assert.rejects(f.finalize(draft), code('WORKSPACE_RESTRICTED'));
    await f.admin.control.query(`UPDATE security.workspaces SET ${field}=false WHERE workspace_id=$1`, [f.workspaceId]);
  }
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='restricted' WHERE workspace_id=$1", [f.workspaceId]);
  await assert.rejects(f.finalize(draft), code('WORKSPACE_RESTRICTED'));
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='active' WHERE workspace_id=$1", [f.workspaceId]);
  await transaction(f.admin.control, async (c) => {
    await c.query("UPDATE security.grants SET state='revoked',revoked_at=clock_timestamp() WHERE workspace_id=$1 AND device_id=$2 AND state='active'", [f.workspaceId, f.deviceId]);
  });
  await assert.rejects(f.projectCreation.context(a.cookieValue, a.csrfToken, { ...draft.request, operationId: randomUUID() }));
  await assert.rejects(f.finalize(draft));
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.project_creations WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  const expired = await fixture(t), timed = await expired.prepare(); await expired.stage(timed); expired.advance(600001);
  assert.equal((await expired.status(timed)).state, 'expired');
  await assert.rejects(expired.finalize(timed), code('REAUTH_REQUIRED'));
  // Align the fixture's recent-auth timestamp with its virtual clock, then prove
  // the immutable creation expiry independently of the password recency gate.
  await expired.admin.control.query('UPDATE security.sessions SET authenticated_at=$2 WHERE workspace_id=$1 AND revoked_at IS NULL', [expired.workspaceId, new Date(Date.now() + 600001)]);
  await assert.rejects(expired.finalize(timed), code('PROJECT_CHANGED'));
});

test('CP07: interrupted control commit rolls back atomically and retries the exact staged operation once', async (t) => {
  const f = await fixture(t), draft = await f.prepare(); await f.stage(draft);
  f.setHooks({ beforeControlCommit: async () => { throw new Error('injected before control commit'); } });
  await assert.rejects(f.finalize(draft), code('PROJECT_UNAVAILABLE'));
  assert.equal((await f.status(draft)).state, 'staged');
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.project_creations WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  assert.equal((await f.admin.application.query('SELECT 1 FROM app.projects WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  f.setHooks(); assert.equal((await f.finalize(draft)).state, 'completed');
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2', [f.workspaceId, draft.request.operationId])).rowCount, 1);
});

test('CP07: committed creation survives lost response and failed projection with no partial availability', async (t) => {
  const f = await fixture(t), draft = await f.prepare(); await f.stage(draft); let observed = false;
  f.setHooks({ beforeProjection: async () => {
    const w = (await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0];
    assert.equal(w.fence_closed, true);
    assert.equal((await f.admin.application.query('SELECT 1 FROM app.projects WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
    assert.equal((await f.admin.control.query('SELECT 1 FROM security.project_creations WHERE workspace_id=$1', [f.workspaceId])).rowCount, 1);
    observed = true; throw new Error('injected projection interruption');
  } });
  const finishing = await f.finalize(draft); assert.equal(finishing.state, 'finishing'); assert.ok(observed);
  f.setHooks(); f.advance(600001);
  const completed = await f.status(draft); assert.equal(completed.state, 'completed'); assert.deepEqual(completed.receipt, finishing.receipt);
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].fence_closed, false);
  f.advance(-600001); const next = await f.prepare(); await f.stage(next);
  f.setHooks({ afterControlCommit: async () => { throw new Error('injected lost response after commit'); } });
  await assert.rejects(f.finalize(next), code('PROJECT_UNAVAILABLE'));
  f.setHooks(); const resumed = await f.status(next); assert.equal(resumed.state, 'completed');
  assert.equal((await f.admin.application.query('SELECT 1 FROM app.projects WHERE workspace_id=$1', [f.workspaceId])).rowCount, 2);
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.project_creations WHERE workspace_id=$1', [f.workspaceId])).rowCount, 2);
});

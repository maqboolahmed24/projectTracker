import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { AppError } from '../src/errors.js';
import { base64urlDecode, digestObject, signObject } from '../src/shared/crypto.js';
import { planningFixture } from './planning-fixture.js';
const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;

test('CP07: persistent encrypted waves overlap and manual acceptance/closures retain versioned outcomes through archive/reopen', async (t) => {
  const f = await planningFixture(t), first = randomUUID(), second = randomUUID(), milestone = randomUUID();
  await f.execute({ action: 'edit_project', patch: { phaseLabel: 'phase', managerProfileId: f.accountId } }, { content: { name: 'Private pilot programme', startDate: '2026-10-01', dueDate: '2026-11-01' } });
  await f.execute({ action: 'create_phase', phase: { id: first, displayOrder: 0, leadProfileId: f.accountId } }, { content: { name: 'Private pilot', objective: 'Validate private assumptions', completionCriteria: 'Record learning', startDate: '2026-10-01', dueDate: '2026-10-20' } });
  await f.execute({ action: 'create_phase', phase: { id: second, displayOrder: 1, leadProfileId: null } }, { content: { name: 'Private expansion', objective: '', completionCriteria: '', startDate: '2026-10-10', dueDate: '2026-11-01' } });
  await f.execute({ action: 'create_milestone', milestone: { id: milestone, phaseId: first, ownerProfileId: f.accountId } }, { content: { name: 'Private acceptance', dueDate: '2026-10-19' } });
  await f.execute({ action: 'start_project' }); await f.execute({ action: 'start_phase', phaseId: first }); await f.execute({ action: 'start_phase', phaseId: second });
  assert.deepEqual((await f.context()).graph.phases.map((p) => p.state), ['active', 'active']);
  await assert.rejects(f.execute({ action: 'complete_phase', phaseId: first }, { outcome: 'Private closure' }), /unaccepted_milestones/);
  await f.execute({ action: 'accept_milestone', milestoneId: milestone }, { outcome: 'Private checkpoint accepted without tasks' });
  await f.execute({ action: 'complete_phase', phaseId: first }, { outcome: 'Private pilot feedback' });
  await f.execute({ action: 'complete_phase', phaseId: second }, { outcome: 'Private expansion feedback' });
  await f.execute({ action: 'complete_project' }, { outcome: 'Private project delivery outcome' });
  await f.execute({ action: 'archive_project' });
  const archived = await f.read(); assert.equal(archived.graph.project.archived, true); assert.equal(archived.graph.snapshots.length, 4);
  assert.equal(archived.records.find((r) => r.kind === 'project')!.content.name, 'Private pilot programme');
  assert.ok(archived.outcomes.some((o) => o.text === 'Private pilot feedback'));
  await assert.rejects(f.execute({ action: 'edit_project', patch: {} }), /scope_read_only/);
  await f.execute({ action: 'unarchive_project' }); await f.execute({ action: 'reopen_project' });
  await f.execute({ action: 'reopen_phase', phaseId: first });
  await f.execute({ action: 'edit_phase', phaseId: first, patch: { displayOrder: 2 } }, { content: { name: 'Private pilot revised', objective: '', completionCriteria: '' } });
  const reopened = await f.read(); assert.deepEqual(reopened.graph.snapshots, archived.graph.snapshots);
  const snapshot = reopened.audits.find((a) => a.data.snapshot?.recordId === first)!;
  assert.equal(snapshot.data.snapshotContents.find((r) => r.id === first)!.content.name, 'Private pilot');
  const stored = await f.admin.application.query('SELECT encrypted_envelope FROM app.projects WHERE workspace_id=$1 UNION ALL SELECT encrypted_envelope FROM app.audit_events WHERE workspace_id=$1 UNION ALL SELECT encrypted_envelope FROM app.updates WHERE workspace_id=$1', [f.workspaceId]);
  assert.equal(JSON.stringify(stored.rows).includes('Private pilot'), false);
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.planning_operations WHERE workspace_id=$1', [f.workspaceId])).rows[0].n, reopened.audits.length);
  assert.equal((await f.admin.application.query("SELECT count(*)::int AS n FROM app.outbox WHERE workspace_id=$1 AND event_type='planning.changed'", [f.workspaceId])).rows[0].n, reopened.audits.length);
});

test('CP07: concurrent child insertion, stale security authority, forged changes and modified retries cannot overwrite the graph', async (t) => {
  const f = await planningFixture(t);
  const first = await f.preparePlanning({ action: 'create_phase', phase: { id: randomUUID(), displayOrder: 0, leadProfileId: null } }, { content: { name: 'First', objective: '', completionCriteria: '' } });
  const second = await f.preparePlanning({ action: 'create_phase', phase: { id: randomUUID(), displayOrder: 1, leadProfileId: null } }, { content: { name: 'Second', objective: '', completionCriteria: '' } });
  const results = await Promise.allSettled([f.save(first), f.save(second)]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal(results.filter((r) => r.status === 'rejected' && code('PLANNING_CHANGED')(r.reason)).length, 1);
  assert.equal((await f.context()).graph.phases.length, 1);
  const draft = await f.preparePlanning({ action: 'start_project' });
  const missing = structuredClone(draft); missing.records = [];
  await assert.rejects(f.save(missing), code('PLANNING_INVALID'));
  const forged = structuredClone(draft); forged.mutation.body.command = { ...forged.mutation.body.command, action: 'archive_project' } as typeof forged.mutation.body.command;
  await assert.rejects(f.save(forged), code('PLANNING_INVALID'));
  const receipt = await f.save(draft); assert.deepEqual(await f.save(draft), receipt);
  const altered = structuredClone(draft); altered.audit.envelope.signature = first.audit.envelope.signature;
  await assert.rejects(f.save(altered), code('PLANNING_CHANGED'));
  const stale = await f.preparePlanning({ action: 'edit_project', patch: {} });
  await f.joined('join_owner');
  await assert.rejects(f.save(stale), code('PLANNING_CHANGED'));
  const current = await f.context(); assert.notEqual(current.binding.securityHead, stale.mutation.body.binding.securityHead);
  assert.equal(current.graph.project.revision, '2');
  // An unsigned inserted row must never be silently excluded from a closure context.
  await f.admin.application.query(`INSERT INTO app.project_phases(workspace_id,id,project_id,encrypted_envelope) VALUES($1,$2,$3,$4)`,
    [f.workspaceId, randomUUID(), f.projectId, first.records[0]!.envelope]);
  await assert.rejects(f.context(), code('PLANNING_CHANGED'));
});

test('CP07: rows, versions, history, outcome, receipt and outbox roll back together; lost replies replay once even when restricted', async (t) => {
  const f = await planningFixture(t), draft = await f.preparePlanning({ action: 'cancel_project' }, { outcome: 'Private cancellation reason' });
  f.setPlanningHooks({ beforeCommit: async () => { throw new Error('injected transaction failure'); } });
  await assert.rejects(f.save(draft), code('PLANNING_UNAVAILABLE'));
  for (const table of ['planning_operations','project_planning_heads','audit_events','updates','record_versions','operation_receipts','outbox'])
    assert.equal((await f.admin.application.query(`SELECT count(*)::int AS n FROM app.${table} WHERE workspace_id=$1`, [f.workspaceId])).rows[0].n, 0, table);
  assert.equal((await f.context()).graph.project.state, 'planned'); assert.equal((await f.planningStatus(draft)).state, 'absent');
  f.setPlanningHooks({ afterCommit: async () => { throw new Error('lost reply'); } }); await assert.rejects(f.save(draft), /lost reply/);
  f.setPlanningHooks(); const saved = await f.planningStatus(draft); assert.equal(saved.state, 'completed');
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='restricted' WHERE workspace_id=$1", [f.workspaceId]);
  assert.deepEqual(await f.save(draft), saved); assert.deepEqual(await f.planningStatus(draft), saved);
  // Context reads remain permitted; first writes enforce current authoritative state.
  const next = await f.preparePlanning({ action: 'reopen_project' });
  await assert.rejects(f.save(next), code('WORKSPACE_RESTRICTED'));
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='active' WHERE workspace_id=$1", [f.workspaceId]);
  const oldGeneration = structuredClone(draft); oldGeneration.mutation.body.binding.dataGeneration = '2';
  await assert.rejects(f.save(oldGeneration), code('PLANNING_CHANGED'));
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.planning_operations WHERE workspace_id=$1', [f.workspaceId])).rows[0].n, 1);
});

test('CP07: project reads and writes require current personal AND device keys; designations do not grant planning or arbitrary project writes', async (t) => {
  const f = await planningFixture(t), member = await f.joined(), reference = f.reference();
  await assert.rejects(f.planning.context(member.auth.cookieValue, member.auth.csrfToken, reference), code('PLANNING_FORBIDDEN'));
  const memberRole = (await f.admin.control.query("SELECT role_id FROM security.roles WHERE workspace_id=$1 AND template='member'", [f.workspaceId])).rows[0].role_id as string;
  await f.finalize(await f.draft('set_access', member.binding.accountId, { roleId: memberRole, projectIds: [f.projectId] }));
  // Access changes revoke the target session; explicit login refreshes current authority.
  const logged = await f.login(member.prepared, member.registered.exportKey);
  const current = await f.planning.context(logged.auth.cookieValue, logged.auth.csrfToken, reference);
  assert.deepEqual(current.binding.permissions, ['read_project','comment','create_tasks','edit_assigned_tasks']);
  await f.execute({ action: 'edit_project', patch: { managerProfileId: member.binding.accountId } });
  const denied = await f.preparePlanning({ action: 'start_project' });
  // A member cannot submit another account's signed operation, even when named Manager.
  await assert.rejects(f.save(denied, logged.auth), code('PLANNING_CHANGED'));
  const phase = randomUUID();
  await assert.rejects(f.execute({ action: 'create_phase', phase: { id: phase, displayOrder: 0, leadProfileId: randomUUID() } }, { content: { name: 'Invalid lead', objective: '', completionCriteria: '' } }), code('PLANNING_FORBIDDEN'));
  await assert.rejects(f.execute({ action: 'edit_project', patch: { teamId: randomUUID() } }), code('PLANNING_INVALID'));
  const auth = f.auth();
  await f.admin.control.query("UPDATE security.grants SET expires_at=created_at+interval '1 minute' WHERE workspace_id=$1 AND device_id=$2 AND scope_kind='project' AND scope_id=$3", [f.workspaceId, f.deviceId, f.projectId]);
  f.advancePlanning(120000);
  await assert.rejects(f.planning.context(auth.cookieValue, auth.csrfToken, f.reference()), code('PLANNING_FORBIDDEN'));
  await assert.rejects(f.save(denied), code('PLANNING_FORBIDDEN'));
});

test('CP07: revocation rotates content epochs, clears current designations and retains the signed planning history', async (t) => {
  const f = await planningFixture(t), member = await f.joined(), role = (await f.admin.control.query("SELECT role_id FROM security.roles WHERE workspace_id=$1 AND template='manager'", [f.workspaceId])).rows[0].role_id as string;
  await f.finalize(await f.draft('set_access', member.binding.accountId, { roleId: role, projectIds: [f.projectId] }));
  const phaseId = randomUUID();
  await f.execute({ action: 'edit_project', patch: { managerProfileId: member.binding.accountId } });
  await f.execute({ action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: member.binding.accountId } }, { content: { name: 'Private wave', objective: '', completionCriteria: '' } });
  const stale = await f.preparePlanning({ action: 'start_project' });
  await f.finalize(await f.draft('suspend', member.binding.accountId));
  await assert.rejects(f.save(stale), code('PLANNING_CHANGED'));
  const current = await f.context(); assert.notEqual(current.binding.keyEpoch, stale.mutation.body.binding.keyEpoch);
  assert.equal(current.graph.project.managerProfileId, null); assert.equal(current.graph.phases[0]!.leadProfileId, null);
  assert.equal(current.history.length, 2); assert.equal((await f.read()).records.find((r) => r.id === phaseId)!.content.name, 'Private wave');
  // A stale permission/epoch claim re-signed by a legitimate device remains invalid.
  const fresh = await f.preparePlanning({ action: 'start_project' });
  const forged = structuredClone(fresh); forged.mutation.body.binding.permissionVersion = '999';
  forged.mutation = await signObject(forged.mutation.body, base64urlDecode(f.originalBundle.signingPrivateKey));
  await assert.rejects(f.save(forged), code('PLANNING_CHANGED'));
  assert.equal((await f.save(fresh)).state, 'completed');
});


test('CP07: real shared task preparation, carry-forward and cancellation preserve identity/assignments and commit the complete cascade atomically', async (t) => {
  const f = await planningFixture(t), member = await f.joined(), role = (await f.admin.control.query("SELECT role_id FROM security.roles WHERE workspace_id=$1 AND template='member'", [f.workspaceId])).rows[0].role_id as string;
  await f.finalize(await f.draft('set_access', member.binding.accountId, { roleId: role, projectIds: [f.projectId] }));
  const first = randomUUID(), second = randomUUID(), milestone = randomUUID(), sharedTask = randomUUID(), unscheduled = randomUUID();
  for (const [id, order] of [[first, 0], [second, 1]] as const) await f.execute({ action: 'create_phase', phase: { id, displayOrder: order, leadProfileId: null } }, { content: { name: `Wave ${order}`, objective: '', completionCriteria: '' } });
  await f.execute({ action: 'create_milestone', milestone: { id: milestone, phaseId: null, ownerProfileId: null } }, { content: { name: 'Manual checkpoint' } });
  await f.execute({ action: 'start_project' });
  await f.execute({ action: 'start_phase', phaseId: first }); await f.execute({ action: 'start_phase', phaseId: second });
  await f.execute({ action: 'accept_milestone', milestoneId: milestone }, { outcome: 'Original acceptance before scope expansion' });
  const accepted = (await f.context()).graph.snapshots;
  await f.execute({ action: 'create_task', task: { id: sharedTask, phaseId: first, milestoneId: milestone, assigneeIds: [f.accountId, member.binding.accountId], leadProfileId: member.binding.accountId } },
    { content: { title: 'Private collaborative task', description: '', acceptanceCriteria: '', dueDate: '2026-10-10' } });
  let current = await f.context(); assert.equal(current.graph.tasks[0]!.state, 'todo'); assert.equal(current.graph.milestones[0]!.state, 'open'); assert.deepEqual(current.graph.snapshots, accepted);
  const assignments = (await f.admin.application.query('SELECT * FROM app.task_assignments WHERE workspace_id=$1 AND task_id=$2 ORDER BY member_id', [f.workspaceId, sharedTask])).rows;
  assert.equal(assignments.length, 2);
  await f.execute({ action: 'carry_task', taskId: sharedTask, phaseId: second, milestoneId: milestone }, { outcome: 'Explicitly moved to the next wave' });
  assert.deepEqual((await f.admin.application.query('SELECT * FROM app.task_assignments WHERE workspace_id=$1 AND task_id=$2 ORDER BY member_id', [f.workspaceId, sharedTask])).rows, assignments);
  current = await f.context(); assert.equal(current.graph.tasks[0]!.id, sharedTask); assert.equal(current.graph.tasks[0]!.phaseId, second); assert.equal(current.graph.tasks[0]!.leadProfileId, member.binding.accountId);
  assert.equal(current.graph.movements[0]!.fromPhaseId, first); assert.equal(current.graph.movements[0]!.toPhaseId, second);
  await f.execute({ action: 'complete_phase', phaseId: first }, { outcome: 'Task carried forward rather than counted delivered' });
  const closing = (await f.context()).graph.snapshots.at(-1)!; assert.equal(closing.carriedWork[0]!.taskId, sharedTask); assert.equal(closing.tasks.length, 0);
  await assert.rejects(f.execute({ action: 'cancel_phase', phaseId: second, tasks: [], milestones: [] }, { outcome: 'Incomplete cancellation' }), /resolution_required/);
  const cancel = await f.preparePlanning({ action: 'cancel_phase', phaseId: second, tasks: [{ taskId: sharedTask, action: 'cancel' }], milestones: [] }, { outcome: 'Explicitly cancel unfinished work' });
  const counts = async () => (await f.admin.application.query(`SELECT (SELECT count(*) FROM app.record_versions WHERE workspace_id=$1)::int AS versions,
    (SELECT count(*) FROM app.planning_operations WHERE workspace_id=$1)::int AS operations, (SELECT count(*) FROM app.updates WHERE workspace_id=$1)::int AS updates`, [f.workspaceId])).rows[0];
  const before = await counts(); f.setPlanningHooks({ beforeCommit: async () => { throw new Error('injected multi-row cancellation failure'); } });
  await assert.rejects(f.save(cancel), code('PLANNING_UNAVAILABLE')); assert.deepEqual(await counts(), before);
  current = await f.context(); assert.equal(current.graph.tasks[0]!.state, 'todo'); assert.equal(current.graph.phases.find((p) => p.id === second)!.state, 'active');
  f.setPlanningHooks(); await f.save(cancel);
  await f.execute({ action: 'cancel_milestone', milestoneId: milestone }, { outcome: 'Close the abandoned checkpoint' });
  await f.execute({ action: 'create_task', task: { id: unscheduled, phaseId: null, milestoneId: null, assigneeIds: [], leadProfileId: null } }, { content: { title: 'Private unscheduled work', description: '', acceptanceCriteria: '' } });
  await assert.rejects(f.execute({ action: 'complete_project' }, { outcome: 'Cannot omit unscheduled work' }), /unfinished_tasks/);
  await f.execute({ action: 'cancel_project' }, { outcome: 'Cancel remaining unscheduled work' });
  current = await f.context(); assert.equal(current.graph.tasks.find((task) => task.id === unscheduled)!.state, 'cancelled');
  assert.equal(current.graph.phases.find((p) => p.id === first)!.state, 'complete');
  assert.deepEqual(current.graph.snapshots.find((snapshot) => snapshot.operationId === closing.operationId), closing);
  assert.equal((await f.admin.application.query("SELECT count(*)::int AS n FROM app.record_versions WHERE workspace_id=$1 AND record_type='task' AND record_id=$2", [f.workspaceId, sharedTask])).rows[0].n, 3);
  assert.deepEqual((await f.admin.application.query('SELECT * FROM app.task_assignments WHERE workspace_id=$1 AND task_id=$2 ORDER BY member_id', [f.workspaceId, sharedTask])).rows, assignments);
});

test('CP07: ordinary Members can prepare only their own assigned Todo task, with no implicit management authority', async (t) => {
  const f = await planningFixture(t), member = await f.joined(), role = (await f.admin.control.query("SELECT role_id FROM security.roles WHERE workspace_id=$1 AND template='member'", [f.workspaceId])).rows[0].role_id as string;
  await f.finalize(await f.draft('set_access', member.binding.accountId, { roleId: role, projectIds: [f.projectId] }));
  const logged = await f.login(member.prepared, member.registered.exportKey), id = randomUUID(), content = { title: 'Private member work', description: '', acceptanceCriteria: '' };
  const intent = { action: 'create_task' as const, task: { id, phaseId: null, milestoneId: null, assigneeIds: [member.binding.accountId], leadProfileId: member.binding.accountId } };
  const payload = await f.preparePlanning(intent, { content }, logged.auth, logged.bundle);
  assert.equal((await f.save(payload, logged.auth)).state, 'completed');
  await assert.rejects(f.preparePlanning({ ...intent, task: { ...intent.task, id: randomUUID(), assigneeIds: [] } }, { content }, logged.auth, logged.bundle), /permission_denied/);
  await assert.rejects(f.preparePlanning({ ...intent, task: { ...intent.task, id: randomUUID(), assigneeIds: [member.binding.accountId, f.accountId] } }, { content }, logged.auth, logged.bundle), /permission_denied/);
  assert.equal((await f.context()).graph.tasks.length, 1);
});

test('CP07: phase and milestone identities cannot overwrite records belonging to another authorized project', async (t) => {
  const f = await planningFixture(t), phaseId = randomUUID(), milestoneId = randomUUID();
  await f.execute({ action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: null } }, { content: { name: 'Original wave', objective: '', completionCriteria: '' } });
  await f.execute({ action: 'create_milestone', milestone: { id: milestoneId, phaseId: null, ownerProfileId: null } }, { content: { name: 'Original milestone' } });
  const beforePhase = (await f.admin.application.query('SELECT * FROM app.project_phases WHERE workspace_id=$1 AND id=$2', [f.workspaceId, phaseId])).rows[0];
  const beforeMilestone = (await f.admin.application.query('SELECT * FROM app.milestones WHERE workspace_id=$1 AND id=$2', [f.workspaceId, milestoneId])).rows[0];
  const other = await f.createProject('Other authorized project');
  await assert.rejects(f.execute({ action: 'create_phase', phase: { id: phaseId, displayOrder: 4, leadProfileId: null } }, { projectId: other, content: { name: 'Overwrite attempt', objective: '', completionCriteria: '' } }), code('PLANNING_INVALID'));
  await assert.rejects(f.execute({ action: 'create_milestone', milestone: { id: milestoneId, phaseId: null, ownerProfileId: null } }, { projectId: other, content: { name: 'Overwrite attempt' } }), code('PLANNING_INVALID'));
  assert.deepEqual((await f.admin.application.query('SELECT * FROM app.project_phases WHERE workspace_id=$1 AND id=$2', [f.workspaceId, phaseId])).rows[0], beforePhase);
  assert.deepEqual((await f.admin.application.query('SELECT * FROM app.milestones WHERE workspace_id=$1 AND id=$2', [f.workspaceId, milestoneId])).rows[0], beforeMilestone);
  const current = await f.context(other); assert.equal(current.graph.phases.length, 0); assert.equal(current.graph.milestones.length, 0); assert.equal(current.history.length, 0);
});

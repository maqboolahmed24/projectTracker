import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { AppError } from '../src/errors.js';
import { base64urlDecode, canonicalJson, digestObject, signObject } from '../src/shared/crypto.js';
import type { PlanningIntent } from '../src/client/planning-crypto.js';
import { planningFixture } from './planning-fixture.js';

type Fixture = Awaited<ReturnType<typeof planningFixture>>;
const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;
const content = (title = 'Private shared task') => ({ title, description: 'One retained task', acceptanceCriteria: 'Verified result' });
async function createTask(f: Fixture, assigneeIds = [f.accountId], extra: { phaseId?: string; milestoneId?: string } = {}) {
  const id = randomUUID();
  await f.execute({ action: 'create_task', task: { id, assigneeIds, leadProfileId: assigneeIds[0] ?? null,
    phaseId: extra.phaseId ?? null, milestoneId: extra.milestoneId ?? null } }, { content: content() });
  return id;
}
async function task(f: Fixture, id: string) { return (await f.context()).graph.tasks.find((row) => row.id === id)!; }
async function envelope(f: Fixture, id: string) { return (await f.context()).records.find((row) => row.kind === 'task' && row.id === id)!.envelope; }
async function memberWithRole(f: Fixture, template: 'member' | 'manager' | 'viewer') {
  const joined = await f.joined(), role = (await f.admin.control.query('SELECT role_id FROM security.roles WHERE workspace_id=$1 AND template=$2', [f.workspaceId, template])).rows[0].role_id as string;
  await f.finalize(await f.draft('set_access', joined.binding.accountId, { roleId: role, projectIds: [f.projectId] }));
  return { ...joined, ...await f.login(joined.prepared, joined.registered.exportKey) };
}
async function executeAs(f: Fixture, command: PlanningIntent, actor: Awaited<ReturnType<Fixture['joined']>>, options: Parameters<Fixture['preparePlanning']>[1] = {}) {
  return f.save(await f.preparePlanning(command, options, actor.auth, actor.bundle), actor.auth);
}
/** Valid actor signature, deliberately bypassing only the client's workflow guard. */
async function rejectAtService(f: Fixture, intent: PlanningIntent, expected: string, actor?: Awaited<ReturnType<Fixture['joined']>>) {
  const closure = ['accept_milestone','complete_phase','complete_project'].includes(intent.action);
  // A cancellable project supplies a correctly encrypted, signed outcome using this
  // same current binding. The rejected closure changes only the requested action.
  if (closure) assert.equal(actor,undefined);
  const payload = closure ? await f.preparePlanning({ action:'cancel_project' },{ outcome:'Premature closure must fail atomically' }) :
    await f.preparePlanning({ action: 'edit_project', patch: {} });
  const current = closure ? {binding:payload.mutation.body.binding} : await f.context(undefined, actor?.auth ?? f.auth());
  const outcome = 'outcome' in payload.mutation.body.command ? payload.mutation.body.command.outcome : undefined;
  payload.mutation.body.binding = current.binding;
  payload.mutation.body.command = { ...intent, operationId: current.binding.operationId, expected: current.binding.before,
    ...(closure ? {outcome} : {}) } as typeof payload.mutation.body.command;
  payload.mutation.body.nextVersion = String(BigInt(current.binding.beforeVersion) + 1n);
  payload.mutation = await signObject(payload.mutation.body, base64urlDecode((actor?.bundle ?? f.originalBundle).signingPrivateKey));
  await assert.rejects(f.save(payload, actor?.auth ?? f.auth()), code(expected));
}

test('CP08 service: shared assignment edits preserve attribution, execution is explicit, and task reopen restores milestone acceptance atomically', async (t) => {
  const f = await planningFixture(t), member = await memberWithRole(f, 'member'), milestoneId = randomUUID();
  await f.execute({ action: 'create_milestone', milestone: { id: milestoneId, phaseId: null, ownerProfileId: null } }, { content: { name: 'Delivery acceptance' } });
  const id = await createTask(f, [f.accountId, member.binding.accountId], { milestoneId });
  assert.equal((await f.context()).graph.project.reviewEnabled, false);
  await rejectAtService(f, { action: 'start_task', taskId: id }, 'PLANNING_PARENT_NOT_ACTIVE');
  const originalAssignment = (await f.admin.application.query('SELECT * FROM app.task_assignments WHERE workspace_id=$1 AND task_id=$2 AND member_id=$3', [f.workspaceId,id,member.binding.accountId])).rows[0];
  await f.execute({ action: 'assign_task', taskId: id, assigneeIds: [member.binding.accountId], leadProfileId: member.binding.accountId, teamId: null });
  assert.deepEqual((await f.admin.application.query('SELECT * FROM app.task_assignments WHERE workspace_id=$1 AND task_id=$2 AND member_id=$3', [f.workspaceId,id,member.binding.accountId])).rows[0], originalAssignment);
  assert.equal((await task(f,id)).leadProfileId, member.binding.accountId);
  await f.execute({ action: 'start_project' });
  const prior = await envelope(f,id);
  await executeAs(f, { action: 'start_task', taskId: id }, member);
  await executeAs(f, { action: 'set_task_todo', taskId: id }, member);
  await executeAs(f, { action: 'request_task_completion', taskId: id, acceptanceConfirmed: true }, member);
  assert.equal((await task(f,id)).state, 'done'); assert.deepEqual(await envelope(f,id), prior);
  await f.execute({ action: 'accept_milestone', milestoneId }, { outcome: 'Completed shared work accepted' });
  const snapshots = (await f.context()).graph.snapshots;
  await f.execute({ action: 'reopen_task', taskId: id }, { outcome: 'New unfinished work required' });
  const reopened = await f.context(); assert.equal(reopened.graph.tasks[0]!.state, 'in_progress');
  assert.equal(reopened.graph.milestones[0]!.state, 'open'); assert.deepEqual(reopened.graph.snapshots, snapshots);
  assert.equal(reopened.graph.tasks[0]!.approvalOperationId, null); assert.deepEqual(await envelope(f,id), prior);
  await f.execute({ action: 'cancel_task', taskId: id }, { outcome: 'Explicitly abandoned remaining work' });
  await f.execute({ action: 'restore_task', taskId: id }, { outcome: 'Deliberately restored to the plan' });
  assert.equal((await task(f,id)).state, 'todo');
});

test('CP08 service: named non-assignee approval preserves submitted ciphertext, rejects stale/substituted proofs, and resumes a lost receipt once', async (t) => {
  const f = await planningFixture(t), assignee = await f.joined('join_owner'), phaseId=randomUUID(),milestoneId=randomUUID();
  await f.execute({action:'create_phase',phase:{id:phaseId,displayOrder:0,leadProfileId:null}},{content:{name:'Reviewed delivery wave'}});
  await f.execute({action:'create_milestone',milestone:{id:milestoneId,phaseId,ownerProfileId:null}},{content:{name:'Reviewed acceptance'}});
  const id = await createTask(f, [assignee.binding.accountId],{phaseId,milestoneId});
  await f.execute({ action: 'start_project' });
  await f.execute({ action:'start_phase',phaseId });
  await f.execute({ action: 'set_project_review', enabled: true, reviewers: [{ taskId: id, reviewerProfileId: f.accountId }] }, { outcome: 'Require one independent reviewer' });
  const submittedContent = await envelope(f,id);
  await executeAs(f, { action: 'request_task_completion', taskId: id, acceptanceConfirmed: true }, assignee);
  let row = await task(f,id); assert.equal(row.state, 'review'); assert.equal(row.submittedRevision, row.contentRevision);
  assert.deepEqual(await envelope(f,id), submittedContent);
  const beforeClosure=await f.context();
  for(const intent of [{action:'accept_milestone',milestoneId},{action:'complete_phase',phaseId},{action:'complete_project'}] as const) {
    await rejectAtService(f,intent,'PLANNING_UNFINISHED_TASKS');
    const unchanged=await f.context();
    assert.deepEqual(unchanged.graph,beforeClosure.graph); assert.deepEqual(unchanged.history,beforeClosure.history);
    assert.equal(unchanged.binding.beforeHead,beforeClosure.binding.beforeHead); assert.equal(unchanged.binding.beforeVersion,beforeClosure.binding.beforeVersion);
  }
  const approve = { action: 'approve_task' as const, taskId: id, submittedRevision: row.submittedRevision!, submittedPolicyRevision: row.submittedPolicyRevision! };
  await rejectAtService(f, approve, 'PLANNING_PERMISSION_DENIED', assignee);
  const stale = await f.preparePlanning(approve);
  const replacement = await f.preparePlanning({ action: 'edit_task', taskId: id }, { content: content('Substituted unsubmitted content') });
  const substituted = structuredClone(stale), changedRecord = substituted.records.find((record) => record.kind === 'task' && record.id === id)!;
  changedRecord.envelope = replacement.records.find((record) => record.kind === 'task' && record.id === id)!.envelope;
  substituted.mutation.body.records.find((record) => record.kind === 'task' && record.id === id)!.digest = await digestObject(changedRecord.envelope);
  substituted.mutation = await signObject(substituted.mutation.body, base64urlDecode(f.originalBundle.signingPrivateKey));
  await assert.rejects(f.save(substituted), code('PLANNING_INVALID'));
  assert.equal((await task(f,id)).state, 'review'); assert.deepEqual(await envelope(f,id), submittedContent);
  await executeAs(f, { action: 'edit_task', taskId: id }, assignee, { content: content('Revised acceptance submission') });
  row = await task(f,id); assert.equal(row.state, 'in_progress'); assert.equal(row.submittedRevision, null);
  await assert.rejects(f.save(stale), code('PLANNING_CHANGED'));
  await executeAs(f, { action: 'request_task_completion', taskId: id, acceptanceConfirmed: true }, assignee);
  row = await task(f,id); const beforeApproval = await envelope(f,id);
  const fresh = await f.preparePlanning({ action: 'approve_task', taskId: id, submittedRevision: row.submittedRevision!, submittedPolicyRevision: row.submittedPolicyRevision! });
  f.setPlanningHooks({ afterCommit: async () => { throw new Error('lost approval response'); } });
  await assert.rejects(f.save(fresh), /lost approval response/); f.setPlanningHooks();
  const receipt = await f.planningStatus(fresh); assert.equal(receipt.state, 'completed'); assert.deepEqual(await f.save(fresh), receipt);
  row = await task(f,id); assert.equal(row.state, 'done'); assert.equal(row.approvalOperationId, fresh.mutation.body.binding.operationId);
  assert.deepEqual(await envelope(f,id), beforeApproval);
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.planning_operations WHERE workspace_id=$1 AND operation_id=$2', [f.workspaceId,fresh.mutation.body.binding.operationId])).rows[0].n, 1);
  assert.equal((await f.context()).graph.milestones[0]!.state,'open');
  await rejectAtService(f,{action:'complete_phase',phaseId},'PLANNING_UNACCEPTED_MILESTONES');
  await f.execute({action:'accept_milestone',milestoneId},{outcome:'Independent review accepted manually'});
  await f.execute({action:'complete_phase',phaseId},{outcome:'Reviewed wave closed explicitly'});
  await f.execute({action:'complete_project'},{outcome:'Reviewed project closed explicitly'});
  assert.equal((await f.read()).graph.project.state,'complete');
});

test('CP08 service: disabling review rolls back or commits its entire pending-review cascade and never completes work implicitly', async (t) => {
  const f = await planningFixture(t), assignee = await f.joined('join_owner'), ids = [await createTask(f,[assignee.binding.accountId]), await createTask(f,[assignee.binding.accountId])];
  await f.execute({ action: 'start_project' });
  await f.execute({ action: 'set_project_review', enabled: true, reviewers: ids.map((taskId) => ({ taskId, reviewerProfileId: f.accountId })) }, { outcome: 'Independent review required' });
  for (const taskId of ids) await executeAs(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true }, assignee);
  const before = await f.context(), payload = await f.preparePlanning({ action: 'set_project_review', enabled: false, reviewers: [] }, { outcome: 'Owner explicitly disables review' });
  f.setPlanningHooks({ beforeCommit: async () => { throw new Error('injected policy cascade failure'); } });
  await assert.rejects(f.save(payload), code('PLANNING_UNAVAILABLE')); f.setPlanningHooks();
  const rolledBack = await f.context(); assert.deepEqual(rolledBack.graph,before.graph); assert.deepEqual(rolledBack.history,before.history);
  assert.equal((await f.planningStatus(payload)).state,'absent'); await f.save(payload);
  const after = await f.context(); assert.equal(after.graph.project.reviewEnabled,false);
  assert.ok(after.graph.tasks.every((row) => row.state === 'in_progress' && row.submittedRevision === null && row.approvalOperationId === null));
  for (const id of ids) assert.deepEqual(after.records.find((record) => record.id === id)!.envelope,before.records.find((record) => record.id === id)!.envelope);
  await executeAs(f, { action: 'request_task_completion', taskId: ids[0]!, acceptanceConfirmed: true }, assignee);
  assert.equal((await task(f,ids[0]!)).state,'done'); assert.equal((await task(f,ids[1]!)).state,'in_progress');
});

test('CP08 service: reviewer permission loss clears authority immediately and an explicit other Owner can replace the missing reviewer', async (t) => {
  const f = await planningFixture(t), reviewer = await memberWithRole(f,'manager'), fallback = await f.joined('join_owner'), id = await createTask(f);
  await f.execute({ action: 'start_project' });
  await f.execute({ action: 'set_project_review', enabled: true, reviewers: [{ taskId: id, reviewerProfileId: reviewer.binding.accountId }] }, { outcome: 'Named project reviewer' });
  await f.execute({ action: 'request_task_completion', taskId: id, acceptanceConfirmed: true });
  const submitted = await task(f,id), oldProof = await f.preparePlanning({ action: 'approve_task', taskId: id, submittedRevision: submitted.submittedRevision!, submittedPolicyRevision: submitted.submittedPolicyRevision! }, {}, reviewer.auth, reviewer.bundle);
  const memberRole = f.prepared.payload.genesis.body.roles.member;
  await f.finalize(await f.draft('set_access', reviewer.binding.accountId, { roleId: memberRole, projectIds: [f.projectId] }));
  const current = await task(f,id); assert.equal(current.state,'review'); assert.equal(current.reviewerProfileId,null);
  assert.equal(current.submittedRevision,submitted.submittedRevision);
  const relogged = { ...reviewer, ...await f.login(reviewer.prepared,reviewer.registered.exportKey) };
  await assert.rejects(f.save(oldProof,relogged.auth),code('PLANNING_CHANGED'));
  await f.execute({ action: 'select_task_reviewer', taskId: id, reviewerProfileId: fallback.binding.accountId });
  const replacement = await task(f,id);
  await executeAs(f, { action: 'approve_task', taskId: id, submittedRevision: replacement.submittedRevision!, submittedPolicyRevision: replacement.submittedPolicyRevision! }, fallback);
  assert.equal((await task(f,id)).state,'done');
});

test('CP08 service: blockers retain actor/time/content, gate completion independently, and survive task cancellation/restoration without silent resolution', async (t) => {
  const f = await planningFixture(t), member = await memberWithRole(f,'member'), id = await createTask(f,[member.binding.accountId]), first = randomUUID(), second = randomUUID();
  for (const blockerId of [first,second]) await executeAs(f, { action: 'create_blocker', blocker: { id: blockerId, taskId: id, responsibleProfileId: member.binding.accountId } }, member,
    { content: { reason: 'Private prerequisite unresolved', nextAction: 'Obtain the required input' } });
  const created = await f.context(); assert.equal(created.graph.blockers!.length,2);
  assert.ok(created.graph.blockers!.every((blocker) => blocker.createdBy === member.binding.accountId && blocker.resolvedAt === null));
  const firstContent = created.records.find((record) => record.id === first)!.envelope;
  await f.execute({ action: 'start_project' }); await executeAs(f,{ action:'start_task',taskId:id },member);
  await rejectAtService(f,{ action:'request_task_completion',taskId:id,acceptanceConfirmed:true },'PLANNING_BLOCKED_TASK',member);
  await executeAs(f,{ action:'resolve_blocker',blockerId:first },member,{ outcome:'Input received and checked' });
  const resolved = (await f.context()).graph.blockers!.find((blocker) => blocker.id === first)!;
  assert.equal(resolved.state,'resolved'); assert.equal(resolved.resolvedBy,member.binding.accountId); assert.ok(resolved.resolvedAt);
  assert.deepEqual((await f.context()).records.find((record) => record.id === first)!.envelope,firstContent);
  await rejectAtService(f,{ action:'request_task_completion',taskId:id,acceptanceConfirmed:true },'PLANNING_BLOCKED_TASK',member);
  await f.execute({ action:'cancel_task',taskId:id },{ outcome:'Pause this abandoned scope explicitly' });
  assert.equal((await f.context()).graph.blockers!.find((blocker) => blocker.id === second)!.state,'open');
  await f.execute({ action:'restore_task',taskId:id },{ outcome:'Bring the same work back' });
  await rejectAtService(f,{ action:'request_task_completion',taskId:id,acceptanceConfirmed:true },'PLANNING_BLOCKED_TASK',member);
  await executeAs(f,{ action:'resolve_blocker',blockerId:second },member,{ outcome:'Second prerequisite obtained' });
  await executeAs(f,{ action:'request_task_completion',taskId:id,acceptanceConfirmed:true },member); assert.equal((await task(f,id)).state,'done');
  await assert.rejects(executeAs(f,{ action:'reopen_blocker',blockerId:first },member,{ outcome:'Input no longer valid' }),/scope_read_only|invalid_transition/);
  await f.execute({ action:'reopen_task',taskId:id },{ outcome:'Recheck changed prerequisites' });
  await executeAs(f,{ action:'reopen_blocker',blockerId:first },member,{ outcome:'Input no longer valid' });
  const reopened = (await f.context()).graph.blockers!.find((blocker) => blocker.id === first)!;
  assert.equal(reopened.state,'open'); assert.equal(reopened.resolvedAt,null); assert.equal(reopened.createdAt,resolved.createdAt);
  const secondResolved = (await f.context()).graph.blockers!.find((blocker) => blocker.id === second)!;
  await f.finalize(await f.draft('suspend',member.binding.accountId));
  const removed = (await f.context()).graph.blockers!.find((blocker) => blocker.id === first)!;
  assert.equal(removed.state,'open'); assert.equal(removed.responsibleProfileId,null); assert.equal(removed.createdBy,member.binding.accountId);
  const resolvedRemoved = (await f.context()).graph.blockers!.find((blocker) => blocker.id === second)!;
  assert.deepEqual(resolvedRemoved,{ ...secondResolved,responsibleProfileId:null });
  assert.equal(canonicalJson((await f.context()).records).includes('Private prerequisite unresolved'),false);
});

test('CP08 service: valid signatures from read-only and comment-only actors cannot alter assignments or blockers', async (t) => {
  const f = await planningFixture(t), viewer = await memberWithRole(f,'viewer'), member = await memberWithRole(f,'member'), id = await createTask(f);
  // The ordinary unassigned Member has comment permission but no authority to edit this task.
  for (const actor of [viewer,member]) {
    await rejectAtService(f,{ action:'assign_task',taskId:id,assigneeIds:[actor.binding.accountId],leadProfileId:null,teamId:null },'PLANNING_PERMISSION_DENIED',actor);
    await rejectAtService(f,{ action:'create_blocker',blocker:{ id:randomUUID(),taskId:id,responsibleProfileId:actor.binding.accountId } },'PLANNING_PERMISSION_DENIED',actor);
  }
  assert.deepEqual((await task(f,id)).assigneeIds,[f.accountId]); assert.equal((await f.context()).graph.blockers!.length,0);
});

test('CP08 service: reopening Done and restoring Cancelled work clears an unavailable reviewer while preserving the historical approval', async (t) => {
  const f = await planningFixture(t), reviewer = await memberWithRole(f,'manager');
  const doneId = await createTask(f), cancelledId = await createTask(f);
  await f.execute({ action:'start_project' });
  await f.execute({ action:'set_project_review',enabled:true,reviewers:[doneId,cancelledId].map((taskId) => ({ taskId,reviewerProfileId:reviewer.binding.accountId })) },
    { outcome:'Require the named independent reviewer' });
  await f.execute({ action:'request_task_completion',taskId:doneId,acceptanceConfirmed:true });
  const submitted = await task(f,doneId);
  const approval = await executeAs(f,{ action:'approve_task',taskId:doneId,submittedRevision:submitted.submittedRevision!,submittedPolicyRevision:submitted.submittedPolicyRevision! },reviewer);
  await f.execute({ action:'cancel_task',taskId:cancelledId },{ outcome:'Cancel this planned work explicitly' });
  const closed = await f.context();
  assert.ok(closed.graph.tasks.every((row) => row.reviewerProfileId === reviewer.binding.accountId));
  await f.finalize(await f.draft('set_access',reviewer.binding.accountId,
    { roleId:f.prepared.payload.genesis.body.roles.member,projectIds:[f.projectId] }));
  const unavailable = await f.context();
  assert.deepEqual(unavailable.graph.tasks,closed.graph.tasks);
  await f.execute({ action:'reopen_task',taskId:doneId },{ outcome:'Recheck the completed work with a new reviewer' });
  await f.execute({ action:'restore_task',taskId:cancelledId },{ outcome:'Restore the cancelled work to the plan' });
  const restored = await f.context(), readable = await f.read();
  for (const id of [doneId,cancelledId]) {
    const row = restored.graph.tasks.find((entry) => entry.id === id)!;
    assert.equal(row.state,id === doneId ? 'in_progress' : 'todo');
    assert.equal(row.reviewerProfileId,null); assert.equal(row.submittedRevision,null); assert.equal(row.approvalOperationId,null);
    assert.deepEqual(restored.records.find((record) => record.id === id)!.envelope,closed.records.find((record) => record.id === id)!.envelope);
    assert.equal(readable.records.find((record) => record.id === id)!.content.title,'Private shared task');
  }
  assert.deepEqual(restored.history.slice(0,closed.history.length),closed.history);
  assert.deepEqual(restored.history.find((mutation) => mutation.body.binding.operationId === approval.receipt!.operationId),approval.receipt!.mutation);
  assert.equal(approval.receipt!.mutation.body.binding.accountId,reviewer.binding.accountId);
  await assert.rejects(f.execute({ action:'request_task_completion',taskId:doneId,acceptanceConfirmed:true }),/reviewer_required/);
});

test('CP08 service: reopening a closed phase and restoring cancelled work clears unavailable current leads and milestone owners without rewriting snapshots', async (t) => {
  const f = await planningFixture(t), member = await memberWithRole(f,'member'), phaseId = randomUUID(), milestoneId = randomUUID();
  await f.execute({ action:'create_phase',phase:{ id:phaseId,displayOrder:0,leadProfileId:member.binding.accountId } },{ content:{ name:'Private completed wave' } });
  await f.execute({ action:'create_milestone',milestone:{ id:milestoneId,phaseId,ownerProfileId:member.binding.accountId } },{ content:{ name:'Private accepted outcome' } });
  const id = await createTask(f,[f.accountId],{ phaseId,milestoneId });
  await f.execute({ action:'cancel_task',taskId:id },{ outcome:'Explicitly defer unfinished scope' });
  await f.execute({ action:'start_project' }); await f.execute({ action:'start_phase',phaseId });
  await f.execute({ action:'accept_milestone',milestoneId },{ outcome:'Accept the remaining wave scope' });
  await f.execute({ action:'complete_phase',phaseId },{ outcome:'Record the initial wave result' });
  const closed = await f.read();
  await f.finalize(await f.draft('suspend',member.binding.accountId));
  const removed = await f.context();
  assert.equal(removed.graph.phases[0]!.leadProfileId,member.binding.accountId);
  assert.equal(removed.graph.milestones[0]!.ownerProfileId,member.binding.accountId);
  await f.execute({ action:'reopen_phase',phaseId });
  const opened = await f.context(); assert.equal(opened.graph.phases[0]!.leadProfileId,null);
  await f.execute({ action:'restore_task',taskId:id },{ outcome:'Bring the cancelled work into the reopened wave' });
  const restored = await f.read();
  assert.equal(restored.graph.tasks[0]!.state,'todo'); assert.equal(restored.graph.milestones[0]!.state,'open');
  assert.equal(restored.graph.milestones[0]!.ownerProfileId,null);
  assert.deepEqual(restored.graph.snapshots,closed.graph.snapshots);
  assert.equal(restored.records.find((record) => record.id === id)!.content.title,'Private shared task');
});

test('CP08 service: removing an assignee invalidates pending review even when its named reviewer retains approval authority', async (t) => {
  const f = await planningFixture(t), member = await memberWithRole(f,'member'), id = await createTask(f,[member.binding.accountId]);
  await f.execute({ action:'start_project' });
  await f.execute({ action:'set_project_review',enabled:true,reviewers:[{ taskId:id,reviewerProfileId:f.accountId }] },{ outcome:'Require an independent Owner review' });
  await executeAs(f,{ action:'request_task_completion',taskId:id,acceptanceConfirmed:true },member);
  const submitted = await task(f,id), beforeContent = await envelope(f,id);
  const approve = { action:'approve_task' as const,taskId:id,submittedRevision:submitted.submittedRevision!,submittedPolicyRevision:submitted.submittedPolicyRevision! };
  const oldProof = await f.preparePlanning(approve);
  await f.finalize(await f.draft('suspend',member.binding.accountId));
  const current = await task(f,id);
  assert.equal(current.state,'in_progress'); assert.deepEqual(current.assigneeIds,[]); assert.equal(current.leadProfileId,null);
  assert.equal(current.reviewerProfileId,f.accountId); assert.equal(current.submittedRevision,null);
  assert.equal(current.submittedPolicyRevision,null); assert.equal(current.approvalOperationId,null);
  assert.deepEqual(await envelope(f,id),beforeContent);
  await assert.rejects(f.save(oldProof),code('PLANNING_CHANGED'));
  await rejectAtService(f,approve,'PLANNING_REVIEWER_REQUIRED');
  const readable = await f.read();
  assert.equal(readable.graph.tasks[0]!.state,'in_progress');
  assert.equal(readable.records.find((record) => record.id === id)!.content.title,'Private shared task');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { canonicalJson, digestObject } from '../src/shared/crypto.js';
import { preparePlanning, readPlanning, type PlanningIntent, type PlanningPrivateContent } from '../src/client/planning-crypto.js';
import { IndexedPlanningStore } from '../src/client/planning-store.js';
import { PlanningController, type PlanningTransport } from '../src/client/planning-controller.js';
import { IndexedPairingStore } from '../src/client/pairing.js';
import { refreshAccessKeys } from '../src/client/access-change-crypto.js';
import type { AuthController } from '../src/client/auth-controller.js';
import { planningClientFixture } from './planning-client-fixture.js';
import { origin } from './project-create-client-fixture.js';
import { WriteConflict, WriteError } from '../src/client/write-state.js';

async function execute(f: Awaited<ReturnType<typeof planningClientFixture>>, command: PlanningIntent, content?: PlanningPrivateContent, outcome?: string) {
  const payload = await preparePlanning({ ...await f.input(), command, ...(content ? { content } : {}), ...(outcome === undefined ? {} : { outcome }) }, f.f.owner.bundle);
  await f.apply(payload); return payload;
}

test('CP07 planning client: overlapping waves, manual milestone acceptance and closure preserve readable encrypted historical outcomes after reopen', async () => {
  const f = await planningClientFixture(), phaseA = randomUUID(), phaseB = randomUUID(), milestone = randomUUID();
  await execute(f, { action: 'start_project' });
  const created = await execute(f, { action: 'create_phase', phase: { id: phaseA, displayOrder: 0, leadProfileId: null } },
    { name: 'Private discovery', objective: 'Understand needs', completionCriteria: 'A reviewed brief', startDate: '2026-09-01', dueDate: '2026-09-20' });
  assert.equal(canonicalJson(created).includes('Private discovery'), false); assert.equal(canonicalJson(created).includes('Understand needs'), false);
  await execute(f, { action: 'create_phase', phase: { id: phaseB, displayOrder: 1, leadProfileId: null } },
    { name: 'Private delivery', objective: 'Test rollout', completionCriteria: 'Working service', startDate: '2026-09-10', dueDate: '2026-09-30' });
  await execute(f, { action: 'start_phase', phaseId: phaseA }); await execute(f, { action: 'start_phase', phaseId: phaseB });
  await execute(f, { action: 'create_milestone', milestone: { id: milestone, phaseId: phaseA, ownerProfileId: null } }, { name: 'Private manual review' });
  await assert.rejects(execute(f, { action: 'complete_phase', phaseId: phaseA }, undefined, 'Cannot skip acceptance'));
  const accepted = await execute(f, { action: 'accept_milestone', milestoneId: milestone }, undefined, 'Reviewed brief accepted');
  assert.equal(canonicalJson(accepted).includes('Reviewed brief accepted'), false);
  await execute(f, { action: 'complete_phase', phaseId: phaseA }, undefined, 'Discovery completed with learning');
  await execute(f, { action: 'cancel_phase', phaseId: phaseB, tasks: [], milestones: [] }, undefined, 'Delivery deferred deliberately');
  await execute(f, { action: 'complete_project' }, undefined, 'Starter project complete');
  const closed = await readPlanning(await f.input(), f.f.owner.bundle), priorSnapshots = canonicalJson(closed.graph.snapshots), priorAudit = canonicalJson(closed.audits);
  for (const [index, audit] of closed.audits.entries()) {
    const signed = (await f.context()).history[index]!.body.binding;
    assert.equal(audit.actorId, signed.accountId); assert.equal(audit.deviceId, signed.deviceId);
    assert.equal(audit.operationId, signed.operationId); assert.equal(audit.signedAt, signed.issuedAt);
  }
  const shuffled = await f.input(); shuffled.context.audits.reverse(); shuffled.context.outcomes.reverse();
  const ordered = await readPlanning(shuffled, f.f.owner.bundle);
  assert.equal(canonicalJson(ordered.audits), canonicalJson(closed.audits), 'Authenticated mutation sequence orders audit objects, regardless of server row order');
  assert.equal(canonicalJson(ordered.outcomes), canonicalJson(closed.outcomes), 'Outcome order follows the same signed chain');
  assert.equal(closed.graph.project.state, 'complete'); assert.equal(closed.graph.snapshots.length, 4);
  assert.equal(closed.outcomes.find((r) => r.id === closed.graph.snapshots[0]!.outcome.recordId)?.text, 'Reviewed brief accepted');
  assert.equal(closed.audits.at(-1)!.data.snapshotContents.find((r) => r.kind === 'project')!.content.name, 'Private original project');
  await execute(f, { action: 'archive_project' });
  await assert.rejects(execute(f, { action: 'edit_project', patch: {} }, { name: 'Forbidden archived rename' }));
  await execute(f, { action: 'unarchive_project' }); await execute(f, { action: 'reopen_project' });
  await execute(f, { action: 'edit_project', patch: {} }, { name: 'Private new project name' });
  const reopened = await readPlanning(await f.input(), f.f.owner.bundle);
  assert.equal(canonicalJson(reopened.graph.snapshots), priorSnapshots); assert.equal(canonicalJson(reopened.audits.slice(0, closed.audits.length)), priorAudit);
  assert.equal(reopened.records.find((r) => r.kind === 'project')!.content.name, 'Private new project name');
  assert.equal(reopened.graph.phases.find((r) => r.id === phaseB)!.state, 'cancelled');
});

test('CP07 planning client: missing children, rewritten metadata/ciphertext/history, rollback pins, invalid dates and expired writes are rejected', async () => {
  const f = await planningClientFixture(), old = await f.input(), phaseId = randomUUID();
  await assert.rejects(execute(f, { action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: null } },
    { name: 'Wrong dates', objective: '', completionCriteria: '', startDate: '2026-10-10', dueDate: '2026-10-01' }));
  await execute(f, { action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: null } }, { name: 'Real child', objective: '', completionCriteria: '' });
  const current = await f.input(), read = await readPlanning(current, f.f.owner.bundle);
  assert.deepEqual(read.authority, { accountId: current.context.binding.accountId, isOwner: current.context.binding.isOwner,
    permissions: current.context.binding.permissions, eligibleAssigneeIds: current.context.binding.eligibleAssigneeIds,
    eligibleReviewerIds: current.context.binding.version === 1 ? [] : current.context.binding.eligibleReviewerIds });
  await assert.rejects(readPlanning({ ...old, pin: read.pin }, f.f.owner.bundle));
  for (const modify of [
    (v: typeof current) => { v.context.graph.phases = []; },
    (v: typeof current) => { v.context.records = v.context.records.filter((r) => r.kind !== 'phase'); },
    (v: typeof current) => { v.context.history = []; },
    (v: typeof current) => { v.context.audits = []; },
    (v: typeof current) => { v.context.records[0]!.envelope.header.recordId = randomUUID(); },
    (v: typeof current) => { v.context.binding.permissions = ['read_project']; },
    (v: typeof current) => { v.context.binding.isOwner = false; },
    (v: typeof current) => { v.context.binding.eligibleAssigneeIds.push(randomUUID()); },
  ]) { const altered = structuredClone(current); modify(altered); await assert.rejects(readPlanning(altered, f.f.owner.bundle)); }
  const expired = structuredClone(current); expired.context.binding.issuedAt = new Date(Date.now() - 120000).toISOString(); expired.context.binding.expiresAt = new Date(Date.now() - 60000).toISOString();
  await assert.rejects(preparePlanning({ ...expired, command: { action: 'start_project' } }, f.f.owner.bundle));
  await assert.rejects(preparePlanning({ ...current, command: { action: 'start_project' }, outcome: 'Unexpected outcome' }, f.f.owner.bundle));
});

test('CP07 planning controller: lost save reply reloads exact ciphertext once, verifies receipt/history and removes corrupt local drafts on Forget', async () => {
  const f = await planningClientFixture(), factory = new IDBFactory(), name = randomUUID(), pins = await IndexedPairingStore.open(origin, randomUUID(), factory);
  await pins.recordVerifiedHistory(f.f.history);
  let store = await IndexedPlanningStore.open(origin, name, factory), saves = 0, lostReply = true;
  const actor = { workspaceId: f.f.workspaceId, accountId: f.f.owner.accountId, deviceId: f.f.owner.deviceId },
    auth = { origin, current: () => ({ localAccess: 'unlocked', session: { ...actor, credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1' } }),
      worker: { readPlanning: (input: Parameters<typeof readPlanning>[0]) => readPlanning(input, f.f.owner.bundle),
        preparePlanning: (input: Parameters<typeof preparePlanning>[0]) => preparePlanning(input, f.f.owner.bundle) } } as unknown as AuthController,
    transport: PlanningTransport = { origin, context: async (ref) => f.context(ref.operationId),
      history: async () => ({ genesis: f.f.history.genesis, transitions: f.f.history.transitions, anchor: f.f.history.expected, current: f.f.history.expected }),
      status: async (ref) => { const receipt = f.receipts.get(ref.operationId) ?? null; return { state: receipt ? 'completed' : 'absent', receipt }; },
      save: async (payload) => { saves++; assert.equal(canonicalJson((await store.get(actor.workspaceId, payload.mutation.body.binding.operationId))?.payload), canonicalJson(payload));
        const receipt = await f.apply(payload); if (lostReply) { lostReply = false; throw new Error('Lost save response'); } return receipt; } },
    access = { refreshKeys: () => refreshAccessKeys({ history: f.f.history, delivery: { ...actor, current: f.f.history.expected, materials: f.f.materials } }, f.f.owner.bundle) };
  let controller = new PlanningController(auth, transport, store, pins, access); const operationId = randomUUID(), phaseId = randomUUID();
  await assert.rejects(controller.execute({ projectId: f.projectId, operationId, command: { action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: null } },
    content: { name: 'Local secret wave', objective: '', completionCriteria: '' } }), /Lost save response/);
  const record = await store.get(actor.workspaceId, operationId); assert.ok(record); assert.equal(canonicalJson(record).includes('Local secret wave'), false); assert.equal(saves, 1);
  store.close(); store = await IndexedPlanningStore.open(origin, name, factory); controller = new PlanningController(auth, transport, store, pins, access);
  const result = await controller.resume(operationId); assert.equal(result.state, 'completed'); assert.equal(saves, 1);
  assert.equal((await controller.read(f.projectId)).records.find((r) => r.id === phaseId)?.content.name, 'Local secret wave');
  const receipt = f.receipts.get(operationId)!; f.receipts.set(operationId, { ...receipt, requestHash: '0'.repeat(64) }); await assert.rejects(controller.resume(operationId)); f.receipts.set(operationId, receipt);
  await assert.rejects(controller.execute({ reviewed: (await controller.read(f.projectId)).pin, projectId: f.projectId, operationId, command: { action: 'start_project' } })); assert.equal(saves, 1);
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = factory.open(name, 1); request.onsuccess = () => resolve(request.result); request.onerror = reject; });
  await new Promise<void>((resolve, reject) => { const tx = db.transaction('operations', 'readwrite'); tx.objectStore('operations').put({ ...record, payload: null }, `${origin}:${actor.workspaceId}:${operationId}`); tx.oncomplete = () => resolve(); tx.onabort = reject; }); db.close();
  await controller.forgetDevice(actor); assert.equal(await store.get(actor.workspaceId, operationId), undefined); store.close(); pins.close();
});

test('CP11 planning edits bind reviewed state, preserve unsaved input on conflict and never submit offline or automatically rebase',async()=>{
  const f=await planningClientFixture(),factory=new IDBFactory(),store=await IndexedPlanningStore.open(origin,randomUUID(),factory),pins=await IndexedPairingStore.open(origin,randomUUID(),factory);
  await pins.recordVerifiedHistory(f.f.history);let saves=0,prepares=0,contexts=0;
  const actor={workspaceId:f.f.workspaceId,accountId:f.f.owner.accountId,deviceId:f.f.owner.deviceId},auth={origin,
    current:()=>({localAccess:'unlocked',session:{...actor,credentialGeneration:'1',sessionGeneration:'1',dataGeneration:'1'}}),worker:{
      readPlanning:(input:Parameters<typeof readPlanning>[0])=>readPlanning(input,f.f.owner.bundle),
      preparePlanning:(input:Parameters<typeof preparePlanning>[0])=>{prepares++;return preparePlanning(input,f.f.owner.bundle);}}} as unknown as AuthController,
    transport:PlanningTransport={origin,context:ref=>{contexts++;return f.context(ref.operationId);},
      history:async()=>({genesis:f.f.history.genesis,transitions:f.f.history.transitions,anchor:f.f.history.expected,current:f.f.history.expected}),
      status:async ref=>{const receipt=f.receipts.get(ref.operationId)??null;return{state:receipt?'completed':'absent',receipt};},
      save:payload=>{saves++;return f.apply(payload);}},access={refreshKeys:()=>refreshAccessKeys({history:f.f.history,delivery:{...actor,current:f.f.history.expected,materials:f.f.materials}},f.f.owner.bundle)},
    controller=new PlanningController(auth,transport,store,pins,access);
  try{
    const reviewed=(await controller.read(f.projectId)).pin;
    await assert.rejects(controller.execute({projectId:f.projectId,command:{action:'start_project'}}),error=>error instanceof WriteError&&error.code==='REVIEW_REQUIRED');
    await controller.execute({projectId:f.projectId,reviewed,command:{action:'edit_project',patch:{}},content:{name:'Private first edit'}});
    const operationId=randomUUID(),input={projectId:f.projectId,operationId,reviewed,command:{action:'edit_project' as const,patch:{}},content:{name:'Private unsaved second edit'}},pending=controller.execute(input);
    input.content.name='Caller changed memory after submitting';
    let conflict:WriteConflict<Awaited<ReturnType<typeof controller.read>>,typeof input>|undefined;
    try{await pending;assert.fail('Stale reviewed edit must conflict');}catch(error){assert.ok(error instanceof WriteConflict);conflict=error;}
    assert.equal(conflict!.unsaved.content.name,'Private unsaved second edit');assert.equal(conflict!.current.records.find(r=>r.kind==='project')!.content.name,'Private first edit');
    assert.equal(saves,1);assert.equal(prepares,1);assert.equal(await store.get(actor.workspaceId,operationId),undefined);
    const offlineBefore={contexts,prepares,saves},descriptor=Object.getOwnPropertyDescriptor(globalThis.navigator,'onLine');
    Object.defineProperty(globalThis.navigator,'onLine',{configurable:true,value:false});
    try{await assert.rejects(controller.execute({...conflict!.unsaved,reviewed:conflict!.current.pin}),error=>error instanceof WriteError&&error.code==='OFFLINE');}
    finally{if(descriptor)Object.defineProperty(globalThis.navigator,'onLine',descriptor);else Reflect.deleteProperty(globalThis.navigator,'onLine');}
    assert.deepEqual({contexts,prepares,saves},offlineBefore);
    // Deliberately saving the reviewed new version uses a new operation identity.
    const freshId=randomUUID();await controller.execute({...conflict!.unsaved,operationId:freshId,reviewed:conflict!.current.pin});
    assert.equal(saves,2);assert.notEqual(freshId,operationId);
  }finally{store.close();pins.close();}
});

test('CP07 planning storage: business pins reject regression and same-version forks, keeping the higher authenticated data generation', async () => {
  const store = await IndexedPlanningStore.open(origin, randomUUID(), new IDBFactory()), reference = { workspaceId: randomUUID(), projectId: randomUUID() },
    pin = { ...reference, dataGeneration: '1', version: '2', head: await digestObject({ version: 2 }) };
  await store.recordPin(pin); await store.recordPin(pin);
  await assert.rejects(store.recordPin({ ...pin, version: '1' })); await assert.rejects(store.recordPin({ ...pin, head: '0'.repeat(64) }));
  await store.recordPin({ ...pin, dataGeneration: '2', version: '0' }); await assert.rejects(store.recordPin(pin));
  assert.equal((await store.pin(reference))!.dataGeneration, '2'); store.close();
});

test('CP07 planning client: real Todo preparation carries the same assigned task, reopens destination acceptance and retains private content during explicit cancellation', async () => {
  const f = await planningClientFixture(), phaseA = randomUUID(), phaseB = randomUUID(), milestoneId = randomUUID(), taskId = randomUUID(), accountId = f.f.owner.accountId;
  await execute(f, { action: 'start_project' });
  for (const [id, displayOrder] of [[phaseA, 0], [phaseB, 1]] as const) {
    await execute(f, { action: 'create_phase', phase: { id, displayOrder, leadProfileId: null } }, { name: `Private wave ${displayOrder}`, objective: '', completionCriteria: '' });
    await execute(f, { action: 'start_phase', phaseId: id });
  }
  await execute(f, { action: 'create_milestone', milestone: { id: milestoneId, phaseId: phaseB, ownerProfileId: null } }, { name: 'Previously accepted checkpoint' });
  await execute(f, { action: 'accept_milestone', milestoneId }, undefined, 'Initial manual acceptance');
  const task = { id: taskId, phaseId: phaseA, milestoneId: null, assigneeIds: [accountId], leadProfileId: accountId };
  await assert.rejects(execute(f, { action: 'create_task', task }, { title: ' ', description: '', acceptanceCriteria: '' }));
  const prepared = await execute(f, { action: 'create_task', task }, { title: 'Private retained task', description: 'One complete delivery', dueDate: '2026-10-01', acceptanceCriteria: 'Review against the brief' });
  assert.equal(canonicalJson(prepared).includes('Private retained task'), false); assert.equal(canonicalJson(prepared).includes('Review against the brief'), false);
  await assert.rejects(execute(f, { action: 'complete_phase', phaseId: phaseA }, undefined, 'Unfinished task must block'));
  await assert.rejects(execute(f, { action: 'complete_project' }, undefined, 'Unfinished project must block'));
  await execute(f, { action: 'carry_task', taskId, phaseId: phaseB, milestoneId }, undefined, 'Carried into the next wave');
  const carried = await readPlanning(await f.input(), f.f.owner.bundle);
  assert.equal(carried.graph.tasks.length, 1); assert.equal(carried.graph.tasks[0]!.id, taskId); assert.deepEqual(carried.graph.tasks[0]!.assigneeIds, [accountId]);
  assert.equal(carried.graph.tasks[0]!.leadProfileId, accountId); assert.equal(carried.graph.milestones[0]!.state, 'open'); assert.equal(carried.graph.movements[0]!.fromPhaseId, phaseA);
  assert.equal(carried.graph.snapshots[0]!.milestones[0]!.state, 'accepted');
  await execute(f, { action: 'cancel_phase', phaseId: phaseB, tasks: [{ taskId, action: 'cancel' }], milestones: [{ milestoneId, action: 'cancel' }] }, undefined, 'Explicitly cancelled remaining work');
  const cancelled = await readPlanning(await f.input(), f.f.owner.bundle), before = carried.records.find((r) => r.id === taskId)!, after = cancelled.records.find((r) => r.id === taskId)!;
  assert.equal(cancelled.graph.tasks[0]!.state, 'cancelled'); assert.equal(canonicalJson(after.content), canonicalJson(before.content));
  assert.equal(cancelled.audits.at(-1)!.data.snapshotContents.find((r) => r.id === taskId)!.content.title, 'Private retained task');
});

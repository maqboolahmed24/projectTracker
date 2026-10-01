import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { orderedTaskIds, moveTaskInOrder } from '../src/shared/task-order.js';
import { projectPrivateData } from '../src/shared/project-create.js';
import { canonicalJson } from '../src/shared/crypto.js';
import { decodeContentData, transformContentData1To2 } from '../src/shared/content-schema.js';
import { preparePlanning, readPlanning, type PlanningIntent, type PlanningPrivateContent } from '../src/client/planning-crypto.js';
import { planningClientFixture } from './planning-client-fixture.js';

test('task ordering retains new tasks and only changes visible group slots', () => {
  const ids = ['a', 'hidden', 'b', 'other-phase', 'c'];
  assert.deepEqual(orderedTaskIds(ids, undefined), ids);
  assert.deepEqual(orderedTaskIds(ids, ['c', 'a', 'c', 'removed']), ['c', 'a', 'hidden', 'b', 'other-phase']);
  const moved = moveTaskInOrder(ids, ['a', 'b', 'c'], 'c', 'a', 'before');
  assert.deepEqual(moved, ['c', 'hidden', 'a', 'other-phase', 'b']);
  assert.deepEqual(moveTaskInOrder(moved, ['a', 'b', 'c'], 'c', 'b', 'after'), ids);
  assert.deepEqual(moveTaskInOrder(ids, ['a', 'c'], 'c', 'a', 'before'), ['c', 'hidden', 'b', 'other-phase', 'a']);
  assert.deepEqual(moveTaskInOrder(ids, ['a', 'c'], 'hidden', 'a', 'before'), ids);
  assert.deepEqual(moveTaskInOrder(ids, ['a', 'c'], 'a', 'a', 'after'), ids);
  assert.deepEqual(ids, ['a', 'hidden', 'b', 'other-phase', 'c']);
});

test('encrypted project order is optional, bounded, unique and preserved by the schema upgrade', () => {
  const id = randomUUID(), old = { name: 'Historical project', description: 'Keep this text exactly.' };
  assert.deepEqual(projectPrivateData.parse(old), old);
  assert.equal(Object.hasOwn(projectPrivateData.parse(old), 'taskOrder'), false);
  const next = { ...old, taskOrder: [id, randomUUID()] };
  assert.deepEqual(projectPrivateData.parse(next), next);
  assert.equal(projectPrivateData.safeParse({ ...old, taskOrder: [id, id] }).success, false);
  assert.equal(projectPrivateData.safeParse({ ...old, taskOrder: ['not-an-id'] }).success, false);
  assert.equal(projectPrivateData.safeParse({ ...old, taskOrder: Array.from({ length: 2001 }, () => randomUUID()) }).success, false);
  const transformed = transformContentData1To2('project', next, value => projectPrivateData.parse(value));
  assert.deepEqual(decodeContentData(2, 'project', transformed), next);
});

for (const version of [1, 2] as const) test(`task order survives real encrypted planning history and closing snapshots with protocol ${version}`, async () => {
  const f = await planningClientFixture({ version }), first = randomUUID(), second = randomUUID();
  const execute = async (command: PlanningIntent, content?: PlanningPrivateContent, outcome?: string) => {
    const payload = await preparePlanning({ ...await f.input(), command, ...(content ? { content } : {}), ...(outcome ? { outcome } : {}) }, f.f.owner.bundle);
    await f.apply(payload); return payload;
  };
  assert.equal(Object.hasOwn((await readPlanning(await f.input(), f.f.owner.bundle)).records[0]!.content, 'taskOrder'), false);
  for (const [id, title] of [[first, 'First task'], [second, 'Second task']] as const) {
    await execute({ action: 'create_task', task: { id, phaseId: null, milestoneId: null, assigneeIds: [], leadProfileId: null } }, { title });
  }
  const existing = (await readPlanning(await f.input(), f.f.owner.bundle)).records.find(row => row.kind === 'project')!.content;
  const payload = await execute({ action: 'edit_project', patch: {} }, { ...existing, name: String(existing.name), taskOrder: [second, first] });
  assert.equal(canonicalJson(payload).includes('taskOrder'), false, 'Order is private project content, never a plaintext request field');
  let read = await readPlanning(await f.input(), f.f.owner.bundle);
  assert.deepEqual(read.records.find(row => row.kind === 'project')!.content.taskOrder, [second, first]);
  assert.equal(read.records.find(row => row.kind === 'project')!.content.name, existing.name);
  assert.deepEqual([...read.graph.tasks.map(row => row.id)].sort(), [first, second].sort(), 'Presentation order does not rewrite structural task identity or grouping');
  await execute({ action: 'start_project' });
  await execute({ action: 'cancel_project' }, undefined, 'Preserve the shared task order in the history.');
  read = await readPlanning(await f.input(), f.f.owner.bundle);
  assert.deepEqual(read.records.find(row => row.kind === 'project')!.content.taskOrder, [second, first]);
  assert.deepEqual(read.audits.at(-1)!.data.snapshotContents.find(row => row.kind === 'project')!.content.taskOrder, [second, first]);
  await assert.rejects(preparePlanning({ ...await f.input(), command: { action: 'edit_project', patch: {} }, content: { name: String(existing.name), taskOrder: [first, second] } }, f.f.owner.bundle));
});

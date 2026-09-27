import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { AppError } from '../src/errors.js';
import { base64urlDecode, signObject } from '../src/shared/crypto.js';
import type { PlanningPayload } from '../src/shared/planning-api.js';
import { planningFixture } from './planning-fixture.js';

test('CP07: service rejects signed cross-project and wrong-wave links even when the actor can access both projects', async (t) => {
  const f = await planningFixture(t), foreignPhase = randomUUID(), foreignMilestone = randomUUID();
  await f.execute({ action: 'create_phase', phase: { id: foreignPhase, displayOrder: 0, leadProfileId: null } },
    { content: { name: 'Foreign project wave', objective: '', completionCriteria: '' } });
  await f.execute({ action: 'create_milestone', milestone: { id: foreignMilestone, phaseId: foreignPhase, ownerProfileId: null } },
    { content: { name: 'Foreign project milestone' } });
  const projectId = await f.createProject('Other authorized project'), first = randomUUID(), second = randomUUID(), milestoneId = randomUUID();
  for (const [id, displayOrder] of [[first, 0], [second, 1]] as const) {
    await f.execute({ action: 'create_phase', phase: { id, displayOrder, leadProfileId: null } },
      { projectId, content: { name: `Local wave ${displayOrder}`, objective: '', completionCriteria: '' } });
  }
  await f.execute({ action: 'create_milestone', milestone: { id: milestoneId, phaseId: first, ownerProfileId: null } },
    { projectId, content: { name: 'Local wave milestone' } });
  const beforeForeign = await f.context(), beforeLocal = await f.context(projectId);

  // Re-sign an invalid link with the real Owner device. This intentionally skips
  // the client guard so rejection must come from the production service policy.
  const rejectSigned = async (payload: PlanningPayload, code: string) => {
    payload.mutation = await signObject(payload.mutation.body, base64urlDecode(f.originalBundle.signingPrivateKey));
    await assert.rejects(f.save(payload), (error: unknown) => error instanceof AppError && error.code === code);
    assert.equal((await f.planningStatus(payload)).state, 'absent');
  };
  const milestoneDraft = await f.preparePlanning({ action: 'create_milestone', milestone: { id: randomUUID(), phaseId: null, ownerProfileId: null } },
    { projectId, content: { name: 'Invalid foreign wave link' } });
  assert.equal(milestoneDraft.mutation.body.command.action, 'create_milestone');
  if (milestoneDraft.mutation.body.command.action !== 'create_milestone') throw new Error('Unexpected fixture command');
  milestoneDraft.mutation.body.command.milestone.phaseId = foreignPhase;
  await rejectSigned(milestoneDraft, 'PLANNING_NOT_FOUND');

  for (const [phaseId, linkedMilestoneId, expected] of [
    [foreignPhase, null, 'PLANNING_NOT_FOUND'],
    [first, foreignMilestone, 'PLANNING_INVALID_LINK'],
    [second, milestoneId, 'PLANNING_INVALID_LINK'],
  ] as const) {
    const draft = await f.preparePlanning({ action: 'create_task', task: { id: randomUUID(), phaseId: first, milestoneId, assigneeIds: [f.accountId], leadProfileId: null } },
      { projectId, content: { title: 'Invalid task link', description: '', acceptanceCriteria: '' } });
    if (draft.mutation.body.command.action !== 'create_task') throw new Error('Unexpected fixture command');
    draft.mutation.body.command.task.phaseId = phaseId;
    draft.mutation.body.command.task.milestoneId = linkedMilestoneId;
    await rejectSigned(draft, expected);
  }
  for (const [id, before] of [[f.projectId, beforeForeign], [projectId, beforeLocal]] as const) {
    const after = await f.context(id);
    assert.deepEqual(after.graph, before.graph);
    assert.deepEqual(after.records, before.records);
    assert.deepEqual(after.history, before.history);
    assert.equal(after.binding.beforeHead, before.binding.beforeHead);
  }
});

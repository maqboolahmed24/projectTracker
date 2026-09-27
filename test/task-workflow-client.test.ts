import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { base64urlDecode, canonicalJson, digestObject, encryptContent, randomKey, signObject, verifyContentEnvelope } from '../src/shared/crypto.js';
import { planningAuthority, validatePlanningPayload } from '../src/shared/planning-api.js';
import { evaluatePlanning, planningRevisionSnapshot } from '../src/shared/planning.js';
import { preparePlanning, readPlanning, type PlanningIntent, type PlanningPrivateContent } from '../src/client/planning-crypto.js';
import { planningClientFixture } from './planning-client-fixture.js';
import type { Actor } from './project-create-client-fixture.js';

type Fixture = Awaited<ReturnType<typeof planningClientFixture>>;
async function execute(f: Fixture, command: PlanningIntent, content?: PlanningPrivateContent, outcome?: string, actor: Actor = f.f.owner) {
  const payload = await preparePlanning({ ...await f.input(undefined, actor), command,
    ...(content === undefined ? {} : { content }), ...(outcome === undefined ? {} : { outcome }) }, actor.bundle);
  await f.apply(payload); return payload;
}
const content = (title: string) => ({ title, description: 'Private shared description', acceptanceCriteria: 'Private acceptance conditions' });

test('CP08 client: a v1 history upgrades once without rewriting signatures, snapshots or retained task content', async () => {
  const f = await planningClientFixture(), taskId = randomUUID(), milestoneId = randomUUID();
  await execute(f, { action: 'start_project' });
  await execute(f, { action: 'create_milestone', milestone: { id: milestoneId, phaseId: null, ownerProfileId: null } }, { name: 'Legacy private milestone' });
  await execute(f, { action: 'accept_milestone', milestoneId }, undefined, 'Legacy acceptance');
  const created = await execute(f, { action: 'create_task', task: { id: taskId, phaseId: null, milestoneId: null, assigneeIds: [f.f.owner.accountId], leadProfileId: null } }, content('Legacy private title'));
  const legacy = await f.input(), before = await readPlanning(legacy, f.f.owner.bundle), oldHash = await digestObject(legacy.context.history), oldAudits = canonicalJson(before.audits);
  f.upgrade();
  const started = await execute(f, { action: 'start_task', taskId });
  assert.equal(started.mutation.body.purpose, 'ukda.planning-mutation.v2');
  assert.equal(canonicalJson(started.records.find((r) => r.id === taskId)!.envelope), canonicalJson(created.records.find((r) => r.id === taskId)!.envelope));
  const current = await f.input(), read = await readPlanning(current, f.f.owner.bundle);
  assert.equal(await digestObject(current.context.history.slice(0, legacy.context.history.length)), oldHash);
  assert.equal(canonicalJson(read.audits.slice(0, before.audits.length)), oldAudits);
  assert.equal(canonicalJson(read.graph.snapshots), canonicalJson(before.graph.snapshots));
  assert.equal(read.records.find((r) => r.id === taskId)!.content.title, 'Legacy private title');
  assert.equal(read.records.find((r) => r.id === taskId)!.revision, '2'); assert.equal(read.records.find((r) => r.id === taskId)!.contentRevision, '1');
  await assert.rejects(preparePlanning({ ...current, command: { action: 'set_task_todo', taskId }, content: content('Hidden metadata replacement') }, f.f.owner.bundle));
  const metadata = await preparePlanning({ ...current, command: { action: 'set_task_todo', taskId } }, f.f.owner.bundle),
    original = current.context.records.find((r) => r.id === taskId)!, signing = base64urlDecode(f.f.owner.bundle.signingPrivateKey, 64), arbitraryKey = await randomKey();
  try {
    // A valid signer can manufacture different ciphertext with the exact old header/revision.
    // The server cannot decrypt it; exact retention is what rejects this substitution.
    const substitute = { ...original, envelope: await encryptContent(original.envelope.header, content('Malicious same-revision text'), arbitraryKey, signing) };
    assert.equal(substitute.envelope.header.revision, original.envelope.header.revision);
    assert.equal(await verifyContentEnvelope(substitute.envelope, base64urlDecode(f.f.owner.bundle.signingPublicKey, 32), original.envelope.header), true);
    const records = metadata.records.map((r) => r.id === taskId ? substitute : r), body = { ...metadata.mutation.body,
      records: await Promise.all(metadata.mutation.body.records.map(async (r) => r.id === taskId ? { ...r, digest: await digestObject(substitute.envelope) } : r)) },
      mutation = await signObject(body, signing), forged = { ...metadata, records, mutation };
    await assert.rejects(validatePlanningPayload(forged, current.context.binding, current.context.graph, current.context.records), /Replaced immutable task content/);
    const result = evaluatePlanning(current.context.graph, metadata.mutation.body.command, planningAuthority(current.context.binding)),
      forgedContext = { ...current.context, graph: result.state, binding: { ...current.context.binding, operationId: randomUUID(),
        beforeHead: await digestObject(mutation), beforeVersion: body.nextVersion, beforeGraphDigest: body.afterGraphDigest, before: planningRevisionSnapshot(result.state) },
      records: current.context.records.map((r) => r.id === taskId ? substitute : r), history: [...current.context.history, mutation], audits: [...current.context.audits, metadata.audit] };
    await assert.rejects(readPlanning({ ...current, context: forgedContext as typeof current.context }, f.f.owner.bundle), /Replaced historical task content/);
  } finally { signing.fill(0); arbitraryKey.fill(0); }
});

test('CP08 client: named non-assignee review retains ciphertext, rejects stale approval and invalidates review on every material edit', async () => {
  const f = await planningClientFixture({ version: 2, secondOwner: true }), reviewer = f.secondOwner!, taskId = randomUUID();
  await execute(f, { action: 'start_project' });
  const created = await execute(f, { action: 'create_task', task: { id: taskId, phaseId: null, milestoneId: null, assigneeIds: [f.f.owner.accountId], leadProfileId: f.f.owner.accountId } }, content('Private reviewed title'));
  await execute(f, { action: 'set_project_review', enabled: true, reviewers: [{ taskId, reviewerProfileId: reviewer.accountId }] }, undefined, 'Require named independent review');
  await execute(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true });
  const submitted = f.state().tasks[0]!;
  await assert.rejects(execute(f, { action: 'approve_task', taskId, submittedRevision: submitted.submittedRevision!, submittedPolicyRevision: submitted.submittedPolicyRevision! }));
  await execute(f, { action: 'reject_task', taskId }, undefined, 'Private rejection explains remaining work', reviewer);
  await execute(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true });
  const changed = await execute(f, { action: 'edit_task', taskId }, { ...content('Private revised title'), startDate: '2026-10-01', dueDate: '2026-10-03', priority: 'high' });
  assert.notEqual(await digestObject(changed.records[0]!.envelope), await digestObject(created.records[0]!.envelope));
  assert.equal(f.state().tasks[0]!.state, 'in_progress');
  await assert.rejects(execute(f, { action: 'approve_task', taskId, submittedRevision: submitted.submittedRevision!, submittedPolicyRevision: submitted.submittedPolicyRevision! }, undefined, undefined, reviewer));
  await execute(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true });
  const ready = f.state().tasks[0]!, approved = await execute(f, { action: 'approve_task', taskId, submittedRevision: ready.submittedRevision!, submittedPolicyRevision: ready.submittedPolicyRevision! }, undefined, undefined, reviewer);
  assert.equal(canonicalJson(approved.records.find((r) => r.id === taskId)!.envelope), canonicalJson(changed.records.find((r) => r.id === taskId)!.envelope));
  const read = await readPlanning(await f.input(undefined, reviewer), reviewer.bundle);
  assert.equal(read.authority.accountId, reviewer.accountId);
  assert.equal(read.authority.isOwner, true);
  assert.ok(read.authority.eligibleReviewerIds.includes(reviewer.accountId));
  const alteredAuthority = await f.input(undefined, reviewer);
  if (alteredAuthority.context.binding.version !== 1) alteredAuthority.context.binding.eligibleReviewerIds = [];
  await assert.rejects(readPlanning(alteredAuthority, reviewer.bundle));
  assert.equal(read.graph.tasks[0]!.state, 'done'); assert.equal(read.records.find((r) => r.id === taskId)!.content.title, 'Private revised title');
  assert.equal(read.outcomes.some((r) => r.text === 'Private rejection explains remaining work'), true);
  assert.equal(read.audits.find(row => row.data.action === 'reject_task')?.outcome, 'Private rejection explains remaining work');
  assert.equal(canonicalJson(approved).includes('Private'), false);
  await assert.rejects(execute(f, { action: 'edit_task', taskId }, content('Forbidden Done edit')));
  await execute(f, { action: 'reopen_task', taskId }, undefined, 'Explicitly reopen finished work');
  await execute(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true });
  await execute(f, { action: 'set_project_review', enabled: false, reviewers: [] }, undefined, 'Private policy change reason');
  assert.equal(f.state().tasks[0]!.state, 'in_progress');
});

test('CP08 client: encrypted blocker content survives resolve/reopen, multiple blockers prevent completion and cancelled work requires restore', async () => {
  const f = await planningClientFixture({ version: 2 }), taskId = randomUUID(), blockers = [randomUUID(), randomUUID()];
  await execute(f, { action: 'create_task', task: { id: taskId, phaseId: null, milestoneId: null, assigneeIds: [f.f.owner.accountId], leadProfileId: null } }, content('Private blocked work'));
  await assert.rejects(execute(f, { action: 'start_task', taskId })); await execute(f, { action: 'start_project' });
  for (const id of blockers) await execute(f, { action: 'create_blocker', blocker: { id, taskId, responsibleProfileId: f.f.owner.accountId } }, { reason: 'Private dependency reason', nextAction: 'Private next step' });
  const before = await f.context(), original = before.records.find((r) => r.id === blockers[0])!.envelope;
  await execute(f, { action: 'resolve_blocker', blockerId: blockers[0]! }, undefined, 'Private first resolution');
  assert.equal(canonicalJson((await f.context()).records.find((r) => r.id === blockers[0])!.envelope), canonicalJson(original));
  await assert.rejects(execute(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true }));
  await execute(f, { action: 'cancel_task', taskId }, undefined, 'Private cancellation');
  await assert.rejects(execute(f, { action: 'edit_task', taskId }, content('Forbidden cancelled edit')));
  await execute(f, { action: 'restore_task', taskId }, undefined, 'Private restoration');
  await assert.rejects(execute(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true }));
  await execute(f, { action: 'resolve_blocker', blockerId: blockers[1]! }, undefined, 'Private second resolution');
  await execute(f, { action: 'reopen_blocker', blockerId: blockers[0]! }, undefined, 'Private reopening explanation');
  await assert.rejects(execute(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true }));
  await execute(f, { action: 'resolve_blocker', blockerId: blockers[0]! }, undefined, 'Private final resolution');
  await execute(f, { action: 'request_task_completion', taskId, acceptanceConfirmed: true });
  await assert.rejects(execute(f, { action: 'reopen_blocker', blockerId: blockers[0]! }, undefined, 'Must reopen Done task first'));
  const read = await readPlanning(await f.input(), f.f.owner.bundle);
  assert.equal(read.graph.tasks[0]!.state, 'done'); assert.equal(read.graph.blockers!.every((r) => r.state === 'resolved'), true);
  assert.equal(read.records.find((r) => r.id === blockers[0])!.content.reason, 'Private dependency reason');
  assert.equal(read.outcomes.some((r) => r.text === 'Private reopening explanation'), true);
  await assert.rejects(execute(f, { action: 'create_task', task: { id: randomUUID(), phaseId: null, milestoneId: null, assigneeIds: [], leadProfileId: null } },
    { ...content('Invalid private dates'), startDate: '2026-10-05', dueDate: '2026-10-01' }));
});

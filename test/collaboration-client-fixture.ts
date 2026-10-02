import { randomUUID } from 'node:crypto';
import { digestObject } from '../src/shared/crypto.js';
import { collaborationBindingFromPlanning, collaborationContext, assertCollaborationCurrentBinding, validateCollaborationPayload, verifyCollaborationEntry,
  type CollaborationEntry, type CollaborationPayload, type CollaborationReceipt } from '../src/shared/collaboration.js';
import { preparePlanning, planningSecurityResolver, type PlanningIntent } from '../src/client/planning-crypto.js';
import { planningClientFixture } from './planning-client-fixture.js';

export async function collaborationClientFixture() {
  const planning = await planningClientFixture({ version: 2 }), taskId = randomUUID(), owner = planning.f.owner,
    records = new Map<string, CollaborationEntry>(), receipts = new Map<string, CollaborationReceipt>();
  const command = async (intent: PlanningIntent, outcome?: string) => {
    const payload = await preparePlanning({ ...await planning.input(), command: intent, ...(outcome ? { outcome } : {}) }, owner.bundle);
    await planning.apply(payload); return payload;
  };
  const created = await preparePlanning({ ...await planning.input(), command: { action: 'create_task', task: { id: taskId, phaseId: null, milestoneId: null,
    assigneeIds: [owner.accountId], leadProfileId: null } }, content: { title: 'Private discussion task' } }, owner.bundle); await planning.apply(created);
  const entry = async (entryId: string): Promise<CollaborationEntry | null> => {
    if (records.has(entryId)) return records.get(entryId)!;
    const context = await planning.context(), mutation = context.history.find((m) => m.body.outcome?.id === entryId);
    return mutation ? { origin: { kind: 'planning', operationId: mutation.body.binding.operationId, entryId }, moderation: null } : null;
  };
  const context = async (entryId: string, kind: 'comment' | 'update', operationId: string = randomUUID()) => {
    const current = await planning.context(operationId);
    return collaborationContext.parse({ planning: current, binding: collaborationBindingFromPlanning(current.binding, { entryId, kind }), entry: await entry(entryId) });
  };
  const apply = async (payload: CollaborationPayload): Promise<CollaborationReceipt> => {
    const b = payload.mutation.body.binding, current = await planning.context(b.operationId), existing = await entry(b.entryId),
      securityAt = planningSecurityResolver(planning.f.history, planning.f.state);
    await assertCollaborationCurrentBinding(b, current);
    const verified = existing ? await verifyCollaborationEntry(existing, current, securityAt) : null,
      { result } = await validateCollaborationPayload(payload, b, current.graph, verified), hash = await digestObject(payload), prior = receipts.get(b.operationId);
    if (prior) { if (prior.requestHash !== hash) throw new Error('Operation already used'); return prior; }
    records.set(b.entryId, payload.mutation.body.command.action.startsWith('post_') ? { origin: { kind: 'post', payload }, moderation: null }
      : b.version===1 ? { ...existing!, moderation: payload } : {...existing!,events:[...(existing?.events??[]),payload]});
    const receipt: CollaborationReceipt = { version: 1, workspaceId: b.workspaceId, projectId: b.projectId, operationId: b.operationId, entryId: b.entryId,
      kind: b.kind, revision: result.revision, head: result.head, dataGeneration: b.dataGeneration, requestHash: hash, committedAt: new Date().toISOString(), mutation: payload.mutation };
    receipts.set(b.operationId, receipt); return receipt;
  };
  return { planning, owner, taskId, records, receipts, entry, context, apply, command,
    input: async (entryId: string, kind: 'comment' | 'update', operationId?: string) => ({ context: await context(entryId, kind, operationId), history: planning.f.history,
      accountId: owner.accountId, deviceId: owner.deviceId }),
    readInput: async (entries: CollaborationEntry[], includeHidden = false) => ({ ...await planning.input(), entries, includeHidden }) };
}

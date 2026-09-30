import { z } from 'zod';
import { binary, permissionCapabilities, contentEnvelope, counter, digest, identifier, positiveCounter, type ContentEnvelope } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyContentEnvelope, verifyObject } from './crypto.js';
import { projectCreateHeader, projectCreateTransition } from './project-create.js';
import { evaluatePlanning, planningEnvelopeReference, planningRevisionSnapshot, type PlanningAuthority, type PlanningCommand, type LegacyPlanningCommand, type PlanningState, upgradePlanningGraph } from './planning.js';
import type { SecurityHistoryState } from './security-history.js';
import { closingSettings, type ClosingSettings } from './closing-settings.js';
import { upgradeItem, upgradeProof, validateUpgradeItems, verifyUpgradeItem } from './encrypted-upgrades.js';

/** Graph and individual transport pages remain bounded independently of lifetime history. */
export const PLANNING_MAX_RECORDS = 2000, PLANNING_MAX_HISTORY = 512, PLANNING_MAX_BYTES = 16 * 1024 * 1024;
export const PLANNING_HISTORY_PAGE_SIZE = 64, PLANNING_HISTORY_MAX_OPERATIONS = 8192;
export const PLANNING_HISTORY_MAX_BYTES = 384 * 1024 * 1024;
const ids = z.array(identifier).max(PLANNING_MAX_RECORDS).refine((v) => new Set(v).size === v.length);
const lifecycle = z.enum(['planned', 'active', 'complete', 'cancelled']);
const base = { workspaceId: identifier, id: identifier, revision: positiveCounter };
export const planningProject = z.strictObject({ ...base, state: lifecycle, archived: z.boolean(), phaseLabel: z.enum(['phase', 'wave']), managerProfileId: identifier.nullable(), teamId: identifier.nullable() });
export const planningPhase = z.strictObject({ ...base, projectId: identifier, state: lifecycle, archived: z.boolean(), displayOrder: z.number().int().nonnegative(), leadProfileId: identifier.nullable() });
export const planningMilestone = z.strictObject({ ...base, projectId: identifier, state: z.enum(['open', 'accepted', 'cancelled']), phaseId: identifier.nullable(), ownerProfileId: identifier.nullable() });
export const planningTask = z.strictObject({ ...base, projectId: identifier, state: z.enum(['todo', 'in_progress', 'review', 'done', 'cancelled']), phaseId: identifier.nullable(), milestoneId: identifier.nullable(), assigneeIds: ids, leadProfileId: identifier.nullable() });
const revisionRef = z.strictObject({ id: identifier, revision: positiveCounter });
const planningExpectedV1 = z.strictObject({ projectRevision: positiveCounter, phases: z.array(revisionRef).max(PLANNING_MAX_RECORDS), milestones: z.array(revisionRef).max(PLANNING_MAX_RECORDS), tasks: z.array(revisionRef).max(PLANNING_MAX_RECORDS) });
const movement = z.strictObject({ operationId: identifier, taskId: identifier, taskRevision: positiveCounter, fromPhaseId: identifier.nullable(), toPhaseId: identifier.nullable(), fromMilestoneId: identifier.nullable(), toMilestoneId: identifier.nullable(), reason: planningEnvelopeReference });
const snapshot = z.strictObject({ operationId: identifier, kind: z.enum(['project', 'phase', 'milestone']), recordId: identifier, action: z.enum(['complete', 'accept', 'cancel']), outcome: planningEnvelopeReference,
  project: planningProject, phases: z.array(planningPhase).max(PLANNING_MAX_RECORDS), milestones: z.array(planningMilestone).max(PLANNING_MAX_RECORDS), tasks: z.array(planningTask).max(PLANNING_MAX_RECORDS), carriedWork: z.array(movement).max(PLANNING_MAX_RECORDS) });
const planningGraphV1 = z.strictObject({ project: planningProject, phases: z.array(planningPhase).max(PLANNING_MAX_RECORDS), milestones: z.array(planningMilestone).max(PLANNING_MAX_RECORDS), tasks: z.array(planningTask).max(PLANNING_MAX_RECORDS), snapshots: z.array(snapshot).max(PLANNING_MAX_HISTORY), movements: z.array(movement).max(PLANNING_MAX_RECORDS) });
const common = { operationId: identifier, expected: planningExpectedV1 };
const no = (action: 'start_project' | 'reopen_project' | 'archive_project' | 'unarchive_project') => z.strictObject({ ...common, action: z.literal(action) });
const phaseOnly = (action: 'start_phase' | 'reopen_phase' | 'archive_phase' | 'unarchive_phase') => z.strictObject({ ...common, action: z.literal(action), phaseId: identifier });
const planningCommandV1 = z.discriminatedUnion('action', [
  z.strictObject({ ...common, action: z.literal('edit_project'), patch: planningProject.pick({ phaseLabel: true, managerProfileId: true, teamId: true }).partial().refine((patch) => Object.values(patch).every((value) => value !== undefined)).transform((patch) => ({ ...(patch.phaseLabel !== undefined ? { phaseLabel: patch.phaseLabel } : {}), ...(patch.managerProfileId !== undefined ? { managerProfileId: patch.managerProfileId } : {}), ...(patch.teamId !== undefined ? { teamId: patch.teamId } : {}) })) }),
  no('start_project'), no('reopen_project'), no('archive_project'), no('unarchive_project'),
  z.strictObject({ ...common, action: z.enum(['complete_project', 'cancel_project']), outcome: planningEnvelopeReference }),
  z.strictObject({ ...common, action: z.literal('create_phase'), phase: planningPhase.pick({ id: true, displayOrder: true, leadProfileId: true }) }),
  z.strictObject({ ...common, action: z.literal('edit_phase'), phaseId: identifier, patch: planningPhase.pick({ displayOrder: true, leadProfileId: true }).partial().refine((patch) => Object.values(patch).every((value) => value !== undefined)).transform((patch) => ({ ...(patch.displayOrder !== undefined ? { displayOrder: patch.displayOrder } : {}), ...(patch.leadProfileId !== undefined ? { leadProfileId: patch.leadProfileId } : {}) })) }),
  phaseOnly('start_phase'), phaseOnly('reopen_phase'), phaseOnly('archive_phase'), phaseOnly('unarchive_phase'),
  z.strictObject({ ...common, action: z.literal('complete_phase'), phaseId: identifier, outcome: planningEnvelopeReference }),
  z.strictObject({ ...common, action: z.literal('cancel_phase'), phaseId: identifier, outcome: planningEnvelopeReference,
    tasks: z.array(z.discriminatedUnion('action', [z.strictObject({ taskId: identifier, action: z.literal('cancel') }), z.strictObject({ taskId: identifier, action: z.literal('move'), phaseId: identifier.nullable(), milestoneId: identifier.nullable() })])).max(PLANNING_MAX_RECORDS),
    milestones: z.array(z.discriminatedUnion('action', [z.strictObject({ milestoneId: identifier, action: z.literal('cancel') }), z.strictObject({ milestoneId: identifier, action: z.literal('move'), phaseId: identifier.nullable() })])).max(PLANNING_MAX_RECORDS) }),
  z.strictObject({ ...common, action: z.literal('create_milestone'), milestone: planningMilestone.pick({ id: true, phaseId: true, ownerProfileId: true }) }),
  z.strictObject({ ...common, action: z.literal('edit_milestone'), milestoneId: identifier, patch: planningMilestone.pick({ phaseId: true, ownerProfileId: true }).partial().refine((patch) => Object.values(patch).every((value) => value !== undefined)).transform((patch) => ({ ...(patch.phaseId !== undefined ? { phaseId: patch.phaseId } : {}), ...(patch.ownerProfileId !== undefined ? { ownerProfileId: patch.ownerProfileId } : {}) })) }),
  z.strictObject({ ...common, action: z.enum(['accept_milestone', 'cancel_milestone']), milestoneId: identifier, outcome: planningEnvelopeReference }),
  z.strictObject({ ...common, action: z.literal('reopen_milestone'), milestoneId: identifier }),
  z.strictObject({ ...common, action: z.literal('create_task'), task: planningTask.pick({ id: true, phaseId: true, milestoneId: true, assigneeIds: true, leadProfileId: true }) }),
  z.strictObject({ ...common, action: z.literal('carry_task'), taskId: identifier, phaseId: identifier.nullable(), milestoneId: identifier.nullable(), outcome: planningEnvelopeReference }),
]) satisfies z.ZodType<LegacyPlanningCommand>;
export const planningReference = z.strictObject({ workspaceId: identifier, projectId: identifier, operationId: identifier });
export const planningStatusRequest = planningReference.extend({ dataGeneration: positiveCounter, requestHash: digest });
const planningBindingV1 = planningReference.extend({ version: z.literal(1), origin: z.string().url(), accountId: identifier, deviceId: identifier,
  credentialGeneration: positiveCounter, sessionGeneration: positiveCounter, keyGeneration: positiveCounter, signingPublicKey: binary(32),
  eligibleAssigneeIds: ids, permissionVersion: positiveCounter, permissions: z.array(z.enum(permissionCapabilities)), isOwner: z.boolean(), keyEpoch: positiveCounter,
  securityVersion: positiveCounter, securityHead: digest, dataGeneration: positiveCounter,
  beforeVersion: counter, beforeHead: digest, beforeGraphDigest: digest, before: planningExpectedV1,
  issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime() });
export const planningProjectV2 = planningProject.extend({ reviewEnabled: z.boolean(), reviewPolicyRevision: positiveCounter });
export const planningTaskV2 = planningTask.extend({ contentRevision: positiveCounter, teamId: identifier.nullable(), reviewerProfileId: identifier.nullable(), submittedRevision: positiveCounter.nullable(), submittedPolicyRevision: positiveCounter.nullable(), approvalOperationId: identifier.nullable() });
export const planningBlocker = z.strictObject({ ...base, projectId: identifier, taskId: identifier, contentRevision: positiveCounter, state: z.enum(['open','resolved']), responsibleProfileId: identifier.nullable(), createdBy: identifier, createdAt: z.iso.datetime(), resolvedBy: identifier.nullable(), resolvedAt: z.iso.datetime().nullable() });
const planningExpectedV2 = planningExpectedV1.extend({ blockers: z.array(revisionRef).max(PLANNING_MAX_RECORDS) });
export const planningExpected = z.union([planningExpectedV1, planningExpectedV2]);
const snapshotV2 = snapshot.extend({ project: planningProjectV2, tasks: z.array(planningTaskV2).max(PLANNING_MAX_RECORDS), blockers: z.array(planningBlocker).max(PLANNING_MAX_RECORDS) });
const planningGraphV2 = planningGraphV1.extend({ version: z.literal(2), project: planningProjectV2, tasks: z.array(planningTaskV2).max(PLANNING_MAX_RECORDS), blockers: z.array(planningBlocker).max(PLANNING_MAX_RECORDS), snapshots: z.array(z.union([snapshot,snapshotV2])).max(PLANNING_MAX_HISTORY) });
export const planningGraph = z.union([planningGraphV2,planningGraphV1]);
const commonV2 = { operationId: identifier, expected: planningExpectedV2 };
const taskOnly = (action: 'edit_task'|'start_task'|'set_task_todo') => z.strictObject({ ...commonV2, action: z.literal(action), taskId: identifier });
const taskReason = (action: 'reject_task'|'cancel_task'|'reopen_task'|'restore_task') => z.strictObject({ ...commonV2, action: z.literal(action), taskId: identifier, outcome: planningEnvelopeReference });
const planningCommandV2: z.ZodType<Exclude<PlanningCommand,{action:'upgrade_content'}>> = z.discriminatedUnion('action', [
  z.strictObject({ ...commonV2, action: z.literal('create_task'), task: planningTask.pick({ id:true,phaseId:true,milestoneId:true,assigneeIds:true,leadProfileId:true }).extend({ teamId: identifier.nullable().optional(), reviewerProfileId: identifier.nullable().optional() }).transform((t) => ({ id:t.id,phaseId:t.phaseId,milestoneId:t.milestoneId,assigneeIds:t.assigneeIds,leadProfileId:t.leadProfileId,...(t.teamId !== undefined ? {teamId:t.teamId}:{}),...(t.reviewerProfileId !== undefined ? {reviewerProfileId:t.reviewerProfileId}:{}) })) }),
  ...planningCommandV1.options.filter(schema=>!schema.shape.action.safeParse('create_task').success).map((schema) => schema.extend({ expected: planningExpectedV2 })),
  taskOnly('edit_task'),taskOnly('start_task'),taskOnly('set_task_todo'),
  z.strictObject({ ...commonV2, action:z.literal('assign_task'),taskId:identifier,assigneeIds:ids,leadProfileId:identifier.nullable(),teamId:identifier.nullable() }),
  z.strictObject({ ...commonV2, action:z.literal('request_task_completion'),taskId:identifier,acceptanceConfirmed:z.literal(true) }),
  z.strictObject({ ...commonV2, action:z.literal('select_task_reviewer'),taskId:identifier,reviewerProfileId:identifier.nullable() }),
  z.strictObject({ ...commonV2, action:z.literal('approve_task'),taskId:identifier,submittedRevision:positiveCounter,submittedPolicyRevision:positiveCounter }),
  taskReason('reject_task'),taskReason('cancel_task'),taskReason('reopen_task'),taskReason('restore_task'),
  z.strictObject({ ...commonV2, action:z.literal('set_project_review'),enabled:z.boolean(),reviewers:z.array(z.strictObject({taskId:identifier,reviewerProfileId:identifier})).max(PLANNING_MAX_RECORDS),outcome:planningEnvelopeReference }),
  z.strictObject({ ...commonV2, action:z.literal('create_blocker'),blocker:z.strictObject({id:identifier,taskId:identifier,responsibleProfileId:identifier}) }),
  z.strictObject({ ...commonV2, action:z.literal('edit_blocker'),blockerId:identifier,responsibleProfileId:identifier }),
  z.strictObject({ ...commonV2, action:z.enum(['resolve_blocker','reopen_blocker']),blockerId:identifier,outcome:planningEnvelopeReference }),
] ) as unknown as z.ZodType<Exclude<PlanningCommand,{action:'upgrade_content'}>>;
const planningUpgradeCommand = z.strictObject({ ...commonV2, action: z.literal('upgrade_content'), records: z.array(z.strictObject({ kind: z.enum(['project','phase','milestone','task','blocker']), id: identifier })).min(1).max(32) });
const planningCommandV3 = z.union([planningCommandV2, planningUpgradeCommand]);
export const planningCommand = z.union([planningCommandV2,planningUpgradeCommand,planningCommandV1]) satisfies z.ZodType<PlanningCommand>;
export const planningBindingV2 = planningBindingV1.extend({version:z.literal(2),eligibleReviewerIds:ids,before:planningExpectedV2});
export const planningBindingV3 = planningBindingV2.extend({ version: z.literal(3), writeSchema: z.literal(2) });
export const planningBinding = z.discriminatedUnion('version',[planningBindingV1,planningBindingV2,planningBindingV3]);
export type PlanningBinding = z.infer<typeof planningBinding>;
export const planningRecord = z.strictObject({ kind: z.enum(['project', 'phase', 'milestone', 'task', 'blocker']), id: identifier, envelope: contentEnvelope });
export type PlanningRecord = z.infer<typeof planningRecord>;
const encryptedObject = z.strictObject({ id: identifier, envelope: contentEnvelope });
const recordRef = z.strictObject({ kind: planningRecord.shape.kind, id: identifier, revision: positiveCounter, digest });
const objectRef = z.strictObject({ id: identifier, digest });
const planningMutationBodyV1 = z.strictObject({ purpose: z.literal('ukda.planning-mutation.v1'), binding: planningBindingV1, command: planningCommandV1,
  nextVersion: positiveCounter, afterGraphDigest: digest, records: z.array(recordRef.extend({kind:z.enum(['project','phase','milestone','task'])})).max(PLANNING_MAX_RECORDS), audit: objectRef, outcome: objectRef.nullable() });
const planningMutationBodyV2 = planningMutationBodyV1.extend({purpose:z.literal('ukda.planning-mutation.v2'),binding:planningBindingV2,command:planningCommandV2,records:z.array(recordRef.extend({contentRevision:positiveCounter})).max(PLANNING_MAX_RECORDS),closingSettings:closingSettings.optional()});
const planningMutationBodyV3 = planningMutationBodyV2.extend({ purpose: z.literal('ukda.planning-mutation.v3'), binding: planningBindingV3, command: planningCommandV3,
  records: z.array(recordRef.extend({ contentRevision: positiveCounter, envelopeRevision: positiveCounter })).max(PLANNING_MAX_RECORDS), upgrade: upgradeProof.optional() });
export const planningMutationBody = z.discriminatedUnion('purpose',[planningMutationBodyV1, planningMutationBodyV2, planningMutationBodyV3]);
export const planningMutation = z.strictObject({ body: planningMutationBody, signature: binary(64) }).transform(value=>{
  // The protocol repeats the exact predecessor vector in the binding and
  // command. Share equal parsed values without changing any signed JSON bytes.
  if(JSON.stringify(value.body.command.expected)===JSON.stringify(value.body.binding.before))value.body.command.expected=value.body.binding.before;
  return value;
});
export type PlanningMutation = z.infer<typeof planningMutation>;
/** Parsed revision references contain exactly id/revision. Reuse equal values
 * across immutable predecessors without changing the original signed JSON. */
export function sharePlanningRevisionReferences(history:PlanningMutation[],current?:PlanningBinding['before']):PlanningMutation[]{
  const refs=new Map<string,{id:string;revision:string}>(),max=PLANNING_MAX_RECORDS*32;
  const visit=(vector:{phases:readonly{id:string;revision:string}[];milestones:readonly{id:string;revision:string}[];tasks:readonly{id:string;revision:string}[];blockers?:readonly{id:string;revision:string}[]})=>{for(const field of ['phases','milestones','tasks','blockers'] as const){const rows=vector[field] as {id:string;revision:string}[]|undefined;if(!rows)continue;
    for(let i=0;i<rows.length;i++){const row=rows[i]!,key=`${row.id}:${row.revision}`,prior=refs.get(key);if(prior)rows[i]=prior;else if(refs.size<max)refs.set(key,row);}}};
  for(const mutation of history){visit(mutation.body.binding.before);if(mutation.body.command.expected!==mutation.body.binding.before)visit(mutation.body.command.expected);}
  if(current)visit(current);return history;
}
export const planningPayload = z.strictObject({ mutation: planningMutation, records: z.array(planningRecord).max(PLANNING_MAX_RECORDS), audit: encryptedObject, outcome: encryptedObject.nullable(), upgradeItems: z.array(upgradeItem).min(1).max(32).optional() });
export type PlanningPayload = z.infer<typeof planningPayload>;
export const planningContext = z.strictObject({ binding: planningBinding, graph: planningGraph, records: z.array(planningRecord).max(PLANNING_MAX_RECORDS),
  creation: projectCreateTransition, history: z.array(planningMutation).max(PLANNING_HISTORY_MAX_OPERATIONS).transform(history=>sharePlanningRevisionReferences(history)),
  materials: z.array(z.strictObject({ id: identifier, digest, kind: z.string().max(64), value: z.unknown() })).max(16384),
  outcomes: z.array(encryptedObject).max(PLANNING_HISTORY_MAX_OPERATIONS), audits: z.array(encryptedObject).max(PLANNING_HISTORY_MAX_OPERATIONS),
  upgrades: z.array(z.strictObject({ operationId: identifier, items: z.array(upgradeItem).min(1).max(32) })).max(PLANNING_HISTORY_MAX_OPERATIONS).optional() });
export type PlanningContext = Omit<z.infer<typeof planningContext>, 'graph'> & {graph:PlanningState};
/** An authenticated current graph plus a cursor for immutable original signed history. */
export const planningHistoryAnchor = z.strictObject({ version: counter, head: digest, dataGeneration: positiveCounter,
  securityVersion: positiveCounter, securityHead: digest });
export type PlanningHistoryAnchor = z.infer<typeof planningHistoryAnchor>;
export const planningContextFrame = planningContext.omit({ history: true, audits: true, outcomes: true, upgrades: true });
export const planningPagedContext = z.strictObject({ protocol: z.literal(1), context: planningContextFrame, anchor: planningHistoryAnchor });
export type PlanningPagedContext = Omit<z.infer<typeof planningPagedContext>, 'context'> & { context: Omit<PlanningContext, 'history'|'audits'|'outcomes'|'upgrades'> };
export const planningOperationsRequest = planningReference.extend({ anchor: planningHistoryAnchor, afterVersion: counter });
export const planningOperationsPage = z.strictObject({ protocol: z.literal(1), anchor: planningHistoryAnchor, afterVersion: counter,
  previousHead: digest, nextVersion: counter, nextHead: digest, complete: z.boolean(),
  history: z.array(planningMutation).max(PLANNING_HISTORY_PAGE_SIZE), audits: z.array(encryptedObject).max(PLANNING_HISTORY_PAGE_SIZE),
  outcomes: z.array(encryptedObject).max(PLANNING_HISTORY_PAGE_SIZE),
  upgrades: z.array(z.strictObject({ operationId: identifier, items: z.array(upgradeItem).min(1).max(32) })).max(PLANNING_HISTORY_PAGE_SIZE) });
export type PlanningOperationsPage = z.infer<typeof planningOperationsPage>;
export function planningAnchorFor(context: Pick<PlanningContext, 'binding'>): PlanningHistoryAnchor {
  const b=context.binding;
  return { version:b.beforeVersion,head:b.beforeHead,dataGeneration:b.dataGeneration,securityVersion:b.securityVersion,securityHead:b.securityHead };
}
export function planningFrame(context: PlanningContext): PlanningPagedContext {
  const {history:_history,audits:_audits,outcomes:_outcomes,upgrades:_upgrades,...frame}=context;
  return { protocol:1,context:frame,anchor:planningAnchorFor(context) };
}
const PLANNING_WIRE_DEPTH=32, PLANNING_WIRE_NODES=1_000_000;
const contextKeys=new Set(['binding','graph','records','creation','history','materials','outcomes','audits','upgrades']);
/** Project only complete native contexts; signatures and every other response field stay intact. */
export function planningWireValue(value: unknown): unknown {
  let nodes=0;
  function visit(item:unknown,depth:number):unknown {
    if(++nodes>PLANNING_WIRE_NODES||depth>PLANNING_WIRE_DEPTH)throw new Error('Planning wire nesting exceeds bounds');
    if(!item||typeof item!=='object')return item;
    if(Array.isArray(item))return item.map(entry=>visit(entry,depth+1));
    const object=item as Record<string,unknown>;
    if(Object.keys(object).every(key=>contextKeys.has(key))&&contextKeys.size-1<=Object.keys(object).length&&
      object.binding&&object.graph&&object.creation&&Array.isArray(object.records)&&Array.isArray(object.history)&&
      Array.isArray(object.materials)&&Array.isArray(object.outcomes)&&Array.isArray(object.audits)) {
      if(object.history.length>PLANNING_HISTORY_PAGE_SIZE)return planningFrame(item as PlanningContext);
      return item;
    }
    return Object.fromEntries(Object.entries(object).map(([key,entry])=>[key,visit(entry,depth+1)]));
  }
  return visit(value,0);
}
/** Legacy clients must fail explicitly rather than receiving an unbounded native context. */
export function assertLegacyPlanningWireValue(value:unknown):void {
  let nodes=0;
  function visit(item:unknown,depth:number):void {
    if(++nodes>PLANNING_WIRE_NODES||depth>PLANNING_WIRE_DEPTH)throw new Error('Planning wire nesting exceeds bounds');
    if(!item||typeof item!=='object')return;
    if(Array.isArray(item)){for(const entry of item)visit(entry,depth+1);return;}
    const object=item as Record<string,unknown>;
    if(Object.keys(object).every(key=>contextKeys.has(key))&&contextKeys.size-1<=Object.keys(object).length&&object.binding&&object.graph&&object.creation&&Array.isArray(object.history)&&Array.isArray(object.audits)&&Array.isArray(object.outcomes)) {
      if(object.history.length>PLANNING_MAX_HISTORY||new TextEncoder().encode(canonicalJson(object)).byteLength>PLANNING_MAX_BYTES)throw new Error('Legacy planning context exceeded');return;
    }
    for(const entry of Object.values(object))visit(entry,depth+1);
  }
  visit(value,0);
}
export async function hydratePlanningWireValue(value:unknown,
  readPage:(request:z.infer<typeof planningOperationsRequest>)=>Promise<unknown>):Promise<unknown> {
  let nodes=0,frames=0,totalBytes=new TextEncoder().encode(canonicalJson(value)).byteLength;
  async function visit(item:unknown,depth:number):Promise<unknown> {
    if(++nodes>PLANNING_WIRE_NODES||depth>PLANNING_WIRE_DEPTH)throw new Error('Planning wire nesting exceeds bounds');
    if(!item||typeof item!=='object')return item;
    if(Array.isArray(item)) {const result:unknown[]=[];for(const entry of item)result.push(await visit(entry,depth+1));return result;}
    const object=item as Record<string,unknown>;
    if(Object.keys(object).length===3&&object.protocol===1&&object.context&&object.anchor) {
      if(++frames>32)throw new Error('Planning frame count exceeds bounds');
      return readPlanningOperationPages(item,async request=>{const page=await readPage(request);
        totalBytes+=new TextEncoder().encode(canonicalJson(page)).byteLength;
        if(totalBytes>PLANNING_HISTORY_MAX_BYTES)throw new Error('Combined planning histories exceed bounds');return page;});
    }
    const result:Record<string,unknown>={};for(const [key,entry]of Object.entries(object))result[key]=await visit(entry,depth+1);return result;
  }
  return visit(value,0);
}
/** Page boundaries are not trusted; original mutation signatures are verified after assembly. */
export async function readPlanningOperationPages(frameValue: unknown,
  readPage: (request: z.infer<typeof planningOperationsRequest>) => Promise<unknown>): Promise<PlanningContext> {
  const frame=planningPagedContext.parse(frameValue),b=frame.context.binding,anchor=frame.anchor;
  if (!same(anchor,planningAnchorFor(frame.context))||BigInt(anchor.version)>BigInt(PLANNING_HISTORY_MAX_OPERATIONS)) throw new Error('Invalid planning page anchor');
  const context: PlanningContext={...frame.context,history:[],audits:[],outcomes:[]};
  let version='0',head=await digestObject(frame.context.creation),bytes=new TextEncoder().encode(canonicalJson(frame)).byteLength;
  const upgrades:NonNullable<PlanningContext['upgrades']>=[];
  for (let pageNumber=0;pageNumber<=PLANNING_HISTORY_MAX_OPERATIONS;pageNumber++) {
    if (version===anchor.version) {
      if(head!==anchor.head)throw new Error('Invalid planning final page head');
      if(upgrades.length)context.upgrades=upgrades;
      sharePlanningRevisionReferences(context.history,context.binding.before);
      return context;
    }
    const page=planningOperationsPage.parse(await readPage({workspaceId:b.workspaceId,projectId:b.projectId,operationId:b.operationId,anchor,afterVersion:version}));
    const pageBytes=new TextEncoder().encode(canonicalJson(page)).byteLength;bytes+=pageBytes;
    if(pageBytes>PLANNING_MAX_BYTES||bytes>PLANNING_HISTORY_MAX_BYTES||!same(page.anchor,anchor)||page.afterVersion!==version||page.previousHead!==head||!page.history.length)throw new Error('Invalid planning page boundary');
    for(const mutation of page.history) {
      const prior=mutation.body.binding;
      if(prior.workspaceId!==b.workspaceId||prior.projectId!==b.projectId||prior.beforeVersion!==version||prior.beforeHead!==head||mutation.body.nextVersion!==String(BigInt(version)+1n))throw new Error('Incomplete planning page chain');
      context.history.push(mutation);version=mutation.body.nextVersion;head=await digestObject(mutation);
    }
    if(page.nextVersion!==version||page.nextHead!==head||BigInt(version)>BigInt(anchor.version)||page.complete!==(version===anchor.version))throw new Error('Invalid planning page completion');
    context.audits.push(...page.audits);context.outcomes.push(...page.outcomes);upgrades.push(...page.upgrades);
    if(context.audits.length>PLANNING_HISTORY_MAX_OPERATIONS||context.outcomes.length>PLANNING_HISTORY_MAX_OPERATIONS||upgrades.length>PLANNING_HISTORY_MAX_OPERATIONS)throw new Error('Planning assembled record limit exceeded');
  }
  throw new Error('Planning page limit exceeded');
}

/** Call only after verifyPlanningContext; unstamped legacy closures are explicitly unrecorded. */
export function readPlanningClosingSettings(context: PlanningContext, operationId: string): ClosingSettings | null {
  if (!context.graph.snapshots.some(snapshot => snapshot.operationId === operationId)) return null;
  const body = context.history.find(mutation => mutation.body.binding.operationId === operationId)?.body;
  return body && body.purpose !== 'ukda.planning-mutation.v1' && body.closingSettings ? structuredClone(body.closingSettings) : null;
}
export const planningReceipt = z.strictObject({ version: z.literal(1), workspaceId: identifier, projectId: identifier, operationId: identifier, dataGeneration: positiveCounter,
  requestHash: digest, planningVersion: positiveCounter, planningHead: digest, graphDigest: digest, committedAt: z.iso.datetime(), mutation: planningMutation });
export type PlanningReceipt = z.infer<typeof planningReceipt>;
export const planningView = z.strictObject({ state: z.enum(['absent', 'completed']), receipt: planningReceipt.nullable() });
export type PlanningView = z.infer<typeof planningView>;
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const sorted = <T extends { id: string }>(v: readonly T[]) => [...v].sort((a, b) => a.id.localeCompare(b.id));
export function canonicalPlanningGraph(state: PlanningState): PlanningState {
  const tasks = (rows: PlanningState['tasks']) => sorted(rows).map((task) => ({ ...task, assigneeIds: [...task.assigneeIds].sort() }));
  return { ...state, phases: sorted(state.phases), milestones: sorted(state.milestones), tasks: tasks(state.tasks),
    snapshots: state.snapshots.map((snapshot) => ({ ...snapshot, phases: sorted(snapshot.phases), milestones: sorted(snapshot.milestones), tasks: tasks(snapshot.tasks), ...(snapshot.blockers ? {blockers:sorted(snapshot.blockers)} : {}) })), ...(state.version === 2 ? {blockers:sorted(state.blockers ?? [])} : {}) };
}
export const planningGraphDigest = (state: PlanningState) => digestObject(canonicalPlanningGraph(state));
export function initialPlanningGraph(creation: z.infer<typeof projectCreateTransition>): PlanningState {
  const b = creation.body.binding;
  return { project: { workspaceId: b.workspaceId, id: b.projectId, revision: '1', state: 'planned', archived: false, phaseLabel: 'wave', managerProfileId: null, teamId: null }, phases: [], milestones: [], tasks: [], snapshots: [], movements: [] };
}
/** Security cleanup is an independently authorized, deterministic projection, never a new business edit. */
export function applyPlanningSecurityCleanup(graph: PlanningState, security: SecurityHistoryState, at: string): PlanningState {
  const eligible = new Set(planningEligibleAssignees(security, graph.project.id, at));
  const reviewers = new Set(planningEligibleReviewers(security, graph.project.id, at));
  const clear = (id: string | null) => id && !eligible.has(id) ? null : id;
  return { ...graph, project: { ...graph.project, managerProfileId: clear(graph.project.managerProfileId) },
    phases: graph.phases.map((p) => ['complete', 'cancelled'].includes(p.state) ? p : { ...p, leadProfileId: clear(p.leadProfileId) }),
    milestones: graph.milestones.map((m) => m.state === 'open' ? { ...m, ownerProfileId: clear(m.ownerProfileId) } : m),
    tasks: graph.tasks.map((t) => {
      const assigneeIds = t.assigneeIds.filter((id) => eligible.has(id));
      return { ...t, assigneeIds, leadProfileId: clear(t.leadProfileId),
        ...(graph.version === 2 && !['done','cancelled'].includes(t.state) ? {reviewerProfileId:t.reviewerProfileId && reviewers.has(t.reviewerProfileId) && !t.assigneeIds.includes(t.reviewerProfileId) ? t.reviewerProfileId : null} : {}),
        ...(graph.version === 2 && t.state === 'review' && assigneeIds.length !== t.assigneeIds.length ? {state:'in_progress' as const,submittedRevision:null,submittedPolicyRevision:null,approvalOperationId:null} : {}) };
    }),
    ...(graph.version === 2 ? {blockers:(graph.blockers ?? []).map((b) => ({...b,responsibleProfileId:clear(b.responsibleProfileId)}))} : {}) };
}
export function planningEligibleAssignees(security: SecurityHistoryState, projectId: string, at: string): string[] {
  return Object.values(security.profiles).filter((p) => p.active && p.scopes.some((s) => s.scope === 'project' && s.scopeId === projectId && s.permissions.includes('read_project') &&
    (s.expiresAt === null || Date.parse(s.expiresAt) > Date.parse(at)))).map((p) => p.accountId).sort();
}
export function planningEligibleReviewers(security: SecurityHistoryState, projectId: string, at: string): string[] {
  const eligible = new Set(planningEligibleAssignees(security,projectId,at));
  return Object.values(security.profiles).filter((p) => eligible.has(p.accountId) && p.scopes.some((s) => s.scope === 'project' && s.scopeId === projectId && (s.expiresAt === null || Date.parse(s.expiresAt) > Date.parse(at)) && (p.owner || s.permissions.includes('approve_tasks')))).map((p) => p.accountId).sort();
}
export function planningAuthority(binding: PlanningBinding): PlanningAuthority {
  return { actor: { workspaceId: binding.workspaceId, accountId: binding.accountId, active: true, isOwner: false },
    // These are ordinary business actions. Effective permissions already include Owner personal rights intersected with this device's signed restrictions.
    eligibleAssigneeIds: binding.eligibleAssigneeIds, ...(binding.version !== 1 ? {eligibleReviewerIds:binding.eligibleReviewerIds,isOwner:binding.isOwner,now:binding.issuedAt} : {}), access: { workspaceId: binding.workspaceId, projectId: binding.projectId, accountId: binding.accountId, state: 'active', keysReady: true, permissions: binding.permissions } };
}
export function verifyPlanningBinding(binding: PlanningBinding, security: SecurityHistoryState): void {
  const p = security.profiles[binding.accountId], d = security.devices[binding.deviceId], key = security.scopeHeads[`project:${binding.projectId}`];
  const available = (scope: { scope: string; scopeId: string; keyEpoch: string; expiresAt: string | null }) => scope.scope === 'project' && scope.scopeId === binding.projectId && scope.keyEpoch === binding.keyEpoch &&
    (scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.parse(binding.issuedAt));
  const personal = p?.scopes.find(available), device = d?.scopes.find(available), role = p ? security.roles[p.projectRoles[binding.projectId]?.id ?? p.role.id] : undefined;
  const permissions = personal?.permissions.filter((permission) => device?.permissions.includes(permission));
  if (security.workspaceId !== binding.workspaceId || security.origin !== binding.origin || security.securityHead !== binding.securityHead || security.securityVersion !== binding.securityVersion ||
    security.dataGeneration !== binding.dataGeneration || !p?.active || !d?.active || d.accountId !== p.accountId || p.owner !== binding.isOwner ||
    p.credentialGeneration !== binding.credentialGeneration || p.sessionGeneration !== binding.sessionGeneration || d.keyGeneration !== binding.keyGeneration ||
    d.signingPublicKey !== binding.signingPublicKey || key?.keyEpoch !== binding.keyEpoch || role?.revision !== binding.permissionVersion ||
    !permissions?.includes('read_project') || !same(permissions, binding.permissions) || !same(binding.eligibleAssigneeIds, planningEligibleAssignees(security, binding.projectId, binding.issuedAt)) || Date.parse(binding.expiresAt) <= Date.parse(binding.issuedAt) ||
    Date.parse(binding.expiresAt) - Date.parse(binding.issuedAt) > 600000 || (binding.version !== 1 && !same(binding.eligibleReviewerIds,planningEligibleReviewers(security,binding.projectId,binding.issuedAt))) ||
    (binding.version===3 ? (security.writeSchema??1)!==2&&!security.activeUpgrade : (security.writeSchema??1)!==1)) throw new Error('Invalid planning authority');
}
export function planningContentHeader(binding: PlanningBinding, kind: ContentEnvelope['header']['recordType'], id: string, revision: string): ContentEnvelope['header'] {
  return { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: binding.workspaceId, scope: 'project', scopeId: binding.projectId,
    recordId: id, recordType: kind, schema: binding.version === 3 ? 2 : 1, keyEpoch: binding.keyEpoch, revision, operationId: binding.operationId, accountId: binding.accountId, deviceId: binding.deviceId,
    keyGeneration: binding.keyGeneration, permissionVersion: binding.permissionVersion, securityVersion: binding.securityVersion, securityHead: binding.securityHead, dataGeneration: binding.dataGeneration,
    action: 'planning.change', approvalPolicyId: null, approvalPolicyRevision: null };
}
export function planningRecordReplacesContent(command: PlanningCommand, kind: PlanningRecord['kind'], id: string): boolean {
  if (command.action === 'upgrade_content') return command.records.some(record => record.kind === kind && record.id === id);
  if (kind === 'task') return command.action === 'create_task' && command.task.id === id || command.action === 'edit_task' && command.taskId === id;
  if (kind === 'blocker') return command.action === 'create_blocker' && command.blocker.id === id || command.action === 'edit_blocker' && command.blockerId === id;
  return true;
}
export function planningEnvelopeRevision(binding: PlanningBinding, command: PlanningCommand,
  ref: { kind: PlanningRecord['kind']; id: string; revision: string; contentRevision?: string }, prior?: PlanningRecord): string {
  if (binding.version !== 3) return ref.contentRevision ?? ref.revision;
  if (planningRecordReplacesContent(command, ref.kind, ref.id)) return ref.revision;
  if (!prior) throw new Error('Missing immutable planning content');
  return prior.envelope.header.revision;
}
export function planningChangedRecords(result: ReturnType<typeof evaluatePlanning>): {kind:PlanningRecord['kind'];id:string;revision:string;contentRevision?:string}[] {
  const rows: {kind:PlanningRecord['kind'];id:string;revision:string;contentRevision?:string}[] = [];
  const add = (kind:PlanningRecord['kind'],row:{id:string;revision:string;contentRevision?:string}) => rows.push({kind,id:row.id,revision:row.revision,...(result.state.version === 2 ? {contentRevision:row.contentRevision ?? row.revision} : {})});
  if (result.changed.project) add('project',result.state.project);
  for (const [kind,records,changed] of [['phase',result.state.phases,result.changed.phaseIds],['milestone',result.state.milestones,result.changed.milestoneIds],['task',result.state.tasks,result.changed.taskIds],['blocker',result.state.blockers ?? [],result.changed.blockerIds ?? []]] as const) {
    for (const id of changed) add(kind,records.find((r) => r.id === id)!);
  }
  return rows.sort((a,b) => `${a.kind}:${a.id}`.localeCompare(`${b.kind}:${b.id}`));
}
export async function validatePlanningPayload(value: unknown, binding: PlanningBinding, graph: PlanningState, currentRecords?: readonly PlanningRecord[]) {
  const payload = planningPayload.parse(value), body = payload.mutation.body;
  if (!same(body.binding, binding) || body.command.operationId !== binding.operationId || !same(body.command.expected, binding.before) ||
    body.nextVersion !== String(BigInt(binding.beforeVersion) + 1n) || binding.beforeGraphDigest !== await planningGraphDigest(graph) ||
    (binding.version !== 1) !== (graph.version === 2) || body.purpose !== `ukda.planning-mutation.v${binding.version}` ||
    !await verifyObject(payload.mutation, base64urlDecode(binding.signingPublicKey), body.purpose)) throw new Error('Invalid planning mutation');
  const result = evaluatePlanning(graph, body.command, planningAuthority(binding)), expected = planningChangedRecords(result);
  if (body.purpose !== 'ukda.planning-mutation.v1' && body.closingSettings &&
    (!result.snapshot || body.closingSettings.workspaceId !== binding.workspaceId)) throw new Error('Invalid closing settings');
  if (body.afterGraphDigest !== await planningGraphDigest(result.state) || expected.length !== payload.records.length || expected.length !== body.records.length ||
    new Set(payload.records.map((r) => `${r.kind}:${r.id}`)).size !== payload.records.length) throw new Error('Incomplete planning mutation');
  for (let i = 0; i < expected.length; i++) {
    const ref = expected[i]!, record = payload.records.find((r) => r.kind === ref.kind && r.id === ref.id), hash = record ? await digestObject(record.envelope) : '';
    const prior = currentRecords?.find((r) => r.kind === ref.kind && r.id === ref.id), envelopeRevision = planningEnvelopeRevision(binding,body.command,ref,prior);
    if (!record || !same(body.records[i], { ...ref, ...(binding.version === 3 ? {envelopeRevision} : {}), digest: hash })) throw new Error('Invalid planning ciphertext');
    if (binding.version !== 1 && !planningRecordReplacesContent(body.command,ref.kind,ref.id)) {
      if (!prior || !same(record.envelope,prior.envelope) || record.envelope.header.revision !== envelopeRevision) throw new Error('Replaced immutable task content');
    } else if (!await verifyContentEnvelope(record.envelope,base64urlDecode(binding.signingPublicKey),planningContentHeader(binding,ref.kind,ref.id,envelopeRevision))) throw new Error('Invalid planning ciphertext');
  }
  if (body.command.action === 'upgrade_content') {
    if (body.purpose !== 'ukda.planning-mutation.v3' || !body.upgrade || !payload.upgradeItems || !currentRecords) throw new Error('Missing signed content upgrade');
    const upgraded = await validateUpgradeItems(body.upgrade,payload.upgradeItems);
    if (upgraded.items.length !== expected.length) throw new Error('Incomplete content upgrade');
    for (const item of upgraded.items) {
      const record = currentRecords.find(record => record.kind === item.source.kind && record.id === item.source.id);
      const target = payload.records.find(record => record.kind === item.target.kind && record.id === item.target.id);
      if (!record || !target || !same(record.envelope,item.sourceEnvelope) || !same(target.envelope,item.envelope) ||
        !same(await planningUpgradeReference(graph,record),item.source)) throw new Error('Changed upgrade source');
      await verifyUpgradeItem(item,record.envelope,planningContentHeader(binding,record.kind,record.id,item.target.envelopeRevision),base64urlDecode(binding.signingPublicKey));
    }
  } else if (payload.upgradeItems || body.purpose === 'ukda.planning-mutation.v3' && body.upgrade) throw new Error('Unexpected content upgrade');
  if (payload.audit.id === payload.outcome?.id || payload.records.some((r) => r.id === payload.audit.id || r.id === payload.outcome?.id)) throw new Error('Reused planning object');
  for (const [kind, object, reference] of [['audit', payload.audit, body.audit], ['update', payload.outcome, body.outcome]] as const) {
    if ((object === null) !== (reference === null)) throw new Error('Missing planning object');
    if (object && (!reference || reference.id !== object.id || reference.digest !== await digestObject(object.envelope) ||
      !await verifyContentEnvelope(object.envelope, base64urlDecode(binding.signingPublicKey), planningContentHeader(binding, kind, object.id, '1')))) throw new Error('Invalid planning object');
  }
  const reason = 'outcome' in body.command ? body.command.outcome : null;
  if (reason ? !payload.outcome || !same(reason, { recordId: payload.outcome.id, revision: '1', digest: body.outcome?.digest }) : payload.outcome !== null) throw new Error('Invalid outcome binding');
  return { payload, result };
}
export async function planningUpgradeReference(graph: PlanningState, record: PlanningRecord) {
  const row = record.kind === 'project' ? graph.project.id === record.id ? graph.project : undefined :
    record.kind === 'phase' ? graph.phases.find(row => row.id === record.id) : record.kind === 'milestone' ? graph.milestones.find(row => row.id === record.id) :
    record.kind === 'task' ? graph.tasks.find(row => row.id === record.id) : graph.blockers?.find(row => row.id === record.id);
  if (!row) throw new Error('Missing upgrade source');
  return { kind:record.kind,id:record.id,projectId:graph.project.id,revision:row.revision,
    contentRevision:'contentRevision' in row ? row.contentRevision! : null,envelopeRevision:record.envelope.header.revision,
    schema:record.envelope.header.schema,keyEpoch:record.envelope.header.keyEpoch,digest:await digestObject(record.envelope) };
}
export type PlanningSecurityResolver = (version: string, head?: string) => Promise<SecurityHistoryState>;
async function cleanupThrough(graph: PlanningState, fromVersion: string, target: SecurityHistoryState, at: string, securityAt: PlanningSecurityResolver) {
  if (BigInt(target.securityVersion) < BigInt(fromVersion)) throw new Error('Reordered security history');
  for (let version = BigInt(fromVersion) + 1n; version < BigInt(target.securityVersion); version++) {
    const intermediate = await securityAt(version.toString());
    if (intermediate.workspaceId !== target.workspaceId || intermediate.securityVersion !== version.toString()) throw new Error('Invalid security cleanup history');
    graph = applyPlanningSecurityCleanup(graph, intermediate, '1970-01-01T00:00:00.000Z');
  }
  return applyPlanningSecurityCleanup(graph, target, at);
}
interface VerifiedPlanningReplay { graph:PlanningState; head:string; version:string; securityVersion:string;
  records:Map<string,{revision:string;digest:string}>; operationIds:Set<string>; fingerprints:string[] }
const replayCache=new Map<string,VerifiedPlanningReplay>();
async function replayFingerprint(mutation:PlanningMutation):Promise<string> {
  // Schema parsing normalizes property order. This private cache fingerprint can
  // therefore use ordinary JSON; public lineage hashes/signatures still use the
  // original canonical protocol. Re-fingerprinting rejects every changed prefix.
  const bytes=new TextEncoder().encode(JSON.stringify(mutation)),hash=new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',bytes));
  return Array.from(hash,byte=>byte.toString(16).padStart(2,'0')).join('');
}
/** Explicit lifecycle invalidation is useful for Worker logout; cache entries contain metadata only. */
export function clearPlanningReplayCache():void {replayCache.clear();}
/** Replays every signed operation from authenticated creation, detecting omitted children/history. */
export async function verifyPlanningContext(value: unknown, securityAt: PlanningSecurityResolver): Promise<PlanningContext> {
  const context = planningContext.parse(value), b = context.binding, creation = context.creation;
  const created = await securityAt(creation.body.binding.nextSecurityVersion, await digestObject(creation));
  if (created.workspaceId !== b.workspaceId || creation.body.binding.projectId !== b.projectId || !creation.body.project) throw new Error('Invalid project origin');
  const creationHead=await digestObject(creation),cacheKey=`${b.origin}:${b.workspaceId}:${b.projectId}:${b.dataGeneration}:${creationHead}`;
  const cached=replayCache.get(cacheKey),fingerprints:string[]=[];
  let graph = initialPlanningGraph(creation), head = creationHead, version = '0', securityVersion = created.securityVersion;
  let records = new Map<string, { revision: string; digest: string }>([[`project:${b.projectId}`, { revision: '1', digest: creation.body.project.digest }]]),seen=new Set<string>(),offset=0;
  if(cached&&cached.fingerprints.length<=context.history.length) {
    for(let i=0;i<cached.fingerprints.length;i++) {const supplied=await replayFingerprint(context.history[i]!);if(supplied!==cached.fingerprints[i])throw new Error('Changed verified planning prefix');fingerprints.push(supplied);}
    graph=structuredClone(cached.graph);head=cached.head;version=cached.version;securityVersion=cached.securityVersion;
    records=new Map(cached.records);seen=new Set(cached.operationIds);offset=cached.fingerprints.length;
  }
  for (const mutation of context.history.slice(offset)) {
    const body = mutation.body, prior = body.binding;
    if (prior.workspaceId !== b.workspaceId || prior.projectId !== b.projectId || prior.beforeVersion !== version || prior.beforeHead !== head || seen.has(prior.operationId)) throw new Error('Incomplete planning chain');
    seen.add(prior.operationId);
    const security = await securityAt(prior.securityVersion, prior.securityHead); verifyPlanningBinding(prior, security);
    if (security.activeUpgrade && body.command.action!=='upgrade_content') throw new Error('Ordinary planning write during content maintenance');
    if (body.command.action==='upgrade_content' && (body.purpose!=='ukda.planning-mutation.v3'||!body.upgrade||
      security.activeUpgrade?.migrationId!==body.upgrade.migrationId||security.activeUpgrade.manifestDigest!==body.upgrade.manifestDigest)) throw new Error('Upgrade outside authenticated migration');
    if (prior.version !== 1) graph = upgradePlanningGraph(graph);
    else if (graph.version === 2) throw new Error('Planning protocol downgrade');
    graph = await cleanupThrough(graph, securityVersion, security, prior.issuedAt, securityAt); securityVersion = security.securityVersion;
    const reason = 'outcome' in body.command ? body.command.outcome : null;
    if (security.licenceState !== 'active' || security.entitlementState !== 'activated' || (reason ? !body.outcome || !same(reason, { recordId: body.outcome.id, revision: '1', digest: body.outcome.digest }) : body.outcome !== null)) throw new Error('Invalid historical planning authority or outcome');
    if (prior.beforeGraphDigest !== await planningGraphDigest(graph) || !same(prior.before, planningRevisionSnapshot(graph)) ||
      body.command.operationId !== prior.operationId || !same(body.command.expected, prior.before) ||
      body.nextVersion !== String(BigInt(version) + 1n) || !await verifyObject(mutation, base64urlDecode(prior.signingPublicKey), body.purpose)) throw new Error('Invalid planning chain');
    const result = evaluatePlanning(graph, body.command, planningAuthority(prior)), refs = planningChangedRecords(result);
    if (body.purpose !== 'ukda.planning-mutation.v1' && body.closingSettings &&
      (!result.snapshot || body.closingSettings.workspaceId !== prior.workspaceId)) throw new Error('Invalid historical closing settings');
    if (body.afterGraphDigest !== await planningGraphDigest(result.state) || refs.length !== body.records.length ||
      refs.some((ref, i) => { const actual = body.records[i]!; return !same(ref, {kind:actual.kind,id:actual.id,revision:actual.revision,...('contentRevision' in actual ? {contentRevision:actual.contentRevision} : {})}) ||
        prior.version === 3 && (!('envelopeRevision' in actual) || actual.envelopeRevision !== (planningRecordReplacesContent(body.command,ref.kind,ref.id) ? ref.revision : records.get(`${ref.kind}:${ref.id}`)?.revision)); })) throw new Error('Invalid planning result');
    if (body.command.action === 'upgrade_content') {
      const saved = context.upgrades?.filter(upgrade => upgrade.operationId === prior.operationId);
      if (body.purpose !== 'ukda.planning-mutation.v3' || !body.upgrade || saved?.length !== 1) throw new Error('Missing historical upgrade proof');
      const upgraded = await validateUpgradeItems(body.upgrade,saved[0]!.items);
      if (upgraded.items.length !== refs.length) throw new Error('Incomplete historical upgrade');
      for (const item of upgraded.items) {
        const old = records.get(`${item.source.kind}:${item.source.id}`), target = body.records.find(ref => ref.kind === item.target.kind && ref.id === item.target.id);
        const sourceRecord = planningRecord.parse({kind:item.source.kind,id:item.source.id,envelope:item.sourceEnvelope});
        if (!security.activeUpgrade?.manifest.some(source=>source.kind===item.source.kind&&source.id===item.source.id&&source.projectId===item.source.projectId) || !old || old.digest !== item.source.digest || old.revision !== item.source.envelopeRevision ||
          !same(await planningUpgradeReference(graph,sourceRecord),item.source) || !target || target.digest !== item.target.digest || target.revision !== item.target.revision ||
          !('envelopeRevision' in target) || target.envelopeRevision !== item.target.envelopeRevision) throw new Error('Invalid historical upgrade source');
        await verifyPlanningRecordProducer(context,sourceRecord,old);
        await verifyUpgradeItem(item,item.sourceEnvelope,planningContentHeader(prior,sourceRecord.kind,sourceRecord.id,item.target.envelopeRevision),base64urlDecode(prior.signingPublicKey));
      }
    } else if (body.purpose === 'ukda.planning-mutation.v3' && body.upgrade) throw new Error('Unexpected historical upgrade');
    for (const ref of body.records) {
      const contentRevision = 'envelopeRevision' in ref ? ref.envelopeRevision : 'contentRevision' in ref ? ref.contentRevision : ref.revision;
      if (prior.version !== 1 && !planningRecordReplacesContent(body.command,ref.kind,ref.id)) {
        const previous = records.get(`${ref.kind}:${ref.id}`);
        if (!previous || previous.digest !== ref.digest || previous.revision !== contentRevision) throw new Error('Replaced historical task content');
      }
      records.set(`${ref.kind}:${ref.id}`, { revision: contentRevision, digest: ref.digest });
    }
    graph = result.state; head = await digestObject(mutation); fingerprints.push(await replayFingerprint(mutation)); version = body.nextVersion;
  }
  const candidate:VerifiedPlanningReplay={graph:structuredClone(graph),head,version,securityVersion,records:new Map(records),operationIds:new Set(seen),fingerprints};
  const security = await securityAt(b.securityVersion, b.securityHead); verifyPlanningBinding(b, security);
  if (b.version !== 1) graph = upgradePlanningGraph(graph);
  else if (graph.version === 2) throw new Error('Planning protocol downgrade');
  graph = await cleanupThrough(graph, securityVersion, security, b.issuedAt, securityAt);
  if (b.beforeHead !== head || b.beforeVersion !== version || b.beforeGraphDigest !== await planningGraphDigest(graph) ||
    b.beforeGraphDigest !== await planningGraphDigest(context.graph) || !same(b.before, planningRevisionSnapshot(graph)) || records.size !== context.records.length) throw new Error('Incomplete planning context');
  for (const record of context.records) {
    const ref = records.get(`${record.kind}:${record.id}`);
    if (!ref || ref.revision !== record.envelope.header.revision || ref.digest !== await digestObject(record.envelope)) throw new Error('Invalid current planning record');
    await verifyPlanningRecordProducer(context,record,ref);
    records.delete(`${record.kind}:${record.id}`);
  }
  const upgradeIds=context.history.filter(m=>m.body.command.action==='upgrade_content').map(m=>m.body.binding.operationId);
  if ((context.upgrades?.length ?? 0)!==upgradeIds.length || context.upgrades?.some(entry=>!upgradeIds.includes(entry.operationId))) throw new Error('Incomplete planning upgrade history');
  for (const [kind, objects] of [['audit', context.audits], ['outcome', context.outcomes]] as const) {
    const refs = context.history.map((m) => ({ ref: m.body[kind], binding: m.body.binding })).filter((item) => item.ref !== null),byId=new Map(refs.map(ref=>[ref.ref!.id,ref]));
    if (refs.length !== objects.length || new Set(objects.map((o) => o.id)).size !== objects.length) throw new Error('Incomplete planning history objects');
    for (const object of objects) { const known = byId.get(object.id);
      if (!known || known.ref!.digest !== await digestObject(object.envelope) || !await verifyContentEnvelope(object.envelope, base64urlDecode(known.binding.signingPublicKey), planningContentHeader(known.binding, kind === 'audit' ? 'audit' : 'update', object.id, '1'))) throw new Error('Invalid historical planning object'); }
  }
  for (const material of context.materials) if (material.digest !== await digestObject(material.value)) throw new Error('Invalid planning material');
  if(replayCache.size>=8&&!replayCache.has(cacheKey))replayCache.delete(replayCache.keys().next().value!);
  replayCache.delete(cacheKey);replayCache.set(cacheKey,candidate);
  return context;
}
async function verifyPlanningRecordProducer(context: PlanningContext,record: PlanningRecord,ref:{revision:string;digest:string}):Promise<void> {
  const creation=context.creation;
  if (record.kind==='project' && record.envelope.header.operationId===creation.body.binding.operationId) {
    if (ref.digest!==creation.body.project?.digest || !await verifyContentEnvelope(record.envelope,base64urlDecode(creation.body.binding.authorizer.device.signingPublicKey),projectCreateHeader(creation.body.binding))) throw new Error('Invalid creation ciphertext');
    return;
  }
  const producer=context.history.find(m=>m.body.binding.operationId===record.envelope.header.operationId),produced=producer?.body.records.find(r=>r.kind===record.kind&&r.id===record.id);
  if (!producer||!produced||produced.digest!==ref.digest||
    producer.body.binding.version!==1&&!planningRecordReplacesContent(producer.body.command,record.kind,record.id)||
    !await verifyContentEnvelope(record.envelope,base64urlDecode(producer.body.binding.signingPublicKey),planningContentHeader(producer.body.binding,record.kind,record.id,ref.revision))) throw new Error('Invalid planning content producer');
}

import { z } from 'zod';
import { binary } from '../shared/contracts.js';
import { base64urlDecode, canonicalJson, decryptContent, digestObject, encryptContent, signObject } from '../shared/crypto.js';
import { projectPrivateData, projectCreateHeader } from '../shared/project-create.js';
import { planningCommand, planningContentHeader, planningChangedRecords, planningGraphDigest, planningPayload,
  planningAuthority, planningRecordReplacesContent, validatePlanningPayload, verifyPlanningContext, type PlanningContext, type PlanningPayload, type PlanningRecord } from '../shared/planning-api.js';
import { planningEnvelopeRevision, planningRecord, planningUpgradeReference } from '../shared/planning-api.js';
import { CONTENT_TRANSFORM_1_TO_2, transformContentData1To2 } from '../shared/content-schema.js';
import { upgradeProof, type UpgradeItem } from '../shared/encrypted-upgrades.js';
import { evaluatePlanning, type PlanningCommand, type PlanningState, type PlanningClosingSnapshot } from '../shared/planning.js';
import { verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState } from '../shared/security-history.js';
import type { DeviceBundle } from './device-store.js';
import type { PairingScope } from '../shared/pairing.js';
import { readDeviceScopeKeyMaterial } from './pairing.js';
import { planningPin, type PlanningPin } from './planning-store.js';
import { closingSettings, type ClosingSettings } from '../shared/closing-settings.js';
import { readReportingSettings, type ReadReportingSettingsInput } from './reporting-settings-crypto.js';

const dates = (v: { startDate?: string | undefined; dueDate?: string | undefined }) => !v.startDate || !v.dueDate || v.startDate <= v.dueDate;
export const phasePrivateData = z.strictObject({ name: z.string().trim().min(1).max(240), objective: z.string().max(20000).default(''),
  startDate: z.iso.date().optional(), dueDate: z.iso.date().optional(), completionCriteria: z.string().max(20000).default('') }).refine(dates);
export const milestonePrivateData = z.strictObject({ name: z.string().trim().min(1).max(240), dueDate: z.iso.date().optional() });
export const taskPrivateData = z.strictObject({ title: z.string().trim().min(1).max(240), description: z.string().max(20000).default(''),
  dueDate: z.iso.date().optional(), startDate: z.iso.date().optional(), priority: z.enum(['low', 'normal', 'high']).optional(),
  acceptanceCriteria: z.string().max(20000).default('') }).refine(dates);
export const blockerPrivateData = z.strictObject({ reason: z.string().trim().min(1).max(20000), nextAction: z.string().trim().min(1).max(20000) });
export type PlanningPrivateContent = z.input<typeof projectPrivateData> | z.input<typeof phasePrivateData> | z.input<typeof milestonePrivateData> | z.input<typeof taskPrivateData> | z.input<typeof blockerPrivateData>;
type OmitCommand<T> = T extends unknown ? Omit<T, 'operationId' | 'expected' | 'outcome'> : never;
export type PlanningIntent = OmitCommand<PlanningCommand>;
export class PlanningClientError extends Error {
  constructor(readonly code: 'INVALID_PLANNING' | 'INCOMPLETE_KEYS' | 'TRUST_REQUIRED' | 'CONFLICT' | 'EXPIRED' | 'NOT_FOUND' | 'CANCELLED' | 'STORAGE') {
    super(`Planning failed (${code})`); this.name = 'PlanningClientError';
  }
}
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
function invalid(): never { throw new PlanningClientError('INVALID_PLANNING'); }
const outcomeData = z.strictObject({ text: z.string().trim().min(1).max(20000) });
export interface ReadPlanningInput { context: PlanningContext; history: SecurityHistoryInput; accountId: string; deviceId: string; pin?: PlanningPin }
export interface PreparePlanningInput extends ReadPlanningInput { command: PlanningIntent; content?: PlanningPrivateContent; outcome?: string; closingSettings?: ReadReportingSettingsInput; upgrade?: {migrationId:string;manifestDigest:string} }
export interface ReadablePlanningRecord { kind: PlanningRecord['kind']; id: string; revision: string; contentRevision?: string; envelopeRevision?:string; content: Record<string, unknown> }
export interface PlanningAuditData { version: 1; action: PlanningCommand['action']; changed: { kind: PlanningRecord['kind']; id: string; before: Record<string, unknown> | null; after: Record<string, unknown> }[];
  snapshot: PlanningClosingSnapshot | null; snapshotContents: ReadablePlanningRecord[]; closingSettings?: ClosingSettings }
export interface ReadablePlanningAudit { id: string; actorId: string; deviceId: string; operationId: string; signedAt: string; closingSettings: ClosingSettings | null; outcome: string | null; data: PlanningAuditData }
/** Current verified presentation authority. Server and Worker policy still gate each write. */
export interface ReadablePlanningAuthority {
  accountId: string; isOwner: boolean; permissions: PlanningContext['binding']['permissions'];
  eligibleAssigneeIds: string[]; eligibleReviewerIds: string[];
}
export interface ReadablePlanning { graph: PlanningState; records: ReadablePlanningRecord[]; pin: PlanningPin;
  outcomes: { id: string; text: string }[]; audits: ReadablePlanningAudit[]; authority: ReadablePlanningAuthority }
function parseContent(kind: PlanningRecord['kind'], value: unknown): Record<string, unknown> {
  if (kind === 'project') return projectPrivateData.parse(value);
  if (kind === 'phase') return phasePrivateData.parse(value);
  if (kind === 'milestone') return milestonePrivateData.parse(value);
  if (kind === 'blocker') return blockerPrivateData.parse(value);
  return taskPrivateData.parse(value);
}
function pinFor(c: PlanningContext): PlanningPin { const b = c.binding; return { workspaceId: b.workspaceId, projectId: b.projectId,
  dataGeneration: b.dataGeneration, version: b.beforeVersion, head: b.beforeHead }; }
function checkPin(pin: PlanningPin | undefined, current: PlanningPin): void {
  if (!pin) return; const prior = planningPin.parse(pin);
  if (prior.workspaceId !== current.workspaceId || prior.projectId !== current.projectId || BigInt(current.dataGeneration) < BigInt(prior.dataGeneration) ||
    prior.dataGeneration === current.dataGeneration && (BigInt(current.version) < BigInt(prior.version) || current.version === prior.version && current.head !== prior.head)) invalid();
}
export function planningSecurityResolver(history: SecurityHistoryInput, current: SecurityHistoryState) {
  const cache = new Map<string, Promise<SecurityHistoryState>>([[`${current.securityVersion}:${current.securityHead}`, Promise.resolve(current)]]);
  return async (version: string, requestedHead?: string) => {
    if (BigInt(version) > BigInt(current.securityVersion) || BigInt(version) < 1n) invalid();
    const offset = Number(BigInt(version) - 1n);
    if (!Number.isSafeInteger(offset) || offset > history.transitions.length) invalid();
    const head = requestedHead ?? await digestObject(offset === 0 ? history.genesis : history.transitions[offset - 1]);
    const key = `${version}:${head}`; let promise = cache.get(key);
    if (!promise) {
      if (BigInt(version) > BigInt(current.securityVersion) || BigInt(version) < 1n) invalid();
      const length = Number(BigInt(version) - 1n); if (!Number.isSafeInteger(length) || length > history.transitions.length) invalid();
      const { pin: _pin, ...base } = history;
      promise = verifySecurityHistory({ ...base, transitions: history.transitions.slice(0, length), expected: { securityVersion: version, securityHead: head } }); cache.set(key, promise);
    }
    return promise;
  };
}
async function projectRing(context: PlanningContext, state: SecurityHistoryState, accountId: string, deviceId: string, bundle: DeviceBundle) {
  const b = context.binding, profile = state.profiles[accountId], device = state.devices[deviceId];
  const eligible = (scope: { scope: string; scopeId: string; keyEpoch: string; permissions: string[]; expiresAt: string | null }) => scope.scope === 'project' && scope.scopeId === b.projectId &&
    scope.keyEpoch === b.keyEpoch && scope.permissions.includes('read_project') && (scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.now());
  const personal = profile?.scopes.find(eligible), approved = device?.scopes.find(eligible);
  if (!profile?.active || !device?.active || device.accountId !== accountId || !personal || !approved ||
    bundle.signingPublicKey !== device.signingPublicKey || bundle.recipientPublicKey !== device.recipientPublicKey) invalid();
  const scope: PairingScope = { scope: 'project', scopeId: b.projectId, mode: 'content', keyEpoch: b.keyEpoch,
    permissions: approved.permissions.filter((permission) => personal.permissions.includes(permission)), expiresAt: approved.expiresAt,
    sources: approved.manifests.filter((ref) => context.materials.some((m) => m.id === ref.id && m.digest === ref.digest))
      .map((ref) => ({ grantId: deviceId, generation: device.keyGeneration, manifestId: ref.id, manifestDigest: ref.digest })) };
  if (!scope.sources.length) throw new PlanningClientError('INCOMPLETE_KEYS');
  const [value] = await readDeviceScopeKeyMaterial({ scopes: [scope], history: state, materials: context.materials, holder: { workspaceId: b.workspaceId,
    custodyEpoch: state.custodyEpoch, approverAccountId: accountId, approverDevice: { id: device.id, keyGeneration: device.keyGeneration,
      signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey } } }, bundle);
  return z.strictObject({ version: z.literal(1), mode: z.literal('content'), scope: z.literal('project'), scopeId: z.literal(b.projectId), keyEpoch: z.literal(b.keyEpoch),
    keys: z.array(z.strictObject({ epoch: z.string(), key: binary(32) })).min(1) }).parse(value).keys;
}
/** Internal Worker helper shared by planning and collaboration; never exposed through the browser entry point. */
export async function openVerifiedPlanning(value: ReadPlanningInput, bundle: DeviceBundle) {
  const input = copy(value), state = await verifySecurityHistory(input.history), context = await verifyPlanningContext(input.context, planningSecurityResolver(input.history, state)), b = context.binding;
  if (b.accountId !== input.accountId || b.deviceId !== input.deviceId || b.securityHead !== state.securityHead || b.securityVersion !== state.securityVersion ||
    b.signingPublicKey !== bundle.signingPublicKey || Date.parse(b.issuedAt) > Date.now() + 30000) invalid();
  checkPin(input.pin, pinFor(context));
  const ring = await projectRing(context, state, input.accountId, input.deviceId, bundle);
  const decrypt = async (envelope: PlanningRecord['envelope'], header: PlanningRecord['envelope']['header'], signingPublicKey: string) => {
    const entry = ring.find((key) => key.epoch === header.keyEpoch); if (!entry) throw new PlanningClientError('INCOMPLETE_KEYS');
    const key = base64urlDecode(entry.key, 32);
    try { return await decryptContent(envelope, key, base64urlDecode(signingPublicKey, 32), header); } finally { key.fill(0); }
  };
  const records: ReadablePlanningRecord[] = [];
  const decryptRecord = async (record:PlanningRecord):Promise<Record<string,unknown>> => {
    const envelopeDigest=await digestObject(record.envelope),mutation=context.history.find(m=>m.body.binding.operationId===record.envelope.header.operationId&&m.body.records.some(r=>r.id===record.id&&r.kind===record.kind&&r.digest===envelopeDigest));
    const header=mutation?planningContentHeader(mutation.body.binding,record.kind,record.id,record.envelope.header.revision):projectCreateHeader(context.creation.body.binding);
    if (!mutation&&(record.kind!=='project'||record.id!==b.projectId||record.envelope.header.revision!=='1')) invalid();
    const signer=mutation?.body.binding.signingPublicKey??context.creation.body.binding.authorizer.device.signingPublicKey;
    const content=await decrypt(record.envelope,header,signer);parseContent(record.kind,content);
    return content as Record<string,unknown>;
  };
  for (const upgrade of context.upgrades??[]) for (const item of upgrade.items) {
    const source=await decryptRecord(planningRecord.parse({kind:item.source.kind,id:item.source.id,envelope:item.sourceEnvelope}));
    const target=await decryptRecord(planningRecord.parse({kind:item.target.kind,id:item.target.id,envelope:item.envelope}));
    if (!same(source,target)) invalid();
  }
  for (const record of context.records) {
    const envelopeDigest = await digestObject(record.envelope);
    // Metadata-only task writes retain their original content author and ciphertext.
    const mutation = context.history.find((m) => m.body.binding.operationId === record.envelope.header.operationId &&
      m.body.records.some((r) => r.id === record.id && r.kind === record.kind && r.digest === envelopeDigest));
    const header = mutation ? planningContentHeader(mutation.body.binding, record.kind, record.id, record.envelope.header.revision) : projectCreateHeader(context.creation.body.binding);
    if (!mutation && (record.kind !== 'project' || record.id !== b.projectId || record.envelope.header.revision !== '1')) invalid();
    const signer = mutation?.body.binding.signingPublicKey ?? context.creation.body.binding.authorizer.device.signingPublicKey;
    const row = record.kind === 'project' ? context.graph.project :
      (record.kind === 'phase' ? context.graph.phases : record.kind === 'milestone' ? context.graph.milestones : record.kind === 'blocker' ? context.graph.blockers ?? [] : context.graph.tasks).find((row) => row.id === record.id);
    if (!row) invalid();
    records.push({ kind: record.kind, id: record.id, revision: row.revision, contentRevision: 'contentRevision' in row ? row.contentRevision! : row.revision,
      ...(record.envelope.header.schema===2?{envelopeRevision:record.envelope.header.revision}:{}),
      content: parseContent(record.kind, await decrypt(record.envelope, header, signer)) });
  }
  const outcomes: ReadablePlanning['outcomes'] = [], audits: ReadablePlanning['audits'] = [];
  const outcomeObjects = new Map(context.outcomes.map((object) => [object.id, object])), auditObjects = new Map(context.audits.map((object) => [object.id, object]));
  // Signed chain sequence is authoritative; storage/transport object ordering is not.
  for (const mutation of context.history) {
    if (!mutation.body.outcome) continue;
    const object = outcomeObjects.get(mutation.body.outcome.id); if (!object) invalid();
    const text = outcomeData.parse(await decrypt(object.envelope, planningContentHeader(mutation.body.binding, 'update', object.id, '1'), mutation.body.binding.signingPublicKey)).text;
    outcomes.push({ id: object.id, text });
  }
  for (const mutation of context.history) {
    const object = auditObjects.get(mutation.body.audit.id); if (!object) invalid();
    const data = await decrypt(object.envelope, planningContentHeader(mutation.body.binding, 'audit', object.id, '1'), mutation.body.binding.signingPublicKey) as PlanningAuditData;
    if (!data || data.version !== 1 || data.action !== mutation.body.command.action || !Array.isArray(data.changed) || !Array.isArray(data.snapshotContents) ||
      !same(data.snapshot, context.graph.snapshots.find((snapshot) => snapshot.operationId === mutation.body.binding.operationId) ?? null)) invalid();
    if (!same(data.changed.map((r) => ({ kind: r.kind, id: r.id })), mutation.body.records.map((r) => ({ kind: r.kind, id: r.id })))) invalid();
    for (const change of data.changed) { parseContent(change.kind, change.after); if (change.before !== null) parseContent(change.kind, change.before); }
    if (!data.snapshot && data.snapshotContents.length) invalid();
    if (data.snapshot) {
      const refs = [{ kind: 'project', row: data.snapshot.project }, ...data.snapshot.phases.map((row) => ({ kind: 'phase', row })),
        ...data.snapshot.milestones.map((row) => ({ kind: 'milestone', row })), ...data.snapshot.tasks.map((row) => ({ kind: 'task', row })),
        ...(data.snapshot.blockers ?? []).map((row) => ({ kind: 'blocker', row }))];
      if (refs.length !== data.snapshotContents.length || new Set(data.snapshotContents.map((r) => `${r.kind}:${r.id}`)).size !== refs.length) invalid();
      for (const ref of refs) { const saved = data.snapshotContents.find((r) => r.kind === ref.kind && r.id === ref.row.id);
        if (!saved || saved.revision !== ref.row.revision) invalid(); parseContent(saved.kind, saved.content); }
    }
    const binding = mutation.body.binding;
    const stamp = 'closingSettings' in mutation.body ? mutation.body.closingSettings ?? null : null;
    if (stamp ? !same(data.closingSettings, stamp) : data.closingSettings !== undefined) invalid();
    audits.push({ id: object.id, actorId: binding.accountId, deviceId: binding.deviceId, operationId: binding.operationId, signedAt: binding.issuedAt, closingSettings: stamp,
      outcome: mutation.body.outcome ? outcomes.find(row => row.id === mutation.body.outcome!.id)!.text : null, data });
  }
  const authority: ReadablePlanningAuthority = { accountId: b.accountId, isOwner: b.isOwner,
    permissions: [...b.permissions], eligibleAssigneeIds: [...b.eligibleAssigneeIds],
    eligibleReviewerIds: b.version === 1 ? [] : [...b.eligibleReviewerIds] };
  return { context, state, ring, decryptRecord, readable: { graph: context.graph, records, outcomes, audits, pin: pinFor(context), authority } satisfies ReadablePlanning };
}
/** Returns authorised plaintext for presentation only; the caller must not persist it. */
export async function readPlanning(input: ReadPlanningInput, bundle: DeviceBundle): Promise<ReadablePlanning> { return (await openVerifiedPlanning(input, bundle)).readable; }
export async function preparePlanning(value: PreparePlanningInput, bundle: DeviceBundle): Promise<PlanningPayload> {
  const input = copy(value), { context, state, ring, readable, decryptRecord } = await openVerifiedPlanning(input, bundle), b = context.binding;
  if (Date.parse(b.expiresAt) <= Date.now()) throw new PlanningClientError('EXPIRED');
  if (state.licenceState !== 'active' || state.entitlementState !== 'activated') invalid();
  const entry = ring.find((key) => key.epoch === b.keyEpoch); if (!entry) throw new PlanningClientError('INCOMPLETE_KEYS');
  const key = base64urlDecode(entry.key, 32), signing = base64urlDecode(bundle.signingPrivateKey, 64), publicKey = base64urlDecode(bundle.signingPublicKey, 32);
  const seal = async (kind: PlanningRecord['kind'] | 'audit' | 'update', id: string, revision: string, plaintext: unknown) => {
    const header = planningContentHeader(b, kind, id, revision), envelope = await encryptContent(header, plaintext, key, signing);
    if (!same(await decryptContent(envelope, key, publicKey, header), plaintext)) invalid(); return envelope;
  };
  try {
    const needsOutcome = ['complete_project', 'cancel_project', 'complete_phase', 'cancel_phase', 'accept_milestone', 'cancel_milestone', 'carry_task',
      'reject_task', 'cancel_task', 'reopen_task', 'restore_task', 'set_project_review', 'resolve_blocker', 'reopen_blocker'].includes(input.command.action);
    let outcome: PlanningPayload['outcome'] = null;
    if (needsOutcome) { const text = outcomeData.parse({ text: input.outcome }); const id = crypto.randomUUID(); outcome = { id, envelope: await seal('update', id, '1', text) }; }
    else if (input.outcome !== undefined) invalid();
    const command = planningCommand.parse({ ...input.command, operationId: b.operationId, expected: b.before,
      ...(outcome ? { outcome: { recordId: outcome.id, revision: '1', digest: await digestObject(outcome.envelope) } } : {}) }),
      result = evaluatePlanning(context.graph, command, planningAuthority(b)), changed = planningChangedRecords(result), records: PlanningPayload['records'] = [],
      contents = new Map(readable.records.map((record) => [`${record.kind}:${record.id}`, record]));
    const target = command.action === 'edit_project' ? { kind: 'project' as const, id: b.projectId } : command.action === 'create_phase' ? { kind: 'phase' as const, id: command.phase.id } :
      command.action === 'edit_phase' ? { kind: 'phase' as const, id: command.phaseId } : command.action === 'create_milestone' ? { kind: 'milestone' as const, id: command.milestone.id } :
      command.action === 'edit_milestone' ? { kind: 'milestone' as const, id: command.milestoneId } :
      command.action === 'create_task' ? { kind: 'task' as const, id: command.task.id } : command.action === 'edit_task' ? { kind: 'task' as const, id: command.taskId } :
      command.action === 'create_blocker' ? { kind: 'blocker' as const, id: command.blocker.id } : command.action === 'edit_blocker' ? { kind: 'blocker' as const, id: command.blockerId } : undefined;
    if (input.content !== undefined && !target || ['create_phase', 'create_milestone', 'create_task', 'edit_task', 'create_blocker', 'edit_blocker'].includes(command.action) && input.content === undefined) invalid();
    const audited: PlanningAuditData['changed'] = [], upgradeItems:UpgradeItem[]=[];
    if ((command.action==='upgrade_content')!==(input.upgrade!==undefined)||command.action==='upgrade_content'&&b.version!==3) invalid();
    if (command.action==='upgrade_content') {
      if (!state.activeUpgrade || state.activeUpgrade.migrationId!==input.upgrade!.migrationId || state.activeUpgrade.manifestDigest!==input.upgrade!.manifestDigest ||
        command.records.some(ref=>!state.activeUpgrade!.manifest.some(source=>source.kind===ref.kind&&source.id===ref.id&&source.projectId===b.projectId))) invalid();
    } else if (state.activeUpgrade) invalid();
    for (const ref of changed) {
      const prior = contents.get(`${ref.kind}:${ref.id}`); let content = input.content !== undefined && target?.kind === ref.kind && target.id === ref.id ?
        parseContent(ref.kind, input.content) : prior?.content;
      if (!content) invalid();
      const retained = context.records.find((record) => record.kind === ref.kind && record.id === ref.id),
        replace = b.version === 1 || planningRecordReplacesContent(command, ref.kind, ref.id),
        contentRevision = planningEnvelopeRevision(b,command,ref,retained);
      if (!replace && !retained) invalid();
      if (command.action==='upgrade_content') {
        if (!retained||retained.envelope.header.schema!==1) invalid();
        content=await decryptRecord(retained);
        transformContentData1To2(ref.kind,content,value=>parseContent(ref.kind,value));
      }
      const envelope=replace?await seal(ref.kind,ref.id,contentRevision,content):retained!.envelope;
      records.push({kind:ref.kind,id:ref.id,envelope});
      if (command.action==='upgrade_content') {
        const source=await planningUpgradeReference(context.graph,retained!);
        upgradeItems.push({source,target:{...source,revision:ref.revision,envelopeRevision:contentRevision,schema:2,keyEpoch:b.keyEpoch,digest:await digestObject(envelope)},sourceEnvelope:retained!.envelope,envelope});
      }
      audited.push({ kind: ref.kind, id: ref.id, before: prior?.content ?? null, after: content }); contents.set(`${ref.kind}:${ref.id}`, { ...ref, content });
    }
    const snapshot = result.snapshot ?? null, snapshotContents: ReadablePlanningRecord[] = [];
    let stamp: ClosingSettings | undefined;
    if (snapshot && b.version !== 1) {
      if (!input.closingSettings || input.closingSettings.accountId !== b.accountId || input.closingSettings.deviceId !== b.deviceId ||
        input.closingSettings.settings.securityHead !== b.securityHead || input.closingSettings.settings.securityVersion !== b.securityVersion ||
        input.closingSettings.settings.dataGeneration !== b.dataGeneration) invalid();
      const settings = await readReportingSettings(input.closingSettings, bundle);
      if (settings.timezone === null) invalid();
      stamp = closingSettings.parse({ workspaceId: b.workspaceId, revision: settings.revision, head: settings.head,
        initialDigest: settings.pin.initialDigest, timezone: settings.timezone });
    }
    if (snapshot) {
      const refs = [{ kind: 'project', row: snapshot.project }, ...snapshot.phases.map((row) => ({ kind: 'phase', row })),
        ...snapshot.milestones.map((row) => ({ kind: 'milestone', row })), ...snapshot.tasks.map((row) => ({ kind: 'task', row })),
        ...(snapshot.blockers ?? []).map((row) => ({ kind: 'blocker', row }))];
      for (const ref of refs) { const record = contents.get(`${ref.kind}:${ref.row.id}`); if (!record || record.revision !== ref.row.revision) invalid(); snapshotContents.push(record); }
    }
    const auditData: PlanningAuditData = { version: 1, action: command.action, changed: audited, snapshot, snapshotContents, ...(stamp ? { closingSettings: stamp } : {}) }, auditId = crypto.randomUUID(),
      audit = { id: auditId, envelope: await seal('audit', auditId, '1', auditData) },
      upgrade=command.action==='upgrade_content'?upgradeProof.parse({migrationId:input.upgrade!.migrationId,manifestDigest:input.upgrade!.manifestDigest,transformId:CONTENT_TRANSFORM_1_TO_2,sourceSchema:1,targetSchema:2,items:upgradeItems.map(({source,target})=>({source,target}))}):undefined,
      mutation = await signObject({ purpose: b.version === 1 ? 'ukda.planning-mutation.v1' as const : b.version===2 ? 'ukda.planning-mutation.v2' as const : 'ukda.planning-mutation.v3' as const, binding: b, command, nextVersion: String(BigInt(b.beforeVersion) + 1n),
        afterGraphDigest: await planningGraphDigest(result.state), records: await Promise.all(records.map(async (record, index) => ({ ...changed[index]!, ...(b.version===3?{envelopeRevision:record.envelope.header.revision}:{}),digest: await digestObject(record.envelope) }))), audit: { id: audit.id, digest: await digestObject(audit.envelope) },
        outcome: outcome ? { id: outcome.id, digest: await digestObject(outcome.envelope) } : null, ...(stamp ? { closingSettings: stamp } : {}),...(upgrade?{upgrade}:{}) }, signing);
    return (await validatePlanningPayload(planningPayload.parse({ mutation, records, audit, outcome,...(upgrade?{upgradeItems}:{}) }), b, context.graph, context.records)).payload;
  } finally { key.fill(0); signing.fill(0); }
}

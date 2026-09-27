import { z } from 'zod';
import type { PlanningClosingSnapshot, PlanningState, PlanningTask } from './planning.js';
import { identifier } from './contracts.js';
import { PLANNING_MAX_RECORDS, planningGraph } from './planning-api.js';
import { closingSettings, type ClosingSettings } from './closing-settings.js';

export const PROGRESS_CALCULATION_VERSION = 'progress-health-v1' as const;
export type ProgressScope = { kind: 'project' } | { kind: 'phase' | 'milestone'; id: string } |
  { kind: 'filtered'; taskIds: readonly string[] };
export type ProgressRecordKind = 'project' | 'phase' | 'milestone' | 'task';
export interface ProgressDateRecord { kind: ProgressRecordKind; id: string; startDate?: string; dueDate?: string }
export interface ProgressInput {
  graph: PlanningState; dates: readonly ProgressDateRecord[]; scope: ProgressScope; timezone: string; asOfUtc: string;
  source: { complete: boolean; current: boolean; verified: boolean; decrypted: boolean };
  milestoneOrder: readonly { id: string; order: number }[];
  closingSettingsByOperation?: readonly { operationId: string; settings: ClosingSettings }[];
}
export interface ProgressCounts {
  taskCount: number | null; nonCancelledTaskCount: number | null; doneTaskCount: number | null;
  unfinishedTaskCount: number | null; cancelledTaskCount: number | null; percentage: number | null;
  emptyLabel: 'No work planned' | 'No active work' | null;
}
export interface EffectiveDeadline {
  kind: ProgressRecordKind; id: string; dueDate: string | null;
  source: { kind: 'project' | 'phase' | 'milestone' | 'task'; id: string } | null; inherited: boolean;
}
export interface ProgressSignals {
  overdue: { taskIds: string[]; milestoneIds: string[]; phaseIds: string[]; project: boolean };
  missingDates: { taskIds: string[]; milestoneIds: string[]; phaseIds: string[]; project: boolean };
  missingDateCount: number; blockedTaskIds: string[]; openBlockerIds: string[];
}
export type ProgressHealth = 'delayed' | 'at_risk' | 'not_enough_information' | 'on_track' | 'terminal';
export type ProgressReason = 'incomplete' | 'not_current' | 'unverified' | 'not_decrypted' | 'invalid_data' |
  'overdue_work' | 'open_blockers' | 'no_work_planned' | 'missing_deadlines' | 'no_overdue_work_or_open_blockers' | 'terminal_scope';
export interface ProgressWarning {
  code: 'outside_parent_dates'; kind: 'phase' | 'milestone' | 'task'; id: string;
  parentKind: 'project' | 'phase'; parentId: string; field: 'startDate' | 'dueDate'; boundary: 'before_start' | 'after_due';
}
export interface ProgressResult {
  calculationVersion: typeof PROGRESS_CALCULATION_VERSION; workspaceId: string; projectId: string; scope: ProgressScope;
  timezone: string; asOfUtc: string; localDate: string; nextMidnightUtc: string; current: boolean;
  progress: ProgressCounts; awaitingAcceptance: boolean;
  lifecycle: 'planned' | 'active' | 'complete' | 'cancelled' | 'open' | 'accepted' | null; archived: boolean;
  health: ProgressHealth; reasons: ProgressReason[]; signals: ProgressSignals; deadlines: EffectiveDeadline[];
  blockers: { id: string; taskId: string; ageDays: number; needsResponsiblePerson: boolean }[];
  nextMilestone: { id: string; deadline: EffectiveDeadline; creationOrder: number } | null;
  closingSnapshot: PlanningClosingSnapshot | null; closingSettings: ClosingSettings | null; warnings: ProgressWarning[];
}
const boundedIds = z.array(identifier).max(PLANNING_MAX_RECORDS).refine(ids => new Set(ids).size === ids.length);
export const progressScopeSchema = z.discriminatedUnion('kind', [z.strictObject({ kind: z.literal('project') }),
  z.strictObject({ kind: z.literal('phase'), id: identifier }), z.strictObject({ kind: z.literal('milestone'), id: identifier }),
  z.strictObject({ kind: z.literal('filtered'), taskIds: boundedIds })]);
const recordKind = z.enum(['project', 'phase', 'milestone', 'task']), nonnegative = z.number().int().min(0).max(PLANNING_MAX_RECORDS),
  deadlineSchema = z.strictObject({ kind: recordKind, id: identifier, dueDate: z.iso.date().nullable(),
    source: z.strictObject({ kind: recordKind, id: identifier }).nullable(), inherited: z.boolean() }),
  signalGroup = z.strictObject({ taskIds: boundedIds, milestoneIds: boundedIds, phaseIds: boundedIds, project: z.boolean() });
/** A stale decrypted cache is still strictly parsed; current results additionally require exact recomputation against current provenance. */
export const progressResultSchema = z.strictObject({ calculationVersion: z.literal(PROGRESS_CALCULATION_VERSION), workspaceId: identifier, projectId: identifier,
  scope: progressScopeSchema, timezone: z.string().min(1).max(100), asOfUtc: z.iso.datetime(), localDate: z.iso.date(), nextMidnightUtc: z.iso.datetime(), current: z.boolean(),
  progress: z.strictObject({ taskCount: nonnegative.nullable(), nonCancelledTaskCount: nonnegative.nullable(), doneTaskCount: nonnegative.nullable(),
    unfinishedTaskCount: nonnegative.nullable(), cancelledTaskCount: nonnegative.nullable(), percentage: z.number().int().min(0).max(100).nullable(),
    emptyLabel: z.enum(['No work planned', 'No active work']).nullable() }), awaitingAcceptance: z.boolean(),
  lifecycle: z.enum(['planned', 'active', 'complete', 'cancelled', 'open', 'accepted']).nullable(), archived: z.boolean(),
  health: z.enum(['delayed', 'at_risk', 'not_enough_information', 'on_track', 'terminal']),
  reasons: z.array(z.enum(['incomplete', 'not_current', 'unverified', 'not_decrypted', 'invalid_data', 'overdue_work', 'open_blockers', 'no_work_planned', 'missing_deadlines', 'no_overdue_work_or_open_blockers', 'terminal_scope'])).max(11),
  signals: z.strictObject({ overdue: signalGroup, missingDates: signalGroup, missingDateCount: nonnegative, blockedTaskIds: boundedIds, openBlockerIds: boundedIds }),
  deadlines: z.array(deadlineSchema).max(PLANNING_MAX_RECORDS), blockers: z.array(z.strictObject({ id: identifier, taskId: identifier,
    ageDays: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER), needsResponsiblePerson: z.boolean() })).max(PLANNING_MAX_RECORDS),
  nextMilestone: z.strictObject({ id: identifier, deadline: deadlineSchema, creationOrder: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER) }).nullable(),
  closingSnapshot: planningGraph.options[1].shape.snapshots.element.nullable(),
  closingSettings: closingSettings.nullable(),
  warnings: z.array(z.strictObject({ code: z.literal('outside_parent_dates'), kind: z.enum(['phase', 'milestone', 'task']), id: identifier,
    parentKind: z.enum(['project', 'phase']), parentId: identifier, field: z.enum(['startDate', 'dueDate']), boundary: z.enum(['before_start', 'after_due']) })).max(4 * PLANNING_MAX_RECORDS),
}).refine(result => {
  const p = result.progress;
  if (!result.current) return [p.taskCount, p.nonCancelledTaskCount, p.doneTaskCount, p.unfinishedTaskCount, p.cancelledTaskCount, p.percentage, p.emptyLabel].every(v => v === null) && result.health === 'not_enough_information';
  if (p.taskCount === null || p.nonCancelledTaskCount === null || p.doneTaskCount === null || p.unfinishedTaskCount === null || p.cancelledTaskCount === null) return false;
  const expected = p.nonCancelledTaskCount ? Math.min(p.unfinishedTaskCount ? 99 : 100, Math.round(p.doneTaskCount * 100 / p.nonCancelledTaskCount)) : null;
  return p.taskCount === p.nonCancelledTaskCount + p.cancelledTaskCount && p.nonCancelledTaskCount === p.doneTaskCount + p.unfinishedTaskCount &&
    p.percentage === expected && p.emptyLabel === (p.nonCancelledTaskCount ? null : p.taskCount ? 'No active work' : 'No work planned');
}) satisfies z.ZodType<ProgressResult>;
export class ProgressError extends Error { constructor() { super('Invalid progress calculation input'); this.name = 'ProgressError'; } }
function invalid(): never { throw new ProgressError(); }
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const sortedIds = (ids: readonly string[]) => [...new Set(ids)].sort(compare);
const unfinished = (task: PlanningTask) => task.state !== 'done' && task.state !== 'cancelled';
const terminal = (state: string | null) => state === 'complete' || state === 'cancelled' || state === 'accepted';

export function canonicalProgressScope(scope: ProgressScope): ProgressScope {
  return scope.kind === 'filtered' ? { kind: 'filtered', taskIds: sortedIds(scope.taskIds) } :
    scope.kind === 'project' ? { kind: 'project' } : { kind: scope.kind, id: scope.id };
}

/** Server time is an explicit input. A local calendar boundary is never assumed to be 24 hours away. */
export function progressClock(asOfUtc: string, timezone: string): { localDate: string; nextMidnightUtc: string } {
  if (!z.iso.datetime().safeParse(asOfUtc).success) invalid();
  let formatter: Intl.DateTimeFormat;
  try { formatter = new Intl.DateTimeFormat('en-GB-u-ca-gregory-nu-latn', { timeZone: timezone, year: 'numeric', month: '2-digit', day: '2-digit' }); }
  catch { invalid(); }
  const dateAt = (instant: number) => {
    const parts = formatter.formatToParts(instant), part = (kind: string) => parts.find(p => p.type === kind)!.value;
    return `${part('year').padStart(4, '0')}-${part('month')}-${part('day')}`;
  };
  let low = Date.parse(asOfUtc), high = low + 48 * 60 * 60 * 1000;
  const localDate = dateAt(low);
  if (!Number.isFinite(low) || dateAt(high) <= localDate) invalid();
  // Find the first UTC millisecond whose local date has advanced. This also
  // handles 23/25-hour DST days and zones whose midnight offset changes.
  while (high - low > 1) { const middle = Math.floor((low + high) / 2); if (dateAt(middle) === localDate) low = middle; else high = middle; }
  return { localDate, nextMidnightUtc: new Date(high).toISOString() };
}

function counts(tasks: readonly PlanningTask[]): ProgressCounts {
  const unique = new Map(tasks.map(t => [t.id, t])), values = [...unique.values()], active = values.filter(t => t.state !== 'cancelled'),
    done = active.filter(t => t.state === 'done').length, remaining = active.length - done;
  return { taskCount: values.length, nonCancelledTaskCount: active.length, doneTaskCount: done, unfinishedTaskCount: remaining,
    cancelledTaskCount: values.length - active.length, percentage: active.length ? Math.min(remaining ? 99 : 100, Math.round(done * 100 / active.length)) : null,
    emptyLabel: active.length ? null : values.length ? 'No active work' : 'No work planned' };
}
function emptyCounts(): ProgressCounts { return { taskCount: null, nonCancelledTaskCount: null, doneTaskCount: null, unfinishedTaskCount: null, cancelledTaskCount: null, percentage: null, emptyLabel: null }; }
function emptySignals(): ProgressSignals { return { overdue: { taskIds: [], milestoneIds: [], phaseIds: [], project: false },
  missingDates: { taskIds: [], milestoneIds: [], phaseIds: [], project: false }, missingDateCount: 0, blockedTaskIds: [], openBlockerIds: [] }; }

/** The adapter authenticates/decrypts the complete graph before setting these source flags. */
export function calculateProgress(input: ProgressInput): ProgressResult {
  const { graph, timezone, asOfUtc } = input, scope = canonicalProgressScope(input.scope), clock = progressClock(asOfUtc, timezone),
    phase = scope.kind === 'phase' ? graph.phases.find(p => p.id === scope.id) : undefined,
    milestone = scope.kind === 'milestone' ? graph.milestones.find(m => m.id === scope.id) : undefined;
  if (scope.kind === 'phase' && !phase || scope.kind === 'milestone' && !milestone ||
    scope.kind === 'filtered' && scope.taskIds.some(id => !graph.tasks.some(t => t.id === id))) invalid();
  const lifecycle = scope.kind === 'project' ? graph.project.state : phase?.state ?? milestone?.state ?? null,
    archived = scope.kind === 'project' ? graph.project.archived : phase?.archived ?? false;
  const result: ProgressResult = { calculationVersion: PROGRESS_CALCULATION_VERSION, workspaceId: graph.project.workspaceId, projectId: graph.project.id,
    scope, timezone, asOfUtc, ...clock, current: false, progress: emptyCounts(), awaitingAcceptance: false, lifecycle, archived,
    health: 'not_enough_information', reasons: [], signals: emptySignals(), deadlines: [], blockers: [], nextMilestone: null, closingSnapshot: null, closingSettings: null, warnings: [] };
  for (const [flag, reason] of [['complete', 'incomplete'], ['current', 'not_current'], ['verified', 'unverified'], ['decrypted', 'not_decrypted']] as const)
    if (!input.source[flag]) result.reasons.push(reason);
  if (result.reasons.length) return result;

  const rows = new Map<string, ProgressDateRecord>(), expected = new Set([`project:${graph.project.id}`, ...graph.phases.map(p => `phase:${p.id}`),
    ...graph.milestones.map(m => `milestone:${m.id}`), ...graph.tasks.map(t => `task:${t.id}`)]);
  for (const record of input.dates) {
    const key = `${record.kind}:${record.id}`;
    if (!expected.has(key) || rows.has(key) || record.startDate !== undefined && !z.iso.date().safeParse(record.startDate).success ||
      record.dueDate !== undefined && !z.iso.date().safeParse(record.dueDate).success || record.startDate && record.dueDate && record.startDate > record.dueDate) {
      result.reasons = ['invalid_data']; return result;
    }
    rows.set(key, record);
  }
  if (rows.size !== expected.size || (graph.blockers ?? []).some(b => !z.iso.datetime().safeParse(b.createdAt).success)) {
    result.reasons = ['invalid_data']; return result;
  }
  const settingsByOperation = new Map<string, ClosingSettings>();
  for (const stamp of input.closingSettingsByOperation ?? []) {
    const parsed = closingSettings.safeParse(stamp.settings);
    if (!parsed.success || parsed.data.workspaceId !== graph.project.workspaceId || settingsByOperation.has(stamp.operationId)) {
      result.reasons = ['invalid_data']; return result;
    }
    settingsByOperation.set(stamp.operationId, parsed.data);
  }
  const tasks = graph.tasks.filter(t => scope.kind === 'project' || scope.kind === 'phase' && t.phaseId === scope.id ||
    scope.kind === 'milestone' && t.milestoneId === scope.id || scope.kind === 'filtered' && scope.taskIds.includes(t.id)),
    phases = scope.kind === 'project' ? [...graph.phases] : phase ? [phase] : [],
    milestones = scope.kind === 'project' ? [...graph.milestones] : phase ? graph.milestones.filter(m => m.phaseId === phase.id) : milestone ? [milestone] : [];
  const order = new Map<string, number>();
  for (const item of input.milestoneOrder) {
    if (order.has(item.id) || !Number.isSafeInteger(item.order) || item.order < 0) { result.reasons = ['invalid_data']; return result; }
    order.set(item.id, item.order);
  }
  if (!terminal(lifecycle) && milestones.some(m => m.state === 'open' && !order.has(m.id))) { result.reasons = ['invalid_data']; return result; }
  result.progress = counts(tasks); result.current = true;
  result.awaitingAcceptance = milestone?.state === 'open' && result.progress.percentage === 100;
  if (terminal(lifecycle)) {
    const kind = scope.kind, id = scope.kind === 'project' ? graph.project.id : 'id' in scope ? scope.id : null,
      action = lifecycle === 'cancelled' ? 'cancel' : lifecycle === 'accepted' ? 'accept' : 'complete';
    result.health = 'terminal'; result.reasons = ['terminal_scope'];
    // Snapshot order is the already verified immutable planning history order.
    result.closingSnapshot = structuredClone([...graph.snapshots].reverse().find(s => s.kind === kind && s.recordId === id && s.action === action) ?? null);
    result.closingSettings = result.closingSnapshot ? structuredClone(settingsByOperation.get(result.closingSnapshot.operationId) ?? null) : null;
    return result;
  }
  const date = (kind: ProgressRecordKind, id: string) => rows.get(`${kind}:${id}`)!,
    projectDate = date('project', graph.project.id), deadline = (kind: ProgressRecordKind, id: string, phaseId: string | null = null): EffectiveDeadline => {
      const own = date(kind, id), inherited = phaseId ? date('phase', phaseId) : null;
      if (own.dueDate) return { kind, id, dueDate: own.dueDate, source: { kind, id }, inherited: false };
      if (inherited?.dueDate) return { kind, id, dueDate: inherited.dueDate, source: { kind: 'phase', id: phaseId! }, inherited: true };
      return { kind, id, dueDate: kind !== 'project' ? projectDate.dueDate ?? null : null,
        source: kind !== 'project' && projectDate.dueDate ? { kind: 'project', id: graph.project.id } : null, inherited: kind !== 'project' && !!projectDate.dueDate };
    };
  const openTasks = tasks.filter(unfinished), openMilestones = milestones.filter(m => m.state === 'open'), openPhases = phases.filter(p => !terminal(p.state));
  result.deadlines = [...tasks.filter(t => t.state !== 'cancelled').map(t => deadline('task', t.id, t.phaseId)),
    ...milestones.filter(m => m.state !== 'cancelled').map(m => deadline('milestone', m.id, m.phaseId)),
    ...phases.filter(p => p.state !== 'cancelled').map(p => deadline('phase', p.id)), ...(scope.kind === 'project' ? [deadline('project', graph.project.id)] : [])]
    .sort((a, b) => compare(`${a.kind}:${a.id}`, `${b.kind}:${b.id}`));
  const signals = result.signals;
  const collect = (kind: ProgressRecordKind, id: string) => {
    const effective = result.deadlines.find(d => d.kind === kind && d.id === id)!;
    for (const [target, matches] of [[signals.missingDates, effective.dueDate === null], [signals.overdue, effective.dueDate !== null && effective.dueDate < clock.localDate]] as const) {
      if (!matches) continue;
      if (kind === 'project') target.project = true;
      else target[kind === 'task' ? 'taskIds' : kind === 'phase' ? 'phaseIds' : 'milestoneIds'].push(id);
    }
  };
  for (const t of openTasks) collect('task', t.id);
  for (const m of openMilestones) collect('milestone', m.id);
  for (const p of openPhases) collect('phase', p.id);
  if (scope.kind === 'project') collect('project', graph.project.id);
  for (const group of [signals.overdue, signals.missingDates]) for (const key of ['taskIds', 'milestoneIds', 'phaseIds'] as const) group[key].sort(compare);
  signals.missingDateCount = signals.missingDates.taskIds.length + signals.missingDates.milestoneIds.length + signals.missingDates.phaseIds.length + Number(signals.missingDates.project);
  const unfinishedIds = new Set(openTasks.map(t => t.id));
  result.blockers = (graph.blockers ?? []).filter(b => b.state === 'open' && unfinishedIds.has(b.taskId)).map(b => ({ id: b.id, taskId: b.taskId,
    ageDays: Math.max(0, Math.floor((Date.parse(asOfUtc) - Date.parse(b.createdAt)) / 86400000)), needsResponsiblePerson: b.responsibleProfileId === null })).sort((a, b) => compare(a.id, b.id));
  signals.openBlockerIds = result.blockers.map(b => b.id); signals.blockedTaskIds = sortedIds(result.blockers.map(b => b.taskId));
  result.nextMilestone = openMilestones.map(m => ({ id: m.id, deadline: deadline('milestone', m.id, m.phaseId), creationOrder: order.get(m.id)! }))
    .sort((a, b) => a.deadline.dueDate === null && b.deadline.dueDate !== null ? 1 : a.deadline.dueDate !== null && b.deadline.dueDate === null ? -1 :
      compare(a.deadline.dueDate ?? '', b.deadline.dueDate ?? '') || a.creationOrder - b.creationOrder || compare(a.id, b.id))[0] ?? null;
  const warn = (kind: 'phase' | 'milestone' | 'task', id: string, parentKind: 'project' | 'phase', parentId: string) => {
    const own = date(kind, id), parent = date(parentKind, parentId);
    for (const field of ['startDate', 'dueDate'] as const) if (own[field]) {
      if (parent.startDate && own[field]! < parent.startDate) result.warnings.push({ code: 'outside_parent_dates', kind, id, parentKind, parentId, field, boundary: 'before_start' });
      if (parent.dueDate && own[field]! > parent.dueDate) result.warnings.push({ code: 'outside_parent_dates', kind, id, parentKind, parentId, field, boundary: 'after_due' });
    }
  };
  for (const p of phases.filter(p => p.state !== 'cancelled')) warn('phase', p.id, 'project', graph.project.id);
  for (const row of [...tasks.map(t => ({ ...t, kind: 'task' as const })), ...milestones.map(m => ({ ...m, kind: 'milestone' as const }))].filter(r => r.state !== 'cancelled')) {
    warn(row.kind, row.id, 'project', graph.project.id); if (row.phaseId) warn(row.kind, row.id, 'phase', row.phaseId);
  }
  result.warnings.sort((a, b) => compare(JSON.stringify(a), JSON.stringify(b)));
  const overdueCount = signals.overdue.taskIds.length + signals.overdue.milestoneIds.length + signals.overdue.phaseIds.length + Number(signals.overdue.project),
    noWork = result.progress.nonCancelledTaskCount === 0 && milestones.every(m => m.state === 'cancelled');
  if (overdueCount) { result.health = 'delayed'; result.reasons = ['overdue_work']; }
  else if (result.blockers.length) { result.health = 'at_risk'; result.reasons = ['open_blockers']; }
  else if (noWork || signals.missingDateCount) { result.health = 'not_enough_information'; result.reasons = [...(noWork ? ['no_work_planned' as const] : []), ...(signals.missingDateCount ? ['missing_deadlines' as const] : [])]; }
  else { result.health = 'on_track'; result.reasons = ['no_overdue_work_or_open_blockers']; }
  return result;
}

export interface AggregateProgress {
  calculationVersion: typeof PROGRESS_CALCULATION_VERSION; workspaceId: string; projectIds: string[];
  timezone: string; asOfUtc: string; localDate: string; nextMidnightUtc: string; current: boolean; progress: ProgressCounts;
  overdueCount: number; missingDateCount: number; blockedTaskCount: number; openBlockerCount: number;
}
/** Combine exactly one explicit visible fragment per project; never average percentages. */
export function aggregateProgress(results: readonly ProgressResult[]): AggregateProgress {
  const first = results[0]; if (!first) invalid();
  if (new Set(results.map(r => r.projectId)).size !== results.length || results.some(r => r.workspaceId !== first.workspaceId || r.timezone !== first.timezone ||
    r.asOfUtc !== first.asOfUtc || r.localDate !== first.localDate || r.nextMidnightUtc !== first.nextMidnightUtc || r.calculationVersion !== PROGRESS_CALCULATION_VERSION)) invalid();
  const current = results.every(r => r.current), total = (key: keyof ProgressCounts) => results.reduce((sum, r) => sum + Number(r.progress[key]), 0),
    taskCount = total('taskCount'), active = total('nonCancelledTaskCount'), done = total('doneTaskCount'), unfinishedCount = total('unfinishedTaskCount');
  return { calculationVersion: PROGRESS_CALCULATION_VERSION, workspaceId: first.workspaceId, projectIds: sortedIds(results.map(r => r.projectId)), timezone: first.timezone,
    asOfUtc: first.asOfUtc, localDate: first.localDate, nextMidnightUtc: first.nextMidnightUtc, current,
    progress: current ? { taskCount, nonCancelledTaskCount: active, doneTaskCount: done, unfinishedTaskCount: unfinishedCount, cancelledTaskCount: total('cancelledTaskCount'),
      percentage: active ? Math.min(unfinishedCount ? 99 : 100, Math.round(done * 100 / active)) : null, emptyLabel: active ? null : taskCount ? 'No active work' : 'No work planned' } : emptyCounts(),
    overdueCount: current ? results.reduce((sum, r) => sum + r.signals.overdue.taskIds.length + r.signals.overdue.milestoneIds.length + r.signals.overdue.phaseIds.length + Number(r.signals.overdue.project), 0) : 0,
    missingDateCount: current ? results.reduce((sum, r) => sum + r.signals.missingDateCount, 0) : 0,
    blockedTaskCount: current ? results.reduce((sum, r) => sum + r.signals.blockedTaskIds.length, 0) : 0,
    openBlockerCount: current ? results.reduce((sum, r) => sum + r.signals.openBlockerIds.length, 0) : 0 };
}

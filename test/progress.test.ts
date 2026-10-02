import assert from 'node:assert/strict';
import test from 'node:test';
import { aggregateProgress, calculateProgress, canonicalProgressScope, progressClock, progressResultSchema, ProgressError,
  type ProgressDateRecord, type ProgressInput } from '../src/shared/progress.js';
import type { PlanningBlocker, PlanningClosingSnapshot, PlanningMilestone, PlanningPhase, PlanningState, PlanningTask } from '../src/shared/planning.js';

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const workspaceId = id(1), projectId = id(2), actorId = id(3), asOfUtc = '2026-09-26T12:00:00.000Z';
function project(): PlanningState {
  return { version: 2, project: { workspaceId, id: projectId, revision: '1', state: 'active', archived: false, phaseLabel: 'wave', managerProfileId: null, teamId: null },
    tasks: [], phases: [], milestones: [], blockers: [], snapshots: [], movements: [] };
}
function task(n: number, patch: Partial<PlanningTask> = {}): PlanningTask {
  return { id: id(n), workspaceId, projectId, revision: '1', state: 'todo', phaseId: null, milestoneId: null, assigneeIds: [actorId], leadProfileId: actorId, ...patch };
}
function phase(n: number, patch: Partial<PlanningPhase> = {}): PlanningPhase {
  return { id: id(n), workspaceId, projectId, revision: '1', state: 'active', archived: false, displayOrder: n, leadProfileId: null, ...patch };
}
function milestone(n: number, patch: Partial<PlanningMilestone> = {}): PlanningMilestone {
  return { id: id(n), workspaceId, projectId, revision: '1', state: 'open', phaseId: null, ownerProfileId: null, ...patch };
}
function blocker(n: number, taskId: string, patch: Partial<PlanningBlocker> = {}): PlanningBlocker {
  return { id: id(n), workspaceId, projectId, revision: '1', contentRevision: '1', state: 'open', taskId, responsibleProfileId: actorId,
    createdBy: actorId, createdAt: '2026-09-24T12:00:00.000Z', resolvedBy: null, resolvedAt: null, ...patch };
}
function input(graph: PlanningState, patch: Partial<ProgressInput> = {}, dateOverrides: ProgressDateRecord[] = []): ProgressInput {
  const rows: ProgressDateRecord[] = [{ kind: 'project', id: graph.project.id, dueDate: '2026-12-31' },
    ...graph.phases.map(p => ({ kind: 'phase' as const, id: p.id })), ...graph.milestones.map(m => ({ kind: 'milestone' as const, id: m.id })),
    ...graph.tasks.map(t => ({ kind: 'task' as const, id: t.id }))];
  return { graph, dates: rows.map(row => dateOverrides.find(d => d.kind === row.kind && d.id === row.id) ?? row), scope: { kind: 'project' },
    timezone: 'Europe/London', asOfUtc, source: { complete: true, current: true, verified: true, decrypted: true },
    milestoneOrder: graph.milestones.map((m, order) => ({ id: m.id, order })), ...patch };
}

test('CP10 progress: distinct shared tasks, unscheduled work and scopes use counts rather than averaging wave percentages', () => {
  const graph = project(); graph.phases = [phase(10), phase(11)]; graph.milestones = [milestone(20, { phaseId: id(10) })];
  graph.tasks = [task(30, { state: 'done', phaseId: id(10), milestoneId: id(20), assigneeIds: [actorId, id(4)] }),
    task(31, { phaseId: id(11) }), task(32, { phaseId: id(11) }), task(33, { phaseId: id(11) }), task(34, { state: 'done' })];
  const whole = calculateProgress(input(graph));
  assert.equal(whole.progress.doneTaskCount, 2); assert.equal(whole.progress.nonCancelledTaskCount, 5); assert.equal(whole.progress.percentage, 40);
  assert.equal(calculateProgress(input(graph, { scope: { kind: 'phase', id: id(10) } })).progress.percentage, 100);
  assert.equal(calculateProgress(input(graph, { scope: { kind: 'phase', id: id(11) } })).progress.percentage, 0);
  const acceptedWork = calculateProgress(input(graph, { scope: { kind: 'milestone', id: id(20) } }));
  assert.equal(acceptedWork.progress.percentage, 100); assert.equal(acceptedWork.awaitingAcceptance, true);
  const filter = calculateProgress(input(graph, { scope: { kind: 'filtered', taskIds: [id(34), id(30), id(30)] } }));
  assert.deepEqual(filter.scope, { kind: 'filtered', taskIds: [id(30), id(34)] }); assert.equal(filter.progress.doneTaskCount, 2); assert.equal(filter.progress.percentage, 100);
  assert.throws(() => calculateProgress(input(graph, { scope: { kind: 'filtered', taskIds: [id(999)] } })), ProgressError);
});

test('CP10 progress: 199 of 200 cannot round to 100 and Review is unfinished', () => {
  const graph = project(); graph.tasks = Array.from({ length: 200 }, (_, n) => task(100 + n, { state: n < 199 ? 'done' : 'review' }));
  const partial = calculateProgress(input(graph));
  assert.equal(partial.progress.percentage, 99); assert.equal(partial.progress.unfinishedTaskCount, 1);
  graph.tasks = graph.tasks.map(t => ({ ...t, state: 'done' }));
  assert.equal(calculateProgress(input(graph)).progress.percentage, 100);
});

test('CP10 progress: empty and all-cancelled scopes use the distinct no-work labels', () => {
  const graph = project(), empty = calculateProgress(input(graph));
  assert.equal(empty.progress.percentage, null); assert.equal(empty.progress.emptyLabel, 'No work planned'); assert.equal(empty.health, 'not_enough_information');
  graph.tasks = [task(30, { state: 'cancelled' })];
  const cancelled = calculateProgress(input(graph));
  assert.equal(cancelled.progress.taskCount, 1); assert.equal(cancelled.progress.nonCancelledTaskCount, 0); assert.equal(cancelled.progress.percentage, null);
  assert.equal(cancelled.progress.emptyLabel, 'No active work');
  graph.phases = [phase(10)];
  assert.equal(calculateProgress(input(graph)).health, 'not_enough_information', 'An empty wave is not itself a work/checkpoint plan');
});

test('CP10 clock: London due-today boundaries and 23/25-hour local days use timezone calendar transitions', () => {
  const cases = [
    ['2026-03-29T00:00:00.000Z', '2026-03-29', '2026-03-29T23:00:00.000Z'],
    ['2026-10-24T23:00:00.000Z', '2026-10-25', '2026-10-26T00:00:00.000Z'],
    ['2026-09-24T22:59:59.999Z', '2026-09-24', '2026-09-24T23:00:00.000Z'],
    ['2026-09-24T23:00:00.000Z', '2026-09-25', '2026-09-25T23:00:00.000Z'],
  ];
  for (const [instant, localDate, nextMidnightUtc] of cases) assert.deepEqual(progressClock(instant!, 'Europe/London'), { localDate, nextMidnightUtc });
  const graph = project(); graph.tasks = [task(30)];
  const due = [{ kind: 'task' as const, id: id(30), dueDate: '2026-09-24' }];
  assert.equal(calculateProgress(input(graph, { asOfUtc: cases[2]![0]! }, due)).health, 'on_track');
  assert.equal(calculateProgress(input(graph, { asOfUtc: cases[3]![0]! }, due)).health, 'delayed');
  assert.throws(() => progressClock(asOfUtc, 'not/a-zone'), ProgressError);
});

test('CP10 deadlines: inheritance is labelled and changing timezone never changes entered dates', () => {
  const graph = project(); graph.phases = [phase(10), phase(11)]; graph.milestones = [milestone(20, { phaseId: id(10) }), milestone(21)];
  graph.tasks = [task(30, { phaseId: id(10) }), task(31), task(32, { phaseId: id(10) })];
  const source = input(graph, { asOfUtc: '2026-09-25T00:30:00.000Z' }, [{ kind: 'project', id: projectId, dueDate: '2026-09-24' },
    { kind: 'phase', id: id(10), dueDate: '2026-10-01' }, { kind: 'task', id: id(32), dueDate: '2026-11-01' }]), before = structuredClone(source), result = calculateProgress(source);
  const find = (kind: string, target: number) => result.deadlines.find(d => d.kind === kind && d.id === id(target))!;
  assert.deepEqual(find('task', 30).source, { kind: 'phase', id: id(10) }); assert.equal(find('task', 30).inherited, true);
  assert.deepEqual(find('task', 31).source, { kind: 'project', id: projectId });
  assert.deepEqual(find('task', 32).source, { kind: 'task', id: id(32) }); assert.equal(find('task', 32).inherited, false);
  assert.deepEqual(find('milestone', 20).source, { kind: 'phase', id: id(10) }); assert.deepEqual(find('milestone', 21).source, { kind: 'project', id: projectId });
  assert.deepEqual(find('phase', 11).source, { kind: 'project', id: projectId });
  const western = calculateProgress({ ...source, timezone: 'America/New_York' });
  assert.equal(result.localDate, '2026-09-25'); assert.equal(western.localDate, '2026-09-24');
  assert.equal(western.signals.overdue.project, false); assert.equal(result.signals.overdue.project, true);
  assert.deepEqual(source, before);
});

test('CP10 health: delay outranks blockers, blockers outrank missing dates and counts retain missing information', () => {
  const graph = project(); graph.tasks = [task(30), task(31)]; graph.blockers = [blocker(40, id(30)), blocker(41, id(30), { responsibleProfileId: null })];
  const source = input(graph, {}, [{ kind: 'project', id: projectId }, { kind: 'task', id: id(30), dueDate: '2026-09-25' }]);
  let result = calculateProgress(source);
  assert.equal(result.health, 'delayed'); assert.equal(result.signals.missingDateCount, 2); assert.deepEqual(result.signals.blockedTaskIds, [id(30)]);
  assert.equal(result.signals.openBlockerIds.length, 2); assert.ok(result.blockers.every(b => b.ageDays === 2)); assert.equal(result.blockers[1]!.needsResponsiblePerson, true);
  source.dates = source.dates.map(d => d.kind === 'task' && d.id === id(30) ? { ...d, dueDate: '2026-09-26' } : d);
  result = calculateProgress(source); assert.equal(result.health, 'at_risk'); assert.equal(result.signals.missingDateCount, 2);
  graph.blockers = graph.blockers!.map(b => ({ ...b, state: 'resolved' as const }));
  assert.equal(calculateProgress(source).health, 'not_enough_information');
  source.dates = source.dates.map(d => d.kind === 'project' ? { ...d, dueDate: '2026-12-31' } : d);
  result = calculateProgress(source); assert.equal(result.health, 'on_track'); assert.deepEqual(result.reasons, ['no_overdue_work_or_open_blockers']);
});

test('CP10 health: late acceptance delays a 100%-Done milestone and next selection uses dates, creation order then IDs', () => {
  const graph = project(); graph.milestones = [milestone(21), milestone(20), milestone(22), milestone(23)]; graph.tasks = [task(30, { milestoneId: id(20), state: 'done' })];
  const source = input(graph, { milestoneOrder: [{ id: id(21), order: 2 }, { id: id(20), order: 2 }, { id: id(22), order: 0 }, { id: id(23), order: 3 }] },
    [{ kind: 'project', id: projectId }, { kind: 'milestone', id: id(20), dueDate: '2026-09-24' }, { kind: 'milestone', id: id(21), dueDate: '2026-09-24' },
      { kind: 'milestone', id: id(22), dueDate: '2026-10-01' }]);
  const result = calculateProgress({ ...source, scope: { kind: 'milestone', id: id(20) } });
  assert.equal(result.progress.percentage, 100); assert.equal(result.awaitingAcceptance, true); assert.equal(result.health, 'delayed');
  assert.equal(calculateProgress(source).nextMilestone!.id, id(20));
  source.milestoneOrder = source.milestoneOrder.map(m => m.id === id(21) ? { ...m, order: 1 } : m);
  assert.equal(calculateProgress(source).nextMilestone!.id, id(21));
  graph.milestones = graph.milestones.map(m => m.id === id(23) ? m : { ...m, state: 'accepted' });
  assert.equal(calculateProgress(source).nextMilestone!.id, id(23)); assert.equal(calculateProgress(source).nextMilestone!.deadline.dueDate, null);
  graph.milestones = graph.milestones.map(m => ({ ...m, state: 'accepted' }));
  assert.equal(calculateProgress(source).nextMilestone, null);
});

test('CP10 exclusions: cancelled overdue entities and their unresolved blockers do not affect current project health', () => {
  const graph = project(); graph.phases = [phase(10, { state: 'cancelled' })]; graph.milestones = [milestone(20, { state: 'cancelled', phaseId: id(10) })];
  graph.tasks = [task(30, { state: 'cancelled', phaseId: id(10), milestoneId: id(20) }), task(31)]; graph.blockers = [blocker(40, id(30))];
  const result = calculateProgress(input(graph, {}, [{ kind: 'phase', id: id(10), dueDate: '2020-01-01' }, { kind: 'milestone', id: id(20), dueDate: '2020-01-01' },
    { kind: 'task', id: id(30), dueDate: '2020-01-01' }]));
  assert.equal(result.health, 'on_track'); assert.equal(result.progress.nonCancelledTaskCount, 1); assert.equal(result.blockers.length, 0);
  assert.deepEqual(result.signals.overdue, { project: false, taskIds: [], milestoneIds: [], phaseIds: [] });
  assert.equal(result.nextMilestone, null);
});

test('CP10 validity: incomplete, stale, unverified, undecrypted or malformed data cannot yield current progress', () => {
  const graph = project(); graph.tasks = [task(30, { state: 'done' })];
  const source = input(graph);
  for (const flag of ['complete', 'current', 'verified', 'decrypted'] as const) {
    const result = calculateProgress({ ...source, source: { ...source.source, [flag]: false } });
    assert.equal(result.current, false); assert.equal(result.health, 'not_enough_information'); assert.equal(result.progress.percentage, null); assert.equal(result.progress.taskCount, null);
  }
  for (const dates of [source.dates.slice(1), [...source.dates, source.dates[0]!], source.dates.map(d => d.kind === 'task' ? { ...d, startDate: '2026-10-01', dueDate: '2026-09-01' } : d),
    source.dates.map(d => d.kind === 'task' ? { ...d, dueDate: '2026-02-30' } : d)]) {
    const result = calculateProgress({ ...source, dates }); assert.equal(result.current, false); assert.equal(result.progress.percentage, null); assert.deepEqual(result.reasons, ['invalid_data']);
  }
  graph.milestones = [milestone(20)];
  const missingOrder = calculateProgress(input(graph, { milestoneOrder: [] }));
  assert.equal(missingOrder.current, false); assert.equal(missingOrder.progress.taskCount, null); assert.equal(missingOrder.nextMilestone, null);
});

test('CP10 cache shape: bounded strict result parsing does not accept extra content, impossible totals or false 100%', () => {
  const graph = project(); graph.tasks = [task(30, { state: 'done' }), task(31)];
  const current = calculateProgress(input(graph)), incomplete = calculateProgress(input(graph, { source: { complete: false, current: true, verified: true, decrypted: true } }));
  assert.deepEqual(progressResultSchema.parse(current), current); assert.deepEqual(progressResultSchema.parse(incomplete), incomplete);
  assert.equal(progressResultSchema.safeParse({ ...current, title: 'Unexpected private field' }).success, false);
  assert.equal(progressResultSchema.safeParse({ ...current, progress: { ...current.progress, percentage: 100 } }).success, false);
  assert.equal(progressResultSchema.safeParse({ ...current, progress: { ...current.progress, doneTaskCount: 3 } }).success, false);
  assert.equal(progressResultSchema.safeParse({ ...incomplete, progress: current.progress }).success, false);
});

test('CP10 terminal scopes: retain the newest matching immutable outcome, without present-day judgement or inferred historical timezone', () => {
  const graph = project(); graph.project.state = 'complete'; graph.project.archived = true; graph.tasks = [task(30, { state: 'done' })];
  const snapshot = (n: number, kind: PlanningClosingSnapshot['kind'], recordId: string, action: PlanningClosingSnapshot['action']): PlanningClosingSnapshot => ({
    operationId: id(n), kind, recordId, action, outcome: { recordId: id(n + 100), revision: '1', digest: 'a'.repeat(64) },
    project: structuredClone(graph.project), phases: [], milestones: [], tasks: structuredClone(graph.tasks), carriedWork: [],
  });
  graph.snapshots = [snapshot(50, 'project', projectId, 'complete'), snapshot(51, 'project', projectId, 'complete'), snapshot(52, 'phase', id(10), 'complete')];
  const before = structuredClone(graph), result = calculateProgress(input(graph, { asOfUtc: '2099-01-01T00:00:00.000Z' }));
  assert.equal(result.health, 'terminal'); assert.equal(result.lifecycle, 'complete'); assert.equal(result.archived, true);
  assert.equal(result.closingSnapshot!.operationId, id(51)); assert.equal(result.deadlines.length, 0); assert.equal(result.signals.missingDateCount, 0);
  assert.equal('timezone' in result.closingSnapshot!, false); assert.deepEqual(graph, before);
  assert.equal(result.closingSettings, null, 'An unstamped historical timezone remains unrecorded');
  const settings = { workspaceId, revision: '0', head: 'a'.repeat(64), initialDigest: 'b'.repeat(64), timezone: 'Europe/London' },
    recorded = calculateProgress(input(graph, { timezone: 'America/New_York', closingSettingsByOperation: [
      { operationId: id(50), settings: { ...settings, timezone: 'Asia/Tokyo' } }, { operationId: id(51), settings },
    ] }));
  assert.equal(recorded.timezone, 'America/New_York'); assert.deepEqual(recorded.closingSettings, settings);
  assert.equal(recorded.closingSnapshot!.operationId, id(51)); assert.deepEqual(progressResultSchema.parse(recorded), recorded);
  assert.deepEqual(graph, before, 'Current timezone changes never rewrite prior closing snapshots');
  graph.snapshots = [];
  assert.equal(calculateProgress(input(graph)).closingSnapshot, null, 'An absent outcome is not invented');
});

test('CP10 warnings and blocker age: date ranges never reschedule work, and age uses elapsed UTC periods across DST', () => {
  const graph = project(); graph.phases = [phase(10)]; graph.tasks = [task(30, { phaseId: id(10) })];
  graph.blockers = [blocker(40, id(30), { createdAt: '2026-03-29T00:30:00.000Z' })];
  const source = input(graph, { asOfUtc: '2026-03-29T23:30:00.000Z' }, [{ kind: 'project', id: projectId, startDate: '2026-03-01', dueDate: '2026-04-30' },
    { kind: 'phase', id: id(10), startDate: '2026-03-10', dueDate: '2026-04-20' }, { kind: 'task', id: id(30), startDate: '2026-03-05', dueDate: '2026-04-25' }]), before = structuredClone(source);
  const result = calculateProgress(source); assert.equal(result.blockers[0]!.ageDays, 0); assert.equal(result.warnings.length, 2);
  assert.ok(result.warnings.every(w => w.parentKind === 'phase')); assert.deepEqual(source, before);
  assert.equal(calculateProgress({ ...source, asOfUtc: '2026-03-30T00:30:00.000Z' }).blockers[0]!.ageDays, 1);
});

test('CP10 aggregation: explicit visible fragments sum tasks once, reject mixed scope clocks and remain deterministic', () => {
  const a = project(), b = project(); a.tasks = [task(30, { state: 'done' })]; b.project.id = id(5);
  b.tasks = [task(31, { projectId: id(5) }), task(32, { projectId: id(5) }), task(33, { projectId: id(5) })];
  const first = calculateProgress(input(a)), second = calculateProgress(input(b)), aggregated = aggregateProgress([first, second]);
  assert.equal(aggregated.progress.percentage, 25); assert.equal(aggregated.progress.nonCancelledTaskCount, 4); assert.deepEqual(aggregated.projectIds, [projectId, id(5)]);
  assert.deepEqual(aggregateProgress([second, first]), aggregated);
  assert.throws(() => aggregateProgress([first, first]), ProgressError);
  assert.throws(() => aggregateProgress([first, { ...second, timezone: 'UTC' }]), ProgressError);
  assert.equal(aggregateProgress([first, { ...second, current: false }]).progress.percentage, null);
  assert.deepEqual(calculateProgress(input(a)), calculateProgress(input(structuredClone(a))));
  assert.deepEqual(canonicalProgressScope({ kind: 'filtered', taskIds: [id(31), id(30), id(31)] }), { kind: 'filtered', taskIds: [id(30), id(31)] });
});

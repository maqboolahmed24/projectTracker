import test from 'node:test';
import assert from 'node:assert/strict';
import { runWorkspaceUpdate, type UpdateProgress, type UpdateRunnerOptions, type UpdateStage } from '../frontend/settings/update-runner.js';
import type { UpgradeOperationResult } from '../src/client/upgrade-controller.js';

type Upgrades = UpdateRunnerOptions['upgrades'];
function operation(kind: UpgradeOperationResult['receipt']['kind'], operationId: string = kind, state: UpgradeOperationResult['state'] = 'completed'): UpgradeOperationResult {
  return { state, migrationId: 'migration', operationId, receipt: {
    version: 1, workspaceId: 'workspace', migrationId: 'migration', operationId, actorId: 'owner',
    dataGeneration: '1', kind, requestHash: 'request', manifestDigest: 'manifest', completedCount: 0, committedAt: '2026-10-01T00:00:00.000Z',
  } };
}
function progress(completed = 0, total = 3, state: UpdateProgress['state'] = 'active'): UpdateProgress {
  return { state, migrationId: 'migration', completed, total, writeSchema: 1 };
}
function harness(methods: Partial<Upgrades> = {}) {
  const calls: string[] = [], stages: UpdateStage[] = [], reports: UpdateProgress[] = [], waits: number[] = [];
  let running = false, stop = false;
  const unexpected = (name: string): never => { throw new Error(`Unexpected ${name}`); };
  const track = async <T>(name: string, work: () => Promise<T>): Promise<T> => {
    assert.equal(running, false, `overlapping controller operation: ${name}`);
    running = true; calls.push(name);
    try { await Promise.resolve(); return await work(); } finally { running = false; }
  };
  const upgrades: Upgrades = {
    pending: () => track('pending', () => methods.pending?.() ?? Promise.resolve([])),
    progress: migrationId => track(`progress:${migrationId ?? 'current'}`, () => methods.progress?.(migrationId) ?? unexpected('progress')),
    resume: operationId => track(`resume:${operationId}`, () => methods.resume?.(operationId) ?? unexpected('resume')),
    start: operationId => track('start', () => methods.start?.(operationId) ?? unexpected('start')),
    advance: (migrationId, operationId) => track(`advance:${migrationId}`, () => methods.advance?.(migrationId, operationId) ?? unexpected('advance')),
    finish: (migrationId, operationId) => track(`finish:${migrationId}`, () => methods.finish?.(migrationId, operationId) ?? unexpected('finish')),
  };
  const options: UpdateRunnerOptions = { upgrades, shouldStop: () => stop, onProgress: value => reports.push(value), onStage: value => stages.push(value),
    wait: async milliseconds => { assert.equal(running, false); waits.push(milliseconds); } };
  return { calls, stages, reports, waits, options, stop: () => { stop = true; }, run: () => runWorkspaceUpdate(options) };
}

test('automatic workspace update runs start, verified batches and finish serially', async () => {
  const snapshots = [progress(0, 3, 'available'), progress(), progress(1), progress(3)];
  const h = harness({ progress: async () => snapshots.shift()!, start: async () => operation('start'), advance: async () => operation('batch'), finish: async () => operation('finish') });
  assert.deepEqual(await h.run(), { state: 'completed' });
  assert.deepEqual(h.calls, ['pending', 'progress:current', 'start', 'progress:migration', 'advance:migration', 'progress:migration', 'advance:migration', 'progress:migration', 'finish:migration']);
  assert.deepEqual(h.reports.map(value => value.completed), [0, 0, 1, 3]);
  assert.deepEqual(h.stages, ['checking', 'starting', 'updating', 'updating', 'finishing']);
});

test('automatic workspace update finishes an already verified or empty manifest without an extra batch', async () => {
  for (const total of [0, 3]) {
    const h = harness({ progress: async () => progress(total, total), finish: async () => operation('finish') });
    assert.deepEqual(await h.run(), { state: 'completed' });
    assert.deepEqual(h.calls, ['pending', 'progress:current', 'finish:migration']);
  }
});

test('saved operations settle sequentially and finishing reuses only its saved operation ID', async () => {
  let resumes = 0;
  const h = harness({ pending: async () => ['saved-start', 'saved-batch'], resume: async id => {
    if (id === 'saved-start') return operation('start', id, ++resumes < 3 ? 'finishing' : 'completed');
    return operation('batch', id);
  }, progress: async () => progress(3), finish: async () => operation('finish') });
  assert.deepEqual(await h.run(), { state: 'completed' });
  assert.deepEqual(h.calls, ['pending', 'resume:saved-start', 'resume:saved-start', 'resume:saved-start', 'resume:saved-batch', 'progress:current', 'finish:migration']);
  assert.deepEqual(h.waits, [250, 500]);
});

test('a resumed finish receipt completes without querying the obsolete schema context', async () => {
  const h = harness({ pending: async () => ['saved-finish'], resume: async id => operation('finish', id) });
  assert.deepEqual(await h.run(), { state: 'completed' });
  assert.deepEqual(h.calls, ['pending', 'resume:saved-finish']);
  assert.equal(h.reports.length, 0);
});

test('a new finish that is still finishing is resumed with its original operation ID', async () => {
  const h = harness({ progress: async () => progress(3), finish: async () => operation('finish', 'final-signed-operation', 'finishing'), resume: async id => operation('finish', id) });
  assert.deepEqual(await h.run(), { state: 'completed' });
  assert.deepEqual(h.calls, ['pending', 'progress:current', 'finish:migration', 'resume:final-signed-operation']);
  assert.deepEqual(h.stages, ['checking', 'finishing', 'waiting']);
});

test('stop fences prevent work before the run and after awaited reads', async () => {
  const before = harness(); before.stop();
  assert.deepEqual(await before.run(), { state: 'stopped' }); assert.deepEqual(before.calls, []);
  const pending = harness({ pending: async () => { pending.stop(); return ['saved']; } });
  assert.deepEqual(await pending.run(), { state: 'stopped' }); assert.deepEqual(pending.calls, ['pending']);
  const reading = harness({ progress: async () => { reading.stop(); return progress(0, 3, 'available'); } });
  assert.deepEqual(await reading.run(), { state: 'stopped' }); assert.deepEqual(reading.calls, ['pending', 'progress:current']);
});

test('stop during a batch waits for that call but schedules no next read, batch or finish', async () => {
  let release!: (value: Awaited<ReturnType<Upgrades['advance']>>) => void;
  const pending = new Promise<Awaited<ReturnType<Upgrades['advance']>>>(resolve => { release = resolve; });
  let entered!: () => void; const advancing = new Promise<void>(resolve => { entered = resolve; });
  const h = harness({ progress: async () => progress(), advance: async () => { entered(); return pending; } });
  const running = h.run(); await advancing; h.stop(); release(operation('batch'));
  assert.deepEqual(await running, { state: 'stopped' });
  assert.deepEqual(h.calls, ['pending', 'progress:current', 'advance:migration']);
});

test('stop in callbacks or backoff cannot begin another controller operation', async () => {
  const reporting = harness({ progress: async () => progress(0, 3, 'available') });
  reporting.options.onProgress = () => reporting.stop();
  assert.deepEqual(await reporting.run(), { state: 'stopped' }); assert.deepEqual(reporting.calls, ['pending', 'progress:current']);
  const staging = harness({ progress: async () => progress() });
  staging.options.onStage = value => { if (value === 'updating') staging.stop(); };
  assert.deepEqual(await staging.run(), { state: 'stopped' }); assert.deepEqual(staging.calls, ['pending', 'progress:current']);
  const waiting = harness({ pending: async () => ['saved'], resume: async id => operation('batch', id, 'finishing') });
  waiting.options.wait = async () => { waiting.stop(); };
  assert.deepEqual(await waiting.run(), { state: 'stopped' }); assert.deepEqual(waiting.calls, ['pending', 'resume:saved']);
});

test('server paused, aborted and completed states never begin a fresh mutation', async () => {
  for (const state of ['paused', 'aborted', 'completed'] as const) {
    const h = harness({ progress: async () => progress(state === 'completed' ? 3 : 0, 3, state) });
    assert.deepEqual(await h.run(), { state: state === 'aborted' ? 'stopped' : state });
    assert.deepEqual(h.calls, ['pending', 'progress:current']);
  }
  const snapshots = [progress(), progress(1, 3, 'paused')];
  const paused = harness({ progress: async () => snapshots.shift()!, advance: async () => operation('batch') });
  assert.deepEqual(await paused.run(), { state: 'paused' });
  assert.deepEqual(paused.calls, ['pending', 'progress:current', 'advance:migration', 'progress:migration']);
});

test('unchanged, regressed or replaced manifests stop after one batch rather than spinning', async () => {
  for (const next of [progress(1), progress(0), progress(2, 4), { ...progress(2), migrationId: 'changed' }, progress(2, 3, 'available')]) {
    const snapshots = [progress(1), next];
    const h = harness({ progress: async () => snapshots.shift()!, advance: async () => operation('batch') });
    await assert.rejects(h.run(), { code: 'UPDATE_STALLED' });
    assert.deepEqual(h.calls, ['pending', 'progress:current', 'advance:migration', 'progress:migration']);
  }
});

test('ready-to-finish still requires confirmed progress before finalization', async () => {
  const snapshots = [progress(2), progress(3)];
  const h = harness({ progress: async () => snapshots.shift()!, advance: async () => ({ state: 'ready_to_finish', migrationId: 'migration', completed: 3, total: 3 }), finish: async () => operation('finish') });
  assert.deepEqual(await h.run(), { state: 'completed' });
  const stalled = harness({ progress: async () => progress(2), advance: async () => ({ state: 'ready_to_finish', migrationId: 'migration', completed: 3, total: 3 }) });
  await assert.rejects(stalled.run(), { code: 'UPDATE_STALLED' });
});

test('non-finite, invalid and excessive manifest counts cannot schedule mutations', async () => {
  for (const snapshot of [progress(0, Infinity), progress(0, 20_001), progress(-1), progress(4), progress(0.5), progress(0, NaN), progress(1, 3, 'completed')]) {
    const h = harness({ progress: async () => snapshot });
    await assert.rejects(h.run(), { code: 'UPDATE_STALLED' });
    assert.deepEqual(h.calls, ['pending', 'progress:current']);
  }
});

test('six bounded finishing retries preserve the operation and stop on unresolved status', async () => {
  const h = harness({ pending: async () => ['saved'], resume: async id => operation('batch', id, 'finishing') });
  await assert.rejects(h.run(), { code: 'UPDATE_WAITING' });
  assert.deepEqual(h.calls, ['pending', ...Array<string>(7).fill('resume:saved')]);
  assert.deepEqual(h.waits, [250, 500, 1000, 2000, 4000, 4000]);
});

test('network and conflict failures propagate unchanged without replay or new mutations', async () => {
  for (const code of ['NETWORK', 'CONFLICT']) {
    for (const method of ['resume', 'start', 'advance', 'finish', 'progress'] as const) {
      const error = Object.assign(new Error(code), { code });
      const h = harness({ pending: async () => method === 'resume' ? ['unknown-write'] : [],
        progress: async () => { if (method === 'progress') throw error; return progress(method === 'finish' ? 3 : 0, 3, method === 'start' ? 'available' : 'active'); },
        resume: async () => { throw error; }, start: async () => { throw error; }, advance: async () => { throw error; }, finish: async () => { throw error; } });
      await assert.rejects(h.run(), value => value === error);
      assert.equal(h.calls.filter(call => call.startsWith(method)).length, 1);
      assert.deepEqual(h.waits, []);
    }
  }
});

test('auth clearing during a failed request stops quietly and does not start recovery work', async () => {
  const h = harness({ progress: async () => progress(), advance: async () => { h.stop(); throw Object.assign(new Error('CANCELLED'), { code: 'CANCELLED' }); } });
  assert.deepEqual(await h.run(), { state: 'stopped' });
  assert.deepEqual(h.calls, ['pending', 'progress:current', 'advance:migration']);
});

for (const source of ['finish', 'saved-finish', 'finishing-retry'] as const) {
  test(`pause during ${source} preserves a verified finish receipt without another context read`, async () => {
    let release!: (value: UpgradeOperationResult) => void;
    const finalRequest = new Promise<UpgradeOperationResult>(resolve => { release = resolve; });
    let entered!: () => void; const finishing = new Promise<void>(resolve => { entered = resolve; });
    const complete = async () => { entered(); return finalRequest; };
    const h = harness({
      pending: async () => source === 'saved-finish' ? ['saved-final'] : [],
      progress: async () => progress(3),
      finish: source === 'finishing-retry' ? async () => operation('finish', 'saved-final', 'finishing') : complete,
      resume: complete,
    });
    const running = h.run(); await finishing; h.stop(); release(operation('finish', 'saved-final'));
    assert.deepEqual(await running, { state: 'completed' });
    assert.deepEqual(h.calls, source === 'saved-finish' ? ['pending', 'resume:saved-final'] :
      ['pending', 'progress:current', 'finish:migration', ...(source === 'finishing-retry' ? ['resume:saved-final'] : [])]);
    assert.equal(h.reports.length, source === 'saved-finish' ? 0 : 1);
  });
}

test('pause during an unresolved finish preserves stopped state and schedules no retry', async () => {
  const h = harness({ progress: async () => progress(3), finish: async () => {
    h.stop(); return operation('finish', 'still-finishing', 'finishing');
  } });
  assert.deepEqual(await h.run(), { state: 'stopped' });
  assert.deepEqual(h.calls, ['pending', 'progress:current', 'finish:migration']);
  assert.deepEqual(h.waits, []);
});

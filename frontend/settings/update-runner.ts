import type { UpgradeController, UpgradeOperationResult } from '../../src/client/upgrade-controller.js';
import { UPGRADE_MAX_MANIFEST_RECORDS } from '../../src/shared/upgrade-api.js';

export type UpdateProgress = Awaited<ReturnType<UpgradeController['progress']>>;
export type UpdateStage = 'checking' | 'starting' | 'updating' | 'finishing' | 'waiting';
export type UpdateRunnerResult = { state: 'completed' | 'stopped' | 'paused' };
export interface UpdateRunnerOptions {
  upgrades: Pick<UpgradeController, 'pending' | 'resume' | 'progress' | 'start' | 'advance' | 'finish'>;
  shouldStop: () => boolean;
  onProgress: (progress: UpdateProgress) => void;
  onStage: (stage: UpdateStage) => void;
  wait?: (milliseconds: number) => Promise<void>;
}

const stopped = Symbol('update stopped');
const completed = Symbol('update completed');
const delay = (milliseconds: number) => new Promise<void>(resolve => setTimeout(resolve, milliseconds));
function updateError(code: 'UPDATE_WAITING' | 'UPDATE_STALLED') {
  return Object.assign(new Error(code), { code });
}

/** Run only after an explicit, confirmed request. The controller retains all
 * signing, verification and saved operation IDs. An unknown write result stops
 * this run; only a confirmed `finishing` result permits the same saved retry. */
export async function runWorkspaceUpdate({ upgrades, shouldStop, onProgress, onStage, wait = delay }: UpdateRunnerOptions): Promise<UpdateRunnerResult> {
  const check = () => { if (shouldStop()) throw stopped; };
  const stage = (value: UpdateStage) => { check(); onStage(value); check(); };
  const perform = async <T>(work: () => Promise<T>): Promise<T> => {
    check(); const result = await work(); check(); return result;
  };
  const performSaved = async (work: () => Promise<UpgradeOperationResult>) => {
    check(); const result = await work();
    // The controller returns this receipt only after verifying the committed
    // finish. A pause cannot undo that commit: preserve completion even if the
    // person stopped this run while the final request was already in flight.
    if (result.state === 'completed' && result.receipt.kind === 'finish') throw completed;
    check(); return result;
  };
  const report = (value: UpdateProgress) => {
    if (!Number.isSafeInteger(value.total) || !Number.isSafeInteger(value.completed) || value.total < 0 ||
      value.total > UPGRADE_MAX_MANIFEST_RECORDS || value.completed < 0 || value.completed > value.total ||
      value.state === 'completed' && value.completed !== value.total) throw updateError('UPDATE_STALLED');
    check(); onProgress(value); check(); return value;
  };
  const terminal = (value: UpdateProgress): UpdateRunnerResult | undefined => value.state === 'completed' ? { state: 'completed' } :
    value.state === 'paused' ? { state: 'paused' } : value.state === 'aborted' ? { state: 'stopped' } : undefined;
  const settle = async (initial: UpgradeOperationResult) => {
    let result = initial;
    const operationId = result.operationId;
    for (let attempt = 0; result.state === 'finishing'; attempt++) {
      if (attempt === 6) throw updateError('UPDATE_WAITING');
      stage('waiting');
      await perform(() => wait(Math.min(250 * 2 ** attempt, 4000)));
      result = await performSaved(() => upgrades.resume(operationId));
    }
    return result;
  };
  try {
    stage('checking');
    const pending = await perform(() => upgrades.pending());
    for (const operationId of pending) {
      await settle(await performSaved(() => upgrades.resume(operationId)));
    }
    let progress = report(await perform(() => upgrades.progress()));
    let ended = terminal(progress); if (ended) return ended;
    if (progress.state === 'available') {
      stage('starting');
      const result = await settle(await perform(() => upgrades.start()));
      progress = report(await perform(() => upgrades.progress(result.migrationId)));
      ended = terminal(progress); if (ended) return ended;
    }
    if (progress.state !== 'active') throw updateError('UPDATE_STALLED');
    const migrationId = progress.migrationId, total = progress.total;
    // Each verified batch must consume at least one member of this finite
    // manifest, so this run cannot silently grow or spin on unchanged progress.
    let remainingSteps = total - progress.completed;
    while (progress.completed < total) {
      if (remainingSteps-- <= 0) throw updateError('UPDATE_STALLED');
      stage('updating');
      const advanced = await perform(() => upgrades.advance(migrationId));
      if (advanced.state !== 'ready_to_finish') await settle(advanced);
      const next = report(await perform(() => upgrades.progress(migrationId)));
      if (next.migrationId !== migrationId || next.total !== total) throw updateError('UPDATE_STALLED');
      if (next.state === 'paused' || next.state === 'aborted') return terminal(next)!;
      if (next.completed <= progress.completed) throw updateError('UPDATE_STALLED');
      ended = terminal(next); if (ended) return ended;
      if (next.state !== 'active') throw updateError('UPDATE_STALLED');
      progress = next;
    }
    stage('finishing');
    const result = await settle(await performSaved(() => upgrades.finish(migrationId)));
    if (result.receipt.kind !== 'finish') throw updateError('UPDATE_STALLED');
    return { state: 'completed' };
  } catch (error) {
    if (error === completed) return { state: 'completed' };
    if (error === stopped || shouldStop()) return { state: 'stopped' };
    throw error;
  }
}

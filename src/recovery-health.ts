import type pg from 'pg';
import { z } from 'zod';

const age = z.number().finite().nonnegative().nullable();
const store = z.object({backupAgeMs: age, recoveryRecordLagMs: age,
  lastSuccessfulDrillAt: z.iso.datetime().nullable(), backupFresh: z.boolean(), recoveryRecordsFresh: z.boolean(),
  archiveFailureOutstanding: z.boolean()});
const checkpoints = z.object({activeWorkspaces:z.number().int().nonnegative().nullable(),coveredWorkspaces:z.number().int().nonnegative().nullable(),
  oldestUsableCheckpointAgeMs:age,checkpointsFresh:z.boolean()}).superRefine((value,context)=>{
  if((value.activeWorkspaces===null)!==(value.coveredWorkspaces===null)||
    value.activeWorkspaces!==null&&value.coveredWorkspaces!==null&&value.coveredWorkspaces>value.activeWorkspaces||
    value.oldestUsableCheckpointAgeMs!==null&&(value.activeWorkspaces===null||value.activeWorkspaces===0||value.coveredWorkspaces!==value.activeWorkspaces))
    context.addIssue({code:'custom',message:'Inconsistent checkpoint coverage'});
});
const recorded = z.object({app: store, control: store, controlReplication: z.object({
  synchronousCommit: z.enum(['on', 'remote_apply', 'remote_write', 'local', 'off']),
  configuredStandby: z.string().max(256), synchronousReplicas: z.number().int().nonnegative(), replayLagBytes: z.number().nonnegative(),
}),contentCheckpoints:checkpoints.optional()});
const FRESH_MS = 3 * 60_000, DAY_MS = 24 * 60 * 60_000;

/** Internal operator monitoring only. Missing evidence is explicitly unavailable,
 * never a zero-valued healthy metric. Age values continue to grow after capture. */
export async function recoveryHealth(control: pg.Pool, now = new Date()) {
  const row = (await control.query<{measured_at: Date;metrics:unknown}>(
    'SELECT measured_at,metrics FROM security.recovery_health WHERE id=true')).rows[0];
  if (!row) return {status: 'unmeasured' as const};
  const value = recorded.safeParse(row.metrics), elapsed = now.getTime() - row.measured_at.getTime();
  if (!value.success || !Number.isFinite(elapsed) || elapsed < -5000) return {status: 'invalid' as const};
  const adjusted = (s: z.infer<typeof store>) => {
    const backupAgeMs = s.backupAgeMs === null ? null : s.backupAgeMs + Math.max(0, elapsed);
    const recoveryRecordLagMs = s.recoveryRecordLagMs === null ? null : s.recoveryRecordLagMs + Math.max(0, elapsed);
    const drillAge = s.lastSuccessfulDrillAt === null ? null : now.getTime() - Date.parse(s.lastSuccessfulDrillAt);
    return {backupAgeMs, recoveryRecordLagMs, lastSuccessfulDrillAt: s.lastSuccessfulDrillAt,
      backupFresh: backupAgeMs !== null && backupAgeMs <= DAY_MS,
      recoveryRecordsFresh: recoveryRecordLagMs !== null && recoveryRecordLagMs <= 15 * 60_000,
      restoreDrillFresh: drillAge !== null && drillAge >= 0 && drillAge <= 30 * DAY_MS,
      archiveFailureOutstanding: s.archiveFailureOutstanding};
  };
  const application = adjusted(value.data.app), security = adjusted(value.data.control), r = value.data.controlReplication;
  const known = value.data.contentCheckpoints;
  const oldestUsableCheckpointAgeMs = known?.oldestUsableCheckpointAgeMs == null ? null : known.oldestUsableCheckpointAgeMs + Math.max(0,elapsed);
  const contentCheckpoints = {activeWorkspaces:known?.activeWorkspaces??null,coveredWorkspaces:known?.coveredWorkspaces??null,oldestUsableCheckpointAgeMs,
    checkpointsFresh:known!==undefined&&known.activeWorkspaces!==null&&known.coveredWorkspaces===known.activeWorkspaces&&
      (known.activeWorkspaces===0||oldestUsableCheckpointAgeMs!==null&&oldestUsableCheckpointAgeMs<=15*60_000)};
  const replicaDurable = ['on', 'remote_apply'].includes(r.synchronousCommit) && r.configuredStandby.length > 0 && r.synchronousReplicas > 0;
  const healthy = [application, security].every(s => s.backupFresh && s.recoveryRecordsFresh && s.restoreDrillFresh && !s.archiveFailureOutstanding) && replicaDurable && contentCheckpoints.checkpointsFresh;
  return {status: elapsed > FRESH_MS ? 'stale' as const : healthy ? 'healthy' as const : 'degraded' as const,
    measuredAt: row.measured_at.toISOString(), application, security, contentCheckpoints,
    controlReplication: {durable: replicaDurable, synchronousReplicas: r.synchronousReplicas, replayLagBytes: r.replayLagBytes}};
}

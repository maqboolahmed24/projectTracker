import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir,mkdtemp,readFile,rm,writeFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import { restorationFixture } from '../dist/test/restoration-fixture.js';
import { origin } from '../dist/test/password-change-fixture.js';
import { RestorationService } from '../dist/src/modules/restoration/service.js';
import { finalizeDeletionIfDue } from '../dist/src/modules/lifecycle/deadline.js';
import { EntitlementOperations } from '../dist/src/modules/identity/entitlements.js';
import { transaction } from '../dist/src/db.js';
import * as restoration from '../dist/src/shared/restoration.js';
import * as manifest from '../dist/src/modules/restoration/manifest.js';
import * as purge from '../dist/src/modules/lifecycle/purge.js';
import * as crypto from '../dist/src/shared/crypto.js';
import { recoveryCommand } from './recovery.mjs';
import { repositoryInfo } from './physical-backups.mjs';
import { RecoveryRecords,repositorySecret } from '../ops/recovery-records.mjs';
import { CONTENT_CHECKPOINT_INTERVAL_MS } from '../ops/recovery-policy.mjs';

// Explicit local operations drill; excluded from npm test. Only JavaScript Date
// advances. PostgreSQL, WAL archival, pgBackRest, disk IO and timers remain real.
test('CP12 checkpoint schedule: real signed WAL points reuse daily full bases and reject corrupt freshness evidence',async t=>{
  const drillId=randomUUID(),started=performance.now(),originalControlAdmin=process.env.CONTROL_ADMIN_DATABASE_URL;
  let f,directory,previousHealth,healthCaptured=false;
  t.after(async()=>{
    t.mock.timers.reset();
    if(f&&healthCaptured){
      if(previousHealth)await f.admin.control.query('INSERT INTO security.recovery_health(id,measured_at,metrics) VALUES(true,$1,$2) ON CONFLICT(id) DO UPDATE SET measured_at=EXCLUDED.measured_at,metrics=EXCLUDED.metrics',[previousHealth.measured_at,previousHealth.metrics]);
      else await f.admin.control.query('DELETE FROM security.recovery_health WHERE id=true');
    }
    if(directory)await rm(directory,{recursive:true,force:true});
    if(originalControlAdmin===undefined)delete process.env.CONTROL_ADMIN_DATABASE_URL;else process.env.CONTROL_ADMIN_DATABASE_URL=originalControlAdmin;
  });
  // Fixture runtime configuration must not inherit operator-only admin secrets.
  f=await restorationFixture(t);
  process.env.CONTROL_ADMIN_DATABASE_URL=originalControlAdmin??parseEnv(await readFile('.env.admin','utf8')).CONTROL_ADMIN_DATABASE_URL;
  previousHealth=(await f.admin.control.query('SELECT measured_at,metrics FROM security.recovery_health WHERE id=true')).rows[0];healthCaptured=true;
  const eligible=(await f.admin.control.query("SELECT workspace_id FROM security.workspaces WHERE lifecycle IN('active','pending_deletion') AND NOT restore_quarantine AND (delete_after IS NULL OR delete_after>clock_timestamp()) ORDER BY workspace_id")).rows.map(row=>row.workspace_id);
  assert.deepEqual(eligible,[f.workspaceId],'Run the scheduling drill in an otherwise idle disposable database');
  await mkdir('.local',{recursive:true,mode:0o700});directory=await mkdtemp('.local/recovery-schedule-');
  const records=new RecoveryRecords(directory,await repositorySecret('.local/recovery/app.conf')),
    trusted={[f.secrets.keyId]:await new EntitlementOperations(f.databases,f.secrets).publicSigningKey()},
    runtime={databases:f.databases,secrets:f.secrets,application:f.admin.application,control:f.admin.control,actor:f.operator,records,transaction,
      ...restoration,...manifest,...purge,...crypto,trusted,
      service:hooks=>new RestorationService({...f,origin,...(hooks?{hooks}:{})}),
      finalize:workspaceId=>finalizeDeletionIfDue({...f,workspaceId})};
  const first=await recoveryCommand(runtime,'tick');assert.equal(first.checkpoints.length,1);
  const initial=first.checkpoints[0];assert.equal(initial.workspaceId,f.workspaceId);
  const saved=await records.read(f.workspaceId,initial.checkpointId);
  await restoration.verifyRestoreServiceObject(saved.value.manifest,trusted);
  assert.equal(saved.value.manifest.body.capturedAt,initial.capturedAt);assert.ok(saved.value.keyObjects.length>0);
  const fullLabels={};for(const store of ['app','control'])fullLabels[store]=(await repositoryInfo(store)).backup.map(row=>row.label);
  const schedulerStart=Date.now();t.mock.timers.enable({apis:['Date'],now:schedulerStart});
  const immediate=await recoveryCommand(runtime,'tick');assert.deepEqual(immediate.checkpoints,[]);assert.equal((await records.list()).length,1);
  t.mock.timers.tick(CONTENT_CHECKPOINT_INTERVAL_MS+1);
  const due=await recoveryCommand(runtime,'tick');assert.equal(due.checkpoints.length,1);
  const next=due.checkpoints[0];assert.notEqual(next.checkpointId,initial.checkpointId);
  const checkpointInterval=Date.parse(next.capturedAt)-Date.parse(initial.capturedAt);
  assert.equal(checkpointInterval,schedulerStart+CONTENT_CHECKPOINT_INTERVAL_MS+1-Date.parse(initial.capturedAt));
  assert.ok(checkpointInterval>=CONTENT_CHECKPOINT_INTERVAL_MS+1);
  assert.equal(next.backupLabel,initial.backupLabel);assert.equal(next.controlBackupLabel,initial.controlBackupLabel);
  const fresh=await recoveryCommand(runtime,'metrics');assert.deepEqual(fresh.contentCheckpoints,
    {activeWorkspaces:1,coveredWorkspaces:1,oldestUsableCheckpointAgeMs:0,checkpointsFresh:true});
  // The latest opaque index still exists, but changed authenticated ciphertext
  // cannot claim freshness. The older signed point is the only usable fallback.
  const latestPath=`${directory}/${f.workspaceId}.${next.checkpointId}.sealed`,corrupt=JSON.parse(await readFile(latestPath,'utf8'));
  const tag=Buffer.from(corrupt.tag,'base64');tag[0]^=1;corrupt.tag=tag.toString('base64');await writeFile(latestPath,JSON.stringify(corrupt));
  await assert.rejects(records.read(f.workspaceId,next.checkpointId));
  const fallback=await recoveryCommand(runtime,'metrics');assert.deepEqual(fallback.contentCheckpoints,
    {activeWorkspaces:1,coveredWorkspaces:1,oldestUsableCheckpointAgeMs:checkpointInterval,checkpointsFresh:true});
  const replacement=await recoveryCommand(runtime,'tick');assert.equal(replacement.checkpoints.length,1);
  assert.notEqual(replacement.checkpoints[0].checkpointId,next.checkpointId);
  assert.equal(replacement.checkpoints[0].backupLabel,initial.backupLabel);assert.equal(replacement.checkpoints[0].controlBackupLabel,initial.controlBackupLabel);
  assert.equal((await recoveryCommand(runtime,'metrics')).contentCheckpoints.oldestUsableCheckpointAgeMs,0);
  for(const store of ['app','control'])assert.deepEqual((await repositoryInfo(store)).backup.map(row=>row.label),fullLabels[store]);
  assert.equal((await records.list()).length,3);
  t.mock.timers.reset();
  const evidence={drillId,completedAt:new Date().toISOString(),workspaceId:f.workspaceId,totalWallMs:Math.round(performance.now()-started),
    schedulerClock:'node:test Date only; database, archives, subprocesses and delay timers use real time',schedulerAdvanceMs:CONTENT_CHECKPOINT_INTERVAL_MS+1,
    firstTickCaptured:true,immediateTickCaptured:false,dueTickCaptured:true,dailyFullLabelsUnchanged:true,
    fullLabels:{app:initial.backupLabel,control:initial.controlBackupLabel},checkpointIds:[initial.checkpointId,next.checkpointId,replacement.checkpoints[0].checkpointId],
    corruptLatestRejected:true,authenticatedFallbackAgeMs:fallback.contentCheckpoints.oldestUsableCheckpointAgeMs,replacementCaptured:true,
    environment:'local single-host Docker; disposable encrypted fixture; scheduling evidence, not measured wall-clock RPO'};
  await mkdir('test-results',{recursive:true});await writeFile(`test-results/checkpoint-12-schedule-drill-${drillId}.json`,JSON.stringify(evidence,null,2)+'\n');
  t.diagnostic(JSON.stringify(evidence));
});

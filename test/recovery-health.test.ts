import test from 'node:test';
import assert from 'node:assert/strict';
import type pg from 'pg';
import { recoveryHealth } from '../src/recovery-health.js';

const now = new Date('2026-09-27T12:00:00Z');
const store = {backupAgeMs: 1000, recoveryRecordLagMs: 1000, lastSuccessfulDrillAt: now.toISOString(),
  backupFresh: true, recoveryRecordsFresh: true, archiveFailureOutstanding: false};
const metrics = {app: store, control: store, contentCheckpoints:{activeWorkspaces:2,coveredWorkspaces:2,oldestUsableCheckpointAgeMs:1000,checkpointsFresh:true},
  controlReplication: {synchronousCommit: 'on', configuredStandby: 'FIRST 1 (replica)', synchronousReplicas: 1, replayLagBytes: 0}};
const pool = (rows: unknown[]) => ({query: async () => ({rows})}) as unknown as pg.Pool;

test('recovery monitoring distinguishes missing, malformed, stale and measured evidence', async () => {
  assert.equal((await recoveryHealth(pool([]), now)).status, 'unmeasured');
  assert.equal((await recoveryHealth(pool([{measured_at: now, metrics: {app: {}}}]), now)).status, 'invalid');
  assert.equal((await recoveryHealth(pool([{measured_at: now, metrics}]), now)).status, 'healthy');
  const measured = new Date(now.getTime() - 190000);
  const old = await recoveryHealth(pool([{measured_at: measured, metrics}]), now);
  assert.equal(old.status, 'stale'); assert.equal(old.application?.backupAgeMs, 191000);
});
test('unknown drills, failed archives and non-durable replication cannot report healthy recovery', async () => {
  for (const bad of [
    {...metrics, app: {...store, lastSuccessfulDrillAt: null}},
    {...metrics, app: {...store, archiveFailureOutstanding: true}},
    {...metrics, controlReplication: {...metrics.controlReplication, synchronousCommit: 'remote_write'}},
    {...metrics, controlReplication: {...metrics.controlReplication, synchronousReplicas: 0}},
  ]) assert.equal((await recoveryHealth(pool([{measured_at: now, metrics: bad}]), now)).status, 'degraded');
});

test('fresh WAL cannot conceal a stale usable manifest, and checkpoint age grows after measurement',async()=>{
  const stale={...metrics,contentCheckpoints:{...metrics.contentCheckpoints,oldestUsableCheckpointAgeMs:900001,checkpointsFresh:true}};
  const result=await recoveryHealth(pool([{measured_at:now,metrics:stale}]),now);
  assert.equal(result.application?.recoveryRecordsFresh,true);assert.equal(result.contentCheckpoints?.checkpointsFresh,false);assert.equal(result.status,'degraded');
  const near={...metrics,contentCheckpoints:{...metrics.contentCheckpoints,oldestUsableCheckpointAgeMs:899000}};
  const aged=await recoveryHealth(pool([{measured_at:new Date(now.getTime()-2000),metrics:near}]),now);
  assert.equal(aged.contentCheckpoints?.oldestUsableCheckpointAgeMs,901000);assert.equal(aged.status,'degraded');
});

test('legacy health rows remain readable but report missing checkpoint evidence explicitly',async()=>{
  const {contentCheckpoints:_checkpoints,...legacy}=metrics;
  const result=await recoveryHealth(pool([{measured_at:now,metrics:legacy}]),now);
  assert.equal(result.status,'degraded');assert.equal(result.application?.backupAgeMs,1000);
  assert.deepEqual(result.contentCheckpoints,{activeWorkspaces:null,coveredWorkspaces:null,oldestUsableCheckpointAgeMs:null,checkpointsFresh:false});
  const missing={...metrics,contentCheckpoints:{activeWorkspaces:2,coveredWorkspaces:1,oldestUsableCheckpointAgeMs:null,checkpointsFresh:true}};
  const partial=await recoveryHealth(pool([{measured_at:now,metrics:missing}]),now);assert.equal(partial.status,'degraded');assert.equal(partial.contentCheckpoints?.oldestUsableCheckpointAgeMs,null);
  const empty={...metrics,contentCheckpoints:{activeWorkspaces:0,coveredWorkspaces:0,oldestUsableCheckpointAgeMs:null,checkpointsFresh:true}};
  assert.equal((await recoveryHealth(pool([{measured_at:now,metrics:empty}]),now)).status,'healthy');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { backupConfiguration, backupHealth, checkpointDue, checkpointHealth, CONTENT_CHECKPOINT_INTERVAL_MS, DAY, openCheckpoint, planDeletionExpiry, sealCheckpoint } from '../ops/recovery-policy.mjs';

test('independent encrypted stores retain continuous archives and remove expired backup history', () => {
  for (const store of ['app', 'control']) {
    const config = backupConfiguration(store, 'ab'.repeat(32));
    assert.match(config, /repo1-cipher-type=aes-256-cbc/);
    assert.match(config, /repo1-retention-full-type=time\nrepo1-retention-full=30/);
    assert.match(config, /repo1-retention-history=0/);
    assert.match(config, /archive-async=n/);
    assert.ok(!config.includes('repo1-retention-archive='));
  }
  assert.throws(() => backupConfiguration('other', 'ab'.repeat(32)));
  assert.throws(() => backupConfiguration('app', 'secret\nrepo1-path=/elsewhere'));
});
test('deadline expiry includes backups started before purge and cannot destroy the only recovery base', () => {
  const at = Date.parse('2026-09-01T12:00:00Z');
  const purge = {livePayloadsPurgedAt: new Date(at).toISOString(), backupExpiresAt: new Date(at + 30 * DAY).toISOString()};
  const backups = [{label: 'before', type: 'full', timestamp: {start: (at - DAY) / 1000, stop: (at - DAY + 60000) / 1000}},
    {label: 'overlap', type: 'full', timestamp: {start: (at - 1000) / 1000, stop: (at + 1000) / 1000}},
    {label: 'clean', type: 'full', timestamp: {start: (at + 1000) / 1000, stop: (at + 2000) / 1000}}];
  assert.deepEqual(planDeletionExpiry(backups, [purge], at + 30 * DAY - 1), []);
  assert.deepEqual(planDeletionExpiry(backups, [purge], at + 30 * DAY), ['before', 'overlap']);
  assert.throws(() => planDeletionExpiry(backups.slice(0, 2), [purge], at + 30 * DAY), /clean full backup/);
  assert.throws(() => planDeletionExpiry(backups, [{...purge, backupExpiresAt: new Date(at + 31 * DAY).toISOString()}], at + 32 * DAY), /deadline/);
});
test('unmeasured and failed backup/archive states never become healthy zeroes', () => {
  const now = Date.now();
  const missing = backupHealth([], {}, {now});
  assert.equal(missing.backupAgeMs, null); assert.equal(missing.recoveryRecordLagMs, null);
  assert.equal(missing.lastSuccessfulDrillAt, null); assert.equal(missing.backupFresh, false); assert.equal(missing.recoveryRecordsFresh, false);
  const actual = backupHealth([{timestamp: {stop: (now - 1000) / 1000}}], {last_archived_time: new Date(now - 2000).toISOString(), last_failed_time: new Date(now - 500).toISOString()}, {now});
  assert.equal(actual.backupAgeMs, 1000); assert.equal(actual.backupFresh, true); assert.equal(actual.archiveFailureOutstanding, true);
});
test('checkpoint envelope authenticates tenant/identity, secret and complete bytes with fresh nonces', () => {
  const workspace = '10000000-0000-4000-8000-000000000001', checkpoint = '10000000-0000-4000-8000-000000000002';
  const secret = '42'.repeat(32), payload = {manifest: {signed: true}, keyObjects: ['already-encrypted']};
  const encoded = sealCheckpoint(payload, secret, workspace, checkpoint);
  assert.deepEqual(openCheckpoint(encoded, secret, workspace, checkpoint), payload);
  assert.notEqual(encoded, sealCheckpoint(payload, secret, workspace, checkpoint));
  assert.ok(!encoded.includes('already-encrypted'));
  assert.throws(() => openCheckpoint(encoded, '43'.repeat(32), workspace, checkpoint));
  assert.throws(() => openCheckpoint(encoded, secret, checkpoint, workspace));
  const tampered = JSON.parse(encoded); tampered.ciphertext = Buffer.from('changed').toString('base64');
  assert.throws(() => openCheckpoint(JSON.stringify(tampered), secret, workspace, checkpoint));
});

test('content checkpoints become due every five minutes independently of the daily full backup cadence', () => {
  const now=Date.parse('2026-09-27T12:00:00Z');assert.equal(CONTENT_CHECKPOINT_INTERVAL_MS,300000);
  const index={capturedAt:new Date(now-CONTENT_CHECKPOINT_INTERVAL_MS+1).toISOString()};
  assert.equal(checkpointDue(index,now),false);assert.equal(checkpointDue(index,now+1),true);
  for(const absent of [null,{}, {capturedAt:'invalid'}, {capturedAt:new Date(now+1).toISOString()}])assert.equal(checkpointDue(absent,now),true);
  assert.throws(()=>checkpointDue(index,NaN));
});

test('usable checkpoint health uses each active workspace latest point and exposes the oldest of those points', () => {
  const now=Date.parse('2026-09-27T12:00:00Z'),point=(workspaceId,age)=>({workspaceId,capturedAt:new Date(now-age).toISOString()});
  assert.deepEqual(checkpointHealth(['one','two'],[point('one',DAY),point('one',1000),point('two',300000),point('retired',DAY)],{now}),
    {activeWorkspaces:2,coveredWorkspaces:2,oldestUsableCheckpointAgeMs:300000,checkpointsFresh:true});
  const late=checkpointHealth(['one','two'],[point('one',1000),point('two',900001)],{now});assert.equal(late.oldestUsableCheckpointAgeMs,900001);assert.equal(late.checkpointsFresh,false);
  const freshWal=backupHealth([{timestamp:{stop:(now-1000)/1000}}],{last_archived_time:new Date(now-1000).toISOString()},{now});
  assert.equal(freshWal.recoveryRecordsFresh,true);assert.equal(late.checkpointsFresh,false);
});

test('missing checkpoint coverage and unavailable inventory stay unknown rather than healthy zeroes', () => {
  const now=Date.parse('2026-09-27T12:00:00Z');
  assert.deepEqual(checkpointHealth(null,null,{now}),{activeWorkspaces:null,coveredWorkspaces:null,oldestUsableCheckpointAgeMs:null,checkpointsFresh:false});
  assert.deepEqual(checkpointHealth(['one','two'],[{workspaceId:'one',capturedAt:new Date(now-1000).toISOString()},
    {workspaceId:'two',capturedAt:new Date(now+1).toISOString()}],{now}),{activeWorkspaces:2,coveredWorkspaces:1,oldestUsableCheckpointAgeMs:null,checkpointsFresh:false});
  assert.deepEqual(checkpointHealth([],[],{now}),{activeWorkspaces:0,coveredWorkspaces:0,oldestUsableCheckpointAgeMs:null,checkpointsFresh:true});
});

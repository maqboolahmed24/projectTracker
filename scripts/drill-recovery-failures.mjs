import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { compose, sql, withPhysicalLock } from './physical-backups.mjs';

const result = await withPhysicalLock(async () => {
  const drillId = randomUUID();
  // Override with a deliberately wrong public fixture secret. No actual secret
  // is placed in argv, reports or error output.
  // `info` returns exit 0 and can put non-JSON error bytes in its JSON output.
  // `check` has an authoritative failure exit status and logs are suppressed.
  await assert.rejects(compose(['exec', '-T', '--user', 'postgres', '-e', `PGBACKREST_REPO1_CIPHER_PASS=${'00'.repeat(32)}`,
    'app-db', 'pgbackrest', '--stanza=app', 'check']));
  let acknowledged = false, writeFailure, pendingWrite;
  let synchronousWaitObserved = false;
  await compose(['stop', '-t', '10', 'control-replica']);
  try {
    pendingWrite = sql('control', `INSERT INTO ukda_recovery_drill.probes VALUES('${drillId}','synchronous-wait-probe');`)
      .then(() => { acknowledged = true; }, error => { writeFailure = error; });
    // statement_timeout does not bound an implicit COMMIT's synchronous wait.
    // Observe the real wait, then restore the replica before awaiting completion.
    for (let i = 0; i < 50; i++) {
      const waiting = await sql('control', `SELECT count(*) FROM pg_stat_activity WHERE wait_event='SyncRep' AND query LIKE '%${drillId}%'`);
      if (waiting === '1') { synchronousWaitObserved = true; break; }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(synchronousWaitObserved && !acknowledged && !writeFailure, 'Security writes must wait for their durable replica before acknowledging');
    assert.equal(await sql('control', "SELECT current_setting('synchronous_standby_names')"), 'FIRST 1 (ukda_control_replica)');
  } finally { await compose(['start', '--wait', 'control-replica']); }
  await pendingWrite;
  assert.ok(acknowledged && !writeFailure, 'The original write must complete after the same replica returns');
  let replayed = false;
  for (let i = 0; i < 30; i++) {
    const read = await compose(['exec', '-T', 'control-replica', 'gosu', 'postgres', 'psql', '-X', '-U', 'ukda_control_admin', '-d', 'ukda_control', '-Atc', `SELECT count(*) FROM ukda_recovery_drill.probes WHERE id='${drillId}'`]);
    if (read === '1') { replayed = true; break; }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  assert.ok(replayed, 'The unacknowledged local commit must reach the replica after it returns');
  await sql('control', `DELETE FROM ukda_recovery_drill.probes WHERE id='${drillId}'`);
  return {drillId, completedAt: new Date().toISOString(), wrongRepositorySecretRejected: true,
    replicaOutagePreventedAcknowledgement: true, resumedReplicationVerified: true,
    synchronousWaitObserved, note: 'The original write waited, then acknowledged after the same replica returned; no weaker commit mode or repeated write was used.'};
});
process.stdout.write(JSON.stringify(result, null, 2) + '\n');

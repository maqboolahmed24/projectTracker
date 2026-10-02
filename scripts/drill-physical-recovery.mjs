import { randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { backrest, compose, execute, isolatedRestore, repositoryInfo, sql, withPhysicalLock, metrics } from './physical-backups.mjs';
import { storeInfo } from '../ops/recovery-policy.mjs';

/** Bounded, explicit local infrastructure drill. It never installs the restored
 * snapshot into live application/control data. Composed Owner recovery is a
 * separate mandatory checkpoint-12 drill. Every artifact identifies that limit. */
export async function drillPhysicalRecovery() {
  return withPhysicalLock(async () => {
    const drillId = randomUUID(), target = `ukda_cp_${drillId.replaceAll('-', '_')}`, startedAt = Date.now();
    const results = [];
    for (const store of ['app', 'control']) {
      const latest = (await repositoryInfo(store)).backup.at(-1);
      if (!latest) throw new Error('Create physical backups before running a recovery drill');
      await sql(store, `CREATE SCHEMA IF NOT EXISTS ukda_recovery_drill;\nCREATE TABLE IF NOT EXISTS ukda_recovery_drill.probes(id uuid PRIMARY KEY,value text NOT NULL);\nINSERT INTO ukda_recovery_drill.probes VALUES('${drillId}','at-checkpoint');\nSELECT pg_create_restore_point('${target}');\nUPDATE ukda_recovery_drill.probes SET value='current-authority-remains-later' WHERE id='${drillId}';\nSELECT pg_switch_wal();`);
      await backrest(store, ['check']);
      const recoveryStarted = Date.now(), recovered = await isolatedRestore(store, latest.label, target);
      const selected = await execute(['exec', '--user', 'postgres', recovered.name, 'psql', '-X', '-U', storeInfo(store).user, '-d', storeInfo(store).database, '-Atc', `SELECT value FROM ukda_recovery_drill.probes WHERE id='${drillId}'`]);
      const current = await sql(store, `SELECT value FROM ukda_recovery_drill.probes WHERE id='${drillId}'`);
      if (selected !== 'at-checkpoint' || current !== 'current-authority-remains-later') throw new Error(`PITR content mismatch in ${store}; retained ${recovered.name}`);
      results.push({...recovered, recoveredValue: selected, currentValue: current, replayDurationMs: Date.now() - recoveryStarted});
      // Keep the paused snapshot volume for the evidence period, but stop its
      // process so it cannot be mistaken for an active database service.
      await execute(['exec', '--user', 'postgres', recovered.name, 'pg_ctl', '-D', '/var/lib/postgresql/18/docker', '-m', 'fast', '-w', 'stop']);
      await execute(['stop', recovered.name]);
      await sql(store, `DELETE FROM ukda_recovery_drill.probes WHERE id='${drillId}';`);
    }
    // The acknowledged control write must be visible on the actual standby.
    const replication = await compose(['exec', '-T', 'control-replica', 'gosu', 'postgres', 'psql', '-X', '-U', 'ukda_control_admin', '-d', 'ukda_control', '-Atc', "SELECT pg_is_in_recovery() AND EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='ukda_recovery_drill')"]);
    if (replication !== 't') throw new Error('Security replica did not retain the acknowledged schema');
    const result = {version: 1, drillId, completedAt: new Date().toISOString(), elapsedMs: Date.now() - startedAt,
      scope: 'physical PITR and separate current primaries only; Owner verification and revocation matrix still required',
      results, synchronousReplicaVerified: true, metrics: await metrics()};
    const path = fileURLToPath(new URL(`../test-results/checkpoint-12-physical-drill-${drillId}.json`, import.meta.url));
    await writeFile(path, JSON.stringify(result, null, 2) + '\n', {flag: 'wx', mode: 0o600});
    return {path, ...result};
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.stdout.write(JSON.stringify(await drillPhysicalRecovery(), null, 2) + '\n'); }
  catch (error) { process.stderr.write(`Physical drill failed: ${error.message}\n`); process.exitCode = 1; }
}

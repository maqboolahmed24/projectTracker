import { spawn } from 'node:child_process';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import pg from 'pg';
import { backupConfiguration, backupHealth, storeInfo } from '../ops/recovery-policy.mjs';
import { recoveryDeployment, recoveryImage, replicationPassword, replicationHbaRules, replicationReadinessSql } from '../ops/recovery-deployment.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const deployment = recoveryDeployment();
const directory = deployment.directory;
const docker = process.env.UKDA_DOCKER ?? 'docker';
const composeArgs = deployment.composeArgs;
export const PHYSICAL_LOCK = 'ukda.recovery:physical';

/** Never surface child stdout/stderr on failure: operational tools can otherwise
 * disclose credentials or row contents. Successful commands return only their
 * deliberately selected metadata to their caller. No shell interpolation. */
export async function execute(args, {input, timeoutMs = 600000} = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(docker, args, {cwd: root, stdio: ['pipe', 'pipe', 'pipe']});
    let out = '', size = 0, exceeded = false;
    const timer = setTimeout(() => { child.kill('SIGTERM'); }, timeoutMs);
    child.stdout.on('data', b => { size += b.length; if (size > 64 * 1024 * 1024) { exceeded = true; child.kill('SIGTERM'); } else out += b; });
    child.stderr.on('data', () => {});
    child.once('error', () => { clearTimeout(timer); reject(new Error('Recovery subprocess could not start')); });
    child.once('close', code => { clearTimeout(timer); code === 0 && !exceeded ? resolve(out.trim()) : reject(new Error('Recovery subprocess failed; inspect its current process/container state before retrying')); });
    child.stdin.on('error', () => {}); child.stdin.end(input);
  });
}
export const compose = (args, options) => execute([...composeArgs, ...args], options);
export async function sql(store, statement) {
  const s = storeInfo(store);
  return compose(['exec', '-T', s.service, 'psql', '-X', '-U', s.user, '-d', s.database, '-At', '-v', 'ON_ERROR_STOP=1'], {input: statement});
}
export async function backrest(store, args) {
  return compose(['exec', '-T', '--user', 'postgres', storeInfo(store).service, 'pgbackrest', `--stanza=${store}`, ...args]);
}
export async function repositoryInfo(store) {
  let value;
  try { value = JSON.parse(await backrest(store, ['--output=json', 'info'])); }
  catch { throw new Error('Recovery repository information is unavailable or invalid'); }
  const info = value.find(v => v.name === store);
  if (!info || info.status.code !== 0) throw new Error('Recovery repository not ready');
  return info;
}
export async function withPhysicalLock(action) {
  const url = process.env.CONTROL_ADMIN_DATABASE_URL;
  if (!url) throw new Error('CONTROL_ADMIN_DATABASE_URL is required for recovery operations');
  const client = new pg.Client({connectionString: url, connectionTimeoutMillis: 5000, application_name: 'ukda-recovery-operator'});
  await client.connect();
  try {
    const locked = await client.query('SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS acquired', [PHYSICAL_LOCK]);
    if (!locked.rows[0]?.acquired) throw new Error('Another recovery or purge operation is active');
    return await action(client);
  } finally { await client.end(); }
}
async function waitFor(check, label) {
  for (let i = 0; i < 60; i++) { if (await check()) return; await new Promise(r => setTimeout(r, 1000)); }
  throw new Error(`Timed out waiting for ${label}; the existing operation must be inspected before retrying`);
}

export async function setup({configuration = deployment, runCompose = compose, runSql = sql, runBackrest = backrest, wait = waitFor} = {}) {
  const directory = configuration.directory;
  await mkdir(directory, {recursive: true, mode: 0o700}); await chmod(directory, 0o700);
  for (const store of ['app', 'control']) {
    const path = `${directory}/${store}.conf`;
    try { await writeFile(path, backupConfiguration(store, randomBytes(32).toString('hex')), {flag: 'wx', mode: 0o600}); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    await chmod(path, 0o600);
  }
  const passfile = `${directory}/replication.pgpass`;
  try { await writeFile(passfile, `${configuration.primaryHost}:5432:*:ukda_replica:${randomBytes(32).toString('hex')}\n`, {flag: 'wx', mode: 0o600}); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  await chmod(passfile, 0o600);
  const password = replicationPassword(await readFile(passfile, 'utf8'), configuration);
  await runCompose(['up', '-d', '--no-build', '--wait', 'app-db', 'control-db']);
  if (configuration.requireTls && await runSql('control', 'SHOW ssl;') !== 'on') throw new Error('Primary database TLS must be enabled before replication setup');
  // Never disable synchronous commits on an existing installation. An existing
  // replica may start before these read-only idempotency checks on a resumed setup.
  const exists = await runSql('control', "SELECT count(*) FROM pg_roles WHERE rolname='ukda_replica';");
  if (exists === '0') await runSql('control', `CREATE ROLE ukda_replica WITH LOGIN REPLICATION PASSWORD '${password}';`);
  // Prepend the managed grant and rejection before legacy/broader rules. A
  // resumed cloud setup must not leave the old local 'all' grant effective.
  await runCompose(['exec', '-T', 'control-db', 'sh', '-c', `set -eu
temporary=$(mktemp "$PGDATA/pg_hba.conf.ukda.XXXXXX")
trap 'rm -f "$temporary"' EXIT
{
  printf '%s\\n' '# BEGIN UKDA REPLICATION' "$1" "$2" '# END UKDA REPLICATION'
  awk '/^# BEGIN UKDA REPLICATION$/ {if (skip) exit 1; skip=1; next} /^# END UKDA REPLICATION$/ {if (!skip) exit 1; skip=0; next} !skip {print} END {if (skip) exit 1}' "$PGDATA/pg_hba.conf"
} > "$temporary"
chown postgres:postgres "$temporary"
chmod 600 "$temporary"
mv "$temporary" "$PGDATA/pg_hba.conf"`, 'ukda-replication-hba', ...replicationHbaRules(configuration)]);
  if (await runSql('control', 'SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL;') !== '0') throw new Error('Replication access rules are invalid');
  await runSql('control', 'SELECT pg_reload_conf();');
  if (configuration.replicaMode !== 'external') await runCompose(['up', '-d', '--no-build', '--wait', 'control-replica']);
  await wait(async () => (await runSql('control', replicationReadinessSql(configuration))) === '1', 'streaming replica');
  await runSql('control', "ALTER SYSTEM SET synchronous_standby_names='FIRST 1 (ukda_control_replica)';\nSELECT pg_reload_conf();");
  await wait(async () => (await runSql('control', replicationReadinessSql(configuration, true))) === '1', 'durable synchronous replica');
  for (const store of ['app', 'control']) { await runBackrest(store, ['stanza-create']); await runBackrest(store, ['check']); }
  return {configured: true, replica: 'synchronous', repositoryEncryption: 'aes-256-cbc', retentionDays: 30, archiveTimeoutSeconds: 60};
}
export async function assertNoPartialPurge(control) {
  const exists = await control.query("SELECT to_regclass('security.workspace_purges') IS NOT NULL AS present");
  if (exists.rows[0]?.present) {
    // Block from the durable tombstone onward, including a crash between the
    // application delete and control-store progress update.
    const pending = await control.query('SELECT 1 FROM security.workspace_purges WHERE live_payloads_purged_at IS NULL LIMIT 1');
    if (pending.rowCount) throw new Error('Finish physical workspace purge before creating another backup');
  }
}
/** The caller holds PHYSICAL_LOCK through checkpoint-manifest capture as well. */
export async function physicalFullBackups(control, {purgeInProgress = false} = {}) {
  if (!purgeInProgress) await assertNoPartialPurge(control);
  const results = {};
  for (const store of ['app', 'control']) {
    await backrest(store, ['--type=full', 'backup']);
    const info = await repositoryInfo(store), latest = info.backup.at(-1);
    if (!latest || latest.type !== 'full') throw new Error('Full backup not confirmed');
    results[store] = {label: latest.label, start: latest.timestamp.start, stop: latest.timestamp.stop, archive: latest.archive};
  }
  return results;
}
export async function metrics() {
  const result = {};
  for (const store of ['app', 'control']) {
    const info = await repositoryInfo(store);
    const archiver = JSON.parse(await sql(store, 'SELECT row_to_json(s) FROM (SELECT last_archived_time,last_failed_time,archived_count,failed_count FROM pg_stat_archiver) s;'));
    result[store] = backupHealth(info.backup, archiver);
  }
  result.controlReplication = JSON.parse(await sql('control', "SELECT json_build_object('synchronousCommit',current_setting('synchronous_commit'),'configuredStandby',current_setting('synchronous_standby_names'),'synchronousReplicas',(SELECT count(*) FROM pg_stat_replication WHERE state='streaming' AND sync_state='sync'),'replayLagBytes',(SELECT coalesce(max(pg_wal_lsn_diff(pg_current_wal_lsn(),replay_lsn)),0) FROM pg_stat_replication WHERE application_name='ukda_control_replica'))"));
  return result;
}

/** Restore only into a new, network-isolated volume/container. There is no option
 * to overwrite either running primary. Control restores are recovery evidence;
 * an old control copy is never promoted as current application authority. */
export async function isolatedRestore(store, label, target) {
  storeInfo(store);
  if (!/^\d{8}-\d{6}F$/.test(label) || !/^ukda_cp_[a-f0-9_]{8,64}$/.test(target)) throw new Error('Invalid backup label or restore point');
  const info = await repositoryInfo(store);
  if (!info.backup.some(b => b.label === label)) throw new Error('Backup label is not present');
  const id = await compose(['ps', '-q', storeInfo(store).service]);
  const inspection = JSON.parse(await execute(['inspect', id]))[0];
  const image = recoveryImage(deployment, inspection);
  const repo = inspection.Mounts.find(m => m.Destination === '/backrest' && m.Type === 'volume')?.Name;
  if (!repo) throw new Error('Encrypted repository mount not found');
  const name = `ukda-recovery-${store}-${randomUUID()}`;
  const volume = `${name}-data`;
  await execute(['volume', 'create', '--label', 'ukda.recovery.drill=true', volume]);
  await execute(['run', '-d', '--name', name, '--label', 'ukda.recovery.drill=true', '--network', 'none',
    '-v', `${volume}:/var/lib/postgresql`, '-v', `${repo}:/backrest:ro`,
    '-v', `${directory}/${store}.conf:/run/secrets/pgbackrest.conf:ro`, '--entrypoint', 'sh',
    image, '-c', 'sleep infinity']);
  try {
    await execute(['exec', name, 'sh', '-c', 'install -d -o postgres -g postgres -m 700 /etc/pgbackrest /var/lib/postgresql/18/docker; install -o postgres -g postgres -m 600 /run/secrets/pgbackrest.conf /etc/pgbackrest/pgbackrest.conf']);
    await execute(['exec', '--user', 'postgres', name, 'pgbackrest', `--stanza=${store}`, `--set=${label}`, '--type=name', `--target=${target}`, '--target-action=pause', 'restore']);
    await execute(['exec', '--user', 'postgres', name, 'pg_ctl', '-D', '/var/lib/postgresql/18/docker', '-l', '/var/lib/postgresql/restore.log',
      '-o', '-c listen_addresses= -c ssl=off -c archive_mode=off -c synchronous_standby_names=', '-w', 'start']);
    await waitFor(async () => (await execute(['exec', '--user', 'postgres', name, 'psql', '-X', '-U', storeInfo(store).user, '-d', storeInfo(store).database, '-Atc', "SELECT pg_get_wal_replay_pause_state()='paused'"])) === 't', 'isolated recovery target');
    return {name, volume, store, label, target, status: 'paused_at_target', network: 'none'};
  } catch { throw new Error(`Isolated restore failed; inspect retained container ${name} and volume ${volume}`); }
}

async function main(args) {
  const [command, ...values] = args;
  if (command === 'setup' && !values.length) return setup();
  if (command === 'backup' && !values.length) return withPhysicalLock(physicalFullBackups);
  if (command === 'metrics' && !values.length) return metrics();
  if (command === 'verify' && !values.length) {
    for (const store of ['app', 'control']) await backrest(store, ['verify']);
    return {verified: ['app', 'control']};
  }
  if (command === 'restore' && values.length === 3) return withPhysicalLock(() => isolatedRestore(...values));
  throw new Error('Usage: physical-backups.mjs setup | backup | metrics | verify | restore <app|control> <full-label> <named-target>');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.stdout.write(JSON.stringify(await main(process.argv.slice(2)), null, 2) + '\n'); }
  catch (error) { process.stderr.write(`Recovery operation failed: ${error.message}\n`); process.exitCode = 1; }
}

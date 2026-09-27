import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { recoveryDeployment, recoveryImage, replicationHost, replicationCidr, replicationPassword,
  replicationHbaRules, replicationReadinessSql } from '../ops/recovery-deployment.mjs';
import { setup } from '../scripts/physical-backups.mjs';

const external = {
  UKDA_RECOVERY_REPLICA_MODE: 'external', UKDA_REPLICATION_PRIMARY_HOST: 'primary.internal',
  UKDA_REPLICATION_ALLOWED_CIDR: '10.20.0.5/32', UKDA_REPLICATION_REQUIRE_TLS: 'true',
};

test('local defaults remain local while cloud paths and immutable image can be selected', () => {
  const local = recoveryDeployment({});
  assert.deepEqual(local.composeArgs, ['compose', '-f', 'compose.yaml', '-f', 'compose.recovery.yaml']);
  assert.equal(local.primaryHost, 'control-db'); assert.equal(local.replicaMode, 'local');
  assert.match(local.directory, /\.local\/recovery$/); assert.match(local.recordsDirectory, /\.local\/recovery-records$/);
  const image = `registry.example/maqbool/postgres@sha256:${'a'.repeat(64)}`;
  const cloud = recoveryDeployment({...external, UKDA_RECOVERY_IMAGE: image, UKDA_RECOVERY_DIRECTORY: '/srv/private/recovery',
    UKDA_RECOVERY_RECORDS_DIRECTORY: '/srv/records', UKDA_RECOVERY_COMPOSE_FILE: '/srv/primary.yaml'});
  assert.deepEqual(cloud.composeArgs, ['compose', '-f', '/srv/primary.yaml']);
  assert.equal(cloud.directory, '/srv/private/recovery'); assert.equal(cloud.recordsDirectory, '/srv/records');
  assert.equal(recoveryImage(cloud, {}), image);
  const id = `sha256:${'b'.repeat(64)}`;
  assert.equal(recoveryImage(local, {Image: id}), id);
  assert.equal(recoveryImage(recoveryDeployment({UKDA_RECOVERY_IMAGE: id}), {}), id);
  assert.throws(() => recoveryImage(local, {Image: 'mutable:latest'}));
  for (const value of ['', 'repo:latest', `repo@sha256:${'g'.repeat(64)}`, '--privileged'])
    assert.throws(() => recoveryDeployment({UKDA_RECOVERY_IMAGE: value}));
  for (const name of ['UKDA_RECOVERY_DIRECTORY', 'UKDA_RECOVERY_RECORDS_DIRECTORY', 'UKDA_RECOVERY_COMPOSE_FILE'])
    for (const value of ['', '/tmp/x\nextra', '/tmp/x:extra']) assert.throws(() => recoveryDeployment({[name]: value}));
});

test('external deployment fails closed without TLS, an explicit primary and a single standby address', () => {
  for (const name of ['UKDA_REPLICATION_PRIMARY_HOST', 'UKDA_REPLICATION_ALLOWED_CIDR', 'UKDA_REPLICATION_REQUIRE_TLS']) {
    const env = {...external}; delete env[name]; assert.throws(() => recoveryDeployment(env));
  }
  assert.throws(() => recoveryDeployment({...external, UKDA_REPLICATION_REQUIRE_TLS: 'false'}));
  assert.throws(() => recoveryDeployment({UKDA_REPLICATION_PRIMARY_HOST: 'remote.internal'}));
  assert.throws(() => recoveryDeployment({UKDA_RECOVERY_REPLICA_MODE: 'anything'}));
  for (const value of ['all', '0.0.0.0/0', '10.20.0.0/24', '10.20.0.5/32\nhost all all all trust', '999.1.1.1/32', '0.0.0.0/32', '224.0.0.1/32'])
    assert.throws(() => replicationCidr(value));
  for (const value of ['host sslmode=disable', 'primary\nsslmode=disable', "primary'", '/socket', '[::1]', '999.1.1.1', '-primary', 'a'.repeat(64)])
    assert.throws(() => replicationHost(value));
  assert.equal(replicationHost('control-db'), 'control-db'); assert.equal(replicationHost('10.20.0.4'), '10.20.0.4');
});

test('replication secrets stay bound to one host and encrypted connection checks use the allowed address', () => {
  const config = recoveryDeployment(external), secret = 'a'.repeat(64);
  assert.equal(replicationPassword(`primary.internal:5432:*:ukda_replica:${secret}\n`, config), secret);
  for (const contents of [`control-db:5432:*:ukda_replica:${secret}\n`, `*:5432:*:ukda_replica:${secret}\n`,
    `primary.internal:5432:*:ukda_replica:${secret}\nother`, `primary.internal:5432:*:ukda_replica:${secret}'`])
    assert.throws(() => replicationPassword(contents, config));
  assert.deepEqual(replicationHbaRules(config), [
    'hostssl replication ukda_replica 10.20.0.5/32 scram-sha-256', 'host replication ukda_replica all reject',
  ]);
  const query = replicationReadinessSql(config, true);
  assert.match(query, /s\.ssl=true/); assert.match(query, /r\.client_addr='10\.20\.0\.5'::inet/);
  assert.match(query, /state='streaming'/); assert.match(query, /sync_state='sync'/);
});

async function setupFixture(t, env = external, ssl = 'on', ready = true) {
  const directory = await mkdtemp(join(tmpdir(), 'ukda-recovery-config-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const configuration = recoveryDeployment({...env, UKDA_RECOVERY_DIRECTORY: directory}), calls = [];
  const dependencies = {
    configuration,
    runCompose: async args => { calls.push({kind: 'compose', args}); return ''; },
    runSql: async (store, statement) => {
      calls.push({kind: 'sql', statement});
      if (statement === 'SHOW ssl;') return ssl;
      if (statement.includes('pg_hba_file_rules')) return '0';
      if (statement.includes('FROM pg_roles')) return '1';
      if (statement.includes('FROM pg_stat_replication')) return ready ? '1' : '0';
      return 't';
    },
    runBackrest: async (store, args) => { calls.push({kind: 'backrest', store, args}); },
    wait: async (check, label) => { calls.push({kind: 'wait', label}); if (!await check()) throw new Error(`Not ready: ${label}`); },
  };
  return {dependencies, calls, directory};
}

test('external setup waits for verified streaming and sync without starting a local replica', async t => {
  const {dependencies, calls, directory} = await setupFixture(t);
  const result = await setup(dependencies);
  assert.equal(result.replica, 'synchronous');
  assert.ok(!calls.some(c => c.kind === 'compose' && c.args[0] === 'up' && c.args.includes('control-replica')));
  assert.deepEqual(calls.filter(c => c.kind === 'wait').map(c => c.label), ['streaming replica', 'durable synchronous replica']);
  assert.ok(calls.findIndex(c => c.kind === 'wait') < calls.findIndex(c => c.statement?.startsWith('ALTER SYSTEM')));
  assert.ok(!calls.some(c => /synchronous_standby_names\s*=\s*''/.test(c.statement ?? '')));
  const secret = await readFile(join(directory, 'replication.pgpass'), 'utf8');
  assert.match(secret, /^primary\.internal:5432:\*:ukda_replica:[a-f0-9]{64}\n$/);
  assert.equal(calls.filter(c => c.kind === 'backrest').length, 4);
});

test('local setup still starts its replica; missing remote TLS or streaming cannot report success', async t => {
  const local = await setupFixture(t, {}); await setup(local.dependencies);
  assert.ok(local.calls.some(c => c.kind === 'compose' && c.args[0] === 'up' && c.args.includes('control-replica')));
  const insecure = await setupFixture(t, external, 'off');
  await assert.rejects(setup(insecure.dependencies), /TLS must be enabled/);
  assert.ok(!insecure.calls.some(c => c.kind === 'backrest' || c.statement?.startsWith('ALTER SYSTEM')));
  const unavailable = await setupFixture(t, external, 'on', false);
  await assert.rejects(setup(unavailable.dependencies), /streaming replica/);
  assert.ok(!unavailable.calls.some(c => c.kind === 'backrest' || c.statement?.startsWith('ALTER SYSTEM')));
  const asynchronous = await setupFixture(t);
  const query = asynchronous.dependencies.runSql;
  asynchronous.dependencies.runSql = (store, statement) => statement.includes("r.sync_state='sync'") ? '0' : query(store, statement);
  await assert.rejects(setup(asynchronous.dependencies), /durable synchronous replica/);
  assert.ok(!asynchronous.calls.some(c => c.kind === 'backrest'));
});

test('HBA installation puts the restrictive grant before a legacy broad grant and is idempotent', async t => {
  const {dependencies, calls, directory} = await setupFixture(t); await setup(dependencies);
  const command = calls.find(c => c.kind === 'compose' && c.args.includes('ukda-replication-hba')).args;
  const bin = join(directory, 'bin'); await mkdir(bin);
  await writeFile(join(bin, 'chown'), '#!/bin/sh\nexit 0\n', {mode: 0o755});
  const hba = join(directory, 'pg_hba.conf');
  await writeFile(hba, 'local all all trust\nhost replication ukda_replica all scram-sha-256\n');
  const run = () => spawnSync('/bin/sh', command.slice(command.indexOf('-c')), {
    env: {...process.env, PATH: `${bin}:/usr/bin:/bin`, PGDATA: directory}, encoding: 'utf8',
  });
  assert.equal(run().status, 0);
  const expected = await readFile(hba, 'utf8');
  assert.match(expected, /^# BEGIN UKDA REPLICATION\nhostssl replication ukda_replica 10\.20\.0\.5\/32 scram-sha-256\nhost replication ukda_replica all reject\n/);
  assert.ok(expected.indexOf('all reject') < expected.indexOf('all scram-sha-256'));
  assert.equal(run().status, 0); assert.equal(await readFile(hba, 'utf8'), expected);
  const malformed = '# BEGIN UKDA REPLICATION\nlocal all all trust\n';
  await writeFile(hba, malformed);
  assert.notEqual(run().status, 0); assert.equal(await readFile(hba, 'utf8'), malformed);
});

test('standby rejects connection injection before touching files and verifies TLS for seed and reconnect', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ukda-standby-config-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const script = new URL('../ops/postgres/standby.sh', import.meta.url).pathname;
  for (const host of ['', 'primary sslmode=disable', "primary'", '999.0.0.1', '-primary']) {
    const result = spawnSync('/bin/bash', [script], {env: {PATH: '/usr/bin:/bin', UKDA_REPLICATION_PRIMARY_HOST: host}, encoding: 'utf8'});
    assert.equal(result.status, 1); assert.match(result.stderr, /Invalid replication primary host/);
  }
  const plaintext = spawnSync('/bin/bash', [script], {env: {PATH: '/usr/bin:/bin', UKDA_REPLICATION_PRIMARY_HOST: 'primary.internal'}, encoding: 'utf8'});
  assert.equal(plaintext.status, 1); assert.match(plaintext.stderr, /requires verified TLS/);
  const bin = join(directory, 'bin'); await mkdir(bin);
  const log = join(directory, 'commands');
  await writeFile(join(bin, 'install'), '#!/bin/sh\nexit 0\n', {mode: 0o755});
  await writeFile(join(bin, 'gosu'), '#!/bin/sh\nprintf "%s\\n" "$@" >> "$UKDA_TEST_COMMAND_LOG"\n', {mode: 0o755});
  await writeFile(join(directory, 'standby.signal'), '');
  const result = spawnSync('/bin/bash', [script], {env: {...process.env, PATH: `${bin}:/usr/bin:/bin`, PGDATA: directory,
    UKDA_REPLICATION_PRIMARY_HOST: 'primary.internal', UKDA_REPLICATION_REQUIRE_TLS: 'true', UKDA_TEST_COMMAND_LOG: log}, encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  const commands = await readFile(log, 'utf8');
  assert.match(commands, /--dbname=host=primary\.internal.*sslmode=verify-full sslrootcert=\/var\/lib\/postgresql\/tls\/replication-ca\.crt/);
  assert.match(commands, /primary_conninfo=host=primary\.internal.*sslmode=verify-full/);
});

#!/usr/bin/env node
// Read-only configuration checks. Resolved Compose output can contain secrets;
// keep it in memory and never forward child output or exception detail.
import { spawnSync } from 'node:child_process';
import { readFile, realpath, stat } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const folder = dirname(fileURLToPath(import.meta.url));
const root = resolve(folder, '../..');
const pin = /^(?:[a-zA-Z0-9][a-zA-Z0-9._:/-]*@)?sha256:[a-f0-9]{64}$/;
const privateIPv4 = value => {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return false;
  const octets = value.split('.').map(Number);
  return octets.every(n => n >= 0 && n <= 255) && (octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168));
};
const assert = (condition, message) => { if (!condition) throw new Error(message); };
async function externalFile(path, label, secret = true) {
  assert(typeof path === 'string' && isAbsolute(path), `${label} must use an absolute external path`);
  let location, details;
  try { location = await realpath(path); details = await stat(location); }
  catch { throw new Error(`${label} is unavailable`); }
  const relation = relative(root, location);
  assert(relation === '..' || relation.startsWith(`..${sep}`) || isAbsolute(relation), `${label} must be outside the checkout`);
  assert(details.isFile(), `${label} must be a regular file`);
  assert(!secret || (details.mode & 0o077) === 0, `${label} must not be readable by other users`);
  assert(details.size > 0 && details.size < 128 * 1024, `${label} is empty or unexpectedly large`);
}

try {
  const [target, envPath, extra] = process.argv.slice(2);
  assert(['primary', 'standby'].includes(target) && envPath && !extra,
    'Usage: node ops/cloud/validate.mjs primary|standby /absolute/cloud.env');
  await externalFile(envPath, 'Cloud configuration', false);
  const manifest = resolve(folder, `compose.${target}.yaml`);
  const result = spawnSync('docker', ['compose', '--env-file', envPath, '-f', manifest,
    '--profile', 'application', 'config', '--format', 'json'], {encoding: 'utf8', maxBuffer: 2 * 1024 * 1024});
  assert(result.status === 0, 'Compose validation failed; check required variables and external file paths (resolved output is withheld)');
  let config;
  try { config = JSON.parse(result.stdout); }
  catch { throw new Error('Compose did not return a valid configuration'); }
  assert(config.name === `ukda-cloud-${target}`, 'Cloud project name must remain separate from local projects');
  for (const [name, service] of Object.entries(config.services)) {
    assert(pin.test(service.image ?? ''), `${name} requires an image pinned by a full SHA-256 digest or local image ID`);
    assert(service.pull_policy === 'never', `${name} requires explicitly loaded or pulled images`);
    assert(service.read_only === true && service.restart === 'unless-stopped', `${name} requires the configured restart and filesystem protection`);
  }
  for (const [name, secret] of Object.entries(config.secrets ?? {})) {
    await externalFile(secret.file, `Secret ${name}`, !name.endsWith('-ca') && !name.endsWith('-cert'));
    // Compose file secrets preserve host permissions. The non-root Node user
    // must be able to read this public certificate through its bind mount.
    if (name === 'database-ca') assert(((await stat(secret.file)).mode & 0o004) !== 0,
      'Database CA certificate must be readable by the non-root application user (for example mode 0644)');
  }
  if (target === 'primary') {
    const {api, worker, frontend, gateway} = config.services;
    const env = api.environment;
    let origin;
    try { origin = new URL(env.APP_ORIGIN); } catch { throw new Error('A valid permanent HTTPS origin is required'); }
    assert(origin.protocol === 'https:' && origin.origin === env.APP_ORIGIN && !origin.username && !origin.password,
      'APP_ORIGIN must be an exact HTTPS origin');
    assert(origin.origin === frontend.environment.APP_ORIGIN && origin.origin === gateway.environment.UKDA_APP_ORIGIN,
      'Public origins must agree');
    for (const [label, service] of [['API', api], ['worker', worker]]) {
      assert(service.environment.NODE_ENV === 'production', `${label} must run in production mode`);
      assert(!Object.hasOwn(service.environment, 'ADMIN_DATABASE_URL') && !Object.hasOwn(service.environment, 'CONTROL_ADMIN_DATABASE_URL'),
        `${label} must not receive migration/operator credentials`);
      for (const key of ['DATABASE_URL', 'CONTROL_DATABASE_URL']) {
        let url;
        try { url = new URL(service.environment[key]); } catch { throw new Error(`${label} ${key} is missing or invalid`); }
        const expectedHost = key === 'DATABASE_URL' ? 'app-db' : 'control-db';
        const expectedUser = key === 'DATABASE_URL' ? 'ukda_app_runtime' : 'ukda_control_runtime';
        assert(url.hostname === expectedHost && url.username === expectedUser && url.password && !url.password.includes('local_only'),
          `${label} ${key} must use its private database and limited production role`);
        assert(url.searchParams.get('sslmode') === 'verify-full' &&
          url.searchParams.get('sslrootcert') === '/run/secrets/database-ca.crt', `${label} ${key} must verify the database certificate`);
      }
    }
    for (const key of ['SECURITY_MASTER_KEY', 'SECURITY_KEY_ID', 'OPAQUE_SERVER_SETUP', 'OPAQUE_SETUP_ID', 'AUTH_SERVER_IDENTITY']) {
      assert(typeof api.environment[key] === 'string' && api.environment[key].length > 0, `API is missing identity configuration ${key}`);
      assert(!Object.hasOwn(worker.environment, key), `Worker must not receive API identity configuration ${key}`);
    }
    // env_file values are resolved into environment by Compose; inspect the
    // original configuration only to locate the required external file safely.
    const unresolved = spawnSync('docker', ['compose', '--env-file', envPath, '-f', manifest,
      '--profile', 'application', 'config', '--no-env-resolution', '--format', 'json'],
    {encoding: 'utf8', maxBuffer: 2 * 1024 * 1024});
    assert(unresolved.status === 0, 'Compose could not validate runtime secret file references');
    let raw;
    try { raw = JSON.parse(unresolved.stdout); } catch { throw new Error('Compose returned invalid runtime file references'); }
    for (const file of raw.services.api.env_file ?? []) await externalFile(file.path, 'Runtime secret environment');
    for (const file of raw.services.worker.env_file ?? []) await externalFile(file.path, 'Worker database environment');
    assert(raw.services.api.env_file?.[0]?.path !== raw.services.worker.env_file?.[0]?.path,
      'API and worker require separate environment files');
    const privateBinding = config.services['control-db'].ports.find(port => port.host_ip !== '127.0.0.1');
    assert(privateIPv4(privateBinding?.host_ip ?? ''), 'Control replication must bind an RFC1918 private IPv4 address');
    const repositories = ['app-backups', 'control-backups'].map(name => config.volumes[name].driver_opts);
    for (const repository of repositories) {
      const address = /^addr=([^,]+),/.exec(repository.o)?.[1];
      assert(privateIPv4(address ?? '') && address !== privateBinding.host_ip, 'Backups require a separate private secondary host');
      assert(/^:\/[a-zA-Z0-9/_-]+$/.test(repository.device), 'NFS repositories require simple absolute export paths');
    }
    assert(repositories[0].device !== repositories[1].device, 'Application and control repositories must use separate exports');
    for (const name of ['app-backrest', 'control-backrest']) {
      const contents = await readFile(config.secrets[name].file, 'utf8');
      assert(/^repo1-path=\/backrest$/m.test(contents) && /^repo1-cipher-type=aes-256-cbc$/m.test(contents) &&
        /^repo1-cipher-pass=[a-f0-9]{64}$/m.test(contents), `${name} must configure the encrypted /backrest repository`);
    }
  } else {
    const replica = config.services['control-replica'];
    assert(!replica.ports?.length && replica.environment.UKDA_REPLICATION_SSLMODE === 'verify-full' &&
      replica.environment.UKDA_REPLICATION_REQUIRE_TLS === 'true' && replica.environment.UKDA_RECOVERY_REPLICA_MODE === 'external',
      'Standby requires external mode and verified TLS with no published database port');
  }
  process.stdout.write(`Cloud ${target} configuration checks passed. Cloud networking, images, credentials and recovery remain unverified.\n`);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : 'Cloud configuration validation failed'}\n`);
  process.exitCode = 1;
}

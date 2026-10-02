import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const digest = 'sha256:[a-f0-9]{64}';
const pinnedImage = new RegExp(`^[a-z0-9][a-z0-9._:/-]*@${digest}$`);
const imageId = new RegExp(`^${digest}$`);

function option(env, name, fallback) {
  const value = env[name] ?? fallback;
  if (typeof value !== 'string' || !value || /[\x00-\x1f\x7f]/.test(value)) throw new Error(`Invalid ${name}`);
  return value;
}

export function replicationHost(value) {
  if (typeof value !== 'string' || value.length > 253 || !value.length ||
      !value.split('.').every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label)) ||
      /^[0-9.]+$/.test(value) && isIP(value) !== 4) throw new Error('Invalid replication primary host');
  return value;
}

/** An external standby has one known IPv4 address, not a subnet-wide grant. */
export function replicationCidr(value) {
  const match = typeof value === 'string' && value.match(/^([^/]+)\/32$/);
  if (!match || isIP(match[1]) !== 4 || Number(match[1].split('.')[0]) === 0 ||
      Number(match[1].split('.')[0]) >= 224) throw new Error('Replication requires one valid IPv4 /32 address');
  return value;
}

export function recoveryDeployment(env = process.env) {
  const mode = option(env, 'UKDA_RECOVERY_REPLICA_MODE', 'local');
  if (!['local', 'external'].includes(mode)) throw new Error('Invalid recovery replica mode');
  const primaryHost = replicationHost(option(env, 'UKDA_REPLICATION_PRIMARY_HOST', 'control-db'));
  const tls = option(env, 'UKDA_REPLICATION_REQUIRE_TLS', 'false');
  if (!['true', 'false'].includes(tls)) throw new Error('Invalid replication TLS setting');
  const remote = mode === 'external' || primaryHost !== 'control-db';
  if (remote && (!env.UKDA_REPLICATION_PRIMARY_HOST || tls !== 'true' || !env.UKDA_REPLICATION_ALLOWED_CIDR))
    throw new Error('External replication requires an explicit primary host, TLS and standby /32 address');
  const allowedCidr = env.UKDA_REPLICATION_ALLOWED_CIDR === undefined && !remote ? 'all' : replicationCidr(env.UKDA_REPLICATION_ALLOWED_CIDR);
  const absolute = (name, fallback) => {
    const value = option(env, name, fallback);
    // These directories become Docker bind-mount sources; ':' changes that syntax.
    if (value.includes(':')) throw new Error(`Invalid ${name}`);
    return resolve(root, value);
  };
  const image = env.UKDA_RECOVERY_IMAGE;
  if (image !== undefined && (typeof image !== 'string' || !pinnedImage.test(image) && !imageId.test(image)))
    throw new Error('UKDA_RECOVERY_IMAGE must be an immutable sha256 image ID or repository digest');
  return {
    composeArgs: env.UKDA_RECOVERY_COMPOSE_FILE === undefined ? ['compose', '-f', 'compose.yaml', '-f', 'compose.recovery.yaml'] :
      ['compose', '-f', absolute('UKDA_RECOVERY_COMPOSE_FILE', 'compose.yaml')],
    directory: absolute('UKDA_RECOVERY_DIRECTORY', '.local/recovery'),
    recordsDirectory: absolute('UKDA_RECOVERY_RECORDS_DIRECTORY', '.local/recovery-records'),
    image, replicaMode: mode, primaryHost, allowedCidr, requireTls: tls === 'true',
  };
}

export function recoveryImage(configuration, inspection) {
  if (configuration.image) return configuration.image;
  if (!imageId.test(inspection?.Image ?? '')) throw new Error('Running recovery image identity is unavailable');
  return inspection.Image;
}

export function replicationPassword(contents, configuration) {
  const prefix = `${configuration.primaryHost}:5432:*:ukda_replica:`;
  const line = contents.replace(/\r?\n$/, '');
  if (!line.startsWith(prefix) || !/^[a-f0-9]{64}$/.test(line.slice(prefix.length)))
    throw new Error('Invalid replication secret file or primary host binding');
  return line.slice(prefix.length);
}

export function replicationHbaRules(configuration) {
  return [`${configuration.requireTls ? 'hostssl' : 'host'} replication ukda_replica ${configuration.allowedCidr} scram-sha-256`,
    'host replication ukda_replica all reject'];
}

export function replicationReadinessSql(configuration, synchronous = false) {
  const remoteAddress = configuration.allowedCidr === 'all' ? '' : ` AND r.client_addr='${configuration.allowedCidr.slice(0, -3)}'::inet`;
  return `SELECT count(*) FROM pg_stat_replication r LEFT JOIN pg_stat_ssl s ON s.pid=r.pid WHERE r.application_name='ukda_control_replica' AND r.usename='ukda_replica' AND r.state='streaming'${synchronous ? " AND r.sync_state='sync'" : ''}${configuration.requireTls ? ' AND s.ssl=true' : ''}${remoteAddress};`;
}

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

export const DAY = 24 * 60 * 60 * 1000;
export const RETENTION_MS = 30 * DAY;
export const BACKUP_MAX_AGE_MS = DAY;
export const WAL_TARGET_MS = 15 * 60 * 1000;
export const CONTENT_CHECKPOINT_INTERVAL_MS = 5 * 60 * 1000;
export const STORES = Object.freeze({app: {service: 'app-db', database: 'ukda_app', user: 'ukda_app_admin'},
  control: {service: 'control-db', database: 'ukda_control', user: 'ukda_control_admin'}});

export function storeInfo(name) {
  if (!Object.hasOwn(STORES, name)) throw new Error('Unknown recovery store');
  return STORES[name];
}
export function backupConfiguration(store, secret) {
  const info = storeInfo(store);
  if (!/^[a-f0-9]{64}$/.test(secret)) throw new Error('Invalid repository secret');
  return `[global]\nrepo1-path=/backrest\nrepo1-cipher-type=aes-256-cbc\nrepo1-cipher-pass=${secret}\nrepo1-retention-full-type=time\nrepo1-retention-full=30\nrepo1-retention-history=0\narchive-async=n\narchive-timeout=120\nprocess-max=2\nstart-fast=y\nlog-level-console=warn\nlog-level-file=off\ncompress-type=zst\n[${store}]\npg1-path=/var/lib/postgresql/18/docker\npg1-user=${info.user}\npg1-database=${info.database}\n`;
}

/** Time-based pgBackRest retention may deliberately retain a base older than
 * thirty days. A deletion cutoff overrides that availability policy explicitly.
 * Never remove the last clean full backup; report a blocker if no clean copy exists. */
export function planDeletionExpiry(backups, purges, now = Date.now()) {
  if (!Number.isFinite(now)) throw new Error('Invalid retention time');
  const due = purges.filter(p => Number.isFinite(Date.parse(p.backupExpiresAt)) && Date.parse(p.backupExpiresAt) <= now);
  const expired = new Set();
  for (const purge of due) {
    const boundary = Date.parse(purge.livePayloadsPurgedAt);
    if (!Number.isFinite(boundary) || Date.parse(purge.backupExpiresAt) > boundary + RETENTION_MS)
      throw new Error('Invalid purge retention deadline');
    // A backup that started before physical purge is conservatively contaminated,
    // even if it finished later. A fresh full backup must have begun after purge.
    if (!backups.some(b => b.type === 'full' && b.timestamp.start * 1000 >= boundary))
      throw new Error('Deletion expiry requires a clean full backup or repository retirement');
    for (const backup of backups) if (backup.timestamp.start * 1000 < boundary) expired.add(backup.label);
  }
  return [...expired].sort();
}

export function backupHealth(backups, archiver, {now = Date.now(), lastDrillAt = null} = {}) {
  const latest = Math.max(0, ...backups.map(b => b.timestamp.stop * 1000));
  const archived = archiver.last_archived_time ? Date.parse(archiver.last_archived_time) : null;
  const failed = archiver.last_failed_time ? Date.parse(archiver.last_failed_time) : null;
  const backupAgeMs = latest ? Math.max(0, now - latest) : null;
  const recoveryRecordLagMs = archived === null ? null : Math.max(0, now - archived);
  return {backupAgeMs, recoveryRecordLagMs, lastSuccessfulDrillAt: lastDrillAt,
    backupFresh: backupAgeMs !== null && backupAgeMs <= BACKUP_MAX_AGE_MS,
    recoveryRecordsFresh: recoveryRecordLagMs !== null && recoveryRecordLagMs <= WAL_TARGET_MS,
    archiveFailureOutstanding: failed !== null && (archived === null || failed > archived)};
}

/** A daily full backup remains the base. Only the small signed inventory and
 * named, archived WAL boundary need this shorter cadence. */
export function checkpointDue(index, now = Date.now()) {
  if (!Number.isFinite(now)) throw new Error('Invalid checkpoint time');
  const captured = typeof index?.capturedAt === 'string' ? Date.parse(index.capturedAt) : NaN;
  return !Number.isFinite(captured) || captured > now || now - captured >= CONTENT_CHECKPOINT_INTERVAL_MS;
}

/** The caller supplies only authenticated, archived indexes whose referenced
 * backup bases still exist. Fresh WAL by itself is not a usable content point. */
export function checkpointHealth(activeWorkspaceIds, usableIndexes, {now = Date.now()} = {}) {
  if (!Number.isFinite(now)) throw new Error('Invalid checkpoint time');
  if (activeWorkspaceIds == null || usableIndexes == null) return {activeWorkspaces:null, coveredWorkspaces:null,
    oldestUsableCheckpointAgeMs:null, checkpointsFresh:false};
  if (!Array.isArray(activeWorkspaceIds) || !Array.isArray(usableIndexes) || activeWorkspaceIds.some(id => typeof id !== 'string' || !id))
    throw new Error('Invalid checkpoint inventory');
  const active = new Set(activeWorkspaceIds), latest = new Map();
  for (const index of usableIndexes) {
    if (!active.has(index?.workspaceId)) continue;
    const captured = typeof index.capturedAt === 'string' ? Date.parse(index.capturedAt) : NaN;
    if (Number.isFinite(captured) && captured <= now && captured > (latest.get(index.workspaceId) ?? -Infinity)) latest.set(index.workspaceId, captured);
  }
  const complete = latest.size === active.size;
  const oldestUsableCheckpointAgeMs = complete && active.size ? Math.max(...[...latest.values()].map(time => now - time)) : null;
  return {activeWorkspaces:active.size, coveredWorkspaces:latest.size, oldestUsableCheckpointAgeMs,
    checkpointsFresh:complete && (active.size === 0 || oldestUsableCheckpointAgeMs <= WAL_TARGET_MS)};
}

function checkpointKey(secret) {
  if (!/^[a-f0-9]{64}$/.test(secret)) throw new Error('Invalid checkpoint secret');
  return Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'hex'), 'ukda-recovery-v1', 'checkpoint-manifest', 32));
}
function checkpointAAD(workspaceId, checkpointId) {
  for (const id of [workspaceId, checkpointId]) if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error('Invalid checkpoint identity');
  return Buffer.from(JSON.stringify(['ukda.checkpoint.v1', workspaceId, checkpointId]));
}
/** Protects service metadata and already-encrypted customer objects. This key
 * cannot decrypt customer content, and is kept outside the backup repositories. */
export function sealCheckpoint(value, secret, workspaceId, checkpointId) {
  const key = checkpointKey(secret), nonce = randomBytes(12);
  try {
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(checkpointAAD(workspaceId, checkpointId));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    return JSON.stringify({version: 1, nonce: nonce.toString('base64'), ciphertext: ciphertext.toString('base64'), tag: cipher.getAuthTag().toString('base64')});
  } finally { key.fill(0); }
}
export function openCheckpoint(encoded, secret, workspaceId, checkpointId) {
  if (Buffer.byteLength(encoded) > 64 * 1024 * 1024) throw new Error('Checkpoint too large');
  const value = JSON.parse(encoded), key = checkpointKey(secret);
  try {
    if (value.version !== 1 || Object.keys(value).sort().join(',') !== 'ciphertext,nonce,tag,version') throw new Error('Unknown checkpoint format');
    const nonce = Buffer.from(value.nonce, 'base64'), tag = Buffer.from(value.tag, 'base64');
    if (nonce.length !== 12 || tag.length !== 16) throw new Error('Invalid checkpoint envelope');
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(checkpointAAD(workspaceId, checkpointId)); decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(value.ciphertext, 'base64')), decipher.final()]).toString('utf8'));
  } finally { key.fill(0); }
}

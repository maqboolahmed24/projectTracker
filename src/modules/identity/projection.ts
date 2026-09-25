import type pg from 'pg';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { tenantTransaction } from '../../persistence.js';
import { genesisBody } from '../../shared/activation.js';
import { binary, contentEnvelope, identifier } from '../../shared/contracts.js';
import { canonicalJson } from '../../shared/crypto.js';
import { projectAccessSnapshot, readAccessSnapshot } from './access-projection.js';
import { projectOwnershipNotices, readOwnershipNotices } from './ownership-notices.js';
export { BUILTIN_ROLE_PERMISSIONS } from '../../shared/permissions.js';

const lockName = (workspaceId: string) => `ukda.workspace:${workspaceId}`;
const heldFences = new WeakMap<pg.PoolClient, { databases: Databases; workspaceId: string }>();
const genesisObject = z.strictObject({ body: genesisBody, signature: binary(64) });

async function applicationTransaction<T>(client: pg.PoolClient, workspaceId: string, action: () => Promise<T>): Promise<T> {
  await client.query('BEGIN');
  try {
    await client.query("SELECT set_config('ukda.workspace_id', $1, true), set_config('ukda.profile_id', '', true)", [workspaceId]);
    const result = await action();
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  }
}

/** Drain data readers, commit the closed fence, then run the separate authority action. */
export async function withSecurityFence<T>(databases: Databases, workspaceId: string,
  action: (lockedAppClient: pg.PoolClient) => Promise<T>, options: { enqueueActivationProjection?: boolean } = {}): Promise<T> {
  if (!identifier.safeParse(workspaceId).success) throw new AppError('INVALID_REQUEST', 'Invalid workspace reference', 400);
  const client = await databases.application.connect();
  // A checked-out pg client can emit an error outside a query when its connection dies.
  const disconnected = () => {};
  client.on('error', disconnected);
  let locked = false;
  let fenced = false;
  try {
    await client.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', [lockName(workspaceId)]);
    locked = true;
    await applicationTransaction(client, workspaceId, async () => {
      await client.query(`INSERT INTO app.workspaces (workspace_id, fence_closed) VALUES ($1, true)
        ON CONFLICT (workspace_id) DO UPDATE SET fence_closed=true, updated_at=clock_timestamp()`, [workspaceId]);
      if (options.enqueueActivationProjection) {
        await client.query(`SELECT graphile_worker.add_job('activation_projection', $1::json,
          job_key => $2, max_attempts => 10)`, [{ workspaceId }, `activation:${workspaceId}`]);
      }
    });
    fenced = true;
    heldFences.set(client, { databases, workspaceId });
    return await action(client);
  } catch (error) {
    // If a callback projected successfully and then failed, close the fence again
    // while we still hold its lock. A lost connection is discarded below.
    if (fenced) {
      await client.query('ROLLBACK').catch(() => {});
      await applicationTransaction(client, workspaceId, async () => {
        await client.query('UPDATE app.workspaces SET fence_closed=true,updated_at=clock_timestamp() WHERE workspace_id=$1', [workspaceId]);
      }).catch(() => {});
    }
    throw error;
  } finally {
    heldFences.delete(client);
    // The action must not leave a transaction open, including on an exception.
    await client.query('ROLLBACK').catch(() => {});
    if (locked) await client.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [lockName(workspaceId)]).catch(() => {});
    // Always discard this dedicated session; even an ambiguous unlock cannot leak a lock into the pool.
    client.release(true);
    client.removeListener('error', disconnected);
  }
}

interface WorkspaceAuthority {
  workspace_id: string; lifecycle: 'pending_activation' | 'active' | 'pending_deletion' | 'deleted';
  licence_state: 'active' | 'restricted' | 'revoked'; security_head: string; security_version: string;
  data_generation: string; write_schema: number; content_maintenance: boolean; restore_quarantine: boolean;
  genesis_object_id: string | null; current_custody_manifest_object_id: string | null; custody_epoch: string;
}
interface StoredObject { object_id: string; object_kind: string; state: string; versioned_object: unknown }
interface ProfileAuthority {
  profile_id: string; state: 'pending' | 'active' | 'suspended' | 'removed'; is_owner: boolean;
  profile_object_id: string | null; object_kind: string | null; object_state: string | null; versioned_object: unknown;
}
export type ProjectionResult = { state: 'pending' | 'deleted' } |
  { state: 'ready'; securityHead: string; securityVersion: string; dataGeneration: string };

const authorityColumns = `workspace_id,lifecycle,licence_state,security_head,security_version,
  data_generation,write_schema,content_maintenance,restore_quarantine,genesis_object_id,current_custody_manifest_object_id,custody_epoch`;
function unavailable() { return new AppError('SECURITY_FENCED', 'Workspace security state cannot be projected', 503); }

/** This projects already committed, validated control authority; it does not create an authority decision. */
export async function projectAuthoritativeWorkspace(databases: Databases, workspaceId: string, lockedAppClient?: pg.PoolClient): Promise<ProjectionResult> {
  if (!lockedAppClient) return withSecurityFence(databases, workspaceId, (client) => projectAuthoritativeWorkspace(databases, workspaceId, client));
  const fence = heldFences.get(lockedAppClient);
  if (fence?.databases !== databases || fence.workspaceId !== workspaceId) throw unavailable();
  const projectedVersion = await applicationTransaction(lockedAppClient, workspaceId, async () =>
    (await lockedAppClient.query<{ security_version: string }>('SELECT security_version FROM app.workspaces WHERE workspace_id=$1', [workspaceId])).rows[0]?.security_version);
  if (projectedVersion === undefined) throw unavailable();
  const snapshot = await tenantTransaction(databases.control, workspaceId, undefined, async (control) => {
    const authority = (await control.query<WorkspaceAuthority>(`SELECT ${authorityColumns} FROM security.workspaces WHERE workspace_id=$1`, [workspaceId])).rows[0];
    if (!authority) throw new AppError('NOT_FOUND', 'Workspace not available', 404);
    if (authority.lifecycle === 'pending_activation' || authority.lifecycle === 'deleted') return { authority };
    if (!authority.genesis_object_id || authority.security_version === '0') throw unavailable();
    const objects = await control.query<StoredObject>(`SELECT object_id,object_kind,state,versioned_object FROM security.staged_objects
      WHERE workspace_id=$1 AND object_id=ANY($2::uuid[])`, [workspaceId, [authority.genesis_object_id, workspaceId]]);
    const profiles = await control.query<ProfileAuthority>(`SELECT p.profile_id,p.state,p.is_owner,p.profile_object_id,
        o.object_kind,o.state AS object_state,o.versioned_object
      FROM security.profiles p LEFT JOIN security.staged_objects o
        ON o.workspace_id=p.workspace_id AND o.object_id=p.profile_object_id
      WHERE p.workspace_id=$1 ORDER BY p.profile_id`, [workspaceId]);
    if (BigInt(projectedVersion) > BigInt(authority.security_version)) throw unavailable();
    return { authority, objects: objects.rows, profiles: profiles.rows, access: await readAccessSnapshot(control, workspaceId),
      notices: await readOwnershipNotices(control, workspaceId, projectedVersion, authority.security_version) };
  });
  const authority = snapshot.authority;
  if (authority.lifecycle === 'pending_activation') return { state: 'pending' };
  if (authority.lifecycle === 'deleted') return { state: 'deleted' };
  if (!snapshot.objects || !snapshot.profiles || !snapshot.access) throw unavailable();
  const access = snapshot.access;
  const genesis = snapshot.objects.find((object) => object.object_id === authority.genesis_object_id && object.object_kind === 'genesis' && object.state === 'committed');
  const workspace = snapshot.objects.find((object) => object.object_id === workspaceId && object.object_kind === 'encrypted_workspace' && object.state === 'committed');
  if (!genesis || !workspace) throw unavailable();
  const genesisParsed = genesisObject.safeParse(genesis.versioned_object);
  const workspaceParsed = contentEnvelope.safeParse(workspace.versioned_object);
  if (!genesisParsed.success || !workspaceParsed.success || genesisParsed.data.body.workspaceId !== workspaceId ||
    genesisParsed.data.body.genesisId !== authority.genesis_object_id || workspaceParsed.data.header.workspaceId !== workspaceId ||
    workspaceParsed.data.header.scope !== 'workspace' || workspaceParsed.data.header.scopeId !== workspaceId ||
    workspaceParsed.data.header.recordId !== workspaceId || workspaceParsed.data.header.recordType !== 'workspace') throw unavailable();
  const profiles = snapshot.profiles.map((profile) => {
    if (!profile.profile_object_id) {
      if (profile.state !== 'pending') throw unavailable();
      return { ...profile, envelope: {}, revision: '1', schema: 1, keyEpoch: '1' };
    }
    const envelope = contentEnvelope.safeParse(profile.versioned_object);
    if (profile.object_kind !== 'encrypted_profile' || profile.object_state !== 'committed' || !envelope.success ||
      envelope.data.header.workspaceId !== workspaceId || envelope.data.header.scope !== 'workspace' ||
      envelope.data.header.scopeId !== workspaceId || envelope.data.header.recordId !== profile.profile_id ||
      envelope.data.header.recordType !== 'profile') throw unavailable();
    return { ...profile, envelope: envelope.data, revision: envelope.data.header.revision,
      schema: envelope.data.header.schema, keyEpoch: envelope.data.header.keyEpoch };
  });
  await applicationTransaction(lockedAppClient, workspaceId, async () => {
    await lockedAppClient.query(`UPDATE app.workspaces SET security_head=$2,security_version=$3,data_generation=$4,
      lifecycle=$5,licence_state=$6,write_schema=$7,content_maintenance=$8,restore_quarantine=$9,
      encrypted_envelope=CASE WHEN encrypted_envelope='{}'::jsonb THEN $10::jsonb ELSE encrypted_envelope END,
      updated_at=clock_timestamp() WHERE workspace_id=$1`, [workspaceId, authority.security_head, authority.security_version,
      authority.data_generation, authority.lifecycle, authority.licence_state, authority.write_schema,
      authority.content_maintenance, authority.restore_quarantine, workspaceParsed.data]);
    for (const profile of profiles) {
      await lockedAppClient.query(`INSERT INTO app.profiles (workspace_id,id,state,is_owner,revision,schema_version,key_epoch,encrypted_envelope)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (workspace_id,id) DO UPDATE SET
        state=EXCLUDED.state,is_owner=EXCLUDED.is_owner,revision=EXCLUDED.revision,schema_version=EXCLUDED.schema_version,
        key_epoch=EXCLUDED.key_epoch,encrypted_envelope=EXCLUDED.encrypted_envelope,updated_at=clock_timestamp()`,
      [workspaceId, profile.profile_id, profile.state, profile.is_owner, profile.revision, profile.schema, profile.keyEpoch, profile.envelope]);
    }
    await projectAccessSnapshot(lockedAppClient, workspaceId, access, genesisParsed.data.body, authority.security_version);
    await projectOwnershipNotices(lockedAppClient, workspaceId, snapshot.notices ?? [],
      profiles.filter((profile) => profile.state === 'active' && profile.is_owner).map((profile) => profile.profile_id));
    // Every authority writer must hold the same fence. This additional reread fails closed
    // if a mismatched/out-of-protocol authority change occurred while copying the projection.
    const current = await tenantTransaction(databases.control, workspaceId, undefined, async (control) =>
      (await control.query<WorkspaceAuthority>(`SELECT ${authorityColumns} FROM security.workspaces WHERE workspace_id=$1`, [workspaceId])).rows[0]);
    if (!current || canonicalJson(current) !== canonicalJson(authority)) throw unavailable();
    const reopened = await lockedAppClient.query(`UPDATE app.workspaces SET fence_closed=false,updated_at=clock_timestamp()
      WHERE workspace_id=$1 AND security_head=$2 AND security_version=$3 AND data_generation=$4 AND fence_closed`,
    [workspaceId, authority.security_head, authority.security_version, authority.data_generation]);
    if (reopened.rowCount !== 1) throw unavailable();
  });
  return { state: 'ready', securityHead: authority.security_head, securityVersion: authority.security_version, dataGeneration: authority.data_generation };
}

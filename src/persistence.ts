import type pg from 'pg';
import { transaction, type Databases } from './db.js';
import { AppError } from './errors.js';
import { parseInput } from './http.js';
import { identifier } from './shared/contracts.js';

/** Only authentication middleware may construct this context, never request bodies/headers. */
export interface DataPrincipal {
  workspaceId: string;
  profileId: string;
  securityHead: string;
  securityVersion: string;
  dataGeneration: string;
}

export async function tenantTransaction<T>(pool: pg.Pool, workspaceId: string, profileId: string | undefined,
  action: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  parseInput(identifier, workspaceId);
  if (profileId !== undefined) parseInput(identifier, profileId);
  return transaction(pool, async (client) => {
    await client.query("SELECT set_config('ukda.workspace_id', $1, true), set_config('ukda.profile_id', $2, true)", [workspaceId, profileId ?? '']);
    return action(client);
  });
}

interface WorkspaceState {
  security_head: string; security_version: string; data_generation: string;
  lifecycle: string; licence_state: string; content_maintenance: boolean; restore_quarantine: boolean;
  write_schema: number;
}

/** The shared lock drains before any exclusive security fence can change authority. */
export async function dataTransaction<T>(databases: Databases, principal: DataPrincipal,
  action: (client: pg.PoolClient, state: WorkspaceState) => Promise<T>, options: { write?: boolean } = {}): Promise<T> {
  return tenantTransaction(databases.application, principal.workspaceId, principal.profileId, async (client) => {
    await client.query("SELECT pg_advisory_xact_lock_shared(hashtextextended('ukda.workspace:' || $1, 0))", [principal.workspaceId]);
    const projection = await client.query<WorkspaceState & { fence_closed: boolean }>(
      'SELECT * FROM app.workspaces WHERE workspace_id = $1', [principal.workspaceId]);
    const projected = projection.rows[0];
    if (!projected) throw new AppError('NOT_FOUND', 'Workspace not available', 404);
    if (projected.fence_closed) throw new AppError('SECURITY_FENCED', 'Workspace security state is being synchronized', 503);
    let authority: WorkspaceState | undefined;
    try {
      authority = await tenantTransaction(databases.control, principal.workspaceId, undefined, async (control) =>
        (await control.query<WorkspaceState>('SELECT security_head,security_version,data_generation,lifecycle,licence_state,content_maintenance,restore_quarantine,write_schema FROM security.workspaces WHERE workspace_id = $1', [principal.workspaceId])).rows[0]);
    } catch {
      throw new AppError('SECURITY_UNAVAILABLE', 'Workspace security state is unavailable', 503);
    }
    if (!authority || !['active', 'pending_deletion'].includes(authority.lifecycle)) throw new AppError('NOT_FOUND', 'Workspace not available', 404);
    if (authority.restore_quarantine) throw new AppError('RESTORE_QUARANTINE', 'Workspace restoration is in progress', 503);
    if (projected.security_head !== authority.security_head || projected.security_version !== authority.security_version ||
      projected.data_generation !== authority.data_generation) throw new AppError('SECURITY_FENCED', 'Workspace security state is being synchronized', 503);
    if (principal.dataGeneration !== authority.data_generation) throw new AppError('STALE_GENERATION', 'Refresh workspace state before continuing', 409);
    if (principal.securityHead !== authority.security_head || principal.securityVersion !== authority.security_version) {
      throw new AppError('SECURITY_STATE_CHANGED', 'Refresh workspace security state before continuing', 409);
    }
    const profile = await client.query('SELECT 1 FROM app.profiles WHERE workspace_id=$1 AND id=$2 AND state=$3', [principal.workspaceId, principal.profileId, 'active']);
    if (!profile.rowCount) throw new AppError('FORBIDDEN', 'This operation is not permitted', 403);
    if (options.write && (authority.lifecycle !== 'active' || authority.licence_state !== 'active' || authority.content_maintenance)) {
      throw new AppError('WORKSPACE_RESTRICTED', 'Workspace writes are temporarily restricted', 423);
    }
    return action(client, authority);
  });
}

/** No response cache is enabled; future caches must bind every current authority generation. */
export function scopedCacheKey(principal: DataPrincipal, projectId: string, recordId: string): string {
  return JSON.stringify([principal.workspaceId, principal.profileId, principal.dataGeneration,
    principal.securityVersion, principal.securityHead, projectId, recordId]);
}

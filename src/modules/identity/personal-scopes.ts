import type pg from 'pg';
import { capabilities, positiveCounter } from '../../shared/contracts.js';
import type { PairingScope } from '../../shared/pairing.js';

export class PersonalScopeError extends Error { constructor() { super('Current personal key scope is unavailable'); } }
interface ScopeGrant {
  grant_id: string; generation: string; scope_kind: 'workspace' | 'project'; scope_id: string | null; key_epoch: string;
  permissions: string[]; expires_at: Date | null; key_manifest_object_id: string | null; object_hash: string | null;
  definition_state: string | null; expected_epoch: string | null; role_id: string | null; role_revision: string | null;
  role_state: string | null; current_role_revision: string | null;
}
const unavailable = (): never => { throw new PersonalScopeError(); };
const earliest = (values: (Date | null)[]) => values.reduce<Date | null>((first, value) => value && (!first || value < first) ? value : first, null);

/**
 * Person grants survive device loss. Their explicit key_epoch describes the delivered
 * scope: Owner workspace custody uses custody_epoch; member workspace and projects
 * use the ordinary content epoch in scope_heads. Never infer either from ciphertext.
 * The caller holds current workspace authority and has checked the active profile.
 */
export async function readPersonalScopes(client: pg.PoolClient, workspaceId: string, accountId: string, isOwner: boolean, now: Date): Promise<PairingScope[]> {
  const rows = (await client.query<ScopeGrant>(`SELECT g.grant_id,g.generation,g.scope_kind,g.scope_id,g.key_epoch,g.permissions,g.expires_at,
      g.key_manifest_object_id,o.object_hash,d.state AS definition_state,g.role_id,g.role_revision,r.state AS role_state,r.revision AS current_role_revision,
      CASE WHEN g.scope_kind='workspace' AND $3 THEN w.custody_epoch ELSE h.key_epoch END AS expected_epoch
    FROM security.grants g JOIN security.workspaces w ON w.workspace_id=g.workspace_id
    LEFT JOIN security.scope_heads h ON h.workspace_id=g.workspace_id AND h.scope_kind=g.scope_kind AND h.scope_id=coalesce(g.scope_id,g.workspace_id)
    LEFT JOIN security.staged_objects o ON o.workspace_id=g.workspace_id AND o.object_id=g.key_manifest_object_id AND o.state='committed'
    LEFT JOIN security.staged_objects d ON d.workspace_id=g.workspace_id AND d.object_id=g.signed_grant_object_id
    LEFT JOIN security.roles r ON r.workspace_id=g.workspace_id AND r.role_id=g.role_id
    WHERE g.workspace_id=$1 AND g.profile_id=$2 AND g.device_id IS NULL AND g.state='active' AND g.revoked_at IS NULL
      AND (g.expires_at IS NULL OR g.expires_at>$4) AND g.security_version<=w.security_version
      AND ((g.scope_kind='workspace' AND g.scope_id IS NULL AND g.grant_kind=CASE WHEN $3 THEN 'owner' ELSE 'membership' END)
        OR (g.scope_kind='project' AND g.grant_kind='project'))
    ORDER BY g.scope_kind,g.scope_id,g.grant_id`, [workspaceId, accountId, isOwner, now])).rows;
  const groups = new Map<string, ScopeGrant[]>();
  for (const row of rows) {
    if (!row.key_manifest_object_id || !row.object_hash || row.definition_state !== 'committed' ||
      !positiveCounter.safeParse(row.key_epoch).success || row.key_epoch !== row.expected_epoch || !row.permissions.includes('read_project') ||
      (row.role_id !== null && (row.role_state !== 'active' || row.role_revision === null || row.current_role_revision === null ||
        BigInt(row.role_revision) > BigInt(row.current_role_revision)))) unavailable();
    const key = `${row.scope_kind}:${row.scope_id ?? workspaceId}`, group = groups.get(key) ?? []; group.push(row); groups.set(key, group);
  }
  const scopes = [...groups.values()].map((group): PairingScope => {
    const first = group[0]!, permissions = new Set(group.flatMap((row) => row.permissions));
    return { scope: first.scope_kind, scopeId: first.scope_id ?? workspaceId, mode: first.scope_kind === 'workspace' && isOwner ? 'custody' : 'content',
      keyEpoch: first.key_epoch, expiresAt: earliest(group.map((row) => row.expires_at))?.toISOString() ?? null,
      permissions: capabilities.filter((permission) => permissions.has(permission)), sources: group.map((row) => ({ grantId: row.grant_id,
        generation: row.generation, manifestId: row.key_manifest_object_id!, manifestDigest: row.object_hash! })) };
  });
  if (!scopes.some((scope) => scope.scope === 'workspace')) unavailable();
  return scopes.sort((a, b) => `${a.scope}:${a.scopeId}`.localeCompare(`${b.scope}:${b.scopeId}`));
}

/** A same-account approver may delegate only its still-current device delivery subset. */
export async function intersectDeviceScopes(client: pg.PoolClient, workspaceId: string, accountId: string, deviceId: string,
  personal: readonly PairingScope[], now: Date): Promise<PairingScope[]> {
  const rows = (await client.query<ScopeGrant>(`SELECT g.* FROM security.grants g
    JOIN security.devices d ON d.workspace_id=g.workspace_id AND d.profile_id=g.profile_id AND d.device_id=g.device_id
    JOIN security.workspaces w ON w.workspace_id=g.workspace_id
    JOIN security.staged_objects s ON s.workspace_id=g.workspace_id AND s.object_id=g.signed_grant_object_id AND s.state='committed'
    JOIN security.staged_objects m ON m.workspace_id=g.workspace_id AND m.object_id=g.key_manifest_object_id AND m.state='committed'
    WHERE g.workspace_id=$1 AND g.profile_id=$2 AND g.device_id=$3 AND d.state='active' AND d.revoked_at IS NULL
      AND g.generation=d.key_generation AND d.approval_security_version<=w.security_version
      AND g.state='active' AND g.revoked_at IS NULL AND g.security_version<=w.security_version
      AND (g.expires_at IS NULL OR g.expires_at>$4)
      AND ((g.scope_kind='workspace' AND g.grant_kind='device') OR (g.scope_kind='project' AND g.grant_kind='project'))`,
  [workspaceId, accountId, deviceId, now])).rows;
  const scopes: PairingScope[] = [];
  for (const scope of personal) {
    const grants = rows.filter((row) => row.scope_kind === scope.scope && (row.scope_id ?? workspaceId) === scope.scopeId && row.key_epoch === scope.keyEpoch);
    const available = new Set(grants.flatMap((row) => row.permissions)), permissions = scope.permissions.filter((permission) => available.has(permission));
    if (!permissions.includes('read_project')) continue;
    scopes.push({ ...scope, permissions, expiresAt: earliest([scope.expiresAt ? new Date(scope.expiresAt) : null,
      ...grants.map((row) => row.expires_at)])?.toISOString() ?? null });
  }
  if (!scopes.some((scope) => scope.scope === 'workspace')) unavailable();
  return scopes;
}

/** Historical immutable delivery never overrides a person's current permission or epoch. */
export function personalScopesCover(current: readonly PairingScope[], delivered: readonly PairingScope[]): boolean {
  return delivered.every((scope) => current.some((known) => known.scope === scope.scope && known.scopeId === scope.scopeId &&
    known.mode === scope.mode && known.keyEpoch === scope.keyEpoch && scope.permissions.every((permission) => known.permissions.includes(permission)) &&
    (known.expiresAt === null || (scope.expiresAt !== null && Date.parse(scope.expiresAt) <= Date.parse(known.expiresAt)))));
}

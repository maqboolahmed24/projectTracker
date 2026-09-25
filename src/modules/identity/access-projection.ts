import type pg from 'pg';
import { createHash, randomUUID } from 'node:crypto';
import { AppError } from '../../errors.js';
import type { GenesisBody } from '../../shared/activation.js';
import { contentEnvelope } from '../../shared/contracts.js';
import { canonicalJson } from '../../shared/crypto.js';
import { BUILTIN_ROLE_PERMISSIONS } from '../../shared/permissions.js';

const unavailable = () => new AppError('SECURITY_FENCED', 'Workspace access state cannot be projected', 503);
interface Role {
  role_id: string; template: keyof typeof BUILTIN_ROLE_PERMISSIONS | 'custom'; revision: string;
  state: 'active' | 'retired'; permissions: string[]; definition_object_id: string;
  definition_state: string | null; encrypted_role_object_id: string | null;
  label_kind: string | null; label_state: string | null; label: unknown; security_version: string;
}
interface Scope {
  scope_kind: 'workspace' | 'project'; scope_id: string; key_epoch: string;
  recovery_manifest_object_id: string; manifest_state: string | null; security_version: string;
}
interface Grant {
  grant_id: string; profile_id: string; scope_id: string; role_id: string | null; role_revision: string | null;
  generation: string; permissions: string[]; state: 'pending' | 'active' | 'revoked'; key_epoch: string;
  expires_at: Date | null; revoked_at: Date | null; security_version: string;
  definition_state: string | null; manifest_state: string | null;
}
export interface AccessSnapshot { roles: Role[]; scopes: Scope[]; grants: Grant[]; custodyReady: boolean }

/** Called only inside the workspace authority reader; these are committed control records. */
export async function readAccessSnapshot(control: pg.PoolClient, workspaceId: string): Promise<AccessSnapshot> {
  const roles = (await control.query<Role>(`SELECT r.*,d.state AS definition_state,
      e.object_kind AS label_kind,e.state AS label_state,e.versioned_object AS label
    FROM security.roles r LEFT JOIN security.staged_objects d
      ON d.workspace_id=r.workspace_id AND d.object_id=r.definition_object_id
    LEFT JOIN security.staged_objects e ON e.workspace_id=r.workspace_id AND e.object_id=r.encrypted_role_object_id
    WHERE r.workspace_id=$1 ORDER BY r.role_id`, [workspaceId])).rows;
  const scopes = (await control.query<Scope>(`SELECT s.*,o.state AS manifest_state FROM security.scope_heads s
    LEFT JOIN security.staged_objects o ON o.workspace_id=s.workspace_id AND o.object_id=s.recovery_manifest_object_id
    WHERE s.workspace_id=$1 ORDER BY s.scope_kind,s.scope_id`, [workspaceId])).rows;
  const grants = (await control.query<Grant>(`SELECT g.*,d.state AS definition_state,m.state AS manifest_state
    FROM security.grants g LEFT JOIN security.staged_objects d
      ON d.workspace_id=g.workspace_id AND d.object_id=g.signed_grant_object_id
    LEFT JOIN security.staged_objects m ON m.workspace_id=g.workspace_id AND m.object_id=g.key_manifest_object_id
    WHERE g.workspace_id=$1 AND g.grant_kind='project' AND g.scope_kind='project' AND g.device_id IS NULL
    ORDER BY g.scope_id,g.profile_id,g.generation,g.grant_id`, [workspaceId])).rows;
  const custodyReady = (await control.query(`SELECT 1 FROM security.workspaces w JOIN security.staged_objects o
    ON o.workspace_id=w.workspace_id AND o.object_id=w.current_custody_manifest_object_id
    WHERE w.workspace_id=$1 AND o.object_kind='custody_manifest' AND o.state='committed'
      AND o.versioned_object->'header'->>'keyEpoch'=w.custody_epoch::text`, [workspaceId])).rowCount === 1;
  return { roles, scopes, grants, custodyReady };
}

/** New activation derives initial role identities and scope pointers from its validated signed genesis. */
export async function initializeAccessAuthority(control: pg.PoolClient, body: GenesisBody): Promise<void> {
  for (const template of Object.keys(BUILTIN_ROLE_PERMISSIONS) as (keyof typeof BUILTIN_ROLE_PERMISSIONS)[]) {
    await control.query(`INSERT INTO security.roles(workspace_id,role_id,template,revision,state,permissions,definition_object_id,security_version)
      VALUES($1,$2,$3,1,'active',$4,$5,1)`,
    [body.workspaceId, body.roles[template], template, BUILTIN_ROLE_PERMISSIONS[template], body.genesisId]);
  }
  await control.query(`INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version)
    VALUES($1,'workspace',$1,1,$2,1)`, [body.workspaceId, body.custodyId]);
}

/** Project the whole access snapshot before opening the fence. Never infer access from a team or assignment. */
export async function projectAccessSnapshot(application: pg.PoolClient, workspaceId: string, snapshot: AccessSnapshot,
  genesis: GenesisBody, securityVersion: string, now = new Date()): Promise<void> {
  if (!snapshot.custodyReady || !snapshot.scopes.some((scope) => scope.scope_kind === 'workspace' && scope.scope_id === workspaceId)) throw unavailable();
  for (const template of Object.keys(BUILTIN_ROLE_PERMISSIONS) as (keyof typeof BUILTIN_ROLE_PERMISSIONS)[]) {
    if (!snapshot.roles.some((role) => role.role_id === genesis.roles[template] && role.template === template)) throw unavailable();
  }
  for (const role of snapshot.roles) {
    if (role.definition_state !== 'committed' || BigInt(role.security_version) > BigInt(securityVersion)) throw unavailable();
    if (role.definition_object_id === genesis.genesisId && (role.template === 'custom' || role.revision !== '1' ||
      role.role_id !== genesis.roles[role.template] || canonicalJson(role.permissions) !== canonicalJson(BUILTIN_ROLE_PERMISSIONS[role.template]))) throw unavailable();
    let label: unknown = {};
    if (role.encrypted_role_object_id !== null) {
      const parsed = contentEnvelope.safeParse(role.label);
      if (!parsed.success || role.label_kind !== 'encrypted_role' || role.label_state !== 'committed' ||
        parsed.data.header.workspaceId !== workspaceId || parsed.data.header.scope !== 'workspace' ||
        parsed.data.header.recordId !== role.role_id || parsed.data.header.recordType !== 'role' || parsed.data.header.revision !== role.revision) throw unavailable();
      label = parsed.data;
    } else if (role.template === 'custom') throw unavailable();
    await application.query(`INSERT INTO app.roles(workspace_id,id,template,revision,state,permissions,encrypted_envelope)
      VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(workspace_id,id) DO UPDATE SET template=EXCLUDED.template,
      revision=EXCLUDED.revision,state=EXCLUDED.state,permissions=EXCLUDED.permissions,
      encrypted_envelope=EXCLUDED.encrypted_envelope,updated_at=clock_timestamp()`,
    [workspaceId, role.role_id, role.template, role.revision, role.state, role.permissions, label]);
  }
  // A deleted/missing definition must not leave an older application role usable.
  await application.query("UPDATE app.roles SET state='retired' WHERE workspace_id=$1 AND NOT(id=ANY($2::uuid[]))", [workspaceId, snapshot.roles.map((role) => role.role_id)]);
  for (const scope of snapshot.scopes) {
    if (scope.manifest_state !== 'committed' || BigInt(scope.security_version) > BigInt(securityVersion)) throw unavailable();
    await application.query(`INSERT INTO app.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,security_version)
      VALUES($1,$2,$3,$4,$5) ON CONFLICT(workspace_id,scope_kind,scope_id) DO UPDATE SET
      key_epoch=EXCLUDED.key_epoch,security_version=EXCLUDED.security_version`,
    [workspaceId, scope.scope_kind, scope.scope_id, scope.key_epoch, scope.security_version]);
  }
  const desired = new Map<string, Grant>();
  for (const grant of snapshot.grants) {
    // Older unbound security-only grants never supply application access.
    if (grant.role_id === null || grant.role_revision === null) continue;
    const key = `${grant.scope_id}:${grant.profile_id}`, prior = desired.get(key);
    if (prior?.state === 'active' && grant.state === 'active') throw unavailable();
    if (!prior || grant.state === 'active' || prior.state !== 'active' && BigInt(grant.generation) >= BigInt(prior.generation)) desired.set(key, grant);
  }
  const previous = (await application.query<{ project_id: string; profile_id: string }>(
    'SELECT project_id,profile_id FROM app.project_access WHERE workspace_id=$1', [workspaceId])).rows;
  const touchedProjects = new Set(previous.map((access) => access.project_id));
  for (const grant of desired.values()) {
    const role = snapshot.roles.find((value) => value.role_id === grant.role_id);
    const scope = snapshot.scopes.find((value) => value.scope_kind === 'project' && value.scope_id === grant.scope_id);
    const active = grant.state === 'active' && grant.revoked_at === null && (!grant.expires_at || grant.expires_at > now);
    if (active && (!role || role.state !== 'active' || BigInt(grant.role_revision!) > BigInt(role.revision) ||
      !scope || grant.key_epoch !== scope.key_epoch || grant.definition_state !== 'committed' || grant.manifest_state !== 'committed' ||
      BigInt(grant.security_version) > BigInt(securityVersion))) throw unavailable();
    await application.query(`INSERT INTO app.project_access(workspace_id,project_id,profile_id,role_id,state,revision,
        grant_id,role_revision,permissions,key_epoch,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(workspace_id,project_id,profile_id) DO UPDATE SET
      role_id=EXCLUDED.role_id,state=EXCLUDED.state,revision=EXCLUDED.revision,grant_id=EXCLUDED.grant_id,
      role_revision=EXCLUDED.role_revision,permissions=EXCLUDED.permissions,key_epoch=EXCLUDED.key_epoch,
      expires_at=EXCLUDED.expires_at,updated_at=clock_timestamp()`,
    [workspaceId, grant.scope_id, grant.profile_id, grant.role_id, active ? 'active' : grant.state === 'pending' ? 'pending' : 'revoked',
      grant.generation, grant.grant_id, grant.role_revision, grant.permissions, grant.key_epoch, grant.expires_at]);
    touchedProjects.add(grant.scope_id);
  }
  for (const access of previous) if (!desired.has(`${access.project_id}:${access.profile_id}`)) {
    await application.query("UPDATE app.project_access SET state='revoked',updated_at=clock_timestamp() WHERE workspace_id=$1 AND project_id=$2 AND profile_id=$3",
      [workspaceId, access.project_id, access.profile_id]);
  }
  for (const projectId of touchedProjects) await clearRemovedResponsibilities(application, workspaceId, projectId, securityVersion, now);
  await application.query("SELECT set_config('ukda.profile_id','',true)");
}

async function clearRemovedResponsibilities(application: pg.PoolClient, workspaceId: string, projectId: string, securityVersion: string, now: Date) {
  const people = (await application.query<{ id: string; is_owner: boolean; eligible: boolean }>(`SELECT p.id,p.is_owner,
      (p.state='active' AND a.state='active' AND r.state='active' AND 'read_project'=ANY(a.permissions)
       AND (a.expires_at IS NULL OR a.expires_at>$3)) AS eligible
    FROM app.project_access a JOIN app.profiles p ON p.workspace_id=a.workspace_id AND p.id=a.profile_id
    JOIN app.roles r ON r.workspace_id=a.workspace_id AND r.id=a.role_id
    WHERE a.workspace_id=$1 AND a.project_id=$2 ORDER BY p.id`, [workspaceId, projectId, now])).rows;
  const owner = people.find((person) => person.is_owner && person.eligible);
  if (!owner) throw unavailable();
  // Internal authority projection still runs through explicit Owner project RLS.
  await application.query("SELECT set_config('ukda.profile_id',$1,true)", [owner.id]);
  const eligible = people.filter((person) => person.eligible).map((person) => person.id);
  // Capture only work that this cleanup will leave newly unassigned. Existing
  // unassigned tasks, terminal work and tasks with a surviving assignee do not
  // create another notification on every authority projection.
  const newlyUnassigned = (await application.query<{ id: string }>(`SELECT task.id FROM app.tasks task
    WHERE task.workspace_id=$1 AND task.project_id=$2 AND task.state NOT IN ('done','cancelled')
      AND EXISTS (SELECT 1 FROM app.task_assignments a WHERE a.workspace_id=task.workspace_id
        AND a.task_id=task.id AND NOT(a.member_id=ANY($3::uuid[])))
      AND NOT EXISTS (SELECT 1 FROM app.task_assignments a WHERE a.workspace_id=task.workspace_id
        AND a.task_id=task.id AND a.member_id=ANY($3::uuid[])) ORDER BY task.id`,
  [workspaceId, projectId, eligible])).rows;
  for (const [table, column, extra] of [
    ['tasks', 'lead_profile_id', " AND state NOT IN ('done','cancelled')"],
    ['tasks', 'reviewer_profile_id', " AND state NOT IN ('done','cancelled')"],
    ['project_phases', 'lead_profile_id', " AND state NOT IN ('complete','cancelled')"],
    ['milestones', 'owner_profile_id', " AND state='open'"],
    ['blockers', 'responsible_profile_id', " AND state='open'"],
  ] as const) {
    await application.query(`UPDATE app.${table} SET ${column}=NULL,updated_at=clock_timestamp()
      WHERE workspace_id=$1 AND project_id=$2 AND ${column} IS NOT NULL AND NOT(${column}=ANY($3::uuid[]))${extra}`,
    [workspaceId, projectId, eligible]);
  }
  // All current assignments (including closed tasks) need valid references. History remains in record versions.
  await application.query(`UPDATE app.tasks SET lead_profile_id=NULL WHERE workspace_id=$1 AND project_id=$2
    AND lead_profile_id IS NOT NULL AND NOT(lead_profile_id=ANY($3::uuid[]))`, [workspaceId, projectId, eligible]);
  await application.query(`DELETE FROM app.task_assignments WHERE workspace_id=$1 AND project_id=$2
    AND NOT(member_id=ANY($3::uuid[]))`, [workspaceId, projectId, eligible]);
  await application.query(`UPDATE app.projects SET manager_profile_id=NULL,updated_at=clock_timestamp()
    WHERE workspace_id=$1 AND id=$2 AND manager_profile_id IS NOT NULL AND NOT(manager_profile_id=ANY($3::uuid[]))`,
  [workspaceId, projectId, eligible]);
  if (newlyUnassigned.length) {
    const manager = (await application.query<{ manager_profile_id: string | null }>(
      'SELECT manager_profile_id FROM app.projects WHERE workspace_id=$1 AND id=$2', [workspaceId, projectId])).rows[0]?.manager_profile_id;
    const recipients = people.filter((person) => person.eligible && (person.is_owner || person.id === manager));
    for (const recipient of recipients) {
      // Internal projection still uses each recipient's current RLS visibility.
      await application.query("SELECT set_config('ukda.profile_id',$1,true)", [recipient.id]);
      for (const task of newlyUnassigned) {
        const bytes = createHash('sha256').update(JSON.stringify(['ukda.security.work_unassigned.v1',
          workspaceId, securityVersion, projectId, task.id])).digest().subarray(0, 16);
        bytes[6] = (bytes[6]! & 0x0f) | 0x80; bytes[8] = (bytes[8]! & 0x3f) | 0x80;
        const hex = bytes.toString('hex');
        const eventId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
        // A security notice is not suppressed by project mute or self-action.
        // Details are fetched/decrypted separately under current project access.
        await application.query(`INSERT INTO app.notifications(workspace_id,id,recipient_profile_id,project_id,
          event_id,event_type,record_id) VALUES($1,$2,$3,$4,$5,'security.work_unassigned',$6)
          ON CONFLICT(workspace_id,recipient_profile_id,event_id) DO NOTHING`,
        [workspaceId, randomUUID(), recipient.id, projectId, eventId, task.id]);
      }
    }
  }
}

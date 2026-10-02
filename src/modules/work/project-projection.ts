import type pg from 'pg';
import { AppError } from '../../errors.js';
import { contentEnvelope } from '../../shared/contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyContentEnvelope, verifyObject } from '../../shared/crypto.js';
import { projectCreateHeader, projectCreateTransition } from '../../shared/project-create.js';

const unavailable = () => new AppError('SECURITY_FENCED', 'Committed project creation cannot be projected', 503);
interface Row { project_id: string; operation_id: string; project_object_id: string; security_version: string; created_at: Date;
  object_kind: string; object_state: string; object_hash: string; versioned_object: unknown;
  transition_kind: string; transition_state: string; transition_hash: string; transition: unknown; sequence: string; head: string; signed_transition: unknown }
export async function readProjectCreations(control: pg.PoolClient, workspaceId: string, throughVersion: string) {
  const rows = (await control.query<Row>(`SELECT p.*,o.object_kind,o.state AS object_state,o.object_hash,o.versioned_object,
      s.object_kind AS transition_kind,s.state AS transition_state,s.object_hash AS transition_hash,s.versioned_object AS transition,
      t.sequence,t.head,t.signed_transition
    FROM security.project_creations p
    LEFT JOIN security.staged_objects o ON o.workspace_id=p.workspace_id AND o.object_id=p.project_object_id
    LEFT JOIN security.staged_objects s ON s.workspace_id=p.workspace_id AND s.object_id=p.operation_id
    LEFT JOIN security.security_transitions t ON t.workspace_id=p.workspace_id AND t.sequence=p.security_version
    WHERE p.workspace_id=$1 ORDER BY p.security_version`, [workspaceId])).rows;
  return Promise.all(rows.map(async (row) => {
    const parsed = projectCreateTransition.safeParse(row.transition), envelope = contentEnvelope.safeParse(row.versioned_object);
    if (!parsed.success || !envelope.success) throw unavailable();
    const transition = parsed.data, body = transition.body, b = body.binding, ref = body.project!;
    if (row.object_kind !== 'encrypted_project' || row.object_state !== 'committed' || row.transition_kind !== 'signed_grant' || row.transition_state !== 'committed' ||
      b.workspaceId !== workspaceId || b.projectId !== row.project_id || b.operationId !== row.operation_id || b.nextSecurityVersion !== row.security_version ||
      BigInt(row.security_version) > BigInt(throughVersion) || row.sequence !== row.security_version || row.head !== row.transition_hash ||
      row.transition_hash !== await digestObject(transition) || canonicalJson(row.signed_transition) !== canonicalJson(transition) ||
      ref.id !== row.project_object_id || row.object_hash !== ref.digest || row.object_hash !== await digestObject(envelope.data) ||
      !await verifyObject(transition, base64urlDecode(b.authorizer.device.signingPublicKey, 32), 'ukda.project-scope-provision.v1') ||
      !await verifyContentEnvelope(envelope.data, base64urlDecode(b.authorizer.device.signingPublicKey, 32), projectCreateHeader(b))) throw unavailable();
    return { id: row.project_id, envelope: envelope.data, createdAt: row.created_at };
  }));
}
export async function projectCommittedCreations(application: pg.PoolClient, workspaceId: string,
  projects: Awaited<ReturnType<typeof readProjectCreations>>) {
  const absent = new Set((await application.query<{project_id:string}>('SELECT project_id FROM app.unrecovered_projects WHERE workspace_id=$1',[workspaceId])).rows.map(row=>row.project_id));
  try { for (const project of projects) {
    if (absent.has(project.id)) continue;
    const owner = (await application.query<{ id: string }>(`SELECT p.id FROM app.project_access a
      JOIN app.profiles p ON p.workspace_id=a.workspace_id AND p.id=a.profile_id
      JOIN app.roles r ON r.workspace_id=a.workspace_id AND r.id=a.role_id
      WHERE a.workspace_id=$1 AND a.project_id=$2 AND p.state='active' AND p.is_owner
        AND a.state='active' AND r.state='active' AND 'read_project'=ANY(a.permissions)
        AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) ORDER BY p.id LIMIT 1`, [workspaceId, project.id])).rows[0];
    if (!owner) throw unavailable();
    // Security projection uses current explicit Owner project grants through the
    // same RLS policy as normal reads. The project FK is deferred until commit.
    await application.query("SELECT set_config('ukda.profile_id',$1,true)", [owner.id]);
    const prior = (await application.query<{ revision: string; encrypted_envelope: unknown }>('SELECT revision,encrypted_envelope FROM app.projects WHERE workspace_id=$1 AND id=$2', [workspaceId, project.id])).rows[0];
    if (prior) {
      if (prior.revision === '1' && canonicalJson(prior.encrypted_envelope) !== canonicalJson(project.envelope)) throw unavailable();
      continue;
    }
    await application.query(`INSERT INTO app.projects(workspace_id,id,state,archived,phase_label,revision,schema_version,key_epoch,encrypted_envelope,created_at)
      VALUES($1,$2,'planned',false,'wave',1,$5,$6,$3,$4)`, [workspaceId, project.id, project.envelope, project.createdAt,project.envelope.header.schema,project.envelope.header.keyEpoch]);
  } } finally { await application.query("SELECT set_config('ukda.profile_id','',true)"); }
}

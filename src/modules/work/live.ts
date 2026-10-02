import type { Databases } from '../../db.js';
import { transaction } from '../../db.js';
import { AppError } from '../../errors.js';
import { dataTransaction } from '../../persistence.js';
import { digestObject } from '../../shared/crypto.js';
import { liveRequest, type LiveCheckpoint } from '../../shared/live.js';
import type { SessionService } from '../identity/sessions.js';
import { readCurrentDeviceProjectScopes } from './planning.js';

/** Each batch takes a new security fence; connections do not retain access grants. */
export class LiveService {
  constructor(readonly options: { databases: Databases; sessions: SessionService; now?: () => Date }) {}
  async checkpoint(cookie: string, csrfToken: string, input: unknown): Promise<LiveCheckpoint> {
    const parsed = liveRequest.safeParse(input);
    if (!parsed.success) throw new AppError('INVALID_REQUEST', 'Invalid live request', 400);
    const initial = await this.options.sessions.authenticate(cookie, { csrfToken, approved: true });
    if (initial.workspaceId !== parsed.data.workspaceId) throw new AppError('NOT_FOUND', 'Workspace not available', 404);
    return dataTransaction(this.options.databases, initial, async (application, state) => {
      return transaction(this.options.databases.control, async (control) => {
        const now = this.options.now?.() ?? new Date();
        const principal = await this.options.sessions.resolveCurrent(control, cookie, { csrfToken, approved: true }, now);
        if (principal.workspaceId !== initial.workspaceId || principal.profileId !== initial.profileId ||
          principal.deviceId !== initial.deviceId || principal.securityHead !== initial.securityHead ||
          principal.securityVersion !== initial.securityVersion || principal.dataGeneration !== initial.dataGeneration) {
          throw new AppError('SECURITY_STATE_CHANGED', 'Refresh current access', 409);
        }
        const scopes = (await readCurrentDeviceProjectScopes(control, principal, now)).filter((s) => s.scope === 'project');
        const ids = scopes.map((s) => s.scopeId).sort();
        // A single SQL snapshot, explicit device filtering in addition to person RLS.
        // The digest includes no encrypted or decrypted business payloads. Summary
        // cache writes are intentionally absent: publishing cannot refresh itself.
        const result = await application.query<{ metadata: unknown }>(`SELECT jsonb_build_object(
          'workspace',(SELECT revision::text FROM app.workspaces WHERE workspace_id=$1),
          'projects',COALESCE((SELECT jsonb_agg(jsonb_build_array(p.id,p.revision::text,p.archived,h.planning_version::text,h.planning_head) ORDER BY p.id)
            FROM app.projects p LEFT JOIN app.project_planning_heads h ON h.workspace_id=p.workspace_id AND h.project_id=p.id
            WHERE p.workspace_id=$1 AND p.id=ANY($2::uuid[])), '[]'::jsonb),
          'comments',COALESCE((SELECT jsonb_agg(jsonb_build_array(id,revision::text) ORDER BY id) FROM app.comments WHERE workspace_id=$1 AND project_id=ANY($2::uuid[])), '[]'::jsonb),
          'updates',COALESCE((SELECT jsonb_agg(jsonb_build_array(id,revision::text) ORDER BY id) FROM app.updates WHERE workspace_id=$1 AND project_id=ANY($2::uuid[])), '[]'::jsonb),
          'teams',COALESCE((SELECT jsonb_agg(jsonb_build_array(id,revision::text) ORDER BY id) FROM app.teams WHERE workspace_id=$1), '[]'::jsonb),
          'inbox',COALESCE((SELECT jsonb_agg(jsonb_build_array(id,revision::text) ORDER BY id) FROM app.notification_receipts WHERE workspace_id=$1 AND recipient_profile_id=$3), '[]'::jsonb)
        ) AS metadata`, [principal.workspaceId, ids, principal.accountId]);
        return { version: 1, observedAt: now.toISOString(), fingerprint: await digestObject({
          metadata: result.rows[0]!.metadata,
          scopes: scopes.map((s) => ({ id: s.scopeId, epoch: s.keyEpoch, permissions: [...s.permissions].sort(), expiresAt: s.expiresAt })).sort((a, b) => a.id.localeCompare(b.id)),
          securityHead: principal.securityHead, dataGeneration: principal.dataGeneration,
          lifecycle: state.lifecycle, licenceState: state.licence_state, maintenance: state.content_maintenance,
        }) };
      });
    });
  }
}

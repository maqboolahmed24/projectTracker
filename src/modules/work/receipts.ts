import type pg from 'pg';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { dataTransaction, tenantTransaction } from '../../persistence.js';
import { receiptLookupRequest, receiptLookupResponse, type ReceiptLookupRequest, type ReceiptLookupResponse } from '../../shared/receipts.js';
import { inboxMutation } from '../../shared/inbox.js';
import { SessionService, type SessionPrincipal } from '../identity/sessions.js';
import { readCurrentDeviceProjectScopes } from './planning.js';

interface Options { databases: Databases; sessions: SessionService; now?: () => Date;
  requestBudget?: (scope: { workspaceId: string; accountId: string }) => Promise<void> }
const unavailable = () => new AppError('NOT_FOUND', 'Operation not available', 404);
interface OperationRow { receipt: unknown; request_digest: string; data_generation: string; project_id?: string;
  actor_profile_id?: string; project_ids?: string[]; signed_change?: unknown }

/** Receipt lookup after explicit logout retains no local ciphertext or request hash.
 * All acknowledgements remain actor-bound and use current person AND device scope.
 */
export class ReceiptService {
  constructor(private readonly options: Options) {}
  async lookup(cookie: string, csrf: string, input: unknown): Promise<ReceiptLookupResponse> {
    const request = parseInput(receiptLookupRequest, input);
    const initial = await this.options.sessions.authenticate(cookie, { csrfToken: csrf, approved: true });
    if (initial.workspaceId !== request.workspaceId) throw unavailable();
    await this.options.requestBudget?.({ workspaceId: initial.workspaceId, accountId: initial.accountId });
    return dataTransaction(this.options.databases, initial, app =>
      tenantTransaction(this.options.databases.control, initial.workspaceId, initial.accountId, async control => {
        const now = this.options.now?.() ?? new Date();
        const current = await this.options.sessions.resolveCurrent(control, cookie, { csrfToken: csrf, approved: true }, now);
        if (current.workspaceId !== initial.workspaceId || current.accountId !== initial.accountId || current.deviceId !== initial.deviceId ||
          current.securityHead !== initial.securityHead || current.securityVersion !== initial.securityVersion || current.dataGeneration !== initial.dataGeneration)
          throw new AppError('SECURITY_STATE_CHANGED', 'Refresh workspace security state before continuing', 409);
        const scopes = await readCurrentDeviceProjectScopes(control, current, now);
        const projects = new Set(scopes.filter(s => s.scope === 'project' && s.permissions.includes('read_project')).map(s => s.scopeId));
        if ('projectId' in request && !projects.has(request.projectId)) throw unavailable();
        if (['project', 'role', 'access', 'reporting-settings'].includes(request.kind)) {
          const owner = await control.query("SELECT 1 FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 AND state='active' AND is_owner", [current.workspaceId, current.accountId]);
          if (!owner.rowCount || !scopes.some(s => s.scope === 'workspace')) throw unavailable();
        }
        return this.read(app, control, current, request, projects);
      }));
  }
  private async read(app: pg.PoolClient, control: pg.PoolClient, p: SessionPrincipal, request: ReceiptLookupRequest,
    projects: Set<string>): Promise<ReceiptLookupResponse> {
    let receipt: unknown = null, hash: string | undefined;
    const params = [request.workspaceId, request.operationId];
    if (request.kind === 'planning' || request.kind === 'collaboration') {
      // Table selection is a closed constant, never a caller-supplied SQL name.
      const table = request.kind === 'planning' ? 'app.planning_operations' : 'app.collaboration_operations';
      const row = (await app.query<OperationRow>(`SELECT receipt,request_digest,data_generation,project_id FROM ${table}
        WHERE workspace_id=$1 AND operation_id=$2 AND project_id=$3 AND data_generation=$4`, [...params, request.projectId, p.dataGeneration])).rows[0];
      if (row) {
        const parsed = receiptLookupResponse.parse({ kind: request.kind, receipt: row.receipt });
        if ((parsed.kind === 'planning' || parsed.kind === 'collaboration') && parsed.receipt?.mutation.body.binding.accountId === p.accountId) {
          receipt = parsed.receipt; hash = row.request_digest;
        }
      }
    } else if (request.kind === 'team') {
      const row = (await app.query<{ encrypted_envelope: { receipt: unknown }; request_digest: string }>(`SELECT encrypted_envelope,request_digest
        FROM app.operation_receipts WHERE workspace_id=$1 AND operation_id=$2 AND actor_profile_id=$3 AND data_generation=$4
        AND action IN ('teams.create','teams.update')`, [...params, p.accountId, p.dataGeneration])).rows[0];
      if (row) { receipt = row.encrypted_envelope.receipt; hash = row.request_digest; }
    } else if (request.kind === 'reporting-settings' || request.kind === 'reporting-summary') {
      const row = (await app.query<OperationRow>(`SELECT receipt,request_digest,data_generation,project_ids FROM app.reporting_operations
        WHERE workspace_id=$1 AND operation_id=$2 AND actor_profile_id=$3 AND data_generation=$4 AND kind=$5`,
      [...params, p.accountId, p.dataGeneration, request.kind === 'reporting-settings' ? 'settings' : 'summary'])).rows[0];
      if (row) {
        if (!row.project_ids?.every(id => projects.has(id))) throw unavailable();
        receipt = row.receipt; hash = row.request_digest;
      }
    } else if (request.kind === 'inbox') {
      const row = (await app.query<OperationRow>(`SELECT receipt,request_digest,data_generation,signed_change FROM app.inbox_operations
        WHERE workspace_id=$1 AND operation_id=$2 AND actor_profile_id=$3 AND data_generation=$4`, [...params, p.accountId, p.dataGeneration])).rows[0];
      if (row) {
        const command = inboxMutation.parse(row.signed_change).body.command;
        if (command.action === 'set_project_muted' && !projects.has(command.projectId)) throw unavailable();
        receipt = row.receipt; hash = row.request_digest;
      }
    } else {
      const kind = { project: 'project.create', role: 'role.define', access: 'access.change' }[request.kind];
      const row = (await control.query<{ outcome: unknown; request_hash: string }>(`SELECT outcome,request_hash FROM security.operation_receipts
        WHERE workspace_id=$1 AND operation_id=$2 AND operation_kind=$3`, [...params, kind])).rows[0];
      if (row) {
        const parsed = receiptLookupResponse.parse({ kind: request.kind, receipt: row.outcome });
        if ((parsed.kind === 'project' || parsed.kind === 'role' || parsed.kind === 'access') && parsed.receipt) {
          const binding = parsed.receipt.transition.body.binding;
          if (binding.authorizer.accountId === p.accountId && binding.dataGeneration === p.dataGeneration) {
            if (parsed.kind === 'project' && !projects.has(parsed.receipt.projectId)) throw unavailable();
            receipt = parsed.receipt; hash = row.request_hash;
          }
        }
      }
    }
    const result = receiptLookupResponse.parse({ kind: request.kind, receipt });
    if (result.receipt && (result.receipt.workspaceId !== request.workspaceId || result.receipt.operationId !== request.operationId || result.receipt.requestHash !== hash))
      throw new AppError('RECEIPT_UNAVAILABLE', 'Operation receipt is temporarily unavailable', 503);
    return result;
  }
}

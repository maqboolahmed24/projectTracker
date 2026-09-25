import sodium from 'libsodium-wrappers';
import { z } from 'zod';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { tenantTransaction } from '../../persistence.js';
import { identifier } from '../../shared/contracts.js';
import { base64urlEncode, digestObject, signObject, type SignedObject } from '../../shared/crypto.js';
import { projectAuthoritativeWorkspace, withSecurityFence, type ProjectionResult } from './projection.js';
import { ServiceSecrets } from './secrets.js';

import { entitlementActions, entitlementTransitionBody, licenceState, restrictionState, type EntitlementTransitionBody } from '../../shared/entitlement.js';
export { entitlementActions, entitlementTransitionBody, type EntitlementTransitionBody } from '../../shared/entitlement.js';
export const entitlementChange = z.strictObject({ licenceId: identifier, operationId: identifier, action: z.enum(entitlementActions) });
export type EntitlementChange = z.infer<typeof entitlementChange>;
export interface OperationalActor { operatorId: string }
type LicenceState = z.infer<typeof licenceState>;

export const entitlementPolicyActions = ['authenticate', 'replace_device_existing_scopes', 'read', 'recover', 'change_password',
  'revoke_access', 'export', 'request_deletion', 'cancel_deletion', 'content_write', 'create_project', 'invite', 'promote_owner', 'expand_access'] as const;
export type EntitlementPolicyAction = typeof entitlementPolicyActions[number];
const restrictedAllowed = new Set<EntitlementPolicyAction>(['authenticate', 'replace_device_existing_scopes', 'read', 'recover',
  'change_password', 'revoke_access', 'export', 'request_deletion', 'cancel_deletion']);

/** Licence guard only: caller must separately enforce identity, scope, deletion, maintenance and restore guards. */
export function entitlementAllows(state: string, action: string): boolean {
  if (!restrictionState.safeParse(state).success || !(entitlementPolicyActions as readonly string[]).includes(action)) return false;
  return state === 'active' || restrictedAllowed.has(action as EntitlementPolicyAction);
}
export function assertEntitlementAllows(state: string, action: EntitlementPolicyAction): void {
  if (!entitlementAllows(state, action)) throw new AppError('WORKSPACE_RESTRICTED', 'This action is unavailable while the licence is restricted', 423);
}

export interface EntitlementReceipt {
  operationId: string; licenceId: string; action: EntitlementChange['action']; operatorId: string;
  workspaceId: string | null; entitlementState: LicenceState; licenceState: z.infer<typeof restrictionState> | null;
  securityHead: string | null; securityVersion: string | null; changedAt: string;
  transition: SignedObject<EntitlementTransitionBody>;
}
export interface EntitlementResult { receipt: EntitlementReceipt; projection: ProjectionResult | null }
interface LicenceRow { licence_id: string; state: LicenceState; activated_workspace_id: string | null }
interface Authority {
  lifecycle: 'pending_activation' | 'active' | 'pending_deletion' | 'deleted'; security_head: string;
  security_version: string; data_generation: string; licence_state: z.infer<typeof restrictionState>;
}
class RetryWithWorkspaceFence extends Error {}
const conflict = () => new AppError('OPERATION_CONFLICT', 'Entitlement operation does not match its receipt', 409);
const missing = () => new AppError('NOT_FOUND', 'Entitlement is not available', 404);

/**
 * Operational-only service. OS/deployment access and operational secrets authenticate
 * the calling CLI; operatorId is audit attribution, not a customer login credential.
 * Service signatures authorize only the exact entitlement before/after states. They
 * cannot authorize ownership, grant, profile, session or content-key changes.
 */
export class EntitlementOperations {
  readonly #db: Databases;
  readonly #secrets: ServiceSecrets;
  readonly #now: () => Date;
  constructor(databases: Databases, secrets: ServiceSecrets, options: { now?: () => Date } = {}) {
    this.#db = databases; this.#secrets = secrets; this.#now = options.now ?? (() => new Date());
  }

  /** Distribute this through trusted operational configuration; an embedded key alone is not a trust root. */
  async publicSigningKey(): Promise<string> {
    await sodium.ready;
    const seed = this.#secrets.digest('entitlement-signing-key', this.#secrets.keyId);
    const pair = sodium.crypto_sign_seed_keypair(seed);
    try { return base64urlEncode(pair.publicKey); }
    finally { seed.fill(0); pair.privateKey.fill(0); }
  }

  async change(input: EntitlementChange, actor: OperationalActor): Promise<EntitlementResult> {
    const request = entitlementChange.safeParse(input);
    const operator = z.strictObject({ operatorId: identifier }).safeParse(actor);
    if (!request.success || !operator.success) throw new AppError('INVALID_REQUEST', 'Invalid entitlement operation', 400);
    const change = request.data, operatorId = operator.data.operatorId;
    const requestHash = await digestObject({ version: 1, purpose: 'ukda.entitlement-request.v1', ...change, operatorId });
    // A mismatched replay cannot close a healthy workspace's fence.
    const previous = await this.#db.control.query<{ request_hash: string }>('SELECT request_hash FROM security.entitlement_operations WHERE operation_id=$1', [change.operationId]);
    if (previous.rows[0] && previous.rows[0].request_hash !== requestHash) throw conflict();
    for (let retry = 0; retry < 3; retry++) {
      const licence = (await this.#db.control.query<LicenceRow>('SELECT licence_id,state,activated_workspace_id FROM security.licences WHERE licence_id=$1', [change.licenceId])).rows[0];
      if (!licence) throw missing();
      const workspaceId = licence.activated_workspace_id;
      const authority = workspaceId ? await tenantTransaction(this.#db.control, workspaceId, undefined, async (client) =>
        (await client.query<Authority>('SELECT lifecycle,security_head,security_version,data_generation,licence_state FROM security.workspaces WHERE workspace_id=$1', [workspaceId])).rows[0]) : undefined;
      // Retired consumed markers remain consumed, even after the workspace was purged.
      // They have no protected application data to project or recreate.
      const needsFence = workspaceId !== null && authority !== undefined && authority.lifecycle !== 'deleted';
      try {
        if (!needsFence) {
          const receipt = await this.#commit(change, operatorId, requestHash, workspaceId, false);
          return { receipt, projection: authority?.lifecycle === 'deleted' || workspaceId !== null ? { state: 'deleted' } : null };
        }
        return await withSecurityFence(this.#db, workspaceId, async (application) => {
          const receipt = await this.#commit(change, operatorId, requestHash, workspaceId, true);
          const projection = await projectAuthoritativeWorkspace(this.#db, workspaceId, application);
          return { receipt, projection };
        }, { enqueueActivationProjection: true });
      } catch (error) {
        if (error instanceof RetryWithWorkspaceFence) continue;
        if (typeof error === 'object' && error !== null && 'code' in error && error.code === '23505') throw conflict();
        throw error;
      }
    }
    throw new AppError('RETRY_REQUIRED', 'Retry the same entitlement operation', 409);
  }

  async #commit(change: EntitlementChange, operatorId: string, requestHash: string, expectedWorkspaceId: string | null, hasFence: boolean): Promise<EntitlementReceipt> {
    return transaction(this.#db.control, async (control) => {
      await control.query("SET LOCAL synchronous_commit='on'");
      const licence = (await control.query<LicenceRow>('SELECT licence_id,state,activated_workspace_id FROM security.licences WHERE licence_id=$1 FOR UPDATE', [change.licenceId])).rows[0];
      if (!licence) throw missing();
      // Never acquire an application fence while holding the licence lock: activation
      // acquires that fence first, then locks licence -> attempt -> workspace.
      if (licence.activated_workspace_id !== expectedWorkspaceId) throw new RetryWithWorkspaceFence();
      const previous = (await control.query<{ request_hash: string; outcome: EntitlementReceipt }>('SELECT request_hash,outcome FROM security.entitlement_operations WHERE operation_id=$1', [change.operationId])).rows[0];
      if (previous) {
        if (previous.request_hash !== requestHash) throw conflict();
        return previous.outcome;
      }
      const attempts = await control.query<{ activation_id: string; workspace_id: string }>(`SELECT activation_id,workspace_id FROM security.activation_attempts
        WHERE licence_id=$1 AND state='reserved' ORDER BY activation_id FOR UPDATE`, [change.licenceId]);
      let authority: Authority | undefined;
      if (expectedWorkspaceId) {
        await control.query("SELECT set_config('ukda.workspace_id',$1,true)", [expectedWorkspaceId]);
        authority = (await control.query<Authority>('SELECT lifecycle,security_head,security_version,data_generation,licence_state FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE', [expectedWorkspaceId])).rows[0];
        if (authority && authority.lifecycle !== 'deleted' && !hasFence) throw new RetryWithWorkspaceFence();
        if (authority?.lifecycle === 'pending_activation') throw missing();
      }
      const activeAuthority = authority && authority.lifecycle !== 'deleted' ? authority : undefined;
      if (activeAuthority?.security_version === '0') throw missing();
      const afterState: LicenceState = change.action === 'revoke' ? 'revoked' : change.action === 'legacy_expire' ? 'legacy_expired' : expectedWorkspaceId ? 'activated' : 'available';
      const afterRestriction = activeAuthority ? (change.action === 'reinstate' ? 'active' : 'restricted') : authority?.licence_state ?? null;
      const version = activeAuthority ? String(BigInt(activeAuthority.security_version) + 1n) : null;
      const now = this.#now();
      await sodium.ready;
      const seed = this.#secrets.digest('entitlement-signing-key', this.#secrets.keyId);
      const pair = sodium.crypto_sign_seed_keypair(seed);
      let transition: SignedObject<EntitlementTransitionBody>;
      try {
        const body = entitlementTransitionBody.parse({ version: 1, purpose: 'ukda.entitlement-transition.v1', ...change,
          operatorId, workspaceId: expectedWorkspaceId, previousHead: activeAuthority?.security_head ?? null,
          securityVersion: version, dataGeneration: activeAuthority?.data_generation ?? null,
          before: { entitlementState: licence.state, licenceState: authority?.licence_state ?? null },
          after: { entitlementState: afterState, licenceState: afterRestriction }, changedAt: now.toISOString(),
          serviceKeyId: this.#secrets.keyId, servicePublicKey: base64urlEncode(pair.publicKey) });
        transition = await signObject(body, pair.privateKey);
      } finally { seed.fill(0); pair.privateKey.fill(0); }
      const head = activeAuthority ? await digestObject(transition) : null;
      const receipt: EntitlementReceipt = { ...change, operatorId, workspaceId: expectedWorkspaceId,
        entitlementState: afterState, licenceState: afterRestriction, securityHead: head, securityVersion: version,
        changedAt: now.toISOString(), transition };
      if (!expectedWorkspaceId) {
        for (const attempt of attempts.rows) {
          await control.query("SELECT set_config('ukda.workspace_id',$1,true)", [attempt.workspace_id]);
          await control.query(`DELETE FROM security.workspaces WHERE workspace_id=$1 AND lifecycle='pending_activation' AND security_version=0 AND activated_at IS NULL`, [attempt.workspace_id]);
          await control.query(`UPDATE security.activation_attempts SET state='cancelled',staged_public_state='{}',staged_payload_hash=NULL,
            staged_registration_record=NULL,proof_id=NULL,proof_server_state=NULL,proof_expires_at=NULL,proof_verified_at=NULL WHERE activation_id=$1`, [attempt.activation_id]);
        }
      }
      await control.query(`UPDATE security.licences SET state=$2,
        reservation_generation=reservation_generation+CASE WHEN activated_workspace_id IS NULL THEN 1 ELSE 0 END,
        updated_at=$3 WHERE licence_id=$1`, [change.licenceId, afterState, now]);
      if (activeAuthority && expectedWorkspaceId) {
        await control.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition,created_at)
          VALUES($1,$2,$3,$4,$5,$6,'service',$7,$8)`, [expectedWorkspaceId, version, change.operationId, activeAuthority.security_head, head, `entitlement.${change.action}`, transition, now]);
        await control.query(`UPDATE security.workspaces SET licence_state=$2,security_version=$3,security_head=$4,updated_at=$5 WHERE workspace_id=$1`,
        [expectedWorkspaceId, afterRestriction, version, head, now]);
        await control.query(`INSERT INTO security.operation_receipts(workspace_id,operation_id,request_hash,operation_kind,security_version,outcome,created_at)
          VALUES($1,$2,$3,$4,$5,$6,$7)`, [expectedWorkspaceId, change.operationId, requestHash, `entitlement.${change.action}`, version, receipt, now]);
      }
      const stored = await control.query<{ outcome: EntitlementReceipt }>(`INSERT INTO security.entitlement_operations(operation_id,licence_id,request_hash,action,operator_id,outcome,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING outcome`, [change.operationId, change.licenceId, requestHash, change.action, operatorId, receipt, now]);
      return stored.rows[0]!.outcome;
    });
  }
}

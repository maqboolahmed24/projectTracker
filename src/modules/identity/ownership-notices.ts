import { createHash } from 'node:crypto';
import type pg from 'pg';
import { AppError } from '../../errors.js';
import { accessTransition } from '../../shared/access-change.js';
import { enrolmentTransition } from '../../shared/enrolment.js';
import { recoveryTransition } from '../../shared/recovery.js';
import { base64urlDecode, digestObject, verifyObject, type SignedObject } from '../../shared/crypto.js';

export interface OwnershipNotice {
  operationId: string; actorId: string; targetId: string;
  eventType: 'security.owner_added' | 'security.owner_promoted' | 'security.owner_demoted' |
    'security.owner_suspended' | 'security.owner_removed' | 'security.owner_recovered';
}
interface JournalRow { operation_id: string; sequence: string; previous_head: string; head: string; signed_transition: unknown }
function unavailable(): never { throw new AppError('SECURITY_FENCED', 'Ownership notices cannot be projected', 503); }

/** Read committed authority decisions, never pending ceremony state or caller-supplied notice metadata. */
export async function readOwnershipNotices(control: pg.PoolClient, workspaceId: string,
  afterVersion: string, throughVersion: string): Promise<OwnershipNotice[]> {
  const rows = (await control.query<JournalRow>(`SELECT operation_id,sequence,previous_head,head,signed_transition
    FROM security.security_transitions WHERE workspace_id=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence`,
  [workspaceId, afterVersion, throughVersion])).rows;
  const result: OwnershipNotice[] = [];
  for (const row of rows) {
    const purpose = (row.signed_transition as { body?: { purpose?: string } } | null)?.body?.purpose;
    let notice: OwnershipNotice | undefined, publicKey: string, signed: SignedObject<{ purpose: string }>, binding: { workspaceId: string; operationId: string; securityHead: string; nextSecurityVersion: string };
    try {
      if (purpose === 'ukda.profile-enrolment.v1' || purpose === 'ukda.owner-promotion.v1') {
        const transition = enrolmentTransition.parse(row.signed_transition), b = transition.body.transcript.binding;
        if (b.kind === 'join_member') continue;
        binding = b; publicKey = b.authorizer.device.signingPublicKey; signed = transition;
        notice = { operationId: b.operationId, actorId: b.authorizer.accountId, targetId: b.accountId,
          eventType: b.kind === 'join_owner' ? 'security.owner_added' : 'security.owner_promoted' };
      } else if (purpose === 'ukda.access-change.v1') {
        const transition = accessTransition.parse(row.signed_transition), b = transition.body.binding;
        if (!b.priorTarget.owner) continue;
        if (!['demote_owner', 'suspend', 'remove'].includes(b.action) || transition.body.plan.target.owner) unavailable();
        binding = b; publicKey = b.authorizer.device.signingPublicKey; signed = transition;
        notice = { operationId: b.operationId, actorId: b.authorizer.accountId, targetId: b.targetAccountId,
          eventType: b.action === 'demote_owner' ? 'security.owner_demoted' : b.action === 'suspend' ? 'security.owner_suspended' : 'security.owner_removed' };
      } else if (purpose === 'ukda.account-recovery.v1') {
        const transition = recoveryTransition.parse(row.signed_transition), b = transition.body.transcript.binding;
        if (!b.isOwner) continue;
        binding = b; publicKey = b.authorizer.kind === 'phrase' ? b.authorizer.recovery.signingPublicKey : b.authorizer.device.signingPublicKey; signed = transition;
        notice = { operationId: b.operationId, actorId: b.authorizer.accountId, targetId: b.accountId, eventType: 'security.owner_recovered' };
      } else continue;
      // Services already validate the historical signing authority at commit. These
      // checks bind classification to those immutable signed bytes and journal row.
      if (binding.workspaceId !== workspaceId || binding.operationId !== row.operation_id || binding.nextSecurityVersion !== row.sequence ||
        binding.securityHead !== row.previous_head || await digestObject(row.signed_transition) !== row.head ||
        !await verifyObject(signed, base64urlDecode(publicKey, 32), purpose)) unavailable();
      result.push(notice);
    } catch { unavailable(); }
  }
  return result;
}

function noticeId(workspaceId: string, operationId: string, recipientId: string): string {
  const bytes = createHash('sha256').update(JSON.stringify(['ukda.ownership-notice.v1', workspaceId, operationId, recipientId])).digest().subarray(0, 16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x80; bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex'); return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Caller holds the projection transaction; recipient RLS and idempotency remain enforced. */
export async function projectOwnershipNotices(application: pg.PoolClient, workspaceId: string,
  notices: readonly OwnershipNotice[], activeOwnerIds: readonly string[]): Promise<void> {
  try {
    for (const recipientId of [...new Set(activeOwnerIds)].sort()) {
      await application.query("SELECT set_config('ukda.profile_id',$1,true)", [recipientId]);
      for (const notice of notices) {
        if (notice.actorId === recipientId || notice.targetId === recipientId) continue;
        await application.query(`INSERT INTO app.notifications(workspace_id,id,recipient_profile_id,event_id,event_type,record_id)
          VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(workspace_id,recipient_profile_id,event_id) DO NOTHING`,
        [workspaceId, noticeId(workspaceId, notice.operationId, recipientId), recipientId, notice.operationId, notice.eventType, notice.targetId]);
      }
    }
  } finally { await application.query("SELECT set_config('ukda.profile_id','',true)"); }
}

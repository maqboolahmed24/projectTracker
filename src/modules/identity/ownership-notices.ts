import { createHash } from 'node:crypto';
import type pg from 'pg';
import { AppError } from '../../errors.js';
import { accessTransition } from '../../shared/access-change.js';
import { enrolmentTransition } from '../../shared/enrolment.js';
import { recoveryTransition } from '../../shared/recovery.js';
import { roleTransition } from '../../shared/roles.js';
import { lifecycleMutation } from '../../shared/lifecycle.js';
import { base64urlDecode, digestObject, verifyObject, type SignedObject } from '../../shared/crypto.js';

export interface OwnershipNotice {
  operationId: string; actorId: string; targetId: string;
  affectedProfileIds?: string[];
  eventType: 'security.owner_added' | 'security.owner_promoted' | 'security.owner_demoted' |
    'security.owner_suspended' | 'security.owner_removed' | 'security.owner_recovered' |
    'security.member_added' | 'security.access_changed' | 'security.member_suspended' |
    'security.member_removed' | 'security.member_reactivated' | 'security.member_recovered' | 'security.role_changed' |
    'security.deletion_requested'|'security.deletion_cancelled'|'security.erasure_requested';
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
      if(purpose==='ukda.workspace-lifecycle.v1'){
        const transition=lifecycleMutation.parse(row.signed_transition),b=transition.body.binding;
        binding=b;publicKey=b.signingPublicKey;signed=transition;
        notice={operationId:b.operationId,actorId:b.accountId,targetId:b.action==='request_erasure'?b.accountId:workspaceId,
          eventType:b.action==='request_deletion'?'security.deletion_requested':b.action==='cancel_deletion'?'security.deletion_cancelled':'security.erasure_requested'};
      } else if (purpose === 'ukda.profile-enrolment.v1' || purpose === 'ukda.owner-promotion.v1') {
        const transition = enrolmentTransition.parse(row.signed_transition), b = transition.body.transcript.binding;
        binding = b; publicKey = b.authorizer.device.signingPublicKey; signed = transition;
        notice = { operationId: b.operationId, actorId: b.authorizer.accountId, targetId: b.accountId,
          eventType: b.kind === 'join_member' ? 'security.member_added' : b.kind === 'join_owner' ? 'security.owner_added' : 'security.owner_promoted' };
      } else if (purpose === 'ukda.access-change.v1') {
        const transition = accessTransition.parse(row.signed_transition), b = transition.body.binding;
        if (b.priorTarget.owner && (!['demote_owner', 'suspend', 'remove'].includes(b.action) || transition.body.plan.target.owner)) unavailable();
        binding = b; publicKey = b.authorizer.device.signingPublicKey; signed = transition;
        notice = { operationId: b.operationId, actorId: b.authorizer.accountId, targetId: b.targetAccountId,
          eventType: b.priorTarget.owner ? (b.action === 'demote_owner' ? 'security.owner_demoted' : b.action === 'suspend' ? 'security.owner_suspended' : 'security.owner_removed') :
            b.action === 'suspend' ? 'security.member_suspended' : b.action === 'remove' ? 'security.member_removed' :
            b.action === 'reactivate_member' ? 'security.member_reactivated' : 'security.access_changed' };
      } else if (purpose === 'ukda.custom-role-definition.v1') {
        const transition=roleTransition.parse(row.signed_transition),b=transition.body.binding;
        if(b.action!=='update'||canonicalPermissions(b.previous!.permissions)===canonicalPermissions(transition.body.role.permissions))continue;
        binding=b;publicKey=b.authorizer.device.signingPublicKey;signed=transition;
        const affected=(await control.query<{profile_id:string}>(`SELECT DISTINCT p.profile_id FROM security.profiles p
          LEFT JOIN security.grants g ON g.workspace_id=p.workspace_id AND g.profile_id=p.profile_id AND g.device_id IS NULL
            AND g.state='active' AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>statement_timestamp())
          LEFT JOIN security.staged_objects o ON o.workspace_id=g.workspace_id AND o.object_id=g.signed_grant_object_id AND o.state='committed'
          WHERE p.workspace_id=$1 AND p.state='active' AND (p.role_id=$2 OR g.role_id=$2 OR
            (p.role_id IS NULL AND g.grant_kind='membership' AND o.versioned_object->'body'->'transcript'->'binding'->'role'->>'id'=$2::text))`,[workspaceId,b.roleId])).rows.map(row=>row.profile_id);
        notice={operationId:b.operationId,actorId:b.authorizer.accountId,targetId:b.roleId,affectedProfileIds:affected,eventType:'security.role_changed'};
      } else if (purpose === 'ukda.account-recovery.v1') {
        const transition = recoveryTransition.parse(row.signed_transition), b = transition.body.transcript.binding;
        binding = b; publicKey = b.authorizer.kind === 'phrase' ? b.authorizer.recovery.signingPublicKey : b.authorizer.device.signingPublicKey; signed = transition;
        notice = { operationId: b.operationId, actorId: b.authorizer.accountId, targetId: b.accountId,
          eventType: b.isOwner ? 'security.owner_recovered' : 'security.member_recovered' };
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
function canonicalPermissions(permissions:readonly string[]){return JSON.stringify([...permissions].sort());}

/** Caller holds the projection transaction; recipient RLS and idempotency remain enforced. */
export async function projectOwnershipNotices(application: pg.PoolClient, workspaceId: string,
  notices: readonly OwnershipNotice[], activeOwnerIds: readonly string[], activeProfileIds: readonly string[]): Promise<void> {
  try {
    const active=new Set(activeProfileIds);
    for (const notice of notices) for (const recipientId of [...new Set([...activeOwnerIds,...(notice.affectedProfileIds??[notice.targetId])])].filter(id=>active.has(id)).sort()) {
      await application.query("SELECT set_config('ukda.profile_id',$1,true)", [recipientId]);
        // Security notices include the affected active person and all active Owners,
        // including the actor; project mute never suppresses them.
        await application.query(`INSERT INTO app.notifications(workspace_id,id,recipient_profile_id,event_id,event_type,record_id)
          VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(workspace_id,recipient_profile_id,event_id) DO NOTHING`,
        [workspaceId, noticeId(workspaceId, notice.operationId, recipientId), recipientId, notice.operationId, notice.eventType, notice.targetId]);
    }
  } finally { await application.query("SELECT set_config('ukda.profile_id','',true)"); }
}

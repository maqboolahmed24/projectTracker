import type pg from 'pg';
import { AppError } from '../../errors.js';
import { contentEnvelope, type ContentEnvelope } from '../../shared/contracts.js';
import { digestObject } from '../../shared/crypto.js';
import { upgradeRecordRef, type UpgradeRecordRef } from '../../shared/encrypted-upgrades.js';
import { UPGRADE_MAX_MANIFEST_RECORDS } from '../../shared/upgrade-api.js';

export interface CurrentUpgradeRecord { reference: UpgradeRecordRef; envelope: ContentEnvelope }
export const upgradeTables = { workspace:'workspaces',profile:'profiles',role:'roles',team:'teams',project:'projects',phase:'project_phases',
  milestone:'milestones',task:'tasks',blocker:'blockers',comment:'comments',update:'updates' } as const;
export const upgradeRecordKey = (r: Pick<UpgradeRecordRef,'kind'|'id'>) => `${r.kind}:${r.id}`;

/** One SQL statement provides one complete MVCC view. History, audits, receipts,
 * custody and disposable derived summaries are not mutable business content. */
export async function readCurrentUpgradeRecords(application: pg.PoolClient, workspaceId: string, control?:pg.PoolClient): Promise<CurrentUpgradeRecord[]> {
  const select = Object.entries(upgradeTables).map(([kind,table]) => {
    const project = ['project','phase','milestone','task','blocker','comment','update'].includes(kind);
    return `SELECT '${kind}'::text AS kind,${kind==='workspace'?'workspace_id':'id'} AS id,
      ${project?(kind==='project'?'id':'project_id'):'NULL::uuid'} AS project_id,revision,
      ${kind==='task'||kind==='blocker'?'content_revision':'NULL::bigint'} AS content_revision,encrypted_envelope
      FROM app.${table} WHERE workspace_id=$1 AND encrypted_envelope ? 'header'`;
  });
  const rows=(await application.query(`SELECT * FROM (${select.join(' UNION ALL ')}) current_records ORDER BY kind,id LIMIT $2`,
    [workspaceId,UPGRADE_MAX_MANIFEST_RECORDS+1])).rows;
  if(rows.length>UPGRADE_MAX_MANIFEST_RECORDS)throw new AppError('UPGRADE_TOO_LARGE','The complete upgrade manifest exceeds this release limit',413);
  const records:CurrentUpgradeRecord[]=[];
  for(const row of rows){
    const envelope=contentEnvelope.parse(row.encrypted_envelope),h=envelope.header;
    if(h.workspaceId!==workspaceId||h.recordType!==row.kind||h.recordId!==row.id||h.scopeId!==(row.project_id??workspaceId))
      throw new AppError('UPGRADE_CHANGED','Current encrypted content does not match its authoritative record',409);
    records.push({reference:upgradeRecordRef.parse({kind:row.kind,id:row.id,projectId:row.project_id,revision:row.kind==='workspace'?h.revision:row.revision,
      contentRevision:row.content_revision,envelopeRevision:h.revision,schema:h.schema,keyEpoch:h.keyEpoch,digest:await digestObject(envelope)}),envelope});
  }
  // Invitations commit encrypted pending labels in the authority store before a
  // security transition requires an application projection. The upgrade caller
  // holds that workspace's control row lock, also used by invitation rotation and
  // enrolment. Include this exact content without creating account authority.
  if(control){
    const pending=(await control.query(`SELECT p.profile_id,o.versioned_object,o.object_hash
      FROM security.profiles p JOIN security.staged_objects o ON o.workspace_id=p.workspace_id AND o.object_id=p.profile_object_id
      WHERE p.workspace_id=$1 AND p.state='pending' AND o.object_kind='encrypted_profile' AND o.state='committed'
      ORDER BY p.profile_id LIMIT $2`,[workspaceId,UPGRADE_MAX_MANIFEST_RECORDS+1])).rows;
    for(const row of pending){
      const envelope=contentEnvelope.parse(row.versioned_object),h=envelope.header,hash=await digestObject(envelope);
      if(h.workspaceId!==workspaceId||h.scope!=='workspace'||h.scopeId!==workspaceId||h.recordType!=='profile'||h.recordId!==row.profile_id||hash!==row.object_hash)
        throw new AppError('UPGRADE_CHANGED','Pending encrypted profile does not match its authoritative reference',409);
      const record={reference:upgradeRecordRef.parse({kind:'profile',id:row.profile_id,projectId:null,revision:h.revision,contentRevision:null,
        envelopeRevision:h.revision,schema:h.schema,keyEpoch:h.keyEpoch,digest:hash}),envelope};
      const index=records.findIndex(current=>current.reference.kind==='profile'&&current.reference.id===row.profile_id);
      if(index<0)records.push(record);else records[index]=record;
    }
  }
  if(records.length>UPGRADE_MAX_MANIFEST_RECORDS)throw new AppError('UPGRADE_TOO_LARGE','The complete upgrade manifest exceeds this release limit',413);
  return records.sort((left,right)=>upgradeRecordKey(left.reference)<upgradeRecordKey(right.reference)?-1:upgradeRecordKey(left.reference)>upgradeRecordKey(right.reference)?1:0);
}

import { z } from 'zod';
import { binary, contentEnvelope, counter, digest, identifier, pageQuery, positiveCounter } from './contracts.js';
import { base64urlDecode, digestObject, verifyContentEnvelope, verifyObject, type ContentHeader } from './crypto.js';
import { upgradeItem, upgradeProof, validateUpgradeItems, verifyUpgradeItem } from './encrypted-upgrades.js';

export const teamContent = z.strictObject({ name: z.string().trim().min(1).max(200), description: z.string().max(10000).default('') });
export const teamReference = z.strictObject({ workspaceId: identifier, teamId: identifier, operationId: identifier });
const legacyTeamRequest = teamReference.extend({ action: z.enum(['create', 'update']) });
export const teamContextRequest = teamReference.extend({ action: z.enum(['create', 'update', 'upgrade_content']) });
export const teamMembers = z.array(identifier).max(4096).refine((ids) => new Set(ids).size === ids.length);
export const teamBindingV1 = legacyTeamRequest.extend({ expectedRevision: counter, previousDigest: digest.nullable(),
  previousMemberIds: teamMembers, securityHead: digest, securityVersion: positiveCounter, dataGeneration: positiveCounter,
  keyEpoch: positiveCounter, authorizer: z.strictObject({ accountId: identifier, deviceId: identifier,
    keyGeneration: positiveCounter, signingPublicKey: binary(32) }) });
// Keep v1 byte-for-byte compatible: old signatures did not bind a timestamp.
export const teamBindingV2 = teamBindingV1.extend({ version: z.literal(2), issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime() });
export const teamBindingV3 = teamBindingV2.extend({ version: z.literal(3), action: teamContextRequest.shape.action, writeSchema: z.union([z.literal(1),z.literal(2)]) });
export const teamBinding = z.union([teamBindingV1, teamBindingV2, teamBindingV3]);
export type TeamBinding = z.infer<typeof teamBinding>;
const teamMutationV1 = z.strictObject({ body: z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.team-change.v1'),
  binding: teamBindingV1, memberIds: teamMembers, contentDigest: digest }), signature: binary(64) });
const teamMutationV2 = z.strictObject({ body: z.strictObject({ version: z.literal(2), purpose: z.literal('ukda.team-change.v2'),
  binding: teamBindingV2, memberIds: teamMembers, contentDigest: digest }), signature: binary(64) });
const teamMutationV3 = z.strictObject({ body: z.strictObject({ version:z.literal(3),purpose:z.literal('ukda.team-change.v3'),binding:teamBindingV3,
  memberIds:teamMembers,contentDigest:digest,upgrade:upgradeProof.optional() }),signature:binary(64) });
export const teamMutation = z.union([teamMutationV1, teamMutationV2, teamMutationV3]);
export function teamMutationBody(binding: TeamBinding, memberIds: string[], contentDigest: string) {
  return 'version' in binding && binding.version===3 ? { version:3 as const,purpose:'ukda.team-change.v3' as const,binding,memberIds,contentDigest }
    : 'version' in binding ? { version: 2 as const, purpose: 'ukda.team-change.v2' as const, binding, memberIds, contentDigest }
    : { version: 1 as const, purpose: 'ukda.team-change.v1' as const, binding, memberIds, contentDigest };
}
export const teamPayload = z.strictObject({ mutation: teamMutation, envelope: contentEnvelope, upgradeItems:z.array(upgradeItem).length(1).optional() });
export type TeamPayload = z.infer<typeof teamPayload>;
export const teamContext = z.strictObject({ binding: teamBinding, previous: contentEnvelope.nullable(), previousSignedChange: teamPayload.nullable() });
export type TeamContext = z.infer<typeof teamContext>;
export const teamListRequest = z.strictObject({ workspaceId: identifier, ...pageQuery.shape });
export const teamReceipt = z.strictObject({ version: z.literal(1), workspaceId: identifier, operationId: identifier,
  teamId: identifier, actorId: identifier, revision: positiveCounter, dataGeneration: positiveCounter, requestHash: digest });
export type TeamReceipt = z.infer<typeof teamReceipt>;
export const teamHistoryAnchor = z.strictObject({ revision: positiveCounter, digest });
export const teamHistoryRequest = z.strictObject({ workspaceId: identifier, teamId: identifier,
  afterRevision: counter.default('0'), anchor: teamHistoryAnchor.optional(), limit: z.number().int().min(1).max(100).default(50) })
  .refine((value) => value.afterRevision === '0' || value.anchor !== undefined);
export type TeamHistoryRequest = z.infer<typeof teamHistoryRequest>;
export const teamHistoryPage = z.strictObject({ workspaceId: identifier, teamId: identifier, securityHead: digest,
  securityVersion: positiveCounter, dataGeneration: positiveCounter, anchor: teamHistoryAnchor,
  records: z.array(z.strictObject({ payload: teamPayload, recordedAt: z.iso.datetime() })).min(1).max(100),
  nextRevision: positiveCounter.nullable(), complete: z.boolean() });
export type TeamHistoryPage = z.infer<typeof teamHistoryPage>;
export const TEAM_HISTORY_MAX_BYTES = 8 * 1024 * 1024;

export function teamHeader(binding: TeamBinding): ContentHeader {
  const b = teamBinding.parse(binding);
  return { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: b.workspaceId,
    scope: 'workspace', scopeId: b.workspaceId, recordType: 'team', recordId: b.teamId, schema: 'version' in b && b.version===3 ? (b.action==='upgrade_content'?2:b.writeSchema) : 1, keyEpoch: b.keyEpoch,
    revision: String(BigInt(b.expectedRevision) + 1n), operationId: b.operationId, accountId: b.authorizer.accountId,
    deviceId: b.authorizer.deviceId, keyGeneration: b.authorizer.keyGeneration, permissionVersion: b.securityVersion,
    securityVersion: b.securityVersion, securityHead: b.securityHead, dataGeneration: b.dataGeneration,
    action: `teams.${b.action}`, approvalPolicyId: null, approvalPolicyRevision: null };
}

/** Signed membership metadata and ciphertext belong to one immutable business operation. */
export async function validateTeamPayload(value: unknown): Promise<TeamPayload> {
  const payload = teamPayload.parse(value), b = payload.mutation.body.binding, key = base64urlDecode(b.authorizer.signingPublicKey, 32);
  if ('version' in b && (Date.parse(b.expiresAt) <= Date.parse(b.issuedAt) ||
    Date.parse(b.expiresAt) - Date.parse(b.issuedAt) > 600_000)) throw new Error('Invalid signed team timestamp');
  if ((b.action === 'create') !== (b.expectedRevision === '0') || (b.expectedRevision === '0') !== (b.previousDigest === null) ||
    b.action === 'create' && b.previousMemberIds.length !== 0 ||
    payload.mutation.body.contentDigest !== await digestObject(payload.envelope) ||
    !await verifyObject<TeamPayload['mutation']['body']>(payload.mutation, key, payload.mutation.body.purpose) ||
    !await verifyContentEnvelope(payload.envelope, key, teamHeader(b))) throw new Error('Invalid signed team change');
  const body=payload.mutation.body;
  if(b.action==='upgrade_content') {
    if(body.version!==3||!body.upgrade||!payload.upgradeItems||body.memberIds.length!==b.previousMemberIds.length||
      [...body.memberIds].sort().some((id,i)=>id!==[...b.previousMemberIds].sort()[i])) throw new Error('Invalid team upgrade');
    const {items}=await validateUpgradeItems(body.upgrade,payload.upgradeItems),item=items[0]!;
    if(items.length!==1||item.source.kind!=='team'||item.source.id!==b.teamId||item.source.projectId!==null||
      item.source.revision!==b.expectedRevision||item.source.digest!==b.previousDigest||item.target.digest!==body.contentDigest) throw new Error('Changed team upgrade source');
    await verifyUpgradeItem(item,item.sourceEnvelope,teamHeader(b),key);
  } else if(payload.upgradeItems||body.version===3&&body.upgrade) throw new Error('Unexpected team upgrade');
  return payload;
}

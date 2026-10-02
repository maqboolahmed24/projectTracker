import { z } from 'zod';
import { binary, contentEnvelope, digest, identifier, positiveCounter, type ContentEnvelope } from './contracts.js';
import { CONTENT_TRANSFORM_1_TO_2 } from './content-schema.js';
import { base64urlDecode, canonicalJson, digestObject, verifyContentEnvelope, verifyObject, type ContentHeader } from './crypto.js';
import type { SecurityHistoryState } from './security-history.js';

export const UPGRADE_MAX_BATCH_RECORDS = 32;
export const upgradeRecordKind = z.enum(['workspace', 'profile', 'role', 'team', 'project', 'phase', 'milestone', 'task', 'blocker', 'comment', 'update']);
export const upgradeRecordRef = z.strictObject({
  kind: upgradeRecordKind, id: identifier, projectId: identifier.nullable(),
  revision: positiveCounter, contentRevision: positiveCounter.nullable(), envelopeRevision: positiveCounter,
  schema: z.union([z.literal(1), z.literal(2)]), keyEpoch: positiveCounter, digest,
}).refine(value => (['project', 'phase', 'milestone', 'task', 'blocker', 'comment', 'update'].includes(value.kind)) === (value.projectId !== null))
  .refine(value => value.kind !== 'project' || value.projectId === value.id)
  .refine(value => (value.kind === 'task' || value.kind === 'blocker') === (value.contentRevision !== null));
export type UpgradeRecordRef = z.infer<typeof upgradeRecordRef>;
export const upgradeItemRefs = z.strictObject({ source: upgradeRecordRef, target: upgradeRecordRef }).refine(({ source, target }) =>
  source.kind === target.kind && source.id === target.id && source.projectId === target.projectId && source.schema === 1 && target.schema === 2 &&
  BigInt(target.revision) === BigInt(source.revision) + 1n && target.envelopeRevision === target.revision && target.contentRevision === source.contentRevision);
export const upgradeItem = upgradeItemRefs.safeExtend({ sourceEnvelope: contentEnvelope, envelope: contentEnvelope });
export type UpgradeItem = z.infer<typeof upgradeItem>;
export const upgradeProof = z.strictObject({
  migrationId: identifier, transformId: z.literal(CONTENT_TRANSFORM_1_TO_2), sourceSchema: z.literal(1), targetSchema: z.literal(2),
  manifestDigest: digest, items: z.array(upgradeItemRefs).min(1).max(UPGRADE_MAX_BATCH_RECORDS),
}).refine(value => new Set(value.items.map(item => `${item.source.kind}:${item.source.id}`)).size === value.items.length);
export type UpgradeProof = z.infer<typeof upgradeProof>;

export const upgradeOwnerBinding = z.strictObject({ workspaceId:identifier,migrationId:identifier,operationId:identifier,origin:z.string().url(),
  accountId:identifier,deviceId:identifier,credentialGeneration:positiveCounter,sessionGeneration:positiveCounter,keyGeneration:positiveCounter,signingPublicKey:binary(32),
  securityVersion:positiveCounter,nextSecurityVersion:positiveCounter,securityHead:digest,dataGeneration:positiveCounter,
  ownershipVersion:positiveCounter,custodyEpoch:positiveCounter,workspaceKeyEpoch:positiveCounter,issuedAt:z.iso.datetime(),expiresAt:z.iso.datetime() });
export type UpgradeOwnerBinding = z.infer<typeof upgradeOwnerBinding>;
export function verifyUpgradeOwner(binding: UpgradeOwnerBinding, state: SecurityHistoryState): void {
  const person=state.profiles[binding.accountId],device=state.devices[binding.deviceId];
  const eligible=(scope:{scope:string;scopeId:string;mode:string;keyEpoch:string;permissions:string[];expiresAt:string|null})=>
    scope.scope==='workspace'&&scope.scopeId===state.workspaceId&&scope.mode==='custody'&&scope.keyEpoch===state.custodyEpoch&&
    scope.permissions.includes('read_project')&&scope.permissions.includes('plan_projects')&&(scope.expiresAt===null||Date.parse(scope.expiresAt)>Date.parse(binding.issuedAt));
  if (state.workspaceId!==binding.workspaceId||state.origin!==binding.origin||state.securityVersion!==binding.securityVersion||state.securityHead!==binding.securityHead||
    state.dataGeneration!==binding.dataGeneration||state.ownershipVersion!==binding.ownershipVersion||state.custodyEpoch!==binding.custodyEpoch||state.workspaceKeyEpoch!==binding.workspaceKeyEpoch||
    state.licenceState!=='active'||state.entitlementState!=='activated'||!person?.active||!person.owner||!device?.active||device.accountId!==person.accountId||
    person.credentialGeneration!==binding.credentialGeneration||person.sessionGeneration!==binding.sessionGeneration||device.keyGeneration!==binding.keyGeneration||device.signingPublicKey!==binding.signingPublicKey||
    !person.scopes.some(eligible)||!device.scopes.some(eligible)||BigInt(binding.nextSecurityVersion)!==BigInt(binding.securityVersion)+1n||
    Date.parse(binding.expiresAt)<=Date.parse(binding.issuedAt)||Date.parse(binding.expiresAt)-Date.parse(binding.issuedAt)>600_000) throw new Error('Invalid current upgrade Owner');
}
const identityObjectRef=z.strictObject({kind:z.enum(['workspace','profile','role']),recordId:identifier,id:identifier,digest});
export const identityUpgradeTransition=z.strictObject({body:z.strictObject({purpose:z.literal('ukda.identity-content-upgrade.v1'),binding:upgradeOwnerBinding,
  upgrade:upgradeProof,objects:z.array(identityObjectRef).min(1).max(UPGRADE_MAX_BATCH_RECORDS)}),signature:binary(64)});
export const identityUpgradePayload=z.strictObject({mutation:identityUpgradeTransition,upgradeItems:z.array(upgradeItem).min(1).max(UPGRADE_MAX_BATCH_RECORDS)});
export type IdentityUpgradePayload=z.infer<typeof identityUpgradePayload>;
export const identityUpgradeHistory=identityUpgradeTransition.extend({upgradeItems:z.array(upgradeItem).min(1).max(UPGRADE_MAX_BATCH_RECORDS)});
export function identityUpgradeHeader(binding:UpgradeOwnerBinding,ref:UpgradeRecordRef):ContentHeader {
  return {version:1,purpose:'ukda.content.v1',algorithm:'XChaCha20-Poly1305',workspaceId:binding.workspaceId,scope:'workspace',scopeId:binding.workspaceId,
    recordType:ref.kind,recordId:ref.id,schema:2,keyEpoch:binding.workspaceKeyEpoch,revision:ref.envelopeRevision,operationId:binding.operationId,
    accountId:binding.accountId,deviceId:binding.deviceId,keyGeneration:binding.keyGeneration,permissionVersion:binding.securityVersion,
    securityVersion:binding.securityVersion,securityHead:binding.securityHead,dataGeneration:binding.dataGeneration,action:'identity.upgrade_content',approvalPolicyId:null,approvalPolicyRevision:null};
}
export async function validateIdentityUpgrade(value:unknown,state:SecurityHistoryState):Promise<IdentityUpgradePayload> {
  const payload=identityUpgradePayload.parse(value),body=payload.mutation.body,b=body.binding;
  verifyUpgradeOwner(b,state);
  if (body.upgrade.migrationId!==b.migrationId||!await verifyObject(payload.mutation,base64urlDecode(b.signingPublicKey,32),body.purpose)) throw new Error('Invalid identity upgrade signature');
  const {items}=await validateUpgradeItems(body.upgrade,payload.upgradeItems);
  if (items.length!==body.objects.length||new Set(body.objects.map(object=>object.id)).size!==items.length) throw new Error('Incomplete identity upgrade objects');
  for (const item of items) {
    const object=body.objects.find(object=>object.kind===item.target.kind&&object.recordId===item.target.id);
    if (!object||object.id===b.operationId||object.digest!==item.target.digest||item.target.projectId!==null||item.target.keyEpoch!==b.workspaceKeyEpoch) throw new Error('Invalid identity upgrade object');
    await verifyUpgradeItem(item,item.sourceEnvelope,identityUpgradeHeader(b,item.target),base64urlDecode(b.signingPublicKey,32));
  }
  return payload;
}
export async function applyIdentityUpgradeHistory(value:unknown,state:SecurityHistoryState):Promise<z.infer<typeof identityUpgradeHistory>> {
  const history=identityUpgradeHistory.parse(value),payload=await validateIdentityUpgrade({mutation:{body:history.body,signature:history.signature},upgradeItems:history.upgradeItems},state),body=payload.mutation.body;
  if (!state.activeUpgrade||state.activeUpgrade.migrationId!==body.upgrade.migrationId||state.activeUpgrade.manifestDigest!==body.upgrade.manifestDigest) throw new Error('Identity upgrade outside active migration');
  for (const item of payload.upgradeItems) {
    const ref=item.source,object=body.objects.find(object=>object.kind===ref.kind&&object.recordId===ref.id)!;
    if (!state.activeUpgrade.manifest.some(source=>source.kind===ref.kind&&source.id===ref.id)) throw new Error('Identity upgrade outside source manifest');
    if (ref.kind==='workspace') {
      if (ref.id!==state.workspaceId||state.workspaceContent?.digest!==ref.digest||state.workspaceContent.revision!==ref.revision) throw new Error('Changed workspace upgrade source');
      state.workspaceContent={objectId:object.id,digest:object.digest,revision:item.target.revision};
    } else if (ref.kind==='profile') {
      const profile=state.profiles[ref.id];
      if (profile) {
        if (profile.profile.objectDigest!==ref.digest||profile.profile.revision!==ref.revision) throw new Error('Changed profile upgrade source');
        profile.profile={...profile.profile,objectId:object.id,objectDigest:object.digest,revision:item.target.revision};
      } else {
        const pending=state.pendingProfileContent?.[ref.id], original=state.activeUpgrade.manifest.find(source=>source.kind==='profile'&&source.id===ref.id);
        if (pending ? pending.digest!==ref.digest||pending.revision!==ref.revision : !original||canonicalJson(original)!==canonicalJson(ref)) throw new Error('Changed pending profile upgrade source');
        state.pendingProfileContent ??= {};
        state.pendingProfileContent[ref.id]={objectId:object.id,digest:object.digest,revision:item.target.revision};
      }
    } else if (ref.kind==='role') {
      const role=state.roles[ref.id];
      if (!role||role.template!=='custom'||role.revision!==ref.revision||role.label?.digest!==ref.digest) throw new Error('Changed role upgrade source');
      role.revision=item.target.revision;role.label={id:object.id,revision:item.target.revision,digest:object.digest};
    } else throw new Error('Invalid identity upgrade kind');
  }
  return history;
}

/** Outer native mutation signatures bind this proof; items are never unsigned replacement authority. */
export async function validateUpgradeItems(value: unknown, itemValues: unknown): Promise<{ proof: UpgradeProof; items: UpgradeItem[] }> {
  const proof = upgradeProof.parse(value), items = z.array(upgradeItem).min(1).max(UPGRADE_MAX_BATCH_RECORDS).parse(itemValues);
  if (canonicalJson(proof.items) !== canonicalJson(items.map(({ source, target }) => ({ source, target })))) throw new Error('Upgrade items do not match signed proof');
  for (const item of items) {
    const header = item.envelope.header, ref = item.target;
    if (header.recordType !== ref.kind || header.recordId !== ref.id || header.schema !== 2 || header.keyEpoch !== ref.keyEpoch ||
      header.revision !== ref.envelopeRevision || header.scope !== (ref.projectId === null ? 'workspace' : 'project') ||
      header.scopeId !== (ref.projectId ?? header.workspaceId) || await digestObject(item.envelope) !== ref.digest) throw new Error('Invalid upgrade ciphertext reference');
    if (item.sourceEnvelope.header.schema !== 1 || await digestObject(item.sourceEnvelope) !== item.source.digest) throw new Error('Invalid upgrade source ciphertext');
  }
  return { proof, items };
}

/** Exact current source and the native mutation's expected target header are both required. */
export async function verifyUpgradeItem(itemValue: unknown, sourceEnvelope: ContentEnvelope, expectedHeader: ContentHeader,
  signingPublicKey: Uint8Array): Promise<UpgradeItem> {
  const item = upgradeItem.parse(itemValue), source = item.source, h = sourceEnvelope.header;
  if (h.workspaceId !== expectedHeader.workspaceId || h.recordType !== source.kind || h.recordId !== source.id || h.schema !== source.schema ||
    h.revision !== source.envelopeRevision || h.keyEpoch !== source.keyEpoch || await digestObject(sourceEnvelope) !== source.digest ||
    expectedHeader.schema !== 2 || expectedHeader.recordType !== item.target.kind || expectedHeader.recordId !== item.target.id ||
    expectedHeader.revision !== item.target.envelopeRevision || expectedHeader.keyEpoch !== item.target.keyEpoch ||
    await digestObject(item.envelope) !== item.target.digest || !await verifyContentEnvelope(item.envelope, signingPublicKey, expectedHeader)) {
    throw new Error('Invalid authenticated content upgrade');
  }
  return item;
}

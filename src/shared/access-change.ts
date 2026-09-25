import { z } from 'zod';
import { binary, capabilities, contentEnvelope, digest, identifier, positiveCounter, counter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, recipientEnvelope, verifyContentEnvelope, verifyObject, verifyRecipientEnvelope, type ContentHeader, type RecipientHeader } from './crypto.js';
import { pairingPublicDevice } from './pairing.js';
import { customRolePermissions } from './permissions.js';
import type { SecurityHistoryState, HistoryProfile, HistoryScope } from './security-history.js';

export const accessRole = z.strictObject({ id: identifier, revision: positiveCounter });
const profileReference = z.strictObject({ id: identifier, revision: positiveCounter, objectId: identifier, objectDigest: digest });
export const accessScope = z.strictObject({ scope: z.enum(['workspace', 'project']), scopeId: identifier, mode: z.enum(['content', 'custody']),
  keyEpoch: positiveCounter, permissions: customRolePermissions, expiresAt: z.iso.datetime().nullable() });
export type AccessScope = z.infer<typeof accessScope>;
export const accessReference = z.strictObject({ workspaceId: identifier, operationId: identifier });
export type AccessReference = z.infer<typeof accessReference>;
export const accessRequest = accessReference.extend({ action: z.enum(['set_access', 'demote_owner', 'suspend', 'remove', 'reactivate_member']),
  targetAccountId: identifier, desired: z.strictObject({ roleId: identifier, projectIds: z.array(identifier).max(255) }).nullable(), receiptTokenHash: digest })
  .refine((v) => ['set_access', 'demote_owner', 'reactivate_member'].includes(v.action) === (v.desired !== null) &&
    (!v.desired || new Set(v.desired.projectIds).size === v.desired.projectIds.length));
export type AccessRequest = z.infer<typeof accessRequest>;
const authorizer = z.strictObject({ accountId: identifier, device: pairingPublicDevice, credentialGeneration: positiveCounter, sessionGeneration: positiveCounter });
export const accessPriorTarget = z.strictObject({ state: z.enum(['active', 'suspended', 'removed']), owner: z.boolean(),
  credentialGeneration: positiveCounter, sessionGeneration: positiveCounter, recoveryGeneration: counter,
  role: accessRole, projectRoles: z.record(identifier, accessRole), profile: profileReference });
export const accessBinding = z.strictObject({ ...accessRequest.shape, version: z.literal(1), origin: z.string().max(256), authorizer,
  priorTarget: accessPriorTarget, securityVersion: positiveCounter, nextSecurityVersion: positiveCounter, securityHead: digest,
  dataGeneration: positiveCounter, ownershipVersion: positiveCounter, custodyEpoch: positiveCounter, workspaceKeyEpoch: positiveCounter,
  genesisFingerprint: digest, issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime() })
  .refine((v) => accessRequest.safeParse({ workspaceId: v.workspaceId, operationId: v.operationId, action: v.action,
    targetAccountId: v.targetAccountId, desired: v.desired, receiptTokenHash: v.receiptTokenHash }).success &&
    positiveCounter.safeParse(v.securityVersion).success && positiveCounter.safeParse(v.nextSecurityVersion).success &&
    BigInt(v.nextSecurityVersion) === BigInt(v.securityVersion) + 1n && Date.parse(v.expiresAt) > Date.parse(v.issuedAt) &&
    Date.parse(v.expiresAt) - Date.parse(v.issuedAt) <= 600_000);
export type AccessBinding = z.infer<typeof accessBinding>;
export const accessRecipient = z.strictObject({ accountId: identifier, kind: z.enum(['device', 'recovery']), id: identifier,
  keyGeneration: positiveCounter, signingPublicKey: binary(32), recipientPublicKey: binary(32), scope: accessScope });
export type AccessRecipient = z.infer<typeof accessRecipient>;
export const accessPlan = z.strictObject({ version: z.literal(1), target: z.strictObject({ accountId: identifier,
  state: z.enum(['active', 'suspended', 'removed']), owner: z.boolean(), role: accessRole, projectRoles: z.record(identifier, accessRole),
  credentialGeneration: positiveCounter, sessionGeneration: positiveCounter, recoveryGeneration: counter, profileRevision: positiveCounter }),
  nextOwnershipVersion: positiveCounter, nextCustodyEpoch: positiveCounter, nextWorkspaceKeyEpoch: positiveCounter, rotateCustody: z.boolean(),
  rotations: z.array(z.strictObject({ scope: z.enum(['workspace', 'project']), scopeId: identifier, previousEpoch: positiveCounter, nextEpoch: positiveCounter })).max(256),
  profiles: z.array(z.strictObject({ accountId: identifier, role: accessRole, projectRoles: z.record(identifier, accessRole), scopes: z.array(accessScope).max(256) })).max(4096),
  devices: z.array(z.strictObject({ accountId: identifier, device: pairingPublicDevice, active: z.boolean(), scopes: z.array(accessScope).max(256) })).max(8192),
  recipients: z.array(accessRecipient).max(8192) });
export type AccessPlan = z.infer<typeof accessPlan>;
const objectReference = z.strictObject({ id: identifier, digest, revision: positiveCounter });
const deliveryDescriptor = z.strictObject({ id: identifier, digest, recipient: accessRecipient });
export const accessTransition = z.strictObject({ body: z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.access-change.v1'),
  binding: accessBinding, plan: accessPlan, transcriptDigest: digest, custody: objectReference.nullable(), profile: objectReference.nullable(),
  deliveries: z.array(deliveryDescriptor).max(8192) }), signature: binary(64) });
export type AccessTransition = z.infer<typeof accessTransition>;
const contentObject = z.strictObject({ id: identifier, envelope: contentEnvelope });
export const accessPayload = z.strictObject({ transition: accessTransition, custody: contentObject.nullable(), profile: contentObject.nullable(),
  deliveries: z.array(z.strictObject({ id: identifier, envelope: recipientEnvelope })).max(8192) });
export type AccessPayload = z.infer<typeof accessPayload>;
const material = z.strictObject({ id: identifier, digest, kind: z.string().max(64), value: z.unknown() });
export const accessContext = z.strictObject({ binding: accessBinding, plan: accessPlan, materials: z.array(material).max(16384) });
export type AccessContext = z.infer<typeof accessContext>;
export const accessReceipt = z.strictObject({ version: z.literal(1), workspaceId: identifier, operationId: identifier, targetAccountId: identifier,
  securityVersion: positiveCounter, securityHead: digest, requestHash: digest, committedAt: z.iso.datetime(), transition: accessTransition });
export type AccessReceipt = z.infer<typeof accessReceipt>;
export const accessView = z.strictObject({ state: z.enum(['absent', 'staged', 'completed', 'finishing', 'expired']), requestHash: digest.nullable(), receipt: accessReceipt.nullable() });
export type AccessView = z.infer<typeof accessView>;
export const accessFinalize = accessReference.extend({ requestHash: digest, receiptToken: binary(32) });
export const accessStatus = accessReference.extend({ receiptToken: binary(32).optional() });
export const accessDelivery = z.strictObject({ workspaceId: identifier, accountId: identifier, deviceId: identifier,
  current: z.strictObject({ securityHead: digest, securityVersion: positiveCounter }), materials: z.array(material).max(16384) });
export type AccessDelivery = z.infer<typeof accessDelivery>;
export class AccessContractError extends Error { constructor() { super('Invalid access change'); this.name = 'AccessContractError'; } }
function invalid(): never { throw new AccessContractError(); }
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const copy = <T>(v: T): T => JSON.parse(canonicalJson(v)) as T;
const next = (v: string) => String(BigInt(v) + 1n);
const key = (s: Pick<AccessScope, 'scope' | 'scopeId'>) => `${s.scope}:${s.scopeId}`;
const ordered = <T>(values: T[], id: (v: T) => string) => values.sort((a, b) => id(a).localeCompare(id(b), 'en'));
function policy(scope: HistoryScope): AccessScope { const { manifests: _manifests, ...p } = scope; return copy(p); }
function previous(profile: HistoryProfile): z.infer<typeof accessPriorTarget> {
  return { state: profile.state, owner: profile.owner, credentialGeneration: profile.credentialGeneration, sessionGeneration: profile.sessionGeneration,
    recoveryGeneration: profile.recoveryGeneration, role: copy(profile.role), projectRoles: copy(profile.projectRoles), profile: copy(profile.profile) };
}
export function createAccessBinding(requestValue: AccessRequest, state: SecurityHistoryState, actor: AccessBinding['authorizer'],
  times: { issuedAt: string; expiresAt: string }): AccessBinding {
  const request = accessRequest.parse(copy(requestValue)), target = state.profiles[request.targetAccountId]; if (!target) invalid();
  const result = accessBinding.parse({ ...request, version: 1, origin: state.origin, authorizer: actor, priorTarget: previous(target),
    securityVersion: state.securityVersion, nextSecurityVersion: next(state.securityVersion), securityHead: state.securityHead, dataGeneration: state.dataGeneration,
    ownershipVersion: state.ownershipVersion, custodyEpoch: state.custodyEpoch, workspaceKeyEpoch: state.workspaceKeyEpoch,
    genesisFingerprint: state.genesisFingerprint, ...times });
  deriveAccessPlan(result, state); return result;
}
/** One deterministic authority plan; no server-selected recipient or epoch is trusted. */
export function deriveAccessPlan(value: AccessBinding, state: SecurityHistoryState): AccessPlan {
  const b = accessBinding.parse(copy(value)), target = state.profiles[b.targetAccountId], owner = state.profiles[b.authorizer.accountId], signer = state.devices[b.authorizer.device.id];
  const live = (s: AccessScope) => s.expiresAt === null || Date.parse(s.expiresAt) > Date.parse(b.issuedAt);
  const custody = (s: AccessScope) => s.scope === 'workspace' && s.scopeId === b.workspaceId && s.mode === 'custody' && s.keyEpoch === state.custodyEpoch && live(s);
  if (b.origin !== state.origin || b.workspaceId !== state.workspaceId || b.genesisFingerprint !== state.genesisFingerprint ||
    b.securityHead !== state.securityHead || b.securityVersion !== state.securityVersion || b.dataGeneration !== state.dataGeneration ||
    b.ownershipVersion !== state.ownershipVersion || b.custodyEpoch !== state.custodyEpoch || b.workspaceKeyEpoch !== state.workspaceKeyEpoch ||
    !target || !same(b.priorTarget, previous(target)) || !owner?.active || !owner.owner || !signer?.active || signer.accountId !== owner.accountId ||
    b.authorizer.credentialGeneration !== owner.credentialGeneration || b.authorizer.sessionGeneration !== owner.sessionGeneration ||
    !same(b.authorizer.device, { id: signer.id, keyGeneration: signer.keyGeneration, signingPublicKey: signer.signingPublicKey, recipientPublicKey: signer.recipientPublicKey }) ||
    !owner.scopes.some(custody) || !signer.scopes.some(custody)) invalid();
  if (b.action === 'reactivate_member' ? target.state !== 'suspended' : b.action === 'remove' ?
    !['active', 'suspended'].includes(target.state) : !target.active || target.state !== 'active') invalid();
  if ((b.action === 'set_access' && target.owner) || (b.action === 'demote_owner' && !target.owner)) invalid();
  const inactive = b.action === 'suspend' || b.action === 'remove', departure = target.owner && (inactive || b.action === 'demote_owner');
  if (departure && !Object.values(state.profiles).some((p) => p.accountId !== target.accountId && p.active && p.owner && p.scopes.some(custody) &&
    Object.values(state.recoveryAuthorities).some((r) => r.accountId === p.accountId && r.active && r.generation === p.recoveryGeneration && r.custodyEpoch === state.custodyEpoch))) invalid();
  const selected = b.desired ? state.roles[b.desired.roleId] : undefined;
  if (b.desired && (!selected || selected.state !== 'active' || selected.template === 'owner' ||
    b.desired.projectIds.some((id) => !state.scopeHeads[`project:${id}`]))) invalid();
  const resultingRole = selected ? { id: selected.id, revision: selected.revision } : copy(target.role);
  const selectedRoles = selected ? Object.fromEntries(b.desired!.projectIds.map((id) => [id, copy(resultingRole)])) : copy(target.projectRoles);
  const desiredScopes: AccessScope[] = inactive ? [] : [{ scope: 'workspace', scopeId: b.workspaceId, mode: 'content', keyEpoch: state.workspaceKeyEpoch,
    permissions: [...selected!.permissions], expiresAt: b.action === 'reactivate_member' ? null : target.scopes.find((s) => s.scope === 'workspace')?.expiresAt ?? null },
    ...b.desired!.projectIds.map((id): AccessScope => ({ scope: 'project', scopeId: id, mode: 'content', keyEpoch: state.scopeHeads[`project:${id}`]!.keyEpoch,
      permissions: [...selected!.permissions], expiresAt: b.action === 'reactivate_member' ? null : target.scopes.find((s) => s.scope === 'project' && s.scopeId === id)?.expiresAt ?? null }))];
  if (state.licenceState !== 'active' || state.entitlementState !== 'activated') {
    if (b.action === 'reactivate_member' || desiredScopes.some((s) => !target.scopes.some((old) => key(old) === key(s) &&
      s.permissions.every((p) => old.permissions.includes(p)) && (old.expiresAt === null || (s.expiresAt !== null && Date.parse(s.expiresAt) <= Date.parse(old.expiresAt)))))) invalid();
  }
  const priorScopes = target.owner ? Object.values(state.scopeHeads) : target.scopes;
  const rotations = ordered([...new Map(priorScopes.filter((s) => !desiredScopes.some((after) => key(after) === key(s)))
    .map((s) => { const head = state.scopeHeads[key(s)]; if (!head) invalid(); return [key(s), { scope: head.scope, scopeId: head.scopeId, previousEpoch: head.keyEpoch, nextEpoch: next(head.keyEpoch) }] as const; })).values()], key);
  const rotateCustody = departure || rotations.length > 0, custodyEpoch = rotateCustody ? next(state.custodyEpoch) : state.custodyEpoch;
  const currentEpoch = (s: AccessScope) => s.mode === 'custody' ? custodyEpoch : rotations.find((r) => key(r) === key(s))?.nextEpoch ?? state.scopeHeads[key(s)]?.keyEpoch ?? invalid();
  const profiles: AccessPlan['profiles'] = ordered(Object.values(state.profiles).filter((p) => p.accountId === target.accountId ? !inactive : p.active).map((p) => ({
    accountId: p.accountId, role: p.accountId === target.accountId ? resultingRole : copy(p.role), projectRoles: p.accountId === target.accountId ? selectedRoles : copy(p.projectRoles),
    scopes: ordered((p.accountId === target.accountId ? desiredScopes : p.scopes.map(policy)).map((s) => ({ ...s, keyEpoch: currentEpoch(s) })), key),
  })), (p) => p.accountId);
  const recipients: AccessRecipient[] = [], devices: AccessPlan['devices'] = [];
  for (const d of ordered(Object.values(state.devices).filter((d) => d.active), (d) => d.id)) {
    const person = state.profiles[d.accountId]!, after = profiles.find((p) => p.accountId === d.accountId), isTarget = d.accountId === target.accountId;
    const workspaceMode = person.owner ? 'custody' : 'content', workspaceEpoch = person.owner ? state.custodyEpoch : state.workspaceKeyEpoch;
    const healthy = person.active && person.scopes.some((s) => s.scope === 'workspace' && s.scopeId === b.workspaceId && s.mode === workspaceMode && s.keyEpoch === workspaceEpoch && s.permissions.includes('read_project') && live(s)) && d.scopes.some((s) => s.scope === 'workspace' && s.scopeId === b.workspaceId && s.mode === workspaceMode && live(s) &&
      s.keyEpoch === (person.owner ? state.custodyEpoch : state.workspaceKeyEpoch) && s.permissions.includes('read_project'));
    const active = !!after && (!isTarget || (healthy && b.action !== 'reactivate_member'));
    const scopes: AccessScope[] = !active || !healthy ? [] : after!.scopes.flatMap((s) => {
      if (!live(s)) return [];
      if (isTarget) return [copy(s)];
      const old = d.scopes.find((v) => key(v) === key(s) && v.mode === s.mode && live(v) && v.keyEpoch ===
        (v.mode === 'custody' ? state.custodyEpoch : state.scopeHeads[key(v)]?.keyEpoch));
      if (!old) return [];
      const permissions = s.permissions.filter((p) => old.permissions.includes(p)); if (!permissions.includes('read_project')) return [];
      const expiresAt = old.expiresAt === null ? s.expiresAt : s.expiresAt === null ? old.expiresAt : Date.parse(old.expiresAt) < Date.parse(s.expiresAt) ? old.expiresAt : s.expiresAt;
      return [{ ...s, permissions, expiresAt }];
    });
    const device = { id: d.id, keyGeneration: d.keyGeneration, signingPublicKey: d.signingPublicKey, recipientPublicKey: d.recipientPublicKey };
    devices.push({ accountId: d.accountId, device, active, scopes: ordered(scopes, key) });
    for (const scope of scopes) if (isTarget || (scope.mode === 'custody' && rotateCustody) || rotations.some((r) => key(r) === key(scope)))
      recipients.push({ accountId: d.accountId, kind: 'device', id: d.id, keyGeneration: d.keyGeneration, signingPublicKey: d.signingPublicKey, recipientPublicKey: d.recipientPublicKey, scope });
  }
  if (rotateCustody) for (const p of profiles) {
    const source = state.profiles[p.accountId]!; if (!source.owner || p.accountId === target.accountId) continue;
    const recovery = Object.values(state.recoveryAuthorities).find((r) => r.accountId === p.accountId && r.active && r.generation === source.recoveryGeneration && r.custodyEpoch === state.custodyEpoch);
    const scope = p.scopes.find((s) => s.mode === 'custody' && live(s)); if (!recovery || !scope) invalid();
    recipients.push({ accountId: p.accountId, kind: 'recovery', id: recovery.id, keyGeneration: recovery.generation, signingPublicKey: recovery.signingPublicKey, recipientPublicKey: recovery.recipientPublicKey, scope });
  }
  return accessPlan.parse({ version: 1, target: { accountId: target.accountId, state: b.action === 'remove' ? 'removed' : b.action === 'suspend' ? 'suspended' : 'active',
    owner: false, role: resultingRole, projectRoles: selectedRoles, credentialGeneration: b.action === 'remove' ? next(target.credentialGeneration) : target.credentialGeneration,
    sessionGeneration: next(target.sessionGeneration), recoveryGeneration: departure ? next(target.recoveryGeneration) : target.recoveryGeneration,
    profileRevision: b.action === 'remove' ? next(target.profile.revision) : target.profile.revision },
    nextOwnershipVersion: departure ? next(state.ownershipVersion) : state.ownershipVersion, nextCustodyEpoch: custodyEpoch,
    nextWorkspaceKeyEpoch: rotations.find((r) => r.scope === 'workspace')?.nextEpoch ?? state.workspaceKeyEpoch, rotateCustody, rotations, profiles, devices,
    recipients: ordered(recipients, (r) => `${r.kind}:${r.id}:${key(r.scope)}`) });
}
export const accessTranscriptDigest = (binding: AccessBinding, plan: AccessPlan) => digestObject({ version: 1, purpose: 'ukda.access-plan.v1', binding, plan });
export const accessReceiptTokenHash = (reference: AccessReference, token: string) => digestObject({ purpose: 'ukda.access-receipt.v1', ...accessReference.parse(reference), token: binary(32).parse(token) });
function baseHeader(b: AccessBinding): Omit<ContentHeader, 'recordId' | 'recordType' | 'keyEpoch' | 'revision' | 'action'> {
  return { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: b.workspaceId, scope: 'workspace', scopeId: b.workspaceId,
    schema: 1, operationId: b.operationId, accountId: b.authorizer.accountId, deviceId: b.authorizer.device.id, keyGeneration: b.authorizer.device.keyGeneration,
    permissionVersion: b.nextSecurityVersion, securityVersion: b.securityVersion, securityHead: b.securityHead, dataGeneration: b.dataGeneration, approvalPolicyId: null, approvalPolicyRevision: null };
}
export function accessCustodyHeader(b: AccessBinding, p: AccessPlan, id: string): ContentHeader {
  if (!p.rotateCustody) invalid(); return { ...baseHeader(b), recordId: identifier.parse(id), recordType: 'custody', keyEpoch: p.nextCustodyEpoch, revision: p.nextCustodyEpoch, action: 'access.rotate_custody' };
}
export function accessProfileHeader(b: AccessBinding, p: AccessPlan): ContentHeader {
  if (b.action !== 'remove') invalid(); return { ...baseHeader(b), recordId: b.targetAccountId, recordType: 'profile', keyEpoch: p.nextWorkspaceKeyEpoch, revision: p.target.profileRevision, action: 'profile.remove' };
}
export async function accessRecipientHeader(b: AccessBinding, p: AccessPlan, r: AccessRecipient): Promise<RecipientHeader> {
  if (!p.recipients.some((known) => same(known, r))) invalid();
  return { version: 1, purpose: 'ukda.recipient.v1', algorithm: 'X25519-SealedBox', workspaceId: b.workspaceId,
    scope: r.scope.scope, scopeId: r.scope.scopeId, keyEpoch: r.scope.keyEpoch, recipientAccountId: r.accountId, recipientId: r.id,
    recipientKind: r.kind, recipientKeyGeneration: r.keyGeneration, recipientPublicKey: r.recipientPublicKey,
    senderAccountId: b.authorizer.accountId, senderDeviceId: b.authorizer.device.id, senderKeyGeneration: b.authorizer.device.keyGeneration,
    securityVersion: b.securityVersion, securityHead: b.securityHead, ceremonyId: b.operationId, transcriptDigest: await accessTranscriptDigest(b, p) };
}
export async function validateAccessTransition(value: unknown, expected: AccessBinding, state: SecurityHistoryState): Promise<AccessTransition> {
  const transition = accessTransition.parse(copy(value)), body = transition.body, plan = deriveAccessPlan(expected, state);
  if (!same(body.binding, expected) || !same(body.plan, plan) || body.transcriptDigest !== await accessTranscriptDigest(expected, plan) ||
    !!body.custody !== plan.rotateCustody || (!!body.profile !== (expected.action === 'remove')) || body.custody?.revision !== (plan.rotateCustody ? plan.nextCustodyEpoch : undefined) ||
    body.profile?.revision !== (expected.action === 'remove' ? plan.target.profileRevision : undefined) ||
    body.deliveries.length !== plan.recipients.length || !same(ordered(body.deliveries.map((d) => d.recipient), (r) => `${r.kind}:${r.id}:${key(r.scope)}`), plan.recipients) ||
    !await verifyObject(transition, base64urlDecode(expected.authorizer.device.signingPublicKey, 32), 'ukda.access-change.v1')) invalid();
  const ids = [expected.operationId, ...body.deliveries.map((d) => d.id), ...(body.custody ? [body.custody.id] : []), ...(body.profile ? [body.profile.id] : [])];
  if (new Set(ids).size !== ids.length) invalid(); return transition;
}
export async function validateAccessPayload(value: unknown, expected: AccessBinding, state: SecurityHistoryState) {
  const payload = accessPayload.parse(copy(value)), transition = await validateAccessTransition(payload.transition, expected, state), body = transition.body;
  const publicKey = base64urlDecode(expected.authorizer.device.signingPublicKey, 32);
  for (const kind of ['custody', 'profile'] as const) {
    const descriptor = body[kind], object = payload[kind]; if (!!descriptor !== !!object) invalid();
    if (descriptor && object && (object.id !== descriptor.id || await digestObject(object.envelope) !== descriptor.digest ||
      !await verifyContentEnvelope(object.envelope, publicKey, kind === 'custody' ? accessCustodyHeader(expected, body.plan, object.id) : accessProfileHeader(expected, body.plan)))) invalid();
  }
  if (payload.deliveries.length !== body.deliveries.length || new Set(payload.deliveries.map((d) => d.id)).size !== payload.deliveries.length) invalid();
  for (const descriptor of body.deliveries) { const object = payload.deliveries.find((d) => d.id === descriptor.id);
    if (!object || await digestObject(object.envelope) !== descriptor.digest || !await verifyRecipientEnvelope(object.envelope, publicKey, await accessRecipientHeader(expected, body.plan, descriptor.recipient))) invalid(); }
  return { payload, securityHead: await digestObject(transition), requestHash: await digestObject(payload) };
}
export async function validateAccessReceipt(value: unknown, expected: AccessBinding, state: SecurityHistoryState): Promise<AccessReceipt> {
  const receipt = accessReceipt.parse(copy(value)); await validateAccessTransition(receipt.transition, expected, state);
  if (receipt.workspaceId !== expected.workspaceId || receipt.operationId !== expected.operationId || receipt.targetAccountId !== expected.targetAccountId ||
    receipt.securityVersion !== expected.nextSecurityVersion || receipt.securityHead !== await digestObject(receipt.transition)) invalid(); return receipt;
}
/** A self-revoked actor can verify the exact previously validated local operation without fresh content/history access. */
export async function validateAccessReceiptForPayload(value: unknown, payloadValue: AccessPayload): Promise<AccessReceipt> {
  const receipt = accessReceipt.parse(copy(value)), payload = accessPayload.parse(copy(payloadValue)), b = payload.transition.body.binding;
  if (!same(receipt.transition, payload.transition) || receipt.requestHash !== await digestObject(payload) || receipt.workspaceId !== b.workspaceId ||
    receipt.operationId !== b.operationId || receipt.targetAccountId !== b.targetAccountId || receipt.securityVersion !== b.nextSecurityVersion ||
    receipt.securityHead !== await digestObject(payload.transition) || !await verifyObject(payload.transition, base64urlDecode(b.authorizer.device.signingPublicKey, 32), 'ukda.access-change.v1')) invalid();
  return receipt;
}
export function verifyAccessBindingAgainstHistory(binding: AccessBinding, plan: AccessPlan, state: SecurityHistoryState): void {
  if (!same(deriveAccessPlan(binding, state), plan)) invalid();
}

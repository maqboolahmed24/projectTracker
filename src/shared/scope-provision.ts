import { z } from 'zod';
import { binary, contentEnvelope, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, recipientEnvelope, verifyContentEnvelope, verifyObject, verifyRecipientEnvelope, type ContentHeader, type RecipientHeader } from './crypto.js';
import { accessBinding, accessPlan, accessRecipient, type AccessRecipient, type AccessScope } from './access-change.js';
import type { SecurityHistoryState, HistoryScope } from './security-history.js';

export const scopeProvisionRequest = z.strictObject({ workspaceId: identifier, operationId: identifier, projectId: identifier,
  selected: z.array(z.strictObject({ accountId: identifier, roleId: identifier })).max(4096) }).refine((v) => new Set(v.selected.map((s) => s.accountId)).size === v.selected.length);
export type ScopeProvisionRequest = z.infer<typeof scopeProvisionRequest>;
export const scopeProvisionBinding = z.strictObject({ ...scopeProvisionRequest.shape, version: z.literal(1), origin: z.string().max(256),
  authorizer: accessBinding.shape.authorizer, securityVersion: positiveCounter, nextSecurityVersion: positiveCounter, securityHead: digest,
  dataGeneration: positiveCounter, ownershipVersion: positiveCounter, custodyEpoch: positiveCounter, workspaceKeyEpoch: positiveCounter,
  genesisFingerprint: digest, issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime() }).refine((v) => positiveCounter.safeParse(v.securityVersion).success &&
    positiveCounter.safeParse(v.nextSecurityVersion).success && BigInt(v.nextSecurityVersion) === BigInt(v.securityVersion) + 1n &&
    new Set(v.selected.map((s) => s.accountId)).size === v.selected.length && Date.parse(v.expiresAt) > Date.parse(v.issuedAt) && Date.parse(v.expiresAt) - Date.parse(v.issuedAt) <= 600_000);
export type ScopeProvisionBinding = z.infer<typeof scopeProvisionBinding>;
export const scopeProvisionPlan = z.strictObject({ version: z.literal(1), projectId: identifier, nextCustodyEpoch: positiveCounter,
  profiles: accessPlan.shape.profiles, devices: accessPlan.shape.devices, recipients: accessPlan.shape.recipients });
export type ScopeProvisionPlan = z.infer<typeof scopeProvisionPlan>;
const reference = z.strictObject({ id: identifier, digest, revision: positiveCounter });
export const scopeProvisionTransition = z.strictObject({ body: z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.project-scope-provision.v1'),
  binding: scopeProvisionBinding, plan: scopeProvisionPlan, transcriptDigest: digest, custody: reference,
  deliveries: z.array(z.strictObject({ id: identifier, digest, recipient: accessRecipient })).max(8192) }), signature: binary(64) });
export type ScopeProvisionTransition = z.infer<typeof scopeProvisionTransition>;
export const scopeProvisionPayload = z.strictObject({ transition: scopeProvisionTransition, custody: z.strictObject({ id: identifier, envelope: contentEnvelope }),
  deliveries: z.array(z.strictObject({ id: identifier, envelope: recipientEnvelope })).max(8192) });
export type ScopeProvisionPayload = z.infer<typeof scopeProvisionPayload>;
export class ScopeProvisionError extends Error { constructor() { super('Invalid signed project scope provisioning'); this.name = 'ScopeProvisionError'; } }
function invalid(): never { throw new ScopeProvisionError(); }
const copy = <T>(v: T): T => JSON.parse(canonicalJson(v)) as T;
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const next = (v: string) => String(BigInt(v) + 1n);
const key = (v: Pick<AccessScope, 'scope' | 'scopeId'>) => `${v.scope}:${v.scopeId}`;
const ordered = <T>(values: T[], id: (v: T) => string) => values.sort((a, b) => id(a).localeCompare(id(b), 'en'));
function policy(v: HistoryScope): AccessScope { const { manifests: _manifests, ...scope } = v; return copy(scope); }
export function createScopeProvisionBinding(requestValue: ScopeProvisionRequest, state: SecurityHistoryState,
  actor: ScopeProvisionBinding['authorizer'], times: { issuedAt: string; expiresAt: string }): ScopeProvisionBinding {
  const binding = scopeProvisionBinding.parse({ ...scopeProvisionRequest.parse(copy(requestValue)), version: 1, origin: state.origin, authorizer: actor,
    securityVersion: state.securityVersion, nextSecurityVersion: next(state.securityVersion), securityHead: state.securityHead,
    dataGeneration: state.dataGeneration, ownershipVersion: state.ownershipVersion, custodyEpoch: state.custodyEpoch, workspaceKeyEpoch: state.workspaceKeyEpoch,
    genesisFingerprint: state.genesisFingerprint, ...times }); deriveScopeProvisionPlan(binding, state); return binding;
}
/** A security bootstrap primitive. It provisions no business project rows or inferred memberships. */
export function deriveScopeProvisionPlan(value: ScopeProvisionBinding, state: SecurityHistoryState): ScopeProvisionPlan {
  const b = scopeProvisionBinding.parse(copy(value)), actor = b.authorizer, owner = state.profiles[actor.accountId], signer = state.devices[actor.device.id];
  const live = (s: AccessScope) => s.expiresAt === null || Date.parse(s.expiresAt) > Date.parse(b.issuedAt);
  const custody = (s: AccessScope) => s.scope === 'workspace' && s.scopeId === b.workspaceId && s.mode === 'custody' && s.keyEpoch === state.custodyEpoch && live(s);
  if (state.workspaceId !== b.workspaceId || state.origin !== b.origin || state.genesisFingerprint !== b.genesisFingerprint ||
    state.securityHead !== b.securityHead || state.securityVersion !== b.securityVersion || state.dataGeneration !== b.dataGeneration ||
    state.ownershipVersion !== b.ownershipVersion || state.custodyEpoch !== b.custodyEpoch || state.workspaceKeyEpoch !== b.workspaceKeyEpoch ||
    state.licenceState !== 'active' || state.entitlementState !== 'activated' || state.scopeHeads[`project:${b.projectId}`] || b.projectId === b.workspaceId ||
    !owner?.active || !owner.owner || !signer?.active || signer.accountId !== owner.accountId ||
    actor.credentialGeneration !== owner.credentialGeneration || actor.sessionGeneration !== owner.sessionGeneration ||
    !same(actor.device, { id: signer.id, keyGeneration: signer.keyGeneration, signingPublicKey: signer.signingPublicKey, recipientPublicKey: signer.recipientPublicKey }) ||
    !owner.scopes.some(custody) || !signer.scopes.some(custody)) invalid();
  for (const selected of b.selected) {
    const p = state.profiles[selected.accountId], r = state.roles[selected.roleId];
    if (!p?.active || p.owner || !r || r.state !== 'active' || r.template === 'owner') invalid();
  }
  const ownerRole = Object.values(state.roles).find((r) => r.template === 'owner')!;
  const profiles = ordered(Object.values(state.profiles).filter((p) => p.active).map((p) => {
    const selected = b.selected.find((s) => s.accountId === p.accountId), role = p.owner ? ownerRole : selected ? state.roles[selected.roleId]! : undefined;
    const scopes = p.scopes.map(policy).map((s) => s.mode === 'custody' ? { ...s, keyEpoch: next(state.custodyEpoch) } : s);
    if (role) scopes.push({ scope: 'project', scopeId: b.projectId, mode: 'content', keyEpoch: '1', permissions: [...role.permissions], expiresAt: null });
    return { accountId: p.accountId, role: copy(p.role), projectRoles: { ...copy(p.projectRoles), ...(role ? { [b.projectId]: { id: role.id, revision: role.revision } } : {}) }, scopes: ordered(scopes, key) };
  }), (p) => p.accountId);
  const recipients: AccessRecipient[] = [], devices: ScopeProvisionPlan['devices'] = [];
  for (const d of ordered(Object.values(state.devices).filter((d) => d.active), (d) => d.id)) {
    const person = state.profiles[d.accountId]!, after = profiles.find((p) => p.accountId === d.accountId), mode = person.owner ? 'custody' : 'content';
    const workspaceEpoch = person.owner ? state.custodyEpoch : state.workspaceKeyEpoch;
    const eligible = (s: AccessScope) => s.scope === 'workspace' && s.scopeId === b.workspaceId && s.mode === mode && s.keyEpoch === workspaceEpoch && s.permissions.includes('read_project') && live(s);
    const healthy = person.active && person.scopes.some(eligible) && d.scopes.some(eligible);
    const scopes: AccessScope[] = !after || !healthy ? [] : after.scopes.flatMap((s) => {
      if (!live(s)) return [];
      if (s.scope === 'project' && s.scopeId === b.projectId) return [copy(s)];
      const old = d.scopes.find((v) => key(v) === key(s) && v.mode === s.mode && live(v) && v.keyEpoch === (v.mode === 'custody' ? state.custodyEpoch : state.scopeHeads[key(v)]?.keyEpoch));
      if (!old) return []; const permissions = s.permissions.filter((p) => old.permissions.includes(p)); if (!permissions.includes('read_project')) return [];
      const expiresAt = old.expiresAt === null ? s.expiresAt : s.expiresAt === null ? old.expiresAt : Date.parse(old.expiresAt) < Date.parse(s.expiresAt) ? old.expiresAt : s.expiresAt;
      return [{ ...s, permissions, expiresAt }];
    });
    const device = { id: d.id, keyGeneration: d.keyGeneration, signingPublicKey: d.signingPublicKey, recipientPublicKey: d.recipientPublicKey };
    devices.push({ accountId: d.accountId, device, active: !!after, scopes: ordered(scopes, key) });
    for (const scope of scopes) if (scope.mode === 'custody' || (scope.scope === 'project' && scope.scopeId === b.projectId))
      recipients.push({ accountId: d.accountId, kind: 'device', ...device, scope });
  }
  for (const p of profiles) if (state.profiles[p.accountId]!.owner) {
    const source = state.profiles[p.accountId]!, recovery = Object.values(state.recoveryAuthorities).find((r) => r.accountId === p.accountId && r.active && r.generation === source.recoveryGeneration && r.custodyEpoch === state.custodyEpoch);
    const scope = p.scopes.find((s) => s.mode === 'custody' && live(s)); if (!recovery || !scope) invalid();
    recipients.push({ accountId: p.accountId, kind: 'recovery', id: recovery.id, keyGeneration: recovery.generation, signingPublicKey: recovery.signingPublicKey, recipientPublicKey: recovery.recipientPublicKey, scope });
  }
  return scopeProvisionPlan.parse({ version: 1, projectId: b.projectId, nextCustodyEpoch: next(state.custodyEpoch), profiles, devices,
    recipients: ordered(recipients, (r) => `${r.kind}:${r.id}:${key(r.scope)}`) });
}
export const scopeProvisionTranscriptDigest = (b: ScopeProvisionBinding, p: ScopeProvisionPlan) => digestObject({ version: 1, purpose: 'ukda.scope-provision-plan.v1', binding: b, plan: p });
export function scopeProvisionCustodyHeader(b: ScopeProvisionBinding, p: ScopeProvisionPlan, id: string): ContentHeader {
  return { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: b.workspaceId, scope: 'workspace', scopeId: b.workspaceId,
    recordId: identifier.parse(id), recordType: 'custody', schema: 1, keyEpoch: p.nextCustodyEpoch, revision: p.nextCustodyEpoch, operationId: b.operationId,
    accountId: b.authorizer.accountId, deviceId: b.authorizer.device.id, keyGeneration: b.authorizer.device.keyGeneration, permissionVersion: b.nextSecurityVersion,
    securityVersion: b.securityVersion, securityHead: b.securityHead, dataGeneration: b.dataGeneration, action: 'scope.provision_custody', approvalPolicyId: null, approvalPolicyRevision: null };
}
export async function scopeProvisionRecipientHeader(b: ScopeProvisionBinding, p: ScopeProvisionPlan, r: AccessRecipient): Promise<RecipientHeader> {
  if (!p.recipients.some((v) => same(v, r))) invalid(); return { version: 1, purpose: 'ukda.recipient.v1', algorithm: 'X25519-SealedBox', workspaceId: b.workspaceId,
    scope: r.scope.scope, scopeId: r.scope.scopeId, keyEpoch: r.scope.keyEpoch, recipientAccountId: r.accountId, recipientId: r.id, recipientKind: r.kind,
    recipientKeyGeneration: r.keyGeneration, recipientPublicKey: r.recipientPublicKey, senderAccountId: b.authorizer.accountId,
    senderDeviceId: b.authorizer.device.id, senderKeyGeneration: b.authorizer.device.keyGeneration, securityVersion: b.securityVersion, securityHead: b.securityHead,
    ceremonyId: b.operationId, transcriptDigest: await scopeProvisionTranscriptDigest(b, p) };
}
export async function validateScopeProvisionTransition(value: unknown, expected: ScopeProvisionBinding, state: SecurityHistoryState): Promise<ScopeProvisionTransition> {
  const transition = scopeProvisionTransition.parse(copy(value)), body = transition.body, plan = deriveScopeProvisionPlan(expected, state);
  if (!same(body.binding, expected) || !same(body.plan, plan) || body.custody.revision !== plan.nextCustodyEpoch ||
    body.transcriptDigest !== await scopeProvisionTranscriptDigest(expected, plan) || body.deliveries.length !== plan.recipients.length ||
    !same(ordered(body.deliveries.map((d) => d.recipient), (r) => `${r.kind}:${r.id}:${key(r.scope)}`), plan.recipients) ||
    !await verifyObject(transition, base64urlDecode(expected.authorizer.device.signingPublicKey, 32), 'ukda.project-scope-provision.v1')) invalid();
  const ids = [expected.operationId, body.custody.id, ...body.deliveries.map((d) => d.id)]; if (new Set(ids).size !== ids.length) invalid(); return transition;
}
export async function validateScopeProvisionPayload(value: unknown, expected: ScopeProvisionBinding, state: SecurityHistoryState) {
  const payload = scopeProvisionPayload.parse(copy(value)), transition = await validateScopeProvisionTransition(payload.transition, expected, state), body = transition.body;
  const publicKey = base64urlDecode(expected.authorizer.device.signingPublicKey, 32);
  if (payload.custody.id !== body.custody.id || await digestObject(payload.custody.envelope) !== body.custody.digest ||
    !await verifyContentEnvelope(payload.custody.envelope, publicKey, scopeProvisionCustodyHeader(expected, body.plan, payload.custody.id)) ||
    payload.deliveries.length !== body.deliveries.length || new Set(payload.deliveries.map((d) => d.id)).size !== payload.deliveries.length) invalid();
  for (const d of body.deliveries) { const object = payload.deliveries.find((v) => v.id === d.id);
    if (!object || await digestObject(object.envelope) !== d.digest || !await verifyRecipientEnvelope(object.envelope, publicKey, await scopeProvisionRecipientHeader(expected, body.plan, d.recipient))) invalid(); }
  return { payload, securityHead: await digestObject(transition), requestHash: await digestObject(payload) };
}

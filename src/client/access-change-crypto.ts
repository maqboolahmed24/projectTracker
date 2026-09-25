import { z } from 'zod';
import { binary, identifier, positiveCounter } from '../shared/contracts.js';
import { base64urlEncode, canonicalJson, randomKey } from '../shared/crypto.js';

const keyEntry = z.strictObject({ epoch: positiveCounter, key: binary(32) });
const keyring = z.array(keyEntry).min(1).max(4096).refine((values) => new Set(values.map((value) => value.epoch)).size === values.length);
export const retainedCustodyManifest = z.strictObject({ version: z.literal(1), custodyEpoch: positiveCounter, workspaceKeys: keyring,
  projectKeys: z.array(z.strictObject({ projectId: identifier, keys: keyring })).max(4096)
    .refine((values) => new Set(values.map((value) => value.projectId)).size === values.length) });
export type RetainedCustodyManifest = z.infer<typeof retainedCustodyManifest>;
const rotation = z.strictObject({ scope: z.enum(['workspace', 'project']), scopeId: identifier, previousEpoch: positiveCounter, nextEpoch: positiveCounter })
  .refine((value) => BigInt(value.nextEpoch) === BigInt(value.previousEpoch) + 1n);
/** Worker-internal only: the caller first verifies the exact plan against independently replayed history. */
export async function rotateRetainedKeyrings(input: { workspaceId: string; manifest: RetainedCustodyManifest;
  nextCustodyEpoch: string; rotations: z.infer<typeof rotation>[] }): Promise<RetainedCustodyManifest> {
  const workspaceId = identifier.parse(input.workspaceId), manifest = retainedCustodyManifest.parse(JSON.parse(canonicalJson(input.manifest))),
    rotations = z.array(rotation).max(4097).refine((items) => new Set(items.map((item) => `${item.scope}:${item.scopeId}`)).size === items.length).parse(input.rotations),
    nextCustodyEpoch = positiveCounter.parse(input.nextCustodyEpoch);
  if (BigInt(nextCustodyEpoch) < BigInt(manifest.custodyEpoch) || BigInt(nextCustodyEpoch) > BigInt(manifest.custodyEpoch) + 1n ||
    rotations.length && nextCustodyEpoch === manifest.custodyEpoch) throw new Error('Invalid rotation plan');
  for (const item of rotations) {
    if (item.scope === 'workspace' && item.scopeId !== workspaceId) throw new Error('Invalid rotation scope');
    const entries = item.scope === 'workspace' ? manifest.workspaceKeys : manifest.projectKeys.find((project) => project.projectId === item.scopeId)?.keys;
    if (!entries || !entries.some((entry) => entry.epoch === item.previousEpoch) || entries.some((entry) => BigInt(entry.epoch) > BigInt(item.previousEpoch))) throw new Error('Missing current scope key');
    const key = await randomKey();
    try { entries.push({ epoch: item.nextEpoch, key: base64urlEncode(key) }); } finally { key.fill(0); }
  }
  manifest.custodyEpoch = nextCustodyEpoch;
  return retainedCustodyManifest.parse(manifest);
}

import { base64urlDecode, decryptContent, digestObject, encryptContent, sealRecipient, signObject } from '../shared/crypto.js';
import { accessContext, accessDelivery, accessPayload, accessRequest, deriveAccessPlan, accessTranscriptDigest, accessCustodyHeader,
  accessProfileHeader, accessRecipientHeader, validateAccessPayload, type AccessContext, type AccessPayload, type AccessRequest, type AccessDelivery } from '../shared/access-change.js';
import { verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState, type HistoryScope } from '../shared/security-history.js';
import type { DeviceBundle } from './device-store.js';
import type { PairingScope } from '../shared/pairing.js';
import { readOwnerCustodyKeyMaterial, readDeviceScopeKeyMaterial } from './pairing.js';

export class AccessChangeClientError extends Error {
  constructor(readonly code: 'INVALID_CHANGE' | 'INCOMPLETE_KEYS' | 'TRUST_REQUIRED' | 'CONFLICT' | 'EXPIRED' | 'NOT_FOUND' | 'CANCELLED' | 'STORAGE') {
    super(`Access change failed (${code})`); this.name = 'AccessChangeClientError';
  }
}
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
function invalid(): never { throw new AccessChangeClientError('INVALID_CHANGE'); }
function currentManifest(manifest: RetainedCustodyManifest, state: SecurityHistoryState): void {
  if (manifest.custodyEpoch !== state.custodyEpoch) invalid();
  for (const head of Object.values(state.scopeHeads)) {
    const entries = head.scope === 'workspace' ? manifest.workspaceKeys : manifest.projectKeys.find((project) => project.projectId === head.scopeId)?.keys;
    if (!entries || !entries.some((entry) => entry.epoch === head.keyEpoch) || entries.some((entry) => BigInt(entry.epoch) > BigInt(head.keyEpoch))) throw new AccessChangeClientError('INCOMPLETE_KEYS');
  }
}
export interface PrepareAccessChangeInput { request: AccessRequest; context: AccessContext; history: SecurityHistoryInput }
/** The exact history-derived plan is checked before any private material is opened or sealed. */
export async function prepareAccessChange(value: PrepareAccessChangeInput, bundle: DeviceBundle): Promise<AccessPayload> {
  const input = copy(value), context = accessContext.parse(input.context), binding = context.binding, request = accessRequest.parse(input.request), state = await verifySecurityHistory(input.history);
  if (!same(request, { workspaceId: binding.workspaceId, operationId: binding.operationId, action: binding.action,
    targetAccountId: binding.targetAccountId, desired: binding.desired, receiptTokenHash: binding.receiptTokenHash }) ||
    Date.parse(binding.expiresAt) <= Date.now() || Date.parse(binding.issuedAt) > Date.now() + 30_000 ||
    bundle.signingPublicKey !== binding.authorizer.device.signingPublicKey || bundle.recipientPublicKey !== binding.authorizer.device.recipientPublicKey) invalid();
  const plan = deriveAccessPlan(binding, state); if (!same(plan, context.plan)) invalid();
  if (plan.recipients.some((recipient) => recipient.scope.expiresAt !== null && Date.parse(recipient.scope.expiresAt) <= Date.now())) throw new AccessChangeClientError('EXPIRED');
  const opened = await readOwnerCustodyKeyMaterial({ accountId: binding.authorizer.accountId, deviceId: binding.authorizer.device.id,
    history: state, materials: context.materials }, bundle);
  if (!same(opened.payload.manifest, { id: state.custodyManifest.id, digest: state.custodyManifest.digest })) invalid();
  const previous = retainedCustodyManifest.parse(opened.manifest); currentManifest(previous, state);
  const manifest = await rotateRetainedKeyrings({ workspaceId: binding.workspaceId, manifest: previous,
    nextCustodyEpoch: plan.nextCustodyEpoch, rotations: plan.rotations });
  const signing = base64urlDecode(bundle.signingPrivateKey, 64), custodyKey = plan.rotateCustody ? await randomKey() : base64urlDecode(opened.payload.custodyKey, 32);
  const deliveries: AccessPayload['deliveries'] = [], descriptors: AccessPayload['transition']['body']['deliveries'] = [];
  let custody: AccessPayload['custody'] = null, profile: AccessPayload['profile'] = null;
  try {
    let custodyReference = opened.payload.manifest;
    if (plan.rotateCustody) {
      const id = crypto.randomUUID(), header = accessCustodyHeader(binding, plan, id), envelope = await encryptContent(header, manifest, custodyKey, signing);
      if (!same(await decryptContent(envelope, custodyKey, base64urlDecode(bundle.signingPublicKey, 32), header), manifest)) invalid();
      custody = { id, envelope }; custodyReference = { id, digest: await digestObject(envelope) };
    }
    if (binding.action === 'remove') {
      const entry = manifest.workspaceKeys.find((key) => key.epoch === plan.nextWorkspaceKeyEpoch); if (!entry) throw new AccessChangeClientError('INCOMPLETE_KEYS');
      const key = base64urlDecode(entry.key, 32);
      try {
        const header = accessProfileHeader(binding, plan), plaintext = { displayName: 'Former member' }, envelope = await encryptContent(header, plaintext, key, signing);
        if (!same(await decryptContent(envelope, key, base64urlDecode(bundle.signingPublicKey, 32), header), plaintext)) invalid(); profile = { id: crypto.randomUUID(), envelope };
      } finally { key.fill(0); }
    }
    for (const recipient of plan.recipients) {
      const scope = recipient.scope;
      if (scope.expiresAt !== null && Date.parse(scope.expiresAt) <= Date.now()) throw new AccessChangeClientError('EXPIRED');
      const entries = scope.scope === 'workspace' ? manifest.workspaceKeys : manifest.projectKeys.find((project) => project.projectId === scope.scopeId)?.keys;
      if (scope.mode === 'content' && (!entries || !entries.some((entry) => entry.epoch === scope.keyEpoch))) throw new AccessChangeClientError('INCOMPLETE_KEYS');
      const plaintext = scope.mode === 'custody' ? { version: 1, mode: 'custody', custodyEpoch: plan.nextCustodyEpoch,
        custodyKey: base64urlEncode(custodyKey), manifest: custodyReference } : { version: 1, mode: 'content', scope: scope.scope,
        scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, keys: entries!.filter((entry) => BigInt(entry.epoch) <= BigInt(scope.keyEpoch)) };
      const id = crypto.randomUUID(), envelope = await sealRecipient(await accessRecipientHeader(binding, plan, recipient), plaintext, signing);
      deliveries.push({ id, envelope }); descriptors.push({ id, digest: await digestObject(envelope), recipient });
    }
    const transition = await signObject({ version: 1 as const, purpose: 'ukda.access-change.v1' as const, binding, plan,
      transcriptDigest: await accessTranscriptDigest(binding, plan),
      custody: custody ? { id: custody.id, digest: await digestObject(custody.envelope), revision: plan.nextCustodyEpoch } : null,
      profile: profile ? { id: profile.id, digest: await digestObject(profile.envelope), revision: plan.target.profileRevision } : null, deliveries: descriptors }, signing);
    return (await validateAccessPayload(accessPayload.parse({ transition, custody, profile, deliveries }), binding, state)).payload;
  } finally { signing.fill(0); custodyKey.fill(0); }
}
export interface RefreshAccessKeysInput { delivery: AccessDelivery; history: SecurityHistoryInput }
export interface RefreshedAccess { complete: true; scopeCount: number; securityHead: string; securityVersion: string; custodyEpoch: string; ownershipVersion: string }
/** Current approval grants and person scopes both constrain the data the Worker will decrypt. */
export async function refreshAccessKeys(value: RefreshAccessKeysInput, bundle: DeviceBundle): Promise<RefreshedAccess> {
  const input = copy(value), delivery = accessDelivery.parse(input.delivery), state = await verifySecurityHistory(input.history);
  const profile = state.profiles[delivery.accountId], device = state.devices[delivery.deviceId];
  if (delivery.workspaceId !== state.workspaceId || !same(delivery.current, { securityHead: state.securityHead, securityVersion: state.securityVersion }) ||
    !profile?.active || !device?.active || device.accountId !== profile.accountId || device.signingPublicKey !== bundle.signingPublicKey ||
    device.recipientPublicKey !== bundle.recipientPublicKey) invalid();
  const live = (scope: HistoryScope) => scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.now();
  const scopes: PairingScope[] = device.scopes.filter(live).map((scope) => {
    const personal = profile.scopes.find((entry) => entry.scope === scope.scope && entry.scopeId === scope.scopeId && entry.mode === scope.mode && live(entry));
    const epoch = scope.mode === 'custody' ? state.custodyEpoch : state.scopeHeads[`${scope.scope}:${scope.scopeId}`]?.keyEpoch;
    if (!personal || scope.keyEpoch !== epoch || personal.keyEpoch !== epoch || !scope.permissions.includes('read_project') ||
      !scope.permissions.every((permission) => personal.permissions.includes(permission)) ||
      personal.expiresAt !== null && (scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.parse(personal.expiresAt))) invalid();
    const { manifests, ...policy } = scope;
    const sources = manifests.filter((entry) => delivery.materials.some((material) => material.id === entry.id && material.digest === entry.digest))
      .map((entry) => ({ grantId: delivery.deviceId, generation: '1', manifestId: entry.id, manifestDigest: entry.digest }));
    if (!sources.length) throw new AccessChangeClientError('INCOMPLETE_KEYS'); return { ...policy, sources };
  });
  if (!scopes.some((scope) => scope.scope === 'workspace' && scope.scopeId === state.workspaceId && scope.mode === (profile.owner ? 'custody' : 'content'))) invalid();
  await readDeviceScopeKeyMaterial({ scopes, history: state, materials: delivery.materials, holder: { workspaceId: state.workspaceId, custodyEpoch: state.custodyEpoch,
    approverAccountId: profile.accountId, approverDevice: { id: device.id, keyGeneration: device.keyGeneration, signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey } } }, bundle);
  if (profile.owner) {
    const opened = await readOwnerCustodyKeyMaterial({ accountId: profile.accountId, deviceId: device.id, history: state, materials: delivery.materials }, bundle);
    if (!same(opened.payload.manifest, { id: state.custodyManifest.id, digest: state.custodyManifest.digest })) invalid(); currentManifest(retainedCustodyManifest.parse(opened.manifest), state);
  }
  return { complete: true, scopeCount: scopes.length, securityHead: state.securityHead, securityVersion: state.securityVersion,
    custodyEpoch: state.custodyEpoch, ownershipVersion: state.ownershipVersion };
}

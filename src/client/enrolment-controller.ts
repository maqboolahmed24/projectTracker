import { z } from 'zod';
import { genesisBody } from '../shared/activation.js';
import { binary, contentEnvelope, digest, identifier } from '../shared/contracts.js';
import { base64urlDecode, base64urlEncode, canonicalJson, decryptContent, digestObject, encryptContent, sealRecipient, signObject, verifyRecipientEnvelope } from '../shared/crypto.js';
import { enrolmentBinding, enrolmentTranscript, enrolmentDraft, enrolmentPublicDraft, enrolmentApproval, enrolmentReceipt,
  enrolmentReference, enrolmentOperationReference, enrolmentIssuedJoin, enrolmentConfirmationFor, enrolmentRecipientHeader, enrolmentRecipientDevices,
  enrolmentProfileHeader, validateEnrolmentDraft, validateEnrolmentPublicApproval, validateEnrolmentReceipt,
  type EnrolmentBinding, type EnrolmentDraft, type EnrolmentPublicDraft, type EnrolmentApproval, type EnrolmentReceipt,
  type EnrolmentReference, type EnrolmentOperationReference, type EnrolmentIssuedJoin } from '../shared/enrolment.js';
import { enrolmentView, enrolmentIssueJoin, enrolmentIssuanceRequest, enrolmentIssuanceContext, type EnrolmentView, type EnrolmentIssuanceContext } from '../shared/enrolment-api.js';
import { verifyEnrolmentBindingAgainstHistory, verifyEnrolmentTranscriptAgainstHistory, verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import type { PairingMaterial, PairingScope } from '../shared/pairing.js';
import { prepareJoinEnrolment, rebindJoinEnrolment, preparePromotionEnrolment, verifyPreparedEnrolment, verifyEnrolmentFingerprint,
  confirmEnrolmentRecipient, confirmEnrolmentAuthorizer, encryptEnrolmentProfile, enrolmentDeviceContext,
  type PrepareJoinEnrolmentInput, type PreparedEnrolment, type NewEnrolmentOwnerKit } from './enrolment-crypto.js';
import { IndexedEnrolmentStore, preparedEnrolment, type EnrolmentRecord } from './enrolment-store.js';
import { IndexedDeviceStore, type DeviceBundle, type DeviceWrapper } from './device-store.js';
import { IndexedPairingStore, readDeviceScopeKeyMaterial, readRecoveryCustodyKeyMaterial, readSecurityHistoryPages, historyResponse, type PairingHistoryResponse } from './pairing.js';
import { recoveryKeys } from './recovery.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import type { OpaquePublicConfiguration } from './opaque.js';
import type { RememberedProfiles } from './remembered-profiles.js';

export class EnrolmentClientError extends Error {
  constructor(readonly code: 'INVALID_ENROLMENT' | 'TRUST_REQUIRED' | 'CONFLICT' | 'NOT_FOUND' | 'CANCELLED' | 'PASSWORD_CONFIRMATION' | 'INCOMPLETE_KEYS' | 'STORAGE') {
    super(`Enrolment failed (${code})`); this.name = 'EnrolmentClientError';
  }
}
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
const same = (left: unknown, right: unknown) => canonicalJson(left) === canonicalJson(right);
function invalid(): never { throw new EnrolmentClientError('INVALID_ENROLMENT'); }
async function trustedBinding(history: SecurityHistoryInput, binding: EnrolmentBinding) {
  const state = await verifySecurityHistory(history); verifyEnrolmentBindingAgainstHistory(binding, state); return state;
}
export interface PrepareJoinInvitationInput { request: z.infer<typeof enrolmentIssuanceRequest>; context: EnrolmentIssuanceContext; history: SecurityHistoryInput; displayName: string }
export const invitationIntent = z.strictObject({ version: z.literal(1), kind: z.enum(['join_member', 'join_owner']),
  role: enrolmentBinding.shape.role, workspaceId: identifier, accountId: identifier, operationId: identifier,
  projectScope: z.discriminatedUnion('mode', [z.strictObject({ mode: z.literal('all_ordinary') }),
    z.strictObject({ mode: z.literal('selected'), projectIds: z.array(identifier).max(255).refine((ids) => new Set(ids).size === ids.length && same(ids, [...ids].sort())) })]) })
  .refine((value) => (value.kind === 'join_owner') === (value.projectScope.mode === 'all_ordinary'));
const invitedProfile = z.strictObject({ displayName: z.string().min(1).max(200), invitation: invitationIntent });
/** Encrypts a pending profile only after checking current Owner authority against the independent local pin. */
export async function prepareJoinInvitation(value: PrepareJoinInvitationInput, bundle: DeviceBundle): Promise<z.infer<typeof enrolmentIssueJoin>> {
  const input = copy(value), request = enrolmentIssuanceRequest.parse(input.request), context = enrolmentIssuanceContext.parse(input.context), state = await verifySecurityHistory(input.history);
  const owner = state.profiles[context.authorizer.accountId], device = state.devices[context.authorizer.device.id], role = state.roles[request.roleId];
  if (state.workspaceId !== request.workspaceId || context.workspaceId !== request.workspaceId || context.accountId !== request.accountId ||
    context.operationId !== request.operationId || context.kind !== request.kind || context.genesisFingerprint !== state.genesisFingerprint ||
    !same(context.current, { securityHead: state.securityHead, securityVersion: state.securityVersion }) || context.custodyEpoch !== state.custodyEpoch ||
    state.profiles[request.accountId] || state.licenceState !== 'active' || state.entitlementState !== 'activated' ||
    !owner?.active || !owner.owner || !device?.active || device.accountId !== owner.accountId || !role || role.state !== 'active' ||
    !same(context.role, { id: role.id, revision: role.revision, permissions: role.permissions }) || (role.template === 'owner') !== (request.kind === 'join_owner') ||
    context.authorizer.credentialGeneration !== owner.credentialGeneration || context.authorizer.sessionGeneration !== owner.sessionGeneration ||
    !same(context.authorizer.device, { id: device.id, keyGeneration: device.keyGeneration, signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey }) ||
    bundle.signingPublicKey !== device.signingPublicKey || bundle.recipientPublicKey !== device.recipientPublicKey) invalid();
  const eligible = (scope: typeof owner.scopes[number]) => scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.now();
  const workspace = owner.scopes.find((scope) => scope.scope === 'workspace' && scope.scopeId === request.workspaceId && scope.mode === 'custody' && scope.keyEpoch === state.custodyEpoch && eligible(scope));
  if (!workspace || !device.scopes.some((scope) => scope.scope === 'workspace' && scope.mode === 'custody' && scope.keyEpoch === state.custodyEpoch && eligible(scope)) ||
    request.projectIds.some((id) => !owner.scopes.some((scope) => scope.scope === 'project' && scope.scopeId === id && eligible(scope) && role.permissions.every((permission) => scope.permissions.includes(permission))))) invalid();
  const expected = { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: request.workspaceId,
    scope: 'workspace', scopeId: request.workspaceId, recordId: request.accountId, recordType: 'profile', schema: 1,
    keyEpoch: state.workspaceKeyEpoch, revision: context.header.revision, operationId: request.operationId, accountId: owner.accountId,
    deviceId: device.id, keyGeneration: device.keyGeneration, permissionVersion: role.revision, securityVersion: state.securityVersion,
    securityHead: state.securityHead, dataGeneration: state.dataGeneration, action: 'profile.invite', approvalPolicyId: null, approvalPolicyRevision: null };
  if (!same(context.header, expected)) invalid();
  const scope: PairingScope = { scope: 'workspace', scopeId: request.workspaceId, mode: 'content', keyEpoch: state.workspaceKeyEpoch,
    expiresAt: workspace.expiresAt, permissions: [...workspace.permissions], sources: workspace.manifests.map((manifest) =>
      ({ grantId: request.operationId, generation: '1', manifestId: manifest.id, manifestDigest: manifest.digest })) };
  // Materials may contain only the current source reference rather than every retained historical device envelope.
  scope.sources = scope.sources.filter((source) => context.materials.some((material) => material.id === source.manifestId && material.digest === source.manifestDigest));
  if (!scope.sources.length) throw new EnrolmentClientError('INCOMPLETE_KEYS');
  const payloads = await readDeviceScopeKeyMaterial({ scopes: [scope], history: state, materials: context.materials,
    holder: { workspaceId: request.workspaceId, custodyEpoch: state.custodyEpoch, approverAccountId: owner.accountId, approverDevice: context.authorizer.device } }, bundle);
  const ring = z.object({ mode: z.literal('content'), keys: z.array(z.object({ epoch: z.string(), key: binary(32) })) }).parse(payloads[0]);
  const entry = ring.keys.find((key) => key.epoch === state.workspaceKeyEpoch); if (!entry) throw new EnrolmentClientError('INCOMPLETE_KEYS');
  const key = base64urlDecode(entry.key, 32), signing = base64urlDecode(bundle.signingPrivateKey, 64);
  try {
    const displayName = z.string().trim().min(1).max(200).refine((name) => !/[\uD800-\uDFFF]/u.test(name)).parse(input.displayName);
    const plaintext = { displayName, invitation: invitationIntent.parse({ version: 1, kind: request.kind, role: context.role,
      workspaceId: request.workspaceId, accountId: request.accountId, operationId: request.operationId,
      projectScope: request.kind === 'join_owner' ? { mode: 'all_ordinary' } : { mode: 'selected', projectIds: [...request.projectIds].sort() } }) };
    const envelope = await encryptContent(context.header, plaintext, key, signing);
    const readback = await decryptContent(envelope, key, base64urlDecode(bundle.signingPublicKey, 32), context.header);
    if (!same(readback, plaintext)) invalid(); return { ...request, profile: { id: crypto.randomUUID(), envelope } };
  } finally { key.fill(0); signing.fill(0); }
}
export type PrepareEnrolmentDraftInput = { history: SecurityHistoryInput } & (
  | { mode: 'join'; input: PrepareJoinEnrolmentInput }
  | { mode: 'rebind'; input: Parameters<typeof rebindJoinEnrolment>[0] }
  | { mode: 'promotion'; input: Parameters<typeof preparePromotionEnrolment>[0]; previous?: PreparedEnrolment });
/** Worker-only preparation: independently verified history precedes any binding-sensitive operation. */
export async function prepareEnrolmentDraft(value: PrepareEnrolmentDraftInput): Promise<PreparedEnrolment> {
  const input = copy(value), binding = enrolmentBinding.parse(input.input.binding);
  const state = await trustedBinding(input.history, binding);
  if (input.mode === 'join' || input.mode === 'rebind') {
    const prepared = input.mode === 'join' ? await prepareJoinEnrolment(input.input, binding) : await rebindJoinEnrolment(input.input, binding);
    verifyEnrolmentTranscriptAgainstHistory(prepared.draft.transcript, state); return prepared;
  }
  const prepared = await preparePromotionEnrolment(input.input, binding);
  if (input.previous) {
    const previous = preparedEnrolment.parse(input.previous), prior = previous.draft.transcript;
    if (prior.binding.kind !== 'promote_owner' || prior.binding.operationId !== binding.operationId ||
      prior.binding.workspaceId !== binding.workspaceId || prior.binding.accountId !== binding.accountId ||
      prior.binding.approvalAttemptId === binding.approvalAttemptId || BigInt(binding.attemptGeneration) <= BigInt(prior.binding.attemptGeneration) ||
      Date.parse(binding.expiresAt) > Date.parse(prior.binding.expiresAt) || !same(prior.device, prepared.draft.transcript.device) ||
      prior.wrapperHash !== prepared.draft.transcript.wrapperHash || !prior.recovery || !prepared.draft.transcript.recovery ||
      prior.recovery.signingPublicKey !== prepared.draft.transcript.recovery.signingPublicKey ||
      prior.recovery.recipientPublicKey !== prepared.draft.transcript.recovery.recipientPublicKey) invalid();
    prepared.draft.transcript.recovery = prior.recovery;
    const keys = await recoveryKeys(input.input.newOwnerKit.phrase, { workspaceId: binding.workspaceId, accountId: binding.accountId });
    try { prepared.draft.newRecoveryConfirmation = await signObject(enrolmentConfirmationFor(prepared.draft.transcript,
      await digestObject(prepared.draft.transcript), 'new_recovery'), keys.signing.privateKey); }
    finally { keys.signing.privateKey.fill(0); keys.recipient.privateKey.fill(0); }
    await verifyPreparedEnrolment(prepared, input.input.exportKey, binding);
  }
  verifyEnrolmentTranscriptAgainstHistory(prepared.draft.transcript, state); return prepared;
}
export interface VerifyEnrolmentDraftInput { prepared: PreparedEnrolment; exportKey: string; history: SecurityHistoryInput }
export async function verifyEnrolmentDraft(input: VerifyEnrolmentDraftInput): Promise<{ verified: true }> {
  const accepted = copy(input), binding = accepted.prepared.draft.transcript.binding;
  const state = await trustedBinding(accepted.history, binding); verifyEnrolmentTranscriptAgainstHistory(accepted.prepared.draft.transcript, state);
  return verifyPreparedEnrolment(accepted.prepared, accepted.exportKey, binding);
}
export async function confirmEnrolmentTarget(input: VerifyEnrolmentDraftInput & { fingerprint: string }) {
  const accepted = copy(input), binding = accepted.prepared.draft.transcript.binding;
  const state = await trustedBinding(accepted.history, binding); verifyEnrolmentTranscriptAgainstHistory(accepted.prepared.draft.transcript, state);
  return confirmEnrolmentRecipient(accepted, binding);
}
export interface PrepareEnrolmentApprovalInput { draft: EnrolmentPublicDraft; fingerprint: string; history: SecurityHistoryInput; materials: PairingMaterial[] }
/** The pending profile is signed original intent, not editable server invitation metadata. */
async function verifyInvitationIntent(input: PrepareEnrolmentApprovalInput, workspaceKeyring: { epoch: string; key: string }[]) {
  const binding = input.draft.transcript.binding;
  if (binding.kind === 'promote_owner') return;
  const material = input.materials.find((entry) => entry.id === binding.profile.objectId);
  if (!material || material.kind !== 'encrypted_profile' || material.digest !== binding.profile.objectDigest ||
    await digestObject(material.value) !== binding.profile.objectDigest) throw new EnrolmentClientError('INCOMPLETE_KEYS');
  const envelope = contentEnvelope.parse(material.value), header = envelope.header;
  if (header.workspaceId !== binding.workspaceId || header.scope !== 'workspace' || header.scopeId !== binding.workspaceId ||
    header.recordId !== binding.accountId || header.recordType !== 'profile' || header.action !== 'profile.invite' ||
    header.operationId !== binding.operationId || header.revision !== binding.profile.revision || header.schema !== 1 ||
    header.approvalPolicyId !== null || header.approvalPolicyRevision !== null || BigInt(header.securityVersion) < 1n ||
    BigInt(header.securityVersion) > BigInt(input.history.expected.securityVersion)) invalid();
  // The complete independently anchored chain was checked above. Verify its historical
  // issuer prefix without applying the newer local rollback pin to this earlier prefix.
  const { pin: _pin, ...anchored } = input.history;
  const previous = await verifySecurityHistory({ ...anchored, transitions: input.history.transitions.slice(0, Number(BigInt(header.securityVersion) - 1n)),
    expected: { securityHead: header.securityHead, securityVersion: header.securityVersion } });
  const issuer = previous.profiles[header.accountId], signer = previous.devices[header.deviceId];
  if (!issuer?.active || !issuer.owner || !signer?.active || signer.accountId !== issuer.accountId || signer.keyGeneration !== header.keyGeneration ||
    header.dataGeneration !== previous.dataGeneration || header.keyEpoch !== previous.workspaceKeyEpoch) invalid();
  const entry = workspaceKeyring.find((key) => key.epoch === header.keyEpoch); if (!entry) throw new EnrolmentClientError('INCOMPLETE_KEYS');
  const key = base64urlDecode(entry.key, 32);
  try {
    const plaintext = invitedProfile.parse(await decryptContent(envelope, key, base64urlDecode(signer.signingPublicKey, 32), header)), intent = plaintext.invitation;
    const role = previous.roles[intent.role.id];
    if (!role || !same(intent.role, { id: role.id, revision: role.revision, permissions: role.permissions }) ||
      header.permissionVersion !== intent.role.revision || intent.workspaceId !== binding.workspaceId || intent.accountId !== binding.accountId ||
      intent.operationId !== binding.operationId || intent.kind !== binding.kind || !same(intent.role, binding.role) ||
      (intent.projectScope.mode === 'selected' && !same(intent.projectScope.projectIds, binding.scopes.filter((scope) => scope.scope === 'project').map((scope) => scope.scopeId).sort()))) invalid();
  } finally { key.fill(0); }
}
/** Current approving Owner keys and decoded scope keyrings stay inside the Worker. */
export async function prepareEnrolmentApproval(value: PrepareEnrolmentApprovalInput, bundle: DeviceBundle): Promise<EnrolmentApproval> {
  const input = copy(value), draft = enrolmentPublicDraft.parse(input.draft), transcript = draft.transcript, binding = transcript.binding;
  const state = await trustedBinding(input.history, binding), fingerprint = await verifyEnrolmentFingerprint(transcript, input.fingerprint, binding);
  verifyEnrolmentTranscriptAgainstHistory(transcript, state);
  if (bundle.signingPublicKey !== binding.authorizer.device.signingPublicKey || bundle.recipientPublicKey !== binding.authorizer.device.recipientPublicKey) invalid();
  if (!draft.recipientConfirmation) invalid();
  const holder = { workspaceId: binding.workspaceId, custodyEpoch: binding.custodyEpoch,
    approverAccountId: binding.authorizer.accountId, approverDevice: binding.authorizer.device };
  const payloads = await readDeviceScopeKeyMaterial({ scopes: binding.scopes, holder, history: state, materials: input.materials }, bundle);
  let profile: EnrolmentApproval['profile'] = null;
  if (binding.kind !== 'promote_owner') {
    const workspace = binding.scopes.find((scope) => scope.scope === 'workspace')!;
    const content = await readDeviceScopeKeyMaterial({ scopes: [{ ...workspace, mode: 'content', keyEpoch: binding.workspaceKeyEpoch }], holder, history: state, materials: input.materials }, bundle);
    const ring = z.object({ mode: z.literal('content'), keys: z.array(z.object({ epoch: z.string(), key: binary(32) })) }).parse(content[0]);
    await verifyInvitationIntent(input, ring.keys);
    const entry = ring.keys.find((key) => key.epoch === binding.workspaceKeyEpoch); if (!entry) throw new EnrolmentClientError('INCOMPLETE_KEYS');
    const key = base64urlDecode(entry.key, 32);
    try { profile = await encryptEnrolmentProfile(input, bundle, key, binding); } finally { key.fill(0); }
  }
  const signing = base64urlDecode(bundle.signingPrivateKey, 64), deliveries: EnrolmentApproval['deliveries'] = [], descriptors: EnrolmentApproval['transition']['body']['deliveries'] = [];
  try {
    for (const [index, scope] of binding.scopes.entries()) {
      const recipients = enrolmentRecipientDevices(transcript).map((device) => ({ kind: 'device' as const, id: device.id }));
      const all: { kind: 'device' | 'recovery'; id: string }[] = scope.mode === 'custody' ? [...recipients, { kind: 'recovery', id: transcript.recovery!.id }] : recipients;
      for (const recipient of all) {
        const id = crypto.randomUUID(), envelope = await sealRecipient(enrolmentRecipientHeader(transcript, fingerprint, scope, recipient.kind, recipient.id), payloads[index], signing);
        deliveries.push({ id, envelope }); descriptors.push({ id, scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch,
          recipientKind: recipient.kind, recipientId: recipient.id, digest: await digestObject(envelope) });
      }
    }
    const authorizerConfirmation = await confirmEnrolmentAuthorizer(input, bundle, binding);
    const transition = await signObject({ version: 1 as const, purpose: binding.kind === 'promote_owner' ? 'ukda.owner-promotion.v1' as const : 'ukda.profile-enrolment.v1' as const,
      transcript, transcriptDigest: fingerprint, recipientConfirmation: draft.recipientConfirmation, authorizerConfirmation,
      newRecoveryConfirmation: draft.newRecoveryConfirmation, deliveries: descriptors,
      profile: profile ? { id: profile.id, profileId: binding.accountId, revision: binding.nextProfileRevision, digest: await digestObject(profile.envelope) } : null }, signing);
    const approval = enrolmentApproval.parse({ transition, deliveries, profile });
    await validateEnrolmentPublicApproval(approval, binding, transcript.configuration); return approval;
  } finally { signing.fill(0); }
}
const materialSchema = z.strictObject({ id: identifier, digest, kind: z.string().max(64), value: z.unknown() });
export const enrolmentDelivery = z.strictObject({ receipt: enrolmentReceipt, deliveries: enrolmentApproval.shape.deliveries, materials: z.array(materialSchema).max(4096) });
export type EnrolmentDelivery = z.infer<typeof enrolmentDelivery>;
export interface VerifyEnrolmentDeliveryInput { delivery: EnrolmentDelivery; history: SecurityHistoryInput; newOwnerPhrase?: string }
export async function verifyEnrolmentDelivery(value: VerifyEnrolmentDeliveryInput, bundle: DeviceBundle): Promise<{ complete: true; scopeCount: number; displayName?: string }> {
  const input = copy(value), delivery = enrolmentDelivery.parse(input.delivery), transcript = delivery.receipt.transition.body.transcript, binding = transcript.binding;
  await validateEnrolmentReceipt(delivery.receipt, transcript);
  const state = await verifySecurityHistory(input.history), profile = state.profiles[binding.accountId], device = state.devices[transcript.device.id];
  if (state.origin !== binding.origin || state.workspaceId !== binding.workspaceId || state.genesisFingerprint !== binding.genesisFingerprint ||
    !input.history.transitions.some((transition) => same(transition, delivery.receipt.transition)) || BigInt(state.securityVersion) < BigInt(delivery.receipt.securityVersion) ||
    !profile?.active || !device?.active || device.accountId !== binding.accountId || device.keyGeneration !== transcript.device.keyGeneration ||
    bundle.signingPublicKey !== transcript.device.signingPublicKey || bundle.recipientPublicKey !== transcript.device.recipientPublicKey ||
    device.signingPublicKey !== bundle.signingPublicKey || device.recipientPublicKey !== bundle.recipientPublicKey ||
    profile.credentialGeneration !== binding.nextCredentialGeneration || profile.sessionGeneration !== binding.nextSessionGeneration ||
    profile.recoveryGeneration !== binding.nextRecoveryGeneration || profile.owner !== (binding.kind !== 'join_member') || state.dataGeneration !== binding.dataGeneration) invalid();
  const descriptors = delivery.receipt.transition.body.deliveries.filter((entry) => entry.recipientKind === 'recovery' || entry.recipientId === transcript.device.id);
  if (new Set(delivery.deliveries.map((entry) => entry.id)).size !== delivery.deliveries.length || delivery.deliveries.length !== descriptors.length) throw new EnrolmentClientError('INCOMPLETE_KEYS');
  const materials = new Map<string, PairingMaterial>();
  for (const material of [...delivery.materials, ...delivery.deliveries.map((entry) => ({ id: entry.id, kind: 'key_envelope',
    digest: descriptors.find((descriptor) => descriptor.id === entry.id)?.digest ?? '', value: entry.envelope }))]) {
    if (await digestObject(material.value) !== material.digest || (materials.has(material.id) && !same(materials.get(material.id), material))) throw new EnrolmentClientError('INCOMPLETE_KEYS');
    materials.set(material.id, material);
  }
  const scopes: PairingScope[] = [];
  for (const scope of binding.scopes) {
    const expected = descriptors.filter((entry) => entry.scope === scope.scope && entry.scopeId === scope.scopeId);
    for (const descriptor of expected) {
      const envelope = delivery.deliveries.find((entry) => entry.id === descriptor.id)?.envelope;
      if (!envelope || await digestObject(envelope) !== descriptor.digest || !await verifyRecipientEnvelope(envelope,
        base64urlDecode(binding.authorizer.device.signingPublicKey, 32), enrolmentRecipientHeader(transcript, delivery.receipt.transition.body.transcriptDigest,
          scope, descriptor.recipientKind, descriptor.recipientId))) throw new EnrolmentClientError('INCOMPLETE_KEYS');
    }
    const own = expected.find((entry) => entry.recipientKind === 'device' && entry.recipientId === transcript.device.id);
    const covers = (known: typeof profile.scopes[number]) => known.scope === scope.scope && known.scopeId === scope.scopeId && known.mode === scope.mode && known.keyEpoch === scope.keyEpoch &&
      scope.permissions.every((permission) => known.permissions.includes(permission)) && (known.expiresAt === null || Date.parse(known.expiresAt) > Date.now());
    if (!own || !profile.scopes.some(covers) || !device.scopes.some((known) => covers(known) &&
      known.manifests.some((manifest) => manifest.id === own.id && manifest.digest === own.digest)) ||
      (scope.mode === 'custody' && state.custodyEpoch !== binding.custodyEpoch) ||
      (scope.scope === 'workspace' && scope.mode === 'content' && scope.keyEpoch !== state.workspaceKeyEpoch)) invalid();
    scopes.push({ ...scope, sources: [{ grantId: binding.operationId, generation: '1', manifestId: own.id, manifestDigest: own.digest }] });
  }
  const holder = { workspaceId: binding.workspaceId, custodyEpoch: binding.custodyEpoch, approverAccountId: binding.accountId, approverDevice: transcript.device };
  const materialList = [...materials.values()];
  await readDeviceScopeKeyMaterial({ scopes, holder, history: state, materials: materialList }, bundle);
  if (transcript.recovery) {
    if (!input.newOwnerPhrase) throw new EnrolmentClientError('INCOMPLETE_KEYS');
    const keys = await recoveryKeys(input.newOwnerPhrase, { workspaceId: binding.workspaceId, accountId: binding.accountId });
    try {
      if (base64urlEncode(keys.signing.publicKey) !== transcript.recovery.signingPublicKey || base64urlEncode(keys.recipient.publicKey) !== transcript.recovery.recipientPublicKey) throw new EnrolmentClientError('INCOMPLETE_KEYS');
      await readRecoveryCustodyKeyMaterial({ accountId: binding.accountId, recoveryId: transcript.recovery.id, recoveryGeneration: transcript.recovery.generation,
        history: state, materials: materialList }, keys.recipient.privateKey);
    } finally { keys.signing.privateKey.fill(0); keys.recipient.privateKey.fill(0); }
  }
  const descriptor = delivery.receipt.transition.body.profile;
  let displayName: string | undefined;
  if (descriptor) {
    const material = materials.get(descriptor.id); if (!material || material.digest !== descriptor.digest) throw new EnrolmentClientError('INCOMPLETE_KEYS');
    const workspace = scopes.find((scope) => scope.scope === 'workspace')!;
    const payloads = await readDeviceScopeKeyMaterial({ scopes: [{ ...workspace, mode: 'content', keyEpoch: binding.workspaceKeyEpoch }], holder, history: state, materials: materialList }, bundle);
    const ring = z.object({ mode: z.literal('content'), keys: z.array(z.object({ epoch: z.string(), key: binary(32) })) }).parse(payloads[0]);
    const entry = ring.keys.find((key) => key.epoch === binding.workspaceKeyEpoch); if (!entry) throw new EnrolmentClientError('INCOMPLETE_KEYS');
    const key = base64urlDecode(entry.key, 32);
    try { displayName = z.strictObject({ displayName: z.string().min(1).max(200) }).parse(await decryptContent(contentEnvelope.parse(material.value), key,
      base64urlDecode(binding.authorizer.device.signingPublicKey, 32), enrolmentProfileHeader(transcript))).displayName; } finally { key.fill(0); }
  }
  return { complete: true, scopeCount: scopes.length, ...(displayName ? { displayName } : {}) };
}

type Reference = EnrolmentReference | EnrolmentOperationReference;
export interface EnrolmentTransport {
  readonly origin: string;
  issueJoin(input: z.infer<typeof enrolmentIssueJoin>, options?: AuthRequestOptions): Promise<EnrolmentIssuedJoin>;
  issuanceContext(input: z.infer<typeof enrolmentIssuanceRequest>, options?: AuthRequestOptions): Promise<EnrolmentIssuanceContext>;
  issuanceHistory(reference: EnrolmentOperationReference, options?: AuthRequestOptions): Promise<PairingHistoryResponse>;
  revokeJoin(reference: EnrolmentOperationReference, options?: AuthRequestOptions): Promise<EnrolmentView>;
  begin(input: { workspaceId: string; code: string; resumeToken: string }, options?: AuthRequestOptions): Promise<EnrolmentView>;
  beginPromotion(input: { workspaceId: string; accountId: string; operationId: string }, options?: AuthRequestOptions): Promise<EnrolmentView>;
  claimPromotion(reference: EnrolmentReference, options?: AuthRequestOptions): Promise<EnrolmentView>;
  stagePromotion(input: EnrolmentReference & { draft: EnrolmentDraft }, options?: AuthRequestOptions): Promise<EnrolmentView>;
  claim(reference: EnrolmentOperationReference, options?: AuthRequestOptions): Promise<EnrolmentView>;
  inspect(reference: Reference, options?: AuthRequestOptions): Promise<EnrolmentView>;
  status(reference: Reference, options?: AuthRequestOptions): Promise<EnrolmentView>;
  registration(input: EnrolmentReference & { registrationRequest: string }, options?: AuthRequestOptions): Promise<{ registrationResponse: string; configuration: OpaquePublicConfiguration }>;
  startProof(input: EnrolmentReference & { draft: EnrolmentDraft; startLoginRequest: string }, options?: AuthRequestOptions): Promise<{
    proofId: string; expiresAt: string; loginResponse: string; configuration: OpaquePublicConfiguration; draftHash: string }>;
  finishProof(input: EnrolmentReference & { proofId: string; finishLoginRequest: string }, options?: AuthRequestOptions): Promise<{ verified: true }>;
  unlockStart(input: EnrolmentReference & { startLoginRequest: string }, options?: AuthRequestOptions): Promise<{ proofId: string; expiresAt: string; loginResponse: string; configuration: OpaquePublicConfiguration }>;
  unlockFinish(input: EnrolmentReference & { proofId: string; finishLoginRequest: string }, options?: AuthRequestOptions): Promise<{ verified: true }>;
  confirm(input: Reference & { confirmation: EnrolmentDraft['recipientConfirmation'] }, options?: AuthRequestOptions): Promise<EnrolmentView>;
  materials(reference: EnrolmentOperationReference, options?: AuthRequestOptions): Promise<PairingMaterial[]>;
  stage(input: EnrolmentOperationReference & { approval: EnrolmentApproval }, options?: AuthRequestOptions): Promise<EnrolmentView>;
  finalize(input: EnrolmentOperationReference & { requestHash: string }, options?: AuthRequestOptions): Promise<{ receipt: EnrolmentReceipt }>;
  history(reference: Reference, mode: 'transcript' | 'current', options?: AuthRequestOptions): Promise<PairingHistoryResponse>;
  delivery(operationId: string, options?: AuthRequestOptions): Promise<EnrolmentDelivery>;
  cancel(reference: EnrolmentReference, options?: AuthRequestOptions): Promise<EnrolmentView>;
}
export class HttpEnrolmentTransport extends AuthenticatedHttp implements EnrolmentTransport {
  constructor(origin: string, private readonly csrfToken: () => string | undefined, fetcher?: typeof fetch) { super(origin, fetcher); }
  private request<T>(path: string, body: unknown, schema: z.ZodType<T>, options?: AuthRequestOptions, authenticated = false): Promise<T> {
    const csrfToken = this.csrfToken(); if (authenticated && !csrfToken) throw new AuthClientError('AUTH_REQUIRED');
    return this.post(`/v1/auth/enrolment/${path}`, body, schema, { ...options, ...(csrfToken ? { csrfToken } : {}) });
  }
  issueJoin(input: z.infer<typeof enrolmentIssueJoin>, options?: AuthRequestOptions) { return this.request('join/issue', input, enrolmentIssuedJoin, options, true); }
  issuanceContext(input: z.infer<typeof enrolmentIssuanceRequest>, options?: AuthRequestOptions) { return this.request('join/context', input, enrolmentIssuanceContext, options, true); }
  issuanceHistory(reference: EnrolmentOperationReference, options?: AuthRequestOptions) {
    return readSecurityHistoryPages(reference.operationId, 'current', (page) => { const { mode: _mode, ...cursor } = page;
      return this.request('join/history', { ...reference, ...cursor }, historyResponse, options, true); });
  }
  revokeJoin(reference: EnrolmentOperationReference, options?: AuthRequestOptions) { return this.request('join/revoke', reference, enrolmentView, options, true); }
  begin(input: { workspaceId: string; code: string; resumeToken: string }, options?: AuthRequestOptions) { return this.request('join/begin', input, enrolmentView, options); }
  beginPromotion(input: { workspaceId: string; accountId: string; operationId: string }, options?: AuthRequestOptions) { return this.request('promotion/begin', input, enrolmentView, options, true); }
  claimPromotion(reference: EnrolmentReference, options?: AuthRequestOptions) { return this.request('promotion/claim', reference, enrolmentView, options, true); }
  stagePromotion(input: EnrolmentReference & { draft: EnrolmentDraft }, options?: AuthRequestOptions) { return this.request('promotion/stage', input, enrolmentView, options, true); }
  claim(reference: EnrolmentOperationReference, options?: AuthRequestOptions) { return this.request('claim', reference, enrolmentView, options, true); }
  inspect(reference: Reference, options?: AuthRequestOptions) { return this.request('inspect', reference, enrolmentView, options, !('resumeToken' in reference)); }
  status(reference: Reference, options?: AuthRequestOptions) { return this.request('status', reference, enrolmentView, options, !('resumeToken' in reference)); }
  registration(input: EnrolmentReference & { registrationRequest: string }, options?: AuthRequestOptions) { return this.request('registration', input,
    z.strictObject({ registrationResponse: binary(1, 4096), configuration: genesisBody.shape.opaque }), options); }
  startProof(input: EnrolmentReference & { draft: EnrolmentDraft; startLoginRequest: string }, options?: AuthRequestOptions) { return this.request('proof/start', input,
    z.strictObject({ proofId: identifier, expiresAt: z.iso.datetime(), loginResponse: binary(1, 4096), configuration: genesisBody.shape.opaque, draftHash: digest }), options); }
  finishProof(input: EnrolmentReference & { proofId: string; finishLoginRequest: string }, options?: AuthRequestOptions) { return this.request('proof/finish', input, z.strictObject({ verified: z.literal(true) }), options); }
  unlockStart(input: EnrolmentReference & { startLoginRequest: string }, options?: AuthRequestOptions) { return this.request('unlock/start', input,
    z.strictObject({ proofId: identifier, expiresAt: z.iso.datetime(), loginResponse: binary(1, 4096), configuration: genesisBody.shape.opaque }), options); }
  unlockFinish(input: EnrolmentReference & { proofId: string; finishLoginRequest: string }, options?: AuthRequestOptions) { return this.request('unlock/finish', input, z.strictObject({ verified: z.literal(true) }), options); }
  confirm(input: Reference & { confirmation: EnrolmentDraft['recipientConfirmation'] }, options?: AuthRequestOptions) { return this.request('confirm', input, enrolmentView, options, !('resumeToken' in input)); }
  materials(reference: EnrolmentOperationReference, options?: AuthRequestOptions) { return this.request('materials', reference, z.array(materialSchema).max(4096), options, true); }
  stage(input: EnrolmentOperationReference & { approval: EnrolmentApproval }, options?: AuthRequestOptions) { return this.request('stage', input, enrolmentView, options, true); }
  finalize(input: EnrolmentOperationReference & { requestHash: string }, options?: AuthRequestOptions) { return this.request('finalize', input, z.object({ receipt: enrolmentReceipt }), options, true); }
  history(reference: Reference, mode: 'transcript' | 'current', options?: AuthRequestOptions) {
    return readSecurityHistoryPages(reference.operationId, mode, (page) => this.request('history', { ...reference, ...page }, historyResponse, options, mode === 'current' || !('resumeToken' in reference)));
  }
  delivery(operationId: string, options?: AuthRequestOptions) { return this.request('delivery', { operationId }, enrolmentDelivery, options, true); }
  cancel(reference: EnrolmentReference, options?: AuthRequestOptions) { return this.request('cancel', reference, enrolmentView, options); }
  protected override responseLimit(path: string): number { return ['/v1/auth/enrolment/history', '/v1/auth/enrolment/join/history'].includes(path) ? 3 * 1_048_576 : super.responseLimit(path); }
}

export interface EnrolmentProgress { localId: string; operation: EnrolmentOperationReference | null; state: string; fingerprint: string | null; deviceId: string | null }
export type EnrolmentResumeResult = EnrolmentProgress & { access: 'pending' | 'login_required' | 'recovery_kit_required' | 'content_ready' | 'incomplete_keys' };
/** Durable public/ciphertext state only; password/export keys are scoped to explicit calls and cleared on logout. */
export class EnrolmentController {
  private epoch = 0;
  private readonly requests = new Set<AbortController>();
  private readonly running = new Set<Promise<unknown>>();
  private readonly exports = new Map<string, string>();
  constructor(private readonly auth: AuthController, private readonly transport: EnrolmentTransport, private readonly devices: IndexedDeviceStore,
    readonly operations: IndexedEnrolmentStore, private readonly pins: IndexedPairingStore, private readonly options: { trustedServiceKeys?: Record<string, string>; remembered?: RememberedProfiles } = {}) {
    if (auth.origin !== transport.origin || auth.origin !== operations.origin || auth.origin !== pins.origin) invalid();
  }
  attachAuthLifecycle(): () => void {
    const clear = this.auth.onClear(() => this.clear()), forget = this.auth.onForget((reference) => this.forgetDevice(reference));
    return () => { clear(); forget(); };
  }
  clear(): void { this.epoch++; this.exports.clear(); for (const request of this.requests) request.abort(); }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    this.clear(); await Promise.allSettled([...this.running]); await this.operations.forgetDevice(reference);
  }
  private check(epoch: number): void { if (this.epoch !== epoch) throw new EnrolmentClientError('CANCELLED'); }
  private run<T>(work: (signal: AbortSignal, epoch: number) => Promise<T>): Promise<T> {
    const request = new AbortController(), epoch = this.epoch; this.requests.add(request);
    const result = work(request.signal, epoch).then((value) => { this.check(epoch); return value; }); this.running.add(result);
    void result.finally(() => { this.requests.delete(request); this.running.delete(result); }).catch(() => {}); return result;
  }
  private async save(record: EnrolmentRecord, value: EnrolmentRecord, epoch: number): Promise<EnrolmentRecord> {
    this.check(epoch); const next = { ...value, revision: record.revision + 1 };
    await this.operations.put(next, record.revision); this.check(epoch); return next;
  }
  private async recipient(localId: string): Promise<EnrolmentRecord> {
    const record = await this.operations.get('recipient', localId);
    if (!record || record.role !== 'recipient') throw new EnrolmentClientError('NOT_FOUND'); return record;
  }
  private reference(record: EnrolmentRecord): EnrolmentReference {
    if (!record.operationId || !record.resumeToken) throw new EnrolmentClientError('CONFLICT');
    return { workspaceId: record.workspaceId, operationId: record.operationId, resumeToken: record.resumeToken };
  }
  private progress(record: EnrolmentRecord): EnrolmentProgress {
    return { localId: record.localId, operation: record.operationId ? { workspaceId: record.workspaceId, operationId: record.operationId } : null,
      state: record.receipt ? 'completed' : record.view?.state ?? 'starting', fingerprint: record.view?.transcriptDigest ?? null, deviceId: record.deviceId };
  }
  private async acceptView(value: EnrolmentView, reference: EnrolmentOperationReference, accountId?: string | null): Promise<EnrolmentView> {
    const view = enrolmentView.parse(copy(value));
    if (view.workspaceId !== reference.workspaceId || view.operationId !== reference.operationId || (accountId && view.accountId !== accountId) ||
      (view.binding && (view.binding.origin !== this.auth.origin || view.binding.workspaceId !== view.workspaceId || view.binding.operationId !== view.operationId ||
        view.binding.accountId !== view.accountId || view.binding.kind !== view.kind)) ||
      (view.transcript && (!same(view.transcript.binding, view.binding) || view.transcriptDigest !== await digestObject(view.transcript) ||
        !view.publicDraft || !same(view.publicDraft.transcript, view.transcript)))) invalid();
    return view;
  }
  private async history(reference: Reference, binding: EnrolmentBinding, genesisFingerprint: string, signal: AbortSignal, receipt?: EnrolmentReceipt): Promise<SecurityHistoryInput> {
    const pin = await this.pins.pin(binding.workspaceId);
    if (genesisFingerprint !== binding.genesisFingerprint || (pin && pin.genesisFingerprint !== genesisFingerprint)) throw new EnrolmentClientError('TRUST_REQUIRED');
    const response = await this.transport.history(reference, receipt ? 'current' : 'transcript', { signal });
    if (!receipt && !same(response.anchor, { securityHead: binding.securityHead, securityVersion: binding.securityVersion })) invalid();
    if (receipt && (BigInt(response.anchor.securityVersion) < BigInt(receipt.securityVersion) || !same(response.anchor, response.current) ||
      !response.transitions.some((transition) => same(transition, receipt.transition)))) invalid();
    const input: SecurityHistoryInput = { workspaceId: binding.workspaceId, origin: binding.origin, genesisFingerprint,
      genesis: response.genesis, transitions: response.transitions, expected: response.anchor, ...(pin ? { pin } : {}), trustedServiceKeys: this.options.trustedServiceKeys ?? {} };
    const state = await verifySecurityHistory(input); if (!receipt) verifyEnrolmentBindingAgainstHistory(binding, state); return input;
  }
  private async newRecipient(workspaceId: string, localId: string, fingerprint: string, epoch: number, operationId: string | null = null): Promise<EnrolmentRecord> {
    const record: EnrolmentRecord = { version: 1, role: 'recipient', localId, revision: 1, origin: this.auth.origin, workspaceId,
      accountId: null, deviceId: null, operationId, resumeToken: base64urlEncode(crypto.getRandomValues(new Uint8Array(32))),
      genesisFingerprint: digest.parse(fingerprint), view: null, prepared: null, approval: null, receipt: null };
    this.check(epoch); await this.operations.put(record, 0); this.check(epoch); return record;
  }
  beginJoin(input: { workspaceId: string; code: string; genesisFingerprint?: string }, localId: string = crypto.randomUUID()): Promise<EnrolmentProgress> {
    return this.run(async (signal, epoch) => {
      const pin = await this.pins.pin(input.workspaceId); this.check(epoch);
      const fingerprint = input.genesisFingerprint ?? pin?.genesisFingerprint; if (!fingerprint) throw new EnrolmentClientError('TRUST_REQUIRED');
      if (pin && pin.genesisFingerprint !== fingerprint) throw new EnrolmentClientError('TRUST_REQUIRED');
      let record = await this.operations.get('recipient', localId); this.check(epoch);
      if (!record) record = await this.newRecipient(input.workspaceId, localId, fingerprint, epoch);
      if (record.workspaceId !== input.workspaceId || record.genesisFingerprint !== fingerprint || record.view?.kind === 'promote_owner') throw new EnrolmentClientError('CONFLICT');
      if (record.operationId) return this.progress(record);
      const value = await this.transport.begin({ workspaceId: input.workspaceId, code: input.code, resumeToken: record.resumeToken! }, { signal }); this.check(epoch);
      const view = await this.acceptView(value, { workspaceId: input.workspaceId, operationId: value.operationId }); this.check(epoch);
      if (view.kind === 'promote_owner') invalid();
      record = await this.save(record, { ...record, accountId: view.accountId, operationId: view.operationId, view }, epoch); return this.progress(record);
    });
  }
  issueEncryptedJoin(input: z.infer<typeof enrolmentIssueJoin>): Promise<EnrolmentIssuedJoin> { return this.run((signal) => this.transport.issueJoin(input, { signal })); }
  issueJoin(input: { kind: 'join_member' | 'join_owner'; roleId: string; projectIds: string[]; displayName: string; accountId?: string; operationId?: string }): Promise<EnrolmentIssuedJoin> {
    return this.run(async (signal, epoch) => {
      const current = this.auth.current(); if (current?.localAccess !== 'unlocked') throw new AuthClientError('AUTH_REQUIRED');
      const request = enrolmentIssuanceRequest.parse({ workspaceId: current.session.workspaceId, accountId: input.accountId ?? crypto.randomUUID(),
        operationId: input.operationId ?? crypto.randomUUID(), kind: input.kind, roleId: input.roleId, projectIds: input.projectIds });
      const pin = await this.pins.pin(request.workspaceId); this.check(epoch); if (!pin) throw new EnrolmentClientError('TRUST_REQUIRED');
      const context = await this.transport.issuanceContext(request, { signal }); this.check(epoch);
      const response = await this.transport.issuanceHistory({ workspaceId: request.workspaceId, operationId: request.operationId }, { signal }); this.check(epoch);
      if (!same(response.anchor, context.current) || !same(response.anchor, response.current) || context.genesisFingerprint !== pin.genesisFingerprint) invalid();
      const history: SecurityHistoryInput = { workspaceId: request.workspaceId, origin: this.auth.origin, genesisFingerprint: pin.genesisFingerprint,
        genesis: response.genesis, transitions: response.transitions, expected: response.anchor, pin, trustedServiceKeys: this.options.trustedServiceKeys ?? {} };
      const prepared = await this.auth.worker.prepareJoinInvitation({ request, context, history, displayName: input.displayName }, { signal }); this.check(epoch);
      await this.pins.recordVerifiedHistory(history); this.check(epoch);
      return this.transport.issueJoin(prepared, { signal });
    });
  }
  revokeJoin(reference: EnrolmentOperationReference): Promise<EnrolmentView> { return this.run((signal) => this.transport.revokeJoin(reference, { signal })); }
  beginPromotion(accountId: string, operationId: string = crypto.randomUUID()): Promise<EnrolmentView> {
    return this.run((signal) => { const current = this.auth.current(); if (current?.localAccess !== 'unlocked') throw new AuthClientError('AUTH_REQUIRED');
      return this.transport.beginPromotion({ workspaceId: current.session.workspaceId, accountId, operationId }, { signal }); });
  }
  claimPromotion(referenceValue: EnrolmentOperationReference, password: string, localId: string = crypto.randomUUID()): Promise<EnrolmentProgress> {
    return this.run(async (signal, epoch) => {
      const reference = enrolmentOperationReference.parse(referenceValue); await this.auth.reauthenticate(password); this.check(epoch);
      const current = this.auth.current(), pin = await this.pins.pin(reference.workspaceId); this.check(epoch);
      if (current?.localAccess !== 'unlocked' || !current.session.deviceId || current.session.workspaceId !== reference.workspaceId) throw new AuthClientError('AUTH_REQUIRED');
      if (!pin) throw new EnrolmentClientError('TRUST_REQUIRED');
      let record = await this.operations.get('recipient', localId); this.check(epoch);
      if (!record) record = await this.newRecipient(reference.workspaceId, localId, pin.genesisFingerprint, epoch, reference.operationId);
      if (record.operationId !== reference.operationId || record.workspaceId !== reference.workspaceId || (record.accountId && record.accountId !== current.session.accountId)) invalid();
      const view = await this.acceptView(await this.transport.claimPromotion(this.reference(record), { signal }), reference, current.session.accountId); this.check(epoch);
      if (view.kind !== 'promote_owner') invalid();
      record = await this.save(record, { ...record, accountId: current.session.accountId, deviceId: current.session.deviceId, view }, epoch); return this.progress(record);
    });
  }
  claim(referenceValue: EnrolmentOperationReference): Promise<EnrolmentProgress> {
    return this.run(async (signal, epoch) => {
      const reference = enrolmentOperationReference.parse(referenceValue), current = this.auth.current();
      if (current?.localAccess !== 'unlocked' || !current.session.deviceId || current.session.workspaceId !== reference.workspaceId) throw new AuthClientError('AUTH_REQUIRED');
      const pin = await this.pins.pin(reference.workspaceId); this.check(epoch); if (!pin) throw new EnrolmentClientError('TRUST_REQUIRED');
      const view = await this.acceptView(await this.transport.claim(reference, { signal }), reference); this.check(epoch);
      if (!view.binding || view.binding.authorizer.accountId !== current.session.accountId || view.binding.authorizer.device.id !== current.session.deviceId) invalid();
      const history = await this.history(reference, view.binding, pin.genesisFingerprint, signal); this.check(epoch);
      await this.pins.recordVerifiedHistory(history); this.check(epoch);
      const old = await this.operations.get('owner', reference.operationId); this.check(epoch);
      const sameAttempt = old?.view?.binding && same(old.view.binding, view.binding) && old.accountId === current.session.accountId && old.deviceId === current.session.deviceId;
      const record: EnrolmentRecord = { version: 1, role: 'owner', localId: reference.operationId, revision: (old?.revision ?? 0) + 1, origin: this.auth.origin,
        workspaceId: reference.workspaceId, accountId: current.session.accountId, deviceId: current.session.deviceId, operationId: reference.operationId,
        resumeToken: null, genesisFingerprint: pin.genesisFingerprint, view, prepared: null, approval: sameAttempt ? old?.approval ?? null : null, receipt: old?.receipt ?? null };
      await this.operations.put(record, old?.revision ?? 0); this.check(epoch); return this.progress(record);
    });
  }
  private async readback(record: EnrolmentRecord, exportKey: string, history: SecurityHistoryInput, signal: AbortSignal, epoch: number): Promise<void> {
    if (!record.prepared || !record.operationId) throw new EnrolmentClientError('CONFLICT');
    const transcript = record.prepared.draft.transcript, context = enrolmentDeviceContext(transcript);
    let wrapper: DeviceWrapper | undefined;
    if (transcript.binding.kind === 'promote_owner') wrapper = await this.devices.getActive(context.workspaceId, context.accountId, context.deviceId);
    else { this.check(epoch); await this.devices.stage(record.prepared.deviceWrapper, record.operationId); this.check(epoch); wrapper = await this.devices.getStaged(record.operationId); }
    this.check(epoch);
    if (!wrapper || await digestObject(wrapper) !== transcript.wrapperHash) throw new EnrolmentClientError('STORAGE');
    await this.auth.worker.verifyEnrolmentDraft({ prepared: { ...record.prepared, deviceWrapper: wrapper }, exportKey, history }, { signal }); this.check(epoch);
  }
  private async passwordProof(record: EnrolmentRecord, password: string, history: SecurityHistoryInput, signal: AbortSignal, epoch: number): Promise<string> {
    if (!record.prepared || record.prepared.draft.transcript.binding.kind === 'promote_owner') throw new EnrolmentClientError('CONFLICT');
    const draft = record.prepared.draft, start = await this.auth.worker.startLogin(password, { signal }); this.check(epoch);
    const response = await this.transport.startProof({ ...this.reference(record), draft, startLoginRequest: start.startLoginRequest }, { signal }); this.check(epoch);
    const checked = await validateEnrolmentDraft(draft, draft.transcript.binding, draft.transcript.configuration);
    if (!same(response.configuration, draft.transcript.configuration) || response.draftHash !== checked.draftHash) invalid();
    const finish = await this.auth.worker.finishLogin({ password, clientLoginState: start.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration }, { signal }); this.check(epoch);
    await this.readback(record, finish.exportKey, history, signal, epoch);
    await this.transport.finishProof({ ...this.reference(record), proofId: response.proofId, finishLoginRequest: finish.finishLoginRequest }, { signal }); this.check(epoch);
    this.exports.set(record.localId, finish.exportKey); return finish.exportKey;
  }
  prepare(localId: string, password: string, confirmation: string, displayName: string, newOwnerKit?: NewEnrolmentOwnerKit): Promise<EnrolmentProgress> {
    return this.run(async (signal, epoch) => {
      if (password !== confirmation) throw new EnrolmentClientError('PASSWORD_CONFIRMATION');
      let record = await this.recipient(localId);
      const view = await this.acceptView(await this.transport.status(this.reference(record), { signal }), this.reference(record), record.accountId); this.check(epoch);
      if (!view.binding || view.receipt || view.kind === 'promote_owner') throw new EnrolmentClientError('CONFLICT');
      const history = await this.history(this.reference(record), view.binding, record.genesisFingerprint, signal); this.check(epoch);
      if (!record.prepared) {
        const start = await this.auth.worker.startRegistration(password, { signal }); this.check(epoch);
        const response = await this.transport.registration({ ...this.reference(record), registrationRequest: start.registrationRequest }, { signal }); this.check(epoch);
        const result = await this.auth.worker.finishRegistration({ password, clientRegistrationState: start.clientRegistrationState,
          registrationResponse: response.registrationResponse, configuration: response.configuration }, { signal }); this.check(epoch);
        const prepared = await this.auth.worker.prepareEnrolmentDraft({ mode: 'join', history, input: { binding: view.binding,
          configuration: response.configuration, registrationRecord: result.registrationRecord, exportKey: result.exportKey, displayName, ...(newOwnerKit ? { newOwnerKit } : {}) } }, { signal }); this.check(epoch);
        record = await this.save(record, { ...record, view, prepared, deviceId: prepared.draft.transcript.device.id }, epoch);
        await this.readback(record, result.exportKey, history, signal, epoch);
        this.exports.set(localId, result.exportKey);
      } else if (!same(record.prepared.draft.transcript.binding, view.binding)) {
        // Possession of the retained password record unlocks local ciphertext but does not prove the new attempt.
        const start = await this.auth.worker.startLogin(password, { signal }); this.check(epoch);
        const response = await this.transport.unlockStart({ ...this.reference(record), startLoginRequest: start.startLoginRequest }, { signal }); this.check(epoch);
        if (!same(response.configuration, record.prepared.draft.transcript.configuration)) invalid();
        const result = await this.auth.worker.finishLogin({ password, clientLoginState: start.clientLoginState,
          loginResponse: response.loginResponse, configuration: response.configuration }, { signal }); this.check(epoch);
        await this.transport.unlockFinish({ ...this.reference(record), proofId: response.proofId, finishLoginRequest: result.finishLoginRequest }, { signal }); this.check(epoch);
        const prepared = await this.auth.worker.prepareEnrolmentDraft({ mode: 'rebind', history, input: { prepared: record.prepared, binding: view.binding,
          exportKey: result.exportKey, ...(newOwnerKit ? { newOwnerKit } : {}) } }, { signal }); this.check(epoch);
        record = await this.save(record, { ...record, view, prepared, approval: null }, epoch);
      }
      await this.passwordProof(record, password, history, signal, epoch);
      const accepted = await this.acceptView(await this.transport.status(this.reference(record), { signal }), this.reference(record), record.accountId); this.check(epoch);
      if (!same(accepted.transcript, record.prepared!.draft.transcript) || !accepted.passwordProved) invalid();
      await this.pins.recordVerifiedHistory(history); this.check(epoch);
      record = await this.save(record, { ...record, view: accepted }, epoch); return this.progress(record);
    });
  }
  preparePromotion(localId: string, password: string, newOwnerKit: NewEnrolmentOwnerKit): Promise<EnrolmentProgress> {
    return this.run(async (signal, epoch) => {
      let record = await this.recipient(localId);
      const view = await this.acceptView(await this.transport.status(this.reference(record), { signal }), this.reference(record), record.accountId); this.check(epoch);
      if (!view.binding || view.kind !== 'promote_owner' || view.receipt) throw new EnrolmentClientError('CONFLICT');
      const history = await this.history(this.reference(record), view.binding, record.genesisFingerprint, signal); this.check(epoch);
      await this.auth.reauthenticateWithExportKey(password, async (exportKey, session) => {
        this.check(epoch);
        if (!session.deviceId || session.accountId !== record.accountId || session.workspaceId !== record.workspaceId ||
          session.credentialGeneration !== view.binding!.credentialGeneration || session.sessionGeneration !== view.binding!.sessionGeneration) invalid();
        const wrapper = await this.devices.getActive(session.workspaceId, session.accountId, session.deviceId); this.check(epoch);
        if (!wrapper) throw new EnrolmentClientError('STORAGE');
        if (!record.prepared || !same(record.prepared.draft.transcript.binding, view.binding)) {
          const prepared = await this.auth.worker.prepareEnrolmentDraft({ mode: 'promotion', history, input: { binding: view.binding!, deviceId: session.deviceId,
            existingWrapper: wrapper, exportKey, newOwnerKit }, ...(record.prepared ? { previous: record.prepared } : {}) }, { signal }); this.check(epoch);
          record = await this.save(record, { ...record, view, prepared, deviceId: session.deviceId, approval: null }, epoch);
        }
        await this.readback(record, exportKey, history, signal, epoch); this.exports.set(localId, exportKey);
      }); this.check(epoch);
      const staged = await this.acceptView(await this.transport.stagePromotion({ ...this.reference(record), draft: record.prepared!.draft }, { signal }), this.reference(record), record.accountId); this.check(epoch);
      if (!same(staged.transcript, record.prepared!.draft.transcript)) invalid();
      await this.pins.recordVerifiedHistory(history); this.check(epoch);
      record = await this.save(record, { ...record, view: staged }, epoch); return this.progress(record);
    });
  }
  confirmRecipient(localId: string, fullFingerprint: string, password?: string): Promise<EnrolmentProgress> {
    return this.run(async (signal, epoch) => {
      let record = await this.recipient(localId); if (!record.prepared || record.receipt) throw new EnrolmentClientError('CONFLICT');
      const view = await this.acceptView(await this.transport.status(this.reference(record), { signal }), this.reference(record), record.accountId); this.check(epoch);
      const binding = record.prepared.draft.transcript.binding;
      if (!same(view.transcript, record.prepared.draft.transcript)) throw new EnrolmentClientError('CONFLICT');
      const history = await this.history(this.reference(record), binding, record.genesisFingerprint, signal); this.check(epoch);
      let exportKey = this.exports.get(localId);
      if (password !== undefined) {
        if (binding.kind === 'promote_owner') await this.auth.reauthenticateWithExportKey(password, async (value) => { this.check(epoch); exportKey = value; });
        else exportKey = await this.passwordProof(record, password, history, signal, epoch);
      }
      if (!exportKey) throw new AuthClientError('REAUTH_REQUIRED');
      await this.readback(record, exportKey, history, signal, epoch);
      const proof = await this.auth.worker.confirmEnrolmentTarget({ prepared: record.prepared, exportKey, history, fingerprint: fullFingerprint }, { signal }); this.check(epoch);
      record = await this.save(record, { ...record, prepared: { ...record.prepared, draft: { ...record.prepared.draft, recipientConfirmation: proof } } }, epoch);
      const confirmed = await this.acceptView(await this.transport.confirm({ ...this.reference(record), confirmation: proof }, { signal }), this.reference(record), record.accountId); this.check(epoch);
      if (!same(confirmed.recipientConfirmation, proof)) invalid();
      await this.pins.recordVerifiedHistory(history); this.check(epoch);
      record = await this.save(record, { ...record, view: confirmed }, epoch); return this.progress(record);
    });
  }
  approve(referenceValue: EnrolmentOperationReference, fullFingerprint: string): Promise<EnrolmentProgress> {
    return this.run(async (signal, epoch) => {
      const reference = enrolmentOperationReference.parse(referenceValue);
      let record = await this.operations.get('owner', reference.operationId); this.check(epoch);
      if (!record || record.workspaceId !== reference.workspaceId) throw new EnrolmentClientError('NOT_FOUND');
      const current = this.auth.current();
      if (current?.localAccess !== 'unlocked' || current.session.accountId !== record.accountId || current.session.deviceId !== record.deviceId) throw new AuthClientError('AUTH_REQUIRED');
      const view = await this.acceptView(await this.transport.inspect(reference, { signal }), reference); this.check(epoch);
      if (view.receipt) {
        if (!record.approval) throw new EnrolmentClientError('CONFLICT');
        const receipt = await validateEnrolmentReceipt(view.receipt, record.approval.transition.body.transcript);
        if (!same(receipt.transition, record.approval.transition)) invalid();
        record = await this.save(record, { ...record, view, receipt }, epoch); return this.progress(record);
      }
      if (!view.binding || !view.publicDraft || !view.transcript || !view.recipientConfirmation || !same(view.binding, record.view?.binding)) throw new EnrolmentClientError('CONFLICT');
      await verifyEnrolmentFingerprint(view.transcript, fullFingerprint, view.binding);
      const history = await this.history(reference, view.binding, record.genesisFingerprint, signal); this.check(epoch);
      if (!record.approval) {
        const materials = await this.transport.materials(reference, { signal }); this.check(epoch);
        const approval = await this.auth.worker.prepareEnrolmentApproval({ draft: view.publicDraft, fingerprint: fullFingerprint, history, materials }, { signal }); this.check(epoch);
        record = await this.save(record, { ...record, view, approval }, epoch);
      }
      const approval = record.approval!;
      if (!same(approval.transition.body.transcript, view.transcript)) throw new EnrolmentClientError('CONFLICT');
      await validateEnrolmentPublicApproval(approval, view.binding, view.transcript.configuration);
      await this.transport.confirm({ ...reference, confirmation: approval.transition.body.authorizerConfirmation }, { signal }); this.check(epoch);
      const staged = await this.acceptView(await this.transport.stage({ ...reference, approval }, { signal }), reference); this.check(epoch);
      if (!staged.approvalStaged || !staged.requestHash || staged.approvalHash !== await digestObject(approval)) invalid();
      record = await this.save(record, { ...record, view: staged }, epoch);
      const result = await this.transport.finalize({ ...reference, requestHash: staged.requestHash }, { signal }); this.check(epoch);
      const receipt = await validateEnrolmentReceipt(result.receipt, approval.transition.body.transcript);
      if (receipt.requestHash !== staged.requestHash || !same(receipt.transition, approval.transition)) invalid();
      record = await this.save(record, { ...record, receipt }, epoch); return this.progress(record);
    });
  }
  private async acceptReceipt(record: EnrolmentRecord, value: EnrolmentReceipt, epoch: number): Promise<EnrolmentRecord> {
    if (!record.prepared || !record.prepared.draft.recipientConfirmation) throw new EnrolmentClientError('CONFLICT');
    const receipt = await validateEnrolmentReceipt(value, record.prepared.draft.transcript); this.check(epoch);
    if ((record.receipt && !same(record.receipt, receipt)) || !same(receipt.transition.body.recipientConfirmation, record.prepared.draft.recipientConfirmation) ||
      !same(receipt.transition.body.newRecoveryConfirmation, record.prepared.draft.newRecoveryConfirmation)) invalid();
    record = await this.save(record, { ...record, receipt }, epoch);
    if (record.prepared!.draft.transcript.binding.kind !== 'promote_owner') {
      await this.devices.stage(record.prepared!.deviceWrapper, receipt.operationId); this.check(epoch);
      await this.devices.commit(receipt.operationId, { ...enrolmentDeviceContext(record.prepared!.draft.transcript), operationId: receipt.operationId }); this.check(epoch);
    } else {
      const context = enrolmentDeviceContext(record.prepared!.draft.transcript), wrapper = await this.devices.getActive(context.workspaceId, context.accountId, context.deviceId); this.check(epoch);
      if (!wrapper || await digestObject(wrapper) !== receipt.wrapperHash) throw new EnrolmentClientError('STORAGE');
    }
    this.exports.delete(record.localId); return record;
  }
  resume(localId: string, newOwnerPhrase?: string): Promise<EnrolmentResumeResult> {
    return this.run(async (signal, epoch) => {
      let record = await this.recipient(localId); if (!record.operationId) return { ...this.progress(record), access: 'pending' };
      const reference = this.reference(record), view = await this.acceptView(await this.transport.status(reference, { signal }), reference, record.accountId); this.check(epoch);
      if (!view.receipt) { record = await this.save(record, { ...record, view }, epoch); return { ...this.progress(record), access: 'pending' }; }
      record = await this.acceptReceipt(record, view.receipt, epoch);
      const current = this.auth.current(), receipt = record.receipt!, binding = record.prepared!.draft.transcript.binding;
      if (current?.localAccess !== 'unlocked' || current.session.workspaceId !== receipt.workspaceId || current.session.accountId !== receipt.accountId ||
        current.session.deviceId !== receipt.deviceId || current.session.credentialGeneration !== receipt.credentialGeneration ||
        current.session.sessionGeneration !== receipt.sessionGeneration || current.session.dataGeneration !== receipt.dataGeneration) return { ...this.progress(record), access: 'login_required' };
      if (binding.kind !== 'join_member' && !newOwnerPhrase) return { ...this.progress(record), access: 'recovery_kit_required' };
      const history = await this.history(reference, binding, record.genesisFingerprint, signal, receipt); this.check(epoch);
      const delivery = await this.transport.delivery(receipt.operationId, { signal }); this.check(epoch); if (!same(delivery.receipt, receipt)) invalid();
      try {
        const verified = await this.auth.worker.verifyEnrolmentDelivery({ delivery, history, ...(newOwnerPhrase ? { newOwnerPhrase } : {}) }, { signal }); this.check(epoch);
        if (verified.displayName && this.options.remembered) { await this.options.remembered.remember({ workspaceId: receipt.workspaceId,
          accountId: receipt.accountId, deviceId: receipt.deviceId, displayName: verified.displayName }); this.check(epoch); }
      }
      catch (error) { this.check(epoch); if (error && typeof error === 'object' && 'code' in error && error.code === 'INCOMPLETE_KEYS') return { ...this.progress(record), access: 'incomplete_keys' }; throw error; }
      await this.pins.recordVerifiedHistory(history); this.check(epoch); return { ...this.progress(record), access: 'content_ready' };
    });
  }
  cancel(localId: string): Promise<EnrolmentProgress> {
    return this.run(async (signal, epoch) => {
      const metadata = await this.operations.capability(localId); this.check(epoch); if (!metadata) throw new EnrolmentClientError('NOT_FOUND');
      const reference = { workspaceId: metadata.workspaceId, operationId: metadata.operationId, resumeToken: metadata.resumeToken };
      const view = await this.acceptView(await this.transport.cancel(reference, { signal }), reference, metadata.accountId); this.check(epoch);
      if (view.receipt) return this.progress(await this.acceptReceipt(await this.recipient(localId), view.receipt, epoch));
      if (!['cancelled', 'expired', 'revoked'].includes(view.state)) throw new EnrolmentClientError('CONFLICT');
      if (!metadata.promotion) { await this.devices.discardUncommitted(metadata.operationId, metadata.deviceId ?? undefined); this.check(epoch); }
      await this.operations.discardCancelled(localId, reference); this.check(epoch); this.exports.delete(localId);
      return { localId, operation: { workspaceId: metadata.workspaceId, operationId: metadata.operationId }, state: view.state, fingerprint: view.transcriptDigest, deviceId: metadata.deviceId };
    });
  }
}

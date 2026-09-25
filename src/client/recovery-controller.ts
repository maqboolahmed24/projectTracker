import { z } from 'zod';
import { genesisBody } from '../shared/activation.js';
import { binary, digest, identifier } from '../shared/contracts.js';
import { base64urlDecode, base64urlEncode, canonicalJson, digestObject, generateRecipientKeyPair, generateSigningKeyPair,
  sealRecipient, signObject, verifyRecipientEnvelope } from '../shared/crypto.js';
import { recoveryBinding, recoveryTranscript, recoveryDraft, recoveryPhraseChallenge, recoveryConfirmationFor,
  recoveryRecipientHeader, recoveryApproval, recoveryReceipt, recoveryView, recoveryReference, recoveryOperationReference,
  recoveryIssuedReset, validateRecoveryDraft, validateRecoveryApproval, validateRecoveryReceipt, validateRecoveryTransition, validateRecoveryPublicApproval, recoveryConfirmation, recoveryResult,
  type RecoveryBinding, type RecoveryTranscript, type RecoveryDraft, type RecoveryPhraseChallenge, type RecoveryPhraseProof,
  type RecoveryConfirmation, type RecoveryApproval, type RecoveryReceipt, type RecoveryReference,
  type RecoveryOperationReference, type RecoveryView, type RecoveryIssuedReset, type RecoveryResult } from '../shared/recovery.js';
import { verifyRecoveryBindingAgainstHistory, verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState } from '../shared/security-history.js';
import { deviceWrapper, IndexedDeviceStore, unwrapDeviceBundle, wrapDeviceBundle, type DeviceBundle, type DeviceContext, type DeviceWrapper } from './device-store.js';
import { readDeviceScopeKeyMaterial, readRecoveryCustodyKeyMaterial, IndexedPairingStore, readSecurityHistoryPages, historyResponse, type PairingHistoryResponse } from './pairing.js';
import type { PairingMaterial, PairingScope } from '../shared/pairing.js';
import { recoveryKeys, verifyRecoveryWords } from './recovery.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import type { OpaquePublicConfiguration } from './opaque.js';

export class RecoveryClientError extends Error {
  constructor(readonly code: 'INVALID_RECOVERY' | 'FINGERPRINT_MISMATCH' | 'TRUST_REQUIRED' | 'INCOMPLETE_KEYS' | 'CONFLICT' | 'STORAGE' | 'NOT_FOUND' | 'CANCELLED' | 'PASSWORD_CONFIRMATION') {
    super(`Account recovery failed (${code})`); this.name = 'RecoveryClientError';
  }
}
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
const same = (left: unknown, right: unknown) => canonicalJson(left) === canonicalJson(right);
function invalid(): never { throw new RecoveryClientError('INVALID_RECOVERY'); }
function fresh(binding: { issuedAt: string; expiresAt: string }) {
  if (Date.parse(binding.expiresAt) <= Date.now() || Date.parse(binding.issuedAt) > Date.now() + 30_000) invalid();
}
export function recoveryDeviceContext(transcript: RecoveryTranscript): DeviceContext {
  return { workspaceId: transcript.binding.workspaceId, accountId: transcript.binding.accountId,
    deviceId: transcript.device.id, credentialGeneration: transcript.binding.nextCredentialGeneration };
}
export const recoveryKitIdentity = z.strictObject({ origin: z.string(), workspaceId: identifier, accountId: identifier, genesisFingerprint: digest });
export type RecoveryKitIdentity = z.infer<typeof recoveryKitIdentity>;
export const proveOwnerPhraseInput = z.strictObject({ challenge: recoveryPhraseChallenge, kit: recoveryKitIdentity, phrase: z.string().max(512) });
export type ProveOwnerPhraseInput = z.infer<typeof proveOwnerPhraseInput>;
/** Possession challenge only. Full independently anchored history is required before custody is opened. */
export async function proveOwnerPhrase(input: ProveOwnerPhraseInput): Promise<RecoveryPhraseProof> {
  const accepted = proveOwnerPhraseInput.parse(copy(input)), { challenge, kit } = accepted, binding = challenge.binding;
  fresh(challenge); fresh(binding);
  if (binding.authorizer.kind !== 'phrase' || kit.origin !== binding.origin || kit.workspaceId !== binding.workspaceId ||
    kit.accountId !== binding.accountId || kit.genesisFingerprint !== binding.genesisFingerprint) invalid();
  const keys = await recoveryKeys(accepted.phrase, { workspaceId: kit.workspaceId, accountId: kit.accountId });
  try {
    if (base64urlEncode(keys.signing.publicKey) !== binding.authorizer.recovery.signingPublicKey ||
      base64urlEncode(keys.recipient.publicKey) !== binding.authorizer.recovery.recipientPublicKey) invalid();
    return signObject(challenge, keys.signing.privateKey);
  } finally { keys.signing.privateKey.fill(0); keys.recipient.privateKey.fill(0); }
}
export const prepareRecoveryDraftInput = z.strictObject({ binding: recoveryBinding, configuration: genesisBody.shape.opaque,
  registrationRecord: binary(1, 4096), exportKey: binary(32, 1024),
  newOwnerKit: z.strictObject({ phrase: z.string().max(512), positions: z.array(z.number().int()).length(3), answers: z.array(z.string().max(32)).length(3) }).optional() });
export type PrepareRecoveryDraftInput = z.infer<typeof prepareRecoveryDraftInput>;
export const verifyRecoveryDraftWrapperInput = z.strictObject({ draft: recoveryDraft, wrapper: deviceWrapper, exportKey: binary(32, 1024) });
export type VerifyRecoveryDraftWrapperInput = z.infer<typeof verifyRecoveryDraftWrapperInput>;
/** Private key material exists only in the Worker; returned draft/wrapper contain no password or phrase. */
export async function prepareRecoveryDraft(input: PrepareRecoveryDraftInput): Promise<{ draft: RecoveryDraft; wrapper: DeviceWrapper }> {
  const accepted = prepareRecoveryDraftInput.parse(copy(input)), binding = accepted.binding;
  fresh(binding);
  if (binding.isOwner !== !!accepted.newOwnerKit) invalid();
  if (accepted.newOwnerKit) verifyRecoveryWords(accepted.newOwnerKit.phrase, accepted.newOwnerKit.positions, accepted.newOwnerKit.answers);
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  let recovery: Awaited<ReturnType<typeof recoveryKeys>> | undefined;
  try {
    if (accepted.newOwnerKit) recovery = await recoveryKeys(accepted.newOwnerKit.phrase, { workspaceId: binding.workspaceId, accountId: binding.accountId });
    const device = { id: crypto.randomUUID(), keyGeneration: binding.nextDeviceKeyGeneration,
      signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
    const context = { workspaceId: binding.workspaceId, accountId: binding.accountId, deviceId: device.id, credentialGeneration: binding.nextCredentialGeneration };
    const wrapper = await wrapDeviceBundle(context, { signingPrivateKey: base64urlEncode(signing.privateKey), recipientPrivateKey: base64urlEncode(recipient.privateKey),
      signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey }, accepted.exportKey);
    const transcript = recoveryTranscript.parse({ version: 1, purpose: 'ukda.recovery-transcript.v1', binding, device,
      recovery: recovery ? { id: crypto.randomUUID(), generation: binding.nextRecoveryGeneration, signingPublicKey: base64urlEncode(recovery.signing.publicKey), recipientPublicKey: base64urlEncode(recovery.recipient.publicKey) } : null,
      configuration: accepted.configuration, registrationRecordHash: await digestObject(accepted.registrationRecord), wrapperHash: await digestObject(wrapper) });
    const transcriptDigest = await digestObject(transcript);
    const draft: RecoveryDraft = { transcript, registrationRecord: accepted.registrationRecord, recipientConfirmation: null,
      newRecoveryConfirmation: recovery ? await signObject(recoveryConfirmationFor(transcript, transcriptDigest, 'new_recovery'), recovery.signing.privateKey) : null };
    await verifyRecoveryDraftWrapper({ draft, wrapper, exportKey: accepted.exportKey });
    return { draft, wrapper };
  } finally { signing.privateKey.fill(0); recipient.privateKey.fill(0); recovery?.signing.privateKey.fill(0); recovery?.recipient.privateKey.fill(0); }
}
async function recoveryBundle(input: VerifyRecoveryDraftWrapperInput): Promise<DeviceBundle> {
  const accepted = verifyRecoveryDraftWrapperInput.parse(copy({ draft: input.draft, wrapper: input.wrapper, exportKey: input.exportKey })), transcript = accepted.draft.transcript;
  await validateRecoveryDraft(accepted.draft, transcript.binding, transcript.configuration);
  if (await digestObject(accepted.wrapper) !== transcript.wrapperHash) invalid();
  const bundle = await unwrapDeviceBundle(recoveryDeviceContext(transcript), accepted.wrapper, accepted.exportKey);
  if (bundle.signingPublicKey !== transcript.device.signingPublicKey || bundle.recipientPublicKey !== transcript.device.recipientPublicKey) invalid();
  return bundle;
}
export async function verifyRecoveryDraftWrapper(input: VerifyRecoveryDraftWrapperInput): Promise<{ verified: true }> {
  await recoveryBundle(input); return { verified: true };
}
async function trustedBinding(input: SecurityHistoryInput, binding: RecoveryBinding): Promise<SecurityHistoryState> {
  const state = await verifySecurityHistory(input);
  verifyRecoveryBindingAgainstHistory(binding, state);
  return state;
}
export async function verifyRecoveryFingerprint(transcript: RecoveryTranscript, supplied: string): Promise<string> {
  const accepted = recoveryTranscript.parse(copy(transcript)), normalized = typeof supplied === 'string' ? supplied.trim().toLowerCase() : '';
  const actual = await digestObject(accepted);
  if (!digest.safeParse(normalized).success || normalized !== actual) throw new RecoveryClientError('FINGERPRINT_MISMATCH');
  fresh(accepted.binding); return actual;
}
export interface ConfirmRecoveryRecipientInput extends VerifyRecoveryDraftWrapperInput { fingerprint: string; history: SecurityHistoryInput }
export async function confirmRecoveryRecipient(input: ConfirmRecoveryRecipientInput): Promise<RecoveryConfirmation> {
  const transcript = recoveryTranscript.parse(copy(input.draft.transcript)), fingerprint = await verifyRecoveryFingerprint(transcript, input.fingerprint);
  await trustedBinding(input.history, transcript.binding);
  const bundle = await recoveryBundle(input), signing = base64urlDecode(bundle.signingPrivateKey, 64);
  try { return signObject(recoveryConfirmationFor(transcript, fingerprint, 'recipient'), signing); } finally { signing.fill(0); }
}
const publicRecoveryDraft = z.strictObject({ transcript: recoveryTranscript, recipientConfirmation: recoveryConfirmation.nullable(), newRecoveryConfirmation: recoveryConfirmation.nullable() });
export interface PrepareRecoveryApprovalInput { draft: Pick<RecoveryDraft, 'transcript' | 'recipientConfirmation' | 'newRecoveryConfirmation'>; fingerprint: string; history: SecurityHistoryInput; materials: PairingMaterial[] }
export interface PreparePhraseRecoveryApprovalInput extends PrepareRecoveryApprovalInput { draft: RecoveryDraft; wrapper: DeviceWrapper; exportKey: string; phrase: string; kit: RecoveryKitIdentity }
async function prepareApproval(input: PrepareRecoveryApprovalInput, payloads: unknown[], envelopeKey: Uint8Array, authorityKey: Uint8Array): Promise<RecoveryApproval> {
  const draft = publicRecoveryDraft.parse(copy({ transcript: input.draft.transcript, recipientConfirmation: input.draft.recipientConfirmation, newRecoveryConfirmation: input.draft.newRecoveryConfirmation })), transcript = draft.transcript, fingerprint = await verifyRecoveryFingerprint(transcript, input.fingerprint);
  if (!draft.recipientConfirmation || payloads.length !== transcript.binding.scopes.length) invalid();
  const deliveries: RecoveryApproval['deliveries'] = [];
  const descriptors: RecoveryApproval['transition']['body']['deliveries'] = [];
  for (const [index, scope] of transcript.binding.scopes.entries()) {
    const kinds: ('device' | 'recovery')[] = scope.mode === 'custody' ? ['device', 'recovery'] : ['device'];
    for (const kind of kinds) {
      const id = crypto.randomUUID(), envelope = await sealRecipient(recoveryRecipientHeader(transcript, fingerprint, scope, kind), payloads[index], envelopeKey);
      deliveries.push({ id, envelope }); descriptors.push({ id, scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch,
        recipientKind: kind, recipientId: kind === 'device' ? transcript.device.id : transcript.recovery!.id, digest: await digestObject(envelope) });
    }
  }
  const authorizerConfirmation = await signObject(recoveryConfirmationFor(transcript, fingerprint, 'authorizer'), authorityKey);
  const transition = await signObject({ version: 1 as const, purpose: 'ukda.account-recovery.v1' as const, transcript, transcriptDigest: fingerprint,
    recipientConfirmation: draft.recipientConfirmation, authorizerConfirmation, newRecoveryConfirmation: draft.newRecoveryConfirmation,
    deliveries: descriptors, revokeAllDevices: true as const, revokeAllSessions: true as const }, authorityKey);
  const approval = recoveryApproval.parse({ transition, deliveries });
  await validateRecoveryPublicApproval(approval, transcript.binding, transcript.configuration);
  return approval;
}
/** Phrase authority opens only the verified current custody. Newly generated device signs its new envelopes. */
export async function preparePhraseRecoveryApproval(input: PreparePhraseRecoveryApprovalInput): Promise<RecoveryApproval> {
  const draft = recoveryDraft.parse(copy(input.draft)), binding = draft.transcript.binding, kit = recoveryKitIdentity.parse(input.kit);
  await verifyRecoveryFingerprint(draft.transcript, input.fingerprint);
  const state = await trustedBinding(input.history, binding);
  if (binding.authorizer.kind !== 'phrase' || kit.origin !== binding.origin || kit.workspaceId !== binding.workspaceId || kit.accountId !== binding.accountId || kit.genesisFingerprint !== state.genesisFingerprint) invalid();
  const keys = await recoveryKeys(input.phrase, { workspaceId: binding.workspaceId, accountId: binding.accountId });
  let signing: Uint8Array | undefined;
  try {
    const bundle = await recoveryBundle(input); signing = base64urlDecode(bundle.signingPrivateKey, 64);
    if (base64urlEncode(keys.signing.publicKey) !== binding.authorizer.recovery.signingPublicKey || base64urlEncode(keys.recipient.publicKey) !== binding.authorizer.recovery.recipientPublicKey) invalid();
    const custody = await readRecoveryCustodyKeyMaterial({ accountId: binding.accountId, recoveryId: binding.authorizer.recovery.id,
      recoveryGeneration: binding.authorizer.recovery.generation, history: state, materials: input.materials }, keys.recipient.privateKey);
    const payloads = binding.scopes.map((scope) => {
      if (scope.mode === 'custody') return custody.payload;
      const entries = scope.scope === 'workspace' ? custody.manifest.workspaceKeys : custody.manifest.projectKeys.find((item) => item.projectId === scope.scopeId)?.keys;
      if (!entries?.some((item) => item.epoch === scope.keyEpoch)) throw new RecoveryClientError('INCOMPLETE_KEYS');
      return { version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, keys: entries };
    });
    return await prepareApproval(input, payloads, signing, keys.signing.privateKey);
  } finally { keys.signing.privateKey.fill(0); keys.recipient.privateKey.fill(0); signing?.fill(0); }
}
/** Current approved Owner keys remain cached inside the Worker and never leave this operation. */
export async function prepareOwnerRecoveryApproval(input: PrepareRecoveryApprovalInput, bundle: DeviceBundle): Promise<RecoveryApproval> {
  const draft = publicRecoveryDraft.parse(copy(input.draft)), binding = draft.transcript.binding;
  await verifyRecoveryFingerprint(draft.transcript, input.fingerprint);
  const state = await trustedBinding(input.history, binding);
  if (binding.authorizer.kind !== 'owner_reset' || bundle.signingPublicKey !== binding.authorizer.device.signingPublicKey || bundle.recipientPublicKey !== binding.authorizer.device.recipientPublicKey) invalid();
  const payloads = await readDeviceScopeKeyMaterial({ scopes: binding.scopes, history: state, materials: input.materials,
    holder: { workspaceId: binding.workspaceId, custodyEpoch: binding.custodyEpoch, approverAccountId: binding.authorizer.accountId, approverDevice: binding.authorizer.device } }, bundle);
  const signing = base64urlDecode(bundle.signingPrivateKey, 64);
  try { return await prepareApproval(input, payloads, signing, signing); } finally { signing.fill(0); }
}
const materialSchema = z.strictObject({ id: identifier, digest, kind: z.string().max(64), value: z.unknown() });
export const recoveryDelivery = z.strictObject({ receipt: recoveryReceipt, deliveries: recoveryApproval.shape.deliveries, materials: z.array(materialSchema).max(4096) });
export type RecoveryDelivery = z.infer<typeof recoveryDelivery>;
export interface VerifyRecoveryDeliveryInput { delivery: RecoveryDelivery; history: SecurityHistoryInput; newOwnerPhrase?: string }
/** Every eligible encrypted scope must decrypt successfully before declaring this device content-ready. */
export async function verifyRecoveryDelivery(input: VerifyRecoveryDeliveryInput, bundle: DeviceBundle): Promise<{ complete: true; scopeCount: number }> {
  const delivery = recoveryDelivery.parse(copy(input.delivery)), transcript = delivery.receipt.transition.body.transcript, binding = transcript.binding;
  await validateRecoveryReceipt(delivery.receipt, transcript);
  const state = await verifySecurityHistory(input.history), device = state.devices[transcript.device.id], profile = state.profiles[binding.accountId];
  if (state.origin !== binding.origin || state.workspaceId !== binding.workspaceId || state.genesisFingerprint !== binding.genesisFingerprint ||
    !input.history.transitions.some((item) => same(item, delivery.receipt.transition)) || BigInt(state.securityVersion) < BigInt(delivery.receipt.securityVersion) ||
    !device?.active || !profile?.active || device.accountId !== binding.accountId || device.keyGeneration !== binding.nextDeviceKeyGeneration ||
    device.signingPublicKey !== bundle.signingPublicKey || device.recipientPublicKey !== bundle.recipientPublicKey ||
    bundle.signingPublicKey !== transcript.device.signingPublicKey || bundle.recipientPublicKey !== transcript.device.recipientPublicKey ||
    profile.credentialGeneration !== binding.nextCredentialGeneration || profile.sessionGeneration !== binding.nextSessionGeneration || state.dataGeneration !== binding.dataGeneration) invalid();
  if (new Set(delivery.deliveries.map((item) => item.id)).size !== delivery.deliveries.length || delivery.deliveries.length !== delivery.receipt.transition.body.deliveries.length) throw new RecoveryClientError('INCOMPLETE_KEYS');
  const sender = binding.authorizer.kind === 'phrase' ? transcript.device : binding.authorizer.device;
  // The authenticated delivery endpoint may include the same committed envelope in
  // both its delivery list and source-material list; duplicates must agree exactly.
  const materialMap = new Map<string, PairingMaterial>();
  for (const material of [...delivery.materials, ...delivery.deliveries.map((item) => ({ id: item.id, kind: 'key_envelope',
    digest: delivery.receipt.transition.body.deliveries.find((entry) => entry.id === item.id)?.digest ?? '', value: item.envelope }))]) {
    if (await digestObject(material.value) !== material.digest || (materialMap.has(material.id) && !same(materialMap.get(material.id), material))) throw new RecoveryClientError('INCOMPLETE_KEYS');
    materialMap.set(material.id, material);
  }
  const materials = [...materialMap.values()];
  const scopes: PairingScope[] = [];
  for (const scope of binding.scopes) {
    const descriptors = delivery.receipt.transition.body.deliveries.filter((item) => item.scope === scope.scope && item.scopeId === scope.scopeId);
    const descriptor = descriptors.find((item) => item.recipientKind === 'device');
    if (!descriptor || (scope.mode === 'custody' && (!profile.owner || state.custodyEpoch !== binding.custodyEpoch)) ||
      !device.scopes.some((known) => known.scope === scope.scope && known.scopeId === scope.scopeId && known.mode === scope.mode && known.keyEpoch === scope.keyEpoch &&
        scope.permissions.every((permission) => known.permissions.includes(permission)) && (known.expiresAt === null || Date.parse(known.expiresAt) > Date.now()) && known.manifests.some((item) => item.id === descriptor.id && item.digest === descriptor.digest))) invalid();
    for (const expected of descriptors) {
      const envelope = delivery.deliveries.find((item) => item.id === expected.id)?.envelope;
      if (!envelope || await digestObject(envelope) !== expected.digest || !await verifyRecipientEnvelope(envelope, base64urlDecode(sender.signingPublicKey, 32),
        recoveryRecipientHeader(transcript, delivery.receipt.transition.body.transcriptDigest, scope, expected.recipientKind))) throw new RecoveryClientError('INCOMPLETE_KEYS');
    }
    scopes.push({ ...scope, sources: [{ grantId: binding.operationId, generation: '1', manifestId: descriptor.id, manifestDigest: descriptor.digest }] });
  }
  await readDeviceScopeKeyMaterial({ scopes, history: state, holder: { workspaceId: binding.workspaceId, custodyEpoch: binding.custodyEpoch,
    approverAccountId: binding.accountId, approverDevice: transcript.device }, materials }, bundle);
  if (transcript.recovery) {
    if (!input.newOwnerPhrase) throw new RecoveryClientError('INCOMPLETE_KEYS');
    const recovery = await recoveryKeys(input.newOwnerPhrase, { workspaceId: binding.workspaceId, accountId: binding.accountId });
    try {
      if (base64urlEncode(recovery.signing.publicKey) !== transcript.recovery.signingPublicKey ||
        base64urlEncode(recovery.recipient.publicKey) !== transcript.recovery.recipientPublicKey) throw new RecoveryClientError('INCOMPLETE_KEYS');
      await readRecoveryCustodyKeyMaterial({ accountId: binding.accountId, recoveryId: transcript.recovery.id, recoveryGeneration: transcript.recovery.generation,
        history: state, materials }, recovery.recipient.privateKey);
    } finally { recovery.signing.privateKey.fill(0); recovery.recipient.privateKey.fill(0); }
  }
  return { complete: true, scopeCount: scopes.length };
}

export interface RecoveryTransport {
  readonly origin: string;
  issueReset(input: { workspaceId: string; accountId: string; resetId: string }, options?: AuthRequestOptions): Promise<RecoveryIssuedReset>;
  revokeReset(input: { workspaceId: string; resetId: string }, options?: AuthRequestOptions): Promise<RecoveryView>;
  beginReset(input: { workspaceId: string; code: string; resumeToken: string }, options?: AuthRequestOptions): Promise<RecoveryView>;
  beginPhrase(input: RecoveryReference & { accountId: string }, options?: AuthRequestOptions): Promise<RecoveryPhraseChallenge>;
  provePhrase(input: RecoveryReference & { proof: RecoveryPhraseProof }, options?: AuthRequestOptions): Promise<RecoveryView>;
  inspect(reference: RecoveryReference | RecoveryOperationReference, options?: AuthRequestOptions): Promise<RecoveryView>;
  claim(reference: RecoveryOperationReference, options?: AuthRequestOptions): Promise<RecoveryView>;
  registration(input: RecoveryReference & { registrationRequest: string }, options?: AuthRequestOptions): Promise<{ registrationResponse: string; configuration: OpaquePublicConfiguration }>;
  startProof(input: RecoveryReference & { draft: RecoveryDraft; startLoginRequest: string }, options?: AuthRequestOptions): Promise<{
    proofId: string; expiresAt: string; loginResponse: string; configuration: OpaquePublicConfiguration; draftHash: string }>;
  finishProof(input: RecoveryReference & { proofId: string; finishLoginRequest: string }, options?: AuthRequestOptions): Promise<{ verified: true }>;
  confirm(input: (RecoveryReference | RecoveryOperationReference) & { confirmation: RecoveryConfirmation }, options?: AuthRequestOptions): Promise<RecoveryView>;
  materials(reference: RecoveryReference | RecoveryOperationReference, options?: AuthRequestOptions): Promise<PairingMaterial[]>;
  stage(input: (RecoveryReference | RecoveryOperationReference) & { approval: RecoveryApproval }, options?: AuthRequestOptions): Promise<RecoveryView>;
  finalize(input: (RecoveryReference | RecoveryOperationReference) & { requestHash: string }, options?: AuthRequestOptions): Promise<RecoveryResult>;
  status(reference: RecoveryReference | RecoveryOperationReference, options?: AuthRequestOptions): Promise<RecoveryView>;
  cancel(reference: RecoveryReference, options?: AuthRequestOptions): Promise<RecoveryView>;
  history(reference: RecoveryReference | RecoveryOperationReference, mode: 'transcript' | 'current', options?: AuthRequestOptions): Promise<PairingHistoryResponse>;
  delivery(operationId: string, options?: AuthRequestOptions): Promise<RecoveryDelivery>;
}
export class HttpRecoveryTransport extends AuthenticatedHttp implements RecoveryTransport {
  constructor(origin: string, private readonly csrfToken: () => string | undefined, fetcher?: typeof fetch) { super(origin, fetcher); }
  private request<T>(path: string, value: unknown, schema: z.ZodType<T>, options?: AuthRequestOptions, authenticated = false): Promise<T> {
    const csrfToken = authenticated ? this.csrfToken() : undefined;
    if (authenticated && !csrfToken) throw new AuthClientError('AUTH_REQUIRED');
    return this.post(`/v1/auth/recovery/${path}`, value, schema, { ...options, ...(csrfToken ? { csrfToken } : {}) });
  }
  private owner(reference: RecoveryReference | RecoveryOperationReference): boolean { return !('resumeToken' in reference); }
  issueReset(input: { workspaceId: string; accountId: string; resetId: string }, options?: AuthRequestOptions) { return this.request('reset/issue', input, recoveryIssuedReset, options, true); }
  revokeReset(input: { workspaceId: string; resetId: string }, options?: AuthRequestOptions) { return this.request('reset/revoke', input, recoveryView, options, true); }
  beginReset(input: { workspaceId: string; code: string; resumeToken: string }, options?: AuthRequestOptions) { return this.request('reset/begin', input, recoveryView, options); }
  beginPhrase(input: RecoveryReference & { accountId: string }, options?: AuthRequestOptions) { return this.request('phrase/begin', input, recoveryPhraseChallenge, options); }
  provePhrase(input: RecoveryReference & { proof: RecoveryPhraseProof }, options?: AuthRequestOptions) { return this.request('phrase/prove', input, recoveryView, options); }
  inspect(reference: RecoveryReference | RecoveryOperationReference, options?: AuthRequestOptions) { return this.request('inspect', reference, recoveryView, options, this.owner(reference)); }
  claim(reference: RecoveryOperationReference, options?: AuthRequestOptions) { return this.request('claim', reference, recoveryView, options, true); }
  registration(input: RecoveryReference & { registrationRequest: string }, options?: AuthRequestOptions) { return this.request('registration', input,
    z.strictObject({ registrationResponse: binary(1, 4096), configuration: genesisBody.shape.opaque }), options) as Promise<{ registrationResponse: string; configuration: OpaquePublicConfiguration }>; }
  startProof(input: RecoveryReference & { draft: RecoveryDraft; startLoginRequest: string }, options?: AuthRequestOptions) { return this.request('proof/start', input,
    z.strictObject({ proofId: identifier, expiresAt: z.iso.datetime(), loginResponse: binary(1, 4096), configuration: genesisBody.shape.opaque, draftHash: digest }), options) as Promise<{
      proofId: string; expiresAt: string; loginResponse: string; configuration: OpaquePublicConfiguration; draftHash: string }>; }
  finishProof(input: RecoveryReference & { proofId: string; finishLoginRequest: string }, options?: AuthRequestOptions) { return this.request('proof/finish', input, z.strictObject({ verified: z.literal(true) }), options); }
  confirm(input: (RecoveryReference | RecoveryOperationReference) & { confirmation: RecoveryConfirmation }, options?: AuthRequestOptions) { return this.request('confirm', input, recoveryView, options, this.owner(input)); }
  materials(reference: RecoveryReference | RecoveryOperationReference, options?: AuthRequestOptions) { return this.request('materials', reference, z.array(materialSchema).max(4096), options, this.owner(reference)); }
  stage(input: (RecoveryReference | RecoveryOperationReference) & { approval: RecoveryApproval }, options?: AuthRequestOptions) { return this.request('stage', input, recoveryView, options, this.owner(input)); }
  finalize(input: (RecoveryReference | RecoveryOperationReference) & { requestHash: string }, options?: AuthRequestOptions) { return this.request('finalize', input, recoveryResult, options, this.owner(input)); }
  status(reference: RecoveryReference | RecoveryOperationReference, options?: AuthRequestOptions) { return this.request('status', reference, recoveryView, options, this.owner(reference)); }
  cancel(reference: RecoveryReference, options?: AuthRequestOptions) { return this.request('cancel', reference, recoveryView, options); }
  history(reference: RecoveryReference | RecoveryOperationReference, mode: 'transcript' | 'current', options?: AuthRequestOptions) {
    return readSecurityHistoryPages(reference.operationId, mode, (page) => this.request('history', { ...reference, ...page }, historyResponse, options, mode === 'current' || this.owner(reference)));
  }
  delivery(operationId: string, options?: AuthRequestOptions) { return this.request('delivery', { operationId }, recoveryDelivery, options, true); }
  protected override responseLimit(path: string): number { return path === '/v1/auth/recovery/history' ? 3 * 1_048_576 : super.responseLimit(path); }
}

const recipientRecord = z.strictObject({ version: z.literal(1), role: z.literal('recipient'), localId: identifier, revision: z.number().int().positive(),
  origin: z.string(), workspaceId: identifier, accountId: identifier.nullable(), deviceId: identifier.nullable(), resumeToken: binary(32), operationId: identifier.nullable(),
  kit: recoveryKitIdentity.nullable(), challenge: recoveryPhraseChallenge.nullable(), view: recoveryView.nullable(),
  prepared: z.strictObject({ draft: recoveryDraft, wrapper: deviceWrapper }).nullable(), approval: recoveryApproval.nullable(), receipt: recoveryReceipt.nullable() });
const ownerRecord = z.strictObject({ version: z.literal(1), role: z.literal('owner'), localId: identifier, revision: z.number().int().positive(), origin: z.string(),
  workspaceId: identifier, accountId: identifier, deviceId: identifier, operationId: identifier, view: recoveryView,
  approval: recoveryApproval.nullable(), receipt: recoveryReceipt.nullable() });
const recoveryRecord = z.discriminatedUnion('role', [recipientRecord, ownerRecord]);
export type RecoveryRecipientRecord = z.infer<typeof recipientRecord>;
export type RecoveryOwnerRecord = z.infer<typeof ownerRecord>;
export type RecoveryRecord = z.infer<typeof recoveryRecord>;
const storageKey = (origin: string, role: RecoveryRecord['role'], localId: string) => `${origin}:${role}:${localId}`;
/** Capabilities and signed/public ciphertext only. Codes, phrases, passwords and export keys are never persisted. */
export class IndexedRecoveryStore {
  private constructor(readonly origin: string, private readonly database: IDBDatabase) { database.onversionchange = () => database.close(); }
  static async open(origin: string, name = 'ukda-recovery-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedRecoveryStore> {
    const accepted = new AuthenticatedHttp(origin).origin;
    if (!factory) throw new RecoveryClientError('STORAGE');
    return new Promise((resolve, reject) => {
      let settled = false; const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new RecoveryClientError('STORAGE')); };
      request.onerror = request.onblocked = fail;
      request.onupgradeneeded = () => { request.result.createObjectStore('operations'); };
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedRecoveryStore(accepted, request.result)); };
    });
  }
  private transaction<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore, done: (value: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction;
      try { transaction = this.database.transaction('operations', mode, mode === 'readwrite' ? { durability: 'strict' } : {}); }
      catch { reject(new RecoveryClientError('STORAGE')); return; }
      let value: T, complete = false, failure: unknown;
      const fail = (error: unknown) => { failure = error; try { transaction.abort(); } catch { reject(error); } };
      transaction.onabort = () => reject(failure instanceof RecoveryClientError ? failure : new RecoveryClientError('STORAGE'));
      transaction.oncomplete = () => complete ? resolve(value) : reject(new RecoveryClientError('STORAGE'));
      try { action(transaction.objectStore('operations'), (result) => { value = result; complete = true; }, fail); } catch (error) { fail(error); }
    });
  }
  get(role: RecoveryRecord['role'], localId: string): Promise<RecoveryRecord | undefined> {
    identifier.parse(localId);
    return this.transaction('readonly', (store, done, fail) => { const request = store.get(storageKey(this.origin, role, localId)); request.onsuccess = () => {
      try { const value = request.result === undefined ? undefined : recoveryRecord.parse(copy(request.result));
        if (value && (value.origin !== this.origin || value.role !== role || value.localId !== localId)) invalid(); done(value);
      } catch (error) { fail(error); }
    }; });
  }
  put(record: RecoveryRecord, expectedRevision: number): Promise<void> {
    const accepted = recoveryRecord.parse(copy(record));
    if (accepted.origin !== this.origin || accepted.revision !== expectedRevision + 1) throw new RecoveryClientError('CONFLICT');
    return this.transaction('readwrite', (store, done, fail) => { const request = store.get(storageKey(this.origin, accepted.role, accepted.localId)); request.onsuccess = () => {
      try { const previous = request.result === undefined ? undefined : recoveryRecord.parse(request.result);
        if ((previous?.revision ?? 0) !== expectedRevision) throw new RecoveryClientError('CONFLICT');
        store.put(accepted, storageKey(this.origin, accepted.role, accepted.localId)); done(undefined);
      } catch (error) { fail(error); }
    }; });
  }
  /** Minimal capability survives corrupt encrypted draft fields; used only to cancel, never to finalize. */
  capability(localId: string): Promise<{ workspaceId: string; operationId: string; resumeToken: string; accountId: string | null; deviceId: string | null } | undefined> {
    identifier.parse(localId);
    return this.transaction('readonly', (store, done, fail) => { const request = store.get(storageKey(this.origin, 'recipient', localId)); request.onsuccess = () => { try {
      const metadata = z.object({ origin: z.literal(this.origin), role: z.literal('recipient'), localId: z.literal(localId), workspaceId: identifier,
        operationId: identifier, resumeToken: binary(32), accountId: identifier.nullable(), deviceId: identifier.nullable() }).safeParse(request.result);
      if (!metadata.success) { done(undefined); return; }
      const { workspaceId, operationId, resumeToken, accountId, deviceId } = metadata.data; done({ workspaceId, operationId, resumeToken, accountId, deviceId });
    } catch (error) { fail(error); } }; });
  }
  discardCancelled(localId: string, reference: RecoveryReference): Promise<void> {
    return this.transaction('readwrite', (store, done, fail) => { const key = storageKey(this.origin, 'recipient', localId), request = store.get(key); request.onsuccess = () => { try {
      const parsed = z.object({ workspaceId: identifier, operationId: identifier, resumeToken: binary(32) }).safeParse(request.result);
      if (request.result !== undefined && (!parsed.success || !same(parsed.data, reference))) throw new RecoveryClientError('CONFLICT');
      store.delete(key); done(undefined);
    } catch (error) { fail(error); } }; });
  }
  list(): Promise<{ role: RecoveryRecord['role']; localId: string; workspaceId: string; accountId: string | null; operationId: string | null; state: string }[]> {
    return this.transaction('readonly', (store, done, fail) => { const request = store.getAll(); request.onsuccess = () => {
      try { done(request.result.flatMap((raw: unknown) => { const parsed = recoveryRecord.safeParse(raw); if (!parsed.success || parsed.data.origin !== this.origin) return [];
        const record = parsed.data; return [{ role: record.role, localId: record.localId, workspaceId: record.workspaceId, accountId: record.accountId,
          operationId: record.operationId, state: record.receipt ? 'completed' : record.view?.state ?? 'starting' }]; }));
      } catch (error) { fail(error); }
    }; });
  }
  forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    return this.transaction('readwrite', (store, done, fail) => { const request = store.openCursor(); request.onsuccess = () => { try {
      const cursor = request.result; if (!cursor) { done(undefined); return; }
      const metadata = z.object({ origin: z.string(), workspaceId: identifier, accountId: identifier, deviceId: identifier }).safeParse(cursor.value);
      if (metadata.success && metadata.data.origin === this.origin && metadata.data.workspaceId === reference.workspaceId &&
        metadata.data.accountId === reference.accountId && metadata.data.deviceId === reference.deviceId) cursor.delete();
      cursor.continue();
    } catch (error) { fail(error); } }; });
  }
  close(): void { this.database.close(); }
}

export interface RecoveryProgress { localId: string; operation: RecoveryOperationReference | null; state: string; fingerprint: string | null; deviceId: string | null }
export type RecoveryResumeResult = RecoveryProgress & { access: 'pending' | 'login_required' | 'recovery_kit_required' | 'content_ready' | 'incomplete_keys' };
/** Headless browser flow. Persistence precedes every irreversible step; secrets live only during explicit calls. */
export class RecoveryController {
  private epoch = 0;
  private readonly running = new Set<Promise<unknown>>();
  private readonly requests = new Set<AbortController>();
  private readonly exports = new Map<string, string>();
  constructor(private readonly auth: AuthController, private readonly transport: RecoveryTransport,
    private readonly devices: IndexedDeviceStore, readonly operations: IndexedRecoveryStore, private readonly pins: IndexedPairingStore,
    private readonly options: { trustedServiceKeys?: Record<string, string> } = {}) {
    if (auth.origin !== transport.origin || auth.origin !== operations.origin || auth.origin !== pins.origin) invalid();
  }
  attachAuthLifecycle(): () => void {
    const clear = this.auth.onClear(() => this.clear());
    const forget = this.auth.onForget((reference) => this.forgetDevice(reference));
    return () => { clear(); forget(); };
  }
  clear(): void { this.epoch++; this.exports.clear(); for (const request of this.requests) request.abort(); }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    this.clear(); await Promise.allSettled([...this.running]); await this.operations.forgetDevice(reference);
  }
  private check(epoch: number): void { if (epoch !== this.epoch) throw new RecoveryClientError('CANCELLED'); }
  private run<T>(work: (signal: AbortSignal, epoch: number) => Promise<T>): Promise<T> {
    const abort = new AbortController(), epoch = this.epoch; this.requests.add(abort);
    const result = work(abort.signal, epoch).then((value) => { this.check(epoch); return value; });
    this.running.add(result);
    void result.finally(() => { this.requests.delete(abort); this.running.delete(result); }).catch(() => {});
    return result;
  }
  private async save<T extends RecoveryRecord>(previous: T, next: T, epoch: number): Promise<T> {
    this.check(epoch); const accepted = { ...next, revision: previous.revision + 1 };
    await this.operations.put(accepted, previous.revision); this.check(epoch); return accepted;
  }
  private async recipient(localId: string): Promise<RecoveryRecipientRecord> {
    const record = await this.operations.get('recipient', localId);
    if (!record || record.role !== 'recipient') throw new RecoveryClientError('NOT_FOUND'); return record;
  }
  private reference(record: RecoveryRecipientRecord): RecoveryReference {
    if (!record.operationId) throw new RecoveryClientError('CONFLICT');
    return { workspaceId: record.workspaceId, operationId: record.operationId, resumeToken: record.resumeToken };
  }
  private progress(record: RecoveryRecord): RecoveryProgress {
    return { localId: record.localId, operation: record.operationId ? { workspaceId: record.workspaceId, operationId: record.operationId } : null,
      state: record.receipt ? 'completed' : record.view?.state ?? 'starting', fingerprint: record.view?.transcriptDigest ?? null, deviceId: record.deviceId };
  }
  private async acceptView(value: RecoveryView, reference: RecoveryOperationReference, accountId?: string | null): Promise<RecoveryView> {
    const view = recoveryView.parse(copy(value));
    if (view.workspaceId !== reference.workspaceId || view.operationId !== reference.operationId || (accountId && view.accountId !== accountId) ||
      (view.binding && (view.binding.origin !== this.auth.origin || view.binding.workspaceId !== view.workspaceId || view.binding.operationId !== view.operationId || view.binding.accountId !== view.accountId)) ||
      (view.transcript && (!same(view.binding, view.transcript.binding) || view.transcriptDigest !== await digestObject(view.transcript)))) invalid();
    return view;
  }
  private async history(reference: RecoveryReference | RecoveryOperationReference, binding: RecoveryBinding, signal: AbortSignal,
    options: { receipt?: RecoveryReceipt; requirePin?: boolean; kit?: RecoveryKitIdentity | null } = {}): Promise<SecurityHistoryInput> {
    const pin = await this.pins.pin(binding.workspaceId);
    if (options.requirePin && !pin) throw new RecoveryClientError('TRUST_REQUIRED');
    if (options.kit && (options.kit.origin !== binding.origin || options.kit.accountId !== binding.accountId ||
      options.kit.workspaceId !== binding.workspaceId || options.kit.genesisFingerprint !== binding.genesisFingerprint)) invalid();
    const response = await this.transport.history(reference, options.receipt ? 'current' : 'transcript', { signal });
    if (!options.receipt && !same(response.anchor, { securityHead: binding.securityHead, securityVersion: binding.securityVersion })) invalid();
    if (options.receipt && (BigInt(response.anchor.securityVersion) < BigInt(options.receipt.securityVersion) || !same(response.anchor, response.current) ||
      !response.transitions.some((item) => same(item, options.receipt!.transition)))) invalid();
    const input: SecurityHistoryInput = { workspaceId: binding.workspaceId, origin: binding.origin, genesisFingerprint: options.kit?.genesisFingerprint ?? binding.genesisFingerprint,
      genesis: response.genesis, transitions: response.transitions, expected: response.anchor, ...(pin ? { pin } : {}), trustedServiceKeys: this.options.trustedServiceKeys ?? {} };
    const state = await verifySecurityHistory(input);
    if (!options.receipt) verifyRecoveryBindingAgainstHistory(binding, state);
    return input;
  }
  private async createRecipient(workspaceId: string, localId: string, accountId: string | null, kit: RecoveryKitIdentity | null, epoch: number): Promise<RecoveryRecipientRecord> {
    const record: RecoveryRecipientRecord = { version: 1, role: 'recipient', localId, revision: 1, origin: this.auth.origin, workspaceId, accountId,
      deviceId: null, operationId: kit ? localId : null, resumeToken: base64urlEncode(crypto.getRandomValues(new Uint8Array(32))), kit,
      challenge: null, view: null, prepared: null, approval: null, receipt: null };
    this.check(epoch); await this.operations.put(record, 0); this.check(epoch); return record;
  }
  beginPhrase(kitValue: RecoveryKitIdentity, localId: string = crypto.randomUUID()): Promise<RecoveryProgress> {
    return this.run(async (signal, epoch) => {
      const kit = recoveryKitIdentity.parse(kitValue); if (kit.origin !== this.auth.origin) invalid();
      let record = await this.operations.get('recipient', localId);
      if (!record) record = await this.createRecipient(kit.workspaceId, localId, kit.accountId, kit, epoch);
      if (record.role !== 'recipient' || !same(record.kit, kit)) throw new RecoveryClientError('CONFLICT');
      if (record.view || record.challenge) return this.progress(record);
      const challenge = await this.transport.beginPhrase({ ...this.reference(record), accountId: kit.accountId }, { signal }); this.check(epoch);
      if (challenge.binding.origin !== kit.origin || challenge.binding.workspaceId !== kit.workspaceId || challenge.binding.accountId !== kit.accountId ||
        challenge.binding.operationId !== record.operationId || challenge.binding.genesisFingerprint !== kit.genesisFingerprint) invalid();
      record = await this.save(record, { ...record, challenge }, epoch); return this.progress(record);
    });
  }
  provePhrase(localId: string, phrase: string): Promise<RecoveryProgress> {
    return this.run(async (signal, epoch) => {
      let record = await this.recipient(localId);
      if (!record.challenge || !record.kit) throw new RecoveryClientError('CONFLICT');
      const proof = await this.auth.worker.proveOwnerPhrase({ challenge: record.challenge, kit: record.kit, phrase }, { signal }); this.check(epoch);
      const view = await this.acceptView(await this.transport.provePhrase({ ...this.reference(record), proof }, { signal }), this.reference(record), record.accountId);
      this.check(epoch); if (!view.binding) invalid();
      const history = await this.history(this.reference(record), view.binding, signal, { kit: record.kit }); this.check(epoch);
      await this.pins.recordVerifiedHistory(history); this.check(epoch);
      record = await this.save(record, { ...record, view }, epoch); return this.progress(record);
    });
  }
  beginReset(workspaceId: string, code: string, localId: string = crypto.randomUUID()): Promise<RecoveryProgress> {
    return this.run(async (signal, epoch) => {
      let record = await this.operations.get('recipient', localId);
      if (!record) record = await this.createRecipient(workspaceId, localId, null, null, epoch);
      if (record.role !== 'recipient' || record.workspaceId !== workspaceId || record.kit) throw new RecoveryClientError('CONFLICT');
      if (record.operationId) return this.progress(record);
      const value = await this.transport.beginReset({ workspaceId, code, resumeToken: record.resumeToken }, { signal }); this.check(epoch);
      const view = await this.acceptView(value, { workspaceId, operationId: value.operationId }); this.check(epoch);
      record = await this.save(record, { ...record, accountId: view.accountId, operationId: view.operationId, view }, epoch); return this.progress(record);
    });
  }
  /** Return value is an ephemeral code to show once; it is never written to browser storage. */
  issueReset(accountId: string, resetId: string = crypto.randomUUID()): Promise<RecoveryIssuedReset> {
    return this.run(async (signal) => {
      const current = this.auth.current(); if (current?.localAccess !== 'unlocked') throw new AuthClientError('AUTH_REQUIRED');
      return this.transport.issueReset({ workspaceId: current.session.workspaceId, accountId, resetId }, { signal });
    });
  }
  revokeReset(workspaceId: string, resetId: string): Promise<RecoveryView> { return this.run((signal) => this.transport.revokeReset({ workspaceId, resetId }, { signal })); }
  claim(referenceValue: RecoveryOperationReference): Promise<RecoveryProgress> {
    return this.run(async (signal, epoch) => {
      const reference = recoveryOperationReference.parse(referenceValue), current = this.auth.current();
      if (current?.localAccess !== 'unlocked' || !current.session.deviceId || current.session.workspaceId !== reference.workspaceId) throw new AuthClientError('AUTH_REQUIRED');
      const view = await this.acceptView(await this.transport.claim(reference, { signal }), reference); this.check(epoch);
      if (!view.binding || view.binding.authorizer.kind !== 'owner_reset' || view.binding.authorizer.accountId !== current.session.accountId || view.binding.authorizer.device.id !== current.session.deviceId) invalid();
      const history = await this.history(reference, view.binding, signal, { requirePin: true }); this.check(epoch);
      await this.pins.recordVerifiedHistory(history); this.check(epoch);
      const old = await this.operations.get('owner', reference.operationId); this.check(epoch);
      if (old && (old.role !== 'owner' || old.accountId !== current.session.accountId || old.deviceId !== current.session.deviceId)) throw new RecoveryClientError('CONFLICT');
      const record: RecoveryOwnerRecord = { version: 1, role: 'owner', localId: reference.operationId, revision: (old?.revision ?? 0) + 1, origin: this.auth.origin,
        workspaceId: reference.workspaceId, accountId: current.session.accountId, deviceId: current.session.deviceId, operationId: reference.operationId,
        view, approval: old?.approval ?? null, receipt: old?.receipt ?? null };
      await this.operations.put(record, old?.revision ?? 0); this.check(epoch); return this.progress(record);
    });
  }
  private async passwordProof(record: RecoveryRecipientRecord, password: string, signal: AbortSignal, epoch: number): Promise<string> {
    if (!record.prepared) throw new RecoveryClientError('CONFLICT');
    const start = await this.auth.worker.startLogin(password, { signal }); this.check(epoch);
    const response = await this.transport.startProof({ ...this.reference(record), draft: record.prepared.draft, startLoginRequest: start.startLoginRequest }, { signal }); this.check(epoch);
    const draft = record.prepared.draft;
    if (!same(response.configuration, draft.transcript.configuration) || response.draftHash !== await digestObject({ transcript: draft.transcript,
      registrationRecord: draft.registrationRecord, newRecoveryConfirmation: draft.newRecoveryConfirmation })) invalid();
    const finish = await this.auth.worker.finishLogin({ password, clientLoginState: start.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration }, { signal }); this.check(epoch);
    await this.auth.worker.verifyRecoveryDraftWrapper({ ...record.prepared, exportKey: finish.exportKey }, { signal }); this.check(epoch);
    await this.transport.finishProof({ ...this.reference(record), proofId: response.proofId, finishLoginRequest: finish.finishLoginRequest }, { signal }); this.check(epoch);
    this.exports.set(record.localId, finish.exportKey); return finish.exportKey;
  }
  private async readback(record: RecoveryRecipientRecord, exportKey: string, signal: AbortSignal, epoch: number): Promise<void> {
    if (!record.prepared) throw new RecoveryClientError('CONFLICT');
    this.check(epoch); await this.devices.stage(record.prepared.wrapper, record.operationId!); this.check(epoch);
    const wrapper = await this.devices.getStaged(record.operationId!); this.check(epoch);
    if (!wrapper || await digestObject(wrapper) !== record.prepared.draft.transcript.wrapperHash) throw new RecoveryClientError('STORAGE');
    await this.auth.worker.verifyRecoveryDraftWrapper({ draft: record.prepared.draft, wrapper, exportKey }, { signal }); this.check(epoch);
  }
  prepare(localId: string, password: string, confirmation: string, newOwnerKit?: PrepareRecoveryDraftInput['newOwnerKit']): Promise<RecoveryProgress> {
    return this.run(async (signal, epoch) => {
      if (password !== confirmation) throw new RecoveryClientError('PASSWORD_CONFIRMATION');
      let record = await this.recipient(localId);
      const view = await this.acceptView(await this.transport.status(this.reference(record), { signal }), this.reference(record), record.accountId); this.check(epoch);
      if (!view.binding || view.receipt) throw new RecoveryClientError('CONFLICT');
      if (record.prepared && !same(record.prepared.draft.transcript.binding, view.binding)) {
        if (view.transcript || view.approvalStaged) throw new RecoveryClientError('CONFLICT');
        await this.devices.discardUncommitted(record.operationId!, record.prepared.draft.transcript.device.id); this.check(epoch);
        record = await this.save(record, { ...record, prepared: null, approval: null, deviceId: null, view }, epoch);
      }
      if (!record.prepared) {
        const start = await this.auth.worker.startRegistration(password, { signal }); this.check(epoch);
        const response = await this.transport.registration({ ...this.reference(record), registrationRequest: start.registrationRequest }, { signal }); this.check(epoch);
        const result = await this.auth.worker.finishRegistration({ password, clientRegistrationState: start.clientRegistrationState,
          registrationResponse: response.registrationResponse, configuration: response.configuration }, { signal }); this.check(epoch);
        const prepared = await this.auth.worker.prepareRecoveryDraft({ binding: view.binding, configuration: response.configuration,
          registrationRecord: result.registrationRecord, exportKey: result.exportKey, ...(newOwnerKit ? { newOwnerKit } : {}) }, { signal }); this.check(epoch);
        record = await this.save(record, { ...record, view, prepared, deviceId: prepared.draft.transcript.device.id }, epoch);
        await this.readback(record, result.exportKey, signal, epoch);
      }
      await this.passwordProof(record, password, signal, epoch);
      const next = await this.acceptView(await this.transport.status(this.reference(record), { signal }), this.reference(record), record.accountId); this.check(epoch);
      if (!same(next.transcript, record.prepared!.draft.transcript)) invalid();
      record = await this.save(record, { ...record, view: next }, epoch); return this.progress(record);
    });
  }
  confirmRecipient(localId: string, fullFingerprint: string, password?: string): Promise<RecoveryProgress> {
    return this.run(async (signal, epoch) => {
      let record = await this.recipient(localId); if (!record.prepared || record.receipt) throw new RecoveryClientError('CONFLICT');
      const view = await this.acceptView(await this.transport.status(this.reference(record), { signal }), this.reference(record), record.accountId); this.check(epoch);
      if (!same(view.transcript, record.prepared.draft.transcript)) throw new RecoveryClientError('CONFLICT');
      const fingerprint = await verifyRecoveryFingerprint(record.prepared.draft.transcript, fullFingerprint);
      const history = await this.history(this.reference(record), record.prepared.draft.transcript.binding, signal, { kit: record.kit }); this.check(epoch);
      const exportKey = password === undefined ? this.exports.get(localId) : await this.passwordProof(record, password, signal, epoch);
      if (!exportKey) throw new AuthClientError('REAUTH_REQUIRED');
      await this.readback(record, exportKey, signal, epoch);
      const proof = record.prepared.draft.recipientConfirmation ?? await this.auth.worker.confirmRecoveryRecipient({ ...record.prepared, exportKey, fingerprint, history }, { signal }); this.check(epoch);
      record = await this.save(record, { ...record, prepared: { ...record.prepared, draft: { ...record.prepared.draft, recipientConfirmation: proof } } }, epoch);
      await this.pins.recordVerifiedHistory(history); this.check(epoch);
      const confirmed = await this.acceptView(await this.transport.confirm({ ...this.reference(record), confirmation: proof }, { signal }), this.reference(record), record.accountId); this.check(epoch);
      if (!same(confirmed.recipientConfirmation, proof)) invalid();
      record = await this.save(record, { ...record, view: confirmed }, epoch); return this.progress(record);
    });
  }
  approvePhrase(localId: string, fingerprint: string, oldPhrase: string, password?: string): Promise<RecoveryProgress> {
    return this.run(async (signal, epoch) => {
      let record = await this.recipient(localId);
      if (!record.prepared || !record.kit || !record.prepared.draft.recipientConfirmation) throw new RecoveryClientError('CONFLICT');
      const reference = this.reference(record), status = await this.acceptView(await this.transport.status(reference, { signal }), reference, record.accountId); this.check(epoch);
      if (status.receipt) return this.progress(await this.acceptRecipientReceipt(record, status.receipt, epoch));
      if (!same(status.transcript, record.prepared.draft.transcript)) throw new RecoveryClientError('CONFLICT');
      await verifyRecoveryFingerprint(record.prepared.draft.transcript, fingerprint);
      const history = await this.history(reference, record.prepared.draft.transcript.binding, signal, { kit: record.kit, requirePin: true }); this.check(epoch);
      const exportKey = password === undefined ? this.exports.get(localId) : await this.passwordProof(record, password, signal, epoch);
      if (!exportKey) throw new AuthClientError('REAUTH_REQUIRED'); await this.readback(record, exportKey, signal, epoch);
      if (!record.approval) {
        const materials = await this.transport.materials(reference, { signal }); this.check(epoch);
        const approval = await this.auth.worker.preparePhraseRecoveryApproval({ ...record.prepared, fingerprint, history, materials,
          exportKey, phrase: oldPhrase, kit: record.kit }, { signal }); this.check(epoch);
        await validateRecoveryApproval(approval, record.prepared.draft, record.prepared.draft.transcript.binding, record.prepared.draft.transcript.configuration);
        record = await this.save(record, { ...record, approval }, epoch);
      }
      const approval = record.approval!;
      await this.transport.confirm({ ...reference, confirmation: approval.transition.body.authorizerConfirmation }, { signal }); this.check(epoch);
      const staged = await this.acceptView(await this.transport.stage({ ...reference, approval }, { signal }), reference, record.accountId); this.check(epoch);
      const expected = await digestObject({ ...approval, registrationRecord: record.prepared!.draft.registrationRecord });
      if (!staged.approvalStaged || staged.requestHash !== expected) invalid();
      record = await this.save(record, { ...record, view: staged }, epoch);
      const result = await this.transport.finalize({ ...reference, requestHash: expected }, { signal }); this.check(epoch);
      return this.progress(await this.acceptRecipientReceipt(record, result.receipt, epoch));
    });
  }
  approve(referenceValue: RecoveryOperationReference, fingerprint: string): Promise<RecoveryProgress> {
    return this.run(async (signal, epoch) => {
      const reference = recoveryOperationReference.parse(referenceValue);
      let record = await this.operations.get('owner', reference.operationId);
      if (!record || record.role !== 'owner' || record.workspaceId !== reference.workspaceId) throw new RecoveryClientError('NOT_FOUND');
      const current = this.auth.current();
      if (current?.localAccess !== 'unlocked' || current.session.accountId !== record.accountId || current.session.deviceId !== record.deviceId) throw new AuthClientError('AUTH_REQUIRED');
      const view = await this.acceptView(await this.transport.inspect(reference, { signal }), reference); this.check(epoch);
      if (view.receipt) { const receipt = await validateRecoveryReceipt(view.receipt, record.approval?.transition.body.transcript ?? view.receipt.transition.body.transcript);
        record = await this.save(record, { ...record, view, receipt }, epoch); return this.progress(record); }
      if (!view.transcript || !view.recipientConfirmation || !view.binding) throw new RecoveryClientError('CONFLICT');
      await verifyRecoveryFingerprint(view.transcript, fingerprint);
      const history = await this.history(reference, view.binding, signal, { requirePin: true }); this.check(epoch);
      if (!record.approval) {
        const materials = await this.transport.materials(reference, { signal }); this.check(epoch);
        const approval = await this.auth.worker.prepareOwnerRecoveryApproval({ draft: { transcript: view.transcript, recipientConfirmation: view.recipientConfirmation,
          newRecoveryConfirmation: view.newRecoveryConfirmation }, fingerprint, history, materials }, { signal }); this.check(epoch);
        record = await this.save(record, { ...record, view, approval }, epoch);
      }
      const approval = record.approval!;
      if (!same(approval.transition.body.transcript, view.transcript)) throw new RecoveryClientError('CONFLICT');
      await this.transport.confirm({ ...reference, confirmation: approval.transition.body.authorizerConfirmation }, { signal }); this.check(epoch);
      const staged = await this.acceptView(await this.transport.stage({ ...reference, approval }, { signal }), reference); this.check(epoch);
      if (!staged.approvalStaged || !staged.requestHash) invalid();
      record = await this.save(record, { ...record, view: staged }, epoch);
      const result = await this.transport.finalize({ ...reference, requestHash: staged.requestHash }, { signal }); this.check(epoch);
      const receipt = await validateRecoveryReceipt(result.receipt, approval.transition.body.transcript);
      if (receipt.requestHash !== staged.requestHash || !same(receipt.transition, approval.transition)) invalid();
      record = await this.save(record, { ...record, receipt }, epoch); return this.progress(record);
    });
  }
  private async acceptRecipientReceipt(record: RecoveryRecipientRecord, value: RecoveryReceipt, epoch: number): Promise<RecoveryRecipientRecord> {
    if (!record.prepared) throw new RecoveryClientError('CONFLICT');
    const receipt = await validateRecoveryReceipt(value, record.prepared.draft.transcript); this.check(epoch);
    if (record.receipt && !same(record.receipt, receipt)) invalid();
    if (!record.prepared.draft.recipientConfirmation || !same(receipt.transition.body.recipientConfirmation, record.prepared.draft.recipientConfirmation) ||
      !same(receipt.transition.body.newRecoveryConfirmation, record.prepared.draft.newRecoveryConfirmation)) invalid();
    if (record.approval && (receipt.requestHash !== await digestObject({ ...record.approval, registrationRecord: record.prepared.draft.registrationRecord }) ||
      !same(receipt.transition, record.approval.transition))) invalid();
    // Persist the authenticated matching receipt before promotion; an interruption can safely retry both operations.
    record = await this.save(record, { ...record, receipt }, epoch);
    await this.devices.stage(record.prepared!.wrapper, receipt.operationId); this.check(epoch);
    await this.devices.commit(receipt.operationId, { ...recoveryDeviceContext(record.prepared!.draft.transcript), operationId: receipt.operationId }); this.check(epoch);
    this.exports.delete(record.localId); return record;
  }
  resume(localId: string, newOwnerPhrase?: string): Promise<RecoveryResumeResult> {
    return this.run(async (signal, epoch) => {
      let record = await this.recipient(localId);
      if (!record.operationId) return { ...this.progress(record), access: 'pending' };
      const reference = this.reference(record), view = await this.acceptView(await this.transport.status(reference, { signal }), reference, record.accountId); this.check(epoch);
      if (!view.receipt) { record = await this.save(record, { ...record, view }, epoch); return { ...this.progress(record), access: 'pending' }; }
      record = await this.acceptRecipientReceipt(record, view.receipt, epoch);
      const current = this.auth.current(), receipt = record.receipt!;
      if (current?.localAccess !== 'unlocked' || current.session.workspaceId !== receipt.workspaceId || current.session.accountId !== receipt.accountId ||
        current.session.deviceId !== receipt.deviceId || current.session.credentialGeneration !== receipt.credentialGeneration ||
        current.session.sessionGeneration !== receipt.sessionGeneration || current.session.dataGeneration !== receipt.dataGeneration) return { ...this.progress(record), access: 'login_required' };
      if (record.prepared!.draft.transcript.recovery && !newOwnerPhrase) return { ...this.progress(record), access: 'recovery_kit_required' };
      const history = await this.history(reference, record.prepared!.draft.transcript.binding, signal, { receipt, requirePin: true, kit: record.kit }); this.check(epoch);
      const delivery = await this.transport.delivery(receipt.operationId, { signal }); this.check(epoch);
      if (!same(delivery.receipt, receipt)) invalid();
      try { await this.auth.worker.verifyRecoveryDelivery({ delivery, history, ...(newOwnerPhrase ? { newOwnerPhrase } : {}) }, { signal }); this.check(epoch); }
      catch (error) { this.check(epoch); if (error && typeof error === 'object' && 'code' in error && error.code === 'INCOMPLETE_KEYS') return { ...this.progress(record), access: 'incomplete_keys' }; throw error; }
      await this.pins.recordVerifiedHistory(history); this.check(epoch);
      return { ...this.progress(record), access: 'content_ready' };
    });
  }
  cancel(localId: string): Promise<RecoveryProgress> {
    return this.run(async (signal, epoch) => {
      const metadata = await this.operations.capability(localId); this.check(epoch);
      if (!metadata) throw new RecoveryClientError('NOT_FOUND');
      const reference = { workspaceId: metadata.workspaceId, operationId: metadata.operationId, resumeToken: metadata.resumeToken };
      const view = await this.acceptView(await this.transport.cancel(reference, { signal }), reference, metadata.accountId); this.check(epoch);
      if (view.receipt) return this.progress(await this.acceptRecipientReceipt(await this.recipient(localId), view.receipt, epoch));
      if (!['cancelled', 'expired', 'revoked'].includes(view.state)) throw new RecoveryClientError('CONFLICT');
      await this.devices.discardUncommitted(metadata.operationId, metadata.deviceId ?? undefined); this.check(epoch);
      await this.operations.discardCancelled(localId, reference); this.check(epoch); this.exports.delete(localId);
      return { localId, operation: { workspaceId: metadata.workspaceId, operationId: metadata.operationId }, state: view.state, fingerprint: view.transcriptDigest, deviceId: metadata.deviceId };
    });
  }
}

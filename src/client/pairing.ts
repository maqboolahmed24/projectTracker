import { z } from 'zod';
import { genesisBody } from '../shared/activation.js';
import { binary, contentEnvelope, counter, digest, identifier, positiveCounter } from '../shared/contracts.js';
import { base64urlDecode, base64urlEncode, canonicalJson, decryptContent, digestObject, generateRecipientKeyPair,
  generateSigningKeyPair, openRecipient, recipientEnvelope, sealRecipient, signObject, verifyObject } from '../shared/crypto.js';
import { pairingApproval, pairingBegin, pairingConfirmation, pairingConfirmationFor, pairingGrant, pairingGrantBody,
  pairingReceipt, pairingRecipientHeader, pairingTranscript, type PairingApproval, type PairingBegin, type PairingConfirmation,
  type PairingDelivery, type PairingMaterial, type PairingReceipt, type PairingScope, type PairingTranscript, type PairingView } from '../shared/pairing.js';
import { securityPin, verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState, type SecurityPin, type HistoryScope } from '../shared/security-history.js';
import { deviceContext, deviceWrapper, IndexedDeviceStore, unwrapDeviceBundle, wrapDeviceBundle, type DeviceBundle, type DeviceContext, type DeviceWrapper } from './device-store.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import type { RememberedProfiles } from './remembered-profiles.js';

export class PairingClientError extends Error {
  constructor(readonly code: 'INVALID_PAIRING' | 'FINGERPRINT_MISMATCH' | 'TRUST_REQUIRED' | 'INCOMPLETE_KEYS' | 'CONFLICT' | 'STORAGE' | 'NOT_FOUND' | 'CANCELLED') {
    super(`Device pairing failed (${code})`); this.name = 'PairingClientError';
  }
}
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
const same = (one: unknown, two: unknown) => canonicalJson(one) === canonicalJson(two);
const keyEntry = z.strictObject({ epoch: positiveCounter, key: binary(32) });
const keyEntries = z.array(keyEntry).min(1).max(4096).refine((entries) => new Set(entries.map((entry) => entry.epoch)).size === entries.length);
const custodyManifest = z.strictObject({ version: z.literal(1), custodyEpoch: positiveCounter, workspaceKeys: keyEntries,
  projectKeys: z.array(z.strictObject({ projectId: identifier, keys: keyEntries })).max(4096) });
const custodyPayload = z.strictObject({ version: z.literal(1), mode: z.literal('custody'), custodyEpoch: positiveCounter,
  custodyKey: binary(32), manifest: z.strictObject({ id: identifier, digest }) });
const initialCustodyPayload = z.strictObject({ version: z.literal(1), custodyEpoch: positiveCounter, custodyKey: binary(32) });
const contentPayload = z.strictObject({ version: z.literal(1), mode: z.literal('content'), scope: z.enum(['workspace', 'project']),
  scopeId: identifier, keyEpoch: positiveCounter, keys: keyEntries });
const materialSchema = z.strictObject({ id: identifier, digest, kind: z.string().max(64), value: z.unknown() });
const materialList = z.array(materialSchema).max(4096);
export const pairingViewSchema = z.strictObject({ operationId: identifier,
  state: z.enum(['waiting_approver', 'verifying', 'confirmed', 'completed', 'expired', 'cancelled']), request: pairingBegin,
  transcript: pairingTranscript.nullable(), transcriptDigest: digest.nullable(), recipientConfirmation: pairingConfirmation.nullable(),
  approverConfirmation: pairingConfirmation.nullable(), approvalStaged: z.boolean(), receipt: pairingReceipt.nullable() });
export const pairingDeliverySchema = z.strictObject({ receipt: pairingReceipt, deliveries: pairingApproval.shape.deliveries, materials: materialList });
export const pairingDeviceInput = z.strictObject({ context: deviceContext, exportKey: binary(32, 1024) });
export type PairingDeviceInput = z.infer<typeof pairingDeviceInput>;
export const pairingRecipientInput = z.strictObject({ transcript: pairingTranscript, fingerprint: digest, wrapper: deviceWrapper, exportKey: binary(32, 1024) });
export type PairingRecipientInput = z.infer<typeof pairingRecipientInput>;
export interface PairingApproverInput { transcript: PairingTranscript; fingerprint: string; history: SecurityHistoryInput }
export interface PreparePairingApprovalInput extends PairingApproverInput {
  recipientConfirmation: PairingConfirmation; approverConfirmation: PairingConfirmation; materials: PairingMaterial[];
}
export interface VerifyPairingDeliveryInput { delivery: PairingDelivery; history: SecurityHistoryInput }

/** Full SHA-256 only: callers obtain this through a separate trusted channel/QR. */
export async function verifyPairingFingerprint(transcript: PairingTranscript, supplied: string): Promise<string> {
  const value = pairingTranscript.parse(copy(transcript));
  const normalized = typeof supplied === 'string' ? supplied.trim().toLowerCase() : '';
  const fingerprint = await digestObject(value);
  if (!digest.safeParse(normalized).success || normalized !== fingerprint) throw new PairingClientError('FINGERPRINT_MISMATCH');
  if (Date.parse(value.expiresAt) <= Date.now() || Date.parse(value.issuedAt) > Date.now() + 30_000) throw new PairingClientError('INVALID_PAIRING');
  return fingerprint;
}
function contextFor(transcript: PairingTranscript): DeviceContext {
  return { workspaceId: transcript.workspaceId, accountId: transcript.accountId, deviceId: transcript.device.id,
    credentialGeneration: transcript.credentialGeneration };
}
/** Worker-only; no private key material crosses its response boundary. */
export async function createPairingDevice(input: PairingDeviceInput) {
  const accepted = pairingDeviceInput.parse(input);
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  try {
    const device = { id: accepted.context.deviceId, keyGeneration: '1', signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
    const wrapper = await wrapDeviceBundle(accepted.context, { signingPrivateKey: base64urlEncode(signing.privateKey),
      recipientPrivateKey: base64urlEncode(recipient.privateKey), signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey }, accepted.exportKey);
    return { device, wrapper };
  } finally { signing.privateKey.fill(0); recipient.privateKey.fill(0); }
}
export async function verifyPairingDevice(input: PairingDeviceInput & { wrapper: DeviceWrapper }) {
  const bundle = await unwrapDeviceBundle(input.context, input.wrapper, input.exportKey);
  return { deviceId: input.context.deviceId, signingPublicKey: bundle.signingPublicKey, recipientPublicKey: bundle.recipientPublicKey };
}
export async function confirmPairingRecipient(input: PairingRecipientInput): Promise<PairingConfirmation> {
  const accepted = pairingRecipientInput.parse(copy(input)), transcript = accepted.transcript;
  const fingerprint = await verifyPairingFingerprint(transcript, accepted.fingerprint);
  if (await digestObject(accepted.wrapper) !== transcript.localBundleDigest) throw new PairingClientError('INVALID_PAIRING');
  const bundle = await unwrapDeviceBundle(contextFor(transcript), accepted.wrapper, accepted.exportKey);
  if (bundle.signingPublicKey !== transcript.device.signingPublicKey || bundle.recipientPublicKey !== transcript.device.recipientPublicKey) throw new PairingClientError('INVALID_PAIRING');
  const key = base64urlDecode(bundle.signingPrivateKey, 64);
  try { return signObject(pairingConfirmationFor(transcript, fingerprint, 'recipient'), key); } finally { key.fill(0); }
}
async function verifiedHistory(input: SecurityHistoryInput, transcript: PairingTranscript): Promise<SecurityHistoryState> {
  if (input.workspaceId !== transcript.workspaceId || input.origin !== transcript.origin || input.genesisFingerprint !== transcript.genesisFingerprint ||
    input.expected.securityHead !== transcript.securityHead || input.expected.securityVersion !== transcript.securityVersion) throw new PairingClientError('INVALID_PAIRING');
  const state = await verifySecurityHistory(input);
  const approver = state.devices[transcript.approverDevice.id], profile = state.profiles[transcript.approverAccountId];
  if (!approver?.active || !profile?.active || approver.accountId !== transcript.approverAccountId || profile.owner !== transcript.approverIsOwner ||
    approver.signingPublicKey !== transcript.approverDevice.signingPublicKey || approver.recipientPublicKey !== transcript.approverDevice.recipientPublicKey ||
    approver.keyGeneration !== transcript.approverDevice.keyGeneration || profile.credentialGeneration !== transcript.approverCredentialGeneration ||
    profile.sessionGeneration !== transcript.approverSessionGeneration || state.dataGeneration !== transcript.dataGeneration ||
    state.ownershipVersion !== transcript.ownershipVersion || state.custodyEpoch !== transcript.custodyEpoch ||
    (!profile.owner && transcript.accountId !== transcript.approverAccountId)) throw new PairingClientError('INVALID_PAIRING');
  const recipient = state.profiles[transcript.accountId];
  if (!recipient?.active || recipient.credentialGeneration !== transcript.credentialGeneration || recipient.sessionGeneration !== transcript.sessionGeneration) throw new PairingClientError('INVALID_PAIRING');
  const covers = (known: HistoryScope, scope: PairingScope) => known.scope === scope.scope && known.scopeId === scope.scopeId &&
    known.mode === scope.mode && known.keyEpoch === scope.keyEpoch && scope.permissions.every((permission) => known.permissions.includes(permission)) &&
    (known.expiresAt === null || (scope.expiresAt !== null && Date.parse(scope.expiresAt) <= Date.parse(known.expiresAt)));
  if (new Set(transcript.scopes.map((scope) => `${scope.scope}:${scope.scopeId}`)).size !== transcript.scopes.length) throw new PairingClientError('INVALID_PAIRING');
  for (const scope of transcript.scopes) {
    if (new Set(scope.permissions).size !== scope.permissions.length || new Set(scope.sources.map((source) => source.grantId)).size !== scope.sources.length) throw new PairingClientError('INVALID_PAIRING');
    const known = recipient.scopes.find((entry) => covers(entry, scope));
    if (!known || (recipient.accountId === profile.accountId && !approver.scopes.some((entry) => covers(entry, scope))) ||
      (scope.expiresAt !== null && Date.parse(scope.expiresAt) <= Date.now())) throw new PairingClientError('INVALID_PAIRING');
    const manifests = [...known.manifests, ...Object.values(state.devices).filter((device) => device.active && device.accountId === recipient.accountId)
      .flatMap((device) => device.scopes.filter((entry) => covers(entry, scope)).flatMap((entry) => entry.manifests))];
    if (scope.sources.some((source) => !manifests.some((item) => item.id === source.manifestId && item.digest === source.manifestDigest))) throw new PairingClientError('INVALID_PAIRING');
  }
  return state;
}
export async function confirmPairingApprover(input: PairingApproverInput, bundle: DeviceBundle): Promise<PairingConfirmation> {
  const transcript = pairingTranscript.parse(copy(input.transcript));
  const fingerprint = await verifyPairingFingerprint(transcript, input.fingerprint);
  await verifiedHistory(input.history, transcript);
  if (bundle.signingPublicKey !== transcript.approverDevice.signingPublicKey || bundle.recipientPublicKey !== transcript.approverDevice.recipientPublicKey) throw new PairingClientError('INVALID_PAIRING');
  const key = base64urlDecode(bundle.signingPrivateKey, 64);
  try { return signObject(pairingConfirmationFor(transcript, fingerprint, 'approver'), key); } finally { key.fill(0); }
}
async function verifyConfirmations(transcript: PairingTranscript, fingerprint: string, recipient: PairingConfirmation, approver: PairingConfirmation) {
  for (const [role, proof, publicKey] of [['recipient', recipient, transcript.device.signingPublicKey], ['approver', approver, transcript.approverDevice.signingPublicKey]] as const) {
    if (!same(proof.body, pairingConfirmationFor(transcript, fingerprint, role)) ||
      !await verifyObject(proof, base64urlDecode(publicKey, 32), 'ukda.device-pair-confirmation.v1')) throw new PairingClientError('INVALID_PAIRING');
  }
}
async function materialsById(materials: PairingMaterial[]): Promise<Map<string, PairingMaterial>> {
  const map = new Map<string, PairingMaterial>();
  for (const item of materialList.parse(copy(materials))) {
    if (map.has(item.id) || await digestObject(item.value) !== item.digest) throw new PairingClientError('INCOMPLETE_KEYS');
    map.set(item.id, item);
  }
  return map;
}
function signer(state: SecurityHistoryState, deviceId: string, accountId: string, keyGeneration: string): Uint8Array {
  const device = state.devices[deviceId];
  if (!device || device.accountId !== accountId || device.keyGeneration !== keyGeneration) throw new PairingClientError('INCOMPLETE_KEYS');
  return base64urlDecode(device.signingPublicKey, 32);
}
async function openCustodyManifest(id: string, expectedDigest: string, custodyKey: string, epoch: string,
  materials: Map<string, PairingMaterial>, state: SecurityHistoryState) {
  const item = materials.get(id);
  if (!item || item.digest !== expectedDigest || item.kind !== 'custody_manifest') throw new PairingClientError('INCOMPLETE_KEYS');
  const envelope = contentEnvelope.parse(item.value), header = envelope.header;
  if (header.workspaceId !== state.workspaceId || header.scope !== 'workspace' || header.scopeId !== state.workspaceId || header.recordId !== id || header.recordType !== 'custody') throw new PairingClientError('INCOMPLETE_KEYS');
  const key = base64urlDecode(custodyKey, 32);
  try {
    const manifest = custodyManifest.parse(await decryptContent(envelope, key, signer(state, header.deviceId, header.accountId, header.keyGeneration), header));
    if (manifest.custodyEpoch !== epoch) throw new PairingClientError('INCOMPLETE_KEYS');
    return manifest;
  } finally { key.fill(0); }
}
function scopeMatches(value: { scope: string; scopeId: string }, scope: PairingScope) { return value.scope === scope.scope && value.scopeId === scope.scopeId; }
async function scopePayload(scope: PairingScope, transcript: Pick<PairingTranscript, 'workspaceId' | 'custodyEpoch' | 'approverAccountId' | 'approverDevice'>, state: SecurityHistoryState,
  materials: Map<string, PairingMaterial>, bundle: DeviceBundle) {
  for (const source of scope.sources) if (materials.get(source.manifestId)?.digest !== source.manifestDigest) throw new PairingClientError('INCOMPLETE_KEYS');
  const opened: unknown[] = [];
  const recipientKey = base64urlDecode(bundle.recipientPrivateKey, 32);
  try {
    for (const item of materials.values()) {
      if (item.kind !== 'key_envelope') continue;
      const parsed = recipientEnvelope.safeParse(item.value); if (!parsed.success) throw new PairingClientError('INCOMPLETE_KEYS');
      const header = parsed.data.header;
      if (header.recipientId !== transcript.approverDevice.id || header.recipientKind !== 'device' || header.recipientAccountId !== transcript.approverAccountId ||
        header.recipientPublicKey !== bundle.recipientPublicKey || header.workspaceId !== transcript.workspaceId ||
        !(scopeMatches(header, scope) || (scope.mode === 'content' && header.scope === 'workspace'))) continue;
      opened.push(await openRecipient(parsed.data, recipientKey, signer(state, header.senderDeviceId, header.senderAccountId, header.senderKeyGeneration), header));
    }
  } finally { recipientKey.fill(0); }
  for (const value of opened) {
    const delivered = custodyPayload.safeParse(value), initial = initialCustodyPayload.safeParse(value);
    if (!delivered.success && !initial.success) continue;
    const custody = delivered.success ? delivered.data : initial.data!;
    if (custody.custodyEpoch !== transcript.custodyEpoch) continue;
    const references = delivered.success ? [delivered.data.manifest] : [...materials.values()].filter((item) => item.kind === 'custody_manifest').map((item) => ({ id: item.id, digest: item.digest }));
    for (const ref of references) {
      const manifest = await openCustodyManifest(ref.id, ref.digest, custody.custodyKey, custody.custodyEpoch, materials, state);
      if (scope.mode === 'custody') return { version: 1 as const, mode: 'custody' as const, custodyEpoch: custody.custodyEpoch, custodyKey: custody.custodyKey, manifest: ref };
      const keys = scope.scope === 'workspace' ? manifest.workspaceKeys : manifest.projectKeys.find((item) => item.projectId === scope.scopeId)?.keys;
      if (keys?.some((key) => key.epoch === scope.keyEpoch)) return contentPayload.parse({ version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, keys });
    }
  }
  const merged = new Map<string, string>();
  for (const value of opened) {
    const parsed = contentPayload.safeParse(value);
    if (!parsed.success || !scopeMatches(parsed.data, scope) || parsed.data.keyEpoch !== scope.keyEpoch) continue;
    for (const key of parsed.data.keys) {
      if (merged.has(key.epoch) && merged.get(key.epoch) !== key.key) throw new PairingClientError('INCOMPLETE_KEYS');
      merged.set(key.epoch, key.key);
    }
  }
  if (scope.mode !== 'content' || !merged.has(scope.keyEpoch)) throw new PairingClientError('INCOMPLETE_KEYS');
  return contentPayload.parse({ version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch,
    keys: [...merged].sort(([a], [b]) => BigInt(a) < BigInt(b) ? -1 : 1).map(([epoch, key]) => ({ epoch, key })) });
}
/** Internal Worker reuse by reset/recovery; never export these plaintext results through RPC or persist them. */
export async function readDeviceScopeKeyMaterial(input: {
  scopes: PairingScope[]; holder: Pick<PairingTranscript, 'workspaceId' | 'custodyEpoch' | 'approverAccountId' | 'approverDevice'>;
  history: SecurityHistoryState; materials: PairingMaterial[];
}, bundle: DeviceBundle) {
  const materials = await materialsById(input.materials);
  return Promise.all(input.scopes.map((scope) => scopePayload(scope, input.holder, input.history, materials, bundle)));
}
/** Internal Worker-only rotation helper. The caller supplies independently replayed signed history. */
export async function readOwnerCustodyKeyMaterial(input: {
  accountId: string; deviceId: string; history: SecurityHistoryState; materials: PairingMaterial[];
}, bundle: DeviceBundle) {
  const state = input.history, profile = state.profiles[input.accountId], device = state.devices[input.deviceId];
  const eligible = (scope: HistoryScope) => scope.scope === 'workspace' && scope.scopeId === state.workspaceId &&
    scope.mode === 'custody' && scope.keyEpoch === state.custodyEpoch && scope.permissions.includes('read_project') &&
    (scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.now());
  if (!profile?.active || !profile.owner || !device?.active || device.accountId !== input.accountId ||
    device.signingPublicKey !== bundle.signingPublicKey || device.recipientPublicKey !== bundle.recipientPublicKey ||
    !device.scopes.some(eligible)) throw new PairingClientError('INCOMPLETE_KEYS');
  const scope = profile.scopes.find(eligible); if (!scope) throw new PairingClientError('INCOMPLETE_KEYS');
  const materials = await materialsById(input.materials);
  const sources = scope.manifests.filter((entry) => materials.get(entry.id)?.digest === entry.digest)
    .map((entry) => ({ grantId: device.id, generation: '1', manifestId: entry.id, manifestDigest: entry.digest }));
  if (!sources.length) throw new PairingClientError('INCOMPLETE_KEYS');
  const payload = custodyPayload.parse(await scopePayload({ scope: scope.scope, scopeId: scope.scopeId, mode: scope.mode,
    keyEpoch: scope.keyEpoch, permissions: scope.permissions, expiresAt: scope.expiresAt, sources },
  { workspaceId: state.workspaceId, custodyEpoch: state.custodyEpoch, approverAccountId: input.accountId,
    approverDevice: { id: device.id, keyGeneration: device.keyGeneration, signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey } }, state, materials, bundle));
  const manifest = await openCustodyManifest(payload.manifest.id, payload.manifest.digest, payload.custodyKey, state.custodyEpoch, materials, state);
  return { payload, manifest };
}
/** A current Owner's phrase unwraps only its independently pinned current custody hierarchy. */
export async function readRecoveryCustodyKeyMaterial(input: {
  accountId: string; recoveryId: string; recoveryGeneration: string; history: SecurityHistoryState; materials: PairingMaterial[];
}, recoveryRecipientKey: Uint8Array) {
  const state = input.history, profile = state.profiles[input.accountId], authority = state.recoveryAuthorities[`${input.accountId}:${input.recoveryGeneration}`];
  if (!profile?.active || !profile.owner || !authority?.active || authority.accountId !== input.accountId ||
    authority.id !== input.recoveryId || authority.generation !== input.recoveryGeneration || profile.recoveryGeneration !== authority.generation || authority.custodyEpoch !== state.custodyEpoch) throw new PairingClientError('INCOMPLETE_KEYS');
  const materials = await materialsById(input.materials), source = materials.get(authority.custodyEnvelope.id);
  if (!source || source.kind !== 'key_envelope' || source.digest !== authority.custodyEnvelope.digest) throw new PairingClientError('INCOMPLETE_KEYS');
  const envelope = recipientEnvelope.parse(source.value), header = envelope.header;
  if (header.workspaceId !== state.workspaceId || header.scope !== 'workspace' || header.scopeId !== state.workspaceId ||
    header.recipientKind !== 'recovery' || header.recipientAccountId !== input.accountId || header.recipientId !== authority.id ||
    header.recipientKeyGeneration !== authority.generation || header.recipientPublicKey !== authority.recipientPublicKey) throw new PairingClientError('INCOMPLETE_KEYS');
  const value = await openRecipient(envelope, recoveryRecipientKey, signer(state, header.senderDeviceId, header.senderAccountId, header.senderKeyGeneration), header);
  const delivered = custodyPayload.safeParse(value), initial = initialCustodyPayload.safeParse(value);
  if (!delivered.success && !initial.success) throw new PairingClientError('INCOMPLETE_KEYS');
  const custody = delivered.success ? delivered.data : initial.data!;
  if (custody.custodyEpoch !== state.custodyEpoch) throw new PairingClientError('INCOMPLETE_KEYS');
  const current = profile.scopes.filter((scope) => scope.scope === 'workspace' && scope.scopeId === state.workspaceId && scope.mode === 'custody')
    .flatMap((scope) => scope.manifests).filter((ref) => materials.get(ref.id)?.kind === 'custody_manifest');
  const references = delivered.success ? [delivered.data.manifest] : current;
  for (const reference of references) {
    // A recovery transition may make the current manifest an authenticated indirect
    // reference inside the exact authority-bound recipient envelope.
    if (!delivered.success && !current.some((ref) => ref.id === reference.id && ref.digest === reference.digest)) continue;
    const manifest = await openCustodyManifest(reference.id, reference.digest, custody.custodyKey, state.custodyEpoch, materials, state);
    return { payload: custodyPayload.parse({ version: 1, mode: 'custody', custodyEpoch: state.custodyEpoch, custodyKey: custody.custodyKey, manifest: reference }), manifest };
  }
  throw new PairingClientError('INCOMPLETE_KEYS');
}
/** Worker-only approver operation: all decrypted custody/content keys remain inside the worker. */
export async function preparePairingApproval(input: PreparePairingApprovalInput, bundle: DeviceBundle): Promise<PairingApproval> {
  const transcript = pairingTranscript.parse(copy(input.transcript));
  const fingerprint = await verifyPairingFingerprint(transcript, input.fingerprint), state = await verifiedHistory(input.history, transcript);
  await verifyConfirmations(transcript, fingerprint, input.recipientConfirmation, input.approverConfirmation);
  if (bundle.signingPublicKey !== transcript.approverDevice.signingPublicKey || bundle.recipientPublicKey !== transcript.approverDevice.recipientPublicKey) throw new PairingClientError('INVALID_PAIRING');
  const materials = await materialsById(input.materials), signing = base64urlDecode(bundle.signingPrivateKey, 64);
  try {
    const deliveries: PairingApproval['deliveries'] = [];
    for (const scope of transcript.scopes) deliveries.push({ id: crypto.randomUUID(), envelope: await sealRecipient(pairingRecipientHeader(transcript, fingerprint, scope),
      await scopePayload(scope, transcript, state, materials, bundle), signing) });
    const body = pairingGrantBody.parse({ version: 1, purpose: 'ukda.device-pair-grant.v1', operationId: transcript.operationId,
      workspaceId: transcript.workspaceId, grantId: transcript.operationId, securityVersion: (BigInt(transcript.securityVersion) + 1n).toString(),
      previousHead: transcript.securityHead, transcript, transcriptDigest: fingerprint, recipientConfirmation: input.recipientConfirmation,
      approverConfirmation: input.approverConfirmation, deliveries: await Promise.all(deliveries.map(async (item, index) => ({ id: item.id,
        scope: transcript.scopes[index]!.scope, scopeId: transcript.scopes[index]!.scopeId, digest: await digestObject(item.envelope) }))) });
    return pairingApproval.parse({ grant: await signObject(body, signing), deliveries });
  } finally { signing.fill(0); }
}
export async function verifyPairingReceipt(value: PairingReceipt, transcript: PairingTranscript): Promise<PairingReceipt> {
  const receipt = pairingReceipt.parse(copy(value)), grant = receipt.grant.body, fingerprint = await digestObject(transcript);
  if (!same(grant.transcript, transcript) || receipt.operationId !== transcript.operationId || receipt.workspaceId !== transcript.workspaceId ||
    receipt.accountId !== transcript.accountId || receipt.deviceId !== transcript.device.id || receipt.transcriptDigest !== fingerprint ||
    receipt.dataGeneration !== transcript.dataGeneration || receipt.securityVersion !== (BigInt(transcript.securityVersion) + 1n).toString() ||
    receipt.securityVersion !== grant.securityVersion || receipt.securityHead !== await digestObject(receipt.grant) ||
    grant.operationId !== transcript.operationId || grant.grantId !== transcript.operationId || grant.workspaceId !== transcript.workspaceId || receipt.grantId !== grant.grantId || grant.previousHead !== transcript.securityHead || grant.transcriptDigest !== fingerprint ||
    !await verifyObject(receipt.grant, base64urlDecode(transcript.approverDevice.signingPublicKey, 32), 'ukda.device-pair-grant.v1')) throw new PairingClientError('INVALID_PAIRING');
  await verifyConfirmations(transcript, fingerprint, grant.recipientConfirmation, grant.approverConfirmation);
  if (grant.deliveries.length !== transcript.scopes.length || new Set(grant.deliveries.map((item) => item.id)).size !== grant.deliveries.length || new Set(grant.deliveries.map((item) => `${item.scope}:${item.scopeId}`)).size !== transcript.scopes.length ||
    transcript.scopes.some((scope) => !grant.deliveries.some((item) => scopeMatches(item, scope)))) throw new PairingClientError('INVALID_PAIRING');
  return receipt;
}
/** Verifies/decrypts every required envelope without returning content or custody keys. */
export async function verifyPairingDelivery(input: VerifyPairingDeliveryInput, bundle: DeviceBundle): Promise<{ complete: true; scopeCount: number }> {
  const delivery = pairingDeliverySchema.parse(copy(input.delivery)), transcript = delivery.receipt.grant.body.transcript;
  await verifyPairingReceipt(delivery.receipt, transcript);
  const state = await verifySecurityHistory(input.history);
  if (state.workspaceId !== transcript.workspaceId || state.origin !== transcript.origin || state.genesisFingerprint !== transcript.genesisFingerprint ||
    BigInt(state.securityVersion) < BigInt(delivery.receipt.securityVersion) || !input.history.transitions.some((transition) => same(transition, delivery.receipt.grant)) ||
    bundle.signingPublicKey !== transcript.device.signingPublicKey || bundle.recipientPublicKey !== transcript.device.recipientPublicKey) throw new PairingClientError('INVALID_PAIRING');
  const device = state.devices[transcript.device.id], profile = state.profiles[transcript.accountId];
  if (!device?.active || !profile?.active || device.accountId !== transcript.accountId || device.keyGeneration !== transcript.device.keyGeneration ||
    device.signingPublicKey !== bundle.signingPublicKey || device.recipientPublicKey !== bundle.recipientPublicKey ||
    profile.credentialGeneration !== transcript.credentialGeneration || profile.sessionGeneration !== transcript.sessionGeneration ||
    state.dataGeneration !== transcript.dataGeneration) throw new PairingClientError('INVALID_PAIRING');
  for (const scope of transcript.scopes) {
    const descriptor = delivery.receipt.grant.body.deliveries.find((entry) => scopeMatches(entry, scope));
    if ((scope.mode === 'custody' && (!profile.owner || state.custodyEpoch !== transcript.custodyEpoch)) ||
      !device.scopes.some((known) => scopeMatches(known, scope) && known.mode === scope.mode && known.keyEpoch === scope.keyEpoch &&
        scope.permissions.every((permission) => known.permissions.includes(permission)) && (known.expiresAt === null || Date.parse(known.expiresAt) > Date.now()) &&
        known.manifests.some((item) => item.id === descriptor?.id && item.digest === descriptor.digest))) throw new PairingClientError('INVALID_PAIRING');
  }
  const materials = await materialsById(delivery.materials), recipient = base64urlDecode(bundle.recipientPrivateKey, 32);
  try {
    if (delivery.deliveries.length !== transcript.scopes.length || new Set(delivery.deliveries.map((item) => item.id)).size !== delivery.deliveries.length) throw new PairingClientError('INCOMPLETE_KEYS');
    for (const scope of transcript.scopes) {
      const expected = delivery.receipt.grant.body.deliveries.find((item) => scopeMatches(item, scope));
      const envelope = delivery.deliveries.find((item) => item.id === expected?.id)?.envelope;
      if (!expected || !envelope || await digestObject(envelope) !== expected.digest) throw new PairingClientError('INCOMPLETE_KEYS');
      const payload = await openRecipient(envelope, recipient, base64urlDecode(transcript.approverDevice.signingPublicKey, 32), pairingRecipientHeader(transcript, delivery.receipt.transcriptDigest, scope));
      if (scope.mode === 'custody') {
        const custody = custodyPayload.parse(payload);
        if (custody.custodyEpoch !== transcript.custodyEpoch) throw new PairingClientError('INCOMPLETE_KEYS');
        await openCustodyManifest(custody.manifest.id, custody.manifest.digest, custody.custodyKey, custody.custodyEpoch, materials, state);
      } else {
        const content = contentPayload.parse(payload);
        if (!scopeMatches(content, scope) || content.keyEpoch !== scope.keyEpoch || !content.keys.some((item) => item.epoch === scope.keyEpoch)) throw new PairingClientError('INCOMPLETE_KEYS');
      }
    }
    return { complete: true, scopeCount: transcript.scopes.length };
  } finally { recipient.fill(0); }
}

const recipientRecord = z.strictObject({ role: z.literal('recipient'), operationId: identifier, revision: z.number().int().positive(),
  origin: z.string().url(), context: deviceContext, request: pairingBegin, wrapper: deviceWrapper,
  transcript: pairingTranscript.nullable(), confirmation: pairingConfirmation.nullable(), receipt: pairingReceipt.nullable(),
  delivery: pairingDeliverySchema.nullable(), ready: z.boolean() });
const approverRecord = z.strictObject({ role: z.literal('approver'), operationId: identifier, revision: z.number().int().positive(),
  origin: z.string().url(), workspaceId: identifier, accountId: identifier, deviceId: identifier,
  transcript: pairingTranscript, confirmation: pairingConfirmation.nullable(), approval: pairingApproval.nullable(), receipt: pairingReceipt.nullable() });
const pairingRecord = z.discriminatedUnion('role', [recipientRecord, approverRecord]);
export type PairingRecipientRecord = z.infer<typeof recipientRecord>;
export type PairingApproverRecord = z.infer<typeof approverRecord>;
export type PairingRecord = z.infer<typeof pairingRecord>;
const pinRecord = z.strictObject({ origin: z.string().url(), workspaceId: identifier, pin: securityPin });
const recordKey = (origin: string, role: PairingRecord['role'], operationId: string) => `${origin}:${role}:${operationId}`;

/** Only signed public protocol metadata and encrypted wrappers/envelopes are persisted. */
export class IndexedPairingStore {
  private closed = false;
  private constructor(readonly origin: string, private readonly database: IDBDatabase) {
    database.onversionchange = () => this.close(); database.onclose = () => { this.closed = true; };
  }
  static async open(origin: string, name = 'ukda-pairing-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedPairingStore> {
    const accepted = new AuthenticatedHttp(origin).origin;
    if (!factory) throw new PairingClientError('STORAGE');
    return new Promise((resolve, reject) => {
      let settled = false;
      const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new PairingClientError('STORAGE')); };
      request.onerror = request.onblocked = fail;
      request.onupgradeneeded = () => { request.result.createObjectStore('operations'); request.result.createObjectStore('pins'); };
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedPairingStore(accepted, request.result)); };
    });
  }
  private transaction<T>(name: string, mode: IDBTransactionMode, action: (store: IDBObjectStore, done: (value: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    if (this.closed) return Promise.reject(new PairingClientError('STORAGE'));
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction;
      try { transaction = this.database.transaction(name, mode, mode === 'readwrite' ? { durability: 'strict' } : {}); }
      catch { reject(new PairingClientError('STORAGE')); return; }
      let value: T, complete = false, failure: unknown;
      const fail = (error: unknown) => { failure = error instanceof PairingClientError ? error : new PairingClientError('STORAGE'); try { transaction.abort(); } catch { reject(failure); } };
      transaction.onabort = () => reject(failure ?? new PairingClientError('STORAGE'));
      transaction.oncomplete = () => complete ? resolve(value) : reject(new PairingClientError('STORAGE'));
      try { action(transaction.objectStore(name), (result) => { value = result; complete = true; }, fail); } catch (error) { fail(error); }
    });
  }
  async get(role: 'recipient', operationId: string): Promise<PairingRecipientRecord | undefined>;
  async get(role: 'approver', operationId: string): Promise<PairingApproverRecord | undefined>;
  async get(role: PairingRecord['role'], operationId: string): Promise<PairingRecord | undefined> {
    identifier.parse(operationId);
    return this.transaction('operations', 'readonly', (store, done, fail) => {
      const request = store.get(recordKey(this.origin, role, operationId));
      request.onsuccess = () => { try {
        const record = request.result === undefined ? undefined : pairingRecord.parse(request.result);
        if (record && (record.origin !== this.origin || record.operationId !== operationId || record.role !== role)) throw new PairingClientError('STORAGE');
        done(record);
      } catch (error) { fail(error); } };
    });
  }
  /** Compare-and-swap prevents another tab from overwriting a different immutable draft. */
  async save<T extends PairingRecord>(value: T, expectedRevision: number | null): Promise<T> {
    const accepted = pairingRecord.parse(copy(value));
    if (accepted.origin !== this.origin || accepted.revision !== (expectedRevision ?? 0) + 1) throw new PairingClientError('CONFLICT');
    if (accepted.role === 'recipient' && (accepted.operationId !== accepted.request.operationId || accepted.context.deviceId !== accepted.request.device.id ||
      !same(contextForWrapper(accepted.wrapper), accepted.context))) throw new PairingClientError('INVALID_PAIRING');
    return this.transaction('operations', 'readwrite', (store, done, fail) => {
      const key = recordKey(this.origin, accepted.role, accepted.operationId), request = store.get(key);
      request.onsuccess = () => { try {
        const existing = request.result === undefined ? undefined : pairingRecord.parse(request.result);
        if ((existing?.revision ?? null) !== expectedRevision) {
          if (existing && same(existing, accepted)) { done(existing as T); return; }
          throw new PairingClientError('CONFLICT');
        }
        if (existing && (existing.role !== accepted.role || (existing.role === 'recipient' && accepted.role === 'recipient' &&
          (!same(existing.context, accepted.context) || !same(existing.request, accepted.request) || !same(existing.wrapper, accepted.wrapper))) ||
          (existing.role === 'approver' && accepted.role === 'approver' && !same(existing.transcript, accepted.transcript)))) throw new PairingClientError('CONFLICT');
        store.put(accepted, key); done(accepted as T);
      } catch (error) { fail(error); } };
    });
  }
  async list(): Promise<{ role: PairingRecord['role']; operationId: string; workspaceId: string; accountId: string; deviceId: string; completed: boolean }[]> {
    return this.transaction('operations', 'readonly', (store, done, fail) => {
      const request = store.getAll(); request.onsuccess = () => { try {
        done((request.result as unknown[]).map((item) => pairingRecord.parse(item)).filter((item) => item.origin === this.origin).map((item) => {
          const context = item.role === 'recipient' ? item.context : item;
          return { role: item.role, operationId: item.operationId, workspaceId: context.workspaceId, accountId: context.accountId, deviceId: context.deviceId, completed: item.receipt !== null };
        }));
      } catch (error) { fail(error); } };
    });
  }
  async pin(workspaceId: string): Promise<SecurityPin | undefined> {
    identifier.parse(workspaceId);
    return this.transaction('pins', 'readonly', (store, done, fail) => {
      const request = store.get(`${this.origin}:${workspaceId}`); request.onsuccess = () => { try {
        const value = request.result === undefined ? undefined : pinRecord.parse(request.result);
        if (value && (value.origin !== this.origin || value.workspaceId !== workspaceId)) throw new PairingClientError('STORAGE');
        done(value?.pin);
      } catch (error) { fail(error); } };
    });
  }
  /** Independent trust is an activation draft/receipt, prior pin, or full compared fingerprint. */
  async recordVerifiedHistory(input: SecurityHistoryInput): Promise<SecurityPin> {
    if (input.origin !== this.origin) throw new PairingClientError('INVALID_PAIRING');
    const previous = await this.pin(input.workspaceId);
    const state = await verifySecurityHistory({ ...input, ...(previous ? { pin: previous } : {}) });
    const next = securityPin.parse({ genesisFingerprint: state.genesisFingerprint, securityHead: state.securityHead, securityVersion: state.securityVersion });
    return this.transaction('pins', 'readwrite', (store, done, fail) => {
      const key = `${this.origin}:${input.workspaceId}`, request = store.get(key);
      request.onsuccess = () => { try {
        const current = request.result === undefined ? undefined : pinRecord.parse(request.result).pin;
        if (current && (current.genesisFingerprint !== next.genesisFingerprint || BigInt(current.securityVersion) > BigInt(next.securityVersion) ||
          (current.securityVersion === next.securityVersion && current.securityHead !== next.securityHead))) throw new PairingClientError('CONFLICT');
        if (!same(current ?? null, previous ?? null) && !same(current, next)) throw new PairingClientError('CONFLICT');
        store.put({ origin: this.origin, workspaceId: input.workspaceId, pin: next }, key); done(next);
      } catch (error) { fail(error); } };
    });
  }
  /** Forget removes encrypted pending copies; workspace-level rollback pins remain. */
  async forget(reference: Pick<DeviceContext, 'workspaceId' | 'accountId' | 'deviceId'>): Promise<void> {
    deviceContext.parse({ ...reference, credentialGeneration: '1' });
    return this.transaction('operations', 'readwrite', (store, done, fail) => {
      const request = store.openCursor(); request.onsuccess = () => { try {
        const cursor = request.result; if (!cursor) { done(); return; }
        // Ciphertext corruption must not prevent explicitly forgetting its identity.
        // Unrelated malformed rows cannot be attributed safely and do not block cleanup.
        const item = z.object({ origin: z.string(), context: z.unknown().optional() }).safeParse(cursor.value);
        const identity = z.object({ workspaceId: identifier, accountId: identifier, deviceId: identifier });
        const contexts = [identity.safeParse(item.success ? item.data.context : undefined), identity.safeParse(cursor.value)];
        if (item.success && item.data.origin === this.origin && contexts.some((context) => context.success &&
          context.data.workspaceId === reference.workspaceId && context.data.accountId === reference.accountId && context.data.deviceId === reference.deviceId)) cursor.delete();
        cursor.continue();
      } catch (error) { fail(error); } };
    });
  }
  close(): void { if (!this.closed) { this.closed = true; this.database.close(); } }
}
function contextForWrapper(wrapper: DeviceWrapper): DeviceContext { const { workspaceId, accountId, deviceId, credentialGeneration } = wrapper.header; return { workspaceId, accountId, deviceId, credentialGeneration }; }

const historyHead = z.strictObject({ securityHead: digest, securityVersion: positiveCounter });
export const historyResponse = z.strictObject({ workspaceId: identifier, operationId: identifier, mode: z.enum(['transcript', 'current']),
  anchor: historyHead, current: historyHead, afterVersion: counter, genesis: z.strictObject({ body: genesisBody, signature: binary(64) }).nullable(),
  transitions: z.array(z.unknown()).max(256), nextAfterVersion: positiveCounter.nullable() });
export interface PairingHistoryResponse { genesis: SecurityHistoryInput['genesis']; transitions: unknown[];
  anchor: { securityHead: string; securityVersion: string }; current: { securityHead: string; securityVersion: string } }

export interface PairingTransport {
  readonly origin: string;
  begin(csrf: string, input: PairingBegin, options?: AuthRequestOptions): Promise<PairingView>;
  inspect(operationId: string, options?: AuthRequestOptions): Promise<PairingView>;
  claim(csrf: string, operationId: string, options?: AuthRequestOptions): Promise<PairingView>;
  confirm(csrf: string, input: PairingConfirmation, options?: AuthRequestOptions): Promise<PairingView>;
  materials(operationId: string, options?: AuthRequestOptions): Promise<PairingMaterial[]>;
  stage(csrf: string, input: PairingApproval, options?: AuthRequestOptions): Promise<PairingView>;
  commit(csrf: string, operationId: string, options?: AuthRequestOptions): Promise<{ receipt: PairingReceipt; projection: unknown }>;
  delivery(operationId: string, options?: AuthRequestOptions): Promise<PairingDelivery>;
  history(operationId: string, mode: 'transcript' | 'current', options?: AuthRequestOptions): Promise<PairingHistoryResponse>;
}
export class HttpPairingTransport extends AuthenticatedHttp implements PairingTransport {
  begin(csrfToken: string, input: PairingBegin, options?: AuthRequestOptions) { return this.post('/v1/auth/pairing/begin', input, pairingViewSchema, { ...options, csrfToken }); }
  inspect(operationId: string, options?: AuthRequestOptions) { return this.post('/v1/auth/pairing/inspect', { operationId }, pairingViewSchema, options); }
  claim(csrfToken: string, operationId: string, options?: AuthRequestOptions) { return this.post('/v1/auth/pairing/claim', { operationId }, pairingViewSchema, { ...options, csrfToken }); }
  confirm(csrfToken: string, input: PairingConfirmation, options?: AuthRequestOptions) { return this.post('/v1/auth/pairing/confirm', input, pairingViewSchema, { ...options, csrfToken }); }
  materials(operationId: string, options?: AuthRequestOptions) { return this.post('/v1/auth/pairing/materials', { operationId }, materialList, options); }
  stage(csrfToken: string, input: PairingApproval, options?: AuthRequestOptions) { return this.post('/v1/auth/pairing/stage', input, pairingViewSchema, { ...options, csrfToken }); }
  commit(csrfToken: string, operationId: string, options?: AuthRequestOptions) { return this.post('/v1/auth/pairing/commit', { operationId }, z.strictObject({ receipt: pairingReceipt, projection: z.unknown() }), { ...options, csrfToken }); }
  delivery(operationId: string, options?: AuthRequestOptions) { return this.post('/v1/auth/pairing/delivery', { operationId }, pairingDeliverySchema, options); }
  protected override responseLimit(path: string): number { return path === '/v1/auth/pairing/history' ? 3 * 1_048_576 : super.responseLimit(path); }
  async history(operationId: string, mode: 'transcript' | 'current', options?: AuthRequestOptions): Promise<PairingHistoryResponse> {
    return readSecurityHistoryPages(operationId, mode, (request) => this.post('/v1/auth/pairing/history', request, historyResponse, options));
  }
}

/** Shared bounded assembler; the transport supplies its own authenticated page endpoint. */
export async function readSecurityHistoryPages(operationId: string, mode: 'transcript' | 'current',
  fetchPage: (request: { operationId: string; mode: 'transcript' | 'current'; anchor?: PairingHistoryResponse['anchor']; afterVersion?: string }) => Promise<z.infer<typeof historyResponse>>): Promise<PairingHistoryResponse> {
    identifier.parse(operationId);
    let anchor: PairingHistoryResponse['anchor'] | undefined, current: PairingHistoryResponse['current'] | undefined;
    let genesis: PairingHistoryResponse['genesis'] | undefined, workspaceId: string | undefined, afterVersion = '0';
    const transitions: unknown[] = [];
    for (let pageNumber = 0; pageNumber < 100000; pageNumber++) {
      const page = await fetchPage({ operationId, mode, ...(anchor ? { anchor, afterVersion } : {}) });
      if (page.afterVersion !== afterVersion || page.operationId !== operationId || page.mode !== mode || (workspaceId && page.workspaceId !== workspaceId) ||
        (anchor && !same(page.anchor, anchor)) || BigInt(page.current.securityVersion) < BigInt(page.anchor.securityVersion) ||
        (current && (BigInt(page.current.securityVersion) < BigInt(current.securityVersion) ||
        (page.current.securityVersion === current.securityVersion && page.current.securityHead !== current.securityHead)))) throw new PairingClientError('INVALID_PAIRING');
      anchor ??= page.anchor; current = page.current; workspaceId ??= page.workspaceId;
      if (pageNumber === 0) {
        if (!page.genesis || page.genesis.body.workspaceId !== workspaceId) throw new PairingClientError('INVALID_PAIRING');
        genesis = page.genesis;
      } else if (page.genesis !== null) throw new PairingClientError('INVALID_PAIRING');
      const records = [...(page.genesis ? [page.genesis] : []), ...page.transitions];
      if (records.length === 0 || records.some((record) => new TextEncoder().encode(canonicalJson(record)).length > 1_048_576)) throw new PairingClientError('INVALID_PAIRING');
      const next = String(BigInt(afterVersion) + BigInt(records.length));
      if (BigInt(next) > BigInt(anchor.securityVersion) || transitions.length + page.transitions.length > 100000 ||
        (page.nextAfterVersion !== null && (page.nextAfterVersion !== next || next === anchor.securityVersion))) throw new PairingClientError('INVALID_PAIRING');
      transitions.push(...page.transitions);
      if (page.nextAfterVersion === null) {
        if (next !== anchor.securityVersion || !genesis) throw new PairingClientError('INVALID_PAIRING');
        if (mode === 'current' && !same(current, anchor)) throw new PairingClientError('CONFLICT');
        return { genesis, transitions, anchor, current };
      }
      afterVersion = next;
    }
    throw new PairingClientError('INVALID_PAIRING');
}

/** Called only after ActivationController has matched the HTTPS receipt to its local draft. */
export async function seedActivationPin(store: IndexedPairingStore, genesis: SecurityHistoryInput['genesis'],
  receipt: { workspaceId: string; accountId: string; deviceId: string; operationId: string; genesisFingerprint: string; securityHead: string; securityVersion: string }): Promise<SecurityPin> {
  if (genesis.body.workspaceId !== receipt.workspaceId || genesis.body.accountId !== receipt.accountId || genesis.body.device.id !== receipt.deviceId ||
    genesis.body.operationId !== receipt.operationId || receipt.securityVersion !== '1' || receipt.securityHead !== receipt.genesisFingerprint ||
    await digestObject(genesis) !== receipt.genesisFingerprint) throw new PairingClientError('INVALID_PAIRING');
  return store.recordVerifiedHistory({ workspaceId: receipt.workspaceId, origin: store.origin, genesisFingerprint: receipt.genesisFingerprint,
    genesis, transitions: [], expected: { securityHead: receipt.securityHead, securityVersion: receipt.securityVersion } });
}
export type PairingProgress = { operationId: string; state: PairingView['state'] | 'content_ready'; deviceId: string; fingerprint: string | null };
/** Coordinates durable ciphertext only; password/export keys and unwrapped keys never enter its store. */
export class PairingController {
  private operation: AbortController | undefined;
  private epoch = 0;
  private readonly detach: (() => void)[];
  constructor(private readonly auth: AuthController, private readonly transport: PairingTransport,
    private readonly devices: IndexedDeviceStore, readonly store: IndexedPairingStore,
    private readonly options: { remembered?: RememberedProfiles; trustedServiceKeys?: Record<string, string> } = {}) {
    if (auth.origin !== transport.origin || store.origin !== auth.origin || (options.remembered && options.remembered.origin !== auth.origin)) throw new PairingClientError('INVALID_PAIRING');
    this.detach = [auth.onClear(() => this.clear()), auth.onForget((reference) => store.forget(reference))];
  }
  clear(): void { this.epoch++; this.operation?.abort(); this.operation = undefined; }
  close(): void { this.clear(); this.detach.forEach((detach) => detach()); }
  private check(epoch: number) { if (this.epoch !== epoch) throw new PairingClientError('CANCELLED'); }
  private async run<T>(action: (signal: AbortSignal, epoch: number) => Promise<T>): Promise<T> {
    if (this.operation) throw new PairingClientError('CONFLICT');
    const operation = new AbortController(), epoch = this.epoch; this.operation = operation;
    try { const value = await action(operation.signal, epoch); this.check(epoch); return value; }
    finally { if (this.operation === operation) this.operation = undefined; }
  }
  private session(approved = false) {
    const state = this.auth.current();
    if (!state || (approved && (state.localAccess !== 'unlocked' || state.session.accessLevel !== 'device_approved'))) throw new AuthClientError('AUTH_REQUIRED');
    return state.session;
  }
  private recipient(record: PairingRecipientRecord) {
    const session = this.session();
    if (session.workspaceId !== record.context.workspaceId || session.accountId !== record.context.accountId ||
      session.credentialGeneration !== record.context.credentialGeneration) throw new PairingClientError('INVALID_PAIRING');
    return session;
  }
  private approver(record: PairingApproverRecord) {
    const session = this.session(true);
    if (session.workspaceId !== record.workspaceId || session.accountId !== record.accountId || session.deviceId !== record.deviceId ||
      session.credentialGeneration !== record.transcript.approverCredentialGeneration || session.sessionGeneration !== record.transcript.approverSessionGeneration) throw new PairingClientError('INVALID_PAIRING');
    return session;
  }
  private async view(value: PairingView, operationId: string, record?: PairingRecipientRecord | PairingApproverRecord): Promise<PairingView> {
    const view = pairingViewSchema.parse(copy(value));
    if (view.operationId !== operationId || view.request.operationId !== operationId ||
      (view.transcript && (view.transcript.operationId !== operationId || view.transcript.origin !== this.auth.origin ||
      !same(view.request.device, view.transcript.device) || view.request.localBundleDigest !== view.transcript.localBundleDigest ||
      view.transcriptDigest !== await digestObject(view.transcript)))) throw new PairingClientError('INVALID_PAIRING');
    if (record?.role === 'recipient' && (!same(record.request, view.request) || (view.transcript &&
      (!same(contextFor(view.transcript), record.context) || (record.transcript && !same(record.transcript, view.transcript)))))) throw new PairingClientError('INVALID_PAIRING');
    if (record?.role === 'approver' && !same(record.transcript, view.transcript)) throw new PairingClientError('INVALID_PAIRING');
    return view;
  }
  private progress(view: PairingView): PairingProgress { return { operationId: view.operationId, state: view.state, deviceId: view.request.device.id, fingerprint: view.transcriptDigest }; }
  private async history(transcript: PairingTranscript, signal: AbortSignal, receipt?: PairingReceipt, requirePin = false): Promise<SecurityHistoryInput> {
    const pin = await this.store.pin(transcript.workspaceId);
    if (requirePin && !pin) throw new PairingClientError('TRUST_REQUIRED');
    const response = await this.transport.history(transcript.operationId, receipt ? 'current' : 'transcript', { signal });
    if (!receipt && !same(response.anchor, { securityHead: transcript.securityHead, securityVersion: transcript.securityVersion })) throw new PairingClientError('INVALID_PAIRING');
    if (receipt && (BigInt(response.anchor.securityVersion) < BigInt(receipt.securityVersion) || !same(response.anchor, response.current))) throw new PairingClientError('CONFLICT');
    const input: SecurityHistoryInput = { genesis: response.genesis, transitions: response.transitions, workspaceId: transcript.workspaceId, origin: transcript.origin,
      genesisFingerprint: transcript.genesisFingerprint, expected: response.anchor, ...(pin ? { pin } : {}),
      trustedServiceKeys: this.options.trustedServiceKeys ?? {} };
    await verifySecurityHistory(input);
    if (receipt && !response.transitions.some((transition) => same(transition, receipt.grant))) throw new PairingClientError('INVALID_PAIRING');
    return input;
  }
  /** Stable operation ID is optional at first creation and is discoverable through store.list(). */
  begin(operationId: string = crypto.randomUUID()): Promise<PairingProgress> {
    identifier.parse(operationId);
    return this.run(async (signal, epoch) => {
      let record = await this.store.get('recipient', operationId);
      if (!record) {
        record = await this.auth.withExportKey(async (exportKey, session) => {
          if (session.accessLevel !== 'restricted') throw new PairingClientError('CONFLICT');
          const context = { workspaceId: session.workspaceId, accountId: session.accountId, deviceId: crypto.randomUUID(), credentialGeneration: session.credentialGeneration };
          const created = await this.auth.worker.createPairingDevice({ context, exportKey }, { signal }); this.check(epoch);
          const request = pairingBegin.parse({ operationId, device: created.device, localBundleDigest: await digestObject(created.wrapper) });
          this.check(epoch);
          return this.store.save({ role: 'recipient', origin: this.auth.origin, revision: 1, operationId, context, request, wrapper: created.wrapper,
            transcript: null, confirmation: null, receipt: null, delivery: null, ready: false }, null);
        });
      }
      const draft = record, session = this.recipient(draft);
      if (draft.receipt) return { operationId, state: 'completed', deviceId: draft.context.deviceId, fingerprint: draft.receipt.transcriptDigest };
      await this.auth.withExportKey(async (exportKey) => {
        await this.devices.stage(draft.wrapper, operationId);
        const readback = await this.devices.getStaged(operationId);
        if (!readback || await digestObject(readback) !== draft.request.localBundleDigest) throw new PairingClientError('STORAGE');
        const verified = await this.auth.worker.verifyPairingDevice({ context: draft.context, exportKey, wrapper: readback }, { signal });
        if (verified.signingPublicKey !== draft.request.device.signingPublicKey || verified.recipientPublicKey !== draft.request.device.recipientPublicKey) throw new PairingClientError('INVALID_PAIRING');
      });
      this.check(epoch);
      return this.progress(await this.view(await this.transport.begin(session.csrfToken, draft.request, { signal }), operationId, draft));
    });
  }
  confirmRecipient(operationId: string, fullFingerprint: string): Promise<PairingProgress> {
    return this.run(async (signal, epoch) => {
      let record = await this.store.get('recipient', operationId); if (!record) throw new PairingClientError('NOT_FOUND');
      const session = this.recipient(record), view = await this.view(await this.transport.inspect(operationId, { signal }), operationId, record);
      if (!view.transcript || view.receipt) throw new PairingClientError('CONFLICT');
      const fingerprint = await verifyPairingFingerprint(view.transcript, fullFingerprint);
      const history = await this.history(view.transcript, signal);
      await verifiedHistory(history, view.transcript);
      const transcript = view.transcript;
      const proof = record.confirmation ?? await this.auth.withExportKey((exportKey) => this.auth.worker.confirmPairingRecipient({
        transcript, fingerprint, wrapper: record!.wrapper, exportKey }, { signal }));
      this.check(epoch);
      if (!record.confirmation) record = await this.store.save({ ...record, revision: record.revision + 1, transcript, confirmation: proof }, record.revision);
      await this.store.recordVerifiedHistory(history); this.check(epoch);
      return this.progress(await this.view(await this.transport.confirm(session.csrfToken, proof, { signal }), operationId, record));
    });
  }
  claim(operationId: string): Promise<PairingProgress> {
    return this.run(async (signal, epoch) => {
      const session = this.session(true), view = await this.view(await this.transport.claim(session.csrfToken, operationId, { signal }), operationId);
      if (!view.transcript || view.receipt || view.transcript.approverAccountId !== session.accountId || view.transcript.approverDevice.id !== session.deviceId) throw new PairingClientError('INVALID_PAIRING');
      await this.history(view.transcript, signal, undefined, true); this.check(epoch);
      const existing = await this.store.get('approver', operationId); this.check(epoch);
      if (existing) await this.view(view, operationId, existing);
      else await this.store.save({ role: 'approver', origin: this.auth.origin, operationId, revision: 1, workspaceId: session.workspaceId,
        accountId: session.accountId, deviceId: session.deviceId!, transcript: view.transcript, confirmation: null, approval: null, receipt: null }, null);
      return this.progress(view);
    });
  }
  confirmApprover(operationId: string, fullFingerprint: string): Promise<PairingProgress> {
    return this.run(async (signal, epoch) => {
      let record = await this.store.get('approver', operationId); if (!record) throw new PairingClientError('NOT_FOUND');
      const session = this.approver(record), view = await this.view(await this.transport.inspect(operationId, { signal }), operationId, record);
      if (view.receipt) throw new PairingClientError('CONFLICT');
      const fingerprint = await verifyPairingFingerprint(record.transcript, fullFingerprint);
      const history = await this.history(record.transcript, signal, undefined, true);
      const proof = record.confirmation ?? await this.auth.worker.confirmPairingApprover({ transcript: record.transcript, fingerprint, history }, { signal });
      this.check(epoch);
      if (!record.confirmation) record = await this.store.save({ ...record, revision: record.revision + 1, confirmation: proof }, record.revision);
      await this.store.recordVerifiedHistory(history); this.check(epoch);
      return this.progress(await this.view(await this.transport.confirm(session.csrfToken, proof, { signal }), operationId, record));
    });
  }
  /** Persist exact signed ciphertext before staging; retries never re-seal an ambiguous submission. */
  approve(operationId: string): Promise<PairingReceipt> {
    return this.run(async (signal, epoch) => {
      let record = await this.store.get('approver', operationId); if (!record?.confirmation) throw new PairingClientError('TRUST_REQUIRED');
      const session = this.approver(record), view = await this.view(await this.transport.inspect(operationId, { signal }), operationId, record);
      let receipt = view.receipt;
      if (!receipt) {
        if (!view.recipientConfirmation || !view.approverConfirmation || !same(view.approverConfirmation, record.confirmation)) throw new PairingClientError('CONFLICT');
        if (!record.approval) {
          const history = await this.history(record.transcript, signal, undefined, true);
          const approval = await this.auth.worker.preparePairingApproval({ transcript: record.transcript, fingerprint: await digestObject(record.transcript), history,
            recipientConfirmation: view.recipientConfirmation, approverConfirmation: record.confirmation, materials: await this.transport.materials(operationId, { signal }) }, { signal });
          this.check(epoch); record = await this.store.save({ ...record, revision: record.revision + 1, approval }, record.revision);
        }
        const readback = await this.store.get('approver', operationId);
        if (!readback?.approval || !same(record.approval, readback.approval)) throw new PairingClientError('STORAGE');
        this.check(epoch);
        await this.view(await this.transport.stage(session.csrfToken, readback.approval, { signal }), operationId, record);
        this.check(epoch);
        receipt = (await this.transport.commit(session.csrfToken, operationId, { signal })).receipt;
      }
      const verified = await verifyPairingReceipt(receipt, record.transcript);
      if (record.approval && !same(verified.grant, record.approval.grant)) throw new PairingClientError('INVALID_PAIRING');
      const history = await this.history(record.transcript, signal, verified, true); this.check(epoch);
      if (!record.receipt) await this.store.save({ ...record, revision: record.revision + 1, receipt: verified }, record.revision);
      await this.store.recordVerifiedHistory(history); return verified;
    });
  }
  /** After restart, login first; no password/export key is recovered from local storage. */
  resumeRecipient(operationId: string, displayName?: string): Promise<PairingProgress> {
    return this.run(async (signal, epoch) => {
      let record = await this.store.get('recipient', operationId); if (!record) throw new PairingClientError('NOT_FOUND');
      this.recipient(record);
      const view = await this.view(await this.transport.inspect(operationId, { signal }), operationId, record);
      if (!view.receipt) return this.progress(view);
      if (!record.transcript || !record.confirmation) throw new PairingClientError('TRUST_REQUIRED');
      const receipt = await verifyPairingReceipt(view.receipt, record.transcript);
      if (!same(receipt.grant.body.recipientConfirmation, record.confirmation)) throw new PairingClientError('INVALID_PAIRING');
      const history = await this.history(record.transcript, signal, receipt, true); this.check(epoch);
      if (!record.receipt) record = await this.store.save({ ...record, revision: record.revision + 1, receipt }, record.revision);
      else if (!same(record.receipt, receipt)) throw new PairingClientError('INVALID_PAIRING');
      const state = this.auth.current();
      if (state?.localAccess !== 'unlocked' || state.session.deviceId !== record.context.deviceId) {
        const draft = record;
        await this.auth.withExportKey(async (exportKey) => {
          await this.devices.stage(draft.wrapper, operationId);
          const wrapper = await this.devices.getStaged(operationId);
          if (!wrapper || await digestObject(wrapper) !== draft.request.localBundleDigest) throw new PairingClientError('STORAGE');
          await this.auth.worker.verifyPairingDevice({ context: draft.context, wrapper, exportKey }, { signal });
        });
        this.check(epoch);
        await this.devices.commit(operationId, { ...record.context, operationId });
        await this.auth.approveLocalDevice(record.context.deviceId);
      }
      this.check(epoch);
      const delivery = await this.transport.delivery(operationId, { signal });
      if (!same(delivery.receipt, receipt)) throw new PairingClientError('INVALID_PAIRING');
      try { await this.auth.worker.verifyPairingDelivery({ delivery, history }, { signal }); }
      catch (error) {
        if (signal.aborted) throw new PairingClientError('CANCELLED');
        throw new PairingClientError('INCOMPLETE_KEYS');
      }
      this.check(epoch);
      record = await this.store.save({ ...record, revision: record.revision + 1, delivery, ready: true }, record.revision);
      this.check(epoch); await this.store.recordVerifiedHistory(history); this.check(epoch);
      if (displayName !== undefined && this.options.remembered) await this.options.remembered.remember({ workspaceId: record.context.workspaceId, accountId: record.context.accountId, deviceId: record.context.deviceId, displayName });
      return { operationId, state: 'content_ready', deviceId: record.context.deviceId, fingerprint: receipt.transcriptDigest };
    });
  }
}

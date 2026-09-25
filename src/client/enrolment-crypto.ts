import sodium from 'libsodium-wrappers';
import { z } from 'zod';
import { genesisBody } from '../shared/activation.js';
import { binary, identifier, positiveCounter } from '../shared/contracts.js';
import { base64urlDecode, base64urlEncode, canonicalJson, decryptContent, digestObject, encryptContent,
  generateRecipientKeyPair, generateSigningKeyPair, HKDF_SALT, openRecipient, ready, sealRecipient, signObject, verifyObject,
  type KeyPair } from '../shared/crypto.js';
import { parseJsonStrict } from '../shared/json.js';
import { enrolmentBinding, enrolmentDraft, enrolmentTranscript, enrolmentConfirmationFor, enrolmentLabelContextHash,
  enrolmentSetupNameHeader, enrolmentSetupNamePayload, enrolmentProfileHeader, validateEnrolmentDraft, validateEnrolmentPublicDraft,
  type EnrolmentBinding, type EnrolmentDraft, type EnrolmentTranscript, type EnrolmentConfirmation, type EnrolmentPreName } from '../shared/enrolment.js';
import { deviceBundle, deviceWrapper, unwrapDeviceBundle, wrapDeviceBundle, type DeviceWrapper, type DeviceBundle, type DeviceContext } from './device-store.js';
import { recoveryKeys, verifyRecoveryWords } from './recovery.js';

const NAME_WRAP_PURPOSE = 'ukda.setup-name-wrap.v1' as const;
const NAME_LOCAL_PURPOSE = 'ukda.local-setup-name.v1' as const;
const utf8 = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const displayName = z.string().min(1).max(200).refine((name) => name.trim() === name && name.length > 0 && !/[\uD800-\uDFFF]/u.test(name));
const origin = z.string().max(256).refine((value) => {
  try { const url = new URL(value); return url.origin === value && (url.protocol === 'https:' ||
    (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))); } catch { return false; }
});
export const setupNameContext = z.strictObject({ origin, workspaceId: identifier, accountId: identifier, operationId: identifier, credentialGeneration: positiveCounter });
export type SetupNameContext = z.infer<typeof setupNameContext>;
const nameHeader = setupNameContext.extend({ version: z.literal(1), purpose: z.literal(NAME_LOCAL_PURPOSE),
  derivation: z.strictObject({ salt: z.literal(HKDF_SALT), purpose: z.literal(NAME_WRAP_PURPOSE) }) });
export const setupNameWrapper = z.strictObject({ header: nameHeader, nonce: binary(24), ciphertext: binary(16, 4096) });
export type SetupNameWrapper = z.infer<typeof setupNameWrapper>;
export class EnrolmentCryptoError extends Error {
  constructor(readonly code: 'INVALID_CONTEXT' | 'INVALID_DRAFT' | 'LOCAL_VERIFICATION' | 'FINGERPRINT_MISMATCH' | 'INVALID_NAME' | 'EXPIRED') {
    super(`Enrolment cryptography failed (${code})`); this.name = 'EnrolmentCryptoError';
  }
}
function invalid(): never { throw new EnrolmentCryptoError('INVALID_CONTEXT'); }
function snapshot<T>(schema: z.ZodType<T>, value: unknown): T {
  try { return schema.parse(parseJsonStrict(canonicalJson(value))); } catch { throw new EnrolmentCryptoError('INVALID_DRAFT'); }
}
const same = (one: unknown, two: unknown) => canonicalJson(one) === canonicalJson(two);
function nameOf(value: string): string {
  const result = displayName.safeParse(typeof value === 'string' ? value.trim() : value);
  if (!result.success) throw new EnrolmentCryptoError('INVALID_NAME'); return result.data;
}
function headerFor(context: SetupNameContext): SetupNameWrapper['header'] {
  return { ...context, version: 1, purpose: NAME_LOCAL_PURPOSE, derivation: { salt: HKDF_SALT, purpose: NAME_WRAP_PURPOSE } };
}
function exportBytes(exportKey: string | Uint8Array): Uint8Array {
  try {
    if (typeof exportKey !== 'string' && !(exportKey instanceof Uint8Array)) invalid();
    const bytes = typeof exportKey === 'string' ? base64urlDecode(exportKey) : new Uint8Array(exportKey);
    if (bytes.length < 32 || bytes.length > 1024) { bytes.fill(0); invalid(); } return bytes;
  } catch { throw new EnrolmentCryptoError('LOCAL_VERIFICATION'); }
}
/** Operation separation is explicit in HKDF info; shared deriveKey's older context remains unchanged. */
async function nameKey(source: Uint8Array, context: SetupNameContext): Promise<Uint8Array> {
  const material = await globalThis.crypto.subtle.importKey('raw', new Uint8Array(source), 'HKDF', false, ['deriveBits']);
  const parameters = { version: 1, purpose: NAME_WRAP_PURPOSE, workspaceId: context.workspaceId, accountId: context.accountId, operationId: context.operationId };
  return new Uint8Array(await globalThis.crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: utf8.encode(HKDF_SALT), info: utf8.encode(canonicalJson(parameters)) }, material, 256));
}
/** Worker-only plaintext input. Persist the returned ciphertext, never the name or export key. */
export async function wrapSetupName(context: SetupNameContext, name: string, exportKey: string | Uint8Array): Promise<SetupNameWrapper> {
  const accepted = snapshot(setupNameContext, context), normalized = nameOf(name), source = exportBytes(exportKey);
  let key: Uint8Array | undefined, message: Uint8Array | undefined;
  try {
    await ready; key = await nameKey(source, accepted); const header = headerFor(accepted), nonce = sodium.randombytes_buf(24);
    message = utf8.encode(canonicalJson({ version: 1, displayName: normalized }));
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, canonicalJson(header), null, nonce, key);
    return { header, nonce: base64urlEncode(nonce), ciphertext: base64urlEncode(ciphertext) };
  } finally { source.fill(0); key?.fill(0); message?.fill(0); }
}
/** Worker-only; decrypted name must never be persisted or logged by callers. */
export async function unwrapSetupName(context: SetupNameContext, wrapper: SetupNameWrapper, exportKey: string | Uint8Array): Promise<string> {
  const accepted = snapshot(setupNameContext, context), envelope = snapshot(setupNameWrapper, wrapper);
  if (!same(envelope.header, headerFor(accepted))) throw new EnrolmentCryptoError('LOCAL_VERIFICATION');
  const source = exportBytes(exportKey); let key: Uint8Array | undefined, message: Uint8Array | undefined;
  try {
    await ready; key = await nameKey(source, accepted);
    message = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, base64urlDecode(envelope.ciphertext), canonicalJson(envelope.header), base64urlDecode(envelope.nonce, 24), key);
    return z.strictObject({ version: z.literal(1), displayName }).parse(parseJsonStrict(decoder.decode(message))).displayName;
  } catch { throw new EnrolmentCryptoError('LOCAL_VERIFICATION'); }
  finally { source.fill(0); key?.fill(0); message?.fill(0); }
}
function acceptedBinding(value: EnrolmentBinding, expected: EnrolmentBinding): EnrolmentBinding {
  const binding = snapshot(enrolmentBinding, value), authority = snapshot(enrolmentBinding, expected);
  if (!same(binding, authority)) invalid();
  if (Date.parse(binding.expiresAt) <= Date.now() || Date.parse(binding.issuedAt) > Date.now() + 30_000) throw new EnrolmentCryptoError('EXPIRED');
  return binding;
}
export function enrolmentDeviceContext(transcript: EnrolmentTranscript): DeviceContext {
  return { workspaceId: transcript.binding.workspaceId, accountId: transcript.binding.accountId, deviceId: transcript.device.id,
    credentialGeneration: transcript.binding.nextCredentialGeneration };
}
function nameContext(binding: EnrolmentBinding): SetupNameContext {
  return { origin: binding.origin, workspaceId: binding.workspaceId, accountId: binding.accountId, operationId: binding.operationId, credentialGeneration: binding.nextCredentialGeneration };
}
export interface NewEnrolmentOwnerKit { phrase: string; positions: readonly number[]; answers: readonly string[] }
export interface PreparedEnrolment { draft: EnrolmentDraft; deviceWrapper: DeviceWrapper; nameWrapper: SetupNameWrapper | null }
export interface PrepareJoinEnrolmentInput {
  binding: EnrolmentBinding; configuration: z.infer<typeof genesisBody.shape.opaque>; registrationRecord: string; exportKey: string;
  displayName: string; newOwnerKit?: NewEnrolmentOwnerKit;
}
/** Callers must independently verify binding against current signed history before invoking authority-sensitive helpers. */
async function recoveryFor(binding: EnrolmentBinding, kit: NewEnrolmentOwnerKit | undefined) {
  if (binding.kind === 'join_member') { if (kit) invalid(); return undefined; }
  if (!kit) invalid(); verifyRecoveryWords(kit.phrase, kit.positions, kit.answers);
  return recoveryKeys(kit.phrase, { workspaceId: binding.workspaceId, accountId: binding.accountId });
}
async function newRecoveryConfirmation(transcript: EnrolmentTranscript, keys: Awaited<ReturnType<typeof recoveryKeys>> | undefined): Promise<EnrolmentConfirmation | null> {
  if (!keys) return null;
  return signObject(enrolmentConfirmationFor(transcript, await digestObject(transcript), 'new_recovery'), keys.signing.privateKey);
}
async function setupNameProposal(preName: EnrolmentPreName, name: string, signing: Uint8Array) {
  const binding = preName.binding, context = await enrolmentLabelContextHash(preName);
  return sealRecipient(enrolmentSetupNameHeader(preName, context), { version: 1, mode: 'setup_name', workspaceId: binding.workspaceId,
    accountId: binding.accountId, operationId: binding.operationId, approvalAttemptId: binding.approvalAttemptId,
    attemptGeneration: binding.attemptGeneration, labelContextDigest: context, displayName: nameOf(name) }, signing);
}
/** Generates a device only for JOIN. Returned objects contain no plaintext private keys, name, phrase or export key. */
export async function prepareJoinEnrolment(input: PrepareJoinEnrolmentInput, expectedBinding: EnrolmentBinding): Promise<PreparedEnrolment> {
  input = parseJsonStrict(canonicalJson(input)) as typeof input;
  const binding = acceptedBinding(input.binding, expectedBinding); if (binding.kind === 'promote_owner') invalid();
  const configuration = snapshot(genesisBody.shape.opaque, input.configuration), registrationRecord = snapshot(binary(1, 4096), input.registrationRecord);
  const normalizedName = nameOf(input.displayName), signing = await generateSigningKeyPair();
  let recipient: KeyPair | undefined, recovery: Awaited<ReturnType<typeof recoveryKeys>> | undefined;
  try {
    recipient = await generateRecipientKeyPair(); recovery = await recoveryFor(binding, input.newOwnerKit);
    const device = { id: crypto.randomUUID(), keyGeneration: binding.nextDeviceKeyGeneration, signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
    const wrapper = await wrapDeviceBundle({ workspaceId: binding.workspaceId, accountId: binding.accountId, deviceId: device.id, credentialGeneration: binding.nextCredentialGeneration },
      { signingPrivateKey: base64urlEncode(signing.privateKey), recipientPrivateKey: base64urlEncode(recipient.privateKey), signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey }, input.exportKey);
    const wrappedName = await wrapSetupName(nameContext(binding), normalizedName, input.exportKey);
    const preName: EnrolmentPreName = { version: 1, binding, device, recovery: recovery ? { id: crypto.randomUUID(), generation: binding.nextRecoveryGeneration,
      signingPublicKey: base64urlEncode(recovery.signing.publicKey), recipientPublicKey: base64urlEncode(recovery.recipient.publicKey) } : null,
      wrapperHash: await digestObject(wrapper), configuration, registrationRecordHash: await digestObject(registrationRecord) };
    const setupName = await setupNameProposal(preName, normalizedName, signing.privateKey);
    const transcript = snapshot(enrolmentTranscript, { ...preName, version: 1, purpose: 'ukda.enrolment-transcript.v1', setupNameDigest: await digestObject(setupName) });
    const prepared: PreparedEnrolment = { draft: { transcript, registrationRecord, setupName, recipientConfirmation: null,
      newRecoveryConfirmation: await newRecoveryConfirmation(transcript, recovery) }, deviceWrapper: wrapper, nameWrapper: wrappedName };
    await verifyPreparedEnrolment(prepared, input.exportKey, binding); return prepared;
  } finally { signing.privateKey.fill(0); recipient?.privateKey.fill(0); recovery?.signing.privateKey.fill(0); recovery?.recipient.privateKey.fill(0); }
}

/** Read-back check before publishing setup. Authority is supplied by the caller's current history verifier. */
export async function verifyPreparedEnrolment(preparedValue: PreparedEnrolment, exportKey: string, expectedBinding: EnrolmentBinding): Promise<{ verified: true }> {
  const prepared = snapshot(z.strictObject({ draft: enrolmentDraft, deviceWrapper, nameWrapper: setupNameWrapper.nullable() }), preparedValue);
  const transcript = prepared.draft.transcript, binding = acceptedBinding(transcript.binding, expectedBinding);
  await validateEnrolmentDraft(prepared.draft, binding, transcript.configuration);
  if (await digestObject(prepared.deviceWrapper) !== transcript.wrapperHash) throw new EnrolmentCryptoError('LOCAL_VERIFICATION');
  const bundle = await unwrapDeviceBundle(enrolmentDeviceContext(transcript), prepared.deviceWrapper, exportKey);
  if (bundle.signingPublicKey !== transcript.device.signingPublicKey || bundle.recipientPublicKey !== transcript.device.recipientPublicKey) invalid();
  if (binding.kind === 'promote_owner') { if (prepared.nameWrapper !== null) invalid(); }
  else {
    if (!prepared.nameWrapper) invalid();
    await unwrapSetupName(nameContext(binding), prepared.nameWrapper, exportKey);
  }
  return { verified: true };
}
function preNameFor(transcript: EnrolmentTranscript, binding = transcript.binding): EnrolmentPreName {
  return { version: 1, binding, device: transcript.device, recovery: transcript.recovery, wrapperHash: transcript.wrapperHash,
    configuration: transcript.configuration, registrationRecordHash: transcript.registrationRecordHash };
}
/** Takeover retains private device material and password registration; only the attempt-bound packet/proofs change. */
export async function rebindJoinEnrolment(input: { prepared: PreparedEnrolment; binding: EnrolmentBinding; exportKey: string; newOwnerKit?: NewEnrolmentOwnerKit },
  expectedBinding: EnrolmentBinding): Promise<PreparedEnrolment> {
  input = parseJsonStrict(canonicalJson(input)) as typeof input;
  const binding = acceptedBinding(input.binding, expectedBinding), prior = snapshot(enrolmentDraft, input.prepared.draft).transcript;
  if (binding.kind === 'promote_owner' || binding.kind !== prior.binding.kind || binding.workspaceId !== prior.binding.workspaceId || binding.origin !== prior.binding.origin ||
    binding.accountId !== prior.binding.accountId || binding.operationId !== prior.binding.operationId || binding.invitationGeneration !== prior.binding.invitationGeneration ||
    binding.nextCredentialGeneration !== prior.binding.nextCredentialGeneration || binding.nextRecoveryGeneration !== prior.binding.nextRecoveryGeneration ||
    binding.approvalAttemptId === prior.binding.approvalAttemptId || BigInt(binding.attemptGeneration) <= BigInt(prior.binding.attemptGeneration) ||
    Date.parse(binding.expiresAt) > Date.parse(prior.binding.expiresAt)) invalid();
  await verifyPreparedEnrolment(input.prepared, input.exportKey, prior.binding);
  const bundle = await unwrapDeviceBundle(enrolmentDeviceContext(prior), input.prepared.deviceWrapper, input.exportKey);
  const name = await unwrapSetupName(nameContext(binding), input.prepared.nameWrapper!, input.exportKey), signing = base64urlDecode(bundle.signingPrivateKey, 64);
  let recovery: Awaited<ReturnType<typeof recoveryKeys>> | undefined;
  try {
    recovery = await recoveryFor(binding, input.newOwnerKit);
    if (recovery && (!prior.recovery || base64urlEncode(recovery.signing.publicKey) !== prior.recovery.signingPublicKey ||
      base64urlEncode(recovery.recipient.publicKey) !== prior.recovery.recipientPublicKey)) invalid();
    const preName = preNameFor(prior, binding), setupName = await setupNameProposal(preName, name, signing);
    const transcript = snapshot(enrolmentTranscript, { ...prior, binding, setupNameDigest: await digestObject(setupName) });
    const result: PreparedEnrolment = { deviceWrapper: snapshot(deviceWrapper, input.prepared.deviceWrapper), nameWrapper: snapshot(setupNameWrapper, input.prepared.nameWrapper),
      draft: { transcript, registrationRecord: input.prepared.draft.registrationRecord, setupName, recipientConfirmation: null,
        newRecoveryConfirmation: await newRecoveryConfirmation(transcript, recovery) } };
    await verifyPreparedEnrolment(result, input.exportKey, binding); return result;
  } finally { signing.fill(0); recovery?.signing.privateKey.fill(0); recovery?.recipient.privateKey.fill(0); }
}
/** Promotion uses the exact healthy existing device/wrapper. It never registers or rewraps a password. */
export async function preparePromotionEnrolment(input: { binding: EnrolmentBinding; deviceId: string; existingWrapper: DeviceWrapper;
  exportKey: string; newOwnerKit: NewEnrolmentOwnerKit }, expectedBinding: EnrolmentBinding): Promise<PreparedEnrolment> {
  input = parseJsonStrict(canonicalJson(input)) as typeof input;
  const binding = acceptedBinding(input.binding, expectedBinding); if (binding.kind !== 'promote_owner') invalid();
  const device = binding.currentDevices.find((entry) => entry.id === input.deviceId); if (!device) invalid();
  const wrapper = snapshot(deviceWrapper, input.existingWrapper);
  const bundle = await unwrapDeviceBundle({ workspaceId: binding.workspaceId, accountId: binding.accountId, deviceId: device.id,
    credentialGeneration: binding.credentialGeneration }, wrapper, input.exportKey);
  if (bundle.signingPublicKey !== device.signingPublicKey || bundle.recipientPublicKey !== device.recipientPublicKey) invalid();
  const recovery = await recoveryFor(binding, input.newOwnerKit);
  try {
    if (!recovery) invalid();
    const transcript = snapshot(enrolmentTranscript, { version: 1, purpose: 'ukda.enrolment-transcript.v1', binding, device,
      recovery: { id: crypto.randomUUID(), generation: binding.nextRecoveryGeneration, signingPublicKey: base64urlEncode(recovery.signing.publicKey), recipientPublicKey: base64urlEncode(recovery.recipient.publicKey) },
      wrapperHash: await digestObject(wrapper), configuration: null, registrationRecordHash: null, setupNameDigest: null });
    const prepared: PreparedEnrolment = { deviceWrapper: wrapper, nameWrapper: null, draft: { transcript, registrationRecord: null, setupName: null,
      recipientConfirmation: null, newRecoveryConfirmation: await newRecoveryConfirmation(transcript, recovery) } };
    await verifyPreparedEnrolment(prepared, input.exportKey, binding); return prepared;
  } finally { recovery?.signing.privateKey.fill(0); recovery?.recipient.privateKey.fill(0); }
}
export async function verifyEnrolmentFingerprint(value: EnrolmentTranscript, supplied: string, expectedBinding: EnrolmentBinding): Promise<string> {
  const transcript = snapshot(enrolmentTranscript, value); acceptedBinding(transcript.binding, expectedBinding);
  const actual = await digestObject(transcript), normalized = typeof supplied === 'string' ? supplied.trim().toLowerCase() : '';
  if (!/^[0-9a-f]{64}$/.test(normalized) || normalized !== actual) throw new EnrolmentCryptoError('FINGERPRINT_MISMATCH'); return actual;
}
/** Returns a signature only; private device material remains inside the Worker invocation. */
export async function confirmEnrolmentRecipient(input: { prepared: PreparedEnrolment; exportKey: string; fingerprint: string }, expectedBinding: EnrolmentBinding): Promise<EnrolmentConfirmation> {
  input = parseJsonStrict(canonicalJson(input)) as typeof input;
  const transcript = snapshot(enrolmentTranscript, input.prepared.draft.transcript);
  const fingerprint = await verifyEnrolmentFingerprint(transcript, input.fingerprint, expectedBinding);
  await verifyPreparedEnrolment(input.prepared, input.exportKey, expectedBinding);
  const bundle = await unwrapDeviceBundle(enrolmentDeviceContext(transcript), input.prepared.deviceWrapper, input.exportKey), key = base64urlDecode(bundle.signingPrivateKey, 64);
  try { return signObject(enrolmentConfirmationFor(transcript, fingerprint, 'recipient'), key); } finally { key.fill(0); }
}
export type EnrolmentPublicDraft = Omit<EnrolmentDraft, 'registrationRecord'>;
async function ownerDraft(input: EnrolmentPublicDraft, fingerprint: string, bundle: DeviceBundle, expectedBinding: EnrolmentBinding) {
  input = parseJsonStrict(canonicalJson(input)) as EnrolmentPublicDraft;
  const transcript = snapshot(enrolmentTranscript, input.transcript), binding = acceptedBinding(transcript.binding, expectedBinding);
  const checkedFingerprint = await verifyEnrolmentFingerprint(transcript, fingerprint, binding);
  await validateEnrolmentPublicDraft(input, binding, transcript.configuration);
  if (!input.recipientConfirmation || bundle.signingPublicKey !== binding.authorizer.device.signingPublicKey ||
    bundle.recipientPublicKey !== binding.authorizer.device.recipientPublicKey) invalid();
  return { transcript, binding, fingerprint: checkedFingerprint };
}
/** Worker-only name opening. No workspace key is shared with a pending profile. */
export async function openEnrolmentSetupName(input: { draft: EnrolmentPublicDraft; fingerprint: string }, bundle: DeviceBundle,
  expectedBinding: EnrolmentBinding): Promise<string> {
  input = parseJsonStrict(canonicalJson(input)) as typeof input;
  bundle = snapshot(deviceBundle, bundle);
  const { transcript, binding } = await ownerDraft(input.draft, input.fingerprint, bundle, expectedBinding);
  if (binding.kind === 'promote_owner' || !input.draft.setupName) invalid();
  const preName = preNameFor(transcript), context = await enrolmentLabelContextHash(preName), key = base64urlDecode(bundle.recipientPrivateKey, 32);
  try {
    const payload = await openRecipient(input.draft.setupName, key, base64urlDecode(transcript.device.signingPublicKey, 32), enrolmentSetupNameHeader(preName, context));
    const expected = { version: 1 as const, mode: 'setup_name' as const, workspaceId: binding.workspaceId, accountId: binding.accountId,
      operationId: binding.operationId, approvalAttemptId: binding.approvalAttemptId, attemptGeneration: binding.attemptGeneration, labelContextDigest: context };
    const parsed = snapshot(enrolmentSetupNamePayload, payload);
    displayName.parse(parsed.displayName);
    const { displayName: name, ...actual } = parsed; if (!same(actual, expected)) invalid(); return name;
  } finally { key.fill(0); }
}
export async function confirmEnrolmentAuthorizer(input: { draft: EnrolmentPublicDraft; fingerprint: string }, bundle: DeviceBundle,
  expectedBinding: EnrolmentBinding): Promise<EnrolmentConfirmation> {
  bundle = snapshot(deviceBundle, bundle);
  const checked = await ownerDraft(input.draft, input.fingerprint, bundle, expectedBinding), key = base64urlDecode(bundle.signingPrivateKey, 64);
  try {
    const proof = await signObject(enrolmentConfirmationFor(checked.transcript, checked.fingerprint, 'authorizer'), key);
    if (!await verifyObject(proof, base64urlDecode(bundle.signingPublicKey, 32), 'ukda.enrolment-confirmation.v1')) invalid(); return proof;
  } finally { key.fill(0); }
}
/** Current workspaceKey must come from independently verified scope material. Persist/retry this exact ciphertext. */
export async function encryptEnrolmentProfile(input: { draft: EnrolmentPublicDraft; fingerprint: string }, bundle: DeviceBundle,
  workspaceKey: Uint8Array, expectedBinding: EnrolmentBinding) {
  input = parseJsonStrict(canonicalJson(input)) as typeof input;
  bundle = snapshot(deviceBundle, bundle);
  const key = new Uint8Array(workspaceKey), signing = base64urlDecode(bundle.signingPrivateKey, 64);
  try {
    const name = await openEnrolmentSetupName(input, bundle, expectedBinding), transcript = snapshot(enrolmentTranscript, input.draft.transcript);
    const header = enrolmentProfileHeader(transcript), envelope = await encryptContent(header, { displayName: name }, key, signing);
    const readback = await decryptContent(envelope, key, base64urlDecode(bundle.signingPublicKey, 32), header);
    if (!same(readback, { displayName: name })) throw new EnrolmentCryptoError('LOCAL_VERIFICATION');
    return { id: crypto.randomUUID(), envelope };
  } finally { key.fill(0); signing.fill(0); }
}

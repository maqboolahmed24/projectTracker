import { z } from 'zod';
import { genesisBody } from './activation.js';
import { binary, capabilities, contentEnvelope, counter, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, recipientEnvelope, verifyContentEnvelope, verifyObject,
  verifyRecipientEnvelope, type ContentHeader, type RecipientHeader } from './crypto.js';
import { parseJsonStrict } from './json.js';
import { pairingPublicDevice, pairingScope, type PairingScope } from './pairing.js';
import { customRolePermissions } from './permissions.js';
import { recoveryPublicAuthority } from './recovery.js';

export const JOIN_CODE_TTL_MS = 3_600_000;
export const JOIN_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const joinCode = z.string().regex(/^JOIN-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
/** An online, one-use credential; never derive a permanent encryption key from this code. */
export function generateJoinCode(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(12));
  try {
    const symbols = Array.from(bytes, (byte) => JOIN_CODE_ALPHABET[byte & 31]!).join('');
    return `JOIN-${symbols.slice(0, 4)}-${symbols.slice(4, 8)}-${symbols.slice(8)}`;
  } finally { bytes.fill(0); }
}

const origin = z.string().max(256).refine((value) => {
  try { const parsed = new URL(value); return parsed.origin === value && (parsed.protocol === 'https:' ||
    (parsed.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname))); } catch { return false; }
});
const equal = (left: unknown, right: unknown) => canonicalJson(left) === canonicalJson(right);
const next = (before: string, after: string) => counter.safeParse(before).success && positiveCounter.safeParse(after).success && BigInt(after) === BigInt(before) + 1n;
const unique = (values: readonly string[]) => new Set(values).size === values.length;

export const enrolmentKind = z.enum(['join_member', 'join_owner', 'promote_owner']);
export const enrolmentRole = z.strictObject({ id: identifier, revision: positiveCounter, permissions: customRolePermissions });
export const enrolmentProfile = z.strictObject({ id: identifier, revision: positiveCounter, objectId: identifier, objectDigest: digest });
export const enrolmentAuthorizer = z.strictObject({ accountId: identifier, device: pairingPublicDevice,
  credentialGeneration: positiveCounter, sessionGeneration: positiveCounter });

/** Exact trusted current-state snapshot; it is not permission to trust values received from the target. */
export const enrolmentBinding = z.strictObject({
  version: z.literal(1), kind: enrolmentKind, origin, workspaceId: identifier, accountId: identifier,
  operationId: identifier, approvalAttemptId: identifier, attemptGeneration: positiveCounter, invitationGeneration: counter,
  profile: enrolmentProfile, nextProfileRevision: positiveCounter, role: enrolmentRole,
  credentialGeneration: counter, nextCredentialGeneration: positiveCounter,
  sessionGeneration: counter, nextSessionGeneration: positiveCounter,
  recoveryGeneration: counter, nextRecoveryGeneration: counter,
  deviceKeyGeneration: counter, nextDeviceKeyGeneration: positiveCounter,
  ownershipVersion: positiveCounter, nextOwnershipVersion: positiveCounter,
  securityVersion: positiveCounter, nextSecurityVersion: positiveCounter,
  securityHead: digest, genesisFingerprint: digest, dataGeneration: positiveCounter, custodyEpoch: positiveCounter, workspaceKeyEpoch: positiveCounter,
  authorizer: enrolmentAuthorizer, currentDevices: z.array(pairingPublicDevice).max(256),
  scopes: z.array(pairingScope).min(1).max(256), issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime(),
}).refine((value) => value.profile.id === value.accountId && value.authorizer.accountId !== value.accountId &&
  value.approvalAttemptId !== value.operationId && next(value.securityVersion, value.nextSecurityVersion) &&
  next(value.sessionGeneration, value.nextSessionGeneration) && Date.parse(value.expiresAt) > Date.parse(value.issuedAt) &&
  Date.parse(value.expiresAt) - Date.parse(value.issuedAt) <= JOIN_CODE_TTL_MS)
  .refine((value) => value.kind === 'promote_owner' ? value.invitationGeneration === '0' &&
    positiveCounter.safeParse(value.credentialGeneration).success && value.nextCredentialGeneration === value.credentialGeneration &&
    positiveCounter.safeParse(value.deviceKeyGeneration).success && value.nextDeviceKeyGeneration === value.deviceKeyGeneration &&
    value.currentDevices.length > 0 && value.nextProfileRevision === value.profile.revision :
    positiveCounter.safeParse(value.invitationGeneration).success && value.credentialGeneration === '0' && value.nextCredentialGeneration === '1' &&
    value.sessionGeneration === '0' && value.nextSessionGeneration === '1' && value.deviceKeyGeneration === '0' && value.nextDeviceKeyGeneration === '1' &&
    value.recoveryGeneration === '0' && value.currentDevices.length === 0 && next(value.profile.revision, value.nextProfileRevision))
  .refine((value) => value.kind === 'join_member' ? value.nextRecoveryGeneration === '0' && value.nextOwnershipVersion === value.ownershipVersion :
    next(value.recoveryGeneration, value.nextRecoveryGeneration) && next(value.ownershipVersion, value.nextOwnershipVersion) &&
    equal(value.role.permissions, [...capabilities]))
  .refine((value) => unique(value.currentDevices.map((device) => device.id)) &&
    unique(value.currentDevices.map((device) => device.signingPublicKey)) && unique(value.currentDevices.map((device) => device.recipientPublicKey)) &&
    value.currentDevices.every((device) => device.id !== value.authorizer.device.id) &&
    unique(value.scopes.map((scope) => `${scope.scope}:${scope.scopeId}`)) &&
    value.scopes.filter((scope) => scope.scope === 'workspace').length === 1 &&
    value.scopes.every((scope) => unique(scope.permissions) && scope.permissions.includes('read_project') &&
      unique(scope.sources.map((source) => source.grantId)) &&
      (scope.scope !== 'workspace' || scope.scopeId === value.workspaceId) &&
      (scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.parse(value.issuedAt)) &&
      (scope.mode !== 'custody' || (value.kind !== 'join_member' && scope.scope === 'workspace' && scope.keyEpoch === value.custodyEpoch)) &&
      (value.kind !== 'join_member' || scope.permissions.every((permission) => value.role.permissions.includes(permission)))) &&
    (value.kind === 'join_member' ? value.scopes.every((scope) => scope.mode === 'content') :
      value.scopes.filter((scope) => scope.mode === 'custody').length === 1));
export type EnrolmentBinding = z.infer<typeof enrolmentBinding>;

export const enrolmentOperationReference = z.strictObject({ workspaceId: identifier, operationId: identifier });
export type EnrolmentOperationReference = z.infer<typeof enrolmentOperationReference>;
export const enrolmentReference = enrolmentOperationReference.extend({ resumeToken: binary(32) });
export type EnrolmentReference = z.infer<typeof enrolmentReference>;
export const enrolmentAttemptReference = enrolmentOperationReference.extend({ approvalAttemptId: identifier, attemptGeneration: positiveCounter });
export const enrolmentBegin = z.strictObject({ workspaceId: identifier, code: joinCode, resumeToken: binary(32) });
export const enrolmentIssuedJoin = z.strictObject({ workspaceId: identifier, accountId: identifier, operationId: identifier,
  invitationGeneration: positiveCounter, code: joinCode, expiresAt: z.iso.datetime() });
export type EnrolmentIssuedJoin = z.infer<typeof enrolmentIssuedJoin>;

const transcriptShape = { version: z.literal(1), purpose: z.literal('ukda.enrolment-transcript.v1'), binding: enrolmentBinding,
  device: pairingPublicDevice, recovery: recoveryPublicAuthority.nullable(), wrapperHash: digest,
  configuration: genesisBody.shape.opaque.nullable(), registrationRecordHash: digest.nullable(), setupNameDigest: digest.nullable() };
export const enrolmentTranscript = z.strictObject(transcriptShape)
  .refine((value) => value.device.id !== value.binding.authorizer.device.id &&
    (value.binding.kind === 'promote_owner' ? value.configuration === null && value.registrationRecordHash === null && value.setupNameDigest === null &&
      value.binding.currentDevices.some((known) => equal(known, value.device)) :
      value.device.keyGeneration === value.binding.nextDeviceKeyGeneration &&
      value.configuration !== null && value.registrationRecordHash !== null && value.setupNameDigest !== null &&
      value.configuration.identifiers.client === `ukda:${value.binding.workspaceId}:${value.binding.accountId}`))
  .refine((value) => value.binding.kind === 'join_member' ? value.recovery === null : value.recovery !== null &&
    value.recovery.generation === value.binding.nextRecoveryGeneration && value.recovery.id !== value.device.id &&
    value.recovery.id !== value.binding.authorizer.device.id && !value.binding.currentDevices.some((known) => known.id === value.recovery?.id));
export type EnrolmentTranscript = z.infer<typeof enrolmentTranscript>;

/** Inputs available before sealing the setup name: no final-transcript hash cycle. */
export const enrolmentPreName = z.strictObject({ version: z.literal(1), binding: enrolmentBinding, device: pairingPublicDevice,
  recovery: recoveryPublicAuthority.nullable(), wrapperHash: digest,
  configuration: genesisBody.shape.opaque.nullable(), registrationRecordHash: digest.nullable() });
export type EnrolmentPreName = z.infer<typeof enrolmentPreName>;
export const enrolmentSetupNamePayload = z.strictObject({ version: z.literal(1), mode: z.literal('setup_name'),
  workspaceId: identifier, accountId: identifier, operationId: identifier, approvalAttemptId: identifier,
  attemptGeneration: positiveCounter, labelContextDigest: digest, displayName: z.string().min(1).max(200).refine((value) => value.trim().length > 0) });
export type EnrolmentSetupNamePayload = z.infer<typeof enrolmentSetupNamePayload>;

export const enrolmentConfirmationBody = z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.enrolment-confirmation.v1'),
  workspaceId: identifier, operationId: identifier, approvalAttemptId: identifier, attemptGeneration: positiveCounter,
  transcriptDigest: digest, role: z.enum(['recipient', 'authorizer', 'new_recovery']), accountId: identifier,
  signerId: identifier, signerGeneration: positiveCounter, kitVerified: z.literal(true).optional(),
}).refine((value) => (value.role === 'new_recovery') === (value.kitVerified === true));
export const enrolmentConfirmation = z.strictObject({ body: enrolmentConfirmationBody, signature: binary(64) });
export type EnrolmentConfirmation = z.infer<typeof enrolmentConfirmation>;
export const enrolmentDraft = z.strictObject({ transcript: enrolmentTranscript, registrationRecord: binary(1, 4096).nullable(),
  setupName: recipientEnvelope.nullable(), recipientConfirmation: enrolmentConfirmation.nullable(), newRecoveryConfirmation: enrolmentConfirmation.nullable() });
export type EnrolmentDraft = z.infer<typeof enrolmentDraft>;
export const enrolmentPublicDraft = enrolmentDraft.omit({ registrationRecord: true });
export type EnrolmentPublicDraft = z.infer<typeof enrolmentPublicDraft>;
export const enrolmentProfileDescriptor = z.strictObject({ id: identifier, profileId: identifier, revision: positiveCounter, digest });
export const enrolmentDeliveryDescriptor = z.strictObject({ id: identifier, scope: z.enum(['workspace', 'project']), scopeId: identifier,
  keyEpoch: positiveCounter, recipientKind: z.enum(['device', 'recovery']), recipientId: identifier, digest });
export const enrolmentTransitionBody = z.strictObject({ version: z.literal(1),
  purpose: z.enum(['ukda.profile-enrolment.v1', 'ukda.owner-promotion.v1']),
  transcript: enrolmentTranscript, transcriptDigest: digest, recipientConfirmation: enrolmentConfirmation,
  authorizerConfirmation: enrolmentConfirmation, newRecoveryConfirmation: enrolmentConfirmation.nullable(),
  profile: enrolmentProfileDescriptor.nullable(), deliveries: z.array(enrolmentDeliveryDescriptor).min(1).max(4097),
}).refine((value) => (value.transcript.binding.kind === 'promote_owner') === (value.purpose === 'ukda.owner-promotion.v1'));
export const enrolmentTransition = z.strictObject({ body: enrolmentTransitionBody, signature: binary(64) });
export type EnrolmentTransition = z.infer<typeof enrolmentTransition>;
const delivery = z.strictObject({ id: identifier, envelope: recipientEnvelope });
const profileObject = z.strictObject({ id: identifier, envelope: contentEnvelope });
export const enrolmentApproval = z.strictObject({ transition: enrolmentTransition, deliveries: z.array(delivery).min(1).max(4097),
  profile: profileObject.nullable() });
export type EnrolmentApproval = z.infer<typeof enrolmentApproval>;
export const enrolmentPayload = enrolmentApproval.extend({ registrationRecord: binary(1, 4096).nullable(), setupName: recipientEnvelope.nullable() });
export type EnrolmentPayload = z.infer<typeof enrolmentPayload>;
export const enrolmentReceipt = z.strictObject({ version: z.literal(1), operationId: identifier, approvalAttemptId: identifier,
  attemptGeneration: positiveCounter, workspaceId: identifier, accountId: identifier, deviceId: identifier,
  credentialGeneration: positiveCounter, sessionGeneration: positiveCounter, keyGeneration: positiveCounter,
  recoveryGeneration: counter, ownershipVersion: positiveCounter, profileRevision: positiveCounter,
  dataGeneration: positiveCounter, securityVersion: positiveCounter, securityHead: digest,
  requestHash: digest, wrapperHash: digest, committedAt: z.iso.datetime(), transition: enrolmentTransition });
export type EnrolmentReceipt = z.infer<typeof enrolmentReceipt>;
export const enrolmentResult = z.strictObject({ state: z.enum(['completed', 'finishing']), receipt: enrolmentReceipt });
export type EnrolmentResult = z.infer<typeof enrolmentResult>;

export class EnrolmentContractError extends Error {
  constructor() { super('Invalid enrolment contract'); this.name = 'EnrolmentContractError'; }
}
function snapshot<T>(schema: z.ZodType<T>, value: unknown): T {
  try { return schema.parse(parseJsonStrict(canonicalJson(value))); } catch { throw new EnrolmentContractError(); }
}

function preNameFrom(transcript: EnrolmentTranscript): EnrolmentPreName {
  const { binding, device, recovery, wrapperHash, configuration, registrationRecordHash } = transcript;
  return { version: 1, binding, device, recovery, wrapperHash, configuration, registrationRecordHash };
}
export function enrolmentLabelContext(value: EnrolmentPreName) {
  const input = snapshot(enrolmentPreName, value);
  const { binding, device, recovery, configuration } = input;
  if (binding.kind === 'promote_owner' || device.keyGeneration !== binding.nextDeviceKeyGeneration ||
    device.id === binding.authorizer.device.id || configuration === null || input.registrationRecordHash === null ||
    configuration.identifiers.client !== `ukda:${binding.workspaceId}:${binding.accountId}` ||
    (binding.kind === 'join_member' ? recovery !== null : recovery === null || recovery.generation !== binding.nextRecoveryGeneration ||
      recovery.id === device.id || recovery.id === binding.authorizer.device.id)) throw new EnrolmentContractError();
  return { ...input, purpose: 'ukda.enrolment-label-context.v1' as const };
}
export async function enrolmentLabelContextHash(value: EnrolmentPreName): Promise<string> { return digestObject(enrolmentLabelContext(value)); }
export function enrolmentSetupNameHeader(value: EnrolmentPreName, labelContextDigest: string): RecipientHeader {
  const input = enrolmentLabelContext(value), { binding, device } = input, owner = binding.authorizer;
  return { version: 1, purpose: 'ukda.recipient.v1', algorithm: 'X25519-SealedBox', workspaceId: binding.workspaceId,
    scope: 'workspace', scopeId: binding.workspaceId, keyEpoch: binding.workspaceKeyEpoch,
    recipientAccountId: owner.accountId, recipientId: owner.device.id, recipientKind: 'device',
    recipientKeyGeneration: owner.device.keyGeneration, recipientPublicKey: owner.device.recipientPublicKey,
    senderAccountId: binding.accountId, senderDeviceId: device.id, senderKeyGeneration: device.keyGeneration,
    securityVersion: binding.securityVersion, securityHead: binding.securityHead,
    ceremonyId: binding.approvalAttemptId, transcriptDigest: digest.parse(labelContextDigest) };
}
export function enrolmentConfirmationFor(transcript: EnrolmentTranscript, transcriptDigest: string,
  role: EnrolmentConfirmation['body']['role']): EnrolmentConfirmation['body'] {
  const { binding } = transcript;
  const signer = role === 'recipient' ? { accountId: binding.accountId, id: transcript.device.id, generation: transcript.device.keyGeneration } :
    role === 'authorizer' ? { accountId: binding.authorizer.accountId, id: binding.authorizer.device.id, generation: binding.authorizer.device.keyGeneration } :
      transcript.recovery && { accountId: binding.accountId, id: transcript.recovery.id, generation: transcript.recovery.generation };
  if (!signer) throw new EnrolmentContractError();
  return enrolmentConfirmationBody.parse({ version: 1, purpose: 'ukda.enrolment-confirmation.v1',
    workspaceId: binding.workspaceId, operationId: binding.operationId, approvalAttemptId: binding.approvalAttemptId,
    attemptGeneration: binding.attemptGeneration, transcriptDigest, role, accountId: signer.accountId,
    signerId: signer.id, signerGeneration: signer.generation, ...(role === 'new_recovery' ? { kitVerified: true } : {}) });
}
export function enrolmentRecipientDevices(transcript: EnrolmentTranscript): EnrolmentTranscript['device'][] {
  return transcript.binding.kind === 'promote_owner' ? transcript.binding.currentDevices : [transcript.device];
}
export function enrolmentRecipientHeader(transcript: EnrolmentTranscript, transcriptDigest: string, scope: PairingScope,
  recipientKind: 'device' | 'recovery', deviceId = transcript.device.id): RecipientHeader {
  const { binding } = transcript, owner = binding.authorizer;
  const recipient = recipientKind === 'recovery' ? transcript.recovery : enrolmentRecipientDevices(transcript).find((device) => device.id === deviceId);
  if (!recipient || !binding.scopes.some((known) => equal(known, scope)) ||
    (recipientKind === 'recovery' && (scope.mode !== 'custody' || scope.scope !== 'workspace'))) throw new EnrolmentContractError();
  return { version: 1, purpose: 'ukda.recipient.v1', algorithm: 'X25519-SealedBox', workspaceId: binding.workspaceId,
    scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, recipientAccountId: binding.accountId,
    recipientId: recipient.id, recipientKind, recipientKeyGeneration: 'keyGeneration' in recipient ? recipient.keyGeneration : recipient.generation,
    recipientPublicKey: recipient.recipientPublicKey, senderAccountId: owner.accountId, senderDeviceId: owner.device.id,
    senderKeyGeneration: owner.device.keyGeneration, securityVersion: binding.securityVersion, securityHead: binding.securityHead,
    ceremonyId: binding.approvalAttemptId, transcriptDigest: digest.parse(transcriptDigest) };
}
export function enrolmentProfileHeader(transcript: EnrolmentTranscript): ContentHeader {
  const { binding } = transcript, owner = binding.authorizer;
  if (binding.kind === 'promote_owner') throw new EnrolmentContractError();
  return { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: binding.workspaceId,
    scope: 'workspace', scopeId: binding.workspaceId, recordId: binding.accountId, recordType: 'profile', schema: 1,
    keyEpoch: binding.workspaceKeyEpoch, revision: binding.nextProfileRevision, operationId: binding.approvalAttemptId,
    accountId: owner.accountId, deviceId: owner.device.id, keyGeneration: owner.device.keyGeneration,
    permissionVersion: binding.role.revision, securityVersion: binding.securityVersion, securityHead: binding.securityHead,
    dataGeneration: binding.dataGeneration, action: 'profile.enrol', approvalPolicyId: null, approvalPolicyRevision: null };
}

type Configuration = EnrolmentTranscript['configuration'];
function sameAuthority(transcript: EnrolmentTranscript, expected: EnrolmentBinding, configuration: Configuration): void {
  if (!equal(transcript.binding, snapshot(enrolmentBinding, expected)) || !equal(transcript.configuration, configuration)) throw new EnrolmentContractError();
}
async function validConfirmation(confirmation: EnrolmentConfirmation | null, transcript: EnrolmentTranscript, transcriptDigest: string,
  role: EnrolmentConfirmation['body']['role']): Promise<boolean> {
  if (!confirmation) return false;
  const key = role === 'recipient' ? transcript.device.signingPublicKey : role === 'authorizer' ?
    transcript.binding.authorizer.device.signingPublicKey : transcript.recovery?.signingPublicKey;
  return !!key && equal(confirmation.body, enrolmentConfirmationFor(transcript, transcriptDigest, role)) &&
    await verifyObject(confirmation, base64urlDecode(key, 32), 'ukda.enrolment-confirmation.v1');
}
async function verifyCredentialAndName(transcript: EnrolmentTranscript, record: string | null,
  setupName: EnrolmentDraft['setupName']): Promise<void> {
  if (transcript.binding.kind === 'promote_owner') {
    if (record !== null || setupName !== null) throw new EnrolmentContractError();
    return;
  }
  if (record === null || transcript.registrationRecordHash !== await digestObject(record)) throw new EnrolmentContractError();
  await verifyName(transcript, setupName);
}
async function verifyName(transcript: EnrolmentTranscript, setupName: EnrolmentDraft['setupName']): Promise<void> {
  if (transcript.binding.kind === 'promote_owner') {
    if (setupName !== null) throw new EnrolmentContractError();
    return;
  }
  if (setupName === null || transcript.setupNameDigest !== await digestObject(setupName) || !await verifyRecipientEnvelope(setupName,
      base64urlDecode(transcript.device.signingPublicKey, 32), enrolmentSetupNameHeader(preNameFrom(transcript),
        await enrolmentLabelContextHash(preNameFrom(transcript))))) throw new EnrolmentContractError();
}

/** No registration record is needed to verify or decrypt a joining person's name proposal. */
export async function validateEnrolmentPublicDraft(value: unknown, expected: EnrolmentBinding, configuration?: Configuration) {
  const draft = snapshot(enrolmentPublicDraft, value), { transcript } = draft;
  sameAuthority(transcript, expected, configuration === undefined ? transcript.configuration : configuration);
  await verifyName(transcript, draft.setupName);
  const transcriptDigest = await digestObject(transcript);
  if ((draft.recipientConfirmation && !await validConfirmation(draft.recipientConfirmation, transcript, transcriptDigest, 'recipient')) ||
    (transcript.recovery ? !await validConfirmation(draft.newRecoveryConfirmation, transcript, transcriptDigest, 'new_recovery') :
      draft.newRecoveryConfirmation !== null)) throw new EnrolmentContractError();
  return { draft, transcriptDigest };
}

/** Password proof precedes explicit full-fingerprint confirmation; the latter may initially be null. */
export async function validateEnrolmentDraft(value: unknown, expected: EnrolmentBinding, configuration: Configuration) {
  const draft = snapshot(enrolmentDraft, value), { transcript } = draft;
  const { registrationRecord: _record, ...publicDraft } = draft;
  const { transcriptDigest } = await validateEnrolmentPublicDraft(publicDraft, expected, configuration);
  await verifyCredentialAndName(transcript, draft.registrationRecord, draft.setupName);
  const { recipientConfirmation: _confirmation, ...proofDraft } = draft;
  return { draft, transcriptDigest, draftHash: await digestObject(proofDraft) };
}

/** Current-state/history callers supply expected authority; a self-signed claimed Owner is insufficient. */
export async function validateEnrolmentTransition(value: unknown, expected: EnrolmentBinding, configuration: Configuration) {
  const transition = snapshot(enrolmentTransition, value), { transcript, transcriptDigest, profile, deliveries } = transition.body;
  sameAuthority(transcript, expected, configuration);
  const binding = transcript.binding;
  if (transcriptDigest !== await digestObject(transcript) ||
    !await validConfirmation(transition.body.recipientConfirmation, transcript, transcriptDigest, 'recipient') ||
    !await validConfirmation(transition.body.authorizerConfirmation, transcript, transcriptDigest, 'authorizer') ||
    !await verifyObject(transition, base64urlDecode(binding.authorizer.device.signingPublicKey, 32), transition.body.purpose) ||
    (transcript.recovery ? !await validConfirmation(transition.body.newRecoveryConfirmation, transcript, transcriptDigest, 'new_recovery') :
      transition.body.newRecoveryConfirmation !== null)) throw new EnrolmentContractError();
  if (binding.kind === 'promote_owner' ? profile !== null : !profile || profile.profileId !== binding.accountId ||
    profile.revision !== binding.nextProfileRevision || profile.id === binding.profile.objectId) throw new EnrolmentContractError();
  const devices = enrolmentRecipientDevices(transcript);
  if (deliveries.length !== binding.scopes.length * devices.length + (transcript.recovery ? 1 : 0) ||
    !unique(deliveries.map((entry) => entry.id)) || deliveries.some((entry) => entry.id === binding.approvalAttemptId ||
      entry.id === binding.operationId || entry.id === binding.profile.objectId || entry.id === profile?.id) ||
    profile?.id === binding.approvalAttemptId || profile?.id === binding.operationId) throw new EnrolmentContractError();
  for (const scope of binding.scopes) {
    const matches = deliveries.filter((entry) => entry.scope === scope.scope && entry.scopeId === scope.scopeId && entry.keyEpoch === scope.keyEpoch);
    if (matches.length !== devices.length + (scope.mode === 'custody' ? 1 : 0) ||
      devices.some((device) => matches.filter((entry) => entry.recipientKind === 'device' && entry.recipientId === device.id).length !== 1) ||
      (scope.mode === 'custody' && matches.filter((entry) => entry.recipientKind === 'recovery' && entry.recipientId === transcript.recovery?.id).length !== 1)) throw new EnrolmentContractError();
  }
  return { transition, transcriptDigest, securityHead: await digestObject(transition) };
}

/** Owner approval verifies all public/ciphertext bytes without exposing the recipient's OPAQUE record. */
export async function validateEnrolmentPublicApproval(value: unknown, expected: EnrolmentBinding, configuration: Configuration) {
  const approval = snapshot(enrolmentApproval, value);
  const checked = await validateEnrolmentTransition(approval.transition, expected, configuration);
  const { transcript, profile } = approval.transition.body, signer = base64urlDecode(transcript.binding.authorizer.device.signingPublicKey, 32);
  if (!unique(approval.deliveries.map((entry) => entry.id)) || approval.deliveries.length !== approval.transition.body.deliveries.length) throw new EnrolmentContractError();
  for (const descriptor of approval.transition.body.deliveries) {
    const found = approval.deliveries.find((entry) => entry.id === descriptor.id);
    const scope = transcript.binding.scopes.find((entry) => entry.scope === descriptor.scope && entry.scopeId === descriptor.scopeId);
    if (!found || !scope || await digestObject(found.envelope) !== descriptor.digest ||
      !await verifyRecipientEnvelope(found.envelope, signer, enrolmentRecipientHeader(transcript, checked.transcriptDigest, scope,
        descriptor.recipientKind, descriptor.recipientId))) throw new EnrolmentContractError();
  }
  if (profile ? !approval.profile || approval.profile.id !== profile.id || await digestObject(approval.profile.envelope) !== profile.digest ||
    !await verifyContentEnvelope(approval.profile.envelope, signer, enrolmentProfileHeader(transcript)) : approval.profile !== null) throw new EnrolmentContractError();
  return { ...checked, approval };
}
export async function validateEnrolmentPayload(value: unknown, expected: EnrolmentBinding, configuration: Configuration) {
  const payload = snapshot(enrolmentPayload, value);
  const { approval: _approval, ...checked } = await validateEnrolmentPublicApproval({ transition: payload.transition,
    deliveries: payload.deliveries, profile: payload.profile }, expected, configuration);
  await verifyCredentialAndName(payload.transition.body.transcript, payload.registrationRecord, payload.setupName);
  return { ...checked, payload, requestHash: await digestObject(payload) };
}
export async function validateEnrolmentApproval(value: unknown, expectedDraft: EnrolmentDraft, expected: EnrolmentBinding, configuration: Configuration) {
  const approval = snapshot(enrolmentApproval, value), { draft } = await validateEnrolmentDraft(expectedDraft, expected, configuration);
  if (!equal(approval.transition.body.transcript, draft.transcript) ||
    !equal(approval.transition.body.recipientConfirmation, draft.recipientConfirmation) ||
    !equal(approval.transition.body.newRecoveryConfirmation, draft.newRecoveryConfirmation)) throw new EnrolmentContractError();
  return validateEnrolmentPayload({ ...approval, registrationRecord: draft.registrationRecord, setupName: draft.setupName }, expected, configuration);
}
export async function validateEnrolmentReceipt(value: unknown, expected: EnrolmentTranscript): Promise<EnrolmentReceipt> {
  const receipt = snapshot(enrolmentReceipt, value), transcript = snapshot(enrolmentTranscript, expected), binding = transcript.binding;
  const checked = await validateEnrolmentTransition(receipt.transition, binding, transcript.configuration);
  if (!equal(receipt.transition.body.transcript, transcript) || receipt.operationId !== binding.operationId ||
    receipt.approvalAttemptId !== binding.approvalAttemptId || receipt.attemptGeneration !== binding.attemptGeneration ||
    receipt.workspaceId !== binding.workspaceId || receipt.accountId !== binding.accountId || receipt.deviceId !== transcript.device.id ||
    receipt.credentialGeneration !== binding.nextCredentialGeneration || receipt.sessionGeneration !== binding.nextSessionGeneration ||
    receipt.keyGeneration !== transcript.device.keyGeneration || receipt.recoveryGeneration !== binding.nextRecoveryGeneration ||
    receipt.ownershipVersion !== binding.nextOwnershipVersion || receipt.profileRevision !== binding.nextProfileRevision ||
    receipt.dataGeneration !== binding.dataGeneration || receipt.securityVersion !== binding.nextSecurityVersion ||
    receipt.securityHead !== checked.securityHead || receipt.wrapperHash !== transcript.wrapperHash) throw new EnrolmentContractError();
  return receipt;
}

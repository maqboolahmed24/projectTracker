import { z } from 'zod';
import { genesisBody, transcriptFromGenesis } from './activation.js';
import { binary, capabilities, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyObject } from './crypto.js';
import { entitlementTransitionBody } from './entitlement.js';
import { pairingConfirmationFor, pairingGrant, type PairingScope } from './pairing.js';
import { passwordChangePayload } from './password-change.js';
import { recoveryBinding, recoveryTransition, validateRecoveryTransition, type RecoveryBinding } from './recovery.js';
import { enrolmentBinding, enrolmentTranscript, enrolmentTransition, validateEnrolmentTransition, type EnrolmentBinding, type EnrolmentTranscript } from './enrolment.js';
import { BUILTIN_ROLE_PERMISSIONS, type BuiltinRole } from './permissions.js';
import { roleBinding, roleTransition, validateRoleTransition, type RoleBinding } from './roles.js';
import { accessTransition, validateAccessTransition, type AccessTransition } from './access-change.js';
import { scopeProvisionTransition, validateScopeProvisionTransition, type ScopeProvisionTransition } from './scope-provision.js';
import { parseJsonStrict } from './json.js';

export interface HistoryScope {
  scope: 'workspace' | 'project'; scopeId: string; mode: 'custody' | 'content'; keyEpoch: string;
  permissions: (typeof capabilities)[number][]; manifests: { id: string; digest: string }[];
  expiresAt: string | null;
}
export interface HistoryProfile {
  state: 'active' | 'suspended' | 'removed';
  accountId: string; active: boolean; owner: boolean; credentialGeneration: string; sessionGeneration: string;
  recoveryGeneration: string;
  profile: EnrolmentBinding['profile'];
  role: { id: string; revision: string };
  projectRoles: Record<string, { id: string; revision: string }>;
  scopes: HistoryScope[];
}
export interface HistoryRole {
  id: string; template: BuiltinRole | 'custom'; revision: string; permissions: (typeof capabilities)[number][];
  state: 'active' | 'retired'; label: { id: string; revision: string; digest: string } | null;
}
/** Retain retired public recovery keys so older signed transitions remain verifiable. */
export interface HistoryRecoveryAuthority {
  accountId: string; id: string; generation: string; active: boolean;
  signingPublicKey: string; recipientPublicKey: string; custodyEpoch: string;
  custodyEnvelope: { id: string; digest: string };
}
export interface HistoryDevice {
  id: string; accountId: string; active: boolean; keyGeneration: string;
  signingPublicKey: string; recipientPublicKey: string; scopes: HistoryScope[];
}
export interface SecurityHistoryState {
  workspaceId: string; origin: string; genesisFingerprint: string; securityHead: string; securityVersion: string;
  dataGeneration: string; ownershipVersion: string; custodyEpoch: string; workspaceKeyEpoch: string;
  entitlementState: 'activated' | 'revoked' | 'legacy_expired'; licenceState: 'active' | 'restricted' | 'revoked';
  profiles: Record<string, HistoryProfile>; devices: Record<string, HistoryDevice>;
  recoveryAuthorities: Record<string, HistoryRecoveryAuthority>;
  roles: Record<string, HistoryRole>;
  scopeHeads: Record<string, { scope: 'workspace' | 'project'; scopeId: string; keyEpoch: string }>;
  custodyManifest: { id: string; digest: string; revision: string };
}
export const securityPin = z.strictObject({ genesisFingerprint: digest, securityHead: digest, securityVersion: positiveCounter });
export type SecurityPin = z.infer<typeof securityPin>;
const historyInput = z.strictObject({
  workspaceId: identifier, origin: z.string().url(), genesisFingerprint: digest,
  genesis: z.strictObject({ body: genesisBody, signature: binary(64) }), transitions: z.array(z.unknown()),
  expected: z.strictObject({ securityHead: digest, securityVersion: positiveCounter }), pin: securityPin.optional(),
  trustedServiceKeys: z.record(z.string().min(1).max(64), binary(32)).default({}),
});
export type SecurityHistoryInput = z.input<typeof historyInput>;
export class SecurityHistoryError extends Error {
  constructor(readonly code: 'INVALID_HISTORY' | 'TRUST_MISMATCH' | 'ROLLBACK') {
    super(`Security history verification failed (${code})`); this.name = 'SecurityHistoryError';
  }
}
const invalid = () => new SecurityHistoryError('INVALID_HISTORY');
const next = (version: string) => String(BigInt(version) + 1n);
const equal = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const copy = <T>(value: T): T => parseJsonStrict(canonicalJson(value)) as T;
function checkHead(state: SecurityHistoryState, workspaceId: string, previousHead: string | null, version: string | null) {
  if (workspaceId !== state.workspaceId || previousHead !== state.securityHead || version !== next(state.securityVersion)) throw invalid();
}
function scopeKey(scope: Pick<HistoryScope, 'scope' | 'scopeId'>) { return `${scope.scope}:${scope.scopeId}`; }
function unique(values: readonly string[]) { return new Set(values).size === values.length; }
function covers(known: HistoryScope, claimed: PairingScope) {
  return scopeKey(known) === scopeKey(claimed) && known.mode === claimed.mode && known.keyEpoch === claimed.keyEpoch &&
    (known.expiresAt === null || (claimed.expiresAt !== null && Date.parse(claimed.expiresAt) <= Date.parse(known.expiresAt))) &&
    unique(claimed.permissions) && claimed.permissions.every((permission) => known.permissions.includes(permission));
}
function publicDeviceMatches(known: HistoryDevice, supplied: { id: string; keyGeneration: string; signingPublicKey: string; recipientPublicKey: string }) {
  return known.id === supplied.id && known.keyGeneration === supplied.keyGeneration &&
    known.signingPublicKey === supplied.signingPublicKey && known.recipientPublicKey === supplied.recipientPublicKey;
}

/** No role/project mutation is inferred: unsupported authority changes require their own signed transition. */
export function verifyEnrolmentBindingAgainstHistory(value: EnrolmentBinding, state: SecurityHistoryState): void {
  try {
    const binding = enrolmentBinding.parse(copy(value));
    if (binding.workspaceId !== state.workspaceId || binding.origin !== state.origin || binding.genesisFingerprint !== state.genesisFingerprint ||
      binding.securityHead !== state.securityHead || binding.securityVersion !== state.securityVersion || binding.dataGeneration !== state.dataGeneration ||
      binding.ownershipVersion !== state.ownershipVersion || binding.custodyEpoch !== state.custodyEpoch || binding.workspaceKeyEpoch !== state.workspaceKeyEpoch ||
      state.licenceState !== 'active' || state.entitlementState !== 'activated') throw invalid();
    const role = state.roles[binding.role.id], ownerKind = binding.kind !== 'join_member';
    if (!role || role.state !== 'active' || role.revision !== binding.role.revision || !equal(role.permissions, binding.role.permissions) ||
      (role.template === 'owner') !== ownerKind) throw invalid();
    const authorizer = state.profiles[binding.authorizer.accountId], signer = state.devices[binding.authorizer.device.id];
    const eligible = (scope: HistoryScope) => scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.parse(binding.issuedAt);
    const currentCustody = (scope: HistoryScope) => scope.scope === 'workspace' && scope.scopeId === state.workspaceId &&
      scope.mode === 'custody' && scope.keyEpoch === state.custodyEpoch && eligible(scope);
    if (!authorizer?.active || !authorizer.owner || !signer?.active || signer.accountId !== authorizer.accountId ||
      !publicDeviceMatches(signer, binding.authorizer.device) || binding.authorizer.credentialGeneration !== authorizer.credentialGeneration ||
      binding.authorizer.sessionGeneration !== authorizer.sessionGeneration || !authorizer.scopes.some(currentCustody) || !signer.scopes.some(currentCustody)) throw invalid();
    const target = state.profiles[binding.accountId];
    if (binding.kind === 'promote_owner') {
      if (!target?.active || target.owner || binding.credentialGeneration !== target.credentialGeneration ||
        binding.sessionGeneration !== target.sessionGeneration || binding.recoveryGeneration !== target.recoveryGeneration ||
        !equal(binding.profile, target.profile)) throw invalid();
      const devices = Object.values(state.devices).filter((device) => device.accountId === target.accountId);
      // Device rows remain historical identities after a delivery lease expires.
      // Promotion must not revive an expired browser by sealing new Owner custody
      // to it. Match the current personal + device workspace read gate used by
      // device authentication, without treating other old capabilities as access.
      const currentWorkspace = (scope: HistoryScope) => scope.scope === 'workspace' && scope.scopeId === state.workspaceId &&
        scope.mode === 'content' && scope.keyEpoch === state.workspaceKeyEpoch && scope.permissions.includes('read_project') && eligible(scope);
      const personalWorkspace = target.scopes.some(currentWorkspace);
      const preserved = devices.filter((device) => device.active && personalWorkspace && device.scopes.some(currentWorkspace));
      const maximum = devices.reduce((current, device) => BigInt(device.keyGeneration) > current ? BigInt(device.keyGeneration) : current, 0n);
      if (binding.deviceKeyGeneration !== String(maximum) || preserved.length !== binding.currentDevices.length ||
        binding.currentDevices.some((device) => !preserved.some((known) => publicDeviceMatches(known, device)))) throw invalid();
    } else if (target || Object.values(state.devices).some((device) => device.accountId === binding.accountId) ||
      Object.values(state.recoveryAuthorities).some((authority) => authority.accountId === binding.accountId)) throw invalid();

    const currentScopes = [
      ...Object.values(state.profiles).filter((profile) => profile.active).flatMap((profile) => profile.scopes),
      ...Object.values(state.devices).filter((device) => device.active && state.profiles[device.accountId]?.active).flatMap((device) => device.scopes),
    ].filter(eligible);
    const projects = new Set(currentScopes.filter((scope) => scope.scope === 'project').map(scopeKey));
    if (ownerKind && (binding.scopes.length !== projects.size + 1 || [...projects].some((key) => !binding.scopes.some((scope) => scopeKey(scope) === key)))) throw invalid();
    const ownerCustody = [...authorizer.scopes, ...Object.values(state.devices)
      .filter((device) => device.active && device.accountId === authorizer.accountId).flatMap((device) => device.scopes)].filter(currentCustody);
    for (const scope of binding.scopes) {
      let sources: HistoryScope[];
      if (scope.scope === 'workspace') {
        if (scope.keyEpoch !== (ownerKind ? state.custodyEpoch : state.workspaceKeyEpoch) || scope.mode !== (ownerKind ? 'custody' : 'content')) throw invalid();
        sources = ownerCustody;
      } else {
        const known = currentScopes.filter((entry) => scopeKey(entry) === scopeKey(scope));
        if (!known.length || known.some((entry) => entry.mode !== 'content' || entry.keyEpoch !== scope.keyEpoch) || scope.mode !== 'content' ||
          !authorizer.scopes.some((entry) => covers(entry, scope) && eligible(entry))) throw invalid();
        sources = known.filter((entry) => covers(entry, scope));
      }
      if (ownerKind && (!equal([...scope.permissions].sort(), [...capabilities].sort()) ||
        !authorizer.scopes.some((entry) => scopeKey(entry) === scopeKey(scope) && entry.expiresAt === scope.expiresAt && eligible(entry)))) throw invalid();
      if (!scope.sources.length || scope.sources.some((source) => !sources.some((known) =>
        (known.expiresAt === null || (scope.expiresAt !== null && Date.parse(scope.expiresAt) <= Date.parse(known.expiresAt))) &&
        scope.permissions.every((permission) => known.permissions.includes(permission)) &&
        known.manifests.some((manifest) => manifest.id === source.manifestId && manifest.digest === source.manifestDigest)))) throw invalid();
    }
  } catch (error) {
    if (error instanceof SecurityHistoryError) throw error;
    throw invalid();
  }
}

/** Internal journal application follows validation; old public identity keys remain for verification. */
function applyAccessTransition(state: SecurityHistoryState, transition: AccessTransition): void {
  const { binding, plan, custody, profile, deliveries } = transition.body;
  if (custody) state.custodyManifest = copy(custody);
  for (const rotation of plan.rotations) state.scopeHeads[scopeKey(rotation)] = { scope: rotation.scope, scopeId: rotation.scopeId, keyEpoch: rotation.nextEpoch };
  state.custodyEpoch = plan.nextCustodyEpoch; state.workspaceKeyEpoch = plan.nextWorkspaceKeyEpoch; state.ownershipVersion = plan.nextOwnershipVersion;
  const source = { id: state.custodyManifest.id, digest: state.custodyManifest.digest };
  for (const changed of plan.profiles) {
    const person = state.profiles[changed.accountId]!;
    person.role = copy(changed.role); person.projectRoles = copy(changed.projectRoles);
    person.scopes = changed.scopes.map((scope) => ({ ...copy(scope), manifests: [copy(source)] }));
  }
  const target = state.profiles[binding.targetAccountId]!;
  target.state = plan.target.state; target.active = plan.target.state === 'active'; target.owner = plan.target.owner;
  target.credentialGeneration = plan.target.credentialGeneration; target.sessionGeneration = plan.target.sessionGeneration;
  target.recoveryGeneration = plan.target.recoveryGeneration; target.role = copy(plan.target.role); target.projectRoles = copy(plan.target.projectRoles);
  if (!target.active) target.scopes = [];
  if (profile) target.profile = { id: target.accountId, revision: profile.revision, objectId: profile.id, objectDigest: profile.digest };
  for (const changed of plan.devices) {
    const device = state.devices[changed.device.id]!; device.active = changed.active;
    device.scopes = changed.scopes.map((scope) => {
      const delivery = deliveries.find((d) => d.recipient.kind === 'device' && d.recipient.id === device.id && scopeKey(d.recipient.scope) === scopeKey(scope));
      const previous = device.scopes.find((s) => scopeKey(s) === scopeKey(scope) && s.mode === scope.mode && s.keyEpoch === scope.keyEpoch);
      if (!delivery && !previous) throw invalid();
      return { ...copy(scope), manifests: delivery ? [{ id: delivery.id, digest: delivery.digest }] : copy(previous!.manifests) };
    });
  }
  for (const authority of Object.values(state.recoveryAuthorities)) {
    if (authority.accountId === target.accountId && !target.owner) authority.active = false;
    if (!authority.active || !custody) continue;
    const delivery = deliveries.find((d) => d.recipient.kind === 'recovery' && d.recipient.accountId === authority.accountId && d.recipient.id === authority.id && d.recipient.keyGeneration === authority.generation);
    if (!delivery) throw invalid(); authority.custodyEpoch = plan.nextCustodyEpoch;
    authority.custodyEnvelope = { id: delivery.id, digest: delivery.digest };
  }
}

function applyScopeProvisionTransition(state: SecurityHistoryState, transition: ScopeProvisionTransition): void {
  const { binding, plan, custody, deliveries } = transition.body;
  state.scopeHeads[`project:${binding.projectId}`] = { scope: 'project', scopeId: binding.projectId, keyEpoch: '1' };
  state.custodyManifest = copy(custody); state.custodyEpoch = plan.nextCustodyEpoch;
  const source = { id: custody.id, digest: custody.digest };
  for (const changed of plan.profiles) {
    const person = state.profiles[changed.accountId]!;
    person.role = copy(changed.role); person.projectRoles = copy(changed.projectRoles);
    person.scopes = changed.scopes.map((scope) => ({ ...copy(scope), manifests: [copy(source)] }));
  }
  for (const changed of plan.devices) {
    const device = state.devices[changed.device.id]!; device.active = changed.active;
    device.scopes = changed.scopes.map((scope) => {
      const delivery = deliveries.find((d) => d.recipient.kind === 'device' && d.recipient.id === device.id && scopeKey(d.recipient.scope) === scopeKey(scope));
      const previous = device.scopes.find((s) => scopeKey(s) === scopeKey(scope) && s.mode === scope.mode && s.keyEpoch === scope.keyEpoch);
      if (!delivery && !previous) throw invalid();
      return { ...copy(scope), manifests: delivery ? [{ id: delivery.id, digest: delivery.digest }] : copy(previous!.manifests) };
    });
  }
  for (const authority of Object.values(state.recoveryAuthorities).filter((r) => r.active)) {
    const delivery = deliveries.find((d) => d.recipient.kind === 'recovery' && d.recipient.accountId === authority.accountId && d.recipient.id === authority.id && d.recipient.keyGeneration === authority.generation);
    if (!delivery) throw invalid();
    authority.custodyEpoch = plan.nextCustodyEpoch; authority.custodyEnvelope = { id: delivery.id, digest: delivery.digest };
  }
}

/** Role definitions change defaults only; assignment snapshots are separate signed authority. */
export function verifyRoleBindingAgainstHistory(value: RoleBinding, state: SecurityHistoryState): void {
  try {
    const binding = roleBinding.parse(copy(value)), actor = binding.authorizer;
    if (binding.workspaceId !== state.workspaceId || binding.origin !== state.origin || binding.genesisFingerprint !== state.genesisFingerprint ||
      binding.securityHead !== state.securityHead || binding.securityVersion !== state.securityVersion || binding.dataGeneration !== state.dataGeneration ||
      binding.ownershipVersion !== state.ownershipVersion || binding.custodyEpoch !== state.custodyEpoch || binding.workspaceKeyEpoch !== state.workspaceKeyEpoch ||
      state.licenceState !== 'active' || state.entitlementState !== 'activated') throw invalid();
    const profile = state.profiles[actor.accountId], device = state.devices[actor.device.id];
    const custody = (scope: HistoryScope) => scope.scope === 'workspace' && scope.scopeId === state.workspaceId && scope.mode === 'custody' &&
      scope.keyEpoch === state.custodyEpoch && scope.permissions.includes('read_project') &&
      (scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.parse(binding.issuedAt));
    if (!profile?.active || !profile.owner || !device?.active || device.accountId !== actor.accountId || !publicDeviceMatches(device, actor.device) ||
      actor.credentialGeneration !== profile.credentialGeneration || actor.sessionGeneration !== profile.sessionGeneration ||
      !profile.scopes.some(custody) || !device.scopes.some(custody)) throw invalid();
    const previous = state.roles[binding.roleId];
    if (binding.action === 'create' ? previous !== undefined : !previous || previous.template !== 'custom' || previous.state !== 'active' ||
      !equal(previous, binding.previous)) throw invalid();
    if (binding.action === 'retire' && Object.values(state.profiles).some((entry) => entry.active &&
      (entry.role.id === binding.roleId || Object.values(entry.projectRoles).some((role) => role.id === binding.roleId)))) throw invalid();
  } catch (error) { if (error instanceof SecurityHistoryError) throw error; throw invalid(); }
}

/** Check recipient freshness before any client seals private material, using the same rule as journal replay. */
export function verifyEnrolmentTranscriptAgainstHistory(value: EnrolmentTranscript, state: SecurityHistoryState): void {
  try {
    const transcript = enrolmentTranscript.parse(copy(value)), binding = transcript.binding;
    verifyEnrolmentBindingAgainstHistory(binding, state);
    const devices = Object.values(state.devices), authorities = Object.values(state.recoveryAuthorities), fresh = transcript.device;
    if (binding.kind !== 'promote_owner' && (state.devices[fresh.id] || devices.some((device) =>
      device.signingPublicKey === fresh.signingPublicKey || device.recipientPublicKey === fresh.recipientPublicKey) ||
      authorities.some((authority) => authority.id === fresh.id || authority.signingPublicKey === fresh.signingPublicKey ||
        authority.recipientPublicKey === fresh.recipientPublicKey))) throw invalid();
    const recovery = transcript.recovery;
    if (recovery && (authorities.some((authority) => authority.id === recovery.id || authority.signingPublicKey === recovery.signingPublicKey ||
      authority.recipientPublicKey === recovery.recipientPublicKey) || devices.some((device) => device.id === recovery.id ||
      device.signingPublicKey === recovery.signingPublicKey || device.recipientPublicKey === recovery.recipientPublicKey) ||
      recovery.signingPublicKey === fresh.signingPublicKey || recovery.recipientPublicKey === fresh.recipientPublicKey)) throw invalid();
  } catch (error) {
    if (error instanceof SecurityHistoryError) throw error;
    throw invalid();
  }
}

/** A recovery binding is authority only after its fields match independently verified history. */
export function verifyRecoveryBindingAgainstHistory(value: RecoveryBinding, state: SecurityHistoryState): void {
  try {
    const binding = recoveryBinding.parse(copy(value)), profile = state.profiles[binding.accountId];
    if (!profile?.active || binding.isOwner !== profile.owner || binding.workspaceId !== state.workspaceId || binding.origin !== state.origin ||
      binding.genesisFingerprint !== state.genesisFingerprint || binding.securityHead !== state.securityHead || binding.securityVersion !== state.securityVersion ||
      binding.dataGeneration !== state.dataGeneration || binding.ownershipVersion !== state.ownershipVersion || binding.custodyEpoch !== state.custodyEpoch ||
      binding.credentialGeneration !== profile.credentialGeneration || binding.sessionGeneration !== profile.sessionGeneration ||
      binding.recoveryGeneration !== profile.recoveryGeneration) throw invalid();
    const targetDevices = Object.values(state.devices).filter((device) => device.accountId === profile.accountId);
    const highestGeneration = targetDevices.reduce((highest, device) => BigInt(device.keyGeneration) > highest ? BigInt(device.keyGeneration) : highest, 0n);
    if (binding.deviceKeyGeneration !== String(highestGeneration)) throw invalid();
    if (profile.owner) {
      const current = state.recoveryAuthorities[`${profile.accountId}:${profile.recoveryGeneration}`];
      if (!current?.active || current.custodyEpoch !== state.custodyEpoch || !equal(binding.currentRecovery,
        { id: current.id, generation: current.generation, signingPublicKey: current.signingPublicKey, recipientPublicKey: current.recipientPublicKey })) throw invalid();
    } else if (binding.currentRecovery !== null) throw invalid();
    if (binding.authorizer.kind === 'owner_reset') {
      const authority = binding.authorizer, owner = state.profiles[authority.accountId], device = state.devices[authority.device.id];
      if (!owner?.active || !owner.owner || !device?.active || device.accountId !== owner.accountId || !publicDeviceMatches(device, authority.device) ||
        authority.credentialGeneration !== owner.credentialGeneration || authority.sessionGeneration !== owner.sessionGeneration ||
        authority.resetId !== binding.operationId || !device.scopes.some((scope) => scope.mode === 'custody' && scope.scope === 'workspace' &&
          scope.scopeId === state.workspaceId && scope.keyEpoch === state.custodyEpoch &&
          (scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.parse(binding.issuedAt)))) throw invalid();
    }
    const eligible = profile.scopes.filter((scope) => scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.parse(binding.issuedAt));
    if (eligible.length !== binding.scopes.length || !binding.scopes.some((scope) => scope.scope === 'workspace' && scope.scopeId === state.workspaceId)) throw invalid();
    for (const scope of binding.scopes) {
      const known = eligible.find((entry) => covers(entry, scope));
      if (!known || (scope.expiresAt !== null && Date.parse(scope.expiresAt) <= Date.parse(binding.issuedAt)) ||
        !equal([...known.permissions].sort(), [...scope.permissions].sort())) throw invalid();
      const manifests = [...known.manifests, ...targetDevices.filter((device) => device.active)
        .flatMap((device) => device.scopes.filter((entry) => covers(entry, scope)).flatMap((entry) => entry.manifests))];
      if (scope.sources.some((source) => !manifests.some((entry) => entry.id === source.manifestId && entry.digest === source.manifestDigest))) throw invalid();
    }
  } catch (error) {
    if (error instanceof SecurityHistoryError) throw error;
    throw invalid();
  }
}

/**
 * Replay only explicitly supported transitions from an independently pinned genesis.
 * `expected` must come from the locally verified pairing transcript/current operation;
 * service keys come from trusted deployment configuration, never the history itself.
 * Historical timestamps are validated structurally, not against today's clock.
 */
export async function verifySecurityHistory(value: SecurityHistoryInput): Promise<SecurityHistoryState> {
  try {
    // Snapshot before the first await; callers cannot mutate a verified prefix in flight.
    const input = historyInput.parse(copy(value));
    const body = input.genesis.body;
    const fingerprint = await digestObject(input.genesis);
    if (fingerprint !== input.genesisFingerprint || (input.pin && input.pin.genesisFingerprint !== fingerprint)) {
      throw new SecurityHistoryError('TRUST_MISMATCH');
    }
    if (body.workspaceId !== input.workspaceId || body.origin !== input.origin || new URL(input.origin).origin !== input.origin ||
      body.transcriptDigest !== await digestObject(transcriptFromGenesis(body)) ||
      !equal(body.ownerPermissions, [...capabilities]) || !unique(body.manifest.map((entry) => entry.id)) ||
      !await verifyObject(input.genesis, base64urlDecode(body.device.signingPublicKey, 32), 'ukda.genesis.v1')) throw invalid();
    const custody = body.manifest.find((entry) => entry.id === body.custodyId && entry.kind === 'custody_manifest');
    const recoveryEnvelope = body.manifest.find((entry) => entry.id === body.recoveryEnvelopeId && entry.kind === 'key_envelope');
    const profileObject = body.manifest.find((entry) => entry.id === body.accountId && entry.kind === 'encrypted_profile');
    if (!custody || !recoveryEnvelope || !profileObject || !unique(Object.values(body.roles)) ||
      Object.values(body.roles).some((id) => [body.workspaceId, body.accountId, body.device.id, body.recovery.id, body.genesisId,
        body.custodyId, body.deviceEnvelopeId, body.recoveryEnvelopeId].includes(id))) throw invalid();
    const workspaceScope: HistoryScope = { scope: 'workspace', scopeId: body.workspaceId, mode: 'custody', keyEpoch: '1',
      permissions: [...body.ownerPermissions], manifests: [{ id: custody.id, digest: custody.digest }], expiresAt: null };
    const state: SecurityHistoryState = { workspaceId: body.workspaceId, origin: body.origin, genesisFingerprint: fingerprint,
      securityHead: fingerprint, securityVersion: '1', dataGeneration: '1', ownershipVersion: '1', custodyEpoch: '1', workspaceKeyEpoch: '1',
      entitlementState: 'activated', licenceState: 'active',
      profiles: { [body.accountId]: { accountId: body.accountId, state: 'active', active: true, owner: true, credentialGeneration: '1',
        role: { id: body.roles.owner, revision: '1' }, projectRoles: {},
        sessionGeneration: '1', recoveryGeneration: '1', profile: { id: body.accountId, revision: '1', objectId: profileObject.id,
          objectDigest: profileObject.digest }, scopes: [copy(workspaceScope)] } },
      devices: { [body.device.id]: { ...body.device, accountId: body.accountId, active: true, keyGeneration: '1', scopes: [copy(workspaceScope)] } },
      recoveryAuthorities: { [`${body.accountId}:1`]: { ...body.recovery, accountId: body.accountId, generation: '1', active: true,
        custodyEpoch: '1', custodyEnvelope: { id: recoveryEnvelope.id, digest: recoveryEnvelope.digest } } },
      roles: Object.fromEntries((Object.keys(BUILTIN_ROLE_PERMISSIONS) as BuiltinRole[]).map((template) => [body.roles[template],
        { id: body.roles[template], template, revision: '1', permissions: [...BUILTIN_ROLE_PERMISSIONS[template]], state: 'active', label: null }])),
      scopeHeads: { [`workspace:${body.workspaceId}`]: { scope: 'workspace', scopeId: body.workspaceId, keyEpoch: '1' } },
      custodyManifest: { id: custody.id, digest: custody.digest, revision: '1' } };
    if (input.pin && BigInt(input.expected.securityVersion) < BigInt(input.pin.securityVersion)) throw new SecurityHistoryError('ROLLBACK');
    let foundPin = !input.pin;
    const acceptPin = () => {
      if (input.pin && state.securityVersion === input.pin.securityVersion) {
        if (state.securityHead !== input.pin.securityHead) throw new SecurityHistoryError('ROLLBACK');
        foundPin = true;
      }
    };
    acceptPin();
    const operations = new Set([body.operationId]);
    for (const unknown of input.transitions) {
      const outer = z.object({ body: z.object({ purpose: z.string() }), signature: binary(64) }).parse(unknown);
      let operationId: string;
      if (outer.body.purpose === 'ukda.entitlement-transition.v1') {
        const transition = z.strictObject({ body: entitlementTransitionBody, signature: binary(64) }).parse(unknown);
        const change = transition.body;
        if (!change.workspaceId) throw invalid();
        checkHead(state, change.workspaceId, change.previousHead, change.securityVersion);
        const key = input.trustedServiceKeys[change.serviceKeyId];
        if (!key || key !== change.servicePublicKey || change.dataGeneration !== state.dataGeneration ||
          change.before.entitlementState !== state.entitlementState || change.before.licenceState !== state.licenceState ||
          !await verifyObject(transition, base64urlDecode(key, 32), 'ukda.entitlement-transition.v1')) throw invalid();
        state.entitlementState = change.after.entitlementState as SecurityHistoryState['entitlementState'];
        state.licenceState = change.after.licenceState!;
        operationId = change.operationId;
      } else if (outer.body.purpose === 'ukda.device-pair-grant.v1') {
        const transition = pairingGrant.parse(unknown), grant = transition.body, transcript = grant.transcript;
        checkHead(state, grant.workspaceId, grant.previousHead, grant.securityVersion);
        const recipient = state.profiles[transcript.accountId], approver = state.profiles[transcript.approverAccountId];
        const signer = state.devices[transcript.approverDevice.id];
        if (!recipient?.active || !approver?.active || !signer?.active || signer.accountId !== approver.accountId ||
          !publicDeviceMatches(signer, transcript.approverDevice) || transcript.approverIsOwner !== approver.owner ||
          (recipient.accountId !== approver.accountId && !approver.owner) || state.devices[transcript.device.id] ||
          Object.values(state.devices).some((device) => device.signingPublicKey === transcript.device.signingPublicKey ||
            device.recipientPublicKey === transcript.device.recipientPublicKey) ||
          transcript.origin !== state.origin || transcript.workspaceId !== state.workspaceId ||
          transcript.genesisFingerprint !== state.genesisFingerprint || transcript.securityHead !== state.securityHead ||
          transcript.securityVersion !== state.securityVersion || transcript.dataGeneration !== state.dataGeneration ||
          transcript.ownershipVersion !== state.ownershipVersion || transcript.custodyEpoch !== state.custodyEpoch ||
          transcript.credentialGeneration !== recipient.credentialGeneration || transcript.sessionGeneration !== recipient.sessionGeneration ||
          transcript.approverCredentialGeneration !== approver.credentialGeneration || transcript.approverSessionGeneration !== approver.sessionGeneration ||
          transcript.device.keyGeneration !== '1' || grant.operationId !== transcript.operationId || grant.grantId !== grant.operationId ||
          grant.transcriptDigest !== await digestObject(transcript) || !unique(transcript.scopes.map(scopeKey)) ||
          !unique(grant.deliveries.map((entry) => entry.id)) || !unique(grant.deliveries.map(scopeKey)) ||
          grant.deliveries.length !== transcript.scopes.length) throw invalid();
        if (!signer.scopes.some((scope) => scope.scope === 'workspace' && scope.scopeId === state.workspaceId) ||
          !transcript.scopes.some((scope) => scope.scope === 'workspace' && scope.scopeId === state.workspaceId)) throw invalid();
        for (const role of ['recipient', 'approver'] as const) {
          const confirmation = role === 'recipient' ? grant.recipientConfirmation : grant.approverConfirmation;
          const key = role === 'recipient' ? transcript.device.signingPublicKey : signer.signingPublicKey;
          if (!equal(confirmation.body, pairingConfirmationFor(transcript, grant.transcriptDigest, role)) ||
            !await verifyObject(confirmation, base64urlDecode(key, 32), 'ukda.device-pair-confirmation.v1')) throw invalid();
        }
        if (!await verifyObject(transition, base64urlDecode(signer.signingPublicKey, 32), 'ukda.device-pair-grant.v1')) throw invalid();
        const newScopes: HistoryScope[] = [];
        for (const scope of transcript.scopes) {
          if (scope.expiresAt !== null && Date.parse(scope.expiresAt) <= Date.parse(transcript.issuedAt)) throw invalid();
          const known = recipient.scopes.find((entry) => covers(entry, scope));
          if (!known || (recipient.accountId === approver.accountId && !signer.scopes.some((entry) => covers(entry, scope))) ||
            !unique(scope.sources.map((entry) => entry.grantId))) throw invalid();
          // Server-generated grant UUIDs are not genesis trust anchors. Require each
          // cited manifest to have appeared in this profile's prior signed authority.
          const manifests = [...known.manifests, ...Object.values(state.devices).filter((device) => device.active && device.accountId === recipient.accountId)
            .flatMap((device) => device.scopes.filter((entry) => covers(entry, scope)).flatMap((entry) => entry.manifests))];
          if (scope.sources.some((source) => !manifests.some((entry) => entry.id === source.manifestId && entry.digest === source.manifestDigest))) throw invalid();
          const delivery = grant.deliveries.find((entry) => scopeKey(entry) === scopeKey(scope));
          if (!delivery) throw invalid();
          newScopes.push({ scope: scope.scope, scopeId: scope.scopeId, mode: scope.mode, keyEpoch: scope.keyEpoch,
            permissions: [...scope.permissions], manifests: [{ id: delivery.id, digest: delivery.digest }], expiresAt: scope.expiresAt });
        }
        state.devices[transcript.device.id] = { ...transcript.device, accountId: recipient.accountId, active: true, scopes: newScopes };
        operationId = grant.operationId;
      } else if (outer.body.purpose === 'ukda.password-change.v1') {
        const transition = passwordChangePayload.shape.transition.parse(unknown), binding = transition.body.binding;
        checkHead(state, binding.workspaceId, binding.securityHead, binding.nextSecurityVersion);
        const profile = state.profiles[binding.accountId], signer = state.devices[binding.deviceId];
        if (!profile?.active || !signer?.active || signer.accountId !== profile.accountId || binding.origin !== state.origin ||
          binding.securityVersion !== state.securityVersion || binding.dataGeneration !== state.dataGeneration ||
          binding.ownershipVersion !== state.ownershipVersion || binding.custodyEpoch !== state.custodyEpoch ||
          binding.credentialGeneration !== profile.credentialGeneration || binding.sessionGeneration !== profile.sessionGeneration ||
          binding.keyGeneration !== signer.keyGeneration || binding.signingPublicKey !== signer.signingPublicKey ||
          binding.recipientPublicKey !== signer.recipientPublicKey ||
          !signer.scopes.some((scope) => scope.scope === 'workspace' && (scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.parse(binding.issuedAt))) ||
          !await verifyObject(transition, base64urlDecode(signer.signingPublicKey, 32), 'ukda.password-change.v1')) throw invalid();
        profile.credentialGeneration = binding.nextCredentialGeneration; profile.sessionGeneration = binding.nextSessionGeneration;
        for (const device of Object.values(state.devices)) if (device.accountId === profile.accountId && device.id !== signer.id) device.active = false;
        operationId = binding.operationId;
      } else if (outer.body.purpose === 'ukda.profile-enrolment.v1' || outer.body.purpose === 'ukda.owner-promotion.v1') {
        const transition = enrolmentTransition.parse(unknown), { transcript, deliveries } = transition.body, binding = transcript.binding;
        checkHead(state, binding.workspaceId, binding.securityHead, binding.nextSecurityVersion);
        verifyEnrolmentTranscriptAgainstHistory(transcript, state);
        const authorities = Object.values(state.recoveryAuthorities), fresh = transcript.device, recovery = transcript.recovery;
        await validateEnrolmentTransition(transition, binding, transcript.configuration);
        const deviceScopes = (deviceId: string): HistoryScope[] => binding.scopes.map((scope) => {
          const delivery = deliveries.find((item) => item.recipientKind === 'device' && item.recipientId === deviceId && scopeKey(item) === scopeKey(scope))!;
          return { scope: scope.scope, scopeId: scope.scopeId, mode: scope.mode, keyEpoch: scope.keyEpoch, permissions: [...scope.permissions],
            manifests: [{ id: delivery.id, digest: delivery.digest }], expiresAt: scope.expiresAt };
        });
        const preserved = binding.kind === 'promote_owner' ? binding.currentDevices : [fresh];
        for (const device of preserved) state.devices[device.id] = { ...device, accountId: binding.accountId, active: true, scopes: deviceScopes(device.id) };
        const profileScopes = binding.scopes.map((scope): HistoryScope => ({ scope: scope.scope, scopeId: scope.scopeId, mode: scope.mode,
          keyEpoch: scope.keyEpoch, permissions: [...scope.permissions], expiresAt: scope.expiresAt,
          manifests: [...scope.sources.map((source) => ({ id: source.manifestId, digest: source.manifestDigest })),
            ...preserved.flatMap((device) => deviceScopes(device.id).find((entry) => scopeKey(entry) === scopeKey(scope))!.manifests)] }));
        const profile = transition.body.profile;
        state.profiles[binding.accountId] = { accountId: binding.accountId, state: 'active', active: true, owner: binding.kind !== 'join_member',
          credentialGeneration: binding.nextCredentialGeneration, sessionGeneration: binding.nextSessionGeneration,
          recoveryGeneration: binding.nextRecoveryGeneration, scopes: profileScopes,
          role: { id: binding.role.id, revision: binding.role.revision },
          projectRoles: Object.fromEntries(binding.scopes.filter((scope) => scope.scope === 'project').map((scope) => [scope.scopeId, { id: binding.role.id, revision: binding.role.revision }])),
          profile: profile ? { id: binding.accountId, revision: profile.revision, objectId: profile.id, objectDigest: profile.digest } : copy(binding.profile) };
        if (recovery) {
          for (const authority of authorities) if (authority.accountId === binding.accountId) authority.active = false;
          const delivery = deliveries.find((item) => item.recipientKind === 'recovery' && item.recipientId === recovery.id)!;
          state.recoveryAuthorities[`${binding.accountId}:${recovery.generation}`] = { ...recovery, accountId: binding.accountId, active: true,
            custodyEpoch: binding.custodyEpoch, custodyEnvelope: { id: delivery.id, digest: delivery.digest } };
        }
        state.ownershipVersion = binding.nextOwnershipVersion;
        operationId = binding.operationId;
      } else if (outer.body.purpose === 'ukda.account-recovery.v1') {
        const transition = recoveryTransition.parse(unknown), { transcript, deliveries } = transition.body, binding = transcript.binding;
        checkHead(state, binding.workspaceId, binding.securityHead, binding.nextSecurityVersion);
        verifyRecoveryBindingAgainstHistory(binding, state);
        const knownDevices = Object.values(state.devices), knownRecoveries = Object.values(state.recoveryAuthorities);
        const fresh = transcript.device;
        if (state.devices[fresh.id] || knownDevices.some((device) => device.signingPublicKey === fresh.signingPublicKey || device.recipientPublicKey === fresh.recipientPublicKey) ||
          knownRecoveries.some((authority) => authority.id === fresh.id || authority.signingPublicKey === fresh.signingPublicKey || authority.recipientPublicKey === fresh.recipientPublicKey)) throw invalid();
        const recovery = transcript.recovery;
        if (recovery && (knownRecoveries.some((authority) => authority.id === recovery.id || authority.signingPublicKey === recovery.signingPublicKey || authority.recipientPublicKey === recovery.recipientPublicKey) ||
          knownDevices.some((device) => device.id === recovery.id || device.signingPublicKey === recovery.signingPublicKey || device.recipientPublicKey === recovery.recipientPublicKey) ||
          recovery.signingPublicKey === fresh.signingPublicKey || recovery.recipientPublicKey === fresh.recipientPublicKey)) throw invalid();
        await validateRecoveryTransition(transition, binding, transcript.configuration);
        const profile = state.profiles[binding.accountId]!;
        profile.credentialGeneration = binding.nextCredentialGeneration;
        profile.sessionGeneration = binding.nextSessionGeneration;
        profile.recoveryGeneration = binding.nextRecoveryGeneration;
        for (const device of knownDevices) if (device.accountId === profile.accountId) device.active = false;
        const scopes = binding.scopes.map((scope): HistoryScope => {
          const delivery = deliveries.find((item) => item.recipientKind === 'device' && item.recipientId === fresh.id && scopeKey(item) === scopeKey(scope))!;
          return { scope: scope.scope, scopeId: scope.scopeId, mode: scope.mode, keyEpoch: scope.keyEpoch, permissions: [...scope.permissions],
            manifests: [{ id: delivery.id, digest: delivery.digest }], expiresAt: scope.expiresAt };
        });
        state.devices[fresh.id] = { ...fresh, accountId: profile.accountId, active: true, scopes };
        if (recovery) {
          for (const authority of knownRecoveries) if (authority.accountId === profile.accountId) authority.active = false;
          const delivery = deliveries.find((item) => item.recipientKind === 'recovery' && item.recipientId === recovery.id)!;
          state.recoveryAuthorities[`${profile.accountId}:${recovery.generation}`] = { ...recovery, accountId: profile.accountId, active: true,
            custodyEpoch: binding.custodyEpoch, custodyEnvelope: { id: delivery.id, digest: delivery.digest } };
        }
        operationId = binding.operationId;
      } else if (outer.body.purpose === 'ukda.project-scope-provision.v1') {
        const transition = scopeProvisionTransition.parse(unknown), binding = transition.body.binding;
        checkHead(state, binding.workspaceId, binding.securityHead, binding.nextSecurityVersion);
        await validateScopeProvisionTransition(transition, binding, state);
        applyScopeProvisionTransition(state, transition);
        operationId = binding.operationId;
      } else if (outer.body.purpose === 'ukda.access-change.v1') {
        const transition = accessTransition.parse(unknown), binding = transition.body.binding;
        checkHead(state, binding.workspaceId, binding.securityHead, binding.nextSecurityVersion);
        await validateAccessTransition(transition, binding, state);
        applyAccessTransition(state, transition);
        operationId = binding.operationId;
      } else if (outer.body.purpose === 'ukda.custom-role-definition.v1') {
        const transition = roleTransition.parse(unknown), binding = transition.body.binding;
        checkHead(state, binding.workspaceId, binding.securityHead, binding.nextSecurityVersion);
        verifyRoleBindingAgainstHistory(binding, state);
        await validateRoleTransition(transition, binding);
        state.roles[binding.roleId] = copy(transition.body.role);
        operationId = binding.operationId;
      } else throw invalid();
      if (operations.has(operationId)) throw invalid();
      operations.add(operationId);
      state.securityHead = await digestObject(unknown); state.securityVersion = next(state.securityVersion);
      acceptPin();
    }
    if (!foundPin) throw new SecurityHistoryError('ROLLBACK');
    if (state.securityHead !== input.expected.securityHead || state.securityVersion !== input.expected.securityVersion) throw invalid();
    return state;
  } catch (error) {
    if (error instanceof SecurityHistoryError) throw error;
    throw invalid();
  }
}

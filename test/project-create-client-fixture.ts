import { randomUUID } from 'node:crypto';
import { base64urlEncode, digestObject, randomKey } from '../src/shared/crypto.js';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { unwrapDeviceBundle, type DeviceBundle } from '../src/client/device-store.js';
import { prepareJoinInvitation, prepareEnrolmentDraft, confirmEnrolmentTarget, prepareEnrolmentApproval } from '../src/client/enrolment-controller.js';
import { enrolmentDeviceContext } from '../src/client/enrolment-crypto.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../src/client/opaque.js';
import { enrolmentBinding, type EnrolmentBinding } from '../src/shared/enrolment.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../src/shared/security-history.js';
import type { PairingMaterial } from '../src/shared/pairing.js';
import type { AvatarSelection } from '../src/shared/avatar.js';

export const origin = 'https://project-client.ukda.example', next = (value: string) => String(BigInt(value) + 1n);
export interface Actor { accountId: string; deviceId: string; bundle: DeviceBundle; phrase: string | undefined }
export async function ownerFixture(options: { avatar?: AvatarSelection } = {}) {
  const workspaceId = randomUUID(), accountId = randomUUID(), exportKey = base64urlEncode(await randomKey()), phrase = await newOwnerPhrase();
  const configuration: OpaquePublicConfiguration = { configId: OPAQUE_CONFIG_ID, setupId: 'access-client', keyStretching: OPAQUE_KEY_STRETCHING,
    serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } };
  const prepared = await prepareOwnerActivation({ binding: { workspaceId, accountId, origin, activationId: randomUUID(), operationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1' },
    configuration, exportKey, registrationRecord: base64urlEncode(await randomKey()), phrase, challengePositions: [1, 9, 19],
    challengeAnswers: [1, 9, 19].map((index) => phrase.split(' ')[index]!), displayName: 'Private Owner', workspaceName: 'Private access workspace', ...options });
  const genesis = prepared.payload.genesis, head = await digestObject(genesis), deviceId = genesis.body.device.id;
  const history: SecurityHistoryInput = { workspaceId, origin, genesisFingerprint: head, genesis, transitions: [], expected: { securityHead: head, securityVersion: '1' } };
  const bundle = await unwrapDeviceBundle({ workspaceId, accountId, deviceId, credentialGeneration: '1' }, prepared.deviceWrapper, exportKey);
  const materials: PairingMaterial[] = [
    { id: genesis.body.custodyId, kind: 'custody_manifest', value: prepared.payload.objects.custody, digest: await digestObject(prepared.payload.objects.custody) },
    { id: genesis.body.deviceEnvelopeId, kind: 'key_envelope', value: prepared.payload.objects.deviceCustody, digest: await digestObject(prepared.payload.objects.deviceCustody) },
    { id: genesis.body.recoveryEnvelopeId, kind: 'key_envelope', value: prepared.payload.objects.recoveryCustody, digest: await digestObject(prepared.payload.objects.recoveryCustody) },
  ];
  return { workspaceId, configuration, owner: { accountId, deviceId, bundle, phrase } as Actor, history, state: await verifySecurityHistory(history), materials,
    initialWorkspace: prepared.payload.objects.workspace, initialProfile: prepared.payload.objects.profile };
}
export type OwnerFixture = Awaited<ReturnType<typeof ownerFixture>>;
export function actorAuthority(f: OwnerFixture, actor = f.owner) {
  const profile = f.state.profiles[actor.accountId]!, device = f.state.devices[actor.deviceId]!;
  return { accountId: actor.accountId, device: { id: device.id, keyGeneration: device.keyGeneration, signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey },
    credentialGeneration: profile.credentialGeneration, sessionGeneration: profile.sessionGeneration };
}
export async function append(f: OwnerFixture, transition: unknown, version: string) {
  f.history = { ...f.history, transitions: [...f.history.transitions, transition], expected: { securityHead: await digestObject(transition), securityVersion: version } };
  f.state = await verifySecurityHistory(f.history);
}
export async function join(f: OwnerFixture, owner = false): Promise<Actor> {
  const state = f.state, accountId = randomUUID(), operationId = randomUUID(), now = Date.now(), kind = owner ? 'join_owner' : 'join_member',
    role = Object.values(state.roles).find((entry) => entry.template === (owner ? 'owner' : 'member'))!, authorizer = actorAuthority(f);
  const profile = await prepareJoinInvitation({ request: { workspaceId: f.workspaceId, accountId, operationId, kind, roleId: role.id, projectIds: [] },
    history: f.history, displayName: 'Private invited account', context: { workspaceId: f.workspaceId, accountId, operationId, kind,
      role: { id: role.id, revision: role.revision, permissions: role.permissions }, authorizer, genesisFingerprint: state.genesisFingerprint,
      custodyEpoch: state.custodyEpoch, current: f.history.expected, materials: f.materials,
      header: { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: f.workspaceId, scope: 'workspace', scopeId: f.workspaceId,
        recordId: accountId, recordType: 'profile', schema: 1, keyEpoch: state.workspaceKeyEpoch, revision: '1', operationId, accountId: f.owner.accountId,
        deviceId: f.owner.deviceId, keyGeneration: authorizer.device.keyGeneration, permissionVersion: role.revision, securityVersion: state.securityVersion,
        securityHead: state.securityHead, dataGeneration: state.dataGeneration, action: 'profile.invite', approvalPolicyId: null, approvalPolicyRevision: null } } }, f.owner.bundle);
  const profileDigest = await digestObject(profile.profile.envelope); f.materials.push({ id: profile.profile.id, kind: 'encrypted_profile', value: profile.profile.envelope, digest: profileDigest });
  const binding: EnrolmentBinding = enrolmentBinding.parse({ version: 1, kind, origin, workspaceId: f.workspaceId, accountId, operationId,
    approvalAttemptId: randomUUID(), attemptGeneration: '1', invitationGeneration: '1', profile: { id: accountId, revision: '1', objectId: profile.profile.id, objectDigest: profileDigest },
    nextProfileRevision: '2', role: { id: role.id, revision: role.revision, permissions: role.permissions }, credentialGeneration: '0', nextCredentialGeneration: '1',
    sessionGeneration: '0', nextSessionGeneration: '1', recoveryGeneration: '0', nextRecoveryGeneration: owner ? '1' : '0', deviceKeyGeneration: '0', nextDeviceKeyGeneration: '1',
    ownershipVersion: state.ownershipVersion, nextOwnershipVersion: owner ? next(state.ownershipVersion) : state.ownershipVersion, securityVersion: state.securityVersion,
    nextSecurityVersion: next(state.securityVersion), securityHead: state.securityHead, genesisFingerprint: state.genesisFingerprint, dataGeneration: state.dataGeneration,
    custodyEpoch: state.custodyEpoch, workspaceKeyEpoch: state.workspaceKeyEpoch, authorizer, currentDevices: [],
    scopes: state.profiles[f.owner.accountId]!.scopes.map((scope) => { const { manifests, ...rest } = scope; return { ...rest,
      mode: owner ? 'custody' : 'content', keyEpoch: owner ? state.custodyEpoch : state.workspaceKeyEpoch, permissions: role.permissions,
      sources: manifests.map((entry) => ({ grantId: randomUUID(), generation: '1', manifestId: entry.id, manifestDigest: entry.digest })) }; }),
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 3600000).toISOString() });
  const exportKey = base64urlEncode(await randomKey()), phrase = owner ? await newOwnerPhrase() : undefined, positions = [1, 8, 20];
  const prepared = await prepareEnrolmentDraft({ mode: 'join', history: f.history, input: { binding, exportKey, displayName: 'Private confirmed account',
    configuration: { ...f.configuration, identifiers: { client: `ukda:${f.workspaceId}:${accountId}`, server: origin } }, registrationRecord: base64urlEncode(await randomKey()),
    ...(phrase ? { newOwnerKit: { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) } } : {}) } });
  const fingerprint = await digestObject(prepared.draft.transcript); prepared.draft.recipientConfirmation = await confirmEnrolmentTarget({ prepared, exportKey, history: f.history, fingerprint });
  const { registrationRecord: _record, ...draft } = prepared.draft;
  const approval = await prepareEnrolmentApproval({ draft, fingerprint, history: f.history, materials: f.materials }, f.owner.bundle);
  await append(f, approval.transition, binding.nextSecurityVersion);
  for (const object of approval.deliveries) f.materials.push({ id: object.id, kind: 'key_envelope', value: object.envelope, digest: await digestObject(object.envelope) });
  const bundle = await unwrapDeviceBundle(enrolmentDeviceContext(prepared.draft.transcript), prepared.deviceWrapper, exportKey);
  return { accountId, deviceId: prepared.draft.transcript.device.id, bundle, phrase };
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { actorAuthority, append, join, origin, ownerFixture, type Actor, type OwnerFixture } from './project-create-client-fixture.js';
import { base64urlDecode, base64urlEncode, decryptContent, digestObject, encryptContent, randomKey, recipientEnvelope, sealRecipient } from '../src/shared/crypto.js';
import { contentEnvelope } from '../src/shared/contracts.js';
import { createAccessBinding, deriveAccessPlan, type AccessRequest } from '../src/shared/access-change.js';
import { prepareAccessChange } from '../src/client/access-change-crypto.js';
import { prepareJoinInvitation, type PrepareJoinInvitationInput } from '../src/client/enrolment-controller.js';
import { readDeviceScopeKeyMaterial } from '../src/client/pairing.js';
import type { PairingMaterial, PairingScope } from '../src/shared/pairing.js';

function materialInput(f: OwnerFixture, materials = f.materials) {
  const source = f.state.profiles[f.owner.accountId]!.scopes.find(scope => scope.scope === 'workspace')!;
  const scope: PairingScope = { ...source, mode: 'content', keyEpoch: f.state.workspaceKeyEpoch,
    sources: source.manifests.map(ref => ({ grantId: randomUUID(), generation: '1', manifestId: ref.id, manifestDigest: ref.digest })) };
  return { scopes: [scope], materials, history: f.state, holder: { workspaceId: f.workspaceId, custodyEpoch: f.state.custodyEpoch,
    approverAccountId: f.owner.accountId, approverDevice: actorAuthority(f).device } };
}

async function forgedCustody(f: OwnerFixture, attacker: Actor) {
  const attackerDevice = f.state.devices[attacker.deviceId]!, manifestId = randomUUID(), custodyKey = await randomKey(), contentKey = await randomKey();
  const signing = base64urlDecode(attacker.bundle.signingPrivateKey, 64);
  try {
    const previous = contentEnvelope.parse(f.materials.find(item => item.id === f.state.custodyManifest.id)!.value);
    const manifest = await encryptContent({ ...previous.header, recordId: manifestId, accountId: attacker.accountId, deviceId: attacker.deviceId,
      keyGeneration: attackerDevice.keyGeneration, operationId: randomUUID(), securityVersion: f.state.securityVersion, securityHead: f.state.securityHead },
    { version: 1, custodyEpoch: f.state.custodyEpoch, workspaceKeys: [{ epoch: f.state.workspaceKeyEpoch, key: base64urlEncode(contentKey) }], projectKeys: [] }, custodyKey, signing);
    const manifestDigest = await digestObject(manifest);
    const original = recipientEnvelope.parse(f.materials.find(item => item.kind === 'key_envelope' &&
      recipientEnvelope.safeParse(item.value).success && recipientEnvelope.parse(item.value).header.recipientId === f.owner.deviceId)!.value);
    const delivery = await sealRecipient({ ...original.header, keyEpoch: f.state.custodyEpoch, senderAccountId: attacker.accountId,
      senderDeviceId: attacker.deviceId, senderKeyGeneration: attackerDevice.keyGeneration,
      securityVersion: f.state.securityVersion, securityHead: f.state.securityHead, ceremonyId: randomUUID() },
    { version: 1, mode: 'custody', custodyEpoch: f.state.custodyEpoch, custodyKey: base64urlEncode(custodyKey), manifest: { id: manifestId, digest: manifestDigest } }, signing);
    const injected: PairingMaterial[] = [{ id: randomUUID(), kind: 'key_envelope', value: delivery, digest: await digestObject(delivery) },
      { id: manifestId, kind: 'custody_manifest', value: manifest, digest: manifestDigest }];
    return { injected, contentKey: base64urlEncode(contentKey) };
  } finally { custodyKey.fill(0); contentKey.fill(0); signing.fill(0); }
}

async function suspend(f: OwnerFixture, target: Actor) {
  const request: AccessRequest = { workspaceId: f.workspaceId, operationId: randomUUID(), action: 'suspend', targetAccountId: target.accountId,
    desired: null, receiptTokenHash: await digestObject(randomUUID()) };
  const binding = createAccessBinding(request, f.state, actorAuthority(f), { issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600000).toISOString() });
  const payload = await prepareAccessChange({ request, context: { binding, plan: deriveAccessPlan(binding, f.state), materials: f.materials }, history: f.history }, f.owner.bundle);
  await append(f, payload.transition, binding.nextSecurityVersion);
  for (const item of [...(payload.custody ? [{ ...payload.custody, kind: 'custody_manifest' }] : []), ...payload.deliveries.map(value => ({ ...value, kind: 'key_envelope' }))])
    f.materials.push({ id: item.id, kind: item.kind, value: item.envelope, digest: await digestObject(item.envelope) });
}

function invitation(f: OwnerFixture, materials: PairingMaterial[]): PrepareJoinInvitationInput {
  const role = Object.values(f.state.roles).find(value => value.template === 'member')!, authorizer = actorAuthority(f);
  const request = { workspaceId: f.workspaceId, accountId: randomUUID(), operationId: randomUUID(), kind: 'join_member' as const, roleId: role.id, projectIds: [] };
  return { request, history: f.history, displayName: 'Confidential newly invited person', context: { workspaceId: request.workspaceId,
    accountId: request.accountId, operationId: request.operationId, kind: request.kind,
    role: { id: role.id, revision: role.revision, permissions: role.permissions }, authorizer,
    genesisFingerprint: f.state.genesisFingerprint, custodyEpoch: f.state.custodyEpoch, current: f.history.expected, materials,
    header: { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: f.workspaceId, scope: 'workspace', scopeId: f.workspaceId,
      recordId: request.accountId, recordType: 'profile', schema: 1, keyEpoch: f.state.workspaceKeyEpoch, revision: '1', operationId: request.operationId,
      accountId: f.owner.accountId, deviceId: f.owner.deviceId, keyGeneration: authorizer.device.keyGeneration, permissionVersion: role.revision,
      securityVersion: f.state.securityVersion, securityHead: f.state.securityHead, dataGeneration: f.state.dataGeneration,
      action: 'profile.invite', approvalPolicyId: null, approvalPolicyRevision: null } } };
}

for (const retired of [false, true]) test(`CP13: ${retired ? 'revoked' : 'ordinary'} signer cannot substitute custody to choose a new invitation encryption key`, async () => {
  const f = await ownerFixture(), attacker = await join(f);
  if (retired) await suspend(f, attacker);
  assert.equal(f.state.devices[attacker.deviceId]!.active, !retired);
  const legitimate = await readDeviceScopeKeyMaterial(materialInput(f), f.owner.bundle);
  const forged = await forgedCustody(f, attacker), materials = [...forged.injected, ...f.materials];
  assert.deepEqual(await readDeviceScopeKeyMaterial(materialInput(f, materials), f.owner.bundle), legitimate,
    'Unreferenced custody must not take precedence over the genuine signed delivery');
  const prepared = await prepareJoinInvitation(invitation(f, materials), f.owner.bundle), envelope = prepared.profile.envelope;
  const ring = legitimate[0] as { keys: { epoch: string; key: string }[] };
  const key = base64urlDecode(ring.keys.find(entry => entry.epoch === f.state.workspaceKeyEpoch)!.key), attackerKey = base64urlDecode(forged.contentKey);
  try {
    const plaintext = await decryptContent(envelope, key, base64urlDecode(f.owner.bundle.signingPublicKey), envelope.header) as { displayName: string };
    assert.equal(plaintext.displayName, 'Confidential newly invited person');
    await assert.rejects(decryptContent(envelope, attackerKey, base64urlDecode(f.owner.bundle.signingPublicKey), envelope.header));
  } finally { key.fill(0); attackerKey.fill(0); }
  const missing = materials.filter(item => !f.state.devices[f.owner.deviceId]!.scopes.some(scope => scope.manifests.some(ref => ref.id === item.id)) &&
    item.id !== f.state.genesisDeviceEnvelope?.id || item.id === f.state.custodyManifest.id);
  await assert.rejects(readDeviceScopeKeyMaterial(materialInput(f, missing), f.owner.bundle),
    'Genuine source manifest plus injected recipient ciphertext cannot replace the missing authorised device envelope');
});

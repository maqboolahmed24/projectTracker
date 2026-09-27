import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING } from '../src/client/opaque.js';
import { initialContentHeader, initialRecipientHeader, transcriptFromGenesis } from '../src/shared/activation.js';
import { base64urlDecode, base64urlEncode, canonicalJson, decryptContent, openRecipient, randomKey } from '../src/shared/crypto.js';
import { validateIdentityContent } from '../src/client/upgrade-content-crypto.js';
import { transformContentData1To2 } from '../src/shared/content-schema.js';
import type { AvatarSelection } from '../src/shared/avatar.js';

async function setupInput(): Promise<Parameters<typeof prepareOwnerActivation>[0]> {
  const workspaceId = randomUUID(), accountId = randomUUID(), origin = 'https://ukda.example', phrase = await newOwnerPhrase();
  const positions = [1, 8, 20];
  return { binding: { activationId: randomUUID(), operationId: randomUUID(), workspaceId, accountId,
    reservationGeneration: '1', draftGeneration: '1', origin },
  configuration: { configId: OPAQUE_CONFIG_ID, keyStretching: OPAQUE_KEY_STRETCHING, setupId: 'avatar-activation',
    serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } },
  registrationRecord: base64urlEncode(await randomKey()), exportKey: base64urlEncode(await randomKey()), phrase,
  challengePositions: positions, challengeAnswers: positions.map(position => phrase.split(' ')[position]!),
  displayName: 'Private Avatar Owner', workspaceName: 'Private Avatar Workspace' };
}

async function readProfile(input: Awaited<ReturnType<typeof setupInput>>, prepared: Awaited<ReturnType<typeof prepareOwnerActivation>>) {
  const transcript = transcriptFromGenesis(prepared.payload.genesis.body), objects = prepared.payload.objects;
  const bundle = await unwrapDeviceBundle({ workspaceId: input.binding.workspaceId, accountId: input.binding.accountId,
    deviceId: transcript.device.id, credentialGeneration: '1' }, prepared.deviceWrapper, input.exportKey);
  const signer = base64urlDecode(bundle.signingPublicKey, 32), recipient = base64urlDecode(bundle.recipientPrivateKey, 32);
  let custodyKey: Uint8Array | undefined, workspaceKey: Uint8Array | undefined;
  try {
    const custody = await openRecipient(objects.deviceCustody, recipient, signer,
      initialRecipientHeader(transcript, prepared.payload.genesis.body.transcriptDigest, 'device')) as { custodyKey: string };
    custodyKey = base64urlDecode(custody.custodyKey, 32);
    const manifest = await decryptContent(objects.custody, custodyKey, signer, initialContentHeader(transcript, 'custody')) as { workspaceKeys: { key: string }[] };
    workspaceKey = base64urlDecode(manifest.workspaceKeys[0]!.key, 32);
    return await decryptContent(objects.profile, workspaceKey, signer, initialContentHeader(transcript, 'profile'));
  } finally { recipient.fill(0); custodyKey?.fill(0); workspaceKey?.fill(0); }
}

test('avatar: first Owner selection is authenticated encrypted profile content and never public metadata', async () => {
  const input = await setupInput(), avatar = { shapeId: 'shape-20', colourId: 'violet' } as const;
  const prepared = await prepareOwnerActivation({ ...input, avatar });
  assert.equal(canonicalJson(await readProfile(input, prepared)), canonicalJson({ displayName: input.displayName, avatar }));
  const uploaded = JSON.stringify(prepared.payload), persisted = JSON.stringify({ payload: prepared.payload, wrapper: prepared.deviceWrapper });
  for (const privateValue of [input.displayName, avatar.shapeId, `"colourId":"${avatar.colourId}"`]) {
    assert.equal(uploaded.includes(privateValue), false); assert.equal(persisted.includes(privateValue), false);
  }
  const changed = structuredClone(prepared);
  const ciphertext = base64urlDecode(changed.payload.objects.profile.ciphertext); ciphertext[0] = ciphertext[0]! ^ 1;
  changed.payload.objects.profile.ciphertext = base64urlEncode(ciphertext);
  await assert.rejects(readProfile(input, changed));
});

test('avatar: first Owner rejects invalid selections and retains legacy absence', async () => {
  const input = await setupInput();
  for (const avatar of [null, { shapeId: 'shape-21', colourId: 'teal' }, { shapeId: 'shape-01', colourId: '#ffffff' },
    { shapeId: 'shape-01', colourId: 'teal', url: 'https://example.test/photo.svg' }]) {
    await assert.rejects(prepareOwnerActivation({ ...input, avatar: avatar as unknown as AvatarSelection }));
  }
  const prepared = await prepareOwnerActivation(input);
  assert.equal(canonicalJson(await readProfile(input, prepared)), canonicalJson({ displayName: input.displayName }));
});

test('avatar: identity representation upgrades preserve selected and legacy profiles exactly', () => {
  for (const profile of [{ displayName: 'Legacy person' }, { displayName: 'Selected person', avatar: { shapeId: 'shape-07', colourId: 'coral' } }]) {
    const before = JSON.stringify(profile);
    const transformed = transformContentData1To2('profile', profile, value => validateIdentityContent('profile', value));
    assert.deepEqual(transformed.data, profile); assert.equal(JSON.stringify(profile), before);
  }
  assert.throws(() => validateIdentityContent('profile', { displayName: 'Invalid person', avatar: { shapeId: 'unknown', colourId: 'teal' } }));
});

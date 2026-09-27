import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test, { type TestContext } from 'node:test';
import { base64urlEncode, generateRecipientKeyPair, generateSigningKeyPair, signObject, verifyObject } from '../src/shared/crypto.js';
import { inboxBinding, inboxCommand, inboxListRequest, validateInboxMutation, type InboxBinding, type InboxCommand } from '../src/shared/inbox.js';
import { prepareInbox } from '../src/client/inbox-crypto.js';

async function fixture(t: TestContext) {
  const signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  t.after(() => { signing.privateKey.fill(0); recipient.privateKey.fill(0); });
  const bundle = { signingPrivateKey: base64urlEncode(signing.privateKey), signingPublicKey: base64urlEncode(signing.publicKey),
    recipientPrivateKey: base64urlEncode(recipient.privateKey), recipientPublicKey: base64urlEncode(recipient.publicKey) };
  const binding: InboxBinding = inboxBinding.parse({ version: 1, workspaceId: randomUUID(), operationId: randomUUID(), origin: 'https://workspace.example.test',
    accountId: randomUUID(), deviceId: randomUUID(), signingPublicKey: bundle.signingPublicKey, keyGeneration: '1', credentialGeneration: '1',
    sessionGeneration: '1', dataGeneration: '1', securityHead: 'a'.repeat(64), securityVersion: '1',
    issuedAt: '2026-09-26T12:00:00.000Z', expiresAt: '2026-09-26T12:10:00.000Z' });
  return { signing, bundle, binding };
}

test('CP09 Inbox crypto: signed read flags and project mute use a distinct purpose and contain only permitted preferences', async t => {
  const f = await fixture(t), commands: InboxCommand[] = [
    { action: 'set_read', records: [{ id: randomUUID(), expectedRevision: '1' }], read: true },
    { action: 'set_project_muted', projectId: randomUUID(), expectedRevision: '0', muted: true },
  ];
  for (const command of commands) {
    const input = { binding: { ...f.binding, operationId: randomUUID() }, command }, original = structuredClone(input),
      mutation = await prepareInbox(input, f.bundle);
    assert.deepEqual(await validateInboxMutation(mutation), mutation);
    assert.deepEqual(mutation.body, { purpose: 'ukda.inbox.v1', ...original });
    assert.deepEqual(input, original);
    assert.equal(await verifyObject(mutation, f.signing.publicKey, 'ukda.inbox.v1'), true);
    for (const purpose of ['ukda.collaboration.v1', 'ukda.planning.v1', 'ukda.security-transition.v1'])
      assert.equal(await verifyObject(mutation, f.signing.publicKey, purpose), false);
    assert.equal(JSON.stringify(mutation).includes(f.bundle.signingPrivateKey), false);
    assert.equal(JSON.stringify(mutation).includes(f.bundle.recipientPrivateKey), false);
  }
});

test('CP09 Inbox crypto: wrong signer and changes to actor, operation, security scope or target invalidate the signature', async t => {
  const f = await fixture(t), other = await fixture(t), command: InboxCommand = { action: 'set_project_muted', projectId: randomUUID(), expectedRevision: '0', muted: true },
    original = await prepareInbox({ binding: f.binding, command }, f.bundle);
  await assert.rejects(prepareInbox({ binding: f.binding, command }, other.bundle), /Inbox signer mismatch/);
  await assert.rejects(prepareInbox({ binding: f.binding, command }, { ...f.bundle, signingPrivateKey: other.bundle.signingPrivateKey }));
  for (const patch of [{ workspaceId: randomUUID() }, { accountId: randomUUID() }, { deviceId: randomUUID() }, { operationId: randomUUID() },
    { credentialGeneration: '2' }, { dataGeneration: '2' }, { securityHead: 'b'.repeat(64) }, { signingPublicKey: other.bundle.signingPublicKey }]) {
    await assert.rejects(validateInboxMutation({ ...original, body: { ...original.body, binding: { ...original.body.binding, ...patch } } }));
  }
  for (const patch of [{ projectId: randomUUID() }, { expectedRevision: '1' }, { muted: false }])
    await assert.rejects(validateInboxMutation({ ...original, body: { ...original.body, command: { ...command, ...patch } } }));
  const wrongPurpose = await signObject({ ...original.body, purpose: 'ukda.collaboration.v1' }, f.signing.privateKey);
  await assert.rejects(validateInboxMutation(wrongPurpose));
});

test('CP09 Inbox crypto: signed lifetime is bounded even with a genuine device signature', async t => {
  const f = await fixture(t), command: InboxCommand = { action: 'set_read', records: [{ id: randomUUID(), expectedRevision: '1' }], read: false };
  for (const expiresAt of [f.binding.issuedAt, '2026-09-26T11:59:59.000Z', '2026-09-26T12:10:00.001Z']) {
    const value = await signObject({ purpose: 'ukda.inbox.v1' as const, binding: { ...f.binding, expiresAt }, command }, f.signing.privateKey);
    await assert.rejects(validateInboxMutation(value), /Invalid Inbox change/);
  }
  // Wall-clock freshness/current authority is checked by the Worker and service;
  // the shared verifier authenticates the retained historical signed preference.
  const value = await prepareInbox({ binding: f.binding, command }, f.bundle);
  assert.equal((await validateInboxMutation(value)).body.binding.expiresAt, f.binding.expiresAt);
});

test('CP09 Inbox crypto: strict schemas bound batches, reject duplicate targets and prevent arbitrary content signing', async t => {
  const f = await fixture(t), records = Array.from({ length: 100 }, () => ({ id: randomUUID(), expectedRevision: '1' })),
    command = { action: 'set_read' as const, records, read: true };
  assert.equal(inboxCommand.safeParse(command).success, true);
  for (const invalid of [{ ...command, records: [] }, { ...command, records: [...records, { id: randomUUID(), expectedRevision: '1' }] },
    { ...command, records: [records[0], records[0]] }, { ...command, records: [{ ...records[0], expectedRevision: '0' }] },
    { ...command, text: 'Private project content' }, { ...command, action: 'send_email' }]) {
    assert.equal(inboxCommand.safeParse(invalid).success, false);
    await assert.rejects(prepareInbox({ binding: f.binding, command: invalid as InboxCommand }, f.bundle));
  }
  assert.equal(inboxCommand.safeParse({ action: 'set_project_muted', projectId: randomUUID(), expectedRevision: '-1', muted: true }).success, false);
  assert.equal(inboxBinding.safeParse({ ...f.binding, text: 'Unrelated private content' }).success, false);
  for (const limit of [0, 101]) assert.equal(inboxListRequest.safeParse({ workspaceId: f.binding.workspaceId, limit }).success, false);
});

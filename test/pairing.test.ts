import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { createDatabases, transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { PairingService } from '../src/modules/identity/pairing.js';
import { SessionService } from '../src/modules/identity/sessions.js';
import { ServiceSecrets } from '../src/modules/identity/secrets.js';
import { initializeAccessAuthority } from '../src/modules/identity/access-projection.js';
import { initialContentHeader, initialRecipientHeader, activationManifest, type ActivationTranscript } from '../src/shared/activation.js';
import { capabilities } from '../src/shared/contracts.js';
import { base64urlEncode, canonicalJson, digestObject, encryptContent, generateRecipientKeyPair, generateSigningKeyPair, openRecipient, randomKey, sealRecipient, signObject } from '../src/shared/crypto.js';
import { pairingConfirmationFor, pairingRecipientHeader, type PairingApproval, type PairingView } from '../src/shared/pairing.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';

const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;
async function fixture(t: TestContext) {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const appUrl = process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ?? local.ADMIN_DATABASE_URL;
  const controlUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(appUrl && controlUrl, 'Pairing tests require explicit fixture admin credentials');
  const admin = { application: new pg.Pool({ connectionString: appUrl }), control: new pg.Pool({ connectionString: controlUrl }) };
  const db = createDatabases(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }));
  const origin = 'https://pairing.example', workspaceId = randomUUID(), accountId = randomUUID(), deviceId = randomUUID(), licenceId = randomUUID();
  const operationId = randomUUID(), signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  const recoverySigning = await generateSigningKeyPair(), recoveryRecipient = await generateRecipientKeyPair();
  const workspaceKey = await randomKey(), custodyKey = await randomKey();
  let now = new Date();
  const secrets = new ServiceSecrets({ SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'pairing-test' });
  const sessions = new SessionService({ databases: db, secrets, origin, now: () => new Date(now) });
  const pairing = new PairingService({ databases: db, sessions, origin, now: () => new Date(now) });
  const setup: ActivationTranscript = { version: 1, purpose: 'ukda.activation-transcript.v1', origin, workspaceId, accountId, operationId,
    activationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1',
    device: { id: deviceId, signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) },
    recovery: { id: randomUUID(), signingPublicKey: base64urlEncode(recoverySigning.publicKey), recipientPublicKey: base64urlEncode(recoveryRecipient.publicKey) },
    genesisId: randomUUID(), custodyId: randomUUID(), deviceEnvelopeId: randomUUID(), recoveryEnvelopeId: randomUUID(),
    roles: { owner: randomUUID(), manager: randomUUID(), member: randomUUID(), viewer: randomUUID() },
    opaque: { configId: 'ukda.opaque.ristretto255.argon2id-m64-t3-p4.v1', setupId: 'fixture', serverStaticPublicKey: base64urlEncode(randomBytes(32)), identifiers: { client: accountId, server: origin }, keyStretching: 'memory-constrained' },
    registrationDigest: await digestObject('fixture'), ownerPermissions: [...capabilities] };
  const transcriptDigest = await digestObject(setup);
  const objects = {
    workspace: await encryptContent(initialContentHeader(setup, 'workspace'), { name: 'Fixture' }, workspaceKey, signing.privateKey),
    profile: await encryptContent(initialContentHeader(setup, 'profile'), { name: 'Owner' }, workspaceKey, signing.privateKey),
    custody: await encryptContent(initialContentHeader(setup, 'custody'), { version: 1, custodyEpoch: '1', workspaceKeys: [{ epoch: '1', key: base64urlEncode(workspaceKey) }], projectKeys: [] }, custodyKey, signing.privateKey),
    deviceCustody: await sealRecipient(initialRecipientHeader(setup, transcriptDigest, 'device'), { version: 1, custodyEpoch: '1', custodyKey: base64urlEncode(custodyKey) }, signing.privateKey),
    recoveryCustody: await sealRecipient(initialRecipientHeader(setup, transcriptDigest, 'recovery'), { version: 1, custodyEpoch: '1', custodyKey: base64urlEncode(custodyKey) }, signing.privateKey),
  };
  const manifests = await activationManifest(setup, objects);
  const { purpose: _purpose, ...setupBody } = setup;
  const genesis = await signObject({ ...setupBody, purpose: 'ukda.genesis.v1' as const, transcriptDigest, manifest: manifests.map(({ value: _value, ...entry }) => entry) }, signing.privateKey);
  const genesisFingerprint = await digestObject(genesis);
  const ownerGrantId = randomUUID(), deviceGrantId = randomUUID();
  t.after(async () => {
    try {
      await admin.application.query('SELECT graphile_worker.remove_job($1)', [`activation:${workspaceId}`]);
      await transaction(admin.application, async (client) => { for (const table of ['profiles', 'roles', 'workspaces']) await client.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [workspaceId]); });
      await admin.control.query('DELETE FROM security.ceremonies WHERE workspace_id=$1', [workspaceId]);
      await admin.control.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
      await admin.control.query('DELETE FROM security.licences WHERE licence_id=$1', [licenceId]);
    } finally { await Promise.allSettled([db.close(), admin.application.end(), admin.control.end()]); }
  });
  await transaction(admin.control, async (client) => {
    await client.query("INSERT INTO security.licences(licence_id,verification_digest,verification_key_id) VALUES($1,$2,'fixture')", [licenceId, randomBytes(32)]);
    await client.query("INSERT INTO security.workspaces(workspace_id,licence_id,lifecycle,security_head,security_version,ownership_version,custody_epoch,activated_at) VALUES($1,$2,'active',$3,1,1,1,$4)", [workspaceId, licenceId, genesisFingerprint, now]);
    await client.query("INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition) VALUES($1,1,$2,repeat('0',64),$3,'workspace.activate','device',$4,$5,$6)", [workspaceId, operationId, genesisFingerprint, accountId, deviceId, genesis]);
    for (const object of [{ id: setup.genesisId, kind: 'genesis', digest: genesisFingerprint, value: genesis }, ...manifests]) {
      await client.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
        VALUES($1,$2,$3,$4,$5,$6,'committed',1)`, [workspaceId, object.id, object.kind, object.digest, object.value, operationId]);
    }
    await initializeAccessAuthority(client, genesis.body);
    await client.query('UPDATE security.workspaces SET genesis_object_id=$2,current_custody_manifest_object_id=$3 WHERE workspace_id=$1', [workspaceId, setup.genesisId, setup.custodyId]);
    await client.query(`INSERT INTO security.profiles(workspace_id,profile_id,state,is_owner,owner_ready_at,profile_object_id,credential_generation,opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers)
      VALUES($1,$2,'active',true,$3,$2,1,'AA','fixture','fixture','{}')`, [workspaceId, accountId, now]);
    await client.query(`INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approval_security_version,approved_at)
      VALUES($1,$2,$3,1,$4,$5,'active',1,$6)`, [workspaceId, deviceId, accountId, signing.publicKey, recipient.publicKey, now]);
    for (const [id, kind, device] of [[ownerGrantId, 'owner', null], [deviceGrantId, 'device', deviceId]]) await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,activated_at)
      VALUES($1,$2,$3,$4,$5,'workspace',1,$6,'active',$7,$8,1,1,$9)`, [workspaceId, id, accountId, device, kind, [...capabilities], setup.genesisId, setup.custodyId, now]);
  });
  const issue = (approved = false, profileId = accountId, approvedDevice = deviceId) => transaction(db.control, (client) => sessions.issue(client, {
    workspaceId, profileId, credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1',
    accessLevel: approved ? 'device_approved' : 'restricted', ...(approved ? { deviceId: approvedDevice } : {}) }, now));
  const existing = await issue(true), fresh = await issue();
  async function start() {
    const newSigning = await generateSigningKeyPair(), newRecipient = await generateRecipientKeyPair();
    const request = { operationId: randomUUID(), device: { id: randomUUID(), keyGeneration: '1', signingPublicKey: base64urlEncode(newSigning.publicKey), recipientPublicKey: base64urlEncode(newRecipient.publicKey) }, localBundleDigest: await digestObject({ verifiedLocalWrapper: randomUUID() }) };
    await pairing.begin(fresh.cookieValue, fresh.csrfToken, request);
    const view = await pairing.claim(existing.cookieValue, existing.csrfToken, request.operationId);
    return { request, view, newSigning, newRecipient };
  }
  async function confirm(pending: Awaited<ReturnType<typeof start>>) {
    const transcript = pending.view.transcript!, hash = pending.view.transcriptDigest!;
    await pairing.confirm(fresh.cookieValue, fresh.csrfToken, await signObject(pairingConfirmationFor(transcript, hash, 'recipient'), pending.newSigning.privateKey));
    return pairing.confirm(existing.cookieValue, existing.csrfToken, await signObject(pairingConfirmationFor(transcript, hash, 'approver'), signing.privateKey));
  }
  async function approval(view: PairingView): Promise<PairingApproval> {
    const transcript = view.transcript!, hash = view.transcriptDigest!;
    const deliveries = await Promise.all(transcript.scopes.map(async (scope) => ({ id: randomUUID(), envelope: await sealRecipient(pairingRecipientHeader(transcript, hash, scope),
      scope.mode === 'custody' ? { version: 1, mode: 'custody', custodyEpoch: transcript.custodyEpoch, custodyKey: base64urlEncode(custodyKey), manifest: { id: setup.custodyId, digest: await digestObject(objects.custody) } } : { version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, keys: [{ epoch: '1', key: base64urlEncode(workspaceKey) }] }, signing.privateKey) })));
    const grant = await signObject({ version: 1 as const, purpose: 'ukda.device-pair-grant.v1' as const, operationId: transcript.operationId,
      workspaceId, grantId: transcript.operationId, securityVersion: String(BigInt(transcript.securityVersion) + 1n), previousHead: transcript.securityHead,
      transcript, transcriptDigest: hash, recipientConfirmation: view.recipientConfirmation!, approverConfirmation: view.approverConfirmation!,
      deliveries: await Promise.all(deliveries.map(async (delivery, index) => ({ id: delivery.id, scope: transcript.scopes[index]!.scope, scopeId: transcript.scopes[index]!.scopeId, digest: await digestObject(delivery.envelope) }))) }, signing.privateKey);
    return { grant, deliveries };
  }
  return { db, admin, sessions, pairing, issue, existing, fresh, start, confirm, approval, setup, genesis, genesisFingerprint, origin, signing, workspaceKey,
    workspaceId, accountId, deviceId, ownerGrantId, deviceGrantId, now: () => new Date(now), advance: (ms: number) => { now = new Date(now.getTime() + ms); } };
}

test('CP04: both full transcript confirmations activate one device; private delivery needs fresh device proof and is repeatable', async (t) => {
  const f = await fixture(t), pending = await f.start();
  assert.equal(pending.view.transcript?.genesisFingerprint, f.genesisFingerprint);
  assert.equal(pending.view.transcript?.approverDevice.id, f.deviceId);
  assert.equal(pending.view.transcript?.device.id, pending.request.device.id);
  await assert.rejects(f.pairing.materials(f.fresh.cookieValue, pending.request.operationId), code('DEVICE_APPROVAL_REQUIRED'));
  const materials = await f.pairing.materials(f.existing.cookieValue, pending.request.operationId);
  assert.ok(materials.some((item) => item.id === f.setup.custodyId)); assert.ok(materials.some((item) => item.id === f.setup.deviceEnvelopeId));
  const confirmed = await f.confirm(pending), approval = await f.approval(confirmed);
  await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, approval);
  await assert.rejects(f.sessions.beginDeviceChallenge(f.fresh.cookieValue, f.fresh.csrfToken, pending.request.device.id), code('DEVICE_APPROVAL_REQUIRED'));
  const committed = await f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, pending.request.operationId);
  assert.equal(committed.projection.state, 'ready'); assert.equal(committed.receipt.securityVersion, '2');
  assert.equal((await f.sessions.authenticate(f.fresh.cookieValue)).accessLevel, 'restricted');
  await assert.rejects(f.pairing.delivery(f.fresh.cookieValue, pending.request.operationId), code('DEVICE_APPROVAL_REQUIRED'));
  const challenge = await f.sessions.beginDeviceChallenge(f.fresh.cookieValue, f.fresh.csrfToken, pending.request.device.id);
  const approved = await f.sessions.completeDeviceChallenge(f.fresh.cookieValue, f.fresh.csrfToken, await signObject(challenge, pending.newSigning.privateKey));
  const delivery = await f.pairing.delivery(approved.cookieValue, pending.request.operationId);
  assert.equal(canonicalJson(delivery), canonicalJson(await f.pairing.delivery(approved.cookieValue, pending.request.operationId)));
  const decrypted = await openRecipient(delivery.deliveries[0]!.envelope, pending.newRecipient.privateKey, f.signing.publicKey,
    pairingRecipientHeader(pending.view.transcript!, pending.view.transcriptDigest!, pending.view.transcript!.scopes[0]!)) as { mode: string };
  assert.equal(decrypted.mode, 'custody');
  const history = await verifySecurityHistory({ workspaceId: f.workspaceId, origin: f.origin, genesisFingerprint: f.genesisFingerprint,
    genesis: f.genesis, transitions: [committed.receipt.grant], expected: { securityHead: committed.receipt.securityHead, securityVersion: '2' } });
  assert.equal(history.devices[pending.request.device.id]?.active, true);
  await assert.rejects(f.pairing.confirm(approved.cookieValue, approved.csrfToken, confirmed.recipientConfirmation), code('PAIRING_INVALID'));
});

test('CP04: operation resume and lost-response replay keep the same grant and immutable delivery', async (t) => {
  const f = await fixture(t), pending = await f.start();
  const again = await f.issue();
  assert.equal((await f.pairing.begin(again.cookieValue, again.csrfToken, pending.request)).operationId, pending.request.operationId);
  await assert.rejects(f.pairing.begin(again.cookieValue, again.csrfToken, { ...pending.request, operationId: f.setup.operationId }), code('OPERATION_CONFLICT'));
  const changed = { ...pending.request, localBundleDigest: 'b'.repeat(64) };
  await assert.rejects(f.pairing.begin(again.cookieValue, again.csrfToken, changed), code('OPERATION_CONFLICT'));
  const confirmed = await f.confirm(pending), approval = await f.approval(confirmed);
  await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, approval);
  await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, approval);
  const first = await f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, pending.request.operationId);
  const replay = await f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, pending.request.operationId);
  assert.equal(canonicalJson(first.receipt), canonicalJson(replay.receipt));
  const inspection = await f.pairing.inspect(again.cookieValue, pending.request.operationId);
  assert.equal(inspection.state, 'completed'); assert.equal(inspection.receipt?.deviceId, pending.request.device.id);
  const counts = await f.admin.control.query('SELECT (SELECT count(*) FROM security.security_transitions WHERE workspace_id=$1) AS transitions,(SELECT count(*) FROM security.operation_receipts WHERE workspace_id=$1) AS receipts', [f.workspaceId]);
  assert.deepEqual(counts.rows[0], { transitions: '2', receipts: '1' });
});

test('CP04: failed transcript proof is consumed; missing peer confirmation and tampered envelopes cannot commit', async (t) => {
  const f = await fixture(t), wrong = await f.start();
  await assert.rejects(f.pairing.confirm(f.fresh.cookieValue, f.fresh.csrfToken,
    await signObject({ ...pairingConfirmationFor(wrong.view.transcript!, wrong.view.transcriptDigest!, 'recipient'), transcriptDigest: 'a'.repeat(64) }, wrong.newSigning.privateKey)), code('PAIRING_INVALID'));
  assert.equal((await f.pairing.inspect(f.fresh.cookieValue, wrong.request.operationId)).state, 'cancelled');
  await assert.rejects(f.pairing.confirm(f.fresh.cookieValue, f.fresh.csrfToken,
    await signObject(pairingConfirmationFor(wrong.view.transcript!, wrong.view.transcriptDigest!, 'recipient'), wrong.newSigning.privateKey)), code('PAIRING_INVALID'));
  const pending = await f.start(), confirmed = await f.confirm(pending), approval = await f.approval(confirmed);
  const unconfirmed = await f.start();
  const forged = structuredClone(approval); forged.grant.body.operationId = unconfirmed.request.operationId;
  await assert.rejects(f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, forged), code('PAIRING_FORBIDDEN'));
  const tampered = structuredClone(approval); tampered.deliveries[0]!.envelope.header.recipientId = randomUUID();
  await assert.rejects(f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, tampered), code('PAIRING_INVALID'));
  await assert.rejects(f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, pending.request.operationId), code('PAIRING_INVALID'));
  assert.equal((await f.admin.control.query('SELECT state FROM security.devices WHERE workspace_id=$1 AND device_id=$2', [f.workspaceId, pending.request.device.id])).rows[0]?.state, 'pending');
});

test('CP04: current security head, grant and approver revocation are rechecked before pairing commits', async (t) => {
  const f = await fixture(t), first = await f.start(), stale = await f.start();
  const a = await f.approval(await f.confirm(first)), b = await f.approval(await f.confirm(stale));
  await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, a);
  await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, b);
  await f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, first.request.operationId);
  await assert.rejects(f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, stale.request.operationId), code('PAIRING_INVALID'));
  const revoked = await f.start(), c = await f.approval(await f.confirm(revoked));
  await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, c);
  await f.admin.control.query("UPDATE security.grants SET state='revoked',revoked_at=now() WHERE workspace_id=$1 AND grant_id=$2", [f.workspaceId, f.deviceGrantId]);
  await assert.rejects(f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, revoked.request.operationId), code('DEVICE_APPROVAL_REQUIRED'));
  assert.equal((await f.admin.control.query('SELECT state FROM security.devices WHERE workspace_id=$1 AND device_id=$2', [f.workspaceId, revoked.request.device.id])).rows[0]?.state, 'pending');
});

test('CP04: restricted entitlement preserves approved replacement while expiry and scope changes reject it', async (t) => {
  const f = await fixture(t);
  await f.admin.control.query("UPDATE security.workspaces SET licence_state='restricted' WHERE workspace_id=$1", [f.workspaceId]);
  const pending = await f.start(), approval = await f.approval(await f.confirm(pending));
  await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, approval);
  assert.equal((await f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, pending.request.operationId)).receipt.securityVersion, '2');
  const changed = await f.start(), staged = await f.approval(await f.confirm(changed));
  await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, staged);
  await f.admin.control.query("UPDATE security.grants SET permissions=ARRAY['read_project'] WHERE workspace_id=$1 AND grant_id=$2", [f.workspaceId, f.ownerGrantId]);
  await assert.rejects(f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, changed.request.operationId), code('PAIRING_INVALID'));
  const expired = await f.start(); f.advance(600_000);
  assert.equal((await f.pairing.inspect(f.fresh.cookieValue, expired.request.operationId)).state, 'expired');
  await assert.rejects(f.pairing.confirm(f.fresh.cookieValue, f.fresh.csrfToken, await signObject(pairingConfirmationFor(expired.view.transcript!, expired.view.transcriptDigest!, 'recipient'), expired.newSigning.privateKey)), code('PAIRING_INVALID'));
});

test('CP04: any active Owner can pair an existing member; an ordinary member cannot approve another account', async (t) => {
  const f = await fixture(t), memberId = randomUUID(), oldDeviceId = randomUUID(), envelopeId = randomUUID(), grantId = randomUUID();
  const oldSigning = await generateSigningKeyPair(), oldRecipient = await generateRecipientKeyPair();
  const memberProfile = await encryptContent({ ...initialContentHeader(f.setup, 'profile'), recordId: memberId }, { name: 'Existing member' }, f.workspaceKey, f.signing.privateKey);
  const memberEnvelope = await sealRecipient({ ...initialRecipientHeader(f.setup, await digestObject(f.setup), 'device'), recipientAccountId: memberId,
    recipientId: oldDeviceId, recipientPublicKey: base64urlEncode(oldRecipient.publicKey) },
    { version: 1, mode: 'content', scope: 'workspace', scopeId: f.workspaceId, keyEpoch: '1', keys: [{ epoch: '1', key: base64urlEncode(f.workspaceKey) }] }, f.signing.privateKey);
  // Pre-existing member authority fixture; profile invitations are exercised by CP6.
  await transaction(f.admin.control, async (client) => {
    for (const [id, kind, value] of [[memberId, 'encrypted_profile', memberProfile], [envelopeId, 'key_envelope', memberEnvelope]] as const) await client.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
      VALUES($1,$2,$3,$4,$5,$6,'committed',1)`, [f.workspaceId, id, kind, await digestObject(value), value, randomUUID()]);
    await client.query(`INSERT INTO security.profiles(workspace_id,profile_id,state,profile_object_id,credential_generation,opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers)
      VALUES($1,$2,'active',$2,1,'AA','fixture','fixture','{}')`, [f.workspaceId, memberId]);
    await client.query(`INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approval_security_version,approved_at)
      VALUES($1,$2,$3,1,$4,$5,'active',1,$6)`, [f.workspaceId, oldDeviceId, memberId, oldSigning.publicKey, oldRecipient.publicKey, f.now()]);
    await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,activated_at)
      VALUES($1,$2,$3,$4,'device','workspace',1,ARRAY['read_project'],'active',$5,$6,1,1,$7)`, [f.workspaceId, grantId, memberId, oldDeviceId, f.setup.genesisId, envelopeId, f.now()]);
    await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,activated_at)
      VALUES($1,$2,$3,'membership','workspace',1,ARRAY['read_project'],'active',$4,$5,1,1,$6)`, [f.workspaceId, randomUUID(), memberId, f.setup.genesisId, envelopeId, f.now()]);
  });
  const ordinaryApproved = await f.issue(true, memberId, oldDeviceId), ownPending = await f.start();
  await assert.rejects(f.pairing.claim(ordinaryApproved.cookieValue, ordinaryApproved.csrfToken, ownPending.request.operationId), code('PAIRING_FORBIDDEN'));
  const fresh = await f.issue(false, memberId), signing = await generateSigningKeyPair(), recipient = await generateRecipientKeyPair();
  const request = { operationId: randomUUID(), device: { id: randomUUID(), keyGeneration: '1', signingPublicKey: base64urlEncode(signing.publicKey), recipientPublicKey: base64urlEncode(recipient.publicKey) }, localBundleDigest: 'd'.repeat(64) };
  await f.pairing.begin(fresh.cookieValue, fresh.csrfToken, request);
  const view = await f.pairing.claim(f.existing.cookieValue, f.existing.csrfToken, request.operationId);
  assert.equal(view.transcript?.accountId, memberId); assert.equal(view.transcript?.scopes[0]?.mode, 'content');
  assert.deepEqual(view.transcript?.scopes[0]?.permissions, ['read_project']);
  const materials = await f.pairing.materials(f.existing.cookieValue, request.operationId);
  assert.ok(materials.some((material) => material.id === f.setup.custodyId), 'Owner needs current custody ciphertext to rewrap member content keys');
  await f.pairing.confirm(fresh.cookieValue, fresh.csrfToken, await signObject(pairingConfirmationFor(view.transcript!, view.transcriptDigest!, 'recipient'), signing.privateKey));
  const confirmed = await f.pairing.confirm(f.existing.cookieValue, f.existing.csrfToken, await signObject(pairingConfirmationFor(view.transcript!, view.transcriptDigest!, 'approver'), f.signing.privateKey));
  await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, await f.approval(confirmed));
  await f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, request.operationId);
  const challenge = await f.sessions.beginDeviceChallenge(fresh.cookieValue, fresh.csrfToken, request.device.id);
  const approved = await f.sessions.completeDeviceChallenge(fresh.cookieValue, fresh.csrfToken, await signObject(challenge, signing.privateKey));
  const delivery = await f.pairing.delivery(approved.cookieValue, request.operationId);
  assert.equal(delivery.materials.some((material) => material.kind === 'custody_manifest'), false);
  const value = await openRecipient(delivery.deliveries[0]!.envelope, recipient.privateKey, f.signing.publicKey,
    pairingRecipientHeader(view.transcript!, view.transcriptDigest!, view.transcript!.scopes[0]!)) as { mode: string; keys: unknown[] };
  assert.equal(value.mode, 'content'); assert.equal(value.keys.length, 1);
});

test('CP04: pairing preserves finite grant expiry and empty CSRF never bypasses session validation', async (t) => {
  const f = await fixture(t), expiresAt = new Date(f.now().getTime() + 60_000);
  await f.admin.control.query('UPDATE security.grants SET expires_at=$3 WHERE workspace_id=$1 AND grant_id=$2', [f.workspaceId, f.ownerGrantId, expiresAt]);
  const pending = await f.start(); assert.equal(pending.view.transcript?.scopes[0]?.expiresAt, expiresAt.toISOString());
  await assert.rejects(f.pairing.claim(f.existing.cookieValue, '', pending.request.operationId), code('CSRF_INVALID'));
  const approval = await f.approval(await f.confirm(pending));
  await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, approval);
  await f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, pending.request.operationId);
  const row = (await f.admin.control.query('SELECT expires_at FROM security.grants WHERE workspace_id=$1 AND grant_id=$2', [f.workspaceId, pending.request.operationId])).rows[0];
  assert.equal(row?.expires_at.toISOString(), expiresAt.toISOString());
  f.advance(60_000);
  await assert.rejects(f.sessions.beginDeviceChallenge(f.fresh.cookieValue, f.fresh.csrfToken, pending.request.device.id), code('DEVICE_APPROVAL_REQUIRED'));
});

test('CP06: same-account pairing intersects personal scopes with the approving device and explicit delivered epochs', async (t) => {
  const f = await fixture(t), projectId = randomUUID(), missingDeviceProjectId = randomUUID();
  const expiry = new Date(f.now().getTime() + 120_000);
  await transaction(f.admin.control, async (client) => {
    await client.query("UPDATE security.grants SET permissions=ARRAY['read_project'],expires_at=$3 WHERE workspace_id=$1 AND grant_id=$2", [f.workspaceId, f.deviceGrantId, expiry]);
    for (const scopeId of [projectId, missingDeviceProjectId]) {
      // The authority epoch is explicit; this security-only fixture uses a committed material reference.
      await client.query(`INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version)
        VALUES($1,'project',$2,2,$3,1)`, [f.workspaceId, scopeId, f.setup.custodyId]);
      await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,scope_id,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,activated_at)
        VALUES($1,$2,$3,'project','project',$4,1,ARRAY['read_project','comment'],'active',$5,$6,2,1,$7)`,
      [f.workspaceId, randomUUID(), f.accountId, scopeId, f.setup.genesisId, f.setup.custodyId, f.now()]);
    }
    await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,scope_id,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,activated_at)
      VALUES($1,$2,$3,$4,'project','project',$5,1,ARRAY['read_project'],'active',$6,$7,2,1,$8)`,
    [f.workspaceId, randomUUID(), f.accountId, f.deviceId, projectId, f.setup.genesisId, f.setup.custodyId, f.now()]);
  });
  const pending = await f.start(), scopes = pending.view.transcript!.scopes;
  assert.equal(scopes.length, 2); assert.ok(!scopes.some((scope) => scope.scopeId === missingDeviceProjectId));
  assert.deepEqual(scopes.find((scope) => scope.scope === 'workspace')!.permissions, ['read_project']);
  assert.equal(scopes.find((scope) => scope.scope === 'workspace')!.expiresAt, expiry.toISOString());
  const project = scopes.find((scope) => scope.scopeId === projectId)!;
  assert.deepEqual(project.permissions, ['read_project']); assert.equal(project.keyEpoch, '2');
  const personal = (await f.admin.control.query('SELECT permissions FROM security.grants WHERE workspace_id=$1 AND grant_id=$2', [f.workspaceId, f.ownerGrantId])).rows[0];
  assert.ok(personal.permissions.includes('approve_tasks'), 'Device narrowing must not mutate personal authority');
});

test('CP04: concurrent pairing commits serialize one accepted head and keep the rejected workspace projection usable', async (t) => {
  const f = await fixture(t), first = await f.start(), second = await f.start();
  for (const pending of [first, second]) await f.pairing.stageApproval(f.existing.cookieValue, f.existing.csrfToken, await f.approval(await f.confirm(pending)));
  const results = await Promise.allSettled([first, second].map((pending) => f.pairing.commit(f.existing.cookieValue, f.existing.csrfToken, pending.request.operationId)));
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  const rejected = results.find((result) => result.status === 'rejected'); assert.ok(rejected && code('PAIRING_INVALID')(rejected.reason));
  const app = await transaction(f.admin.application, async (client) => {
    await client.query('SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))', [`ukda.workspace:${f.workspaceId}`]);
    return (await client.query('SELECT fence_closed,security_version FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0];
  });
  assert.deepEqual(app, { fence_closed: false, security_version: '2' }, rejected.reason instanceof Error ? rejected.reason.stack : undefined);
  const control = (await f.admin.control.query('SELECT count(*) AS count FROM security.devices WHERE workspace_id=$1 AND state=\'active\'', [f.workspaceId])).rows[0];
  assert.equal(control?.count, '2');
});

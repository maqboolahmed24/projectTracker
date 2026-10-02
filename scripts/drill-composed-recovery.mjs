import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import { restorationFixture } from '../dist/test/restoration-fixture.js';
import { origin, oldPassword, newPassword } from '../dist/test/password-change-fixture.js';
import { RestorationService } from '../dist/src/modules/restoration/service.js';
import { LifecycleService } from '../dist/src/modules/lifecycle/service.js';
import { finalizeDeletionIfDue } from '../dist/src/modules/lifecycle/deadline.js';
import { EntitlementOperations } from '../dist/src/modules/identity/entitlements.js';
import { transaction } from '../dist/src/db.js';
import * as restoration from '../dist/src/shared/restoration.js';
import * as manifest from '../dist/src/modules/restoration/manifest.js';
import * as purge from '../dist/src/modules/lifecycle/purge.js';
import * as crypto from '../dist/src/shared/crypto.js';
import { verifySecurityHistory } from '../dist/src/shared/security-history.js';
import { readRestoration } from '../dist/src/client/restoration-crypto.js';
import { prepareLifecycle } from '../dist/src/client/lifecycle-crypto.js';
import { proveOwnerPhrase } from '../dist/src/client/recovery-controller.js';
import { recoveryCommand } from './recovery.mjs';
import { RecoveryRecords, repositorySecret } from '../ops/recovery-records.mjs';
import { assertNoPartialPurge } from './physical-backups.mjs';

// Explicit operational drill: excluded from npm test. It creates fixture-owned
// encrypted data, real full backups and isolated PITR databases. No old control
// backup is installed. Service/customer fixture keys exist only in this process.
test('CP12 composed recovery: physical PITR, latest reset/removal/phrase authority, Owner verification and physical purge', async t => {
  const drillId = randomUUID(), started = performance.now();
  const originalControlAdmin = process.env.CONTROL_ADMIN_DATABASE_URL;
  let f, directory;
  t.after(async () => {
    if (f) for (const [pool, schema, tables] of [
      [f.admin.application, 'app', ['export_sessions', 'lifecycle_tombstones']],
      [f.admin.control, 'security', ['erasure_requests', 'workspace_purges', 'retired_security_links', 'deletion_tombstones']],
    ]) await transaction(pool, async c => {
      await c.query("SET LOCAL session_replication_role='replica'");
      for (const table of tables) await c.query(`DELETE FROM ${schema}.${table} WHERE workspace_id=$1`, [f.workspaceId]);
    });
    if (directory) await rm(directory, {recursive: true, force: true});
    if (originalControlAdmin === undefined) delete process.env.CONTROL_ADMIN_DATABASE_URL;
    else process.env.CONTROL_ADMIN_DATABASE_URL = originalControlAdmin;
  });
  f = await restorationFixture(t);
  // Fixtures deliberately reject migration credentials in runtime config. Only
  // the separate maintenance-lock helper receives this operator connection.
  process.env.CONTROL_ADMIN_DATABASE_URL = originalControlAdmin ?? parseEnv(await readFile('.env.admin', 'utf8')).CONTROL_ADMIN_DATABASE_URL;
  await mkdir('.local', {recursive: true, mode: 0o700});
  directory = await mkdtemp('.local/recovery-composed-');
  const records = new RecoveryRecords(directory, await repositorySecret('.local/recovery/app.conf'));
  const runtime = {
    databases: f.databases, secrets: f.secrets, application: f.admin.application, control: f.admin.control,
    actor: f.operator, records, transaction, ...restoration, ...manifest, ...purge, ...crypto,
    service: hooks => new RestorationService({...f, origin, ...(hooks ? {hooks} : {})}),
    finalize: workspaceId => finalizeDeletionIfDue({...f, workspaceId}),
    trusted: {[f.secrets.keyId]: await new EntitlementOperations(f.databases, f.secrets).publicSigningKey()},
  };
  const otherOwner = await f.joined('join_owner'), member = await f.joined(), removedMember = await f.joined();
  await f.execute({action: 'edit_project', patch: {}}, {content: {name: 'Composed checkpoint history'}});
  const checkpointResult = await recoveryCommand(runtime, 'checkpoint', [f.workspaceId]);
  assert.equal(checkpointResult.checkpoints.length, 1);
  const checkpoint = checkpointResult.checkpoints[0];
  const captured = await records.read(f.workspaceId, checkpoint.checkpointId);
  assert.ok(captured.value.keyObjects.length > 0);
  await f.execute({action: 'edit_project', patch: {}}, {content: {name: 'Later content outside selected recovery point'}});
  const memberPassword = 'Composed reset fixture password 873209';
  const reset = await f.recover({accountId: member.binding.accountId, password: memberPassword});
  await f.finalize(await f.draft('remove', removedMember.binding.accountId));
  await f.finalize(await f.draft('remove', otherOwner.binding.accountId));
  const rotated = await f.recover({accountId: f.accountId, phrase: f.phrase, password: newPassword});
  const before = await verifySecurityHistory(await f.history()), failureAt = Date.now(), restoreStarted = performance.now();
  const restored = await recoveryCommand(runtime, 'restore', [f.workspaceId, checkpoint.checkpointId]);
  assert.equal(restored.state, 'ready_for_verification');
  assert.equal(restored.ownerVerificationRequired, true);
  await assert.rejects(f.sessions.authenticate(rotated.auth.cookieValue, {approved: true}));
  await assert.rejects(f.restoreLogin(member.binding.accountId, member.prepared.deviceWrapper.header.deviceId, member.bundle, newPassword));
  await f.restoreLogin(member.binding.accountId, reset.deviceId, reset.bundle, memberPassword);
  for (const removed of [otherOwner, removedMember]) await assert.rejects(f.restoreLogin(removed.binding.accountId, removed.prepared.deviceWrapper.header.deviceId, removed.bundle, newPassword));
  const oldRef = {workspaceId: f.workspaceId, accountId: f.accountId, operationId: randomUUID(), resumeToken: f.secrets.token()};
  const challenge = await rotated.recovery.beginPhrase(oldRef);
  await assert.rejects(proveOwnerPhrase({challenge, kit: {workspaceId: f.workspaceId, accountId: f.accountId, origin, genesisFingerprint: before.genesisFingerprint}, phrase: f.phrase}));
  const owner = await f.recover({accountId: f.accountId, phrase: rotated.phrase, password: 'Composed recovered Owner fixture secret 689203'});
  await assert.rejects(f.planning.context(owner.auth.cookieValue, owner.auth.csrfToken, f.reference()));
  const context = await f.restoration.context(owner.auth, {workspaceId: f.workspaceId, restoreId: restored.restoreId, operationId: randomUUID()});
  const inspected = await readRestoration({context, history: await f.history(), accountId: f.accountId, deviceId: owner.deviceId}, owner.bundle);
  assert.ok(inspected.verifiedSamples > 1);
  assert.equal((await f.restoration.verify(owner.auth, await f.restoreProof(restored.restoreId, owner.auth, owner.bundle))).state, 'completed');
  const restoreMs = Math.round(performance.now() - restoreStarted), after = await verifySecurityHistory(await f.history());
  assert.equal(after.dataGeneration, String(BigInt(before.dataGeneration) + 1n));
  assert.equal(after.profiles[otherOwner.binding.accountId].active, false);
  assert.equal(after.profiles[removedMember.binding.accountId].active, false);
  assert.equal(after.profiles[member.binding.accountId].credentialGeneration, '2');
  assert.equal(after.profiles[f.accountId].recoveryGeneration, '3');
  assert.equal(after.restoreQuarantine, false);
  const ordinary = await f.context(f.projectId, owner.auth);
  assert.equal(ordinary.records.find(r => r.kind === 'project').envelope.header.revision, '2');
  const lifecycle = new LifecycleService({...f, origin}), deletionContext = await lifecycle.context(owner.auth, {workspaceId: f.workspaceId, operationId: randomUUID(), action: 'request_deletion'});
  const keys = await f.refresh(owner.auth, owner.bundle);
  const request = await prepareLifecycle({context: deletionContext, history: keys.history, materials: keys.delivery.materials,
    accountId: f.accountId, deviceId: owner.deviceId, confirmationName: 'Password fixture workspace'}, owner.bundle);
  const deleted = await lifecycle.save(owner.auth, request), deletionStarted = performance.now();
  // Only the deadline clock is advanced. Backups, WAL, deletion, VACUUM, and
  // expiry timestamps below use the actual running databases and wall clock.
  await finalizeDeletionIfDue({...f, workspaceId: f.workspaceId, now: new Date(deleted.receipt.deletion.deleteAfter)});
  await assert.rejects(assertNoPartialPurge(f.admin.control));
  await assert.rejects(recoveryCommand(runtime, 'restore', [f.workspaceId, checkpoint.checkpointId]));
  const purged = await recoveryCommand(runtime, 'purge', [f.workspaceId]);
  assert.equal(purged.state, 'physically_purged');
  const marker = (await f.admin.control.query('SELECT live_payloads_purged_at,backup_expires_at FROM security.workspace_purges WHERE workspace_id=$1', [f.workspaceId])).rows[0];
  assert.ok(marker.live_payloads_purged_at);
  assert.equal(new Date(marker.backup_expires_at) - new Date(marker.live_payloads_purged_at), 30 * 86400000);
  assert.equal((await records.list()).length, 0);
  assert.equal((await f.admin.application.query('SELECT 1 FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.workspaces WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  await assert.rejects(f.activation.reservations.reserve({licenceKey: f.licence.licenceKey, resumeToken: f.secrets.token(), operationId: randomUUID()}));
  const completedAt = new Date().toISOString(), health = await recoveryCommand(runtime, 'metrics');
  for (const store of ['app', 'control']) health[store].lastSuccessfulDrillAt = completedAt;
  await f.admin.control.query('INSERT INTO security.recovery_health(id,measured_at,metrics) VALUES(true,clock_timestamp(),$1) ON CONFLICT(id) DO UPDATE SET measured_at=EXCLUDED.measured_at,metrics=EXCLUDED.metrics', [health]);
  const evidence = {drillId, completedAt, workspaceId: f.workspaceId, checkpointId: checkpoint.checkpointId,
    backups: checkpointResult.backups, selectedPointAgeAtFailureMs: failureAt - Date.parse(checkpoint.capturedAt),
    restoreThroughOwnerVerificationMs: restoreMs, physicalPurgeMs: Math.round(performance.now() - deletionStarted),
    totalMs: Math.round(performance.now() - started), verifiedSamples: inspected.verifiedSamples,
    latestAuthorityPreserved: ['member_reset', 'member_removal', 'owner_removal', 'phrase_rotation'],
    currentPhraseRecoveryInQuarantine: true, oldSnapshotAfterDeletionDenied: true, consumedLicenceReuseDenied: true,
    physicalPurgeCompleted: true, backupExpiry: new Date(marker.backup_expires_at).toISOString(),
    deadlineClockAdvancedForDrill: true, environment: 'local single-host Docker; fixture data; no production durability claim'};
  await writeFile(`test-results/checkpoint-12-composed-drill-${drillId}.json`, JSON.stringify(evidence, null, 2) + '\n');
  t.diagnostic(JSON.stringify(evidence));
});

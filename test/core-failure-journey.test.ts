import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { transaction } from '../src/db.js';
import { dataTransaction } from '../src/persistence.js';
import { AppError } from '../src/errors.js';
import { LifecycleService } from '../src/modules/lifecycle/service.js';
import { finalizeDeletionIfDue } from '../src/modules/lifecycle/deadline.js';
import { RecoveryService } from '../src/modules/identity/recovery.js';
import { deliverNotificationJob } from '../src/modules/notifications/delivery.js';
import { prepareUpgradeStart } from '../src/client/encrypted-upgrades-crypto.js';
import { prepareLifecycle } from '../src/client/lifecycle-crypto.js';
import { readRestoration } from '../src/client/restoration-crypto.js';
import { PlanningClientError, readPlanning } from '../src/client/planning-crypto.js';
import { digestObject } from '../src/shared/crypto.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { planningPayload } from '../src/shared/planning-api.js';
import { restorationFixture } from './restoration-fixture.js';
import { planningFixture } from './planning-fixture.js';
import { oldPassword, newPassword, origin } from './password-change-fixture.js';

const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;

test('CP13 failure journey: tenant denial, interrupted migration, competing Owners, restore after revocation and final deletion compose', { timeout: 180000 }, async t => {
  let f: Awaited<ReturnType<typeof restorationFixture>>;
  // Register before fixture teardown closes its pools. These are fixture-owned
  // permanent markers; application code and this journey never bypass them.
  t.after(async () => {
    if (!f) return;
    for (const [pool, schema, tables] of [
      [f.admin.application, 'app', ['lifecycle_tombstones']],
      [f.admin.control, 'security', ['erasure_requests', 'workspace_purges', 'retired_security_links', 'deletion_tombstones']],
    ] as const) await transaction(pool, async client => {
      await client.query("SET LOCAL session_replication_role='replica'");
      for (const table of tables) await client.query(`DELETE FROM ${schema}.${table} WHERE workspace_id=$1`, [f.workspaceId]);
    });
  });
  f = await restorationFixture(t);
  const foreign = await planningFixture(t), other = await f.joined('join_owner');
  const initialAuth = f.auth();
  await assert.rejects(f.planning.context(initialAuth.cookieValue, initialAuth.csrfToken,
    { workspaceId: foreign.workspaceId, projectId: foreign.projectId, operationId: randomUUID() }), code('PLANNING_FORBIDDEN'));
  await f.execute({ action: 'edit_project', patch: {} }, { content: { name: 'Retained integrated recovery content' } });
  const before = await f.context();
  const ordinaryDraft = await f.preparePlanning({ action: 'edit_project', patch: {} }, { content: { name: 'Denied during integrated migration' } });

  const start = await prepareUpgradeStart(await f.upgradeInput(), f.originalBundle);
  const migrationId = start.body.binding.migrationId;
  f.setUpgradeHooks({ afterCommit: async () => { throw new Error('Integrated upgrade acknowledgement lost'); } });
  await assert.rejects(f.upgrades.start(initialAuth, start), /Integrated upgrade acknowledgement lost/);
  f.setUpgradeHooks();
  const receipt = await f.upgrades.status(initialAuth, { workspaceId: f.workspaceId, migrationId,
    operationId: start.body.binding.operationId, dataGeneration: start.body.binding.dataGeneration, requestHash: await digestObject(start) });
  assert.equal(receipt.state, 'completed');
  assert.equal((await f.upgrades.start(initialAuth, start)).receipt!.requestHash, receipt.receipt!.requestHash);
  assert.equal((await f.admin.control.query('SELECT count(*)::int AS count FROM security.security_transitions WHERE workspace_id=$1 AND operation_id=$2',
    [f.workspaceId, start.body.binding.operationId])).rows[0].count, 1);
  await assert.rejects(f.preparePlanning({ action: 'edit_project', patch: {} }, { content: { name: 'Denied during integrated migration' } }),
    error => error instanceof PlanningClientError && error.code === 'INVALID_PLANNING');
  await assert.rejects(f.save(ordinaryDraft), code('WORKSPACE_RESTRICTED'));

  const partial = await f.prepareUpgradeBatch(migrationId, 'planning');
  await f.upgrades.batch(initialAuth, partial);
  const native = planningPayload.parse(partial.payload), operationId = native.mutation.body.binding.operationId;
  const partialHistory = (await f.admin.application.query('SELECT signed_mutation,upgrade_items,receipt FROM app.planning_operations WHERE workspace_id=$1 AND operation_id=$2',
    [f.workspaceId, operationId])).rows[0];
  const oldOutbox = (await f.admin.application.query('SELECT id,data_generation FROM app.outbox WHERE workspace_id=$1 AND operation_id=$2',
    [f.workspaceId, operationId])).rows[0];
  assert.ok(oldOutbox);
  const staleFirst = await f.prepareUpgradeBatch(migrationId, 'identity');
  const staleSecond = await f.prepareUpgradeBatch(migrationId, 'identity', undefined, other.auth, other.bundle);
  const checkpoint = await f.checkpoint();
  const originalSources = (await f.admin.application.query('SELECT source_reference,source_envelope FROM app.encrypted_upgrade_sources WHERE workspace_id=$1 ORDER BY record_type,record_id',
    [f.workspaceId])).rows;
  const beforeRemoval = await verifySecurityHistory(await f.history());
  const firstRemovesSecond = await f.draft('remove', other.binding.accountId);
  const secondRemovesFirst = await f.draft('remove', f.accountId, null, other.auth, other.bundle);
  const competition = await Promise.allSettled([f.finalize(firstRemovesSecond), f.finalize(secondRemovesFirst, other.auth)]);
  assert.equal(competition.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(competition.filter(result => result.status === 'rejected').length, 1);
  const removed = await verifySecurityHistory(await f.history());
  const owners = Object.values(removed.profiles).filter(profile => profile.active && profile.owner);
  assert.equal(owners.length, 1);
  const firstSurvives = owners[0]!.accountId === f.accountId;
  const survivor = firstSurvives
    ? { accountId: f.accountId, deviceId: f.deviceId, bundle: f.originalBundle, auth: initialAuth, password: oldPassword, stale: staleFirst }
    : { accountId: other.binding.accountId, deviceId: other.prepared.deviceWrapper.header.deviceId, bundle: other.bundle, auth: other.auth, password: newPassword, stale: staleSecond };
  const loser = firstSurvives
    ? { accountId: other.binding.accountId, deviceId: other.prepared.deviceWrapper.header.deviceId, bundle: other.bundle, auth: other.auth, password: newPassword, stale: staleSecond }
    : { accountId: f.accountId, deviceId: f.deviceId, bundle: f.originalBundle, auth: initialAuth, password: oldPassword, stale: staleFirst };
  assert.ok(BigInt(removed.custodyEpoch) > BigInt(beforeRemoval.custodyEpoch));
  assert.ok(BigInt(removed.workspaceKeyEpoch) > BigInt(beforeRemoval.workspaceKeyEpoch));
  await assert.rejects(f.sessions.authenticate(loser.auth.cookieValue, { approved: true }));
  await assert.rejects(f.upgrades.batch(loser.auth, loser.stale));
  await assert.rejects(f.upgrades.batch(survivor.auth, survivor.stale));
  await assert.rejects(f.draft('remove', survivor.accountId, null, survivor.auth, survivor.bundle), code('ACCESS_CHANGED'));

  const restoreId = await f.begin(checkpoint.manifest);
  await assert.rejects(f.sessions.authenticate(survivor.auth.cookieValue, { approved: true }));
  await f.install();
  await f.restoration.reconcile({ workspaceId: f.workspaceId, restoreId });
  await assert.rejects(f.restoreLogin(loser.accountId, loser.deviceId, loser.bundle, loser.password));
  const currentAuth = await f.restoreLogin(survivor.accountId, survivor.deviceId, survivor.bundle, survivor.password);
  await assert.rejects(f.context(f.projectId, currentAuth), error => error instanceof AppError && ['RESTORE_QUARANTINE', 'SECURITY_FENCED'].includes(error.code));
  const restoreContext = await f.restoration.context(currentAuth, { workspaceId: f.workspaceId, restoreId, operationId: randomUUID() });
  const localVerification = await readRestoration({ context: restoreContext, history: await f.history(), accountId: survivor.accountId, deviceId: survivor.deviceId }, survivor.bundle);
  assert.ok(localVerification.verifiedSamples > 0);
  assert.equal((await f.restoration.verify(currentAuth, await f.restoreProof(restoreId, currentAuth, survivor.bundle))).state, 'completed');
  const restored = await verifySecurityHistory(await f.history());
  assert.equal(restored.profiles[loser.accountId]!.active, false);
  assert.equal(restored.devices[loser.deviceId]!.active, false);
  assert.equal(restored.custodyEpoch, removed.custodyEpoch);
  assert.equal(restored.dataGeneration, String(BigInt(removed.dataGeneration) + 1n));
  assert.equal(restored.activeUpgrade!.migrationId, migrationId);
  assert.deepEqual((await f.admin.application.query('SELECT signed_mutation,upgrade_items,receipt FROM app.planning_operations WHERE workspace_id=$1 AND operation_id=$2',
    [f.workspaceId, operationId])).rows[0], partialHistory);
  assert.deepEqual((await f.admin.application.query('SELECT source_reference,source_envelope FROM app.encrypted_upgrade_sources WHERE workspace_id=$1 ORDER BY record_type,record_id',
    [f.workspaceId])).rows, originalSources);
  await assert.rejects(f.upgrades.batch(currentAuth, survivor.stale));
  await f.allUpgradeBatches(migrationId, currentAuth, survivor.bundle);
  assert.equal((await f.finishUpgrade(migrationId, currentAuth, survivor.bundle)).view.state, 'completed');
  const current = await f.context(f.projectId, currentAuth);
  const readable = await readPlanning({ context: current, history: await f.history(), accountId: survivor.accountId, deviceId: survivor.deviceId }, survivor.bundle);
  assert.equal(readable.records.find(record => record.kind === 'project')!.content.name, 'Retained integrated recovery content');
  assert.deepEqual(current.history.slice(0, before.history.length), before.history);
  assert.equal((await verifySecurityHistory(await f.history())).writeSchema, 2);

  const lifecycle = new LifecycleService({ ...f, origin });
  const deletionContext = await lifecycle.context(currentAuth, { workspaceId: f.workspaceId, operationId: randomUUID(), action: 'request_deletion' });
  const keys = await f.refresh(currentAuth, survivor.bundle);
  const deletion = await prepareLifecycle({ context: deletionContext, history: keys.history, materials: keys.delivery.materials,
    accountId: survivor.accountId, deviceId: survivor.deviceId, confirmationName: 'Password fixture workspace' }, survivor.bundle);
  const deletionReceipt = (await lifecycle.save(currentAuth, deletion)).receipt!;
  const deadline = Date.parse(deletionReceipt.deletion!.deleteAfter);
  t.mock.timers.enable({ apis: ['Date'], now: deadline - 1000 });
  try {
    // Reauthenticate immediately before expiry so denial proves the workspace
    // deadline, not the absolute lifetime of an old session.
    const recent = await f.restoreLogin(survivor.accountId, survivor.deviceId, survivor.bundle, survivor.password);
    const principal = await f.sessions.authenticate(recent.cookieValue, { approved: true });
    t.mock.timers.setTime(deadline);
    assert.equal((await f.admin.control.query('SELECT lifecycle FROM security.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].lifecycle, 'pending_deletion');
    await assert.rejects(dataTransaction(f.databases, principal, async () => true), code('NOT_FOUND'));
    await assert.rejects(f.sessions.authenticate(recent.cookieValue, { approved: true }));
    await assert.rejects(f.upgrades.start(recent, start));
    await deliverNotificationJob(f.databases, { workspaceId: f.workspaceId, outboxId: oldOutbox.id, dataGeneration: oldOutbox.data_generation });
    assert.deepEqual(await finalizeDeletionIfDue({ ...f, workspaceId: f.workspaceId, now: new Date(deadline) }), { deleted: true });
    assert.deepEqual(await finalizeDeletionIfDue({ ...f, workspaceId: f.workspaceId, now: new Date(deadline + 1) }), { deleted: true });
    await assert.rejects(f.restoration.begin({ workspaceId: f.workspaceId, restoreId: randomUUID(), manifest: checkpoint.manifest }, f.operator));
    await assert.rejects(new RecoveryService({ ...f, origin }).beginPhrase({ workspaceId: f.workspaceId, accountId: survivor.accountId,
      operationId: randomUUID(), resumeToken: f.secrets.token() }));
    await assert.rejects(lifecycle.status(recent, { workspaceId: f.workspaceId, operationId: deletion.body.binding.operationId,
      dataGeneration: deletion.body.binding.dataGeneration, requestHash: await digestObject(deletion) }));
    assert.equal((await f.admin.control.query("SELECT count(*)::int AS count FROM security.security_transitions WHERE workspace_id=$1 AND action='workspace.deleted'",
      [f.workspaceId])).rows[0].count, 1);
    assert.equal((await f.admin.control.query("SELECT count(*)::int AS count FROM security.deletion_tombstones WHERE workspace_id=$1 AND entity_kind='workspace'",
      [f.workspaceId])).rows[0].count, 1);
  } finally { t.mock.timers.reset(); }
});

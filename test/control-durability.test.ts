import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { LifecycleService } from '../src/modules/lifecycle/service.js';
import { prepareLifecycle } from '../src/client/lifecycle-crypto.js';
import { restorationFixture } from './restoration-fixture.js';
import { origin } from './password-change-fixture.js';

for (const incoming of ['off', 'local'] as const) {
  test(`CP13 control durability: lifecycle, upgrades and restore override ${incoming} on their actual committing connection`, async t => {
    const original = process.env.CONTROL_DATABASE_URL;
    assert.ok(original, 'Control durability tests require runtime control credentials');
    const url = new URL(original);
    url.searchParams.set('options', `${url.searchParams.get('options') ?? ''} -c synchronous_commit=${incoming}`.trim());
    // This affects only pools created by this test fixture, never a database role
    // or running service. Restore the process environment before exercising work.
    process.env.CONTROL_DATABASE_URL = url.href;
    let f: Awaited<ReturnType<typeof restorationFixture>>;
    try { f = await restorationFixture(t); }
    finally { process.env.CONTROL_DATABASE_URL = original; }

    const baseline = async () => assert.equal((await f.databases.control.query('SHOW synchronous_commit')).rows[0].synchronous_commit, incoming);
    await baseline();
    let stage = '';
    const observed: string[] = [];
    const beforeControlCommit = async (control: pg.PoolClient) => {
      // Query PostgreSQL on the same transaction that has written the authority
      // and receipt, rather than testing for a particular SQL string in source.
      assert.equal((await control.query('SHOW synchronous_commit')).rows[0].synchronous_commit, 'on', stage);
      observed.push(stage);
    };

    const lifecycle = new LifecycleService({ ...f, origin, hooks: { beforeControlCommit } });
    for (const action of ['request_deletion', 'cancel_deletion'] as const) {
      const auth = f.auth(), context = await lifecycle.context(auth, { workspaceId: f.workspaceId, operationId: randomUUID(), action });
      const current = await f.refresh();
      const payload = await prepareLifecycle({ context, history: current.history, materials: current.delivery.materials,
        accountId: f.accountId, deviceId: f.deviceId, ...(action === 'request_deletion' ? { confirmationName: 'Password fixture workspace' } : {}) }, f.originalBundle);
      stage = `lifecycle.${action}`;
      assert.equal((await lifecycle.save(auth, payload)).state, 'completed');
    }
    await baseline();

    f.setUpgradeHooks({ beforeControlCommit });
    stage = 'upgrade.start';
    const upgrade = await f.startUpgrade();
    assert.equal(upgrade.view.state, 'completed');
    stage = 'upgrade.identity';
    await f.allUpgradeBatches(upgrade.migrationId);
    stage = 'upgrade.finish';
    assert.equal((await f.finishUpgrade(upgrade.migrationId)).view.state, 'completed');
    await baseline();

    const checkpoint = await f.checkpoint();
    f.setRestoreHooks({ beforeControlCommit });
    stage = 'restore.begin';
    const restoreId = await f.begin(checkpoint.manifest);
    await f.install();
    await f.restoration.reconcile({ workspaceId: f.workspaceId, restoreId });
    const auth = await f.restoreLogin();
    stage = 'restore.verify';
    assert.equal((await f.restoration.verify(auth, await f.restoreProof(restoreId, auth))).state, 'completed');
    await baseline();
    assert.deepEqual(observed, ['lifecycle.request_deletion', 'lifecycle.cancel_deletion', 'upgrade.start', 'upgrade.identity',
      'upgrade.finish', 'restore.begin', 'restore.verify']);
  });
}

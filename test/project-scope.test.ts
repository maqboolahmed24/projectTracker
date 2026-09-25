import assert from 'node:assert/strict';
import test from 'node:test';
import { passwordFixture } from './password-change-fixture.js';
import { provisionProjectScope } from './project-scope-fixture.js';
import { transaction } from '../src/db.js';
import { readOwnerCustodyKeyMaterial } from '../src/client/pairing.js';
import { base64urlEncode } from '../src/shared/crypto.js';
import type { PairingMaterial } from '../src/shared/pairing.js';
import { readPersonalScopes } from '../src/modules/identity/personal-scopes.js';

test('CP06: signed project scope provisioning preserves current Owner access and decrypts its new project key', async (t) => {
  let f: Awaited<ReturnType<typeof passwordFixture>>;
  t.after(async () => { if (f) await transaction(f.admin.application, async (c) => {
    await c.query('DELETE FROM app.project_access WHERE workspace_id=$1', [f.workspaceId]);
    await c.query('DELETE FROM app.projects WHERE workspace_id=$1', [f.workspaceId]);
  }); });
  f = await passwordFixture(t);
  const before = await f.sessions.authenticate(f.auth().cookieValue, { approved: true });
  const provisioned = await provisionProjectScope(f);
  const after = await f.sessions.authenticate(f.auth().cookieValue, { approved: true });
  assert.equal(after.sessionGeneration, before.sessionGeneration);
  assert.equal(after.credentialGeneration, before.credentialGeneration);
  assert.equal(after.dataGeneration, before.dataGeneration);
  assert.equal(provisioned.state.custodyEpoch, '2');
  const access = (await f.admin.application.query('SELECT state,key_epoch,role_id FROM app.project_access WHERE workspace_id=$1 AND project_id=$2 AND profile_id=$3',
    [f.workspaceId, provisioned.projectId, f.accountId])).rows;
  assert.deepEqual(access, [{ state: 'active', key_epoch: '1', role_id: f.prepared.payload.genesis.body.roles.owner }]);
  const materials = (await f.admin.control.query<PairingMaterial>('SELECT object_id AS id,object_hash AS digest,object_kind AS kind,versioned_object AS value FROM security.staged_objects WHERE workspace_id=$1 AND state=\'committed\'', [f.workspaceId])).rows;
  const opened = await readOwnerCustodyKeyMaterial({ accountId: f.accountId, deviceId: f.deviceId, history: provisioned.state, materials }, f.originalBundle);
  assert.deepEqual(opened.manifest.workspaceKeys, provisioned.manifest.workspaceKeys);
  assert.deepEqual(opened.manifest.projectKeys, [{ projectId: provisioned.projectId, keys: [{ epoch: '1', key: base64urlEncode(provisioned.projectKey) }] }]);
  const scopes = await transaction(f.databases.control, async (c) => {
    await c.query("SELECT set_config('ukda.workspace_id',$1,true)", [f.workspaceId]);
    return readPersonalScopes(c, f.workspaceId, f.accountId, true, new Date());
  });
  assert.equal(scopes.find((s) => s.scope === 'project')?.keyEpoch, '1');
  assert.equal(scopes.find((s) => s.scope === 'workspace')?.keyEpoch, '2');
});

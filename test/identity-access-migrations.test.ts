import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test, { type TestContext } from 'node:test';
import { parseEnv } from 'node:util';
import pg from 'pg';

async function runtime(t: TestContext, store: 'control' | 'application') {
  const url = store === 'control' ? process.env.CONTROL_DATABASE_URL : process.env.DATABASE_URL;
  assert.ok(url, 'Identity migration tests require the runtime database URL');
  const c = new pg.Client({ connectionString: url });
  await c.connect(); await c.query('BEGIN');
  t.after(async () => { await c.query('ROLLBACK').catch(() => {}); await c.end(); });
  return c;
}
async function context(c: pg.Client, workspace: string, profile = '') {
  await c.query("SELECT set_config('ukda.workspace_id',$1,true),set_config('ukda.profile_id',$2,true)", [workspace, profile]);
}
async function rejectsSql(c: pg.Client, code: string, sql: string, values: unknown[] = []) {
  await c.query('SAVEPOINT expected_failure');
  try { await assert.rejects(c.query(sql, values), (e: unknown) => (e as { code?: string }).code === code); }
  finally { await c.query('ROLLBACK TO SAVEPOINT expected_failure'); await c.query('RELEASE SAVEPOINT expected_failure'); }
}
function ids() {
  return { workspace: randomUUID(), licence: randomUUID(), profile: randomUUID(), device: randomUUID(),
    object: randomUUID(), otherObject: randomUUID(), operation: randomUUID(), role: randomUUID(),
    membership: randomUUID(), deviceGrant: randomUUID(), project: randomUUID() };
}
async function controlFixture(t: TestContext) {
  const c = await runtime(t, 'control');
  const states = [ids(), ids()] as const;
  for (const s of states) {
    await context(c, s.workspace);
    await c.query("INSERT INTO security.licences(licence_id,verification_digest,verification_key_id) VALUES($1,$2,'cp06-fixture')", [s.licence, randomBytes(32)]);
    await c.query(`INSERT INTO security.workspaces(workspace_id,licence_id,lifecycle,activated_at,security_head,security_version,custody_epoch)
      VALUES($1,$2,'active',now(),repeat('a',64),1,1)`, [s.workspace, s.licence]);
    for (const sequence of [1, 2]) await c.query(`INSERT INTO security.security_transitions
      (workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition)
      VALUES($1,$2,$3,$4,$5,'fixture','service','{}')`, [s.workspace, sequence, randomUUID(), (sequence === 1 ? '0' : 'a').repeat(64), (sequence === 1 ? 'a' : 'b').repeat(64)]);
    for (const [object, hash] of [[s.object, 'c'], [s.otherObject, 'd']]) await c.query(`INSERT INTO security.staged_objects
      (workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
      VALUES($1,$2,'signed_grant',$3,'{}',$4,'committed',1)`, [s.workspace, object, hash!.repeat(64), s.operation]);
    await c.query(`INSERT INTO security.roles(workspace_id,role_id,template,permissions,definition_object_id,security_version)
      VALUES($1,$2,'member',ARRAY['read_project','comment'],$3,1)`, [s.workspace, s.role, s.object]);
    await c.query(`INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version)
      VALUES($1,'workspace',$1,1,$2,1),($1,'project',$3,1,$2,1)`, [s.workspace, s.object, s.project]);
    await c.query(`UPDATE security.workspaces SET current_custody_manifest_object_id=$2 WHERE workspace_id=$1`, [s.workspace, s.object]);
    await c.query(`INSERT INTO security.profiles(workspace_id,profile_id,state,credential_generation,opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers)
      VALUES($1,$2,'active',1,$3,'fixture','fixture','{}')`, [s.workspace, s.profile, randomBytes(64).toString('base64url')]);
    await c.query(`INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approved_at,approval_security_version)
      VALUES($1,$2,$3,1,$4,$5,'active',now(),1)`, [s.workspace, s.device, s.profile, randomBytes(32), randomBytes(32)]);
    await c.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,generation,state,signed_grant_object_id,key_manifest_object_id,security_version,activated_at)
      VALUES($1,$2,$3,'membership','workspace',1,'active',$4,$4,1,now())`, [s.workspace, s.membership, s.profile, s.object]);
    await c.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,generation,state,signed_grant_object_id,security_version,activated_at)
      VALUES($1,$2,$3,$4,'device','workspace',1,'active',$5,1,now())`, [s.workspace, s.deviceGrant, s.profile, s.device, s.object]);
  }
  await c.query('SET CONSTRAINTS ALL IMMEDIATE');
  return { c, a: states[0], b: states[1] };
}

test('CP06: authoritative roles and scope heads force tenant isolation and tenant-bound references', async (t) => {
  const { c, a, b } = await controlFixture(t);
  const catalog = await c.query(`SELECT relname,relrowsecurity,relforcerowsecurity,relowner=current_user::regrole AS owned
    FROM pg_class WHERE oid IN ('security.roles'::regclass,'security.scope_heads'::regclass)`);
  assert.equal(catalog.rowCount, 2);
  for (const row of catalog.rows) { assert.equal(row.relrowsecurity, true); assert.equal(row.relforcerowsecurity, true); assert.equal(row.owned, false); }
  await context(c, a.workspace);
  assert.deepEqual((await c.query('SELECT workspace_id FROM security.roles')).rows.map((r) => r.workspace_id), [a.workspace]);
  assert.equal((await c.query('SELECT * FROM security.scope_heads')).rowCount, 2);
  await rejectsSql(c, '42501', `INSERT INTO security.scope_heads VALUES($1,'project',$2,1,$3,1)`, [b.workspace, randomUUID(), b.object]);
  await rejectsSql(c, '23503', 'UPDATE security.roles SET definition_object_id=$2,revision=2,security_version=2 WHERE workspace_id=$1', [a.workspace, b.object]);
  await rejectsSql(c, '23503', "UPDATE security.scope_heads SET recovery_manifest_object_id=$2,security_version=2 WHERE workspace_id=$1", [a.workspace, b.object]);
  await rejectsSql(c, '23503', 'UPDATE security.workspaces SET current_custody_manifest_object_id=$2 WHERE workspace_id=$1', [a.workspace, b.object]);
  await rejectsSql(c, '23514', "INSERT INTO security.scope_heads VALUES($1,'workspace',$2,1,$3,1)", [a.workspace, randomUUID(), a.object]);
  await context(c, '');
  for (const table of ['roles', 'scope_heads']) assert.equal((await c.query(`SELECT * FROM security.${table}`)).rowCount, 0);
});

test('CP06: personal membership survives last-device revocation and cannot be device-bound or duplicated', async (t) => {
  const { c, a, b } = await controlFixture(t); await context(c, a.workspace);
  await rejectsSql(c, '23514', 'UPDATE security.grants SET device_id=$2 WHERE workspace_id=$1 AND grant_id=$3', [a.workspace, a.device, a.membership]);
  await rejectsSql(c, '23505', `INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,generation,state,signed_grant_object_id,security_version,activated_at)
    VALUES($1,$2,$3,'membership','workspace',1,'active',$4,1,now())`, [a.workspace, randomUUID(), a.profile, a.object]);
  await c.query("UPDATE security.grants SET state='revoked',revoked_at=now() WHERE workspace_id=$1 AND grant_id=$2", [a.workspace, a.deviceGrant]);
  await c.query("UPDATE security.devices SET state='revoked',revoked_at=now() WHERE workspace_id=$1 AND device_id=$2", [a.workspace, a.device]);
  const membership = (await c.query('SELECT state,device_id,key_epoch FROM security.grants WHERE workspace_id=$1 AND grant_id=$2', [a.workspace, a.membership])).rows[0];
  assert.deepEqual(membership, { state: 'active', device_id: null, key_epoch: '1' });
  const projectGrant = randomUUID();
  await c.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,scope_id,generation,signed_grant_object_id,role_id,role_revision)
    VALUES($1,$2,$3,'project','project',$4,1,$5,$6,1)`, [a.workspace, projectGrant, a.profile, a.project, a.object, a.role]);
  await rejectsSql(c, '23503', 'UPDATE security.grants SET role_id=$3 WHERE workspace_id=$1 AND grant_id=$2', [a.workspace, projectGrant, b.role]);
  await rejectsSql(c, '23514', 'UPDATE security.grants SET role_revision=NULL WHERE workspace_id=$1 AND grant_id=$2', [a.workspace, projectGrant]);
  await rejectsSql(c, '23514', 'UPDATE security.grants SET key_epoch=0 WHERE workspace_id=$1', [a.workspace]);
});

test('CP06: current profile roles require complete assignment references from the same tenant', async (t) => {
  const { c, a, b } = await controlFixture(t); await context(c, a.workspace);
  await rejectsSql(c, '23514', 'UPDATE security.profiles SET role_id=$2 WHERE workspace_id=$1', [a.workspace, a.role]);
  await rejectsSql(c, '23503', 'UPDATE security.profiles SET role_id=$2,role_revision=1,role_assignment_object_id=$3 WHERE workspace_id=$1', [a.workspace, b.role, a.object]);
  await rejectsSql(c, '23503', 'UPDATE security.profiles SET role_id=$2,role_revision=1,role_assignment_object_id=$3 WHERE workspace_id=$1', [a.workspace, a.role, b.object]);
  await c.query('UPDATE security.profiles SET role_id=$2,role_revision=1,role_assignment_object_id=$3 WHERE workspace_id=$1', [a.workspace, a.role, a.object]);
  await rejectsSql(c, '23514', 'UPDATE security.profiles SET role_revision=0 WHERE workspace_id=$1', [a.workspace]);
  await c.query("UPDATE security.profiles SET state='suspended' WHERE workspace_id=$1", [a.workspace]);
  assert.deepEqual((await c.query('SELECT role_id,role_revision,role_assignment_object_id FROM security.profiles WHERE workspace_id=$1', [a.workspace])).rows,
    [{ role_id: a.role, role_revision: '1', role_assignment_object_id: a.object }]);
});

test('CP06: role changes and scope epochs require advancing signed authority and valid permissions', async (t) => {
  const { c, a } = await controlFixture(t); await context(c, a.workspace);
  await rejectsSql(c, '23514', "UPDATE security.roles SET permissions=ARRAY['read_project'] WHERE workspace_id=$1", [a.workspace]);
  for (const permissions of [['read_project', 'ownership'], ['comment'], ['read_project', 'read_project'], ['read_project', null]]) {
    await rejectsSql(c, '23514', 'UPDATE security.roles SET permissions=$2,revision=2,security_version=2 WHERE workspace_id=$1', [a.workspace, permissions]);
  }
  await c.query("UPDATE security.roles SET permissions=ARRAY['read_project'],revision=2,security_version=2 WHERE workspace_id=$1", [a.workspace]);
  await rejectsSql(c, '23514', 'UPDATE security.roles SET revision=1 WHERE workspace_id=$1', [a.workspace]);
  await rejectsSql(c, '23514', 'UPDATE security.scope_heads SET key_epoch=2 WHERE workspace_id=$1', [a.workspace]);
  await c.query('UPDATE security.scope_heads SET key_epoch=2,recovery_manifest_object_id=$2,security_version=2 WHERE workspace_id=$1', [a.workspace, a.otherObject]);
  await rejectsSql(c, '23514', 'UPDATE security.scope_heads SET key_epoch=1 WHERE workspace_id=$1', [a.workspace]);
  await rejectsSql(c, '23514', 'UPDATE security.scope_heads SET recovery_manifest_object_id=$2 WHERE workspace_id=$1', [a.workspace, a.object]);
});

async function appFixture(t: TestContext) {
  const c = await runtime(t, 'application'); const s = { ...ids(), owner: randomUUID(), task: randomUUID() };
  await context(c, s.workspace, s.profile);
  await c.query('INSERT INTO app.workspaces(workspace_id) VALUES($1)', [s.workspace]);
  await c.query("INSERT INTO app.roles(workspace_id,id,template,permissions,encrypted_envelope) VALUES($1,$2,'member',ARRAY['read_project','comment'],'{}')", [s.workspace, s.role]);
  await c.query("INSERT INTO app.profiles(workspace_id,id,state,is_owner,encrypted_envelope) VALUES($1,$2,'active',false,'{}'),($1,$3,'active',true,'{}')", [s.workspace, s.profile, s.owner]);
  // Access precedes project inside this deferred transaction so project RLS can
  // verify the exact recipient grant without any migration-role bypass.
  await c.query(`INSERT INTO app.project_access(workspace_id,project_id,profile_id,role_id,state,permissions,grant_id)
    VALUES($1,$2,$3,$4,'active',ARRAY['read_project'],$5)`, [s.workspace, s.project, s.profile, s.role, randomUUID()]);
  await c.query("INSERT INTO app.projects(workspace_id,id,encrypted_envelope) VALUES($1,$2,'{}')", [s.workspace, s.project]);
  await c.query("INSERT INTO app.tasks(workspace_id,project_id,id,encrypted_envelope) VALUES($1,$2,$3,'{}')", [s.workspace, s.project, s.task]);
  await c.query("INSERT INTO app.scope_heads VALUES($1,'workspace',$1,1,1),($1,'project',$2,1,1)", [s.workspace, randomUUID()]);
  await c.query('SET CONSTRAINTS ALL IMMEDIATE');
  return { c, s };
}

test('CP06: application RLS uses effective permissions, expiry and active roles without an Owner bypass', async (t) => {
  const { c, s } = await appFixture(t);
  const readable = async () => (await c.query('SELECT app.can_read_project($1) AS allowed', [s.project])).rows[0].allowed;
  assert.equal(await readable(), true);
  await c.query("UPDATE app.roles SET permissions='{}',revision=revision+1 WHERE workspace_id=$1", [s.workspace]);
  assert.equal(await readable(), true, 'A definition edit does not rewrite the existing grant snapshot');
  await c.query("UPDATE app.project_access SET permissions='{}' WHERE workspace_id=$1", [s.workspace]);
  assert.equal(await readable(), false);
  await c.query("UPDATE app.roles SET permissions=ARRAY['read_project','comment'] WHERE workspace_id=$1", [s.workspace]);
  assert.equal(await readable(), false, 'Expanding the definition cannot expand an old grant');
  await c.query("UPDATE app.project_access SET permissions=ARRAY['read_project'],expires_at=now()-interval '1 second' WHERE workspace_id=$1", [s.workspace]);
  assert.equal(await readable(), false);
  await c.query('UPDATE app.project_access SET expires_at=NULL WHERE workspace_id=$1', [s.workspace]);
  await c.query("UPDATE app.roles SET state='retired' WHERE workspace_id=$1", [s.workspace]); assert.equal(await readable(), false);
  await c.query("UPDATE app.roles SET state='active' WHERE workspace_id=$1", [s.workspace]); assert.equal(await readable(), true);
  await context(c, s.workspace, s.owner); assert.equal(await readable(), false);
  assert.equal((await c.query('SELECT * FROM app.projects')).rowCount, 0);
  await context(c, ''); assert.equal((await c.query('SELECT * FROM app.scope_heads')).rowCount, 0);
  await context(c, s.workspace, s.profile);
  assert.equal((await c.query('SELECT * FROM app.scope_heads')).rowCount, 2, 'Scope mirror does not require an application project');
  await rejectsSql(c, '42501', "INSERT INTO app.scope_heads VALUES($1,'workspace',$1,1,1)", [randomUUID()]);
  const foreignWorkspace = randomUUID(); await context(c, foreignWorkspace);
  await c.query('INSERT INTO app.workspaces(workspace_id) VALUES($1)', [foreignWorkspace]);
  await c.query("INSERT INTO app.scope_heads VALUES($1,'project',$2,1,1)", [foreignWorkspace, randomUUID()]);
  await c.query('DELETE FROM app.workspaces WHERE workspace_id=$1', [foreignWorkspace]);
  assert.equal((await c.query('SELECT * FROM app.scope_heads')).rowCount, 0, 'Derived mirrors cascade with their workspace');
});

test('CP06: assignment checks use grant snapshots and require cleanup before expiry or retirement', async (t) => {
  const { c, s } = await appFixture(t);
  await c.query('INSERT INTO app.task_assignments(workspace_id,project_id,task_id,member_id,assigned_by) VALUES($1,$2,$3,$4,$4)', [s.workspace, s.project, s.task, s.profile]);
  await c.query("UPDATE app.roles SET permissions='{}',revision=revision+1 WHERE workspace_id=$1", [s.workspace]);
  await rejectsSql(c, '23514', "UPDATE app.roles SET state='retired' WHERE workspace_id=$1", [s.workspace]);
  await rejectsSql(c, '23514', "UPDATE app.project_access SET permissions='{}' WHERE workspace_id=$1", [s.workspace]);
  await rejectsSql(c, '23514', "UPDATE app.project_access SET expires_at=now()-interval '1 second' WHERE workspace_id=$1", [s.workspace]);
  await c.query('DELETE FROM app.task_assignments WHERE workspace_id=$1', [s.workspace]);
  await c.query("UPDATE app.project_access SET permissions='{}',expires_at=now()-interval '1 second' WHERE workspace_id=$1", [s.workspace]);
  await c.query("UPDATE app.roles SET state='retired' WHERE workspace_id=$1", [s.workspace]);
});

test('CP06: project notices disappear after grant expiry/revocation and inactive accounts see no workspace notices', async (t) => {
  const { c, s } = await appFixture(t);
  await c.query(`INSERT INTO app.notifications(workspace_id,id,recipient_profile_id,project_id,event_id,event_type)
    VALUES($1,$2,$3,$4,$5,'fixture.event'),($1,$6,$3,NULL,$7,'fixture.event')`,
  [s.workspace, randomUUID(), s.profile, s.project, randomUUID(), randomUUID(), randomUUID()]);
  const count = async () => (await c.query('SELECT * FROM app.notifications')).rowCount;
  assert.equal(await count(), 2);
  await c.query("UPDATE app.project_access SET expires_at=now()-interval '1 second' WHERE workspace_id=$1", [s.workspace]);
  assert.equal(await count(), 1);
  await c.query("UPDATE app.project_access SET expires_at=NULL,state='revoked' WHERE workspace_id=$1", [s.workspace]);
  assert.equal(await count(), 1);
  await c.query("UPDATE app.profiles SET state='suspended' WHERE workspace_id=$1 AND id=$2", [s.workspace, s.profile]);
  assert.equal(await count(), 0);
});

test('CP06: legacy bootstrap requires retained epoch-one genesis and never invents member authority or content epochs', async (t) => {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const url = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(url, 'Bootstrap replay requires an explicit fixture admin URL');
  const c = new pg.Client({ connectionString: url }); await c.connect(); await c.query('BEGIN');
  t.after(async () => { await c.query('ROLLBACK').catch(() => {}); await c.end(); });
  // Replay only inside a random, rollback-only schema. No shared schema, ledger,
  // service credentials, real signed object, or production history is modified.
  const schema = `cp06_${randomUUID().replaceAll('-', '')}`;
  const migration = async (name: string) => (await readFile(new URL(`../../migrations/control/${name}`, import.meta.url), 'utf8')).replace(/\bsecurity\b/g, schema);
  for (const name of ['001_security.sql', '002_activation.sql', '003_activation_credentials.sql', '004_entitlements.sql', '005_authentication.sql']) await c.query(await migration(name));
  const states = [
    { ...ids(), epoch: 1, malformed: false },
    { ...ids(), epoch: 2, malformed: false },
    { ...ids(), epoch: 1, malformed: true },
  ];
  for (const s of states) {
    await context(c, s.workspace);
    const roleIds = { owner: randomUUID(), manager: randomUUID(), member: randomUUID(), viewer: randomUUID() };
    if (s.malformed) roleIds.viewer = roleIds.member;
    const genesis = { body: { purpose: 'ukda.genesis.v1', workspaceId: s.workspace, genesisId: s.object, custodyId: s.otherObject,
      roles: roleIds, manifest: [{ id: s.otherObject, kind: 'custody_manifest', digest: 'b'.repeat(64) },
        { id: s.workspace, kind: 'encrypted_workspace', digest: 'c'.repeat(64) }] }, signature: 'fixture-only' };
    await c.query(`INSERT INTO ${schema}.licences(licence_id,verification_digest,verification_key_id) VALUES($1,$2,'fixture')`, [s.licence, randomBytes(32)]);
    await c.query(`INSERT INTO ${schema}.workspaces(workspace_id,licence_id,lifecycle,activated_at,security_head,security_version,custody_epoch,genesis_object_id)
      VALUES($1,$2,'active',now(),repeat('a',64),1,$3,$4)`, [s.workspace, s.licence, s.epoch, s.object]);
    await c.query(`INSERT INTO ${schema}.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition)
      VALUES($1,1,$2,repeat('0',64),repeat('a',64),'activation','service',$3)`, [s.workspace, s.operation, { genesis, recoveryProof: {} }]);
    for (const object of [
      { id: s.object, kind: 'genesis', hash: 'a', value: genesis },
      { id: s.otherObject, kind: 'custody_manifest', hash: 'b', value: { header: { keyEpoch: '1', scope: 'workspace', scopeId: s.workspace } } },
      { id: s.workspace, kind: 'encrypted_workspace', hash: 'c', value: { header: { keyEpoch: '1' } } },
      { id: s.project, kind: 'custody_manifest', hash: 'd', value: { header: { keyEpoch: '7', scope: 'project', scopeId: s.project } } },
      { id: s.role, kind: 'key_envelope', hash: 'e', value: { header: { keyEpoch: '5', scope: 'project', scopeId: s.project } } },
    ]) await c.query(`INSERT INTO ${schema}.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
      VALUES($1,$2,$3,$4,$5,$6,'committed',1)`, [s.workspace, object.id, object.kind, object.hash.repeat(64), object.value, s.operation]);
    await c.query(`INSERT INTO ${schema}.profiles(workspace_id,profile_id,state,is_owner,owner_ready_at,credential_generation,opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers)
      VALUES($1,$2,'active',true,now(),1,'Zml4dHVyZQ','fixture','fixture','{}')`, [s.workspace, s.profile]);
    await c.query(`INSERT INTO ${schema}.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approved_at)
      VALUES($1,$2,$3,1,$4,$5,'active',now())`, [s.workspace, s.device, s.profile, randomBytes(32), randomBytes(32)]);
    await c.query(`INSERT INTO ${schema}.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,generation,state,signed_grant_object_id,key_manifest_object_id,security_version,activated_at)
      VALUES($1,$2,$3,$4,'owner','workspace',1,'active',$5,$6,1,now()),($1,$7,$3,$4,'device','workspace',1,'active',$5,$6,1,now())`,
    [s.workspace, s.membership, s.profile, s.device, s.object, s.otherObject, s.deviceGrant]);
    await c.query(`INSERT INTO ${schema}.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,scope_id,generation,signed_grant_object_id,key_manifest_object_id)
      VALUES($1,$2,$3,'project','project',$4,1,$5,$4),($1,$6,$3,'project','project',$4,1,$5,$7)`,
    [s.workspace, randomUUID(), s.profile, s.project, s.object, randomUUID(), s.role]);
  }
  await c.query('SET CONSTRAINTS ALL IMMEDIATE');
  const before = (await c.query(`SELECT workspace_id,object_id,object_hash,versioned_object FROM ${schema}.staged_objects ORDER BY workspace_id,object_id`)).rows;
  await c.query(await migration('006_identity_access.sql'));
  assert.deepEqual((await c.query(`SELECT workspace_id,object_id,object_hash,versioned_object FROM ${schema}.staged_objects ORDER BY workspace_id,object_id`)).rows, before);
  for (const s of states) {
    await context(c, s.workspace);
    const valid = s.epoch === 1 && !s.malformed;
    assert.equal((await c.query(`SELECT current_custody_manifest_object_id FROM ${schema}.workspaces WHERE workspace_id=$1`, [s.workspace])).rows[0].current_custody_manifest_object_id, valid ? s.otherObject : null);
    assert.equal((await c.query(`SELECT * FROM ${schema}.roles WHERE workspace_id=$1`, [s.workspace])).rowCount, valid ? 4 : 0);
    assert.equal((await c.query(`SELECT * FROM ${schema}.scope_heads WHERE workspace_id=$1`, [s.workspace])).rowCount, valid ? 1 : 0);
    assert.equal((await c.query(`SELECT device_id FROM ${schema}.grants WHERE workspace_id=$1 AND grant_id=$2`, [s.workspace, s.membership])).rows[0].device_id, null);
    assert.equal((await c.query(`SELECT * FROM ${schema}.grants WHERE workspace_id=$1 AND grant_kind='membership'`, [s.workspace])).rowCount, 0);
    const epochs = (await c.query(`SELECT key_manifest_object_id,key_epoch FROM ${schema}.grants WHERE workspace_id=$1 AND grant_kind='project'`, [s.workspace])).rows;
    assert.equal(epochs.find((r) => r.key_manifest_object_id === s.project)?.key_epoch, '1', 'Custody-wrapped content does not reveal its ordinary epoch');
    assert.equal(epochs.find((r) => r.key_manifest_object_id === s.role)?.key_epoch, '5', 'Matching recipient header supplies an explicit scope epoch');
  }
});

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { parseEnv } from 'node:util';
import pg from 'pg';

test('CP06: profile role backfill follows the latest committed assignment and preserves signed history', async (t) => {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const url = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(url, 'Role backfill test requires the fixture admin URL');
  const c = new pg.Client({ connectionString: url }); await c.connect(); await c.query('BEGIN');
  t.after(async () => { await c.query('ROLLBACK').catch(() => {}); await c.end(); });
  // Rollback-only schema: these are trusted-row migration fixtures, not evidence
  // that a fabricated signature is accepted by the application's verifier.
  const schema = `cp06_roles_${randomUUID().replaceAll('-', '')}`;
  const migration = async (name: string) => (await readFile(new URL(`../../migrations/control/${name}`, import.meta.url), 'utf8')).replace(/\bsecurity\b/g, schema);
  for (const name of ['001_security.sql', '002_activation.sql', '003_activation_credentials.sql', '004_entitlements.sql', '005_authentication.sql', '006_identity_access.sql']) await c.query(await migration(name));
  const workspaceId = randomUUID(), licenceId = randomUUID(), genesisId = randomUUID();
  const founder = randomUUID(), promoted = randomUUID(), pending = randomUUID(), unbound = randomUUID();
  const ownerRole = randomUUID(), memberRole = randomUUID(), memberAssignment = randomUUID(), promotion = randomUUID();
  await c.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
  await c.query(`INSERT INTO ${schema}.licences(licence_id,verification_digest,verification_key_id) VALUES($1,$2,'migration-fixture')`, [licenceId, randomBytes(32)]);
  await c.query(`INSERT INTO ${schema}.workspaces(workspace_id,licence_id,lifecycle,activated_at,security_head,security_version,custody_epoch,genesis_object_id)
    VALUES($1,$2,'active',now(),repeat('c',64),3,1,$3)`, [workspaceId, licenceId, genesisId]);
  const genesis = { body: { purpose: 'ukda.genesis.v1', workspaceId, genesisId, accountId: founder, roles: { owner: ownerRole } }, signature: 'migration-fixture' };
  const enrolment = { body: { purpose: 'ukda.profile-enrolment.v1', transcript: { binding: { workspaceId, accountId: promoted, role: { id: memberRole, revision: '1' } } } }, signature: 'migration-fixture' };
  const promotedOwner = { body: { purpose: 'ukda.owner-promotion.v1', transcript: { binding: { workspaceId, accountId: promoted, role: { id: ownerRole, revision: '1' } } } }, signature: 'migration-fixture' };
  for (const [sequence, id, hash, value] of [
    [1, genesisId, 'a', genesis], [2, memberAssignment, 'b', enrolment], [3, promotion, 'c', promotedOwner],
  ] as const) {
    await c.query(`INSERT INTO ${schema}.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
      VALUES($1,$2,$3,$4,$5,$6,'committed',$7)`, [workspaceId, id, sequence === 1 ? 'genesis' : 'signed_grant', hash.repeat(64), value, randomUUID(), sequence]);
    await c.query(`INSERT INTO ${schema}.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition)
      VALUES($1,$2,$3,$4,$5,'fixture','service',$6)`, [workspaceId, sequence, randomUUID(), (sequence === 1 ? '0' : sequence === 2 ? 'a' : 'b').repeat(64), hash.repeat(64), sequence === 1 ? { genesis: value } : value]);
  }
  for (const [roleId, template] of [[ownerRole, 'owner'], [memberRole, 'member']]) {
    await c.query(`INSERT INTO ${schema}.roles(workspace_id,role_id,template,permissions,definition_object_id,security_version)
      VALUES($1,$2,$3,ARRAY['read_project'],$4,1)`, [workspaceId, roleId, template, genesisId]);
  }
  for (const profileId of [founder, promoted, pending, unbound]) {
    await c.query(`INSERT INTO ${schema}.profiles(workspace_id,profile_id,state,credential_generation,opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers)
      VALUES($1,$2,$3,1,'Zml4dHVyZQ','fixture','fixture','{}')`, [workspaceId, profileId, profileId === pending ? 'pending' : 'active']);
  }
  // Neither a pending signed-looking payload nor a committed object absent from
  // the journal may create authority. A newer staged change cannot undo promotion.
  for (const [accountId, state, hash] of [[pending, 'staged', 'd'], [promoted, 'staged', 'e'], [unbound, 'committed', 'f']] as const) {
    const value = { body: { purpose: 'ukda.profile-enrolment.v1', transcript: { binding: { workspaceId, accountId, role: { id: memberRole, revision: '1' } } } }, signature: 'migration-fixture' };
    await c.query(`INSERT INTO ${schema}.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
      VALUES($1,$2,'signed_grant',$3,$4,$5,$6,$7)`, [workspaceId, randomUUID(), hash.repeat(64), value, randomUUID(), state, state === 'committed' ? 3 : null]);
  }
  await c.query('SET CONSTRAINTS ALL IMMEDIATE');
  const immutable = async () => ({
    objects: (await c.query(`SELECT * FROM ${schema}.staged_objects ORDER BY object_id`)).rows,
    transitions: (await c.query(`SELECT * FROM ${schema}.security_transitions ORDER BY sequence`)).rows,
  });
  const before = await immutable();
  await c.query(await migration('007_profile_roles.sql'));
  assert.deepEqual(await immutable(), before);
  const assignments = (await c.query(`SELECT profile_id,role_id,role_revision,role_assignment_object_id FROM ${schema}.profiles`)).rows;
  const assignment = (id: string) => {
    const row = assignments.find((p) => p.profile_id === id)!;
    return [row.role_id, row.role_revision, row.role_assignment_object_id];
  };
  assert.deepEqual(assignment(founder), [ownerRole, '1', genesisId]);
  assert.deepEqual(assignment(promoted), [ownerRole, '1', promotion]);
  assert.deepEqual(assignment(pending), [null, null, null]);
  assert.deepEqual(assignment(unbound), [null, null, null]);
});

import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { createDatabases, transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { dataTransaction, tenantTransaction } from '../src/persistence.js';
import { projectAuthoritativeWorkspace, withSecurityFence, BUILTIN_ROLE_PERMISSIONS } from '../src/modules/identity/projection.js';
import { initializeAccessAuthority } from '../src/modules/identity/access-projection.js';
import { genesisBody } from '../src/shared/activation.js';
import { initialContentHeader, type ActivationTranscript } from '../src/shared/activation.js';
import { capabilities } from '../src/shared/contracts.js';
import { digestObject } from '../src/shared/crypto.js';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}
async function eventually(check: () => Promise<boolean>) {
  const deadline = Date.now() + 5_000;
  while (!await check()) {
    if (Date.now() > deadline) throw new Error('Timed out waiting for fence contention');
    await delay(10);
  }
}

async function fixture(t: TestContext, pending = false) {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const appAdminUrl = process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ?? local.ADMIN_DATABASE_URL;
  const controlAdminUrl = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(appAdminUrl && controlAdminUrl, 'Security fence tests require explicit fixture admin credentials');
  const admin = { application: new pg.Pool({ connectionString: appAdminUrl }), control: new pg.Pool({ connectionString: controlAdminUrl }) };
  const db = createDatabases(loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' }));
  const workspaceId = randomUUID(), profileId = randomUUID(), licenceId = randomUUID(), operationId = randomUUID();
  const roles = { owner: randomUUID(), manager: randomUUID(), member: randomUUID(), viewer: randomUUID() };
  const transcript: ActivationTranscript = {
    version: 1, purpose: 'ukda.activation-transcript.v1', workspaceId, accountId: profileId, operationId,
    activationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1', origin: 'https://fixture.example',
    device: { id: randomUUID(), signingPublicKey: randomBytes(32).toString('base64url'), recipientPublicKey: randomBytes(32).toString('base64url') },
    recovery: { id: randomUUID(), signingPublicKey: randomBytes(32).toString('base64url'), recipientPublicKey: randomBytes(32).toString('base64url') },
    genesisId: randomUUID(), custodyId: randomUUID(), deviceEnvelopeId: randomUUID(), recoveryEnvelopeId: randomUUID(), roles,
    opaque: { configId: 'ukda.opaque.ristretto255.argon2id-m64-t3-p4.v1', setupId: 'fixture', serverStaticPublicKey: randomBytes(32).toString('base64url'), identifiers: { client: profileId, server: 'fixture' }, keyStretching: 'memory-constrained' },
    registrationDigest: 'b'.repeat(64), ownerPermissions: [...capabilities],
  };
  // Synthetic encrypted bytes test projection and isolation, not cryptographic authenticity.
  const envelope = (kind: 'workspace' | 'profile' | 'custody') => ({ header: initialContentHeader(transcript, kind), nonce: randomBytes(24).toString('base64url'), ciphertext: randomBytes(48).toString('base64url'), signature: randomBytes(64).toString('base64url') });
  const workspaceEnvelope = envelope('workspace'), profileEnvelope = envelope('profile');
  const manifest = [
    { id: workspaceId, kind: 'encrypted_workspace' }, { id: profileId, kind: 'encrypted_profile' },
    { id: transcript.custodyId, kind: 'custody_manifest' }, { id: transcript.deviceEnvelopeId, kind: 'key_envelope' },
    { id: transcript.recoveryEnvelopeId, kind: 'key_envelope' },
  ].map((entry) => ({ ...entry, digest: randomBytes(32).toString('hex') }));
  const genesis = { body: { ...transcript, purpose: 'ukda.genesis.v1', transcriptDigest: 'c'.repeat(64), manifest }, signature: randomBytes(64).toString('base64url') };
  t.after(async () => {
    try {
      await admin.application.query('SELECT graphile_worker.remove_job($1)', [`activation:${workspaceId}`]);
      await transaction(admin.application, async (client) => {
        for (const table of ['notifications', 'notification_preferences', 'blockers', 'task_assignments', 'tasks', 'milestones', 'project_phases', 'project_access', 'projects', 'profiles', 'roles', 'workspaces']) await client.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [workspaceId]);
      });
      await admin.control.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [workspaceId]);
      await admin.control.query('DELETE FROM security.licences WHERE licence_id=$1', [licenceId]);
    } finally { await Promise.allSettled([db.close(), admin.application.end(), admin.control.end()]); }
  });
  await transaction(admin.control, async (client) => {
    await client.query(`INSERT INTO security.licences(licence_id,verification_digest,verification_key_id)
      VALUES($1,$2,'cp03-fence-fixture')`, [licenceId, randomBytes(32)]);
    await client.query(`INSERT INTO security.workspaces(workspace_id,licence_id,lifecycle,security_head,security_version,activated_at)
      VALUES($1,$2,$3,$4,$5,$6)`, [workspaceId, licenceId, pending ? 'pending_activation' : 'active', (pending ? '0' : 'a').repeat(64), pending ? '0' : '1', pending ? null : new Date()]);
    if (pending) return;
    await client.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition)
      VALUES($1,1,$2,repeat('0',64),repeat('a',64),'fixture','service','{}')`, [workspaceId, operationId]);
    for (const [id, kind, value] of [[transcript.genesisId, 'genesis', genesis], [workspaceId, 'encrypted_workspace', workspaceEnvelope], [profileId, 'encrypted_profile', profileEnvelope], [transcript.custodyId, 'custody_manifest', envelope('custody')]] as const) {
      await client.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
        VALUES($1,$2,$3,$4,$5,$6,'committed',1)`, [workspaceId, id, kind, await digestObject(value), value, operationId]);
    }
    await initializeAccessAuthority(client, genesisBody.parse(genesis.body));
    await client.query('UPDATE security.workspaces SET genesis_object_id=$2,current_custody_manifest_object_id=$3,custody_epoch=1,ownership_version=1 WHERE workspace_id=$1', [workspaceId, transcript.genesisId, transcript.custodyId]);
    await client.query(`INSERT INTO security.profiles(workspace_id,profile_id,state,is_owner,owner_ready_at,profile_object_id,credential_generation,
      opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers)
      VALUES($1,$2,'active',true,now(),$2,1,'AA','fixture','fixture','{}')`, [workspaceId, profileId]);
  });
  return { db, admin, workspaceId, profileId, roles, operationId, transcript, workspaceEnvelope, profileEnvelope,
    principal: { workspaceId, profileId, securityHead: 'a'.repeat(64), securityVersion: '1', dataGeneration: '1' } };
}

test('CP03: fence drains an in-flight data read and survives action failure', { timeout: 15_000 }, async (t) => {
  const f = await fixture(t);
  await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  const entered = deferred(), releaseRead = deferred();
  const reading = dataTransaction(f.db, f.principal, async () => { entered.resolve(); await releaseRead.promise; return 'read completed'; });
  await entered.promise;
  let actionEntered = false;
  const failure = new Error('synthetic interruption after durable fence');
  const fencing = withSecurityFence(f.db, f.workspaceId, async () => {
    actionEntered = true;
    const row = (await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0];
    assert.equal(row.fence_closed, true);
    throw failure;
  });
  const failureObserved = assert.rejects(fencing, (error: unknown) => error === failure);
  try {
    await eventually(async () => (await f.admin.application.query(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted
      AND classid=((hashtextextended($1,0)>>32)&4294967295)::oid AND objid=(hashtextextended($1,0)&4294967295)::oid AND objsubid=1) AS waiting`, [`ukda.workspace:${f.workspaceId}`])).rows[0]?.waiting === true);
    assert.equal(actionEntered, false);
    assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.fence_closed, false);
  } finally { releaseRead.resolve(); }
  assert.equal(await reading, 'read completed');
  await failureObserved;
  assert.equal(actionEntered, true);
  await assert.rejects(dataTransaction(f.db, f.principal, async () => 'must not run'), (error: unknown) => error instanceof AppError && error.code === 'SECURITY_FENCED');
  const probe = await f.db.application.connect();
  try {
    assert.equal((await probe.query('SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS acquired', [`ukda.workspace:${f.workspaceId}`])).rows[0]?.acquired, true);
    await probe.query('SELECT pg_advisory_unlock(hashtextextended($1,0))', [`ukda.workspace:${f.workspaceId}`]);
  } finally { probe.release(true); }
  const recovered = await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  assert.equal(recovered.state, 'ready');
  assert.equal(await dataTransaction(f.db, f.principal, async () => 'allowed'), 'allowed');
  await assert.rejects(withSecurityFence(f.db, f.workspaceId, async (client) => {
    await projectAuthoritativeWorkspace(f.db, f.workspaceId, client);
    throw failure;
  }), (error: unknown) => error === failure);
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.fence_closed, true);
});

test('CP03/06: projection repairs role authority and preserves later encrypted workspace edits on retries', async (t) => {
  const f = await fixture(t);
  const first = await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  assert.deepEqual(first, { state: 'ready', securityHead: 'a'.repeat(64), securityVersion: '1', dataGeneration: '1' });
  await tenantTransaction(f.db.application, f.workspaceId, f.profileId, async (client) => {
    const roles = (await client.query('SELECT id,template,permissions,encrypted_envelope FROM app.roles WHERE workspace_id=$1', [f.workspaceId])).rows;
    assert.equal(roles.length, 4);
    for (const role of roles) {
      assert.equal(role.id, f.roles[role.template as keyof typeof f.roles]);
      assert.deepEqual(role.permissions, BUILTIN_ROLE_PERMISSIONS[role.template as keyof typeof BUILTIN_ROLE_PERMISSIONS]);
      assert.deepEqual(role.encrypted_envelope, {});
    }
    const profile = (await client.query('SELECT state,is_owner,encrypted_envelope FROM app.profiles WHERE workspace_id=$1', [f.workspaceId])).rows[0];
    assert.equal(profile.state, 'active'); assert.equal(profile.is_owner, true); assert.deepEqual(profile.encrypted_envelope, f.profileEnvelope);
    assert.deepEqual((await client.query('SELECT encrypted_envelope FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.encrypted_envelope, f.workspaceEnvelope);
    await client.query("UPDATE app.roles SET permissions=ARRAY['read_project'] WHERE workspace_id=$1 AND id=$2", [f.workspaceId, f.roles.manager]);
    await client.query(`UPDATE app.workspaces SET encrypted_envelope=$2 WHERE workspace_id=$1`, [f.workspaceId, { ciphertext: randomBytes(32).toString('base64url') }]);
  });
  const before = (await f.admin.application.query('SELECT encrypted_envelope FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.encrypted_envelope;
  await withSecurityFence(f.db, f.workspaceId, async (client) => {
    await f.admin.control.query(`UPDATE security.workspaces SET security_version=2,security_head=repeat('b',64),licence_state='restricted',content_maintenance=true WHERE workspace_id=$1`, [f.workspaceId]);
    assert.equal((await projectAuthoritativeWorkspace(f.db, f.workspaceId, client)).state, 'ready');
  });
  await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  const workspace = (await f.admin.application.query('SELECT * FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0];
  assert.equal(workspace.fence_closed, false); assert.equal(workspace.licence_state, 'restricted');
  assert.equal(workspace.content_maintenance, true); assert.equal(workspace.security_version, '2');
  assert.deepEqual(workspace.encrypted_envelope, before);
  assert.deepEqual((await f.admin.application.query('SELECT permissions FROM app.roles WHERE workspace_id=$1 AND id=$2', [f.workspaceId, f.roles.manager])).rows[0]?.permissions, BUILTIN_ROLE_PERMISSIONS.manager);
  const currentPrincipal = { ...f.principal, securityHead: 'b'.repeat(64), securityVersion: '2' };
  assert.equal(await dataTransaction(f.db, currentPrincipal, async () => 'read allowed'), 'read allowed');
  await assert.rejects(dataTransaction(f.db, currentPrincipal, async () => 'write forbidden', { write: true }), (error: unknown) => error instanceof AppError && error.code === 'WORKSPACE_RESTRICTED');
});

async function projectFixture(t: TestContext) {
  const f = await fixture(t);
  await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  const memberId = randomUUID(), projectId = randomUUID(), memberGrantId = randomUUID(), ownerGrantId = randomUUID();
  const memberEnvelope = { ...f.profileEnvelope, header: { ...f.profileEnvelope.header, recordId: memberId } };
  await transaction(f.admin.control, async (control) => {
    await control.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,
      staged_operation_id,state,committed_security_version) VALUES($1,$2,'encrypted_profile',$3,$4,$5,'committed',1)`,
    [f.workspaceId, memberId, await digestObject(memberEnvelope), memberEnvelope, f.operationId]);
    await control.query(`INSERT INTO security.profiles(workspace_id,profile_id,state,profile_object_id,credential_generation,
      opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers)
      VALUES($1,$2,'active',$2,1,'AA','fixture','fixture','{}')`, [f.workspaceId, memberId]);
    await control.query(`INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version)
      VALUES($1,'project',$2,1,$3,1)`, [f.workspaceId, projectId, f.transcript.custodyId]);
    for (const [id, account, role, permissions] of [
      [ownerGrantId, f.profileId, f.roles.owner, [...capabilities]],
      [memberGrantId, memberId, f.roles.member, ['read_project']],
    ] as const) await control.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,scope_id,
      generation,permissions,state,signed_grant_object_id,key_manifest_object_id,security_version,activated_at,role_id,role_revision)
      VALUES($1,$2,$3,'project','project',$4,1,$5,'active',$6,$7,1,now(),$8,1)`,
    [f.workspaceId, id, account, projectId, permissions, f.transcript.genesisId, f.transcript.custodyId, role]);
  });
  // Projection fixtures represent already-validated authority. Crypto and enrolment are tested separately.
  const encryptedProject = { ciphertext: randomBytes(40).toString('base64url') };
  await f.admin.application.query('INSERT INTO app.projects(workspace_id,id,encrypted_envelope) VALUES($1,$2,$3)', [f.workspaceId, projectId, encryptedProject]);
  await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  return { ...f, memberId, projectId, memberGrantId, ownerGrantId, encryptedProject };
}

test('CP06: projected access uses its signed permission snapshot and mirrors write epochs without rewriting ciphertext', async (t) => {
  const f = await projectFixture(t);
  const access = (await f.admin.application.query('SELECT * FROM app.project_access WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.memberId])).rows[0];
  assert.deepEqual(access.permissions, ['read_project']);
  assert.equal(access.grant_id, f.memberGrantId);
  assert.equal(access.revision, '1');
  assert.equal(access.role_revision, '1');
  assert.equal((await f.admin.application.query('SELECT permissions FROM app.roles WHERE workspace_id=$1 AND id=$2', [f.workspaceId, f.roles.member])).rows[0]?.permissions.includes('create_tasks'), true);
  await tenantTransaction(f.db.application, f.workspaceId, f.memberId, async (application) => {
    assert.equal((await application.query('SELECT id FROM app.projects WHERE workspace_id=$1', [f.workspaceId])).rowCount, 1);
  });
  await withSecurityFence(f.db, f.workspaceId, async (application) => {
    await transaction(f.admin.control, async (control) => {
      await control.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition)
        VALUES($1,2,$2,repeat('a',64),repeat('b',64),'fixture','service','{}')`, [f.workspaceId, randomUUID()]);
      await control.query("UPDATE security.scope_heads SET key_epoch=2,security_version=2 WHERE workspace_id=$1 AND scope_kind='project' AND scope_id=$2", [f.workspaceId, f.projectId]);
      await control.query("UPDATE security.grants SET key_epoch=2,security_version=2 WHERE workspace_id=$1 AND scope_id=$2", [f.workspaceId, f.projectId]);
      await control.query("UPDATE security.workspaces SET security_version=2,security_head=repeat('b',64) WHERE workspace_id=$1", [f.workspaceId]);
    });
    await projectAuthoritativeWorkspace(f.db, f.workspaceId, application);
  });
  const project = (await f.admin.application.query('SELECT key_epoch,encrypted_envelope FROM app.projects WHERE workspace_id=$1 AND id=$2', [f.workspaceId, f.projectId])).rows[0];
  assert.equal(project.key_epoch, '1');
  assert.deepEqual(project.encrypted_envelope, f.encryptedProject);
  assert.equal((await f.admin.application.query("SELECT key_epoch FROM app.scope_heads WHERE workspace_id=$1 AND scope_kind='project'", [f.workspaceId])).rows[0]?.key_epoch, '2');
  await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS count FROM app.project_access WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.count, 2);
});

test('CP06: access removal clears live responsibilities before fence opens and preserves ciphertext and authorship', async (t) => {
  const f = await projectFixture(t), taskId = randomUUID(), phaseId = randomUUID(), milestoneId = randomUUID(), blockerId = randomUUID();
  const encrypted = { ciphertext: randomBytes(40).toString('base64url') };
  await tenantTransaction(f.db.application, f.workspaceId, f.profileId, async (application) => {
    await application.query('UPDATE app.projects SET manager_profile_id=$3 WHERE workspace_id=$1 AND id=$2', [f.workspaceId, f.projectId, f.memberId]);
    await application.query(`INSERT INTO app.project_phases(workspace_id,id,project_id,lead_profile_id,encrypted_envelope)
      VALUES($1,$2,$3,$4,$5)`, [f.workspaceId, phaseId, f.projectId, f.memberId, encrypted]);
    await application.query(`INSERT INTO app.milestones(workspace_id,id,project_id,owner_profile_id,encrypted_envelope)
      VALUES($1,$2,$3,$4,$5)`, [f.workspaceId, milestoneId, f.projectId, f.memberId, encrypted]);
    await application.query(`INSERT INTO app.tasks(workspace_id,id,project_id,lead_profile_id,reviewer_profile_id,encrypted_envelope)
      VALUES($1,$2,$3,$4,$4,$5)`, [f.workspaceId, taskId, f.projectId, f.memberId, encrypted]);
    await application.query(`INSERT INTO app.task_assignments(workspace_id,task_id,project_id,member_id,assigned_by)
      VALUES($1,$2,$3,$4,$5)`, [f.workspaceId, taskId, f.projectId, f.memberId, f.profileId]);
    await application.query(`INSERT INTO app.blockers(workspace_id,id,project_id,task_id,responsible_profile_id,created_by,encrypted_envelope)
      VALUES($1,$2,$3,$4,$5,$5,$6)`, [f.workspaceId, blockerId, f.projectId, taskId, f.memberId, encrypted]);
  });
  await withSecurityFence(f.db, f.workspaceId, async (application) => {
    await f.admin.control.query("UPDATE security.grants SET state='revoked',revoked_at=now() WHERE workspace_id=$1 AND grant_id=$2", [f.workspaceId, f.memberGrantId]);
    await projectAuthoritativeWorkspace(f.db, f.workspaceId, application);
  });
  const task = (await f.admin.application.query('SELECT * FROM app.tasks WHERE workspace_id=$1 AND id=$2', [f.workspaceId, taskId])).rows[0];
  assert.equal(task.lead_profile_id, null); assert.equal(task.reviewer_profile_id, null);
  assert.deepEqual(task.encrypted_envelope, encrypted); assert.equal(task.revision, '1');
  assert.equal((await f.admin.application.query('SELECT * FROM app.task_assignments WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  for (const [table, column] of [['projects', 'manager_profile_id'], ['project_phases', 'lead_profile_id'], ['milestones', 'owner_profile_id'], ['blockers', 'responsible_profile_id']] as const) {
    assert.equal((await f.admin.application.query(`SELECT ${column} FROM app.${table} WHERE workspace_id=$1`, [f.workspaceId])).rows[0]?.[column], null);
  }
  const blocker = (await f.admin.application.query('SELECT created_by,encrypted_envelope FROM app.blockers WHERE workspace_id=$1', [f.workspaceId])).rows[0];
  assert.equal(blocker.created_by, f.memberId); assert.deepEqual(blocker.encrypted_envelope, encrypted);
  await tenantTransaction(f.db.application, f.workspaceId, f.memberId, async (application) => {
    assert.equal((await application.query('SELECT id FROM app.tasks WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
    assert.equal((await application.query('SELECT id FROM app.notifications WHERE workspace_id=$1', [f.workspaceId])).rowCount, 0);
  });
  await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  await tenantTransaction(f.db.application, f.workspaceId, f.profileId, async (application) => {
    const notices = (await application.query('SELECT * FROM app.notifications WHERE workspace_id=$1', [f.workspaceId])).rows;
    assert.equal(notices.length, 1, 'reprojection cannot duplicate the removal notice');
    assert.equal(notices[0].recipient_profile_id, f.profileId); assert.equal(notices[0].project_id, f.projectId);
    assert.equal(notices[0].event_type, 'security.work_unassigned'); assert.equal(notices[0].record_id, taskId);
    assert.deepEqual(notices[0].encrypted_envelope, {}, 'notice stores opaque references, not task content or names');
  });
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.fence_closed, false);
});

test('CP06: removal notices select newly unassigned work, survive mute and roll back with failed projection', async (t) => {
  const f = await projectFixture(t);
  const managerId = randomUUID(), managerEnvelope = { ...f.profileEnvelope, header: { ...f.profileEnvelope.header, recordId: managerId } };
  await transaction(f.admin.control, async (control) => {
    await control.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,
      staged_operation_id,state,committed_security_version) VALUES($1,$2,'encrypted_profile',$3,$4,$5,'committed',1)`,
    [f.workspaceId, managerId, await digestObject(managerEnvelope), managerEnvelope, f.operationId]);
    await control.query(`INSERT INTO security.profiles(workspace_id,profile_id,state,profile_object_id,credential_generation,
      opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers)
      VALUES($1,$2,'active',$2,1,'AA','fixture','fixture','{}')`, [f.workspaceId, managerId]);
    await control.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,scope_id,
      generation,permissions,state,signed_grant_object_id,key_manifest_object_id,security_version,activated_at,role_id,role_revision)
      VALUES($1,$2,$3,'project','project',$4,1,$5,'active',$6,$7,1,now(),$8,1)`,
    [f.workspaceId, randomUUID(), managerId, f.projectId, [...capabilities], f.transcript.genesisId, f.transcript.custodyId, f.roles.manager]);
  });
  await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  const [newly, already, shared, closed] = [randomUUID(), randomUUID(), randomUUID(), randomUUID()] as const;
  await tenantTransaction(f.db.application, f.workspaceId, f.profileId, async (application) => {
    await application.query('UPDATE app.projects SET manager_profile_id=$3 WHERE workspace_id=$1 AND id=$2', [f.workspaceId, f.projectId, managerId]);
    for (const id of [newly, already, shared, closed]) await application.query(`INSERT INTO app.tasks
      (workspace_id,id,project_id,state,encrypted_envelope) VALUES($1,$2,$3,$4,'{}')`,
    [f.workspaceId, id, f.projectId, id === closed ? 'done' : 'todo']);
    for (const id of [newly, shared, closed]) await application.query(`INSERT INTO app.task_assignments
      (workspace_id,task_id,project_id,member_id,assigned_by) VALUES($1,$2,$3,$4,$5)`,
    [f.workspaceId, id, f.projectId, f.memberId, f.profileId]);
    await application.query(`INSERT INTO app.task_assignments(workspace_id,task_id,project_id,member_id,assigned_by)
      VALUES($1,$2,$3,$4,$4)`, [f.workspaceId, shared, f.projectId, f.profileId]);
    await application.query(`INSERT INTO app.notification_preferences(workspace_id,id,profile_id,project_id,muted)
      VALUES($1,$2,$3,$4,true)`, [f.workspaceId, randomUUID(), f.profileId, f.projectId]);
  });
  // Force the notification write to fail after relationship cleanup inside the
  // same application transaction. Its rollback must preserve both or neither.
  await assert.rejects(withSecurityFence(f.db, f.workspaceId, async (application) => {
    await f.admin.control.query("UPDATE security.grants SET state='revoked',revoked_at=now() WHERE workspace_id=$1 AND grant_id=$2", [f.workspaceId, f.memberGrantId]);
    const query = application.query;
    application.query = ((...args: unknown[]) => {
      if (typeof args[0] === 'string' && args[0].includes('INSERT INTO app.notifications')) throw new Error('notification write interrupted');
      return Reflect.apply(query, application, args);
    }) as typeof application.query;
    try { await projectAuthoritativeWorkspace(f.db, f.workspaceId, application); }
    finally { application.query = query; }
  }), /notification write interrupted/);
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.task_assignments WHERE workspace_id=$1', [f.workspaceId])).rows[0].n, 4);
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.notifications WHERE workspace_id=$1', [f.workspaceId])).rows[0].n, 0);
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].fence_closed, true);
  await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  const notices = (await f.admin.application.query('SELECT record_id,recipient_profile_id,event_id FROM app.notifications WHERE workspace_id=$1', [f.workspaceId])).rows;
  assert.equal(notices.length, 2); assert.ok(notices.every((notice) => notice.record_id === newly));
  assert.deepEqual(new Set(notices.map((notice) => notice.recipient_profile_id)), new Set([managerId, f.profileId]));
  assert.equal(new Set(notices.map((notice) => notice.event_id)).size, 1, 'same event is deduplicated separately for each recipient');
  await tenantTransaction(f.db.application, f.workspaceId, managerId, async (application) => {
    assert.equal((await application.query('SELECT id FROM app.notifications WHERE workspace_id=$1', [f.workspaceId])).rowCount, 1);
  });
  assert.equal((await f.admin.application.query('SELECT count(*)::int AS n FROM app.task_assignments WHERE workspace_id=$1', [f.workspaceId])).rows[0].n, 1);
  assert.equal((await f.admin.application.query('SELECT state FROM app.tasks WHERE workspace_id=$1 AND id=$2', [f.workspaceId, closed])).rows[0].state, 'done');
});

test('CP06: missing committed keys keep prior access projection fenced until repaired', async (t) => {
  const f = await projectFixture(t);
  await assert.rejects(withSecurityFence(f.db, f.workspaceId, async (application) => {
    await f.admin.control.query('UPDATE security.grants SET key_manifest_object_id=NULL WHERE workspace_id=$1 AND grant_id=$2', [f.workspaceId, f.memberGrantId]);
    await projectAuthoritativeWorkspace(f.db, f.workspaceId, application);
  }), (error: unknown) => error instanceof AppError && error.code === 'SECURITY_FENCED');
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.fence_closed, true);
  await assert.rejects(dataTransaction(f.db, f.principal, async () => 'must not run'), (error: unknown) => error instanceof AppError && error.code === 'SECURITY_FENCED');
  await withSecurityFence(f.db, f.workspaceId, async (application) => {
    await f.admin.control.query('UPDATE security.grants SET key_manifest_object_id=$3 WHERE workspace_id=$1 AND grant_id=$2', [f.workspaceId, f.memberGrantId, f.transcript.custodyId]);
    await projectAuthoritativeWorkspace(f.db, f.workspaceId, application);
  });
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.fence_closed, false);
});

test('CP03: a committed authority decision remains committed when projection fails, and a later retry repairs it', async (t) => {
  const f = await fixture(t);
  await projectAuthoritativeWorkspace(f.db, f.workspaceId);
  const wrongObjectId = randomUUID(), operationId = randomUUID();
  const wrongEnvelope = { ...f.profileEnvelope, header: { ...f.profileEnvelope.header, recordId: randomUUID() } };
  await assert.rejects(withSecurityFence(f.db, f.workspaceId, async (client) => {
    await transaction(f.admin.control, async (control) => {
      await control.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition)
        VALUES($1,2,$2,repeat('a',64),repeat('b',64),'fixture','service','{}')`, [f.workspaceId, operationId]);
      await control.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
        VALUES($1,$2,'encrypted_profile',$3,$4,$5,'committed',2)`, [f.workspaceId, wrongObjectId, await digestObject(wrongEnvelope), wrongEnvelope, operationId]);
      await control.query('UPDATE security.profiles SET profile_object_id=$2 WHERE workspace_id=$1 AND profile_id=$3', [f.workspaceId, wrongObjectId, f.profileId]);
      await control.query("UPDATE security.workspaces SET security_version=2,security_head=repeat('b',64) WHERE workspace_id=$1", [f.workspaceId]);
    });
    return projectAuthoritativeWorkspace(f.db, f.workspaceId, client);
  }), (error: unknown) => error instanceof AppError && error.code === 'SECURITY_FENCED');
  const application = (await f.admin.application.query('SELECT fence_closed,security_version FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0];
  assert.deepEqual(application, { fence_closed: true, security_version: '1' });
  assert.equal((await f.admin.control.query('SELECT security_version FROM security.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.security_version, '2');
  await withSecurityFence(f.db, f.workspaceId, async (client) => {
    await transaction(f.admin.control, async (control) => {
      await control.query('UPDATE security.profiles SET profile_object_id=$2 WHERE workspace_id=$1 AND profile_id=$2', [f.workspaceId, f.profileId]);
      await control.query("UPDATE security.workspaces SET security_version=3,security_head=repeat('c',64) WHERE workspace_id=$1", [f.workspaceId]);
    });
    assert.equal((await projectAuthoritativeWorkspace(f.db, f.workspaceId, client)).state, 'ready');
  });
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.fence_closed, false);
});

test('CP03: pending/deleted workspaces stay fenced and an arbitrary application client cannot reopen them', async (t) => {
  const f = await fixture(t, true);
  assert.deepEqual(await projectAuthoritativeWorkspace(f.db, f.workspaceId), { state: 'pending' });
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.fence_closed, true);
  // Inspect from another connection before the authority action runs. A live worker
  // may claim this job but cannot pass the held session fence before this assertion.
  await withSecurityFence(f.db, f.workspaceId, async () => {
    const job = (await f.admin.application.query('SELECT payload,max_attempts FROM graphile_worker._private_jobs WHERE key=$1', [`activation:${f.workspaceId}`])).rows[0];
    assert.deepEqual(job?.payload, { workspaceId: f.workspaceId });
    assert.equal(job?.max_attempts, 10);
    assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.fence_closed, true);
  }, { enqueueActivationProjection: true });
  const unheld = await f.db.application.connect();
  try { await assert.rejects(projectAuthoritativeWorkspace(f.db, f.workspaceId, unheld), (error: unknown) => error instanceof AppError && error.code === 'SECURITY_FENCED'); }
  finally { unheld.release(); }
  await f.admin.control.query("UPDATE security.workspaces SET lifecycle='deleted',deleted_at=now() WHERE workspace_id=$1", [f.workspaceId]);
  assert.deepEqual(await projectAuthoritativeWorkspace(f.db, f.workspaceId), { state: 'deleted' });
  assert.equal((await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0]?.fence_closed, true);
});

import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import pg from 'pg';
import sodium from 'libsodium-wrappers';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createDatabases, transaction } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { tenantTransaction, dataTransaction, type DataPrincipal } from '../src/persistence.js';

// Credentials remain private to fixture setup; runtime config never contains an admin URL.
async function admins() {
  const local = parseEnv(await readFile(new URL('../../.env.admin', import.meta.url), 'utf8').catch(() => ''));
  const application = process.env.MIGRATION_TEST_ADMIN_DATABASE_URL ?? local.ADMIN_DATABASE_URL;
  const control = process.env.PERSISTENCE_TEST_CONTROL_ADMIN_DATABASE_URL ?? local.CONTROL_ADMIN_DATABASE_URL;
  assert.ok(application && control, 'Persistence integration tests require explicit fixture admin credentials');
  return { application: new pg.Pool({ connectionString: application }), control: new pg.Pool({ connectionString: control }) };
}

async function encryptedFixture() {
  await sodium.ready;
  const secret = 'private-project-label-' + randomUUID();
  const key = sodium.randombytes_buf(32);
  const nonce = sodium.randombytes_buf(24);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(new TextEncoder().encode(secret), null, null, nonce, key);
  const encrypted = { ciphertext: sodium.to_base64(ciphertext, sodium.base64_variants.URLSAFE_NO_PADDING), nonce: sodium.to_base64(nonce, sodium.base64_variants.URLSAFE_NO_PADDING) };
  // The fixture deliberately keeps its content key only in this client-side closure.
  return { secret, key, encrypted, decrypt: () => new TextDecoder().decode(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, key)) };
}

async function fixture(t: TestContext) {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', LOG_LEVEL: 'silent' });
  const db = createDatabases(config);
  const admin = await admins();
  const encrypted = await encryptedFixture();
  const states = [0, 1].map(() => ({ workspaceId: randomUUID(), profileId: randomUUID(),
    strangerId: randomUUID(), projectId: randomUUID(), secondProjectId: randomUUID(), roleId: randomUUID(),
    phaseId: randomUUID(), secondPhaseId: randomUUID(), milestoneId: randomUUID(), taskId: randomUUID(),
    licenceId: randomUUID(), securityHead: 'a'.repeat(64), securityVersion: '1', dataGeneration: '1' }));
  t.after(async () => {
    try {
      for (const state of states) {
        await transaction(admin.application, async (c) => {
          for (const table of ['notifications','summaries','team_members','teams','task_assignments','tasks','milestones','project_phases','project_access','projects','profiles','roles','workspaces']) {
            await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [state.workspaceId]);
          }
        });
        await admin.control.query('DELETE FROM security.workspaces WHERE workspace_id=$1', [state.workspaceId]);
        await admin.control.query('DELETE FROM security.licences WHERE licence_id=$1', [state.licenceId]);
      }
    } finally { await Promise.allSettled([db.close(), admin.application.end(), admin.control.end()]); }
  });
  for (const state of states) {
    await transaction(admin.control, async (c) => {
      await c.query(`INSERT INTO security.licences(licence_id,verification_digest,verification_key_id) VALUES($1,$2,'fixture')`, [state.licenceId, sodium.randombytes_buf(32)]);
      await c.query(`INSERT INTO security.workspaces(workspace_id,licence_id,lifecycle,security_head,security_version,activated_at) VALUES($1,$2,'active',$3,1,now())`, [state.workspaceId,state.licenceId,state.securityHead]);
    });
    await transaction(admin.application, async (c) => {
      await c.query(`INSERT INTO app.workspaces(workspace_id,security_head,security_version,fence_closed,lifecycle) VALUES($1,$2,1,false,'active')`, [state.workspaceId,state.securityHead]);
      await c.query(`INSERT INTO app.roles(workspace_id,id,permissions,encrypted_envelope) VALUES($1,$2,ARRAY['read_project','create_tasks','edit_assigned_tasks'], $3)`, [state.workspaceId,state.roleId,encrypted.encrypted]);
      for (const id of [state.profileId,state.strangerId]) await c.query(`INSERT INTO app.profiles(workspace_id,id,state,encrypted_envelope) VALUES($1,$2,'active',$3)`, [state.workspaceId,id,encrypted.encrypted]);
      for (const id of [state.projectId,state.secondProjectId]) {
        await c.query(`INSERT INTO app.projects(workspace_id,id,encrypted_envelope) VALUES($1,$2,$3)`, [state.workspaceId,id,encrypted.encrypted]);
        await c.query(`INSERT INTO app.project_access(workspace_id,project_id,profile_id,state,role_id,permissions)
          VALUES($1,$2,$3,'active',$4,ARRAY['read_project','create_tasks','edit_assigned_tasks'])`, [state.workspaceId,id,state.profileId,state.roleId]);
      }
      for (const id of [state.phaseId,state.secondPhaseId]) await c.query(`INSERT INTO app.project_phases(workspace_id,project_id,id,encrypted_envelope) VALUES($1,$2,$3,$4)`, [state.workspaceId,state.projectId,id,encrypted.encrypted]);
      await c.query(`INSERT INTO app.milestones(workspace_id,project_id,id,phase_id,encrypted_envelope) VALUES($1,$2,$3,$4,$5)`, [state.workspaceId,state.projectId,state.milestoneId,state.phaseId,encrypted.encrypted]);
      await c.query(`INSERT INTO app.tasks(workspace_id,project_id,id,phase_id,milestone_id,encrypted_envelope) VALUES($1,$2,$3,$4,$5,$6)`, [state.workspaceId,state.projectId,state.taskId,state.phaseId,state.milestoneId,encrypted.encrypted]);
      await c.query(`INSERT INTO app.task_assignments(workspace_id,task_id,member_id,assigned_by,project_id) VALUES($1,$2,$3,$3,$4)`, [state.workspaceId,state.taskId,state.profileId,state.projectId]);
      await c.query(`UPDATE app.tasks SET lead_profile_id=$3 WHERE workspace_id=$1 AND id=$2`, [state.workspaceId,state.taskId,state.profileId]);
      await c.query(`INSERT INTO app.notifications(workspace_id,id,recipient_profile_id,project_id,event_id,event_type) VALUES($1,$2,$3,$4,$5,'task.assigned')`, [state.workspaceId,randomUUID(),state.profileId,state.projectId,randomUUID()]);
      await c.query(`INSERT INTO app.summaries(workspace_id,id,project_id,scope_type,scope_fingerprint,permission_revision,source_revision,calculation_version,calculated_by_profile_id,calculated_at,encrypted_envelope) VALUES($1,$2,$3,'project','fixture',1,1,'1',$4,now(),$5)`, [state.workspaceId,randomUUID(),state.projectId,state.profileId,encrypted.encrypted]);
      const teamId=randomUUID();
      await c.query('INSERT INTO app.teams(workspace_id,id,encrypted_envelope) VALUES($1,$2,$3)',[state.workspaceId,teamId,encrypted.encrypted]);
      await c.query('INSERT INTO app.team_members(workspace_id,team_id,profile_id) VALUES($1,$2,$3)',[state.workspaceId,teamId,state.strangerId]);

    });
  }
  const a = states[0]!; const b = states[1]!;
  return { config, db, admin, encrypted, a, b };
}

function hasPgCode(...codes: string[]) { return (error: unknown) => typeof error === 'object' && error !== null && 'code' in error && codes.includes(String(error.code)); }

test('CP02: actual runtime RLS hides foreign workspaces and unprovisioned projects, and clears pooled context', async (t) => {
  const { db, admin, a, b } = await fixture(t);
  assert.equal((await db.application.query('SELECT * FROM app.projects')).rowCount, 0);
  await tenantTransaction(db.application,a.workspaceId,a.profileId, async (c) => {
    const rows = (await c.query('SELECT workspace_id FROM app.projects')).rows;
    assert.equal(rows.length,2); assert.ok(rows.every((row) => row.workspace_id===a.workspaceId));
    assert.equal((await c.query('SELECT * FROM app.tasks WHERE id=$1',[b.taskId])).rowCount,0);
    assert.equal((await c.query('UPDATE app.tasks SET revision=revision+1 WHERE id=$1',[b.taskId])).rowCount,0);
    for (const table of ['notifications','summaries']) {
      const scoped=(await c.query(`SELECT workspace_id FROM app.${table}`)).rows;
      assert.equal(scoped.length,1); assert.equal(scoped[0]?.workspace_id,a.workspaceId);
    }
  });
  assert.equal((await db.application.query('SELECT * FROM app.projects')).rowCount,0);
  // A workspace team and even an Owner label cannot bypass project key provisioning.
  await admin.application.query('UPDATE app.profiles SET is_owner=true WHERE workspace_id=$1 AND id=$2',[a.workspaceId,a.strangerId]);
  await tenantTransaction(db.application,a.workspaceId,a.strangerId, async (c) => {
    for(const table of ['projects','summaries','notifications']) assert.equal((await c.query(`SELECT * FROM app.${table}`)).rowCount,0);
  });
  const catalog=await db.application.query(`SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,c.relowner=current_user::regrole AS is_owner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='app' AND c.relkind='r'`);
  assert.equal(catalog.rowCount,22);
  for(const table of catalog.rows) { assert.equal(table.relrowsecurity,true); assert.equal(table.relforcerowsecurity,true); assert.equal(table.is_owner,false); }
  await assert.rejects(db.application.query('ALTER TABLE app.tasks DISABLE ROW LEVEL SECURITY'),hasPgCode('42501'));
  await assert.rejects(db.application.query('TRUNCATE app.tasks'),hasPgCode('42501'));

  await assert.rejects(tenantTransaction(db.application,a.workspaceId,a.profileId, async (c) => {
    await c.query(`INSERT INTO app.profiles(workspace_id,id,encrypted_envelope) VALUES($1,$2,'{}')`,[b.workspaceId,randomUUID()]);
  }),hasPgCode('42501'));
});

test('CP02: tenant-aware constraints reject duplicate assignments, foreign links, wrong phases and missing project grants atomically', async (t) => {
  const { db, a, b, encrypted } = await fixture(t);
  const rejected = async (sql: string, params: unknown[], codes=['23503','23514','42501']) => assert.rejects(tenantTransaction(db.application,a.workspaceId,a.profileId, async (c) => { await c.query(sql,params); }),hasPgCode(...codes));
  await rejected('INSERT INTO app.task_assignments(workspace_id,task_id,member_id,assigned_by,project_id) VALUES($1,$2,$3,$3,$4)',[a.workspaceId,a.taskId,a.profileId,a.projectId],['23505']);
  await rejected('INSERT INTO app.task_assignments(workspace_id,task_id,member_id,assigned_by,project_id) VALUES($1,$2,$3,$4,$5)',[a.workspaceId,a.taskId,a.strangerId,a.profileId,a.projectId]);
  await rejected('INSERT INTO app.task_assignments(workspace_id,task_id,member_id,assigned_by,project_id) VALUES($1,$2,$3,$4,$5)',[a.workspaceId,a.taskId,b.profileId,a.profileId,a.projectId]);
  await rejected("UPDATE app.roles SET state='retired' WHERE workspace_id=$1 AND id=$2",[a.workspaceId,a.roleId]);
  await rejected('UPDATE app.tasks SET lead_profile_id=$3 WHERE workspace_id=$1 AND id=$2',[a.workspaceId,a.taskId,a.strangerId]);
  await rejected('UPDATE app.tasks SET milestone_id=$3 WHERE workspace_id=$1 AND id=$2',[a.workspaceId,a.taskId,b.milestoneId]);
  await rejected('UPDATE app.tasks SET project_id=$3 WHERE workspace_id=$1 AND id=$2',[a.workspaceId,a.taskId,a.secondProjectId]);
  await rejected('UPDATE app.tasks SET phase_id=$3 WHERE workspace_id=$1 AND id=$2',[a.workspaceId,a.taskId,a.secondPhaseId]);
  await rejected('UPDATE app.milestones SET phase_id=$3 WHERE workspace_id=$1 AND id=$2',[a.workspaceId,a.milestoneId,a.secondPhaseId]);
  await rejected("UPDATE app.project_access SET state='revoked' WHERE workspace_id=$1 AND profile_id=$2",[a.workspaceId,a.profileId]);
  await tenantTransaction(db.application,a.workspaceId,a.profileId,async(c)=>{
    const task=(await c.query('SELECT phase_id,lead_profile_id FROM app.tasks WHERE workspace_id=$1 AND id=$2',[a.workspaceId,a.taskId])).rows[0];
    assert.equal(task.phase_id,a.phaseId); assert.equal(task.lead_profile_id,a.profileId);
    assert.equal((await c.query('SELECT * FROM app.task_assignments WHERE workspace_id=$1 AND task_id=$2',[a.workspaceId,a.taskId])).rowCount,1);
    // Deferred phase compatibility allows one deliberate atomic relocation.
    await c.query('UPDATE app.milestones SET phase_id=$3 WHERE workspace_id=$1 AND id=$2',[a.workspaceId,a.milestoneId,a.secondPhaseId]);
    await c.query('UPDATE app.tasks SET phase_id=$3 WHERE workspace_id=$1 AND id=$2',[a.workspaceId,a.taskId,a.secondPhaseId]);
  });
  assert.ok(encrypted.encrypted.ciphertext);
});

test('CP02: encrypted read APIs enforce tenant, project, fence and current authority state', async (t) => {
  const { config, db, admin, a, b }=await fixture(t);
  const sessions = new Map<string,DataPrincipal>([['Bearer fixture-a',a],['Bearer fixture-b',b],['Bearer fixture-stranger',{...a,profileId:a.strangerId}]]);
  const api=buildApp(config,{...db,close:async()=>{}},undefined,async(request)=>{
    const principal=sessions.get(request.headers.authorization??'');
    if(!principal) throw new AppError('AUTH_REQUIRED','Authentication required',401);
    return principal;
  });
  t.after(()=>api.close());
  const read=async(path: string,token='fixture-a')=>api.inject({url:path,headers:{authorization:`Bearer ${token}`}});
  const path=`/v1/workspaces/${a.workspaceId}/projects/${a.projectId}`;
  assert.equal((await read(path)).statusCode,200);
  assert.equal((await read(`${path}/records/tasks`)).json().records.length,1);
  assert.equal((await read(`/v1/workspaces/${b.workspaceId}/projects/${b.projectId}`)).statusCode,404);
  assert.equal((await read(`/v1/workspaces/${a.workspaceId}/projects/${b.projectId}`)).statusCode,404);
  assert.equal((await read(path,'fixture-stranger')).statusCode,404);
  assert.equal((await read(`/v1/workspaces/${a.workspaceId}/projects?limit=1000`)).statusCode,400);
  assert.equal((await read(path)).headers['cache-control'],'no-store');
  const offlineControl=new pg.Pool({connectionString:'postgres://fixture:unavailable@127.0.0.1:1/unavailable',connectionTimeoutMillis:300});
  try { await assert.rejects(dataTransaction({...db,control:offlineControl},a,async()=>true),(error:unknown)=>error instanceof AppError&&error.code==='SECURITY_UNAVAILABLE'); }
  finally { await offlineControl.end(); }

  await admin.application.query('UPDATE app.workspaces SET fence_closed=true WHERE workspace_id=$1',[a.workspaceId]);
  assert.equal((await read(path)).json().error.code,'SECURITY_FENCED');
  await admin.application.query('UPDATE app.workspaces SET fence_closed=false WHERE workspace_id=$1',[a.workspaceId]);
  await admin.control.query("UPDATE security.workspaces SET licence_state='restricted' WHERE workspace_id=$1",[a.workspaceId]);
  assert.equal((await read(path)).statusCode,200);
  await assert.rejects(dataTransaction(db,a,async()=>true,{write:true}),(e:unknown)=>e instanceof AppError&&e.code==='WORKSPACE_RESTRICTED');
  await admin.control.query('UPDATE security.workspaces SET security_version=2,security_head=$2 WHERE workspace_id=$1',[a.workspaceId,'b'.repeat(64)]);
  assert.equal((await read(path)).json().error.code,'SECURITY_FENCED');
});

test('CP02: provider-readable rows contain ciphertext without the private value or content key', async(t)=>{
  const {admin,a,encrypted}=await fixture(t);
  const rows=(await admin.application.query('SELECT row_to_json(p) AS row FROM app.projects p WHERE workspace_id=$1',[a.workspaceId])).rows;
  const stored=JSON.stringify(rows);
  assert.equal(stored.includes(encrypted.secret),false);
  assert.equal(stored.includes(Buffer.from(encrypted.key).toString('base64url')),false);
  assert.ok(stored.includes(encrypted.encrypted.ciphertext));
  assert.equal(encrypted.decrypt(),encrypted.secret);
  await sodium.ready;
  assert.throws(()=>sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,sodium.from_base64(encrypted.encrypted.ciphertext,sodium.base64_variants.URLSAFE_NO_PADDING),null,sodium.from_base64(encrypted.encrypted.nonce,sodium.base64_variants.URLSAFE_NO_PADDING),sodium.randombytes_buf(32)));
});


test('CP02: history and receipts remain immutable under the application role',async(t)=>{
  const {db,a,encrypted}=await fixture(t);
  const rollback=new Error('fixture rollback');
  await assert.rejects(tenantTransaction(db.application,a.workspaceId,a.profileId,async(c)=>{
    await c.query(`INSERT INTO app.record_versions(workspace_id,id,project_id,record_type,record_id,record_revision,actor_profile_id,operation_id,encrypted_envelope) VALUES($1,$2,$3,'task',$4,1,$5,$6,$7)`,[a.workspaceId,randomUUID(),a.projectId,a.taskId,a.profileId,randomUUID(),encrypted.encrypted]);
    await c.query(`INSERT INTO app.audit_events(workspace_id,id,project_id,record_type,record_id,action,actor_profile_id,operation_id,encrypted_envelope) VALUES($1,$2,$3,'task',$4,'task.edit',$5,$6,$7)`,[a.workspaceId,randomUUID(),a.projectId,a.taskId,a.profileId,randomUUID(),encrypted.encrypted]);
    await c.query(`INSERT INTO app.operation_receipts(workspace_id,id,project_id,data_generation,action,actor_profile_id,operation_id,request_digest,encrypted_envelope) VALUES($1,$2,$3,1,'task.edit',$4,$5,$6,$7)`,[a.workspaceId,randomUUID(),a.projectId,a.profileId,randomUUID(),'a'.repeat(64),encrypted.encrypted]);
    for(const table of ['record_versions','audit_events','operation_receipts']) {
      for(const sql of [`UPDATE app.${table} SET encrypted_envelope='{}' WHERE workspace_id=$1`,`DELETE FROM app.${table} WHERE workspace_id=$1`]) {
        await c.query('SAVEPOINT expected_failure');
        await assert.rejects(c.query(sql,[a.workspaceId]),hasPgCode('55000'));
        await c.query('ROLLBACK TO SAVEPOINT expected_failure');
      }
      assert.equal((await c.query(`SELECT * FROM app.${table} WHERE workspace_id=$1`,[a.workspaceId])).rowCount,1);
    }
    throw rollback;
  }),(e:unknown)=>e===rollback);
});

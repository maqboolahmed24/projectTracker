import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { transaction } from '../src/db.js';
import { RoleService } from '../src/modules/identity/roles.js';
import { EnrolmentService } from '../src/modules/identity/enrolment.js';
import { EntitlementOperations } from '../src/modules/identity/entitlements.js';
import { projectAuthoritativeWorkspace } from '../src/modules/identity/projection.js';
import { prepareJoinEnrolment, confirmEnrolmentRecipient, confirmEnrolmentAuthorizer, encryptEnrolmentProfile, enrolmentDeviceContext } from '../src/client/enrolment-crypto.js';
import { startRegistration, finishRegistration, startLogin, finishLogin } from '../src/client/opaque.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { base64urlDecode, decryptContent, digestObject, encryptContent, openRecipient, sealRecipient, signObject } from '../src/shared/crypto.js';
import { enrolmentRecipientHeader, type EnrolmentApproval } from '../src/shared/enrolment.js';
import type { RolePayload, RoleContext } from '../src/shared/roles.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { passwordFixture, origin, newPassword } from './password-change-fixture.js';
const errorCode = (code: string) => (error: unknown) => error instanceof AppError && error.code === code;
async function fixture(t: TestContext) {
  let f: Awaited<ReturnType<typeof passwordFixture>>;
  t.after(async () => { if (f) {
    await f.admin.control.query('DELETE FROM security.ceremonies WHERE workspace_id=$1', [f.workspaceId]);
    await f.admin.control.query('DELETE FROM security.entitlement_operations WHERE licence_id=$1', [f.licence.licenceId]);
    await transaction(f.admin.application, async (c) => {
      await c.query('DELETE FROM app.project_access WHERE workspace_id=$1', [f.workspaceId]);
      await c.query('DELETE FROM app.projects WHERE workspace_id=$1', [f.workspaceId]);
    });
  } });
  f = await passwordFixture(t);
  let offset = 0, hooks: NonNullable<ConstructorParameters<typeof RoleService>[0]['hooks']> = {};
  const make = () => new RoleService({ ...f, origin, now: () => new Date(Date.now() + offset), hooks }); let service = make();
  const custody = await openRecipient(f.prepared.payload.objects.deviceCustody, base64urlDecode(f.originalBundle.recipientPrivateKey), base64urlDecode(f.originalBundle.signingPublicKey), f.prepared.payload.objects.deviceCustody.header) as { custodyKey: string };
  const manifest = await decryptContent(f.prepared.payload.objects.custody, base64urlDecode(custody.custodyKey), base64urlDecode(f.originalBundle.signingPublicKey), f.prepared.payload.objects.custody.header) as { workspaceKeys: { epoch: string; key: string }[] };
  const workspaceKey = base64urlDecode(manifest.workspaceKeys[0]!.key), privateKey = base64urlDecode(f.originalBundle.signingPrivateKey);
  const call = () => [f.auth().cookieValue, f.auth().csrfToken] as const;
  async function payload(context: RoleContext, permissions: RolePayload['transition']['body']['role']['permissions'] = ['read_project'], displayName = 'Private editorial role'): Promise<RolePayload> {
    const b = context.binding, label = { id: randomUUID(), envelope: await encryptContent(context.labelHeader, { displayName }, workspaceKey, privateKey) };
    return { label, transition: await signObject({ version: 1 as const, purpose: 'ukda.custom-role-definition.v1' as const, binding: b,
      role: { id: b.roleId, template: 'custom' as const, revision: b.nextRevision, state: b.action === 'retire' ? 'retired' as const : 'active' as const,
        permissions: b.action === 'retire' ? b.previous!.permissions : permissions, label: { id: label.id, revision: b.nextRevision, digest: await digestObject(label.envelope) } } }, privateKey) };
  }
  async function draft(action: 'create' | 'update' | 'retire' = 'create', roleId: string = randomUUID(), permissions: RolePayload['transition']['body']['role']['permissions'] = ['read_project']) {
    const reference = { workspaceId: f.workspaceId, operationId: randomUUID() }, context = await service.context(...call(), { ...reference, action, roleId });
    const prepared = await payload(context, permissions), staged = await service.stage(...call(), prepared);
    assert.equal(staged.requestHash, await digestObject(prepared));
    return { context, payload: prepared, reference, request: { ...reference, requestHash: staged.requestHash! }, roleId };
  }
  async function create(permissions: RolePayload['transition']['body']['role']['permissions'] = ['read_project']) { const d = await draft('create', randomUUID(), permissions); return { ...d, result: await service.finalize(...call(), d.request) }; }
  async function join(roleId: string) {
    const enrolment = new EnrolmentService({ ...f, origin }), accountId = randomUUID(), operationId = randomUUID();
    const issuance = { workspaceId: f.workspaceId, accountId, operationId, kind: 'join_member' as const, roleId, projectIds: [] };
    const context = await enrolment.issuanceContext(...call(), issuance), profile = { id: randomUUID(), envelope: await encryptContent(context.header,
      { displayName: 'Private pending member', invitation: { version: 1, kind: 'join_member', role: context.role, workspaceId: f.workspaceId, accountId, operationId, projectScope: { mode: 'selected', projectIds: [] } } }, workspaceKey, privateKey) };
    const issued = await enrolment.issueJoin(...call(), { ...issuance, profile }), reference = { workspaceId: f.workspaceId, operationId, resumeToken: f.secrets.token() };
    await enrolment.begin({ workspaceId: f.workspaceId, code: issued.code, resumeToken: reference.resumeToken });
    const binding = (await enrolment.claim({ workspaceId: f.workspaceId, operationId }, f.auth())).binding!;
    const started = await startRegistration(newPassword), registration = await enrolment.registration({ ...reference, registrationRequest: started.registrationRequest });
    const registered = await finishRegistration({ password: newPassword, clientRegistrationState: started.clientRegistrationState, registrationResponse: registration.registrationResponse, configuration: registration.configuration });
    const prepared = await prepareJoinEnrolment({ binding, configuration: registration.configuration, registrationRecord: registered.registrationRecord, exportKey: registered.exportKey, displayName: 'Private member' }, binding);
    const login = await startLogin(newPassword), proof = await enrolment.startProof({ ...reference, draft: prepared.draft, startLoginRequest: login.startLoginRequest });
    const finish = await finishLogin({ password: newPassword, clientLoginState: login.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
    await enrolment.finishProof({ ...reference, proofId: proof.proofId, finishLoginRequest: finish.finishLoginRequest });
    const transcript = prepared.draft.transcript, transcriptDigest = await digestObject(transcript);
    prepared.draft.recipientConfirmation = await confirmEnrolmentRecipient({ prepared, exportKey: registered.exportKey, fingerprint: transcriptDigest }, binding);
    await enrolment.confirm(reference, prepared.draft.recipientConfirmation);
    const { registrationRecord: _record, ...publicDraft } = prepared.draft, authorizerConfirmation = await confirmEnrolmentAuthorizer({ draft: publicDraft, fingerprint: transcriptDigest }, f.originalBundle, binding);
    await enrolment.confirm({ workspaceId: f.workspaceId, operationId }, authorizerConfirmation, f.auth());
    const deliveries = await Promise.all(binding.scopes.map(async (scope) => ({ id: randomUUID(), envelope: await sealRecipient(enrolmentRecipientHeader(transcript, transcriptDigest, scope, 'device', transcript.device.id),
      { version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, keys: manifest.workspaceKeys }, privateKey) })));
    const finalProfile = await encryptEnrolmentProfile({ draft: publicDraft, fingerprint: transcriptDigest }, f.originalBundle, workspaceKey, binding);
    const approval: EnrolmentApproval = { profile: finalProfile, deliveries, transition: await signObject({ version: 1 as const, purpose: 'ukda.profile-enrolment.v1' as const,
      transcript, transcriptDigest, recipientConfirmation: prepared.draft.recipientConfirmation, authorizerConfirmation, newRecoveryConfirmation: null,
      profile: { id: finalProfile.id, profileId: accountId, revision: binding.nextProfileRevision, digest: await digestObject(finalProfile.envelope) },
      deliveries: await Promise.all(deliveries.map(async (d) => ({ id: d.id, scope: d.envelope.header.scope, scopeId: d.envelope.header.scopeId, keyEpoch: d.envelope.header.keyEpoch,
        recipientKind: d.envelope.header.recipientKind, recipientId: d.envelope.header.recipientId, digest: await digestObject(d.envelope) }))) }, privateKey) };
    const staged = await enrolment.stage({ workspaceId: f.workspaceId, operationId }, approval, f.auth());
    assert.equal((await enrolment.finalize({ workspaceId: f.workspaceId, operationId, requestHash: staged.requestHash! }, f.auth())).state, 'completed');
    const log = await startLogin(newPassword), response = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId, startLoginRequest: log.startLoginRequest });
    const logged = await finishLogin({ password: newPassword, clientLoginState: log.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration });
    const restricted = await f.authentication.finishLogin({ loginId: response.loginId, finishLoginRequest: logged.finishLoginRequest });
    const bundle = await unwrapDeviceBundle(enrolmentDeviceContext(transcript), prepared.deviceWrapper, logged.exportKey);
    const challenge = await f.sessions.beginDeviceChallenge(restricted.cookieValue, restricted.csrfToken, transcript.device.id);
    const session = await f.sessions.completeDeviceChallenge(restricted.cookieValue, restricted.csrfToken, await signObject(challenge, base64urlDecode(bundle.signingPrivateKey)));
    return { accountId, session, transition: approval.transition };
  }
  return { ...f, get roles() { return service; }, call, payload, draft, create, join, workspaceKey,
    setHooks(value: typeof hooks = {}) { hooks = value; service = make(); }, advance(ms: number) { offset += ms; } };
}

test('CP06: custom role commits once with encrypted label, exact readback, paginated list and durable history', async (t) => {
  const f = await fixture(t), draft = await f.draft();
  assert.deepEqual(await f.roles.stage(...f.call(), draft.payload), await f.roles.status(...f.call(), draft.reference));
  const results = await Promise.all([1, 2].map(() => f.roles.finalize(...f.call(), draft.request)));
  assert.equal(results[0]!.state, 'completed'); assert.deepEqual(results[0], results[1]);
  const update = await f.draft('update', draft.roleId, ['read_project', 'comment']);
  const updated = await f.roles.finalize(...f.call(), update.request); assert.equal(updated.state, 'completed');
  assert.deepEqual((await f.roles.status(...f.call(), draft.reference)).receipt, results[0]!.receipt);
  assert.deepEqual((await f.roles.finalize(...f.call(), draft.request)).receipt, results[0]!.receipt);
  const first = await f.roles.list(...f.call(), { workspaceId: f.workspaceId, limit: 2 });
  assert.equal(first.roles.length, 2); assert.equal(first.nextRoleId, first.roles.at(-1)!.id);
  const second = await f.roles.list(...f.call(), { workspaceId: f.workspaceId, afterRoleId: first.nextRoleId!, limit: 100 });
  assert.equal(second.nextRoleId, null); assert.equal(new Set([...first.roles, ...second.roles].map((r) => r.id)).size, 5);
  const label = [...first.roles, ...second.roles].find((r) => r.id === draft.roleId)!.label!;
  const plain = await decryptContent(label.envelope, f.workspaceKey, base64urlDecode(f.originalBundle.signingPublicKey), label.envelope.header) as { displayName: string };
  assert.equal(plain.displayName, 'Private editorial role');
  const history = await verifySecurityHistory({ workspaceId: f.workspaceId, origin, genesisFingerprint: await digestObject(f.prepared.payload.genesis), genesis: f.prepared.payload.genesis,
    transitions: [results[0]!.receipt!.transition, updated.receipt!.transition], expected: { securityHead: updated.receipt!.securityHead, securityVersion: updated.receipt!.securityVersion } });
  assert.deepEqual(history.roles[draft.roleId]!.permissions, ['read_project', 'comment']);
  const provider = JSON.stringify((await f.admin.control.query('SELECT versioned_object FROM security.staged_objects WHERE workspace_id=$1', [f.workspaceId])).rows);
  assert.equal(provider.includes(plain.displayName), false); assert.equal(provider.includes(f.originalBundle.signingPrivateKey), false);
});

test('CP06: definition updates preserve a real member role snapshot and cannot retire an active original role without projects', async (t) => {
  const f = await fixture(t), created = await f.create(), member = await f.join(created.roleId);
  const grants = () => f.admin.control.query("SELECT grant_id,permissions,generation,role_id,role_revision FROM security.grants WHERE workspace_id=$1 AND profile_id=$2 ORDER BY grant_id", [f.workspaceId, member.accountId]);
  const before = (await grants()).rows, update = await f.draft('update', created.roleId, ['read_project', 'comment']);
  assert.equal((await f.roles.finalize(...f.call(), update.request)).state, 'completed'); assert.deepEqual((await grants()).rows, before);
  const retire = { workspaceId: f.workspaceId, operationId: randomUUID(), roleId: created.roleId, action: 'retire' };
  await assert.rejects(f.roles.context(...f.call(), retire), errorCode('ROLE_IN_USE'));
  for (const method of ['context', 'list', 'status'] as const) {
    const input = method === 'context' ? { ...retire, action: 'update' } : method === 'list' ? { workspaceId: f.workspaceId } : created.reference;
    await assert.rejects(f.roles[method](member.session.cookieValue, member.session.csrfToken, input), errorCode('ROLE_FORBIDDEN'));
  }
  // Lease expiry restricts keys, but does not silently unassign the person's original role.
  await f.admin.control.query("UPDATE security.grants SET expires_at=greatest(created_at,activated_at)+interval '1 second' WHERE workspace_id=$1 AND profile_id=$2 AND device_id IS NULL", [f.workspaceId, member.accountId]);
  f.advance(10_000);
  await assert.rejects(f.roles.context(...f.call(), retire), errorCode('ROLE_IN_USE'));

});

test('CP06: project grant permission snapshots stay unchanged on definition edits and block retirement', async (t) => {
  const f = await fixture(t), role = await f.create(), projectId = randomUUID(), grantId = randomUUID(), genesis = f.prepared.payload.genesis.body;
  // This prevalidated assignment fixture tests projection snapshots independently of later assignment-command implementation.
  await transaction(f.admin.control, async (c) => {
    await c.query("INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version) VALUES($1,'project',$2,1,$3,1)", [f.workspaceId, projectId, genesis.custodyId]);
    await c.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,scope_id,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,activated_at,role_id,role_revision)
      VALUES($1,$2,$3,'project','project',$4,1,ARRAY['read_project'],'active',$5,$6,1,2,now(),$7,1)`, [f.workspaceId, grantId, f.accountId, projectId, role.reference.operationId, genesis.custodyId, role.roleId]);
  });
  await f.admin.application.query("INSERT INTO app.projects(workspace_id,id,encrypted_envelope) VALUES($1,$2,'{}')", [f.workspaceId, projectId]);
  assert.equal((await projectAuthoritativeWorkspace(f.databases, f.workspaceId)).state, 'ready');
  const snapshot = (await f.admin.application.query('SELECT role_id,role_revision,permissions FROM app.project_access WHERE workspace_id=$1 AND project_id=$2', [f.workspaceId, projectId])).rows;
  const update = await f.draft('update', role.roleId, ['read_project', 'comment']); assert.equal((await f.roles.finalize(...f.call(), update.request)).state, 'completed');
  assert.deepEqual((await f.admin.application.query('SELECT role_id,role_revision,permissions FROM app.project_access WHERE workspace_id=$1 AND project_id=$2', [f.workspaceId, projectId])).rows, snapshot);
  await assert.rejects(f.roles.context(...f.call(), { workspaceId: f.workspaceId, operationId: randomUUID(), roleId: role.roleId, action: 'retire' }), errorCode('ROLE_IN_USE'));
});

test('CP06: role definitions reject built-in edits, tampering, stale heads and expired staged changes; unused retirement retains label revision', async (t) => {
  const f = await fixture(t), created = await f.create();
  await assert.rejects(f.roles.context(...f.call(), { workspaceId: f.workspaceId, operationId: randomUUID(), action: 'update', roleId: f.prepared.payload.genesis.body.roles.member }), errorCode('BUILTIN_ROLE_IMMUTABLE'));
  const stale = await f.draft('update', created.roleId), retired = await f.draft('retire', created.roleId);
  const tampered = structuredClone(stale.payload); tampered.transition.body.role.permissions.push('comment');
  await assert.rejects(f.roles.stage(...f.call(), tampered), errorCode('ROLE_INVALID'));
  const result = await f.roles.finalize(...f.call(), retired.request); assert.equal(result.state, 'completed');
  assert.equal(result.receipt!.roleRevision, '2'); assert.equal(result.receipt!.transition.body.role.state, 'retired');
  await assert.rejects(f.roles.finalize(...f.call(), stale.request), errorCode('ROLE_CHANGED'));
  const pending = await f.draft(); f.advance(600_001);
  assert.equal((await f.roles.status(...f.call(), pending.reference)).state, 'expired');
  await assert.rejects(f.roles.finalize(...f.call(), pending.request));
});

test('CP06: role rollback and lost commit retain exact receipts; restricted licence allows Owner list/status while blocking writes', async (t) => {
  const f = await fixture(t), draft = await f.draft();
  f.setHooks({ beforeControlCommit: async () => { throw new Error('private control failure'); } });
  await assert.rejects(f.roles.finalize(...f.call(), draft.request), errorCode('ROLE_UNAVAILABLE'));
  assert.equal((await f.admin.control.query('SELECT 1 FROM security.roles WHERE workspace_id=$1 AND role_id=$2', [f.workspaceId, draft.roleId])).rowCount, 0);
  assert.equal((await f.roles.status(...f.call(), draft.reference)).state, 'staged');
  let observedClosed = false;
  f.setHooks({ afterControlCommit: async () => { observedClosed = (await f.admin.application.query('SELECT fence_closed FROM app.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0].fence_closed; throw new Error('lost response'); } });
  await assert.rejects(f.roles.finalize(...f.call(), draft.request), errorCode('ROLE_UNAVAILABLE')); assert.ok(observedClosed);
  f.setHooks({ beforeProjection: async () => { throw new Error('projection offline'); } });
  const finishing = await f.roles.status(...f.call(), draft.reference); assert.equal(finishing.state, 'finishing'); assert.ok(finishing.receipt);
  assert.equal((await f.roles.stage(...f.call(), draft.payload)).state, 'finishing', 'Stage replay cannot imply projection completion');
  f.setHooks(); const repaired = await f.roles.status(...f.call(), draft.reference); assert.equal(repaired.state, 'completed'); assert.deepEqual(repaired.receipt, finishing.receipt);
  await new EntitlementOperations(f.databases, f.secrets).change({ licenceId: f.licence.licenceId, operationId: randomUUID(), action: 'revoke' }, { operatorId: randomUUID() });
  assert.equal((await f.roles.list(...f.call(), { workspaceId: f.workspaceId })).roles.length, 5);
  assert.deepEqual((await f.roles.status(...f.call(), draft.reference)).receipt, repaired.receipt);
  await assert.rejects(f.roles.context(...f.call(), { workspaceId: f.workspaceId, operationId: randomUUID(), roleId: randomUUID(), action: 'create' }), errorCode('WORKSPACE_RESTRICTED'));
  await assert.rejects(f.roles.list('invalid', f.auth().csrfToken, { workspaceId: f.workspaceId }));
  await assert.rejects(f.roles.status('invalid', f.auth().csrfToken, draft.reference));
});

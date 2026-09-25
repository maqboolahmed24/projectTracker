import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { EnrolmentService } from '../src/modules/identity/enrolment.js';
import { PairingService } from '../src/modules/identity/pairing.js';
import { startRegistration, finishRegistration, startLogin, finishLogin } from '../src/client/opaque.js';
import { newOwnerPhrase, recoveryKeys } from '../src/client/recovery.js';
import { unwrapDeviceBundle, wrapDeviceBundle, type DeviceBundle } from '../src/client/device-store.js';
import { prepareJoinEnrolment, preparePromotionEnrolment, rebindJoinEnrolment, confirmEnrolmentRecipient, confirmEnrolmentAuthorizer,
  encryptEnrolmentProfile, enrolmentDeviceContext, type PreparedEnrolment, type NewEnrolmentOwnerKit } from '../src/client/enrolment-crypto.js';
import { base64urlDecode, base64urlEncode, digestObject, decryptContent, encryptContent, generateRecipientKeyPair, generateSigningKeyPair, openRecipient, sealRecipient, signObject } from '../src/shared/crypto.js';
import { enrolmentRecipientHeader, enrolmentRecipientDevices, type EnrolmentApproval, type EnrolmentBinding, type EnrolmentReference } from '../src/shared/enrolment.js';
import type { EnrolmentAuth } from '../src/shared/enrolment-api.js';
import { pairingConfirmationFor, pairingRecipientHeader, type PairingApproval } from '../src/shared/pairing.js';
import { verifySecurityHistory } from '../src/shared/security-history.js';
import { passwordFixture, origin, newPassword } from './password-change-fixture.js';
import { transaction } from '../src/db.js';
import { AccessChangeService } from '../src/modules/identity/access-change.js';
import { EntitlementOperations } from '../src/modules/identity/entitlements.js';
import { prepareAccessChange, refreshAccessKeys } from '../src/client/access-change-crypto.js';
import { readOwnerCustodyKeyMaterial } from '../src/client/pairing.js';
import { accessReceiptTokenHash, type AccessRequest } from '../src/shared/access-change.js';
import type { SecurityHistoryInput } from '../src/shared/security-history.js';
import { provisionProjectScope } from './project-scope-fixture.js';
const code = (expected: string) => (e: unknown) => e instanceof AppError && e.code === expected;
const password = newPassword;
async function kit(): Promise<NewEnrolmentOwnerKit> { const phrase = await newOwnerPhrase(), positions = [2, 8, 20]; return { phrase, positions, answers: positions.map((n) => phrase.split(' ')[n]!) }; }
async function enrolmentFixture(t: TestContext) {
  let f: Awaited<ReturnType<typeof passwordFixture>>;
  t.after(async () => { if (f) await f.admin.control.query('DELETE FROM security.ceremonies WHERE workspace_id=$1', [f.workspaceId]); });
  f = await passwordFixture(t); let offset = 0, hooks: NonNullable<ConstructorParameters<typeof EnrolmentService>[0]['hooks']> = {};
  let service = new EnrolmentService({ ...f, origin, now: () => new Date(Date.now() + offset), hooks });
  const custody = await openRecipient(f.prepared.payload.objects.deviceCustody, base64urlDecode(f.originalBundle.recipientPrivateKey), base64urlDecode(f.originalBundle.signingPublicKey), f.prepared.payload.objects.deviceCustody.header) as { custodyKey: string };
  const manifest = await decryptContent(f.prepared.payload.objects.custody, base64urlDecode(custody.custodyKey), base64urlDecode(f.originalBundle.signingPublicKey), f.prepared.payload.objects.custody.header) as { workspaceKeys: { epoch: string; key: string }[] };
  const workspaceKey = base64urlDecode(manifest.workspaceKeys[0]!.key);
  async function issue(kind: 'join_member' | 'join_owner' = 'join_member', accountId: string = randomUUID(), auth: EnrolmentAuth = f.auth(), bundle = f.originalBundle) {
    const request = { workspaceId: f.workspaceId, accountId, operationId: randomUUID(), kind, roleId: f.prepared.payload.genesis.body.roles[kind === 'join_member' ? 'member' : 'owner'], projectIds: [] };
    const context = await service.issuanceContext(auth.cookieValue, auth.csrfToken, request);
    const profile = { id: randomUUID(), envelope: await encryptContent(context.header, { displayName: 'Pending private person', invitation: {
      version: 1, kind, role: context.role, workspaceId: f.workspaceId, accountId, operationId: request.operationId,
      projectScope: kind === 'join_owner' ? { mode: 'all_ordinary' } : { mode: 'selected', projectIds: [...request.projectIds].sort() },
    } }, workspaceKey, base64urlDecode(bundle.signingPrivateKey)) };
    const issued = await service.issueJoin(auth.cookieValue, auth.csrfToken, { ...request, profile });
    return { issued, request, profile };
  }
  async function begin(issued: Awaited<ReturnType<typeof issue>>['issued'], auth: EnrolmentAuth = f.auth()) {
    const ref: EnrolmentReference = { workspaceId: f.workspaceId, operationId: issued.operationId, resumeToken: f.secrets.token() };
    await service.begin({ workspaceId: ref.workspaceId, code: issued.code, resumeToken: ref.resumeToken });
    const view = await service.claim({ workspaceId: ref.workspaceId, operationId: ref.operationId }, auth); return { ref, binding: view.binding! };
  }
  async function prove(ref: EnrolmentReference, prepared: PreparedEnrolment, exportKey: string) {
    const login = await startLogin(password), proof = await service.startProof({ ...ref, draft: prepared.draft, startLoginRequest: login.startLoginRequest });
    const finish = await finishLogin({ password, clientLoginState: login.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
    assert.equal(finish.exportKey, exportKey); await service.finishProof({ ...ref, proofId: proof.proofId, finishLoginRequest: finish.finishLoginRequest }); return { proof, finish };
  }
  async function prepare(ref: EnrolmentReference, binding: EnrolmentBinding) {
    const start = await startRegistration(password), response = await service.registration({ ...ref, registrationRequest: start.registrationRequest });
    const registered = await finishRegistration({ password, clientRegistrationState: start.clientRegistrationState, registrationResponse: response.registrationResponse, configuration: response.configuration });
    const newOwnerKit = binding.kind === 'join_owner' ? await kit() : undefined;
    const prepared = await prepareJoinEnrolment({ binding, configuration: response.configuration, registrationRecord: registered.registrationRecord, exportKey: registered.exportKey, displayName: 'Confirmed private person', ...(newOwnerKit ? { newOwnerKit } : {}) }, binding);
    const proven = await prove(ref, prepared, registered.exportKey); return { prepared, registered, newOwnerKit, proven };
  }
  async function approve(ref: EnrolmentReference, prepared: PreparedEnrolment, exportKey: string, auth: EnrolmentAuth = f.auth(), bundle: DeviceBundle = f.originalBundle) {
    const transcript = prepared.draft.transcript, binding = transcript.binding, transcriptDigest = await digestObject(transcript), key = base64urlDecode(bundle.signingPrivateKey);
    prepared.draft.recipientConfirmation = await confirmEnrolmentRecipient({ prepared, exportKey, fingerprint: transcriptDigest }, binding);
    await service.confirm(ref, prepared.draft.recipientConfirmation);
    const { registrationRecord: _record, ...draft } = prepared.draft;
    const authorizerConfirmation = await confirmEnrolmentAuthorizer({ draft, fingerprint: transcriptDigest }, bundle, binding);
    const publicRef = { workspaceId: ref.workspaceId, operationId: ref.operationId }; await service.confirm(publicRef, authorizerConfirmation, auth);
    const deliveries: EnrolmentApproval['deliveries'] = [];
    for (const scope of binding.scopes) {
      const value = scope.mode === 'custody' ? { version: 1, mode: 'custody', custodyEpoch: binding.custodyEpoch, custodyKey: custody.custodyKey,
        manifest: { id: f.prepared.payload.genesis.body.custodyId, digest: await digestObject(f.prepared.payload.objects.custody) } } :
        { version: 1, mode: 'content', scope: scope.scope, scopeId: scope.scopeId, keyEpoch: scope.keyEpoch, keys: manifest.workspaceKeys };
      for (const device of enrolmentRecipientDevices(transcript)) deliveries.push({ id: randomUUID(), envelope: await sealRecipient(enrolmentRecipientHeader(transcript, transcriptDigest, scope, 'device', device.id), value, key) });
      if (scope.mode === 'custody') deliveries.push({ id: randomUUID(), envelope: await sealRecipient(enrolmentRecipientHeader(transcript, transcriptDigest, scope, 'recovery'), value, key) });
    }
    const profile = binding.kind === 'promote_owner' ? null : await encryptEnrolmentProfile({ draft, fingerprint: transcriptDigest }, bundle, workspaceKey, binding);
    const approval: EnrolmentApproval = { profile, deliveries, transition: await signObject({ version: 1 as const, purpose: binding.kind === 'promote_owner' ? 'ukda.owner-promotion.v1' as const : 'ukda.profile-enrolment.v1' as const,
      transcript, transcriptDigest, recipientConfirmation: prepared.draft.recipientConfirmation, authorizerConfirmation, newRecoveryConfirmation: prepared.draft.newRecoveryConfirmation,
      profile: profile ? { id: profile.id, profileId: binding.accountId, revision: binding.nextProfileRevision, digest: await digestObject(profile.envelope) } : null,
      deliveries: await Promise.all(deliveries.map(async (d) => ({ id: d.id, scope: d.envelope.header.scope, scopeId: d.envelope.header.scopeId, keyEpoch: d.envelope.header.keyEpoch, recipientKind: d.envelope.header.recipientKind, recipientId: d.envelope.header.recipientId, digest: await digestObject(d.envelope) }))) }, key) };
    const staged = await service.stage(publicRef, approval, auth); assert.equal(staged.approvalHash, await digestObject(approval)); return { approval, requestHash: staged.requestHash!, publicRef };
  }
  async function login(prepared: PreparedEnrolment, expectedExport: string) {
    const transcript = prepared.draft.transcript, binding = transcript.binding, start = await startLogin(password);
    const response = await f.authentication.startLogin({ workspaceId: f.workspaceId, accountId: binding.accountId, startLoginRequest: start.startLoginRequest });
    const finish = await finishLogin({ password, clientLoginState: start.clientLoginState, loginResponse: response.loginResponse, configuration: response.configuration }); assert.equal(finish.exportKey, expectedExport);
    const restricted = await f.authentication.finishLogin({ loginId: response.loginId, finishLoginRequest: finish.finishLoginRequest }), bundle = await unwrapDeviceBundle(enrolmentDeviceContext(transcript), prepared.deviceWrapper, finish.exportKey);
    const challenge = await f.sessions.beginDeviceChallenge(restricted.cookieValue, restricted.csrfToken, transcript.device.id);
    const session = await f.sessions.completeDeviceChallenge(restricted.cookieValue, restricted.csrfToken, await signObject(challenge, base64urlDecode(bundle.signingPrivateKey)));
    return { session, bundle, auth: { cookieValue: session.cookieValue, csrfToken: session.csrfToken } };
  }
  async function joined(kind: 'join_member' | 'join_owner' = 'join_member') { const invitation = await issue(kind), started = await begin(invitation.issued), draft = await prepare(started.ref, started.binding), staged = await approve(started.ref, draft.prepared, draft.registered.exportKey);
    const result = await service.finalize({ ...staged.publicRef, requestHash: staged.requestHash }, f.auth()); return { ...invitation, ...started, ...draft, ...staged, result, ...await login(draft.prepared, draft.registered.exportKey) }; }
  return { ...f, get enrolment() { return service; }, issue, begin, prepare, prove, approve, login, joined, workspaceKey, custody, manifest,
    advance(ms: number) { offset += ms; }, setHooks(nextHooks: typeof hooks) { hooks = nextHooks; service = new EnrolmentService({ ...f, origin, hooks, now: () => new Date(Date.now() + offset) }); } };
}

export async function accessChangeFixture(t: TestContext) {
  let f: Awaited<ReturnType<typeof enrolmentFixture>>;
  t.after(async () => { if (f) {
    await f.admin.control.query('DELETE FROM security.entitlement_operations WHERE licence_id=$1', [f.licence.licenceId]);
    await transaction(f.admin.application, async (c) => {
      await c.query('DELETE FROM app.notifications WHERE workspace_id=$1', [f.workspaceId]);
      await c.query('DELETE FROM app.project_access WHERE workspace_id=$1', [f.workspaceId]);
      await c.query('DELETE FROM app.projects WHERE workspace_id=$1', [f.workspaceId]);
    });
  } });
  f = await enrolmentFixture(t); let hooks: NonNullable<ConstructorParameters<typeof AccessChangeService>[0]['hooks']> = {}, offset = 0;
  const make = () => new AccessChangeService({ ...f, origin, now: () => new Date(Date.now() + offset), hooks }); let service = make();
  async function history(): Promise<SecurityHistoryInput> {
    const w = (await f.admin.control.query('SELECT security_head,security_version FROM security.workspaces WHERE workspace_id=$1', [f.workspaceId])).rows[0];
    return { workspaceId: f.workspaceId, origin, genesisFingerprint: await digestObject(f.prepared.payload.genesis), genesis: f.prepared.payload.genesis,
      transitions: (await f.admin.control.query('SELECT signed_transition FROM security.security_transitions WHERE workspace_id=$1 AND sequence>1 ORDER BY sequence', [f.workspaceId])).rows.map((r) => r.signed_transition),
      expected: { securityHead: w.security_head, securityVersion: w.security_version }, trustedServiceKeys: { [f.secrets.keyId]: await new EntitlementOperations(f.databases, f.secrets).publicSigningKey() } };
  }
  async function draft(action: AccessRequest['action'], targetAccountId: string, desired: AccessRequest['desired'] = null,
    auth = f.auth(), bundle: DeviceBundle = f.originalBundle) {
    const reference = { workspaceId: f.workspaceId, operationId: randomUUID() }, receiptToken = f.secrets.token();
    const request: AccessRequest = { ...reference, action, targetAccountId, desired, receiptTokenHash: await accessReceiptTokenHash(reference, receiptToken) };
    const context = await service.context(auth.cookieValue, auth.csrfToken, request), payload = await prepareAccessChange({ request, context, history: await history() }, bundle);
    const staged = await service.stage(auth.cookieValue, auth.csrfToken, payload); assert.equal(staged.requestHash, await digestObject(payload));
    return { reference, receiptToken, request, context, payload, finalize: { ...reference, receiptToken, requestHash: staged.requestHash! } };
  }
  const finalize = (prepared: Awaited<ReturnType<typeof draft>>, auth = f.auth()) => service.finalize(auth.cookieValue, auth.csrfToken, prepared.finalize);
  const status = (prepared: Awaited<ReturnType<typeof draft>>) => service.status(undefined, undefined, { ...prepared.reference, receiptToken: prepared.receiptToken });
  async function refresh(auth = f.auth(), bundle: DeviceBundle = f.originalBundle) {
    const delivery = await service.currentDelivery(auth.cookieValue, auth.csrfToken, { workspaceId: f.workspaceId });
    const input = await history(); return { delivery, refreshed: await refreshAccessKeys({ delivery, history: input }, bundle), history: input };
  }
  return { ...f, history, draft, finalize, status, refresh, get access() { return service; },
    setAccessHooks(value: typeof hooks = {}) { hooks = value; service = make(); }, advanceAccess(ms: number) { offset += ms; } };
}

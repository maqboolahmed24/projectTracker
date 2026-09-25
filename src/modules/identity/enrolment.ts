import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { contentEnvelope, identifier } from '../../shared/contracts.js';
import { base64urlDecode, base64urlEncode, canonicalJson, digestObject, verifyContentEnvelope, verifyObject } from '../../shared/crypto.js';
import { enrolmentBinding, enrolmentApproval, enrolmentConfirmation, enrolmentConfirmationFor, enrolmentReceipt,
  enrolmentReference, generateJoinCode, JOIN_CODE_TTL_MS, validateEnrolmentDraft, validateEnrolmentApproval,
  type EnrolmentBinding, type EnrolmentDraft, type EnrolmentPublicDraft, type EnrolmentApproval, type EnrolmentConfirmation,
  type EnrolmentReference, type EnrolmentOperationReference, type EnrolmentReceipt, type EnrolmentResult, type EnrolmentIssuedJoin } from '../../shared/enrolment.js';
import { enrolmentBegin, enrolmentIssueJoin, enrolmentBeginPromotion, enrolmentClaimPromotion, enrolmentRegistration,
  enrolmentProofStart, enrolmentProofFinish, enrolmentPromotionDraft, enrolmentUnlockStart, enrolmentUnlockFinish, enrolmentIssuanceRequest, type EnrolmentIssuanceContext, type EnrolmentAuth, type EnrolmentView } from '../../shared/enrolment-api.js';
import type { PairingMaterial, PairingScope } from '../../shared/pairing.js';
import { OpaqueService } from './opaque.js';
import { ServiceSecrets } from './secrets.js';
import { SessionService, type SessionPrincipal } from './sessions.js';
import { assertEntitlementAllows } from './entitlements.js';
import { intersectDeviceScopes, PersonalScopeError, personalScopesCover, readPersonalScopes } from './personal-scopes.js';
import { projectAuthoritativeWorkspace, withSecurityFence } from './projection.js';
export type { EnrolmentAuth } from '../../shared/enrolment-api.js';
interface Options { databases: Databases; secrets: ServiceSecrets; opaque: OpaqueService; sessions: SessionService; origin: string;
  now?: () => Date; requestBudget?: (scope: { workspaceId: string; accountId: string; history: boolean }) => Promise<void>;
  hooks?: { beforeControlCommit?: () => Promise<void>; afterControlCommit?: () => Promise<void>; beforeProjection?: () => Promise<void> } }
interface Authority { lifecycle: string; licence_state: string; security_head: string; security_version: string; data_generation: string;
  ownership_version: string; custody_epoch: string; genesis_object_id: string; current_custody_manifest_object_id: string; content_maintenance: boolean; restore_quarantine: boolean }
interface Profile { profile_id: string; state: string; is_owner: boolean; credential_generation: string; session_generation: string;
  invitation_generation: string; recovery_generation: string; profile_object_id: string; opaque_registration_record: string | null }
interface Saved { kind: EnrolmentBinding['kind']; roleId: string; projectIds: string[]; invitationGeneration: string; issuerAccountId: string;
  codeDigest?: string; codeKeyId?: string; redeemedAt?: string; resumeExpiresAt: string; attemptGeneration: string;
  binding?: EnrolmentBinding; draft?: EnrolmentPublicDraft; retainedIdentity?: { device: EnrolmentDraft['transcript']['device']; recovery: EnrolmentDraft['transcript']['recovery']; wrapperHash: string; registrationRecordHash: string | null };
  draftHash?: string; authorizerConfirmation?: EnrolmentConfirmation; proofId?: string; proofExpiresAt?: string; proofVerifiedAt?: string;
  requestHash?: string; approvalHash?: string; promotionSessionId?: string; unlockId?: string; unlockExpiresAt?: string; unlockHash?: string }
interface Ceremony { workspace_id: string; ceremony_id: string; profile_id: string; kind: string; state: string; generation: string;
  public_state: Saved; verification_digest: Buffer | null; verification_key_id: string | null; expires_at: Date;
  staged_registration_record: string | null; server_state_ciphertext: Buffer | null; server_state_key_id: string | null }
interface Stored { object_id: string; object_hash: string; object_kind: string; versioned_object: unknown; state: string; staged_operation_id: string }
const invalid = () => new AppError('ENROLMENT_INVALID', 'Enrolment is unavailable; resume a current invitation', 401);
const changed = () => new AppError('ENROLMENT_CHANGED', 'Enrolment authority changed; obtain fresh approval', 409);
const forbidden = () => new AppError('ENROLMENT_FORBIDDEN', 'Current approved authority is required', 403);
const equal = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const next = (n: string) => String(BigInt(n) + 1n);
function parse<T>(schema: z.ZodType<T>, value: unknown): T { const p = schema.safeParse(value); if (!p.success) throw new AppError('INVALID_REQUEST', 'Invalid enrolment request', 400); return p.data; }
/** Named invitations have no content authority until their signed fenced enrolment commits. */
export class EnrolmentService {
  readonly #o: Options; readonly #now: () => Date;
  constructor(options: Options) { if (new URL(options.origin).origin !== options.origin) throw new Error('Enrolment requires an exact origin'); this.#o = options; this.#now = options.now ?? (() => new Date()); }
  async #tx<T>(workspaceId: string, action: (c: pg.PoolClient, w: Authority, now: Date) => Promise<T>): Promise<T> {
    if (!identifier.safeParse(workspaceId).success) throw invalid();
    try { return await transaction(this.#o.databases.control, async (c) => {
      await c.query("SET LOCAL synchronous_commit='on'"); await c.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
      const w = (await c.query<Authority>('SELECT * FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE', [workspaceId])).rows[0];
      if (!w || !['active', 'pending_deletion'].includes(w.lifecycle) || w.security_version === '0') throw invalid();
      return action(c, w, this.#now());
    }); } catch (e) { if (e instanceof AppError) throw e; throw new AppError('ENROLMENT_UNAVAILABLE', 'Enrolment is temporarily unavailable; retain the local draft', 503); }
  }
  #writable(w: Authority, kind: EnrolmentBinding['kind']) { assertEntitlementAllows(w.licence_state, kind === 'promote_owner' ? 'promote_owner' : 'invite');
    if (w.lifecycle !== 'active' || w.content_maintenance || w.restore_quarantine) throw new AppError('WORKSPACE_RESTRICTED', 'Enrolment is unavailable while workspace writes are restricted', 423); }
  async #profile(c: pg.PoolClient, workspaceId: string, id: string): Promise<Profile> { const p = (await c.query<Profile>('SELECT * FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 FOR SHARE', [workspaceId, id])).rows[0]; if (!p) throw invalid(); return p; }
  async #session(c: pg.PoolClient, workspaceId: string, auth: EnrolmentAuth, now: Date, recent = true) { const p = await this.#o.sessions.resolveCurrent(c, auth.cookieValue, { csrfToken: auth.csrfToken, approved: true, recent }, now); if (p.workspaceId !== workspaceId) throw forbidden(); return p; }
  async #owner(c: pg.PoolClient, workspaceId: string, auth: EnrolmentAuth, now: Date) { const p = await this.#session(c, workspaceId, auth, now); const a = await this.#profile(c, workspaceId, p.accountId); if (!a.is_owner || a.state !== 'active') throw forbidden(); return p; }
  async #row(c: pg.PoolClient, ref: EnrolmentOperationReference, history = false): Promise<Ceremony> {
    if (!identifier.safeParse(ref.operationId).success) throw invalid();
    const row = (await c.query<Ceremony>('SELECT * FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2 FOR UPDATE', [ref.workspaceId, ref.operationId])).rows[0];
    if (!row || !['invitation', 'owner_promotion'].includes(row.kind) || !['join_member', 'join_owner', 'promote_owner'].includes(row.public_state.kind)) throw invalid();
    await this.#o.requestBudget?.({ workspaceId: row.workspace_id, accountId: row.profile_id, history }); return row;
  }
  #cap(row: Ceremony, ref: EnrolmentReference, now: Date) { parse(enrolmentReference, { workspaceId: ref.workspaceId, operationId: ref.operationId, resumeToken: ref.resumeToken });
    if (!row.verification_digest || row.verification_key_id !== this.#o.secrets.keyId || Date.parse(row.public_state.resumeExpiresAt) <= now.getTime() ||
      !this.#o.secrets.matches('enrolment-resume', `${row.workspace_id}:${row.ceremony_id}:${ref.resumeToken}`, row.verification_digest)) throw invalid(); }
  #live(row: Ceremony, now: Date) { if (!['issued', 'waiting_approval'].includes(row.state) || row.expires_at <= now) throw invalid(); }
  async #save(c: pg.PoolClient, row: Ceremony) { await c.query('UPDATE security.ceremonies SET public_state=$3 WHERE workspace_id=$1 AND ceremony_id=$2', [row.workspace_id, row.ceremony_id, row.public_state]); }
  async #role(c: pg.PoolClient, workspaceId: string, roleId: string, kind: EnrolmentBinding['kind']) {
    const r = (await c.query<{ role_id: string; revision: string; permissions: EnrolmentBinding['role']['permissions']; template: string }>(`SELECT r.* FROM security.roles r JOIN security.staged_objects o ON o.workspace_id=r.workspace_id AND o.object_id=r.definition_object_id AND o.state='committed' WHERE r.workspace_id=$1 AND r.role_id=$2 AND r.state='active'`, [workspaceId, roleId])).rows[0];
    if (!r || (r.template === 'owner') !== (kind !== 'join_member')) throw changed(); return r;
  }
  async #device(c: pg.PoolClient, workspaceId: string, accountId: string, deviceId: string) {
    const d = (await c.query<{ device_id: string; key_generation: string; signing_public_key: Buffer; recipient_public_key: Buffer }>("SELECT * FROM security.devices WHERE workspace_id=$1 AND profile_id=$2 AND device_id=$3 AND state='active' AND revoked_at IS NULL", [workspaceId, accountId, deviceId])).rows[0];
    if (!d) throw forbidden(); return { id: d.device_id, keyGeneration: d.key_generation, signingPublicKey: base64urlEncode(d.signing_public_key), recipientPublicKey: base64urlEncode(d.recipient_public_key) };
  }
  async #binding(c: pg.PoolClient, row: Ceremony, w: Authority, authorizer: EnrolmentBinding['authorizer'], now: Date, attemptId: string, attemptGeneration: string): Promise<EnrolmentBinding> {
    const s = row.public_state, target = await this.#profile(c, row.workspace_id, row.profile_id), promote = s.kind === 'promote_owner';
    if (target.is_owner || target.state !== (promote ? 'active' : 'pending') || (!promote && (target.credential_generation !== '0' || target.invitation_generation !== s.invitationGeneration))) throw changed();
    const role = await this.#role(c, row.workspace_id, s.roleId, s.kind);
    const profileObject = (await c.query<Stored>("SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND object_kind='encrypted_profile' AND state='committed'", [row.workspace_id, target.profile_object_id])).rows[0];
    if (!profileObject || await digestObject(profileObject.versioned_object) !== profileObject.object_hash) throw changed();
    const profileEnvelope = contentEnvelope.parse(profileObject.versioned_object);
    const genesis = (await c.query<Stored>("SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND state='committed'", [row.workspace_id, w.genesis_object_id])).rows[0]; if (!genesis) throw changed();
    const heads = (await c.query<{ scope_kind: 'workspace' | 'project'; scope_id: string; key_epoch: string; recovery_manifest_object_id: string; object_hash: string }>(`SELECT h.*,o.object_hash FROM security.scope_heads h JOIN security.staged_objects o ON o.workspace_id=h.workspace_id AND o.object_id=h.recovery_manifest_object_id AND o.state='committed' WHERE h.workspace_id=$1 AND h.security_version<=$2 ORDER BY h.scope_kind,h.scope_id`, [row.workspace_id, w.security_version])).rows;
    const workspaceHead = heads.find((h) => h.scope_kind === 'workspace' && h.scope_id === row.workspace_id); if (!workspaceHead) throw changed();
    const personal = await readPersonalScopes(c, row.workspace_id, authorizer.accountId, true, now), workspace = personal.find((p) => p.scope === 'workspace')!;
    const projectIds = s.kind === 'join_member' ? s.projectIds : heads.filter((h) => h.scope_kind === 'project').map((h) => h.scope_id);
    const scopes: PairingScope[] = [{ ...workspace, mode: s.kind === 'join_member' ? 'content' : 'custody',
      keyEpoch: s.kind === 'join_member' ? workspaceHead.key_epoch : w.custody_epoch, permissions: [...role.permissions] }];
    for (const id of projectIds) { const source = personal.find((p) => p.scope === 'project' && p.scopeId === id), head = heads.find((h) => h.scope_kind === 'project' && h.scope_id === id);
      if (!source || !head || source.keyEpoch !== head.key_epoch || role.permissions.some((p) => !source.permissions.includes(p))) throw changed();
      scopes.push({ ...source, permissions: [...role.permissions] }); }
    scopes.sort((a, b) => `${a.scope}:${a.scopeId}`.localeCompare(`${b.scope}:${b.scopeId}`));
    const allDevices = (await c.query<{ device_id: string; state: string; key_generation: string }>('SELECT device_id,state,key_generation FROM security.devices WHERE workspace_id=$1 AND profile_id=$2 ORDER BY device_id', [row.workspace_id, row.profile_id])).rows;
    const currentDevices: EnrolmentBinding['currentDevices'] = [];
    if (promote) { const membership = await readPersonalScopes(c, row.workspace_id, row.profile_id, false, now);
      for (const d of allDevices.filter((d) => d.state === 'active')) { try {
        await intersectDeviceScopes(c, row.workspace_id, row.profile_id, d.device_id, membership, now);
        currentDevices.push(await this.#device(c, row.workspace_id, row.profile_id, d.device_id));
      } catch (error) { if (!(error instanceof PersonalScopeError)) throw error; } }
    }
    const maximum = allDevices.reduce((n, d) => BigInt(d.key_generation) > n ? BigInt(d.key_generation) : n, 0n).toString();
    if (!promote && allDevices.length) throw changed();
    return enrolmentBinding.parse({ version: 1, kind: s.kind, origin: this.#o.origin, workspaceId: row.workspace_id, accountId: row.profile_id, operationId: row.ceremony_id,
      approvalAttemptId: attemptId, attemptGeneration, invitationGeneration: promote ? '0' : target.invitation_generation,
      profile: { id: row.profile_id, revision: profileEnvelope.header.revision, objectId: profileObject.object_id, objectDigest: profileObject.object_hash },
      nextProfileRevision: promote ? profileEnvelope.header.revision : next(profileEnvelope.header.revision), role: { id: role.role_id, revision: role.revision, permissions: role.permissions },
      credentialGeneration: target.credential_generation, nextCredentialGeneration: promote ? target.credential_generation : '1',
      sessionGeneration: promote ? target.session_generation : '0', nextSessionGeneration: promote ? next(target.session_generation) : '1',
      recoveryGeneration: target.recovery_generation, nextRecoveryGeneration: s.kind === 'join_member' ? '0' : next(target.recovery_generation),
      deviceKeyGeneration: maximum, nextDeviceKeyGeneration: promote ? maximum : '1', ownershipVersion: w.ownership_version,
      nextOwnershipVersion: s.kind === 'join_member' ? w.ownership_version : next(w.ownership_version), securityVersion: w.security_version, nextSecurityVersion: next(w.security_version),
      securityHead: w.security_head, genesisFingerprint: genesis.object_hash, dataGeneration: w.data_generation, custodyEpoch: w.custody_epoch,
      workspaceKeyEpoch: workspaceHead.key_epoch, authorizer, currentDevices, scopes, issuedAt: s.binding?.issuedAt ?? now.toISOString(), expiresAt: row.expires_at.toISOString() });
  }
  async #check(c: pg.PoolClient, row: Ceremony, w: Authority, now: Date) {
    this.#live(row, now); this.#writable(w, row.public_state.kind); const b = row.public_state.binding; if (!b) throw invalid();
    const owner = await this.#profile(c, row.workspace_id, b.authorizer.accountId);
    if (!owner.is_owner || owner.state !== 'active' || owner.credential_generation !== b.authorizer.credentialGeneration || owner.session_generation !== b.authorizer.sessionGeneration ||
      !equal(await this.#device(c, row.workspace_id, owner.profile_id, b.authorizer.device.id), b.authorizer.device)) throw forbidden();
    const personal = await readPersonalScopes(c, row.workspace_id, owner.profile_id, true, now);
    await intersectDeviceScopes(c, row.workspace_id, owner.profile_id, b.authorizer.device.id, personal, now);
    if (!equal(b, await this.#binding(c, row, w, b.authorizer, now, b.approvalAttemptId, b.attemptGeneration))) throw changed();
  }
  async #with<T>(ref: EnrolmentOperationReference | EnrolmentReference, auth: EnrolmentAuth | undefined,
    action: (c: pg.PoolClient, row: Ceremony, w: Authority, now: Date, principal?: SessionPrincipal) => Promise<T>, checked = true): Promise<T> {
    return this.#tx(ref.workspaceId, async (c, w, now) => { const principal = auth ? await this.#owner(c, ref.workspaceId, auth, now) : undefined;
      const row = await this.#row(c, ref); if (!principal) { if (!('resumeToken' in ref)) throw invalid(); this.#cap(row, ref, now); }
      if (checked) await this.#check(c, row, w, now); return action(c, row, w, now, principal); });
  }
  #approver(row: Ceremony, p?: SessionPrincipal) { const a = row.public_state.binding?.authorizer; if (!a || !p || a.accountId !== p.accountId || a.device.id !== p.deviceId) throw forbidden(); }
  async #receipt(c: pg.PoolClient, row: Ceremony): Promise<EnrolmentReceipt> { const receipt = (await c.query<{ outcome: unknown; request_hash: string }>("SELECT outcome,request_hash FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2 AND operation_kind IN ('profile.enrol','owner.promote')", [row.workspace_id, row.ceremony_id])).rows[0];
    if (!receipt || receipt.request_hash !== row.public_state.requestHash) throw invalid(); return enrolmentReceipt.parse(receipt.outcome); }
  async #view(c: pg.PoolClient, row: Ceremony, now: Date): Promise<EnrolmentView> { const s = row.public_state, d = s.draft;
    return { workspaceId: row.workspace_id, accountId: row.profile_id, operationId: row.ceremony_id, kind: s.kind,
      state: row.state === 'completed' ? 'completed' : ['cancelled', 'revoked', 'expired'].includes(row.state) ? row.state as 'cancelled' | 'revoked' | 'expired' :
        row.expires_at <= now ? 'expired' : s.requestHash ? 'confirmed' : d ? 'verifying' : s.binding ? 'waiting_approval' : 'issued',
      binding: s.binding ?? null, publicDraft: d ?? null, transcript: d?.transcript ?? null, transcriptDigest: d ? await digestObject(d.transcript) : null,
      recipientConfirmation: d?.recipientConfirmation ?? null, newRecoveryConfirmation: d?.newRecoveryConfirmation ?? null, authorizerConfirmation: s.authorizerConfirmation ?? null,
      passwordProved: Boolean(s.proofVerifiedAt), approvalStaged: Boolean(s.requestHash), approvalHash: s.approvalHash ?? null, requestHash: s.requestHash ?? null,
      receipt: row.state === 'completed' ? await this.#receipt(c, row) : null, expiresAt: row.expires_at.toISOString(), resumeExpiresAt: s.resumeExpiresAt };
  }
  async #insert(c: pg.PoolClient, w: Authority, owner: SessionPrincipal, workspaceId: string, accountId: string, operationId: string, saved: Saved, now: Date, expires: Date) {
    await c.query(`INSERT INTO security.ceremonies(workspace_id,ceremony_id,profile_id,kind,generation,approving_profile_id,approving_device_id,
      expected_credential_generation,expected_ownership_version,expected_security_version,expected_custody_epoch,public_state,created_at,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, [workspaceId, operationId, accountId, saved.kind === 'promote_owner' ? 'owner_promotion' : 'invitation',
      saved.kind === 'promote_owner' ? '1' : saved.invitationGeneration, owner.accountId, owner.deviceId, (await this.#profile(c, workspaceId, accountId)).credential_generation,
      w.ownership_version, w.security_version, w.custody_epoch, saved, now, expires]);
  }
  async issueJoin(cookie: string, csrf: string, input: unknown): Promise<EnrolmentIssuedJoin> {
    const r = parse(enrolmentIssueJoin, input);
    return this.#tx(r.workspaceId, async (c, w, now) => { this.#writable(w, r.kind); const owner = await this.#owner(c, r.workspaceId, { cookieValue: cookie, csrfToken: csrf }, now);
      await this.#o.requestBudget?.({ workspaceId: r.workspaceId, accountId: r.accountId, history: false });
      if (owner.accountId === r.accountId || (await c.query('SELECT 1 FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [r.workspaceId, r.operationId])).rowCount) throw changed();
      const role = await this.#role(c, r.workspaceId, r.roleId, r.kind), signer = await this.#device(c, r.workspaceId, owner.accountId, owner.deviceId!);
      const existing = (await c.query<Profile>('SELECT * FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 FOR UPDATE', [r.workspaceId, r.accountId])).rows[0];
      if (existing && (existing.state !== 'pending' || existing.credential_generation !== '0' || existing.is_owner)) throw changed();
      const epoch = (await c.query<{ key_epoch: string }>("SELECT key_epoch FROM security.scope_heads WHERE workspace_id=$1 AND scope_kind='workspace' AND scope_id=$1", [r.workspaceId])).rows[0]?.key_epoch;
      const prior = existing?.profile_object_id ? (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [r.workspaceId, existing.profile_object_id])).rows[0] : undefined;
      const revision = prior ? next(contentEnvelope.parse(prior.versioned_object).header.revision) : '1', header = r.profile.envelope.header;
      const expected = { version: 1 as const, purpose: 'ukda.content.v1' as const, algorithm: 'XChaCha20-Poly1305' as const, workspaceId: r.workspaceId,
        scope: 'workspace' as const, scopeId: r.workspaceId, recordId: r.accountId, recordType: 'profile' as const, schema: 1 as const,
        keyEpoch: epoch!, revision, operationId: r.operationId, accountId: owner.accountId, deviceId: signer.id, keyGeneration: signer.keyGeneration,
        permissionVersion: role.revision, securityVersion: w.security_version, securityHead: w.security_head, dataGeneration: w.data_generation,
        action: 'profile.invite', approvalPolicyId: null, approvalPolicyRevision: null };
      if (!epoch || !equal(header, expected) || !await verifyContentEnvelope(r.profile.envelope, base64urlDecode(signer.signingPublicKey), expected)) throw changed();
      const personal = await readPersonalScopes(c, r.workspaceId, owner.accountId, true, now);
      if (r.projectIds.some((id) => !personal.some((p) => p.scope === 'project' && p.scopeId === id && role.permissions.every((permission) => p.permissions.includes(permission))))) throw changed();
      await c.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version,created_at)
        VALUES($1,$2,'encrypted_profile',$3,$4,$5,'committed',$6,$7)`, [r.workspaceId, r.profile.id, await digestObject(r.profile.envelope), r.profile.envelope, r.operationId, w.security_version, now]);
      const generation = next(existing?.invitation_generation ?? '0');
      if (existing) await c.query('UPDATE security.profiles SET invitation_generation=$3,profile_object_id=$4,updated_at=$5 WHERE workspace_id=$1 AND profile_id=$2', [r.workspaceId, r.accountId, generation, r.profile.id, now]);
      else await c.query('INSERT INTO security.profiles(workspace_id,profile_id,profile_object_id,invitation_generation,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5)', [r.workspaceId, r.accountId, r.profile.id, generation, now]);
      await c.query("UPDATE security.ceremonies SET state='revoked',staged_registration_record=NULL,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND profile_id=$2 AND kind='invitation' AND state IN ('issued','waiting_approval')", [r.workspaceId, r.accountId]);
      const code = generateJoinCode(), expires = new Date(now.getTime() + JOIN_CODE_TTL_MS), saved: Saved = { kind: r.kind, roleId: r.roleId, projectIds: r.projectIds,
        invitationGeneration: generation, issuerAccountId: owner.accountId, codeDigest: this.#o.secrets.digest('enrolment-code', `${r.workspaceId}:${code}`).toString('hex'), codeKeyId: this.#o.secrets.keyId,
        resumeExpiresAt: expires.toISOString(), attemptGeneration: '0' };
      await this.#insert(c, w, owner, r.workspaceId, r.accountId, r.operationId, saved, now, expires);
      return { workspaceId: r.workspaceId, accountId: r.accountId, operationId: r.operationId, invitationGeneration: generation, code, expiresAt: expires.toISOString() };
    });
  }
  async revokeJoin(cookie: string, csrf: string, ref: EnrolmentOperationReference): Promise<EnrolmentView> { return this.#with(ref, { cookieValue: cookie, csrfToken: csrf }, async (c, row, _w, now) => {
    if (row.kind !== 'invitation' || row.state === 'completed') throw invalid(); await this.#retire(c, row, 'revoked'); return this.#view(c, row, now); }, false); }
  async #retire(c: pg.PoolClient, row: Ceremony, state: 'cancelled' | 'revoked') { await c.query('UPDATE security.ceremonies SET state=$3,staged_registration_record=NULL,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND ceremony_id=$2', [row.workspace_id, row.ceremony_id, state]); row.state = state; }
  async begin(input: unknown): Promise<EnrolmentView> { const r = parse(enrolmentBegin, input); return this.#tx(r.workspaceId, async (c, w, now) => {
    const digest = this.#o.secrets.digest('enrolment-code', `${r.workspaceId}:${r.code}`).toString('hex');
    const matches = (await c.query<Ceremony>("SELECT * FROM security.ceremonies WHERE workspace_id=$1 AND kind='invitation' AND public_state->>'codeDigest'=$2 AND public_state->>'codeKeyId'=$3 FOR UPDATE", [r.workspaceId, digest, this.#o.secrets.keyId])).rows;
    if (matches.length !== 1) throw invalid(); const row = matches[0]!; await this.#o.requestBudget?.({ workspaceId: row.workspace_id, accountId: row.profile_id, history: false });
    if (row.public_state.redeemedAt) { this.#cap(row, { workspaceId: row.workspace_id, operationId: row.ceremony_id, resumeToken: r.resumeToken }, now); if (row.state === 'completed') return this.#view(c, row, now); }
    this.#live(row, now); this.#writable(w, row.public_state.kind); const target = await this.#profile(c, row.workspace_id, row.profile_id);
    if (target.state !== 'pending' || target.invitation_generation !== row.public_state.invitationGeneration) throw invalid();
    if (!row.public_state.redeemedAt) { row.public_state.redeemedAt = now.toISOString(); await c.query('UPDATE security.ceremonies SET verification_digest=$3,verification_key_id=$4,public_state=$5 WHERE workspace_id=$1 AND ceremony_id=$2', [row.workspace_id, row.ceremony_id,
      this.#o.secrets.digest('enrolment-resume', `${row.workspace_id}:${row.ceremony_id}:${r.resumeToken}`), this.#o.secrets.keyId, row.public_state]); }
    return this.#view(c, row, now);
  }); }
  async beginPromotion(cookie: string, csrf: string, input: unknown): Promise<EnrolmentView> { const r = parse(enrolmentBeginPromotion, input); return this.#tx(r.workspaceId, async (c, w, now) => {
    this.#writable(w, 'promote_owner'); const owner = await this.#owner(c, r.workspaceId, { cookieValue: cookie, csrfToken: csrf }, now), target = await this.#profile(c, r.workspaceId, r.accountId);
    await this.#o.requestBudget?.({ workspaceId: r.workspaceId, accountId: r.accountId, history: false });
    if (owner.accountId === target.profile_id || target.state !== 'active' || target.is_owner) throw changed();
    const role = (await c.query<{ role_id: string }>("SELECT role_id FROM security.roles WHERE workspace_id=$1 AND template='owner' AND state='active'", [r.workspaceId])).rows[0]; if (!role) throw changed();
    const prior = (await c.query<Ceremony>('SELECT * FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [r.workspaceId, r.operationId])).rows[0];
    if (prior) { if (prior.profile_id !== r.accountId || prior.kind !== 'owner_promotion') throw changed(); return this.#view(c, prior, now); }
    await c.query("UPDATE security.ceremonies SET state='cancelled',staged_registration_record=NULL,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND profile_id=$2 AND kind='owner_promotion' AND state IN ('issued','waiting_approval')", [r.workspaceId, r.accountId]);
    const expires = new Date(now.getTime() + JOIN_CODE_TTL_MS), saved: Saved = { kind: 'promote_owner', roleId: role.role_id, projectIds: [], invitationGeneration: '0', issuerAccountId: owner.accountId, resumeExpiresAt: expires.toISOString(), attemptGeneration: '0' };
    await this.#insert(c, w, owner, r.workspaceId, r.accountId, r.operationId, saved, now, expires); return this.#view(c, await this.#row(c, r), now);
  }); }
  async claimPromotion(input: unknown, auth: EnrolmentAuth): Promise<EnrolmentView> { const r = parse(enrolmentClaimPromotion, input); return this.#tx(r.workspaceId, async (c, w, now) => {
    const target = await this.#session(c, r.workspaceId, auth, now), row = await this.#row(c, r); this.#writable(w, 'promote_owner'); this.#live(row, now);
    if (row.kind !== 'owner_promotion' || target.accountId !== row.profile_id) throw forbidden();
    if (row.public_state.redeemedAt) this.#cap(row, r, now); else { row.public_state.redeemedAt = now.toISOString();
      await c.query('UPDATE security.ceremonies SET verification_digest=$3,verification_key_id=$4,public_state=$5 WHERE workspace_id=$1 AND ceremony_id=$2', [row.workspace_id, row.ceremony_id, this.#o.secrets.digest('enrolment-resume', `${row.workspace_id}:${row.ceremony_id}:${r.resumeToken}`), this.#o.secrets.keyId, row.public_state]); }
    return this.#view(c, row, now);
  }); }
  async claim(ref: EnrolmentOperationReference, auth: EnrolmentAuth): Promise<EnrolmentView> { return this.#with(ref, auth, async (c, row, w, now, principal) => {
    this.#live(row, now); this.#writable(w, row.public_state.kind); const s = row.public_state; if (!s.redeemedAt || principal!.accountId === row.profile_id) throw forbidden();
    const authorizer = { accountId: principal!.accountId, device: await this.#device(c, row.workspace_id, principal!.accountId, principal!.deviceId!), credentialGeneration: principal!.credentialGeneration, sessionGeneration: principal!.sessionGeneration };
    if (s.binding && equal(s.binding.authorizer, authorizer)) { try { await this.#check(c, row, w, now); return this.#view(c, row, now); } catch (e) { if (!(e instanceof AppError)) throw e; } }
    if (s.draft) s.retainedIdentity = { device: s.draft.transcript.device, recovery: s.draft.transcript.recovery, wrapperHash: s.draft.transcript.wrapperHash, registrationRecordHash: s.draft.transcript.registrationRecordHash };
    s.attemptGeneration = next(s.attemptGeneration); delete s.binding; delete s.draft; delete s.draftHash; delete s.proofId; delete s.proofExpiresAt; delete s.proofVerifiedAt; delete s.authorizerConfirmation; delete s.requestHash; delete s.approvalHash; delete s.promotionSessionId;
    s.binding = await this.#binding(c, row, w, authorizer, now, randomUUID(), s.attemptGeneration);
    await c.query("UPDATE security.ceremonies SET state='waiting_approval',approving_profile_id=$3,approving_device_id=$4,public_state=$5,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND ceremony_id=$2", [row.workspace_id, row.ceremony_id, principal!.accountId, principal!.deviceId, s]);
    row.state = 'waiting_approval'; return this.#view(c, row, now);
  }, false); }
  async inspect(ref: EnrolmentOperationReference | EnrolmentReference, auth?: EnrolmentAuth): Promise<EnrolmentView> { return this.#with(ref, auth, (c, row, _w, now) => this.#view(c, row, now), false); }
  async registration(input: unknown) { const r = parse(enrolmentRegistration, input); return this.#with(r, undefined, (_c, row) => { if (row.kind !== 'invitation') throw invalid(); return this.#o.opaque.response(row.workspace_id, row.profile_id, r.registrationRequest); }); }
  #proofContext(row: Ceremony, proofId: string, hash: string) { return canonicalJson(['ukda.enrolment-password-proof.v1', this.#o.origin, row.workspace_id, row.ceremony_id, row.public_state.binding!.approvalAttemptId, row.profile_id, proofId, hash]); }
  async #freshKeys(c: pg.PoolClient, row: Ceremony, transcript: EnrolmentDraft['transcript']) {
    const device = transcript.device, recovery = transcript.recovery;
    if (recovery && (recovery.signingPublicKey === device.signingPublicKey || recovery.recipientPublicKey === device.recipientPublicKey)) throw changed();
    for (const key of [...(row.kind === 'invitation' ? [device] : []), ...(recovery ? [recovery] : [])]) {
      if ((await c.query(`SELECT 1 FROM security.devices WHERE workspace_id=$1 AND (device_id=$2 OR signing_public_key=$3 OR recipient_public_key=$4)
        UNION ALL SELECT 1 FROM security.recovery_authorities r JOIN security.staged_objects o ON o.workspace_id=r.workspace_id AND o.object_id=r.custody_envelope_object_id
        WHERE r.workspace_id=$1 AND (o.versioned_object->'header'->>'recipientId'=$2::text OR r.proof_public_key=$3 OR r.recipient_public_key=$4)`,
      [row.workspace_id, key.id, base64urlDecode(key.signingPublicKey), base64urlDecode(key.recipientPublicKey)])).rowCount) throw changed();
    }
    const retained = row.public_state.retainedIdentity;
    if (retained && !equal(retained, { device, recovery, wrapperHash: transcript.wrapperHash, registrationRecordHash: transcript.registrationRecordHash })) throw changed();
  }
  async startProof(input: unknown) { const r = parse(enrolmentProofStart, input); return this.#with(r, undefined, async (c, row, _w, now) => {
    if (row.kind !== 'invitation') throw invalid(); const configuration = await this.#o.opaque.publicConfiguration(row.workspace_id, row.profile_id);
    let checked: Awaited<ReturnType<typeof validateEnrolmentDraft>>; try { checked = await validateEnrolmentDraft(r.draft, row.public_state.binding!, configuration); } catch { throw changed(); }
    const { registrationRecord, ...draft } = checked.draft; if (!registrationRecord) throw invalid();
    if (row.public_state.draftHash && row.public_state.draftHash !== checked.draftHash) throw changed();
    if (row.public_state.draft?.recipientConfirmation && draft.recipientConfirmation && !equal(row.public_state.draft.recipientConfirmation, draft.recipientConfirmation)) throw changed();
    draft.recipientConfirmation ??= row.public_state.draft?.recipientConfirmation ?? null;
    await this.#freshKeys(c, row, draft.transcript); await this.#o.opaque.validateRegistrationRecord(row.workspace_id, row.profile_id, registrationRecord);
    const proof = await this.#o.opaque.startLogin(row.workspace_id, row.profile_id, registrationRecord, r.startLoginRequest), proofId = randomUUID();
    const expiresAt = new Date(Math.min(now.getTime() + 120_000, row.expires_at.getTime())), state = await this.#o.secrets.protectState(this.#proofContext(row, proofId, checked.draftHash), proof.serverLoginState);
    Object.assign(row.public_state, { draft, draftHash: checked.draftHash, proofId, proofExpiresAt: expiresAt.toISOString() }); delete row.public_state.proofVerifiedAt;
    await c.query('UPDATE security.ceremonies SET public_state=$3,staged_registration_record=$4,server_state_ciphertext=$5,server_state_key_id=$6 WHERE workspace_id=$1 AND ceremony_id=$2', [row.workspace_id, row.ceremony_id, row.public_state, registrationRecord, Buffer.from(state), this.#o.secrets.keyId]);
    return { proofId, expiresAt: expiresAt.toISOString(), loginResponse: proof.loginResponse, configuration, draftHash: checked.draftHash };
  }); }
  async finishProof(input: unknown) { const r = parse(enrolmentProofFinish, input); const accepted = await this.#with(r, undefined, async (c, row, _w, now) => {
    const s = row.public_state, expiry = s.proofExpiresAt; if (row.kind !== 'invitation' || s.proofId !== r.proofId || !expiry || !s.draftHash || !row.server_state_ciphertext) return false;
    delete s.proofExpiresAt; delete s.proofVerifiedAt;
    await c.query('UPDATE security.ceremonies SET public_state=$3,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND ceremony_id=$2', [row.workspace_id, row.ceremony_id, s]);
    if (Date.parse(expiry) <= now.getTime() || row.server_state_key_id !== this.#o.secrets.keyId) return false;
    try { const state = await this.#o.secrets.revealState(this.#proofContext(row, r.proofId, s.draftHash), row.server_state_ciphertext.toString()); await this.#o.opaque.finishLogin(row.workspace_id, row.profile_id, state, r.finishLoginRequest); } catch { return false; }
    s.proofVerifiedAt = now.toISOString(); await this.#save(c, row); return true;
  }); if (!accepted) throw invalid(); return { verified: true as const }; }
  async stagePromotion(input: unknown, auth: EnrolmentAuth): Promise<EnrolmentView> { const r = parse(enrolmentPromotionDraft, input); return this.#tx(r.workspaceId, async (c, w, now) => {
    const target = await this.#session(c, r.workspaceId, auth, now), row = await this.#row(c, r); this.#cap(row, r, now); await this.#check(c, row, w, now);
    if (row.kind !== 'owner_promotion' || target.accountId !== row.profile_id || target.deviceId !== r.draft.transcript.device.id) throw forbidden();
    let checked: Awaited<ReturnType<typeof validateEnrolmentDraft>>; try { checked = await validateEnrolmentDraft(r.draft, row.public_state.binding!, null); } catch { throw changed(); }
    if (row.public_state.draftHash && row.public_state.draftHash !== checked.draftHash) throw changed(); await this.#freshKeys(c, row, checked.draft.transcript);
    const { registrationRecord: _record, ...draft } = checked.draft; draft.recipientConfirmation ??= row.public_state.draft?.recipientConfirmation ?? null;
    Object.assign(row.public_state, { draft, draftHash: checked.draftHash, proofVerifiedAt: now.toISOString(), promotionSessionId: target.sessionId });
    await this.#save(c, row); return this.#view(c, row, now);
  }); }
  async #proved(c: pg.PoolClient, row: Ceremony, now: Date) { const s = row.public_state;
    if (!s.draft || !s.proofVerifiedAt || now.getTime() - Date.parse(s.proofVerifiedAt) >= 300_000 || (row.kind === 'invitation' && !row.staged_registration_record)) throw new AppError('PASSWORD_PROOF_REQUIRED', 'Confirm the current enrolment password proof', 401);
    if (row.kind === 'owner_promotion') { const b = s.binding!;
      const valid = await c.query(`SELECT 1 FROM security.sessions WHERE workspace_id=$1 AND profile_id=$2 AND session_id=$3 AND device_id=$4
        AND access_level='device_approved' AND credential_generation=$5 AND session_generation=$6 AND data_generation=$7 AND revoked_at IS NULL
        AND authenticated_at>$8 AND idle_expires_at>$9 AND absolute_expires_at>$9`, [row.workspace_id, row.profile_id, s.promotionSessionId, s.draft.transcript.device.id,
      b.credentialGeneration, b.sessionGeneration, b.dataGeneration, new Date(now.getTime() - 300_000), now]); if (!valid.rowCount) throw forbidden(); }
  }
  async confirm(ref: EnrolmentOperationReference | EnrolmentReference, input: unknown, auth?: EnrolmentAuth): Promise<EnrolmentView> { const confirmation = parse(enrolmentConfirmation, input);
    const result = await this.#with(ref, auth, async (c, row, _w, now, p) => { const d = row.public_state.draft; if (!d || confirmation.body.role === 'new_recovery') throw invalid();
      const binding = d.transcript.binding;
      if (confirmation.body.workspaceId !== binding.workspaceId || confirmation.body.operationId !== binding.operationId ||
        confirmation.body.approvalAttemptId !== binding.approvalAttemptId || confirmation.body.attemptGeneration !== binding.attemptGeneration) throw changed();
      if (confirmation.body.role === 'authorizer') this.#approver(row, p); else if (p) throw forbidden();
      const key = confirmation.body.role === 'authorizer' ? d.transcript.binding.authorizer.device.signingPublicKey : d.transcript.device.signingPublicKey;
      if (!equal(confirmation.body, enrolmentConfirmationFor(d.transcript, await digestObject(d.transcript), confirmation.body.role)) || !await verifyObject(confirmation, base64urlDecode(key), 'ukda.enrolment-confirmation.v1')) {
        await this.#retire(c, row, 'cancelled'); return { error: invalid() }; }
      if (confirmation.body.role === 'authorizer') row.public_state.authorizerConfirmation = confirmation; else d.recipientConfirmation = confirmation;
      await this.#save(c, row); return { view: await this.#view(c, row, now) };
    }); if ('error' in result) throw result.error; return result.view;
  }
  async #materials(c: pg.PoolClient, workspaceId: string, deviceId: string, scopes: readonly PairingScope[], custodyEpoch: string, custody: boolean): Promise<PairingMaterial[]> {
    const ids = [...new Set(scopes.flatMap((s) => s.sources.map((v) => v.manifestId)))];
    const rows = (await c.query<Stored>(`SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND state='committed' AND
      (object_id=ANY($2::uuid[]) OR (object_kind='key_envelope' AND versioned_object->'header'->>'recipientId'=$3 AND versioned_object->'header'->>'recipientKind'='device')
      OR ($4 AND object_kind='custody_manifest' AND versioned_object->'header'->>'scope'='workspace' AND versioned_object->'header'->>'keyEpoch'=$5)) ORDER BY object_id`, [workspaceId, ids, deviceId, custody, custodyEpoch])).rows;
    const materials: PairingMaterial[] = [];
    for (const o of rows) { const h = (o.versioned_object as { header?: { scope: string; scopeId: string } }).header;
      if (!ids.includes(o.object_id) && !scopes.some((s) => s.scope === h?.scope && s.scopeId === h.scopeId)) continue;
      if (await digestObject(o.versioned_object) !== o.object_hash) throw invalid(); materials.push({ id: o.object_id, digest: o.object_hash, kind: o.object_kind, value: o.versioned_object }); }
    if (ids.some((id) => !materials.some((m) => m.id === id))) throw invalid(); return materials;
  }
  async materials(ref: EnrolmentOperationReference, auth: EnrolmentAuth): Promise<PairingMaterial[]> { return this.#with(ref, auth, async (c, row, _w, _now, p) => {
    this.#approver(row, p); const b = row.public_state.binding!, materials = await this.#materials(c, row.workspace_id, p!.deviceId!, b.scopes, b.custodyEpoch, true);
    if (row.kind === 'invitation') { const profile = (await c.query<Stored>("SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND object_kind='encrypted_profile' AND state='committed'", [row.workspace_id, b.profile.objectId])).rows[0];
      if (!profile || profile.object_hash !== b.profile.objectDigest || await digestObject(profile.versioned_object) !== b.profile.objectDigest) throw changed();
      materials.push({ id: profile.object_id, digest: profile.object_hash, kind: profile.object_kind, value: profile.versioned_object }); }
    return materials;
  }); }
  async stage(ref: EnrolmentOperationReference, input: unknown, auth: EnrolmentAuth): Promise<EnrolmentView> { const approval = parse(enrolmentApproval, input); return this.#with(ref, auth, async (c, row, _w, now, p) => {
    this.#approver(row, p); await this.#proved(c, row, now); const s = row.public_state;
    if (!s.authorizerConfirmation || !equal(s.authorizerConfirmation, approval.transition.body.authorizerConfirmation)) throw changed();
    let checked: Awaited<ReturnType<typeof validateEnrolmentApproval>>;
    try { checked = await validateEnrolmentApproval(approval, { ...s.draft!, registrationRecord: row.staged_registration_record }, s.binding!, row.kind === 'invitation' ? await this.#o.opaque.publicConfiguration(row.workspace_id, row.profile_id) : null); } catch { throw changed(); }
    if (s.requestHash && s.requestHash !== checked.requestHash) throw changed(); await this.#freshKeys(c, row, s.draft!.transcript);
    const objects = [{ id: s.binding!.approvalAttemptId, kind: 'signed_grant', value: approval.transition }, ...approval.deliveries.map((d) => ({ id: d.id, kind: 'key_envelope', value: d.envelope })), ...(approval.profile ? [{ id: approval.profile.id, kind: 'encrypted_profile', value: approval.profile.envelope }] : [])];
    if (new Set(objects.map((o) => o.id)).size !== objects.length) throw changed();
    for (const o of objects) { const hash = await digestObject(o.value), previous = (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [row.workspace_id, o.id])).rows[0];
      if (previous && (previous.object_hash !== hash || previous.object_kind !== o.kind || previous.staged_operation_id !== s.binding!.approvalAttemptId || previous.state !== 'staged')) throw changed();
      if (!previous) await c.query('INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)', [row.workspace_id, o.id, o.kind, hash, o.value, s.binding!.approvalAttemptId, now, row.expires_at]);
      const readback = (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [row.workspace_id, o.id])).rows[0]; if (!readback || await digestObject(readback.versioned_object) !== hash || readback.object_hash !== hash) throw invalid();
    }
    s.requestHash = checked.requestHash; s.approvalHash = await digestObject(approval); await this.#save(c, row); return this.#view(c, row, now);
  }); }
  async #approval(c: pg.PoolClient, row: Ceremony): Promise<EnrolmentApproval> { const id = row.public_state.binding!.approvalAttemptId;
    const transition = (await c.query<Stored>("SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND object_kind='signed_grant' AND staged_operation_id=$2", [row.workspace_id, id])).rows[0];
    if (!transition || await digestObject(transition.versioned_object) !== transition.object_hash) throw invalid();
    const signed = enrolmentApproval.shape.transition.parse(transition.versioned_object), deliveries: EnrolmentApproval['deliveries'] = [];
    const read = async (objectId: string, hash: string, kind: string) => { const o = (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND staged_operation_id=$3 AND object_kind=$4', [row.workspace_id, objectId, id, kind])).rows[0]; if (!o || o.object_hash !== hash || await digestObject(o.versioned_object) !== hash) throw invalid(); return o; };
    for (const d of signed.body.deliveries) deliveries.push({ id: d.id, envelope: enrolmentApproval.shape.deliveries.element.shape.envelope.parse((await read(d.id, d.digest, 'key_envelope')).versioned_object) });
    const p = signed.body.profile; const approval = { transition: signed, deliveries, profile: p ? { id: p.id, envelope: contentEnvelope.parse((await read(p.id, p.digest, 'encrypted_profile')).versioned_object) } : null };
    if (await digestObject(approval) !== row.public_state.approvalHash) throw invalid(); return approval;
  }
  async #project(workspaceId: string, receipt: EnrolmentReceipt, application?: pg.PoolClient): Promise<EnrolmentResult> { try { await this.#o.hooks?.beforeProjection?.();
    const r = await projectAuthoritativeWorkspace(this.#o.databases, workspaceId, application); return { state: r.state === 'ready' ? 'completed' : 'finishing', receipt };
  } catch { return { state: 'finishing', receipt }; } }
  async finalize(input: EnrolmentOperationReference & { requestHash: string }, auth: EnrolmentAuth): Promise<EnrolmentResult> {
    if (!/^[0-9a-f]{64}$/.test(input.requestHash)) throw invalid();
    const preflight = await this.#with(input, auth, async (c, row, w, now, p) => { if (row.public_state.requestHash !== input.requestHash) throw changed();
      if (row.state === 'completed') return this.#receipt(c, row); await this.#check(c, row, w, now); this.#approver(row, p); await this.#proved(c, row, now); return undefined; }, false);
    if (preflight) return this.#project(input.workspaceId, preflight);
    const result = await withSecurityFence(this.#o.databases, input.workspaceId, async (application) => {
      let receipt: EnrolmentReceipt;
      try { receipt = await this.#with(input, auth, async (c, row, w, now, p) => {
        const s = row.public_state; if (s.requestHash !== input.requestHash) throw changed(); if (row.state === 'completed') return this.#receipt(c, row);
        await this.#check(c, row, w, now); this.#approver(row, p); await this.#proved(c, row, now);
        const approval = await this.#approval(c, row), b = s.binding!, transcript = approval.transition.body.transcript;
        const configuration = row.kind === 'invitation' ? await this.#o.opaque.publicConfiguration(row.workspace_id, row.profile_id) : null;
        let checked: Awaited<ReturnType<typeof validateEnrolmentApproval>>;
        try { checked = await validateEnrolmentApproval(approval, { ...s.draft!, registrationRecord: row.staged_registration_record }, b, configuration); } catch { throw changed(); }
        if (checked.requestHash !== input.requestHash) throw changed(); await this.#freshKeys(c, row, transcript);
        const kind = row.kind === 'invitation' ? 'profile.enrol' : 'owner.promote';
        await c.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition,created_at)
          VALUES($1,$2,$3,$4,$5,$6,'device',$7,$8,$9,$10)`, [row.workspace_id, b.nextSecurityVersion, row.ceremony_id, b.securityHead, checked.securityHead, kind, b.authorizer.accountId, b.authorizer.device.id, approval.transition, now]);
        await c.query("UPDATE security.staged_objects SET state='committed',committed_security_version=$3 WHERE workspace_id=$1 AND staged_operation_id=$2 AND object_id=ANY($4::uuid[])", [row.workspace_id, b.approvalAttemptId, b.nextSecurityVersion, [b.approvalAttemptId, ...approval.deliveries.map((d) => d.id), ...(approval.profile ? [approval.profile.id] : [])]]);
        if (configuration) {
          await c.query(`UPDATE security.profiles SET state='active',profile_object_id=$3,opaque_registration_record=$4,opaque_setup_id=$5,opaque_config_id=$6,opaque_identifiers=$7,
            credential_generation=$8,session_generation=$9,recovery_generation=$10,is_owner=$11,owner_ready_at=$12,updated_at=$13,
            role_id=$14,role_revision=$15,role_assignment_object_id=$16 WHERE workspace_id=$1 AND profile_id=$2`,
          [row.workspace_id, row.profile_id, approval.profile!.id, row.staged_registration_record, configuration.setupId, configuration.configId, configuration.identifiers,
            b.nextCredentialGeneration, b.nextSessionGeneration, b.nextRecoveryGeneration, s.kind === 'join_owner', s.kind === 'join_owner' ? now : null, now, b.role.id, b.role.revision, b.approvalAttemptId]);
          await c.query(`INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approval_security_version,created_at,approved_at)
            VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8,$8)`, [row.workspace_id, transcript.device.id, row.profile_id, transcript.device.keyGeneration, base64urlDecode(transcript.device.signingPublicKey), base64urlDecode(transcript.device.recipientPublicKey), b.nextSecurityVersion, now]);
        } else await c.query('UPDATE security.profiles SET is_owner=true,owner_ready_at=$3,session_generation=$4,recovery_generation=$5,updated_at=$3,role_id=$6,role_revision=$7,role_assignment_object_id=$8 WHERE workspace_id=$1 AND profile_id=$2', [row.workspace_id, row.profile_id, now, b.nextSessionGeneration, b.nextRecoveryGeneration, b.role.id, b.role.revision, b.approvalAttemptId]);
        // Promotion supersedes ordinary personal and device delivery authority; device keys and OPAQUE remain untouched.
        await c.query("UPDATE security.grants SET state='revoked',revoked_at=$3 WHERE workspace_id=$1 AND profile_id=$2 AND state<>'revoked'", [row.workspace_id, row.profile_id, now]);
        const devices = s.kind === 'promote_owner' ? b.currentDevices : [transcript.device];
        for (const scope of b.scopes) {
          const source = scope.sources[0]!;
          await c.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,scope_id,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,role_id,role_revision,security_version,created_at,activated_at,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10,$11,$12,$13,$14,$15,$15,$16)`,
          [row.workspace_id, randomUUID(), row.profile_id, scope.scope === 'project' ? 'project' : s.kind === 'join_member' ? 'membership' : 'owner', scope.scope,
            scope.scope === 'workspace' ? null : scope.scopeId, b.nextSessionGeneration, scope.permissions, b.approvalAttemptId, source.manifestId, scope.keyEpoch,
            scope.scope === 'project' ? b.role.id : null, scope.scope === 'project' ? b.role.revision : null, b.nextSecurityVersion, now, scope.expiresAt]);
          for (const device of devices) { const d = approval.transition.body.deliveries.find((v) => v.scope === scope.scope && v.scopeId === scope.scopeId && v.recipientKind === 'device' && v.recipientId === device.id)!;
            await c.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,scope_id,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,created_at,activated_at,expires_at)
              VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,$12,$13,$14,$14,$15)`, [row.workspace_id, d.id, row.profile_id, device.id,
            scope.scope === 'workspace' ? 'device' : 'project', scope.scope, scope.scope === 'workspace' ? null : scope.scopeId, device.keyGeneration, scope.permissions, b.approvalAttemptId, d.id, scope.keyEpoch, b.nextSecurityVersion, now, scope.expiresAt]);
          }
        }
        if (transcript.recovery) { const recovery = transcript.recovery, delivery = approval.transition.body.deliveries.find((d) => d.recipientKind === 'recovery')!;
          await c.query("UPDATE security.recovery_authorities SET state='revoked',revoked_at=$3 WHERE workspace_id=$1 AND profile_id=$2 AND state='active'", [row.workspace_id, row.profile_id, now]);
          await c.query(`INSERT INTO security.recovery_authorities(workspace_id,profile_id,generation,proof_public_key,recipient_public_key,custody_envelope_object_id,custody_epoch,state,kit_verified_at,created_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,$8)`, [row.workspace_id, row.profile_id, recovery.generation, base64urlDecode(recovery.signingPublicKey), base64urlDecode(recovery.recipientPublicKey), delivery.id, b.custodyEpoch, now]);
        }
        await c.query('UPDATE security.sessions SET revoked_at=coalesce(revoked_at,$3) WHERE workspace_id=$1 AND profile_id=$2', [row.workspace_id, row.profile_id, now]);
        await c.query("UPDATE security.auth_attempts SET state='consumed',outcome='failed',consumed_at=$3,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND profile_id=$2 AND state='issued'", [row.workspace_id, row.profile_id, now]);
        await c.query("UPDATE security.ceremonies SET state='cancelled',staged_registration_record=NULL,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND profile_id=$2 AND ceremony_id<>$3 AND state IN ('issued','waiting_approval')", [row.workspace_id, row.profile_id, row.ceremony_id]);
        await c.query('UPDATE security.workspaces SET security_head=$2,security_version=$3,ownership_version=$4,updated_at=$5 WHERE workspace_id=$1', [row.workspace_id, checked.securityHead, b.nextSecurityVersion, b.nextOwnershipVersion, now]);
        const receipt = enrolmentReceipt.parse({ version: 1, workspaceId: row.workspace_id, operationId: row.ceremony_id, approvalAttemptId: b.approvalAttemptId, attemptGeneration: b.attemptGeneration,
          accountId: row.profile_id, deviceId: transcript.device.id, credentialGeneration: b.nextCredentialGeneration, sessionGeneration: b.nextSessionGeneration, keyGeneration: transcript.device.keyGeneration,
          recoveryGeneration: b.nextRecoveryGeneration, ownershipVersion: b.nextOwnershipVersion, profileRevision: b.nextProfileRevision, dataGeneration: b.dataGeneration,
          securityVersion: b.nextSecurityVersion, securityHead: checked.securityHead, requestHash: checked.requestHash, wrapperHash: transcript.wrapperHash, committedAt: now.toISOString(), transition: approval.transition });
        const durable = (await c.query<{ outcome: EnrolmentReceipt }>(`INSERT INTO security.operation_receipts(workspace_id,operation_id,request_hash,operation_kind,security_version,outcome,created_at)
          VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING outcome`, [row.workspace_id, row.ceremony_id, checked.requestHash, kind, b.nextSecurityVersion, receipt, now])).rows[0]!.outcome;
        s.resumeExpiresAt = new Date(now.getTime() + 86400_000).toISOString();
        await c.query("UPDATE security.ceremonies SET state='completed',completed_at=$3,public_state=$4,staged_registration_record=NULL,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND ceremony_id=$2", [row.workspace_id, row.ceremony_id, now, s]);
        await this.#o.hooks?.beforeControlCommit?.(); return durable;
      }, false); } catch (error) { if (!(error instanceof AppError)) throw error; await projectAuthoritativeWorkspace(this.#o.databases, input.workspaceId, application); return { error }; }
      await this.#o.hooks?.afterControlCommit?.(); return { result: await this.#project(input.workspaceId, receipt, application) };
    }, { enqueueActivationProjection: true });
    if ('error' in result) throw result.error; return result.result;
  }
  async status(ref: EnrolmentOperationReference | EnrolmentReference, auth?: EnrolmentAuth): Promise<EnrolmentView> { const view = await this.inspect(ref, auth); if (!view.receipt) return view; return { ...view, state: (await this.#project(ref.workspaceId, view.receipt)).state }; }
  async cancel(ref: EnrolmentReference): Promise<EnrolmentView> { return this.#with(parse(enrolmentReference, ref), undefined, async (c, row, _w, now) => { if (row.state !== 'completed') await this.#retire(c, row, 'cancelled'); return this.#view(c, row, now); }, false); }
  async withAuthorizedHistory<T>(ref: EnrolmentOperationReference | EnrolmentReference, auth: EnrolmentAuth | undefined,
    action: (c: pg.PoolClient, context: { workspaceId: string; operationId: string; accountId: string; binding: EnrolmentBinding; receipt: EnrolmentReceipt | null; current: { securityHead: string; securityVersion: string } }) => Promise<T>): Promise<T> {
    return this.#tx(ref.workspaceId, async (c, w, now) => { const principal = auth ? await this.#session(c, ref.workspaceId, auth, now, false) : undefined;
      const row = await this.#row(c, ref, true), b = row.public_state.binding; if (!b) throw invalid(); const receipt = row.state === 'completed' ? await this.#receipt(c, row) : null;
      if (receipt) { if (!principal) throw forbidden(); const target = principal.accountId === row.profile_id && principal.credentialGeneration === receipt.credentialGeneration && principal.sessionGeneration === receipt.sessionGeneration && principal.dataGeneration === receipt.dataGeneration;
        if (!target) await this.#owner(c, ref.workspaceId, auth!, now);
      } else { if (principal) { if (row.kind !== 'owner_promotion' || principal.accountId !== row.profile_id) await this.#owner(c, ref.workspaceId, auth!, now); }
        else { if (!('resumeToken' in ref)) throw forbidden(); this.#cap(row, ref, now); } await this.#check(c, row, w, now); }
      return action(c, { workspaceId: row.workspace_id, operationId: row.ceremony_id, accountId: row.profile_id, binding: b, receipt, current: { securityHead: w.security_head, securityVersion: w.security_version } });
    });
  }
  async delivery(cookie: string, operationId: string) { const initial = await this.#o.sessions.authenticate(cookie, { approved: true }); return this.#tx(initial.workspaceId, async (c, _w, now) => {
    const principal = await this.#o.sessions.resolveCurrent(c, cookie, { approved: true }, now), row = await this.#row(c, { workspaceId: principal.workspaceId, operationId }), receipt = await this.#receipt(c, row);
    const b = receipt.transition.body.transcript.binding, devices = b.kind === 'promote_owner' ? b.currentDevices : [receipt.transition.body.transcript.device];
    if (row.state !== 'completed' || principal.accountId !== row.profile_id || !devices.some((d) => d.id === principal.deviceId) || principal.credentialGeneration !== receipt.credentialGeneration || principal.sessionGeneration !== receipt.sessionGeneration || principal.dataGeneration !== receipt.dataGeneration) throw forbidden();
    const target = await this.#profile(c, row.workspace_id, row.profile_id); if (target.state !== 'active' || target.is_owner !== (b.kind !== 'join_member') || target.recovery_generation !== receipt.recoveryGeneration) throw forbidden();
    if (!personalScopesCover(await readPersonalScopes(c, row.workspace_id, row.profile_id, target.is_owner, now), b.scopes)) throw forbidden();
    const grants = (await c.query<{ key_manifest_object_id: string; key_epoch: string; permissions: string[] }>(`SELECT * FROM security.grants WHERE workspace_id=$1 AND profile_id=$2 AND device_id=$3 AND signed_grant_object_id=$4 AND state='active' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$5)`, [row.workspace_id, row.profile_id, principal.deviceId, b.approvalAttemptId, now])).rows;
    const approval = await this.#approval(c, row); if (!equal(approval.transition, receipt.transition)) throw invalid();
    const deliveries = approval.deliveries.filter((d) => d.envelope.header.recipientKind === 'device' ? d.envelope.header.recipientId === principal.deviceId : target.is_owner);
    for (const scope of b.scopes) { const delivery = deliveries.find((d) => d.envelope.header.recipientKind === 'device' && d.envelope.header.scope === scope.scope && d.envelope.header.scopeId === scope.scopeId);
      if (!delivery || !grants.some((g) => g.key_manifest_object_id === delivery.id && g.key_epoch === scope.keyEpoch && equal(g.permissions, scope.permissions))) throw forbidden(); }
    // Ordinary members receive their sealed content keyrings, never Owner custody ciphertext/source envelopes.
    const materials = target.is_owner ? await this.#materials(c, row.workspace_id, principal.deviceId!, b.scopes, b.custodyEpoch, true) : [];
    if (approval.profile) materials.push({ id: approval.profile.id, digest: await digestObject(approval.profile.envelope), kind: 'encrypted_profile', value: approval.profile.envelope });
    return { receipt, deliveries, materials };
  }); }
  async issuanceContext(cookie: string, csrf: string, input: unknown): Promise<EnrolmentIssuanceContext> {
    const r = parse(enrolmentIssuanceRequest, input); return this.#tx(r.workspaceId, async (c, w, now) => {
      this.#writable(w, r.kind); const owner = await this.#owner(c, r.workspaceId, { cookieValue: cookie, csrfToken: csrf }, now);
      await this.#o.requestBudget?.({ workspaceId: r.workspaceId, accountId: r.accountId, history: false });
      if (owner.accountId === r.accountId) throw forbidden(); const role = await this.#role(c, r.workspaceId, r.roleId, r.kind), device = await this.#device(c, r.workspaceId, owner.accountId, owner.deviceId!);
      const target = (await c.query<Profile>('SELECT * FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [r.workspaceId, r.accountId])).rows[0];
      if (target && (target.state !== 'pending' || target.credential_generation !== '0' || target.is_owner)) throw changed();
      const previous = target?.profile_object_id ? (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [r.workspaceId, target.profile_object_id])).rows[0] : undefined;
      const epoch = (await c.query<{ key_epoch: string }>("SELECT key_epoch FROM security.scope_heads WHERE workspace_id=$1 AND scope_kind='workspace' AND scope_id=$1", [r.workspaceId])).rows[0]?.key_epoch;
      const genesis = (await c.query<Stored>("SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND state='committed'", [r.workspaceId, w.genesis_object_id])).rows[0]; if (!epoch || !genesis) throw changed();
      const personal = await readPersonalScopes(c, r.workspaceId, owner.accountId, true, now);
      if (r.projectIds.some((id) => !personal.some((p) => p.scope === 'project' && p.scopeId === id && role.permissions.every((v) => p.permissions.includes(v))))) throw changed();
      return { workspaceId: r.workspaceId, accountId: r.accountId, operationId: r.operationId, kind: r.kind,
        role: { id: role.role_id, revision: role.revision, permissions: role.permissions }, authorizer: { accountId: owner.accountId, device, credentialGeneration: owner.credentialGeneration, sessionGeneration: owner.sessionGeneration },
        header: { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: r.workspaceId, scope: 'workspace', scopeId: r.workspaceId,
          recordId: r.accountId, recordType: 'profile', schema: 1, keyEpoch: epoch, revision: previous ? next(contentEnvelope.parse(previous.versioned_object).header.revision) : '1',
          operationId: r.operationId, accountId: owner.accountId, deviceId: device.id, keyGeneration: device.keyGeneration, permissionVersion: role.revision,
          securityVersion: w.security_version, securityHead: w.security_head, dataGeneration: w.data_generation, action: 'profile.invite', approvalPolicyId: null, approvalPolicyRevision: null },
        genesisFingerprint: genesis.object_hash, custodyEpoch: w.custody_epoch, current: { securityHead: w.security_head, securityVersion: w.security_version },
        materials: await this.#materials(c, r.workspaceId, device.id, personal.filter((p) => p.scope === 'workspace'), w.custody_epoch, true) };
    });
  }
  async withIssuanceHistory<T>(workspaceId: string, auth: EnrolmentAuth, action: (c: pg.PoolClient, context: { workspaceId: string; current: { securityHead: string; securityVersion: string } }) => Promise<T>): Promise<T> {
    return this.#tx(workspaceId, async (c, w, now) => { const p = await this.#owner(c, workspaceId, auth, now);
      await this.#o.requestBudget?.({ workspaceId, accountId: p.accountId, history: true }); return action(c, { workspaceId, current: { securityHead: w.security_head, securityVersion: w.security_version } }); });
  }
  async unlockStart(input: unknown) { const r = parse(enrolmentUnlockStart, input); return this.#with(r, undefined, async (c, row, _w, now) => {
    if (row.kind !== 'invitation' || !row.staged_registration_record) throw invalid();
    const proof = await this.#o.opaque.startLogin(row.workspace_id, row.profile_id, row.staged_registration_record, r.startLoginRequest);
    const id = randomUUID(), expires = new Date(Math.min(now.getTime() + 120_000, row.expires_at.getTime())), hash = await digestObject(row.staged_registration_record);
    const context = this.#proofContext(row, id, `unlock:${hash}`), encrypted = await this.#o.secrets.protectState(context, proof.serverLoginState);
    row.public_state.unlockId = id; row.public_state.unlockExpiresAt = expires.toISOString(); row.public_state.unlockHash = hash;
    delete row.public_state.proofId; delete row.public_state.proofExpiresAt;
    await c.query('UPDATE security.ceremonies SET public_state=$3,server_state_ciphertext=$4,server_state_key_id=$5 WHERE workspace_id=$1 AND ceremony_id=$2', [row.workspace_id, row.ceremony_id, row.public_state, Buffer.from(encrypted), this.#o.secrets.keyId]);
    return { proofId: id, expiresAt: expires.toISOString(), loginResponse: proof.loginResponse, configuration: await this.#o.opaque.publicConfiguration(row.workspace_id, row.profile_id) };
  }); }
  async unlockFinish(input: unknown) { const r = parse(enrolmentUnlockFinish, input); const verified = await this.#with(r, undefined, async (c, row, _w, now) => {
    const s = row.public_state, expires = s.unlockExpiresAt, hash = s.unlockHash;
    if (!hash || s.unlockId !== r.proofId || !expires || !row.server_state_ciphertext) return false;
    delete s.unlockId; delete s.unlockExpiresAt; delete s.unlockHash;
    await c.query('UPDATE security.ceremonies SET public_state=$3,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND ceremony_id=$2', [row.workspace_id, row.ceremony_id, s]);
    if (Date.parse(expires) <= now.getTime() || row.server_state_key_id !== this.#o.secrets.keyId) return false;
    try { const state = await this.#o.secrets.revealState(this.#proofContext(row, r.proofId, `unlock:${hash}`), row.server_state_ciphertext.toString()); await this.#o.opaque.finishLogin(row.workspace_id, row.profile_id, state, r.finishLoginRequest); return true; } catch { return false; }
  }); if (!verified) throw invalid(); return { verified: true as const }; }
}

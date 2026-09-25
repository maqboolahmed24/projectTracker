import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { binary, identifier } from '../../shared/contracts.js';
import { base64urlDecode, base64urlEncode, canonicalJson, digestObject, verifyObject } from '../../shared/crypto.js';
import type { PairingMaterial, PairingScope } from '../../shared/pairing.js';
import { generateResetCode, recoveryBinding, recoveryPhraseChallenge, recoveryReference, recoveryReceipt,
  validateRecoveryPhraseProof, validateRecoveryDraft, validateRecoveryPayload, validateRecoveryApproval, recoveryConfirmation, recoveryConfirmationFor,
  recoveryIssueReset, recoveryRevokeReset, recoveryBeginReset, recoveryBeginPhrase, recoveryRegistration, recoveryProofStart, recoveryProofFinish, recoveryApproval,
  type RecoveryBinding, type RecoveryReference, type RecoveryReceipt, type RecoveryResult, type RecoveryPhraseChallenge,
  type RecoveryPublicAuthority, type RecoveryAuthorizer, type RecoveryDraft, type RecoveryApproval, type RecoveryPayload, type RecoveryView, type RecoveryConfirmation } from '../../shared/recovery.js';
import { assertEntitlementAllows } from './entitlements.js';
import { OpaqueService } from './opaque.js';
import { projectAuthoritativeWorkspace, withSecurityFence } from './projection.js';
import { ServiceSecrets } from './secrets.js';
import { SessionService, type SessionPrincipal } from './sessions.js';
import { personalScopesCover, PersonalScopeError, readPersonalScopes } from './personal-scopes.js';

export interface RecoveryAuth { cookieValue: string; csrfToken: string }
export interface RecoveryOperationReference { workspaceId: string; operationId: string }
interface Options { databases: Databases; secrets: ServiceSecrets; opaque: OpaqueService; sessions: SessionService; origin: string;
  requestBudget?: (scope: { workspaceId: string; accountId: string; history: boolean }) => Promise<void>;
  now?: () => Date; hooks?: { beforeControlCommit?: () => Promise<void>; afterControlCommit?: () => Promise<void>; beforeProjection?: () => Promise<void> } }
interface Authority { lifecycle: string; licence_state: string; security_head: string; security_version: string; data_generation: string;
  ownership_version: string; custody_epoch: string; genesis_object_id: string }
interface Profile { profile_id: string; state: string; is_owner: boolean; credential_generation: string; session_generation: string;
  reset_generation: string; recovery_generation: string }
interface Saved { mode: 'phrase' | 'owner_reset'; accountId: string; isOwner: boolean; credentialGeneration: string; resetGeneration: string;
  codeDigest?: string; codeKeyId?: string; issuerAccountId?: string; issuerDeviceId?: string; redeemedAt?: string;
  resumeExpiresAt: string; binding?: RecoveryBinding; phraseChallenge?: RecoveryPhraseChallenge; phraseVerifiedAt?: string;
  phraseProofHash?: string; draft?: Omit<RecoveryDraft, 'registrationRecord'>; draftHash?: string;
  authorizerConfirmation?: RecoveryConfirmation; proofId?: string; proofExpiresAt?: string; proofVerifiedAt?: string; requestHash?: string }
interface Ceremony { workspace_id: string; ceremony_id: string; profile_id: string; kind: string; state: string; generation: string;
  public_state: Saved; verification_digest: Buffer | null; verification_key_id: string | null; expires_at: Date;
  staged_registration_record: string | null; server_state_ciphertext: Buffer | null; server_state_key_id: string | null }
interface Stored { object_id: string; object_hash: string; object_kind: string; versioned_object: unknown; state: string; staged_operation_id: string }
const invalid = () => new AppError('RECOVERY_INVALID', 'Recovery is unavailable; restart with a current recovery method', 401);
const conflict = () => new AppError('RECOVERY_CHANGED', 'Recovery authority changed; restart with a current recovery method', 409);
const forbidden = () => new AppError('RECOVERY_FORBIDDEN', 'A current approved Owner must authorize this recovery', 403);
const equal = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const next = (value: string) => String(BigInt(value) + 1n);
function parse<T>(schema: z.ZodType<T>, input: unknown): T {
  const value = schema.safeParse(input); if (!value.success) throw new AppError('INVALID_REQUEST', 'Invalid recovery request', 400); return value.data;
}

/** Recovery replaces authentication and device authority within existing scopes; it never changes membership or ownership. */
export class RecoveryService {
  readonly #options: Options; readonly #now: () => Date;
  constructor(options: Options) {
    if (new URL(options.origin).origin !== options.origin) throw new Error('Recovery requires an exact origin');
    this.#options = options; this.#now = options.now ?? (() => new Date());
  }
  async #transaction<T>(workspaceId: string, action: (client: pg.PoolClient, authority: Authority, now: Date) => Promise<T>): Promise<T> {
    if (!identifier.safeParse(workspaceId).success) throw invalid();
    try { return await transaction(this.#options.databases.control, async (client) => {
      await client.query("SET LOCAL synchronous_commit='on'");
      await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
      const authority = (await client.query<Authority>('SELECT * FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE', [workspaceId])).rows[0];
      if (!authority || !['active', 'pending_deletion'].includes(authority.lifecycle) || authority.security_version === '0') throw invalid();
      assertEntitlementAllows(authority.licence_state, 'recover');
      return action(client, authority, this.#now());
    }); } catch (error) { if (error instanceof AppError) throw error;
      throw new AppError('RECOVERY_UNAVAILABLE', 'Recovery is temporarily unavailable; retain the local draft', 503); }
  }
  async #profile(client: pg.PoolClient, workspaceId: string, accountId: string): Promise<Profile> {
    const profile = (await client.query<Profile>('SELECT * FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 FOR SHARE', [workspaceId, accountId])).rows[0];
    if (!profile || profile.state !== 'active') throw invalid(); return profile;
  }
  async #owner(client: pg.PoolClient, workspaceId: string, auth: RecoveryAuth, now: Date): Promise<SessionPrincipal> {
    const principal = await this.#options.sessions.resolveCurrent(client, auth.cookieValue, { csrfToken: auth.csrfToken, approved: true, recent: true }, now);
    if (principal.workspaceId !== workspaceId || !principal.deviceId || !(await this.#profile(client, workspaceId, principal.accountId)).is_owner) throw forbidden();
    return principal;
  }
  async #row(client: pg.PoolClient, reference: RecoveryOperationReference, history = false, alreadyBudgeted = false): Promise<Ceremony> {
    if (!identifier.safeParse(reference.operationId).success) throw invalid();
    const row = (await client.query<Ceremony>('SELECT * FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2 FOR UPDATE', [reference.workspaceId, reference.operationId])).rows[0];
    if (!row || !['member_reset', 'owner_reset', 'owner_recovery'].includes(row.kind)) throw invalid();
    if (!alreadyBudgeted) await this.#options.requestBudget?.({ workspaceId: row.workspace_id, accountId: row.profile_id, history });
    return row;
  }
  #capability(row: Ceremony, reference: RecoveryReference, now: Date) {
    if (!row.verification_digest || row.verification_key_id !== this.#options.secrets.keyId ||
      !this.#options.secrets.matches('recovery-resume', `${row.workspace_id}:${row.ceremony_id}:${reference.resumeToken}`, row.verification_digest) ||
      Date.parse(row.public_state.resumeExpiresAt) <= now.getTime()) throw invalid();
  }
  #live(row: Ceremony, now: Date) {
    if (!['issued', 'waiting_approval'].includes(row.state) || row.expires_at <= now) throw invalid();
  }
  async #save(client: pg.PoolClient, row: Ceremony) {
    await client.query('UPDATE security.ceremonies SET public_state=$3 WHERE workspace_id=$1 AND ceremony_id=$2', [row.workspace_id, row.ceremony_id, row.public_state]);
  }
  async #currentRecovery(client: pg.PoolClient, workspaceId: string, profile: Profile, custodyEpoch?: string): Promise<RecoveryPublicAuthority | null> {
    if (!profile.is_owner) return null;
    const row = (await client.query<{ generation: string; proof_public_key: Buffer; recipient_public_key: Buffer; custody_epoch: string; versioned_object: { header?: { recipientId?: string } }; object_hash: string }>(
      `SELECT r.generation,r.proof_public_key,r.recipient_public_key,r.custody_epoch,o.versioned_object,o.object_hash FROM security.recovery_authorities r
       JOIN security.staged_objects o ON o.workspace_id=r.workspace_id AND o.object_id=r.custody_envelope_object_id AND o.state='committed'
       WHERE r.workspace_id=$1 AND r.profile_id=$2 AND r.state='active' AND r.revoked_at IS NULL AND r.generation=$3`, [workspaceId, profile.profile_id, profile.recovery_generation])).rows[0];
    if (!row || (custodyEpoch !== undefined && row.custody_epoch !== custodyEpoch) || !identifier.safeParse(row.versioned_object.header?.recipientId).success || await digestObject(row.versioned_object) !== row.object_hash) throw invalid();
    return { id: row.versioned_object.header!.recipientId!, generation: row.generation,
      signingPublicKey: base64urlEncode(row.proof_public_key), recipientPublicKey: base64urlEncode(row.recipient_public_key) };
  }
  async #scopes(client: pg.PoolClient, workspaceId: string, profile: Profile): Promise<PairingScope[]> {
    try { return await readPersonalScopes(client, workspaceId, profile.profile_id, profile.is_owner, this.#now()); }
    catch (error) { if (error instanceof PersonalScopeError) throw conflict(); throw error; }
  }
  async #binding(client: pg.PoolClient, row: Ceremony, authority: Authority, authorizer: RecoveryAuthorizer, now: Date): Promise<RecoveryBinding> {
    const profile = await this.#profile(client, row.workspace_id, row.profile_id), currentRecovery = await this.#currentRecovery(client, row.workspace_id, profile, authority.custody_epoch);
    const genesis = (await client.query<{ object_hash: string }>("SELECT object_hash FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND object_kind='genesis' AND state='committed'", [row.workspace_id, authority.genesis_object_id])).rows[0];
    const generation = (await client.query<{ value: string }>('SELECT coalesce(max(key_generation),0)::text AS value FROM security.devices WHERE workspace_id=$1 AND profile_id=$2', [row.workspace_id, row.profile_id])).rows[0]!.value;
    if (!genesis || row.public_state.isOwner !== profile.is_owner || row.public_state.credentialGeneration !== profile.credential_generation || row.public_state.resetGeneration !== profile.reset_generation) throw conflict();
    return recoveryBinding.parse({ version: 1, origin: this.#options.origin, workspaceId: row.workspace_id, operationId: row.ceremony_id, accountId: row.profile_id,
      isOwner: profile.is_owner, credentialGeneration: profile.credential_generation, nextCredentialGeneration: next(profile.credential_generation),
      sessionGeneration: profile.session_generation, nextSessionGeneration: next(profile.session_generation), resetGeneration: profile.reset_generation,
      recoveryGeneration: profile.recovery_generation, nextRecoveryGeneration: profile.is_owner ? next(profile.recovery_generation) : profile.recovery_generation,
      deviceKeyGeneration: generation, nextDeviceKeyGeneration: next(generation), dataGeneration: authority.data_generation,
      securityVersion: authority.security_version, nextSecurityVersion: next(authority.security_version), securityHead: authority.security_head,
      genesisFingerprint: genesis.object_hash, ownershipVersion: authority.ownership_version, custodyEpoch: authority.custody_epoch,
      currentRecovery, authorizer, scopes: await this.#scopes(client, row.workspace_id, profile),
      issuedAt: row.public_state.binding?.issuedAt ?? now.toISOString(), expiresAt: row.expires_at.toISOString() });
  }
  async #check(client: pg.PoolClient, row: Ceremony, authority: Authority, now: Date) {
    this.#live(row, now); const binding = row.public_state.binding; if (!binding) throw invalid();
    if (binding.authorizer.kind === 'phrase') { if (!row.public_state.phraseVerifiedAt) throw invalid(); }
    else {
      const approver = await this.#profile(client, row.workspace_id, binding.authorizer.accountId);
      const authorizer = binding.authorizer;
      if (!approver.is_owner || approver.credential_generation !== authorizer.credentialGeneration || approver.session_generation !== authorizer.sessionGeneration ||
        !(await client.query(`SELECT 1 FROM security.devices d JOIN security.grants g ON g.workspace_id=d.workspace_id AND g.device_id=d.device_id
          JOIN security.staged_objects o ON o.workspace_id=g.workspace_id AND o.object_id=g.signed_grant_object_id AND o.state='committed'
          WHERE d.workspace_id=$1 AND d.device_id=$2 AND d.profile_id=$3 AND d.state='active' AND d.revoked_at IS NULL AND d.key_generation=$4
          AND d.signing_public_key=$5 AND d.recipient_public_key=$6 AND g.grant_kind='device' AND g.scope_kind='workspace' AND g.state='active'
          AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>$7)`, [row.workspace_id, authorizer.device.id, authorizer.accountId,
          authorizer.device.keyGeneration, base64urlDecode(authorizer.device.signingPublicKey), base64urlDecode(authorizer.device.recipientPublicKey), now])).rowCount) throw forbidden();
    }
    if (!equal(binding, await this.#binding(client, row, authority, binding.authorizer, now))) throw conflict();
  }
  async #with<T>(reference: RecoveryOperationReference | RecoveryReference, auth: RecoveryAuth | undefined,
    action: (client: pg.PoolClient, row: Ceremony, authority: Authority, now: Date, principal?: SessionPrincipal) => Promise<T>, checked = true): Promise<T> {
    return this.#transaction(reference.workspaceId, async (client, authority, now) => {
      const principal = auth ? await this.#owner(client, reference.workspaceId, auth, now) : undefined;
      const row = await this.#row(client, reference);
      if (!principal) {
        if (!('resumeToken' in reference)) throw invalid();
        parse(recoveryReference, { workspaceId: reference.workspaceId, operationId: reference.operationId, resumeToken: reference.resumeToken }); this.#capability(row, reference, now);
      }
      if (checked) await this.#check(client, row, authority, now);
      return action(client, row, authority, now, principal);
    });
  }
  async #receipt(client: pg.PoolClient, row: Ceremony): Promise<RecoveryReceipt> {
    const receipt = (await client.query<{ outcome: unknown; request_hash: string }>("SELECT outcome,request_hash FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2 AND operation_kind='account.recover'", [row.workspace_id, row.ceremony_id])).rows[0];
    if (!receipt || receipt.request_hash !== row.public_state.requestHash) throw invalid(); return recoveryReceipt.parse(receipt.outcome);
  }
  async #view(client: pg.PoolClient, row: Ceremony, now: Date): Promise<RecoveryView> {
    const saved = row.public_state, draft = saved.draft;
    return { workspaceId: row.workspace_id, accountId: row.profile_id, operationId: row.ceremony_id,
      state: row.state === 'completed' ? 'completed' : ['cancelled', 'revoked', 'expired'].includes(row.state) ? row.state as 'cancelled' | 'revoked' | 'expired' :
        row.expires_at <= now ? 'expired' : saved.requestHash ? 'confirmed' : draft ? 'verifying' : saved.binding ? 'waiting_approval' : 'issued',
      binding: saved.binding ?? null, transcript: draft?.transcript ?? null, transcriptDigest: draft ? await digestObject(draft.transcript) : null,
      recipientConfirmation: draft?.recipientConfirmation ?? null, newRecoveryConfirmation: draft?.newRecoveryConfirmation ?? null,
      authorizerConfirmation: saved.authorizerConfirmation ?? null, approvalStaged: Boolean(saved.requestHash),
      passwordProved: Boolean(saved.proofVerifiedAt), requestHash: saved.requestHash ?? null,
      receipt: row.state === 'completed' ? await this.#receipt(client, row) : null,
      expiresAt: row.expires_at.toISOString(), resumeExpiresAt: saved.resumeExpiresAt };
  }
  async issueReset(cookie: string, csrf: string, input: unknown) {
    const request = parse(recoveryIssueReset, input);
    return this.#transaction(request.workspaceId, async (client, authority, now) => {
      const owner = await this.#owner(client, request.workspaceId, { cookieValue: cookie, csrfToken: csrf }, now);
      const target = await this.#profile(client, request.workspaceId, request.accountId);
      await this.#options.requestBudget?.({ workspaceId: request.workspaceId, accountId: target.profile_id, history: false });
      if ((await client.query('SELECT 1 FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [request.workspaceId, request.resetId])).rowCount) throw conflict();
      const code = generateResetCode(), generation = next(target.reset_generation), expiresAt = new Date(now.getTime() + 900_000);
      await client.query(`UPDATE security.ceremonies SET state='revoked',server_state_ciphertext=NULL,server_state_key_id=NULL,staged_registration_record=NULL
        WHERE workspace_id=$1 AND profile_id=$2 AND kind IN ('member_reset','owner_reset','owner_recovery') AND state IN ('issued','waiting_approval')`, [request.workspaceId, request.accountId]);
      await client.query('UPDATE security.profiles SET reset_generation=$3,updated_at=$4 WHERE workspace_id=$1 AND profile_id=$2', [request.workspaceId, request.accountId, generation, now]);
      const saved: Saved = { mode: 'owner_reset', accountId: request.accountId, isOwner: target.is_owner, credentialGeneration: target.credential_generation,
        resetGeneration: generation, issuerAccountId: owner.accountId, issuerDeviceId: owner.deviceId!, resumeExpiresAt: expiresAt.toISOString(),
        codeDigest: this.#options.secrets.digest('recovery-reset-code', `${request.workspaceId}:${code}`).toString('hex'), codeKeyId: this.#options.secrets.keyId };
      await client.query(`INSERT INTO security.ceremonies(workspace_id,ceremony_id,profile_id,kind,generation,approving_profile_id,approving_device_id,
        expected_credential_generation,expected_ownership_version,expected_security_version,expected_custody_epoch,public_state,created_at,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, [request.workspaceId, request.resetId, request.accountId,
        target.is_owner ? 'owner_reset' : 'member_reset', generation, owner.accountId, owner.deviceId, target.credential_generation,
        authority.ownership_version, authority.security_version, authority.custody_epoch, saved, now, expiresAt]);
      return { workspaceId: request.workspaceId, accountId: request.accountId, resetId: request.resetId, code, resetGeneration: generation, expiresAt: expiresAt.toISOString() };
    });
  }
  async revokeReset(cookie: string, csrf: string, input: unknown): Promise<RecoveryView> {
    const request = parse(recoveryRevokeReset, input);
    return this.#with({ workspaceId: request.workspaceId, operationId: request.resetId }, { cookieValue: cookie, csrfToken: csrf }, async (client, row, _authority, now) => {
      if (row.public_state.mode !== 'owner_reset' || row.state === 'completed') throw invalid();
      await client.query("UPDATE security.ceremonies SET state='revoked',server_state_ciphertext=NULL,server_state_key_id=NULL,staged_registration_record=NULL WHERE workspace_id=$1 AND ceremony_id=$2", [row.workspace_id, row.ceremony_id]);
      row.state = 'revoked'; return this.#view(client, row, now);
    }, false);
  }
  async beginReset(input: unknown): Promise<RecoveryView> {
    const request = parse(recoveryBeginReset, input);
    return this.#transaction(request.workspaceId, async (client, _authority, now) => {
      const digest = this.#options.secrets.digest('recovery-reset-code', `${request.workspaceId}:${request.code}`).toString('hex');
      const row = (await client.query<Ceremony>(`SELECT * FROM security.ceremonies WHERE workspace_id=$1 AND kind IN ('member_reset','owner_reset')
        AND public_state->>'codeDigest'=$2 AND public_state->>'codeKeyId'=$3 FOR UPDATE`, [request.workspaceId, digest, this.#options.secrets.keyId])).rows[0];
      if (!row) throw invalid();
      await this.#options.requestBudget?.({ workspaceId: row.workspace_id, accountId: row.profile_id, history: false });
      this.#live(row, now);
      const target = await this.#profile(client, request.workspaceId, row.profile_id);
      if (target.reset_generation !== row.public_state.resetGeneration || target.credential_generation !== row.public_state.credentialGeneration || target.is_owner !== row.public_state.isOwner) throw invalid();
      if (row.public_state.redeemedAt) {
        this.#capability(row, { workspaceId: row.workspace_id, operationId: row.ceremony_id, resumeToken: request.resumeToken }, now);
      } else {
        const issuer = await this.#profile(client, request.workspaceId, row.public_state.issuerAccountId!);
        if (!issuer.is_owner) throw invalid();
        row.public_state.redeemedAt = now.toISOString();
        await client.query(`UPDATE security.ceremonies SET verification_digest=$3,verification_key_id=$4,public_state=$5
          WHERE workspace_id=$1 AND ceremony_id=$2`, [row.workspace_id, row.ceremony_id,
          this.#options.secrets.digest('recovery-resume', `${row.workspace_id}:${row.ceremony_id}:${request.resumeToken}`), this.#options.secrets.keyId, row.public_state]);
      }
      return this.#view(client, row, now);
    });
  }
  async beginPhrase(input: unknown): Promise<RecoveryPhraseChallenge> {
    const request = parse(recoveryBeginPhrase, input);
    return this.#transaction(request.workspaceId, async (client, authority, now) => {
      const profile = await this.#profile(client, request.workspaceId, request.accountId);
      await this.#options.requestBudget?.({ workspaceId: request.workspaceId, accountId: profile.profile_id, history: false });
      const recovery = await this.#currentRecovery(client, request.workspaceId, profile);
      if (!profile.is_owner || !recovery) throw invalid();
      await client.query(`UPDATE security.ceremonies SET state='expired' WHERE workspace_id=$1 AND profile_id=$2 AND kind='owner_recovery'
        AND state IN ('issued','waiting_approval') AND public_state->>'phraseVerifiedAt' IS NULL
        AND (public_state->'phraseChallenge'->>'expiresAt')::timestamptz<=$3`, [request.workspaceId, request.accountId, now]);
      const existing = (await client.query<Ceremony>('SELECT * FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2 FOR UPDATE', [request.workspaceId, request.operationId])).rows[0];
      if (existing) {
        this.#capability(existing, { workspaceId: request.workspaceId, operationId: request.operationId, resumeToken: request.resumeToken }, now);
        this.#live(existing, now);
        if (existing.profile_id !== request.accountId || existing.kind !== 'owner_recovery' || !existing.public_state.phraseChallenge || existing.public_state.phraseVerifiedAt || Date.parse(existing.public_state.phraseChallenge.expiresAt) <= now.getTime()) throw invalid();
        return existing.public_state.phraseChallenge;
      }
      const pending = (await client.query<{ count: string }>("SELECT count(*) FROM security.ceremonies WHERE workspace_id=$1 AND profile_id=$2 AND kind='owner_recovery' AND state IN ('issued','waiting_approval') AND expires_at>$3", [request.workspaceId, request.accountId, now])).rows[0]!.count;
      if (Number(pending) >= 5) throw new AppError('RATE_LIMITED', 'Wait for an existing recovery attempt to expire', 429);
      const expiresAt = new Date(now.getTime() + 900_000), saved: Saved = { mode: 'phrase', accountId: request.accountId, isOwner: true,
        credentialGeneration: profile.credential_generation, resetGeneration: profile.reset_generation, resumeExpiresAt: expiresAt.toISOString() };
      await client.query(`INSERT INTO security.ceremonies(workspace_id,ceremony_id,profile_id,kind,generation,verification_digest,verification_key_id,
        expected_credential_generation,expected_ownership_version,expected_security_version,expected_custody_epoch,public_state,created_at,expires_at)
        VALUES($1,$2,$3,'owner_recovery',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, [request.workspaceId, request.operationId, request.accountId,
        profile.recovery_generation, this.#options.secrets.digest('recovery-resume', `${request.workspaceId}:${request.operationId}:${request.resumeToken}`), this.#options.secrets.keyId,
        profile.credential_generation, authority.ownership_version, authority.security_version, authority.custody_epoch, saved, now, expiresAt]);
      const row = await this.#row(client, request, false, true);
      saved.binding = await this.#binding(client, row, authority, { kind: 'phrase', accountId: request.accountId, recovery }, now);
      saved.phraseChallenge = recoveryPhraseChallenge.parse({ version: 1, purpose: 'ukda.owner-phrase-challenge.v1', binding: saved.binding,
        proofId: randomUUID(), nonce: this.#options.secrets.token(), issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 120_000).toISOString() });
      row.public_state = saved; await this.#save(client, row); return saved.phraseChallenge;
    });
  }
  async provePhrase(input: RecoveryReference & { proof: unknown }): Promise<RecoveryView> {
    const reference = parse(recoveryReference, { workspaceId: input.workspaceId, operationId: input.operationId, resumeToken: input.resumeToken });
    const result = await this.#with(reference, undefined, async (client, row, authority, now) => {
      this.#live(row, now); const state = row.public_state, challenge = state.phraseChallenge;
      if (state.mode !== 'phrase' || !challenge || !state.binding) throw invalid();
      if (state.phraseVerifiedAt) {
        if (await digestObject(input.proof) !== state.phraseProofHash) throw invalid();
        await this.#check(client, row, authority, now); return { view: await this.#view(client, row, now) };
      }
      // Failed as well as successful signatures consume this exact challenge in a committed transaction.
      let valid = Date.parse(challenge.expiresAt) > now.getTime();
      try { await validateRecoveryPhraseProof(input.proof, challenge);
        valid = valid && equal(challenge.binding, await this.#binding(client, row, authority, challenge.binding.authorizer, now));
      } catch { valid = false; }
      if (!valid) { await client.query("UPDATE security.ceremonies SET state='cancelled' WHERE workspace_id=$1 AND ceremony_id=$2", [row.workspace_id, row.ceremony_id]); return { error: invalid() }; }
      state.phraseVerifiedAt = now.toISOString(); state.phraseProofHash = await digestObject(input.proof); await this.#save(client, row);
      return { view: await this.#view(client, row, now) };
    }, false);
    if ('error' in result) throw result.error; return result.view;
  }
  async claim(reference: RecoveryOperationReference, auth: RecoveryAuth): Promise<RecoveryView> {
    return this.#with(reference, auth, async (client, row, authority, now, principal) => {
      this.#live(row, now); if (row.public_state.mode !== 'owner_reset' || !row.public_state.redeemedAt) throw invalid();
      const device = (await client.query<{ key_generation: string; signing_public_key: Buffer; recipient_public_key: Buffer }>('SELECT * FROM security.devices WHERE workspace_id=$1 AND device_id=$2', [row.workspace_id, principal!.deviceId])).rows[0]!;
      const authorizer: RecoveryAuthorizer = { kind: 'owner_reset', accountId: principal!.accountId,
        device: { id: principal!.deviceId!, keyGeneration: device.key_generation, signingPublicKey: base64urlEncode(device.signing_public_key), recipientPublicKey: base64urlEncode(device.recipient_public_key) },
        credentialGeneration: principal!.credentialGeneration, sessionGeneration: principal!.sessionGeneration, resetId: row.ceremony_id, resetGeneration: row.public_state.resetGeneration };
      const saved = row.public_state;
      if (saved.binding && equal(saved.binding.authorizer, authorizer)) { await this.#check(client, row, authority, now); return this.#view(client, row, now); }
      // A takeover clears every prior draft/proof/approval. A staged immutable grant requires a fresh reset operation instead.
      if (saved.requestHash) throw conflict();
      delete saved.binding; delete saved.draft; delete saved.draftHash; delete saved.proofId; delete saved.proofExpiresAt; delete saved.proofVerifiedAt; delete saved.authorizerConfirmation;
      saved.binding = await this.#binding(client, row, authority, authorizer, now);
      await client.query(`UPDATE security.ceremonies SET state='waiting_approval',approving_profile_id=$3,approving_device_id=$4,
        public_state=$5,staged_registration_record=NULL,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND ceremony_id=$2`, [row.workspace_id, row.ceremony_id, principal!.accountId, principal!.deviceId, saved]);
      row.state = 'waiting_approval'; return this.#view(client, row, now);
    }, false);
  }
  async inspect(reference: RecoveryOperationReference | RecoveryReference, auth?: RecoveryAuth): Promise<RecoveryView> {
    return this.#with(reference, auth, (client, row, _authority, now) => this.#view(client, row, now), false);
  }
  async registration(input: unknown) {
    const request = parse(recoveryRegistration, input);
    return this.#with(request, undefined, (_client, row) => this.#options.opaque.response(row.workspace_id, row.profile_id, request.registrationRequest));
  }
  #proofContext(row: Ceremony, proofId: string, draftHash: string) {
    return canonicalJson(['ukda.recovery-password-proof.v1', this.#options.origin, row.workspace_id, row.ceremony_id, row.profile_id,
      row.public_state.binding!.credentialGeneration, proofId, draftHash]);
  }
  async startProof(input: unknown) {
    const request = parse(recoveryProofStart, input);
    return this.#with(request, undefined, async (client, row, _authority, now) => {
      const configuration = await this.#options.opaque.publicConfiguration(row.workspace_id, row.profile_id);
      let checked: Awaited<ReturnType<typeof validateRecoveryDraft>>;
      try { checked = await validateRecoveryDraft(request.draft, row.public_state.binding!, configuration); } catch { throw conflict(); }
      const { registrationRecord, ...draft } = checked.draft;
      const draftHash = await digestObject({ transcript: draft.transcript, registrationRecord, newRecoveryConfirmation: draft.newRecoveryConfirmation });
      if (row.public_state.draftHash && row.public_state.draftHash !== draftHash) throw conflict();
      if (row.public_state.draft?.recipientConfirmation && draft.recipientConfirmation && !equal(row.public_state.draft.recipientConfirmation, draft.recipientConfirmation)) throw conflict();
      draft.recipientConfirmation ??= row.public_state.draft?.recipientConfirmation ?? null;
      await this.#freshKeys(client, row.workspace_id, draft.transcript);
      await this.#options.opaque.validateRegistrationRecord(row.workspace_id, row.profile_id, registrationRecord);
      const proof = await this.#options.opaque.startLogin(row.workspace_id, row.profile_id, registrationRecord, request.startLoginRequest);
      const proofId = randomUUID(), expiresAt = new Date(Math.min(now.getTime() + 120_000, row.expires_at.getTime()));
      const protectedState = await this.#options.secrets.protectState(this.#proofContext(row, proofId, draftHash), proof.serverLoginState);
      row.public_state.draft = draft; row.public_state.draftHash = draftHash; row.public_state.proofId = proofId; row.public_state.proofExpiresAt = expiresAt.toISOString(); delete row.public_state.proofVerifiedAt;
      await client.query(`UPDATE security.ceremonies SET public_state=$3,staged_registration_record=$4,server_state_ciphertext=$5,server_state_key_id=$6 WHERE workspace_id=$1 AND ceremony_id=$2`,
        [row.workspace_id, row.ceremony_id, row.public_state, registrationRecord, Buffer.from(protectedState), this.#options.secrets.keyId]);
      return { proofId, expiresAt: expiresAt.toISOString(), loginResponse: proof.loginResponse, configuration, draftHash };
    });
  }
  async finishProof(input: unknown) {
    const request = parse(recoveryProofFinish, input);
    const accepted = await this.#with(request, undefined, async (client, row, _authority, now) => {
      const state = row.public_state, expiry = state.proofExpiresAt;
      if (state.proofId !== request.proofId || !expiry || !state.draftHash || !row.server_state_ciphertext) return false;
      delete state.proofExpiresAt; delete state.proofVerifiedAt;
      await client.query('UPDATE security.ceremonies SET public_state=$3,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND ceremony_id=$2', [row.workspace_id, row.ceremony_id, state]);
      if (Date.parse(expiry) <= now.getTime() || row.server_state_key_id !== this.#options.secrets.keyId) return false;
      try {
        const secret = await this.#options.secrets.revealState(this.#proofContext(row, request.proofId, state.draftHash), row.server_state_ciphertext.toString());
        await this.#options.opaque.finishLogin(row.workspace_id, row.profile_id, secret, request.finishLoginRequest);
      } catch { return false; }
      state.proofVerifiedAt = now.toISOString(); await this.#save(client, row); return true;
    });
    if (!accepted) throw invalid(); return { verified: true as const };
  }
  async #freshKeys(client: pg.PoolClient, workspaceId: string, transcript: RecoveryDraft['transcript']) {
    const device = transcript.device, recovery = transcript.recovery;
    if ((await client.query('SELECT 1 FROM security.devices WHERE workspace_id=$1 AND (device_id=$2 OR signing_public_key=$3 OR recipient_public_key=$4)',
      [workspaceId, device.id, base64urlDecode(device.signingPublicKey), base64urlDecode(device.recipientPublicKey)])).rowCount) throw conflict();
    const keys = [device, ...(recovery ? [recovery] : [])];
    if (recovery && (recovery.id === device.id || recovery.signingPublicKey === device.signingPublicKey || recovery.recipientPublicKey === device.recipientPublicKey)) throw conflict();
    for (const key of keys) {
      if ((await client.query(`SELECT 1 FROM security.devices WHERE workspace_id=$1 AND
          (device_id=$2 OR signing_public_key=$3 OR recipient_public_key=$4) UNION ALL
          SELECT 1 FROM security.recovery_authorities r JOIN security.staged_objects o
          ON o.workspace_id=r.workspace_id AND o.object_id=r.custody_envelope_object_id WHERE r.workspace_id=$1 AND
          (o.versioned_object->'header'->>'recipientId'=$2::text OR r.proof_public_key=$3 OR r.recipient_public_key=$4)`,
        [workspaceId, key.id, base64urlDecode(key.signingPublicKey), base64urlDecode(key.recipientPublicKey)])).rowCount) throw conflict();
    }
  }
  async confirm(reference: RecoveryOperationReference | RecoveryReference, input: unknown, auth?: RecoveryAuth): Promise<RecoveryView> {
    const proof = parse(recoveryConfirmation, input);
    const result = await this.#with(reference, auth, async (client, row, _authority, now, principal) => {
      const draft = row.public_state.draft; if (!draft || proof.body.role === 'new_recovery') throw invalid();
      const binding = row.public_state.binding!, authorizer = binding.authorizer, role = proof.body.role;
      if (role === 'recipient' && principal) throw forbidden();
      if (role === 'authorizer' && authorizer.kind === 'owner_reset' && (!principal || principal.accountId !== authorizer.accountId || principal.deviceId !== authorizer.device.id)) throw forbidden();
      if (role === 'authorizer' && authorizer.kind === 'phrase' && principal) throw forbidden();
      const key = role === 'recipient' ? draft.transcript.device.signingPublicKey : authorizer.kind === 'phrase' ? authorizer.recovery.signingPublicKey : authorizer.device.signingPublicKey;
      const valid = equal(proof.body, recoveryConfirmationFor(draft.transcript, await digestObject(draft.transcript), role)) && await verifyObject(proof, base64urlDecode(key), 'ukda.recovery-confirmation.v1');
      if (!valid) { await client.query("UPDATE security.ceremonies SET state='cancelled' WHERE workspace_id=$1 AND ceremony_id=$2", [row.workspace_id, row.ceremony_id]); return { error: invalid() }; }
      if (role === 'recipient') draft.recipientConfirmation = proof; else row.public_state.authorizerConfirmation = proof;
      await this.#save(client, row); return { view: await this.#view(client, row, now) };
    });
    if ('error' in result) throw result.error; return result.view;
  }
  async #materials(client: pg.PoolClient, row: Ceremony, recipient: { id: string; kind: 'device' | 'recovery' }, custody: boolean): Promise<PairingMaterial[]> {
    const binding = row.public_state.binding!, ids = [...new Set(binding.scopes.flatMap((scope) => scope.sources.map((source) => source.manifestId)))];
    const rows = (await client.query<Stored>(`SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND state='committed' AND
      (object_id=ANY($2::uuid[]) OR (object_kind='key_envelope' AND versioned_object->'header'->>'recipientId'=$3 AND versioned_object->'header'->>'recipientKind'=$4)
      OR ($5 AND object_kind='custody_manifest' AND versioned_object->'header'->>'scope'='workspace' AND versioned_object->'header'->>'scopeId'=$1::text AND versioned_object->'header'->>'keyEpoch'=$6)) ORDER BY object_id`,
      [row.workspace_id, ids, recipient.id, recipient.kind, custody, binding.custodyEpoch])).rows;
    const materials: PairingMaterial[] = [];
    for (const object of rows) {
      const header = (object.versioned_object as { header?: { scope?: string; scopeId?: string } }).header;
      if (!ids.includes(object.object_id) && !binding.scopes.some((scope) => scope.scope === header?.scope && scope.scopeId === header.scopeId)) continue;
      if (await digestObject(object.versioned_object) !== object.object_hash) throw invalid();
      materials.push({ id: object.object_id, digest: object.object_hash, kind: object.object_kind, value: object.versioned_object });
    }
    if (ids.some((id) => !materials.some((item) => item.id === id))) throw invalid(); return materials;
  }
  #approvingPrincipal(row: Ceremony, principal?: SessionPrincipal) {
    const authorizer = row.public_state.binding!.authorizer;
    if (authorizer.kind === 'owner_reset' && (!principal || principal.accountId !== authorizer.accountId || principal.deviceId !== authorizer.device.id)) throw forbidden();
    if (authorizer.kind === 'phrase' && principal) throw forbidden();
  }
  async materials(reference: RecoveryOperationReference | RecoveryReference, auth?: RecoveryAuth): Promise<PairingMaterial[]> {
    return this.#with(reference, auth, (client, row, _authority, _now, principal) => {
      this.#approvingPrincipal(row, principal); const authorizer = row.public_state.binding!.authorizer;
      return this.#materials(client, row, { id: authorizer.kind === 'phrase' ? authorizer.recovery.id : authorizer.device.id,
        kind: authorizer.kind === 'phrase' ? 'recovery' : 'device' }, true);
    });
  }
  #passwordProved(row: Ceremony, now: Date) {
    if (!row.public_state.proofVerifiedAt || now.getTime() - Date.parse(row.public_state.proofVerifiedAt) >= 300_000 || !row.staged_registration_record || !row.public_state.draft) {
      throw new AppError('PASSWORD_PROOF_REQUIRED', 'Repeat verification of the new password', 401);
    }
  }
  async stage(reference: RecoveryOperationReference | RecoveryReference, input: unknown, auth?: RecoveryAuth): Promise<RecoveryView> {
    const approval = parse(recoveryApproval, input);
    return this.#with(reference, auth, async (client, row, _authority, now, principal) => {
      this.#approvingPrincipal(row, principal); this.#passwordProved(row, now);
      const state = row.public_state, configuration = await this.#options.opaque.publicConfiguration(row.workspace_id, row.profile_id);
      if (!state.authorizerConfirmation || !equal(approval.transition.body.authorizerConfirmation, state.authorizerConfirmation)) throw invalid();
      let checked: Awaited<ReturnType<typeof validateRecoveryApproval>>;
      try { checked = await validateRecoveryApproval(approval, { ...state.draft!, registrationRecord: row.staged_registration_record! }, state.binding!, configuration); } catch { throw conflict(); }
      if (state.requestHash && state.requestHash !== checked.requestHash) throw conflict();
      await this.#freshKeys(client, row.workspace_id, checked.payload.transition.body.transcript);
      const objects = [{ id: row.ceremony_id, kind: 'signed_grant', value: approval.transition }, ...approval.deliveries.map((delivery) => ({ id: delivery.id, kind: 'key_envelope', value: delivery.envelope }))];
      if (new Set(objects.map((object) => object.id)).size !== objects.length) throw conflict();
      for (const object of objects) {
        const hash = await digestObject(object.value), existing = (await client.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [row.workspace_id, object.id])).rows[0];
        if (existing && (existing.object_hash !== hash || existing.object_kind !== object.kind || existing.staged_operation_id !== row.ceremony_id || existing.state !== 'staged')) throw conflict();
        if (!existing) await client.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,created_at,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [row.workspace_id, object.id, object.kind, hash, object.value, row.ceremony_id, now, row.expires_at]);
        const readback = (await client.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [row.workspace_id, object.id])).rows[0];
        if (!readback || readback.object_hash !== hash || await digestObject(readback.versioned_object) !== hash) throw invalid();
      }
      state.requestHash = checked.requestHash; await this.#save(client, row); return this.#view(client, row, now);
    });
  }
  async #approval(client: pg.PoolClient, row: Ceremony): Promise<RecoveryApproval> {
    const transition = (await client.query<Stored>("SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND object_kind='signed_grant' AND staged_operation_id=$2", [row.workspace_id, row.ceremony_id])).rows[0];
    if (!transition || await digestObject(transition.versioned_object) !== transition.object_hash) throw invalid();
    const signed = recoveryApproval.shape.transition.parse(transition.versioned_object), deliveries: RecoveryApproval['deliveries'] = [];
    for (const descriptor of signed.body.deliveries) {
      const object = (await client.query<Stored>("SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND object_kind='key_envelope' AND staged_operation_id=$3", [row.workspace_id, descriptor.id, row.ceremony_id])).rows[0];
      if (!object || object.object_hash !== descriptor.digest || await digestObject(object.versioned_object) !== descriptor.digest) throw invalid();
      deliveries.push({ id: object.object_id, envelope: recoveryApproval.shape.deliveries.element.shape.envelope.parse(object.versioned_object) });
    }
    return { transition: signed, deliveries };
  }
  async #project(workspaceId: string, receipt: RecoveryReceipt, application?: pg.PoolClient): Promise<RecoveryResult> {
    try { await this.#options.hooks?.beforeProjection?.(); const result = await projectAuthoritativeWorkspace(this.#options.databases, workspaceId, application);
      return { state: result.state === 'ready' ? 'completed' : 'finishing', receipt }; }
    catch { return { state: 'finishing', receipt }; }
  }
  async finalize(input: (RecoveryOperationReference | RecoveryReference) & { requestHash: string }, auth?: RecoveryAuth): Promise<RecoveryResult> {
    const reference: RecoveryOperationReference | RecoveryReference = 'resumeToken' in input ? parse(recoveryReference, { workspaceId: input.workspaceId, operationId: input.operationId, resumeToken: input.resumeToken }) : { workspaceId: input.workspaceId, operationId: input.operationId };
    if (!/^[0-9a-f]{64}$/.test(input.requestHash)) throw invalid();
    const preflight = async () => this.#with(reference, auth, async (client, row, authority, now, principal) => {
      if (row.public_state.requestHash !== input.requestHash) throw conflict();
      if (row.state === 'completed') return this.#receipt(client, row);
      await this.#check(client, row, authority, now); this.#approvingPrincipal(row, principal); this.#passwordProved(row, now); return undefined;
    }, false);
    const existing = await preflight(); if (existing) return this.#project(reference.workspaceId, existing);
    const result = await withSecurityFence(this.#options.databases, reference.workspaceId, async (application) => {
      let receipt: RecoveryReceipt;
      try { receipt = await this.#with(reference, auth, async (client, row, authority, now, principal) => {
        if (row.public_state.requestHash !== input.requestHash) throw conflict();
        if (row.state === 'completed') return this.#receipt(client, row);
        await this.#check(client, row, authority, now); this.#approvingPrincipal(row, principal); this.#passwordProved(row, now);
        const approval = await this.#approval(client, row), configuration = await this.#options.opaque.publicConfiguration(row.workspace_id, row.profile_id);
        let checked: Awaited<ReturnType<typeof validateRecoveryApproval>>;
        try { checked = await validateRecoveryApproval(approval, { ...row.public_state.draft!, registrationRecord: row.staged_registration_record! }, row.public_state.binding!, configuration); } catch { throw conflict(); }
        if (checked.requestHash !== input.requestHash) throw conflict();
        const { transcript } = approval.transition.body, binding = transcript.binding, authorizer = binding.authorizer;
        await this.#freshKeys(client, row.workspace_id, transcript);
        await client.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition,created_at)
          VALUES($1,$2,$3,$4,$5,'account.recover',$6,$7,$8,$9,$10)`, [row.workspace_id, binding.nextSecurityVersion, row.ceremony_id, binding.securityHead,
          checked.securityHead, authorizer.kind === 'phrase' ? 'recovery' : 'device', authorizer.accountId, authorizer.kind === 'phrase' ? null : authorizer.device.id, approval.transition, now]);
        await client.query("UPDATE security.staged_objects SET state='committed',committed_security_version=$3 WHERE workspace_id=$1 AND staged_operation_id=$2 AND object_id=ANY($4::uuid[])", [row.workspace_id, row.ceremony_id, binding.nextSecurityVersion, [row.ceremony_id, ...approval.deliveries.map((item) => item.id)]]);
        await client.query(`UPDATE security.profiles SET opaque_registration_record=$3,opaque_setup_id=$4,opaque_config_id=$5,opaque_identifiers=$6,
          credential_generation=$7,session_generation=$8,recovery_generation=$9,updated_at=$10 WHERE workspace_id=$1 AND profile_id=$2`, [row.workspace_id, row.profile_id,
          row.staged_registration_record, configuration.setupId, configuration.configId, configuration.identifiers, binding.nextCredentialGeneration, binding.nextSessionGeneration, binding.nextRecoveryGeneration, now]);
        await client.query("UPDATE security.devices SET state='revoked',revoked_at=$3 WHERE workspace_id=$1 AND profile_id=$2 AND state<>'revoked'", [row.workspace_id, row.profile_id, now]);
        await client.query("UPDATE security.grants SET state='revoked',revoked_at=$3 WHERE workspace_id=$1 AND profile_id=$2 AND (device_id IS NOT NULL OR grant_kind IN ('owner','recovery')) AND state<>'revoked'", [row.workspace_id, row.profile_id, now]);
        await client.query('UPDATE security.sessions SET revoked_at=coalesce(revoked_at,$3) WHERE workspace_id=$1 AND profile_id=$2', [row.workspace_id, row.profile_id, now]);
        await client.query(`UPDATE security.auth_attempts SET state='consumed',outcome='failed',consumed_at=$3,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND profile_id=$2 AND state='issued'`, [row.workspace_id, row.profile_id, now]);
        await client.query(`UPDATE security.ceremonies SET state='cancelled',staged_registration_record=NULL,server_state_ciphertext=NULL,server_state_key_id=NULL
          WHERE workspace_id=$1 AND profile_id=$2 AND ceremony_id<>$3 AND state IN ('issued','waiting_approval')`, [row.workspace_id, row.profile_id, row.ceremony_id]);
        await client.query(`INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approval_security_version,created_at,approved_at)
          VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8,$8)`, [row.workspace_id, transcript.device.id, row.profile_id, transcript.device.keyGeneration,
          base64urlDecode(transcript.device.signingPublicKey), base64urlDecode(transcript.device.recipientPublicKey), binding.nextSecurityVersion, now]);
        for (const scope of binding.scopes) {
          const descriptor = approval.transition.body.deliveries.find((entry) => entry.scope === scope.scope && entry.scopeId === scope.scopeId && entry.recipientKind === 'device')!;
          await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,scope_id,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,security_version,created_at,activated_at,expires_at,key_epoch)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,$12,$13,$13,$14,$15)`, [row.workspace_id, scope.scope === 'workspace' ? row.ceremony_id : descriptor.id,
            row.profile_id, transcript.device.id, scope.scope === 'workspace' ? 'device' : 'project', scope.scope, scope.scope === 'workspace' ? null : scope.scopeId,
            transcript.device.keyGeneration, scope.permissions, row.ceremony_id, descriptor.id, binding.nextSecurityVersion, now, scope.expiresAt, scope.keyEpoch]);
          if (scope.mode === 'custody') await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,security_version,created_at,activated_at,expires_at,key_epoch)
            VALUES($1,$2,$3,'owner','workspace',$4,$5,'active',$6,$7,$8,$9,$9,$10,$11)`, [row.workspace_id, randomUUID(), row.profile_id, binding.nextRecoveryGeneration,
            scope.permissions, row.ceremony_id, descriptor.id, binding.nextSecurityVersion, now, scope.expiresAt, scope.keyEpoch]);
        }
        if (transcript.recovery) {
          const recoveryDelivery = approval.transition.body.deliveries.find((entry) => entry.recipientKind === 'recovery')!;
          await client.query("UPDATE security.recovery_authorities SET state='revoked',revoked_at=$3 WHERE workspace_id=$1 AND profile_id=$2 AND state='active'", [row.workspace_id, row.profile_id, now]);
          await client.query(`INSERT INTO security.recovery_authorities(workspace_id,profile_id,generation,proof_public_key,recipient_public_key,custody_envelope_object_id,custody_epoch,state,kit_verified_at,created_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,$8)`, [row.workspace_id, row.profile_id, transcript.recovery.generation,
            base64urlDecode(transcript.recovery.signingPublicKey), base64urlDecode(transcript.recovery.recipientPublicKey), recoveryDelivery.id, binding.custodyEpoch, now]);
        }
        await client.query('UPDATE security.workspaces SET security_head=$2,security_version=$3,updated_at=$4 WHERE workspace_id=$1', [row.workspace_id, checked.securityHead, binding.nextSecurityVersion, now]);
        const receipt = recoveryReceipt.parse({ version: 1, operationId: row.ceremony_id, workspaceId: row.workspace_id, accountId: row.profile_id,
          deviceId: transcript.device.id, credentialGeneration: binding.nextCredentialGeneration, sessionGeneration: binding.nextSessionGeneration,
          keyGeneration: binding.nextDeviceKeyGeneration, recoveryGeneration: binding.nextRecoveryGeneration, dataGeneration: binding.dataGeneration,
          securityVersion: binding.nextSecurityVersion, securityHead: checked.securityHead, requestHash: checked.requestHash,
          wrapperHash: transcript.wrapperHash, committedAt: now.toISOString(), transition: approval.transition });
        await client.query(`INSERT INTO security.operation_receipts(workspace_id,operation_id,request_hash,operation_kind,security_version,outcome,created_at)
          VALUES($1,$2,$3,'account.recover',$4,$5,$6)`, [row.workspace_id, row.ceremony_id, checked.requestHash, binding.nextSecurityVersion, receipt, now]);
        row.public_state.resumeExpiresAt = new Date(now.getTime() + 86400_000).toISOString();
        await client.query(`UPDATE security.ceremonies SET state='completed',completed_at=$3,public_state=$4,staged_registration_record=NULL,
          server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND ceremony_id=$2`, [row.workspace_id, row.ceremony_id, now, row.public_state]);
        await this.#options.hooks?.beforeControlCommit?.(); return receipt;
      }, false); } catch (error) {
        if (!(error instanceof AppError)) throw error;
        await projectAuthoritativeWorkspace(this.#options.databases, reference.workspaceId, application); return { error };
      }
      await this.#options.hooks?.afterControlCommit?.(); return { result: await this.#project(reference.workspaceId, receipt, application) };
    }, { enqueueActivationProjection: true });
    if ('error' in result) throw result.error; return result.result;
  }
  async status(reference: RecoveryOperationReference | RecoveryReference, auth?: RecoveryAuth): Promise<RecoveryView> {
    const view = await this.inspect(reference, auth);
    if (!view.receipt) return view;
    const projected = await this.#project(reference.workspaceId, view.receipt); return { ...view, state: projected.state };
  }
  async cancel(reference: RecoveryReference): Promise<RecoveryView> {
    return this.#with(parse(recoveryReference, reference), undefined, async (client, row, _authority, now) => {
      if (row.state === 'completed') return this.#view(client, row, now);
      await client.query("UPDATE security.ceremonies SET state='cancelled',staged_registration_record=NULL,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND ceremony_id=$2", [row.workspace_id, row.ceremony_id]);
      row.state = 'cancelled'; return this.#view(client, row, now);
    }, false);
  }
  async withAuthorizedHistory<T>(reference: RecoveryOperationReference | RecoveryReference, auth: RecoveryAuth | undefined,
    action: (client: pg.PoolClient, context: { workspaceId: string; operationId: string; accountId: string; binding: RecoveryBinding;
      receipt: RecoveryReceipt | null; current: { securityHead: string; securityVersion: string } }) => Promise<T>): Promise<T> {
    return this.#transaction(reference.workspaceId, async (client, authority, now) => {
      // Hold the workspace authority lock from authorization through the final bounded journal read.
      const session = auth ? await this.#options.sessions.resolveCurrent(client, auth.cookieValue, { csrfToken: auth.csrfToken, approved: true }, now) : undefined;
      if (session && session.workspaceId !== reference.workspaceId) throw forbidden();
      const row = await this.#row(client, reference, true), binding = row.public_state.binding;
      if (!binding) throw invalid();
      const receipt = row.state === 'completed' ? await this.#receipt(client, row) : null;
      if (receipt) {
        if (!session) throw forbidden();
        const target = session.accountId === receipt.accountId && session.deviceId === receipt.deviceId &&
          session.credentialGeneration === receipt.credentialGeneration && session.sessionGeneration === receipt.sessionGeneration && session.dataGeneration === receipt.dataGeneration;
        if (!target) {
          if (binding.authorizer.kind !== 'owner_reset' || session.accountId !== binding.authorizer.accountId || session.deviceId !== binding.authorizer.device.id) throw forbidden();
          await this.#owner(client, reference.workspaceId, auth!, now);
        }
      } else {
        if (session) await this.#owner(client, reference.workspaceId, auth!, now);
        else {
          if (!('resumeToken' in reference)) throw invalid();
          parse(recoveryReference, { workspaceId: reference.workspaceId, operationId: reference.operationId, resumeToken: reference.resumeToken });
          this.#capability(row, reference, now);
        }
        await this.#check(client, row, authority, now);
      }
      return action(client, { workspaceId: row.workspace_id, operationId: row.ceremony_id, accountId: row.profile_id, binding, receipt,
        current: { securityHead: authority.security_head, securityVersion: authority.security_version } });
    });
  }
  async delivery(cookie: string, operationId: string) {
    const initial = await this.#options.sessions.authenticate(cookie, { approved: true });
    return this.#transaction(initial.workspaceId, async (client, _authority, now) => {
      const principal = await this.#options.sessions.resolveCurrent(client, cookie, { approved: true }, now);
      const row = await this.#row(client, { workspaceId: principal.workspaceId, operationId }), receipt = await this.#receipt(client, row);
      if (row.state !== 'completed' || receipt.accountId !== principal.accountId || receipt.deviceId !== principal.deviceId ||
        receipt.credentialGeneration !== principal.credentialGeneration || receipt.sessionGeneration !== principal.sessionGeneration || receipt.dataGeneration !== principal.dataGeneration) throw forbidden();
      const profile = await this.#profile(client, principal.workspaceId, principal.accountId), binding = receipt.transition.body.transcript.binding;
      if (profile.is_owner !== binding.isOwner || profile.recovery_generation !== receipt.recoveryGeneration) throw forbidden();
      if (!personalScopesCover(await this.#scopes(client, principal.workspaceId, profile), binding.scopes)) throw forbidden();
      const grants = (await client.query<{ key_manifest_object_id: string; permissions: string[]; scope_kind: string; scope_id: string | null; key_epoch: string }>(`SELECT * FROM security.grants WHERE workspace_id=$1 AND profile_id=$2 AND device_id=$3
        AND signed_grant_object_id=$4 AND state='active' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$5)`, [row.workspace_id, row.profile_id, principal.deviceId, row.ceremony_id, now])).rows;
      if (binding.scopes.some((scope) => !grants.some((grant) => grant.scope_kind === scope.scope && (grant.scope_id ?? row.workspace_id) === scope.scopeId && grant.key_epoch === scope.keyEpoch && equal(grant.permissions, scope.permissions) &&
        receipt.transition.body.deliveries.some((item) => item.recipientKind === 'device' && item.scope === scope.scope && item.scopeId === scope.scopeId && item.id === grant.key_manifest_object_id)))) throw forbidden();
      const approval = await this.#approval(client, row);
      if (!equal(approval.transition, receipt.transition)) throw invalid();
      return { receipt, deliveries: approval.deliveries, materials: await this.#materials(client, row, { id: principal.deviceId!, kind: 'device' }, profile.is_owner) };
    });
  }
}

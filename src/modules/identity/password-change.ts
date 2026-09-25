import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { base64urlEncode, canonicalJson, digestObject } from '../../shared/crypto.js';
import { passwordChangeBegin, passwordChangeBinding, passwordChangeFinalize, passwordChangePayload,
  passwordChangeProofFinish, passwordChangeProofStart, passwordChangeReference, passwordChangeRegistration,
  validatePasswordChangePayload, type PasswordChangeBinding, type PasswordChangePayload, type PasswordChangeReceipt,
  type PasswordChangeReference, type PasswordChangeResult, type PasswordChangeStatus } from '../../shared/password-change.js';
import type { OpaqueService } from './opaque.js';
import type { ServiceSecrets } from './secrets.js';
import type { SessionPrincipal, SessionService } from './sessions.js';
import { projectAuthoritativeWorkspace, withSecurityFence } from './projection.js';

export interface PasswordChangeAuth { cookieValue: string; csrfToken: string }
interface Hooks { beforeControlCommit?: () => Promise<void>; afterControlCommit?: () => Promise<void>; beforeProjection?: () => Promise<void> }
interface Options { databases: Databases; secrets: ServiceSecrets; opaque: OpaqueService; sessions: SessionService;
  origin: string; now?: () => Date; hooks?: Hooks }
const publicState = z.object({ binding: passwordChangeBinding, resumeExpiresAt: z.iso.datetime(),
  requestHash: z.string().optional(), payload: passwordChangePayload.omit({ registrationRecord: true }).optional(),
  proofId: z.string().optional(), proofExpiresAt: z.iso.datetime().optional(), proofVerifiedAt: z.iso.datetime().optional() });
type PublicState = z.infer<typeof publicState>;
interface Ceremony { workspace_id: string; ceremony_id: string; profile_id: string; device_id: string;
  kind: string; state: string; verification_digest: Buffer | null; verification_key_id: string | null;
  public_state: PublicState; staged_registration_record: string | null; server_state_ciphertext: Buffer | null;
  server_state_key_id: string | null; expires_at: Date }
interface Authority { lifecycle: string; security_version: string; security_head: string; data_generation: string;
  ownership_version: string; custody_epoch: string }
const invalid = () => new AppError('PASSWORD_CHANGE_INVALID', 'Password change is unavailable; sign in and try again', 401);
const conflict = () => new AppError('OPERATION_CONFLICT', 'Password change has changed; keep both local wrappers and restart safely', 409);
const proofRequired = () => new AppError('PASSWORD_PROOF_REQUIRED', 'Repeat verification of the new password', 401);
function parse<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) throw new AppError('INVALID_REQUEST', 'Invalid password-change request', 400);
  return result.data;
}

/** The resume capability resolves a public receipt; it can never issue a session or grant access. */
export class PasswordChangeService {
  readonly #options: Options;
  readonly #now: () => Date;
  constructor(options: Options) { this.#options = options; this.#now = options.now ?? (() => new Date()); }
  async #transaction<T>(action: (client: pg.PoolClient, now: Date) => Promise<T>): Promise<T> {
    try { return await transaction(this.#options.databases.control, async (client) => {
      await client.query("SET LOCAL synchronous_commit='on'"); return action(client, this.#now());
    }); } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('PASSWORD_CHANGE_UNAVAILABLE', 'Password change is temporarily unavailable; retain the local draft', 503);
    }
  }
  async #authority(client: pg.PoolClient, workspaceId: string, exclusive = false): Promise<Authority> {
    await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
    const authority = (await client.query<Authority>(`SELECT lifecycle,security_version,security_head,data_generation,ownership_version,custody_epoch
      FROM security.workspaces WHERE workspace_id=$1 FOR ${exclusive ? 'UPDATE' : 'SHARE'}`, [workspaceId])).rows[0];
    if (!authority || !['active', 'pending_deletion'].includes(authority.lifecycle) || authority.security_version === '0') throw invalid();
    return authority;
  }
  async #read(client: pg.PoolClient, reference: PasswordChangeReference, now: Date): Promise<Ceremony> {
    const row = (await client.query<Ceremony>('SELECT * FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2 FOR UPDATE',
      [reference.workspaceId, reference.operationId])).rows[0];
    if (!row || row.kind !== 'password_change' || row.verification_key_id !== this.#options.secrets.keyId || !row.verification_digest ||
      !this.#options.secrets.matches('password-change-resume', `${reference.workspaceId}:${reference.operationId}:${reference.resumeToken}`, row.verification_digest)) throw invalid();
    const state = publicState.safeParse(row.public_state);
    if (!state.success || Date.parse(state.data.resumeExpiresAt) <= now.getTime()) throw invalid();
    row.public_state = state.data;
    return row;
  }
  async #session(client: pg.PoolClient, auth: PasswordChangeAuth, workspaceId: string, now: Date, recent: boolean) {
    const session = await this.#options.sessions.resolveCurrent(client, auth.cookieValue, { csrfToken: auth.csrfToken, approved: true, recent }, now);
    if (session.workspaceId !== workspaceId || !session.deviceId) throw invalid();
    return session;
  }
  #current(row: Ceremony, authority: Authority, session: SessionPrincipal, now: Date) {
    const binding = row.public_state.binding;
    if (row.state !== 'issued' || row.expires_at <= now) throw invalid();
    if (session.accountId !== binding.accountId || session.deviceId !== binding.deviceId ||
      session.credentialGeneration !== binding.credentialGeneration || session.sessionGeneration !== binding.sessionGeneration ||
      authority.data_generation !== binding.dataGeneration || authority.security_version !== binding.securityVersion ||
      authority.security_head !== binding.securityHead || authority.ownership_version !== binding.ownershipVersion || authority.custody_epoch !== binding.custodyEpoch) throw conflict();
  }
  async #with<T>(reference: PasswordChangeReference, auth: PasswordChangeAuth | undefined,
    action: (client: pg.PoolClient, row: Ceremony, now: Date, authority: Authority) => Promise<T>, options: { recent?: boolean; exclusive?: boolean } = {}): Promise<T> {
    return this.#transaction(async (client, now) => {
      const authority = await this.#authority(client, reference.workspaceId, options.exclusive);
      const session = auth ? await this.#session(client, auth, reference.workspaceId, now, options.recent ?? false) : undefined;
      // Session/profile locks precede ceremony locks, matching security mutation order.
      await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [reference.workspaceId]);
      const row = await this.#read(client, reference, now);
      const checkedAt = this.#now();
      if (Date.parse(row.public_state.resumeExpiresAt) <= checkedAt.getTime()) throw invalid();
      if (session) this.#current(row, authority, session, checkedAt);
      return action(client, row, checkedAt, authority);
    });
  }
  #status(row: Ceremony, now: Date): PasswordChangeStatus {
    const state = row.state === 'issued' && row.expires_at <= now ? 'expired' : row.state;
    return { state: state as PasswordChangeStatus['state'], binding: row.public_state.binding,
      resumeExpiresAt: row.public_state.resumeExpiresAt,
      ...(row.public_state.requestHash ? { requestHash: row.public_state.requestHash } : {}) };
  }
  #proofContext(row: Ceremony, proofId: string, requestHash: string) {
    return canonicalJson(['ukda.password-change-proof.v1', this.#options.origin, row.workspace_id, row.ceremony_id,
      row.profile_id, row.device_id, row.public_state.binding.credentialGeneration, requestHash, proofId]);
  }

  async begin(input: z.infer<typeof passwordChangeBegin>, auth: PasswordChangeAuth): Promise<PasswordChangeStatus> {
    const reference = parse(passwordChangeBegin, input);
    return this.#transaction(async (client, now) => {
      const authority = await this.#authority(client, reference.workspaceId, true);
      now = this.#now();
      const session = await this.#session(client, auth, reference.workspaceId, now, true);
      const existing = await client.query('SELECT 1 FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [reference.workspaceId, reference.operationId]);
      if (existing.rowCount) {
        const row = await this.#read(client, reference, now); this.#current(row, authority, session, now); return this.#status(row, now);
      }
      const device = (await client.query<{ key_generation: string; signing_public_key: Buffer; recipient_public_key: Buffer }>(
        'SELECT key_generation,signing_public_key,recipient_public_key FROM security.devices WHERE workspace_id=$1 AND device_id=$2 AND profile_id=$3',
        [reference.workspaceId, session.deviceId, session.accountId])).rows[0];
      if (!device) throw invalid();
      const expiresAt = new Date(now.getTime() + 900000), resumeExpiresAt = new Date(now.getTime() + 86400000);
      const binding = passwordChangeBinding.parse({ version: 1, origin: this.#options.origin,
        workspaceId: reference.workspaceId, operationId: reference.operationId, accountId: session.accountId, deviceId: session.deviceId,
        keyGeneration: device.key_generation, signingPublicKey: base64urlEncode(device.signing_public_key), recipientPublicKey: base64urlEncode(device.recipient_public_key),
        credentialGeneration: session.credentialGeneration, nextCredentialGeneration: String(BigInt(session.credentialGeneration) + 1n),
        sessionGeneration: session.sessionGeneration, nextSessionGeneration: String(BigInt(session.sessionGeneration) + 1n), dataGeneration: authority.data_generation,
        securityVersion: authority.security_version, nextSecurityVersion: String(BigInt(authority.security_version) + 1n), securityHead: authority.security_head,
        ownershipVersion: authority.ownership_version, custodyEpoch: authority.custody_epoch, issuedAt: now.toISOString(), expiresAt: expiresAt.toISOString() });
      await client.query(`INSERT INTO security.ceremonies(workspace_id,ceremony_id,profile_id,device_id,kind,generation,
        verification_digest,verification_key_id,expected_credential_generation,expected_ownership_version,expected_security_version,
        expected_custody_epoch,public_state,created_at,expires_at)
        VALUES($1,$2,$3,$4,'password_change',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [reference.workspaceId, reference.operationId, session.accountId, session.deviceId, binding.nextCredentialGeneration,
        this.#options.secrets.digest('password-change-resume', `${reference.workspaceId}:${reference.operationId}:${reference.resumeToken}`), this.#options.secrets.keyId,
        binding.credentialGeneration, binding.ownershipVersion, binding.securityVersion, binding.custodyEpoch,
        { binding, resumeExpiresAt: resumeExpiresAt.toISOString() }, now, expiresAt]);
      return { state: 'issued', binding, resumeExpiresAt: resumeExpiresAt.toISOString() };
    });
  }
  async registration(input: z.infer<typeof passwordChangeRegistration>, auth: PasswordChangeAuth) {
    const request = parse(passwordChangeRegistration, input);
    return this.#with(request, auth, (_client, row) => this.#options.opaque.response(row.workspace_id, row.profile_id, request.registrationRequest));
  }
  async startProof(input: z.infer<typeof passwordChangeProofStart>, auth: PasswordChangeAuth) {
    const request = parse(passwordChangeProofStart, input);
    return this.#with(request, auth, async (client, row, now) => {
      const configuration = await this.#options.opaque.publicConfiguration(row.workspace_id, row.profile_id);
      let validated: Awaited<ReturnType<typeof validatePasswordChangePayload>>;
      try { validated = await validatePasswordChangePayload(request.payload, row.public_state.binding, configuration); } catch { throw conflict(); }
      if (row.public_state.requestHash && row.public_state.requestHash !== validated.requestHash) throw conflict();
      await this.#options.opaque.validateRegistrationRecord(row.workspace_id, row.profile_id, validated.payload.registrationRecord);
      const result = await this.#options.opaque.startLogin(row.workspace_id, row.profile_id, validated.payload.registrationRecord, request.startLoginRequest);
      const proofId = randomUUID(), expiresAt = new Date(Math.min(now.getTime() + 120000, row.expires_at.getTime()));
      const protectedState = await this.#options.secrets.protectState(this.#proofContext(row, proofId, validated.requestHash), result.serverLoginState);
      const { registrationRecord, ...draft } = validated.payload;
      const state: PublicState = { binding: row.public_state.binding, resumeExpiresAt: row.public_state.resumeExpiresAt,
        payload: draft, requestHash: validated.requestHash, proofId, proofExpiresAt: expiresAt.toISOString() };
      await client.query(`UPDATE security.ceremonies SET public_state=$3,staged_registration_record=$4,
        server_state_ciphertext=$5,server_state_key_id=$6 WHERE workspace_id=$1 AND ceremony_id=$2`,
      [row.workspace_id, row.ceremony_id, state, registrationRecord, Buffer.from(protectedState), this.#options.secrets.keyId]);
      return { proofId, expiresAt: expiresAt.toISOString(), loginResponse: result.loginResponse, requestHash: validated.requestHash, configuration };
    });
  }
  async finishProof(input: z.infer<typeof passwordChangeProofFinish>, auth: PasswordChangeAuth) {
    const request = parse(passwordChangeProofFinish, input);
    const accepted = await this.#with(request, auth, async (client, row, now) => {
      const state = row.public_state;
      if (state.proofId !== request.proofId || !row.server_state_ciphertext || !state.proofExpiresAt || !state.requestHash) return false;
      const next = { ...state }; delete next.proofExpiresAt; delete next.proofVerifiedAt;
      await client.query(`UPDATE security.ceremonies SET public_state=$3,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND ceremony_id=$2`, [row.workspace_id, row.ceremony_id, next]);
      if (Date.parse(state.proofExpiresAt) <= now.getTime() || row.server_state_key_id !== this.#options.secrets.keyId) return false;
      try {
        const secret = await this.#options.secrets.revealState(this.#proofContext(row, request.proofId, state.requestHash), row.server_state_ciphertext.toString());
        await this.#options.opaque.finishLogin(row.workspace_id, row.profile_id, secret, request.finishLoginRequest);
      } catch { return false; }
      await client.query('UPDATE security.ceremonies SET public_state=$3 WHERE workspace_id=$1 AND ceremony_id=$2',
        [row.workspace_id, row.ceremony_id, { ...next, proofVerifiedAt: now.toISOString() }]);
      return true;
    });
    if (!accepted) throw proofRequired();
    return { verified: true as const };
  }
  async #receipt(client: pg.PoolClient, row: Ceremony): Promise<PasswordChangeReceipt> {
    const result = (await client.query<{ request_hash: string; operation_kind: string; outcome: PasswordChangeReceipt }>(
      'SELECT request_hash,operation_kind,outcome FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2', [row.workspace_id, row.ceremony_id])).rows[0];
    if (!result || result.operation_kind !== 'password.change' || result.request_hash !== row.public_state.requestHash) throw invalid();
    return result.outcome;
  }
  async #project(workspaceId: string, receipt: PasswordChangeReceipt, application?: pg.PoolClient): Promise<PasswordChangeResult> {
    try {
      await this.#options.hooks?.beforeProjection?.();
      const result = await projectAuthoritativeWorkspace(this.#options.databases, workspaceId, application);
      return { state: result.state === 'ready' ? 'completed' : 'finishing', receipt };
    } catch { return { state: 'finishing', receipt }; }
  }
  async finalize(input: z.infer<typeof passwordChangeFinalize>, auth: PasswordChangeAuth): Promise<PasswordChangeResult> {
    const request = parse(passwordChangeFinalize, input);
    // Receipt-first lookup permits an identical retry after every old session was revoked.
    const existing = await this.#with(request, undefined, async (client, row) => {
      if (row.public_state.requestHash !== request.requestHash) throw conflict();
      return row.state === 'completed' ? this.#receipt(client, row) : undefined;
    });
    if (existing) return this.#project(request.workspaceId, existing);
    // Authenticate before closing a healthy workspace's fence.
    try {
      await this.#with(request, auth, async (_client, row, now) => {
        if (!row.public_state.proofVerifiedAt || now.getTime() - Date.parse(row.public_state.proofVerifiedAt) >= 300000) throw proofRequired();
      }, { recent: true });
    } catch (error) {
      // Another identical finalizer may have committed between the receipt lookup
      // and session validation. Resolve that race before reporting stale authority.
      const raced = await this.#with(request, undefined, async (client, row) => {
        if (row.public_state.requestHash !== request.requestHash) throw conflict();
        return row.state === 'completed' ? this.#receipt(client, row) : undefined;
      });
      if (raced) return this.#project(request.workspaceId, raced);
      throw error;
    }
    return withSecurityFence(this.#options.databases, request.workspaceId, async (application) => {
      const receipt = await this.#transaction(async (client, now) => {
        const authority = await this.#authority(client, request.workspaceId, true);
        // Concurrent retries serialize at workspace authority, before session revocation checks.
        const peek = (await client.query<{ state: string }>('SELECT state FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [request.workspaceId, request.operationId])).rows[0];
        if (peek?.state === 'completed') {
          const row = await this.#read(client, request, now);
          if (row.public_state.requestHash !== request.requestHash) throw conflict();
          return this.#receipt(client, row);
        }
        const session = await this.#session(client, auth, request.workspaceId, now, true);
        const row = await this.#read(client, request, now); now = this.#now(); this.#current(row, authority, session, now);
        if (row.public_state.requestHash !== request.requestHash) throw conflict();
        if (!row.public_state.proofVerifiedAt || now.getTime() - Date.parse(row.public_state.proofVerifiedAt) >= 300000 ||
          !row.public_state.payload || !row.staged_registration_record) throw proofRequired();
        const configuration = await this.#options.opaque.publicConfiguration(row.workspace_id, row.profile_id);
        let checked: { payload: PasswordChangePayload; requestHash: string };
        try { checked = await validatePasswordChangePayload({ ...row.public_state.payload, registrationRecord: row.staged_registration_record }, row.public_state.binding, configuration); }
        catch { throw conflict(); }
        if (checked.requestHash !== request.requestHash) throw conflict();
        const binding = row.public_state.binding, transition = checked.payload.transition, head = await digestObject(transition);
        await client.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,
          actor_kind,actor_profile_id,actor_device_id,signed_transition,created_at) VALUES($1,$2,$3,$4,$5,'password.change','device',$6,$7,$8,$9)`,
        [row.workspace_id, binding.nextSecurityVersion, row.ceremony_id, binding.securityHead, head, row.profile_id, row.device_id, transition, now]);
        await client.query(`UPDATE security.profiles SET opaque_registration_record=$3,opaque_setup_id=$4,opaque_config_id=$5,opaque_identifiers=$6,
          credential_generation=$7,session_generation=$8,updated_at=$9 WHERE workspace_id=$1 AND profile_id=$2`,
        [row.workspace_id, row.profile_id, checked.payload.registrationRecord, configuration.setupId, configuration.configId,
          configuration.identifiers, binding.nextCredentialGeneration, binding.nextSessionGeneration, now]);
        await client.query(`UPDATE security.devices SET state='revoked',revoked_at=$4
          WHERE workspace_id=$1 AND profile_id=$2 AND device_id<>$3 AND state<>'revoked'`, [row.workspace_id, row.profile_id, row.device_id, now]);
        await client.query(`UPDATE security.grants SET state='revoked',revoked_at=$4
          WHERE workspace_id=$1 AND profile_id=$2 AND device_id<>$3 AND grant_kind IN ('device','project') AND state<>'revoked'`,
        [row.workspace_id, row.profile_id, row.device_id, now]);
        await client.query('UPDATE security.sessions SET revoked_at=coalesce(revoked_at,$3) WHERE workspace_id=$1 AND profile_id=$2', [row.workspace_id, row.profile_id, now]);
        await client.query(`UPDATE security.auth_attempts SET state='consumed',outcome='failed',consumed_at=$3,server_state_ciphertext=NULL,server_state_key_id=NULL
          WHERE workspace_id=$1 AND profile_id=$2 AND state='issued'`, [row.workspace_id, row.profile_id, now]);
        await client.query(`UPDATE security.ceremonies SET state='cancelled',server_state_ciphertext=NULL,server_state_key_id=NULL,staged_registration_record=NULL
          WHERE workspace_id=$1 AND profile_id=$2 AND ceremony_id<>$3 AND state IN ('issued','waiting_approval')`, [row.workspace_id, row.profile_id, row.ceremony_id]);
        await client.query('UPDATE security.workspaces SET security_version=$2,security_head=$3,updated_at=$4 WHERE workspace_id=$1', [row.workspace_id, binding.nextSecurityVersion, head, now]);
        const completed: PasswordChangeReceipt = { operationId: row.ceremony_id, workspaceId: row.workspace_id, accountId: row.profile_id,
          deviceId: row.device_id, credentialGeneration: binding.nextCredentialGeneration, sessionGeneration: binding.nextSessionGeneration,
          keyGeneration: binding.keyGeneration, dataGeneration: binding.dataGeneration, securityVersion: binding.nextSecurityVersion,
          securityHead: head, requestHash: request.requestHash, wrapperHash: transition.body.wrapperHash, completedAt: now.toISOString(), transition };
        const stored = await client.query<{ outcome: PasswordChangeReceipt }>(`INSERT INTO security.operation_receipts
          (workspace_id,operation_id,request_hash,operation_kind,security_version,outcome,created_at)
          VALUES($1,$2,$3,'password.change',$4,$5,$6) RETURNING outcome`, [row.workspace_id, row.ceremony_id, request.requestHash, binding.nextSecurityVersion, completed, now]);
        await client.query(`UPDATE security.ceremonies SET state='completed',completed_at=$3,public_state=$4,
          server_state_ciphertext=NULL,server_state_key_id=NULL,staged_registration_record=NULL WHERE workspace_id=$1 AND ceremony_id=$2`,
        [row.workspace_id, row.ceremony_id, now, { binding, requestHash: request.requestHash, resumeExpiresAt: new Date(now.getTime() + 86400000).toISOString() }]);
        await this.#options.hooks?.beforeControlCommit?.();
        return stored.rows[0]!.outcome;
      });
      await this.#options.hooks?.afterControlCommit?.();
      return this.#project(request.workspaceId, receipt, application);
    }, { enqueueActivationProjection: true });
  }
  async status(input: PasswordChangeReference): Promise<PasswordChangeStatus> {
    const reference = parse(passwordChangeReference, input);
    const result = await this.#with(reference, undefined, async (client, row, now) => ({ status: this.#status(row, now),
      receipt: row.state === 'completed' ? await this.#receipt(client, row) : undefined }));
    if (!result.receipt) return result.status;
    const projected = await this.#project(reference.workspaceId, result.receipt);
    return { ...result.status, ...projected };
  }
  async cancel(input: PasswordChangeReference, auth: PasswordChangeAuth): Promise<PasswordChangeStatus> {
    const reference = parse(passwordChangeReference, input);
    return this.#with(reference, auth, async (client, row, now) => {
      await client.query(`UPDATE security.ceremonies SET state='cancelled',server_state_ciphertext=NULL,server_state_key_id=NULL,
        staged_registration_record=NULL,public_state=$3 WHERE workspace_id=$1 AND ceremony_id=$2`,
      [row.workspace_id, row.ceremony_id, { binding: row.public_state.binding, resumeExpiresAt: row.public_state.resumeExpiresAt }]);
      return this.#status({ ...row, state: 'cancelled' }, now);
    });
  }
}

import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { transaction } from '../../db.js';
import { AppError } from '../../errors.js';
import { binary, identifier, positiveCounter } from '../../shared/contracts.js';
import { ServiceSecrets } from './secrets.js';

const HOUR = 60 * 60 * 1000;
const token = binary(32);

interface DraftReplacement { operationId: string; expectedDraftGeneration: string; draftGeneration: string }
export interface AttemptRow {
  activation_id: string; licence_id: string; operation_id: string; workspace_id: string;
  reservation_generation: string; resume_digest: Buffer; resume_key_id: string;
  state: 'reserved' | 'completed' | 'expired' | 'cancelled';
  staged_public_state: Record<string, unknown> & { accountId: string; draftReplacements?: DraftReplacement[] };
  request_hash: string | null; completion_receipt: Record<string, unknown> | null;
  created_at: Date; expires_at: Date; completed_at: Date | null; resume_expires_at: Date;
  draft_generation: string; staged_payload_hash: string | null; staged_registration_record: string | null; proof_id: string | null;
  proof_server_state: string | null; proof_expires_at: Date | null; proof_verified_at: Date | null;
}

interface LicenceRow {
  licence_id: string; state: 'available' | 'reserved' | 'activated' | 'revoked' | 'legacy_expired';
  reservation_generation: string; activated_workspace_id: string | null;
}

export interface ActivationStatus {
  activationId: string; operationId: string; workspaceId: string; accountId: string;
  reservationGeneration: string; draftGeneration: string; expiresAt: string;
  resumeExpiresAt: string; state: AttemptRow['state']; receipt?: Record<string, unknown>;
}

function unavailable(): AppError { return new AppError('LICENCE_UNAVAILABLE', 'Licence cannot start setup', 409); }
function invalidAttempt(): AppError { return new AppError('ACTIVATION_INVALID', 'Setup is not available', 404); }
function setWorkspace(client: pg.PoolClient, workspaceId: string) {
  return client.query("SELECT set_config('ukda.workspace_id', $1, true)", [workspaceId]);
}

function publicStatus(row: AttemptRow): ActivationStatus {
  if (!identifier.safeParse(row.staged_public_state.accountId).success) throw invalidAttempt();
  return { activationId: row.activation_id, operationId: row.operation_id, workspaceId: row.workspace_id,
    accountId: row.staged_public_state.accountId, reservationGeneration: row.reservation_generation,
    draftGeneration: row.draft_generation, expiresAt: row.expires_at.toISOString(),
    resumeExpiresAt: row.resume_expires_at.toISOString(), state: row.state,
    ...(row.state === 'completed' && row.completion_receipt ? { receipt: row.completion_receipt } : {}) };
}

/** Service-only API. Issuance is an operational action, never an unauthenticated route. */
export class LicenceReservations {
  readonly #pool: pg.Pool;
  readonly #secrets: ServiceSecrets;
  readonly #now: () => Date;
  constructor(pool: pg.Pool, secrets: ServiceSecrets, options: { now?: () => Date } = {}) {
    this.#pool = pool; this.#secrets = secrets; this.#now = options.now ?? (() => new Date());
  }

  async issueLicence(): Promise<{ licenceId: string; licenceKey: string }> {
    const licenceId = randomUUID();
    const licenceKey = `LIC-${this.#secrets.token()}`;
    await this.#pool.query(`INSERT INTO security.licences
      (licence_id, verification_digest, verification_key_id, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $4)`,
    [licenceId, this.#secrets.digest('licence', licenceKey), this.#secrets.keyId, this.#now()]);
    return { licenceId, licenceKey };
  }

  #validateAttempt(row: AttemptRow, licence: LicenceRow, resumeToken: string, now: Date, allowCompleted: boolean): void {
    if (row.resume_key_id !== this.#secrets.keyId || !this.#secrets.matches('activation-resume', resumeToken, row.resume_digest)) throw invalidAttempt();
    if (row.reservation_generation !== licence.reservation_generation) throw invalidAttempt();
    if (row.state === 'completed') {
      // Consumed entitlement restrictions prevent a new activation, but do not
      // block a bound receipt retry or repair of the existing workspace projection.
      if (!allowCompleted || !['activated', 'revoked', 'legacy_expired'].includes(licence.state) || licence.activated_workspace_id !== row.workspace_id) throw invalidAttempt();
      if (!row.completed_at || now.getTime() >= Math.min(row.resume_expires_at.getTime(), row.completed_at.getTime() + 24 * HOUR)) {
        throw new AppError('ACTIVATION_EXPIRED', 'Setup recovery has expired', 410);
      }
      return;
    }
    if (row.state !== 'reserved' || licence.state !== 'reserved' || licence.activated_workspace_id !== null) throw invalidAttempt();
    if (now >= row.expires_at || now >= row.resume_expires_at) throw new AppError('ACTIVATION_EXPIRED', 'Setup has expired', 410);
  }

  async reserve(input: { licenceKey: string; operationId: string; resumeToken: string }): Promise<ActivationStatus> {
    if (typeof input.licenceKey !== 'string' || !input.licenceKey.startsWith('LIC-') ||
      !token.safeParse(input.licenceKey.slice(4)).success || !identifier.safeParse(input.operationId).success ||
      !token.safeParse(input.resumeToken).success) throw unavailable();
    try {
      return await transaction(this.#pool, async (client) => {
        await client.query("SET LOCAL synchronous_commit='on'");
        const licence = (await client.query<LicenceRow>(`SELECT * FROM security.licences
          WHERE verification_key_id = $1 AND verification_digest = $2 FOR UPDATE`,
        [this.#secrets.keyId, this.#secrets.digest('licence', input.licenceKey)])).rows[0];
        if (!licence) throw unavailable();
        const previous = (await client.query<AttemptRow>('SELECT * FROM security.activation_attempts WHERE operation_id = $1 AND licence_id = $2 FOR UPDATE', [input.operationId, licence.licence_id])).rows[0];
        const now = this.#now();
        if (previous) {
          if (previous.licence_id !== licence.licence_id) throw unavailable();
          this.#validateAttempt(previous, licence, input.resumeToken, now, true);
          return publicStatus(previous);
        }
        if (licence.activated_workspace_id !== null || !['available', 'reserved'].includes(licence.state)) throw unavailable();
        const current = (await client.query<AttemptRow>(`SELECT * FROM security.activation_attempts
          WHERE licence_id = $1 AND state = 'reserved' FOR UPDATE`, [licence.licence_id])).rows[0];
        if (current) {
          if (licence.state !== 'reserved' || current.expires_at > now) throw unavailable();
          await setWorkspace(client, current.workspace_id);
          // Never erase a completed or authority-bearing workspace when recycling an expired claim.
          const removed = await client.query(`DELETE FROM security.workspaces
            WHERE workspace_id = $1 AND lifecycle = 'pending_activation' AND security_version = 0 AND activated_at IS NULL`, [current.workspace_id]);
          if (removed.rowCount !== 1) throw unavailable();
          await client.query(`UPDATE security.activation_attempts SET state = 'expired', staged_public_state = '{}',
            staged_payload_hash = NULL, staged_registration_record = NULL, proof_id = NULL, proof_server_state = NULL,
            proof_expires_at = NULL, proof_verified_at = NULL WHERE activation_id = $1`, [current.activation_id]);
        } else if (licence.state !== 'available') throw unavailable();
        const activationId = randomUUID();
        const workspaceId = randomUUID();
        const accountId = randomUUID();
        const generation = (BigInt(licence.reservation_generation) + 1n).toString();
        const expiresAt = new Date(now.getTime() + HOUR);
        await client.query(`UPDATE security.licences SET state = 'reserved', reservation_generation = $2,
          updated_at = $3 WHERE licence_id = $1`, [licence.licence_id, generation, now]);
        await setWorkspace(client, workspaceId);
        await client.query('INSERT INTO security.workspaces (workspace_id, licence_id, created_at, updated_at) VALUES ($1, $2, $3, $3)', [workspaceId, licence.licence_id, now]);
        const created = (await client.query<AttemptRow>(`INSERT INTO security.activation_attempts
          (activation_id, licence_id, operation_id, workspace_id, reservation_generation, resume_digest,
           resume_key_id, staged_public_state, created_at, expires_at, resume_expires_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10) RETURNING *`,
        [activationId, licence.licence_id, input.operationId, workspaceId, generation,
          this.#secrets.digest('activation-resume', input.resumeToken), this.#secrets.keyId, { accountId }, now, expiresAt])).rows[0];
        if (!created) throw unavailable();
        return publicStatus(created);
      });
    } catch (error) {
      if ((error as { code?: string }).code === '23505') throw unavailable();
      throw error;
    }
  }

  async withAttempt<T>(activationId: string, resumeToken: string,
    callback: (client: pg.PoolClient, row: AttemptRow, now: Date) => Promise<T>,
    options: { allowCompleted?: boolean } = {}): Promise<T> {
    if (!identifier.safeParse(activationId).success || !token.safeParse(resumeToken).success) throw invalidAttempt();
    return transaction(this.#pool, async (client) => {
      await client.query("SET LOCAL synchronous_commit='on'");
      // The unlocked lookup identifies the parent; every path then takes licence -> attempt locks.
      const lookup = (await client.query<{ licence_id: string }>('SELECT licence_id FROM security.activation_attempts WHERE activation_id = $1', [activationId])).rows[0];
      if (!lookup) throw invalidAttempt();
      const licence = (await client.query<LicenceRow>('SELECT * FROM security.licences WHERE licence_id = $1 FOR UPDATE', [lookup.licence_id])).rows[0];
      const row = (await client.query<AttemptRow>('SELECT * FROM security.activation_attempts WHERE activation_id = $1 FOR UPDATE', [activationId])).rows[0];
      if (!licence || !row || row.licence_id !== licence.licence_id) throw invalidAttempt();
      const now = this.#now();
      this.#validateAttempt(row, licence, resumeToken, now, options.allowCompleted === true);
      await setWorkspace(client, row.workspace_id);
      return callback(client, row, now);
    });
  }

  status(activationId: string, resumeToken: string): Promise<ActivationStatus> {
    return this.withAttempt(activationId, resumeToken, async (_client, row) => publicStatus(row), { allowCompleted: true });
  }

  async replaceDraft(activationId: string, resumeToken: string,
    input: { expectedDraftGeneration: string; operationId: string }): Promise<ActivationStatus> {
    if (!positiveCounter.safeParse(input.expectedDraftGeneration).success || !identifier.safeParse(input.operationId).success) {
      throw new AppError('INVALID_REQUEST', 'Invalid setup replacement', 400);
    }
    return this.withAttempt(activationId, resumeToken, async (client, row) => {
      const replacements = row.staged_public_state.draftReplacements ?? [];
      const existing = replacements.find((replacement) => replacement.operationId === input.operationId);
      if (existing) {
        if (existing.expectedDraftGeneration !== input.expectedDraftGeneration) throw new AppError('OPERATION_CONFLICT', 'Setup operation has changed', 409);
        return { ...publicStatus(row), draftGeneration: existing.draftGeneration };
      }
      if (row.draft_generation !== input.expectedDraftGeneration) throw new AppError('DRAFT_CONFLICT', 'Setup draft has changed', 409);
      if (replacements.length >= 128) throw new AppError('DRAFT_LIMIT', 'Start a new setup after this reservation expires', 409);
      const generation = (BigInt(row.draft_generation) + 1n).toString();
      const state = { accountId: row.staged_public_state.accountId,
        draftReplacements: [...replacements, { ...input, draftGeneration: generation }] };
      await client.query("DELETE FROM security.staged_objects WHERE workspace_id = $1 AND state = 'staged'", [row.workspace_id]);
      const updated = (await client.query<AttemptRow>(`UPDATE security.activation_attempts
        SET draft_generation = $2, staged_public_state = $3, staged_payload_hash = NULL, staged_registration_record = NULL,
          request_hash = NULL, proof_id = NULL, proof_server_state = NULL, proof_expires_at = NULL,
          proof_verified_at = NULL WHERE activation_id = $1 RETURNING *`, [activationId, generation, state])).rows[0];
      if (!updated) throw invalidAttempt();
      return publicStatus(updated);
    });
  }
}

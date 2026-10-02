import { randomUUID } from 'node:crypto';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { base64urlDecode, digestObject } from '../../shared/crypto.js';
import { INITIAL_HEAD, validateActivationPayload, type ActivationBinding } from '../../shared/activation.js';
import { LicenceReservations, type AttemptRow } from './licences.js';
import { OpaqueService } from './opaque.js';
import { ServiceSecrets } from './secrets.js';
import { projectAuthoritativeWorkspace, withSecurityFence } from './projection.js';
import { initializeAccessAuthority } from './access-projection.js';

interface ActivationHooks {
  beforeControlCommit?: () => Promise<void>;
  afterControlCommit?: () => Promise<void>;
  beforeProjection?: () => Promise<void>;
}
const invalidDraft = () => new AppError('INVALID_ACTIVATION_DRAFT', 'Setup draft is invalid; repeat setup verification', 400);
const expiredProof = () => new AppError('SETUP_PROOF_INVALID', 'Repeat password verification', 401);

/** Licence setup has its own credential; it never creates or substitutes for a login session. */
export class ActivationService {
  readonly reservations: LicenceReservations;
  readonly #db: Databases;
  readonly #secrets: ServiceSecrets;
  readonly #opaque: OpaqueService;
  readonly #origin: string;
  readonly #hooks: ActivationHooks;
  constructor(input: { databases: Databases; secrets: ServiceSecrets; opaque: OpaqueService; origin: string;
    now?: () => Date; hooks?: ActivationHooks }) {
    this.#db = input.databases; this.#secrets = input.secrets; this.#opaque = input.opaque;
    this.#origin = input.origin; this.#hooks = input.hooks ?? {};
    this.reservations = new LicenceReservations(input.databases.control, input.secrets, input.now ? { now: input.now } : {});
  }

  #binding(row: AttemptRow): ActivationBinding {
    return { activationId: row.activation_id, operationId: row.operation_id, workspaceId: row.workspace_id,
      accountId: row.staged_public_state.accountId, reservationGeneration: row.reservation_generation,
      draftGeneration: row.draft_generation, origin: this.#origin };
  }
  #checkDraft(row: AttemptRow, generation: string) {
    if (row.draft_generation !== generation) throw new AppError('DRAFT_CONFLICT', 'Setup draft has changed', 409);
  }
  #proofContext(row: AttemptRow, proofId: string) {
    return JSON.stringify(['ukda.activation-proof.v1', row.workspace_id, row.staged_public_state.accountId,
      row.activation_id, row.draft_generation, row.staged_payload_hash, proofId]);
  }

  async registration(activationId: string, resumeToken: string, input: { draftGeneration: string; registrationRequest: string }) {
    return this.reservations.withAttempt(activationId, resumeToken, async (_client, row) => {
      this.#checkDraft(row, input.draftGeneration);
      return this.#opaque.response(row.workspace_id, row.staged_public_state.accountId, input.registrationRequest);
    });
  }

  async startProof(activationId: string, resumeToken: string, input: { draftGeneration: string; payload: unknown; startLoginRequest: string }) {
    return this.reservations.withAttempt(activationId, resumeToken, async (client, row, now) => {
      this.#checkDraft(row, input.draftGeneration);
      const configuration = await this.#opaque.publicConfiguration(row.workspace_id, row.staged_public_state.accountId);
      let validated: Awaited<ReturnType<typeof validateActivationPayload>>;
      try { validated = await validateActivationPayload(input.payload, this.#binding(row), configuration); }
      catch { throw invalidDraft(); }
      if (row.staged_payload_hash && row.staged_payload_hash !== validated.requestHash) throw new AppError('OPERATION_CONFLICT', 'Replace the draft before changing setup material', 409);
      await this.#opaque.validateRegistrationRecord(row.workspace_id, row.staged_public_state.accountId, validated.payload.opaqueRegistrationRecord);
      const proof = await this.#opaque.startLogin(row.workspace_id, row.staged_public_state.accountId, validated.payload.opaqueRegistrationRecord, input.startLoginRequest);
      const objects = [...validated.objects, { id: validated.payload.genesis.body.genesisId, kind: 'genesis', value: validated.payload.genesis, digest: validated.genesisFingerprint }];
      for (const object of objects) {
        await client.query(`INSERT INTO security.staged_objects
          (workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,created_at,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (workspace_id,object_id) DO NOTHING`,
        [row.workspace_id, object.id, object.kind, object.digest, object.value, row.operation_id, now, row.expires_at]);
        const stored = (await client.query<{ object_hash: string; versioned_object: unknown; staged_operation_id: string }>(
          'SELECT object_hash,versioned_object,staged_operation_id FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [row.workspace_id, object.id])).rows[0];
        if (!stored || stored.object_hash !== object.digest || stored.staged_operation_id !== row.operation_id || await digestObject(stored.versioned_object) !== object.digest) throw invalidDraft();
      }
      const proofId = randomUUID();
      const expiresAt = new Date(Math.min(now.getTime() + 120_000, row.expires_at.getTime()));
      const protectedState = await this.#secrets.protectState(this.#proofContext({ ...row, staged_payload_hash: validated.requestHash }, proofId), proof.serverLoginState);
      const { opaqueRegistrationRecord, ...publicDraft } = validated.payload;
      await client.query(`UPDATE security.activation_attempts SET staged_public_state=$2,staged_payload_hash=$3,
        staged_registration_record=$4,proof_id=$5,proof_server_state=$6,proof_expires_at=$7,proof_verified_at=NULL WHERE activation_id=$1`,
      [activationId, { ...row.staged_public_state, activation: publicDraft }, validated.requestHash, opaqueRegistrationRecord, proofId, protectedState, expiresAt]);
      return { proofId, expiresAt: expiresAt.toISOString(), loginResponse: proof.loginResponse, requestHash: validated.requestHash, configuration };
    });
  }

  async finishProof(activationId: string, resumeToken: string, input: { draftGeneration: string; proofId: string; finishLoginRequest: string }) {
    // Invalid proofs are consumed in a committed transaction, rather than resurrected by rollback.
    const accepted = await this.reservations.withAttempt(activationId, resumeToken, async (client, row, now) => {
      this.#checkDraft(row, input.draftGeneration);
      if (row.proof_id !== input.proofId || !row.proof_server_state || !row.proof_expires_at || now >= row.proof_expires_at) return false;
      await client.query('UPDATE security.activation_attempts SET proof_server_state=NULL,proof_expires_at=NULL,proof_verified_at=NULL WHERE activation_id=$1', [activationId]);
      try {
        const state = await this.#secrets.revealState(this.#proofContext(row, input.proofId), row.proof_server_state);
        await this.#opaque.finishLogin(row.workspace_id, row.staged_public_state.accountId, state, input.finishLoginRequest);
      } catch { return false; }
      await client.query('UPDATE security.activation_attempts SET proof_verified_at=$2 WHERE activation_id=$1', [activationId, now]);
      return true;
    });
    if (!accepted) throw expiredProof();
    return { verified: true as const };
  }

  async finalize(activationId: string, resumeToken: string, input: { draftGeneration: string; requestHash: string }) {
    // Reject mismatched retries before touching the live workspace's fence.
    const workspaceId = await this.reservations.withAttempt(activationId, resumeToken, async (_client, row, now) => {
      this.#checkDraft(row, input.draftGeneration);
      if ((row.state === 'completed' ? row.request_hash : row.staged_payload_hash) !== input.requestHash) throw new AppError('OPERATION_CONFLICT', 'Setup operation has changed', 409);
      if (row.state !== 'completed' && (!row.proof_verified_at || now.getTime() - row.proof_verified_at.getTime() > 300_000)) throw expiredProof();
      return row.workspace_id;
    }, { allowCompleted: true });
    return withSecurityFence(this.#db, workspaceId, async (application) => {
      const receipt = await this.reservations.withAttempt(activationId, resumeToken, async (control, row, now) => {
        this.#checkDraft(row, input.draftGeneration);
        if (row.state === 'completed') {
          if (row.request_hash !== input.requestHash || !row.completion_receipt) throw new AppError('OPERATION_CONFLICT', 'Setup operation has changed', 409);
          return row.completion_receipt;
        }
        if (!row.staged_payload_hash || row.staged_payload_hash !== input.requestHash) throw new AppError('OPERATION_CONFLICT', 'Setup operation has changed', 409);
        if (!row.proof_verified_at || now.getTime() - row.proof_verified_at.getTime() > 300_000) throw expiredProof();
        const configuration = await this.#opaque.publicConfiguration(row.workspace_id, row.staged_public_state.accountId);
        let validated: Awaited<ReturnType<typeof validateActivationPayload>>;
        try { validated = await validateActivationPayload({ ...(row.staged_public_state.activation as object), opaqueRegistrationRecord: row.staged_registration_record }, this.#binding(row), configuration); }
        catch { throw invalidDraft(); }
        if (validated.requestHash !== input.requestHash) throw invalidDraft();
        const { payload, genesisFingerprint } = validated;
        const body = payload.genesis.body;
        const authority = (await control.query<{ lifecycle: string; security_version: string }>('SELECT lifecycle,security_version FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE', [row.workspace_id])).rows[0];
        if (!authority || authority.lifecycle !== 'pending_activation' || authority.security_version !== '0') throw invalidDraft();
        // Staging committed earlier. Check the immutable read-back manifest again before authority changes.
        for (const object of [...validated.objects, { id: body.genesisId, digest: genesisFingerprint }]) {
          const stored = (await control.query<{ object_hash: string; versioned_object: unknown; state: string }>('SELECT object_hash,versioned_object,state FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [row.workspace_id, object.id])).rows[0];
          if (!stored || stored.state !== 'staged' || stored.object_hash !== object.digest || await digestObject(stored.versioned_object) !== object.digest) throw invalidDraft();
        }
        await control.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition,created_at)
          VALUES($1,1,$2,$3,$4,'workspace.activate','device',$5,$6,$7,$8)`,
        [row.workspace_id, row.operation_id, INITIAL_HEAD, genesisFingerprint, body.accountId, body.device.id, { genesis: payload.genesis, recoveryProof: payload.recoveryProof }, now]);
        await control.query(`INSERT INTO security.profiles(workspace_id,profile_id,state,is_owner,owner_ready_at,profile_object_id,credential_generation,recovery_generation,opaque_registration_record,opaque_setup_id,opaque_config_id,opaque_identifiers,created_at,updated_at,role_id,role_revision,role_assignment_object_id)
          VALUES($1,$2,'active',true,$3,$2,1,1,$4,$5,$6,$7,$3,$3,$8,1,$9)`,
        [row.workspace_id, body.accountId, now, payload.opaqueRegistrationRecord, configuration.setupId, configuration.configId, configuration.identifiers, body.roles.owner, body.genesisId]);
        await control.query(`INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state,approval_security_version,approved_at,created_at)
          VALUES($1,$2,$3,1,$4,$5,'active',1,$6,$6)`,
        [row.workspace_id, body.device.id, body.accountId, base64urlDecode(body.device.signingPublicKey, 32), base64urlDecode(body.device.recipientPublicKey, 32), now]);
        await control.query(`INSERT INTO security.recovery_authorities(workspace_id,profile_id,generation,proof_public_key,recipient_public_key,custody_envelope_object_id,custody_epoch,kit_verified_at,created_at)
          VALUES($1,$2,1,$3,$4,$5,1,$6,$6)`,
        [row.workspace_id, body.accountId, base64urlDecode(body.recovery.signingPublicKey, 32), base64urlDecode(body.recovery.recipientPublicKey, 32), body.recoveryEnvelopeId, now]);
        for (const kind of ['owner', 'device'] as const) {
          await control.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,security_version,activated_at,created_at)
            VALUES($1,$2,$3,$4,$5,'workspace',1,$6,'active',$7,$8,1,$9,$9)`,
          [row.workspace_id, randomUUID(), body.accountId, kind === 'owner' ? null : body.device.id, kind, body.ownerPermissions, body.genesisId, body.custodyId, now]);
        }
        await control.query(`UPDATE security.staged_objects SET state='committed',committed_security_version=1,expires_at=NULL WHERE workspace_id=$1 AND staged_operation_id=$2`, [row.workspace_id, row.operation_id]);
        await initializeAccessAuthority(control, body);
        await control.query(`UPDATE security.workspaces SET lifecycle='active',security_head=$2,security_version=1,ownership_version=1,custody_epoch=1,genesis_object_id=$3,
          current_custody_manifest_object_id=$5,activated_at=$4,updated_at=$4 WHERE workspace_id=$1`, [row.workspace_id, genesisFingerprint, body.genesisId, now, body.custodyId]);
        await control.query(`UPDATE security.licences SET state='activated',activated_workspace_id=$2,activated_at=$3,updated_at=$3 WHERE licence_id=$1`, [row.licence_id, row.workspace_id, now]);
        const completed = { workspaceId: row.workspace_id, accountId: body.accountId, deviceId: body.device.id,
          operationId: row.operation_id, credentialGeneration: '1', dataGeneration: '1', securityVersion: '1', securityHead: genesisFingerprint,
          genesisFingerprint, completedAt: now.toISOString() };
        await control.query(`INSERT INTO security.operation_receipts(workspace_id,operation_id,request_hash,operation_kind,security_version,outcome,created_at)
          VALUES($1,$2,$3,'workspace.activate',1,$4,$5)`, [row.workspace_id, row.operation_id, input.requestHash, completed, now]);
        await control.query(`UPDATE security.activation_attempts SET state='completed',request_hash=$2,completion_receipt=$3,completed_at=$4,resume_expires_at=$5,
          staged_public_state=$6,staged_registration_record=NULL,proof_id=NULL,proof_server_state=NULL,proof_expires_at=NULL,proof_verified_at=NULL WHERE activation_id=$1`,
        [activationId, input.requestHash, completed, now, new Date(now.getTime() + 86_400_000), { accountId: body.accountId }]);
        await this.#hooks.beforeControlCommit?.();
        return completed;
      }, { allowCompleted: true });
      await this.#hooks.afterControlCommit?.();
      try {
        await this.#hooks.beforeProjection?.();
        const projected = await projectAuthoritativeWorkspace(this.#db, workspaceId, application);
        return { state: projected.state === 'ready' ? 'completed' as const : 'finishing_setup' as const, receipt };
      } catch { return { state: 'finishing_setup' as const, receipt }; }
    }, { enqueueActivationProjection: true });
  }

  async status(activationId: string, resumeToken: string) {
    const status = await this.reservations.status(activationId, resumeToken);
    if (status.state !== 'completed') return { ...status, configuration: await this.#opaque.publicConfiguration(status.workspaceId, status.accountId) };
    try {
      const projected = await projectAuthoritativeWorkspace(this.#db, status.workspaceId);
      return { ...status, state: projected.state === 'ready' ? 'completed' as const : 'finishing_setup' as const };
    } catch { return { ...status, state: 'finishing_setup' as const }; }
  }
}

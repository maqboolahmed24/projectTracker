import type pg from 'pg';
import { z } from 'zod';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { identifier } from '../../shared/contracts.js';
import { base64urlDecode, base64urlEncode, canonicalJson, digestObject, verifyObject, verifyRecipientEnvelope } from '../../shared/crypto.js';
import { pairingApproval, pairingBegin, pairingConfirmation, pairingConfirmationFor, pairingReceipt, pairingRecipientHeader, pairingTranscript,
  type PairingApproval, type PairingBegin, type PairingConfirmation, type PairingDelivery, type PairingMaterial, type PairingReceipt,
  type PairingScope, type PairingTranscript, type PairingView } from '../../shared/pairing.js';
import { assertEntitlementAllows } from './entitlements.js';
import { projectAuthoritativeWorkspace, withSecurityFence, type ProjectionResult } from './projection.js';
import { SessionService, type SessionPrincipal } from './sessions.js';
import { intersectDeviceScopes, personalScopesCover, PersonalScopeError, readPersonalScopes } from './personal-scopes.js';

const invalid = () => new AppError('PAIRING_INVALID', 'Restart device pairing and verify the full fingerprint', 409);
const forbidden = () => new AppError('PAIRING_FORBIDDEN', 'This session cannot approve this device', 403);
const conflict = () => new AppError('OPERATION_CONFLICT', 'Pairing operation does not match its saved request', 409);
const equal = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
interface Authority { security_head: string; security_version: string; data_generation: string; ownership_version: string;
  custody_epoch: string; genesis_object_id: string; licence_state: string; lifecycle: string }
interface Profile { profile_id: string; state: string; is_owner: boolean; credential_generation: string; session_generation: string }
interface Device { device_id: string; profile_id: string; key_generation: string; signing_public_key: Buffer; recipient_public_key: Buffer; state: string }
interface Saved { expected: { credentialGeneration: string; sessionGeneration: string; dataGeneration: string }; request: PairingBegin; requestHash: string; transcript: PairingTranscript | null; transcriptDigest: string | null;
  recipientConfirmation: PairingConfirmation | null; approverConfirmation: PairingConfirmation | null; approvalHash: string | null }
interface Ceremony { profile_id: string; device_id: string; kind: string; state: string; public_state: Saved; expires_at: Date }
interface ReceiptRow { request_hash: string; outcome: PairingReceipt }
interface Stored { object_id: string; object_hash: string; object_kind: string; versioned_object: unknown; state: string; staged_operation_id: string }
const publicDevice = (device: Device) => ({ id: device.device_id, keyGeneration: device.key_generation,
  signingPublicKey: base64urlEncode(device.signing_public_key), recipientPublicKey: base64urlEncode(device.recipient_public_key) });

/** Pairing authorizes a new device within existing profile scopes; it cannot grant ownership or expand access. */
export class PairingService {
  readonly #db: Databases; readonly #sessions: SessionService; readonly #origin: string; readonly #now: () => Date;
  constructor(input: { databases: Databases; sessions: SessionService; origin: string; now?: () => Date }) {
    if (new URL(input.origin).origin !== input.origin) throw new Error('Pairing origin must be exact');
    this.#db = input.databases; this.#sessions = input.sessions; this.#origin = input.origin; this.#now = input.now ?? (() => new Date());
  }
  async #transaction<T>(cookie: string, csrf: string | undefined, action: (client: pg.PoolClient, principal: SessionPrincipal) => Promise<T>, approved = false, recent = false): Promise<T> {
    // Authenticate before acquiring a workspace write lock; unauthenticated callers cannot fence another tenant.
    const initial = await this.#sessions.authenticate(cookie, { ...(csrf !== undefined ? { csrfToken: csrf } : {}), approved, recent });
    return transaction(this.#db.control, async (client) => {
      await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [initial.workspaceId]);
      await client.query('SELECT workspace_id FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE', [initial.workspaceId]);
      const principal = await this.#sessions.resolveCurrent(client, cookie, { ...(csrf !== undefined ? { csrfToken: csrf } : {}), approved, recent }, this.#now());
      return action(client, principal);
    });
  }
  async #authority(client: pg.PoolClient, workspaceId: string): Promise<Authority> {
    const state = (await client.query<Authority>('SELECT security_head,security_version,data_generation,ownership_version,custody_epoch,genesis_object_id,licence_state,lifecycle FROM security.workspaces WHERE workspace_id=$1', [workspaceId])).rows[0];
    if (!state || !['active', 'pending_deletion'].includes(state.lifecycle) || !state.genesis_object_id) throw invalid();
    assertEntitlementAllows(state.licence_state, 'replace_device_existing_scopes');
    return state;
  }
  async #profile(client: pg.PoolClient, workspaceId: string, accountId: string): Promise<Profile> {
    const profile = (await client.query<Profile>('SELECT profile_id,state,is_owner,credential_generation,session_generation FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2', [workspaceId, accountId])).rows[0];
    if (!profile || profile.state !== 'active') throw invalid();
    return profile;
  }
  async #ceremony(client: pg.PoolClient, workspaceId: string, operationId: string): Promise<Ceremony> {
    if (!identifier.safeParse(operationId).success) throw invalid();
    const row = (await client.query<Ceremony>('SELECT profile_id,device_id,kind,state,public_state,expires_at FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2 FOR UPDATE', [workspaceId, operationId])).rows[0];
    if (!row || row.kind !== 'device_pair') throw invalid();
    return row;
  }
  async #receipt(client: pg.PoolClient, workspaceId: string, operationId: string): Promise<ReceiptRow | undefined> {
    return (await client.query<ReceiptRow>("SELECT request_hash,outcome FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2 AND operation_kind='device_pair'", [workspaceId, operationId])).rows[0];
  }
  async #viewer(client: pg.PoolClient, principal: SessionPrincipal, ceremony: Ceremony, approver = false): Promise<Profile> {
    const profile = await this.#profile(client, principal.workspaceId, principal.accountId);
    if (approver && (principal.accessLevel !== 'device_approved' || !principal.deviceId)) throw forbidden();
    if (principal.accountId !== ceremony.profile_id && (principal.accessLevel !== 'device_approved' || !profile.is_owner)) throw forbidden();
    return profile;
  }
  #live(ceremony: Ceremony): void {
    if (!['issued', 'waiting_approval'].includes(ceremony.state) || ceremony.expires_at <= this.#now()) throw invalid();
  }
  async #view(client: pg.PoolClient, workspaceId: string, operationId: string, row: Ceremony): Promise<PairingView> {
    const saved = row.public_state, receipt = (await this.#receipt(client, workspaceId, operationId))?.outcome ?? null;
    const state = receipt ? 'completed' : row.state === 'cancelled' || row.state === 'revoked' ? 'cancelled' :
      row.expires_at <= this.#now() || row.state === 'expired' ? 'expired' : !saved.transcript ? 'waiting_approver' :
      saved.recipientConfirmation && saved.approverConfirmation ? 'confirmed' : 'verifying';
    return { operationId, state, request: saved.request, transcript: saved.transcript, transcriptDigest: saved.transcriptDigest,
      recipientConfirmation: saved.recipientConfirmation, approverConfirmation: saved.approverConfirmation,
      approvalStaged: saved.approvalHash !== null, receipt };
  }
  async #save(client: pg.PoolClient, workspaceId: string, operationId: string, saved: Saved): Promise<void> {
    await client.query('UPDATE security.ceremonies SET public_state=$3 WHERE workspace_id=$1 AND ceremony_id=$2', [workspaceId, operationId, saved]);
  }
  async #cancel(client: pg.PoolClient, workspaceId: string, operationId: string): Promise<void> {
    await client.query("UPDATE security.ceremonies SET state=CASE WHEN expires_at<=$3 THEN 'expired' ELSE 'cancelled' END WHERE workspace_id=$1 AND ceremony_id=$2 AND state IN ('issued','waiting_approval')", [workspaceId, operationId, this.#now()]);
  }
  async begin(cookie: string, csrf: string, input: unknown): Promise<PairingView> {
    const parsed = pairingBegin.safeParse(input); if (!parsed.success) throw new AppError('INVALID_REQUEST', 'Invalid pairing request', 400);
    const request = parsed.data, requestHash = await digestObject(request);
    return this.#transaction(cookie, csrf, async (client, principal) => {
      if (principal.accessLevel !== 'restricted') throw forbidden();
      const authority = await this.#authority(client, principal.workspaceId);
      const existing = (await client.query<Ceremony>('SELECT profile_id,device_id,kind,state,public_state,expires_at FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2', [principal.workspaceId, request.operationId])).rows[0];
      if (existing) {
        if (existing.kind !== 'device_pair' || existing.profile_id !== principal.accountId || existing.public_state.requestHash !== requestHash) throw conflict();
        return this.#view(client, principal.workspaceId, request.operationId, existing);
      }
      if ((await client.query('SELECT operation_id FROM security.security_transitions WHERE workspace_id=$1 AND operation_id=$2', [principal.workspaceId, request.operationId])).rowCount) throw conflict();
      const duplicate = (await client.query('SELECT device_id FROM security.devices WHERE workspace_id=$1 AND (device_id=$2 OR signing_public_key=$3 OR recipient_public_key=$4)', [principal.workspaceId, request.device.id, base64urlDecode(request.device.signingPublicKey), base64urlDecode(request.device.recipientPublicKey)])).rowCount;
      if (duplicate) throw conflict();
      // Bound outstanding ceremonies per profile without ever replacing another attempt's keys.
      const count = Number((await client.query<{ count: string }>("SELECT count(*) FROM security.ceremonies WHERE workspace_id=$1 AND profile_id=$2 AND kind='device_pair' AND state IN ('issued','waiting_approval') AND expires_at>$3", [principal.workspaceId, principal.accountId, this.#now()])).rows[0]?.count ?? '0');
      if (count >= 5) throw new AppError('RATE_LIMITED', 'Finish or wait for an existing device pairing', 429);
      await client.query("INSERT INTO security.devices(workspace_id,device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state) VALUES($1,$2,$3,1,$4,$5,'pending')", [principal.workspaceId, request.device.id, principal.accountId, base64urlDecode(request.device.signingPublicKey), base64urlDecode(request.device.recipientPublicKey)]);
      const saved: Saved = { expected: { credentialGeneration: principal.credentialGeneration, sessionGeneration: principal.sessionGeneration, dataGeneration: principal.dataGeneration }, request, requestHash, transcript: null, transcriptDigest: null, recipientConfirmation: null, approverConfirmation: null, approvalHash: null };
      const expiresAt = new Date(this.#now().getTime() + 600_000);
      await client.query(`INSERT INTO security.ceremonies(workspace_id,ceremony_id,profile_id,kind,generation,device_id,expected_credential_generation,
        expected_ownership_version,expected_security_version,expected_custody_epoch,public_state,created_at,expires_at)
        VALUES($1,$2,$3,'device_pair',1,$4,$5,$6,$7,$8,$9,$10,$11)`, [principal.workspaceId, request.operationId, principal.accountId, request.device.id,
        principal.credentialGeneration, authority.ownership_version, authority.security_version, authority.custody_epoch, saved, this.#now(), expiresAt]);
      return this.#view(client, principal.workspaceId, request.operationId, await this.#ceremony(client, principal.workspaceId, request.operationId));
    });
  }
  async inspect(cookie: string, operationId: string): Promise<PairingView> {
    return this.#transaction(cookie, undefined, async (client, principal) => {
      const ceremony = await this.#ceremony(client, principal.workspaceId, operationId); await this.#viewer(client, principal, ceremony);
      return this.#view(client, principal.workspaceId, operationId, ceremony);
    });
  }
  async #scopes(client: pg.PoolClient, workspaceId: string, target: Profile, approver: Profile, deviceId: string): Promise<PairingScope[]> {
    try {
      const scopes = await readPersonalScopes(client, workspaceId, target.profile_id, target.is_owner, this.#now());
      return approver.profile_id === target.profile_id ? await intersectDeviceScopes(client, workspaceId, target.profile_id, deviceId, scopes, this.#now()) : scopes;
    } catch (error) {
      if (error instanceof PersonalScopeError) throw new AppError('PAIRING_KEYS_UNAVAILABLE', 'Current personal key access is not ready for pairing', 409);
      throw error;
    }
  }
  async #snapshot(client: pg.PoolClient, principal: SessionPrincipal, ceremony: Ceremony): Promise<PairingTranscript> {
    const authority = await this.#authority(client, principal.workspaceId), target = await this.#profile(client, principal.workspaceId, ceremony.profile_id);
    const approver = await this.#viewer(client, principal, ceremony, true);
    const device = (await client.query<Device>("SELECT device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state FROM security.devices WHERE workspace_id=$1 AND device_id=$2 AND state='active'", [principal.workspaceId, principal.deviceId])).rows[0];
    const pending = (await client.query<Device>("SELECT device_id,profile_id,key_generation,signing_public_key,recipient_public_key,state FROM security.devices WHERE workspace_id=$1 AND device_id=$2 AND state='pending'", [principal.workspaceId, ceremony.device_id])).rows[0];
    const genesis = (await client.query<{ object_hash: string }>("SELECT object_hash FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND object_kind='genesis' AND state='committed'", [principal.workspaceId, authority.genesis_object_id])).rows[0];
    if (!device || !pending || !genesis || pending.profile_id !== target.profile_id || !equal(publicDevice(pending), ceremony.public_state.request.device)) throw invalid();
    const expected = ceremony.public_state.expected;
    if (expected.credentialGeneration !== target.credential_generation || expected.sessionGeneration !== target.session_generation || expected.dataGeneration !== authority.data_generation) throw invalid();
    const previous = ceremony.public_state.transcript;
    return pairingTranscript.parse({ version: 1, purpose: 'ukda.device-pair-transcript.v1', origin: this.#origin,
      workspaceId: principal.workspaceId, operationId: ceremony.public_state.request.operationId, ceremonyId: ceremony.public_state.request.operationId,
      accountId: target.profile_id, device: publicDevice(pending), localBundleDigest: ceremony.public_state.request.localBundleDigest,
      approverAccountId: approver.profile_id, approverDevice: publicDevice(device), approverIsOwner: approver.is_owner,
      credentialGeneration: target.credential_generation, sessionGeneration: target.session_generation,
      approverCredentialGeneration: approver.credential_generation, approverSessionGeneration: approver.session_generation,
      dataGeneration: authority.data_generation, ownershipVersion: authority.ownership_version, custodyEpoch: authority.custody_epoch,
      genesisFingerprint: genesis.object_hash, securityHead: authority.security_head, securityVersion: authority.security_version,
      scopes: await this.#scopes(client, principal.workspaceId, target, approver, device.device_id),
      issuedAt: previous?.issuedAt ?? this.#now().toISOString(), expiresAt: ceremony.expires_at.toISOString() });
  }
  async claim(cookie: string, csrf: string, operationId: string): Promise<PairingView> {
    return this.#transaction(cookie, csrf, async (client, principal) => {
      const row = await this.#ceremony(client, principal.workspaceId, operationId); this.#live(row);
      const transcript = await this.#snapshot(client, principal, row);
      if (row.public_state.transcript && !equal(row.public_state.transcript, transcript)) throw invalid();
      row.public_state.transcript = transcript; row.public_state.transcriptDigest = await digestObject(transcript);
      await client.query(`UPDATE security.ceremonies SET state='waiting_approval',approving_profile_id=$3,approving_device_id=$4,
        transcript_hash=$5,public_state=$6 WHERE workspace_id=$1 AND ceremony_id=$2`, [principal.workspaceId, operationId, principal.accountId,
        principal.deviceId, row.public_state.transcriptDigest, row.public_state]);
      return this.#view(client, principal.workspaceId, operationId, row);
    }, true, true);
  }
  async confirm(cookie: string, csrf: string, input: unknown): Promise<PairingView> {
    const proof = pairingConfirmation.safeParse(input); if (!proof.success) throw new AppError('INVALID_REQUEST', 'Invalid pairing confirmation', 400);
    const result = await this.#transaction(cookie, csrf, async (client, principal) => {
      const row = await this.#ceremony(client, principal.workspaceId, proof.data.body.operationId); await this.#viewer(client, principal, row);
      const saved = row.public_state, transcript = saved.transcript;
      if (!transcript || !saved.transcriptDigest) throw invalid();
      const approver = proof.data.body.role === 'approver';
      if (approver ? principal.accountId !== transcript.approverAccountId || principal.deviceId !== transcript.approverDevice.id || principal.accessLevel !== 'device_approved' : principal.accountId !== transcript.accountId) throw forbidden();
      if (approver && this.#now().getTime() - principal.authenticatedAt.getTime() >= 300_000) throw new AppError('REAUTH_REQUIRED', 'Confirm your password to continue', 401);
      const authority = await this.#authority(client, principal.workspaceId);
      const target = await this.#profile(client, principal.workspaceId, transcript.accountId);
      const key = base64urlDecode(approver ? transcript.approverDevice.signingPublicKey : transcript.device.signingPublicKey);
      const valid = ['issued', 'waiting_approval'].includes(row.state) && row.expires_at > this.#now() &&
        authority.security_head === transcript.securityHead && authority.data_generation === transcript.dataGeneration &&
        target.credential_generation === transcript.credentialGeneration && target.session_generation === transcript.sessionGeneration &&
        equal(proof.data.body, pairingConfirmationFor(transcript, saved.transcriptDigest, proof.data.body.role)) &&
        await verifyObject(proof.data, key, 'ukda.device-pair-confirmation.v1');
      if (!valid) { await this.#cancel(client, principal.workspaceId, transcript.operationId); return { error: invalid() }; }
      if (approver) saved.approverConfirmation = proof.data; else saved.recipientConfirmation = proof.data;
      await this.#save(client, principal.workspaceId, transcript.operationId, saved);
      return { view: await this.#view(client, principal.workspaceId, transcript.operationId, row) };
    });
    if ('error' in result) throw result.error; return result.view;
  }
  async #materials(client: pg.PoolClient, workspaceId: string, deviceId: string, transcript: PairingTranscript, ownerCustody = false): Promise<PairingMaterial[]> {
    const ids = [...new Set(transcript.scopes.flatMap((scope) => scope.sources.map((source) => source.manifestId)))];
    const custody = ownerCustody || transcript.scopes.some((scope) => scope.mode === 'custody');
    const rows = (await client.query<Stored>(`SELECT object_id,object_hash,object_kind,versioned_object,state,staged_operation_id FROM security.staged_objects
      WHERE workspace_id=$1 AND state='committed' AND (object_id=ANY($2::uuid[]) OR
      (object_kind='key_envelope' AND versioned_object->'header'->>'recipientKind'='device' AND versioned_object->'header'->>'recipientId'=$3) OR
      ($4 AND object_kind='custody_manifest' AND versioned_object->'header'->>'scope'='workspace' AND versioned_object->'header'->>'scopeId'=$1::text AND versioned_object->'header'->>'keyEpoch'=$5))
      ORDER BY object_id`, [workspaceId, ids, deviceId, custody, transcript.custodyEpoch])).rows;
    const result: PairingMaterial[] = [];
    for (const row of rows) {
      if (!ids.includes(row.object_id)) {
        const header = (row.versioned_object as { header?: { scope?: string; scopeId?: string; recipientAccountId?: string } }).header;
        if (!transcript.scopes.some((scope) => header?.scope === scope.scope && header.scopeId === scope.scopeId)) continue;
      }
      if (await digestObject(row.versioned_object) !== row.object_hash) throw invalid();
      result.push({ id: row.object_id, digest: row.object_hash, kind: row.object_kind, value: row.versioned_object });
    }
    if (ids.some((id) => !result.some((row) => row.id === id))) throw invalid();
    return result;
  }
  async materials(cookie: string, operationId: string): Promise<PairingMaterial[]> {
    return this.#transaction(cookie, undefined, async (client, principal) => {
      const row = await this.#ceremony(client, principal.workspaceId, operationId); this.#live(row);
      const transcript = row.public_state.transcript;
      if (!transcript || transcript.approverAccountId !== principal.accountId || transcript.approverDevice.id !== principal.deviceId) throw forbidden();
      if (!equal(transcript, await this.#snapshot(client, principal, row))) throw invalid();
      return this.#materials(client, principal.workspaceId, principal.deviceId!, transcript, (await this.#profile(client, principal.workspaceId, principal.accountId)).is_owner);
    }, true, true);
  }
  async #validateApproval(client: pg.PoolClient, principal: SessionPrincipal, row: Ceremony, approval: PairingApproval): Promise<void> {
    this.#live(row);
    const saved = row.public_state, transcript = saved.transcript;
    if (!transcript || !saved.transcriptDigest || !saved.recipientConfirmation || !saved.approverConfirmation ||
      transcript.approverAccountId !== principal.accountId || transcript.approverDevice.id !== principal.deviceId) throw forbidden();
    if (!equal(await this.#snapshot(client, principal, row), transcript)) throw invalid();
    const body = approval.grant.body, key = base64urlDecode(transcript.approverDevice.signingPublicKey);
    if (body.operationId !== transcript.operationId || body.workspaceId !== transcript.workspaceId || body.grantId !== transcript.operationId ||
      body.previousHead !== transcript.securityHead || BigInt(body.securityVersion) !== BigInt(transcript.securityVersion) + 1n ||
      !equal(body.transcript, transcript) || body.transcriptDigest !== saved.transcriptDigest ||
      !equal(body.recipientConfirmation, saved.recipientConfirmation) || !equal(body.approverConfirmation, saved.approverConfirmation) ||
      !await verifyObject(approval.grant, key, 'ukda.device-pair-grant.v1')) throw invalid();
    if (approval.deliveries.length !== transcript.scopes.length || body.deliveries.length !== transcript.scopes.length ||
      new Set(approval.deliveries.map((delivery) => delivery.id)).size !== approval.deliveries.length ||
      approval.deliveries.some((delivery) => delivery.id === transcript.operationId)) throw invalid();
    for (let index = 0; index < transcript.scopes.length; index++) {
      const scope = transcript.scopes[index]!, delivered = approval.deliveries[index]!, manifest = body.deliveries[index]!;
      if (manifest.id !== delivered.id || manifest.scope !== scope.scope || manifest.scopeId !== scope.scopeId ||
        manifest.digest !== await digestObject(delivered.envelope) ||
        !await verifyRecipientEnvelope(delivered.envelope, key, pairingRecipientHeader(transcript, saved.transcriptDigest, scope))) throw invalid();
    }
    const recipient = base64urlDecode(transcript.device.signingPublicKey);
    if (!await verifyObject(saved.recipientConfirmation, recipient, 'ukda.device-pair-confirmation.v1') ||
      !await verifyObject(saved.approverConfirmation, key, 'ukda.device-pair-confirmation.v1')) throw invalid();
  }
  async stageApproval(cookie: string, csrf: string, input: unknown): Promise<PairingView> {
    const parsed = pairingApproval.safeParse(input); if (!parsed.success) throw new AppError('INVALID_REQUEST', 'Invalid pairing approval', 400);
    const approval = parsed.data, operationId = approval.grant.body.operationId, requestHash = await digestObject(approval);
    return this.#transaction(cookie, csrf, async (client, principal) => {
      const row = await this.#ceremony(client, principal.workspaceId, operationId);
      if (row.public_state.approvalHash && row.public_state.approvalHash !== requestHash) throw conflict();
      const receipt = await this.#receipt(client, principal.workspaceId, operationId);
      if (receipt) { await this.#viewer(client, principal, row, true); if (receipt.request_hash !== requestHash) throw conflict(); return this.#view(client, principal.workspaceId, operationId, row); }
      await this.#validateApproval(client, principal, row, approval);
      const objects = [{ id: operationId, kind: 'signed_grant', value: approval.grant }, ...approval.deliveries.map((delivery) => ({ id: delivery.id, kind: 'key_envelope', value: delivery.envelope }))];
      for (const object of objects) {
        const hash = await digestObject(object.value);
        const exists = (await client.query<Stored>('SELECT object_id,object_hash,object_kind,versioned_object,state,staged_operation_id FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [principal.workspaceId, object.id])).rows[0];
        if (exists && (exists.object_hash !== hash || exists.object_kind !== object.kind || exists.staged_operation_id !== operationId)) throw conflict();
        if (!exists) await client.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,created_at,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [principal.workspaceId, object.id, object.kind, hash, object.value, operationId, this.#now(), row.expires_at]);
        const readback = (await client.query<Stored>('SELECT object_id,object_hash,object_kind,versioned_object,state,staged_operation_id FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [principal.workspaceId, object.id])).rows[0];
        if (!readback || readback.object_hash !== hash || await digestObject(readback.versioned_object) !== hash) throw invalid();
      }
      row.public_state.approvalHash = requestHash; await this.#save(client, principal.workspaceId, operationId, row.public_state);
      return this.#view(client, principal.workspaceId, operationId, row);
    }, true, true);
  }
  async #approval(client: pg.PoolClient, workspaceId: string, operationId: string): Promise<PairingApproval> {
    const grantRow = (await client.query<Stored>("SELECT object_id,object_hash,object_kind,versioned_object,state,staged_operation_id FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2 AND object_kind='signed_grant'", [workspaceId, operationId])).rows[0];
    if (!grantRow) throw invalid();
    const grant = pairingApproval.shape.grant.parse(grantRow.versioned_object);
    const objects = (await client.query<Stored>('SELECT object_id,object_hash,object_kind,versioned_object,state,staged_operation_id FROM security.staged_objects WHERE workspace_id=$1 AND object_id=ANY($2::uuid[])', [workspaceId, grant.body.deliveries.map((item) => item.id)])).rows;
    const deliveries = grant.body.deliveries.map((descriptor) => {
      const stored = objects.find((object) => object.object_id === descriptor.id && object.object_kind === 'key_envelope' && object.object_hash === descriptor.digest);
      if (!stored) throw invalid(); return { id: stored.object_id, envelope: stored.versioned_object };
    });
    return pairingApproval.parse({ grant, deliveries });
  }
  async commit(cookie: string, csrf: string, operationId: string): Promise<{ receipt: PairingReceipt; projection: ProjectionResult }> {
    // Invalid requests are rejected before closing the application fence.
    const initial = await this.#transaction(cookie, csrf, async (client, principal) => {
      const row = await this.#ceremony(client, principal.workspaceId, operationId); await this.#viewer(client, principal, row, true);
      const transcript = row.public_state.transcript;
      if (!transcript || transcript.approverAccountId !== principal.accountId || transcript.approverDevice.id !== principal.deviceId) throw forbidden();
      if (!await this.#receipt(client, principal.workspaceId, operationId)) await this.#validateApproval(client, principal, row, await this.#approval(client, principal.workspaceId, operationId));
      return principal;
    }, true, true);
    return withSecurityFence(this.#db, initial.workspaceId, async (application) => {
      const result = await this.#transaction(cookie, csrf, async (client, principal) => {
        await client.query("SET LOCAL synchronous_commit='on'");
        const row = await this.#ceremony(client, principal.workspaceId, operationId);
        const old = await this.#receipt(client, principal.workspaceId, operationId);
        if (old) return { receipt: pairingReceipt.parse(old.outcome) };
        const approval = await this.#approval(client, principal.workspaceId, operationId);
        try { await this.#validateApproval(client, principal, row, approval); }
        catch (error) { if (!(error instanceof AppError)) throw error; await this.#cancel(client, principal.workspaceId, operationId); return { error }; }
        const body = approval.grant.body, transcript = body.transcript, securityHead = await digestObject(approval.grant), now = this.#now();
        if (await digestObject(approval) !== row.public_state.approvalHash) throw invalid();
        await client.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition)
          VALUES($1,$2,$3,$4,$5,'device.pair','device',$6,$7,$8)`, [principal.workspaceId, body.securityVersion, operationId, body.previousHead, securityHead, principal.accountId, principal.deviceId, approval.grant]);
        await client.query("UPDATE security.staged_objects SET state='committed',committed_security_version=$3 WHERE workspace_id=$1 AND staged_operation_id=$2 AND object_id=ANY($4::uuid[])", [principal.workspaceId, operationId, body.securityVersion, [operationId, ...body.deliveries.map((delivery) => delivery.id)]]);
        await client.query("UPDATE security.devices SET state='active',approval_security_version=$3,approved_at=$4 WHERE workspace_id=$1 AND device_id=$2 AND state='pending'", [principal.workspaceId, transcript.device.id, body.securityVersion, now]);
        for (let index = 0; index < transcript.scopes.length; index++) {
          const scope = transcript.scopes[index]!, delivery = body.deliveries[index]!;
          await client.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,scope_id,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,security_version,activated_at,expires_at,key_epoch)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,$12,$13,$14,$15)`, [principal.workspaceId, scope.scope === 'workspace' ? operationId : delivery.id,
            transcript.accountId, transcript.device.id, scope.scope === 'workspace' ? 'device' : 'project', scope.scope,
            scope.scope === 'workspace' ? null : scope.scopeId, transcript.device.keyGeneration, scope.permissions, operationId, delivery.id, body.securityVersion, now, scope.expiresAt, scope.keyEpoch]);
        }
        await client.query('UPDATE security.workspaces SET security_head=$2,security_version=$3 WHERE workspace_id=$1', [principal.workspaceId, securityHead, body.securityVersion]);
        await client.query("UPDATE security.ceremonies SET state='completed',completed_at=$3 WHERE workspace_id=$1 AND ceremony_id=$2", [principal.workspaceId, operationId, now]);
        const receipt = pairingReceipt.parse({ version: 1, operationId, workspaceId: principal.workspaceId, accountId: transcript.accountId,
          deviceId: transcript.device.id, transcriptDigest: body.transcriptDigest, grantId: operationId, securityHead,
          securityVersion: body.securityVersion, dataGeneration: transcript.dataGeneration, committedAt: now.toISOString(), grant: approval.grant });
        await client.query(`INSERT INTO security.operation_receipts(workspace_id,operation_id,request_hash,operation_kind,security_version,outcome)
          VALUES($1,$2,$3,'device_pair',$4,$5)`, [principal.workspaceId, operationId, row.public_state.approvalHash, body.securityVersion, receipt]);
        return { receipt };
      }, true, true);
      const projection = await projectAuthoritativeWorkspace(this.#db, initial.workspaceId, application);
      // A stale validation is an ordinary rejected operation, so reopen its unchanged projection first.
      if ('error' in result) return { error: result.error, projection };
      return { receipt: result.receipt, projection };
    }, { enqueueActivationProjection: true }).then((result) => { if ('error' in result) throw result.error; return result; });
  }
  async delivery(cookie: string, operationId: string): Promise<PairingDelivery> {
    return this.#transaction(cookie, undefined, async (client, principal) => {
      const receipt = (await this.#receipt(client, principal.workspaceId, operationId))?.outcome;
      if (!receipt || receipt.accountId !== principal.accountId || receipt.deviceId !== principal.deviceId || receipt.dataGeneration !== principal.dataGeneration) throw forbidden();
      const transcript = receipt.grant.body.transcript;
      const profile = await this.#profile(client, principal.workspaceId, principal.accountId);
      if (transcript.scopes.some((scope) => scope.mode === 'custody') && !profile.is_owner) throw forbidden();
      if (!personalScopesCover(await readPersonalScopes(client, principal.workspaceId, principal.accountId, profile.is_owner, this.#now()), transcript.scopes)) throw forbidden();
      if (principal.credentialGeneration !== transcript.credentialGeneration || principal.sessionGeneration !== transcript.sessionGeneration) throw forbidden();
      const rows = (await client.query<{ key_manifest_object_id: string; permissions: string[]; scope_kind: string; scope_id: string | null; key_epoch: string }>(`SELECT g.key_manifest_object_id,g.permissions,g.scope_kind,g.scope_id,g.key_epoch FROM security.grants g
        JOIN security.staged_objects o ON o.workspace_id=g.workspace_id AND o.object_id=g.key_manifest_object_id AND o.state='committed'
        WHERE g.workspace_id=$1 AND g.profile_id=$2 AND g.device_id=$3 AND g.signed_grant_object_id=$4
        AND g.state='active' AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>$5)`, [principal.workspaceId, principal.accountId, principal.deviceId, operationId, this.#now()])).rows;
      if (receipt.grant.body.deliveries.some((item, index) => !rows.some((grant) => grant.key_manifest_object_id === item.id &&
        grant.scope_kind === item.scope && (grant.scope_id ?? principal.workspaceId) === item.scopeId && grant.key_epoch === transcript.scopes[index]!.keyEpoch && equal(grant.permissions, transcript.scopes[index]!.permissions)))) throw forbidden();
      const approval = await this.#approval(client, principal.workspaceId, operationId);
      if (!equal(approval.grant, receipt.grant)) throw invalid();
      // Delivery remains immutable and repeatable. Content-ready is a separate client
      // state reached only after authenticating and decrypting every required keyring.
      return { receipt, deliveries: approval.deliveries, materials: await this.#materials(client, principal.workspaceId, principal.deviceId!, transcript) };
    }, true);
  }
}

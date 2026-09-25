import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import type { DataPrincipal } from '../../persistence.js';
import { authSessionResult, deviceChallenge, deviceProof, type AuthSessionResult, type DeviceChallenge } from '../../shared/auth.js';
import { binary, identifier, positiveCounter } from '../../shared/contracts.js';
import { base64urlEncode, canonicalJson, digestObject, verifyObject } from '../../shared/crypto.js';
import { ServiceSecrets } from './secrets.js';

const IDLE_MS = 30 * 60_000, ABSOLUTE_MS = 12 * 60 * 60_000, RECENT_MS = 5 * 60_000;
export const SESSION_COOKIE_NAME = '__Host-ukda_session';
const rejected = () => new AppError('AUTH_REQUIRED', 'Authentication required', 401);
const proofRejected = () => new AppError('DEVICE_PROOF_INVALID', 'Repeat device verification', 401);
const csrfRejected = () => new AppError('CSRF_INVALID', 'The request could not be verified', 403);
const opaqueToken = binary(32);

function cookieParts(value: string): { workspaceId: string; sessionId: string } | null {
  if (typeof value !== 'string' || value.length > 256) return null;
  const parts = value.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1' || !identifier.safeParse(parts[1]).success ||
    !identifier.safeParse(parts[2]).success || !opaqueToken.safeParse(parts[3]).success) return null;
  return { workspaceId: parts[1]!, sessionId: parts[2]! };
}
export function readSessionCookie(header?: string): string | undefined {
  if (!header) return undefined;
  const matches = header.split(';').map((part) => part.trim()).filter((part) => part.startsWith(`${SESSION_COOKIE_NAME}=`));
  if (matches.length !== 1) return undefined;
  const value = matches[0]!.slice(SESSION_COOKIE_NAME.length + 1);
  return cookieParts(value) ? value : undefined;
}
export function buildSessionCookie(cookieValue: string, absoluteExpiresAt: Date, now = new Date()): string {
  if (!cookieParts(cookieValue) || !Number.isFinite(absoluteExpiresAt.getTime()) || absoluteExpiresAt <= now) throw rejected();
  return `${SESSION_COOKIE_NAME}=${cookieValue}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.floor((absoluteExpiresAt.getTime() - now.getTime()) / 1000)}; Expires=${absoluteExpiresAt.toUTCString()}`;
}
export function clearSessionCookie(): string {
  return `${SESSION_COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

export type IssuedSession = AuthSessionResult & { cookieValue: string };
export interface SessionPrincipal extends DataPrincipal {
  accountId: string; sessionId: string; deviceId: string | null; accessLevel: 'restricted' | 'device_approved';
  credentialGeneration: string; sessionGeneration: string; csrfToken: string;
  authenticatedAt: Date; idleExpiresAt: Date; absoluteExpiresAt: Date;
}
export interface SessionOptions { csrfToken?: string; approved?: boolean; recent?: boolean }
export interface SessionIssue {
  workspaceId: string; profileId: string; credentialGeneration: string; sessionGeneration: string; dataGeneration: string;
  authenticatedAt?: Date; absoluteExpiresAt?: Date; deviceId?: string; accessLevel: 'restricted' | 'device_approved';
}
interface SessionRow {
  workspace_id: string; session_id: string; profile_id: string; device_id: string | null; token_digest: Buffer; token_key_id: string;
  csrf_digest: Buffer; access_level: string; credential_generation: string; session_generation: string; data_generation: string;
  authenticated_at: Date; idle_expires_at: Date; absolute_expires_at: Date; revoked_at: Date | null;
}
interface Authority {
  lifecycle: string; security_head: string; security_version: string; data_generation: string; ownership_version: string; custody_epoch: string;
  profile_state: string; credential_generation: string; session_generation: string;
}
interface DeviceAuthority {
  device_id: string; key_generation: string; signing_public_key: Buffer; recipient_public_key: Buffer;
  grant_id: string; grant_generation: string;
}
interface CeremonyRow {
  profile_id: string; device_id: string; kind: string; state: string; public_state: unknown; transcript_hash: string;
  expires_at: Date; expected_credential_generation: string; expected_ownership_version: string;
  expected_security_version: string; expected_custody_epoch: string;
}

export class SessionService {
  readonly #db: Databases;
  readonly #secrets: ServiceSecrets;
  readonly #origin: string;
  readonly #now: () => Date;
  constructor(input: { databases: Databases; secrets: ServiceSecrets; origin: string; now?: () => Date }) {
    const origin = new URL(input.origin);
    if (origin.origin !== input.origin) throw new Error('Session origin must be an exact origin');
    this.#db = input.databases; this.#secrets = input.secrets; this.#origin = input.origin; this.#now = input.now ?? (() => new Date());
  }
  async #context(client: pg.PoolClient, workspaceId: string): Promise<void> {
    if (!identifier.safeParse(workspaceId).success) throw rejected();
    await client.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
  }
  #csrf(cookieValue: string): string { return this.#secrets.digest('session-csrf-token', cookieValue).toString('base64url'); }
  #csrfMatches(cookieValue: string, token: string, expected: Uint8Array): boolean {
    return opaqueToken.safeParse(token).success && this.#secrets.matches('session-csrf-verifier', `${cookieValue}\0${token}`, expected);
  }
  async #tokenRow(client: pg.PoolClient, cookieValue: string): Promise<SessionRow> {
    const parts = cookieParts(cookieValue);
    if (!parts) throw rejected();
    await this.#context(client, parts.workspaceId);
    const locator = (await client.query<SessionRow>('SELECT * FROM security.sessions WHERE workspace_id=$1 AND session_id=$2', [parts.workspaceId, parts.sessionId])).rows[0];
    if (!locator || locator.token_key_id !== this.#secrets.keyId || !this.#secrets.matches('session-cookie', cookieValue, locator.token_digest)) throw rejected();
    // Security transitions lock workspace before profile/session. Authenticate the
    // locator first, then take that same lock order and recheck the mutable row.
    await this.#identity(client, parts.workspaceId, locator.profile_id);
    const row = (await client.query<SessionRow>('SELECT * FROM security.sessions WHERE workspace_id=$1 AND session_id=$2 FOR UPDATE', [parts.workspaceId, parts.sessionId])).rows[0];
    if (!row || row.token_key_id !== this.#secrets.keyId || !this.#secrets.matches('session-cookie', cookieValue, row.token_digest)) throw rejected();
    if (row.profile_id !== locator.profile_id) throw rejected();
    return row;
  }
  async #identity(client: pg.PoolClient, workspaceId: string, profileId: string): Promise<Authority> {
    const workspace = (await client.query<Omit<Authority, 'profile_state' | 'credential_generation' | 'session_generation'>>(`SELECT lifecycle,security_head,security_version,data_generation,ownership_version,custody_epoch
      FROM security.workspaces WHERE workspace_id=$1 FOR SHARE`, [workspaceId])).rows[0];
    if (!workspace) throw rejected();
    const profile = (await client.query<Pick<Authority, 'profile_state' | 'credential_generation' | 'session_generation'>>(`SELECT state AS profile_state,credential_generation,session_generation
      FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 FOR SHARE`, [workspaceId, profileId])).rows[0];
    if (!profile) throw rejected();
    return { ...workspace, ...profile };
  }
  async #authority(client: pg.PoolClient, workspaceId: string, profileId: string): Promise<Authority> {
    const state = await this.#identity(client, workspaceId, profileId);
    if (!['active', 'pending_deletion'].includes(state.lifecycle) || state.profile_state !== 'active' || state.security_version === '0') throw rejected();
    return state;
  }
  async #device(client: pg.PoolClient, workspaceId: string, profileId: string, deviceId: string, securityVersion: string, now: Date): Promise<DeviceAuthority> {
    const device = (await client.query<DeviceAuthority>(`SELECT d.device_id,d.key_generation,d.signing_public_key,d.recipient_public_key,
      g.grant_id,g.generation AS grant_generation FROM security.devices d
      JOIN security.profiles p ON p.workspace_id=d.workspace_id AND p.profile_id=d.profile_id
      JOIN security.workspaces w ON w.workspace_id=d.workspace_id
      JOIN security.grants g ON g.workspace_id=d.workspace_id AND g.profile_id=d.profile_id AND g.device_id=d.device_id
      JOIN security.staged_objects o ON o.workspace_id=g.workspace_id AND o.object_id=g.signed_grant_object_id
      JOIN security.staged_objects k ON k.workspace_id=g.workspace_id AND k.object_id=g.key_manifest_object_id AND k.state='committed'
      WHERE d.workspace_id=$1 AND d.profile_id=$2 AND d.device_id=$3 AND d.state='active' AND d.revoked_at IS NULL
      AND d.approval_security_version<=$4 AND g.grant_kind='device' AND g.scope_kind='workspace' AND g.scope_id IS NULL
      AND g.state='active' AND g.revoked_at IS NULL AND g.generation=d.key_generation AND g.security_version<=$4
      AND (g.expires_at IS NULL OR g.expires_at>$5) AND o.state='committed'
      AND 'read_project'=ANY(g.permissions) AND EXISTS (
        SELECT 1 FROM security.grants m
        JOIN security.staged_objects s ON s.workspace_id=m.workspace_id AND s.object_id=m.signed_grant_object_id AND s.state='committed'
        JOIN security.staged_objects mk ON mk.workspace_id=m.workspace_id AND mk.object_id=m.key_manifest_object_id AND mk.state='committed'
        LEFT JOIN security.scope_heads h ON h.workspace_id=m.workspace_id AND h.scope_kind='workspace' AND h.scope_id=m.workspace_id
        WHERE m.workspace_id=d.workspace_id AND m.profile_id=d.profile_id AND m.device_id IS NULL
          AND m.scope_kind='workspace' AND m.scope_id IS NULL AND m.grant_kind=CASE WHEN p.is_owner THEN 'owner' ELSE 'membership' END
          AND m.state='active' AND m.revoked_at IS NULL AND m.security_version<=$4 AND (m.expires_at IS NULL OR m.expires_at>$5)
          AND 'read_project'=ANY(m.permissions) AND m.key_epoch=g.key_epoch
          AND m.key_epoch=CASE WHEN p.is_owner THEN w.custody_epoch ELSE h.key_epoch END)
      ORDER BY g.grant_id LIMIT 1`, [workspaceId, profileId, deviceId, securityVersion, now])).rows[0];
    if (!device) throw new AppError('DEVICE_APPROVAL_REQUIRED', 'Approve this device before accessing workspace data', 403);
    return device;
  }
  async #current(client: pg.PoolClient, row: SessionRow, cookieValue: string, options: SessionOptions, now: Date): Promise<{ principal: SessionPrincipal; authority: Authority }> {
    if (row.revoked_at || now >= row.idle_expires_at || now >= row.absolute_expires_at || now < row.authenticated_at ||
      !['restricted', 'device_approved'].includes(row.access_level)) throw rejected();
    if (options.csrfToken !== undefined && !this.#csrfMatches(cookieValue, options.csrfToken, row.csrf_digest)) throw csrfRejected();
    const authority = await this.#authority(client, row.workspace_id, row.profile_id);
    if (row.credential_generation !== authority.credential_generation || row.session_generation !== authority.session_generation ||
      row.data_generation !== authority.data_generation) throw rejected();
    if (row.access_level === 'device_approved') {
      if (!row.device_id) throw rejected();
      await this.#device(client, row.workspace_id, row.profile_id, row.device_id, authority.security_version, now);
    }
    if (options.approved && row.access_level !== 'device_approved') throw new AppError('DEVICE_APPROVAL_REQUIRED', 'Approve this device before accessing workspace data', 403);
    if (options.recent && now.getTime() - row.authenticated_at.getTime() >= RECENT_MS) throw new AppError('REAUTH_REQUIRED', 'Confirm your password to continue', 401);
    return { authority, principal: { workspaceId: row.workspace_id, profileId: row.profile_id, accountId: row.profile_id,
      sessionId: row.session_id, deviceId: row.device_id, accessLevel: row.access_level as SessionPrincipal['accessLevel'],
      credentialGeneration: row.credential_generation, sessionGeneration: row.session_generation, dataGeneration: row.data_generation,
      securityHead: authority.security_head, securityVersion: authority.security_version, csrfToken: this.#csrf(cookieValue),
      authenticatedAt: row.authenticated_at, idleExpiresAt: row.idle_expires_at, absoluteExpiresAt: row.absolute_expires_at } };
  }

  /** Trusted authentication transaction only. Every method sets its own transaction-local workspace. */
  async issue(client: pg.PoolClient, input: SessionIssue, now = this.#now()): Promise<IssuedSession> {
    if (![input.profileId, input.workspaceId].every((id) => identifier.safeParse(id).success) ||
      ![input.credentialGeneration, input.sessionGeneration, input.dataGeneration].every((generation) => positiveCounter.safeParse(generation).success) ||
      !['restricted', 'device_approved'].includes(input.accessLevel) || (input.deviceId !== undefined && !identifier.safeParse(input.deviceId).success)) throw rejected();
    await this.#context(client, input.workspaceId);
    const authority = await this.#authority(client, input.workspaceId, input.profileId);
    if (authority.credential_generation !== input.credentialGeneration || authority.session_generation !== input.sessionGeneration ||
      authority.data_generation !== input.dataGeneration) throw rejected();
    if (input.accessLevel === 'device_approved') {
      if (!input.deviceId) throw rejected();
      await this.#device(client, input.workspaceId, input.profileId, input.deviceId, authority.security_version, now);
    }
    const authenticatedAt = input.authenticatedAt ?? now;
    const absoluteExpiresAt = input.absoluteExpiresAt ?? new Date(authenticatedAt.getTime() + ABSOLUTE_MS);
    if (!Number.isFinite(authenticatedAt.getTime()) || !Number.isFinite(absoluteExpiresAt.getTime()) || authenticatedAt > now || absoluteExpiresAt <= now ||
      absoluteExpiresAt.getTime() > authenticatedAt.getTime() + ABSOLUTE_MS) throw rejected();
    const idleExpiresAt = new Date(Math.min(now.getTime() + IDLE_MS, absoluteExpiresAt.getTime()));
    const sessionId = randomUUID(), cookieValue = `v1.${input.workspaceId}.${sessionId}.${this.#secrets.token()}`, csrfToken = this.#csrf(cookieValue);
    await client.query(`INSERT INTO security.sessions(workspace_id,session_id,profile_id,device_id,token_digest,token_key_id,csrf_digest,
      access_level,credential_generation,session_generation,data_generation,authenticated_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15)`, [input.workspaceId, sessionId, input.profileId,
      input.deviceId ?? null, this.#secrets.digest('session-cookie', cookieValue), this.#secrets.keyId,
      this.#secrets.digest('session-csrf-verifier', `${cookieValue}\0${csrfToken}`), input.accessLevel,
      input.credentialGeneration, input.sessionGeneration, input.dataGeneration, authenticatedAt, now, idleExpiresAt, absoluteExpiresAt]);
    return { ...authSessionResult.parse({ sessionId, workspaceId: input.workspaceId, accountId: input.profileId, deviceId: input.deviceId ?? null,
      accessLevel: input.accessLevel, credentialGeneration: input.credentialGeneration, sessionGeneration: input.sessionGeneration, dataGeneration: input.dataGeneration,
      csrfToken, authenticatedAt: authenticatedAt.toISOString(), idleExpiresAt: idleExpiresAt.toISOString(), absoluteExpiresAt: absoluteExpiresAt.toISOString() }), cookieValue };
  }

  async resolveCurrent(client: pg.PoolClient, cookieValue: string, options: SessionOptions = {}, now = this.#now()): Promise<SessionPrincipal> {
    const row = await this.#tokenRow(client, cookieValue);
    const { principal } = await this.#current(client, row, cookieValue, options, now);
    const idle = new Date(Math.min(now.getTime() + IDLE_MS, row.absolute_expires_at.getTime()));
    await client.query('UPDATE security.sessions SET last_seen_at=$3,idle_expires_at=$4 WHERE workspace_id=$1 AND session_id=$2', [row.workspace_id, row.session_id, now, idle]);
    return { ...principal, idleExpiresAt: idle };
  }
  async authenticate(cookieValue: string, options: SessionOptions = {}): Promise<SessionPrincipal> {
    return transaction(this.#db.control, (client) => this.resolveCurrent(client, cookieValue, options));
  }
  async revoke(client: pg.PoolClient, workspaceId: string, sessionId: string, now = this.#now()): Promise<void> {
    if (!identifier.safeParse(sessionId).success) throw rejected();
    await this.#context(client, workspaceId);
    await client.query('UPDATE security.sessions SET revoked_at=coalesce(revoked_at,$3) WHERE workspace_id=$1 AND session_id=$2', [workspaceId, sessionId, now]);
    await client.query(`UPDATE security.ceremonies SET state='cancelled' WHERE workspace_id=$1 AND kind='device_challenge'
      AND state='issued' AND public_state->>'sessionId'=$2`, [workspaceId, sessionId]);
  }
  async revokeCookie(client: pg.PoolClient, cookieValue: string, now = this.#now()): Promise<boolean> {
    if (!cookieParts(cookieValue)) return false;
    let row: SessionRow;
    try { row = await this.#tokenRow(client, cookieValue); }
    catch (error) { if (error instanceof AppError && error.code === 'AUTH_REQUIRED') return false; throw error; }
    await this.revoke(client, row.workspace_id, row.session_id, now);
    return true;
  }
  async logout(cookieValue: string, csrfToken: string): Promise<void> {
    await transaction(this.#db.control, async (client) => {
      const row = await this.#tokenRow(client, cookieValue);
      if (!this.#csrfMatches(cookieValue, csrfToken, row.csrf_digest)) throw csrfRejected();
      await this.revoke(client, row.workspace_id, row.session_id);
    });
  }

  async beginDeviceChallenge(cookieValue: string, csrfToken: string, deviceId: string): Promise<DeviceChallenge> {
    if (!identifier.safeParse(deviceId).success) throw proofRejected();
    return transaction(this.#db.control, async (client) => {
      const now = this.#now(), row = await this.#tokenRow(client, cookieValue);
      if (!this.#csrfMatches(cookieValue, csrfToken, row.csrf_digest)) throw csrfRejected();
      const { authority } = await this.#current(client, row, cookieValue, {}, now);
      const device = await this.#device(client, row.workspace_id, row.profile_id, deviceId, authority.security_version, now);
      const challenge = deviceChallenge.parse({ version: 1, purpose: 'ukda.device-challenge.v1', origin: this.#origin,
        workspaceId: row.workspace_id, accountId: row.profile_id, sessionId: row.session_id, deviceId, keyGeneration: device.key_generation,
        credentialGeneration: row.credential_generation, sessionGeneration: row.session_generation, dataGeneration: row.data_generation,
        securityVersion: authority.security_version, securityHead: authority.security_head, ownershipVersion: authority.ownership_version,
        custodyEpoch: authority.custody_epoch, grantId: device.grant_id, grantGeneration: device.grant_generation,
        signingPublicKey: base64urlEncode(device.signing_public_key), recipientPublicKey: base64urlEncode(device.recipient_public_key),
        ceremonyId: randomUUID(), nonce: this.#secrets.token(), issuedAt: now.toISOString(),
        expiresAt: new Date(Math.min(now.getTime() + 120_000, row.absolute_expires_at.getTime())).toISOString() });
      await client.query(`UPDATE security.ceremonies SET state='cancelled' WHERE workspace_id=$1 AND kind='device_challenge'
        AND state='issued' AND public_state->>'sessionId'=$2`, [row.workspace_id, row.session_id]);
      await client.query(`INSERT INTO security.ceremonies(workspace_id,ceremony_id,profile_id,device_id,kind,generation,
        expected_credential_generation,expected_ownership_version,expected_security_version,expected_custody_epoch,transcript_hash,public_state,created_at,expires_at)
        VALUES($1,$2,$3,$4,'device_challenge',$5,$6,$7,$8,$9,$10,$11,$12,$13)`, [row.workspace_id, challenge.ceremonyId,
        row.profile_id, deviceId, device.key_generation, row.credential_generation, authority.ownership_version, authority.security_version,
        authority.custody_epoch, await digestObject(challenge), challenge, now, new Date(challenge.expiresAt)]);
      await client.query('UPDATE security.sessions SET last_seen_at=$3,idle_expires_at=$4 WHERE workspace_id=$1 AND session_id=$2',
        [row.workspace_id, row.session_id, now, new Date(Math.min(now.getTime() + IDLE_MS, row.absolute_expires_at.getTime()))]);
      return challenge;
    });
  }

  async completeDeviceChallenge(cookieValue: string, csrfToken: string, proof: unknown): Promise<IssuedSession> {
    // A malformed signature still burns an identifiable proof owned by this authenticated session.
    const reference = z.object({ body: z.object({ ceremonyId: identifier }) }).safeParse(proof);
    if (!reference.success) throw proofRejected();
    const parsed = deviceProof.safeParse(proof);
    const result = await transaction(this.#db.control, async (client) => {
      const now = this.#now(), row = await this.#tokenRow(client, cookieValue);
      if (!this.#csrfMatches(cookieValue, csrfToken, row.csrf_digest)) throw csrfRejected();
      const ceremony = (await client.query<CeremonyRow>('SELECT * FROM security.ceremonies WHERE workspace_id=$1 AND ceremony_id=$2 FOR UPDATE', [row.workspace_id, reference.data.body.ceremonyId])).rows[0];
      const stored = deviceChallenge.safeParse(ceremony?.public_state);
      if (!ceremony || ceremony.kind !== 'device_challenge' || ceremony.profile_id !== row.profile_id ||
        !stored.success || stored.data.sessionId !== row.session_id || ceremony.state !== 'issued') return undefined;
      await client.query(`UPDATE security.ceremonies SET state=$3 WHERE workspace_id=$1 AND ceremony_id=$2`,
        [row.workspace_id, stored.data.ceremonyId, now >= ceremony.expires_at ? 'expired' : 'cancelled']);
      if (!parsed.success || now >= ceremony.expires_at) return undefined;
      try {
        const { authority } = await this.#current(client, row, cookieValue, {}, now);
        const current = await this.#device(client, row.workspace_id, row.profile_id, ceremony.device_id, authority.security_version, now);
        const body = parsed.data.body;
        if (canonicalJson(body) !== canonicalJson(stored.data) || ceremony.transcript_hash !== await digestObject(body) || body.origin !== this.#origin ||
          body.workspaceId !== row.workspace_id || body.accountId !== row.profile_id || body.deviceId !== current.device_id ||
          body.keyGeneration !== current.key_generation || body.grantId !== current.grant_id || body.grantGeneration !== current.grant_generation ||
          body.signingPublicKey !== base64urlEncode(current.signing_public_key) || body.recipientPublicKey !== base64urlEncode(current.recipient_public_key) ||
          body.credentialGeneration !== row.credential_generation || body.sessionGeneration !== row.session_generation || body.dataGeneration !== row.data_generation ||
          body.securityHead !== authority.security_head || body.securityVersion !== authority.security_version ||
          body.ownershipVersion !== authority.ownership_version || body.custodyEpoch !== authority.custody_epoch ||
          ceremony.expected_credential_generation !== body.credentialGeneration || ceremony.expected_security_version !== body.securityVersion ||
          ceremony.expected_ownership_version !== body.ownershipVersion || ceremony.expected_custody_epoch !== body.custodyEpoch ||
          !await verifyObject(parsed.data, current.signing_public_key, 'ukda.device-challenge.v1')) return undefined;
        const issued = await this.issue(client, { workspaceId: row.workspace_id, profileId: row.profile_id,
          deviceId: current.device_id, accessLevel: 'device_approved', credentialGeneration: row.credential_generation,
          sessionGeneration: row.session_generation, dataGeneration: row.data_generation,
          authenticatedAt: row.authenticated_at, absoluteExpiresAt: row.absolute_expires_at }, now);
        await this.revoke(client, row.workspace_id, row.session_id, now);
        await client.query(`UPDATE security.ceremonies SET state='completed',completed_at=$3 WHERE workspace_id=$1 AND ceremony_id=$2`, [row.workspace_id, body.ceremonyId, now]);
        return issued;
      } catch (error) {
        // Authorization failures are committed along with consumption. Database outages
        // must abort the entire transaction so they cannot create partial elevation.
        if (error instanceof AppError) return undefined;
        throw error;
      }
    });
    if (!result) throw proofRejected();
    return result;
  }
}

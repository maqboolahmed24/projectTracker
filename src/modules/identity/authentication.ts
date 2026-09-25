import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { identifier } from '../../shared/contracts.js';
import type { OpaquePublicConfiguration } from '../../client/opaque.js';
import type { OpaqueService } from './opaque.js';
import type { ServiceSecrets } from './secrets.js';
import type { IssuedSession, SessionPrincipal, SessionService } from './sessions.js';

const LIFETIME_MS = 2 * 60 * 1000;
const failure = () => new AppError('AUTHENTICATION_FAILED', 'Authentication failed', 401);

export interface AuthenticationStart {
  loginId: string;
  loginResponse: string;
  configuration: OpaquePublicConfiguration;
  expiresAt: string;
}
export interface LoginStartInput { workspaceId: string; accountId: string; startLoginRequest: string }
export interface LoginFinishInput { loginId: string; finishLoginRequest: string }
export interface ReauthenticationContext { cookieValue: string; csrfToken: string }

interface AccountRow {
  credential_generation: string;
  session_generation: string;
  data_generation: string;
  opaque_registration_record: string;
  opaque_setup_id: string;
  opaque_config_id: string;
  opaque_identifiers: { client?: string; server?: string };
}
interface AttemptRow {
  login_id: string;
  purpose: 'login' | 'reauthentication';
  workspace_id: string;
  profile_id: string;
  eligible: boolean;
  expected_credential_generation: string;
  expected_session_generation: string;
  expected_data_generation: string;
  source_session_id: string | null;
  source_device_id: string | null;
  state: 'issued' | 'consumed';
  server_state_ciphertext: string | null;
  server_state_key_id: string | null;
  expires_at: Date;
}

export interface AuthenticationOptions {
  databases: Databases;
  secrets: ServiceSecrets;
  opaque: OpaqueService;
  sessions: SessionService;
  origin: string;
  now?: () => Date;
}

/** Password proof grants restricted access. Device possession is a separate ceremony. */
export class AuthenticationService {
  readonly #options: AuthenticationOptions;
  readonly #now: () => Date;
  constructor(options: AuthenticationOptions) {
    if (new URL(options.origin).origin !== options.origin) throw new Error('Invalid authentication origin');
    this.#options = options;
    this.#now = options.now ?? (() => new Date());
  }

  async #account(client: pg.PoolClient, workspaceId: string, accountId: string,
    configuration: OpaquePublicConfiguration): Promise<AccountRow | undefined> {
    await client.query("SELECT set_config('ukda.workspace_id', $1, true)", [workspaceId]);
    // Lock authority before the profile, consistent with security transitions.
    const workspace = (await client.query<{ data_generation: string; lifecycle: string; security_version: string }>(
      `SELECT data_generation, lifecycle, security_version FROM security.workspaces
       WHERE workspace_id = $1 FOR SHARE`, [workspaceId])).rows[0];
    const profile = (await client.query<Omit<AccountRow, 'data_generation'> & { state: string }>(
      `SELECT state, credential_generation, session_generation, opaque_registration_record,
              opaque_setup_id, opaque_config_id, opaque_identifiers
       FROM security.profiles WHERE workspace_id = $1 AND profile_id = $2 FOR SHARE`,
      [workspaceId, accountId])).rows[0];
    // Entitlement restrictions preserve authentication, password changes and recovery.
    // Quarantine blocks content through dataTransaction; it must still permit
    // current credentials to reach the separate restricted restore ceremony.
    if (!workspace || !['active', 'pending_deletion'].includes(workspace.lifecycle) || workspace.security_version === '0' ||
      !profile || profile.state !== 'active' || !profile.opaque_registration_record ||
      profile.opaque_setup_id !== configuration.setupId || profile.opaque_config_id !== configuration.configId ||
      profile.opaque_identifiers?.client !== configuration.identifiers.client ||
      profile.opaque_identifiers?.server !== configuration.identifiers.server) return undefined;
    return { ...profile, data_generation: workspace.data_generation };
  }

  #context(attempt: Pick<AttemptRow, 'login_id' | 'purpose' | 'workspace_id' | 'profile_id' |
    'expected_credential_generation' | 'expected_session_generation' | 'expected_data_generation' |
    'source_session_id' | 'source_device_id'>): string {
    return JSON.stringify(['ukda.authentication.v1', this.#options.origin, attempt.login_id, attempt.purpose,
      attempt.workspace_id, attempt.profile_id, attempt.expected_credential_generation,
      attempt.expected_session_generation, attempt.expected_data_generation,
      attempt.source_session_id, attempt.source_device_id]);
  }

  async #start(client: pg.PoolClient, input: LoginStartInput, now: Date,
    source?: SessionPrincipal): Promise<AuthenticationStart> {
    const { opaque, secrets } = this.#options;
    const configuration = await opaque.publicConfiguration(input.workspaceId, input.accountId);
    const account = await this.#account(client, input.workspaceId, input.accountId, configuration);
    if (source && (!account || account.credential_generation !== source.credentialGeneration ||
      account.session_generation !== source.sessionGeneration || account.data_generation !== source.dataGeneration ||
      source.deviceId === null)) throw failure();
    const attempt = {
      login_id: randomUUID(), purpose: source ? 'reauthentication' as const : 'login' as const,
      workspace_id: input.workspaceId, profile_id: input.accountId,
      expected_credential_generation: account?.credential_generation ?? '0',
      expected_session_generation: account?.session_generation ?? '0',
      expected_data_generation: account?.data_generation ?? '0',
      source_session_id: source?.sessionId ?? null, source_device_id: source?.deviceId ?? null,
    };
    const { serverLoginState, loginResponse } = await opaque.startLogin(input.workspaceId, input.accountId,
      account?.opaque_registration_record ?? null, input.startLoginRequest);
    const protectedState = await secrets.protectState(this.#context(attempt), serverLoginState);
    const expiresAt = new Date(now.getTime() + LIFETIME_MS);
    await client.query(`INSERT INTO security.auth_attempts
      (login_id, purpose, workspace_id, profile_id, eligible, expected_credential_generation,
       expected_session_generation, expected_data_generation, source_session_id, source_device_id,
       server_state_ciphertext, server_state_key_id, created_at, expires_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [attempt.login_id, attempt.purpose, input.workspaceId, input.accountId, Boolean(account),
      attempt.expected_credential_generation, attempt.expected_session_generation, attempt.expected_data_generation,
      attempt.source_session_id, attempt.source_device_id, protectedState, secrets.keyId, now, expiresAt]);
    return { loginId: attempt.login_id, loginResponse, configuration, expiresAt: expiresAt.toISOString() };
  }

  async startLogin(input: LoginStartInput): Promise<AuthenticationStart> {
    if (!identifier.safeParse(input.workspaceId).success || !identifier.safeParse(input.accountId).success) throw failure();
    return this.#transaction((client, now) => this.#start(client, input, now));
  }

  async startReauthentication(input: Pick<LoginStartInput, 'startLoginRequest'>,
    context: ReauthenticationContext): Promise<AuthenticationStart> {
    return this.#transaction(async (client, now) => {
      const source = await this.#options.sessions.resolveCurrent(client, context.cookieValue,
        { csrfToken: context.csrfToken, approved: true }, now);
      return this.#start(client, { ...input, workspaceId: source.workspaceId, accountId: source.accountId }, now, source);
    });
  }

  async finishLogin(input: LoginFinishInput, context: { previousCookie?: string } = {}): Promise<IssuedSession> {
    return this.#finish(input, 'login', context);
  }

  async finishReauthentication(input: LoginFinishInput, context: ReauthenticationContext): Promise<IssuedSession> {
    return this.#finish(input, 'reauthentication', context);
  }

  async #finish(input: LoginFinishInput, purpose: AttemptRow['purpose'],
    context: { previousCookie?: string; cookieValue?: string; csrfToken?: string }): Promise<IssuedSession> {
    if (!identifier.safeParse(input.loginId).success) throw failure();
    const result = await this.#transaction(async (client, now): Promise<IssuedSession | undefined> => {
      // Read only the immutable locator before locks. Security mutations take
      // the workspace first and may then invalidate every pending proof.
      const locator = (await client.query<AttemptRow>(
        'SELECT * FROM security.auth_attempts WHERE login_id = $1', [input.loginId])).rows[0];
      if (!locator) return undefined;
      const configuration = await this.#options.opaque.publicConfiguration(locator.workspace_id, locator.profile_id);
      const account = await this.#account(client, locator.workspace_id, locator.profile_id, configuration);
      const attempt = (await client.query<AttemptRow>(
        'SELECT * FROM security.auth_attempts WHERE login_id = $1 FOR UPDATE', [input.loginId])).rows[0];
      if (!attempt || attempt.state !== 'issued') return undefined;
      const consume = async (outcome: 'verified' | 'failed') => {
        await client.query(`UPDATE security.auth_attempts SET state = 'consumed', outcome = $2, consumed_at = $3,
          server_state_ciphertext = NULL, server_state_key_id = NULL WHERE login_id = $1`, [attempt.login_id, outcome, now]);
      };
      if (attempt.purpose !== purpose || attempt.expires_at.getTime() <= now.getTime() ||
        !attempt.server_state_ciphertext || attempt.server_state_key_id !== this.#options.secrets.keyId) {
        await consume('failed'); return undefined;
      }
      try {
        const state = await this.#options.secrets.revealState(this.#context(attempt), attempt.server_state_ciphertext);
        // Even fake records perform the protocol finish. Never return or store its session key.
        await this.#options.opaque.finishLogin(attempt.workspace_id, attempt.profile_id, state, input.finishLoginRequest);
      } catch (error) {
        if (!(error instanceof AppError)) throw error;
        await consume('failed'); return undefined;
      }
      if (!attempt.eligible || !account || account.credential_generation !== attempt.expected_credential_generation ||
        account.session_generation !== attempt.expected_session_generation || account.data_generation !== attempt.expected_data_generation) {
        await consume('failed'); return undefined;
      }
      let source: SessionPrincipal | undefined;
      if (purpose === 'reauthentication') {
        try {
          if (!context.cookieValue || !context.csrfToken) throw failure();
          source = await this.#options.sessions.resolveCurrent(client, context.cookieValue,
            { csrfToken: context.csrfToken, approved: true }, now);
          if (source.workspaceId !== attempt.workspace_id || source.accountId !== attempt.profile_id ||
            source.sessionId !== attempt.source_session_id || source.deviceId !== attempt.source_device_id ||
            source.credentialGeneration !== attempt.expected_credential_generation ||
            source.sessionGeneration !== attempt.expected_session_generation || source.dataGeneration !== attempt.expected_data_generation) throw failure();
        } catch (error) {
          if (!(error instanceof AppError) || error.statusCode >= 500) throw error;
          await consume('failed'); return undefined;
        }
      }
      // Helpers switch tenant context themselves, including cross-workspace account switching.
      if (source) await this.#options.sessions.revoke(client, source.workspaceId, source.sessionId, now);
      else if (context.previousCookie) await this.#options.sessions.revokeCookie(client, context.previousCookie, now);
      const issued = await this.#options.sessions.issue(client, {
        workspaceId: attempt.workspace_id, profileId: attempt.profile_id,
        credentialGeneration: account.credential_generation, sessionGeneration: account.session_generation,
        dataGeneration: account.data_generation, authenticatedAt: now,
        accessLevel: source ? 'device_approved' : 'restricted',
        ...(source ? { deviceId: source.deviceId!, absoluteExpiresAt: source.absoluteExpiresAt } : {}),
      }, now);
      await consume('verified');
      return issued;
    });
    // Failure is thrown only after COMMIT, so failed proofs are durably consumed.
    if (!result) throw failure();
    return result;
  }

  async #transaction<T>(action: (client: pg.PoolClient, now: Date) => Promise<T>): Promise<T> {
    try {
      return await transaction(this.#options.databases.control, async (client) => {
        await client.query("SET LOCAL synchronous_commit = 'on'");
        return action(client, this.#now());
      });
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('AUTHENTICATION_UNAVAILABLE', 'Authentication is temporarily unavailable', 503);
    }
  }
}

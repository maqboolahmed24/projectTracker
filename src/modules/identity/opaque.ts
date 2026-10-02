import * as opaque from '@serenity-kit/opaque';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../../client/opaque.js';
import { AppError } from '../../errors.js';
import { binary, identifier } from '../../shared/contracts.js';

const protocolPacket = binary(1, 4096);

export interface OpaqueServiceOptions {
  serverSetup: string;
  setupId: string;
  serverIdentity: string;
}

/** The deployment persists serverSetup separately; restarting never generates a new one. */
export class OpaqueService {
  readonly #serverSetup: string;
  readonly #setupId: string;
  readonly #serverIdentity: string;
  #publicKey: Promise<string> | undefined;

  constructor(options: OpaqueServiceOptions) {
    if (!protocolPacket.safeParse(options.serverSetup).success ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(options.setupId) ||
      !/^[\x21-\x7e]{1,256}$/.test(options.serverIdentity)) {
      throw new Error('Invalid OPAQUE server configuration');
    }
    this.#serverSetup = options.serverSetup;
    this.#setupId = options.setupId;
    this.#serverIdentity = options.serverIdentity;
  }

  #identifiers(workspaceId: string, accountId: string) {
    if (!identifier.safeParse(workspaceId).success || !identifier.safeParse(accountId).success) {
      throw new AppError('INVALID_OPAQUE_REQUEST', 'Invalid password operation', 400);
    }
    return { client: `ukda:${workspaceId}:${accountId}`, server: this.#serverIdentity };
  }

  async publicConfiguration(workspaceId: string, accountId: string): Promise<OpaquePublicConfiguration> {
    const identifiers = this.#identifiers(workspaceId, accountId);
    this.#publicKey ??= opaque.ready.then(() => {
      try { return opaque.server.getPublicKey(this.#serverSetup); }
      catch { throw new Error('Invalid OPAQUE server configuration'); }
    });
    return { configId: OPAQUE_CONFIG_ID, setupId: this.#setupId, identifiers,
      keyStretching: OPAQUE_KEY_STRETCHING, serverStaticPublicKey: await this.#publicKey };
  }

  async response(workspaceId: string, accountId: string, registrationRequest: string) {
    const configuration = await this.publicConfiguration(workspaceId, accountId);
    if (!protocolPacket.safeParse(registrationRequest).success) throw new AppError('INVALID_OPAQUE_REQUEST', 'Invalid password operation', 400);
    try {
      const result = opaque.server.createRegistrationResponse({ serverSetup: this.#serverSetup,
        userIdentifier: configuration.identifiers.client, registrationRequest });
      return { ...result, configuration };
    } catch {
      throw new AppError('INVALID_OPAQUE_REQUEST', 'Invalid password operation', 400);
    }
  }

  /**
   * Structural validation only: use a completed, context-bound login ceremony
   * before activation to prove the client can use this registration. This probe
   * has no user's password, and its private state and response are discarded.
   */
  async validateRegistrationRecord(workspaceId: string, accountId: string, registrationRecord: string): Promise<void> {
    const configuration = await this.publicConfiguration(workspaceId, accountId);
    if (!protocolPacket.safeParse(registrationRecord).success) throw new AppError('INVALID_OPAQUE_RECORD', 'Invalid password registration', 400);
    try {
      const { startLoginRequest } = opaque.client.startLogin({ password: 'ukda:registration-format-probe:v1' });
      opaque.server.startLogin({ serverSetup: this.#serverSetup, userIdentifier: configuration.identifiers.client,
        registrationRecord, startLoginRequest, identifiers: configuration.identifiers });
    } catch {
      throw new AppError('INVALID_OPAQUE_RECORD', 'Invalid password registration', 400);
    }
  }

  /** Load the record from trusted stored/staged state, never an unauthorised login body. */
  async startLogin(workspaceId: string, accountId: string, registrationRecord: string | null, startLoginRequest: string): Promise<opaque.server.LoginStartResult> {
    const configuration = await this.publicConfiguration(workspaceId, accountId);
    if (!protocolPacket.safeParse(startLoginRequest).success ||
      (registrationRecord !== null && !protocolPacket.safeParse(registrationRecord).success)) {
      throw new AppError('AUTHENTICATION_FAILED', 'Authentication failed', 401);
    }
    try {
      return opaque.server.startLogin({ serverSetup: this.#serverSetup, userIdentifier: configuration.identifiers.client,
        registrationRecord, startLoginRequest, identifiers: configuration.identifiers });
    } catch {
      throw new AppError('AUTHENTICATION_FAILED', 'Authentication failed', 401);
    }
  }

  /** Server state is private, short-lived, single-use, and account/generation-bound by the caller. */
  async finishLogin(workspaceId: string, accountId: string, serverLoginState: string, finishLoginRequest: string): Promise<opaque.server.LoginFinishResult> {
    const configuration = await this.publicConfiguration(workspaceId, accountId);
    if (!protocolPacket.safeParse(serverLoginState).success || !protocolPacket.safeParse(finishLoginRequest).success) {
      throw new AppError('AUTHENTICATION_FAILED', 'Authentication failed', 401);
    }
    try {
      return opaque.server.finishLogin({ serverLoginState, finishLoginRequest, identifiers: configuration.identifiers });
    } catch {
      throw new AppError('AUTHENTICATION_FAILED', 'Authentication failed', 401);
    }
  }
}

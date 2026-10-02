import * as opaque from '@serenity-kit/opaque';
import { binary } from '../shared/contracts.js';

/** Version the entire identifier/stretching policy with each stored credential. */
export const OPAQUE_CONFIG_ID = 'ukda.opaque.ristretto255.argon2id-m64-t3-p4.v1';
export const OPAQUE_KEY_STRETCHING = 'memory-constrained' as const;

export interface OpaquePublicConfiguration {
  configId: typeof OPAQUE_CONFIG_ID;
  setupId: string;
  serverStaticPublicKey: string;
  identifiers: { client: string; server: string };
  keyStretching: typeof OPAQUE_KEY_STRETCHING;
}

export class ClientOpaqueError extends Error {
  constructor(readonly code: 'PASSWORD_POLICY' | 'CONFIGURATION' | 'AUTHENTICATION' | 'SERVER_KEY') {
    super(`Password operation failed (${code})`);
    this.name = 'ClientOpaqueError';
  }
}

// A deliberately small, pinned v1 local denylist, not a comprehensive breach feed.
const commonPasswords = new Set([
  'passwordpassword', 'passwordpasswordpassword', 'password123456789', '123456789012345',
  '1234567890123456', '12345678901234567890', 'qwertyuiopasdfgh', 'qwertyuiopasdfghjkl',
  'letmeinletmeinletmein', 'iloveyouiloveyou', 'correct horse battery staple',
]);

function validPasswordText(password: string, minimum: number): boolean {
  return typeof password === 'string' && password.length <= 2048 &&
    !/[\uD800-\uDFFF]/u.test(password) &&
    [...password].length >= minimum && [...password].length <= 1024;
}

/** Do not trim, normalize, truncate, require character classes, or send the password. */
export function validateNewPassword(password: string): void {
  if (!validPasswordText(password, 15) || commonPasswords.has(password.toLowerCase())) {
    throw new ClientOpaqueError('PASSWORD_POLICY');
  }
}

function validateConfiguration(configuration: OpaquePublicConfiguration): void {
  if (configuration.configId !== OPAQUE_CONFIG_ID || configuration.keyStretching !== OPAQUE_KEY_STRETCHING ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(configuration.setupId) ||
    !binary(32).safeParse(configuration.serverStaticPublicKey).success ||
    !/^ukda:[0-9a-f-]{36}:[0-9a-f-]{36}$/.test(configuration.identifiers.client) ||
    !/^[\x21-\x7e]{1,256}$/.test(configuration.identifiers.server)) {
    throw new ClientOpaqueError('CONFIGURATION');
  }
}

function checkServerKey(actual: string, configuration: OpaquePublicConfiguration): void {
  if (actual !== configuration.serverStaticPublicKey) throw new ClientOpaqueError('SERVER_KEY');
}

/** Run these helpers in a dedicated browser worker: the library's finish calls are synchronous. */
export async function startRegistration(password: string): Promise<opaque.client.StartRegistrationResult> {
  validateNewPassword(password);
  await opaque.ready;
  try { return opaque.client.startRegistration({ password }); }
  catch { throw new ClientOpaqueError('AUTHENTICATION'); }
}

/**
 * Configuration must come from the trusted deployment or an existing pin. Only
 * registrationRecord crosses the network; exportKey and client state stay local.
 * JS strings cannot be reliably zeroed: callers must drop all references promptly.
 */
export async function finishRegistration(input: {
  password: string; clientRegistrationState: string; registrationResponse: string;
  configuration: OpaquePublicConfiguration;
}): Promise<opaque.client.FinishRegistrationResult> {
  validateNewPassword(input.password);
  validateConfiguration(input.configuration);
  await opaque.ready;
  try {
    const result = opaque.client.finishRegistration({
      password: input.password, clientRegistrationState: input.clientRegistrationState,
      registrationResponse: input.registrationResponse, identifiers: input.configuration.identifiers,
      keyStretching: OPAQUE_KEY_STRETCHING,
    });
    checkServerKey(result.serverStaticPublicKey, input.configuration);
    return result;
  } catch (error) {
    if (error instanceof ClientOpaqueError) throw error;
    throw new ClientOpaqueError('AUTHENTICATION');
  }
}

/** Login never reapplies a newer registration denylist to existing credentials. */
export async function startLogin(password: string): Promise<opaque.client.StartLoginResult> {
  if (!validPasswordText(password, 1)) throw new ClientOpaqueError('AUTHENTICATION');
  await opaque.ready;
  try { return opaque.client.startLogin({ password }); }
  catch { throw new ClientOpaqueError('AUTHENTICATION'); }
}

export async function finishLogin(input: {
  password: string; clientLoginState: string; loginResponse: string;
  configuration: OpaquePublicConfiguration;
}): Promise<opaque.client.FinishLoginResult> {
  if (!validPasswordText(input.password, 1)) throw new ClientOpaqueError('AUTHENTICATION');
  validateConfiguration(input.configuration);
  await opaque.ready;
  try {
    const result = opaque.client.finishLogin({
      password: input.password, clientLoginState: input.clientLoginState,
      loginResponse: input.loginResponse, identifiers: input.configuration.identifiers,
      keyStretching: OPAQUE_KEY_STRETCHING,
    });
    if (!result) throw new ClientOpaqueError('AUTHENTICATION');
    checkServerKey(result.serverStaticPublicKey, input.configuration);
    return result;
  } catch (error) {
    if (error instanceof ClientOpaqueError) throw error;
    throw new ClientOpaqueError('AUTHENTICATION');
  }
}

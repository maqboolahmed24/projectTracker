import { z } from 'zod';
import { authSessionResult, deviceChallenge, deviceProof, type AuthSessionResult, type DeviceChallenge, type DeviceProof } from '../shared/auth.js';
import { genesisBody } from '../shared/activation.js';
import { binary, digest, identifier, positiveCounter } from '../shared/contracts.js';
import { canonicalJson } from '../shared/crypto.js';
import { parseJsonStrict } from '../shared/json.js';
import { AuthWorkerClient } from './auth-worker-client.js';
import { IndexedDeviceStore } from './device-store.js';
import type { RememberedProfiles, RememberedProfileReference } from './remembered-profiles.js';

export const authSessionSnapshot = authSessionResult.extend({ securityHead: digest, securityVersion: positiveCounter });
export type AuthSessionSnapshot = z.infer<typeof authSessionSnapshot>;
const startResult = z.strictObject({ loginId: identifier, loginResponse: binary(1, 4096), configuration: genesisBody.shape.opaque, expiresAt: z.iso.datetime() });
export type AuthStartResult = z.infer<typeof startResult>;
const referenceSchema = z.strictObject({ workspaceId: identifier, accountId: identifier, deviceId: identifier.optional() });
export type LoginReference = z.infer<typeof referenceSchema>;
export type AuthErrorCode = 'AUTH_REQUIRED' | 'PROOF_REQUIRED' | 'RATE_LIMITED' | 'UNAVAILABLE' | 'TRANSPORT' | 'CANCELLED'
  | 'REAUTH_REQUIRED' | 'FORBIDDEN' | 'CONTEXT_MISMATCH' | 'LOCAL_DEVICE_UNAVAILABLE' | 'BUSY' | 'LOCAL_CLEANUP' | 'CONFLICT' | 'EXPIRED';
export class AuthClientError extends Error {
  constructor(readonly code: AuthErrorCode) { super(`Authentication operation failed (${code})`); this.name = 'AuthClientError'; }
}
export interface AuthRequestOptions { signal?: AbortSignal }
export interface AuthTransport {
  readonly origin: string;
  loginStart(input: { workspaceId: string; accountId: string; startLoginRequest: string }, options?: AuthRequestOptions): Promise<AuthStartResult>;
  loginFinish(input: { loginId: string; finishLoginRequest: string }, options?: AuthRequestOptions): Promise<AuthSessionResult>;
  session(options?: AuthRequestOptions): Promise<AuthSessionSnapshot>;
  challengeStart(csrfToken: string, deviceId: string, options?: AuthRequestOptions): Promise<DeviceChallenge>;
  challengeFinish(csrfToken: string, proof: DeviceProof, options?: AuthRequestOptions): Promise<AuthSessionResult>;
  reauthStart(csrfToken: string, startLoginRequest: string, options?: AuthRequestOptions): Promise<AuthStartResult>;
  reauthFinish(csrfToken: string, input: { loginId: string; finishLoginRequest: string }, options?: AuthRequestOptions): Promise<AuthSessionResult>;
  logout(csrfToken: string, options?: AuthRequestOptions): Promise<{ loggedOut: true }>;
}
function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  try { return schema.parse(parseJsonStrict(canonicalJson(value))); } catch { throw new AuthClientError('CONTEXT_MISMATCH'); }
}
export function authOrigin(value: string): string {
  try {
    const url = new URL(value);
    if (url.origin !== value || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) ||
      (globalThis.location && globalThis.location.origin !== value)) throw new Error();
    return value;
  } catch { throw new AuthClientError('TRANSPORT'); }
}
/** Same-origin HTTPS cookies; only exact loopback HTTP is accepted for local development. */
export class AuthenticatedHttp {
  readonly origin: string;
  constructor(origin: string, private readonly fetcher: typeof fetch = globalThis.fetch) { this.origin = authOrigin(origin); }
  protected responseLimit(_path: string): number { return 1_048_576; }
  async post<T>(path: string, body: unknown, schema: z.ZodType<T>, options: AuthRequestOptions & { csrfToken?: string } = {}): Promise<T> {
    if (!/^\/v1\/[a-z0-9/-]+$/.test(path)) throw new AuthClientError('TRANSPORT');
    const url = `${this.origin}${path}`;
    const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (options.csrfToken !== undefined) headers['X-CSRF-Token'] = parse(binary(32), options.csrfToken);
    let response: Response; let value: unknown;
    try {
      response = await this.fetcher.call(globalThis, url, { method: 'POST', body: canonicalJson(body), headers,
        credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store', referrerPolicy: 'strict-origin',
        ...(options.signal ? { signal: options.signal } : {}) });
      if (response.url !== url || response.redirected || !response.headers.get('content-type')?.startsWith('application/json')) throw new Error();
      const text = await response.text(); if (text.length > this.responseLimit(path) || new TextEncoder().encode(text).length > this.responseLimit(path)) throw new Error(); value = parseJsonStrict(text);
    } catch { throw new AuthClientError(options.signal?.aborted ? 'CANCELLED' : 'TRANSPORT'); }
    if (!response.ok) {
      const error = z.object({ error: z.object({ code: z.string().max(128) }) }).safeParse(value);
      const code = error.success ? error.data.error.code : undefined;
      if (response.status === 401 && ['AUTH_REQUIRED', 'AUTHENTICATION_FAILED', 'RECOVERY_INVALID'].includes(code ?? '')) throw new AuthClientError('AUTH_REQUIRED');
      if (response.status === 401 && ['REAUTH_REQUIRED', 'PASSWORD_PROOF_REQUIRED'].includes(code ?? '')) throw new AuthClientError('REAUTH_REQUIRED');
      if (response.status === 403 && ['PAIRING_FORBIDDEN', 'RECOVERY_FORBIDDEN'].includes(code ?? '')) throw new AuthClientError('FORBIDDEN');
      if (response.status === 409 && code === 'PAIRING_KEYS_UNAVAILABLE') throw new AuthClientError('UNAVAILABLE');
      if (response.status === 401 && code === 'DEVICE_PROOF_INVALID') throw new AuthClientError('PROOF_REQUIRED');
      if (response.status === 429 && code === 'RATE_LIMITED') throw new AuthClientError('RATE_LIMITED');
      if (response.status === 503 && ['AUTHENTICATION_UNAVAILABLE', 'SETUP_UNAVAILABLE', 'PAIRING_UNAVAILABLE', 'RECOVERY_UNAVAILABLE', 'SECURITY_FENCED'].includes(code ?? '')) throw new AuthClientError('UNAVAILABLE');
      if (response.status === 409 && ['OPERATION_CONFLICT', 'PAIRING_CONFLICT', 'PAIRING_INVALID', 'STALE_SECURITY_STATE', 'HISTORY_CURSOR_INVALID', 'RECOVERY_CHANGED'].includes(code ?? '')) throw new AuthClientError('CONFLICT');
      if (response.status === 410 && ['PAIRING_EXPIRED', 'RECOVERY_EXPIRED'].includes(code ?? '')) throw new AuthClientError('EXPIRED');
      throw new AuthClientError('TRANSPORT');
    }
    return parse(schema, value);
  }
}
export class HttpAuthTransport extends AuthenticatedHttp implements AuthTransport {
  loginStart(input: { workspaceId: string; accountId: string; startLoginRequest: string }, options?: AuthRequestOptions) { return this.post('/v1/auth/login/start', input, startResult, options); }
  loginFinish(input: { loginId: string; finishLoginRequest: string }, options?: AuthRequestOptions) { return this.post('/v1/auth/login/finish', input, authSessionResult, options); }
  session(options?: AuthRequestOptions) { return this.post('/v1/auth/session', {}, authSessionSnapshot, options); }
  challengeStart(csrfToken: string, deviceId: string, options?: AuthRequestOptions) { return this.post('/v1/auth/device-challenge/start', { deviceId }, deviceChallenge, { ...options, csrfToken }); }
  challengeFinish(csrfToken: string, proof: DeviceProof, options?: AuthRequestOptions) { return this.post('/v1/auth/device-challenge/finish', proof, authSessionResult, { ...options, csrfToken }); }
  reauthStart(csrfToken: string, startLoginRequest: string, options?: AuthRequestOptions) { return this.post('/v1/auth/reauth/start', { startLoginRequest }, startResult, { ...options, csrfToken }); }
  reauthFinish(csrfToken: string, input: { loginId: string; finishLoginRequest: string }, options?: AuthRequestOptions) { return this.post('/v1/auth/reauth/finish', input, authSessionResult, { ...options, csrfToken }); }
  logout(csrfToken: string, options?: AuthRequestOptions) { return this.post('/v1/auth/logout', {}, z.strictObject({ loggedOut: z.literal(true) }), { ...options, csrfToken }); }
}

export interface AuthState { session: AuthSessionResult; localAccess: 'pairing_required' | 'unlocked' }
/** No bearer/password/OPAQUE state is written to storage; the cookie is HttpOnly. */
export class AuthController {
  readonly origin: string;
  private sessionValue: AuthSessionResult | undefined;
  private exportKey: string | undefined;
  private operation: AbortController | undefined;
  private loggingOut: Promise<void> | undefined;
  private epoch = 0;
  private unlocked = false;
  private readonly requests = new Set<Promise<unknown>>();
  private readonly clearers = new Set<() => void>();
  private readonly forgetters = new Set<(reference: RememberedProfileReference) => Promise<void>>();
  constructor(private readonly transport: AuthTransport, readonly worker: AuthWorkerClient,
    private readonly devices: IndexedDeviceStore, private readonly remembered?: RememberedProfiles) {
    this.origin = authOrigin(transport.origin);
    if (worker.origin !== this.origin || (remembered && remembered.origin !== this.origin)) throw new AuthClientError('CONTEXT_MISMATCH');
  }
  current(): AuthState | undefined {
    return this.sessionValue ? { session: parse(authSessionResult, this.sessionValue), localAccess: this.unlocked ? 'unlocked' : 'pairing_required' } : undefined;
  }
  /** Plaintext/cache owners register synchronous, idempotent cleanup; logout calls all of them. */
  onClear(clear: () => void): () => void { this.clearers.add(clear); return () => { this.clearers.delete(clear); }; }
  onForget(forget: (reference: RememberedProfileReference) => Promise<void>): () => void { this.forgetters.add(forget); return () => { this.forgetters.delete(forget); }; }
  private clearLocal(): boolean {
    this.exportKey = undefined; this.sessionValue = undefined; this.unlocked = false; this.worker.logout();
    let clean = true; for (const clear of this.clearers) { try { clear(); } catch { clean = false; } } return clean;
  }
  private async request<T>(promise: Promise<T>): Promise<T> {
    this.requests.add(promise); try { return await promise; } finally { this.requests.delete(promise); }
  }
  private sameAccount(session: AuthSessionResult, reference: Pick<LoginReference, 'workspaceId' | 'accountId'>) {
    if (session.workspaceId !== reference.workspaceId || session.accountId !== reference.accountId) throw new AuthClientError('CONTEXT_MISMATCH');
  }
  private checkEpoch(epoch: number) { if (epoch !== this.epoch) throw new AuthClientError('CANCELLED'); }
  private async run<T>(action: (signal: AbortSignal, epoch: number) => Promise<T>): Promise<T> {
    if (this.loggingOut) await this.loggingOut;
    if (this.operation) throw new AuthClientError('BUSY');
    const operation = new AbortController(); this.operation = operation; const epoch = this.epoch;
    try { return await action(operation.signal, epoch); } finally { if (this.operation === operation) this.operation = undefined; }
  }
  async login(reference: LoginReference, password: string): Promise<AuthState> {
    const selected = parse(referenceSchema, reference);
    return this.run(async (signal, epoch) => {
      this.clearLocal();
      try {
        const started = await this.worker.startLogin(password, { signal });
        const response = parse(startResult, await this.request(this.transport.loginStart({ workspaceId: selected.workspaceId,
          accountId: selected.accountId, startLoginRequest: started.startLoginRequest }, { signal })));
        if (response.configuration.identifiers.client !== `ukda:${selected.workspaceId}:${selected.accountId}`) throw new AuthClientError('CONTEXT_MISMATCH');
        const finished = await this.worker.finishLogin({ password, clientLoginState: started.clientLoginState,
          loginResponse: response.loginResponse, configuration: response.configuration }, { signal });
        const session = parse(authSessionResult, await this.request(this.transport.loginFinish({ loginId: response.loginId, finishLoginRequest: finished.finishLoginRequest }, { signal })));
        this.checkEpoch(epoch); this.sameAccount(session, selected);
        if (session.accessLevel !== 'restricted' || session.deviceId !== null) throw new AuthClientError('CONTEXT_MISMATCH');
        this.sessionValue = session; this.exportKey = finished.exportKey;
        if (selected.deviceId) {
          const wrapper = await this.devices.get({ workspaceId: selected.workspaceId, accountId: selected.accountId, deviceId: selected.deviceId, credentialGeneration: session.credentialGeneration });
          if (wrapper) await this.proveDevice(selected.deviceId, signal, epoch);
        }
        this.checkEpoch(epoch); return this.current()!;
      } catch (error) {
        if (epoch === this.epoch) { this.exportKey = undefined; this.unlocked = false; this.worker.logout(); }
        throw error;
      }
    });
  }
  private async proveDevice(deviceId: string, signal: AbortSignal, epoch: number): Promise<void> {
    const session = this.sessionValue; const exportKey = this.exportKey;
    if (!session || !exportKey) throw new AuthClientError('AUTH_REQUIRED');
    const wrapper = await this.devices.get({ workspaceId: session.workspaceId, accountId: session.accountId, deviceId, credentialGeneration: session.credentialGeneration });
    if (!wrapper || wrapper.header.credentialGeneration !== session.credentialGeneration) throw new AuthClientError('LOCAL_DEVICE_UNAVAILABLE');
    const challenge = parse(deviceChallenge, await this.request(this.transport.challengeStart(session.csrfToken, deviceId, { signal })));
    this.checkEpoch(epoch);
    for (const field of ['workspaceId', 'accountId', 'sessionId', 'credentialGeneration', 'sessionGeneration', 'dataGeneration'] as const) {
      if (challenge[field] !== session[field]) throw new AuthClientError('CONTEXT_MISMATCH');
    }
    if (challenge.origin !== this.origin || challenge.deviceId !== deviceId) throw new AuthClientError('CONTEXT_MISMATCH');
    const { version: _version, purpose: _purpose, ceremonyId: _ceremony, nonce: _nonce, issuedAt: _issued, expiresAt: _expires, ...proofContext } = challenge;
    await this.worker.unlockDevice({ context: { workspaceId: session.workspaceId, accountId: session.accountId, deviceId,
      credentialGeneration: session.credentialGeneration }, wrapper, exportKey, proofContext }, { signal });
    const proof = parse(deviceProof, await this.worker.deviceProof(challenge, { signal }));
    const approved = parse(authSessionResult, await this.request(this.transport.challengeFinish(session.csrfToken, proof, { signal })));
    this.checkEpoch(epoch); this.sameAccount(approved, session);
    if (approved.accessLevel !== 'device_approved' || approved.deviceId !== deviceId || approved.credentialGeneration !== session.credentialGeneration ||
      approved.sessionGeneration !== session.sessionGeneration || approved.dataGeneration !== session.dataGeneration ||
      approved.authenticatedAt !== session.authenticatedAt || approved.absoluteExpiresAt !== session.absoluteExpiresAt) throw new AuthClientError('CONTEXT_MISMATCH');
    this.sessionValue = approved; this.exportKey = undefined; this.unlocked = true;
  }
  /** Pairing calls this only after the matching receipt has promoted its local wrapper. */
  approveLocalDevice(deviceId: string): Promise<AuthState> {
    return this.run(async (signal, epoch) => { await this.proveDevice(parse(identifier, deviceId), signal, epoch); return this.current()!; });
  }
  /** Restricted pairing preparation can use the current export key without persisting it. */
  async withExportKey<T>(action: (exportKey: string, session: AuthSessionResult) => Promise<T>): Promise<T> {
    const key = this.exportKey, session = this.sessionValue, epoch = this.epoch;
    if (!key || !session || this.loggingOut) throw new AuthClientError('AUTH_REQUIRED');
    const result = await action(key, parse(authSessionResult, session)); this.checkEpoch(epoch); return result;
  }
  async refresh(): Promise<AuthSessionSnapshot> {
    return this.run(async (signal, epoch) => {
      try {
        const snapshot = parse(authSessionSnapshot, await this.request(this.transport.session({ signal })));
        this.checkEpoch(epoch);
        if (this.sessionValue) {
          this.sameAccount(snapshot, this.sessionValue);
          if (snapshot.sessionId !== this.sessionValue.sessionId || snapshot.deviceId !== this.sessionValue.deviceId ||
            snapshot.credentialGeneration !== this.sessionValue.credentialGeneration || snapshot.sessionGeneration !== this.sessionValue.sessionGeneration ||
            snapshot.dataGeneration !== this.sessionValue.dataGeneration) this.clearLocal();
        }
        // A surviving cookie does not reconstruct local keys or mark a fresh process unlocked.
        this.sessionValue = parse(authSessionResult, { sessionId: snapshot.sessionId, workspaceId: snapshot.workspaceId, accountId: snapshot.accountId,
          deviceId: snapshot.deviceId, accessLevel: snapshot.accessLevel, credentialGeneration: snapshot.credentialGeneration, sessionGeneration: snapshot.sessionGeneration,
          dataGeneration: snapshot.dataGeneration, csrfToken: snapshot.csrfToken, authenticatedAt: snapshot.authenticatedAt,
          idleExpiresAt: snapshot.idleExpiresAt, absoluteExpiresAt: snapshot.absoluteExpiresAt });
        return snapshot;
      } catch (error) { if (error instanceof AuthClientError && error.code === 'AUTH_REQUIRED' && epoch === this.epoch) this.clearLocal(); throw error; }
    });
  }
  async reauthenticate(password: string): Promise<AuthState> {
    return this.reauthenticateWithExportKey(password, async () => {});
  }
  /** Export key is transient callback data; never cached or persisted by this method. */
  async reauthenticateWithExportKey(password: string, action: (exportKey: string, session: AuthSessionResult) => Promise<void>): Promise<AuthState> {
    return this.run(async (signal, epoch) => {
      const previous = this.sessionValue;
      if (!previous || !this.unlocked || previous.accessLevel !== 'device_approved') throw new AuthClientError('AUTH_REQUIRED');
      const start = await this.worker.startLogin(password, { signal });
      const response = parse(startResult, await this.request(this.transport.reauthStart(previous.csrfToken, start.startLoginRequest, { signal })));
      if (response.configuration.identifiers.client !== `ukda:${previous.workspaceId}:${previous.accountId}`) throw new AuthClientError('CONTEXT_MISMATCH');
      const finished = await this.worker.finishLogin({ password, clientLoginState: start.clientLoginState, loginResponse: response.loginResponse,
        configuration: response.configuration }, { signal });
      const session = parse(authSessionResult, await this.request(this.transport.reauthFinish(previous.csrfToken,
        { loginId: response.loginId, finishLoginRequest: finished.finishLoginRequest }, { signal })));
      this.checkEpoch(epoch); this.sameAccount(session, previous);
      if (session.deviceId !== previous.deviceId || session.accessLevel !== 'device_approved' || session.credentialGeneration !== previous.credentialGeneration ||
        session.sessionGeneration !== previous.sessionGeneration || session.dataGeneration !== previous.dataGeneration || session.absoluteExpiresAt !== previous.absoluteExpiresAt) throw new AuthClientError('CONTEXT_MISMATCH');
      this.sessionValue = session;
      await action(finished.exportKey, parse(authSessionResult, session)); this.checkEpoch(epoch);
      return this.current()!;
    });
  }
  /** Local clearing happens before awaiting server revocation; a failed revocation is reported. */
  logout(): Promise<void> {
    this.loggingOut ??= this.performLogout().finally(() => { this.loggingOut = undefined; }); return this.loggingOut;
  }
  private async performLogout(): Promise<void> {
    this.epoch++; this.operation?.abort(); this.operation = undefined;
    const clean = this.clearLocal();
    await Promise.allSettled([...this.requests]);
    try {
      const session = parse(authSessionSnapshot, await this.transport.session());
      parse(z.strictObject({ loggedOut: z.literal(true) }), await this.transport.logout(session.csrfToken));
    } catch (error) {
      if (!(error instanceof AuthClientError && error.code === 'AUTH_REQUIRED')) throw error;
    }
    if (!clean) throw new AuthClientError('LOCAL_CLEANUP');
  }
  async forget(reference: RememberedProfileReference): Promise<void> {
    let failure: unknown;
    try { await this.logout(); } catch (error) { failure = error; }
    const cleanup = await Promise.allSettled([...this.forgetters].map((forget) => forget(reference)));
    if (this.remembered) await this.remembered.forget(reference, this.devices);
    else await this.devices.forget(reference.workspaceId, reference.accountId, reference.deviceId);
    if (cleanup.some((result) => result.status === 'rejected')) throw new AuthClientError('LOCAL_CLEANUP');
    if (failure) throw failure;
  }
}

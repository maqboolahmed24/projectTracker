import type * as recoveryHelpers from './recovery-controller.js';
import type * as enrolmentHelpers from './enrolment-controller.js';
import type * as rolesHelpers from './roles-controller.js';
import type * as accessHelpers from './access-change-crypto.js';
import { z } from 'zod';
import { AuthWorkerError, workerResponse, type AuthWorkerMethods, type AuthWorkerMethod,
  type AuthWorkerErrorCode, type UnlockDeviceInput } from './auth-worker.js';
import type { DeviceChallenge } from '../shared/auth.js';
import type { finishRegistration, finishLogin } from './opaque.js';
import type { PairingDeviceInput, PairingRecipientInput, PairingApproverInput, PreparePairingApprovalInput, VerifyPairingDeliveryInput } from './pairing.js';
import type { DeviceWrapper } from './device-store.js';
import type { PreparePasswordChangeInput, VerifyPasswordChangeWrapperInput } from './password-change.js';

export interface AuthWorkerEndpoint {
  postMessage(message: unknown): void;
  terminate(): void;
  addEventListener(type: 'message' | 'error' | 'messageerror', listener: EventListener): void;
  removeEventListener(type: 'message' | 'error' | 'messageerror', listener: EventListener): void;
}
export interface AuthWorkerClientOptions {
  origin?: string;
  workerUrl?: string | URL;
  /** Test/runtime adapter only; production uses a real same-origin module Worker. */
  createWorker?: () => AuthWorkerEndpoint;
}
export interface WorkerCallOptions { signal?: AbortSignal }
type PendingCall = { resolve: (result: unknown) => void; reject: (error: AuthWorkerError) => void };
const capabilities = z.strictObject({ webAssembly: z.literal(true), webCrypto: z.literal(true), indexedDB: z.literal(true) });

/**
 * No browser storage or fallback implementation. Returned OPAQUE state/export-key
 * strings are ephemeral: callers must discard them after use and on logout;
 * JavaScript strings cannot be reliably zeroed. Decrypted device keys stay in the
 * Worker. Any cancellation terminates it, including synchronous WASM work, and
 * rejects other in-flight requests before a new locked worker can be created.
 */
export class AuthWorkerClient {
  readonly origin: string;
  private readonly factory: () => AuthWorkerEndpoint;
  private worker: AuthWorkerEndpoint | undefined;
  private detach: (() => void) | undefined;
  private initialization: Promise<void> | undefined;
  private readonly pending = new Map<number, PendingCall>();
  private nextId = 1;
  private epoch = 0;
  private resetCode: AuthWorkerErrorCode = 'LOGGED_OUT';
  private closed = false;
  constructor(options: AuthWorkerClientOptions = {}) {
    try {
      const origin = options.origin ?? globalThis.location?.origin;
      if (!origin) throw new Error();
      const parsed = new URL(origin);
      if (parsed.origin !== origin || (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname))) ||
        (globalThis.location && globalThis.location.origin !== origin)) throw new Error();
      this.origin = origin;
      const url = options.workerUrl === undefined ? new URL('./auth-worker.js', import.meta.url) : new URL(options.workerUrl, origin);
      if (!options.createWorker && (url.origin !== origin || url.username || url.password || url.hash)) throw new Error();
      this.factory = options.createWorker ?? (() => {
        if (typeof Worker !== 'function') throw new AuthWorkerError('UNSUPPORTED');
        return new Worker(url, { type: 'module', name: 'ukda-auth-v1' });
      });
    } catch { throw new AuthWorkerError('UNSUPPORTED'); }
  }
  private reset(code: AuthWorkerErrorCode): void {
    this.epoch++; this.resetCode = code;
    const worker = this.worker;
    this.worker = undefined; this.initialization = undefined;
    this.detach?.(); this.detach = undefined;
    // Best-effort explicit zeroing, then immediate termination also stops blocked WASM.
    try { worker?.postMessage({ version: 1, id: this.nextId++, method: 'clear', input: {} }); } catch { /* termination remains authoritative */ }
    try { worker?.terminate(); } catch { /* no worker is reused after a termination error */ }
    for (const call of this.pending.values()) call.reject(new AuthWorkerError(code));
    this.pending.clear();
  }
  private startWorker(): void {
    if (this.closed) throw new AuthWorkerError('CLOSED');
    if (this.worker) return;
    let worker: AuthWorkerEndpoint;
    try { worker = this.factory(); } catch { throw new AuthWorkerError('UNSUPPORTED'); }
    this.worker = worker;
    const message: EventListener = (event) => {
      if (this.worker !== worker) return;
      const parsed = workerResponse.safeParse((event as MessageEvent<unknown>).data);
      if (!parsed.success) { this.reset('INTERNAL'); return; }
      const reply = parsed.data;
      const request = this.pending.get(reply.id);
      if (!request) return;
      this.pending.delete(reply.id);
      if (reply.ok) request.resolve(reply.result); else request.reject(new AuthWorkerError(reply.code));
    };
    const failure: EventListener = () => { if (this.worker === worker) this.reset('UNSUPPORTED'); };
    worker.addEventListener('message', message); worker.addEventListener('error', failure); worker.addEventListener('messageerror', failure);
    this.detach = () => {
      worker.removeEventListener('message', message); worker.removeEventListener('error', failure); worker.removeEventListener('messageerror', failure);
    };
  }
  private send<M extends AuthWorkerMethod>(method: M, input: AuthWorkerMethods[M]['input']): Promise<AuthWorkerMethods[M]['output']> {
    const worker = this.worker;
    if (!worker) return Promise.reject(new AuthWorkerError(this.closed ? 'CLOSED' : 'UNSUPPORTED'));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve: (value) => resolve(value as AuthWorkerMethods[M]['output']), reject });
      try { worker.postMessage({ version: 1, id, method, input }); }
      catch { this.reset('INVALID_REQUEST'); }
    });
  }
  private initialize(): Promise<void> {
    if (this.closed) return Promise.reject(new AuthWorkerError('CLOSED'));
    if (!this.initialization) {
      this.startWorker();
      const worker = this.worker;
      this.initialization = this.send('capabilities', { origin: this.origin }).then((result) => {
        if (!capabilities.safeParse(result).success) throw new AuthWorkerError('UNSUPPORTED');
      }).catch((error: unknown) => {
        if (this.worker === worker) this.reset('UNSUPPORTED');
        throw error instanceof AuthWorkerError ? error : new AuthWorkerError('UNSUPPORTED');
      });
    }
    return this.initialization;
  }
  private async call<M extends AuthWorkerMethod>(method: M, input: AuthWorkerMethods[M]['input'], options: WorkerCallOptions = {}): Promise<AuthWorkerMethods[M]['output']> {
    if (options.signal?.aborted) throw new AuthWorkerError('CANCELLED');
    const abort = () => this.reset('CANCELLED');
    const startedEpoch = this.epoch;
    options.signal?.addEventListener('abort', abort, { once: true });
    try {
      await this.initialize();
      if (options.signal?.aborted) throw new AuthWorkerError('CANCELLED');
      if (this.epoch !== startedEpoch) throw new AuthWorkerError(this.resetCode);
      const result = await this.send(method, input);
      if (this.epoch !== startedEpoch) throw new AuthWorkerError(this.resetCode);
      return result;
    } finally { options.signal?.removeEventListener('abort', abort); }
  }
  prepareRoleChange(input: rolesHelpers.PrepareRoleChangeInput, options?: WorkerCallOptions) { return this.call('prepareRoleChange', input, options); }
  readRoleLabels(input: rolesHelpers.ReadRolesInput, options?: WorkerCallOptions) { return this.call('readRoleLabels', input, options); }
  prepareAccessChange(input: accessHelpers.PrepareAccessChangeInput, options?: WorkerCallOptions) { return this.call('prepareAccessChange', input, options); }
  refreshAccessKeys(input: accessHelpers.RefreshAccessKeysInput, options?: WorkerCallOptions) { return this.call('refreshAccessKeys', input, options); }
  async ready(options: WorkerCallOptions = {}): Promise<void> { await this.call('capabilities', { origin: this.origin }, options); }
  startRegistration(password: string, options?: WorkerCallOptions) { return this.call('startRegistration', { password }, options); }
  finishRegistration(input: Parameters<typeof finishRegistration>[0], options?: WorkerCallOptions) { return this.call('finishRegistration', input, options); }
  startLogin(password: string, options?: WorkerCallOptions) { return this.call('startLogin', { password }, options); }
  finishLogin(input: Parameters<typeof finishLogin>[0], options?: WorkerCallOptions) { return this.call('finishLogin', input, options); }
  unlockDevice(input: UnlockDeviceInput, options?: WorkerCallOptions) { return this.call('unlockDevice', input, options); }
  deviceProof(challenge: DeviceChallenge, options?: WorkerCallOptions) { return this.call('deviceProof', { challenge }, options); }
  preparePasswordChange(input: PreparePasswordChangeInput, options?: WorkerCallOptions) { return this.call('preparePasswordChange', input, options); }
  verifyPasswordChangeWrapper(input: VerifyPasswordChangeWrapperInput, options?: WorkerCallOptions) { return this.call('verifyPasswordChangeWrapper', input, options); }
  createPairingDevice(input: PairingDeviceInput, options?: WorkerCallOptions) { return this.call('createPairingDevice', input, options); }
  verifyPairingDevice(input: PairingDeviceInput & { wrapper: DeviceWrapper }, options?: WorkerCallOptions) { return this.call('verifyPairingDevice', input, options); }
  confirmPairingRecipient(input: PairingRecipientInput, options?: WorkerCallOptions) { return this.call('confirmPairingRecipient', input, options); }
  confirmPairingApprover(input: PairingApproverInput, options?: WorkerCallOptions) { return this.call('confirmPairingApprover', input, options); }
  preparePairingApproval(input: PreparePairingApprovalInput, options?: WorkerCallOptions) { return this.call('preparePairingApproval', input, options); }
  verifyPairingDelivery(input: VerifyPairingDeliveryInput, options?: WorkerCallOptions) { return this.call('verifyPairingDelivery', input, options); }
  proveOwnerPhrase(input: recoveryHelpers.ProveOwnerPhraseInput, options?: WorkerCallOptions) { return this.call('proveOwnerPhrase', input, options); }
  prepareRecoveryDraft(input: recoveryHelpers.PrepareRecoveryDraftInput, options?: WorkerCallOptions) { return this.call('prepareRecoveryDraft', input, options); }
  verifyRecoveryDraftWrapper(input: recoveryHelpers.VerifyRecoveryDraftWrapperInput, options?: WorkerCallOptions) { return this.call('verifyRecoveryDraftWrapper', input, options); }
  confirmRecoveryRecipient(input: recoveryHelpers.ConfirmRecoveryRecipientInput, options?: WorkerCallOptions) { return this.call('confirmRecoveryRecipient', input, options); }
  preparePhraseRecoveryApproval(input: recoveryHelpers.PreparePhraseRecoveryApprovalInput, options?: WorkerCallOptions) { return this.call('preparePhraseRecoveryApproval', input, options); }
  prepareOwnerRecoveryApproval(input: recoveryHelpers.PrepareRecoveryApprovalInput, options?: WorkerCallOptions) { return this.call('prepareOwnerRecoveryApproval', input, options); }
  verifyRecoveryDelivery(input: recoveryHelpers.VerifyRecoveryDeliveryInput, options?: WorkerCallOptions) { return this.call('verifyRecoveryDelivery', input, options); }
  prepareJoinInvitation(input: enrolmentHelpers.PrepareJoinInvitationInput, options?: WorkerCallOptions) { return this.call('prepareJoinInvitation', input, options); }
  prepareEnrolmentDraft(input: enrolmentHelpers.PrepareEnrolmentDraftInput, options?: WorkerCallOptions) { return this.call('prepareEnrolmentDraft', input, options); }
  verifyEnrolmentDraft(input: enrolmentHelpers.VerifyEnrolmentDraftInput, options?: WorkerCallOptions) { return this.call('verifyEnrolmentDraft', input, options); }
  confirmEnrolmentTarget(input: enrolmentHelpers.VerifyEnrolmentDraftInput & { fingerprint: string }, options?: WorkerCallOptions) { return this.call('confirmEnrolmentTarget', input, options); }
  prepareEnrolmentApproval(input: enrolmentHelpers.PrepareEnrolmentApprovalInput, options?: WorkerCallOptions) { return this.call('prepareEnrolmentApproval', input, options); }
  verifyEnrolmentDelivery(input: enrolmentHelpers.VerifyEnrolmentDeliveryInput, options?: WorkerCallOptions) { return this.call('verifyEnrolmentDelivery', input, options); }
  /** Local revocation is immediate; the caller separately revokes the server session. */
  logout(): void { this.reset('LOGGED_OUT'); }
  close(): void { this.closed = true; this.reset('CLOSED'); }
}

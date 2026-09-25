import { z } from 'zod';
import { genesisBody } from '../shared/activation.js';
import { binary, identifier } from '../shared/contracts.js';
import { base64urlDecode, canonicalJson, digestObject, signObject } from '../shared/crypto.js';
import { passwordChangeBinding, passwordChangeBody, passwordChangePayload, passwordChangeReference, passwordChangeStatus,
  passwordChangeReceipt, passwordChangeResult, passwordChangeRegistrationResult, passwordChangeProofResult,
  registrationRecordHash, validatePasswordChangePayload,
  type PasswordChangeBinding, type PasswordChangePayload, type PasswordChangeReference, type PasswordChangeStatus,
  type PasswordChangeResult, type PasswordChangeReceipt } from '../shared/password-change.js';
import { deviceWrapper, IndexedDeviceStore, unwrapDeviceBundle, wrapDeviceBundle, type DeviceBundle, type DeviceContext, type DeviceWrapper } from './device-store.js';
import type { AuthWorkerClient } from './auth-worker-client.js';
import type { AuthSessionResult } from '../shared/auth.js';
import type { OpaquePublicConfiguration } from './opaque.js';
import { parseJsonStrict } from '../shared/json.js';

export const preparePasswordChangeInput = z.strictObject({
  binding: passwordChangeBinding, registrationRecord: binary(1, 4096), configuration: genesisBody.shape.opaque,
  exportKey: binary(32, 1024),
});
export type PreparePasswordChangeInput = z.infer<typeof preparePasswordChangeInput>;
export const verifyPasswordChangeWrapperInput = z.strictObject({ binding: passwordChangeBinding, wrapper: deviceWrapper, exportKey: binary(32, 1024) });
export type VerifyPasswordChangeWrapperInput = z.infer<typeof verifyPasswordChangeWrapperInput>;
export function passwordChangeDeviceContext(binding: PasswordChangeBinding): DeviceContext {
  return { workspaceId: binding.workspaceId, accountId: binding.accountId, deviceId: binding.deviceId,
    credentialGeneration: binding.nextCredentialGeneration };
}

/** Worker-only primitive: private keys never cross the worker's message boundary. */
export async function preparePasswordChange(input: PreparePasswordChangeInput, bundle: DeviceBundle): Promise<{ payload: PasswordChangePayload; wrapper: DeviceWrapper }> {
  const accepted = preparePasswordChangeInput.parse(input), binding = accepted.binding;
  if (bundle.signingPublicKey !== binding.signingPublicKey || bundle.recipientPublicKey !== binding.recipientPublicKey) throw new Error('Invalid password-change device');
  const wrapper = await wrapDeviceBundle(passwordChangeDeviceContext(binding), bundle, accepted.exportKey);
  const readback = await unwrapDeviceBundle(passwordChangeDeviceContext(binding), wrapper, accepted.exportKey);
  if (canonicalJson(readback) !== canonicalJson(bundle)) throw new Error('Invalid password-change wrapper');
  const body = passwordChangeBody.parse({ version: 1, purpose: 'ukda.password-change.v1', binding,
    registrationRecordHash: await registrationRecordHash(accepted.registrationRecord),
    configurationHash: await digestObject(accepted.configuration), wrapperHash: await digestObject(wrapper),
    revokeOtherDevices: true, revokeAllSessions: true });
  const signing = base64urlDecode(bundle.signingPrivateKey, 64);
  try {
    const payload = { transition: await signObject(body, signing), registrationRecord: accepted.registrationRecord, configuration: accepted.configuration };
    await validatePasswordChangePayload(payload, binding, accepted.configuration);
    return { payload, wrapper };
  } finally { signing.fill(0); }
}

/** Worker-only read-back check returns no decrypted key material. */
export async function verifyPasswordChangeWrapper(input: VerifyPasswordChangeWrapperInput): Promise<{ verified: true }> {
  const accepted = verifyPasswordChangeWrapperInput.parse(input);
  const bundle = await unwrapDeviceBundle(passwordChangeDeviceContext(accepted.binding), accepted.wrapper, accepted.exportKey);
  if (bundle.signingPublicKey !== accepted.binding.signingPublicKey || bundle.recipientPublicKey !== accepted.binding.recipientPublicKey) throw new Error('Invalid password-change wrapper');
  return { verified: true };
}

export interface PasswordChangeTransport {
  readonly origin: string;
  begin(reference: PasswordChangeReference, signal?: AbortSignal): Promise<PasswordChangeStatus>;
  status(reference: PasswordChangeReference, signal?: AbortSignal): Promise<PasswordChangeStatus>;
  registration(input: PasswordChangeReference & { registrationRequest: string }, signal?: AbortSignal): Promise<{ registrationResponse: string; configuration: OpaquePublicConfiguration }>;
  startProof(input: PasswordChangeReference & { payload: PasswordChangePayload; startLoginRequest: string }, signal?: AbortSignal): Promise<{
    proofId: string; expiresAt: string; loginResponse: string; configuration: OpaquePublicConfiguration; requestHash: string }>;
  finishProof(input: PasswordChangeReference & { proofId: string; finishLoginRequest: string }, signal?: AbortSignal): Promise<{ verified: true }>;
  finalize(input: PasswordChangeReference & { requestHash: string }, signal?: AbortSignal): Promise<PasswordChangeResult>;
  cancel(reference: PasswordChangeReference, signal?: AbortSignal): Promise<PasswordChangeStatus>;
}
const pendingChange = z.strictObject({ version: z.literal(1), origin: z.string(), reference: passwordChangeReference,
  status: passwordChangeStatus.optional(), draft: z.strictObject({ payload: passwordChangePayload, wrapper: deviceWrapper }).optional() });
type PendingChange = z.infer<typeof pendingChange>;
export class PasswordChangeClientError extends Error {
  constructor(readonly code: 'STORAGE' | 'CONFLICT' | 'INVALID_STATE' | 'LOCAL_VERIFICATION' | 'RECEIPT_MISMATCH' | 'CANCELLED' | 'PASSWORD_CONFIRMATION' | 'TRANSPORT' | 'RATE_LIMITED' | 'AUTHENTICATION') {
    super(`Password change failed (${code})`); this.name = 'PasswordChangeClientError';
  }
}
function snapshot<T>(schema: z.ZodType<T>, value: unknown): T {
  try { return schema.parse(parseJsonStrict(canonicalJson(value))); } catch { throw new PasswordChangeClientError('INVALID_STATE'); }
}

/** HTTPS/same-origin transport. Current CSRF comes from AuthController's authenticated public session. */
export class HttpPasswordChangeTransport implements PasswordChangeTransport {
  readonly origin: string;
  constructor(private readonly input: { origin: string; csrfToken: () => string | undefined; fetcher?: typeof fetch }) {
    try {
      const url = new URL(input.origin);
      if (url.origin !== input.origin || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) ||
        (globalThis.location && globalThis.location.origin !== input.origin)) throw new Error();
      this.origin = url.origin;
    } catch { throw new PasswordChangeClientError('TRANSPORT'); }
  }
  private async post<T>(path: string, input: unknown, schema: z.ZodType<T>, signal?: AbortSignal): Promise<T> {
    const url = `${this.origin}/v1/auth/password-change/${path}`;
    const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (path !== 'status') {
      const csrf = this.input.csrfToken(); if (!binary(32).safeParse(csrf).success) throw new PasswordChangeClientError('AUTHENTICATION');
      headers['X-CSRF-Token'] = csrf!;
    }
    let response: Response, body: unknown;
    try {
      response = await (this.input.fetcher ?? globalThis.fetch).call(globalThis, url, { method: 'POST', headers, body: canonicalJson(input),
        credentials: 'include', mode: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'strict-origin', ...(signal ? { signal } : {}) });
      if (response.redirected || response.url !== url || !response.headers.get('content-type')?.startsWith('application/json')) throw new Error();
      const text = await response.text(); if (text.length > 262144) throw new Error(); body = parseJsonStrict(text);
    } catch { throw new PasswordChangeClientError(signal?.aborted ? 'CANCELLED' : 'TRANSPORT'); }
    if (!response.ok) throw new PasswordChangeClientError(response.status === 429 ? 'RATE_LIMITED' : response.status === 409 ? 'CONFLICT' :
      [401, 403].includes(response.status) ? 'AUTHENTICATION' : 'TRANSPORT');
    return snapshot(schema, body);
  }
  begin(input: PasswordChangeReference, signal?: AbortSignal) { return this.post('begin', input, passwordChangeStatus, signal); }
  status(input: PasswordChangeReference, signal?: AbortSignal) { return this.post('status', input, passwordChangeStatus, signal); }
  registration(input: PasswordChangeReference & { registrationRequest: string }, signal?: AbortSignal) {
    return this.post('registration', input, passwordChangeRegistrationResult, signal) as Promise<{ registrationResponse: string; configuration: OpaquePublicConfiguration }>;
  }
  startProof(input: PasswordChangeReference & { payload: PasswordChangePayload; startLoginRequest: string }, signal?: AbortSignal) {
    return this.post('proof/start', input, passwordChangeProofResult, signal) as Promise<{ proofId: string; expiresAt: string; loginResponse: string; configuration: OpaquePublicConfiguration; requestHash: string }>;
  }
  finishProof(input: PasswordChangeReference & { proofId: string; finishLoginRequest: string }, signal?: AbortSignal) { return this.post('proof/finish', input, z.strictObject({ verified: z.literal(true) }), signal); }
  finalize(input: PasswordChangeReference & { requestHash: string }, signal?: AbortSignal) { return this.post('finalize', input, passwordChangeResult, signal); }
  cancel(input: PasswordChangeReference, signal?: AbortSignal) { return this.post('cancel', input, passwordChangeStatus, signal); }
}

/** Only capability metadata, OPAQUE records and encrypted wrappers persist; never passwords/export keys/private keys. */
export class IndexedPasswordChangeStore {
  private constructor(private readonly db: IDBDatabase) { db.onversionchange = () => db.close(); }
  static async open(name = 'ukda-password-change-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedPasswordChangeStore> {
    if (!factory) throw new PasswordChangeClientError('STORAGE');
    return new Promise((resolve, reject) => {
      let settled = false;
      const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new PasswordChangeClientError('STORAGE')); };
      request.onerror = request.onblocked = fail;
      request.onupgradeneeded = () => { request.result.createObjectStore('changes', { keyPath: 'reference.operationId' }); };
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedPasswordChangeStore(request.result)); };
    });
  }
  private run<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore, set: (value: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction;
      try { transaction = this.db.transaction('changes', mode, { durability: 'strict' }); } catch { reject(new PasswordChangeClientError('STORAGE')); return; }
      let value: T, provided = false, error: unknown;
      const fail = (reason: unknown) => { error = reason; transaction.abort(); };
      transaction.onabort = () => reject(error instanceof PasswordChangeClientError ? error : new PasswordChangeClientError('STORAGE'));
      transaction.oncomplete = () => provided ? resolve(value) : reject(new PasswordChangeClientError('STORAGE'));
      try { action(transaction.objectStore('changes'), (result) => { value = result; provided = true; }, fail); } catch (reason) { fail(reason); }
    });
  }
  get(operationId: string): Promise<PendingChange | undefined> {
    const id = snapshot(identifier, operationId);
    return this.run('readonly', (store, set, fail) => {
      const request = store.get(id); request.onsuccess = () => {
        try { set(request.result === undefined ? undefined : snapshot(pendingChange, request.result)); } catch (error) { fail(error); }
      };
    });
  }
  save(previous: PendingChange | undefined, next: PendingChange): Promise<void> {
    const accepted = snapshot(pendingChange, next), before = previous === undefined ? undefined : snapshot(pendingChange, previous);
    return this.run('readwrite', (store, set, fail) => {
      const request = store.get(accepted.reference.operationId); request.onsuccess = () => {
        try {
          const current = request.result === undefined ? undefined : snapshot(pendingChange, request.result);
          if ((current === undefined) !== (before === undefined) || (current && canonicalJson(current) !== canonicalJson(before))) throw new PasswordChangeClientError('CONFLICT');
          store.put(accepted); set(undefined);
        } catch (error) { fail(error); }
      };
    });
  }
  list(): Promise<Array<{ operationId: string; workspaceId: string; origin: string }>> {
    return this.run('readonly', (store, set, fail) => {
      const request = store.getAll(); request.onsuccess = () => { try {
        set((request.result as unknown[]).map((value) => { const row = snapshot(pendingChange, value);
          return { operationId: row.reference.operationId, workspaceId: row.reference.workspaceId, origin: row.origin }; }));
      } catch (error) { fail(error); } };
    });
  }
  forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    const accepted = snapshot(z.strictObject({ workspaceId: identifier, accountId: identifier, deviceId: identifier }), reference);
    return this.run('readwrite', (store, set, fail) => {
      const request = store.openCursor(); request.onsuccess = () => {
        try {
          const cursor = request.result;
          if (!cursor) { set(undefined); return; }
          // Cleanup depends only on identity metadata; malformed ciphertext in
          // this or an unrelated draft must not prevent explicit erasure.
          const metadata = z.object({ status: z.object({ binding: z.object({ workspaceId: identifier, accountId: identifier, deviceId: identifier }) }) }).safeParse(cursor.value);
          const binding = metadata.success ? metadata.data.status.binding : undefined;
          if (binding?.workspaceId === accepted.workspaceId && binding.accountId === accepted.accountId && binding.deviceId === accepted.deviceId) cursor.delete();
          cursor.continue();
        } catch (error) { fail(error); }
      };
    });
  }
  close() { this.db.close(); }
}

/** Receipt verification is independent of response loss or the active local wrapper pointer. */
async function checkReceipt(pending: PendingChange, value: unknown): Promise<PasswordChangeReceipt> {
  const receipt = snapshot(passwordChangeReceipt, value), draft = pending.draft, binding = pending.status?.binding;
  if (!draft || !binding) throw new PasswordChangeClientError('RECEIPT_MISMATCH');
  const requestHash = await digestObject(draft.payload);
  if (receipt.workspaceId !== binding.workspaceId || receipt.accountId !== binding.accountId || receipt.deviceId !== binding.deviceId ||
    receipt.operationId !== binding.operationId || receipt.credentialGeneration !== binding.nextCredentialGeneration ||
    receipt.sessionGeneration !== binding.nextSessionGeneration || receipt.keyGeneration !== binding.keyGeneration ||
    receipt.dataGeneration !== binding.dataGeneration || receipt.securityVersion !== binding.nextSecurityVersion ||
    receipt.securityHead !== await digestObject(draft.payload.transition) || receipt.requestHash !== requestHash ||
    receipt.wrapperHash !== await digestObject(draft.wrapper) || canonicalJson(receipt.transition) !== canonicalJson(draft.payload.transition)) {
    throw new PasswordChangeClientError('RECEIPT_MISMATCH');
  }
  await validatePasswordChangePayload(draft.payload, binding, draft.payload.configuration);
  return receipt;
}

export class PasswordChangeController {
  readonly #active = new Set<AbortController>();
  #auth: { logout(): Promise<void> } | undefined;
  constructor(private readonly input: { transport: PasswordChangeTransport; changes: IndexedPasswordChangeStore;
    devices: IndexedDeviceStore; worker: AuthWorkerClient }) {
    if (input.transport.origin !== input.worker.origin) throw new PasswordChangeClientError('INVALID_STATE');
  }
  async #run<T>(action: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController(); this.#active.add(controller);
    try { return await action(controller.signal); } finally { this.#active.delete(controller); }
  }
  #check(signal: AbortSignal) { if (signal.aborted) throw new PasswordChangeClientError('CANCELLED'); }
  async #pending(operationId: string) {
    const pending = await this.input.changes.get(operationId);
    if (!pending || pending.origin !== this.input.transport.origin) throw new PasswordChangeClientError('INVALID_STATE');
    return pending;
  }
  async begin(workspaceId: string, operationId = globalThis.crypto.randomUUID()): Promise<PasswordChangeStatus> {
    return this.#run(async (signal) => {
      let pending = await this.input.changes.get(operationId);
      if (!pending) {
        const token = globalThis.crypto.getRandomValues(new Uint8Array(32));
        const { base64urlEncode } = await import('../shared/crypto.js');
        pending = { version: 1, origin: this.input.transport.origin, reference: { workspaceId, operationId, resumeToken: base64urlEncode(token) } };
        token.fill(0); await this.input.changes.save(undefined, pending);
      }
      if (pending.reference.workspaceId !== workspaceId || pending.origin !== this.input.transport.origin) throw new PasswordChangeClientError('CONFLICT');
      const status = snapshot(passwordChangeStatus, await this.input.transport.begin(pending.reference, signal)); this.#check(signal);
      await this.input.changes.save(pending, { ...pending, status }); return status;
    });
  }
  async prepare(operationId: string, newPassword: string, confirmation: string): Promise<void> {
    if (newPassword !== confirmation) throw new PasswordChangeClientError('PASSWORD_CONFIRMATION');
    return this.#run(async (signal) => {
      const pending = await this.#pending(operationId);
      if (!pending.status || pending.status.state !== 'issued' || pending.draft) throw new PasswordChangeClientError('INVALID_STATE');
      const client = await this.input.worker.startRegistration(newPassword, { signal });
      const server = await this.input.transport.registration({ ...pending.reference, registrationRequest: client.registrationRequest }, signal);
      const registration = await this.input.worker.finishRegistration({ password: newPassword, clientRegistrationState: client.clientRegistrationState,
        registrationResponse: server.registrationResponse, configuration: server.configuration }, { signal });
      const draft = await this.input.worker.preparePasswordChange({ binding: pending.status.binding, registrationRecord: registration.registrationRecord,
        configuration: server.configuration, exportKey: registration.exportKey }, { signal });
      this.#check(signal);
      // Persist the exact encrypted draft before staging it in the device store; either write can resume independently.
      await this.input.changes.save(pending, { ...pending, draft });
      this.#check(signal);
      await this.input.devices.stage(draft.wrapper, operationId);
      const stored = await this.input.devices.getStaged(operationId);
      if (!stored || await digestObject(stored) !== draft.payload.transition.body.wrapperHash) throw new PasswordChangeClientError('LOCAL_VERIFICATION');
      await this.input.worker.verifyPasswordChangeWrapper({ binding: pending.status.binding, wrapper: stored, exportKey: registration.exportKey }, { signal });
    });
  }
  async complete(operationId: string, newPassword: string): Promise<PasswordChangeResult> {
    return this.#run(async (signal) => {
      const pending = await this.#pending(operationId), draft = pending.draft, binding = pending.status?.binding;
      if (!draft || !binding) throw new PasswordChangeClientError('INVALID_STATE');
      const current = snapshot(passwordChangeStatus, await this.input.transport.status(pending.reference, signal)); this.#check(signal);
      if (current.receipt && ['completed', 'finishing'].includes(current.state)) {
        // No speculative promotion after restart: normal matching-generation login must unlock first.
        const receipt = await checkReceipt(pending, current.receipt);
        this.#check(signal);
        return { state: current.state as 'completed' | 'finishing', receipt };
      }
      if (current.state !== 'issued' || canonicalJson(current.binding) !== canonicalJson(binding)) throw new PasswordChangeClientError('INVALID_STATE');
      await this.input.devices.stage(draft.wrapper, operationId);
      const stored = await this.input.devices.getStaged(operationId);
      if (!stored || await digestObject(stored) !== draft.payload.transition.body.wrapperHash) throw new PasswordChangeClientError('LOCAL_VERIFICATION');
      const client = await this.input.worker.startLogin(newPassword, { signal });
      const proof = await this.input.transport.startProof({ ...pending.reference, payload: draft.payload, startLoginRequest: client.startLoginRequest }, signal);
      if (proof.requestHash !== await digestObject(draft.payload)) throw new PasswordChangeClientError('CONFLICT');
      const finished = await this.input.worker.finishLogin({ password: newPassword, clientLoginState: client.clientLoginState,
        loginResponse: proof.loginResponse, configuration: proof.configuration }, { signal });
      await this.input.worker.verifyPasswordChangeWrapper({ binding, wrapper: stored, exportKey: finished.exportKey }, { signal });
      await this.input.transport.finishProof({ ...pending.reference, proofId: proof.proofId, finishLoginRequest: finished.finishLoginRequest }, signal);
      this.#check(signal);
      try {
        const result = await this.input.transport.finalize({ ...pending.reference, requestHash: proof.requestHash }, signal);
        const receipt = await checkReceipt(pending, result.receipt); this.#check(signal);
        await this.input.devices.commit(operationId, { ...passwordChangeDeviceContext(binding), operationId });
        return { state: result.state, receipt };
      } finally {
        // Ambiguous responses may already have revoked every old session. Also
        // clear registered plaintext/cache owners and stale public session state.
        this.input.worker.logout(); await this.#auth?.logout().catch(() => {});
      }
    });
  }
  async resume(operationId: string, authenticated?: AuthSessionResult): Promise<PasswordChangeStatus> {
    return this.#run(async (signal) => {
      const pending = await this.#pending(operationId);
      const status = snapshot(passwordChangeStatus, await this.input.transport.status(pending.reference, signal)); this.#check(signal);
      if (status.receipt) {
        const receipt = await checkReceipt(pending, status.receipt);
        this.#check(signal);
        if (authenticated) {
          if (authenticated.accessLevel !== 'device_approved' || authenticated.workspaceId !== receipt.workspaceId ||
            authenticated.accountId !== receipt.accountId || authenticated.deviceId !== receipt.deviceId ||
            authenticated.credentialGeneration !== receipt.credentialGeneration || authenticated.sessionGeneration !== receipt.sessionGeneration) throw new PasswordChangeClientError('RECEIPT_MISMATCH');
          // AuthController already unlocked this exact generation and proved the preserved signer.
          await this.input.devices.commit(operationId, { workspaceId: receipt.workspaceId, accountId: receipt.accountId,
            deviceId: receipt.deviceId, credentialGeneration: receipt.credentialGeneration, operationId });
        }
      }
      return status;
    });
  }
  async cancel(operationId: string): Promise<PasswordChangeStatus> {
    return this.#run(async (signal) => {
      const pending = await this.#pending(operationId);
      const existing = snapshot(passwordChangeStatus, await this.input.transport.status(pending.reference, signal));
      if (existing.receipt) throw new PasswordChangeClientError('CONFLICT');
      const status = ['expired', 'cancelled', 'revoked'].includes(existing.state) ? existing :
        snapshot(passwordChangeStatus, await this.input.transport.cancel(pending.reference, signal));
      this.#check(signal);
      if (!['expired', 'cancelled', 'revoked'].includes(status.state)) throw new PasswordChangeClientError('CONFLICT');
      await this.input.devices.discardUncommitted(operationId, status.binding.deviceId);
      return status;
    });
  }
  /** Logout aborts in-flight password work; encrypted pending wrappers remain available for receipt recovery. */
  clear() { for (const controller of this.#active) controller.abort(); this.input.worker.logout(); }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }) {
    this.clear(); await this.input.changes.forgetDevice(reference);
  }
  /** Register with AuthController when composing the client, including encrypted-draft cleanup on explicit forget. */
  attachAuthLifecycle(auth: {
    onClear(clear: () => void): () => void;
    onForget(forget: (reference: { workspaceId: string; accountId: string; deviceId: string }) => Promise<void>): () => void;
    logout(): Promise<void>;
  }): () => void {
    this.#auth = auth;
    const detachClear = auth.onClear(() => this.clear());
    const detachForget = auth.onForget((reference) => this.forgetDevice(reference));
    return () => { detachClear(); detachForget(); if (this.#auth === auth) this.#auth = undefined; };
  }
}

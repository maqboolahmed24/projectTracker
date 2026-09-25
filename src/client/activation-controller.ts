import { z } from 'zod';
import { activationBinding, activationPayload, genesisBody, validateActivationPayload, type ActivationPayload } from '../shared/activation.js';
import { binary, digest, identifier, positiveCounter } from '../shared/contracts.js';
import { base64urlEncode, canonicalJson, digestObject, randomKey } from '../shared/crypto.js';
import { parseJsonStrict } from '../shared/json.js';
import { beginActivationPassword, prepareOwnerActivation } from './activation.js';
import { deviceContext, deviceWrapper, IndexedDeviceStore, unwrapDeviceBundle, type DeviceContext } from './device-store.js';
import { finishLogin, finishRegistration, startLogin, type OpaquePublicConfiguration } from './opaque.js';

const configurationSchema = genesisBody.shape.opaque;
const receiptSchema = deviceContext.extend({
  operationId: identifier, dataGeneration: z.literal('1'), securityVersion: z.literal('1'),
  securityHead: digest, genesisFingerprint: digest, completedAt: z.iso.datetime(),
});
export type ActivationReceipt = z.infer<typeof receiptSchema>;
const statusSchema = z.strictObject({
  activationId: identifier, operationId: identifier, workspaceId: identifier, accountId: identifier,
  reservationGeneration: positiveCounter, draftGeneration: positiveCounter,
  expiresAt: z.iso.datetime(), resumeExpiresAt: z.iso.datetime(),
  state: z.enum(['reserved', 'completed', 'finishing_setup', 'expired', 'cancelled']),
  receipt: receiptSchema.optional(), configuration: configurationSchema.optional(),
});
export type ActivationStatus = z.infer<typeof statusSchema>;
const registrationSchema = z.strictObject({ registrationResponse: binary(1, 4096), configuration: configurationSchema });
const proofSchema = z.strictObject({ proofId: identifier, expiresAt: z.iso.datetime(), loginResponse: binary(1, 4096), requestHash: digest, configuration: configurationSchema });
const finalSchema = z.strictObject({ state: z.enum(['completed', 'finishing_setup']), receipt: receiptSchema });
export type ActivationResult = z.infer<typeof finalSchema>;

/** Trusted transports authenticate their HTTPS origin; exact loopback HTTP is for local development. */
export interface ActivationTransport {
  readonly origin: string;
  reserve(input: { licenceKey: string; operationId: string; resumeToken: string }): Promise<ActivationStatus>;
  status(activationId: string, resumeToken: string): Promise<ActivationStatus>;
  registration(activationId: string, resumeToken: string, input: { draftGeneration: string; registrationRequest: string }): Promise<z.infer<typeof registrationSchema>>;
  startProof(activationId: string, resumeToken: string, input: { draftGeneration: string; payload: ActivationPayload; startLoginRequest: string }): Promise<z.infer<typeof proofSchema>>;
  finishProof(activationId: string, resumeToken: string, input: { draftGeneration: string; proofId: string; finishLoginRequest: string }): Promise<{ verified: true }>;
  finalize(activationId: string, resumeToken: string, input: { draftGeneration: string; requestHash: string }): Promise<ActivationResult>;
  replaceDraft(activationId: string, resumeToken: string, input: { expectedDraftGeneration: string; operationId: string }): Promise<ActivationStatus>;
}

type ErrorCode = 'INVALID_STATE' | 'CONFLICT' | 'STORAGE' | 'UNAVAILABLE' | 'TRANSPORT' | 'RECEIPT_MISMATCH'
  | 'LOCAL_VERIFICATION' | 'ALREADY_COMMITTED' | 'EXPIRED' | 'RATE_LIMITED' | 'PROOF_REQUIRED';
export class ActivationControllerError extends Error {
  constructor(readonly code: ErrorCode) { super(`Activation operation failed (${code})`); this.name = 'ActivationControllerError'; }
}
function parse<T>(schema: z.ZodType<T>, value: unknown, code: ErrorCode = 'INVALID_STATE'): T {
  try { return schema.parse(parseJsonStrict(canonicalJson(value))); }
  catch { throw new ActivationControllerError(code); }
}
function secureOrigin(value: string): string {
  try {
    const url = new URL(value);
    const loopback = url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if ((url.protocol !== 'https:' && !loopback) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error();
    return url.origin;
  } catch { throw new ActivationControllerError('TRANSPORT'); }
}
const apiErrorSchema = z.strictObject({ error: z.strictObject({
  code: z.string().max(128), message: z.string().max(1024), requestId: z.string().max(128),
}) });
/** Only known status/code pairs become actionable; remote text never enters an error. */
function responseError(status: number, body: unknown): ActivationControllerError {
  const parsed = apiErrorSchema.safeParse(body);
  const code = parsed.success ? parsed.data.error.code : undefined;
  if (status === 410 && code === 'ACTIVATION_EXPIRED') return new ActivationControllerError('EXPIRED');
  if (status === 429 && code === 'RATE_LIMITED') return new ActivationControllerError('RATE_LIMITED');
  if (status === 503 && code === 'SETUP_UNAVAILABLE') return new ActivationControllerError('UNAVAILABLE');
  if (status === 401 && (code === 'SETUP_PROOF_INVALID' || code === 'AUTHENTICATION_FAILED')) return new ActivationControllerError('PROOF_REQUIRED');
  if (status === 409 && (code === 'DRAFT_CONFLICT' || code === 'OPERATION_CONFLICT')) return new ActivationControllerError('CONFLICT');
  return new ActivationControllerError('TRANSPORT');
}

/** Fetch supplies TLS authentication outside loopback; redirects and cross-origin browser use are rejected. */
export class HttpActivationTransport implements ActivationTransport {
  readonly origin: string;
  constructor(origin: string, private readonly fetcher: typeof fetch = globalThis.fetch) {
    this.origin = secureOrigin(origin);
    if (globalThis.location && globalThis.location.origin !== this.origin) throw new ActivationControllerError('TRANSPORT');
  }
  private async post<T>(path: string, body: unknown, schema: z.ZodType<T>, resumeToken?: string): Promise<T> {
    const url = `${this.origin}/v1/activation/${path}`;
    const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (resumeToken !== undefined) headers.Authorization = `Setup ${parse(binary(32), resumeToken)}`;
    let response: Response;
    let value: unknown;
    try {
      response = await this.fetcher.call(globalThis, url, { method: 'POST', headers, body: canonicalJson(body),
        credentials: 'omit', mode: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'strict-origin' });
      if (response.redirected || response.url !== url || !response.headers.get('content-type')?.startsWith('application/json')) throw new Error();
      const text = await response.text();
      if (text.length > 262_144) throw new Error();
      value = parseJsonStrict(text);
    } catch { throw new ActivationControllerError('TRANSPORT'); }
    if (!response.ok) throw responseError(response.status, value);
    return parse(schema, value, 'TRANSPORT');
  }
  private path(activationId: string, action: string) { return `${parse(identifier, activationId)}/${action}`; }
  reserve(input: { licenceKey: string; operationId: string; resumeToken: string }) { return this.post('reserve', input, statusSchema); }
  status(id: string, token: string) { return this.post(this.path(id, 'status'), {}, statusSchema, token); }
  registration(id: string, token: string, input: { draftGeneration: string; registrationRequest: string }) { return this.post(this.path(id, 'registration'), input, registrationSchema, token); }
  startProof(id: string, token: string, input: { draftGeneration: string; payload: ActivationPayload; startLoginRequest: string }) { return this.post(this.path(id, 'proof/start'), input, proofSchema, token); }
  finishProof(id: string, token: string, input: { draftGeneration: string; proofId: string; finishLoginRequest: string }) { return this.post(this.path(id, 'proof/finish'), input, z.strictObject({ verified: z.literal(true) }), token); }
  finalize(id: string, token: string, input: { draftGeneration: string; requestHash: string }) { return this.post(this.path(id, 'finalize'), input, finalSchema, token); }
  replaceDraft(id: string, token: string, input: { expectedDraftGeneration: string; operationId: string }) { return this.post(this.path(id, 'replace-draft'), input, statusSchema, token); }
}

const draftSchema = z.strictObject({
  payload: activationPayload, wrapper: deviceWrapper, context: deviceContext,
  requestHash: digest, genesisFingerprint: digest, wrapperHash: digest, verified: z.boolean(),
});
const pendingSchema = z.strictObject({
  version: z.literal(1), operationId: identifier, resumeToken: binary(32), origin: z.string(),
  status: statusSchema.optional(), draft: draftSchema.optional(),
  candidateDeviceId: identifier.optional(),
  replacement: z.strictObject({ operationId: identifier, expectedDraftGeneration: positiveCounter }).optional(),
});
export type PendingActivation = z.infer<typeof pendingSchema>;
const pendingMetadataSchema = pendingSchema.omit({ draft: true });
type PendingMetadata = z.infer<typeof pendingMetadataSchema>;
function metadata(value: unknown): PendingMetadata {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ActivationControllerError('STORAGE');
  const { draft: _draft, ...fields } = value as Record<string, unknown>;
  return parse(pendingMetadataSchema, fields, 'STORAGE');
}

/**
 * Origin-scoped setup capability and public/encrypted draft only. The resume token
 * authorizes the short-lived server setup reservation; it is not a login session.
 * No password, phrase, export key, plaintext names or private keys are persisted.
 */
export class IndexedActivationStore {
  private closed = false;
  private constructor(private readonly database: IDBDatabase) {
    database.onversionchange = () => this.close(); database.onclose = () => { this.closed = true; };
  }
  static async open(name = 'ukda-activation-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedActivationStore> {
    if (!factory) throw new ActivationControllerError('UNAVAILABLE');
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = () => { settled = true; reject(new ActivationControllerError('STORAGE')); };
      let request: IDBOpenDBRequest;
      try { request = factory.open(name, 1); } catch { fail(); return; }
      request.onerror = fail; request.onblocked = fail;
      request.onupgradeneeded = () => { request.result.createObjectStore('pending', { keyPath: 'operationId' }); };
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedActivationStore(request.result)); };
    });
  }
  private run<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore, result: (value: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    if (this.closed) return Promise.reject(new ActivationControllerError('STORAGE'));
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction;
      try { transaction = this.database.transaction('pending', mode, { durability: 'strict' }); }
      catch { reject(new ActivationControllerError('STORAGE')); return; }
      let result: T; let provided = false; let failure: ActivationControllerError | undefined;
      const fail = (error: unknown) => {
        failure = error instanceof ActivationControllerError ? error : new ActivationControllerError('STORAGE');
        try { transaction.abort(); } catch { reject(failure); }
      };
      transaction.onabort = () => reject(failure ?? new ActivationControllerError('STORAGE'));
      transaction.oncomplete = () => provided ? resolve(result) : reject(new ActivationControllerError('STORAGE'));
      try { action(transaction.objectStore('pending'), (value) => { result = value; provided = true; }, fail); } catch (error) { fail(error); }
    });
  }
  get(operationId: string): Promise<PendingActivation | undefined> {
    const id = parse(identifier, operationId);
    return this.run('readonly', (store, result, fail) => {
      const request = store.get(id);
      request.onsuccess = () => { try { result(request.result === undefined ? undefined : parse(pendingSchema, request.result, 'STORAGE')); } catch (error) { fail(error); } };
    });
  }
  /** Safe operation discovery with last saved status; call resume for current server status. */
  list(): Promise<Array<{ operationId: string; origin: string; state: string }>> {
    return this.run('readonly', (store, result, fail) => {
      const request = store.getAll();
      request.onsuccess = () => {
        try { result((request.result as unknown[]).map((value) => {
          const record = metadata(value);
          return { operationId: record.operationId, origin: record.origin, state: record.replacement ? 'replacing_draft' : record.status?.state ?? 'reserving' };
        })); } catch (error) { fail(error); }
      };
    });
  }
  /** Recovery authority remains readable even when the separately validated draft is corrupt. */
  recovery(operationId: string): Promise<PendingMetadata | undefined> {
    const id = parse(identifier, operationId);
    return this.run('readonly', (store, result, fail) => {
      const request = store.get(id);
      request.onsuccess = () => { try { result(request.result === undefined ? undefined : metadata(request.result)); } catch (error) { fail(error); } };
    });
  }
  saveMetadata(previous: PendingMetadata, next: PendingMetadata, discardDraft = false): Promise<void> {
    const before = parse(pendingMetadataSchema, previous); const accepted = parse(pendingMetadataSchema, next);
    if (before.operationId !== accepted.operationId) throw new ActivationControllerError('CONFLICT');
    return this.run('readwrite', (store, result, fail) => {
      const request = store.get(accepted.operationId);
      request.onsuccess = () => {
        try {
          if (canonicalJson(metadata(request.result)) !== canonicalJson(before)) throw new ActivationControllerError('CONFLICT');
          const draft = (request.result as Record<string, unknown>).draft;
          store.put({ ...accepted, ...(!discardDraft && draft !== undefined ? { draft } : {}) }); result(undefined);
        } catch (error) { fail(error); }
      };
    });
  }
  /** Compare-and-swap prevents another tab from replacing an established draft. */
  save(previous: PendingActivation | undefined, next: PendingActivation): Promise<void> {
    const before = previous === undefined ? undefined : parse(pendingSchema, previous);
    const accepted = parse(pendingSchema, next);
    if (before && before.operationId !== accepted.operationId) throw new ActivationControllerError('CONFLICT');
    return this.run('readwrite', (store, result, fail) => {
      const request = store.get(accepted.operationId);
      request.onsuccess = () => {
        try {
          const current = request.result === undefined ? undefined : parse(pendingSchema, request.result, 'STORAGE');
          if ((current === undefined) !== (before === undefined) || (current && canonicalJson(current) !== canonicalJson(before))) throw new ActivationControllerError('CONFLICT');
          store.put(accepted); result(undefined);
        } catch (error) { fail(error); }
      };
    });
  }
  /** Explicit Forget removes encrypted wrapper copies even if the draft itself is corrupt. */
  forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    const accepted = parse(z.strictObject({ workspaceId: identifier, accountId: identifier, deviceId: identifier }), reference);
    return this.run('readwrite', (store, result, fail) => {
      const request = store.openCursor();
      request.onsuccess = () => {
        try {
          const cursor = request.result;
          if (!cursor) { result(undefined); return; }
          const record = metadata(cursor.value);
          const deviceId = record.candidateDeviceId ?? record.status?.receipt?.deviceId;
          if (record.status?.workspaceId === accepted.workspaceId && record.status.accountId === accepted.accountId && deviceId === accepted.deviceId) cursor.delete();
          cursor.continue();
        } catch (error) { fail(error); }
      };
    });
  }
  close() { this.closed = true; this.database.close(); }
}

/** Password operations belong in a dedicated browser worker; no UI or session is created. */
export class ActivationController {
  readonly origin: string;
  private readonly forgottenDevices = new Set<string>();
  constructor(private readonly transport: ActivationTransport, private readonly pending: IndexedActivationStore, private readonly devices: IndexedDeviceStore,
    private readonly options: { onVerifiedReceipt?: (receipt: ActivationReceipt, genesis: ActivationPayload['genesis']) => Promise<void> } = {}) {
    this.origin = secureOrigin(transport.origin);
  }
  private assertNotForgotten(context: Pick<DeviceContext, 'workspaceId' | 'accountId' | 'deviceId'>) {
    if (this.forgottenDevices.has(`${context.workspaceId}:${context.accountId}:${context.deviceId}`)) throw new ActivationControllerError('CONFLICT');
  }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    const accepted = parse(z.strictObject({ workspaceId: identifier, accountId: identifier, deviceId: identifier }), reference);
    this.forgottenDevices.add(`${accepted.workspaceId}:${accepted.accountId}:${accepted.deviceId}`);
    await this.pending.forgetDevice(accepted);
  }
  attachAuthLifecycle(auth: { onForget(forget: (reference: { workspaceId: string; accountId: string; deviceId: string }) => Promise<void>): () => void }): () => void {
    return auth.onForget((reference) => this.forgetDevice(reference));
  }
  private async load(operationId: string): Promise<PendingActivation> {
    const record = await this.pending.get(operationId);
    if (!record || record.origin !== this.origin) throw new ActivationControllerError('INVALID_STATE');
    return record;
  }
  /** Persist the operation and resume capability before the first network request. */
  async create(): Promise<string> {
    const bytes = await randomKey();
    try {
      const operationId = crypto.randomUUID();
      await this.pending.save(undefined, { version: 1, operationId, resumeToken: base64urlEncode(bytes), origin: this.origin });
      return operationId;
    } finally { bytes.fill(0); }
  }
  private checkStatus(record: PendingActivation, value: unknown): ActivationStatus {
    const status = parse(statusSchema, value, 'RECEIPT_MISMATCH');
    if (status.operationId !== record.operationId) throw new ActivationControllerError('RECEIPT_MISMATCH');
    if (record.status) {
      for (const field of ['activationId', 'workspaceId', 'accountId', 'reservationGeneration', 'draftGeneration'] as const) {
        if (status[field] !== record.status[field]) throw new ActivationControllerError('CONFLICT');
      }
    }
    return status;
  }
  async reserve(operationId: string, licenceKey: string): Promise<ActivationStatus> {
    const record = await this.load(operationId);
    if (record.status) return this.checkStatus(record, await this.transport.status(record.status.activationId, record.resumeToken));
    const status = this.checkStatus(record, await this.transport.reserve({ licenceKey, operationId, resumeToken: record.resumeToken }));
    await this.pending.save(record, { ...record, status });
    return status;
  }
  private binding(record: PendingActivation) {
    if (!record.status) throw new ActivationControllerError('INVALID_STATE');
    const { activationId, operationId, workspaceId, accountId, reservationGeneration, draftGeneration } = record.status;
    return parse(activationBinding, { activationId, operationId, workspaceId, accountId, reservationGeneration, draftGeneration, origin: this.origin });
  }
  private checkConfiguration(configuration: OpaquePublicConfiguration, record: PendingActivation) {
    const accepted = parse(configurationSchema, configuration, 'RECEIPT_MISMATCH');
    const binding = this.binding(record);
    if (accepted.identifiers.client !== `ukda:${binding.workspaceId}:${binding.accountId}`) throw new ActivationControllerError('RECEIPT_MISMATCH');
    return accepted;
  }
  /** Returns the recovery kit in memory only. The caller must arrange the user's backup. */
  async prepare(operationId: string, input: {
    password: string; confirmation: string; phrase: string; challengePositions: readonly number[];
    challengeAnswers: readonly string[]; displayName: string; workspaceName: string;
  }) {
    const record = await this.load(operationId);
    if (!record.status || record.status.state !== 'reserved' || record.draft || record.replacement) throw new ActivationControllerError('CONFLICT');
    const binding = this.binding(record);
    const started = await beginActivationPassword(input.password, input.confirmation);
    const response = parse(registrationSchema, await this.transport.registration(binding.activationId, record.resumeToken,
      { draftGeneration: binding.draftGeneration, registrationRequest: started.registrationRequest }), 'RECEIPT_MISMATCH');
    const configuration = this.checkConfiguration(response.configuration, record);
    const registered = await finishRegistration({ password: input.password, clientRegistrationState: started.clientRegistrationState,
      registrationResponse: response.registrationResponse, configuration });
    const prepared = await prepareOwnerActivation({ ...input, binding, configuration, registrationRecord: registered.registrationRecord, exportKey: registered.exportKey });
    const verified = await validateActivationPayload(prepared.payload, binding, configuration);
    const context: DeviceContext = { workspaceId: binding.workspaceId, accountId: binding.accountId, deviceId: prepared.payload.genesis.body.device.id, credentialGeneration: '1' };
    const draft = { payload: prepared.payload, wrapper: prepared.deviceWrapper, context, requestHash: verified.requestHash,
      genesisFingerprint: verified.genesisFingerprint, wrapperHash: await digestObject(prepared.deviceWrapper), verified: false };
    const staged = { ...record, draft, candidateDeviceId: context.deviceId };
    this.assertNotForgotten(context);
    // Write the encrypted draft first so interruption before the device transaction is recoverable.
    await this.pending.save(record, staged);
    await this.verifyLocal(staged, registered.exportKey);
    await this.pending.save(staged, { ...staged, draft: { ...draft, verified: true } });
    return prepared.recoveryKit;
  }
  private async validateDraft(record: PendingActivation) {
    const draft = record.draft;
    if (!draft) throw new ActivationControllerError('INVALID_STATE');
    const validated = await validateActivationPayload(draft.payload, this.binding(record), draft.payload.genesis.body.opaque);
    const body = draft.payload.genesis.body;
    if (validated.requestHash !== draft.requestHash || validated.genesisFingerprint !== draft.genesisFingerprint ||
      await digestObject(draft.wrapper) !== draft.wrapperHash || draft.context.workspaceId !== body.workspaceId ||
      draft.context.accountId !== body.accountId || draft.context.deviceId !== body.device.id || draft.context.credentialGeneration !== '1') throw new ActivationControllerError('LOCAL_VERIFICATION');
    return draft;
  }
  private async storedWrapper(record: PendingActivation) {
    const draft = await this.validateDraft(record);
    this.assertNotForgotten(draft.context);
    await this.devices.stage(draft.wrapper, record.operationId);
    const wrapper = await this.devices.getStaged(record.operationId);
    if (!wrapper || await digestObject(wrapper) !== draft.wrapperHash) throw new ActivationControllerError('LOCAL_VERIFICATION');
    return wrapper;
  }
  private async verifyLocal(record: PendingActivation, exportKey: string) {
    const wrapper = await this.storedWrapper(record);
    const draft = record.draft!;
    const bundle = await unwrapDeviceBundle(draft.context, wrapper, exportKey);
    if (bundle.signingPublicKey !== draft.payload.genesis.body.device.signingPublicKey || bundle.recipientPublicKey !== draft.payload.genesis.body.device.recipientPublicKey) throw new ActivationControllerError('LOCAL_VERIFICATION');
  }
  private async promote(record: PendingActivation, value: unknown): Promise<ActivationResult> {
    const result = parse(finalSchema, value, 'RECEIPT_MISMATCH');
    const draft = await this.validateDraft(record);
    const receipt = result.receipt;
    if (!draft.verified || receipt.operationId !== record.operationId || receipt.genesisFingerprint !== draft.genesisFingerprint ||
      receipt.securityHead !== draft.genesisFingerprint || receipt.workspaceId !== draft.context.workspaceId || receipt.accountId !== draft.context.accountId ||
      receipt.deviceId !== draft.context.deviceId || receipt.credentialGeneration !== draft.context.credentialGeneration) throw new ActivationControllerError('RECEIPT_MISMATCH');
    await this.storedWrapper(record);
    await this.devices.commit(record.operationId, { ...draft.context, operationId: record.operationId });
    await this.options.onVerifiedReceipt?.(receipt, draft.payload.genesis);
    return result;
  }
  /** Reuses the persisted payload/hash; an uncertain response is recovered through resume(). */
  async activate(operationId: string, password: string): Promise<ActivationResult> {
    let record = await this.load(operationId);
    if (record.replacement) throw new ActivationControllerError('CONFLICT');
    const status = this.checkStatus(record, await this.transport.status(this.binding(record).activationId, record.resumeToken));
    if (status.state === 'completed' || status.state === 'finishing_setup') return this.promote(record, { state: status.state, receipt: status.receipt });
    if (status.state !== 'reserved') throw new ActivationControllerError('INVALID_STATE');
    const draft = await this.validateDraft(record);
    const binding = this.binding(record);
    const started = await startLogin(password);
    const proof = parse(proofSchema, await this.transport.startProof(binding.activationId, record.resumeToken,
      { draftGeneration: binding.draftGeneration, payload: draft.payload, startLoginRequest: started.startLoginRequest }), 'RECEIPT_MISMATCH');
    if (proof.requestHash !== draft.requestHash || canonicalJson(this.checkConfiguration(proof.configuration, record)) !== canonicalJson(draft.payload.genesis.body.opaque)) throw new ActivationControllerError('RECEIPT_MISMATCH');
    const finished = await finishLogin({ password, clientLoginState: started.clientLoginState, loginResponse: proof.loginResponse, configuration: proof.configuration });
    await this.verifyLocal(record, finished.exportKey);
    if (!draft.verified) {
      const next = { ...record, draft: { ...draft, verified: true } };
      await this.pending.save(record, next); record = next;
    }
    parse(z.strictObject({ verified: z.literal(true) }), await this.transport.finishProof(binding.activationId, record.resumeToken,
      { draftGeneration: binding.draftGeneration, proofId: proof.proofId, finishLoginRequest: finished.finishLoginRequest }), 'RECEIPT_MISMATCH');
    return this.promote(record, await this.transport.finalize(binding.activationId, record.resumeToken,
      { draftGeneration: binding.draftGeneration, requestHash: draft.requestHash }));
  }
  /**
   * A committed result needs no password/session; unfinished setup requires re-entry.
   * An expired capability never implies the licence can be redeemed again. After
   * the 24-hour completion recovery window, use normal login or Owner recovery.
   * Preserve every local wrapper on expiry; do not retry or replace automatically.
   */
  async resume(operationId: string, password?: string): Promise<ActivationResult | { state: 'password_required' | 'prepare_required' | 'reserve_required' | 'expired' | 'cancelled' }> {
    const record = await this.load(operationId);
    try {
      if (record.replacement) { await this.replaceDraft(operationId); return { state: 'prepare_required' }; }
      if (!record.status) return { state: 'reserve_required' };
      const status = this.checkStatus(record, await this.transport.status(record.status.activationId, record.resumeToken));
      if (status.state === 'completed' || status.state === 'finishing_setup') return await this.promote(record, { state: status.state, receipt: status.receipt });
      if (status.state === 'expired' || status.state === 'cancelled') return { state: status.state };
      if (!record.draft) return { state: 'prepare_required' };
      if (password === undefined) return { state: 'password_required' };
      return await this.activate(operationId, password);
    } catch (error) {
      if (error instanceof ActivationControllerError && error.code === 'EXPIRED') return { state: 'expired' };
      throw error;
    }
  }
  /** Replace only a confirmed uncommitted server draft, retaining retry identity across crashes. */
  async replaceDraft(operationId: string): Promise<ActivationStatus> {
    let record = await this.pending.recovery(operationId);
    if (!record?.status || record.origin !== this.origin) throw new ActivationControllerError('INVALID_STATE');
    const status = parse(statusSchema, await this.transport.status(record.status.activationId, record.resumeToken), 'RECEIPT_MISMATCH');
    for (const field of ['operationId', 'activationId', 'workspaceId', 'accountId', 'reservationGeneration'] as const) {
      if (status[field] !== record.status[field]) throw new ActivationControllerError('RECEIPT_MISMATCH');
    }
    if (status.state === 'completed' || status.state === 'finishing_setup') throw new ActivationControllerError('ALREADY_COMMITTED');
    if (status.state !== 'reserved') throw new ActivationControllerError('INVALID_STATE');
    if (!record.replacement) {
      if (status.draftGeneration !== record.status.draftGeneration) throw new ActivationControllerError('CONFLICT');
      const next = { ...record, replacement: { operationId: crypto.randomUUID(), expectedDraftGeneration: status.draftGeneration } };
      await this.pending.saveMetadata(record, next); record = next;
    }
    const replacement = record.replacement!;
    const expected = (BigInt(replacement.expectedDraftGeneration) + 1n).toString();
    if (![replacement.expectedDraftGeneration, expected].includes(status.draftGeneration)) throw new ActivationControllerError('CONFLICT');
    const replaced = parse(statusSchema, await this.transport.replaceDraft(status.activationId, record.resumeToken, replacement), 'RECEIPT_MISMATCH');
    for (const field of ['operationId', 'activationId', 'workspaceId', 'accountId', 'reservationGeneration'] as const) {
      if (replaced[field] !== status[field]) throw new ActivationControllerError('RECEIPT_MISMATCH');
    }
    if (replaced.state !== 'reserved' || replaced.draftGeneration !== expected) throw new ActivationControllerError('RECEIPT_MISMATCH');
    if (record.candidateDeviceId) await this.devices.discardUncommitted(operationId, record.candidateDeviceId);
    const { replacement: _replacement, candidateDeviceId: _candidateDeviceId, ...preserved } = record;
    await this.pending.saveMetadata(record, { ...preserved, status: replaced }, true);
    return replaced;
  }
}

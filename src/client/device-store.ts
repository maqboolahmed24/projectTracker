import sodium from 'libsodium-wrappers';
import { z } from 'zod';
import { binary, identifier, positiveCounter } from '../shared/contracts.js';
import { base64urlDecode, base64urlEncode, canonicalJson, deriveKey, HKDF_SALT, ready } from '../shared/crypto.js';
import { parseJsonStrict } from '../shared/json.js';

const WRAP_PURPOSE = 'ukda.device-wrap.v1' as const;
const LOCAL_PURPOSE = 'ukda.local-device.v1' as const;
const utf8 = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const deviceContext = z.strictObject({
  workspaceId: identifier, accountId: identifier, deviceId: identifier,
  credentialGeneration: positiveCounter,
});
export type DeviceContext = z.infer<typeof deviceContext>;

export const deviceBundle = z.strictObject({
  signingPrivateKey: binary(64), recipientPrivateKey: binary(32),
  signingPublicKey: binary(32), recipientPublicKey: binary(32),
});
export type DeviceBundle = z.infer<typeof deviceBundle>;

const deviceHeader = deviceContext.extend({
  version: z.literal(1), purpose: z.literal(LOCAL_PURPOSE),
  derivation: z.strictObject({ salt: z.literal(HKDF_SALT), purpose: z.literal(WRAP_PURPOSE) }),
});
export const deviceWrapper = z.strictObject({
  header: deviceHeader, nonce: binary(24), ciphertext: binary(16, 4096),
});
export type DeviceWrapper = z.infer<typeof deviceWrapper>;

/** The caller must verify this context against the authoritative server receipt. */
export const deviceCommitConfirmation = deviceContext.extend({ operationId: identifier });
export type DeviceCommitConfirmation = z.infer<typeof deviceCommitConfirmation>;

type ErrorCode = 'INVALID_CONTEXT' | 'INVALID_BUNDLE' | 'INVALID_WRAPPER' | 'UNLOCK_FAILED'
  | 'UNAVAILABLE' | 'STORAGE_FAILED' | 'CORRUPT_STORAGE' | 'CONFLICT' | 'NOT_FOUND' | 'RECEIPT_MISMATCH' | 'CLOSED';

export class DeviceStoreError extends Error {
  constructor(readonly code: ErrorCode) {
    super(`Device storage operation failed (${code})`);
    this.name = 'DeviceStoreError';
  }
}

/** Snapshot before awaiting: getters, extra fields, and caller mutation are rejected. */
function parsed<T>(schema: z.ZodType<T>, input: unknown, code: ErrorCode): T {
  try { return schema.parse(parseJsonStrict(canonicalJson(input))); }
  catch { throw new DeviceStoreError(code); }
}

function exportBytes(exportKey: string | Uint8Array): Uint8Array {
  try {
    if (!(exportKey instanceof Uint8Array) && typeof exportKey !== 'string') throw new Error();
    const bytes = typeof exportKey === 'string' ? base64urlDecode(exportKey) : new Uint8Array(exportKey);
    if (bytes.length < 32 || bytes.length > 1024) { bytes.fill(0); throw new Error(); }
    return bytes;
  } catch { throw new DeviceStoreError('UNLOCK_FAILED'); }
}

function headerFor(context: DeviceContext): DeviceWrapper['header'] {
  return { ...context, version: 1, purpose: LOCAL_PURPOSE, derivation: { salt: HKDF_SALT, purpose: WRAP_PURPOSE } };
}

/** Do not accept well-sized but internally inconsistent signing/recipient pairs. */
function checkKeyPairs(bundle: DeviceBundle): void {
  const signing = base64urlDecode(bundle.signingPrivateKey, 64);
  const recipient = base64urlDecode(bundle.recipientPrivateKey, 32);
  let expectedSigning: { publicKey: Uint8Array; privateKey: Uint8Array } | undefined;
  try {
    expectedSigning = sodium.crypto_sign_seed_keypair(signing.subarray(0, 32));
    if (!sodium.memcmp(signing, expectedSigning.privateKey)
      || !sodium.memcmp(base64urlDecode(bundle.signingPublicKey, 32), expectedSigning.publicKey)
      || !sodium.memcmp(base64urlDecode(bundle.recipientPublicKey, 32), sodium.crypto_scalarmult_base(recipient))) {
      throw new DeviceStoreError('INVALID_BUNDLE');
    }
  } finally {
    signing.fill(0); recipient.fill(0); expectedSigning?.privateKey.fill(0);
  }
}

/** Only the returned ciphertext wrapper may be persisted; never persist exportKey. */
export async function wrapDeviceBundle(context: DeviceContext, bundle: DeviceBundle, exportKey: string | Uint8Array): Promise<DeviceWrapper> {
  const acceptedContext = parsed(deviceContext, context, 'INVALID_CONTEXT');
  const acceptedBundle = parsed(deviceBundle, bundle, 'INVALID_BUNDLE');
  const source = exportBytes(exportKey);
  let wrappingKey: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    await ready;
    checkKeyPairs(acceptedBundle);
    wrappingKey = await deriveKey(source, { version: 1, purpose: WRAP_PURPOSE, workspaceId: acceptedContext.workspaceId, accountId: acceptedContext.accountId });
    const header = headerFor(acceptedContext);
    const nonce = sodium.randombytes_buf(24);
    plaintext = utf8.encode(canonicalJson(acceptedBundle));
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, canonicalJson(header), null, nonce, wrappingKey);
    return { header, nonce: base64urlEncode(nonce), ciphertext: base64urlEncode(ciphertext) };
  } catch (error) {
    if (error instanceof DeviceStoreError) throw error;
    throw new DeviceStoreError('UNLOCK_FAILED');
  } finally {
    source.fill(0); wrappingKey?.fill(0); plaintext?.fill(0);
  }
}

/** expected context must come from the selected account/device and current receipt. */
export async function unwrapDeviceBundle(context: DeviceContext, wrapper: DeviceWrapper, exportKey: string | Uint8Array): Promise<DeviceBundle> {
  const acceptedContext = parsed(deviceContext, context, 'INVALID_CONTEXT');
  const accepted = parsed(deviceWrapper, wrapper, 'INVALID_WRAPPER');
  if (canonicalJson(accepted.header) !== canonicalJson(headerFor(acceptedContext))) throw new DeviceStoreError('INVALID_WRAPPER');
  const source = exportBytes(exportKey);
  let wrappingKey: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    await ready;
    wrappingKey = await deriveKey(source, { version: 1, purpose: WRAP_PURPOSE, workspaceId: acceptedContext.workspaceId, accountId: acceptedContext.accountId });
    plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, base64urlDecode(accepted.ciphertext), canonicalJson(accepted.header), base64urlDecode(accepted.nonce, 24), wrappingKey);
    const bundle = parsed(deviceBundle, parseJsonStrict(decoder.decode(plaintext)), 'INVALID_BUNDLE');
    checkKeyPairs(bundle);
    return bundle;
  } catch {
    throw new DeviceStoreError('UNLOCK_FAILED');
  } finally {
    source.fill(0); wrappingKey?.fill(0); plaintext?.fill(0);
  }
}

const storedCandidate = z.strictObject({
  candidateId: identifier, deviceKey: z.string(), generationKey: z.string(), wrapper: deviceWrapper,
});
type StoredCandidate = z.infer<typeof storedCandidate>;
const activePointer = z.strictObject({ deviceKey: z.string(), candidateId: identifier, context: deviceContext });
type ActivePointer = z.infer<typeof activePointer>;
const deviceKey = (context: Pick<DeviceContext, 'workspaceId' | 'accountId' | 'deviceId'>) => `${context.workspaceId}:${context.accountId}:${context.deviceId}`;
const generationKey = (context: DeviceContext) => `${deviceKey(context)}:${context.credentialGeneration}`;
const contextOf = (wrapper: DeviceWrapper): DeviceContext => ({
  workspaceId: wrapper.header.workspaceId, accountId: wrapper.header.accountId,
  deviceId: wrapper.header.deviceId, credentialGeneration: wrapper.header.credentialGeneration,
});
const sameContext = (one: DeviceContext, two: DeviceContext) => canonicalJson(one) === canonicalJson(two);

function readCandidate(value: unknown): StoredCandidate | undefined {
  if (value === undefined) return undefined;
  const accepted = parsed(storedCandidate, value, 'CORRUPT_STORAGE');
  const context = contextOf(accepted.wrapper);
  if (accepted.deviceKey !== deviceKey(context) || accepted.generationKey !== generationKey(context)) throw new DeviceStoreError('CORRUPT_STORAGE');
  return accepted;
}

function readActive(value: unknown, key: string): ActivePointer | undefined {
  if (value === undefined) return undefined;
  const accepted = parsed(activePointer, value, 'CORRUPT_STORAGE');
  if (accepted.deviceKey !== key || deviceKey(accepted.context) !== key) throw new DeviceStoreError('CORRUPT_STORAGE');
  return accepted;
}

type Fail = (error: unknown) => void;

/** Native IndexedDB; inject a standards-compatible factory only for isolated tests. */
export class IndexedDeviceStore {
  private closed = false;
  private constructor(private readonly database: IDBDatabase) {
    database.onversionchange = () => this.close();
    database.onclose = () => { this.closed = true; };
  }

  static async open(databaseName = 'ukda-device-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedDeviceStore> {
    if (!factory || typeof factory.open !== 'function') throw new DeviceStoreError('UNAVAILABLE');
    return new Promise((resolve, reject) => {
      let settled = false;
      let request: IDBOpenDBRequest;
      const unavailable = () => {
        if (!settled) { settled = true; reject(new DeviceStoreError('UNAVAILABLE')); }
      };
      try { request = factory.open(databaseName, 1); }
      catch { unavailable(); return; }
      request.onblocked = unavailable;
      request.onerror = unavailable;
      request.onupgradeneeded = () => {
        try {
          const candidates = request.result.createObjectStore('candidates', { keyPath: 'candidateId' });
          candidates.createIndex('deviceKey', 'deviceKey');
          candidates.createIndex('generationKey', 'generationKey');
          request.result.createObjectStore('active', { keyPath: 'deviceKey' });
        } catch { request.transaction?.abort(); unavailable(); }
      };
      request.onsuccess = () => {
        if (settled) { request.result.close(); return; }
        settled = true;
        resolve(new IndexedDeviceStore(request.result));
      };
    });
  }

  /** Resolves only after the transaction completes, never at request success. */
  private transaction<T>(stores: string[], mode: IDBTransactionMode, action: (transaction: IDBTransaction, result: (value: T) => void, fail: Fail) => void): Promise<T> {
    if (this.closed) return Promise.reject(new DeviceStoreError('CLOSED'));
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction;
      try { transaction = this.database.transaction(stores, mode, mode === 'readwrite' ? { durability: 'strict' } : {}); }
      catch { reject(new DeviceStoreError('STORAGE_FAILED')); return; }
      let value: T;
      let hasResult = false;
      let failure: DeviceStoreError | undefined;
      const fail: Fail = (error) => {
        failure = error instanceof DeviceStoreError ? error : new DeviceStoreError('STORAGE_FAILED');
        try { transaction.abort(); } catch { reject(failure); }
      };
      transaction.onabort = () => reject(failure ?? new DeviceStoreError('STORAGE_FAILED'));
      transaction.onerror = () => { /* Leave the default abort behaviour intact. */ };
      transaction.oncomplete = () => hasResult ? resolve(value) : reject(new DeviceStoreError('STORAGE_FAILED'));
      try { action(transaction, (result) => { value = result; hasResult = true; }, fail); }
      catch (error) { fail(error); }
    });
  }

  private candidate(store: IDBObjectStore, id: string, consume: (candidate: StoredCandidate | undefined) => void, fail: Fail): void {
    const request = store.get(id);
    request.onsuccess = () => { try { consume(readCandidate(request.result)); } catch (error) { fail(error); } };
  }

  /** Use the server operation ID as candidateId; retain it across lost responses. */
  async stage(wrapper: DeviceWrapper, candidateId: string = globalThis.crypto.randomUUID()): Promise<string> {
    const accepted = parsed(deviceWrapper, wrapper, 'INVALID_WRAPPER');
    const id = parsed(identifier, candidateId, 'INVALID_CONTEXT');
    const context = contextOf(accepted);
    const candidate: StoredCandidate = { candidateId: id, deviceKey: deviceKey(context), generationKey: generationKey(context), wrapper: accepted };
    return this.transaction(['candidates'], 'readwrite', (transaction, result, fail) => {
      const store = transaction.objectStore('candidates');
      this.candidate(store, id, (existing) => {
        if (existing && canonicalJson(existing) !== canonicalJson(candidate)) throw new DeviceStoreError('CONFLICT');
        if (!existing) store.add(candidate);
        result(id);
      }, fail);
    });
  }

  /** Caller must unwrap this read-back before sending the server finalisation. */
  async getStaged(candidateId: string): Promise<DeviceWrapper | undefined> {
    const id = parsed(identifier, candidateId, 'INVALID_CONTEXT');
    return this.transaction(['candidates'], 'readonly', (transaction, result, fail) => {
      this.candidate(transaction.objectStore('candidates'), id, (candidate) => result(candidate?.wrapper), fail);
    });
  }

  async getActive(workspaceId: string, accountId: string, deviceId: string): Promise<DeviceWrapper | undefined> {
    const context = parsed(deviceContext, { workspaceId, accountId, deviceId, credentialGeneration: '1' }, 'INVALID_CONTEXT');
    const key = deviceKey(context);
    return this.transaction(['candidates', 'active'], 'readonly', (transaction, result, fail) => {
      const request = transaction.objectStore('active').get(key);
      request.onsuccess = () => {
        try {
          const active = readActive(request.result, key);
          if (!active) { result(undefined); return; }
          this.candidate(transaction.objectStore('candidates'), active.candidateId, (candidate) => {
            if (!candidate || !sameContext(contextOf(candidate.wrapper), active.context)) throw new DeviceStoreError('CORRUPT_STORAGE');
            result(candidate.wrapper);
          }, fail);
        } catch (error) { fail(error); }
      };
    });
  }

  /** Exact generation lookup. Ambiguous uncommitted drafts need their receipt ID. */
  async get(context: DeviceContext): Promise<DeviceWrapper | undefined> {
    const accepted = parsed(deviceContext, context, 'INVALID_CONTEXT');
    return this.transaction(['candidates', 'active'], 'readonly', (transaction, result, fail) => {
      const store = transaction.objectStore('candidates');
      const activeRequest = transaction.objectStore('active').get(deviceKey(accepted));
      activeRequest.onsuccess = () => {
        try {
          const active = readActive(activeRequest.result, deviceKey(accepted));
          if (active && sameContext(active.context, accepted)) {
            this.candidate(store, active.candidateId, (candidate) => {
              if (!candidate || !sameContext(contextOf(candidate.wrapper), accepted)) throw new DeviceStoreError('CORRUPT_STORAGE');
              result(candidate.wrapper);
            }, fail);
            return;
          }
          const request = store.index('generationKey').getAll(generationKey(accepted));
          request.onsuccess = () => {
            try {
              const candidates = (request.result as unknown[]).map(readCandidate);
              if (candidates.length > 1) throw new DeviceStoreError('CONFLICT');
              const candidate = candidates[0];
              if (candidate && !sameContext(contextOf(candidate.wrapper), accepted)) throw new DeviceStoreError('CORRUPT_STORAGE');
              result(candidate?.wrapper);
            } catch (error) { fail(error); }
          };
        } catch (error) { fail(error); }
      };
    });
  }

  /**
   * Promote only after read-back verification and an authenticated successful receipt.
   * This store checks receipt context, not network/server authenticity. No drafts are
   * pruned here: a lost acknowledgement must not destroy either credential wrapper.
   */
  async commit(candidateId: string, confirmation: DeviceCommitConfirmation): Promise<DeviceWrapper> {
    const id = parsed(identifier, candidateId, 'INVALID_CONTEXT');
    const receipt = parsed(deviceCommitConfirmation, confirmation, 'RECEIPT_MISMATCH');
    if (receipt.operationId !== id) throw new DeviceStoreError('RECEIPT_MISMATCH');
    const { operationId: _operationId, ...context } = receipt;
    return this.transaction(['candidates', 'active'], 'readwrite', (transaction, result, fail) => {
      this.candidate(transaction.objectStore('candidates'), id, (candidate) => {
        if (!candidate) throw new DeviceStoreError('NOT_FOUND');
        if (!sameContext(contextOf(candidate.wrapper), context)) throw new DeviceStoreError('RECEIPT_MISMATCH');
        const store = transaction.objectStore('active');
        const request = store.get(deviceKey(context));
        request.onsuccess = () => {
          try {
            const previous = readActive(request.result, deviceKey(context));
            if (previous && (BigInt(previous.context.credentialGeneration) > BigInt(context.credentialGeneration)
              || (previous.context.credentialGeneration === context.credentialGeneration && previous.candidateId !== id))) {
              throw new DeviceStoreError('CONFLICT');
            }
            store.put({ deviceKey: deviceKey(context), candidateId: id, context } satisfies ActivePointer);
            result(candidate.wrapper);
          } catch (error) { fail(error); }
        };
      }, fail);
    });
  }

  /** Explicit cleanup after an authoritative pre-commit draft replacement only. */
  async discardUncommitted(candidateId: string, expectedDeviceId?: string): Promise<void> {
    const id = parsed(identifier, candidateId, 'INVALID_CONTEXT');
    const deviceId = expectedDeviceId === undefined ? undefined : parsed(identifier, expectedDeviceId, 'INVALID_CONTEXT');
    return this.transaction(['candidates', 'active'], 'readwrite', (transaction, result, fail) => {
      const request = transaction.objectStore('active').getAll();
      request.onsuccess = () => {
        try {
          for (const value of request.result as unknown[]) {
            if (parsed(activePointer, value, 'CORRUPT_STORAGE').candidateId === id) throw new DeviceStoreError('CONFLICT');
          }
          const candidates = transaction.objectStore('candidates');
          const candidate = candidates.get(id);
          candidate.onsuccess = () => {
            try {
              // A delayed duplicate replacement must not remove a newer draft using this operation ID.
              const current = candidate.result as { wrapper?: { header?: { deviceId?: unknown } } } | undefined;
              if (deviceId === undefined || current?.wrapper?.header?.deviceId === deviceId) candidates.delete(id);
              result(undefined);
            } catch (error) { fail(error); }
          };
        } catch (error) { fail(error); }
      };
    });
  }

  /** Forget only this device/account; other remembered devices remain untouched. */
  async forget(workspaceId: string, accountId: string, deviceId: string): Promise<void> {
    const context = parsed(deviceContext, { workspaceId, accountId, deviceId, credentialGeneration: '1' }, 'INVALID_CONTEXT');
    const key = deviceKey(context);
    return this.transaction(['candidates', 'active'], 'readwrite', (transaction, result, fail) => {
      const candidates = transaction.objectStore('candidates');
      const request = candidates.index('deviceKey').getAllKeys(key);
      request.onsuccess = () => {
        try {
          for (const id of request.result) candidates.delete(id);
          transaction.objectStore('active').delete(key);
          result(undefined);
        } catch (error) { fail(error); }
      };
    });
  }

  close(): void {
    this.closed = true;
    this.database.close();
  }
}

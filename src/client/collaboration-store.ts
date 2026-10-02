import { z } from 'zod';
import { identifier, positiveCounter } from '../shared/contracts.js';
import { canonicalJson } from '../shared/crypto.js';
import { collaborationPayload, collaborationPin as entryPin } from '../shared/collaboration.js';
import { AuthenticatedHttp } from './auth-controller.js';

export class CollaborationStoreError extends Error {
  constructor(readonly code: 'STORAGE' | 'CONFLICT') { super(`Collaboration storage failed (${code})`); this.name = 'CollaborationStoreError'; }
}
export const storedCollaborationOperation = z.strictObject({ version: z.literal(1), origin: z.string(), workspaceId: identifier,
  accountId: identifier, deviceId: identifier, operationId: identifier, payload: collaborationPayload });
export type StoredCollaborationOperation = z.infer<typeof storedCollaborationOperation>;
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
export const collaborationPin = entryPin.extend({ dataGeneration: positiveCounter });
export type CollaborationPin = z.infer<typeof collaborationPin>;
/** Durable, immutable signed ciphertext only. Names and decoded keys never enter this store. */
export class IndexedCollaborationStore {
  private constructor(readonly origin: string, private readonly database: IDBDatabase) { database.onversionchange = () => database.close(); }
  static async open(origin: string, name = 'ukda-collaboration-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedCollaborationStore> {
    const accepted = new AuthenticatedHttp(origin).origin; if (!factory) throw new CollaborationStoreError('STORAGE');
    return new Promise((resolve, reject) => { let settled = false; const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new CollaborationStoreError('STORAGE')); };
      request.onblocked = request.onerror = fail; request.onupgradeneeded = () => { request.result.createObjectStore('operations'); request.result.createObjectStore('pins'); };
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedCollaborationStore(accepted, request.result)); }; });
  }
  private transaction<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore, done: (value: T) => void, fail: (error: unknown) => void) => void, collection = 'operations'): Promise<T> {
    return new Promise((resolve, reject) => { let tx: IDBTransaction;
      try { tx = this.database.transaction(collection, mode, mode === 'readwrite' ? { durability: 'strict' } : {}); } catch { reject(new CollaborationStoreError('STORAGE')); return; }
      let result: T, complete = false, failure: unknown;
      const fail = (error: unknown) => { failure = error; try { tx.abort(); } catch { reject(error); } };
      tx.onabort = () => reject(failure instanceof CollaborationStoreError ? failure : new CollaborationStoreError('STORAGE'));
      tx.oncomplete = () => complete ? resolve(result) : reject(new CollaborationStoreError('STORAGE'));
      try { work(tx.objectStore(collection), (value) => { result = value; complete = true; }, fail); } catch (error) { fail(error); }
    });
  }
  private key(workspaceId: string, operationId: string): string { return `${this.origin}:${identifier.parse(workspaceId)}:${identifier.parse(operationId)}`; }
  private parse(value: unknown): StoredCollaborationOperation {
    const record = storedCollaborationOperation.parse(copy(value)), binding = record.payload.mutation.body.binding;
    if (record.origin !== this.origin || record.origin !== binding.origin || record.workspaceId !== binding.workspaceId ||
      record.accountId !== binding.accountId || record.deviceId !== binding.deviceId || record.operationId !== binding.operationId) throw new CollaborationStoreError('CONFLICT');
    return record;
  }
  get(workspaceId: string, operationId: string): Promise<StoredCollaborationOperation | undefined> {
    const key = this.key(workspaceId, operationId); return this.transaction('readonly', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      const record = request.result === undefined ? undefined : this.parse(request.result);
      if (record && (record.workspaceId !== workspaceId || record.operationId !== operationId)) throw new CollaborationStoreError('CONFLICT'); done(record);
    } catch (error) { fail(error); } }; });
  }
  put(value: StoredCollaborationOperation): Promise<void> {
    const record = this.parse(value), key = this.key(record.workspaceId, record.operationId);
    return this.transaction('readwrite', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      if (request.result !== undefined && canonicalJson(this.parse(request.result)) !== canonicalJson(record)) throw new CollaborationStoreError('CONFLICT');
      store.put(record, key); done(undefined);
    } catch (error) { fail(error); } }; });
  }
  list(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<{ workspaceId: string; operationId: string; projectId: string; entryId: string }[]> {
    return this.transaction('readonly', (store, done, fail) => { const request = store.getAll(); request.onsuccess = () => { try {
      done(request.result.flatMap((value: unknown) => { const record = storedCollaborationOperation.safeParse(value);
        if (!record.success || record.data.origin !== this.origin || record.data.workspaceId !== reference.workspaceId || record.data.accountId !== reference.accountId || record.data.deviceId !== reference.deviceId) return [];
        return [{ workspaceId: record.data.workspaceId, operationId: record.data.operationId, projectId: record.data.payload.mutation.body.binding.projectId, entryId: record.data.payload.mutation.body.binding.entryId }]; }));
    } catch (error) { fail(error); } }; });
  }
  forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    return this.transaction('readwrite', (store, done, fail) => { const request = store.openCursor(); request.onsuccess = () => { try {
      const cursor = request.result; if (!cursor) { done(undefined); return; }
      const record = z.object({ origin: z.string(), workspaceId: identifier, accountId: identifier, deviceId: identifier }).safeParse(cursor.value);
      if (record.success && record.data.origin === this.origin && record.data.workspaceId === reference.workspaceId &&
        record.data.accountId === reference.accountId && record.data.deviceId === reference.deviceId) cursor.delete(); cursor.continue();
    } catch (error) { fail(error); } }; });
  }
  pin(reference: { workspaceId: string; projectId: string; entryId: string }): Promise<CollaborationPin | undefined> {
    const key = this.key(reference.workspaceId, reference.entryId);
    return this.transaction('readonly', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      const pin = request.result === undefined ? undefined : collaborationPin.parse(request.result);
      if (pin && (pin.workspaceId !== reference.workspaceId || pin.projectId !== reference.projectId || pin.entryId !== reference.entryId)) throw new CollaborationStoreError('CONFLICT'); done(pin);
    } catch (error) { fail(error); } }; }, 'pins');
  }
  recordPin(value: CollaborationPin): Promise<void> {
    const pin = collaborationPin.parse(copy(value)), key = this.key(pin.workspaceId, pin.entryId);
    return this.transaction('readwrite', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      const prior = request.result === undefined ? undefined : collaborationPin.parse(request.result);
      if (prior && (prior.workspaceId !== pin.workspaceId || prior.projectId !== pin.projectId || prior.entryId !== pin.entryId || prior.kind !== pin.kind ||
        BigInt(pin.dataGeneration) < BigInt(prior.dataGeneration) || pin.dataGeneration === prior.dataGeneration &&
        (BigInt(pin.revision) < BigInt(prior.revision) || pin.revision === prior.revision && pin.head !== prior.head))) throw new CollaborationStoreError('CONFLICT');
      store.put(pin, key); done(undefined);
    } catch (error) { fail(error); } }; }, 'pins');
  }
  close(): void { this.database.close(); }
}

import { z } from 'zod';
import { binary, identifier } from '../shared/contracts.js';
import { canonicalJson } from '../shared/crypto.js';
import { accessPayload } from '../shared/access-change.js';
import { AuthenticatedHttp } from './auth-controller.js';

export class AccessChangeStoreError extends Error {
  constructor(readonly code: 'STORAGE' | 'CONFLICT') { super(`Access change storage failed (${code})`); this.name = 'AccessChangeStoreError'; }
}
export const accessChangeRecord = z.strictObject({ version: z.literal(1), origin: z.string(), workspaceId: identifier,
  accountId: identifier, deviceId: identifier, operationId: identifier, receiptToken: binary(32), payload: accessPayload });
export type AccessChangeRecord = z.infer<typeof accessChangeRecord>;
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
/** Immutable signed ciphertext and a receipt-only random capability. No passwords, phrases, labels or decoded keys. */
export class IndexedAccessChangeStore {
  private constructor(readonly origin: string, private readonly database: IDBDatabase) { database.onversionchange = () => database.close(); }
  static async open(origin: string, name = 'ukda-access-change-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedAccessChangeStore> {
    const accepted = new AuthenticatedHttp(origin).origin; if (!factory) throw new AccessChangeStoreError('STORAGE');
    return new Promise((resolve, reject) => { let settled = false; const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new AccessChangeStoreError('STORAGE')); };
      request.onblocked = request.onerror = fail; request.onupgradeneeded = () => request.result.createObjectStore('operations');
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedAccessChangeStore(accepted, request.result)); }; });
  }
  private transaction<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore, done: (value: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    return new Promise((resolve, reject) => { let tx: IDBTransaction;
      try { tx = this.database.transaction('operations', mode, mode === 'readwrite' ? { durability: 'strict' } : {}); } catch { reject(new AccessChangeStoreError('STORAGE')); return; }
      let result: T, complete = false, failure: unknown;
      const fail = (error: unknown) => { failure = error; try { tx.abort(); } catch { reject(error); } };
      tx.onabort = () => reject(failure instanceof AccessChangeStoreError ? failure : new AccessChangeStoreError('STORAGE'));
      tx.oncomplete = () => complete ? resolve(result) : reject(new AccessChangeStoreError('STORAGE'));
      try { work(tx.objectStore('operations'), (value) => { result = value; complete = true; }, fail); } catch (error) { fail(error); }
    });
  }
  private key(operationId: string): string { return `${this.origin}:${identifier.parse(operationId)}`; }
  private parse(value: unknown): AccessChangeRecord {
    const record = accessChangeRecord.parse(copy(value)), binding = record.payload.transition.body.binding;
    if (record.origin !== this.origin || record.origin !== binding.origin || record.workspaceId !== binding.workspaceId ||
      record.accountId !== binding.authorizer.accountId || record.deviceId !== binding.authorizer.device.id || record.operationId !== binding.operationId) throw new AccessChangeStoreError('CONFLICT');
    return record;
  }
  get(operationId: string): Promise<AccessChangeRecord | undefined> {
    const key = this.key(operationId); return this.transaction('readonly', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      const record = request.result === undefined ? undefined : this.parse(request.result);
      if (record && record.operationId !== operationId) throw new AccessChangeStoreError('CONFLICT'); done(record);
    } catch (error) { fail(error); } }; });
  }
  put(value: AccessChangeRecord): Promise<void> {
    const record = this.parse(value), key = this.key(record.operationId);
    return this.transaction('readwrite', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      if (request.result !== undefined && canonicalJson(this.parse(request.result)) !== canonicalJson(record)) throw new AccessChangeStoreError('CONFLICT');
      store.put(record, key); done(undefined);
    } catch (error) { fail(error); } }; });
  }
  list(): Promise<{ workspaceId: string; operationId: string; targetAccountId: string; action: string }[]> {
    return this.transaction('readonly', (store, done, fail) => { const request = store.getAll(); request.onsuccess = () => { try {
      done(request.result.flatMap((value: unknown) => { const record = accessChangeRecord.safeParse(value); if (!record.success || record.data.origin !== this.origin) return [];
        const binding = record.data.payload.transition.body.binding; return [{ workspaceId: record.data.workspaceId, operationId: record.data.operationId,
          targetAccountId: binding.targetAccountId, action: binding.action }]; }));
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
  close(): void { this.database.close(); }
}

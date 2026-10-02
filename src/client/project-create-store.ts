import { z } from 'zod';
import { identifier } from '../shared/contracts.js';
import { canonicalJson } from '../shared/crypto.js';
import { projectCreatePayload } from '../shared/project-create.js';
import { AuthenticatedHttp } from './auth-controller.js';

export class ProjectCreateStoreError extends Error {
  constructor(readonly code: 'STORAGE' | 'CONFLICT') { super(`Project creation storage failed (${code})`); this.name = 'ProjectCreateStoreError'; }
}
export const projectCreateRecord = z.strictObject({ version: z.literal(1), origin: z.string(), workspaceId: identifier,
  accountId: identifier, deviceId: identifier, operationId: identifier, payload: projectCreatePayload });
export type ProjectCreateRecord = z.infer<typeof projectCreateRecord>;
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
/** Durable, immutable signed ciphertext only. Names and decoded keys never enter this store. */
export class IndexedProjectCreateStore {
  private constructor(readonly origin: string, private readonly database: IDBDatabase) { database.onversionchange = () => database.close(); }
  static async open(origin: string, name = 'ukda-project-create-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedProjectCreateStore> {
    const accepted = new AuthenticatedHttp(origin).origin; if (!factory) throw new ProjectCreateStoreError('STORAGE');
    return new Promise((resolve, reject) => { let settled = false; const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new ProjectCreateStoreError('STORAGE')); };
      request.onblocked = request.onerror = fail; request.onupgradeneeded = () => request.result.createObjectStore('operations');
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedProjectCreateStore(accepted, request.result)); }; });
  }
  private transaction<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore, done: (value: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    return new Promise((resolve, reject) => { let tx: IDBTransaction;
      try { tx = this.database.transaction('operations', mode, mode === 'readwrite' ? { durability: 'strict' } : {}); } catch { reject(new ProjectCreateStoreError('STORAGE')); return; }
      let result: T, complete = false, failure: unknown;
      const fail = (error: unknown) => { failure = error; try { tx.abort(); } catch { reject(error); } };
      tx.onabort = () => reject(failure instanceof ProjectCreateStoreError ? failure : new ProjectCreateStoreError('STORAGE'));
      tx.oncomplete = () => complete ? resolve(result) : reject(new ProjectCreateStoreError('STORAGE'));
      try { work(tx.objectStore('operations'), (value) => { result = value; complete = true; }, fail); } catch (error) { fail(error); }
    });
  }
  private key(workspaceId: string, operationId: string): string { return `${this.origin}:${identifier.parse(workspaceId)}:${identifier.parse(operationId)}`; }
  private parse(value: unknown): ProjectCreateRecord {
    const record = projectCreateRecord.parse(copy(value)), binding = record.payload.transition.body.binding;
    if (record.origin !== this.origin || record.origin !== binding.origin || record.workspaceId !== binding.workspaceId ||
      record.accountId !== binding.authorizer.accountId || record.deviceId !== binding.authorizer.device.id || record.operationId !== binding.operationId) throw new ProjectCreateStoreError('CONFLICT');
    return record;
  }
  get(workspaceId: string, operationId: string): Promise<ProjectCreateRecord | undefined> {
    const key = this.key(workspaceId, operationId); return this.transaction('readonly', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      const record = request.result === undefined ? undefined : this.parse(request.result);
      if (record && (record.workspaceId !== workspaceId || record.operationId !== operationId)) throw new ProjectCreateStoreError('CONFLICT'); done(record);
    } catch (error) { fail(error); } }; });
  }
  put(value: ProjectCreateRecord): Promise<void> {
    const record = this.parse(value), key = this.key(record.workspaceId, record.operationId);
    return this.transaction('readwrite', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      if (request.result !== undefined && canonicalJson(this.parse(request.result)) !== canonicalJson(record)) throw new ProjectCreateStoreError('CONFLICT');
      store.put(record, key); done(undefined);
    } catch (error) { fail(error); } }; });
  }
  list(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<{ workspaceId: string; operationId: string; projectId: string }[]> {
    return this.transaction('readonly', (store, done, fail) => { const request = store.getAll(); request.onsuccess = () => { try {
      done(request.result.flatMap((value: unknown) => { const record = projectCreateRecord.safeParse(value);
        if (!record.success || record.data.origin !== this.origin || record.data.workspaceId !== reference.workspaceId || record.data.accountId !== reference.accountId || record.data.deviceId !== reference.deviceId) return [];
        return [{ workspaceId: record.data.workspaceId, operationId: record.data.operationId, projectId: record.data.payload.transition.body.binding.projectId }]; }));
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

import { z } from 'zod';
import { identifier, positiveCounter } from '../shared/contracts.js';
import { canonicalJson } from '../shared/crypto.js';
import { teamPayload } from '../shared/teams.js';
import { AuthenticatedHttp } from './auth-controller.js';

export class TeamsStoreError extends Error {
  constructor(readonly code: 'STORAGE' | 'CONFLICT') { super(`Team storage failed (${code})`); this.name = 'TeamsStoreError'; }
}
export const teamsRecord = z.strictObject({ version: z.literal(1), origin: z.string(), workspaceId: identifier,
  accountId: identifier, deviceId: identifier, operationId: identifier, credentialGeneration: positiveCounter, sessionGeneration: positiveCounter, dataGeneration: positiveCounter, payload: teamPayload });
export type TeamsRecord = z.infer<typeof teamsRecord>;
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
/** Durable, immutable signed ciphertext only. Names and decoded keys never enter this store. */
export class IndexedTeamsStore {
  private constructor(readonly origin: string, private readonly database: IDBDatabase) { database.onversionchange = () => database.close(); }
  static async open(origin: string, name = 'ukda-teams-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedTeamsStore> {
    const accepted = new AuthenticatedHttp(origin).origin; if (!factory) throw new TeamsStoreError('STORAGE');
    return new Promise((resolve, reject) => { let settled = false; const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new TeamsStoreError('STORAGE')); };
      request.onblocked = request.onerror = fail; request.onupgradeneeded = () => request.result.createObjectStore('operations');
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedTeamsStore(accepted, request.result)); }; });
  }
  private transaction<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore, done: (value: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    return new Promise((resolve, reject) => { let tx: IDBTransaction;
      try { tx = this.database.transaction('operations', mode, mode === 'readwrite' ? { durability: 'strict' } : {}); } catch { reject(new TeamsStoreError('STORAGE')); return; }
      let result: T, complete = false, failure: unknown;
      const fail = (error: unknown) => { failure = error; try { tx.abort(); } catch { reject(error); } };
      tx.onabort = () => reject(failure instanceof TeamsStoreError ? failure : new TeamsStoreError('STORAGE'));
      tx.oncomplete = () => complete ? resolve(result) : reject(new TeamsStoreError('STORAGE'));
      try { work(tx.objectStore('operations'), (value) => { result = value; complete = true; }, fail); } catch (error) { fail(error); }
    });
  }
  private key(workspaceId: string, operationId: string): string { return `${this.origin}:${identifier.parse(workspaceId)}:${identifier.parse(operationId)}`; }
  private parse(value: unknown): TeamsRecord {
    const record = teamsRecord.parse(copy(value)), binding = record.payload.mutation.body.binding;
    if (record.origin !== this.origin || record.workspaceId !== binding.workspaceId ||
      record.accountId !== binding.authorizer.accountId || record.deviceId !== binding.authorizer.deviceId || record.operationId !== binding.operationId || record.dataGeneration !== binding.dataGeneration) throw new TeamsStoreError('CONFLICT');
    return record;
  }
  get(workspaceId: string, operationId: string): Promise<TeamsRecord | undefined> {
    const key = this.key(workspaceId, operationId); return this.transaction('readonly', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      const record = request.result === undefined ? undefined : this.parse(request.result);
      if (record && (record.workspaceId !== workspaceId || record.operationId !== operationId)) throw new TeamsStoreError('CONFLICT'); done(record);
    } catch (error) { fail(error); } }; });
  }
  put(value: TeamsRecord): Promise<void> {
    const record = this.parse(value), key = this.key(record.workspaceId, record.operationId);
    return this.transaction('readwrite', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      if (request.result !== undefined && canonicalJson(this.parse(request.result)) !== canonicalJson(record)) throw new TeamsStoreError('CONFLICT');
      store.put(record, key); done(undefined);
    } catch (error) { fail(error); } }; });
  }
  list(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<{ workspaceId: string; operationId: string; teamId: string }[]> {
    return this.transaction('readonly', (store, done, fail) => { const request = store.getAll(); request.onsuccess = () => { try {
      done(request.result.flatMap((value: unknown) => { const record = teamsRecord.safeParse(value);
        if (!record.success || record.data.origin !== this.origin || record.data.workspaceId !== reference.workspaceId || record.data.accountId !== reference.accountId || record.data.deviceId !== reference.deviceId) return [];
        return [{ workspaceId: record.data.workspaceId, operationId: record.data.operationId, teamId: record.data.payload.mutation.body.binding.teamId }]; }));
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

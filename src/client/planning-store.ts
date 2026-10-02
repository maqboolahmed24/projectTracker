import { z } from 'zod';
import { identifier, digest, positiveCounter, counter } from '../shared/contracts.js';
import { canonicalJson } from '../shared/crypto.js';
import { planningPayload } from '../shared/planning-api.js';
import { AuthenticatedHttp } from './auth-controller.js';

export class PlanningStoreError extends Error {
  constructor(readonly code: 'STORAGE' | 'CONFLICT') { super(`Planning storage failed (${code})`); this.name = 'PlanningStoreError'; }
}
export const storedPlanningOperation = z.strictObject({ version: z.literal(1), origin: z.string(), workspaceId: identifier,
  accountId: identifier, deviceId: identifier, operationId: identifier, payload: planningPayload });
export type StoredPlanningOperation = z.infer<typeof storedPlanningOperation>;
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
export const planningPin = z.strictObject({ workspaceId: identifier, projectId: identifier, dataGeneration: positiveCounter, version: counter, head: digest });
export type PlanningPin = z.infer<typeof planningPin>;
/** Durable, immutable signed ciphertext only. Names and decoded keys never enter this store. */
export class IndexedPlanningStore {
  private constructor(readonly origin: string, private readonly database: IDBDatabase) { database.onversionchange = () => database.close(); }
  static async open(origin: string, name = 'ukda-planning-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedPlanningStore> {
    const accepted = new AuthenticatedHttp(origin).origin; if (!factory) throw new PlanningStoreError('STORAGE');
    return new Promise((resolve, reject) => { let settled = false; const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new PlanningStoreError('STORAGE')); };
      request.onblocked = request.onerror = fail; request.onupgradeneeded = () => { request.result.createObjectStore('operations'); request.result.createObjectStore('pins'); };
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedPlanningStore(accepted, request.result)); }; });
  }
  private transaction<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore, done: (value: T) => void, fail: (error: unknown) => void) => void, collection = 'operations'): Promise<T> {
    return new Promise((resolve, reject) => { let tx: IDBTransaction;
      try { tx = this.database.transaction(collection, mode, mode === 'readwrite' ? { durability: 'strict' } : {}); } catch { reject(new PlanningStoreError('STORAGE')); return; }
      let result: T, complete = false, failure: unknown;
      const fail = (error: unknown) => { failure = error; try { tx.abort(); } catch { reject(error); } };
      tx.onabort = () => reject(failure instanceof PlanningStoreError ? failure : new PlanningStoreError('STORAGE'));
      tx.oncomplete = () => complete ? resolve(result) : reject(new PlanningStoreError('STORAGE'));
      try { work(tx.objectStore(collection), (value) => { result = value; complete = true; }, fail); } catch (error) { fail(error); }
    });
  }
  private key(workspaceId: string, operationId: string): string { return `${this.origin}:${identifier.parse(workspaceId)}:${identifier.parse(operationId)}`; }
  private parse(value: unknown): StoredPlanningOperation {
    const record = storedPlanningOperation.parse(copy(value)), binding = record.payload.mutation.body.binding;
    if (record.origin !== this.origin || record.origin !== binding.origin || record.workspaceId !== binding.workspaceId ||
      record.accountId !== binding.accountId || record.deviceId !== binding.deviceId || record.operationId !== binding.operationId) throw new PlanningStoreError('CONFLICT');
    return record;
  }
  get(workspaceId: string, operationId: string): Promise<StoredPlanningOperation | undefined> {
    const key = this.key(workspaceId, operationId); return this.transaction('readonly', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      const record = request.result === undefined ? undefined : this.parse(request.result);
      if (record && (record.workspaceId !== workspaceId || record.operationId !== operationId)) throw new PlanningStoreError('CONFLICT'); done(record);
    } catch (error) { fail(error); } }; });
  }
  put(value: StoredPlanningOperation): Promise<void> {
    const record = this.parse(value), key = this.key(record.workspaceId, record.operationId);
    return this.transaction('readwrite', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      if (request.result !== undefined && canonicalJson(this.parse(request.result)) !== canonicalJson(record)) throw new PlanningStoreError('CONFLICT');
      store.put(record, key); done(undefined);
    } catch (error) { fail(error); } }; });
  }
  list(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<{ workspaceId: string; operationId: string; projectId: string }[]> {
    return this.transaction('readonly', (store, done, fail) => { const request = store.getAll(); request.onsuccess = () => { try {
      done(request.result.flatMap((value: unknown) => { const record = storedPlanningOperation.safeParse(value);
        if (!record.success || record.data.origin !== this.origin || record.data.workspaceId !== reference.workspaceId || record.data.accountId !== reference.accountId || record.data.deviceId !== reference.deviceId) return [];
        return [{ workspaceId: record.data.workspaceId, operationId: record.data.operationId, projectId: record.data.payload.mutation.body.binding.projectId }]; }));
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
  pin(reference: { workspaceId: string; projectId: string }): Promise<PlanningPin | undefined> {
    const key = this.key(reference.workspaceId, reference.projectId);
    return this.transaction('readonly', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      const pin = request.result === undefined ? undefined : planningPin.parse(request.result);
      if (pin && (pin.workspaceId !== reference.workspaceId || pin.projectId !== reference.projectId)) throw new PlanningStoreError('CONFLICT'); done(pin);
    } catch (error) { fail(error); } }; }, 'pins');
  }
  recordPin(value: PlanningPin): Promise<void> {
    const pin = planningPin.parse(copy(value)), key = this.key(pin.workspaceId, pin.projectId);
    return this.transaction('readwrite', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      const prior = request.result === undefined ? undefined : planningPin.parse(request.result);
      if (prior && (BigInt(pin.dataGeneration) < BigInt(prior.dataGeneration) || pin.dataGeneration === prior.dataGeneration &&
        (BigInt(pin.version) < BigInt(prior.version) || pin.version === prior.version && pin.head !== prior.head))) throw new PlanningStoreError('CONFLICT');
      store.put(pin, key); done(undefined);
    } catch (error) { fail(error); } }; }, 'pins');
  }
  close(): void { this.database.close(); }
}

import { z } from 'zod';
import { identifier } from '../shared/contracts.js';
import { canonicalJson } from '../shared/crypto.js';
import { authOrigin } from './auth-controller.js';
import { WriteError } from './write-state.js';

export const requestIdentity = z.strictObject({ origin: z.string(), workspaceId: identifier, accountId: identifier, deviceId: identifier, operationId: identifier });
export type RequestIdentity = z.infer<typeof requestIdentity>;
export async function openRequestDatabase(name: string, factory: IDBFactory | undefined): Promise<IDBDatabase> {
  if (!factory) throw new WriteError('STORAGE');
  return new Promise((resolve, reject) => {
    let failed = false; const request = factory.open(name, 1);
    request.onerror = request.onblocked = () => { failed = true; reject(new WriteError('STORAGE')); };
    request.onupgradeneeded = () => request.result.createObjectStore('requests');
    request.onsuccess = () => { if (failed) request.result.close(); else resolve(request.result); };
  });
}
/** Small storage primitive for exact, schema-checked signed requests, never plaintext forms. */
export class IndexedSignedRequests<T extends RequestIdentity> {
  readonly origin: string;
  protected constructor(origin: string, private readonly database: IDBDatabase, private readonly schema: z.ZodType<T>,
    private readonly bindingIdentity: (record: T) => RequestIdentity) {
    this.origin = authOrigin(origin); database.onversionchange = () => database.close();
  }
  private parse(value: unknown): T {
    const record = this.schema.parse(JSON.parse(canonicalJson(value))), identity = z.object(requestIdentity.shape).parse(record), binding = this.bindingIdentity(record);
    if (identity.origin !== this.origin || canonicalJson(identity) !== canonicalJson(binding)) throw new WriteError('CONFLICT');
    return record;
  }
  private key(workspaceId: string, operationId: string) { return `${this.origin}:${identifier.parse(workspaceId)}:${identifier.parse(operationId)}`; }
  private transaction<R>(mode: IDBTransactionMode, action: (store: IDBObjectStore, done: (value: R) => void, fail: (error: unknown) => void) => void): Promise<R> {
    return new Promise((resolve, reject) => {
      let tx: IDBTransaction;
      try { tx = this.database.transaction('requests', mode, mode === 'readwrite' ? { durability: 'strict' } : {}); }
      catch { reject(new WriteError('STORAGE')); return; }
      let result: R, complete = false, failure: unknown;
      const fail = (error: unknown) => { failure = error; try { tx.abort(); } catch { reject(error); } };
      tx.onabort = () => reject(failure instanceof WriteError ? failure : new WriteError('STORAGE'));
      tx.oncomplete = () => complete ? resolve(result) : reject(new WriteError('STORAGE'));
      try { action(tx.objectStore('requests'), value => { result = value; complete = true; }, fail); } catch (error) { fail(error); }
    });
  }
  get(workspaceId: string, operationId: string): Promise<T | undefined> {
    const key = this.key(workspaceId, operationId);
    return this.transaction('readonly', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      const record = request.result === undefined ? undefined : this.parse(request.result);
      if (record && (record.workspaceId !== workspaceId || record.operationId !== operationId)) throw new WriteError('CONFLICT'); done(record);
    } catch (error) { fail(error); } }; });
  }
  async put(value: T): Promise<void> {
    const record = this.parse(value), key = this.key(record.workspaceId, record.operationId);
    await this.transaction<void>('readwrite', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      if (request.result !== undefined && canonicalJson(this.parse(request.result)) !== canonicalJson(record)) throw new WriteError('CONFLICT');
      store.put(record, key); done(undefined);
    } catch (error) { fail(error); } }; });
    if (canonicalJson(await this.get(record.workspaceId, record.operationId)) !== canonicalJson(record)) throw new WriteError('STORAGE');
  }
  list(reference: Pick<RequestIdentity, 'workspaceId' | 'accountId' | 'deviceId'>): Promise<string[]> {
    return this.transaction('readonly', (store, done, fail) => { const request = store.getAll(); request.onsuccess = () => { try {
      done(request.result.flatMap((value: unknown) => { const result = this.schema.safeParse(value); if (!result.success) return [];
        const r = result.data; return r.origin === this.origin && r.workspaceId === reference.workspaceId && r.accountId === reference.accountId && r.deviceId === reference.deviceId ? [r.operationId] : []; }).sort());
    } catch (error) { fail(error); } }; });
  }
  remove(workspaceId: string, operationId: string): Promise<void> {
    return this.transaction('readwrite', (store, done) => { store.delete(this.key(workspaceId, operationId)); done(undefined); });
  }
  forgetDevice(reference: Pick<RequestIdentity, 'workspaceId' | 'accountId' | 'deviceId'>): Promise<void> {
    return this.transaction('readwrite', (store, done, fail) => { const request = store.openCursor(); request.onsuccess = () => { try {
      const cursor = request.result; if (!cursor) { done(undefined); return; }
      const result = z.object(requestIdentity.shape).safeParse(cursor.value);
      if (result.success) { const r = result.data; if (r.origin === this.origin && r.workspaceId === reference.workspaceId && r.accountId === reference.accountId && r.deviceId === reference.deviceId) cursor.delete(); }
      cursor.continue();
    } catch (error) { fail(error); } }; });
  }
  close() { this.database.close(); }
}

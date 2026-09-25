import { z } from 'zod';
import { binary, digest, identifier } from '../shared/contracts.js';
import { canonicalJson } from '../shared/crypto.js';
import { enrolmentApproval, enrolmentDraft, enrolmentReceipt, type EnrolmentReference } from '../shared/enrolment.js';
import { enrolmentView } from '../shared/enrolment-api.js';
import { deviceWrapper } from './device-store.js';
import { setupNameWrapper } from './enrolment-crypto.js';
import { AuthenticatedHttp } from './auth-controller.js';

export const preparedEnrolment = z.strictObject({ draft: enrolmentDraft, deviceWrapper, nameWrapper: setupNameWrapper.nullable() });
export const enrolmentRecord = z.strictObject({ version: z.literal(1), role: z.enum(['recipient', 'owner']), localId: identifier,
  revision: z.number().int().positive(), origin: z.string(), workspaceId: identifier, accountId: identifier.nullable(), deviceId: identifier.nullable(),
  operationId: identifier.nullable(), resumeToken: binary(32).nullable(), genesisFingerprint: digest,
  view: enrolmentView.nullable(), prepared: preparedEnrolment.nullable(), approval: enrolmentApproval.nullable(), receipt: enrolmentReceipt.nullable() })
  .refine((value) => value.role === 'recipient' ? value.resumeToken !== null : value.resumeToken === null && value.accountId !== null &&
    value.deviceId !== null && value.operationId !== null && value.prepared === null);
export type EnrolmentRecord = z.infer<typeof enrolmentRecord>;
export class EnrolmentStoreError extends Error {
  constructor(readonly code: 'STORAGE' | 'CONFLICT') { super(`Enrolment storage failed (${code})`); this.name = 'EnrolmentStoreError'; }
}
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
const key = (origin: string, role: EnrolmentRecord['role'], id: string) => `${origin}:${role}:${id}`;
/** Stores encrypted drafts, public signatures and random resume capabilities only. Never codes, names, passwords or phrases. */
export class IndexedEnrolmentStore {
  private constructor(readonly origin: string, private readonly database: IDBDatabase) { database.onversionchange = () => database.close(); }
  static async open(origin: string, name = 'ukda-enrolment-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedEnrolmentStore> {
    const accepted = new AuthenticatedHttp(origin).origin;
    if (!factory) throw new EnrolmentStoreError('STORAGE');
    return new Promise((resolve, reject) => {
      let settled = false; const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new EnrolmentStoreError('STORAGE')); };
      request.onerror = request.onblocked = fail;
      request.onupgradeneeded = () => request.result.createObjectStore('operations');
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedEnrolmentStore(accepted, request.result)); };
    });
  }
  private transaction<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore, done: (result: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction;
      try { transaction = this.database.transaction('operations', mode, mode === 'readwrite' ? { durability: 'strict' } : {}); }
      catch { reject(new EnrolmentStoreError('STORAGE')); return; }
      let result: T, complete = false, failure: unknown;
      const fail = (error: unknown) => { failure = error; try { transaction.abort(); } catch { reject(error); } };
      transaction.onabort = () => reject(failure instanceof EnrolmentStoreError ? failure : new EnrolmentStoreError('STORAGE'));
      transaction.oncomplete = () => complete ? resolve(result) : reject(new EnrolmentStoreError('STORAGE'));
      try { action(transaction.objectStore('operations'), (value) => { result = value; complete = true; }, fail); } catch (error) { fail(error); }
    });
  }
  get(role: EnrolmentRecord['role'], localId: string): Promise<EnrolmentRecord | undefined> {
    identifier.parse(localId);
    return this.transaction('readonly', (store, done, fail) => { const request = store.get(key(this.origin, role, localId)); request.onsuccess = () => {
      try { const record = request.result === undefined ? undefined : enrolmentRecord.parse(copy(request.result));
        if (record && (record.origin !== this.origin || record.role !== role || record.localId !== localId)) throw new EnrolmentStoreError('CONFLICT'); done(record);
      } catch (error) { fail(error); }
    }; });
  }
  put(value: EnrolmentRecord, previousRevision: number): Promise<void> {
    const record = enrolmentRecord.parse(copy(value));
    if (record.origin !== this.origin || record.revision !== previousRevision + 1) throw new EnrolmentStoreError('CONFLICT');
    return this.transaction('readwrite', (store, done, fail) => { const request = store.get(key(this.origin, record.role, record.localId)); request.onsuccess = () => {
      try { const previous = request.result === undefined ? undefined : enrolmentRecord.parse(request.result);
        if ((previous?.revision ?? 0) !== previousRevision) throw new EnrolmentStoreError('CONFLICT');
        store.put(record, key(this.origin, record.role, record.localId)); done(undefined);
      } catch (error) { fail(error); }
    }; });
  }
  capability(localId: string): Promise<(EnrolmentReference & { accountId: string | null; deviceId: string | null; promotion: boolean }) | undefined> {
    return this.transaction('readonly', (store, done, fail) => { const request = store.get(key(this.origin, 'recipient', identifier.parse(localId))); request.onsuccess = () => { try {
      const metadata = z.object({ origin: z.literal(this.origin), role: z.literal('recipient'), localId: z.literal(localId), workspaceId: identifier,
        operationId: identifier, resumeToken: binary(32), accountId: identifier.nullable(), deviceId: identifier.nullable(),
        view: z.object({ kind: z.string() }).nullable() }).safeParse(request.result);
      if (!metadata.success) { done(undefined); return; }
      const { workspaceId, operationId, resumeToken, accountId, deviceId, view } = metadata.data;
      done({ workspaceId, operationId, resumeToken, accountId, deviceId, promotion: view?.kind === 'promote_owner' });
    } catch (error) { fail(error); } }; });
  }
  discardCancelled(localId: string, reference: EnrolmentReference): Promise<void> {
    return this.transaction('readwrite', (store, done, fail) => { const id = key(this.origin, 'recipient', localId), request = store.get(id); request.onsuccess = () => { try {
      const metadata = z.object({ workspaceId: identifier, operationId: identifier, resumeToken: binary(32) }).safeParse(request.result);
      if (request.result !== undefined && (!metadata.success || canonicalJson(metadata.data) !== canonicalJson(reference))) throw new EnrolmentStoreError('CONFLICT');
      store.delete(id); done(undefined);
    } catch (error) { fail(error); } }; });
  }
  list(): Promise<{ role: EnrolmentRecord['role']; localId: string; workspaceId: string; accountId: string | null; operationId: string | null; state: string }[]> {
    return this.transaction('readonly', (store, done, fail) => { const request = store.getAll(); request.onsuccess = () => { try {
      done(request.result.flatMap((raw: unknown) => { const value = enrolmentRecord.safeParse(raw); if (!value.success || value.data.origin !== this.origin) return [];
        const record = value.data; return [{ role: record.role, localId: record.localId, workspaceId: record.workspaceId, accountId: record.accountId,
          operationId: record.operationId, state: record.receipt ? 'completed' : record.view?.state ?? 'starting' }]; }));
    } catch (error) { fail(error); } }; });
  }
  forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    return this.transaction('readwrite', (store, done, fail) => { const request = store.openCursor(); request.onsuccess = () => { try {
      const cursor = request.result; if (!cursor) { done(undefined); return; }
      const metadata = z.object({ origin: z.string(), workspaceId: identifier, accountId: identifier, deviceId: identifier }).safeParse(cursor.value);
      if (metadata.success && metadata.data.origin === this.origin && metadata.data.workspaceId === reference.workspaceId &&
        metadata.data.accountId === reference.accountId && metadata.data.deviceId === reference.deviceId) cursor.delete();
      cursor.continue();
    } catch (error) { fail(error); } }; });
  }
  close(): void { this.database.close(); }
}

import { z } from 'zod';
import { identifier } from '../shared/contracts.js';
import type { IndexedDeviceStore } from './device-store.js';

const reference = z.strictObject({ workspaceId: identifier, accountId: identifier, deviceId: identifier });
export type RememberedProfileReference = z.infer<typeof reference>;
const profileInput = reference.extend({ displayName: z.string().min(1).max(200).refine((name) => name.trim().length > 0 && !/[\uD800-\uDFFF]/u.test(name)) });
export type RememberedProfileInput = z.infer<typeof profileInput>;
const card = profileInput.extend({ version: z.literal(1), origin: z.string() });
export type RememberedProfile = z.infer<typeof card>;

export class RememberedProfileError extends Error {
  constructor(readonly code: 'INVALID_PROFILE' | 'STORAGE' | 'UNAVAILABLE' | 'CLOSED') {
    super(`Remembered profile operation failed (${code})`); this.name = 'RememberedProfileError';
  }
}
function originOf(value: string): string {
  try {
    const url = new URL(value);
    if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error();
    return url.origin;
  } catch { throw new RememberedProfileError('INVALID_PROFILE'); }
}
/** No accessors, unknown fields, or nested data can enter this deliberately small card. */
function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error();
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string' || !Object.getOwnPropertyDescriptor(value, key)?.enumerable ||
        !('value' in Object.getOwnPropertyDescriptor(value, key)!)) throw new Error();
    }
    return schema.parse(value);
  } catch { throw new RememberedProfileError('INVALID_PROFILE'); }
}

/** Local convenience cards only; this store never fetches a public profile/member list. */
export class RememberedProfiles {
  readonly origin: string;
  private closed = false;
  private constructor(origin: string, private readonly database: IDBDatabase) {
    this.origin = origin;
    database.onversionchange = () => this.close(); database.onclose = () => { this.closed = true; };
  }
  static async open(origin: string, name = 'ukda-remembered-profiles-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<RememberedProfiles> {
    const acceptedOrigin = originOf(origin);
    if (globalThis.location && globalThis.location.origin !== acceptedOrigin) throw new RememberedProfileError('INVALID_PROFILE');
    if (!factory) throw new RememberedProfileError('UNAVAILABLE');
    return new Promise((resolve, reject) => {
      let settled = false; let request: IDBOpenDBRequest;
      const fail = () => { settled = true; reject(new RememberedProfileError('STORAGE')); };
      try { request = factory.open(name, 1); } catch { fail(); return; }
      request.onerror = fail; request.onblocked = fail;
      request.onupgradeneeded = () => {
        try {
          const profiles = request.result.createObjectStore('profiles', { keyPath: ['origin', 'workspaceId', 'accountId', 'deviceId'] });
          profiles.createIndex('origin', 'origin');
        } catch { request.transaction?.abort(); fail(); }
      };
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new RememberedProfiles(acceptedOrigin, request.result)); };
    });
  }
  private transaction<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore, result: (value: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    if (this.closed) return Promise.reject(new RememberedProfileError('CLOSED'));
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction;
      try { transaction = this.database.transaction('profiles', mode, { durability: 'strict' }); }
      catch { reject(new RememberedProfileError('STORAGE')); return; }
      let value: T; let assigned = false; let failure: RememberedProfileError | undefined;
      const fail = (error: unknown) => {
        failure = error instanceof RememberedProfileError ? error : new RememberedProfileError('STORAGE');
        try { transaction.abort(); } catch { reject(failure); }
      };
      transaction.onabort = () => reject(failure ?? new RememberedProfileError('STORAGE'));
      transaction.oncomplete = () => assigned ? resolve(value) : reject(new RememberedProfileError('STORAGE'));
      try { action(transaction.objectStore('profiles'), (result) => { value = result; assigned = true; }, fail); }
      catch (error) { fail(error); }
    });
  }
  async remember(input: RememberedProfileInput): Promise<RememberedProfile> {
    const accepted = parse(profileInput, input);
    const value: RememberedProfile = { ...accepted, version: 1, origin: this.origin };
    return this.transaction('readwrite', (store, result) => { store.put(value); result(value); });
  }
  async list(): Promise<RememberedProfile[]> {
    return this.transaction('readonly', (store, result, fail) => {
      const request = store.index('origin').getAll(this.origin);
      request.onsuccess = () => {
        try {
          const profiles = (request.result as unknown[]).map((value) => parse(card, value));
          if (profiles.some((profile) => profile.origin !== this.origin)) throw new RememberedProfileError('STORAGE');
          profiles.sort((left, right) => {
            const a = `${left.workspaceId}:${left.accountId}:${left.deviceId}`; const b = `${right.workspaceId}:${right.accountId}:${right.deviceId}`;
            return a < b ? -1 : a > b ? 1 : 0;
          });
          result(profiles);
        } catch { fail(new RememberedProfileError('STORAGE')); }
      };
    });
  }
  async remove(input: RememberedProfileReference): Promise<void> {
    const accepted = parse(reference, input);
    return this.transaction('readwrite', (store, result) => {
      store.delete([this.origin, accepted.workspaceId, accepted.accountId, accepted.deviceId]); result(undefined);
    });
  }
  /**
   * Logout retains cards. Explicit Forget removes encrypted generations first,
   * then the card. Separate databases cannot share an atomic transaction: any
   * failure is reported, and repeating this order safely completes cleanup.
   */
  async forget(input: RememberedProfileReference, devices: Pick<IndexedDeviceStore, 'forget'>): Promise<void> {
    const accepted = parse(reference, input);
    if (this.closed) throw new RememberedProfileError('CLOSED');
    await devices.forget(accepted.workspaceId, accepted.accountId, accepted.deviceId);
    await this.remove(accepted);
  }
  close() { this.closed = true; this.database.close(); }
}

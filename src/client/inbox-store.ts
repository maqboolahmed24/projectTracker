import { z } from 'zod';
import { inboxMutation } from '../shared/inbox.js';
import { IndexedSignedRequests, openRequestDatabase, requestIdentity } from './retry-store.js';

export const storedInboxRequest = requestIdentity.extend({ version: z.literal(1), payload: inboxMutation });
export type StoredInboxRequest = z.infer<typeof storedInboxRequest>;
export class IndexedInboxStore extends IndexedSignedRequests<StoredInboxRequest> {
  private constructor(origin: string, database: IDBDatabase) { super(origin, database, storedInboxRequest, record => {
    const b = record.payload.body.binding; return { origin: b.origin, workspaceId: b.workspaceId, accountId: b.accountId, deviceId: b.deviceId, operationId: b.operationId };
  }); }
  static async open(origin: string, name = 'ukda-inbox-requests-v1', factory: IDBFactory | undefined = globalThis.indexedDB) {
    return new IndexedInboxStore(origin, await openRequestDatabase(name, factory));
  }
}

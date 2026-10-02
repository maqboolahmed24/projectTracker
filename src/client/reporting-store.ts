import { z } from 'zod';
import { reportingSettingsPayload, reportingSummaryPayload } from '../shared/reporting.js';
import { IndexedSignedRequests, openRequestDatabase, requestIdentity } from './retry-store.js';

export const storedReportingRequest = z.discriminatedUnion('kind', [
  requestIdentity.extend({ version: z.literal(1), kind: z.literal('settings'), payload: reportingSettingsPayload }),
  requestIdentity.extend({ version: z.literal(1), kind: z.literal('summary'), payload: reportingSummaryPayload }),
]);
export type StoredReportingRequest = z.infer<typeof storedReportingRequest>;
export class IndexedReportingStore extends IndexedSignedRequests<StoredReportingRequest> {
  private constructor(origin: string, database: IDBDatabase) { super(origin, database, storedReportingRequest, record => {
    const b = record.payload.mutation.body.binding; return { origin: b.origin, workspaceId: b.workspaceId, accountId: b.accountId, deviceId: b.deviceId, operationId: b.operationId };
  }); }
  static async open(origin: string, name = 'ukda-reporting-requests-v1', factory: IDBFactory | undefined = globalThis.indexedDB) {
    return new IndexedReportingStore(origin, await openRequestDatabase(name, factory));
  }
}

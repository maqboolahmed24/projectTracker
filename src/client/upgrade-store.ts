import { z } from 'zod';
import { identifier, positiveCounter } from '../shared/contracts.js';
import { upgradeStart, upgradeFinish } from '../shared/upgrade-api.js';
import { identityUpgradePayload } from '../shared/encrypted-upgrades.js';
import { planningPayload } from '../shared/planning-api.js';
import { teamPayload } from '../shared/teams.js';
import { collaborationPayload } from '../shared/collaboration.js';
import { IndexedSignedRequests, openRequestDatabase, requestIdentity } from './retry-store.js';

const base = requestIdentity.extend({ version: z.literal(1), migrationId: identifier, dataGeneration: positiveCounter });
export const storedUpgradeRequest = z.discriminatedUnion('kind', [
  base.extend({ kind: z.literal('start'), payload: upgradeStart }),
  base.extend({ kind: z.literal('finish'), payload: upgradeFinish }),
  base.extend({ kind: z.literal('identity'), payload: identityUpgradePayload }),
  base.extend({ kind: z.literal('planning'), payload: planningPayload }),
  base.extend({ kind: z.literal('team'), payload: teamPayload }),
  base.extend({ kind: z.literal('collaboration'), payload: collaborationPayload }),
]);
export type StoredUpgradeRequest = z.infer<typeof storedUpgradeRequest>;

export function upgradeRequestBinding(record: StoredUpgradeRequest) {
  if (record.kind === 'start' || record.kind === 'finish') return record.payload.body.binding;
  if (record.kind === 'team') {
    const team = record.payload.mutation.body.binding;
    return { ...team, origin: record.origin, accountId: team.authorizer.accountId, deviceId: team.authorizer.deviceId };
  }
  const b = record.payload.mutation.body.binding;
  return { ...b, origin: 'origin' in b ? b.origin : record.origin };
}

/** Stores only exact signed manifests/ciphertexts for attempted online operations. */
export class IndexedUpgradeStore extends IndexedSignedRequests<StoredUpgradeRequest> {
  private constructor(origin: string, database: IDBDatabase) {
    super(origin, database, storedUpgradeRequest, record => {
      const b = upgradeRequestBinding(record);
      const migrationId = record.kind === 'start' || record.kind === 'finish' ? record.payload.body.binding.migrationId :
        ('upgrade' in record.payload.mutation.body ? record.payload.mutation.body.upgrade?.migrationId : undefined);
      if (record.migrationId !== migrationId || record.dataGeneration !== b.dataGeneration) throw new Error('Invalid stored upgrade reference');
      return { origin: b.origin, workspaceId: b.workspaceId, accountId: b.accountId, deviceId: b.deviceId, operationId: b.operationId };
    });
  }
  static async open(origin: string, name = 'ukda-upgrade-requests-v1', factory: IDBFactory | undefined = globalThis.indexedDB) {
    return new IndexedUpgradeStore(origin, await openRequestDatabase(name, factory));
  }
}

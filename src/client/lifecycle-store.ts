import { z } from 'zod';
import { lifecycleMutation } from '../shared/lifecycle.js';
import { IndexedSignedRequests,openRequestDatabase,requestIdentity } from './retry-store.js';
const record=requestIdentity.extend({version:z.literal(1),payload:lifecycleMutation});
export class IndexedLifecycleStore extends IndexedSignedRequests<z.infer<typeof record>>{
 private constructor(origin:string,db:IDBDatabase){super(origin,db,record,row=>{
  const b=row.payload.body.binding;return {origin:b.origin,workspaceId:b.workspaceId,accountId:b.accountId,deviceId:b.deviceId,operationId:b.operationId};
 });}
 static async open(origin:string,name='ukda-lifecycle-requests-v1',factory:IDBFactory|undefined=globalThis.indexedDB){
  return new IndexedLifecycleStore(origin,await openRequestDatabase(name,factory));
 }
}

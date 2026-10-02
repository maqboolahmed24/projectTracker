import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { z } from 'zod';
import { AuthenticatedHttp } from '../src/client/auth-controller.js';
import { assertOnline, WriteError } from '../src/client/write-state.js';
import { IndexedReportingStore } from '../src/client/reporting-store.js';
import { IndexedInboxStore } from '../src/client/inbox-store.js';
import { prepareReporting } from '../src/client/reporting-crypto.js';
import { prepareInbox } from '../src/client/inbox-crypto.js';
import { canonicalJson } from '../src/shared/crypto.js';
import { reportingClientFixture } from './reporting-client-fixture.js';

test('CP11 exact signed reporting and Inbox requests survive store reopen and clear only the selected identity',async()=>{
  const f=await reportingClientFixture(),input=await f.input(),payload=await prepareReporting(input,f.owner.bundle),b=payload.mutation.body.binding,
    identity={origin:b.origin,workspaceId:b.workspaceId,accountId:b.accountId,deviceId:b.deviceId},factory=new IDBFactory(),name=randomUUID();
  let store=await IndexedReportingStore.open(b.origin,name,factory);
  const record={...identity,version:1 as const,operationId:b.operationId,kind:'summary' as const,payload};await store.put(record);
  assert.equal(canonicalJson(await store.get(b.workspaceId,b.operationId)),canonicalJson(record));
  assert.equal(canonicalJson(record).includes('Private'),false);store.close();store=await IndexedReportingStore.open(b.origin,name,factory);
  assert.deepEqual(await store.list(identity),[b.operationId]);
  const changed=structuredClone(record),envelope=changed.payload.components[0]!.envelope;envelope.nonce=(envelope.nonce.startsWith('A')?'B':'A')+envelope.nonce.slice(1);
  // An established operation ID can never be assigned altered bytes.
  await assert.rejects(store.put(changed));await store.forgetDevice({...identity,deviceId:randomUUID()});assert.deepEqual(await store.list(identity),[b.operationId]);
  await store.forgetDevice(identity);assert.deepEqual(await store.list(identity),[]);store.close();
  const inboxName=randomUUID(),operationId=randomUUID(),issuedAt=new Date().toISOString(),inboxPayload=await prepareInbox({binding:{version:1,...identity,operationId,
    signingPublicKey:f.owner.bundle.signingPublicKey,keyGeneration:'1',credentialGeneration:'1',sessionGeneration:'1',dataGeneration:'1',
    securityHead:b.securityHead,securityVersion:b.securityVersion,issuedAt,expiresAt:new Date(Date.parse(issuedAt)+600000).toISOString()},
    command:{action:'set_project_muted',projectId:f.planning.projectId,expectedRevision:'0',muted:true}},f.owner.bundle);
  let inbox=await IndexedInboxStore.open(b.origin,inboxName,factory);await inbox.put({...identity,version:1,operationId,payload:inboxPayload});inbox.close();
  inbox=await IndexedInboxStore.open(b.origin,inboxName,factory);assert.deepEqual((await inbox.get(b.workspaceId,operationId))!.payload,inboxPayload);
  await inbox.remove(b.workspaceId,operationId);assert.deepEqual(await inbox.list(identity),[]);inbox.close();
});

test('CP11 transport distinguishes conflict, update-required, retry and restricted; offline guard never schedules work',async()=>{
  for(const [serverCode,status,expected] of [['PLANNING_CHANGED',409,'CONFLICT'],['REVISION_CONFLICT',409,'CONFLICT'],
    ['COLLABORATION_CHANGED',409,'CONFLICT'],['REPORTING_CHANGED',409,'CONFLICT'],['UNSUPPORTED_SCHEMA',409,'UPDATE_REQUIRED'],
    ['RETRY_REQUIRED',409,'RETRY_REQUIRED'],['WORKSPACE_RESTRICTED',423,'RESTRICTED']] as const){
    const http=new AuthenticatedHttp('https://ukda.example',async url=>{const response=new Response(JSON.stringify({error:{code:serverCode}}),
      {status,headers:{'content-type':'application/json'}});Object.defineProperty(response,'url',{value:String(url)});return response;});
    await assert.rejects(http.post('/v1/work/planning/save',{},z.unknown()),error=>error instanceof WriteError&&error.code===expected&&error.serverCode===serverCode);
  }
  let submitted=false;assert.throws(()=>{assertOnline(()=>false);submitted=true;},error=>error instanceof WriteError&&error.code==='OFFLINE');assert.equal(submitted,false);
  assertOnline(()=>true);assert.equal(submitted,false);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { indexedDB } from 'fake-indexeddb';
import { fileBulkDraft,sealFileBulk,openFileBulk,type FileBulkDraft } from '../src/client/files-bulk-crypto.js';
import { IndexedFileBulkStore } from '../src/client/files-bulk-store.js';
import { planningClientFixture } from './planning-client-fixture.js';

function draft(projectId:string):FileBulkDraft{return fileBulkDraft.parse({version:1,batchId:randomUUID(),projectId,mode:'register',label:'Private document batch',createdAt:new Date().toISOString(),revision:'0',items:[{id:randomUUID(),taskId:randomUUID(),createOperationId:randomUUID(),uploadOperationId:randomUUID(),submitOperationId:randomUUID(),assignOperationId:randomUUID(),fileId:randomUUID(),versionId:randomUUID(),existingFileId:null,expectedVersionId:null,documentReference:'PRIVATE-HR-001',title:'Private employee guide',filename:'confidential employee guide.txt',plainBytes:7,sha256:'a'.repeat(64),storage:'external',path:'/Volumes/Private/People/employee guide.txt',assigneeIds:[],leadProfileId:null,reviewerProfileId:null,phaseId:null,state:'ready',stage:'pending',errorCode:null}]});}

test('bulk mappings, paths and per-item outcomes are encrypted and bound to their exact scope',async()=>{
 const fixture=await planningClientFixture({version:2}),input=await fixture.input(),value=draft(fixture.projectId),record=await sealFileBulk({...input,draft:value},fixture.f.owner.bundle);
 const raw=JSON.stringify(record);for(const secret of [value.label,value.items[0]!.title,value.items[0]!.filename,value.items[0]!.documentReference,value.items[0]!.path])assert.ok(!raw.includes(secret));
 assert.deepEqual(await openFileBulk({...input,record},fixture.f.owner.bundle),value);
 await assert.rejects(openFileBulk({...input,record:{...record,revision:'1'}},fixture.f.owner.bundle));
 await assert.rejects(openFileBulk({...input,record:{...record,projectId:randomUUID()}},fixture.f.owner.bundle));
 await assert.rejects(openFileBulk({...input,record:{...record,dataGeneration:String(BigInt(record.dataGeneration)+1n)}},fixture.f.owner.bundle));
});

test('bulk storage fences concurrent progress and explicit device removal clears encrypted drafts',async()=>{
 const fixture=await planningClientFixture({version:2}),input=await fixture.input(),value=draft(fixture.projectId),record=await sealFileBulk({...input,draft:value},fixture.f.owner.bundle),store=await IndexedFileBulkStore.open(record.origin,randomUUID(),indexedDB);
 try{await store.put(record,null);await assert.rejects(store.put(record,null));const updated=await sealFileBulk({...input,draft:{...value,revision:'1',items:value.items.map(i=>({...i,state:'saved',stage:'file_saved'}))}},fixture.f.owner.bundle);await store.put(updated,'0');await assert.rejects(store.put(updated,'0'));assert.equal((await store.get(record.workspaceId,record.batchId))?.revision,'1');
  await store.forgetDevice({workspaceId:record.workspaceId,accountId:record.accountId,deviceId:record.deviceId});assert.equal(await store.get(record.workspaceId,record.batchId),undefined);
 }finally{store.close();}
});

test('bulk bounds reject duplicate mappings, oversized uploads and a reviewer assigned to their own work',()=>{
 const value=draft(randomUUID()),item=value.items[0]!;
 assert.equal(fileBulkDraft.safeParse({...value,items:Array.from({length:65},()=>({...item,id:randomUUID(),taskId:randomUUID(),documentReference:randomUUID()}))}).success,false);
 assert.equal(fileBulkDraft.safeParse({...value,items:[item,{...item,id:randomUUID()}]}).success,false);
 assert.equal(fileBulkDraft.safeParse({...value,items:[{...item,storage:'managed',plainBytes:25*1024*1024+1}]}).success,false);
 const reviewer=randomUUID();assert.equal(fileBulkDraft.safeParse({...value,items:[{...item,reviewerProfileId:reviewer,assigneeIds:[reviewer]}]}).success,false);
});

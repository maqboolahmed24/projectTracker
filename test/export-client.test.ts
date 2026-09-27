import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, digestObject, base64urlDecode, verifyObject } from '../src/shared/crypto.js';
import { prepareExport, ExportClientError } from '../src/client/export-crypto.js';
import { exportClientFixture } from './export-client-fixture.js';
import { IDBFactory } from 'fake-indexeddb';
import { randomUUID } from 'node:crypto';
import { IndexedPairingStore } from '../src/client/pairing.js';
import { ExportController, type ExportTransport } from '../src/client/export-controller.js';
import type { AuthController } from '../src/client/auth-controller.js';
import { refreshAccessKeys } from '../src/client/access-change-crypto.js';

test('CP12 export Worker: complete ordinary data, hidden originals and readable history produce allowlisted UTF-8 JSON without security objects',async()=>{
  const f=await exportClientFixture(),input=await f.input(),before=canonicalJson(input),prepared=await prepareExport(input,f.owner.bundle),document=JSON.parse(prepared.json);
  assert.equal(document.exportSchema,1);assert.equal(document.complete,true);assert.match(document.notice,/plaintext project data/);assert.equal(document.workspace.name,'Private access workspace');
  assert.equal(document.projects[0].name,'Private original project');assert.equal(document.tasks[0].title,'Private discussion task');
  assert.deepEqual(document.assignments,[{projectId:f.collab.planning.projectId,taskId:f.collab.taskId,profileId:f.owner.accountId,taskRevision:'1'}]);
  assert.equal(document.comments[0].hidden,true);assert.equal(document.comments[0].text,'Private original discussion');assert.equal(document.comments[0].moderation.reason,'Private moderation reason');
  assert.deepEqual(document.history.planning.map((r:{action:string})=>r.action),['create_project','create_task']);assert.deepEqual(document.history.collaboration.map((r:{action:string})=>r.action),['post_comment','hide_comment']);
  assert.equal(document.profiles[0].displayName,'Private Owner');assert.equal(prepared.documentDigest,await digestObject(document));
  assert.equal(prepared.finalize.body.byteLength,new TextEncoder().encode(prepared.json).byteLength);
  assert.equal(await verifyObject(prepared.finalize,base64urlDecode(f.owner.bundle.signingPublicKey,32),'ukda.plaintext-export.v1'),true);
  const forbidden=new Set(['signature','ciphertext','encrypted_envelope','envelope','nonce','algorithm','signingPublicKey','signingPrivateKey','recipientPublicKey','recipientPrivateKey',
    'keyEpoch','materials','genesis','securityHead','transitions','registrationRecord','exportKey','sessionKey','recovery','password','resumeToken']);
  const walk=(value:unknown)=>{if(Array.isArray(value)){for(const item of value)walk(item);}else if(value&&typeof value==='object')for(const [key,item]of Object.entries(value)){assert.equal(forbidden.has(key),false,`No ${key} in the plaintext data-exit format`);walk(item);}};
  walk(document);assert.equal(prepared.json.includes(f.owner.bundle.signingPrivateKey),false);assert.equal(prepared.json.includes(f.owner.phrase!),false);
  assert.equal(canonicalJson(input),before,'Preparation must not mutate source proof');
});

test('CP12 export controller: a failed final authority gate returns no file and explicit retry cannot auto-submit on reconnect',async()=>{
  const f=await exportClientFixture(),input=await f.input(),origin=input.history.origin,pins=await IndexedPairingStore.open(origin,randomUUID(),new IDBFactory());
  try {await pins.recordVerifiedHistory(input.history);let finalizes=0,deny=true,prepares=0;
    const actor={workspaceId:f.f.workspaceId,accountId:f.owner.accountId,deviceId:f.owner.deviceId},delivery={...actor,current:input.history.expected,materials:input.materials},
      auth={origin,current:()=>({localAccess:'unlocked',session:{...actor,credentialGeneration:'1',sessionGeneration:'1',dataGeneration:'1'}}),
        worker:{prepareExport:async(value:Parameters<typeof prepareExport>[0])=>{prepares++;return prepareExport(value,f.owner.bundle);}}} as unknown as AuthController,
      transport:ExportTransport={origin,start:async()=>input.start,page:async request=>input.pages[request.after===null?0:input.start.sources.findIndex(s=>`${s.kind}:${s.id}`===request.after)+1]!,
        finalize:async signed=>{finalizes++;if(deny)throw new Error('Current Owner revoked');return {version:1,workspaceId:actor.workspaceId,exportId:signed.body.binding.exportId,
          accountId:actor.accountId,dataGeneration:'1',manifestDigest:signed.body.binding.manifestDigest,documentDigest:signed.body.documentDigest,finalizedAt:new Date().toISOString(),complete:true};}},
      access={refreshKeys:()=>refreshAccessKeys({history:input.history,delivery},f.owner.bundle)},security={delivery:async()=>delivery,
        deliveryHistory:async()=>({genesis:input.history.genesis,transitions:input.history.transitions,anchor:input.history.expected,current:input.history.expected})},
      controller=new ExportController(auth,transport,pins,access,security);
    await assert.rejects(controller.generate({acknowledgePlaintext:true,exportId:input.start.binding.exportId}),/Current Owner revoked/);
    assert.equal(prepares,1);assert.equal(finalizes,1);await Promise.resolve();assert.equal(finalizes,1);
    deny=false;const file=await controller.generate({acknowledgePlaintext:true,exportId:input.start.binding.exportId});assert.equal(JSON.parse(file.json).complete,true);assert.equal(finalizes,2);
  }finally{pins.close();}
});

test('CP12 export Worker: missing, duplicated, stale-authority and tampered native sources fail instead of claiming completeness',async()=>{
  const f=await exportClientFixture(),input=await f.input();
  await assert.rejects(prepareExport({...input,acknowledgePlaintext:false as true},f.owner.bundle),e=>e instanceof ExportClientError&&e.code==='ACKNOWLEDGEMENT_REQUIRED');
  await assert.rejects(prepareExport({...input,pages:input.pages.slice(1)},f.owner.bundle));
  const duplicate=structuredClone(input);duplicate.pages[1]=duplicate.pages[0]!;await assert.rejects(prepareExport(duplicate,f.owner.bundle));
  const tampered=structuredClone(input),project=tampered.pages.find(p=>p.data.kind==='project')!;if(project.data.kind!=='project')throw new Error();
  project.data.context.records[0]!.envelope.signature='A'.repeat(86);await assert.rejects(prepareExport(tampered,f.owner.bundle));
  const stale=structuredClone(input);stale.start.binding.credentialGeneration='2';for(const page of stale.pages)page.binding=stale.start.binding;
  await assert.rejects(prepareExport(stale,f.owner.bundle));
  const incompleteManifest=structuredClone(input);incompleteManifest.start.manifest.pop();incompleteManifest.start.binding.manifestDigest=await digestObject(incompleteManifest.start.manifest);
  for(const page of incompleteManifest.pages)page.binding=incompleteManifest.start.binding;await assert.rejects(prepareExport(incompleteManifest,f.owner.bundle));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { digestObject } from '../src/shared/crypto.js';
import { readWorkspaceDirectory } from '../src/client/directory-crypto.js';
import { DirectoryController } from '../src/client/directory-controller.js';
import { IndexedPairingStore } from '../src/client/pairing.js';
import type { AuthController } from '../src/client/auth-controller.js';
import { ownerFixture } from './project-create-client-fixture.js';
import { accessChangeFixture } from './access-change-fixture.js';

async function directoryInput(){
  const f=await ownerFixture({avatar:{shapeId:'shape-20',colourId:'violet'}}),w=f.state.workspaceContent!,p=f.state.profiles[f.owner.accountId]!.profile;
  return {f,input:{history:f.history,accountId:f.owner.accountId,deviceId:f.owner.deviceId,materials:[...f.materials,
    {id:w.objectId,kind:'encrypted_workspace',digest:await digestObject(f.initialWorkspace),value:f.initialWorkspace},
    {id:p.objectId,kind:'encrypted_profile',digest:await digestObject(f.initialProfile),value:f.initialProfile}]}};
}
test('frontend directory: signed current labels and permissions, without keys in presentation',async()=>{
  const {f,input}=await directoryInput(),result=await readWorkspaceDirectory(input,f.owner.bundle);
  assert.equal(result.workspaceName,'Private access workspace');assert.equal(result.isOwner,true);
  assert.equal(result.people[0]!.displayName,'Private Owner');assert.equal(result.people[0]!.avatar.shapeId,'shape-20');
  assert.equal(result.devices[0]!.current,true);assert.equal(JSON.stringify(result).includes(f.owner.bundle.signingPrivateKey),false);
  const duplicate=structuredClone(input);duplicate.materials.push(duplicate.materials.at(-1)!);await assert.rejects(readWorkspaceDirectory(duplicate,f.owner.bundle));
  const substituted=structuredClone(input);substituted.materials.at(-1)!.digest='0'.repeat(64);await assert.rejects(readWorkspaceDirectory(substituted,f.owner.bundle));
  await assert.rejects(readWorkspaceDirectory({...input,accountId:randomUUID()},f.owner.bundle));
  const other=await ownerFixture();await assert.rejects(readWorkspaceDirectory(input,other.owner.bundle));
});
test('frontend directory: logout and authority changes fence plaintext delivery',async()=>{
  const {f,input}=await directoryInput(),pins=await IndexedPairingStore.open(f.history.origin,randomUUID(),new IDBFactory());
  try{await pins.recordVerifiedHistory(f.history);let changed=false,clearDuringRead=false;
    const actor={workspaceId:f.workspaceId,accountId:f.owner.accountId,deviceId:f.owner.deviceId},delivery={...actor,current:f.history.expected,materials:input.materials};
    const auth={origin:f.history.origin,current:()=>({localAccess:'unlocked',session:{...actor,credentialGeneration:'1',sessionGeneration:'1',dataGeneration:'1'}}),worker:{readWorkspaceDirectory:async(value:typeof input)=>{const result=await readWorkspaceDirectory(value,f.owner.bundle);if(clearDuringRead)controller.clear();return result;}}} as unknown as AuthController;
    const controller=new DirectoryController(auth,pins,{refreshKeys:async()=>({} as never)},{origin:f.history.origin,
      delivery:async request=>request.includeDirectory?delivery:{...delivery,current:changed?{securityHead:'f'.repeat(64),securityVersion:'2'}:delivery.current},
      deliveryHistory:async()=>({genesis:input.history.genesis,transitions:input.history.transitions,anchor:input.history.expected,current:input.history.expected})});
    assert.equal((await controller.current()).workspaceName,'Private access workspace');changed=true;await assert.rejects(controller.current(),{code:'CONFLICT'});
    changed=false;clearDuringRead=true;await assert.rejects(controller.current(),{code:'CANCELLED'});
  }finally{pins.close();}
});
test('frontend directory delivery: member sees exact current shared profiles; removed actor is denied',async(t)=>{
  const f=await accessChangeFixture(t),member=await f.joined(),request={workspaceId:f.workspaceId,includeDirectory:true as const};
  const delivered=await f.access.currentDelivery(member.auth.cookieValue,member.auth.csrfToken,request);
  assert.equal(delivered.materials.filter(m=>m.kind==='encrypted_profile').length,2);
  assert.equal(delivered.materials.filter(m=>m.kind==='encrypted_workspace').length,1);
  assert.equal(delivered.materials.every(m=>['key_envelope','encrypted_profile','encrypted_workspace'].includes(m.kind)),true);
  assert.equal(JSON.stringify(delivered).includes('Confirmed private person'),false);
  const read=await readWorkspaceDirectory({history:await f.history(),materials:delivered.materials,accountId:member.binding.accountId,deviceId:member.prepared.draft.transcript.device.id},member.bundle);
  assert.equal(read.isOwner,false);assert.deepEqual(read.people.map(p=>p.displayName).sort(),['Confirmed private person','Password fixture Owner']);
  await assert.rejects(f.access.currentDelivery(member.auth.cookieValue,member.auth.csrfToken,{...request,accountId:f.accountId}));
  const removal=await f.draft('remove',member.binding.accountId);await f.finalize(removal);
  await assert.rejects(f.access.currentDelivery(member.auth.cookieValue,member.auth.csrfToken,request));
});

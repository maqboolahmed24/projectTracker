import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { DEFAULT_AVATAR } from '../src/shared/avatar.js';
import { base64urlDecode, base64urlEncode, digestObject, encryptContent, randomKey } from '../src/shared/crypto.js';
import { exportBinding, exportSourceManifest, exportSources, sortedExportManifest } from '../src/shared/export.js';
import { readCurrentProfile } from '../src/client/profile-crypto.js';
import { ProfileController } from '../src/client/profile-controller.js';
import { prepareExport } from '../src/client/export-crypto.js';
import { IndexedPairingStore } from '../src/client/pairing.js';
import { readWorkspaceKeyRing } from '../src/client/teams-crypto.js';
import { wrapDeviceBundle } from '../src/client/device-store.js';
import type { AuthController } from '../src/client/auth-controller.js';
import { ownerFixture } from './project-create-client-fixture.js';
import { testAuthWorker } from './client-worker-driver.js';

const selected={shapeId:'shape-20',colourId:'violet'} as const;
async function inputFor(f:Awaited<ReturnType<typeof ownerFixture>>) {
  const ref=f.state.profiles[f.owner.accountId]!.profile;
  return {history:f.history,accountId:f.owner.accountId,deviceId:f.owner.deviceId,materials:[...f.materials,
    {id:ref.objectId,kind:'encrypted_profile',digest:await digestObject(f.initialProfile),value:f.initialProfile}]};
}

test('Avatar profile: exact signed current ciphertext returns selected avatar, legacy fallback does not rewrite source',async()=>{
  for(const avatar of [undefined,selected]) {
    const f=await ownerFixture(avatar?{avatar}:{}),input=await inputFor(f),before=JSON.stringify(input);
    const profile=await readCurrentProfile(input,f.owner.bundle);
    assert.deepEqual(profile,{workspaceId:f.workspaceId,accountId:f.owner.accountId,revision:'1',displayName:'Private Owner',avatar:avatar??DEFAULT_AVATAR});
    assert.equal(JSON.stringify(input),before);
  }
});

test('Avatar profile: even valid signer substituted ciphertext, duplicate material, foreign bundle and mismatched actor are denied',async()=>{
  const f=await ownerFixture({avatar:selected}),input=await inputFor(f),ring=await readWorkspaceKeyRing(input,f.state,f.owner.bundle),key=base64urlDecode(ring[0]!.key),signing=base64urlDecode(f.owner.bundle.signingPrivateKey);
  try {
    const forged=await encryptContent(f.initialProfile.header,{displayName:'Forged identity',avatar:{shapeId:'shape-01',colourId:'coral'}},key,signing);
    const substituted=structuredClone(input),record=substituted.materials.at(-1)!;record.value=forged;record.digest=await digestObject(forged);
    await assert.rejects(readCurrentProfile(substituted,f.owner.bundle));
    record.digest=input.materials.at(-1)!.digest;await assert.rejects(readCurrentProfile(substituted,f.owner.bundle));
    await assert.rejects(readCurrentProfile({...input,materials:[...input.materials,input.materials.at(-1)!]},f.owner.bundle));
    await assert.rejects(readCurrentProfile({...input,accountId:randomUUID()},f.owner.bundle));
    const foreign=await ownerFixture();await assert.rejects(readCurrentProfile(input,foreign.owner.bundle));
  }finally{key.fill(0);signing.fill(0);}
});

test('Avatar profile Worker: locked, foreign identity and old session context cannot read the private profile',async(t)=>{
  const f=await ownerFixture({avatar:selected}),input=await inputFor(f),worker=testAuthWorker(f.history.origin);t.after(()=>worker.close());
  await assert.rejects(worker.readCurrentProfile(input),{code:'LOCKED'});
  const p=f.state.profiles[f.owner.accountId]!,d=f.state.devices[f.owner.deviceId]!,context={workspaceId:f.workspaceId,accountId:f.owner.accountId,deviceId:f.owner.deviceId,credentialGeneration:'1'},exportKey=base64urlEncode(await randomKey()),wrapper=await wrapDeviceBundle(context,f.owner.bundle,exportKey),
    proofContext={origin:f.history.origin,...context,sessionId:randomUUID(),keyGeneration:d.keyGeneration,sessionGeneration:p.sessionGeneration,
      dataGeneration:f.state.dataGeneration,securityVersion:f.state.securityVersion,securityHead:f.state.securityHead,ownershipVersion:f.state.ownershipVersion,custodyEpoch:f.state.custodyEpoch,
      grantId:randomUUID(),grantGeneration:'1',signingPublicKey:d.signingPublicKey,recipientPublicKey:d.recipientPublicKey};
  await worker.unlockDevice({context,wrapper,exportKey,proofContext});assert.deepEqual((await worker.readCurrentProfile(input)).avatar,selected);
  await assert.rejects(worker.readCurrentProfile({...input,accountId:randomUUID()}),{code:'CONTEXT_MISMATCH'});
  await worker.unlockDevice({context,wrapper,exportKey,proofContext:{...proofContext,sessionGeneration:'2'}});
  await assert.rejects(worker.readCurrentProfile(input),{code:'CONTEXT_MISMATCH'});
  worker.logout();await assert.rejects(worker.readCurrentProfile(input),{code:'LOCKED'});
});

test('Avatar profile controller: current read is fenced by authority and logout before returning plaintext',async()=>{
  const f=await ownerFixture({avatar:selected}),input=await inputFor(f),origin=f.history.origin,pins=await IndexedPairingStore.open(origin,randomUUID(),new IDBFactory());
  try {await pins.recordVerifiedHistory(f.history);let changed=false,clearDuringRead=false;const actor={workspaceId:f.workspaceId,accountId:f.owner.accountId,deviceId:f.owner.deviceId},
      delivery={...actor,current:f.history.expected,materials:input.materials};
    const auth={origin,current:()=>({localAccess:'unlocked',session:{...actor,credentialGeneration:'1',sessionGeneration:'1',dataGeneration:'1'}}),worker:{readCurrentProfile:async(value:typeof input)=>{
      const result=await readCurrentProfile(value,f.owner.bundle);if(clearDuringRead)controller.clear();return result;}}} as unknown as AuthController;
    const controller=new ProfileController(auth,pins,{refreshKeys:async()=>({} as never)},{origin,delivery:async request=>request.includeProfile?delivery:
      {...delivery,current:changed?{securityHead:'f'.repeat(64),securityVersion:'2'}:delivery.current},
      deliveryHistory:async()=>({genesis:input.history.genesis,transitions:input.history.transitions,anchor:input.history.expected,current:input.history.expected})});
    assert.deepEqual((await controller.current()).avatar,selected);changed=true;await assert.rejects(controller.current(),{code:'CONFLICT'});
    changed=false;clearDuringRead=true;await assert.rejects(controller.current(),{code:'CANCELLED'});
  }finally{pins.close();}
});

test('Avatar export: selection is preserved explicitly and legacy missing selection remains absent',async()=>{
  for(const avatar of [undefined,selected]) {
    const f=await ownerFixture(avatar?{avatar}:{}),input=await inputFor(f),now=Date.now(),data={kind:'workspace' as const,workspace:f.initialWorkspace,
      profiles:[{id:f.owner.accountId,revision:'1',state:'active' as const,envelope:f.initialProfile}],settings:{workspaceId:f.workspaceId,initial:f.initialWorkspace,
        revision:'0',head:await digestObject(f.initialWorkspace),timezone:null,history:[],securityHead:f.state.securityHead,securityVersion:f.state.securityVersion,dataGeneration:'1'}},
      manifest=sortedExportManifest(await exportSourceManifest(data)),sources=exportSources(manifest),binding=exportBinding.parse({version:1,workspaceId:f.workspaceId,exportId:randomUUID(),origin:f.history.origin,
        accountId:f.owner.accountId,deviceId:f.owner.deviceId,credentialGeneration:'1',sessionGeneration:'1',keyGeneration:'1',signingPublicKey:f.owner.bundle.signingPublicKey,
        securityHead:f.state.securityHead,securityVersion:f.state.securityVersion,dataGeneration:'1',manifestDigest:await digestObject(manifest),sourceCount:1,
        issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+600000).toISOString(),acknowledgePlaintext:true});
    const exported=await prepareExport({...input,start:{binding,manifest,sources},pages:[{binding,source:sources[0]!,data,nextCursor:null}],acknowledgePlaintext:true},f.owner.bundle);
    const profile=JSON.parse(exported.json).profiles[0];assert.equal(profile.displayName,'Private Owner');
    if(avatar)assert.deepEqual(profile.avatar,avatar);else assert.equal('avatar'in profile,false);
  }
});

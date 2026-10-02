import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { base64urlDecode, canonicalJson, digestObject, encryptContent, signObject } from '../src/shared/crypto.js';
import { upgradeContext, type UpgradeContext, type UpgradeStart } from '../src/shared/upgrade-api.js';
import { identityUpgradeHistory, type UpgradeRecordRef } from '../src/shared/encrypted-upgrades.js';
import { prepareUpgradeStart, prepareIdentityUpgrade, prepareUpgradeFinish } from '../src/client/encrypted-upgrades-crypto.js';
import { readWorkspaceKeyRing } from '../src/client/teams-crypto.js';
import { readIdentityUpgradeContent } from '../src/client/upgrade-content-crypto.js';
import { ownerFixture, append, type OwnerFixture } from './project-create-client-fixture.js';

const same=(value:unknown)=>canonicalJson(value);
async function context(f:OwnerFixture,migrationId:string,manifest:UpgradeRecordRef[],records:UpgradeContext['records'],start:UpgradeStart|null=null):Promise<UpgradeContext> {
  const s=f.state,p=s.profiles[f.owner.accountId]!,d=s.devices[f.owner.deviceId]!,now=Date.now(),completed=records.filter(r=>r.reference.schema===2).map(r=>r.reference);
  return upgradeContext.parse({state:start?'active':'available',manifest,completed,records,nextCursor:null,start,finish:null,binding:{version:1,
    workspaceId:f.workspaceId,migrationId,operationId:randomUUID(),origin:s.origin,accountId:p.accountId,deviceId:d.id,
    credentialGeneration:p.credentialGeneration,sessionGeneration:p.sessionGeneration,keyGeneration:d.keyGeneration,signingPublicKey:d.signingPublicKey,
    securityVersion:s.securityVersion,nextSecurityVersion:String(BigInt(s.securityVersion)+1n),securityHead:s.securityHead,dataGeneration:s.dataGeneration,
    ownershipVersion:s.ownershipVersion,custodyEpoch:s.custodyEpoch,workspaceKeyEpoch:s.workspaceKeyEpoch,writeSchema:s.writeSchema??1,
    manifestDigest:await digestObject(manifest),manifestCount:manifest.length,completedDigest:await digestObject(completed),completedCount:completed.length,
    issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+600_000).toISOString()}});
}
const input=(f:OwnerFixture,c:UpgradeContext)=>({context:c,history:f.history,accountId:f.owner.accountId,deviceId:f.owner.deviceId,materials:f.materials});
async function workspaceSource(f:OwnerFixture):Promise<UpgradeContext['records'][number]> {
  const envelope=f.initialWorkspace,h=envelope.header;
  return {reference:{kind:'workspace',id:f.workspaceId,projectId:null,revision:'1',contentRevision:null,envelopeRevision:h.revision,schema:1,keyEpoch:h.keyEpoch,digest:await digestObject(envelope)},envelope};
}

test('CP11 identity lifecycle: typed migration is signed, resumable and finish independently verifies current content',async()=>{
  const f=await ownerFixture(),source=await workspaceSource(f),migrationId=randomUUID(),manifest=[source.reference],initialHistory=same(f.history.genesis);
  const before=await context(f,migrationId,manifest,[source]),start=await prepareUpgradeStart(input(f,before),f.owner.bundle);
  await append(f,start,start.body.binding.nextSecurityVersion);
  const current=await context(f,migrationId,manifest,[source],start),payload=await prepareIdentityUpgrade({...input(f,current),records:[source]},f.owner.bundle);
  const transition=identityUpgradeHistory.parse({...payload.mutation,upgradeItems:payload.upgradeItems});
  await append(f,transition,transition.body.binding.nextSecurityVersion);
  const item=payload.upgradeItems[0]!,target={reference:item.target,envelope:item.envelope},finishContext=await context(f,migrationId,manifest,[target],start);
  assert.equal(item.target.schema,2);assert.equal(item.target.revision,'2');assert.equal(same(item.sourceEnvelope),same(source.envelope));
  assert.equal(f.state.writeSchema,1);assert.equal(f.state.activeUpgrade?.migrationId,migrationId);
  await assert.rejects(prepareUpgradeFinish({...input(f,finishContext),records:[],proofs:[]},f.owner.bundle));
  const finish=await prepareUpgradeFinish({...input(f,finishContext),records:[target],proofs:[]},f.owner.bundle);
  await append(f,finish,finish.body.binding.nextSecurityVersion);
  assert.equal(f.state.writeSchema,2);assert.equal(f.state.activeUpgrade,null);assert.equal(same(f.history.genesis),initialHistory);
  const ring=await readWorkspaceKeyRing(input(f,finishContext),f.state,f.owner.bundle),decoded=await readIdentityUpgradeContent(f.history,transition,'workspace',f.workspaceId,ring);
  assert.equal((decoded as {name:string}).name,'Private access workspace');
});

test('CP11 identity lifecycle: a validly signed semantic replacement cannot pass reviewed finish verification',async()=>{
  const f=await ownerFixture(),source=await workspaceSource(f),migrationId=randomUUID(),manifest=[source.reference],before=await context(f,migrationId,manifest,[source]);
  const start=await prepareUpgradeStart(input(f,before),f.owner.bundle);await append(f,start,start.body.binding.nextSecurityVersion);
  const current=await context(f,migrationId,manifest,[source],start),payload=await prepareIdentityUpgrade({...input(f,current),records:[source]},f.owner.bundle),
    ring=await readWorkspaceKeyRing(input(f,current),f.state,f.owner.bundle),key=base64urlDecode(ring[0]!.key,32),signing=base64urlDecode(f.owner.bundle.signingPrivateKey,64);
  try {
    const original=payload.upgradeItems[0]!,envelope=await encryptContent(original.envelope.header,{name:'Unauthorized semantic edit'},key,signing),digest=await digestObject(envelope),
      item={...original,envelope,target:{...original.target,digest}},body={...payload.mutation.body,
        objects:payload.mutation.body.objects.map(object=>({...object,digest})),upgrade:{...payload.mutation.body.upgrade,items:[{source:item.source,target:item.target}]}},
      signed=await signObject(body,signing),transition=identityUpgradeHistory.parse({...signed,upgradeItems:[item]});
    await append(f,transition,body.binding.nextSecurityVersion);
    const target={reference:item.target,envelope},finishContext=await context(f,migrationId,manifest,[target],start);
    await assert.rejects(prepareUpgradeFinish({...input(f,finishContext),records:[target],proofs:[]},f.owner.bundle),/Upgrade changed private content/);
    assert.equal(f.state.writeSchema,1);
  }finally{key.fill(0);signing.fill(0);}
});

test('CP11 identity lifecycle: pending profile content migrates without becoming an active account',async()=>{
  const f=await ownerFixture(),accountId=randomUUID(),migrationId=randomUUID(),ring=await readWorkspaceKeyRing({history:f.history,materials:f.materials,accountId:f.owner.accountId,deviceId:f.owner.deviceId},f.state,f.owner.bundle),
    key=base64urlDecode(ring[0]!.key,32),signing=base64urlDecode(f.owner.bundle.signingPrivateKey,64),role=Object.values(f.state.roles).find(role=>role.template==='member')!;
  try {
    const h={...f.initialWorkspace.header,recordType:'profile' as const,recordId:accountId,securityVersion:f.state.securityVersion,securityHead:f.state.securityHead,
      action:'profile.invite',operationId:randomUUID(),permissionVersion:role.revision},envelope=await encryptContent(h,{displayName:'Pending invitation',invitation:{version:1,kind:'join_member',
        role:{id:role.id,revision:role.revision,permissions:role.permissions},workspaceId:f.workspaceId,accountId,operationId:h.operationId,projectScope:{mode:'selected',projectIds:[]}}},key,signing),
      source={reference:{kind:'profile' as const,id:accountId,projectId:null,revision:'1',contentRevision:null,envelopeRevision:'1',schema:1 as const,keyEpoch:'1',digest:await digestObject(envelope)},envelope},
      manifest=[source.reference],before=await context(f,migrationId,manifest,[source]),start=await prepareUpgradeStart(input(f,before),f.owner.bundle);
    await append(f,start,start.body.binding.nextSecurityVersion);
    const current=await context(f,migrationId,manifest,[source],start),payload=await prepareIdentityUpgrade({...input(f,current),records:[source]},f.owner.bundle),transition=identityUpgradeHistory.parse({...payload.mutation,upgradeItems:payload.upgradeItems});
    await append(f,transition,transition.body.binding.nextSecurityVersion);
    assert.equal(f.state.profiles[accountId],undefined);assert.equal(f.state.pendingProfileContent?.[accountId]?.revision,'2');
    assert.equal(Object.values(f.state.devices).some(device=>device.accountId===accountId),false);
    const item=payload.upgradeItems[0]!,target={reference:item.target,envelope:item.envelope},finishContext=await context(f,migrationId,manifest,[target],start);
    const finish=await prepareUpgradeFinish({...input(f,finishContext),records:[target],proofs:[]},f.owner.bundle);await append(f,finish,finish.body.binding.nextSecurityVersion);
    assert.equal(f.state.profiles[accountId],undefined);assert.equal(f.state.writeSchema,2);
  }finally{key.fill(0);signing.fill(0);}
});

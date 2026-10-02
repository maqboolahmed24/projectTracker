import { randomUUID } from 'node:crypto';
import { base64urlDecode, digestObject, signObject } from '../src/shared/crypto.js';
import { upgradeFinish, upgradeLifecycleBinding, upgradeStart } from '../src/shared/upgrade-api.js';
import type { UpgradeRecordRef } from '../src/shared/encrypted-upgrades.js';
import { append, type OwnerFixture } from './project-create-client-fixture.js';

export async function signedUpgradeStart(f:OwnerFixture,source:UpgradeRecordRef[]) {
  const manifest=[...source].sort((a,b)=>`${a.kind}:${a.id}`<`${b.kind}:${b.id}`?-1:1),migrationId=randomUUID(),manifestDigest=await digestObject(manifest);
  const binding=await lifecycleBinding(f,migrationId,manifestDigest,manifest.length,[]),
    start=upgradeStart.parse(await signObject({purpose:'ukda.encrypted-upgrade-start.v1',binding,sourceSchema:1,targetSchema:2,transformId:'ukda.content-data.v2',manifest},base64urlDecode(f.owner.bundle.signingPrivateKey,64)));
  await append(f,start,binding.nextSecurityVersion);return {migrationId,manifestDigest,manifest};
}
async function lifecycleBinding(f:OwnerFixture,migrationId:string,manifestDigest:string,manifestCount:number,completed:UpgradeRecordRef[]) {
  const s=f.state,p=s.profiles[f.owner.accountId]!,d=s.devices[f.owner.deviceId]!,now=Date.now();
  return upgradeLifecycleBinding.parse({version:1,origin:s.origin,workspaceId:f.workspaceId,migrationId,operationId:randomUUID(),
    accountId:p.accountId,deviceId:d.id,credentialGeneration:p.credentialGeneration,sessionGeneration:p.sessionGeneration,keyGeneration:d.keyGeneration,signingPublicKey:d.signingPublicKey,
    securityVersion:s.securityVersion,nextSecurityVersion:String(BigInt(s.securityVersion)+1n),securityHead:s.securityHead,dataGeneration:s.dataGeneration,
    ownershipVersion:s.ownershipVersion,custodyEpoch:s.custodyEpoch,workspaceKeyEpoch:s.workspaceKeyEpoch,writeSchema:s.writeSchema??1,
    manifestDigest,manifestCount,completedDigest:await digestObject(completed),completedCount:completed.length,
    issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+600_000).toISOString()});
}
export async function signedUpgradeFinish(f:OwnerFixture,targets:UpgradeRecordRef[]) {
  const current=f.state.activeUpgrade!;targets=[...targets].sort((a,b)=>`${a.kind}:${a.id}`<`${b.kind}:${b.id}`?-1:1);
  const binding=await lifecycleBinding(f,current.migrationId,current.manifestDigest,current.manifest.length,targets),
    finish=upgradeFinish.parse(await signObject({purpose:'ukda.encrypted-upgrade-finish.v1',binding,sourceSchema:1,targetSchema:2,transformId:'ukda.content-data.v2',targets},base64urlDecode(f.owner.bundle.signingPrivateKey,64)));
  await append(f,finish,binding.nextSecurityVersion);
}

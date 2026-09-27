import { z } from 'zod';
import { base64urlDecode,canonicalJson,decryptContent,digestObject,signObject } from '../shared/crypto.js';
import { lifecycleContext,validateLifecycleMutation,verifyLifecycleActor,type LifecycleContext,type LifecycleMutation } from '../shared/lifecycle.js';
import { identityUpgradeHistory } from '../shared/encrypted-upgrades.js';
import { verifySecurityHistory,type SecurityHistoryInput } from '../shared/security-history.js';
import type { ContentEnvelope } from '../shared/contracts.js';
import type { PairingMaterial } from '../shared/pairing.js';
import type { DeviceBundle } from './device-store.js';
import { readWorkspaceKeyRing } from './teams-crypto.js';

export interface PrepareLifecycleInput {context:LifecycleContext;history:SecurityHistoryInput;materials:PairingMaterial[];accountId:string;deviceId:string;confirmationName?:string}
export class LifecycleClientError extends Error {constructor(readonly code:'INVALID_LIFECYCLE'|'NAME_MISMATCH'|'INCOMPLETE_KEYS'|'EXPIRED'){super(`Lifecycle request failed (${code})`);this.name='LifecycleClientError';}}
export async function prepareLifecycle(value:PrepareLifecycleInput,bundle:DeviceBundle):Promise<LifecycleMutation>{
 const input=structuredClone(value),context=lifecycleContext.parse(input.context),b=context.binding,state=await verifySecurityHistory(input.history);
 verifyLifecycleActor(b,state);
 if(b.accountId!==input.accountId||b.deviceId!==input.deviceId||bundle.signingPublicKey!==b.signingPublicKey||
  state.devices[b.deviceId]?.recipientPublicKey!==bundle.recipientPublicKey)throw new LifecycleClientError('INVALID_LIFECYCLE');
 if(Date.parse(b.expiresAt)<=Date.now()||Date.parse(b.issuedAt)>Date.now()+30000)throw new LifecycleClientError('EXPIRED');
 if(b.action==='request_deletion'){
  if(state.restoreQuarantine||!context.workspace||await digestObject(context.workspace)!==b.workspaceDigest||state.workspaceContent?.digest!==b.workspaceDigest)throw new LifecycleClientError('INVALID_LIFECYCLE');
  const ring=await readWorkspaceKeyRing(input,state,bundle);
  const open=async(envelope:ContentEnvelope)=>{
   const h=envelope.header,epoch=ring.find(k=>k.epoch===h.keyEpoch),signer=state.devices[h.deviceId];
   if(!epoch||!signer)throw new LifecycleClientError('INCOMPLETE_KEYS');
   const key=base64urlDecode(epoch.key,32);
   try{return await decryptContent(envelope,key,base64urlDecode(signer.signingPublicKey,32),h);}finally{key.fill(0);}
  };
  for(const transition of input.history.transitions){
   const upgraded=identityUpgradeHistory.safeParse(transition);if(!upgraded.success)continue;
   for(const item of upgraded.data.upgradeItems.filter(i=>i.source.kind==='workspace')){
    if(canonicalJson(await open(item.sourceEnvelope))!==canonicalJson(await open(item.envelope)))throw new LifecycleClientError('INVALID_LIFECYCLE');
   }
  }
  const current=z.strictObject({name:z.string().min(1),timezone:z.string().optional()}).parse(await open(context.workspace));
  if(input.confirmationName!==current.name)throw new LifecycleClientError('NAME_MISMATCH');
 }
 const key=base64urlDecode(bundle.signingPrivateKey,64);
 try{return await validateLifecycleMutation(await signObject({purpose:'ukda.workspace-lifecycle.v1' as const,binding:b,nameConfirmed:b.action==='request_deletion'},key),state);}
 finally{key.fill(0);}
}

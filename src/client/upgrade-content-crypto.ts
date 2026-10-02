import { avatarSelection } from '../shared/avatar.js';
import { z } from 'zod';
import { initialContentHeader, transcriptFromGenesis } from '../shared/activation.js';
import { identifier, type ContentEnvelope } from '../shared/contracts.js';
import { base64urlDecode, canonicalJson, decryptContent, digestObject } from '../shared/crypto.js';
import { enrolmentBinding } from '../shared/enrolment.js';
import { identityUpgradeHistory, validateIdentityUpgrade, type UpgradeItem } from '../shared/encrypted-upgrades.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';

type KeyRing = readonly { epoch:string;key:string }[];
const same=(left:unknown,right:unknown)=>canonicalJson(left)===canonicalJson(right);
const invitation=z.strictObject({version:z.literal(1),kind:z.enum(['join_member','join_owner']),role:enrolmentBinding.shape.role,
  workspaceId:identifier,accountId:identifier,operationId:identifier,projectScope:z.discriminatedUnion('mode',[
    z.strictObject({mode:z.literal('all_ordinary')}),z.strictObject({mode:z.literal('selected'),projectIds:z.array(identifier).max(255).refine(ids=>new Set(ids).size===ids.length&&same(ids,[...ids].sort()))})])})
  .refine(value=>(value.kind==='join_owner')===(value.projectScope.mode==='all_ordinary'));
const privateIdentity={
  workspace:z.strictObject({name:z.string(),timezone:z.string().optional()}),
  profile:z.strictObject({displayName:z.string().min(1).max(200),avatar:avatarSelection.optional(),invitation:invitation.optional()}),
  role:z.strictObject({displayName:z.string().trim().min(1).max(200)}),
};
export function validateIdentityContent(kind:'workspace'|'profile'|'role',value:unknown):void { privateIdentity[kind].parse(value); }

/** The caller first authenticates the envelope digest through its native record lineage. */
export async function decryptHistoricalContent(history:SecurityHistoryInput,envelope:ContentEnvelope,ring:KeyRing):Promise<unknown> {
  const h=envelope.header,entry=ring.find(key=>key.epoch===h.keyEpoch);if(!entry)throw new Error('Incomplete historical content keys');
  let publicKey:string,expected=h;
  if(h.securityVersion==='0') {
    if(h.recordType!=='workspace'&&h.recordType!=='profile'&&h.recordType!=='custody')throw new Error('Invalid initial content type');
    expected=initialContentHeader(transcriptFromGenesis(history.genesis.body),h.recordType);publicKey=history.genesis.body.device.signingPublicKey;
  } else {
    const length=Number(BigInt(h.securityVersion)-1n);
    if(!Number.isSafeInteger(length)||length<0||length>history.transitions.length)throw new Error('Invalid historical content authority');
    const {pin:_pin,...base}=history,state=await verifySecurityHistory({...base,transitions:history.transitions.slice(0,length),expected:{securityVersion:h.securityVersion,securityHead:h.securityHead}});
    const device=state.devices[h.deviceId];
    if(h.workspaceId!==state.workspaceId||!device||device.accountId!==h.accountId||device.keyGeneration!==h.keyGeneration)throw new Error('Invalid historical content signer');
    publicKey=device.signingPublicKey;
  }
  const key=base64urlDecode(entry.key,32);
  try{return await decryptContent(envelope,key,base64urlDecode(publicKey,32),expected);}finally{key.fill(0);}
}

export async function verifyDecodedUpgradeItem(history:SecurityHistoryInput,item:UpgradeItem,ring:KeyRing,
  validate:(value:unknown)=>unknown):Promise<unknown> {
  if(await digestObject(item.sourceEnvelope)!==item.source.digest||await digestObject(item.envelope)!==item.target.digest)throw new Error('Changed upgrade ciphertext');
  const source=await decryptHistoricalContent(history,item.sourceEnvelope,ring),target=await decryptHistoricalContent(history,item.envelope,ring);
  validate(source);validate(target);
  if(!same(source,target))throw new Error('Upgrade changed private content');
  return target;
}

/** Current role/profile readers can consume a migrated representation without changing its original author history. */
export async function readIdentityUpgradeContent(history:SecurityHistoryInput,value:unknown,kind:'workspace'|'profile'|'role',recordId:string,ring:KeyRing):Promise<unknown> {
  await verifySecurityHistory(history);
  const transition=identityUpgradeHistory.parse(value);
  if(!history.transitions.some(record=>same(record,transition)))throw new Error('Unanchored identity upgrade');
  const b=transition.body.binding,{pin:_pin,...base}=history,state=await verifySecurityHistory({...base,transitions:history.transitions.slice(0,Number(BigInt(b.securityVersion)-1n)),expected:{securityVersion:b.securityVersion,securityHead:b.securityHead}});
  const payload=await validateIdentityUpgrade({mutation:{body:transition.body,signature:transition.signature},upgradeItems:transition.upgradeItems},state);
  const item=payload.upgradeItems.find(item=>item.target.kind===kind&&item.target.id===recordId);
  if(!item)throw new Error('Missing identity upgrade item');
  return verifyDecodedUpgradeItem(history,item,ring,value=>validateIdentityContent(kind,value));
}

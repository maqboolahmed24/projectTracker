import { contentEnvelope, type permissionCapabilities } from '../shared/contracts.js';
import { resolveAvatarSelection, type AvatarSelection } from '../shared/avatar.js';
import { verifySecurityHistory, type SecurityHistoryState } from '../shared/security-history.js';
import type { DeviceBundle } from './device-store.js';
import { readWorkspaceKeyRing, type TeamKeyInput } from './teams-crypto.js';
import { readVerifiedIdentityContent, ProfileClientError } from './profile-crypto.js';

export interface DirectoryPerson {
  accountId:string;displayName:string;avatar:AvatarSelection;state:'active'|'suspended'|'removed';owner:boolean;
  roleId:string;roleRevision:string;projectIds:string[];
}
export interface WorkspaceDirectory {
  workspaceId:string;workspaceName:string;accountId:string;deviceId:string;isOwner:boolean;genesisFingerprint:string;
  people:DirectoryPerson[];projectIds:string[];permissions:(typeof permissionCapabilities)[number][];
  devices:{id:string;accountId:string;active:boolean;current:boolean}[];
  lifecycle:'active'|'pending_deletion'|'deleted';deletion:SecurityHistoryState['deletion'];
  restoreQuarantine:boolean;activeRestore:SecurityHistoryState['activeRestore'];
  licenceState:SecurityHistoryState['licenceState'];entitlementState:SecurityHistoryState['entitlementState'];
  writeSchema:1|2;activeUpgrade:SecurityHistoryState['activeUpgrade'];
}
export type ReadWorkspaceDirectoryInput=TeamKeyInput;
/** The complete current signed workspace directory is opened only inside the Worker. */
export async function readWorkspaceDirectory(value:ReadWorkspaceDirectoryInput,bundle:DeviceBundle):Promise<WorkspaceDirectory>{
  const input=structuredClone(value),state=await verifySecurityHistory(input.history),person=state.profiles[input.accountId],device=state.devices[input.deviceId];
  const invalid=():never=>{throw new ProfileClientError('INVALID_PROFILE');};
  if(!person?.active||!device?.active||device.accountId!==input.accountId||state.lifecycle==='deleted'||state.restoreQuarantine||
    state.deletion&&Date.parse(state.deletion.deleteAfter)<=Date.now()||!state.workspaceContent)invalid();
  const ring=await readWorkspaceKeyRing(input,state,bundle);
  const material=(id:string,kind:string,digest:string)=>{const found=input.materials.filter(m=>m.id===id);if(found.length!==1||found[0]!.kind!==kind||found[0]!.digest!==digest)invalid();return contentEnvelope.parse(found[0]!.value);};
  const ref=state.workspaceContent!;
  const workspace=await readVerifiedIdentityContent(input.history,state,'workspace',state.workspaceId,material(ref.objectId,'encrypted_workspace',ref.digest),ring) as {name:string};
  const people:DirectoryPerson[]=[];
  for(const p of Object.values(state.profiles)){
    const profile=await readVerifiedIdentityContent(input.history,state,'profile',p.accountId,material(p.profile.objectId,'encrypted_profile',p.profile.objectDigest),ring) as {displayName:string;avatar?:AvatarSelection};
    people.push({accountId:p.accountId,displayName:profile.displayName,avatar:resolveAvatarSelection(profile.avatar),state:p.state,owner:p.owner,
      roleId:p.role.id,roleRevision:p.role.revision,projectIds:p.scopes.filter(s=>s.scope==='project').map(s=>s.scopeId)});
  }
  const live=(s:{expiresAt:string|null})=>s.expiresAt===null||Date.parse(s.expiresAt)>Date.now();
  const eligible=device!.scopes.filter(s=>live(s)&&s.permissions.includes('read_project')&&person!.scopes.some(p=>p.scope===s.scope&&p.scopeId===s.scopeId&&p.mode===s.mode&&p.keyEpoch===s.keyEpoch&&live(p)&&s.permissions.every(permission=>p.permissions.includes(permission)))&&
    s.keyEpoch===(s.mode==='custody'?state.custodyEpoch:state.scopeHeads[`${s.scope}:${s.scopeId}`]?.keyEpoch));
  return {workspaceId:state.workspaceId,workspaceName:workspace.name,accountId:input.accountId,deviceId:input.deviceId,isOwner:person!.owner,genesisFingerprint:state.genesisFingerprint,
    people,projectIds:eligible.filter(s=>s.scope==='project').map(s=>s.scopeId),permissions:eligible.find(s=>s.scope==='workspace')?.permissions??[],
    devices:Object.values(state.devices).filter(d=>person!.owner||d.accountId===input.accountId).map(d=>({id:d.id,accountId:d.accountId,active:d.active,current:d.id===input.deviceId})),
    lifecycle:state.lifecycle??'active',deletion:state.deletion??null,restoreQuarantine:state.restoreQuarantine??false,activeRestore:state.activeRestore??null,
    licenceState:state.licenceState,entitlementState:state.entitlementState,writeSchema:state.writeSchema??1,activeUpgrade:state.activeUpgrade??null};
}

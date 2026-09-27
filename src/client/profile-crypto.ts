import { contentEnvelope, type ContentEnvelope } from '../shared/contracts.js';
import { digestObject } from '../shared/crypto.js';
import { resolveAvatarSelection, type AvatarSelection } from '../shared/avatar.js';
import { identityUpgradeHistory } from '../shared/encrypted-upgrades.js';
import { verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState } from '../shared/security-history.js';
import type { DeviceBundle } from './device-store.js';
import { readWorkspaceKeyRing, type TeamKeyInput } from './teams-crypto.js';
import { decryptHistoricalContent, readIdentityUpgradeContent, validateIdentityContent } from './upgrade-content-crypto.js';

export class ProfileClientError extends Error {
  constructor(readonly code:'INVALID_PROFILE'|'CONFLICT'|'CANCELLED'|'TRUST_REQUIRED') {super(`Profile read failed (${code})`);this.name='ProfileClientError';}
}
function invalid():never {throw new ProfileClientError('INVALID_PROFILE');}
type KeyRing=Awaited<ReturnType<typeof readWorkspaceKeyRing>>;
/** Authenticate the exact current signed reference before any private identity is opened. */
export async function readVerifiedIdentityContent(history:SecurityHistoryInput,state:SecurityHistoryState,kind:'workspace'|'profile',id:string,envelope:ContentEnvelope,ring:KeyRing):Promise<unknown> {
  const hash=await digestObject(envelope),ref=kind==='workspace'?state.workspaceContent:state.profiles[id]?.profile;
  const expected=ref&&('digest'in ref?ref.digest:ref.objectDigest),revision=ref?.revision,h=envelope.header;
  if(!ref||hash!==expected||h.workspaceId!==state.workspaceId||h.recordId!==id||h.recordType!==kind||h.revision!==revision||h.scope!=='workspace'||h.scopeId!==state.workspaceId)invalid();
  for(const value of [...history.transitions].reverse()) {
    const parsed=identityUpgradeHistory.safeParse(value);if(!parsed.success)continue;
    if(parsed.data.upgradeItems.some(item=>item.target.kind===kind&&item.target.id===id&&item.target.digest===hash))return readIdentityUpgradeContent(history,parsed.data,kind,id,ring);
  }
  const value=await decryptHistoricalContent(history,envelope,ring);validateIdentityContent(kind,value);return value;
}
export interface ReadCurrentProfileInput extends TeamKeyInput {}
export interface CurrentProfile {workspaceId:string;accountId:string;revision:string;displayName:string;avatar:AvatarSelection}
/** Worker-only current self profile; the default for older profiles is presentation only. */
export async function readCurrentProfile(value:ReadCurrentProfileInput,bundle:DeviceBundle):Promise<CurrentProfile> {
  const input=structuredClone(value),state=await verifySecurityHistory(input.history),profile=state.profiles[input.accountId];
  if(state.lifecycle==='deleted'||state.restoreQuarantine||state.deletion&&Date.parse(state.deletion.deleteAfter)<=Date.now()||!profile?.active)invalid();
  const ring=await readWorkspaceKeyRing(input,state,bundle),ref=profile.profile;
  const candidates=input.materials.filter(item=>item.id===ref.objectId);
  if(candidates.length!==1)invalid();
  const material=candidates[0]!;
  if(material.kind!=='encrypted_profile'||material.digest!==ref.objectDigest)invalid();
  const envelope=contentEnvelope.parse(material.value),raw=await readVerifiedIdentityContent(input.history,state,'profile',input.accountId,envelope,ring) as {displayName:string;avatar?:unknown};
  return {workspaceId:state.workspaceId,accountId:input.accountId,revision:ref.revision,displayName:raw.displayName,avatar:resolveAvatarSelection(raw.avatar)};
}

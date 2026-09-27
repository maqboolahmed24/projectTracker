import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { DEFAULT_AVATAR } from '../src/shared/avatar.js';
import { readCurrentProfile } from '../src/client/profile-crypto.js';
import { startLogin, finishLogin } from '../src/client/opaque.js';
import { accessChangeFixture } from './access-change-fixture.js';
import { oldPassword } from './password-change-fixture.js';

const denied=(e:unknown)=>e instanceof AppError&&['AUTH_REQUIRED','DEVICE_APPROVAL_REQUIRED','SESSION_REVOKED','ACCESS_FORBIDDEN','SESSION_INVALID','SESSION_EXPIRED'].includes(e.code);
test('Avatar delivery: only an approved current actor receives its own encrypted profile; revoked and password-only sessions are denied',async(t)=>{
  const f=await accessChangeFixture(t),owner=f.auth(),request={workspaceId:f.workspaceId,includeProfile:true as const};
  const unchanged=await f.access.currentDelivery(owner.cookieValue,owner.csrfToken,{workspaceId:f.workspaceId});
  assert.equal(unchanged.materials.some(m=>m.kind==='encrypted_profile'),false,'Existing callers retain the key-only payload');
  const delivered=await f.access.currentDelivery(owner.cookieValue,owner.csrfToken,request),profiles=delivered.materials.filter(m=>m.kind==='encrypted_profile');
  assert.equal(profiles.length,1);assert.equal(profiles[0]!.id,f.accountId);
  const own=await readCurrentProfile({history:await f.history(),materials:delivered.materials,accountId:f.accountId,deviceId:f.deviceId},f.originalBundle);
  assert.equal(own.displayName,'Password fixture Owner');assert.deepEqual(own.avatar,DEFAULT_AVATAR);
  assert.equal(JSON.stringify(delivered).includes('Password fixture Owner'),false);
  await assert.rejects(f.access.currentDelivery(owner.cookieValue,owner.csrfToken,{...request,accountId:randomUUID()}),e=>e instanceof AppError&&e.code==='ACCESS_INVALID');
  const started=await startLogin(oldPassword),response=await f.authentication.startLogin({workspaceId:f.workspaceId,accountId:f.accountId,startLoginRequest:started.startLoginRequest}),
    finished=await finishLogin({password:oldPassword,clientLoginState:started.clientLoginState,loginResponse:response.loginResponse,configuration:response.configuration}),
    restricted=await f.authentication.finishLogin({loginId:response.loginId,finishLoginRequest:finished.finishLoginRequest});
  await assert.rejects(f.access.currentDelivery(restricted.cookieValue,restricted.csrfToken,request),denied);
  const member=await f.joined(),memberDelivery=await f.access.currentDelivery(member.auth.cookieValue,member.auth.csrfToken,request),memberProfiles=memberDelivery.materials.filter(m=>m.kind==='encrypted_profile');
  assert.equal(memberProfiles.length,1);assert.equal(memberProfiles[0]!.id,member.approval.profile!.id);
  assert.equal(memberDelivery.materials.every(m=>m.kind==='key_envelope'||m.id===member.approval.profile!.id),true);
  const memberInput={history:await f.history(),materials:memberDelivery.materials,accountId:member.binding.accountId,deviceId:member.prepared.draft.transcript.device.id};
  assert.equal((await readCurrentProfile(memberInput,member.bundle)).displayName,'Confirmed private person');
  const oldInvitation=structuredClone(memberInput),current=oldInvitation.materials.findIndex(m=>m.kind==='encrypted_profile');
  oldInvitation.materials[current]={...oldInvitation.materials[current]!,value:member.profile.envelope};
  await assert.rejects(readCurrentProfile(oldInvitation,member.bundle),'An older valid invitation cannot stand in for the confirmed profile');
  const removal=await f.draft('remove',member.binding.accountId);await f.finalize(removal);
  await assert.rejects(f.access.currentDelivery(member.auth.cookieValue,member.auth.csrfToken,request),denied);
  await assert.rejects(readCurrentProfile({...memberInput,history:await f.history()},member.bundle));
});

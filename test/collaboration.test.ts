import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { base64urlDecode, digestObject, encryptContent, randomKey, signObject } from '../src/shared/crypto.js';
import { collaborationAudit,collaborationMutation, collaborationBindingFromPlanning, collaborationCommand, collaborationEntryPin, collaborationHeader, collaborationListRequest,
  collaborationText, assertCollaborationCurrentBinding, assertCollaborationPin, evaluateCollaboration, validateCollaborationPayload, verifyCollaborationBinding,
  verifyCollaborationEntry, CollaborationError, type CollaborationBinding, type CollaborationCommand, type CollaborationEntry, type CollaborationPayload,
  type VerifiedCollaborationEntry } from '../src/shared/collaboration.js';
import { verifyPlanningContext } from '../src/shared/planning-api.js';
import { preparePlanning, planningSecurityResolver, type PlanningIntent } from '../src/client/planning-crypto.js';
import { planningClientFixture } from './planning-client-fixture.js';

const rejects=(code:CollaborationError['code'],fn:()=>unknown)=>assert.throws(fn,e=>e instanceof CollaborationError&&e.code===code);
async function fixture() {
  const f=await planningClientFixture({version:2}),taskId=randomUUID();
  const apply=async(command:PlanningIntent,content?:{title:string}|{name:string},outcome?:string)=>{
    const payload=await preparePlanning({...await f.input(),command,...(content?{content}:{}),...(outcome?{outcome}:{})},f.f.owner.bundle);
    await f.apply(payload);return payload;
  };
  await apply({action:'create_task',task:{id:taskId,phaseId:null,milestoneId:null,assigneeIds:[],leadProfileId:null}},{title:'Private shared task'});
  const securityAt=planningSecurityResolver(f.f.history,f.f.state);
  const context=async(operationId:string=randomUUID())=>verifyPlanningContext(await f.context(operationId),securityAt);
  const payload=async(binding:CollaborationBinding,command:CollaborationCommand,original?:VerifiedCollaborationEntry):Promise<CollaborationPayload>=>{
    const key=await randomKey(),signing=base64urlDecode(f.f.owner.bundle.signingPrivateKey,64);
    try {
      const post=command.action.startsWith('post_'),content=post?await encryptContent(collaborationHeader(binding,binding.kind),{text:'Private collaboration text'},key,signing):null,
        contentDigest=content?await digestObject(content):null,auditId=randomUUID();
      const auditData=collaborationAudit.parse({version:1,action:command.action,entryId:binding.entryId,originalDigest:contentDigest??original!.originalDigest,
        beforeHidden:post?null:false,afterHidden:!post,reason:post?null:'Private moderation reason'});
      const audit={id:auditId,envelope:await encryptContent(collaborationHeader(binding,'audit',auditId),auditData,key,signing)};
      return {mutation:collaborationMutation.parse(await signObject({purpose:binding.version===1?'ukda.collaboration.v1':'ukda.collaboration.v2',binding,command,contentDigest,audit:{id:auditId,digest:await digestObject(audit.envelope)}},signing)),content,audit};
    }finally{key.fill(0);signing.fill(0);}
  };
  const post=async(kind:'comment'|'update'='comment')=>{
    const planning=await context(),entryId=randomUUID(),binding=collaborationBindingFromPlanning(planning.binding,{entryId,kind}),
      command:CollaborationCommand=kind==='comment'?{action:'post_comment',entryId,taskId}:{action:'post_update',entryId,phaseId:null},prepared=await payload(binding,command),
      entry:CollaborationEntry={origin:{kind:'post',payload:prepared},moderation:null};
    return {planning,binding,command,payload:prepared,entry,verified:await verifyCollaborationEntry(entry,planning,securityAt)};
  };
  return {...f,taskId,applyPlanning:apply,securityAt,context,payload,post};
}

test('CP09 contract: distinct simultaneous posts from one planning context do not consume its revision or planning head',async()=>{
  const f=await fixture(),planning=await f.context(),before=structuredClone(planning.graph);
  const posts=await Promise.all([randomUUID(),randomUUID()].map(async entryId=>{
    const binding=collaborationBindingFromPlanning({...planning.binding,operationId:randomUUID()},{entryId,kind:'comment'}),command:CollaborationCommand={action:'post_comment',entryId,taskId:f.taskId},payload=await f.payload(binding,command);
    await assertCollaborationCurrentBinding(binding,{...planning,binding:{...planning.binding,operationId:binding.operationId}});
    return validateCollaborationPayload(payload,binding,planning.graph);
  }));
  assert.notEqual(posts[0]!.result.entryId,posts[1]!.result.entryId);assert.ok(posts.every(p=>p.result.revision==='1'&&!p.result.hidden));
  assert.deepEqual(planning.graph,before);assert.equal((await f.context()).binding.beforeHead,planning.binding.beforeHead);
});

test('CP09 contract: unrelated planning changes do not conflict with posting; current terminal scope still rejects the stale preparation',async()=>{
  const f=await fixture(),post=await f.post();
  await f.applyPlanning({action:'start_project'});
  const active=await f.context(post.binding.operationId);
  await assertCollaborationCurrentBinding(post.binding,active);
  await validateCollaborationPayload(post.payload,post.binding,active.graph);
  await f.applyPlanning({action:'cancel_project'},undefined,'Explicit terminal scope');
  const terminal=await f.context(post.binding.operationId);
  await assertCollaborationCurrentBinding(post.binding,terminal);
  await assert.rejects(validateCollaborationPayload(post.payload,post.binding,terminal.graph),e=>e instanceof CollaborationError&&e.code==='scope_read_only');
  const verified=await verifyCollaborationEntry(post.entry,terminal,f.securityAt);
  assert.equal(verified.entryId,post.binding.entryId,'historical valid post remains verifiable after later closure');
});

test('CP09 contract: effective comment permission authorizes participation but Owner identity does not bypass device limits',async()=>{
  const f=await fixture(),post=await f.post(),commenter={...post.binding,permissions:['read_project','comment'] as CollaborationBinding['permissions']};
  assert.equal(evaluateCollaboration(post.command,commenter,post.planning.graph).taskId,f.taskId);
  for(const permissions of [['read_project'],['read_project','manage_tasks']] as CollaborationBinding['permissions'][]) {
    rejects('permission_denied',()=>evaluateCollaboration(post.command,{...post.binding,isOwner:true,permissions},post.planning.graph));
  }
  rejects('not_found',()=>evaluateCollaboration({...post.command,action:'post_comment',taskId:randomUUID()},commenter,post.planning.graph));
  const done={...post.planning.graph,tasks:post.planning.graph.tasks.map(t=>({...t,state:'done' as const}))};
  rejects('scope_read_only',()=>evaluateCollaboration(post.command,commenter,done));
});

test('CP09 contract: task and update moderation have distinct fixed capabilities and remain possible in archived parents',async()=>{
  const f=await fixture(),comment=await f.post(),update=await f.post('update');
  await f.applyPlanning({action:'cancel_project'},undefined,'Close scope');await f.applyPlanning({action:'archive_project'});
  const graph=(await f.context()).graph;
  for(const item of [comment,update]) {
    const command:CollaborationCommand={action:item.verified.kind==='comment'?'hide_comment':'hide_update',entryId:item.verified.entryId,expectedRevision:'1',previousHead:item.verified.head,originalDigest:item.verified.originalDigest};
    const required=item.verified.kind==='comment'?'manage_tasks':'plan_projects',other=required==='manage_tasks'?'plan_projects':'manage_tasks';
    rejects('permission_denied',()=>evaluateCollaboration(command,{...item.binding,permissions:['read_project','comment']},graph,item.verified));
    rejects('permission_denied',()=>evaluateCollaboration(command,{...item.binding,permissions:['read_project',other]},graph,item.verified));
    const result=evaluateCollaboration(command,{...item.binding,permissions:['read_project',required]},graph,item.verified);
    assert.equal(result.hidden,true);assert.equal(result.revision,'2');
  }
});

test('CP09 contract: hide is one revisioned lineage and preserves original ciphertext; stale competing hide and rollback pins fail',async()=>{
  const f=await fixture(),post=await f.post();
  const planning=await f.context(),binding=collaborationBindingFromPlanning(planning.binding,{entryId:post.verified.entryId,kind:'comment'}),
    command:CollaborationCommand={action:'hide_comment',entryId:binding.entryId,expectedRevision:'1',previousHead:post.verified.head,originalDigest:post.verified.originalDigest},
    moderation=await f.payload(binding,command,post.verified),hiddenEntry={...post.entry,moderation};
  const validated=await validateCollaborationPayload(moderation,binding,planning.graph,post.verified),hidden=await verifyCollaborationEntry(hiddenEntry,planning,f.securityAt);
  assert.equal(validated.result.revision,'2');assert.equal(hidden.hidden,true);assert.deepEqual(hidden.original,post.payload.content);
  assertCollaborationPin(hidden,collaborationEntryPin(post.verified));
  rejects('revision_conflict',()=>assertCollaborationPin(post.verified,collaborationEntryPin(hidden)));
  rejects('revision_conflict',()=>assertCollaborationPin({...hidden,originHead:'a'.repeat(64)},collaborationEntryPin(post.verified)));
  rejects('revision_conflict',()=>assertCollaborationPin({...hidden,lineageHeads:[{revision:'1',head:'a'.repeat(64)},{revision:hidden.revision,head:hidden.head}]},collaborationEntryPin(post.verified)));
  rejects('revision_conflict',()=>evaluateCollaboration(command,binding,planning.graph,hidden));
  await assert.rejects(validateCollaborationPayload({...moderation,content:post.payload.content},binding,planning.graph,post.verified));
  assert.equal(post.entry.moderation,null,'verification never mutates the original entry');
});

test('CP09 contract: signed ciphertext, audit and exact target bindings reject tampering',async()=>{
  const f=await fixture(),post=await f.post();
  const ciphertext=structuredClone(post.payload);ciphertext.content!.ciphertext=(ciphertext.content!.ciphertext[0]==='A'?'B':'A')+ciphertext.content!.ciphertext.slice(1);
  await assert.rejects(validateCollaborationPayload(ciphertext,post.binding,post.planning.graph));
  const audit=structuredClone(post.payload);audit.mutation.body.audit.digest='a'.repeat(64);
  await assert.rejects(validateCollaborationPayload(audit,post.binding,post.planning.graph));
  const stale={...post.binding,credentialGeneration:String(BigInt(post.binding.credentialGeneration)+1n)};
  await assert.rejects(assertCollaborationCurrentBinding(stale,post.planning));
  await assert.rejects(assertCollaborationCurrentBinding({...post.binding,planningAnchor:{version:'0',head:'a'.repeat(64)}},post.planning));
  rejects('already_exists',()=>evaluateCollaboration(post.command,post.binding,post.planning.graph,post.verified));
  assert.equal(collaborationCommand.safeParse({...post.command,text:'Hosted plaintext is not a command field'}).success,false);
});

test('CP09 contract: historical verification uses authenticated signer authority and rejects valid signatures without the historical capability',async()=>{
  const f=await fixture(),post=await f.post();
  assert.equal((await verifyCollaborationEntry(post.entry,post.planning,f.securityAt)).signingPublicKey,f.f.owner.bundle.signingPublicKey);
  const untrusted=structuredClone(f.f.state);untrusted.devices[post.binding.deviceId]!.active=false;
  rejects('permission_denied',()=>verifyCollaborationBinding(post.binding,untrusted));
  await assert.rejects(verifyCollaborationEntry(post.entry,post.planning,async()=>untrusted));
  // A genuine key can sign a capability claim; historical profile/device authority must still match it.
  const forgedBinding={...post.binding,permissions:['read_project'] as CollaborationBinding['permissions']},forged=await f.payload(forgedBinding,post.command);
  await assert.rejects(verifyCollaborationEntry({origin:{kind:'post',payload:forged},moderation:null},post.planning,f.securityAt));
});

test('CP09 contract: hiding an existing planning outcome retains the immutable original, historical signer and closing snapshot',async()=>{
  const f=await fixture(),closure=await f.applyPlanning({action:'cancel_project'},undefined,'Private original closing outcome'),planning=await f.context(),saved=structuredClone(planning);
  const origin:CollaborationEntry={origin:{kind:'planning',operationId:closure.mutation.body.binding.operationId,entryId:closure.outcome!.id},moderation:null},
    original=await verifyCollaborationEntry(origin,planning,f.securityAt),binding=collaborationBindingFromPlanning(planning.binding,{entryId:original.entryId,kind:'update'}),
    command:CollaborationCommand={action:'hide_update',entryId:original.entryId,expectedRevision:'1',previousHead:original.head,originalDigest:original.originalDigest},
    moderation=await f.payload(binding,command,original);
  await validateCollaborationPayload(moderation,binding,planning.graph,original);
  const hidden=await verifyCollaborationEntry({...origin,moderation},planning,f.securityAt);
  assert.equal(hidden.hidden,true);assert.deepEqual(hidden.original,closure.outcome!.envelope);assert.equal(hidden.originalHeader.action,'planning.change');
  assert.deepEqual(planning,saved);assert.equal(hidden.auditHeaders.length,2);
  await assert.rejects(verifyCollaborationEntry({...origin,origin:{kind:'planning',operationId:randomUUID(),entryId:original.entryId}},planning,f.securityAt));
});

test('CP09 contract: private text/reason and feed limits are explicit; no edit or unhide action exists',()=>{
  assert.equal(collaborationText.safeParse({text:'   '}).success,false);assert.equal(collaborationText.safeParse({text:'a'.repeat(20_001)}).success,false);
  const base={version:1,action:'hide_comment',entryId:randomUUID(),originalDigest:'a'.repeat(64),beforeHidden:false,afterHidden:true};
  assert.equal(collaborationAudit.safeParse({...base,reason:'  '}).success,false);assert.equal(collaborationAudit.safeParse({...base,reason:null}).success,false);
  assert.equal(collaborationAudit.safeParse({...base,reason:'Necessary moderation'}).success,true);
  assert.equal(collaborationCommand.safeParse({action:'edit_comment',entryId:randomUUID()}).success,false);
  assert.equal(collaborationCommand.safeParse({action:'unhide_update',entryId:randomUUID()}).success,false);
  const request={workspaceId:randomUUID(),projectId:randomUUID(),kind:'comment'};
  assert.equal(collaborationListRequest.safeParse({...request,limit:101}).success,false);
  assert.equal(collaborationListRequest.safeParse({...request,after:randomUUID()}).success,false);
  assert.equal(collaborationListRequest.safeParse({...request,phaseId:randomUUID()}).success,false);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { base64urlDecode, canonicalJson, digestObject, encryptContent, signObject } from '../src/shared/crypto.js';
import { planningAuthority, planningUpgradeReference, validatePlanningPayload, type PlanningContext } from '../src/shared/planning-api.js';
import { evaluatePlanning, planningRevisionSnapshot } from '../src/shared/planning.js';
import { openVerifiedPlanning, preparePlanning, readPlanning, type PlanningIntent, type PlanningPrivateContent } from '../src/client/planning-crypto.js';
import { planningClientFixture } from './planning-client-fixture.js';
import { signedUpgradeStart, signedUpgradeFinish } from './upgrade-client-fixture.js';

type Fixture=Awaited<ReturnType<typeof planningClientFixture>>;
async function execute(f:Fixture,command:PlanningIntent,content?:PlanningPrivateContent,outcome?:string) {
  const payload=await preparePlanning({...await f.input(),command,...(content?{content}:{}),...(outcome?{outcome}:{})},f.f.owner.bundle);await f.apply(payload);return payload;
}
const canonical=(value:unknown)=>canonicalJson(value);

test('CP11 planning: upgrading reviewed and completed work retains semantic revisions, old snapshots and signed history',async()=>{
  const f=await planningClientFixture({version:2,secondOwner:true}),reviewer=f.secondOwner!,taskId=randomUUID(),doneId=randomUUID(),milestoneId=randomUUID();
  await execute(f,{action:'start_project'});
  await execute(f,{action:'create_milestone',milestone:{id:milestoneId,phaseId:null,ownerProfileId:null}},{name:'Historical accepted milestone'});
  await execute(f,{action:'accept_milestone',milestoneId},undefined,'Original closing outcome');
  for(const id of [taskId,doneId])await execute(f,{action:'create_task',task:{id,phaseId:null,milestoneId:null,assigneeIds:[f.f.owner.accountId],leadProfileId:null}},{title:'Preserve task content',description:'',acceptanceCriteria:'Explicit acceptance'});
  await execute(f,{action:'request_task_completion',taskId:doneId,acceptanceConfirmed:true});
  await execute(f,{action:'set_project_review',enabled:true,reviewers:[{taskId,reviewerProfileId:reviewer.accountId}]},undefined,'Require independent review');
  await execute(f,{action:'request_task_completion',taskId,acceptanceConfirmed:true});
  const before:PlanningContext=await f.context(),readBefore=await readPlanning(await f.input(),f.f.owner.bundle),source=await Promise.all(before.records.map(record=>planningUpgradeReference(before.graph,record))),
    migration=await signedUpgradeStart(f.f,source),reviewBefore=before.graph.tasks.find(task=>task.id===taskId)!;
  f.upgrade(3);
  const input=await f.input(),payload=await preparePlanning({...input,command:{action:'upgrade_content',records:input.context.records.map(({kind,id})=>({kind,id}))},upgrade:migration},f.f.owner.bundle);
  assert.equal(payload.mutation.body.purpose,'ukda.planning-mutation.v3');
  assert.equal('upgrade' in payload.mutation.body && Object.hasOwn(payload.mutation.body.upgrade!,'manifest'),false,'Only the authenticated manifest digest enters the bounded proof');
  await f.apply(payload);
  const upgraded:PlanningContext=await f.context(),read=await readPlanning(await f.input(),f.f.owner.bundle),review=upgraded.graph.tasks.find(task=>task.id===taskId)!;
  assert.equal(review.state,'review');assert.equal(review.submittedRevision,reviewBefore.submittedRevision);assert.equal(review.submittedPolicyRevision,reviewBefore.submittedPolicyRevision);
  assert.equal(review.contentRevision,reviewBefore.contentRevision);assert.equal(BigInt(review.revision),BigInt(reviewBefore.revision)+1n);
  assert.equal(canonical(upgraded.graph.snapshots),canonical(before.graph.snapshots));
  assert.equal(canonical(upgraded.history.slice(0,before.history.length)),canonical(before.history));
  assert.equal(canonical(read.audits.slice(0,readBefore.audits.length)),canonical(readBefore.audits));
  for(const item of payload.upgradeItems!) {assert.equal(item.envelope.header.schema,2);assert.equal(item.target.envelopeRevision,item.target.revision);}
  await assert.rejects(preparePlanning({...await f.input(),command:{action:'set_task_todo',taskId}},f.f.owner.bundle),'maintenance rejects ordinary writes');
  const targets=await Promise.all(upgraded.records.map(record=>planningUpgradeReference(upgraded.graph,record)));await signedUpgradeFinish(f.f,targets);
  const approved=await preparePlanning({...await f.input(undefined,reviewer),command:{action:'approve_task',taskId,submittedRevision:review.submittedRevision!,submittedPolicyRevision:review.submittedPolicyRevision!}},reviewer.bundle);
  await f.apply(approved);
  assert.equal(canonical(approved.records.find(record=>record.id===taskId)!.envelope),canonical(upgraded.records.find(record=>record.id===taskId)!.envelope));
  assert.equal((await readPlanning(await f.input(),f.f.owner.bundle)).graph.tasks.find(task=>task.id===taskId)!.state,'done');
  await execute(f,{action:'reopen_task',taskId},undefined,'Explicit semantic reopening');
  const edit=await execute(f,{action:'edit_task',taskId},{title:'New schema two content',description:'',acceptanceCriteria:'Explicit acceptance'}),envelope=edit.records.find(record=>record.id===taskId)!.envelope;
  assert.equal(envelope.header.schema,2);assert.ok(BigInt(envelope.header.revision)>BigInt(upgraded.records.find(record=>record.id===taskId)!.envelope.header.revision));
  assert.equal((await readPlanning(await f.input(),f.f.owner.bundle)).records.find(record=>record.id===taskId)!.content.title,'New schema two content');
});

test('CP11 planning: Owner designation without plan permission cannot migrate, and a signed private-content substitution fails local replay',async()=>{
  const f=await planningClientFixture({version:2}),taskId=randomUUID();
  await execute(f,{action:'create_task',task:{id:taskId,phaseId:null,milestoneId:null,assigneeIds:[f.f.owner.accountId],leadProfileId:null}},{title:'Original task',description:'',acceptanceCriteria:''});
  const before=await f.context(),migration=await signedUpgradeStart(f.f,await Promise.all(before.records.map(record=>planningUpgradeReference(before.graph,record))));f.upgrade(3);
  const input=await f.input(),command={action:'upgrade_content' as const,records:[{kind:'task' as const,id:taskId}]},domainCommand={...command,operationId:input.context.binding.operationId,expected:planningRevisionSnapshot(input.context.graph)},authority=planningAuthority(input.context.binding);
  assert.throws(()=>evaluatePlanning(input.context.graph,domainCommand,{...authority,access:{...authority.access!,permissions:['read_project']}}));
  const payload=await preparePlanning({...input,command,upgrade:migration},f.f.owner.bundle),opened=await openVerifiedPlanning(input,f.f.owner.bundle),
    key=base64urlDecode(opened.ring.find(key=>key.epoch===input.context.binding.keyEpoch)!.key,32),signing=base64urlDecode(f.f.owner.bundle.signingPrivateKey,64);
  try {
    assert.equal(payload.mutation.body.purpose,'ukda.planning-mutation.v3');if(payload.mutation.body.purpose!=='ukda.planning-mutation.v3')throw new Error('Expected v3');
    const item=payload.upgradeItems![0]!,envelope=await encryptContent(item.envelope.header,{title:'Forged semantic change',description:'',acceptanceCriteria:''},key,signing),digest=await digestObject(envelope),
      changed={...item,envelope,target:{...item.target,digest}},body={...payload.mutation.body,records:payload.mutation.body.records.map(ref=>({...ref,digest})),
        upgrade:{...payload.mutation.body.upgrade!,items:[{source:changed.source,target:changed.target}]}},forged={...payload,upgradeItems:[changed],records:[{kind:'task' as const,id:taskId,envelope}],mutation:await signObject(body,signing)};
    // The server validates signed metadata only; the reviewed client transform proves private equivalence.
    await validatePlanningPayload(forged,input.context.binding,input.context.graph,input.context.records);await f.apply(forged);
    await assert.rejects(readPlanning(await f.input(),f.f.owner.bundle));
  }finally{key.fill(0);signing.fill(0);}
});

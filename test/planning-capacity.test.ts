import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { mkdir, writeFile } from 'node:fs/promises';
import { base64urlDecode, canonicalJson, digestObject, encryptContent, signObject } from '../src/shared/crypto.js';
import { planningAuthority, planningChangedRecords, planningContentHeader, planningCommand, planningPayload, planningFrame, planningGraphDigest,
  planningRecordReplacesContent, planningEnvelopeRevision, planningUpgradeReference, readPlanningOperationPages,
  clearPlanningReplayCache, PLANNING_HISTORY_PAGE_SIZE, type PlanningPayload, type PlanningContext, type PlanningOperationsPage } from '../src/shared/planning-api.js';
import { evaluatePlanning } from '../src/shared/planning.js';
import { openVerifiedPlanning, preparePlanning, readPlanning, type PlanningIntent, type PlanningAuditData } from '../src/client/planning-crypto.js';
import { planningClientFixture } from './planning-client-fixture.js';
import { signedUpgradeStart, signedUpgradeFinish } from './upgrade-client-fixture.js';
import type { Actor } from './project-create-client-fixture.js';

/** Opt-in capacity acceptance. Build real signed operations without repeatedly replaying the entire growing history while seeding. */
test('512-task signed lifecycle stays within bounded transport and retains independent review, corrections and immutable content',
  {skip:process.env.RUN_PLANNING_CAPACITY!=='1',timeout:600000},async t=>{
  const start=performance.now(),f=await planningClientFixture({version:2,secondOwner:true}),reviewer=f.secondOwner!,before=await f.context(),
    migration=await signedUpgradeStart(f.f,await Promise.all(before.records.map(r=>planningUpgradeReference(before.graph,r))));
  f.upgrade(3);await f.apply(await preparePlanning({...await f.input(),command:{action:'upgrade_content',records:[{kind:'project',id:f.projectId}]},upgrade:migration},f.f.owner.bundle));
  await signedUpgradeFinish(f.f,await Promise.all((await f.context()).records.map(r=>planningUpgradeReference(f.state(),r))));
  const opened=await openVerifiedPlanning({...await f.input(),historyPlaintext:false},f.f.owner.bundle),
    key=base64urlDecode(opened.ring.find(k=>k.epoch===opened.context.binding.keyEpoch)!.key,32),
    contents=new Map(opened.readable.records.map(r=>[`${r.kind}:${r.id}`,r.content])),ids:string[]=[];
  async function execute(intent:PlanningIntent,content?:Record<string,unknown>,actor:Actor=f.f.owner,outcomeText?:string) {
    const c=await f.rawContext(undefined,actor),b=c.binding,signing=base64urlDecode(actor.bundle.signingPrivateKey,64),
      seal=(kind:Parameters<typeof planningContentHeader>[1],id:string,revision:string,data:unknown)=>encryptContent(planningContentHeader(b,kind,id,revision),data,key,signing);
    try {
      const outcome=outcomeText?{id:randomUUID(),envelope:undefined as unknown as PlanningPayload['audit']['envelope']}:null;
      if(outcome)outcome.envelope=await seal('update',outcome.id,'1',{text:outcomeText});
      const command=planningCommand.parse({...intent,operationId:b.operationId,expected:b.before,...(outcome?{outcome:{recordId:outcome.id,revision:'1',digest:await digestObject(outcome.envelope)}}:{})}),
        result=evaluatePlanning(c.graph,command,planningAuthority(b)),refs=planningChangedRecords(result),records:PlanningPayload['records']=[],changed:PlanningAuditData['changed']=[];
      assert.equal(result.snapshot,undefined);
      for(const ref of refs) {
        const mapKey=`${ref.kind}:${ref.id}`,prior=contents.get(mapKey),next=content??prior;assert.ok(next);
        const retained=c.records.find(r=>r.kind===ref.kind&&r.id===ref.id),revision=planningEnvelopeRevision(b,command,ref,retained),
          envelope=planningRecordReplacesContent(command,ref.kind,ref.id)?await seal(ref.kind,ref.id,revision,next):retained!.envelope;
        records.push({kind:ref.kind,id:ref.id,envelope});changed.push({kind:ref.kind,id:ref.id,before:prior??null,after:next});contents.set(mapKey,next);
      }
      const auditId=randomUUID(),audit={id:auditId,envelope:await seal('audit',auditId,'1',{version:1,action:command.action,changed,snapshot:null,snapshotContents:[]})},
        mutation=await signObject({purpose:'ukda.planning-mutation.v3' as const,binding:b as Extract<typeof b,{version:3}>,command,nextVersion:String(BigInt(b.beforeVersion)+1n),afterGraphDigest:await planningGraphDigest(result.state),
          records:await Promise.all(records.map(async(r,i)=>({...refs[i]!,contentRevision:refs[i]!.contentRevision!,envelopeRevision:r.envelope.header.revision,digest:await digestObject(r.envelope)}))),
          audit:{id:audit.id,digest:await digestObject(audit.envelope)},outcome:outcome?{id:outcome.id,digest:await digestObject(outcome.envelope)}:null},signing);
      return await f.apply(planningPayload.parse({mutation,records,audit,outcome}));
    }finally{signing.fill(0);}
  }
  try {
    await execute({action:'start_project'});await execute({action:'set_project_review',enabled:true,reviewers:[]},undefined,f.f.owner,'Require an independent document review');
    for(let i=0;i<512;i++) {const id=randomUUID();ids.push(id);await execute({action:'create_task',task:{id,phaseId:null,milestoneId:null,assigneeIds:[f.f.owner.accountId],leadProfileId:f.f.owner.accountId,reviewerProfileId:reviewer.accountId}},
      {title:`Document ${i+1}`,description:'Work in the external application and return the exact output.',acceptanceCriteria:'Check the current source and all output versions.',priority:'normal'});}
    for(const [index,taskId]of ids.entries()) {
      await execute({action:'start_task',taskId});await execute({action:'request_task_completion',taskId,acceptanceConfirmed:true});
      const task=f.state().tasks.find(t=>t.id===taskId)!;await execute({action:'approve_task',taskId,submittedRevision:task.submittedRevision!,submittedPolicyRevision:task.submittedPolicyRevision!},undefined,reviewer);
      if(index<16) {
        await execute({action:'reopen_task',taskId},undefined,f.f.owner,'Correct the submitted document');
        await execute({action:'edit_task',taskId},{title:`Document ${index+1} corrected`,description:'The corrected work references the latest source.',acceptanceCriteria:'Check the corrected output.',priority:'normal'});
        await execute({action:'request_task_completion',taskId,acceptanceConfirmed:true});const corrected=f.state().tasks.find(t=>t.id===taskId)!;
        await execute({action:'approve_task',taskId,submittedRevision:corrected.submittedRevision!,submittedPolicyRevision:corrected.submittedPolicyRevision!},undefined,reviewer);
      }
    }
    const seeded=performance.now(),context=await f.rawContext(),frame=planningFrame(context);clearPlanningReplayCache();let pages=0,maxPageBytes=0;
    const hydrated=await readPlanningOperationPages(frame,async request=>{
      const offset=Number(request.afterVersion),history=context.history.slice(offset,offset+PLANNING_HISTORY_PAGE_SIZE),last=history.at(-1)!,
        previousHead=await digestObject(offset?context.history[offset-1]:context.creation),auditIds=new Set(history.map(m=>m.body.audit.id)),outcomeIds=new Set(history.flatMap(m=>m.body.outcome?[m.body.outcome.id]:[])),
        page:PlanningOperationsPage={protocol:1,anchor:request.anchor,afterVersion:request.afterVersion,previousHead,nextVersion:last.body.nextVersion,nextHead:await digestObject(last),complete:last.body.nextVersion===request.anchor.version,history,
          audits:context.audits.filter(a=>auditIds.has(a.id)),outcomes:context.outcomes.filter(a=>outcomeIds.has(a.id)),upgrades:(context.upgrades??[]).filter(u=>history.some(m=>m.body.binding.operationId===u.operationId))};
      pages++;maxPageBytes=Math.max(maxPageBytes,Buffer.byteLength(canonicalJson(page)));return page;
    }),assembled=performance.now();
    const input={context:hydrated,history:f.f.history,accountId:f.f.owner.accountId,deviceId:f.f.owner.deviceId,historyPlaintext:false},view=await readPlanning(input,f.f.owner.bundle),verified=performance.now();
    assert.equal(view.graph.tasks.length,512);assert.ok(view.graph.tasks.every(t=>t.state==='done'&&t.approvalOperationId));assert.equal(view.records.filter(r=>r.kind==='task').length,512);
    const cached=await readPlanning(input,f.f.owner.bundle),cachedAt=performance.now();assert.equal(cached.pin.head,view.pin.head);
    const taskId=ids[0]!,newWrite=await preparePlanning({...input,command:{action:'reopen_task',taskId},outcome:'A fresh revision needs review'},f.f.owner.bundle);await f.apply(newWrite);
    assert.equal(f.state().tasks.find(t=>t.id===taskId)!.approvalOperationId,null);
    const measurement={measuredAt:new Date().toISOString(),node:process.version,tasks:512,operations:Number(context.binding.beforeVersion),pages,maxPageBytes,
      assembledBytes:Buffer.byteLength(canonicalJson(hydrated)),frameBytes:Buffer.byteLength(canonicalJson(frame)),seedMs:Math.round(seeded-start),assembleMs:Math.round(assembled-seeded),
      coldVerifyMs:Math.round(verified-assembled),cachedVerifyMs:Math.round(cachedAt-verified),reopenMs:Math.round(performance.now()-cachedAt),maxResidentMiB:Math.round(process.resourceUsage().maxRSS/1024),
      heapMiB:Math.round(process.memoryUsage().heapUsed/1024/1024),note:'Real signed schema-2 v3 task lifecycle with two Owners, independent review and 16 corrections. Transport and client verification measurement; database/file bytes/browser acceptance is separate.'};
    await mkdir('.local',{recursive:true});await writeFile('.local/planning-capacity-measurement.json',JSON.stringify(measurement,null,2)+'\n',{mode:0o600});t.diagnostic(JSON.stringify(measurement));
  }finally{key.fill(0);clearPlanningReplayCache();}
});

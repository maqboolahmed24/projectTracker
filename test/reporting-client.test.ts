import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { base64urlDecode,canonicalJson,digestObject,encryptContent,signObject } from '../src/shared/crypto.js';
import { reportingSummaryPayload,reportingSummaryHeader } from '../src/shared/reporting.js';
import { calculateReporting,prepareReporting,readReporting,readReportingSettings,prepareReportingSettings } from '../src/client/reporting-crypto.js';
import { openVerifiedPlanning } from '../src/client/planning-crypto.js';
import { reportingClientFixture } from './reporting-client-fixture.js';

test('CP10 Worker reporting authenticates complete source, counts shared tasks once, encrypts exact results and rejects valid-signer false calculations',async()=>{
  const f=await reportingClientFixture(),taskId=randomUUID(),projectId=f.planning.projectId;
  await f.command({action:'start_project'});
  await f.command({action:'create_task',task:{id:taskId,phaseId:null,milestoneId:null,assigneeIds:[f.owner.accountId,f.planning.secondOwner!.accountId].sort(),leadProfileId:f.owner.accountId}},
    {title:'Private shared reporting work',dueDate:'2099-12-31'});
  const input=await f.input(),result=await calculateReporting(input,f.owner.bundle),payload=await prepareReporting(input,f.owner.bundle);
  assert.equal(result.status,'current');assert.equal(result.components[0]!.result.progress.taskCount,1);assert.equal(result.components[0]!.result.progress.doneTaskCount,0);
  assert.equal(result.timezone,'Europe/London');assert.equal(canonicalJson(payload).includes('Private'),false);
  const read=await readReporting({...input,response:{context:input.context,state:'current',payload}},f.owner.bundle);
  assert.deepEqual(read.components,result.components);assert.equal(read.status,'current');
  const missing=structuredClone(input);missing.context.projects[0]!.records=missing.context.projects[0]!.records.filter(r=>r.kind!=='task');
  await assert.rejects(calculateReporting(missing,f.owner.bundle));
  const wrong=structuredClone(input);wrong.context.binding.visibleScopes=[];await assert.rejects(calculateReporting(wrong,f.owner.bundle));
  const fake=structuredClone(payload),b=fake.mutation.body.binding,source=b.sources[0]!,opened=await openVerifiedPlanning(await f.planning.input(),f.owner.bundle),
    key=base64urlDecode(opened.ring.find(k=>k.epoch===source.keyEpoch)!.key,32),signing=base64urlDecode(f.owner.bundle.signingPrivateKey,64),falseResult=structuredClone(result.components[0]!.result);
  falseResult.progress.doneTaskCount=1;falseResult.progress.unfinishedTaskCount=0;falseResult.progress.percentage=100;
  try{
    const component=fake.components[0]!;
    component.envelope=await encryptContent(reportingSummaryHeader(b,projectId,component.id),{version:1,source,result:falseResult},key,signing);
    fake.mutation.body.components[0]!.digest=await digestObject(component.envelope);
    fake.mutation=await signObject(fake.mutation.body,signing);
    await assert.rejects(readReporting({...input,response:{context:input.context,state:'current',payload:reportingSummaryPayload.parse(fake)}},f.owner.bundle));
  }finally{key.fill(0);signing.fill(0);}
  await f.command({action:'edit_task',taskId},{title:'Private revised reporting work',dueDate:'2000-01-01'});
  const newer=await f.input(),stale=await readReporting({...newer,response:{context:newer.context,state:'current',payload}},f.owner.bundle);
  assert.equal(stale.status,'last-calculated');assert.equal((await calculateReporting(newer,f.owner.bundle)).components[0]!.result.health,'delayed');
});

test('CP10 Worker settings verify activation and signed history; timezone and clock changes cannot make a stale cache current',async()=>{
  const f=await reportingClientFixture(),initial=await f.settings(),settings=await readReportingSettings({...f.keys(),settings:initial},f.owner.bundle);
  assert.equal(settings.timezone,'Europe/London');assert.equal(settings.revision,'0');
  const input=await f.input(),summary=await prepareReporting(input,f.owner.bundle),context=await f.settingsContext(),
    payload=await prepareReportingSettings({...f.keys(),context,timezone:'America/New_York'},f.owner.bundle);f.applySettings(payload);
  const changed=await readReportingSettings({...f.keys(),settings:await f.settings(),settingsPin:settings.pin},f.owner.bundle);
  assert.equal(changed.timezone,'America/New_York');assert.equal(changed.revision,'1');
  await assert.rejects(readReportingSettings({...f.keys(),settings:initial,settingsPin:changed.pin},f.owner.bundle));
  const bad=await f.settings();bad.timezone='UTC';await assert.rejects(readReportingSettings({...f.keys(),settings:bad},f.owner.bundle));
  const current=await f.input(),old=await readReporting({...current,response:{context:current.context,state:'current',payload:summary}},f.owner.bundle);
  assert.equal(old.status,'last-calculated');assert.equal(old.timezone,'Europe/London');assert.equal((await calculateReporting(current,f.owner.bundle)).timezone,'America/New_York');
  const future=structuredClone(current);future.context.binding.asOfUtc=new Date(Date.now()+3600000).toISOString();future.context.binding.issuedAt=future.context.binding.asOfUtc;
  future.context.binding.expiresAt=new Date(Date.now()+3900000).toISOString();await assert.rejects(calculateReporting(future,f.owner.bundle));
  const noSummary=await readReporting({...current,response:{context:current.context,state:'missing',payload:null}},f.owner.bundle);
  assert.equal(noSummary.status,'missing');assert.deepEqual(noSummary.components,[]);
});

import { expect,test } from '@playwright/test';
import { calculateProgress,canonicalProgressScope,progressClock,type ProgressInput } from '../../src/shared/progress.js';
import { canonicalJson,digestObject } from '../../src/shared/crypto.js';
import type { PlanningState } from '../../src/shared/planning.js';

const id=(n:number)=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const workspaceId=id(1),projectId=id(2),actorId=id(3),otherId=id(4),phaseId=id(10),milestoneA=id(20),milestoneB=id(21),doneId=id(30),reviewId=id(31),cancelledId=id(32);
const graph:PlanningState={version:2,
  project:{workspaceId,id:projectId,revision:'7',state:'active',archived:false,phaseLabel:'wave',managerProfileId:actorId,teamId:null,reviewEnabled:true,reviewPolicyRevision:'2'},
  phases:[{workspaceId,projectId,id:phaseId,revision:'3',state:'active',archived:false,displayOrder:0,leadProfileId:actorId}],
  milestones:[{workspaceId,projectId,id:milestoneA,revision:'1',state:'open',phaseId,ownerProfileId:actorId},
    {workspaceId,projectId,id:milestoneB,revision:'1',state:'open',phaseId,ownerProfileId:otherId}],
  tasks:[{workspaceId,projectId,id:doneId,revision:'4',contentRevision:'1',state:'done',phaseId,milestoneId:milestoneA,assigneeIds:[actorId,otherId],leadProfileId:actorId},
    {workspaceId,projectId,id:reviewId,revision:'2',contentRevision:'1',state:'review',phaseId:null,milestoneId:null,assigneeIds:[otherId],leadProfileId:otherId},
    {workspaceId,projectId,id:cancelledId,revision:'2',contentRevision:'1',state:'cancelled',phaseId,milestoneId:null,assigneeIds:[actorId],leadProfileId:actorId}],
  blockers:[{workspaceId,projectId,id:id(40),revision:'1',contentRevision:'1',state:'open',taskId:reviewId,responsibleProfileId:null,
    createdBy:actorId,createdAt:'2026-03-28T12:00:00.000Z',resolvedBy:null,resolvedAt:null}],snapshots:[],movements:[]};
const settings={workspaceId,revision:'3',head:'a'.repeat(64),initialDigest:'b'.repeat(64),timezone:'Europe/London'};
const base:Omit<ProgressInput,'asOfUtc'>={graph,timezone:settings.timezone,scope:{kind:'project'},source:{complete:true,current:true,verified:true,decrypted:true},
  dates:[{kind:'project',id:projectId,startDate:'2026-03-01',dueDate:'2026-12-31'},
    {kind:'phase',id:phaseId,startDate:'2026-03-10',dueDate:'2026-09-24'},
    {kind:'milestone',id:milestoneA,dueDate:'2026-09-24'},{kind:'milestone',id:milestoneB,dueDate:'2026-09-24'},
    {kind:'task',id:doneId},{kind:'task',id:reviewId,dueDate:'2026-09-24'},{kind:'task',id:cancelledId,dueDate:'1999-01-01'}],
  milestoneOrder:[{id:milestoneA,order:5},{id:milestoneB,order:2}]};
const inputs:ProgressInput[]=[
  {...base,asOfUtc:'2026-03-29T00:00:00.000Z'},
  {...base,asOfUtc:'2026-10-24T23:00:00.000Z'},
  {...base,asOfUtc:'2026-09-24T22:59:59.999Z'},
  {...base,asOfUtc:'2026-09-24T23:00:00.000Z'},
  {...base,asOfUtc:'2026-09-24T22:59:59.999Z',scope:{kind:'filtered',taskIds:[doneId,doneId]}},
];

test('CP10: fixed progress-health-v1 inputs have identical canonical output in Node and every browser across London DST and due-date boundaries',async({page})=>{
  const expected=await Promise.all(inputs.map(async input=>{
    const value={settings,scope:canonicalProgressScope(input.scope),clock:progressClock(input.asOfUtc,input.timezone),result:calculateProgress(input)};
    return {canonical:canonicalJson(value),digest:await digestObject(value)};
  }));
  await page.goto('/');await page.waitForFunction(()=>!!window.ukda);
  const actual=await page.evaluate(async({inputs,settings})=>Promise.all(inputs.map(async input=>{
    const c=window.ukda,value={settings,scope:c.canonicalProgressScope(input.scope),clock:c.progressClock(input.asOfUtc,input.timezone),result:c.calculateProgress(input)};
    return {canonical:c.cryptography.canonicalJson(value),digest:await c.cryptography.digestObject(value)};
  })),{inputs,settings});
  expect(actual).toEqual(expected);
  const results=actual.map(value=>JSON.parse(value.canonical) as {clock:{localDate:string;nextMidnightUtc:string};result:ReturnType<typeof calculateProgress>});
  expect(results[0]!.clock).toEqual({localDate:'2026-03-29',nextMidnightUtc:'2026-03-29T23:00:00.000Z'});
  expect(results[1]!.clock).toEqual({localDate:'2026-10-25',nextMidnightUtc:'2026-10-26T00:00:00.000Z'});
  expect(Date.parse(results[0]!.clock.nextMidnightUtc)-Date.parse(inputs[0]!.asOfUtc)).toBe(23*60*60*1000);
  expect(Date.parse(results[1]!.clock.nextMidnightUtc)-Date.parse(inputs[1]!.asOfUtc)).toBe(25*60*60*1000);
  expect(results[2]!.result.signals.overdue).toEqual({project:false,taskIds:[],phaseIds:[],milestoneIds:[]});
  expect(results[3]!.result.signals.overdue.taskIds).toEqual([reviewId]);expect(results[3]!.result.health).toBe('delayed');
  expect(results[2]!.result.nextMilestone!.id).toBe(milestoneB);
  for(const value of results.slice(0,4))expect(value.result.progress).toMatchObject({taskCount:3,nonCancelledTaskCount:2,doneTaskCount:1,cancelledTaskCount:1,percentage:50});
  expect(results[4]!.result.progress).toMatchObject({taskCount:1,doneTaskCount:1,percentage:100});
});

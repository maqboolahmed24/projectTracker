import { expect,test } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture,password } from './authentication-fixture.js';
import { ownerPage,enrol } from './planning-helpers.js';
import type { ExecutePlanningInput } from '../../src/client/planning-controller.js';
import type { ReadablePlanning } from '../../src/client/planning-crypto.js';
import type { WriteConflict } from '../../src/client/write-state.js';

test('CP11: two assignees review one task revision; stale input is retained and only an explicit new save can replace current work',async({page,browser})=>{
  test.setTimeout(90000);const f=await authenticationFixture(),context=await browser.newContext({ignoreHTTPSErrors:true}),member=await context.newPage();
  try{
    await ownerPage(page,f);const project=await page.evaluate(()=>window.clientRuntime.projectCreation.create({name:'Private concurrent project'})),person=await enrol(page,member,f,false,[project.projectId]);
    const task=await page.evaluate(async({projectId,ownerId,memberId})=>{const p=window.clientRuntime.planning;
      await p.execute({projectId,reviewed:(await p.read(projectId)).pin,command:{action:'start_project'}});
      return p.createTask({projectId,title:'Private original shared title',assigneeIds:[ownerId,memberId]});
    },{projectId:project.projectId,ownerId:f.accountId,memberId:person.accountId});
    const reviewed=await member.evaluate(projectId=>window.clientRuntime.planning.read(projectId),project.projectId),operationId=randomUUID();let saves=0;
    for(const actor of [page,member])actor.on('request',request=>{if(request.url().endsWith('/v1/work/planning/save'))saves++;});
    await page.evaluate(({projectId,taskId,reviewed})=>window.clientRuntime.planning.execute({projectId,reviewed,command:{action:'edit_task',taskId},content:{title:'Private first assignee title'}}),
      {projectId:project.projectId,taskId:task.taskId,reviewed:reviewed.pin});
    const conflict=await member.evaluate(async({projectId,taskId,reviewed,operationId})=>{
      const input:ExecutePlanningInput={projectId,operationId,reviewed,command:{action:'edit_task',taskId},content:{title:'Private unsaved second assignee title'}};
      try{await window.clientRuntime.planning.execute(input);throw new Error('Expected conflict');}catch(error){if(!(error instanceof window.ukda.WriteConflict))throw error;
        const result=error as WriteConflict<ReadablePlanning,ExecutePlanningInput>;return{code:result.code,current:result.current,unsaved:result.unsaved};}
    },{projectId:project.projectId,taskId:task.taskId,reviewed:reviewed.pin,operationId});
    expect(conflict.code).toBe('CONFLICT');expect(conflict.current.records.find(record=>record.id===task.taskId)!.content.title).toBe('Private first assignee title');
    expect(conflict.unsaved.content).toEqual({title:'Private unsaved second assignee title'});expect(saves).toBe(1);
    const newOperationId=randomUUID();await member.evaluate(({input,reviewed,operationId})=>window.clientRuntime.planning.execute({...input,reviewed,operationId}),
      {input:conflict.unsaved,reviewed:conflict.current.pin,operationId:newOperationId});expect(saves).toBe(2);
    const before=await page.evaluate(()=>window.clientRuntime.planning.pending());await page.context().setOffline(true);
    const offline=await page.evaluate(async projectId=>{try{await window.clientRuntime.planning.createTask({projectId,title:'Private offline input stays with caller'});return'accepted';}
      catch(error){return(error as {code?:string}).code;}},project.projectId);expect(offline).toBe('OFFLINE');
    await page.context().setOffline(false);expect(await page.evaluate(()=>window.clientRuntime.planning.pending())).toEqual(before);expect(saves).toBe(2);
    expect((await member.evaluate(projectId=>window.clientRuntime.planning.read(projectId),project.projectId)).records.find(record=>record.id===task.taskId)!.content.title).toBe('Private unsaved second assignee title');
  }finally{await page.context().setOffline(false);await Promise.allSettled([page.evaluate(()=>window.clientRuntime?.close()),member.evaluate(()=>window.clientRuntime?.close())]);await context.close();await f.close();}
});

test('CP11: uncertain reporting and Inbox writes survive failed sign-out and reload; confirmed sign-out clears requests and retained receipts remain discoverable',async({page})=>{
  test.setTimeout(90000);const f=await authenticationFixture(),reportId=randomUUID(),inboxId=randomUUID();
  try{
    await ownerPage(page,f);const project=await page.evaluate(()=>window.clientRuntime.projectCreation.create({name:'Private durable reporting project'}));let reports=0,inboxWrites=0;
    page.on('request',request=>{if(request.url().endsWith('/v1/reporting/publish'))reports++;if(request.url().endsWith('/v1/inbox/save'))inboxWrites++;});
    for(const path of ['**/v1/reporting/publish','**/v1/inbox/save'])await page.route(path,async route=>{const response=await route.fetch();expect(response.status()).toBe(200);await route.abort('failed');},{times:1});
    const lost=await page.evaluate(async({projectId,reportId,inboxId})=>{let report=false,inbox=false;const c=window.clientRuntime;
      try{await c.reporting.publish({kind:'project',projectId},reportId);}catch{report=true;}try{await c.inbox.setProjectMuted(projectId,true,'0',inboxId);}catch{inbox=true;}
      return{report,inbox,pendingReports:await c.reporting.pending(),pendingInbox:await c.inbox.pending()};},{projectId:project.projectId,reportId,inboxId});
    expect(lost).toEqual({report:true,inbox:true,pendingReports:[reportId],pendingInbox:[inboxId]});
    await page.route('**/v1/auth/logout',route=>route.abort('failed'),{times:1});
    expect(await page.evaluate(async()=>{try{await window.clientRuntime.auth.logout();return false;}catch{return true;}})).toBe(true);
    await page.reload();await page.waitForFunction(()=>!!window.ukda);
    await page.evaluate(async({workspaceId,accountId,deviceId,trustedServiceKeys,password})=>{
      window.clientRuntime=await window.ukda.openClient({trustedServiceKeys});await window.clientRuntime.auth.login({workspaceId,accountId,deviceId},password);
    },{workspaceId:f.workspaceId,accountId:f.accountId,deviceId:f.deviceId,trustedServiceKeys:f.trustedServiceKeys,password});
    const resumed=await page.evaluate(async({reportId,inboxId})=>{const c=window.clientRuntime,pending={reports:await c.reporting.pending(),inbox:await c.inbox.pending()};
      const report=await c.reporting.resume(reportId),inbox=await c.inbox.resume(inboxId);return{pending,report,inbox};},{reportId,inboxId});
    expect(resumed.pending).toEqual({reports:[reportId],inbox:[inboxId]});expect(reports).toBe(1);expect(inboxWrites).toBe(1);
    expect(resumed.report.kind).toBe('summary');expect(resumed.inbox.operationId).toBe(inboxId);
    // Leave a different attempted online save uncertain, then explicitly sign out.
    const abandoned=randomUUID();await page.route('**/v1/reporting/publish',route=>route.abort('failed'),{times:1});
    await page.evaluate(async({projectId,operationId})=>{try{await window.clientRuntime.reporting.publish({kind:'project',projectId},operationId);}catch{}},{projectId:project.projectId,operationId:abandoned});
    expect(await page.evaluate(()=>window.clientRuntime.reporting.pending())).toEqual([abandoned]);
    await page.evaluate(async({workspaceId,accountId,deviceId})=>{await window.clientRuntime.remembered.remember({workspaceId,accountId,deviceId,displayName:'Remembered retry Owner'});await window.clientRuntime.auth.logout();},
      {workspaceId:f.workspaceId,accountId:f.accountId,deviceId:f.deviceId});
    const cleared=await page.evaluate(async({workspaceId,accountId,deviceId,abandoned})=>{const reports=await window.ukda.IndexedReportingStore.open(location.origin),planning=await window.ukda.IndexedPlanningStore.open(location.origin),devices=await window.ukda.IndexedDeviceStore.open();
      try{return{request:await reports.get(workspaceId,abandoned)??null,planning:await planning.list({workspaceId,accountId,deviceId}),wrapper:!!await devices.getActive(workspaceId,accountId,deviceId),cards:(await window.clientRuntime.remembered.list()).length};}
      finally{reports.close();planning.close();devices.close();}},{workspaceId:f.workspaceId,accountId:f.accountId,deviceId:f.deviceId,abandoned});
    expect(cleared).toEqual({request:null,planning:[],wrapper:true,cards:1});
    const acknowledgement=await page.evaluate(async({workspaceId,accountId,deviceId,password,operationId})=>{const c=window.clientRuntime;await c.auth.login({workspaceId,accountId,deviceId},password);
      return c.receipts.lookup({kind:'reporting-summary',operationId});},{workspaceId:f.workspaceId,accountId:f.accountId,deviceId:f.deviceId,password,operationId:reportId});
    expect(acknowledgement.kind).toBe('reporting-summary');expect(acknowledgement.receipt?.operationId).toBe(reportId);
  }finally{await Promise.allSettled([page.evaluate(()=>window.clientRuntime?.close())]);await f.close();}
});

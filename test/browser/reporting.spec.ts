import { expect,test } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture } from './authentication-fixture.js';
import { ownerPage,enrol } from './planning-helpers.js';
import type { ClientRuntime } from '../../src/client/runtime.js';
import type { ReportingLiveState } from '../../src/client/reporting-controller.js';
declare global { interface Window { reportingEvents:ReportingLiveState[]; reportingWatch:ReturnType<ClientRuntime['reporting']['watch']>|undefined;
  reportingDiagnostics:{stage:'started'|'completed'|'failed';name?:string;code?:string}[] } }

test('CP10: verified reports count shared work once, keep reader calculations local and publish exact encrypted project vectors',async({page,browser})=>{
  test.setTimeout(90000);
  const f=await authenticationFixture(),context=await browser.newContext({ignoreHTTPSErrors:true}),member=await context.newPage();
  try{
    await ownerPage(page,f);const created=await page.evaluate(()=>window.clientRuntime.projectCreation.create({name:'Private reporting project'})),person=await enrol(page,member,f,false,[created.projectId]);
    const uploads:string[]=[];page.on('request',request=>{if(request.url().endsWith('/v1/reporting/publish'))uploads.push(request.postData()??'');});
    const result=await page.evaluate(async({projectId,ownerId,memberId})=>{
      const c=window.clientRuntime,p=c.planning,r=c.reporting;await p.execute({ reviewed: (await p.read(projectId)).pin,projectId,command:{action:'start_project'}});
      const task=await p.createTask({projectId,title:'Private shared reporting task',assigneeIds:[ownerId,memberId],leadProfileId:ownerId,dueDate:'2000-01-01'}),scope={kind:'project' as const,projectId};
      const local=await r.calculate(scope);await r.publish(scope);const cached=await r.read(scope);
      await r.setTimezone('America/New_York',(await r.settings()).pin);const stale=await r.read(scope),changed=await r.calculate(scope);
      return {task,local,cached,stale,changed};
    },{projectId:created.projectId,ownerId:f.accountId,memberId:person.accountId});
    expect(result.local.components[0]!.result.progress.taskCount).toBe(1);expect(result.local.components[0]!.result.progress.percentage).toBe(0);
    expect(result.local.components[0]!.result.health).toBe('delayed');expect(result.cached.status).toBe('current');
    expect(result.stale.status).toBe('last-calculated');expect(result.stale.timezone).toBe('Europe/London');expect(result.changed.timezone).toBe('America/New_York');
    const reader=await member.evaluate(async(projectId)=>{const r=window.clientRuntime.reporting,scope={kind:'project' as const,projectId},local=await r.calculate(scope);
      let publishDenied=false,settingsDenied=false;try{await r.publish(scope);}catch{publishDenied=true;}try{await r.setTimezone('UTC',(await r.settings()).pin);}catch{settingsDenied=true;}
      return {local,publishDenied,settingsDenied};},created.projectId);
    expect(reader.local.components[0]!.result.progress.taskCount).toBe(1);expect(reader.publishDenied).toBe(true);expect(reader.settingsDenied).toBe(true);
    const aggregate=await page.evaluate(async({projectId,taskId,ownerId})=>{
      const c=window.clientRuntime,second=await c.projectCreation.create({name:'Private second reporting project'}),team=await c.teams.create({name:'Private reporting group'});
      await c.planning.execute({ reviewed: (await c.planning.read(projectId)).pin,projectId,command:{action:'assign_task',taskId,assigneeIds:[ownerId],leadProfileId:ownerId,teamId:team.teamId}});
      const scope={kind:'visible_projects' as const,projectIds:[second.projectId,projectId]};await c.reporting.publish(scope);
      return {view:await c.reporting.read(scope),team:await c.reporting.calculate({kind:'team',teamId:team.teamId,projectIds:[second.projectId,projectId]})};
    },{projectId:created.projectId,taskId:result.task.taskId,ownerId:f.accountId});
    expect(aggregate.view.status).toBe('current');expect(aggregate.view.components).toHaveLength(2);expect(aggregate.view.aggregate!.progress.taskCount).toBe(1);
    expect(aggregate.team.aggregate!.progress.taskCount).toBe(1);expect(uploads).toHaveLength(2);expect(uploads.every(body=>!body.includes('Private'))).toBe(true);
    const published=JSON.parse(uploads[1]!);expect(published.components).toHaveLength(2);
    expect(published.components.every((part:{projectId:string;envelope:{header:{scope:string;scopeId:string}}})=>part.envelope.header.scope==='project'&&part.envelope.header.scopeId===part.projectId)).toBe(true);
  }finally{await Promise.allSettled([page.evaluate(()=>window.clientRuntime?.close()),member.evaluate(()=>window.clientRuntime?.close())]);await context.close();await f.close();}
});

test('CP10: real SSE invalidates reporting, hidden results are last calculated, and a lost publish reply resumes without duplication',async({page},testInfo)=>{
  test.setTimeout(90000);const f=await authenticationFixture(),operationId=randomUUID();
  const requestDiagnostics:{path:string;status?:number;failure?:string}[]=[];
  page.on('response',response=>{const path=new URL(response.url()).pathname;if(path.startsWith('/v1/'))requestDiagnostics.push({path,status:response.status()});});
  page.on('requestfailed',request=>{const path=new URL(request.url()).pathname;if(path.startsWith('/v1/'))requestDiagnostics.push({path,failure:request.failure()?.errorText??'failed'});});
  try{
    await ownerPage(page,f);const created=await page.evaluate(()=>window.clientRuntime.projectCreation.create({name:'Private live reporting project'}));
    const eventRequests:string[]=[];page.on('request',request=>{if(request.url().includes('/v1/work/live'))eventRequests.push(request.url());});
    await page.evaluate(projectId=>{
      window.reportingEvents=[];window.reportingDiagnostics=[];
      const reporting=window.clientRuntime.reporting,calculate=reporting.calculate.bind(reporting);
      reporting.calculate=async(...args)=>{
        window.reportingDiagnostics.push({stage:'started'});
        try{const result=await calculate(...args);window.reportingDiagnostics.push({stage:'completed'});return result;}
        catch(error){const failure=error as {name?:unknown;code?:unknown};window.reportingDiagnostics.push({stage:'failed',
          ...(typeof failure.name==='string'?{name:failure.name}:{}),...(typeof failure.code==='string'?{code:failure.code}:{})});throw error;}
      };
      window.reportingWatch=reporting.watch({kind:'project',projectId},state=>window.reportingEvents.push(state));
    },created.projectId);
    try{await expect.poll(()=>page.evaluate(()=>window.reportingEvents.at(-1)?.status),{timeout:15000}).toBe('current');}
    catch(error){const diagnostic=await page.evaluate(()=>({calculations:window.reportingDiagnostics,
      states:window.reportingEvents.map(({status,reason,asOfUtc})=>({status,reason,asOfUtc}))}));
      await testInfo.attach('live-initial-diagnostic',{body:JSON.stringify({...diagnostic,requests:requestDiagnostics},null,2),contentType:'application/json'});throw error;}
    const before=await page.evaluate(()=>window.reportingEvents.length);
    await page.evaluate(projectId=>window.clientRuntime.planning.createTask({projectId,title:'Private live task',dueDate:'2099-01-01'}),created.projectId);
    await expect.poll(()=>page.evaluate(()=>window.reportingEvents.at(-1)?.value?.components[0]?.result.progress.taskCount),{timeout:15000}).toBe(1);
    await expect.poll(()=>page.evaluate(index=>window.reportingEvents.slice(index).some(event=>event.reason==='event'&&event.status==='current'&&
      event.value?.components[0]?.result.progress.taskCount===1),before),{timeout:15000}).toBe(true);
    expect(eventRequests.length).toBeGreaterThan(0);expect(eventRequests.every(url=>!url.includes('?'))).toBe(true);
    const hidden=await page.evaluate(()=>{window.reportingWatch!.setVisible(false);const state=window.reportingEvents.at(-1)!;return {status:state.status,health:state.currentHealth,value:state.value,last:state.lastCalculated?.status};});
    expect(hidden).toEqual({status:'last-known',health:'not_enough_information',value:null,last:'last-calculated'});
    await page.evaluate(()=>window.reportingWatch!.setVisible(true));await expect.poll(()=>page.evaluate(()=>window.reportingEvents.at(-1)?.status),{timeout:15000}).toBe('current');
    await page.evaluate(()=>window.reportingWatch!.stop());
    let publishes=0;page.on('request',request=>{if(request.url().endsWith('/v1/reporting/publish'))publishes++;});
    await page.route('**/v1/reporting/publish',async route=>{const response=await route.fetch();expect(response.status()).toBe(200);await route.abort('failed');},{times:1});
    expect(await page.evaluate(async({projectId,operationId})=>{try{await window.clientRuntime.reporting.publish({kind:'project',projectId},operationId);return false;}catch{return true;}},{projectId:created.projectId,operationId})).toBe(true);
    const resumed=await page.evaluate(async operationId=>{const r=window.clientRuntime.reporting,pending=await r.pending(),receipt=await r.resume(operationId);return {pending,receipt,after:await r.pending()};},operationId);
    expect(resumed.pending).toEqual([operationId]);expect(resumed.receipt.kind).toBe('summary');expect(resumed.after).toEqual([]);expect(publishes).toBe(1);
  }finally{await Promise.allSettled([page.evaluate(()=>{window.reportingWatch?.stop();return window.clientRuntime?.close();})]);await f.close();}
});

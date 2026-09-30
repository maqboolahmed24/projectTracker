import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { canonicalJson, digestObject } from '../src/shared/crypto.js';
import { planningAnchorFor, planningContext, planningFrame, planningWireValue, readPlanningOperationPages,
  PLANNING_HISTORY_PAGE_SIZE, PLANNING_MAX_BYTES, type PlanningContext, type PlanningOperationsPage } from '../src/shared/planning-api.js';
import { preparePlanning, readPlanning } from '../src/client/planning-crypto.js';
import { AuthenticatedHttp } from '../src/client/auth-controller.js';
import { planningClientFixture } from './planning-client-fixture.js';
import { origin } from './project-create-client-fixture.js';

async function pageFor(context:PlanningContext,afterVersion:string,anchor=planningAnchorFor(context)):Promise<PlanningOperationsPage> {
  const offset=Number(afterVersion),history=context.history.slice(offset,offset+PLANNING_HISTORY_PAGE_SIZE),last=history.at(-1),
    previousHead=await digestObject(offset?context.history[offset-1]:context.creation),nextVersion=last?.body.nextVersion??afterVersion,
    auditIds=new Set(history.map(m=>m.body.audit.id)),outcomeIds=new Set(history.flatMap(m=>m.body.outcome?[m.body.outcome.id]:[]));
  return {protocol:1,anchor,afterVersion,previousHead,nextVersion,nextHead:last?await digestObject(last):previousHead,
    complete:nextVersion===anchor.version,history,audits:context.audits.filter(a=>auditIds.has(a.id)),outcomes:context.outcomes.filter(o=>outcomeIds.has(o.id)),
    upgrades:(context.upgrades??[]).filter(u=>history.some(m=>m.body.binding.operationId===u.operationId))};
}

async function signedHistory(count:number) {
  const f=await planningClientFixture({version:2});
  for(let i=0;i<count;i++)await f.apply(await preparePlanning({...await f.input(),command:{action:'edit_project',patch:{}},content:{name:`Private project ${i}`}},f.f.owner.bundle));
  return f;
}

test('planning pages preserve original signatures, enforce boundaries, and authenticate more than 512 lifetime changes',async()=>{
  const f=await signedHistory(513),context=await f.context(),frame=planningFrame(context),pages:PlanningOperationsPage[]=[];
  const hydrated=await readPlanningOperationPages(frame,async request=>{const page=await pageFor(context,request.afterVersion,request.anchor);pages.push(page);return page;});
  assert.equal(pages.length,9);assert.ok(pages.every(p=>p.history.length<=64&&Buffer.byteLength(canonicalJson(p))<=PLANNING_MAX_BYTES));
  assert.equal(canonicalJson(hydrated),canonicalJson(context));
  const result=await readPlanning({...await f.input(),context:hydrated},f.f.owner.bundle);
  assert.equal(result.audits.length,513);assert.equal(result.records[0]!.content.name,'Private project 512');
  const rewritten=structuredClone(hydrated);rewritten.history[0]!.signature='A'.repeat(86);
  await assert.rejects(readPlanning({...await f.input(),context:rewritten},f.f.owner.bundle));
  for(const alter of [
    (p:PlanningOperationsPage)=>{p.previousHead='0'.repeat(64);},
    (p:PlanningOperationsPage)=>{p.anchor.head='0'.repeat(64);},
    (p:PlanningOperationsPage)=>{p.history=[];},
    (p:PlanningOperationsPage)=>{p.history.reverse();},
    (p:PlanningOperationsPage)=>{p.complete=true;},
    (p:PlanningOperationsPage)=>{p.nextVersion='1';},
  ]) await assert.rejects(readPlanningOperationPages(frame,async request=>{const p=structuredClone(await pageFor(context,request.afterVersion,request.anchor));alter(p);return p;}));
  const missingAudit=await readPlanningOperationPages(frame,async request=>({...await pageFor(context,request.afterVersion,request.anchor),audits:[]}));
  await assert.rejects(readPlanning({...await f.input(),context:missingAudit},f.f.owner.bundle));
});

test('HTTP automatically hydrates native contexts inside collaboration, reporting, export and restoration responses',async()=>{
  const f=await signedHistory(65),context=await f.context(),csrf='A'.repeat(43),requests:string[]=[],
    source={planning:context,projects:[context],data:{context},recovery:{project:{context}},label:'Preserve unrelated fields'},wire=planningWireValue(source);
  const http=new AuthenticatedHttp(origin,async(url,init)=>{
    const path=String(url).slice(origin.length);requests.push(path);assert.equal((init!.headers as Record<string,string>)['X-CSRF-Token'],csrf);
    assert.equal((init!.headers as Record<string,string>)['X-Planning-History'],'paged-v1');
    const body=JSON.parse(init!.body as string),value=path.endsWith('operations-page')?await pageFor(context,body.afterVersion,body.anchor):wire,
      response=new Response(canonicalJson(value),{headers:{'content-type':'application/json'}});
    Object.defineProperty(response,'url',{value:String(url)});return response;
  });
  const schema=z.strictObject({planning:planningContext,projects:z.array(planningContext),data:z.strictObject({context:planningContext}),
    recovery:z.strictObject({project:z.strictObject({context:planningContext})}),label:z.string()}),result=await http.post('/v1/test/context',{},schema,{csrfToken:csrf});
  assert.equal(canonicalJson(result),canonicalJson(source));assert.equal(requests.filter(path=>path.endsWith('operations-page')).length,2,'Repeated native contexts reuse immutable ciphertext pages');
  await http.post('/v1/test/context',{},schema,{csrfToken:csrf});
  assert.equal(requests.filter(path=>path.endsWith('operations-page')).length,2,'A fresh authorized frame can reuse its unchanged history prefix');
  const small=await f.context(randomUUID());small.history=small.history.slice(0,1);
  assert.equal(planningWireValue(small),small,'Existing small native context shape remains intact');
  assert.deepEqual(planningWireValue({protocol:1,context:'Unrelated',anchor:'Unrelated'}),{protocol:1,context:'Unrelated',anchor:'Unrelated'});
});

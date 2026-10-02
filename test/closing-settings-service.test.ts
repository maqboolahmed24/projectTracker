import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { AppError } from '../src/errors.js';
import { base64urlDecode, digestObject, signObject } from '../src/shared/crypto.js';
import { evaluatePlanning } from '../src/shared/planning.js';
import { planningAuthority, planningGraphDigest, planningPayload, validatePlanningPayload } from '../src/shared/planning-api.js';
import { reportingFixture } from './reporting-fixture.js';
import { closingSettings } from '../src/shared/closing-settings.js';
const changed=(error:unknown)=>error instanceof AppError&&error.code==='PLANNING_CHANGED';

test('CP10 closure: settings stamps survive timezone edits and lost replies; stale or missing proof cannot commit a new snapshot',async t=>{
  const f=await reportingFixture(t),phaseId=randomUUID();
  await f.execute({action:'edit_project',patch:{}},{content:{name:'Private dated delivery',startDate:'2026-09-01',dueDate:'2026-10-01'}});
  await f.execute({action:'create_phase',phase:{id:phaseId,displayOrder:0,leadProfileId:null}},{content:{name:'Private dated wave',startDate:'2026-09-02',dueDate:'2026-09-30'}});
  const beforeDates=(await f.read()).records.map(r=>({id:r.id,startDate:r.content.startDate,dueDate:r.content.dueDate}));
  const london=await f.preparePlanning({action:'cancel_phase',phaseId,tasks:[],milestones:[]},{outcome:'Private original London closure'});
  f.setPlanningHooks({afterCommit:async()=>{throw new Error('Lost closure receipt');}});
  await assert.rejects(f.save(london),/Lost closure receipt/);f.setPlanningHooks();
  const firstRead=await f.read(),first=firstRead.graph.snapshots[0]!,firstAudit=firstRead.audits.find(a=>a.operationId===london.mutation.body.binding.operationId)!;
  assert.ok(firstAudit.closingSettings);assert.equal(firstAudit.closingSettings.timezone,'Europe/London');assert.equal(firstAudit.closingSettings.revision,'0');
  const originalStamp=structuredClone(firstAudit.closingSettings),originalSnapshot=structuredClone(first),stale=await f.preparePlanning({action:'cancel_project'},{outcome:'Prepared before the settings change'});
  await f.reporting.saveSettings(f.auth(),await f.settingDraft('Asia/Tokyo'));
  const expected=await f.planningStatus(london);assert.equal(expected.state,'completed');assert.deepEqual(await f.save(london),expected);
  const current=await f.context();
  await assert.rejects(f.save(stale),changed);
  assert.equal(await planningGraphDigest((await f.context()).graph),await planningGraphDigest(current.graph));
  assert.equal((await f.admin.application.query('SELECT 1 FROM app.planning_operations WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,stale.mutation.body.binding.operationId])).rowCount,0);
  const tokyo=await f.preparePlanning({action:'cancel_project'},{outcome:'New closure with an explicit Tokyo stamp'}),unsignedStamp=structuredClone(tokyo),body=unsignedStamp.mutation.body;
  if(body.purpose!=='ukda.planning-mutation.v2')throw new Error('Expected current v2 closure');
  delete body.closingSettings;
  body.afterGraphDigest=await planningGraphDigest(evaluatePlanning(current.graph,body.command,planningAuthority(body.binding)).state);
  const missing=planningPayload.parse({...unsignedStamp,mutation:await signObject(body,base64urlDecode(f.originalBundle.signingPrivateKey))});
  // This is a genuine signature and valid legacy-compatible graph, not a random
  // corruption: only the new-write requirement rejects its missing settings.
  await validatePlanningPayload(missing,missing.mutation.body.binding,current.graph,current.records);
  await assert.rejects(f.save(missing),changed);
  assert.equal((await f.admin.application.query('SELECT 1 FROM app.planning_operations WHERE workspace_id=$1 AND operation_id=$2',[f.workspaceId,missing.mutation.body.binding.operationId])).rowCount,0);
  await f.save(tokyo);const read=await f.read();
  assert.deepEqual(read.graph.snapshots[0],originalSnapshot);
  const currentAudit=read.audits.find(a=>a.operationId===tokyo.mutation.body.binding.operationId)!;
  assert.equal(currentAudit.closingSettings!.timezone,'Asia/Tokyo');assert.equal(currentAudit.closingSettings!.revision,'1');
  assert.deepEqual(read.records.map(r=>({id:r.id,startDate:r.content.startDate,dueDate:r.content.dueDate})),beforeDates);
  const oldAudit=read.audits.find(a=>a.operationId===london.mutation.body.binding.operationId)!;
  assert.deepEqual(oldAudit.closingSettings,originalStamp);assert.deepEqual(closingSettings.parse(oldAudit.data.closingSettings),originalStamp);
  assert.deepEqual((await f.context()).history.find(m=>m.body.binding.operationId===london.mutation.body.binding.operationId),london.mutation);
  assert.equal(await digestObject(read.graph.snapshots[0]),await digestObject(originalSnapshot));
});

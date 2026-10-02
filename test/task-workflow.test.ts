import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import type { SecurityHistoryState } from '../src/shared/security-history.js';
import { capabilities } from '../src/shared/contracts.js';
import { planningCommand, planningGraph, planningChangedRecords, planningRecordReplacesContent, applyPlanningSecurityCleanup } from '../src/shared/planning-api.js';
import { evaluatePlanning, PlanningError, planningRevisionSnapshot, planningTaskBlocked, upgradePlanningGraph,
  type PlanningAuthority, type PlanningCommand, type PlanningEnvelopeReference, type PlanningState } from '../src/shared/planning.js';

type Action = PlanningCommand extends infer C ? C extends PlanningCommand ? Omit<C,'operationId'|'expected'> : never : never;
const reason = ():PlanningEnvelopeReference => ({recordId:randomUUID(),revision:'1',digest:'b'.repeat(64)});
const denied = (code:PlanningError['code'],f:()=>unknown) => assert.throws(f,(e)=>e instanceof PlanningError && e.code === code);
function fixture() {
  const workspaceId=randomUUID(),projectId=randomUUID(),owner=randomUUID(),first=randomUUID(),second=randomUUID(),reviewer=randomUUID();
  const legacy:PlanningState={project:{workspaceId,id:projectId,revision:'1',state:'planned',archived:false,phaseLabel:'wave',managerProfileId:null,teamId:null},phases:[],milestones:[],tasks:[],snapshots:[],movements:[]};
  const state=upgradePlanningGraph(legacy);
  const auth=(accountId=owner,permissions:NonNullable<PlanningAuthority['access']>['permissions']=[...capabilities],isOwner=accountId===owner):PlanningAuthority=>({actor:{workspaceId,accountId,active:true,isOwner},isOwner,eligibleAssigneeIds:[owner,first,second,reviewer],eligibleReviewerIds:[owner,reviewer],now:'2026-09-26T12:00:00.000Z',access:{workspaceId,projectId,accountId,state:'active',keysReady:true,permissions}});
  const apply=(input:PlanningState,action:Action,authority=auth())=>evaluatePlanning(input,planningCommand.parse({...action,operationId:randomUUID(),expected:planningRevisionSnapshot(input)}),authority);
  const create=(input:PlanningState,assigneeIds=[first,second],milestoneId:string|null=null)=>apply(input,{action:'create_task',task:{id:randomUUID(),phaseId:null,milestoneId,assigneeIds,leadProfileId:assigneeIds[0]??null}}).state;
  const active=()=>apply(state,{action:'start_project'}).state;
  const review=(input:PlanningState)=>apply(input,{action:'set_project_review',enabled:true,reviewers:input.tasks.filter(t=>!['done','cancelled'].includes(t.state)).map(t=>({taskId:t.id,reviewerProfileId:reviewer})),outcome:reason()}).state;
  const submit=(input:PlanningState)=>apply(input,{action:'request_task_completion',taskId:input.tasks[0]!.id,acceptanceConfirmed:true},auth(first,['read_project','edit_assigned_tasks'])).state;
  return {workspaceId,projectId,owner,first,second,reviewer,legacy,state,auth,apply,create,active,review,submit};
}

test('CP08: shared assignees execute one task and explicit reassignment clears its lead without changing content revision',()=>{
  const f=fixture(); let current=f.create(f.active()); const taskId=current.tasks[0]!.id;
  const initial=structuredClone(current);
  current=f.apply(current,{action:'start_task',taskId},f.auth(f.second,['read_project','edit_assigned_tasks'])).state;
  assert.equal(current.tasks.length,1); assert.equal(current.tasks[0]!.state,'in_progress'); assert.equal(initial.tasks[0]!.state,'todo');
  current=f.apply(current,{action:'assign_task',taskId,assigneeIds:[f.second],leadProfileId:null,teamId:null}).state;
  assert.deepEqual(current.tasks[0]!.assigneeIds,[f.second]); assert.equal(current.tasks[0]!.leadProfileId,null);
  assert.equal(current.tasks[0]!.contentRevision,'1'); assert.equal(current.tasks[0]!.revision,'3');
  denied('permission_denied',()=>f.apply(current,{action:'start_task',taskId},f.auth(f.first,['read_project','edit_assigned_tasks'])));
  denied('invalid_context',()=>f.apply(current,{action:'assign_task',taskId,assigneeIds:[f.second],leadProfileId:f.first,teamId:null}));
});

test('CP08: preparation/cancellation work in Planned scopes; execution requires active project and wave',()=>{
  const f=fixture(); let current=f.create(f.state); const taskId=current.tasks[0]!.id;
  current=f.apply(current,{action:'edit_task',taskId}).state;
  denied('parent_not_active',()=>f.apply(current,{action:'start_task',taskId}));
  denied('parent_not_active',()=>f.submit(current));
  current=f.apply(current,{action:'cancel_task',taskId,outcome:reason()}).state;
  denied('scope_read_only',()=>f.apply(current,{action:'edit_task',taskId}));
  current=f.apply(current,{action:'restore_task',taskId,outcome:reason()}).state;
  const phaseId=randomUUID(); current=f.apply(current,{action:'create_phase',phase:{id:phaseId,displayOrder:0,leadProfileId:null}}).state;
  current=f.apply(current,{action:'carry_task',taskId,phaseId,milestoneId:null,outcome:reason()}).state;
  current=f.apply(current,{action:'start_project'}).state;
  denied('parent_not_active',()=>f.apply(current,{action:'start_task',taskId}));
  current=f.apply(current,{action:'start_phase',phaseId}).state;
  assert.equal(f.apply(current,{action:'start_task',taskId}).state.tasks[0]!.state,'in_progress');
});

test('CP08: review defaults off; named eligible non-assignee signs exact submitted content and policy',()=>{
  const f=fixture(); let current=f.create(f.active()); const taskId=current.tasks[0]!.id;
  assert.equal(current.project.reviewEnabled,false);
  assert.equal(f.submit(current).tasks[0]!.state,'done');
  current=f.review(current); current=f.submit(current);
  assert.equal(current.tasks[0]!.state,'review'); assert.equal(current.tasks[0]!.submittedRevision,'1');
  const action:Action={action:'approve_task',taskId,submittedRevision:'1',submittedPolicyRevision:'2'};
  denied('reviewer_required',()=>f.apply(current,action,f.auth(f.owner,['read_project','approve_tasks'])));
  const result=f.apply(current,action,f.auth(f.reviewer,['read_project','approve_tasks']));
  assert.equal(result.state.tasks[0]!.state,'done'); assert.ok(result.state.tasks[0]!.approvalOperationId);
  assert.equal(result.state.tasks[0]!.contentRevision,'1');
  const ref=planningChangedRecords(result).find(r=>r.id===taskId)!;
  assert.equal(ref.contentRevision,'1'); assert.equal(ref.revision,result.state.tasks[0]!.revision);
});

test('CP08: material content/assignment edits invalidate pending review and old approvals cannot complete fresh content',()=>{
  const f=fixture(); let current=f.submit(f.review(f.create(f.active()))); const taskId=current.tasks[0]!.id;
  current=f.apply(current,{action:'edit_task',taskId}).state;
  assert.equal(current.tasks[0]!.state,'in_progress'); assert.equal(current.tasks[0]!.submittedRevision,null); assert.equal(current.tasks[0]!.contentRevision,'2');
  current=f.submit(current);
  denied('stale_approval',()=>f.apply(current,{action:'approve_task',taskId,submittedRevision:'1',submittedPolicyRevision:'2'},f.auth(f.reviewer,['read_project','approve_tasks'])));
  current=f.apply(current,{action:'assign_task',taskId,assigneeIds:[f.first,f.reviewer],leadProfileId:f.first,teamId:null}).state;
  assert.equal(current.tasks[0]!.state,'in_progress'); assert.equal(current.tasks[0]!.reviewerProfileId,null);
  denied('reviewer_required',()=>f.submit(current));
  denied('permission_denied',()=>f.apply(current,{action:'approve_task',taskId,submittedRevision:'2',submittedPolicyRevision:'2'},f.auth(f.reviewer,['read_project','approve_tasks'])));
});

test('CP08: reviewers reject with a reason; eligible Owner replacement is explicit and never permits self-approval',()=>{
  const f=fixture(); let current=f.submit(f.review(f.create(f.active()))); const taskId=current.tasks[0]!.id;
  current=f.apply(current,{action:'reject_task',taskId,outcome:reason()},f.auth(f.reviewer,['read_project','approve_tasks'])).state;
  assert.equal(current.tasks[0]!.state,'in_progress'); assert.equal(current.tasks[0]!.submittedRevision,null);
  current=f.submit(current);
  current=f.apply(current,{action:'select_task_reviewer',taskId,reviewerProfileId:f.owner},f.auth(f.owner,['read_project','approve_tasks'])).state;
  assert.equal(f.apply(current,{action:'approve_task',taskId,submittedRevision:'1',submittedPolicyRevision:'2'},f.auth(f.owner,['read_project','approve_tasks'])).state.tasks[0]!.state,'done');
  let self=f.create(f.active(),[f.owner]);
  denied('reviewer_required',()=>f.apply(self,{action:'set_project_review',enabled:true,reviewers:[{taskId:self.tasks[0]!.id,reviewerProfileId:f.owner}],outcome:reason()}));
  denied('permission_denied',()=>f.apply(self,{action:'select_task_reviewer',taskId:self.tasks[0]!.id,reviewerProfileId:f.owner},f.auth(f.owner,['read_project','approve_tasks'])));
});

test('CP08: project review configuration needs real Owner and device capability; disabling requires fresh completion',()=>{
  const f=fixture(); let current=f.create(f.active()); const taskId=current.tasks[0]!.id;
  const enable:Action={action:'set_project_review',enabled:true,reviewers:[{taskId,reviewerProfileId:f.reviewer}],outcome:reason()};
  denied('permission_denied',()=>f.apply(current,enable,f.auth(f.first,[...capabilities],false)));
  denied('permission_denied',()=>f.apply(current,enable,f.auth(f.owner,['read_project'],true)));
  denied('resolution_required',()=>f.apply(current,{...enable,reviewers:[]}));
  current=f.submit(f.review(current));
  current=f.apply(current,{action:'set_project_review',enabled:false,reviewers:[],outcome:reason()}).state;
  assert.equal(current.tasks[0]!.state,'in_progress'); assert.equal(current.tasks[0]!.submittedRevision,null); assert.equal(current.project.reviewPolicyRevision,'3');
  assert.equal(f.submit(current).tasks[0]!.state,'done');
});

test('CP08: blockers retain independent state, responsibility and actor/time history; one resolution leaves another blocker active',()=>{
  const f=fixture(); let current=f.create(f.active()); const taskId=current.tasks[0]!.id,one=randomUUID(),two=randomUUID();
  const member=f.auth(f.first,['read_project','edit_assigned_tasks']);
  denied('permission_denied',()=>f.apply(current,{action:'create_blocker',blocker:{id:one,taskId,responsibleProfileId:f.second}},member));
  current=f.apply(current,{action:'create_blocker',blocker:{id:one,taskId,responsibleProfileId:f.first}},member).state;
  current=f.apply(current,{action:'create_blocker',blocker:{id:two,taskId,responsibleProfileId:f.second}}).state;
  assert.equal(planningTaskBlocked(current,taskId),true); denied('blocked_task',()=>f.submit(current));
  current=f.apply(current,{action:'resolve_blocker',blockerId:one,outcome:reason()},member).state;
  assert.equal(current.blockers![0]!.resolvedBy,f.first); assert.equal(current.blockers![0]!.resolvedAt,member.now);
  assert.equal(current.blockers![0]!.contentRevision,'1'); assert.equal(planningTaskBlocked(current,taskId),true);
  denied('blocked_task',()=>f.submit(current));
  current=f.apply(current,{action:'resolve_blocker',blockerId:two,outcome:reason()},member).state;
  current=f.submit(current);
  denied('scope_read_only',()=>f.apply(current,{action:'reopen_blocker',blockerId:one,outcome:reason()},member));
  denied('scope_read_only',()=>f.apply(current,{action:'create_blocker',blocker:{id:randomUUID(),taskId,responsibleProfileId:f.first}},member));
  current=f.apply(current,{action:'reopen_task',taskId,outcome:reason()}).state;
  current=f.apply(current,{action:'reopen_blocker',blockerId:one,outcome:reason()},member).state;
  assert.equal(current.blockers![0]!.createdBy,f.first); assert.equal(current.blockers![0]!.resolvedAt,null); assert.equal(planningTaskBlocked(current,taskId),true);
});

test('CP08: read/comment actors cannot change assignments or blockers, including an Owner restricted to a read-only device',()=>{
  const f=fixture(); const current=f.create(f.active()),taskId=current.tasks[0]!.id;
  for(const auth of [f.auth(f.first,['read_project','comment']),f.auth(f.owner,['read_project'])]) {
    denied('permission_denied',()=>f.apply(current,{action:'assign_task',taskId,assigneeIds:[f.first],leadProfileId:null,teamId:null},auth));
    denied('permission_denied',()=>f.apply(current,{action:'create_blocker',blocker:{id:randomUUID(),taskId,responsibleProfileId:auth.actor.accountId}},auth));
    denied('permission_denied',()=>f.apply(current,{action:'edit_task',taskId},auth));
  }
});

test('CP08: cancellation deactivates blockers; restoration atomically reopens acceptance and preserves historical closing evidence',()=>{
  const f=fixture(),milestoneId=randomUUID(); let current=f.apply(f.active(),{action:'create_milestone',milestone:{id:milestoneId,phaseId:null,ownerProfileId:null}}).state;
  current=f.create(current,[f.first,f.second],milestoneId); const taskId=current.tasks[0]!.id;
  current=f.apply(current,{action:'create_blocker',blocker:{id:randomUUID(),taskId,responsibleProfileId:f.first}}).state;
  current=f.apply(current,{action:'cancel_task',taskId,outcome:reason()}).state;
  assert.equal(planningTaskBlocked(current,taskId),false);
  current=f.apply(current,{action:'accept_milestone',milestoneId,outcome:reason()}).state;
  const original=structuredClone(current.snapshots[0]); assert.equal(original!.blockers!.length,1);
  current=f.apply(current,{action:'restore_task',taskId,outcome:reason()}).state;
  assert.equal(current.milestones[0]!.state,'open'); assert.equal(planningTaskBlocked(current,taskId),true); assert.deepEqual(current.snapshots[0],original);
  current=f.apply(current,{action:'resolve_blocker',blockerId:current.blockers![0]!.id,outcome:reason()}).state;
  current=f.submit(current); current=f.apply(current,{action:'accept_milestone',milestoneId,outcome:reason()}).state;
  assert.equal(current.snapshots.length,2); assert.deepEqual(current.snapshots[0],original); assert.equal(current.snapshots[1]!.tasks[0]!.state,'done');
  assert.equal(current.snapshots[1]!.blockers![0]!.state,'resolved');
  current=f.apply(current,{action:'reopen_task',taskId,outcome:reason()}).state;
  assert.equal(current.milestones[0]!.state,'open'); assert.equal(current.tasks[0]!.approvalOperationId,null); assert.deepEqual(current.snapshots[0],original);
});

test('CP08: cascade cancellation snapshots contain final cleared submission markers and preserve blockers',()=>{
  const f=fixture(); let current=f.submit(f.review(f.create(f.active())));
  const taskId=current.tasks[0]!.id;
  current=f.apply(current,{action:'create_blocker',blocker:{id:randomUUID(),taskId,responsibleProfileId:f.first}}).state;
  const result=f.apply(current,{action:'cancel_project',outcome:reason()});
  assert.equal(result.state.tasks[0]!.submittedRevision,null); assert.equal(result.snapshot!.tasks[0]!.submittedRevision,null);
  assert.deepEqual(result.state.snapshots.at(-1),result.snapshot); assert.equal(result.snapshot!.blockers!.length,1);
  assert.equal(planningTaskBlocked(result.state,taskId),false);
});

test('CP08: exact blocker child sets reject concurrent inserts and metadata actions never request task ciphertext replacement',()=>{
  const f=fixture(); const before=f.create(f.active()),taskId=before.tasks[0]!.id;
  const command=planningCommand.parse({action:'request_task_completion',taskId,acceptanceConfirmed:true,operationId:randomUUID(),expected:planningRevisionSnapshot(before)});
  const after=f.apply(before,{action:'create_blocker',blocker:{id:randomUUID(),taskId,responsibleProfileId:f.first}}).state;
  denied('revision_conflict',()=>evaluatePlanning(after,command,f.auth()));
  assert.equal(planningRecordReplacesContent(command,'task',taskId),false);
  assert.equal(planningRecordReplacesContent({operationId:command.operationId,expected:command.expected,action:'edit_task',taskId},'task',taskId),true);
  assert.equal(planningCommand.safeParse({...command,acceptanceConfirmed:false}).success,false);
  assert.equal(planningCommand.safeParse({...command,action:'edit_task',state:'done'}).success,false);
});

test('CP08: explicit v2 boundary leaves legacy bytes unchanged and strict graph schemas reject retroactive defaults',()=>{
  const f=fixture(),original=structuredClone(f.legacy);
  assert.deepEqual(f.legacy,original); assert.equal(Object.hasOwn(f.legacy,'version'),false);
  assert.equal(planningGraph.safeParse(f.state).success,true);
  assert.equal(planningGraph.safeParse({...f.legacy,project:{...f.legacy.project,reviewEnabled:false}}).success,false);
  assert.equal(f.state.project.reviewEnabled,false); assert.deepEqual(f.state.blockers,[]);
});


test('CP08: security cleanup clears current Open and Resolved responsibilities and unavailable reviewers without resolving blockers or erasing historical actors',()=>{
  const f=fixture(); let current=f.submit(f.review(f.create(f.active()))); const taskId=current.tasks[0]!.id;
  for(let i=0;i<2;i++) current=f.apply(current,{action:'create_blocker',blocker:{id:randomUUID(),taskId,responsibleProfileId:f.first}}).state;
  current=f.apply(current,{action:'resolve_blocker',blockerId:current.blockers![0]!.id,outcome:reason()}).state;
  const security:SecurityHistoryState={workspaceId:f.workspaceId,origin:'https://example.test',genesisFingerprint:'a'.repeat(64),securityHead:'b'.repeat(64),securityVersion:'1',dataGeneration:'1',ownershipVersion:'1',custodyEpoch:'1',workspaceKeyEpoch:'1',entitlementState:'activated',licenceState:'active',profiles:{},devices:{},recoveryAuthorities:{},roles:{},scopeHeads:{},custodyManifest:{id:randomUUID(),digest:'a'.repeat(64),revision:'1'}};
  const prior=structuredClone(current);
  const cleaned=applyPlanningSecurityCleanup(current,security,'2026-09-26T12:00:00.000Z');
  assert.deepEqual(cleaned.blockers!.map(b=>b.responsibleProfileId),[null,null]);
  assert.deepEqual(cleaned.blockers!.map(b=>b.state),['resolved','open']);
  assert.equal(cleaned.blockers![0]!.resolvedBy,prior.blockers![0]!.resolvedBy); assert.equal(cleaned.blockers![1]!.createdBy,prior.blockers![1]!.createdBy);
  assert.equal(cleaned.tasks[0]!.reviewerProfileId,null); assert.equal(cleaned.tasks[0]!.state,'in_progress');
  assert.equal(cleaned.tasks[0]!.submittedRevision,null); assert.equal(planningTaskBlocked(cleaned,taskId),true);
  assert.deepEqual(cleaned.snapshots,prior.snapshots); assert.deepEqual(current,prior);
  const legacyTask={workspaceId:f.workspaceId,projectId:f.projectId,id:taskId,revision:'1',state:'review' as const,phaseId:null,milestoneId:null,assigneeIds:[f.first],leadProfileId:f.first};
  assert.equal(applyPlanningSecurityCleanup({...f.legacy,tasks:[legacyTask]},security,'2026-09-26T12:00:00.000Z').tasks[0]!.state,'review');
  const done={...current,tasks:current.tasks.map(t=>({...t,state:'done' as const,approvalOperationId:randomUUID()}))};
  const cleanedDone=applyPlanningSecurityCleanup(done,security,'2026-09-26T12:00:00.000Z');
  assert.equal(cleanedDone.tasks[0]!.state,'done'); assert.equal(cleanedDone.tasks[0]!.approvalOperationId,done.tasks[0]!.approvalOperationId); assert.equal(cleanedDone.tasks[0]!.submittedRevision,done.tasks[0]!.submittedRevision);
});


test('CP08: self-assigned task creation cannot smuggle reviewer selection through create_tasks',()=>{
  const f=fixture(); const member=f.auth(f.first,['read_project','create_tasks','edit_assigned_tasks']);
  const task={id:randomUUID(),phaseId:null,milestoneId:null,assigneeIds:[f.first],leadProfileId:null,reviewerProfileId:f.reviewer};
  denied('permission_denied',()=>f.apply(f.state,{action:'create_task',task},member));
  const {reviewerProfileId:_,...ordinary}=task;
  assert.equal(f.apply(f.state,{action:'create_task',task:ordinary},member).state.tasks[0]!.reviewerProfileId,null);
  assert.equal(f.apply(f.state,{action:'create_task',task}).state.tasks[0]!.reviewerProfileId,f.reviewer);
});


test('CP08: reopening/restoring terminal work clears an unavailable current reviewer while retaining earlier approval history',()=>{
  const f=fixture(); let current=f.submit(f.review(f.create(f.active()))); const taskId=current.tasks[0]!.id;
  current=f.apply(current,{action:'approve_task',taskId,submittedRevision:'1',submittedPolicyRevision:'2'},f.auth(f.reviewer,['read_project','approve_tasks'])).state;
  const historical=structuredClone(current.tasks[0]);
  const authority=f.auth(); authority.eligibleReviewerIds=[f.owner];
  const reopened=f.apply(current,{action:'reopen_task',taskId,outcome:reason()},authority).state;
  assert.equal(reopened.tasks[0]!.reviewerProfileId,null); assert.equal(reopened.tasks[0]!.approvalOperationId,null);
  assert.deepEqual(current.tasks[0],historical); assert.ok(historical!.approvalOperationId);
  const cancelled=f.apply(current,{action:'cancel_task',taskId,outcome:reason()},authority).state;
  assert.equal(cancelled.tasks[0]!.reviewerProfileId,f.reviewer);
  const restored=f.apply(cancelled,{action:'restore_task',taskId,outcome:reason()},authority).state;
  assert.equal(restored.tasks[0]!.reviewerProfileId,null); assert.equal(restored.tasks[0]!.state,'todo');
});


test('CP08: newly active phase/milestone designations clear unavailable people while old closing snapshots remain immutable',()=>{
  const f=fixture(),phaseId=randomUUID(),milestoneId=randomUUID();
  let current=f.apply(f.active(),{action:'create_phase',phase:{id:phaseId,displayOrder:0,leadProfileId:f.second}}).state;
  current=f.apply(current,{action:'cancel_phase',phaseId,tasks:[],milestones:[],outcome:reason()}).state;
  current=f.apply(current,{action:'create_milestone',milestone:{id:milestoneId,phaseId:null,ownerProfileId:f.second}}).state;
  current=f.create(current,[f.first],milestoneId); const taskId=current.tasks[0]!.id;
  current=f.apply(current,{action:'cancel_task',taskId,outcome:reason()}).state;
  current=f.apply(current,{action:'accept_milestone',milestoneId,outcome:reason()}).state;
  const historical=structuredClone(current.snapshots),authority=f.auth(); authority.eligibleAssigneeIds=[f.owner,f.first,f.reviewer];
  current=f.apply(current,{action:'reopen_phase',phaseId},authority).state;
  assert.equal(current.phases[0]!.leadProfileId,null);
  const explicit=f.apply(current,{action:'reopen_milestone',milestoneId},authority).state;
  assert.equal(explicit.milestones[0]!.ownerProfileId,null); assert.deepEqual(explicit.snapshots,historical);
  current=f.apply(current,{action:'restore_task',taskId,outcome:reason()},authority).state;
  assert.equal(current.milestones[0]!.state,'open'); assert.equal(current.milestones[0]!.ownerProfileId,null);
  assert.deepEqual(current.snapshots,historical); assert.equal(historical.at(-1)!.milestones[0]!.ownerProfileId,f.second);
});

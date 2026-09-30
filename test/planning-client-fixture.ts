import { randomUUID } from 'node:crypto';
import { digestObject } from '../src/shared/crypto.js';
import { createProjectBinding } from '../src/shared/project-create.js';
import { deriveScopeProvisionPlan } from '../src/shared/scope-provision.js';
import { prepareProjectCreate } from '../src/client/project-create-crypto.js';
import { initialPlanningGraph, planningBinding, planningContext, planningGraphDigest, planningEligibleReviewers, validatePlanningPayload,
  type PlanningPayload, type PlanningReceipt, type PlanningContext, type PlanningRecord } from '../src/shared/planning-api.js';
import { planningRevisionSnapshot, upgradePlanningGraph } from '../src/shared/planning.js';
import { ownerFixture, append, actorAuthority, join, origin, type Actor } from './project-create-client-fixture.js';

export async function planningClientFixture(options: { version?: 1 | 2 | 3; secondOwner?: boolean } = {}) {
  const f = await ownerFixture(), secondOwner = options.secondOwner ? await join(f, true) : undefined,
    request = { workspaceId: f.workspaceId, operationId: randomUUID(), projectId: randomUUID() }, now = Date.now(),
    binding = createProjectBinding(request, f.state, actorAuthority(f), { issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600000).toISOString() }),
    created = await prepareProjectCreate({ request, context: { binding, plan: deriveScopeProvisionPlan(binding, f.state), materials: f.materials }, history: f.history, name: 'Private original project' }, f.owner.bundle);
  await append(f, created.transition, binding.nextSecurityVersion);
  f.materials.push({ id: created.custody.id, kind: 'custody_manifest', value: created.custody.envelope, digest: await digestObject(created.custody.envelope) });
  for (const object of created.deliveries) f.materials.push({ id: object.id, kind: 'key_envelope', value: object.envelope, digest: await digestObject(object.envelope) });
  let graph = initialPlanningGraph(created.transition), head = await digestObject(created.transition), version = '0', protocolVersion = options.version ?? 1;
  if (protocolVersion !== 1) graph = upgradePlanningGraph(graph);
  const upgrades: NonNullable<PlanningContext['upgrades']> = [];
  const history: PlanningContext['history'] = [], audits: PlanningContext['audits'] = [], outcomes: PlanningContext['outcomes'] = [],
    records = new Map<string, PlanningRecord>([[`project:${request.projectId}`, { kind: 'project', ...created.project }]]), receipts = new Map<string, PlanningReceipt>();
  const context = async (operationId: string = randomUUID(), actor: Actor = f.owner, validate = true):Promise<PlanningContext> => {
    const state = f.state, profile = state.profiles[actor.accountId]!, device = state.devices[actor.deviceId]!, role = state.roles[profile.projectRoles[request.projectId]!.id]!, now = Date.now();
    const binding = planningBinding.parse({ version: protocolVersion, ...(protocolVersion===3?{writeSchema:2}:{}), workspaceId: f.workspaceId, projectId: request.projectId, operationId, origin,
      accountId: actor.accountId, deviceId: actor.deviceId, credentialGeneration: profile.credentialGeneration, sessionGeneration: profile.sessionGeneration,
      keyGeneration: device.keyGeneration, signingPublicKey: device.signingPublicKey, permissionVersion: role.revision,
      permissions: profile.scopes.find((s) => s.scopeId === request.projectId)!.permissions,
      eligibleAssigneeIds: Object.values(state.profiles).filter((p) => p.active && p.scopes.some((scope) => scope.scope === 'project' && scope.scopeId === request.projectId && scope.permissions.includes('read_project') &&
        (scope.expiresAt === null || Date.parse(scope.expiresAt) > now))).map((p) => p.accountId).sort(), isOwner: true, keyEpoch: state.scopeHeads[`project:${request.projectId}`]!.keyEpoch,
      securityVersion: state.securityVersion, securityHead: state.securityHead, dataGeneration: state.dataGeneration,
      ...(protocolVersion !== 1 ? { eligibleReviewerIds: planningEligibleReviewers(state, request.projectId, new Date(now).toISOString()) } : {}),
      beforeVersion: version, beforeHead: head, beforeGraphDigest: await planningGraphDigest(graph), before: planningRevisionSnapshot(graph),
      issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600000).toISOString() });
    const value={ binding, graph, records: [...records.values()], creation: created.transition, history, materials: f.materials, audits, outcomes, ...(upgrades.length?{upgrades}:{}) };
    return validate?planningContext.parse(value):value;
  };
  const apply = async (payload: PlanningPayload): Promise<PlanningReceipt> => {
    const b = payload.mutation.body.binding;
    if (b.beforeHead !== head || b.beforeVersion !== version || receipts.has(b.operationId)) throw new Error('Stale or reused planning operation');
    const validated = await validatePlanningPayload(payload, b, graph, [...records.values()]); graph = validated.result.state; head = await digestObject(payload.mutation); version = payload.mutation.body.nextVersion;
    if(payload.upgradeItems)upgrades.push({operationId:b.operationId,items:payload.upgradeItems});
    history.push(payload.mutation); audits.push(payload.audit); if (payload.outcome) outcomes.push(payload.outcome);
    for (const record of payload.records) records.set(`${record.kind}:${record.id}`, record);
    const receipt: PlanningReceipt = { version: 1, workspaceId: f.workspaceId, projectId: request.projectId, operationId: b.operationId, dataGeneration: f.state.dataGeneration,
      requestHash: await digestObject(payload), planningVersion: version, planningHead: head, graphDigest: payload.mutation.body.afterGraphDigest, committedAt: new Date().toISOString(), mutation: payload.mutation };
    receipts.set(b.operationId, receipt); return receipt;
  };
  return { f, secondOwner, projectId: request.projectId, context, rawContext:(operationId?:string,actor:Actor=f.owner)=>context(operationId,actor,false), apply, receipts, state: () => graph,
    upgrade: (target:2|3=2) => { protocolVersion = target; graph = upgradePlanningGraph(graph); },
    input: async (operationId?: string, actor: Actor = f.owner) => ({ context: await context(operationId, actor), history: f.history,
      accountId: actor.accountId, deviceId: actor.deviceId,
      closingSettings: { history: f.history, materials: f.materials, accountId: actor.accountId, deviceId: actor.deviceId,
        settings: { workspaceId: f.workspaceId, initial: f.initialWorkspace, revision: '0', head: await digestObject(f.initialWorkspace), timezone: null,
          history: [], securityHead: f.state.securityHead, securityVersion: f.state.securityVersion, dataGeneration: f.state.dataGeneration } } }) };
}

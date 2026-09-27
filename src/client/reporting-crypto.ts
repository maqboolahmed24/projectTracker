import { z } from 'zod';
import { base64urlDecode, canonicalJson, decryptContent, digestObject, encryptContent, signObject } from '../shared/crypto.js';
import { verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState } from '../shared/security-history.js';
import { reportingContext, reportingManifest, reportingProjectIds, reportingSummaryHeader,
  reportingSameCheckpoint, validateReportingSummary, type ReportingBinding, type ReportingContext,
  type ReportingRead, type ReportingScope, type ReportingSummaryPayload } from '../shared/reporting.js';
import { calculateProgress, aggregateProgress, progressClock, progressResultSchema, type ProgressResult, type ProgressScope } from '../shared/progress.js';
import type { DeviceBundle } from './device-store.js';
import { openVerifiedPlanning, planningSecurityResolver, type ReadablePlanning } from './planning-crypto.js';
import { actorBinding, fresh, readReportingSettings, type ReportingKeys, type ReportingSettingsPin } from './reporting-settings-crypto.js';
export { readReportingSettings, prepareReportingSettings } from './reporting-settings-crypto.js';
export type { ReportingKeys, ReportingSettingsPin, ReadReportingSettingsInput, PrepareReportingSettingsInput } from './reporting-settings-crypto.js';
import type { PlanningPin } from './planning-store.js';

export class ReportingClientError extends Error {
  constructor(readonly code: 'INVALID_REPORTING' | 'INCOMPLETE_KEYS' | 'TRUST_REQUIRED' | 'CONFLICT' | 'EXPIRED' | 'UNRECORDED_TIMEZONE' | 'CANCELLED' | 'NOT_FOUND') {
    super(`Reporting failed (${code})`); this.name = 'ReportingClientError';
  }
}
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
function invalid(): never { throw new ReportingClientError('INVALID_REPORTING'); }
export interface CalculateReportingInput extends ReportingKeys { context: ReportingContext; planningPins?: PlanningPin[]; settingsPin?: ReportingSettingsPin }
export interface ReadReportingInput extends ReportingKeys { response: ReportingRead; planningPins?: PlanningPin[]; settingsPin?: ReportingSettingsPin }
export interface ReadableReporting {
  status: 'current' | 'last-calculated' | 'missing'; scope: ReportingScope; asOfUtc: string; timezone: string; localDate: string; nextMidnightUtc: string;
  components: { projectId: string; result: ProgressResult }[]; aggregate: ReturnType<typeof aggregateProgress> | null;
  planningPins: PlanningPin[]; settingsPin: ReportingSettingsPin;
}
function reportingDates(readable: ReadablePlanning) {
  return readable.records.filter((record) => record.kind !== 'blocker').map((record) => ({
    kind: record.kind as 'project' | 'phase' | 'milestone' | 'task', id: record.id,
    ...(typeof record.content.startDate === 'string' ? { startDate: record.content.startDate } : {}),
    ...(typeof record.content.dueDate === 'string' ? { dueDate: record.content.dueDate } : {}),
  }));
}
async function verifyReportingBinding(b: ReportingBinding, state: SecurityHistoryState, publish = false) {
  const { p, d, live } = actorBinding(b, state), visibleScopes = p.scopes.filter(s => s.scope === 'project' && live(s)).flatMap(person => {
    const device = d.scopes.find(s => s.scope === 'project' && s.scopeId === person.scopeId && s.keyEpoch === person.keyEpoch && live(s));
    const permissions = person.permissions.filter(permission => device?.permissions.includes(permission)).sort();
    return permissions.includes('read_project') ? [{ projectId: person.scopeId, keyEpoch: person.keyEpoch, permissions }] : [];
  }).sort((a,b) => a.projectId.localeCompare(b.projectId));
  if (!same(visibleScopes,b.visibleScopes) || b.authorizationFingerprint !== await digestObject({securityHead:b.securityHead,securityVersion:b.securityVersion,dataGeneration:b.dataGeneration,visibleScopes}) ||
    b.scopeHash !== await digestObject(b.scope) || !same(reportingProjectIds(b.scope),b.sources.map(s => s.projectId)) || b.asOfUtc !== b.issuedAt ||
    b.localDate !== progressClock(b.asOfUtc,b.timezone).localDate) invalid();
  for (const source of b.sources) {
    const visible = visibleScopes.find(s => s.projectId === source.projectId), role = state.roles[p.projectRoles[source.projectId]?.id ?? p.role.id];
    if (!visible || !same(source.permissions,visible.permissions) || source.keyEpoch !== visible.keyEpoch || source.permissionVersion !== role?.revision ||
      publish && !source.permissions.includes('plan_projects')) invalid();
  }
  if (publish && (state.activeUpgrade || state.licenceState !== 'active' || state.entitlementState !== 'activated')) invalid();
}
function projectScope(scope: ReportingScope, view: ReadablePlanning): ProgressScope {
  if (scope.kind === 'team') return {kind:'filtered',taskIds:view.graph.tasks.filter(t => t.teamId === scope.teamId).map(t=>t.id).sort()};
  if (scope.kind === 'visible_projects' || scope.kind === 'project') return {kind:'project'};
  if (scope.kind === 'filtered') return {kind:'filtered',taskIds:scope.taskIds};
  return {kind:scope.kind,id:scope.id};
}
async function openedReporting(value: CalculateReportingInput, bundle: DeviceBundle) {
  const input = structuredClone(value), context = reportingContext.parse(input.context) as ReportingContext, b = context.binding,
    state = await verifySecurityHistory(input.history), settings = await readReportingSettings({...input,settings:context.settings},bundle);
  await verifyReportingBinding(b,state); fresh(b);
  if (b.accountId !== input.accountId || b.deviceId !== input.deviceId || b.signingPublicKey !== bundle.signingPublicKey ||
    settings.timezone === null || settings.timezone !== b.timezone || settings.revision !== b.settingsRevision || settings.head !== b.settingsHead ||
    settings.pin.initialDigest !== b.initialDigest || !same(context.projects.map(p=>p.binding.projectId),reportingProjectIds(b.scope))) invalid();
  const opened: Awaited<ReturnType<typeof openVerifiedPlanning>>[] = [];
  for (const [index, project] of context.projects.entries()) {
    const pin = input.planningPins?.find(pin=>pin.projectId === project.binding.projectId),
      verified = await openVerifiedPlanning({context:project,history:input.history,accountId:input.accountId,deviceId:input.deviceId,...(pin?{pin}:{})},bundle);
    if (project.binding.workspaceId !== b.workspaceId || project.binding.securityHead !== b.securityHead || project.binding.securityVersion !== b.securityVersion ||
      project.binding.dataGeneration !== b.dataGeneration || !same(await reportingManifest(verified.context),b.sources[index])) invalid();
    opened.push(verified);
  }
  const calculate = (binding: ReportingBinding) => opened.map(project => {
    const result = calculateProgress({graph:project.readable.graph,dates:reportingDates(project.readable),scope:projectScope(binding.scope,project.readable),
      timezone:binding.timezone,asOfUtc:binding.asOfUtc,source:{complete:true,current:true,verified:true,decrypted:true},
      milestoneOrder:project.context.history.flatMap((mutation,index)=>mutation.body.command.action==='create_milestone'?[{id:mutation.body.command.milestone.id,order:index}]:[]),
      closingSettingsByOperation:project.readable.audits.flatMap(audit=>audit.closingSettings ? [{operationId:audit.operationId,settings:audit.closingSettings}] : [])});
    if (!result.current) invalid(); return {projectId:project.context.binding.projectId,result};
  });
  return {context,state,settings,opened,calculate};
}
function readable(binding: ReportingBinding, components: ReadableReporting['components'], opened: Awaited<ReturnType<typeof openedReporting>>, status: ReadableReporting['status'] = 'current'): ReadableReporting {
  return {status,scope:binding.scope,timezone:binding.timezone,asOfUtc:binding.asOfUtc,...progressClock(binding.asOfUtc,binding.timezone),components,
    aggregate:components.length && 'projectIds' in binding.scope ? aggregateProgress(components.map(c=>c.result)) : null,
    planningPins:opened.opened.map(p=>p.readable.pin),settingsPin:opened.settings.pin};
}
export async function calculateReporting(input: CalculateReportingInput,bundle:DeviceBundle):Promise<ReadableReporting> {
  const opened = await openedReporting(input,bundle); return readable(opened.context.binding,opened.calculate(opened.context.binding),opened);
}
export async function prepareReporting(input:CalculateReportingInput,bundle:DeviceBundle):Promise<ReportingSummaryPayload> {
  const opened = await openedReporting(input,bundle), b = opened.context.binding; await verifyReportingBinding(b,opened.state,true);
  const results=opened.calculate(b),components:ReportingSummaryPayload['components']=[],signing=base64urlDecode(bundle.signingPrivateKey,64);
  try {
    for(const [index,result] of results.entries()) {
      const ring=opened.opened[index]!.ring,epoch=ring.find(key=>key.epoch===b.sources[index]!.keyEpoch); if(!epoch)throw new ReportingClientError('INCOMPLETE_KEYS');
      const id=crypto.randomUUID(),header=reportingSummaryHeader(b,result.projectId,id),key=base64urlDecode(epoch.key,32),plaintext={version:1,source:b.sources[index],result:result.result};
      try{const envelope=await encryptContent(header,plaintext,key,signing);
        if(!same(await decryptContent(envelope,key,base64urlDecode(bundle.signingPublicKey,32),header),plaintext))invalid();
        components.push({projectId:result.projectId,id,envelope});}finally{key.fill(0);}
    }
    return validateReportingSummary({components,mutation:await signObject({purpose:'ukda.reporting-summary.v1' as const,binding:b,
      components:await Promise.all(components.map(async c=>({projectId:c.projectId,id:c.id,digest:await digestObject(c.envelope)})))},signing)});
  }finally{signing.fill(0);}
}
export async function readReporting(input:ReadReportingInput,bundle:DeviceBundle):Promise<ReadableReporting> {
  const opened=await openedReporting({...input,context:input.response.context},bundle),current=opened.context.binding,response=input.response;
  if(!response.payload){if(response.state!=='missing')invalid();return readable(current,[],opened,'missing');}
  if(response.state==='missing')invalid();
  const payload=await validateReportingSummary(response.payload),b=payload.mutation.body.binding,
    historyAt=planningSecurityResolver(input.history,opened.state);
  await verifyReportingBinding(b,await historyAt(b.securityVersion,b.securityHead),true);
  // A formerly wider view is never returned as a convenient stale fallback.
  if(b.workspaceId!==current.workspaceId||!same(b.scope,current.scope)||b.authorizationFingerprint!==current.authorizationFingerprint||
    b.initialDigest!==current.initialDigest||BigInt(b.settingsRevision)>BigInt(current.settingsRevision)||Date.parse(b.asOfUtc)>Date.parse(current.asOfUtc))invalid();
  const settingsHistory=opened.context.settings.history.slice(0,Number(b.settingsRevision)),historicalSettings=await readReportingSettings({
    history:input.history,materials:input.materials,accountId:input.accountId,deviceId:input.deviceId,
    settings:{...opened.context.settings,history:settingsHistory,revision:b.settingsRevision,head:b.settingsHead,timezone:settingsHistory.at(-1)?.mutation.body.timezone??null}},bundle);
  if(historicalSettings.timezone!==b.timezone)invalid();
  const components:ReadableReporting['components']=[];
  for(const [index,component] of payload.components.entries()){
    const source=b.sources[index]!,project=opened.opened.find(p=>p.context.binding.projectId===component.projectId),epoch=project?.ring.find(k=>k.epoch===source.keyEpoch);
    if(!epoch)throw new ReportingClientError('INCOMPLETE_KEYS');
    const version=Number(source.planningVersion),history=project!.context.history;
    if(!Number.isSafeInteger(version)||version>history.length||source.planningHead!==await digestObject(version===0?project!.context.creation:history[version-1]!))invalid();
    const original=project!.context.creation.body.project;
    if(!original)invalid();
    const manifest=new Map<string,ReportingBinding['sources'][number]['records'][number]>([[`project:${component.projectId}`,
      {kind:'project',id:component.projectId,revision:'1',contentRevision:'1',digest:original.digest}]]);
    for(const mutation of history.slice(0,version))for(const record of mutation.body.records)
      manifest.set(`${record.kind}:${record.id}`,{kind:record.kind,id:record.id,revision:record.revision,contentRevision:'contentRevision' in record?record.contentRevision:record.revision,digest:record.digest});
    if(!same(source.records,[...manifest.values()].sort((a,b)=>a.kind.localeCompare(b.kind)||a.id.localeCompare(b.id))))invalid();
    const key=base64urlDecode(epoch.key,32);
    try{
      const content=z.strictObject({version:z.literal(1),source:z.unknown(),result:progressResultSchema}).parse(await decryptContent(component.envelope,key,
        base64urlDecode(b.signingPublicKey,32),reportingSummaryHeader(b,component.projectId,component.id))),result=content.result;
      if(!same(content.source,source)||result.workspaceId!==b.workspaceId||result.projectId!==component.projectId||!result.current||
        result.timezone!==b.timezone||result.asOfUtc!==b.asOfUtc||result.localDate!==b.localDate||result.calculationVersion!==b.calculationVersion||
        result.nextMidnightUtc!==progressClock(b.asOfUtc,b.timezone).nextMidnightUtc)invalid();
      components.push({projectId:component.projectId,result});
    }finally{key.fill(0);}
  }
  let status:ReadableReporting['status']='last-calculated';
  if(reportingSameCheckpoint(b,current)){
    if(!same(components,opened.calculate(b)))invalid();
    // UTC blocker ages can change before workspace midnight even with identical revisions.
    const freshComponents=opened.calculate(current).map(c=>({...c,result:{...c.result,asOfUtc:b.asOfUtc}}));
    if(response.state==='current'&&same(components,freshComponents))status='current';
  }
  return readable(b,components,opened,status);
}

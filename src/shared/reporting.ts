import { z } from 'zod';
import { binary, permissionCapabilities, contentEnvelope, counter, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyContentEnvelope, verifyObject, type ContentHeader } from './crypto.js';
import { planningContext, type PlanningContext } from './planning-api.js';

export const REPORTING_MAX_PROJECTS = 16, REPORTING_MAX_BYTES = 32 * 1024 * 1024, REPORTING_MAX_SETTINGS = 512;
export const reportingTimezone = z.string().min(1).max(100).refine((value) => { try { new Intl.DateTimeFormat('en', { timeZone: value }).format(); return true; } catch { return false; } });
const sortedIds = z.array(identifier).max(2000).refine((ids) => ids.every((id, i) => i === 0 || ids[i - 1]! < id));
const projects = z.array(identifier).min(1).max(REPORTING_MAX_PROJECTS).refine((ids) => ids.every((id, i) => i === 0 || ids[i - 1]! < id));
export const reportingScope = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('project'), projectId: identifier }),
  z.strictObject({ kind: z.literal('phase'), projectId: identifier, id: identifier }),
  z.strictObject({ kind: z.literal('milestone'), projectId: identifier, id: identifier }),
  z.strictObject({ kind: z.literal('filtered'), projectId: identifier, taskIds: sortedIds }),
  z.strictObject({ kind: z.literal('visible_projects'), projectIds: projects }),
  z.strictObject({ kind: z.literal('team'), teamId: identifier, projectIds: projects }),
]);
export type ReportingScope = z.infer<typeof reportingScope>;
export const reportingProjectIds = (scope: ReportingScope): string[] => 'projectIds' in scope ? scope.projectIds : [scope.projectId];
export const reportingReference = z.strictObject({ workspaceId: identifier, operationId: identifier });
export const reportingActor = reportingReference.extend({ version: z.literal(1), origin: z.string().url(), accountId: identifier, deviceId: identifier,
  credentialGeneration: positiveCounter, sessionGeneration: positiveCounter, keyGeneration: positiveCounter, signingPublicKey: binary(32),
  securityVersion: positiveCounter, securityHead: digest, dataGeneration: positiveCounter, writeSchema: z.literal(2).optional(), isOwner: z.boolean(), issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime() });
export const reportingSettingsBinding = reportingActor.extend({ expectedRevision: counter, previousHead: digest, initialDigest: digest, previousTimezone: reportingTimezone.nullable() });
export const reportingSettingsPayload = z.strictObject({ mutation: z.strictObject({ body: z.strictObject({ purpose: z.literal('ukda.reporting-settings.v1'),
  binding: reportingSettingsBinding, timezone: reportingTimezone }), signature: binary(64) }) });
export type ReportingSettingsPayload = z.infer<typeof reportingSettingsPayload>;
export const reportingSettings = z.strictObject({ workspaceId: identifier, initial: contentEnvelope, revision: counter, head: digest,
  timezone: reportingTimezone.nullable(), history: z.array(reportingSettingsPayload).max(REPORTING_MAX_SETTINGS),
  securityHead: digest, securityVersion: positiveCounter, dataGeneration: positiveCounter });
export type ReportingSettings = z.infer<typeof reportingSettings>;
export const reportingSettingsContext = z.strictObject({ binding: reportingSettingsBinding, settings: reportingSettings });
export type ReportingSettingsContext = z.infer<typeof reportingSettingsContext>;
export const reportingVisibleScope = z.strictObject({ projectId: identifier, keyEpoch: positiveCounter, permissions: z.array(z.enum(permissionCapabilities)) });
export const reportingSourceRecord = z.strictObject({ kind: z.enum(['project','phase','milestone','task','blocker']), id: identifier,
  revision: positiveCounter, contentRevision: positiveCounter, digest });
export const reportingSource = z.strictObject({ projectId: identifier, permissionVersion: positiveCounter, permissions: z.array(z.enum(permissionCapabilities)), keyEpoch: positiveCounter,
  planningVersion: counter, planningHead: digest, graphDigest: digest, records: z.array(reportingSourceRecord).max(2000) });
export type ReportingSource = z.infer<typeof reportingSource>;
export const reportingContextRequest = reportingReference.extend({ scope: reportingScope, timezone: reportingTimezone });
export const reportingBinding = reportingActor.extend({ scope: reportingScope, scopeHash: digest, authorizationFingerprint: digest,
  visibleScopes: z.array(reportingVisibleScope).max(2000), sources: z.array(reportingSource).min(1).max(REPORTING_MAX_PROJECTS),
  settingsRevision: counter, settingsHead: digest, initialDigest: digest, timezone: reportingTimezone,
  asOfUtc: z.iso.datetime(), localDate: z.iso.date(), complete: z.literal(true), calculationVersion: z.literal('progress-health-v1') });
export type ReportingBinding = z.infer<typeof reportingBinding>;
export const reportingContext = z.strictObject({ binding: reportingBinding, settings: reportingSettings, projects: z.array(planningContext).min(1).max(REPORTING_MAX_PROJECTS) });
export type ReportingContext = Omit<z.infer<typeof reportingContext>, 'projects'> & { projects: PlanningContext[] };
const componentRef = z.strictObject({ projectId: identifier, id: identifier, digest });
export const reportingSummaryPayload = z.strictObject({ mutation: z.strictObject({ body: z.strictObject({ purpose: z.literal('ukda.reporting-summary.v1'),
  binding: reportingBinding, components: z.array(componentRef).min(1).max(REPORTING_MAX_PROJECTS) }), signature: binary(64) }),
  components: z.array(z.strictObject({ projectId: identifier, id: identifier, envelope: contentEnvelope })).min(1).max(REPORTING_MAX_PROJECTS) });
export type ReportingSummaryPayload = z.infer<typeof reportingSummaryPayload>;
export const reportingReceipt = z.strictObject({ version: z.literal(1), workspaceId: identifier, operationId: identifier, accountId: identifier,
  dataGeneration: positiveCounter, requestHash: digest, kind: z.enum(['settings','summary']), head: digest, revision: counter, committedAt: z.iso.datetime() });
export type ReportingReceipt = z.infer<typeof reportingReceipt>;
export const reportingStatusRequest = reportingReference.extend({ dataGeneration: positiveCounter, requestHash: digest, kind: z.enum(['settings','summary']) });
export const reportingView = z.strictObject({ state: z.enum(['absent','completed']), receipt: reportingReceipt.nullable() });
export const reportingRead = z.strictObject({ context: reportingContext, state: z.enum(['current','stale','missing']), payload: reportingSummaryPayload.nullable() });
export type ReportingRead = Omit<z.infer<typeof reportingRead>, 'context'> & { context: ReportingContext };
export function reportingLocalDate(at: string, timezone: string): string {
  const parts = new Intl.DateTimeFormat('en-GB', { timeZone: reportingTimezone.parse(timezone), year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date(at));
  return ['year','month','day'].map((type) => parts.find((part) => part.type === type)!.value).join('-');
}
export async function reportingManifest(context: PlanningContext): Promise<ReportingSource> {
  const b = context.binding;
  const records = await Promise.all(context.records.map(async (record) => {
    const row = record.kind === 'project' ? context.graph.project : record.kind === 'phase' ? context.graph.phases.find((r) => r.id === record.id) :
      record.kind === 'milestone' ? context.graph.milestones.find((r) => r.id === record.id) : record.kind === 'task' ? context.graph.tasks.find((r) => r.id === record.id) : context.graph.blockers?.find((r) => r.id === record.id);
    if (!row) throw new Error('Incomplete reporting source');
    return { kind: record.kind, id: record.id, revision: row.revision, contentRevision: 'contentRevision' in row && row.contentRevision ? row.contentRevision : row.revision, digest: await digestObject(record.envelope) };
  }));
  records.sort((a,b) => a.kind.localeCompare(b.kind) || a.id.localeCompare(b.id));
  return reportingSource.parse({ projectId: b.projectId, permissionVersion: b.permissionVersion, permissions: [...b.permissions].sort(), keyEpoch: b.keyEpoch,
    planningVersion: b.beforeVersion, planningHead: b.beforeHead, graphDigest: b.beforeGraphDigest, records });
}
export function reportingSummaryHeader(binding: ReportingBinding, projectId: string, id: string): ContentHeader {
  const b = reportingBinding.parse(binding), source = b.sources.find((s) => s.projectId === projectId); if (!source) throw new Error('Missing summary source');
  return { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: b.workspaceId, scope: 'project', scopeId: projectId,
    recordId: id, recordType: 'summary', schema: b.writeSchema ?? 1, keyEpoch: source.keyEpoch, revision: '1', operationId: b.operationId, accountId: b.accountId,
    deviceId: b.deviceId, keyGeneration: b.keyGeneration, permissionVersion: source.permissionVersion, securityVersion: b.securityVersion,
    securityHead: b.securityHead, dataGeneration: b.dataGeneration, action: 'reporting.publish', approvalPolicyId: null, approvalPolicyRevision: null };
}
export async function validateReportingSettings(value: unknown): Promise<ReportingSettingsPayload> {
  const payload = reportingSettingsPayload.parse(value), b = payload.mutation.body.binding;
  if (!b.isOwner || Date.parse(b.expiresAt) <= Date.parse(b.issuedAt) || Date.parse(b.expiresAt) - Date.parse(b.issuedAt) > 600_000 ||
    !await verifyObject(payload.mutation, base64urlDecode(b.signingPublicKey, 32), 'ukda.reporting-settings.v1')) throw new Error('Invalid reporting settings');
  return payload;
}
export async function validateReportingSummary(value: unknown): Promise<ReportingSummaryPayload> {
  const payload = reportingSummaryPayload.parse(value), b = payload.mutation.body.binding, key = base64urlDecode(b.signingPublicKey, 32), ids = reportingProjectIds(b.scope);
  if (Date.parse(b.expiresAt) <= Date.parse(b.issuedAt) || Date.parse(b.expiresAt) - Date.parse(b.issuedAt) > 600_000 || b.asOfUtc !== b.issuedAt ||
    b.localDate !== reportingLocalDate(b.asOfUtc,b.timezone) || b.scopeHash !== await digestObject(b.scope) ||
    canonicalJson(b.sources.map((s) => s.projectId)) !== canonicalJson(ids) ||
    canonicalJson(payload.components.map((c) => c.projectId)) !== canonicalJson(ids) ||
    new Set(payload.components.map((c) => c.id)).size !== ids.length ||
    b.authorizationFingerprint !== await digestObject({ securityHead:b.securityHead, securityVersion:b.securityVersion, dataGeneration:b.dataGeneration, visibleScopes:b.visibleScopes }) ||
    b.sources.some((s) => !s.permissions.includes('plan_projects')) ||
    !await verifyObject(payload.mutation,key,'ukda.reporting-summary.v1')) throw new Error('Invalid reporting summary');
  for (let i=0;i<ids.length;i++) { const part=payload.components[i]!, ref=payload.mutation.body.components[i];
    if (!ref || ref.projectId!==part.projectId || ref.id!==part.id || ref.digest!==await digestObject(part.envelope) ||
      !await verifyContentEnvelope(part.envelope,key,reportingSummaryHeader(b,part.projectId,part.id))) throw new Error('Invalid reporting component'); }
  return payload;
}
export function reportingSameCheckpoint(one: ReportingBinding, two: ReportingBinding): boolean {
  return canonicalJson({ scope:one.scope,authorizationFingerprint:one.authorizationFingerprint,sources:one.sources,settingsRevision:one.settingsRevision,settingsHead:one.settingsHead,
    initialDigest:one.initialDigest,timezone:one.timezone,localDate:one.localDate }) === canonicalJson({ scope:two.scope,authorizationFingerprint:two.authorizationFingerprint,sources:two.sources,
    settingsRevision:two.settingsRevision,settingsHead:two.settingsHead,initialDigest:two.initialDigest,timezone:two.timezone,localDate:two.localDate });
}

import { z } from 'zod';
import { base64urlDecode, decryptContent, digestObject, signObject, verifyContentEnvelope } from '../shared/crypto.js';
import { initialContentHeader, transcriptFromGenesis } from '../shared/activation.js';
import { verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState } from '../shared/security-history.js';
import { reportingSettings, reportingSettingsContext, reportingTimezone, validateReportingSettings,
  type ReportingBinding, type ReportingSettings, type ReportingSettingsContext, type ReportingSettingsPayload } from '../shared/reporting.js';
import type { PairingMaterial } from '../shared/pairing.js';
import type { DeviceBundle } from './device-store.js';
import { readWorkspaceKeyRing } from './teams-crypto.js';
import { securityHistoryResolver } from './security-history-resolver.js';
export class ReportingSettingsError extends Error {
  constructor(readonly code: 'INVALID_REPORTING' | 'INCOMPLETE_KEYS' | 'EXPIRED') { super(`Reporting settings failed (${code})`); this.name='ReportingSettingsError'; }
}
function invalid(): never { throw new ReportingSettingsError('INVALID_REPORTING'); }
export interface ReportingKeys { history: SecurityHistoryInput; materials: PairingMaterial[]; accountId: string; deviceId: string }
export interface ReportingSettingsPin { workspaceId: string; revision: string; head: string; initialDigest: string; dataGeneration: string }
export interface ReadReportingSettingsInput extends ReportingKeys { settings: ReportingSettings; settingsPin?: ReportingSettingsPin }
export interface PrepareReportingSettingsInput extends ReportingKeys { context: ReportingSettingsContext; timezone: string; settingsPin?: ReportingSettingsPin }
async function initialTimezone(initial: import('../shared/contracts.js').ContentEnvelope, input: ReportingKeys, bundle: DeviceBundle) {
  const state = await verifySecurityHistory(input.history), genesis = input.history.genesis, ring = await readWorkspaceKeyRing(input, state, bundle);
  const initialDigest = await digestObject(initial);
  if (!genesis.body.manifest.some((entry) => entry.kind === 'encrypted_workspace' && entry.id === state.workspaceId && entry.digest === initialDigest)) invalid();
  const epoch = ring.find((entry) => entry.epoch === initial.header.keyEpoch); if (!epoch) throw new ReportingSettingsError('INCOMPLETE_KEYS');
  const key = base64urlDecode(epoch.key, 32);
  try {
    const data = z.strictObject({ name: z.string(), timezone: z.string().optional() }).parse(await decryptContent(initial, key,
      base64urlDecode(genesis.body.device.signingPublicKey, 32), initialContentHeader(transcriptFromGenesis(genesis.body), 'workspace')));
    return data.timezone ?? null;
  } finally { key.fill(0); }
}
type ReportingActor = ReportingBinding | ReportingSettingsContext['binding'];
export function actorBinding(b: ReportingActor, state: SecurityHistoryState, owner = false) {
  const p = state.profiles[b.accountId], d = state.devices[b.deviceId];
  if (b.workspaceId !== state.workspaceId || b.origin !== state.origin || b.securityHead !== state.securityHead || b.securityVersion !== state.securityVersion ||
    b.dataGeneration !== state.dataGeneration || (b.writeSchema ?? 1) !== (state.writeSchema ?? 1) || !p?.active || !d?.active || d.accountId !== b.accountId ||
    b.credentialGeneration !== p.credentialGeneration || b.sessionGeneration !== p.sessionGeneration || b.keyGeneration !== d.keyGeneration ||
    b.signingPublicKey !== d.signingPublicKey || b.isOwner !== p.owner || owner && !p.owner ||
    Date.parse(b.expiresAt) <= Date.parse(b.issuedAt) || Date.parse(b.expiresAt) - Date.parse(b.issuedAt) > 600000) invalid();
  const live = (s: { expiresAt: string | null }) => s.expiresAt === null || Date.parse(s.expiresAt) > Date.parse(b.issuedAt);
  if (owner && (!p.scopes.some(s => s.scope === 'workspace' && s.mode === 'custody' && s.keyEpoch === state.custodyEpoch && live(s)) ||
    !d.scopes.some(s => s.scope === 'workspace' && s.mode === 'custody' && s.keyEpoch === state.custodyEpoch && live(s)))) invalid();
  return { p, d, live };
}
export function fresh(b: ReportingActor) {
  if (Date.parse(b.issuedAt) > Date.now() + 30000 || Date.parse(b.expiresAt) <= Date.now()) throw new ReportingSettingsError('EXPIRED');
}
export async function readReportingSettings(value: ReadReportingSettingsInput, bundle: DeviceBundle) {
  const input = structuredClone(value), settings = reportingSettings.parse(input.settings), state = await verifySecurityHistory(input.history),
    securityAt = securityHistoryResolver(input.history,state), initialDigest = await digestObject(settings.initial);
  if (settings.workspaceId !== state.workspaceId || settings.securityHead !== state.securityHead || settings.securityVersion !== state.securityVersion || settings.dataGeneration !== state.dataGeneration) invalid();
  const genesis=input.history.genesis,device=state.devices[input.deviceId];
  if(!state.profiles[input.accountId]?.active||!device?.active||device.accountId!==input.accountId||device.signingPublicKey!==bundle.signingPublicKey||device.recipientPublicKey!==bundle.recipientPublicKey||
    !genesis.body.manifest.some(entry=>entry.kind==='encrypted_workspace'&&entry.id===state.workspaceId&&entry.digest===initialDigest)||
    !await verifyContentEnvelope(settings.initial,base64urlDecode(genesis.body.device.signingPublicKey,32),initialContentHeader(transcriptFromGenesis(genesis.body),'workspace')))invalid();
  // An explicit Owner setting is independently authenticated. A project-only
  // device need not receive the historical workspace key to read that setting.
  let timezone = settings.history.length ? null : await initialTimezone(settings.initial,input,bundle), storedTimezone: string | null = null, head = initialDigest;
  if (timezone !== null) timezone = reportingTimezone.parse(timezone);
  for (const [index, value] of settings.history.entries()) {
    const payload = await validateReportingSettings(value), b = payload.mutation.body.binding;
    actorBinding(b, await securityAt(b.securityVersion,b.securityHead), true);
    if (b.workspaceId !== settings.workspaceId || b.initialDigest !== initialDigest || b.expectedRevision !== String(index) || b.previousHead !== head || b.previousTimezone !== storedTimezone) invalid();
    timezone = payload.mutation.body.timezone; storedTimezone = timezone; head = await digestObject(payload.mutation);
  }
  if (settings.revision !== String(settings.history.length) || settings.head !== head || settings.timezone !== storedTimezone) invalid();
  const pin: ReportingSettingsPin = { workspaceId: settings.workspaceId, revision: settings.revision, head, initialDigest, dataGeneration: state.dataGeneration }, known = input.settingsPin;
  if (known && (known.workspaceId !== pin.workspaceId || known.initialDigest !== pin.initialDigest || BigInt(pin.dataGeneration) < BigInt(known.dataGeneration) ||
    pin.dataGeneration === known.dataGeneration && (BigInt(pin.revision) < BigInt(known.revision) || pin.revision === known.revision && pin.head !== known.head))) invalid();
  return { workspaceId: settings.workspaceId, timezone, revision: settings.revision, head, pin };
}
export async function prepareReportingSettings(value: PrepareReportingSettingsInput, bundle: DeviceBundle): Promise<ReportingSettingsPayload> {
  const input = structuredClone(value), context = reportingSettingsContext.parse(input.context), b = context.binding,
    verified = await readReportingSettings({ ...input, settings: context.settings },bundle), state = await verifySecurityHistory(input.history);
  actorBinding(b,state,true); fresh(b);
  if (state.activeUpgrade || state.licenceState !== 'active' || state.entitlementState !== 'activated' || b.accountId !== input.accountId || b.deviceId !== input.deviceId ||
    b.signingPublicKey !== bundle.signingPublicKey || b.expectedRevision !== verified.revision || b.previousHead !== verified.head ||
    b.initialDigest !== verified.pin.initialDigest || b.previousTimezone !== context.settings.timezone) invalid();
  const key = base64urlDecode(bundle.signingPrivateKey,64);
  try { return validateReportingSettings({ mutation: await signObject({ purpose: 'ukda.reporting-settings.v1' as const, binding:b, timezone:reportingTimezone.parse(input.timezone) },key) }); }
  finally { key.fill(0); }
}

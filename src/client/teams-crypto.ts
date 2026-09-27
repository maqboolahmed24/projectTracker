import { z } from 'zod';
import { binary, contentEnvelope, digest, identifier, positiveCounter } from '../shared/contracts.js';
import { base64urlDecode, canonicalJson, decryptContent, digestObject, encryptContent, signObject } from '../shared/crypto.js';
import { TEAM_HISTORY_MAX_BYTES, teamContent, teamContext, teamContextRequest, teamHeader, teamHistoryPage, teamMembers, teamMutationBody, teamPayload, validateTeamPayload,
  type TeamBinding, type TeamContext, type TeamHistoryPage, type TeamPayload } from '../shared/teams.js';
import { verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState, type HistoryScope } from '../shared/security-history.js';
import type { PairingMaterial, PairingScope } from '../shared/pairing.js';
import type { DeviceBundle } from './device-store.js';
import { readDeviceScopeKeyMaterial } from './pairing.js';
import { upgradeProof, type UpgradeItem, type UpgradeRecordRef } from '../shared/encrypted-upgrades.js';

export class TeamsClientError extends Error {
  constructor(readonly code: 'INVALID_TEAM' | 'INCOMPLETE_KEYS' | 'TRUST_REQUIRED' | 'CONFLICT' | 'NOT_FOUND' | 'CANCELLED' | 'STORAGE') {
    super(`Team operation failed (${code})`); this.name = 'TeamsClientError';
  }
}
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
function invalid(): never { throw new TeamsClientError('INVALID_TEAM'); }
export const encryptedTeamsPage = z.strictObject({ records: z.array(z.strictObject({ id: identifier, revision: positiveCounter,
  key_epoch: positiveCounter, encrypted_envelope: contentEnvelope, memberIds: teamMembers, signedChange: teamPayload.nullable() })).max(100),
  nextCursor: identifier.nullable(), securityHead: digest, securityVersion: positiveCounter, dataGeneration: positiveCounter });
export type EncryptedTeamsPage = z.infer<typeof encryptedTeamsPage>;
export interface TeamsPage { records: { teamId: string; revision: string; name: string; description: string; memberIds: string[] }[];
  nextCursor: string | null; securityHead: string; securityVersion: string; dataGeneration: string }
export interface TeamKeyInput { history: SecurityHistoryInput; accountId: string; deviceId: string; materials: PairingMaterial[] }
export interface PrepareTeamChangeInput extends TeamKeyInput { request: z.infer<typeof teamContextRequest>; context: TeamContext;
  name: string; description?: string; memberIds: string[] }
export interface ReadTeamsInput extends TeamKeyInput { page: EncryptedTeamsPage }
export interface ReadTeamHistoryInput extends TeamKeyInput { pages: TeamHistoryPage[] }
export interface PrepareTeamUpgradeInput extends TeamKeyInput { context:TeamContext; migrationId:string; manifestDigest:string }
export interface ReadableTeamChange {
  revision: string; operationId: string; actorId: string; deviceId: string; action: 'create' | 'update' | 'upgrade_content';
  signedAt: string | null; serverRecordedAt: string;
  before: { name: string; description: string; memberIds: string[] } | null;
  after: { name: string; description: string; memberIds: string[] };
}
export interface ReadableTeamHistory { workspaceId: string; teamId: string; anchor: TeamHistoryPage['anchor']; records: ReadableTeamChange[] }
export const TEAM_HISTORY_MAX_REVISIONS = 512;
function actor(state: SecurityHistoryState, accountId: string, deviceId: string, bundle: DeviceBundle, owner = false) {
  const p = state.profiles[accountId], d = state.devices[deviceId];
  if (!p?.active || owner && !p.owner || !d?.active || d.accountId !== accountId || d.signingPublicKey !== bundle.signingPublicKey || d.recipientPublicKey !== bundle.recipientPublicKey) invalid();
  const mode = p.owner ? 'custody' : 'content', epoch = p.owner ? state.custodyEpoch : state.workspaceKeyEpoch;
  const eligible = (s: HistoryScope) => s.scope === 'workspace' && s.scopeId === state.workspaceId && s.mode === mode && s.keyEpoch === epoch &&
    s.permissions.includes('read_project') && (s.expiresAt === null || Date.parse(s.expiresAt) > Date.now());
  const person = p.scopes.find(eligible), device = d.scopes.find(eligible);
  if (!person || !device || !device.permissions.every((permission) => person.permissions.includes(permission))) invalid();
  return { profile: p, device: d, scope: device };
}
/** Internal Worker key-ring reader; private key material never crosses the Worker RPC. */
export async function readWorkspaceKeyRing(input: TeamKeyInput, state: SecurityHistoryState, bundle: DeviceBundle) {
  const current = actor(state, input.accountId, input.deviceId, bundle), { device, scope } = current;
  const sources = scope.manifests.filter((ref) => input.materials.some((m) => m.id === ref.id && m.digest === ref.digest))
    .map((ref) => ({ grantId: device.id, generation: '1', manifestId: ref.id, manifestDigest: ref.digest }));
  if (!sources.length) throw new TeamsClientError('INCOMPLETE_KEYS');
  const wanted: PairingScope = { scope: 'workspace', scopeId: state.workspaceId, mode: 'content', keyEpoch: state.workspaceKeyEpoch,
    permissions: scope.permissions, expiresAt: scope.expiresAt, sources };
  const opened = await readDeviceScopeKeyMaterial({ history: state, materials: input.materials, scopes: [wanted], holder: {
    workspaceId: state.workspaceId, custodyEpoch: state.custodyEpoch, approverAccountId: input.accountId,
    approverDevice: { id: device.id, keyGeneration: device.keyGeneration, signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey } } }, bundle);
  return z.object({ mode: z.literal('content'), keys: z.array(z.object({ epoch: positiveCounter, key: binary(32) })) }).parse(opened[0]).keys;
}
function checkBinding(b: TeamBinding, state: SecurityHistoryState) {
  const p = state.profiles[b.authorizer.accountId], d = state.devices[b.authorizer.deviceId];
  if (b.workspaceId !== state.workspaceId || b.securityHead !== state.securityHead || b.securityVersion !== state.securityVersion ||
    b.dataGeneration !== state.dataGeneration || b.keyEpoch !== state.workspaceKeyEpoch || !p?.active || !p.owner || !d?.active || d.accountId !== p.accountId ||
    d.keyGeneration !== b.authorizer.keyGeneration || d.signingPublicKey !== b.authorizer.signingPublicKey) invalid();
  const custody = (s: HistoryScope) => s.scope === 'workspace' && s.scopeId === state.workspaceId && s.mode === 'custody' &&
    s.keyEpoch === state.custodyEpoch && s.permissions.includes('read_project') &&
    (!('version' in b) || s.expiresAt === null || Date.parse(s.expiresAt) > Date.parse(b.issuedAt));
  if (!p.scopes.some(custody) || !d.scopes.some(custody)) invalid();
}
function checkUpgradePlanner(b:TeamBinding,state:SecurityHistoryState) {
  if(!('version' in b)||b.version!==3) invalid();
  const eligible=(scope:HistoryScope)=>scope.scope==='workspace'&&scope.scopeId===state.workspaceId&&scope.mode==='custody'&&
    scope.keyEpoch===state.custodyEpoch&&scope.permissions.includes('read_project')&&scope.permissions.includes('plan_projects')&&
    (scope.expiresAt===null||Date.parse(scope.expiresAt)>Date.parse(b.issuedAt));
  if(!state.profiles[b.authorizer.accountId]?.scopes.some(eligible)||!state.devices[b.authorizer.deviceId]?.scopes.some(eligible)) invalid();
}
async function historicState(history: SecurityHistoryInput, b: TeamBinding): Promise<SecurityHistoryState> {
  if (BigInt(b.securityVersion) > BigInt(history.expected.securityVersion)) invalid();
  // The complete current chain is verified by the caller first. Replay its exact
  // prefix to prove the record's signer was an Owner at that historical head.
  const { pin: _pin, ...input } = history;
  return verifySecurityHistory({ ...input, transitions: history.transitions.slice(0, Number(BigInt(b.securityVersion) - 1n)),
    expected: { securityHead: b.securityHead, securityVersion: b.securityVersion } });
}
async function openSignedTeam(payloadValue: unknown, history: SecurityHistoryInput, ring: { epoch: string; key: string }[]) {
  const payload = await validateTeamPayload(payloadValue), b = payload.mutation.body.binding;
  const state=await historicState(history,b);checkBinding(b,state);
  if(('version' in b&&b.version===3?b.writeSchema:1)!==(state.writeSchema??1)) invalid();
  if(b.action!=='upgrade_content'&&state.activeUpgrade) invalid();
  const entry = ring.find((k) => k.epoch === b.keyEpoch); if (!entry) throw new TeamsClientError('INCOMPLETE_KEYS');
  const key = base64urlDecode(entry.key, 32);
  try {
    const raw=await decryptContent(payload.envelope,key,base64urlDecode(b.authorizer.signingPublicKey,32),teamHeader(b)),content=teamContent.parse(raw);
    if(b.action==='upgrade_content') {
      checkUpgradePlanner(b,state);
      const body=payload.mutation.body;if(body.version!==3||!body.upgrade) invalid();
      const item=payload.upgradeItems?.[0];if(!item||state.activeUpgrade?.migrationId!==body.upgrade.migrationId||
        state.activeUpgrade.manifestDigest!==body.upgrade.manifestDigest||!state.activeUpgrade.manifest.some(ref=>same(ref,item.source))) invalid();
      const h=item.sourceEnvelope.header,{pin:_pin,...source}=history;
      const prior=await verifySecurityHistory({...source,transitions:history.transitions.slice(0,Number(BigInt(h.securityVersion)-1n)),
        expected:{securityHead:h.securityHead,securityVersion:h.securityVersion}}),signer=prior.devices[h.deviceId],owner=prior.profiles[h.accountId];
      if(!owner?.active||!owner.owner||!signer?.active||signer.accountId!==h.accountId||signer.keyGeneration!==h.keyGeneration||
        h.workspaceId!==state.workspaceId||h.recordType!=='team'||h.recordId!==b.teamId||h.scope!=='workspace'||h.scopeId!==state.workspaceId) invalid();
      const old=ring.find(entry=>entry.epoch===h.keyEpoch);if(!old) throw new TeamsClientError('INCOMPLETE_KEYS');
      const oldKey=base64urlDecode(old.key,32);
      try { const source=await decryptContent(item.sourceEnvelope,oldKey,base64urlDecode(signer.signingPublicKey,32),h);teamContent.parse(source);if(!same(raw,source)) invalid(); }
      finally {oldKey.fill(0);}
    }
    return {payload,content,raw};
  }
  finally { key.fill(0); }
}
/** Private content and keys remain in the Worker; the persisted result is signed ciphertext. */
export async function prepareTeamChange(value: PrepareTeamChangeInput, bundle: DeviceBundle): Promise<TeamPayload> {
  const input = copy(value), context = teamContext.parse(input.context), request = teamContextRequest.parse(input.request), b = context.binding,
    state = await verifySecurityHistory(input.history), content = teamContent.parse({ name: input.name, description: input.description ?? '' }),
    memberIds = teamMembers.parse(input.memberIds).sort();
  actor(state, input.accountId, input.deviceId, bundle, true); checkBinding(b, state);
  if(b.action==='upgrade_content'||state.activeUpgrade||('version' in b&&b.version===3?b.writeSchema:1)!==(state.writeSchema??1)) invalid();
  if ('version' in b && (Date.parse(b.issuedAt) > Date.now() || Date.parse(b.expiresAt) <= Date.now())) invalid();
  if (b.authorizer.accountId !== input.accountId || b.authorizer.deviceId !== input.deviceId ||
    !same(request, { workspaceId: b.workspaceId, teamId: b.teamId, operationId: b.operationId, action: b.action }) ||
    memberIds.some((id) => !state.profiles[id]?.active)) invalid();
  const ring = await readWorkspaceKeyRing(input, state, bundle);
  if (b.action === 'create') { if (context.previous || context.previousSignedChange || b.expectedRevision !== '0' || b.previousDigest !== null || b.previousMemberIds.length) invalid(); }
  else {
    if (!context.previous || !context.previousSignedChange) invalid();
    const previous = await openSignedTeam(context.previousSignedChange, input.history, ring), old = previous.payload.envelope.header;
    if (old.recordId !== b.teamId || old.revision !== b.expectedRevision || await digestObject(context.previous) !== b.previousDigest ||
      !same(previous.payload.envelope, context.previous) || !same([...previous.payload.mutation.body.memberIds].sort(), [...b.previousMemberIds].sort())) invalid();
  }
  const entry = ring.find((k) => k.epoch === b.keyEpoch); if (!entry) throw new TeamsClientError('INCOMPLETE_KEYS');
  const key = base64urlDecode(entry.key, 32), signing = base64urlDecode(bundle.signingPrivateKey, 64);
  try {
    const envelope = await encryptContent(teamHeader(b), content, key, signing);
    if (!same(await decryptContent(envelope, key, base64urlDecode(bundle.signingPublicKey, 32), teamHeader(b)), content)) invalid();
    return validateTeamPayload({ envelope, mutation: await signObject(teamMutationBody(b, memberIds, await digestObject(envelope)), signing) });
  } finally { key.fill(0); signing.fill(0); }
}
/** Released schema transform only; source plaintext is never supplied by the caller. */
export async function prepareTeamUpgrade(value:PrepareTeamUpgradeInput,bundle:DeviceBundle):Promise<TeamPayload> {
  const input=copy(value),context=teamContext.parse(input.context),b=context.binding,state=await verifySecurityHistory(input.history);
  actor(state,input.accountId,input.deviceId,bundle,true);checkBinding(b,state);
  checkUpgradePlanner(b,state);
  if(!('version' in b)||b.version!==3||b.action!=='upgrade_content'||b.writeSchema!==(state.writeSchema??1)||
    b.authorizer.accountId!==input.accountId||b.authorizer.deviceId!==input.deviceId||Date.parse(b.issuedAt)>Date.now()||Date.parse(b.expiresAt)<=Date.now()||
    state.activeUpgrade?.migrationId!==input.migrationId||state.activeUpgrade.manifestDigest!==input.manifestDigest||!context.previous||!context.previousSignedChange) invalid();
  const ring=await readWorkspaceKeyRing(input,state,bundle),previous=await openSignedTeam(context.previousSignedChange,input.history,ring),h=context.previous.header;
  if(!same(previous.payload.envelope,context.previous)||h.recordId!==b.teamId||h.revision!==b.expectedRevision||
    await digestObject(context.previous)!==b.previousDigest||!same([...previous.payload.mutation.body.memberIds].sort(),[...b.previousMemberIds].sort())) invalid();
  const source:UpgradeRecordRef={kind:'team',id:b.teamId,projectId:null,revision:b.expectedRevision,contentRevision:null,envelopeRevision:h.revision,schema:1,keyEpoch:h.keyEpoch,digest:b.previousDigest!};
  if(h.schema!==1||!state.activeUpgrade.manifest.some(ref=>same(ref,source))) invalid();
  const current=ring.find(entry=>entry.epoch===b.keyEpoch);if(!current) throw new TeamsClientError('INCOMPLETE_KEYS');
  const key=base64urlDecode(current.key,32),signing=base64urlDecode(bundle.signingPrivateKey,64);
  try {
    const envelope=await encryptContent(teamHeader(b),previous.raw,key,signing),target:UpgradeRecordRef={...source,revision:envelope.header.revision,
      envelopeRevision:envelope.header.revision,schema:2,keyEpoch:b.keyEpoch,digest:await digestObject(envelope)},
      item:UpgradeItem={source,target,sourceEnvelope:context.previous,envelope},
      upgrade=upgradeProof.parse({migrationId:input.migrationId,manifestDigest:input.manifestDigest,transformId:'ukda.content-data.v2',sourceSchema:1,targetSchema:2,items:[{source,target}]}),
      payload=await validateTeamPayload({envelope,upgradeItems:[item],mutation:await signObject({...teamMutationBody(b,[...b.previousMemberIds].sort(),target.digest),upgrade},signing)});
    if(!same(await decryptContent(envelope,key,base64urlDecode(bundle.signingPublicKey,32),teamHeader(b)),previous.raw)) invalid();
    return payload;
  }finally{key.fill(0);signing.fill(0);}
}
export async function verifyTeamUpgradeTargets(value:TeamKeyInput&{context:TeamContext},bundle:DeviceBundle):Promise<UpgradeRecordRef[]> {
  const input=copy(value),context=teamContext.parse(input.context),state=await verifySecurityHistory(input.history);
  actor(state,input.accountId,input.deviceId,bundle,true);checkBinding(context.binding,state);
  checkUpgradePlanner(context.binding,state);
  if(!context.previousSignedChange||!context.previous) invalid();
  const ring=await readWorkspaceKeyRing(input,state,bundle),opened=await openSignedTeam(context.previousSignedChange,input.history,ring),h=opened.payload.envelope.header;
  if(h.schema!==2||h.recordId!==context.binding.teamId||h.revision!==context.binding.expectedRevision||
    !same(context.previous,opened.payload.envelope)||await digestObject(context.previous)!==context.binding.previousDigest) invalid();
  return [{kind:'team',id:h.recordId,projectId:null,revision:h.revision,contentRevision:null,envelopeRevision:h.revision,schema:2,keyEpoch:h.keyEpoch,digest:await digestObject(opened.payload.envelope)}];
}
export async function readTeams(value: ReadTeamsInput, bundle: DeviceBundle): Promise<TeamsPage> {
  const input = copy(value), page = encryptedTeamsPage.parse(input.page), state = await verifySecurityHistory(input.history);
  actor(state, input.accountId, input.deviceId, bundle);
  if (page.securityHead !== state.securityHead || page.securityVersion !== state.securityVersion || page.dataGeneration !== state.dataGeneration ||
    new Set(page.records.map((r) => r.id)).size !== page.records.length) invalid();
  const ring = await readWorkspaceKeyRing(input, state, bundle), records: TeamsPage['records'] = [];
  for (const row of page.records) {
    if (!row.signedChange) invalid();
    const opened = await openSignedTeam(row.signedChange, input.history, ring), header = opened.payload.envelope.header;
    if (header.recordId !== row.id || header.revision !== row.revision || header.keyEpoch !== row.key_epoch ||
      !same(opened.payload.envelope, row.encrypted_envelope) || !same([...row.memberIds].sort(), [...opened.payload.mutation.body.memberIds].sort())) invalid();
    records.push({ teamId: row.id, revision: row.revision, ...opened.content, memberIds: [...row.memberIds].sort() });
  }
  return { records, nextCursor: page.nextCursor, securityHead: state.securityHead, securityVersion: state.securityVersion, dataGeneration: state.dataGeneration };
}

/** Replay the entire bounded team chain; pagination alone is not a proof of omitted revisions. */
export async function readTeamHistory(value: ReadTeamHistoryInput, bundle: DeviceBundle): Promise<ReadableTeamHistory> {
  if (!value.pages.length || value.pages.length > TEAM_HISTORY_MAX_REVISIONS ||
    new TextEncoder().encode(canonicalJson(value.pages)).byteLength > TEAM_HISTORY_MAX_BYTES) invalid();
  const input = copy(value), pages = input.pages.map((page) => teamHistoryPage.parse(page)), first = pages[0]!,
    state = await verifySecurityHistory(input.history);
  actor(state, input.accountId, input.deviceId, bundle);
  if (BigInt(first.anchor.revision) > BigInt(TEAM_HISTORY_MAX_REVISIONS)) invalid();
  const ring = await readWorkspaceKeyRing(input, state, bundle), records: ReadableTeamChange[] = [], operations = new Set<string>();
  let previous: TeamPayload | null = null, before: ReadableTeamChange['before'] = null;
  for (const [pageIndex, page] of pages.entries()) {
    if (page.workspaceId !== state.workspaceId || page.teamId !== first.teamId || !same(page.anchor, first.anchor) ||
      page.securityHead !== state.securityHead || page.securityVersion !== state.securityVersion || page.dataGeneration !== state.dataGeneration ||
      page.complete !== (pageIndex === pages.length - 1) ||
      page.nextRevision !== (page.complete ? null : page.records.at(-1)!.payload.envelope.header.revision)) invalid();
    for (const row of page.records) {
      if (records.length >= TEAM_HISTORY_MAX_REVISIONS) invalid();
      const { payload, content } = await openSignedTeam(row.payload, input.history, ring), b = payload.mutation.body.binding;
      if (b.workspaceId !== first.workspaceId || b.teamId !== first.teamId || b.expectedRevision !== String(records.length) ||
        b.previousDigest !== (previous ? await digestObject(previous.envelope) : null) ||
        !same([...b.previousMemberIds].sort(), before?.memberIds ?? []) || operations.has(b.operationId) ||
        previous && (BigInt(b.securityVersion) < BigInt(previous.mutation.body.binding.securityVersion) ||
          BigInt(b.dataGeneration) < BigInt(previous.mutation.body.binding.dataGeneration))) invalid();
      const after = { ...content, memberIds: [...payload.mutation.body.memberIds].sort() };
      records.push({ revision: payload.envelope.header.revision, operationId: b.operationId, actorId: b.authorizer.accountId,
        deviceId: b.authorizer.deviceId, action: b.action, signedAt: 'version' in b ? b.issuedAt : null,
        serverRecordedAt: row.recordedAt, before, after });
      operations.add(b.operationId); before = after; previous = payload;
    }
  }
  if (!previous || previous.envelope.header.revision !== first.anchor.revision || await digestObject(previous.envelope) !== first.anchor.digest) invalid();
  return { workspaceId: first.workspaceId, teamId: first.teamId, anchor: first.anchor, records };
}

import { base64urlDecode, canonicalJson, decryptContent, digestObject, encryptContent, signObject } from '../shared/crypto.js';
import { collaborationAudit, collaborationBindingFromPlanning, collaborationCommand, collaborationContext, collaborationHeader,
  collaborationPayload, collaborationReason, collaborationText, assertCollaborationCurrentBinding, validateCollaborationPayload,
  verifyCollaborationEntry, assertCollaborationPin, type CollaborationAudit, type CollaborationCommand, type CollaborationContext, type CollaborationEntry,
  type CollaborationMetadata, type CollaborationPayload, type VerifiedCollaborationEntry } from '../shared/collaboration.js';
import type { PlanningContext } from '../shared/planning-api.js';
import type { SecurityHistoryInput } from '../shared/security-history.js';
import type { DeviceBundle } from './device-store.js';
import { openVerifiedPlanning, planningSecurityResolver } from './planning-crypto.js';
import type { PlanningPin } from './planning-store.js';
import { collaborationPin, type CollaborationPin } from './collaboration-store.js';
import { upgradeProof, type UpgradeItem, type UpgradeRecordRef } from '../shared/encrypted-upgrades.js';

export class CollaborationClientError extends Error {
  constructor(readonly code: 'INVALID_COLLABORATION' | 'INCOMPLETE_KEYS' | 'TRUST_REQUIRED' | 'CONFLICT' | 'EXPIRED' | 'NOT_FOUND' | 'CANCELLED' | 'STORAGE') {
    super(`Collaboration failed (${code})`); this.name = 'CollaborationClientError';
  }
}
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
function invalid(): never { throw new CollaborationClientError('INVALID_COLLABORATION'); }
interface KeyInput { history: SecurityHistoryInput; accountId: string; deviceId: string; pin?: PlanningPin }
export interface PrepareCollaborationInput extends KeyInput { context: CollaborationContext; command: CollaborationCommand; text?: string; reason?: string; entryPin?: CollaborationPin }
export interface PrepareCollaborationUpgradeInput extends KeyInput { context:CollaborationContext; migrationId:string; manifestDigest:string; entryPin?:CollaborationPin }
export interface ReadCollaborationInput extends KeyInput { context: PlanningContext; entries: CollaborationEntry[]; entryPins?: CollaborationPin[]; includeHidden?: boolean }
export interface ReadableCollaborationEntry extends CollaborationMetadata {
  text: string; moderation: { actorId: string; at: string; reason: string } | null; pin: CollaborationPin;
}
export interface ReadableCollaboration { records: ReadableCollaborationEntry[]; planningPin: PlanningPin }
type Ring = { epoch: string; key: string }[];
function pinFor(entry: CollaborationMetadata, generation: string): CollaborationPin {
  return { workspaceId: entry.workspaceId, projectId: entry.projectId, entryId: entry.entryId, kind: entry.kind, dataGeneration: generation, revision: entry.revision, head: entry.head };
}
function checkPin(value: CollaborationPin | undefined, entry: CollaborationMetadata, generation: string): void {
  if (!value) return; const prior = collaborationPin.parse(value);
  if (prior.workspaceId !== entry.workspaceId || prior.projectId !== entry.projectId || prior.entryId !== entry.entryId || prior.kind !== entry.kind || BigInt(generation) < BigInt(prior.dataGeneration)) invalid();
  if (prior.dataGeneration === generation) assertCollaborationPin(entry, prior);
}
async function decrypt(ring: Ring, envelope: VerifiedCollaborationEntry['original'], header: VerifiedCollaborationEntry['originalHeader'], signingPublicKey: string) {
  const entry = ring.find((key) => key.epoch === header.keyEpoch); if (!entry) throw new CollaborationClientError('INCOMPLETE_KEYS');
  const key = base64urlDecode(entry.key, 32);
  try { return await decryptContent(envelope, key, base64urlDecode(signingPublicKey, 32), header); } finally { key.fill(0); }
}
async function readEntry(entry: VerifiedCollaborationEntry, ring: Ring, generation: string, known?: CollaborationPin): Promise<ReadableCollaborationEntry> {
  const pin = pinFor(entry, generation); checkPin(known, entry, generation);
  const text = collaborationText.parse(await decrypt(ring, entry.original, entry.originalHeader, entry.signingPublicKey)).text;
  for(const representation of entry.representations) {
    const before=await decrypt(ring,representation.item.sourceEnvelope,representation.sourceHeader,representation.sourceSigningPublicKey),
      after=await decrypt(ring,representation.item.envelope,representation.targetHeader,representation.targetSigningPublicKey);
    collaborationText.parse(before);if(!same(before,after)||collaborationText.parse(after).text!==text) invalid();
  }
  if(collaborationText.parse(await decrypt(ring,entry.current,entry.currentHeader,entry.currentSigningPublicKey)).text!==text) invalid();
  let moderation: ReadableCollaborationEntry['moderation'] = null;
  let observedHidden=false;
  for (const record of entry.auditHeaders) {
    // openVerifiedPlanning already authenticated and decoded this original planning audit.
    if (entry.origin.kind === 'planning' && record.header.action === 'planning.change') continue;
    const audit = collaborationAudit.parse(await decrypt(ring, record.envelope, record.header, record.signingPublicKey));
    if(audit.version===2) {
      if(audit.entryId!==entry.entryId||audit.originalDigest!==entry.originalDigest||audit.beforeHidden!==observedHidden||audit.afterHidden!==observedHidden) invalid();
      continue;
    }
    const
      hidden = audit.action === 'hide_comment' || audit.action === 'hide_update';
    if (audit.entryId !== entry.entryId || audit.originalDigest !== entry.originalDigest || audit.afterHidden !== hidden ||
      audit.beforeHidden !== (hidden ? false : null) || (audit.reason === null) === hidden ||
      audit.action !== `${hidden ? 'hide' : 'post'}_${entry.kind}`) invalid();
    if (hidden) {
      if (!entry.hidden || !entry.moderatedBy || !entry.moderatedAt || moderation || audit.reason === null) invalid();
      moderation = { actorId: entry.moderatedBy, at: entry.moderatedAt, reason: audit.reason };
      observedHidden=true;
    }
  }
  if (entry.hidden !== (moderation !== null)) invalid();
  const { original: _original, originalHeader: _header, signingPublicKey: _signer, auditHeaders: _audits, origin: _origin, moderation: _moderation,
    current:_current,currentHeader:_currentHeader,currentSigningPublicKey:_currentSigner,representations:_representations,...metadata } = entry;
  return { ...metadata, text, moderation, pin };
}
/** Authenticated plaintext is returned only for presentation; callers must not persist it. */
export async function readCollaboration(value: ReadCollaborationInput, bundle: DeviceBundle): Promise<ReadableCollaboration> {
  const input = copy(value), opened = await openVerifiedPlanning(input, bundle), securityAt = planningSecurityResolver(input.history, opened.state),
    records: ReadableCollaborationEntry[] = [], seen = new Set<string>();
  for (const supplied of input.entries) {
    const verified = await verifyCollaborationEntry(supplied, opened.context, securityAt);
    if (seen.has(verified.entryId) || verified.hidden && input.includeHidden !== true) invalid(); seen.add(verified.entryId);
    records.push(await readEntry(verified, opened.ring, opened.state.dataGeneration, input.entryPins?.find((pin) => pin.entryId === verified.entryId)));
  }
  return { records, planningPin: opened.readable.pin };
}
/** Only signed ciphertext leaves the Worker during an attempted online save. */
export async function prepareCollaboration(value: PrepareCollaborationInput, bundle: DeviceBundle): Promise<CollaborationPayload> {
  const input = copy(value), context = collaborationContext.parse(input.context), b = context.binding,
    opened = await openVerifiedPlanning({ ...input, context: context.planning }, bundle), securityAt = planningSecurityResolver(input.history, opened.state),
    command = collaborationCommand.parse(input.command), prior = context.entry ? await verifyCollaborationEntry(context.entry, opened.context, securityAt) : null;
  if (!same(b, collaborationBindingFromPlanning(opened.context.binding, { entryId: b.entryId, kind: b.kind })) ||
    opened.state.licenceState !== 'active' || opened.state.entitlementState !== 'activated'||opened.state.activeUpgrade||command.action==='upgrade_content') invalid();
  await assertCollaborationCurrentBinding(b, opened.context, new Date());
  if (Date.parse(b.expiresAt) <= Date.now()) throw new CollaborationClientError('EXPIRED');
  if (prior) await readEntry(prior, opened.ring, opened.state.dataGeneration, input.entryPin);
  else if (input.entryPin) invalid();
  const post = command.action === 'post_comment' || command.action === 'post_update';
  if (post ? input.reason !== undefined || input.text === undefined : input.text !== undefined || input.reason === undefined) invalid();
  const entry = opened.ring.find((key) => key.epoch === b.keyEpoch); if (!entry) throw new CollaborationClientError('INCOMPLETE_KEYS');
  const key = base64urlDecode(entry.key, 32), signing = base64urlDecode(bundle.signingPrivateKey, 64), publicKey = base64urlDecode(bundle.signingPublicKey, 32);
  const seal = async (kind: 'comment' | 'update' | 'audit', id: string, plaintext: unknown) => {
    const header = collaborationHeader(b, kind, id), envelope = await encryptContent(header, plaintext, key, signing);
    if (!same(await decryptContent(envelope, key, publicKey, header), plaintext)) invalid(); return envelope;
  };
  try {
    const content = post ? await seal(b.kind, b.entryId, collaborationText.parse({ text: input.text })) : null,
      originalDigest = content ? await digestObject(content) : prior?.originalDigest;
    if (!originalDigest) invalid();
    const data: CollaborationAudit = collaborationAudit.parse({ version: 1, action: command.action, entryId: b.entryId, originalDigest,
      beforeHidden: post ? null : false, afterHidden: !post, reason: post ? null : collaborationReason.parse(input.reason) }),
      auditId = crypto.randomUUID(), audit = { id: auditId, envelope: await seal('audit', auditId, data) },
      mutation = await signObject({ purpose: b.version===1?'ukda.collaboration.v1' as const:'ukda.collaboration.v2' as const, binding: b, command, contentDigest: content ? originalDigest : null,
        audit: { id: audit.id, digest: await digestObject(audit.envelope) } }, signing),
      payload = collaborationPayload.parse({ mutation, content, audit });
    return (await validateCollaborationPayload(payload, b, opened.context.graph, prior)).payload;
  } finally { key.fill(0); signing.fill(0); }
}

/** Current ciphertext is transformed by the released codec; callers cannot supply replacement text. */
export async function prepareCollaborationUpgrade(value:PrepareCollaborationUpgradeInput,bundle:DeviceBundle):Promise<CollaborationPayload> {
  const input=copy(value),context=collaborationContext.parse(input.context),b=context.binding,
    opened=await openVerifiedPlanning({...input,context:context.planning},bundle),securityAt=planningSecurityResolver(input.history,opened.state);
  if(!context.entry||b.version!==2||b.writeSchema!==2||!b.isOwner||opened.state.activeUpgrade?.migrationId!==input.migrationId||
    opened.state.activeUpgrade.manifestDigest!==input.manifestDigest) invalid();
  await assertCollaborationCurrentBinding(b,opened.context,new Date());
  const prior=await verifyCollaborationEntry(context.entry,opened.context,securityAt);await readEntry(prior,opened.ring,opened.state.dataGeneration,input.entryPin);
  const raw=await decrypt(opened.ring,prior.current,prior.currentHeader,prior.currentSigningPublicKey),h=prior.currentHeader,
    source:UpgradeRecordRef={kind:b.kind,id:b.entryId,projectId:b.projectId,revision:prior.revision,contentRevision:null,envelopeRevision:h.revision,schema:1,keyEpoch:h.keyEpoch,digest:await digestObject(prior.current)};
  if(h.schema!==1||!opened.state.activeUpgrade.manifest.some(ref=>same(ref,source))) invalid();
  const entry=opened.ring.find(key=>key.epoch===b.keyEpoch);if(!entry) throw new CollaborationClientError('INCOMPLETE_KEYS');
  const key=base64urlDecode(entry.key,32),signing=base64urlDecode(bundle.signingPrivateKey,64),publicKey=base64urlDecode(bundle.signingPublicKey,32);
  try {
    const revision=String(BigInt(prior.revision)+1n),header=collaborationHeader(b,b.kind,b.entryId,revision),
      content=await encryptContent(header,raw,key,signing),
      target:UpgradeRecordRef={...source,revision,envelopeRevision:revision,schema:2,keyEpoch:b.keyEpoch,digest:await digestObject(content)},
      item:UpgradeItem={source,target,sourceEnvelope:prior.current,envelope:content},
      upgrade=upgradeProof.parse({migrationId:input.migrationId,manifestDigest:input.manifestDigest,transformId:'ukda.content-data.v2',sourceSchema:1,targetSchema:2,items:[{source,target}]}),
      auditId=crypto.randomUUID(),auditData=collaborationAudit.parse({version:2,action:'upgrade_content',entryId:b.entryId,originalDigest:prior.originalDigest,beforeHidden:prior.hidden,afterHidden:prior.hidden,reason:null}),
      audit={id:auditId,envelope:await encryptContent(collaborationHeader(b,'audit',auditId),auditData,key,signing)},
      command:CollaborationCommand={action:'upgrade_content',entryId:b.entryId,expectedRevision:prior.revision,previousHead:prior.head,originalDigest:prior.originalDigest},
      payload=collaborationPayload.parse({content,audit,upgradeItems:[item],mutation:await signObject({purpose:'ukda.collaboration.v2',binding:b,command,contentDigest:target.digest,
        audit:{id:auditId,digest:await digestObject(audit.envelope)},upgrade},signing)});
    if(!same(await decryptContent(content,key,publicKey,header),raw)||
      !same(await decryptContent(audit.envelope,key,publicKey,collaborationHeader(b,'audit',auditId)),auditData)) invalid();
    return (await validateCollaborationPayload(payload,b,opened.context.graph,prior)).payload;
  }finally{key.fill(0);signing.fill(0);}
}

export async function verifyCollaborationUpgradeTargets(value:KeyInput&{context:CollaborationContext},bundle:DeviceBundle):Promise<UpgradeRecordRef[]> {
  const input=copy(value),context=collaborationContext.parse(input.context),opened=await openVerifiedPlanning({...input,context:context.planning},bundle);
  if(!context.entry) invalid();
  const entry=await verifyCollaborationEntry(context.entry,opened.context,planningSecurityResolver(input.history,opened.state));
  await readEntry(entry,opened.ring,opened.state.dataGeneration);
  const h=entry.currentHeader;if(h.schema!==2) invalid();
  return [{kind:entry.kind,id:entry.entryId,projectId:entry.projectId,revision:entry.revision,contentRevision:null,envelopeRevision:h.revision,schema:2,keyEpoch:h.keyEpoch,digest:await digestObject(entry.current)}];
}

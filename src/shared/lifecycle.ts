import { z } from 'zod';
import { binary, contentEnvelope, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyObject } from './crypto.js';
import type { SecurityHistoryState } from './security-history.js';

export const DELETION_DELAY_MS = 168 * 60 * 60 * 1000;
export const LIVE_PURGE_DELAY_MS = 24 * 60 * 60 * 1000;
export const BACKUP_PURGE_DELAY_MS = 30 * 24 * 60 * 60 * 1000;
export const deletionReference = z.strictObject({ requestId: identifier, requestedAt: z.iso.datetime(), deleteAfter: z.iso.datetime() });
export const lifecycleAction = z.enum(['request_deletion', 'cancel_deletion', 'request_erasure']);
export const lifecycleReference = z.strictObject({ workspaceId: identifier, operationId: identifier });
export const lifecycleContextRequest = lifecycleReference.extend({ action: lifecycleAction });
export const lifecycleBinding = z.strictObject({
  version: z.literal(1), workspaceId: identifier, operationId: identifier, action: lifecycleAction, origin: z.string().url(),
  accountId: identifier, deviceId: identifier, isOwner: z.boolean(), credentialGeneration: positiveCounter,
  sessionGeneration: positiveCounter, keyGeneration: positiveCounter, signingPublicKey: binary(32),
  securityVersion: positiveCounter, nextSecurityVersion: positiveCounter, securityHead: digest, dataGeneration: positiveCounter,
  ownershipVersion: positiveCounter, custodyEpoch: positiveCounter, workspaceDigest: digest.nullable(),
  deletion: deletionReference.nullable(), issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime(),
});
export const lifecycleMutation = z.strictObject({ body: z.strictObject({ purpose: z.literal('ukda.workspace-lifecycle.v1'),
  binding: lifecycleBinding, nameConfirmed: z.boolean() }), signature: binary(64) });
export const lifecycleContext = z.strictObject({ binding: lifecycleBinding, workspace: contentEnvelope.nullable() });
export const lifecycleReceipt = z.strictObject({ version: z.literal(1), workspaceId: identifier, operationId: identifier,
  actorId: identifier, dataGeneration: positiveCounter, requestHash: digest, securityHead: digest, securityVersion: positiveCounter,
  action: lifecycleAction, deletion: deletionReference.nullable(), committedAt: z.iso.datetime(), transition: lifecycleMutation });
export const lifecycleView = z.strictObject({ state: z.enum(['absent','finishing','completed']), receipt: lifecycleReceipt.nullable() });
export const lifecycleStatusRequest = lifecycleReference.extend({ requestHash: digest, dataGeneration: positiveCounter });
export const erasureRequestView = z.strictObject({ requestId: identifier, accountId: identifier,
  state: z.enum(['requested','fulfilled']), requestedAt: z.iso.datetime(), fulfilledAt: z.iso.datetime().nullable(), needsSuccessor: z.boolean() });
export const erasureList = z.strictObject({ workspaceId: identifier, requests: z.array(erasureRequestView).max(10000) });
export const deletionFinalization = z.strictObject({ body: z.strictObject({ purpose: z.literal('ukda.workspace-deleted.v1'),
  workspaceId: identifier, operationId: identifier, previousHead: digest, securityVersion: positiveCounter,
  dataGeneration: positiveCounter, nextDataGeneration: positiveCounter, deletion: deletionReference,
  requestDigest: digest, finalizedAt: z.iso.datetime(), serviceKeyId: z.string().min(1).max(64), servicePublicKey: binary(32),
}), signature: binary(64) });
export type LifecycleBinding = z.infer<typeof lifecycleBinding>;
export type LifecycleMutation = z.infer<typeof lifecycleMutation>;
export type LifecycleContext = z.infer<typeof lifecycleContext>;
export type LifecycleReceipt = z.infer<typeof lifecycleReceipt>;
export type LifecycleView = z.infer<typeof lifecycleView>;
export type DeletionReference = z.infer<typeof deletionReference>;

export function verifyLifecycleActor(b: LifecycleBinding, state: SecurityHistoryState) {
  const person = state.profiles[b.accountId], device = state.devices[b.deviceId], at = Date.parse(b.issuedAt);
  const live = (s: { scope: string; scopeId: string; mode: string; keyEpoch: string; permissions: string[]; expiresAt: string|null }) =>
    s.scope === 'workspace' && s.scopeId === state.workspaceId && s.permissions.includes('read_project') &&
    (s.expiresAt === null || Date.parse(s.expiresAt) > at) && (!person?.owner || s.mode === 'custody' && s.keyEpoch === state.custodyEpoch);
  if (b.workspaceId !== state.workspaceId || b.origin !== state.origin || b.securityHead !== state.securityHead || b.securityVersion !== state.securityVersion ||
    b.dataGeneration !== state.dataGeneration || b.ownershipVersion !== state.ownershipVersion || b.custodyEpoch !== state.custodyEpoch ||
    BigInt(b.nextSecurityVersion) !== BigInt(b.securityVersion)+1n || !person?.active || !device?.active || device.accountId !== b.accountId ||
    person.owner !== b.isOwner || person.credentialGeneration !== b.credentialGeneration || person.sessionGeneration !== b.sessionGeneration ||
    device.keyGeneration !== b.keyGeneration || device.signingPublicKey !== b.signingPublicKey || !person.scopes.some(live) || !device.scopes.some(live) ||
    b.action !== 'request_erasure' && !person.owner || Date.parse(b.expiresAt) <= at || Date.parse(b.expiresAt)-at > 300000 ||
    canonicalJson(b.deletion) !== canonicalJson(state.deletion ?? null) || state.lifecycle === 'deleted' ||
    state.deletion && at >= Date.parse(state.deletion.deleteAfter)) throw new Error('Invalid lifecycle authority');
  if (b.action !== 'request_erasure' && b.workspaceDigest !== state.workspaceContent?.digest) throw new Error('Changed workspace confirmation');
}
export async function validateLifecycleMutation(value: unknown, state: SecurityHistoryState): Promise<LifecycleMutation> {
  const signed = lifecycleMutation.parse(value), b = signed.body.binding;
  verifyLifecycleActor(b,state);
  if (!await verifyObject(signed,base64urlDecode(b.signingPublicKey,32),signed.body.purpose) ||
    signed.body.nameConfirmed !== (b.action === 'request_deletion') ||
    b.action === 'request_deletion' && b.deletion !== null || b.action === 'cancel_deletion' && b.deletion === null) throw new Error('Invalid lifecycle request');
  return signed;
}
/** Called from the authenticated security journal; does not rewrite old history. */
export async function applyLifecycleHistory(value: unknown, state: SecurityHistoryState, trustedServiceKeys: Record<string,string>): Promise<string> {
  if ((value as {body?:{purpose?:string}})?.body?.purpose === 'ukda.workspace-deleted.v1') {
    const transition = deletionFinalization.parse(value), b = transition.body, key = trustedServiceKeys[b.serviceKeyId];
    if (!key || key !== b.servicePublicKey || b.workspaceId !== state.workspaceId || b.previousHead !== state.securityHead ||
      BigInt(b.securityVersion) !== BigInt(state.securityVersion)+1n || b.dataGeneration !== state.dataGeneration ||
      BigInt(b.nextDataGeneration) !== BigInt(state.dataGeneration)+1n || state.lifecycle !== 'pending_deletion' ||
      canonicalJson(b.deletion) !== canonicalJson(state.deletion) || b.requestDigest !== state.deletionRequestDigest ||
      Date.parse(b.finalizedAt) < Date.parse(b.deletion.deleteAfter) || !await verifyObject(transition,base64urlDecode(key,32),b.purpose)) throw new Error('Invalid deletion finalization');
    state.lifecycle = 'deleted'; state.dataGeneration = b.nextDataGeneration; state.activeUpgrade = null;
    for (const person of Object.values(state.profiles)) { person.active=false;person.state='removed';person.scopes=[]; }
    for (const device of Object.values(state.devices)) { device.active=false;device.scopes=[]; }
    for (const recovery of Object.values(state.recoveryAuthorities)) recovery.active=false;
    return b.operationId;
  }
  const transition = await validateLifecycleMutation(value,state), b = transition.body.binding;
  if (b.action === 'request_deletion') {
    state.lifecycle='pending_deletion';state.deletion={requestId:b.operationId,requestedAt:b.issuedAt,deleteAfter:new Date(Date.parse(b.issuedAt)+DELETION_DELAY_MS).toISOString()};
    state.deletionRequestDigest=await digestObject(transition);
  } else if (b.action === 'cancel_deletion') { state.lifecycle='active';state.deletion=null;delete state.deletionRequestDigest; }
  return b.operationId;
}

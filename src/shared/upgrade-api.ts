import { z } from 'zod';
import { binary, contentEnvelope, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyObject } from './crypto.js';
import { upgradeRecordRef } from './encrypted-upgrades.js';

export const UPGRADE_MAX_MANIFEST_RECORDS = 20_000;
export const UPGRADE_MAX_CONTEXT_BYTES = 24 * 1024 * 1024;
export const upgradeReference = z.strictObject({ workspaceId: identifier, migrationId: identifier, operationId: identifier });
export const upgradeContextRequest = z.strictObject({ workspaceId: identifier, operationId: identifier,
  migrationId: identifier.optional(), after: z.string().regex(/^[a-z]+:[0-9a-f-]{36}$/).optional() });
export const upgradeLifecycleBinding = upgradeReference.extend({ version: z.literal(1), origin: z.string().url(),
  accountId: identifier, deviceId: identifier, credentialGeneration: positiveCounter, sessionGeneration: positiveCounter,
  keyGeneration: positiveCounter, signingPublicKey: binary(32), securityVersion: positiveCounter, nextSecurityVersion: positiveCounter, securityHead: digest,
  dataGeneration: positiveCounter, ownershipVersion: positiveCounter, custodyEpoch: positiveCounter, workspaceKeyEpoch: positiveCounter,
  writeSchema: z.union([z.literal(1),z.literal(2)]), manifestDigest: digest, manifestCount: z.number().int().min(0).max(UPGRADE_MAX_MANIFEST_RECORDS),
  completedDigest: digest, completedCount: z.number().int().min(0).max(UPGRADE_MAX_MANIFEST_RECORDS),
  issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime() });
export type UpgradeLifecycleBinding = z.infer<typeof upgradeLifecycleBinding>;
const manifest = z.array(upgradeRecordRef).max(UPGRADE_MAX_MANIFEST_RECORDS).refine(rows =>
  rows.every((row,index) => index===0 || `${rows[index-1]!.kind}:${rows[index-1]!.id}` < `${row.kind}:${row.id}`));
export const upgradeStart = z.strictObject({ body: z.strictObject({ purpose: z.literal('ukda.encrypted-upgrade-start.v1'),
  binding: upgradeLifecycleBinding, sourceSchema: z.literal(1), targetSchema: z.literal(2), transformId: z.literal('ukda.content-data.v2'), manifest }), signature: binary(64) });
export type UpgradeStart = z.infer<typeof upgradeStart>;
export const upgradeFinish = z.strictObject({ body: z.strictObject({ purpose: z.literal('ukda.encrypted-upgrade-finish.v1'),
  binding: upgradeLifecycleBinding, sourceSchema: z.literal(1), targetSchema: z.literal(2), transformId: z.literal('ukda.content-data.v2'), targets: manifest }), signature: binary(64) });
export type UpgradeFinish = z.infer<typeof upgradeFinish>;
export const upgradeReceipt = z.strictObject({ version: z.literal(1), workspaceId: identifier, migrationId: identifier,
  operationId: identifier, actorId: identifier, dataGeneration: positiveCounter, kind: z.enum(['start','batch','finish']),
  requestHash: digest, manifestDigest: digest, completedCount: z.number().int().min(0).max(UPGRADE_MAX_MANIFEST_RECORDS), committedAt: z.iso.datetime() });
export type UpgradeReceipt = z.infer<typeof upgradeReceipt>;
export const upgradeView = z.strictObject({ state: z.enum(['absent','finishing','completed']), receipt: upgradeReceipt.nullable() });
export type UpgradeView = z.infer<typeof upgradeView>;
export const upgradeStatusRequest = upgradeReference.extend({ dataGeneration: positiveCounter, requestHash: digest });
export const upgradeBatch = z.strictObject({ workspaceId: identifier, migrationId: identifier,
  kind: z.enum(['planning','team','collaboration','identity']), payload: z.unknown() });
export type UpgradeBatch = z.infer<typeof upgradeBatch>;
export const upgradeContext = z.strictObject({ binding: upgradeLifecycleBinding,
  state: z.enum(['available','active','paused','completed','aborted']), manifest, completed: manifest,
  records: z.array(z.strictObject({ reference: upgradeRecordRef, envelope: contentEnvelope })).max(32),
  nextCursor: z.string().nullable(), start: upgradeStart.nullable(), finish: upgradeFinish.nullable() });
export type UpgradeContext = z.infer<typeof upgradeContext>;

/** Signatures bind the whole finite manifest; the trusted authority is checked by
 * the current server transaction and independently by the unlocked client. */
export async function validateUpgradeLifecycle(value: unknown, kind: 'start'|'finish') {
  const signed = kind==='start' ? upgradeStart.parse(value) : upgradeFinish.parse(value), b=signed.body.binding;
  if (!await verifyObject<typeof signed.body>(signed,base64urlDecode(b.signingPublicKey,32),signed.body.purpose) ||
    Date.parse(b.expiresAt)-Date.parse(b.issuedAt)!==600_000 || BigInt(b.nextSecurityVersion)!==BigInt(b.securityVersion)+1n) throw new Error('Invalid signed upgrade decision');
  if ('manifest' in signed.body) {
    if (b.writeSchema!==1 || b.completedCount!==0 || signed.body.manifest.some(r=>r.schema!==1) ||
      b.manifestCount!==signed.body.manifest.length || b.manifestDigest!==await digestObject(signed.body.manifest) ||
      b.completedDigest!==await digestObject([])) throw new Error('Invalid source manifest');
  } else if (signed.body.targets.some(r=>r.schema!==2) || b.completedCount!==b.manifestCount ||
    b.completedCount!==signed.body.targets.length || b.completedDigest!==await digestObject(signed.body.targets)) throw new Error('Incomplete upgrade');
  return signed;
}

export function sameUpgradeValue(left: unknown,right: unknown): boolean { return canonicalJson(left)===canonicalJson(right); }

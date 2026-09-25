import { z } from 'zod';
import { binary, contentEnvelope, contentHeader, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyContentEnvelope, verifyObject, type ContentHeader } from './crypto.js';
import { pairingPublicDevice } from './pairing.js';
import { customRolePermissions } from './permissions.js';

export const ROLE_CHANGE_TTL_MS = 600_000;
export const roleLabelReference = z.strictObject({ id: identifier, revision: positiveCounter, digest });
export const roleDefinition = z.strictObject({ id: identifier, template: z.literal('custom'), revision: positiveCounter,
  state: z.enum(['active', 'retired']), permissions: customRolePermissions, label: roleLabelReference })
  .refine((value) => value.label.revision === value.revision);
export type RoleDefinition = z.infer<typeof roleDefinition>;
export const roleReference = z.strictObject({ workspaceId: identifier, operationId: identifier });
export type RoleReference = z.infer<typeof roleReference>;
export const roleContextRequest = roleReference.extend({ action: z.enum(['create', 'update', 'retire']), roleId: identifier });
export const roleFinalize = roleReference.extend({ requestHash: digest });
export const roleBinding = roleContextRequest.extend({ version: z.literal(1), origin: z.string().max(256),
  previous: roleDefinition.nullable(), nextRevision: positiveCounter,
  authorizer: z.strictObject({ accountId: identifier, device: pairingPublicDevice, credentialGeneration: positiveCounter, sessionGeneration: positiveCounter }),
  securityVersion: positiveCounter, nextSecurityVersion: positiveCounter, securityHead: digest, dataGeneration: positiveCounter,
  ownershipVersion: positiveCounter, custodyEpoch: positiveCounter, workspaceKeyEpoch: positiveCounter, genesisFingerprint: digest,
  issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime(),
}).refine((value) => [value.securityVersion, value.nextSecurityVersion, value.nextRevision, ...(value.previous ? [value.previous.revision] : [])]
  .every((entry) => positiveCounter.safeParse(entry).success) && BigInt(value.nextSecurityVersion) === BigInt(value.securityVersion) + 1n &&
  BigInt(value.nextRevision) === BigInt(value.previous?.revision ?? '0') + 1n &&
  (value.action === 'create' ? value.previous === null : value.previous !== null && value.previous.id === value.roleId && value.previous.state === 'active') &&
  Date.parse(value.expiresAt) > Date.parse(value.issuedAt) && Date.parse(value.expiresAt) - Date.parse(value.issuedAt) <= ROLE_CHANGE_TTL_MS);
export type RoleBinding = z.infer<typeof roleBinding>;
export const roleTransition = z.strictObject({ body: z.strictObject({ version: z.literal(1), purpose: z.literal('ukda.custom-role-definition.v1'),
  binding: roleBinding, role: roleDefinition }), signature: binary(64) });
export type RoleTransition = z.infer<typeof roleTransition>;
const labelObject = z.strictObject({ id: identifier, envelope: contentEnvelope });
export const rolePayload = z.strictObject({ transition: roleTransition, label: labelObject });
export type RolePayload = z.infer<typeof rolePayload>;
export const roleReceipt = z.strictObject({ version: z.literal(1), workspaceId: identifier, operationId: identifier, roleId: identifier,
  roleRevision: positiveCounter, securityVersion: positiveCounter, securityHead: digest, requestHash: digest, committedAt: z.iso.datetime(), transition: roleTransition });
export type RoleReceipt = z.infer<typeof roleReceipt>;
export const roleContext = z.strictObject({ binding: roleBinding, labelHeader: contentHeader, previousLabel: labelObject.nullable(),
  materials: z.array(z.strictObject({ id: identifier, digest, kind: z.string().max(64), value: z.unknown() })).max(4097) });
export type RoleContext = z.infer<typeof roleContext>;
export const roleView = z.strictObject({ state: z.enum(['absent', 'staged', 'completed', 'finishing', 'expired']), requestHash: digest.nullable(), receipt: roleReceipt.nullable() });
export type RoleView = z.infer<typeof roleView>;
export const roleListRequest = z.strictObject({ workspaceId: identifier, afterRoleId: identifier.optional(), limit: z.number().int().min(1).max(100).default(50) });
export const roleList = z.strictObject({ workspaceId: identifier, roles: z.array(z.strictObject({ id: identifier,
  template: z.enum(['owner', 'manager', 'member', 'viewer', 'custom']), revision: positiveCounter, state: z.enum(['active', 'retired']),
  permissions: customRolePermissions, label: labelObject.nullable() })).max(100), nextRoleId: identifier.nullable(),
  current: z.strictObject({ securityHead: digest, securityVersion: positiveCounter }),
  materials: z.array(z.strictObject({ id: identifier, digest, kind: z.string().max(64), value: z.unknown() })).max(4097) });
export type RoleList = z.infer<typeof roleList>;
export const roleListResult = roleList;
export type RoleListResult = RoleList;
export class RoleContractError extends Error {
  constructor() { super('Invalid custom role change'); this.name = 'RoleContractError'; }
}
const same = (one: unknown, two: unknown) => canonicalJson(one) === canonicalJson(two);
function snapshot<T>(schema: z.ZodType<T>, value: unknown): T {
  try { return schema.parse(JSON.parse(canonicalJson(value))); } catch { throw new RoleContractError(); }
}
export function roleLabelHeader(value: RoleBinding): ContentHeader {
  const binding = snapshot(roleBinding, value), actor = binding.authorizer;
  return { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: binding.workspaceId,
    scope: 'workspace', scopeId: binding.workspaceId, recordId: binding.roleId, recordType: 'role', schema: 1,
    keyEpoch: binding.workspaceKeyEpoch, revision: binding.nextRevision, operationId: binding.operationId,
    accountId: actor.accountId, deviceId: actor.device.id, keyGeneration: actor.device.keyGeneration, permissionVersion: binding.nextRevision,
    securityVersion: binding.securityVersion, securityHead: binding.securityHead, dataGeneration: binding.dataGeneration,
    action: `role.${binding.action}`, approvalPolicyId: null, approvalPolicyRevision: null };
}
export async function validateRoleTransition(value: unknown, expected: RoleBinding): Promise<RoleTransition> {
  const transition = snapshot(roleTransition, value), binding = snapshot(roleBinding, expected), role = transition.body.role;
  if (!same(transition.body.binding, binding) || role.id !== binding.roleId || role.revision !== binding.nextRevision ||
    role.state !== (binding.action === 'retire' ? 'retired' : 'active') || role.label.id === binding.operationId ||
    role.label.id === binding.previous?.label.id || (binding.action === 'retire' && !same(role.permissions, binding.previous?.permissions)) ||
    !await verifyObject(transition, base64urlDecode(binding.authorizer.device.signingPublicKey, 32), 'ukda.custom-role-definition.v1')) throw new RoleContractError();
  return transition;
}
export async function validateRolePayload(value: unknown, expected: RoleBinding): Promise<{ payload: RolePayload; securityHead: string; requestHash: string }> {
  const payload = snapshot(rolePayload, value), transition = await validateRoleTransition(payload.transition, expected), binding = transition.body.binding;
  if (payload.label.id !== transition.body.role.label.id || await digestObject(payload.label.envelope) !== transition.body.role.label.digest ||
    !await verifyContentEnvelope(payload.label.envelope, base64urlDecode(binding.authorizer.device.signingPublicKey, 32), roleLabelHeader(binding))) throw new RoleContractError();
  return { payload, securityHead: await digestObject(transition), requestHash: await digestObject(payload) };
}
export async function validateRoleReceipt(value: unknown, expected: RoleBinding): Promise<RoleReceipt> {
  const receipt = snapshot(roleReceipt, value), transition = await validateRoleTransition(receipt.transition, expected);
  if (receipt.workspaceId !== expected.workspaceId || receipt.operationId !== expected.operationId || receipt.roleId !== expected.roleId ||
    receipt.roleRevision !== expected.nextRevision || receipt.securityVersion !== expected.nextSecurityVersion ||
    receipt.securityHead !== await digestObject(transition)) throw new RoleContractError();
  return receipt;
}

import { z } from 'zod';
import { contentEnvelope, digest, identifier, positiveCounter } from './contracts.js';
import { canonicalJson, digestObject } from './crypto.js';
import { scopeProvisionBinding, scopeProvisionPlan, scopeProvisionPayload, scopeProvisionTransition, createScopeProvisionBinding,
  validateScopeProvisionPayload, scopeProvisionProjectHeader, type ScopeProvisionBinding } from './scope-provision.js';
import type { SecurityHistoryState } from './security-history.js';

export const projectPrivateData = z.strictObject({ name: z.string().trim().min(1).max(240), description: z.string().max(20000).optional(),
  startDate: z.iso.date().optional(), dueDate: z.iso.date().optional(),
  // Optional for historical records; bounded by the planning task capacity.
  taskOrder: z.array(identifier).max(2000).refine(ids => new Set(ids).size === ids.length).optional(),
}).refine((v) => !v.startDate || !v.dueDate || v.startDate <= v.dueDate);
export const projectCreateReference = z.strictObject({ workspaceId: identifier, operationId: identifier });
export type ProjectCreateReference = z.infer<typeof projectCreateReference>;
export const projectCreateRequest = projectCreateReference.extend({ projectId: identifier });
export type ProjectCreateRequest = z.infer<typeof projectCreateRequest>;
export const projectCreateTransition = scopeProvisionTransition.refine((v) => !!v.body.project && v.body.binding.selected.length === 0);
export const projectCreatePayload = scopeProvisionPayload.extend({ transition: projectCreateTransition, project: z.strictObject({ id: identifier, envelope: contentEnvelope }) });
export type ProjectCreatePayload = z.infer<typeof projectCreatePayload>;
export const projectCreateContext = z.strictObject({ binding: scopeProvisionBinding, plan: scopeProvisionPlan,
  materials: z.array(z.strictObject({ id: identifier, digest, kind: z.string().max(64), value: z.unknown() })).max(16384) });
export type ProjectCreateContext = z.infer<typeof projectCreateContext>;
export const projectCreateReceipt = z.strictObject({ version: z.literal(1), workspaceId: identifier, operationId: identifier, projectId: identifier,
  securityVersion: positiveCounter, securityHead: digest, requestHash: digest, committedAt: z.iso.datetime(), transition: projectCreateTransition });
export type ProjectCreateReceipt = z.infer<typeof projectCreateReceipt>;
export const projectCreateView = z.strictObject({ state: z.enum(['absent', 'staged', 'completed', 'finishing', 'expired']), requestHash: digest.nullable(), receipt: projectCreateReceipt.nullable() });
export type ProjectCreateView = z.infer<typeof projectCreateView>;
export const projectCreateFinalize = projectCreateReference.extend({ requestHash: digest });
export const projectCreateHeader = scopeProvisionProjectHeader;
export function createProjectBinding(request: ProjectCreateRequest, state: SecurityHistoryState,
  actor: ScopeProvisionBinding['authorizer'], times: { issuedAt: string; expiresAt: string }): ScopeProvisionBinding {
  return createScopeProvisionBinding({ ...projectCreateRequest.parse(request), selected: [] }, state, actor, times);
}
export async function validateProjectCreatePayload(value: unknown, binding: ScopeProvisionBinding, state: SecurityHistoryState) {
  const payload = projectCreatePayload.parse(value);
  if (binding.selected.length) throw new Error('Project creation grants Owners only');
  const result = await validateScopeProvisionPayload(payload, binding, state);
  return { ...result, payload };
}
export async function validateProjectCreateReceiptForPayload(value: unknown, payload: ProjectCreatePayload): Promise<ProjectCreateReceipt> {
  const receipt = projectCreateReceipt.parse(value), binding = payload.transition.body.binding;
  if (receipt.workspaceId !== binding.workspaceId || receipt.operationId !== binding.operationId || receipt.projectId !== binding.projectId ||
    receipt.securityVersion !== binding.nextSecurityVersion || receipt.securityHead !== await digestObject(payload.transition) ||
    receipt.requestHash !== await digestObject(payload) || canonicalJson(receipt.transition) !== canonicalJson(payload.transition)) throw new Error('Project receipt does not match the encrypted draft');
  return receipt;
}

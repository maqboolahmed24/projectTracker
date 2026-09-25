import { z } from 'zod';
import { binary, digest, identifier, positiveCounter } from './contracts.js';

export const entitlementActions = ['revoke', 'legacy_expire', 'reinstate'] as const;
export const licenceState = z.enum(['available', 'reserved', 'activated', 'revoked', 'legacy_expired']);
export const restrictionState = z.enum(['active', 'restricted', 'revoked']);
const transitionState = z.strictObject({ entitlementState: licenceState, licenceState: restrictionState.nullable() });
export const entitlementTransitionBody = z.strictObject({
  version: z.literal(1), purpose: z.literal('ukda.entitlement-transition.v1'), action: z.enum(entitlementActions),
  operationId: identifier, licenceId: identifier, operatorId: identifier, workspaceId: identifier.nullable(),
  previousHead: digest.nullable(), securityVersion: positiveCounter.nullable(), dataGeneration: positiveCounter.nullable(),
  before: transitionState, after: transitionState, changedAt: z.iso.datetime(),
  serviceKeyId: z.string().min(1).max(64), servicePublicKey: binary(32),
}).refine((body) => body.after.entitlementState === (body.action === 'revoke' ? 'revoked' :
  body.action === 'legacy_expire' ? 'legacy_expired' : body.workspaceId ? 'activated' : 'available'))
  .refine((body) => (body.securityVersion === null) === (body.previousHead === null) &&
    (body.securityVersion === null) === (body.dataGeneration === null))
  .refine((body) => body.securityVersion === null || (body.workspaceId !== null &&
    body.after.licenceState === (body.action === 'reinstate' ? 'active' : 'restricted')));
export type EntitlementTransitionBody = z.infer<typeof entitlementTransitionBody>;

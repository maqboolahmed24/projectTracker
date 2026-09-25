import { z } from 'zod';

// Normalized identifiers and decimal strings avoid lossy JS bigint serialization.
export const identifier = z.string().uuid().refine((id) => id === id.toLowerCase());
const decimalPattern = /^(0|[1-9][0-9]{0,18})$/;
export const counter = z.string().regex(decimalPattern).refine((n) => decimalPattern.test(n) && BigInt(n) <= 9_223_372_036_854_775_807n);
export const positiveCounter = counter.refine((n) => n !== '0');
export const digest = z.string().regex(/^[a-f0-9]{64}$/);
export const recordTypes = ['workspace', 'custody', 'profile', 'role', 'team', 'project', 'phase', 'milestone', 'task', 'blocker', 'comment', 'update', 'summary', 'audit'] as const;
export const capabilities = ['read_project', 'comment', 'create_tasks', 'edit_assigned_tasks', 'manage_tasks', 'approve_tasks', 'plan_projects'] as const;

/** Canonical unpadded base64url, including zero unused tail bits. */
export function binary(minBytes: number, maxBytes = minBytes) {
  return z.string().max(Math.ceil(maxBytes * 4 / 3)).regex(/^[A-Za-z0-9_-]+$/).refine((text) => {
    if (text.length % 4 === 1) return false;
    const length = Math.floor(text.length * 3 / 4);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(text.at(-1) ?? '');
    return length >= minBytes && length <= maxBytes &&
      (text.length % 4 !== 2 || (last & 15) === 0) &&
      (text.length % 4 !== 3 || (last & 3) === 0);
  });
}

export const contentHeader = z.strictObject({
  version: z.literal(1), purpose: z.literal('ukda.content.v1'), algorithm: z.literal('XChaCha20-Poly1305'),
  workspaceId: identifier, scope: z.enum(['workspace', 'project']), scopeId: identifier,
  recordId: identifier, recordType: z.enum(recordTypes), schema: z.literal(1),
  keyEpoch: positiveCounter, revision: positiveCounter, operationId: identifier,
  accountId: identifier, deviceId: identifier, keyGeneration: positiveCounter,
  permissionVersion: positiveCounter, securityVersion: counter, securityHead: digest,
  dataGeneration: positiveCounter, action: z.string().regex(/^[a-z][a-z0-9_.]{0,63}$/),
  approvalPolicyId: identifier.nullable(), approvalPolicyRevision: positiveCounter.nullable(),
}).refine((header) => header.scope !== 'workspace' || header.scopeId === header.workspaceId)
  .refine((header) => (header.approvalPolicyId === null) === (header.approvalPolicyRevision === null));

export const contentEnvelope = z.strictObject({
  header: contentHeader,
  nonce: binary(24), ciphertext: binary(16, 512 * 1024), signature: binary(64),
});
export type ContentEnvelope = z.infer<typeof contentEnvelope>;

export const operationRequest = z.strictObject({
  operationId: identifier, expectedRevision: counter, dataGeneration: positiveCounter,
  envelope: contentEnvelope,
}).refine((request) => counter.safeParse(request.expectedRevision).success &&
  positiveCounter.safeParse(request.envelope.header.revision).success &&
  request.envelope.header.operationId === request.operationId &&
  request.envelope.header.dataGeneration === request.dataGeneration &&
  BigInt(request.envelope.header.revision) === BigInt(request.expectedRevision) + 1n);

export const pageQuery = z.strictObject({
  after: identifier.optional(), limit: z.coerce.number().int().min(1).max(100).default(50),
});

import { z } from 'zod';
import { identifier } from './contracts.js';
import { planningReceipt } from './planning-api.js';
import { collaborationReceipt } from './collaboration.js';
import { teamReceipt } from './teams.js';
import { projectCreateReceipt } from './project-create.js';
import { roleReceipt } from './roles.js';
import { accessReceipt } from './access-change.js';
import { reportingReceipt } from './reporting.js';
import { inboxReceipt } from './inbox.js';

const reference = z.strictObject({ workspaceId: identifier, operationId: identifier });
export const receiptLookupRequest = z.discriminatedUnion('kind', [
  reference.extend({ kind: z.literal('planning'), projectId: identifier }),
  reference.extend({ kind: z.literal('collaboration'), projectId: identifier }),
  reference.extend({ kind: z.literal('team') }),
  reference.extend({ kind: z.literal('project') }),
  reference.extend({ kind: z.literal('role') }),
  reference.extend({ kind: z.literal('access') }),
  reference.extend({ kind: z.literal('reporting-settings') }),
  reference.extend({ kind: z.literal('reporting-summary') }),
  reference.extend({ kind: z.literal('inbox') }),
]);
export type ReceiptLookupRequest = z.infer<typeof receiptLookupRequest>;

/** A server acknowledgement, never authority to install keys or advance trust pins.
 * Retained exact-request retries still validate their original signed request hash.
 */
export const receiptLookupResponse = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('planning'), receipt: planningReceipt.nullable() }),
  z.strictObject({ kind: z.literal('collaboration'), receipt: collaborationReceipt.nullable() }),
  z.strictObject({ kind: z.literal('team'), receipt: teamReceipt.nullable() }),
  z.strictObject({ kind: z.literal('project'), receipt: projectCreateReceipt.nullable() }),
  z.strictObject({ kind: z.literal('role'), receipt: roleReceipt.nullable() }),
  z.strictObject({ kind: z.literal('access'), receipt: accessReceipt.nullable() }),
  z.strictObject({ kind: z.literal('reporting-settings'), receipt: reportingReceipt.refine(r => r.kind === 'settings').nullable() }),
  z.strictObject({ kind: z.literal('reporting-summary'), receipt: reportingReceipt.refine(r => r.kind === 'summary').nullable() }),
  z.strictObject({ kind: z.literal('inbox'), receipt: inboxReceipt.nullable() }),
]);
export type ReceiptLookupResponse = z.infer<typeof receiptLookupResponse>;

import type { z } from 'zod';
import { AppError } from './errors.js';
import { operationRequest } from './shared/contracts.js';

/** Validation failures never echo plaintext, credentials, field values or SQL. */
export function parseInput<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
  return parsed.data;
}

export function checkWritePreconditions(input: {
  expectedRevision: string; actualRevision: string; schema: number; writeSchema: number;
  dataGeneration: string; currentGeneration: string; restricted: boolean;
}): void {
  if (input.dataGeneration !== input.currentGeneration) throw new AppError('STALE_GENERATION', 'Refresh workspace state before saving', 409);
  if (input.schema !== input.writeSchema) throw new AppError('UNSUPPORTED_SCHEMA', 'Update required', 409);
  if (input.restricted) throw new AppError('WORKSPACE_RESTRICTED', 'Workspace writes are temporarily restricted', 423);
  if (input.expectedRevision !== input.actualRevision) throw new AppError('REVISION_CONFLICT', 'The record has changed; review the current version', 409);
}

/** Structural/context validation only. The security module must additionally verify signatures/grants. */
export function parseContentOperation(value: unknown, expected: { workspaceId: string; scopeId: string; recordId: string; recordType: string }) {
  if (typeof value === 'object' && value !== null && 'envelope' in value) {
    const envelope = value.envelope;
    if (typeof envelope === 'object' && envelope !== null && 'header' in envelope) {
      const header = envelope.header;
      if (typeof header === 'object' && header !== null && 'schema' in header && header.schema !== 1) {
        throw new AppError('UNSUPPORTED_SCHEMA', 'Update required', 409);
      }
    }
  }
  const input = parseInput(operationRequest, value);
  const header = input.envelope.header;
  if (header.workspaceId !== expected.workspaceId || header.scopeId !== expected.scopeId ||
    header.recordId !== expected.recordId || header.recordType !== expected.recordType) {
    throw new AppError('INVALID_ENVELOPE_CONTEXT', 'Encrypted record context does not match the operation', 400);
  }
  return input;
}

export function mapDatabaseError(error: unknown): AppError | undefined {
  const code = typeof error === 'object' && error !== null && 'code' in error ? error.code : undefined;
  if (code === '23505') return new AppError('RECORD_CONFLICT', 'The record already exists', 409);
  if (['23503', '23514', '23502', '22P02'].includes(String(code))) return new AppError('INVALID_RELATIONSHIP', 'The record or relationship is invalid', 400);
  if (code === '42501') return new AppError('FORBIDDEN', 'This operation is not permitted', 403);
  if (['40001', '40P01'].includes(String(code))) return new AppError('RETRY_REQUIRED', 'Retry the same operation', 409);
  return undefined;
}

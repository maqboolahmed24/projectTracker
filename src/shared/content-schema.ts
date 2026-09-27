import { z } from 'zod';
import { recordTypes } from './contracts.js';

export const CONTENT_TRANSFORM_1_TO_2 = 'ukda.content-data.v2' as const;
export const contentSchemaVersion = z.union([z.literal(1), z.literal(2)]);
export type ContentSchemaVersion = z.infer<typeof contentSchemaVersion>;
export type ContentRecordType = typeof recordTypes[number];
export class ContentSchemaError extends Error {
  constructor(readonly code: 'UPDATE_REQUIRED' | 'INVALID_CONTENT_SCHEMA') {
    super(code === 'UPDATE_REQUIRED' ? 'Update required to read or write this content schema' : 'Invalid encrypted content schema');
    this.name = 'ContentSchemaError';
  }
}

/** Schema 2 changes the private representation; envelope/signature version 1 stays intact. */
export const contentDataV2 = z.strictObject({
  format: z.literal(CONTENT_TRANSFORM_1_TO_2),
  recordType: z.enum(recordTypes),
  data: z.unknown(),
}).refine(value => Object.hasOwn(value, 'data') && value.data !== undefined);

export function requireContentSchema(value: unknown): ContentSchemaVersion {
  const parsed = contentSchemaVersion.safeParse(value);
  if (!parsed.success) throw new ContentSchemaError('UPDATE_REQUIRED');
  return parsed.data;
}

/** Historical schema 1 is never normalized, defaulted, stripped or rewritten by a reader. */
export const contentSchemaRegistry = {
  1: {
    encode(_recordType: ContentRecordType, data: unknown): unknown { return data; },
    decode(_recordType: ContentRecordType, data: unknown): unknown { return data; },
  },
  2: {
    encode(recordType: ContentRecordType, data: unknown): unknown {
      return contentDataV2.parse({ format: CONTENT_TRANSFORM_1_TO_2, recordType, data });
    },
    decode(recordType: ContentRecordType, value: unknown): unknown {
      const parsed = contentDataV2.safeParse(value);
      if (!parsed.success || parsed.data.recordType !== recordType) throw new ContentSchemaError('INVALID_CONTENT_SCHEMA');
      return parsed.data.data;
    },
  },
} as const;

export function encodeContentData(schema: unknown, recordType: ContentRecordType, data: unknown): unknown {
  return contentSchemaRegistry[requireContentSchema(schema)].encode(recordType, data);
}
export function decodeContentData(schema: unknown, recordType: ContentRecordType, value: unknown): unknown {
  return contentSchemaRegistry[requireContentSchema(schema)].decode(recordType, value);
}

/**
 * The validator is reviewed application code selected by the authenticated record
 * type and provenance. Validation output is deliberately discarded: a parser's
 * defaults or transformations must not alter the original historical fields.
 */
export function transformContentData1To2(recordType: ContentRecordType, value: unknown,
  validate: (value: unknown) => unknown): z.infer<typeof contentDataV2> {
  validate(value);
  return contentDataV2.parse({ format: CONTENT_TRANSFORM_1_TO_2, recordType, data: value });
}

/** Preflight before strict native parsing gives unsupported future ciphertext an explicit update-required result. */
export function assertSupportedContentSchemas(value:unknown):void {
  const pending:unknown[]=[value],seen=new Set<object>();
  while(pending.length) {
    const item=pending.pop();if(!item||typeof item!=='object'||seen.has(item))continue;seen.add(item);
    if(!Array.isArray(item)&&'purpose' in item&&item.purpose==='ukda.content.v1'&&'schema' in item)requireContentSchema(item.schema);
    if(!Array.isArray(item)&&'writeSchema' in item)requireContentSchema(item.writeSchema);
    for(const child of Object.values(item))if(child&&typeof child==='object')pending.push(child);
  }
}

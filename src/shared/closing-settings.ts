import { z } from 'zod';
import { counter, digest, identifier } from './contracts.js';

/** Independent of reporting/planning so historical closure parsing never creates an import cycle. */
export const closingSettings = z.strictObject({ workspaceId: identifier, revision: counter, head: digest, initialDigest: digest,
  timezone: z.string().min(1).max(100).refine(value => {
    try { new Intl.DateTimeFormat('en', { timeZone: value }).format(0); return true; } catch { return false; }
  }),
});
export type ClosingSettings = z.infer<typeof closingSettings>;

import { z } from 'zod';
import { digest, identifier } from './contracts.js';

export const liveRequest = z.strictObject({ workspaceId: identifier });
/** An invalidation hint only. It cannot prove a calculation is current. */
export const liveCheckpoint = z.strictObject({ version: z.literal(1), fingerprint: digest, observedAt: z.iso.datetime() });
export type LiveCheckpoint = z.infer<typeof liveCheckpoint>;
export const LIVE_POLL_MS = 5_000;
export const LIVE_STREAM_MS = 5 * 60_000;
export const LIVE_FALLBACK_MS = 60_000;

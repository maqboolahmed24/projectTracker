import { z } from 'zod';
import { binary, counter, digest, identifier, positiveCounter } from './contracts.js';

export const authSessionResult = z.strictObject({
  sessionId: identifier, workspaceId: identifier, accountId: identifier, deviceId: identifier.nullable(),
  accessLevel: z.enum(['restricted', 'device_approved']), credentialGeneration: positiveCounter,
  sessionGeneration: positiveCounter, dataGeneration: positiveCounter, csrfToken: binary(32),
  authenticatedAt: z.iso.datetime(), idleExpiresAt: z.iso.datetime(), absoluteExpiresAt: z.iso.datetime(),
});
export type AuthSessionResult = z.infer<typeof authSessionResult>;

/** Signed by the selected approved device, never a recovery or arbitrary signing key. */
export const deviceChallenge = z.strictObject({
  version: z.literal(1), purpose: z.literal('ukda.device-challenge.v1'), origin: z.string().url(),
  workspaceId: identifier, accountId: identifier, sessionId: identifier, deviceId: identifier,
  keyGeneration: positiveCounter, credentialGeneration: positiveCounter, sessionGeneration: positiveCounter,
  dataGeneration: positiveCounter, securityVersion: positiveCounter, securityHead: digest,
  ownershipVersion: counter, custodyEpoch: counter, grantId: identifier, grantGeneration: positiveCounter,
  signingPublicKey: binary(32), recipientPublicKey: binary(32), ceremonyId: identifier, nonce: binary(32),
  issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime(),
}).refine((value) => {
  const issued = Date.parse(value.issuedAt), expires = Date.parse(value.expiresAt);
  try { return expires > issued && expires - issued <= 120_000 && new URL(value.origin).origin === value.origin; }
  catch { return false; }
});
export type DeviceChallenge = z.infer<typeof deviceChallenge>;
export const deviceProof = z.strictObject({ body: deviceChallenge, signature: binary(64) });
export type DeviceProof = z.infer<typeof deviceProof>;

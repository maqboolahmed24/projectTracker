import { z } from 'zod';
import { genesisBody } from './activation.js';
import { binary, counter, digest, identifier, positiveCounter } from './contracts.js';
import { base64urlDecode, canonicalJson, digestObject, verifyObject } from './crypto.js';

export const passwordChangeBinding = z.strictObject({
  version: z.literal(1), origin: z.string().max(256), workspaceId: identifier, accountId: identifier,
  operationId: identifier, deviceId: identifier, keyGeneration: positiveCounter,
  credentialGeneration: positiveCounter, nextCredentialGeneration: positiveCounter,
  sessionGeneration: positiveCounter, nextSessionGeneration: positiveCounter,
  dataGeneration: positiveCounter, securityVersion: positiveCounter, nextSecurityVersion: positiveCounter,
  securityHead: digest, ownershipVersion: counter, custodyEpoch: counter,
  signingPublicKey: binary(32), recipientPublicKey: binary(32), issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime(),
}).refine((value) => [value.credentialGeneration, value.nextCredentialGeneration, value.sessionGeneration,
  value.nextSessionGeneration, value.securityVersion, value.nextSecurityVersion].every((entry) => positiveCounter.safeParse(entry).success) &&
  BigInt(value.nextCredentialGeneration) === BigInt(value.credentialGeneration) + 1n &&
  BigInt(value.nextSessionGeneration) === BigInt(value.sessionGeneration) + 1n &&
  BigInt(value.nextSecurityVersion) === BigInt(value.securityVersion) + 1n &&
  Date.parse(value.expiresAt) > Date.parse(value.issuedAt) && Date.parse(value.expiresAt) - Date.parse(value.issuedAt) <= 900_000);
export type PasswordChangeBinding = z.infer<typeof passwordChangeBinding>;
export const passwordChangeBody = z.strictObject({
  version: z.literal(1), purpose: z.literal('ukda.password-change.v1'), binding: passwordChangeBinding,
  registrationRecordHash: digest, configurationHash: digest, wrapperHash: digest,
  revokeOtherDevices: z.literal(true), revokeAllSessions: z.literal(true),
});
export const passwordChangePayload = z.strictObject({
  transition: z.strictObject({ body: passwordChangeBody, signature: binary(64) }),
  registrationRecord: binary(1, 4096), configuration: genesisBody.shape.opaque,
});
export type PasswordChangePayload = z.infer<typeof passwordChangePayload>;
export const passwordChangeReceipt = z.strictObject({
  operationId: identifier, workspaceId: identifier, accountId: identifier, deviceId: identifier,
  credentialGeneration: positiveCounter, sessionGeneration: positiveCounter, keyGeneration: positiveCounter,
  dataGeneration: positiveCounter, securityVersion: positiveCounter, securityHead: digest,
  requestHash: digest, wrapperHash: digest, completedAt: z.iso.datetime(),
  transition: passwordChangePayload.shape.transition,
});
export type PasswordChangeReceipt = z.infer<typeof passwordChangeReceipt>;
export const passwordChangeResult = z.strictObject({ state: z.enum(['completed', 'finishing']), receipt: passwordChangeReceipt });
export type PasswordChangeResult = z.infer<typeof passwordChangeResult>;
export const passwordChangeStatus = z.strictObject({
  state: z.enum(['issued', 'completed', 'finishing', 'cancelled', 'expired', 'revoked']),
  binding: passwordChangeBinding, resumeExpiresAt: z.iso.datetime(), requestHash: digest.optional(),
  receipt: passwordChangeReceipt.optional(),
});
export type PasswordChangeStatus = z.infer<typeof passwordChangeStatus>;
export const passwordChangeReference = z.strictObject({ workspaceId: identifier, operationId: identifier, resumeToken: binary(32) });
export type PasswordChangeReference = z.infer<typeof passwordChangeReference>;
export const passwordChangeBegin = passwordChangeReference;
export const passwordChangeRegistration = passwordChangeReference.extend({ registrationRequest: binary(1, 4096) });
export const passwordChangeProofStart = passwordChangeReference.extend({ payload: passwordChangePayload, startLoginRequest: binary(1, 4096) });
export const passwordChangeProofFinish = passwordChangeReference.extend({ proofId: identifier, finishLoginRequest: binary(1, 4096) });
export const passwordChangeFinalize = passwordChangeReference.extend({ requestHash: digest });
export const passwordChangeRegistrationResult = z.strictObject({ registrationResponse: binary(1, 4096), configuration: genesisBody.shape.opaque });
export const passwordChangeProofResult = z.strictObject({
  proofId: identifier, expiresAt: z.iso.datetime(), loginResponse: binary(1, 4096), configuration: genesisBody.shape.opaque, requestHash: digest,
});

export async function registrationRecordHash(record: string): Promise<string> {
  return digestObject({ purpose: 'ukda.password-registration.v1', record });
}
export async function validatePasswordChangePayload(input: unknown, expected: PasswordChangeBinding,
  configuration: z.infer<typeof genesisBody.shape.opaque>): Promise<{ payload: PasswordChangePayload; requestHash: string }> {
  const payload = passwordChangePayload.parse(input);
  const body = payload.transition.body;
  if (canonicalJson(body.binding) !== canonicalJson(expected) || canonicalJson(payload.configuration) !== canonicalJson(configuration) ||
    body.registrationRecordHash !== await registrationRecordHash(payload.registrationRecord) ||
    body.configurationHash !== await digestObject(configuration) ||
    !await verifyObject(payload.transition, base64urlDecode(expected.signingPublicKey, 32), 'ukda.password-change.v1')) {
    throw new Error('Invalid password change');
  }
  return { payload, requestHash: await digestObject(payload) };
}

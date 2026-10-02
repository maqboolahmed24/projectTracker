import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import { binary, contentEnvelope, digest, identifier } from '../src/shared/contracts.js';
import { derivationContext, recipientEnvelope } from '../src/shared/crypto.js';

const vector = z.strictObject({
  format: z.literal('ukda.crypto-vector.v1'), warning: z.string(),
  signingSeed: binary(32), signingPublicKey: binary(32), contentKey: binary(32),
  content: z.strictObject({ headerCanonical: z.string(), plaintext: z.unknown(), plaintextCanonical: z.string(),
    unsignedDigest: digest, envelopeDigest: digest, envelope: contentEnvelope }),
  recipient: z.strictObject({ seed: binary(32), privateKey: binary(32), payload: z.unknown(), envelope: recipientEnvelope }),
  derivation: z.strictObject({ input: binary(32), context: derivationContext, expected: binary(32) }),
  recovery: z.strictObject({ phrase: z.string(), context: z.strictObject({ workspaceId: identifier, accountId: identifier }),
    signingPublicKey: binary(32), recipientPublicKey: binary(32) }),
});
export async function cryptoVector() {
  // Both npm's compiled Node tests and Playwright's source runner execute at the repository root.
  return vector.parse(JSON.parse(await readFile('test/fixtures/crypto-v1.json', 'utf8')));
}

import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
import sodium from 'libsodium-wrappers';
import { z } from 'zod';
import { binary } from '../../shared/contracts.js';
import { AppError } from '../../errors.js';

const settings = z.object({
  SECURITY_MASTER_KEY: binary(32),
  SECURITY_KEY_ID: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
  OPAQUE_SERVER_SETUP: z.string().min(100).max(10000).regex(/^[A-Za-z0-9_-]+$/),
  OPAQUE_SETUP_ID: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
  AUTH_SERVER_IDENTITY: z.string().min(1).max(200),
});
export type IdentityConfig = z.infer<typeof settings>;
export function loadIdentityConfig(input: NodeJS.ProcessEnv = process.env): IdentityConfig {
  const parsed = settings.safeParse(input);
  if (!parsed.success) throw new Error('Invalid identity configuration; provision persistent operational secrets');
  return parsed.data;
}

/** Operational verifiers/state only. This key never encrypts customer content or device bundles. */
export class ServiceSecrets {
  readonly keyId: string;
  readonly #key: Buffer;
  constructor(config: Pick<IdentityConfig, 'SECURITY_MASTER_KEY' | 'SECURITY_KEY_ID'>) {
    this.#key = Buffer.from(config.SECURITY_MASTER_KEY, 'base64url'); this.keyId = config.SECURITY_KEY_ID;
    if (this.#key.length !== 32 || this.#key.toString('base64url') !== config.SECURITY_MASTER_KEY) throw new Error('Invalid identity configuration');
  }
  digest(purpose: string, value: string): Buffer {
    return createHmac('sha256', this.#key).update(`ukda.service.v1\0${purpose}\0${value}`).digest();
  }
  matches(purpose: string, value: string, expected: Uint8Array): boolean {
    const actual = this.digest(purpose, value);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  }
  token(): string { return randomBytes(32).toString('base64url'); }
  async protectState(context: string, value: string): Promise<string> {
    await sodium.ready;
    const nonce = sodium.randombytes_buf(24);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(new TextEncoder().encode(value), new TextEncoder().encode(context), null, nonce, this.digest('opaque-server-state-key', this.keyId));
    return `${this.keyId}.${Buffer.from(nonce).toString('base64url')}.${Buffer.from(ciphertext).toString('base64url')}`;
  }
  async revealState(context: string, envelope: string): Promise<string> {
    await sodium.ready;
    try {
      const parts = envelope.split('.');
      if (parts.length !== 3 || parts[0] !== this.keyId) throw new Error();
      return new TextDecoder('utf-8', { fatal: true }).decode(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, Buffer.from(parts[2]!, 'base64url'), new TextEncoder().encode(context), Buffer.from(parts[1]!, 'base64url'), this.digest('opaque-server-state-key', this.keyId)));
    } catch { throw new AppError('SETUP_PROOF_INVALID', 'Restart password verification', 401); }
  }
}

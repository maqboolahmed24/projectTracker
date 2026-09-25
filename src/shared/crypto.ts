import sodium from 'libsodium-wrappers';
import { z } from 'zod';
import { binary, contentEnvelope, contentHeader, counter, digest, identifier, positiveCounter, type ContentEnvelope } from './contracts.js';
import { parseJsonStrict } from './json.js';

/** All sodium entry points await initialization; this module has no Node-only imports. */
export const ready = sodium.ready;
const utf8 = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const failure = () => new Error('Invalid cryptographic data');
const purpose = z.string().min(1).max(128).regex(/^[a-z][a-z0-9_.-]*$/);

function validString(value: string): string {
  if (/[\uD800-\uDFFF]/u.test(value)) throw failure();
  return JSON.stringify(value);
}

/** RFC 8785 JCS for JSON values. Reject lossy/non-JSON JavaScript inputs. */
export function canonicalJson(value: unknown): string {
  const ancestors = new Set<object>();
  function visit(current: unknown, depth: number): string {
    if (depth > 64) throw failure();
    if (current === null) return 'null';
    if (typeof current === 'string') return validString(current);
    if (typeof current === 'boolean') return current ? 'true' : 'false';
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) throw failure();
      return JSON.stringify(current);
    }
    if (typeof current !== 'object' || ancestors.has(current)) throw failure();
    ancestors.add(current);
    try {
      if (Array.isArray(current)) {
        // Arrays may not contain holes, accessors, symbols, or additional properties.
        if (Reflect.ownKeys(current).length !== current.length + 1) throw failure();
        const entries: string[] = [];
        for (let index = 0; index < current.length; index++) {
          const property = Object.getOwnPropertyDescriptor(current, String(index));
          if (!property || !('value' in property) || !property.enumerable) throw failure();
          entries.push(visit(property.value, depth + 1));
        }
        return `[${entries.join(',')}]`;
      }
      const prototype: unknown = Object.getPrototypeOf(current);
      if (prototype !== null && prototype !== Object.prototype) throw failure();
      const keys = Reflect.ownKeys(current);
      if (keys.some((key) => typeof key !== 'string')) throw failure();
      // Write entries directly: JSON.stringify(object) reorders integer-like keys.
      return `{${(keys as string[]).sort().map((key) => {
        const property = Object.getOwnPropertyDescriptor(current, key);
        if (!property || !('value' in property) || !property.enumerable) throw failure();
        return `${validString(key)}:${visit(property.value, depth + 1)}`;
      }).join(',')}}`;
    } finally { ancestors.delete(current); }
  }
  return visit(value, 0);
}

export function base64urlEncode(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) throw failure();
  let text = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    text += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlDecode(text: string, expectedBytes?: number): Uint8Array {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) throw failure();
  try {
    const decoded = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    if (base64urlEncode(bytes) !== text || (expectedBytes !== undefined && bytes.length !== expectedBytes)) throw failure();
    return bytes;
  } catch { throw failure(); }
}

function bytesOfLength(bytes: Uint8Array, length: number): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) throw failure();
  return new Uint8Array(bytes);
}

export async function digestObject(value: unknown): Promise<string> {
  const encoded = utf8.encode(canonicalJson(value));
  const hash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', encoded));
  return Array.from(hash, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export interface KeyPair { publicKey: Uint8Array; privateKey: Uint8Array }
export async function generateSigningKeyPair(): Promise<KeyPair> {
  await ready;
  const { publicKey, privateKey } = sodium.crypto_sign_keypair();
  return { publicKey, privateKey };
}
export async function generateRecipientKeyPair(): Promise<KeyPair> {
  await ready;
  const { publicKey, privateKey } = sodium.crypto_box_keypair();
  return { publicKey, privateKey };
}
export async function randomKey(): Promise<Uint8Array> { await ready; return sodium.randombytes_buf(32); }

export interface SignedObject<T> { body: T; signature: string }
export async function signObject<T extends { purpose: string }>(body: T, privateKey: Uint8Array): Promise<SignedObject<T>> {
  if (!purpose.safeParse(body?.purpose).success) throw failure();
  const encoded = canonicalJson(body);
  // Snapshot before an await: later mutation of the supplied object cannot change signed bytes.
  const snapshot = parseJsonStrict(encoded) as T;
  const signingKey = bytesOfLength(privateKey, 64);
  await ready;
  try {
    const signature = sodium.crypto_sign_detached(utf8.encode(encoded), signingKey);
    return { body: snapshot, signature: base64urlEncode(signature) };
  } finally { signingKey.fill(0); }
}

export async function verifyObject<T extends { purpose: string }>(signed: SignedObject<T>, publicKey: Uint8Array, expectedPurpose: string): Promise<boolean> {
  try {
    // Reject accessors and snapshot both fields together before checking the signed purpose.
    const original = canonicalJson(signed);
    const snapshot = parseJsonStrict(original) as SignedObject<T>;
    if (!purpose.safeParse(expectedPurpose).success || !snapshot || typeof snapshot !== 'object' ||
      canonicalJson(Object.keys(snapshot).sort()) !== '["body","signature"]' || snapshot.body?.purpose !== expectedPurpose) return false;
    const encoded = canonicalJson(snapshot.body);
    const signature = base64urlDecode(snapshot.signature, 64);
    const verificationKey = bytesOfLength(publicKey, 32);
    await ready;
    // Fail closed if a caller changes the object while verification is pending.
    if (canonicalJson(signed) !== original) return false;
    return sodium.crypto_sign_verify_detached(signature, utf8.encode(encoded), verificationKey);
  } catch { return false; }
}

export type ContentHeader = z.infer<typeof contentHeader>;
function parsed<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw failure();
  return result.data;
}
function sameContext(actual: unknown, expected: unknown): boolean { return canonicalJson(actual) === canonicalJson(expected); }

/** Encrypt a JSON record; retries persist/reuse this exact returned envelope. */
export async function encryptContent(header: ContentHeader, plaintext: unknown, key: Uint8Array, signingPrivateKey: Uint8Array): Promise<ContentEnvelope> {
  const context = parsed(contentHeader, header);
  const message = utf8.encode(canonicalJson(plaintext));
  // Also enforce the application parser's duplicate/prototype/Unicode policy before encryption.
  parseJsonStrict(decoder.decode(message));
  if (message.length > 512 * 1024 - 16) throw failure();
  const contentKey = bytesOfLength(key, 32), signingKey = bytesOfLength(signingPrivateKey, 64);
  await ready;
  try {
    const nonce = sodium.randombytes_buf(24);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, canonicalJson(context), null, nonce, contentKey);
    const unsigned = { header: context, nonce: base64urlEncode(nonce), ciphertext: base64urlEncode(ciphertext) };
    const signature = sodium.crypto_sign_detached(canonicalJson(unsigned), signingKey);
    return { ...unsigned, signature: base64urlEncode(signature) };
  } finally { contentKey.fill(0); signingKey.fill(0); }
}

export async function verifyContentEnvelope(envelope: unknown, signingPublicKey: Uint8Array, expectedHeader: ContentHeader): Promise<boolean> {
  try {
    const { signature, ...unsigned } = parsed(contentEnvelope, envelope);
    const expected = parsed(contentHeader, expectedHeader);
    if (!sameContext(unsigned.header, expected)) return false;
    const verificationKey = bytesOfLength(signingPublicKey, 32);
    await ready;
    return sodium.crypto_sign_verify_detached(base64urlDecode(signature, 64), canonicalJson(unsigned), verificationKey);
  } catch { return false; }
}

export async function decryptContent(envelope: ContentEnvelope, key: Uint8Array, signingPublicKey: Uint8Array, expectedHeader: ContentHeader): Promise<unknown> {
  const contentKey = bytesOfLength(key, 32);
  try {
    // Parse/copy first so caller mutation across the verification await cannot replace ciphertext.
    const accepted = parsed(contentEnvelope, envelope);
    if (!await verifyContentEnvelope(accepted, signingPublicKey, expectedHeader)) throw failure();
    const message = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, base64urlDecode(accepted.ciphertext), canonicalJson(accepted.header), base64urlDecode(accepted.nonce, 24), contentKey);
    return parseJsonStrict(decoder.decode(message));
  } catch { throw failure(); } finally { contentKey.fill(0); }
}

export const recipientHeader = z.strictObject({
  version: z.literal(1), purpose: z.literal('ukda.recipient.v1'), algorithm: z.literal('X25519-SealedBox'),
  workspaceId: identifier, scope: z.enum(['workspace', 'project']), scopeId: identifier, keyEpoch: positiveCounter,
  recipientAccountId: identifier, recipientId: identifier, recipientKind: z.enum(['device', 'recovery']),
  recipientKeyGeneration: positiveCounter, recipientPublicKey: binary(32),
  senderAccountId: identifier, senderDeviceId: identifier, senderKeyGeneration: positiveCounter,
  securityVersion: counter, securityHead: digest, ceremonyId: identifier, transcriptDigest: digest,
}).refine((header) => header.scope !== 'workspace' || header.scopeId === header.workspaceId);
export type RecipientHeader = z.infer<typeof recipientHeader>;
export const recipientEnvelope = z.strictObject({ header: recipientHeader, ciphertext: binary(48, 512 * 1024), signature: binary(64) });
export type RecipientEnvelope = z.infer<typeof recipientEnvelope>;

/** Sealed boxes need a sender signature and duplicated encrypted context; neither is optional. */
export async function sealRecipient(header: RecipientHeader, payload: unknown, signingPrivateKey: Uint8Array): Promise<RecipientEnvelope> {
  const context = parsed(recipientHeader, header);
  const message = utf8.encode(canonicalJson({ header: context, payload }));
  parseJsonStrict(decoder.decode(message));
  if (message.length > 512 * 1024 - 48) throw failure();
  const signingKey = bytesOfLength(signingPrivateKey, 64);
  await ready;
  try {
    const unsigned = { header: context, ciphertext: base64urlEncode(sodium.crypto_box_seal(message, base64urlDecode(context.recipientPublicKey, 32))) };
    return { ...unsigned, signature: base64urlEncode(sodium.crypto_sign_detached(canonicalJson(unsigned), signingKey)) };
  } finally { signingKey.fill(0); }
}

export async function verifyRecipientEnvelope(envelope: unknown, signingPublicKey: Uint8Array, expectedHeader: RecipientHeader): Promise<boolean> {
  try {
    const { signature, ...unsigned } = parsed(recipientEnvelope, envelope);
    const expected = parsed(recipientHeader, expectedHeader);
    if (!sameContext(unsigned.header, expected)) return false;
    const verificationKey = bytesOfLength(signingPublicKey, 32);
    await ready;
    return sodium.crypto_sign_verify_detached(base64urlDecode(signature, 64), canonicalJson(unsigned), verificationKey);
  } catch { return false; }
}

export async function openRecipient(envelope: RecipientEnvelope, recipientPrivateKey: Uint8Array, signingPublicKey: Uint8Array, expectedHeader: RecipientHeader): Promise<unknown> {
  const recipientKey = bytesOfLength(recipientPrivateKey, 32);
  try {
    const accepted = parsed(recipientEnvelope, envelope);
    if (!await verifyRecipientEnvelope(accepted, signingPublicKey, expectedHeader)) throw failure();
    const plaintext = sodium.crypto_box_seal_open(base64urlDecode(accepted.ciphertext), base64urlDecode(accepted.header.recipientPublicKey, 32), recipientKey);
    const inner = parsed(z.strictObject({ header: recipientHeader, payload: z.unknown() }), parseJsonStrict(decoder.decode(plaintext)));
    if (!sameContext(inner.header, accepted.header)) throw failure();
    return inner.payload;
  } catch { throw failure(); } finally { recipientKey.fill(0); }
}

export const derivationContext = z.strictObject({ version: z.literal(1), purpose, workspaceId: identifier, accountId: identifier });
export type DerivationContext = z.infer<typeof derivationContext>;
/** Public format constants must be retained with any persistent wrapping envelope. */
export const HKDF_SALT = 'ukda.hkdf.v1';
export async function deriveKey(input: Uint8Array, context: DerivationContext): Promise<Uint8Array> {
  if (!(input instanceof Uint8Array) || input.length < 32) throw failure();
  const parameters = parsed(derivationContext, context);
  const source = new Uint8Array(input);
  try {
    const material = await globalThis.crypto.subtle.importKey('raw', source, 'HKDF', false, ['deriveBits']);
    const bits = await globalThis.crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: utf8.encode(HKDF_SALT), info: utf8.encode(canonicalJson(parameters)) }, material, 256);
    return new Uint8Array(bits);
  } finally { source.fill(0); }
}

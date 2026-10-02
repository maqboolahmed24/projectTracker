import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import sodium from 'libsodium-wrappers';
import { deriveKey, randomKey, ready, type KeyPair } from '../shared/crypto.js';

export async function newOwnerPhrase(): Promise<string> {
  const entropy = await randomKey();
  try { return entropyToMnemonic(entropy, wordlist); }
  finally { entropy.fill(0); }
}

export async function recoveryKeys(phrase: string, context: { workspaceId: string; accountId: string }): Promise<{ signing: KeyPair; recipient: KeyPair }> {
  if (!validateMnemonic(phrase, wordlist)) throw new Error('Invalid recovery phrase');
  const entropy = mnemonicToEntropy(phrase, wordlist);
  if (entropy.length !== 32) { entropy.fill(0); throw new Error('A 24-word recovery phrase is required'); }
  let signingSeed: Uint8Array | undefined;
  let recipientSeed: Uint8Array | undefined;
  try {
    await ready;
    signingSeed = await deriveKey(entropy, { version: 1, purpose: 'ukda.recovery-proof.v1', workspaceId: context.workspaceId, accountId: context.accountId });
    recipientSeed = await deriveKey(entropy, { version: 1, purpose: 'ukda.recovery-recipient.v1', workspaceId: context.workspaceId, accountId: context.accountId });
    const signing = sodium.crypto_sign_seed_keypair(signingSeed);
    const recipient = sodium.crypto_box_seed_keypair(recipientSeed);
    return { signing: { publicKey: signing.publicKey, privateKey: signing.privateKey }, recipient: { publicKey: recipient.publicKey, privateKey: recipient.privateKey } };
  } finally { entropy.fill(0); signingSeed?.fill(0); recipientSeed?.fill(0); }
}

/** Zero-based word positions; the UI can display one-based labels without changing the phrase. */
export async function recoveryChallenge(): Promise<number[]> {
  await ready;
  const positions = new Set<number>();
  while (positions.size < 3) positions.add(sodium.randombytes_uniform(24));
  return [...positions].sort((left, right) => left - right);
}

export function verifyRecoveryWords(phrase: string, positions: readonly number[], answers: readonly string[]): void {
  if (!validateMnemonic(phrase, wordlist) || phrase.split(' ').length !== 24 || positions.length !== 3 ||
    new Set(positions).size !== 3 || answers.length !== positions.length ||
    positions.some((position, index) => !Number.isInteger(position) || position < 0 || position > 23 || answers[index]?.trim().toLowerCase() !== phrase.split(' ')[position])) {
    throw new Error('Recovery words do not match');
  }
}

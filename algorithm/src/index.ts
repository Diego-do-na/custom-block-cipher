/**
 * Public API of the algorithm package. This is the locked contract the demo app
 * (and anyone else) should import against — see CLAUDE.md / AGENTS.md at the repo
 * root for the project-level overview.
 */

import { BLOCK_SIZE, DEFAULT_ROUNDS, assertValidRounds } from './constants.js';
import { deriveMasterKeyBytes, deriveSubkeys } from './keySchedule.js';
import { pkcs7Pad, pkcs7Unpad } from './padding.js';
import { encryptCbc, decryptCbc, type CbcEncryptBlockTrace, type CbcDecryptBlockTrace } from './cbc.js';
import { bytesToHex, hexToBytes, textToBytes, bytesToText, randomBytes, concatBytes } from './bytes.js';

export * from './constants.js';
export * from './sbox.js';
export * from './bytes.js';
export * from './padding.js';
export * from './keySchedule.js';
export {
  encryptBlock,
  decryptBlock,
  type EncryptRoundTrace,
  type DecryptRoundTrace,
  type BlockCipherResult,
} from './blockCipher.js';
export { encryptCbc, decryptCbc, type CbcEncryptBlockTrace, type CbcDecryptBlockTrace } from './cbc.js';

export interface CipherOptions {
  /** Number of rounds per block, in [MIN_ROUNDS, MAX_ROUNDS]. Default DEFAULT_ROUNDS. */
  rounds?: number;
}

export interface EncryptResult {
  /** The random per-message IV, hex-encoded. Not secret. */
  ivHex: string;
  /** The ciphertext blocks (excluding the IV), hex-encoded. */
  ciphertextHex: string;
  /** ivHex + ciphertextHex concatenated — this is what decrypt()/decryptWithTrace() expect as input. */
  combinedHex: string;
}

export interface EncryptTrace {
  rounds: number;
  masterKeyBytes: Uint8Array;
  subkeys: Uint8Array[];
  iv: Uint8Array;
  paddedPlainBytes: Uint8Array;
  blocks: CbcEncryptBlockTrace[];
}

export interface DecryptTrace {
  rounds: number;
  masterKeyBytes: Uint8Array;
  subkeys: Uint8Array[];
  iv: Uint8Array;
  blocks: CbcDecryptBlockTrace[];
  paddedPlainBytes: Uint8Array;
}

/**
 * Encrypts UTF-8 text with a passphrase-style key. Generates a fresh random IV
 * per call (see bytes.ts randomBytes) — the same plaintext+key will therefore
 * produce different ciphertext every time, by design.
 */
export function encrypt(plaintext: string, key: string, options: CipherOptions = {}): EncryptResult {
  const { trace } = encryptWithTrace(plaintext, key, options);
  const ivHex = bytesToHex(trace.iv);
  const ciphertextHex = trace.blocks.map((b) => bytesToHex(b.cipherBlock)).join('');
  return { ivHex, ciphertextHex, combinedHex: ivHex + ciphertextHex };
}

/** Same as encrypt(), but also returns the full round-by-round / block-by-block trace for visualization. */
export function encryptWithTrace(
  plaintext: string,
  key: string,
  options: CipherOptions = {},
): { result: EncryptResult; trace: EncryptTrace } {
  const rounds = options.rounds ?? DEFAULT_ROUNDS;
  assertValidRounds(rounds);

  const masterKeyBytes = deriveMasterKeyBytes(key);
  const subkeys = deriveSubkeys(masterKeyBytes, rounds);
  const iv = randomBytes(BLOCK_SIZE);

  const paddedPlainBytes = pkcs7Pad(textToBytes(plaintext), BLOCK_SIZE);
  const plainBlocks = chunk(paddedPlainBytes, BLOCK_SIZE);

  const { cipherBlocks, trace: blocks } = encryptCbc(plainBlocks, iv, subkeys);

  const ivHex = bytesToHex(iv);
  const ciphertextHex = cipherBlocks.map(bytesToHex).join('');
  const result: EncryptResult = { ivHex, ciphertextHex, combinedHex: ivHex + ciphertextHex };

  return { result, trace: { rounds, masterKeyBytes, subkeys, iv, paddedPlainBytes, blocks } };
}

/** Decrypts hex produced by encrypt() (IV concatenated with ciphertext blocks) back to UTF-8 text. */
export function decrypt(combinedHex: string, key: string, options: CipherOptions = {}): string {
  const { plaintext } = decryptWithTrace(combinedHex, key, options);
  return plaintext;
}

/** Same as decrypt(), but also returns the full round-by-round / block-by-block trace for visualization. */
export function decryptWithTrace(
  combinedHex: string,
  key: string,
  options: CipherOptions = {},
): { plaintext: string; trace: DecryptTrace } {
  const rounds = options.rounds ?? DEFAULT_ROUNDS;
  assertValidRounds(rounds);

  const combined = hexToBytes(combinedHex);
  if (combined.length < BLOCK_SIZE || (combined.length - BLOCK_SIZE) % BLOCK_SIZE !== 0) {
    throw new Error(`Ciphertext must be an IV block plus a whole number of ${BLOCK_SIZE}-byte blocks.`);
  }

  const iv = combined.slice(0, BLOCK_SIZE);
  const cipherBlocks = chunk(combined.slice(BLOCK_SIZE), BLOCK_SIZE);

  const masterKeyBytes = deriveMasterKeyBytes(key);
  const subkeys = deriveSubkeys(masterKeyBytes, rounds);

  const { plainBlocks, trace: blocks } = decryptCbc(cipherBlocks, iv, subkeys);
  const paddedPlainBytes = concatBytes(...plainBlocks);
  const plaintext = bytesToText(pkcs7Unpad(paddedPlainBytes, BLOCK_SIZE));

  return { plaintext, trace: { rounds, masterKeyBytes, subkeys, iv, blocks, paddedPlainBytes } };
}

function chunk(bytes: Uint8Array, size: number): Uint8Array[] {
  const blocks: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += size) {
    blocks.push(bytes.slice(i, i + size));
  }
  return blocks;
}

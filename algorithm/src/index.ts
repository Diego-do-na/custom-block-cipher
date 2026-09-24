/**
 * Public API of the algorithm package. This is the locked contract the demo app
 * (and anyone else) should import against — see CLAUDE.md / AGENTS.md at the repo
 * root for the project-level overview.
 *
 * The cipher itself is implemented in C++ (cpp/) and compiled to WebAssembly
 * (wasm/generated/cipher.mjs, built by `npm run build:wasm`). This file is only the
 * binding layer: it loads the module once, then every export forwards to it with the
 * same name, synchronous signature, and result shape the original TypeScript
 * implementation had. No cipher logic lives here.
 *
 * The one thing done on this side is string <-> UTF-8 conversion (TextEncoder /
 * TextDecoder), because JS strings are UTF-16 and only JS can convert them exactly as
 * the original did; the C++ side only ever sees bytes.
 */

import createCipherModule, { type Envelope } from '../wasm/generated/cipher.mjs';
import type {
  BlockCipherResult,
  CbcDecryptBlockTrace,
  CbcEncryptBlockTrace,
  CipherOptions,
  DecryptRoundTrace,
  DecryptTrace,
  EncryptResult,
  EncryptRoundTrace,
  EncryptTrace,
} from './types.js';

export type * from './types.js';

// Loaded once when the package is first imported, so every export below can stay synchronous.
const wasm = await createCipherModule();

/** Unwraps a WASM call's result, rethrowing its error as a plain `Error` with the identical message. */
function unwrap<T>(envelope: Envelope<T>): T {
  if (!envelope.ok) throw new Error(envelope.error);
  return envelope.value;
}

/** Decodes text the C++ side already decoded (replacement chars applied, leading BOM handled) — lossless. */
const cppTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true });

// --- constants ------------------------------------------------------------------------

/** Block size in bytes. Also doubles as the master-key byte length (see keySchedule). */
export const BLOCK_SIZE: number = wasm.BLOCK_SIZE;

/** Default round count. Must be in [MIN_ROUNDS, MAX_ROUNDS]. */
export const DEFAULT_ROUNDS: number = wasm.DEFAULT_ROUNDS;

export const MIN_ROUNDS: number = wasm.MIN_ROUNDS;
export const MAX_ROUNDS: number = wasm.MAX_ROUNDS;

/** Bits rotated per round in the diffusion step. Deliberately NOT a multiple of 8 — see cpp/include/cipher/constants.hpp. */
export const ROTATE_BITS: number = wasm.ROTATE_BITS;

export function assertValidRounds(rounds: number): void {
  unwrap(wasm.assertValidRounds(rounds));
}

// --- S-box ----------------------------------------------------------------------------

/** The cipher's fixed, public S-box (confusion technique #2) — see cpp/src/sbox.cpp. */
export const SBOX: readonly number[] = Array.from(unwrap(wasm.sbox()));

/** Inverse S-box: INV_SBOX[SBOX[i]] = i. */
export const INV_SBOX: readonly number[] = Array.from(unwrap(wasm.invSbox()));

// --- byte helpers ---------------------------------------------------------------------

export function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function bytesToHex(bytes: Uint8Array): string {
  return unwrap(wasm.bytesToHex(bytes));
}

export function hexToBytes(hex: string): Uint8Array {
  return unwrap(wasm.hexToBytes(hex));
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  return unwrap(wasm.concatBytes(chunks));
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  return unwrap(wasm.xorBytes(a, b));
}

/** Circular shift of a byte array's *positions* to the left, e.g. [1,2,3] -> [2,3,1]. */
export function rotateBytesLeft(bytes: Uint8Array, by = 1): Uint8Array {
  return unwrap(wasm.rotateBytesLeft(bytes, by));
}

/** Circular shift of a byte array's *positions* to the right — the inverse of rotateBytesLeft. */
export function rotateBytesRight(bytes: Uint8Array, by = 1): Uint8Array {
  return unwrap(wasm.rotateBytesRight(bytes, by));
}

/** Circular left rotation of the whole byte array treated as one big bit string. */
export function rotateBitsLeft(bytes: Uint8Array, bitCount: number): Uint8Array {
  return unwrap(wasm.rotateBitsLeft(bytes, bitCount));
}

/** Circular right rotation of the whole byte array treated as one big bit string — the inverse of rotateBitsLeft. */
export function rotateBitsRight(bytes: Uint8Array, bitCount: number): Uint8Array {
  return unwrap(wasm.rotateBitsRight(bytes, bitCount));
}

/** Number of differing bits between two equal-length byte arrays, plus a per-byte XOR diff mask. */
export function bitDiff(a: Uint8Array, b: Uint8Array): { diffBits: number; totalBits: number; diffMask: Uint8Array } {
  return unwrap(wasm.bitDiff(a, b));
}

/** Cryptographically-irrelevant but uniformly random bytes, used for the (non-secret) IV. */
export function randomBytes(length: number): Uint8Array {
  return unwrap(wasm.randomBytes(length));
}

// --- padding --------------------------------------------------------------------------

export function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
  return unwrap(wasm.pkcs7Pad(data, blockSize));
}

/** Strips and validates PKCS#7 padding, throwing if the padding is malformed. */
export function pkcs7Unpad(data: Uint8Array, blockSize: number): Uint8Array {
  return unwrap(wasm.pkcs7Unpad(data, blockSize));
}

// --- key schedule ---------------------------------------------------------------------

/** Derives a fixed-size (BLOCK_SIZE) master key from an arbitrary-length key string. */
export function deriveMasterKeyBytes(key: string): Uint8Array {
  return unwrap(wasm.deriveMasterKeyBytes(textToBytes(key)));
}

/** subkey[i] = rotate_left_bits(masterKey, 3 * (i + 1)) XOR roundConstant(i). */
export function deriveSubkeys(masterKeyBytes: Uint8Array, rounds: number): Uint8Array[] {
  return unwrap(wasm.deriveSubkeys(masterKeyBytes, rounds));
}

// --- block cipher + CBC ---------------------------------------------------------------

/** Encrypts a single BLOCK_SIZE block: per round, XOR subkey -> S-box -> rotate bits. */
export function encryptBlock(block: Uint8Array, subkeys: readonly Uint8Array[]): BlockCipherResult<EncryptRoundTrace> {
  return unwrap(wasm.encryptBlock(block, subkeys));
}

/** Decrypts a single BLOCK_SIZE block, inverting each round in reverse order. */
export function decryptBlock(block: Uint8Array, subkeys: readonly Uint8Array[]): BlockCipherResult<DecryptRoundTrace> {
  return unwrap(wasm.decryptBlock(block, subkeys));
}

/** CBC-mode encryption over already-padded plaintext blocks (diffusion #2). */
export function encryptCbc(
  plainBlocks: readonly Uint8Array[],
  iv: Uint8Array,
  subkeys: readonly Uint8Array[],
): { cipherBlocks: Uint8Array[]; trace: CbcEncryptBlockTrace[] } {
  return unwrap(wasm.encryptCbc(plainBlocks, iv, subkeys));
}

/** CBC-mode decryption: decrypt the block first, then undo the chaining XOR. */
export function decryptCbc(
  cipherBlocks: readonly Uint8Array[],
  iv: Uint8Array,
  subkeys: readonly Uint8Array[],
): { plainBlocks: Uint8Array[]; trace: CbcDecryptBlockTrace[] } {
  return unwrap(wasm.decryptCbc(cipherBlocks, iv, subkeys));
}

// --- high-level API -------------------------------------------------------------------

/**
 * Encrypts UTF-8 text with a passphrase-style key. Generates a fresh random IV per
 * call — the same plaintext+key will therefore produce different ciphertext every
 * time, by design.
 */
export function encrypt(plaintext: string, key: string, options: CipherOptions = {}): EncryptResult {
  return unwrap(wasm.encrypt(textToBytes(plaintext), textToBytes(key), options.rounds));
}

/** Same as encrypt(), but also returns the full round-by-round / block-by-block trace for visualization. */
export function encryptWithTrace(
  plaintext: string,
  key: string,
  options: CipherOptions = {},
): { result: EncryptResult; trace: EncryptTrace } {
  return unwrap(wasm.encryptWithTrace(textToBytes(plaintext), textToBytes(key), options.rounds));
}

/** Decrypts hex produced by encrypt() (IV concatenated with ciphertext blocks) back to UTF-8 text. */
export function decrypt(combinedHex: string, key: string, options: CipherOptions = {}): string {
  return cppTextDecoder.decode(unwrap(wasm.decrypt(combinedHex, textToBytes(key), options.rounds)));
}

/** Same as decrypt(), but also returns the full round-by-round / block-by-block trace for visualization. */
export function decryptWithTrace(
  combinedHex: string,
  key: string,
  options: CipherOptions = {},
): { plaintext: string; trace: DecryptTrace } {
  const { plaintextUtf8, trace } = unwrap(wasm.decryptWithTrace(combinedHex, textToBytes(key), options.rounds));
  return { plaintext: cppTextDecoder.decode(plaintextUtf8), trace };
}

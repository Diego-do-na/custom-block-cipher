// Hand-written types for cipher.mjs, the Emscripten build of cpp/ (`make -C cpp wasm`).
// This file is committed; cipher.mjs itself is generated and gitignored.
//
// Every function returns an envelope instead of throwing — see cpp/wasm/bindings.cpp.
// Plaintext and key cross the boundary as UTF-8 bytes, not JS strings.

import type {
  BlockCipherResult,
  CbcDecryptBlockTrace,
  CbcEncryptBlockTrace,
  DecryptRoundTrace,
  DecryptTrace,
  EncryptResult,
  EncryptRoundTrace,
  EncryptTrace,
} from '../../src/types.js';

export type Envelope<T> = { ok: true; value: T } | { ok: false; error: string };

type Bytes = Uint8Array | readonly number[];

export interface CipherWasmModule {
  readonly BLOCK_SIZE: number;
  readonly DEFAULT_ROUNDS: number;
  readonly MIN_ROUNDS: number;
  readonly MAX_ROUNDS: number;
  readonly ROTATE_BITS: number;

  sbox(): Envelope<Uint8Array>;
  invSbox(): Envelope<Uint8Array>;
  assertValidRounds(rounds: number): Envelope<undefined>;

  bytesToHex(bytes: Bytes): Envelope<string>;
  hexToBytes(hex: string): Envelope<Uint8Array>;
  concatBytes(chunks: readonly Bytes[]): Envelope<Uint8Array>;
  xorBytes(a: Bytes, b: Bytes): Envelope<Uint8Array>;
  rotateBytesLeft(bytes: Bytes, by: number): Envelope<Uint8Array>;
  rotateBytesRight(bytes: Bytes, by: number): Envelope<Uint8Array>;
  rotateBitsLeft(bytes: Bytes, bitCount: number): Envelope<Uint8Array>;
  rotateBitsRight(bytes: Bytes, bitCount: number): Envelope<Uint8Array>;
  bitDiff(a: Bytes, b: Bytes): Envelope<{ diffBits: number; totalBits: number; diffMask: Uint8Array }>;
  randomBytes(length: number): Envelope<Uint8Array>;

  pkcs7Pad(data: Bytes, blockSize: number): Envelope<Uint8Array>;
  pkcs7Unpad(data: Bytes, blockSize: number): Envelope<Uint8Array>;

  deriveMasterKeyBytes(keyUtf8: Uint8Array): Envelope<Uint8Array>;
  deriveSubkeys(masterKeyBytes: Bytes, rounds: number): Envelope<Uint8Array[]>;

  encryptBlock(block: Bytes, subkeys: readonly Bytes[]): Envelope<BlockCipherResult<EncryptRoundTrace>>;
  decryptBlock(block: Bytes, subkeys: readonly Bytes[]): Envelope<BlockCipherResult<DecryptRoundTrace>>;
  encryptCbc(
    plainBlocks: readonly Bytes[],
    iv: Bytes,
    subkeys: readonly Bytes[],
  ): Envelope<{ cipherBlocks: Uint8Array[]; trace: CbcEncryptBlockTrace[] }>;
  decryptCbc(
    cipherBlocks: readonly Bytes[],
    iv: Bytes,
    subkeys: readonly Bytes[],
  ): Envelope<{ plainBlocks: Uint8Array[]; trace: CbcDecryptBlockTrace[] }>;

  encrypt(plaintextUtf8: Uint8Array, keyUtf8: Uint8Array, rounds: number | undefined): Envelope<EncryptResult>;
  encryptWithTrace(
    plaintextUtf8: Uint8Array,
    keyUtf8: Uint8Array,
    rounds: number | undefined,
  ): Envelope<{ result: EncryptResult; trace: EncryptTrace }>;
  decrypt(combinedHex: string, keyUtf8: Uint8Array, rounds: number | undefined): Envelope<Uint8Array>;
  decryptWithTrace(
    combinedHex: string,
    keyUtf8: Uint8Array,
    rounds: number | undefined,
  ): Envelope<{ plaintextUtf8: Uint8Array; trace: DecryptTrace }>;
}

declare function createCipherModule(): Promise<CipherWasmModule>;
export default createCipherModule;

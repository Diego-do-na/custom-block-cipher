/**
 * Shapes of everything the cipher returns — field-for-field the same as the C++ structs
 * in cpp/include/cipher/*.hpp, which cpp/wasm/bindings.cpp converts into these objects.
 * The traces exist purely to let the demo visualize internal state without recomputing
 * anything: they mirror the real encrypt/decrypt code paths, they don't replace them.
 */

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

/** One round's state after each sub-step, in encryption order (XOR -> S-box -> rotate). */
export interface EncryptRoundTrace {
  round: number;
  subkey: Uint8Array;
  input: Uint8Array;
  afterXor: Uint8Array;
  afterSub: Uint8Array;
  afterRotate: Uint8Array;
}

/** One round's state after each sub-step, in decryption order (unrotate -> inverse S-box -> XOR). */
export interface DecryptRoundTrace {
  round: number;
  subkey: Uint8Array;
  input: Uint8Array;
  afterUnrotate: Uint8Array;
  afterInvSub: Uint8Array;
  afterXor: Uint8Array;
}

export interface BlockCipherResult<Trace> {
  output: Uint8Array;
  trace: Trace[];
}

/** Per-block trace for CBC encryption — enough to visualize the inter-block chaining (diffusion #2). */
export interface CbcEncryptBlockTrace {
  index: number;
  plainBlock: Uint8Array;
  previous: Uint8Array; // IV for block 0, else the previous ciphertext block
  inputBlock: Uint8Array; // plainBlock XOR previous, fed into the block cipher rounds
  rounds: EncryptRoundTrace[];
  cipherBlock: Uint8Array;
}

export interface CbcDecryptBlockTrace {
  index: number;
  cipherBlock: Uint8Array;
  previous: Uint8Array; // IV for block 0, else the previous ciphertext block
  rounds: DecryptRoundTrace[];
  decryptedBlock: Uint8Array; // DecryptBlock(cipherBlock), before the chaining XOR
  plainBlock: Uint8Array; // decryptedBlock XOR previous
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

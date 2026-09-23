import { rotateBitsLeft, rotateBitsRight, xorBytes } from './bytes.js';
import { SBOX, INV_SBOX } from './sbox.js';
import { BLOCK_SIZE, ROTATE_BITS } from './constants.js';

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

/**
 * Encrypts a single BLOCK_SIZE block. Each round, in order:
 *   1. XOR with the round subkey (confusion #1)
 *   2. Substitute every byte through the S-box (confusion #2)
 *   3. Rotate the block's bits left by ROTATE_BITS (diffusion #1)
 *
 * `subkeys[i]` is used for round `i`; `subkeys.length` determines the round count.
 */
export function encryptBlock(block: Uint8Array, subkeys: readonly Uint8Array[]): BlockCipherResult<EncryptRoundTrace> {
  assertBlockSize(block);
  let state = block;
  const trace: EncryptRoundTrace[] = [];

  for (let round = 0; round < subkeys.length; round++) {
    const subkey = subkeys[round];
    const input = state;
    const afterXor = xorBytes(input, subkey);
    const afterSub = substitute(afterXor, SBOX);
    const afterRotate = rotateBitsLeft(afterSub, ROTATE_BITS);

    trace.push({ round, subkey, input, afterXor, afterSub, afterRotate });
    state = afterRotate;
  }

  return { output: state, trace };
}

/**
 * Decrypts a single BLOCK_SIZE block: reverses the rounds in reverse order, and
 * inverts each step (undo rotate, undo substitution via INV_SBOX, undo XOR).
 */
export function decryptBlock(block: Uint8Array, subkeys: readonly Uint8Array[]): BlockCipherResult<DecryptRoundTrace> {
  assertBlockSize(block);
  let state = block;
  const trace: DecryptRoundTrace[] = [];

  for (let round = subkeys.length - 1; round >= 0; round--) {
    const subkey = subkeys[round];
    const input = state;
    const afterUnrotate = rotateBitsRight(input, ROTATE_BITS);
    const afterInvSub = substitute(afterUnrotate, INV_SBOX);
    const afterXor = xorBytes(afterInvSub, subkey);

    trace.push({ round, subkey, input, afterUnrotate, afterInvSub, afterXor });
    state = afterXor;
  }

  return { output: state, trace };
}

function substitute(block: Uint8Array, table: readonly number[]): Uint8Array {
  const out = new Uint8Array(block.length);
  for (let i = 0; i < block.length; i++) {
    out[i] = table[block[i]];
  }
  return out;
}

function assertBlockSize(block: Uint8Array): void {
  if (block.length !== BLOCK_SIZE) {
    throw new Error(`Block must be exactly ${BLOCK_SIZE} bytes, got ${block.length}`);
  }
}

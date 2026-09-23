import { xorBytes } from './bytes.js';
import { encryptBlock, decryptBlock, type EncryptRoundTrace, type DecryptRoundTrace } from './blockCipher.js';

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

/**
 * CBC-mode encryption over already-padded plaintext blocks (diffusion #2: a change
 * in block i cascades into every block after it, across the whole message).
 */
export function encryptCbc(
  plainBlocks: readonly Uint8Array[],
  iv: Uint8Array,
  subkeys: readonly Uint8Array[],
): { cipherBlocks: Uint8Array[]; trace: CbcEncryptBlockTrace[] } {
  const cipherBlocks: Uint8Array[] = [];
  const trace: CbcEncryptBlockTrace[] = [];
  let previous = iv;

  for (let index = 0; index < plainBlocks.length; index++) {
    const plainBlock = plainBlocks[index];
    const inputBlock = xorBytes(plainBlock, previous);
    const { output: cipherBlock, trace: rounds } = encryptBlock(inputBlock, subkeys);

    trace.push({ index, plainBlock, previous, inputBlock, rounds, cipherBlock });
    cipherBlocks.push(cipherBlock);
    previous = cipherBlock;
  }

  return { cipherBlocks, trace };
}

/** CBC-mode decryption: decrypt the block first, then undo the chaining XOR. */
export function decryptCbc(
  cipherBlocks: readonly Uint8Array[],
  iv: Uint8Array,
  subkeys: readonly Uint8Array[],
): { plainBlocks: Uint8Array[]; trace: CbcDecryptBlockTrace[] } {
  const plainBlocks: Uint8Array[] = [];
  const trace: CbcDecryptBlockTrace[] = [];
  let previous = iv;

  for (let index = 0; index < cipherBlocks.length; index++) {
    const cipherBlock = cipherBlocks[index];
    const { output: decryptedBlock, trace: rounds } = decryptBlock(cipherBlock, subkeys);
    const plainBlock = xorBytes(decryptedBlock, previous);

    trace.push({ index, cipherBlock, previous, rounds, decryptedBlock, plainBlock });
    plainBlocks.push(plainBlock);
    previous = cipherBlock;
  }

  return { plainBlocks, trace };
}

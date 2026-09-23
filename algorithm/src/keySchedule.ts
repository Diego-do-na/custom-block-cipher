import { rotateBitsLeft, textToBytes } from './bytes.js';
import { BLOCK_SIZE } from './constants.js';

/**
 * Derives a fixed-size (BLOCK_SIZE) master key from an arbitrary-length key string.
 *
 * Not a cryptographic hash — just deterministic byte folding, which is all this
 * educational cipher needs: shorter keys are cycled to fill the block, longer keys
 * are XOR-folded down. Same key string always yields the same bytes.
 */
export function deriveMasterKeyBytes(key: string): Uint8Array {
  const raw = textToBytes(key);
  if (raw.length === 0) {
    throw new Error('Key must not be empty.');
  }
  const out = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < raw.length; i++) {
    out[i % BLOCK_SIZE] ^= raw[i];
  }
  return out;
}

/**
 * Key schedule: each round's subkey is a transformation of the ENTIRE master key,
 * never a fragment/substring of it.
 *
 *   subkey[i] = rotate_left_bits(masterKey, 3 * (i + 1)) XOR roundConstant(i)
 *
 * The rotation amount grows with the round index (not just the XOR constant) so
 * that each round's subkey is visibly distinct from every other round's, including
 * round 0. This doesn't need to be cryptographically strong (and isn't) — it only
 * needs to be deterministic and round-distinct.
 */
export function deriveSubkeys(masterKeyBytes: Uint8Array, rounds: number): Uint8Array[] {
  const subkeys: Uint8Array[] = [];
  for (let round = 0; round < rounds; round++) {
    const rotated = rotateBitsLeft(masterKeyBytes, 3 * (round + 1));
    const constant = roundConstant(round);
    const subkey = new Uint8Array(rotated.length);
    for (let i = 0; i < rotated.length; i++) {
      subkey[i] = rotated[i] ^ constant;
    }
    subkeys.push(subkey);
  }
  return subkeys;
}

/** A simple, distinct-per-round byte broadcast into the XOR step of the key schedule. */
function roundConstant(round: number): number {
  return (round + 1) & 0xff;
}

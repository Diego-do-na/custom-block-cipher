/** Block size in bytes. Also doubles as the master-key byte length (see keySchedule.ts). */
export const BLOCK_SIZE = 8;

/** Default round count. Must be in [MIN_ROUNDS, MAX_ROUNDS]. */
export const DEFAULT_ROUNDS = 6;

export const MIN_ROUNDS = 4;
export const MAX_ROUNDS = 6;

/**
 * Bits rotated per round in the diffusion step (see blockCipher.ts). Deliberately
 * NOT a multiple of 8: a whole-byte rotation (e.g. 8 bits) only *relocates* a byte,
 * it never combines byte values — since XOR and the S-box both act independently
 * per byte position, a difference confined to one byte would then stay confined to
 * one byte forever, no matter how many rounds run (see SECURITY.md for the full
 * writeup). Rotating by a non-byte-aligned amount instead spills each byte's bits
 * into its neighbor, so the S-box in the next round mixes originally-separate bytes
 * together — which is what lets a single-bit change cascade into the rest of the
 * block over a few rounds.
 */
export const ROTATE_BITS = 3;

export function assertValidRounds(rounds: number): void {
  if (!Number.isInteger(rounds) || rounds < MIN_ROUNDS || rounds > MAX_ROUNDS) {
    throw new Error(`rounds must be an integer between ${MIN_ROUNDS} and ${MAX_ROUNDS}, got ${rounds}`);
  }
}

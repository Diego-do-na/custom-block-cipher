#pragma once

#include <string>

namespace cipher {

/** Block size in bytes. Also doubles as the master-key byte length (see key_schedule.hpp). */
inline constexpr int BLOCK_SIZE = 8;

/** Default round count. Must be in [MIN_ROUNDS, MAX_ROUNDS]. */
inline constexpr int DEFAULT_ROUNDS = 6;

inline constexpr int MIN_ROUNDS = 4;
inline constexpr int MAX_ROUNDS = 6;

/**
 * Bits rotated per round in the diffusion step (see block_cipher.cpp). Deliberately
 * NOT a multiple of 8: a whole-byte rotation (e.g. 8 bits) only *relocates* a byte,
 * it never combines byte values — since XOR and the S-box both act independently per
 * byte position, a difference confined to one byte would then stay confined to one
 * byte forever, no matter how many rounds run (see SECURITY.md for the full writeup).
 * Rotating by a non-byte-aligned amount instead spills each byte's bits into its
 * neighbor, so the S-box in the next round mixes originally-separate bytes together —
 * which is what lets a single-bit change cascade into the rest of the block over a
 * few rounds.
 */
inline constexpr int ROTATE_BITS = 3;

/**
 * Throws unless `rounds` is an integer in [MIN_ROUNDS, MAX_ROUNDS]. Takes a double
 * because round counts arrive from JavaScript as plain numbers (see wasm/bindings.cpp),
 * and "integer" is checked with JS's Number.isInteger semantics.
 */
void assertValidRounds(double rounds);

/** The error message assertValidRounds throws, given the rejected value already formatted as JS would. */
std::string invalidRoundsMessage(const std::string& roundsAsJsString);

}  // namespace cipher

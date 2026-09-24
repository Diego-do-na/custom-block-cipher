#pragma once

#include <array>
#include <cstdint>

namespace cipher {

/**
 * The cipher's S-box: a fixed, non-secret substitution table (confusion technique #2).
 *
 * This is a random permutation of 0..255, generated once with a seeded shuffle
 * (see scripts/generate-sbox.mjs) and hardcoded in sbox.cpp as a constant — the same
 * way AES hardcodes its S-box, except AES's table is mathematically constructed for
 * resistance to differential/linear cryptanalysis, while this one is just a random
 * permutation. That's an intentional, documented limitation of this educational
 * cipher (see SECURITY.md): it gets non-linearity, but not proven cryptanalytic
 * resistance.
 *
 * Per Kerckhoffs's principle, the S-box is public — the same table is used for every
 * encryption, and security must rest on the secrecy of the key alone.
 */
extern const std::array<std::uint8_t, 256> SBOX;

/** Inverse S-box, derived once at program start: INV_SBOX[SBOX[i]] = i. */
extern const std::array<std::uint8_t, 256> INV_SBOX;

}  // namespace cipher

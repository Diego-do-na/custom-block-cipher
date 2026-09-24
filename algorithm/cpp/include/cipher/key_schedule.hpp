#pragma once

#include <string_view>
#include <vector>

#include "cipher/bytes.hpp"

namespace cipher {

/**
 * Derives a fixed-size (BLOCK_SIZE) master key from an arbitrary-length UTF-8 key string.
 *
 * Not a cryptographic hash — just deterministic byte folding, which is all this
 * educational cipher needs: shorter keys are cycled to fill the block, longer keys
 * are XOR-folded down. Same key string always yields the same bytes.
 */
Bytes deriveMasterKeyBytes(std::string_view key);

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
std::vector<Bytes> deriveSubkeys(const Bytes& masterKeyBytes, double rounds);

}  // namespace cipher

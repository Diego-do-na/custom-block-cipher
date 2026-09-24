#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

/** Byte-array helpers shared across the cipher and the demo's visualizers. */
namespace cipher {

using Bytes = std::vector<std::uint8_t>;

/**
 * UTF-8 text -> bytes, with the same result as JS's TextEncoder.encode on the string
 * the text represents: valid UTF-8 passes through unchanged, and any invalid sequence
 * becomes U+FFFD (which is what JS would already have done when decoding it into a
 * string in the first place).
 */
Bytes textToBytes(std::string_view text);

/**
 * Bytes -> UTF-8 text, with the same result as JS's `new TextDecoder().decode(bytes)`:
 * invalid sequences become U+FFFD and a single leading byte-order mark is dropped.
 */
std::string bytesToText(const Bytes& bytes);

std::string bytesToHex(const Bytes& bytes);

Bytes hexToBytes(std::string_view hex);

Bytes concatBytes(const std::vector<Bytes>& chunks);

Bytes xorBytes(const Bytes& a, const Bytes& b);

/**
 * Circular shift of a byte array's *positions* to the left, e.g. [1,2,3] -> [2,3,1].
 * Shift counts are JS-style numbers (see bytes.cpp for how non-integers behave).
 */
Bytes rotateBytesLeft(const Bytes& bytes, double by = 1);

/** Circular shift of a byte array's *positions* to the right — the inverse of rotateBytesLeft. */
Bytes rotateBytesRight(const Bytes& bytes, double by = 1);

/**
 * Circular left rotation of the whole byte array treated as one big bit string.
 * Used by the key schedule (rotate_left(master_key, n)) — distinct from
 * rotateBytesLeft, which only shifts whole-byte positions.
 */
Bytes rotateBitsLeft(const Bytes& bytes, double bitCount);

/** Circular right rotation of the whole byte array treated as one big bit string — the inverse of rotateBitsLeft. */
Bytes rotateBitsRight(const Bytes& bytes, double bitCount);

struct BitDiffResult {
  std::size_t diffBits;
  std::size_t totalBits;
  Bytes diffMask;
};

/** Number of differing bits between two equal-length byte arrays, plus a per-byte XOR diff mask. */
BitDiffResult bitDiff(const Bytes& a, const Bytes& b);

/** Cryptographically-irrelevant but uniformly random bytes, used for the (non-secret) IV. */
Bytes randomBytes(std::size_t length);

}  // namespace cipher

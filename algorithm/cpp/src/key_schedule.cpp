#include "cipher/key_schedule.hpp"

#include <stdexcept>

#include "cipher/constants.hpp"

namespace cipher {

namespace {

/** A simple, distinct-per-round byte broadcast into the XOR step of the key schedule. */
std::uint8_t roundConstant(long long round) { return static_cast<std::uint8_t>((round + 1) & 0xff); }

}  // namespace

Bytes deriveMasterKeyBytes(std::string_view key) {
  const Bytes raw = textToBytes(key);
  if (raw.empty()) {
    throw std::invalid_argument("Key must not be empty.");
  }
  Bytes out(BLOCK_SIZE, 0);
  for (std::size_t i = 0; i < raw.size(); i++) {
    out[i % BLOCK_SIZE] ^= raw[i];
  }
  return out;
}

std::vector<Bytes> deriveSubkeys(const Bytes& masterKeyBytes, double rounds) {
  std::vector<Bytes> subkeys;
  for (long long round = 0; round < rounds; round++) {
    const Bytes rotated = rotateBitsLeft(masterKeyBytes, static_cast<double>(3 * (round + 1)));
    const std::uint8_t constant = roundConstant(round);
    Bytes subkey(rotated.size());
    for (std::size_t i = 0; i < rotated.size(); i++) {
      subkey[i] = rotated[i] ^ constant;
    }
    subkeys.push_back(std::move(subkey));
  }
  return subkeys;
}

}  // namespace cipher

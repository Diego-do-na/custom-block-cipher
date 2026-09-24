#include "cipher/block_cipher.hpp"

#include <array>
#include <stdexcept>
#include <string>

#include "cipher/constants.hpp"
#include "cipher/sbox.hpp"

namespace cipher {

namespace {

Bytes substitute(const Bytes& block, const std::array<std::uint8_t, 256>& table) {
  Bytes out(block.size());
  for (std::size_t i = 0; i < block.size(); i++) {
    out[i] = table[block[i]];
  }
  return out;
}

void assertBlockSize(const Bytes& block) {
  if (block.size() != BLOCK_SIZE) {
    throw std::invalid_argument("Block must be exactly " + std::to_string(BLOCK_SIZE) + " bytes, got " +
                                std::to_string(block.size()));
  }
}

}  // namespace

BlockCipherResult<EncryptRoundTrace> encryptBlock(const Bytes& block, const std::vector<Bytes>& subkeys) {
  assertBlockSize(block);
  Bytes state = block;
  std::vector<EncryptRoundTrace> trace;

  for (std::size_t round = 0; round < subkeys.size(); round++) {
    const Bytes& subkey = subkeys[round];
    const Bytes input = state;
    Bytes afterXor = xorBytes(input, subkey);
    Bytes afterSub = substitute(afterXor, SBOX);
    Bytes afterRotate = rotateBitsLeft(afterSub, ROTATE_BITS);

    state = afterRotate;
    trace.push_back({static_cast<int>(round), subkey, input, std::move(afterXor), std::move(afterSub),
                     std::move(afterRotate)});
  }

  return {state, std::move(trace)};
}

BlockCipherResult<DecryptRoundTrace> decryptBlock(const Bytes& block, const std::vector<Bytes>& subkeys) {
  assertBlockSize(block);
  Bytes state = block;
  std::vector<DecryptRoundTrace> trace;

  for (auto round = static_cast<long long>(subkeys.size()) - 1; round >= 0; round--) {
    const Bytes& subkey = subkeys[round];
    const Bytes input = state;
    Bytes afterUnrotate = rotateBitsRight(input, ROTATE_BITS);
    Bytes afterInvSub = substitute(afterUnrotate, INV_SBOX);
    Bytes afterXor = xorBytes(afterInvSub, subkey);

    state = afterXor;
    trace.push_back({static_cast<int>(round), subkey, input, std::move(afterUnrotate), std::move(afterInvSub),
                     std::move(afterXor)});
  }

  return {state, std::move(trace)};
}

}  // namespace cipher

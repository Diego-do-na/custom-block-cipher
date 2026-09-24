#include "cipher/cbc.hpp"

namespace cipher {

CbcEncryptResult encryptCbc(const std::vector<Bytes>& plainBlocks, const Bytes& iv, const std::vector<Bytes>& subkeys) {
  CbcEncryptResult result;
  Bytes previous = iv;

  for (std::size_t index = 0; index < plainBlocks.size(); index++) {
    const Bytes& plainBlock = plainBlocks[index];
    Bytes inputBlock = xorBytes(plainBlock, previous);
    auto [cipherBlock, rounds] = encryptBlock(inputBlock, subkeys);

    result.trace.push_back({static_cast<int>(index), plainBlock, previous, std::move(inputBlock), std::move(rounds),
                            cipherBlock});
    result.cipherBlocks.push_back(cipherBlock);
    previous = std::move(cipherBlock);
  }

  return result;
}

CbcDecryptResult decryptCbc(const std::vector<Bytes>& cipherBlocks, const Bytes& iv, const std::vector<Bytes>& subkeys) {
  CbcDecryptResult result;
  Bytes previous = iv;

  for (std::size_t index = 0; index < cipherBlocks.size(); index++) {
    const Bytes& cipherBlock = cipherBlocks[index];
    auto [decryptedBlock, rounds] = decryptBlock(cipherBlock, subkeys);
    Bytes plainBlock = xorBytes(decryptedBlock, previous);

    result.trace.push_back({static_cast<int>(index), cipherBlock, previous, std::move(rounds),
                            std::move(decryptedBlock), plainBlock});
    result.plainBlocks.push_back(std::move(plainBlock));
    previous = cipherBlock;
  }

  return result;
}

}  // namespace cipher

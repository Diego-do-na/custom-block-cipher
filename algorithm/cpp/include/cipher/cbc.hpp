#pragma once

#include <vector>

#include "cipher/block_cipher.hpp"
#include "cipher/bytes.hpp"

namespace cipher {

/** Per-block trace for CBC encryption — enough to visualize the inter-block chaining (diffusion #2). */
struct CbcEncryptBlockTrace {
  int index;
  Bytes plainBlock;
  Bytes previous;    // IV for block 0, else the previous ciphertext block
  Bytes inputBlock;  // plainBlock XOR previous, fed into the block cipher rounds
  std::vector<EncryptRoundTrace> rounds;
  Bytes cipherBlock;
};

struct CbcDecryptBlockTrace {
  int index;
  Bytes cipherBlock;
  Bytes previous;  // IV for block 0, else the previous ciphertext block
  std::vector<DecryptRoundTrace> rounds;
  Bytes decryptedBlock;  // decryptBlock(cipherBlock), before the chaining XOR
  Bytes plainBlock;      // decryptedBlock XOR previous
};

struct CbcEncryptResult {
  std::vector<Bytes> cipherBlocks;
  std::vector<CbcEncryptBlockTrace> trace;
};

struct CbcDecryptResult {
  std::vector<Bytes> plainBlocks;
  std::vector<CbcDecryptBlockTrace> trace;
};

/**
 * CBC-mode encryption over already-padded plaintext blocks (diffusion #2: a change
 * in block i cascades into every block after it, across the whole message).
 */
CbcEncryptResult encryptCbc(const std::vector<Bytes>& plainBlocks, const Bytes& iv, const std::vector<Bytes>& subkeys);

/** CBC-mode decryption: decrypt the block first, then undo the chaining XOR. */
CbcDecryptResult decryptCbc(const std::vector<Bytes>& cipherBlocks, const Bytes& iv, const std::vector<Bytes>& subkeys);

}  // namespace cipher

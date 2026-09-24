#pragma once

#include <vector>

#include "cipher/bytes.hpp"

namespace cipher {

/** One round's state after each sub-step, in encryption order (XOR -> S-box -> rotate). */
struct EncryptRoundTrace {
  int round;
  Bytes subkey;
  Bytes input;
  Bytes afterXor;
  Bytes afterSub;
  Bytes afterRotate;
};

/** One round's state after each sub-step, in decryption order (unrotate -> inverse S-box -> XOR). */
struct DecryptRoundTrace {
  int round;
  Bytes subkey;
  Bytes input;
  Bytes afterUnrotate;
  Bytes afterInvSub;
  Bytes afterXor;
};

template <typename Trace>
struct BlockCipherResult {
  Bytes output;
  std::vector<Trace> trace;
};

/**
 * Encrypts a single BLOCK_SIZE block. Each round, in order:
 *   1. XOR with the round subkey (confusion #1)
 *   2. Substitute every byte through the S-box (confusion #2)
 *   3. Rotate the block's bits left by ROTATE_BITS (diffusion #1)
 *
 * `subkeys[i]` is used for round `i`; `subkeys.size()` determines the round count.
 */
BlockCipherResult<EncryptRoundTrace> encryptBlock(const Bytes& block, const std::vector<Bytes>& subkeys);

/**
 * Decrypts a single BLOCK_SIZE block: reverses the rounds in reverse order, and
 * inverts each step (undo rotate, undo substitution via INV_SBOX, undo XOR).
 */
BlockCipherResult<DecryptRoundTrace> decryptBlock(const Bytes& block, const std::vector<Bytes>& subkeys);

}  // namespace cipher

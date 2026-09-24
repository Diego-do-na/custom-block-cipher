#include "cipher/cipher.hpp"

#include <algorithm>
#include <stdexcept>

namespace cipher {

namespace {

std::vector<Bytes> chunk(const Bytes& bytes, std::size_t size) {
  std::vector<Bytes> blocks;
  for (std::size_t i = 0; i < bytes.size(); i += size) {
    blocks.emplace_back(bytes.begin() + i, bytes.begin() + std::min(i + size, bytes.size()));
  }
  return blocks;
}

std::string joinHex(const std::vector<Bytes>& blocks) {
  std::string out;
  for (const Bytes& block : blocks) out += bytesToHex(block);
  return out;
}

/** Shared by encryptWithTrace (random IV) and the test-only fixed-IV variant. */
EncryptWithTraceResult encryptWithTraceImpl(std::string_view plaintext, std::string_view key,
                                            const CipherOptions& options, const Bytes* fixedIv) {
  const double rounds = options.rounds.value_or(DEFAULT_ROUNDS);
  assertValidRounds(rounds);

  Bytes masterKeyBytes = deriveMasterKeyBytes(key);
  std::vector<Bytes> subkeys = deriveSubkeys(masterKeyBytes, rounds);
  Bytes iv = fixedIv ? *fixedIv : randomBytes(BLOCK_SIZE);

  Bytes paddedPlainBytes = pkcs7Pad(textToBytes(plaintext), BLOCK_SIZE);
  const std::vector<Bytes> plainBlocks = chunk(paddedPlainBytes, BLOCK_SIZE);

  auto [cipherBlocks, blocks] = encryptCbc(plainBlocks, iv, subkeys);

  const std::string ivHex = bytesToHex(iv);
  const std::string ciphertextHex = joinHex(cipherBlocks);
  EncryptResult result{ivHex, ciphertextHex, ivHex + ciphertextHex};

  return {std::move(result),
          {static_cast<int>(rounds), std::move(masterKeyBytes), std::move(subkeys), std::move(iv),
           std::move(paddedPlainBytes), std::move(blocks)}};
}

}  // namespace

EncryptResult encrypt(std::string_view plaintext, std::string_view key, const CipherOptions& options) {
  const EncryptTrace trace = encryptWithTrace(plaintext, key, options).trace;
  const std::string ivHex = bytesToHex(trace.iv);
  std::string ciphertextHex;
  for (const CbcEncryptBlockTrace& block : trace.blocks) ciphertextHex += bytesToHex(block.cipherBlock);
  return {ivHex, ciphertextHex, ivHex + ciphertextHex};
}

EncryptWithTraceResult encryptWithTrace(std::string_view plaintext, std::string_view key, const CipherOptions& options) {
  return encryptWithTraceImpl(plaintext, key, options, nullptr);
}

std::string decrypt(std::string_view combinedHex, std::string_view key, const CipherOptions& options) {
  return decryptWithTrace(combinedHex, key, options).plaintext;
}

DecryptWithTraceResult decryptWithTrace(std::string_view combinedHex, std::string_view key, const CipherOptions& options) {
  const double rounds = options.rounds.value_or(DEFAULT_ROUNDS);
  assertValidRounds(rounds);

  const Bytes combined = hexToBytes(combinedHex);
  if (combined.size() < BLOCK_SIZE || (combined.size() - BLOCK_SIZE) % BLOCK_SIZE != 0) {
    throw std::invalid_argument("Ciphertext must be an IV block plus a whole number of " + std::to_string(BLOCK_SIZE) +
                                "-byte blocks.");
  }

  Bytes iv(combined.begin(), combined.begin() + BLOCK_SIZE);
  const std::vector<Bytes> cipherBlocks = chunk(Bytes(combined.begin() + BLOCK_SIZE, combined.end()), BLOCK_SIZE);

  Bytes masterKeyBytes = deriveMasterKeyBytes(key);
  std::vector<Bytes> subkeys = deriveSubkeys(masterKeyBytes, rounds);

  auto [plainBlocks, blocks] = decryptCbc(cipherBlocks, iv, subkeys);
  Bytes paddedPlainBytes = concatBytes(plainBlocks);
  std::string plaintext = bytesToText(pkcs7Unpad(paddedPlainBytes, BLOCK_SIZE));

  return {std::move(plaintext),
          {static_cast<int>(rounds), std::move(masterKeyBytes), std::move(subkeys), std::move(iv), std::move(blocks),
           std::move(paddedPlainBytes)}};
}

namespace detail {

EncryptWithTraceResult encryptWithTraceUsingIv(std::string_view plaintext, std::string_view key,
                                               const CipherOptions& options, const Bytes& iv) {
  return encryptWithTraceImpl(plaintext, key, options, &iv);
}

}  // namespace detail

}  // namespace cipher

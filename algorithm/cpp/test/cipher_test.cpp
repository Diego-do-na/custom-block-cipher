// C++ port of algorithm/test/cipher.test.ts — same test names, same cases, same thresholds.

#include <algorithm>
#include <string>
#include <vector>

#include "catch2/catch_amalgamated.hpp"
#include "cipher/cipher.hpp"

using namespace cipher;
using Catch::Matchers::ContainsSubstring;

namespace {

std::vector<Bytes> chunkBytes(const Bytes& bytes, std::size_t size) {
  std::vector<Bytes> blocks;
  for (std::size_t i = 0; i < bytes.size(); i += size) {
    blocks.emplace_back(bytes.begin() + i, bytes.begin() + std::min(i + size, bytes.size()));
  }
  return blocks;
}

Bytes cipherBytes(const EncryptTrace& trace) {
  std::vector<Bytes> blocks;
  for (const auto& b : trace.blocks) blocks.push_back(b.cipherBlock);
  return concatBytes(blocks);
}

}  // namespace

TEST_CASE("encryptBlock/decryptBlock round-trip for arbitrary blocks and round counts") {
  const Bytes master = deriveMasterKeyBytes("block level key");
  for (int rounds = MIN_ROUNDS; rounds <= MAX_ROUNDS; rounds++) {
    const std::vector<Bytes> subkeys = deriveSubkeys(master, rounds);
    Bytes block(BLOCK_SIZE);
    for (int i = 0; i < BLOCK_SIZE; i++) block[i] = static_cast<std::uint8_t>((i * 37 + rounds) & 0xff);
    const Bytes cipherBlock = encryptBlock(block, subkeys).output;
    const Bytes plainBlock = decryptBlock(cipherBlock, subkeys).output;
    INFO("round-trip failed at rounds=" << rounds);
    CHECK(plainBlock == block);
  }
}

TEST_CASE("decrypt(encrypt(m, key)) === m for a range of message lengths") {
  const std::vector<std::string> messages = {
      "",
      "a",
      "exactly8",
      "this message is definitely longer than one block",
      "unicode: café ☕ 日本語",
      std::string(100, 'x'),
  };

  for (const std::string& message : messages) {
    const std::string combinedHex = encrypt(message, "a reasonably good passphrase").combinedHex;
    const std::string decrypted = decrypt(combinedHex, "a reasonably good passphrase");
    INFO("round-trip failed for message: " << message);
    CHECK(decrypted == message);
  }
}

TEST_CASE("decrypt(encrypt(m, key)) === m for a range of keys") {
  const std::vector<std::string> keys = {"a", "short", "a much longer passphrase than one block worth of bytes", "密码"};
  for (const std::string& key : keys) {
    const std::string combinedHex = encrypt("constant message", key).combinedHex;
    CHECK(decrypt(combinedHex, key) == "constant message");
  }
}

TEST_CASE("encrypting the same message+key twice yields different ciphertext (random IV)") {
  const EncryptResult a = encrypt("same message", "same key");
  const EncryptResult b = encrypt("same message", "same key");
  CHECK(a.combinedHex != b.combinedHex);
  CHECK(decrypt(a.combinedHex, "same key") == "same message");
  CHECK(decrypt(b.combinedHex, "same key") == "same message");
}

TEST_CASE("decrypting with the wrong key does not silently return the original plaintext") {
  const std::string combinedHex = encrypt("a secret message", "right key").combinedHex;
  // A wrong key almost always corrupts PKCS#7 padding, so this usually throws;
  // on the rare occasion padding happens to validate, it must not recover the message.
  try {
    const std::string decrypted = decrypt(combinedHex, "wrong key");  // outside CHECK, which would swallow the throw
    CHECK(decrypted != "a secret message");
  } catch (const std::exception& err) {
    CHECK_THAT(err.what(), ContainsSubstring("padding", Catch::CaseSensitive::No));
  }
}

TEST_CASE("rejects an out-of-range round count") {
  CHECK_THROWS(encrypt("hi", "key", {MIN_ROUNDS - 1}));
  CHECK_THROWS(encrypt("hi", "key", {MAX_ROUNDS + 1}));
}

TEST_CASE("rejects malformed ciphertext hex") {
  CHECK_THROWS(decrypt("not-hex", "key"));
  CHECK_THROWS(decrypt("ab", "key"));  // shorter than one IV block
}

TEST_CASE("avalanche effect: a single flipped plaintext bit changes a large share of ciphertext bits") {
  const std::string key = "avalanche test key";
  const std::string message = "The quick brown fox jumps over the lazy dog";

  const EncryptTrace baseTrace = encryptWithTrace(message, key).trace;

  Bytes flippedBytes = textToBytes(message);
  flippedBytes[0] ^= 0b00000001;  // flip the lowest bit of the first byte

  const Bytes baseCipher = cipherBytes(baseTrace);

  // Re-encrypt manually with the same IV/subkeys as base to isolate the plaintext-bit effect.
  const Bytes paddedFlipped = pkcs7Pad(flippedBytes, BLOCK_SIZE);
  const std::vector<Bytes> flippedBlocks = chunkBytes(paddedFlipped, BLOCK_SIZE);
  const Bytes flippedCipher = concatBytes(encryptCbc(flippedBlocks, baseTrace.iv, baseTrace.subkeys).cipherBlocks);

  const BitDiffResult diff = bitDiff(baseCipher, flippedCipher);
  const double ratio = static_cast<double>(diff.diffBits) / static_cast<double>(diff.totalBits);

  // A well-mixed cipher should land near 50%; for a small educational cipher we
  // just assert a strong, unmistakable avalanche rather than pin an exact number.
  INFO("expected a strong avalanche effect, got " << ratio * 100 << "% bits changed");
  CHECK(ratio > 0.25);
}

// NEW in the C++ port (not in the original 22 TypeScript tests): SECURITY.md says a
// flipped *key* bit also avalanches, which the original suite never exercised.
TEST_CASE("avalanche effect: a single flipped key bit changes a large share of ciphertext bits") {
  const std::string key = "avalanche test key";
  const std::string message = "The quick brown fox jumps over the lazy dog";

  const EncryptTrace baseTrace = encryptWithTrace(message, key).trace;
  const Bytes baseCipher = cipherBytes(baseTrace);

  // Same IV and plaintext as base; only the lowest bit of the first master-key byte differs.
  Bytes flippedMasterKey = baseTrace.masterKeyBytes;
  flippedMasterKey[0] ^= 0b00000001;
  const std::vector<Bytes> flippedSubkeys = deriveSubkeys(flippedMasterKey, baseTrace.rounds);
  const std::vector<Bytes> plainBlocks = chunkBytes(baseTrace.paddedPlainBytes, BLOCK_SIZE);
  const Bytes flippedCipher = concatBytes(encryptCbc(plainBlocks, baseTrace.iv, flippedSubkeys).cipherBlocks);

  const BitDiffResult diff = bitDiff(baseCipher, flippedCipher);
  const double ratio = static_cast<double>(diff.diffBits) / static_cast<double>(diff.totalBits);

  INFO("expected a strong avalanche effect, got " << ratio * 100 << "% bits changed");
  CHECK(ratio > 0.25);
}

// C++ port of algorithm/test/units.test.ts — same test names, same cases.

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "catch2/catch_amalgamated.hpp"
#include "cipher/cipher.hpp"

using namespace cipher;
using Catch::Matchers::ContainsSubstring;

TEST_CASE("SBOX is a permutation of 0..255") {
  const std::set<int> seen(SBOX.begin(), SBOX.end());
  CHECK(seen.size() == 256);
  CHECK(*std::min_element(SBOX.begin(), SBOX.end()) == 0);
  CHECK(*std::max_element(SBOX.begin(), SBOX.end()) == 255);
}

TEST_CASE("INV_SBOX exactly inverts SBOX") {
  for (int i = 0; i < 256; i++) {
    CHECK(INV_SBOX[SBOX[i]] == i);
  }
}

TEST_CASE("pkcs7Pad/Unpad round-trips for every length in a block") {
  const int blockSize = 8;
  for (int len = 0; len < 20; len++) {
    Bytes data(len);
    for (int i = 0; i < len; i++) data[i] = static_cast<std::uint8_t>(i & 0xff);
    const Bytes padded = pkcs7Pad(data, blockSize);
    CHECK(padded.size() % blockSize == 0);
    INFO("always adds at least one byte of padding");
    CHECK(padded.size() > data.size());
    CHECK(pkcs7Unpad(padded, blockSize) == data);
  }
}

TEST_CASE("pkcs7Unpad rejects malformed padding") {
  const auto noCase = Catch::CaseSensitive::No;
  CHECK_THROWS_WITH(pkcs7Unpad({1, 2, 3, 0}, 8), ContainsSubstring("padded data length", noCase));
  CHECK_THROWS_WITH(pkcs7Unpad({1, 2, 3, 4, 5, 6, 7, 0}, 8), ContainsSubstring("bad pad length", noCase));
  CHECK_THROWS_WITH(pkcs7Unpad({1, 2, 3, 4, 5, 2, 9, 2}, 8), ContainsSubstring("padding bytes do not match", noCase));
}

TEST_CASE("rotateBytesLeft/Right are inverses") {
  const Bytes bytes = {10, 20, 30, 40, 50};
  CHECK(rotateBytesRight(rotateBytesLeft(bytes, 2), 2) == bytes);
}

TEST_CASE("rotateBitsLeft by a full byte-array width is the identity") {
  const Bytes bytes = {1, 2, 3, 4};
  CHECK(rotateBitsLeft(bytes, 32) == bytes);
}

TEST_CASE("rotateBitsLeft actually mixes bits across byte boundaries") {
  const Bytes bytes = {0b10000000, 0b00000000};
  CHECK(rotateBitsLeft(bytes, 1) == Bytes{0b00000000, 0b00000001});
}

TEST_CASE("xorBytes is its own inverse") {
  const Bytes a = {1, 2, 3};
  const Bytes b = {9, 8, 7};
  CHECK(xorBytes(xorBytes(a, b), b) == a);
}

TEST_CASE("bitDiff counts differing bits correctly") {
  const BitDiffResult diff = bitDiff({0b00000000}, {0b00000011});
  CHECK(diff.diffBits == 2);
  CHECK(diff.totalBits == 8);
}

TEST_CASE("hex round-trip") {
  const Bytes bytes = {0, 1, 254, 255, 16};
  CHECK(hexToBytes(bytesToHex(bytes)) == bytes);
}

TEST_CASE("deriveMasterKeyBytes is deterministic and fills BLOCK_SIZE bytes") {
  const Bytes a = deriveMasterKeyBytes("correct horse battery staple");
  const Bytes b = deriveMasterKeyBytes("correct horse battery staple");
  CHECK(a.size() == BLOCK_SIZE);
  CHECK(a == b);
}

TEST_CASE("deriveMasterKeyBytes differs for different keys") {
  CHECK(deriveMasterKeyBytes("key-one") != deriveMasterKeyBytes("key-two"));
}

TEST_CASE("deriveSubkeys produces one visibly distinct subkey per round") {
  const Bytes master = deriveMasterKeyBytes("a shared secret");
  const std::vector<Bytes> subkeys = deriveSubkeys(master, 6);
  CHECK(subkeys.size() == 6);

  std::set<std::string> hexes;
  for (const Bytes& subkey : subkeys) hexes.insert(bytesToHex(subkey));
  INFO("all subkeys should be distinct from each other");
  CHECK(hexes.size() == 6);
  for (const std::string& hex : hexes) {
    INFO("subkey should differ from the raw master key");
    CHECK(hex != bytesToHex(master));
  }
}

TEST_CASE("deriveSubkeys is deterministic for the same master key") {
  const Bytes master = deriveMasterKeyBytes("deterministic please");
  CHECK(deriveSubkeys(master, 5) == deriveSubkeys(master, 5));
}

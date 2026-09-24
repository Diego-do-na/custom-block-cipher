// Byte-for-byte parity against algorithm/test/vectors/golden.json: reference outputs
// captured from the original TypeScript implementation (see scripts/make-golden-vectors.ts).
// Any mismatch here means the C++ port has drifted from the original behavior.

#include <cmath>
#include <fstream>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "catch2/catch_amalgamated.hpp"
#include "cipher/cipher.hpp"
#include "nlohmann/json.hpp"

using namespace cipher;
using json = nlohmann::json;

#ifndef GOLDEN_VECTORS_PATH
#error "GOLDEN_VECTORS_PATH must be defined (see Makefile)"
#endif

namespace {

const json& golden() {
  static const json data = [] {
    std::ifstream in(GOLDEN_VECTORS_PATH);
    if (!in) throw std::runtime_error("cannot open " GOLDEN_VECTORS_PATH);
    return json::parse(in);
  }();
  return data;
}

Bytes bytes(const json& hex) { return hexToBytes(hex.get<std::string>()); }

/** The golden file's hex encoding of a UTF-8 string, as a std::string of those bytes. */
std::string utf8(const json& hex) {
  const Bytes b = bytes(hex);
  return std::string(b.begin(), b.end());
}

std::vector<Bytes> byteList(const json& hexes) {
  std::vector<Bytes> out;
  for (const auto& h : hexes) out.push_back(bytes(h));
  return out;
}

std::vector<std::string> hexList(const std::vector<Bytes>& list) {
  std::vector<std::string> out;
  for (const Bytes& b : list) out.push_back(bytesToHex(b));
  return out;
}

double number(const json& value) {
  if (value.is_number()) return value.get<double>();
  const std::string s = value.get<std::string>();
  if (s == "NaN") return std::numeric_limits<double>::quiet_NaN();
  if (s == "Infinity") return INFINITY;
  if (s == "-Infinity") return -INFINITY;
  if (s == "-0") return -0.0;
  throw std::runtime_error("unexpected number encoding: " + s);
}

CipherOptions options(const json& rounds) {
  CipherOptions o;
  if (!rounds.is_null()) o.rounds = number(rounds);
  return o;
}

/** The message thrown by `fn`, or nullopt if it didn't throw. */
std::optional<std::string> errorOf(const std::function<void()>& fn) {
  try {
    fn();
  } catch (const std::exception& err) {
    return std::string(err.what());
  }
  return std::nullopt;
}

void checkEncryptRounds(const std::vector<EncryptRoundTrace>& actual, const json& expected) {
  REQUIRE(actual.size() == expected.size());
  for (std::size_t i = 0; i < actual.size(); i++) {
    const auto& a = actual[i];
    const auto& e = expected[i];
    CHECK(a.round == e["round"].get<int>());
    CHECK(bytesToHex(a.subkey) == e["subkey"].get<std::string>());
    CHECK(bytesToHex(a.input) == e["input"].get<std::string>());
    CHECK(bytesToHex(a.afterXor) == e["afterXor"].get<std::string>());
    CHECK(bytesToHex(a.afterSub) == e["afterSub"].get<std::string>());
    CHECK(bytesToHex(a.afterRotate) == e["afterRotate"].get<std::string>());
  }
}

void checkDecryptRounds(const std::vector<DecryptRoundTrace>& actual, const json& expected) {
  REQUIRE(actual.size() == expected.size());
  for (std::size_t i = 0; i < actual.size(); i++) {
    const auto& a = actual[i];
    const auto& e = expected[i];
    CHECK(a.round == e["round"].get<int>());
    CHECK(bytesToHex(a.subkey) == e["subkey"].get<std::string>());
    CHECK(bytesToHex(a.input) == e["input"].get<std::string>());
    CHECK(bytesToHex(a.afterUnrotate) == e["afterUnrotate"].get<std::string>());
    CHECK(bytesToHex(a.afterInvSub) == e["afterInvSub"].get<std::string>());
    CHECK(bytesToHex(a.afterXor) == e["afterXor"].get<std::string>());
  }
}

void checkCbcEncryptTrace(const std::vector<CbcEncryptBlockTrace>& actual, const json& expected) {
  REQUIRE(actual.size() == expected.size());
  for (std::size_t i = 0; i < actual.size(); i++) {
    const auto& a = actual[i];
    const auto& e = expected[i];
    CHECK(a.index == e["index"].get<int>());
    CHECK(bytesToHex(a.plainBlock) == e["plainBlock"].get<std::string>());
    CHECK(bytesToHex(a.previous) == e["previous"].get<std::string>());
    CHECK(bytesToHex(a.inputBlock) == e["inputBlock"].get<std::string>());
    checkEncryptRounds(a.rounds, e["rounds"]);
    CHECK(bytesToHex(a.cipherBlock) == e["cipherBlock"].get<std::string>());
  }
}

void checkCbcDecryptTrace(const std::vector<CbcDecryptBlockTrace>& actual, const json& expected) {
  REQUIRE(actual.size() == expected.size());
  for (std::size_t i = 0; i < actual.size(); i++) {
    const auto& a = actual[i];
    const auto& e = expected[i];
    CHECK(a.index == e["index"].get<int>());
    CHECK(bytesToHex(a.cipherBlock) == e["cipherBlock"].get<std::string>());
    CHECK(bytesToHex(a.previous) == e["previous"].get<std::string>());
    checkDecryptRounds(a.rounds, e["rounds"]);
    CHECK(bytesToHex(a.decryptedBlock) == e["decryptedBlock"].get<std::string>());
    CHECK(bytesToHex(a.plainBlock) == e["plainBlock"].get<std::string>());
  }
}

void checkDecryptTrace(const DecryptTrace& actual, const json& expected) {
  CHECK(actual.rounds == expected["rounds"].get<int>());
  CHECK(bytesToHex(actual.masterKeyBytes) == expected["masterKeyBytes"].get<std::string>());
  CHECK(hexList(actual.subkeys) == expected["subkeys"].get<std::vector<std::string>>());
  CHECK(bytesToHex(actual.iv) == expected["iv"].get<std::string>());
  checkCbcDecryptTrace(actual.blocks, expected["blocks"]);
  CHECK(bytesToHex(actual.paddedPlainBytes) == expected["paddedPlainBytes"].get<std::string>());
}

}  // namespace

TEST_CASE("golden: constants, S-box and inverse S-box") {
  const json& c = golden()["constants"];
  CHECK(BLOCK_SIZE == c["BLOCK_SIZE"].get<int>());
  CHECK(DEFAULT_ROUNDS == c["DEFAULT_ROUNDS"].get<int>());
  CHECK(MIN_ROUNDS == c["MIN_ROUNDS"].get<int>());
  CHECK(MAX_ROUNDS == c["MAX_ROUNDS"].get<int>());
  CHECK(ROTATE_BITS == c["ROTATE_BITS"].get<int>());
  CHECK(std::vector<int>(SBOX.begin(), SBOX.end()) == golden()["sbox"].get<std::vector<int>>());
  CHECK(std::vector<int>(INV_SBOX.begin(), INV_SBOX.end()) == golden()["invSbox"].get<std::vector<int>>());
}

TEST_CASE("golden: assertValidRounds accepts/rejects with identical messages") {
  for (const auto& v : golden()["assertValidRounds"]) {
    const auto err = errorOf([&] { assertValidRounds(number(v["rounds"])); });
    INFO("rounds = " << v["rounds"].dump());
    if (v["error"].is_null()) {
      CHECK_FALSE(err.has_value());
    } else {
      CHECK(err == v["error"].get<std::string>());
    }
  }
}

TEST_CASE("golden: key schedule (master key folding + subkeys)") {
  for (const auto& v : golden()["masterKeys"]) {
    CHECK(bytesToHex(deriveMasterKeyBytes(utf8(v["keyUtf8"]))) == v["master"].get<std::string>());
  }
  for (const auto& v : golden()["masterKeyErrors"]) {
    CHECK(errorOf([&] { deriveMasterKeyBytes(utf8(v["keyUtf8"])); }) == v["error"].get<std::string>());
  }
  for (const auto& v : golden()["subkeys"]) {
    CHECK(hexList(deriveSubkeys(bytes(v["master"]), v["rounds"].get<double>())) ==
          v["subkeys"].get<std::vector<std::string>>());
  }
}

TEST_CASE("golden: bit and byte rotation") {
  for (const auto& v : golden()["rotateBits"]) {
    const Bytes input = bytes(v["input"]);
    const double count = v["count"].get<double>();
    INFO("input " << v["input"] << " count " << count);
    CHECK(bytesToHex(rotateBitsLeft(input, count)) == v["left"].get<std::string>());
    CHECK(bytesToHex(rotateBitsRight(input, count)) == v["right"].get<std::string>());
  }
  for (const auto& v : golden()["rotateBytes"]) {
    const Bytes input = bytes(v["input"]);
    const double by = v["by"].get<double>();
    CHECK(bytesToHex(rotateBytesLeft(input, by)) == v["left"].get<std::string>());
    CHECK(bytesToHex(rotateBytesRight(input, by)) == v["right"].get<std::string>());
  }
}

TEST_CASE("golden: byte helpers (xor, concat, hex, bitDiff)") {
  for (const auto& v : golden()["xor"]) {
    if (v.contains("error")) {
      CHECK(errorOf([&] { xorBytes(bytes(v["a"]), bytes(v["b"])); }) == v["error"].get<std::string>());
    } else {
      CHECK(bytesToHex(xorBytes(bytes(v["a"]), bytes(v["b"]))) == v["out"].get<std::string>());
    }
  }
  for (const auto& v : golden()["concat"]) {
    CHECK(bytesToHex(concatBytes(byteList(v["parts"]))) == v["out"].get<std::string>());
  }
  for (const auto& v : golden()["hexToBytes"]) {
    const std::string hex = v["hex"].get<std::string>();
    if (v.contains("error")) {
      CHECK(errorOf([&] { hexToBytes(hex); }) == v["error"].get<std::string>());
    } else {
      CHECK(bytesToHex(hexToBytes(hex)) == v["out"].get<std::string>());
    }
  }
  for (const auto& v : golden()["bytesToHex"]) {
    const auto raw = v["bytes"].get<std::vector<int>>();
    CHECK(bytesToHex(Bytes(raw.begin(), raw.end())) == v["hex"].get<std::string>());
  }
  for (const auto& v : golden()["bitDiff"]) {
    if (v.contains("error")) {
      CHECK(errorOf([&] { bitDiff(bytes(v["a"]), bytes(v["b"])); }) == v["error"].get<std::string>());
      continue;
    }
    const BitDiffResult d = bitDiff(bytes(v["a"]), bytes(v["b"]));
    CHECK(d.diffBits == v["diffBits"].get<std::size_t>());
    CHECK(d.totalBits == v["totalBits"].get<std::size_t>());
    CHECK(bytesToHex(d.diffMask) == v["diffMask"].get<std::string>());
  }
}

TEST_CASE("golden: PKCS#7 pad/unpad") {
  for (const auto& v : golden()["pad"]) {
    CHECK(bytesToHex(pkcs7Pad(bytes(v["data"]), v["blockSize"].get<int>())) == v["padded"].get<std::string>());
  }
  for (const auto& v : golden()["unpad"]) {
    const Bytes data = bytes(v["data"]);
    const int blockSize = v["blockSize"].get<int>();
    INFO("data " << v["data"] << " blockSize " << blockSize);
    if (v.contains("error")) {
      CHECK(errorOf([&] { pkcs7Unpad(data, blockSize); }) == v["error"].get<std::string>());
    } else {
      CHECK(bytesToHex(pkcs7Unpad(data, blockSize)) == v["out"].get<std::string>());
    }
  }
}

TEST_CASE("golden: encryptBlock/decryptBlock full per-round traces") {
  for (const auto& v : golden()["encryptBlock"]) {
    const auto result = encryptBlock(bytes(v["block"]), byteList(v["subkeys"]));
    CHECK(bytesToHex(result.output) == v["output"].get<std::string>());
    checkEncryptRounds(result.trace, v["trace"]);
  }
  for (const auto& v : golden()["decryptBlock"]) {
    const auto result = decryptBlock(bytes(v["block"]), byteList(v["subkeys"]));
    CHECK(bytesToHex(result.output) == v["output"].get<std::string>());
    checkDecryptRounds(result.trace, v["trace"]);
  }
  for (const auto& v : golden()["blockErrors"]) {
    const Bytes block = bytes(v["block"]);
    const std::vector<Bytes> keys = byteList(v["subkeys"]);
    const auto err = errorOf([&] {
      if (v["op"] == "encryptBlock") encryptBlock(block, keys);
      else decryptBlock(block, keys);
    });
    CHECK(err == v["error"].get<std::string>());
  }
}

TEST_CASE("golden: encryptCbc/decryptCbc full per-block traces") {
  for (const auto& v : golden()["encryptCbc"]) {
    const auto result = encryptCbc(byteList(v["plainBlocks"]), bytes(v["iv"]), byteList(v["subkeys"]));
    CHECK(hexList(result.cipherBlocks) == v["cipherBlocks"].get<std::vector<std::string>>());
    checkCbcEncryptTrace(result.trace, v["trace"]);
  }
  for (const auto& v : golden()["decryptCbc"]) {
    const auto result = decryptCbc(byteList(v["cipherBlocks"]), bytes(v["iv"]), byteList(v["subkeys"]));
    CHECK(hexList(result.plainBlocks) == v["plainBlocks"].get<std::vector<std::string>>());
    checkCbcDecryptTrace(result.trace, v["trace"]);
  }
}

TEST_CASE("golden: full encrypt/decrypt matches the TypeScript output and traces") {
  for (const auto& v : golden()["messages"]) {
    const std::string plaintext = utf8(v["plaintextUtf8"]);
    const std::string key = utf8(v["keyUtf8"]);
    const CipherOptions opts = options(v["rounds"]);
    const json& et = v["encryptTrace"];
    INFO("plaintext " << v["plaintext"].dump() << " key " << v["key"].dump());

    // Encryption, pinned to the IV the TypeScript run happened to pick.
    const auto enc = detail::encryptWithTraceUsingIv(plaintext, key, opts, bytes(et["iv"]));
    CHECK(enc.result.ivHex == v["result"]["ivHex"].get<std::string>());
    CHECK(enc.result.ciphertextHex == v["result"]["ciphertextHex"].get<std::string>());
    CHECK(enc.result.combinedHex == v["result"]["combinedHex"].get<std::string>());
    CHECK(enc.trace.rounds == et["rounds"].get<int>());
    CHECK(bytesToHex(enc.trace.masterKeyBytes) == et["masterKeyBytes"].get<std::string>());
    CHECK(hexList(enc.trace.subkeys) == et["subkeys"].get<std::vector<std::string>>());
    CHECK(bytesToHex(enc.trace.paddedPlainBytes) == et["paddedPlainBytes"].get<std::string>());
    checkCbcEncryptTrace(enc.trace.blocks, et["blocks"]);

    // Decrypting the TypeScript-produced ciphertext.
    const auto dec = decryptWithTrace(v["result"]["combinedHex"].get<std::string>(), key, opts);
    CHECK(bytesToHex(textToBytes(dec.plaintext)) == v["decrypted"]["plaintextUtf8"].get<std::string>());
    checkDecryptTrace(dec.trace, v["decrypted"]["trace"]);
  }
}

TEST_CASE("golden: wrong-key decryption fails (or garbles) identically") {
  for (const auto& v : golden()["wrongKey"]) {
    const std::string combinedHex = v["combinedHex"].get<std::string>();
    const std::string key = utf8(v["keyUtf8"]);
    const CipherOptions opts = options(v["rounds"]);
    if (v.contains("error")) {
      CHECK(errorOf([&] { decryptWithTrace(combinedHex, key, opts); }) == v["error"].get<std::string>());
    } else {
      const auto dec = decryptWithTrace(combinedHex, key, opts);
      CHECK(bytesToHex(textToBytes(dec.plaintext)) == v["plaintextUtf8"].get<std::string>());
      checkDecryptTrace(dec.trace, v["trace"]);
    }
  }
}

TEST_CASE("golden: high-level API errors (and their precedence) match") {
  for (const auto& v : golden()["apiErrors"]) {
    const std::string key = utf8(v["keyUtf8"]);
    const CipherOptions opts = options(v["rounds"]);
    INFO(v.dump());
    const auto err = errorOf([&] {
      if (v["op"] == "encrypt") encrypt(utf8(v["plaintextUtf8"]), key, opts);
      else decrypt(v["combinedHex"].get<std::string>(), key, opts);
    });
    CHECK(err == v["error"].get<std::string>());
  }
}

TEST_CASE("golden: avalanche bit counts with a fixed IV are identical") {
  for (const auto& v : golden()["avalanche"]) {
    const Bytes iv = bytes(v["iv"]);
    const auto rounds = v["rounds"].get<double>();
    const Bytes master = deriveMasterKeyBytes(v["key"].get<std::string>());
    const std::vector<Bytes> keys = deriveSubkeys(master, rounds);
    const Bytes padded = pkcs7Pad(textToBytes(v["plaintext"].get<std::string>()), BLOCK_SIZE);
    const auto chunk = [](const Bytes& b) {
      std::vector<Bytes> out;
      for (std::size_t i = 0; i < b.size(); i += BLOCK_SIZE) out.emplace_back(b.begin() + i, b.begin() + i + BLOCK_SIZE);
      return out;
    };
    const Bytes base = concatBytes(encryptCbc(chunk(padded), iv, keys).cipherBlocks);

    const bool plaintextTarget = v["target"] == "plaintext";
    Bytes flipTarget = plaintextTarget ? padded : master;
    flipTarget[v["byteIndex"].get<std::size_t>()] ^= static_cast<std::uint8_t>(1 << (7 - v["bitOffset"].get<int>()));
    const Bytes flipped = plaintextTarget
                              ? concatBytes(encryptCbc(chunk(flipTarget), iv, keys).cipherBlocks)
                              : concatBytes(encryptCbc(chunk(padded), iv, deriveSubkeys(flipTarget, rounds)).cipherBlocks);

    const BitDiffResult d = bitDiff(base, flipped);
    CHECK(bytesToHex(base) == v["baseCipher"].get<std::string>());
    CHECK(bytesToHex(flipped) == v["flippedCipher"].get<std::string>());
    CHECK(d.diffBits == v["diffBits"].get<std::size_t>());
    CHECK(d.totalBits == v["totalBits"].get<std::size_t>());
  }
}

TEST_CASE("golden: UTF-8 decoding matches TextDecoder (replacement chars, leading BOM)") {
  for (const auto& v : golden()["utf8Decode"]) {
    INFO("bytes " << v["bytes"]);
    CHECK(bytesToHex(textToBytes(bytesToText(bytes(v["bytes"])))) == v["textUtf8"].get<std::string>());
  }
}

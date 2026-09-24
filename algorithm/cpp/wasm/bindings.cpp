/**
 * Emscripten/embind bridge between the C++ cipher and JavaScript. Compiled into
 * algorithm/wasm/generated/cipher.mjs, which algorithm/src/index.ts loads.
 *
 * Contains no cipher logic: every function converts JS values to C++ types, calls the
 * matching function from include/cipher/, and converts the result back into a plain
 * JS object with the same field names (and field order) as the original TypeScript
 * implementation — byte arrays as fresh Uint8Array copies.
 *
 * Strings: plaintext and key arrive as UTF-8 bytes (a Uint8Array produced by
 * TextEncoder in index.ts) rather than JS strings, and decrypted plaintext leaves the
 * same way. embind's own string conversion doesn't match TextEncoder/TextDecoder
 * exactly (lone surrogates, a leading BOM), and the original behavior depended on them.
 *
 * Errors: every function returns an envelope — `{ ok: true, value }`, or
 * `{ ok: false, error }` carrying the C++ exception's message — and index.ts throws
 * the JS `Error`. Nothing is thrown from inside WASM: a JS exception unwinding through
 * WASM frames skips restoring Emscripten's stack pointer, leaking stack space on every
 * error until the module crashes (e.g. after enough wrong-key decrypts in the demo).
 */

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <string>
#include <vector>

#include "cipher/cipher.hpp"

using emscripten::val;
using namespace cipher;

namespace {

// --- error translation ---------------------------------------------------------------

/** Runs `fn`, wrapping its result or any C++ exception's message in the envelope described above. */
template <typename Fn>
val guarded(Fn&& fn) {
  val envelope = val::object();
  try {
    val value = fn();
    envelope.set("ok", true);
    envelope.set("value", value);
  } catch (const std::exception& err) {
    envelope.set("ok", false);
    envelope.set("error", std::string(err.what()));
  }
  return envelope;
}

// --- JS <-> C++ conversions ----------------------------------------------------------

Bytes toBytes(const val& array) { return emscripten::convertJSArrayToNumberVector<std::uint8_t>(array); }

std::string toUtf8String(const val& array) {
  const Bytes b = toBytes(array);
  return std::string(b.begin(), b.end());
}

std::vector<Bytes> toByteList(const val& arrays) {
  std::vector<Bytes> out;
  const unsigned length = arrays["length"].as<unsigned>();
  for (unsigned i = 0; i < length; i++) out.push_back(toBytes(arrays[i]));
  return out;
}

val toJs(const Bytes& bytes) {
  return val::global("Uint8Array").new_(emscripten::typed_memory_view(bytes.size(), bytes.data()));
}

val toJs(const std::string& utf8) {
  const Bytes bytes(utf8.begin(), utf8.end());
  return toJs(bytes);
}

val toJs(const std::vector<Bytes>& list) {
  val out = val::array();
  for (const Bytes& b : list) out.call<void>("push", toJs(b));
  return out;
}

/** `options.rounds ?? DEFAULT_ROUNDS`, with non-number values rejected exactly like assertValidRounds would. */
CipherOptions toOptions(const val& rounds) {
  CipherOptions options;
  if (rounds.isUndefined() || rounds.isNull()) return options;
  if (!rounds.isNumber()) {
    throw std::invalid_argument(invalidRoundsMessage(val::global("String")(rounds).as<std::string>()));
  }
  options.rounds = rounds.as<double>();
  return options;
}

/** JS ToNumber, for arguments the original code only ever used arithmetically. */
double toNumber(const val& value) { return val::global("Number")(value).as<double>(); }

val toJs(const EncryptRoundTrace& r) {
  val o = val::object();
  o.set("round", r.round);
  o.set("subkey", toJs(r.subkey));
  o.set("input", toJs(r.input));
  o.set("afterXor", toJs(r.afterXor));
  o.set("afterSub", toJs(r.afterSub));
  o.set("afterRotate", toJs(r.afterRotate));
  return o;
}

val toJs(const DecryptRoundTrace& r) {
  val o = val::object();
  o.set("round", r.round);
  o.set("subkey", toJs(r.subkey));
  o.set("input", toJs(r.input));
  o.set("afterUnrotate", toJs(r.afterUnrotate));
  o.set("afterInvSub", toJs(r.afterInvSub));
  o.set("afterXor", toJs(r.afterXor));
  return o;
}

val toJs(const CbcEncryptBlockTrace& b);
val toJs(const CbcDecryptBlockTrace& b);

template <typename T>
val toJsArray(const std::vector<T>& items) {
  val out = val::array();
  for (const T& item : items) out.call<void>("push", toJs(item));
  return out;
}

val toJs(const CbcEncryptBlockTrace& b) {
  val o = val::object();
  o.set("index", b.index);
  o.set("plainBlock", toJs(b.plainBlock));
  o.set("previous", toJs(b.previous));
  o.set("inputBlock", toJs(b.inputBlock));
  o.set("rounds", toJsArray(b.rounds));
  o.set("cipherBlock", toJs(b.cipherBlock));
  return o;
}

val toJs(const CbcDecryptBlockTrace& b) {
  val o = val::object();
  o.set("index", b.index);
  o.set("cipherBlock", toJs(b.cipherBlock));
  o.set("previous", toJs(b.previous));
  o.set("rounds", toJsArray(b.rounds));
  o.set("decryptedBlock", toJs(b.decryptedBlock));
  o.set("plainBlock", toJs(b.plainBlock));
  return o;
}

val toJs(const EncryptResult& r) {
  val o = val::object();
  o.set("ivHex", r.ivHex);
  o.set("ciphertextHex", r.ciphertextHex);
  o.set("combinedHex", r.combinedHex);
  return o;
}

val toJs(const EncryptTrace& t) {
  val o = val::object();
  o.set("rounds", t.rounds);
  o.set("masterKeyBytes", toJs(t.masterKeyBytes));
  o.set("subkeys", toJs(t.subkeys));
  o.set("iv", toJs(t.iv));
  o.set("paddedPlainBytes", toJs(t.paddedPlainBytes));
  o.set("blocks", toJsArray(t.blocks));
  return o;
}

val toJs(const DecryptTrace& t) {
  val o = val::object();
  o.set("rounds", t.rounds);
  o.set("masterKeyBytes", toJs(t.masterKeyBytes));
  o.set("subkeys", toJs(t.subkeys));
  o.set("iv", toJs(t.iv));
  o.set("blocks", toJsArray(t.blocks));
  o.set("paddedPlainBytes", toJs(t.paddedPlainBytes));
  return o;
}

// --- exported functions ----------------------------------------------------------------

val sbox() { return guarded([] { return toJs(Bytes(SBOX.begin(), SBOX.end())); }); }
val invSbox() { return guarded([] { return toJs(Bytes(INV_SBOX.begin(), INV_SBOX.end())); }); }

val jsAssertValidRounds(val rounds) {
  return guarded([&] {
    if (!rounds.isNumber()) {
      throw std::invalid_argument(invalidRoundsMessage(val::global("String")(rounds).as<std::string>()));
    }
    assertValidRounds(rounds.as<double>());
    return val::undefined();
  });
}

val jsBytesToHex(val bytes) { return guarded([&] { return val(bytesToHex(toBytes(bytes))); }); }
val jsHexToBytes(std::string hex) { return guarded([&] { return toJs(hexToBytes(hex)); }); }
val jsConcatBytes(val chunks) { return guarded([&] { return toJs(concatBytes(toByteList(chunks))); }); }
val jsXorBytes(val a, val b) { return guarded([&] { return toJs(xorBytes(toBytes(a), toBytes(b))); }); }
val jsRotateBytesLeft(val bytes, val by) { return guarded([&] { return toJs(rotateBytesLeft(toBytes(bytes), toNumber(by))); }); }
val jsRotateBytesRight(val bytes, val by) { return guarded([&] { return toJs(rotateBytesRight(toBytes(bytes), toNumber(by))); }); }
val jsRotateBitsLeft(val bytes, val count) { return guarded([&] { return toJs(rotateBitsLeft(toBytes(bytes), toNumber(count))); }); }
val jsRotateBitsRight(val bytes, val count) { return guarded([&] { return toJs(rotateBitsRight(toBytes(bytes), toNumber(count))); }); }
val jsRandomBytes(val length) { return guarded([&] { return toJs(randomBytes(static_cast<std::size_t>(toNumber(length)))); }); }

val jsBitDiff(val a, val b) {
  return guarded([&] {
    const BitDiffResult d = bitDiff(toBytes(a), toBytes(b));
    val o = val::object();
    o.set("diffBits", static_cast<double>(d.diffBits));
    o.set("totalBits", static_cast<double>(d.totalBits));
    o.set("diffMask", toJs(d.diffMask));
    return o;
  });
}

val jsPkcs7Pad(val data, val blockSize) {
  return guarded([&] { return toJs(pkcs7Pad(toBytes(data), static_cast<int>(toNumber(blockSize)))); });
}
val jsPkcs7Unpad(val data, val blockSize) {
  return guarded([&] { return toJs(pkcs7Unpad(toBytes(data), static_cast<int>(toNumber(blockSize)))); });
}

val jsDeriveMasterKeyBytes(val keyUtf8) { return guarded([&] { return toJs(deriveMasterKeyBytes(toUtf8String(keyUtf8))); }); }
val jsDeriveSubkeys(val master, val rounds) {
  return guarded([&] { return toJs(deriveSubkeys(toBytes(master), toNumber(rounds))); });
}

val jsEncryptBlock(val block, val subkeys) {
  return guarded([&] {
    const auto r = encryptBlock(toBytes(block), toByteList(subkeys));
    val o = val::object();
    o.set("output", toJs(r.output));
    o.set("trace", toJsArray(r.trace));
    return o;
  });
}

val jsDecryptBlock(val block, val subkeys) {
  return guarded([&] {
    const auto r = decryptBlock(toBytes(block), toByteList(subkeys));
    val o = val::object();
    o.set("output", toJs(r.output));
    o.set("trace", toJsArray(r.trace));
    return o;
  });
}

val jsEncryptCbc(val plainBlocks, val iv, val subkeys) {
  return guarded([&] {
    const auto r = encryptCbc(toByteList(plainBlocks), toBytes(iv), toByteList(subkeys));
    val o = val::object();
    o.set("cipherBlocks", toJs(r.cipherBlocks));
    o.set("trace", toJsArray(r.trace));
    return o;
  });
}

val jsDecryptCbc(val cipherBlocks, val iv, val subkeys) {
  return guarded([&] {
    const auto r = decryptCbc(toByteList(cipherBlocks), toBytes(iv), toByteList(subkeys));
    val o = val::object();
    o.set("plainBlocks", toJs(r.plainBlocks));
    o.set("trace", toJsArray(r.trace));
    return o;
  });
}

val jsEncrypt(val plaintextUtf8, val keyUtf8, val rounds) {
  return guarded([&] {
    const CipherOptions options = toOptions(rounds);
    return toJs(encrypt(toUtf8String(plaintextUtf8), toUtf8String(keyUtf8), options));
  });
}

val jsEncryptWithTrace(val plaintextUtf8, val keyUtf8, val rounds) {
  return guarded([&] {
    const CipherOptions options = toOptions(rounds);
    const auto r = encryptWithTrace(toUtf8String(plaintextUtf8), toUtf8String(keyUtf8), options);
    val o = val::object();
    o.set("result", toJs(r.result));
    o.set("trace", toJs(r.trace));
    return o;
  });
}

/** Returns the decrypted plaintext as UTF-8 bytes (see the note on strings above). */
val jsDecrypt(std::string combinedHex, val keyUtf8, val rounds) {
  return guarded([&] {
    const CipherOptions options = toOptions(rounds);
    return toJs(decrypt(combinedHex, toUtf8String(keyUtf8), options));
  });
}

val jsDecryptWithTrace(std::string combinedHex, val keyUtf8, val rounds) {
  return guarded([&] {
    const CipherOptions options = toOptions(rounds);
    const auto r = decryptWithTrace(combinedHex, toUtf8String(keyUtf8), options);
    val o = val::object();
    o.set("plaintextUtf8", toJs(r.plaintext));
    o.set("trace", toJs(r.trace));
    return o;
  });
}

}  // namespace

EMSCRIPTEN_BINDINGS(cipher) {
  using emscripten::constant;
  using emscripten::function;

  constant("BLOCK_SIZE", BLOCK_SIZE);
  constant("DEFAULT_ROUNDS", DEFAULT_ROUNDS);
  constant("MIN_ROUNDS", MIN_ROUNDS);
  constant("MAX_ROUNDS", MAX_ROUNDS);
  constant("ROTATE_BITS", ROTATE_BITS);

  function("sbox", &sbox);
  function("invSbox", &invSbox);
  function("assertValidRounds", &jsAssertValidRounds);

  function("bytesToHex", &jsBytesToHex);
  function("hexToBytes", &jsHexToBytes);
  function("concatBytes", &jsConcatBytes);
  function("xorBytes", &jsXorBytes);
  function("rotateBytesLeft", &jsRotateBytesLeft);
  function("rotateBytesRight", &jsRotateBytesRight);
  function("rotateBitsLeft", &jsRotateBitsLeft);
  function("rotateBitsRight", &jsRotateBitsRight);
  function("bitDiff", &jsBitDiff);
  function("randomBytes", &jsRandomBytes);

  function("pkcs7Pad", &jsPkcs7Pad);
  function("pkcs7Unpad", &jsPkcs7Unpad);

  function("deriveMasterKeyBytes", &jsDeriveMasterKeyBytes);
  function("deriveSubkeys", &jsDeriveSubkeys);

  function("encryptBlock", &jsEncryptBlock);
  function("decryptBlock", &jsDecryptBlock);
  function("encryptCbc", &jsEncryptCbc);
  function("decryptCbc", &jsDecryptCbc);

  function("encrypt", &jsEncrypt);
  function("encryptWithTrace", &jsEncryptWithTrace);
  function("decrypt", &jsDecrypt);
  function("decryptWithTrace", &jsDecryptWithTrace);
}

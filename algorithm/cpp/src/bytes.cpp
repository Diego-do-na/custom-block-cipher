#include "cipher/bytes.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <unistd.h>
#if __has_include(<sys/random.h>)
#include <sys/random.h>
#endif

#include "cipher/js_compat.hpp"

namespace cipher {

namespace {

bool isHexDigit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return c - 'A' + 10;
}

/** JS `a % b` on doubles (the result takes the dividend's sign), which is exactly fmod. */
double jsMod(double a, double b) { return std::fmod(a, b); }

/** JS ToInt32 for the values used here (always in [0, 2^31) or NaN): truncation, NaN -> 0. */
long long toInt32(double value) { return std::isfinite(value) ? static_cast<long long>(std::trunc(value)) : 0; }

int popcount(std::uint8_t byte) {
  int count = 0;
  unsigned n = byte;
  while (n) {
    count += n & 1;
    n >>= 1;
  }
  return count;
}

}  // namespace

Bytes textToBytes(std::string_view text) {
  const std::string valid = js::decodeUtf8(Bytes(text.begin(), text.end()), /*ignoreBom=*/true);
  return Bytes(valid.begin(), valid.end());
}

std::string bytesToText(const Bytes& bytes) { return js::decodeUtf8(bytes, /*ignoreBom=*/false); }

std::string bytesToHex(const Bytes& bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (std::uint8_t b : bytes) {
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 0x0f]);
  }
  return out;
}

Bytes hexToBytes(std::string_view hex) {
  if (hex.size() % 2 != 0 || !std::all_of(hex.begin(), hex.end(), isHexDigit)) {
    throw std::invalid_argument("Invalid hex string: \"" + std::string(hex) + "\"");
  }
  Bytes bytes(hex.size() / 2);
  for (std::size_t i = 0; i < bytes.size(); i++) {
    bytes[i] = static_cast<std::uint8_t>(hexValue(hex[i * 2]) * 16 + hexValue(hex[i * 2 + 1]));
  }
  return bytes;
}

Bytes concatBytes(const std::vector<Bytes>& chunks) {
  Bytes out;
  for (const Bytes& chunk : chunks) {
    out.insert(out.end(), chunk.begin(), chunk.end());
  }
  return out;
}

Bytes xorBytes(const Bytes& a, const Bytes& b) {
  if (a.size() != b.size()) {
    throw std::invalid_argument("xorBytes: length mismatch (" + std::to_string(a.size()) + " vs " +
                                std::to_string(b.size()) + ")");
  }
  Bytes out(a.size());
  for (std::size_t i = 0; i < a.size(); i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

Bytes rotateBytesLeft(const Bytes& bytes, double by) {
  const double n = static_cast<double>(bytes.size());
  if (bytes.empty()) return {};
  const double shift = jsMod(jsMod(by, n) + n, n);
  // A non-integer (or NaN) shift makes every source index non-integer in JS, reading
  // `undefined` into the Uint8Array — i.e. all zeros. Integer shifts are the normal case.
  if (!(std::trunc(shift) == shift)) return Bytes(bytes.size(), 0);
  const auto s = static_cast<std::size_t>(shift);
  Bytes out(bytes.size());
  for (std::size_t i = 0; i < bytes.size(); i++) {
    out[i] = bytes[(i + s) % bytes.size()];
  }
  return out;
}

Bytes rotateBytesRight(const Bytes& bytes, double by) { return rotateBytesLeft(bytes, -by); }

Bytes rotateBitsLeft(const Bytes& bytes, double bitCount) {
  const double totalBits = static_cast<double>(bytes.size()) * 8;
  const double shift = jsMod(jsMod(bitCount, totalBits) + totalBits, totalBits);
  if (shift == 0) return bytes;

  const long long byteShift = toInt32(shift) >> 3;
  const long long bitShift = toInt32(shift) & 7;
  const Bytes rotatedBytes = rotateBytesLeft(bytes, static_cast<double>(byteShift));

  if (bitShift == 0) return rotatedBytes;

  const std::size_t n = rotatedBytes.size();
  Bytes out(n);
  for (std::size_t i = 0; i < n; i++) {
    const unsigned current = rotatedBytes[i];
    const unsigned next = rotatedBytes[(i + 1) % n];
    out[i] = static_cast<std::uint8_t>(((current << bitShift) | (next >> (8 - bitShift))) & 0xff);
  }
  return out;
}

Bytes rotateBitsRight(const Bytes& bytes, double bitCount) { return rotateBitsLeft(bytes, -bitCount); }

BitDiffResult bitDiff(const Bytes& a, const Bytes& b) {
  if (a.size() != b.size()) {
    throw std::invalid_argument("bitDiff: length mismatch (" + std::to_string(a.size()) + " vs " +
                                std::to_string(b.size()) + ")");
  }
  Bytes diffMask = xorBytes(a, b);
  std::size_t diffBits = 0;
  for (std::uint8_t byte : diffMask) {
    diffBits += popcount(byte);
  }
  return {diffBits, a.size() * 8, std::move(diffMask)};
}

Bytes randomBytes(std::size_t length) {
  // getentropy is the OS CSPRNG natively, and crypto.getRandomValues under Emscripten —
  // the same source the original TypeScript used. It caps each call at 256 bytes.
  Bytes out(length);
  for (std::size_t offset = 0; offset < length; offset += 256) {
    const std::size_t chunk = std::min<std::size_t>(256, length - offset);
    if (getentropy(out.data() + offset, chunk) != 0) {
      throw std::runtime_error("randomBytes: no secure random source available");
    }
  }
  return out;
}

}  // namespace cipher

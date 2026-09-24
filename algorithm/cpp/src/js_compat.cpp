#include "cipher/js_compat.hpp"

#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>

namespace cipher::js {

namespace {

void appendUtf8(std::string& out, std::uint32_t codePoint) {
  if (codePoint < 0x80) {
    out.push_back(static_cast<char>(codePoint));
  } else if (codePoint < 0x800) {
    out.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
    out.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
  } else if (codePoint < 0x10000) {
    out.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
    out.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
  } else {
    out.push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
    out.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
  }
}

/** The code points ECMAScript's StringToNumber trims: WhiteSpace and LineTerminator. */
bool isJsWhitespace(std::uint32_t c) {
  switch (c) {
    case 0x09: case 0x0A: case 0x0B: case 0x0C: case 0x0D: case 0x20: case 0xA0: case 0x1680:
    case 0x2028: case 0x2029: case 0x202F: case 0x205F: case 0x3000: case 0xFEFF:
      return true;
    default:
      return c >= 0x2000 && c <= 0x200A;
  }
}

/** Decodes one UTF-8 code point starting at `i` (input is assumed valid), advancing `i`. */
std::uint32_t nextCodePoint(std::string_view s, std::size_t& i) {
  const auto b = static_cast<unsigned char>(s[i]);
  int extra = b < 0x80 ? 0 : b < 0xE0 ? 1 : b < 0xF0 ? 2 : 3;
  std::uint32_t cp = extra == 0 ? b : extra == 1 ? (b & 0x1F) : extra == 2 ? (b & 0x0F) : (b & 0x07);
  i++;
  while (extra-- > 0 && i < s.size()) cp = (cp << 6) | (static_cast<unsigned char>(s[i++]) & 0x3F);
  return cp;
}

std::string_view trimJsWhitespace(std::string_view s) {
  std::size_t start = 0;
  while (start < s.size()) {
    std::size_t next = start;
    if (!isJsWhitespace(nextCodePoint(s, next))) break;
    start = next;
  }
  std::size_t end = start;
  for (std::size_t i = start; i < s.size();) {
    if (!isJsWhitespace(nextCodePoint(s, i))) end = i;
  }
  return s.substr(start, end - start);
}

double parseRadixInteger(std::string_view digits, int radix) {
  if (digits.empty()) return std::numeric_limits<double>::quiet_NaN();
  double value = 0;
  for (char c : digits) {
    int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'z') ? c - 'a' + 10 : (c >= 'A' && c <= 'Z') ? c - 'A' + 10 : 99;
    if (d >= radix) return std::numeric_limits<double>::quiet_NaN();
    value = value * radix + d;
  }
  return value;
}

/** StrDecimalLiteral: [+-] (digits [. digits] | . digits) [(e|E) [+-] digits], or [+-]Infinity. */
bool isStrDecimalLiteral(std::string_view s) {
  std::size_t i = 0;
  if (i < s.size() && (s[i] == '+' || s[i] == '-')) i++;
  if (s.substr(i) == "Infinity") return true;
  std::size_t intDigits = 0, fracDigits = 0;
  while (i < s.size() && s[i] >= '0' && s[i] <= '9') { i++; intDigits++; }
  if (i < s.size() && s[i] == '.') {
    i++;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') { i++; fracDigits++; }
  }
  if (intDigits + fracDigits == 0) return false;
  if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
    i++;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) i++;
    std::size_t expDigits = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') { i++; expDigits++; }
    if (expDigits == 0) return false;
  }
  return i == s.size();
}

}  // namespace

std::string numberToString(double value) {
  if (std::isnan(value)) return "NaN";
  if (value == 0) return "0";  // both +0 and -0
  if (value < 0) return "-" + numberToString(-value);
  if (std::isinf(value)) return "Infinity";

  // Shortest round-trip digits, as ECMAScript requires: value = 0.digits * 10^n.
  char buf[64];
  const auto [end, ec] = std::to_chars(buf, buf + sizeof buf, value, std::chars_format::scientific);
  (void)ec;
  const std::string sci(buf, end);  // e.g. "4.5e+00", "1e-07"
  const std::size_t ePos = sci.find('e');
  std::string digits;
  for (char c : sci.substr(0, ePos)) {
    if (c != '.') digits.push_back(c);
  }
  const int k = static_cast<int>(digits.size());
  const int n = std::stoi(sci.substr(ePos + 1)) + 1;

  if (k <= n && n <= 21) return digits + std::string(n - k, '0');
  if (0 < n && n <= 21) return digits.substr(0, n) + "." + digits.substr(n);
  if (-6 < n && n <= 0) return "0." + std::string(-n, '0') + digits;
  const int e = n - 1;
  const std::string exponent = std::string("e") + (e < 0 ? "-" : "+") + std::to_string(std::abs(e));
  if (k == 1) return digits + exponent;
  return digits.substr(0, 1) + "." + digits.substr(1) + exponent;
}

double stringToNumber(std::string_view text) {
  const std::string_view s = trimJsWhitespace(text);
  if (s.empty()) return 0;
  if (s.size() > 2 && s[0] == '0') {
    const char p = s[1];
    if (p == 'x' || p == 'X') return parseRadixInteger(s.substr(2), 16);
    if (p == 'o' || p == 'O') return parseRadixInteger(s.substr(2), 8);
    if (p == 'b' || p == 'B') return parseRadixInteger(s.substr(2), 2);
  }
  if (!isStrDecimalLiteral(s)) return std::numeric_limits<double>::quiet_NaN();
  const bool negative = s[0] == '-';
  const std::string_view unsigned_ = (s[0] == '+' || s[0] == '-') ? s.substr(1) : s;
  if (unsigned_ == "Infinity") return negative ? -INFINITY : INFINITY;
  return std::strtod(std::string(s).c_str(), nullptr);
}

std::string decodeUtf8(const Bytes& bytes, bool ignoreBom) {
  // https://encoding.spec.whatwg.org/#utf-8-decoder
  constexpr std::uint32_t REPLACEMENT = 0xFFFD;
  std::string out;
  std::uint32_t codePoint = 0;
  int bytesSeen = 0, bytesNeeded = 0;
  unsigned lower = 0x80, upper = 0xBF;
  bool bomSeen = ignoreBom;

  auto emit = [&](std::uint32_t cp) {
    if (!bomSeen) {
      bomSeen = true;
      if (cp == 0xFEFF) return;
    }
    appendUtf8(out, cp);
  };

  for (std::size_t i = 0; i < bytes.size();) {
    const unsigned b = bytes[i];
    if (bytesNeeded == 0) {
      i++;
      if (b <= 0x7F) {
        emit(b);
      } else if (b >= 0xC2 && b <= 0xDF) {
        bytesNeeded = 1;
        codePoint = b & 0x1F;
      } else if (b >= 0xE0 && b <= 0xEF) {
        if (b == 0xE0) lower = 0xA0;
        if (b == 0xED) upper = 0x9F;
        bytesNeeded = 2;
        codePoint = b & 0xF;
      } else if (b >= 0xF0 && b <= 0xF4) {
        if (b == 0xF0) lower = 0x90;
        if (b == 0xF4) upper = 0x8F;
        bytesNeeded = 3;
        codePoint = b & 0x7;
      } else {
        emit(REPLACEMENT);
      }
      continue;
    }
    if (b < lower || b > upper) {
      // Invalid continuation: emit U+FFFD and re-process this byte as a fresh lead byte.
      codePoint = 0;
      bytesNeeded = bytesSeen = 0;
      lower = 0x80;
      upper = 0xBF;
      emit(REPLACEMENT);
      continue;
    }
    i++;
    lower = 0x80;
    upper = 0xBF;
    codePoint = (codePoint << 6) | (b & 0x3F);
    if (++bytesSeen == bytesNeeded) {
      emit(codePoint);
      codePoint = 0;
      bytesNeeded = bytesSeen = 0;
    }
  }
  if (bytesNeeded != 0) emit(REPLACEMENT);
  return out;
}

}  // namespace cipher::js

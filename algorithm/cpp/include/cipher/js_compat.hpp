#pragma once

#include <string>
#include <string_view>

#include "cipher/bytes.hpp"

/**
 * Small pieces of JavaScript semantics the port needs to reproduce exactly, because
 * the original implementation's observable behavior depended on them: how numbers
 * print in error messages, how the CLI parses its rounds argument, and how
 * TextDecoder turns bytes into text.
 */
namespace cipher::js {

/** ECMAScript Number::toString(10), e.g. 4 -> "4", 4.5 -> "4.5", 1e-7 -> "1e-7", NaN -> "NaN". */
std::string numberToString(double value);

/** ECMAScript Number(string) (StringToNumber), e.g. " 5 " -> 5, "" -> 0, "0x10" -> 16, "abc" -> NaN. */
double stringToNumber(std::string_view text);

/**
 * The WHATWG Encoding Standard's UTF-8 decoder (what TextDecoder implements): every
 * invalid sequence becomes U+FFFD, and unless `ignoreBom` is set, one leading U+FEFF
 * is dropped. Returns the decoded text re-encoded as (always valid) UTF-8.
 */
std::string decodeUtf8(const Bytes& bytes, bool ignoreBom);

}  // namespace cipher::js

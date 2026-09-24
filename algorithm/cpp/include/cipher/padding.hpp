#pragma once

#include "cipher/bytes.hpp"

namespace cipher {

/**
 * PKCS#7 padding: pad with N bytes of value N, where N = bytes needed to reach the
 * next multiple of blockSize. If already a multiple, a full block of padding is added
 * (so padding is always present and always unambiguous to strip).
 */
Bytes pkcs7Pad(const Bytes& data, int blockSize);

/** Strips and validates PKCS#7 padding, throwing if the padding is malformed. */
Bytes pkcs7Unpad(const Bytes& data, int blockSize);

}  // namespace cipher

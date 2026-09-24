#include "cipher/padding.hpp"

#include <stdexcept>
#include <string>

namespace cipher {

Bytes pkcs7Pad(const Bytes& data, int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("pkcs7Pad: blockSize must be a positive integer, got " + std::to_string(blockSize));
  }
  const std::size_t padLength = blockSize - (data.size() % blockSize);
  Bytes out = data;
  out.insert(out.end(), padLength, static_cast<std::uint8_t>(padLength));
  return out;
}

Bytes pkcs7Unpad(const Bytes& data, int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("pkcs7Unpad: blockSize must be a positive integer, got " + std::to_string(blockSize));
  }
  if (data.empty() || data.size() % blockSize != 0) {
    throw std::invalid_argument("Padded data length must be a positive multiple of " + std::to_string(blockSize) +
                                ", got " + std::to_string(data.size()));
  }

  const int padLength = data.back();
  if (padLength < 1 || padLength > blockSize) {
    throw std::invalid_argument("Invalid PKCS#7 padding: bad pad length byte " + std::to_string(padLength));
  }

  for (std::size_t i = data.size() - padLength; i < data.size(); i++) {
    if (data[i] != padLength) {
      throw std::invalid_argument("Invalid PKCS#7 padding: padding bytes do not match.");
    }
  }

  return Bytes(data.begin(), data.end() - padLength);
}

}  // namespace cipher

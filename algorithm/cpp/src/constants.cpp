#include "cipher/constants.hpp"

#include <cmath>
#include <stdexcept>

#include "cipher/js_compat.hpp"

namespace cipher {

void assertValidRounds(double rounds) {
  const bool isInteger = std::isfinite(rounds) && std::trunc(rounds) == rounds;  // Number.isInteger
  if (!isInteger || rounds < MIN_ROUNDS || rounds > MAX_ROUNDS) {
    throw std::invalid_argument(invalidRoundsMessage(js::numberToString(rounds)));
  }
}

std::string invalidRoundsMessage(const std::string& roundsAsJsString) {
  return "rounds must be an integer between " + std::to_string(MIN_ROUNDS) + " and " + std::to_string(MAX_ROUNDS) +
         ", got " + roundsAsJsString;
}

}  // namespace cipher

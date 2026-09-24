/**
 * Minimal CLI for exercising the cipher in isolation, decoupled from the demo app.
 *
 * Usage:
 *   npm run cli -- encrypt "<plaintext>" "<key>" [rounds]
 *   npm run cli -- decrypt "<combined-hex>" "<key>" [rounds]
 */
#include <exception>
#include <iostream>
#include <optional>
#include <string>

#include "cipher/cipher.hpp"
#include "cipher/js_compat.hpp"

int main(int argc, char** argv) {
  const auto arg = [&](int i) { return i < argc ? std::string(argv[i]) : std::string(); };
  const std::string command = arg(1), text = arg(2), key = arg(3), roundsArg = arg(4);

  cipher::CipherOptions options;
  if (!roundsArg.empty()) options.rounds = cipher::js::stringToNumber(roundsArg);

  if (command.empty() || text.empty() || key.empty()) {
    std::cerr << "Usage: cipher-cli <encrypt|decrypt> <text> <key> [rounds]\n";
    return 1;
  }

  try {
    if (command == "encrypt") {
      const cipher::EncryptResult result = cipher::encrypt(text, key, options);
      std::cout << "IV:         " << result.ivHex << "\n";
      std::cout << "Ciphertext: " << result.ciphertextHex << "\n";
      std::cout << "Combined:   " << result.combinedHex << "\n";
    } else if (command == "decrypt") {
      const std::string plaintext = cipher::decrypt(text, key, options);
      std::cout << "Plaintext: " << plaintext << "\n";
    } else {
      std::cerr << "Unknown command \"" << command << "\". Use \"encrypt\" or \"decrypt\".\n";
      return 1;
    }
  } catch (const std::exception& err) {
    std::cerr << "Error: " << err.what() << "\n";
    return 1;
  }
  return 0;
}

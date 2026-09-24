#pragma once

/**
 * Public API of the algorithm. This is the locked contract the demo app (via the
 * WASM bindings in wasm/bindings.cpp and src/index.ts) and the CLI import against —
 * see CLAUDE.md / AGENTS.md at the repo root for the project-level overview.
 */

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "cipher/block_cipher.hpp"
#include "cipher/bytes.hpp"
#include "cipher/cbc.hpp"
#include "cipher/constants.hpp"
#include "cipher/key_schedule.hpp"
#include "cipher/padding.hpp"
#include "cipher/sbox.hpp"

namespace cipher {

struct CipherOptions {
  /** Number of rounds per block, in [MIN_ROUNDS, MAX_ROUNDS]. Default DEFAULT_ROUNDS. */
  std::optional<double> rounds;
};

struct EncryptResult {
  /** The random per-message IV, hex-encoded. Not secret. */
  std::string ivHex;
  /** The ciphertext blocks (excluding the IV), hex-encoded. */
  std::string ciphertextHex;
  /** ivHex + ciphertextHex concatenated — this is what decrypt()/decryptWithTrace() expect as input. */
  std::string combinedHex;
};

struct EncryptTrace {
  int rounds;
  Bytes masterKeyBytes;
  std::vector<Bytes> subkeys;
  Bytes iv;
  Bytes paddedPlainBytes;
  std::vector<CbcEncryptBlockTrace> blocks;
};

struct DecryptTrace {
  int rounds;
  Bytes masterKeyBytes;
  std::vector<Bytes> subkeys;
  Bytes iv;
  std::vector<CbcDecryptBlockTrace> blocks;
  Bytes paddedPlainBytes;
};

struct EncryptWithTraceResult {
  EncryptResult result;
  EncryptTrace trace;
};

struct DecryptWithTraceResult {
  std::string plaintext;
  DecryptTrace trace;
};

/**
 * Encrypts UTF-8 text with a passphrase-style key. Generates a fresh random IV per
 * call (see bytes.cpp randomBytes) — the same plaintext+key will therefore produce
 * different ciphertext every time, by design.
 */
EncryptResult encrypt(std::string_view plaintext, std::string_view key, const CipherOptions& options = {});

/** Same as encrypt(), but also returns the full round-by-round / block-by-block trace for visualization. */
EncryptWithTraceResult encryptWithTrace(std::string_view plaintext, std::string_view key, const CipherOptions& options = {});

/** Decrypts hex produced by encrypt() (IV concatenated with ciphertext blocks) back to UTF-8 text. */
std::string decrypt(std::string_view combinedHex, std::string_view key, const CipherOptions& options = {});

/** Same as decrypt(), but also returns the full round-by-round / block-by-block trace for visualization. */
DecryptWithTraceResult decryptWithTrace(std::string_view combinedHex, std::string_view key, const CipherOptions& options = {});

namespace detail {

/**
 * encryptWithTrace() with a caller-chosen IV instead of a random one. Test-only: it
 * lets the C++ tests compare a full encryption trace against the golden vectors.
 * Never use a fixed IV for real encryption (see SECURITY.md).
 */
EncryptWithTraceResult encryptWithTraceUsingIv(std::string_view plaintext, std::string_view key,
                                               const CipherOptions& options, const Bytes& iv);

}  // namespace detail

}  // namespace cipher

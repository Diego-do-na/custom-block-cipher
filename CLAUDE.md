# CLAUDE.md

Guidance for Claude Code (or any AI coding agent) working in this repo. This file
is kept in sync with [`AGENTS.md`](AGENTS.md) — same content, tool-agnostic name.
If they ever drift, treat both as needing a fix, not one as authoritative.

## What this project is

A university assignment: design, implement, and defend an **original, from-scratch
symmetric block cipher** that demonstrably uses **confusion** and **diffusion** — the
two foundational principles behind real ciphers like AES. It is not a production
cipher; see [`algorithm/SECURITY.md`](algorithm/SECURITY.md) for the full design
writeup, threat model, and known limitations.

The repo has two top-level folders with a hard boundary between them:

- **`/algorithm`** — the cipher itself. Written in **C++20** (`algorithm/cpp/`), zero
  runtime dependencies, no UI code, compiled to **WebAssembly** (via Emscripten) for
  JavaScript consumers. This is the actual deliverable being graded on
  cryptographic design. A thin, logic-free TypeScript binding
  (`algorithm/src/index.ts`) exposes it as the `@cipher/algorithm` package.
- **`/demo`** — a React + Vite web app for a 10-minute live presentation. It
  **imports** `/algorithm` as a workspace package (`@cipher/algorithm`) rather than
  reimplementing any cipher logic — see "Why the split" below.

The C++ code is a like-for-like port of the original TypeScript implementation
(commit `a517dab`). Its outputs are checked byte-for-byte against reference vectors
captured from that implementation (`algorithm/test/vectors/golden.json`), so the
design, parameters and observable behavior are unchanged.

### Why the split

The assignment is graded on the algorithm's design. Keeping it in an isolated,
dependency-free package means:

- It can be read, tested, and defended in isolation, without wading through UI code.
- The demo can never accidentally diverge from the "real" implementation — there is
  only one implementation, and the demo imports it directly (`demo/package.json`
  depends on `@cipher/algorithm`, resolved via npm workspaces to `../algorithm`,
  whose `src/index.ts` loads the WASM build of the C++ code).
- The demo's `RoundVisualizerSection` and `AvalancheSection` work by calling the
  *same* trace-producing functions (`encryptWithTrace`, `encryptCbc`, etc.) that
  the CLI and tests use — nothing in the UI recomputes cipher steps independently.

## The locked `/algorithm` interface

Everything the demo (or a future test/tool) should import lives in
`algorithm/src/index.ts`. The high-level contract:

```ts
interface CipherOptions {
  rounds?: number; // MIN_ROUNDS..MAX_ROUNDS, default DEFAULT_ROUNDS
}

interface EncryptResult {
  ivHex: string;          // random per-message IV, hex — not secret
  ciphertextHex: string;  // ciphertext blocks (excluding IV), hex
  combinedHex: string;    // ivHex + ciphertextHex — what decrypt() expects
}

function encrypt(plaintext: string, key: string, options?: CipherOptions): EncryptResult;
function decrypt(combinedHex: string, key: string, options?: CipherOptions): string;

// Same as encrypt()/decrypt(), but also return a full round-by-round,
// block-by-block trace for the demo's visualizers:
function encryptWithTrace(plaintext: string, key: string, options?: CipherOptions):
  { result: EncryptResult; trace: EncryptTrace };
function decryptWithTrace(combinedHex: string, key: string, options?: CipherOptions):
  { plaintext: string; trace: DecryptTrace };
```

All of these stay **synchronous**: `src/index.ts` loads the WASM module once, with a
top-level `await`, when the package is first imported. The same API exists natively
in C++ in `algorithm/cpp/include/cipher/cipher.hpp` (used by the CLI and the C++
tests).

Guarantee: `decrypt(encrypt(m, key).combinedHex, key) === m` for any UTF-8 string
`m` (including `''`) and any non-empty key string — **except** that a leading U+FEFF
(byte-order mark) in `m` is dropped on decrypt, because decoding follows
`TextDecoder`'s default behavior. That exception comes from the original
implementation and is kept on purpose (see `algorithm/SECURITY.md`). Verified in
`algorithm/cpp/test/cipher_test.cpp` and `algorithm/test/cipher.test.ts` across a
range of lengths and keys.

Lower-level building blocks are also exported from `algorithm/src/index.ts` for
direct use (the demo uses most of these — see `demo/src/components/*`):
`encryptBlock` / `decryptBlock` (single-block, with per-round trace), `encryptCbc`
/ `decryptCbc` (CBC mode, with per-block trace), `deriveMasterKeyBytes` /
`deriveSubkeys` (key schedule), `pkcs7Pad` / `pkcs7Unpad`, `SBOX` / `INV_SBOX`,
`bytesToHex` / `hexToBytes` / `textToBytes` / `bytesToText`, `bitDiff` (avalanche
bit-diff counter), `BLOCK_SIZE`, `ROTATE_BITS`, `DEFAULT_ROUNDS`, `MIN_ROUNDS`,
`MAX_ROUNDS`.

Changing any of these signatures is a breaking change for the demo — update all
layers together (C++ in `algorithm/cpp/`, the embind bridge in
`algorithm/cpp/wasm/bindings.cpp`, its types in `algorithm/wasm/generated/cipher.d.mts`,
and `algorithm/src/index.ts`), then re-run `npm run algorithm:test` and
`cd demo && npx tsc -b`.

## How to run things

Prerequisites (macOS):

- **Emscripten 6.0.10** — `brew install emscripten`. This is the tested version;
  `make wasm` warns if `em++ --version` reports anything else.
- A C++20 compiler and `make` for the native build and tests — Apple clang from the
  Xcode Command Line Tools (`xcode-select --install`).
- Node.js 20.19+ or 22.12+ (required by Vite), with npm.

From the repo root (npm workspaces — one `npm install` sets up both packages):

```bash
npm install

# algorithm: tests, typecheck, CLI
npm run algorithm:test          # native Catch2 suite, then the TS suite through WASM
npm run algorithm:typecheck
npm run algorithm:build:wasm    # rebuild the WASM module by hand (rarely needed)
npm run algorithm:cli -- encrypt "hello world" "my secret key"
npm run algorithm:cli -- decrypt <combined-hex> "my secret key"

# demo: dev server / production build
npm run demo:dev     # http://localhost:5173
npm run demo:build
```

The WASM module (`algorithm/wasm/generated/cipher.mjs`, a single file with the
`.wasm` embedded) is a **build output and is gitignored**. It's rebuilt from the C++
source automatically before `algorithm:test` (`pretest`), `demo:dev` (`predev`) and
`demo:build` (`prebuild`), so a fresh clone needs only Emscripten installed. Its
hand-written types, `cipher.d.mts`, are committed, so typechecking works without a
build. `algorithm/cpp/Makefile` builds everything (`make -C algorithm/cpp test | cli
| wasm | clean`). Native build output goes to `algorithm/cpp/build/` (gitignored).

`algorithm/scripts/generate-sbox.mjs` is a one-off generator, not run at runtime —
see `algorithm/cpp/include/cipher/sbox.hpp` for why the S-box is a hardcoded
constant rather than generated on each load. `algorithm/scripts/make-golden-vectors.ts`
is the one-off generator for the reference vectors; it has to run against the
original TypeScript sources (see its header comment).

## Status

Both `/algorithm` and `/demo` are complete and built sequentially in one pass
(not by parallel agents with separate ownership, despite that being one option
considered — the two packages are tightly coupled enough, and small enough, that
one consistent implementation was faster and avoided integration drift). The
algorithm was later ported from TypeScript to C++/WebAssembly without design changes.

- `/algorithm`: block cipher, key schedule, padding, CBC mode, CLI — in C++20.
  - Native Catch2 suite (`algorithm/cpp/test/`): 36 test cases, all passing. That is
    the 22 original tests ported 1:1, a new key-bit avalanche test, and 13
    reference-vector parity cases.
  - TS suite run through the WASM bindings (`algorithm/test/`): 39 tests, all
    passing (the same 23, plus 16 parity/bridge tests).
  - Typechecks clean.
- `/demo`: all four required sections built (How It Works explainer, live
  encrypt/decrypt, round-by-round + CBC-chain visualizer, avalanche bit-diff
  comparison). No changes to `demo/src` for the port. Typechecks clean, builds
  clean. Driven end-to-end with Playwright (dev server and production preview) with
  zero console errors.

## Conventions

- **Block size**: `BLOCK_SIZE = 8` bytes (`algorithm/cpp/include/cipher/constants.hpp`).
  The derived master key is also this length (see key schedule below).
- **Rounds**: `DEFAULT_ROUNDS = 6`, configurable per-call via `CipherOptions.rounds`,
  clamped to `[MIN_ROUNDS, MAX_ROUNDS] = [4, 6]` (`assertValidRounds` throws
  outside that range).
- **S-box**: `algorithm/cpp/src/sbox.cpp`. A random permutation of 0..255, generated
  once by `algorithm/scripts/generate-sbox.mjs` (seeded, reproducible) and
  hardcoded as a `std::array<std::uint8_t, 256>` constant — never regenerated at
  runtime, per Kerckhoffs's principle (it's a public constant of the algorithm, not
  a secret). `INV_SBOX` is derived from it once at program start.
- **Key schedule**: `algorithm/cpp/src/key_schedule.cpp`. Each round's subkey is a
  transformation of the *entire* master key (never a fragment/substring):
  `subkey[i] = rotateBitsLeft(masterKey, 3*(i+1)) XOR roundConstant(i)`.
- **Diffusion step**: rotates the block by `ROTATE_BITS = 3` bits (not a whole
  byte) — deliberately not byte-aligned, see
  `algorithm/cpp/include/cipher/constants.hpp` for why (a byte-aligned rotation
  can't mix byte *values*, only relocate them, and would fail the avalanche
  requirement entirely — this was caught by the avalanche test during the original
  implementation).
- **Trace types** (`EncryptRoundTrace`, `DecryptRoundTrace`, `CbcEncryptBlockTrace`,
  `CbcDecryptBlockTrace`, `EncryptTrace`, `DecryptTrace`) exist purely to let the
  demo visualize internal state without recomputing anything — they mirror the
  real encrypt/decrypt code paths, they don't replace them. They are C++ structs in
  `algorithm/cpp/include/cipher/`, turned into plain JS objects with the same field
  names and order (byte arrays as `Uint8Array`) by
  `algorithm/cpp/wasm/bindings.cpp`, and typed in `algorithm/src/types.ts`.
- **WASM bridge**: bridge functions never throw. Each returns `{ ok, value }` or
  `{ ok: false, error }`, and `algorithm/src/index.ts` throws a plain `Error` with
  the identical message. A JS exception thrown from inside WASM would skip
  restoring Emscripten's stack pointer and eventually crash the module. Plaintext
  and key cross the boundary as UTF-8 bytes, converted in `index.ts` with
  `TextEncoder`/`TextDecoder`, not as embind strings.
- **Demo styling**: Tailwind v4 (CSS-based `@theme` tokens in `demo/src/index.css`),
  chosen via the `ui-ux-pro-max` skill — Minimalism/Swiss-style, dark developer-tool
  palette, "Developer Mono" font pairing (JetBrains Mono for headings/hex data, IBM
  Plex Sans for body). No emoji icons — see `demo/src/icons/icons.tsx` for the
  hand-drawn SVG set. Confusion-related UI uses the violet `confusion` token,
  diffusion-related UI uses the cyan `diffusion` token, avalanche bit-diffs use the
  amber `changed` token, consistently across all four sections.

# @cipher/algorithm

From-scratch symmetric block cipher (custom S-box, multi-round confusion/diffusion,
CBC mode, PKCS#7 padding) for a university assignment. Written in C++20 and
compiled to WebAssembly for JavaScript consumers. No UI, no external crypto
libraries, no runtime dependencies. See [`SECURITY.md`](./SECURITY.md) for the
design writeup and [`../CLAUDE.md`](../CLAUDE.md) / [`../AGENTS.md`](../AGENTS.md)
for the locked public interface, prerequisites (Emscripten 6.0.10, a C++20
compiler) and repo-wide conventions.

## Usage

```bash
npm install          # from the repo root — sets up this workspace
npm run algorithm:test         # rebuilds WASM, then runs the C++ and TS suites
npm run algorithm:typecheck
npm run algorithm:cli -- encrypt "hello world" "my secret key"
npm run algorithm:cli -- decrypt <combined-hex> "my secret key"
```

```ts
import { encrypt, decrypt } from '@cipher/algorithm';

const { combinedHex } = encrypt('hello world', 'my secret key');
decrypt(combinedHex, 'my secret key'); // "hello world"
```

## Layout

```
cpp/
  include/cipher/     public headers (one per module; cipher.hpp is the full API)
  src/
    constants.cpp     round bounds check (constants themselves are in constants.hpp)
    sbox.cpp          hardcoded S-box + derived inverse S-box
    bytes.cpp         byte/bit helpers (hex, XOR, rotation, bit-diff, random bytes)
    key_schedule.cpp  master-key derivation + per-round subkey derivation
    block_cipher.cpp  single-block encrypt/decrypt (with per-round trace)
    padding.cpp       PKCS#7 pad/unpad
    cbc.cpp           CBC-mode encrypt/decrypt (with per-block trace)
    cipher.cpp        high-level encrypt/decrypt (with full traces)
    js_compat.cpp     the JS behaviors the original depended on (number formatting,
                      TextDecoder-style UTF-8 decoding)
  cli/main.cpp        minimal CLI
  wasm/bindings.cpp   embind bridge to JavaScript (no cipher logic)
  test/               Catch2 suites: ported unit/integration/avalanche tests + golden parity
  third_party/        Catch2 (amalgamated) and nlohmann/json — test-only
  Makefile            native lib/CLI/tests and the WASM build
src/
  index.ts            public TS API — loads the WASM module, forwards every call
  types.ts            result/trace shapes (mirror the C++ structs)
wasm/generated/
  cipher.mjs          WASM build output (gitignored, rebuilt automatically)
  cipher.d.mts        its hand-written types (committed)
scripts/
  generate-sbox.mjs       one-off S-box generator (not run at runtime)
  make-golden-vectors.ts  one-off reference-vector generator (runs against the original TS)
test/
  units.test.ts       S-box, padding, byte/bit helpers, key schedule — through WASM
  cipher.test.ts      block/CBC round-trips, error handling, avalanche — through WASM
  golden.test.ts      byte-for-byte parity with the original TS implementation, through WASM
  vectors/golden.json reference outputs captured from the original TS implementation
```

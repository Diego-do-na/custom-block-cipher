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

- **`/algorithm`** — the cipher itself. Pure TypeScript, zero runtime dependencies,
  no UI code. This is the actual deliverable being graded on cryptographic design.
- **`/demo`** — a React + Vite web app for a 10-minute live presentation. It
  **imports** `/algorithm` as a workspace package (`@cipher/algorithm`) rather than
  reimplementing any cipher logic — see "Why the split" below.

### Why the split

The assignment is graded on the algorithm's design. Keeping it in an isolated,
dependency-free package means:

- It can be read, tested, and defended in isolation, without wading through UI code.
- The demo can never accidentally diverge from the "real" implementation — there is
  only one implementation, and the demo imports it directly (`demo/package.json`
  depends on `@cipher/algorithm`, resolved via npm workspaces to `../algorithm`).
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

Guarantee: `decrypt(encrypt(m, key).combinedHex, key) === m` for any UTF-8 string
`m` (including `''`) and any non-empty key string. Verified in
`algorithm/test/cipher.test.ts` across a range of lengths and keys.

Lower-level building blocks are also exported from `algorithm/src/index.ts` for
direct use (the demo uses most of these — see `demo/src/components/*`):
`encryptBlock` / `decryptBlock` (single-block, with per-round trace), `encryptCbc`
/ `decryptCbc` (CBC mode, with per-block trace), `deriveMasterKeyBytes` /
`deriveSubkeys` (key schedule), `pkcs7Pad` / `pkcs7Unpad`, `SBOX` / `INV_SBOX`,
`bytesToHex` / `hexToBytes` / `textToBytes` / `bytesToText`, `bitDiff` (avalanche
bit-diff counter), `BLOCK_SIZE`, `ROTATE_BITS`, `DEFAULT_ROUNDS`, `MIN_ROUNDS`,
`MAX_ROUNDS`.

Changing any of these signatures is a breaking change for the demo — update both
sides together, and re-run `npm run algorithm:test` and `cd demo && npx tsc -b`.

## How to run things

From the repo root (npm workspaces — one `npm install` sets up both packages):

```bash
npm install

# algorithm: tests, typecheck, CLI
npm run algorithm:test
npm run --workspace algorithm typecheck
npm run algorithm:cli -- encrypt "hello world" "my secret key"
npm run algorithm:cli -- decrypt <combined-hex> "my secret key"

# demo: dev server / production build
npm run demo:dev     # http://localhost:5173
npm run demo:build
```

The algorithm package has no build step for development — Vite transpiles its
TypeScript source directly (its `package.json` `main`/`types` point at
`src/index.ts`). `algorithm/scripts/generate-sbox.mjs` is a one-off generator, not
run at runtime — see `algorithm/src/sbox.ts` for why the S-box is a hardcoded
constant rather than generated on each load.

## Status

Both `/algorithm` and `/demo` are complete and built sequentially in one pass
(not by parallel agents with separate ownership, despite that being one option
considered — the two packages are tightly coupled enough, and small enough, that
one consistent implementation was faster and avoided integration drift).

- `/algorithm`: block cipher, key schedule, padding, CBC mode, CLI, and 22 tests
  (unit + integration + avalanche) all passing. Typechecks clean.
- `/demo`: all four required sections built (How It Works explainer, live
  encrypt/decrypt, round-by-round + CBC-chain visualizer, avalanche bit-diff
  comparison). Typechecks clean, builds clean, manually driven end-to-end via
  Playwright with zero console errors.

## Conventions

- **Block size**: `BLOCK_SIZE = 8` bytes (`algorithm/src/constants.ts`). The
  derived master key is also this length (see key schedule below).
- **Rounds**: `DEFAULT_ROUNDS = 6`, configurable per-call via `CipherOptions.rounds`,
  clamped to `[MIN_ROUNDS, MAX_ROUNDS] = [4, 6]` (`assertValidRounds` throws
  outside that range).
- **S-box**: `algorithm/src/sbox.ts`. A random permutation of 0..255, generated
  once by `algorithm/scripts/generate-sbox.mjs` (seeded, reproducible) and
  hardcoded as a `readonly number[]` constant — never regenerated at runtime, per
  Kerckhoffs's principle (it's a public constant of the algorithm, not a secret).
  `INV_SBOX` is derived from it once at module load.
- **Key schedule**: `algorithm/src/keySchedule.ts`. Each round's subkey is a
  transformation of the *entire* master key (never a fragment/substring):
  `subkey[i] = rotateBitsLeft(masterKey, 3*(i+1)) XOR roundConstant(i)`.
- **Diffusion step**: rotates the block by `ROTATE_BITS = 3` bits (not a whole
  byte) — deliberately not byte-aligned, see `algorithm/src/constants.ts` for why
  (a byte-aligned rotation can't mix byte *values*, only relocate them, and would
  fail the avalanche requirement entirely — this was caught by
  `algorithm/test/cipher.test.ts`'s avalanche test during implementation).
- **Trace types** (`EncryptRoundTrace`, `DecryptRoundTrace`, `CbcEncryptBlockTrace`,
  `CbcDecryptBlockTrace`, `EncryptTrace`, `DecryptTrace`) exist purely to let the
  demo visualize internal state without recomputing anything — they mirror the
  real encrypt/decrypt code paths, they don't replace them.
- **Demo styling**: Tailwind v4 (CSS-based `@theme` tokens in `demo/src/index.css`),
  chosen via the `ui-ux-pro-max` skill — Minimalism/Swiss-style, dark developer-tool
  palette, "Developer Mono" font pairing (JetBrains Mono for headings/hex data, IBM
  Plex Sans for body). No emoji icons — see `demo/src/icons/icons.tsx` for the
  hand-drawn SVG set. Confusion-related UI uses the violet `confusion` token,
  diffusion-related UI uses the cyan `diffusion` token, avalanche bit-diffs use the
  amber `changed` token, consistently across all four sections.

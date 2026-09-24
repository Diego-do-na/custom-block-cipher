# Security notes

This document is the assignment's required security justification: what this
cipher does, what it deliberately doesn't attempt, and why.

## What this is, and isn't

This is a small, from-scratch educational block cipher built to demonstrate
**confusion** and **diffusion** — the two foundational principles behind real
ciphers like AES — not to withstand real cryptanalysis. Do not use it to protect
anything you actually care about. There is no peer review, no resistance analysis
against differential/linear cryptanalysis, and several intentional simplifications
noted below.

**Implementation.** The cipher is written in C++20 (`algorithm/cpp/`) and compiled
to WebAssembly for the browser demo. It is a like-for-like port of the original
TypeScript implementation (commit `a517dab`): every operation, parameter and
output is unchanged, which is verified byte-for-byte against reference vectors
captured from that implementation (`algorithm/test/vectors/golden.json`). The
design described below is exactly the design that was ported.

## The four required techniques

1. **Confusion #1 — XOR with a round subkey.** `algorithm/cpp/src/block_cipher.cpp`.
   XOR is its own inverse (`x ^ k ^ k == x`), so the same subkey that encrypts a
   round also decrypts it.
2. **Confusion #2 — S-box substitution.** `algorithm/cpp/src/sbox.cpp`. A fixed lookup
   table of 256 values, generated once as a random permutation of 0..255 (Fisher-
   Yates shuffle, seeded PRNG — see `algorithm/scripts/generate-sbox.mjs`) and
   hardcoded as a constant. **Known limitation**: unlike AES's S-box, which is
   mathematically constructed for provable resistance to differential and linear
   cryptanalysis, this S-box is *just* a random permutation. It supplies
   non-linearity (an attacker can't predict output from input via a linear
   formula), but no proven cryptanalytic resistance.
3. **Diffusion #1 — bit rotation.** `algorithm/cpp/src/block_cipher.cpp`, via
   `rotateBitsLeft`/`rotateBitsRight` in `algorithm/cpp/src/bytes.cpp`. The block is
   rotated by `ROTATE_BITS = 3` bits after each round's XOR+S-box step — **not** a
   whole-byte rotation. This matters: XOR and the S-box both act independently per
   byte position, so a whole-byte rotation (a pure position permutation) can never
   combine two bytes' *values* — it can only relocate a byte, meaning a
   single-bit difference would stay confined to one moving byte forever, no matter
   how many rounds ran. This was caught empirically: the first implementation used
   a whole-byte rotation and measured only ~6% avalanche (see git history / the
   original `rotateBytesLeft`-based version); switching to a non-byte-aligned bit
   rotation raised that to ~45%, because it spills bits across byte boundaries,
   which the *next* round's S-box then mixes non-linearly.
4. **Diffusion #2 — CBC chaining.** `algorithm/cpp/src/cbc.cpp`. Each plaintext block
   is XORed with the previous block's ciphertext (or the IV, for block 0) before
   the per-block rounds run. This is diffusion *across the whole message*: a
   change in block `i` cascades into every block after it, not just within one
   block.

## What's secret vs. public

- **Master key**: secret. Never displayed or logged as if public anywhere in this
  codebase or the demo app.
- **IV**: not secret. Generated fresh per encryption (`randomBytes` in
  `algorithm/cpp/src/bytes.cpp`, via `getentropy` — the OS CSPRNG natively, and
  `crypto.getRandomValues` in the WebAssembly build), shown/transmitted
  alongside the ciphertext (`encrypt()`'s `combinedHex` starts with the IV). Its
  only requirement is uniqueness per message under a given key — reusing an IV
  with the same key breaks the CBC diffusion guarantee (two messages with the same
  first block would produce the same first ciphertext block).
- **S-box**: not secret. A fixed constant of the algorithm, identical for every
  encryption. Per Kerckhoffs's principle, security is meant to rest entirely on
  the secrecy of the key, never on hiding the algorithm or its constants — which
  is also why the S-box ships as a public constant in source rather than being
  derived from the key.

## Other known, intentional limitations

- **Key derivation is not a cryptographic hash.** `deriveMasterKeyBytes` in
  `algorithm/cpp/src/key_schedule.cpp` folds an arbitrary-length key string down to
  `BLOCK_SIZE` bytes via simple XOR-folding, not a real hash function. This is
  deterministic (required) but not collision-resistant — different keys could in
  principle fold to the same bytes. Acceptable for a demo; not for real use.
- **The key schedule is not cryptographically strong**, by design (the assignment
  doesn't require it to be): `subkey[i] = rotateBitsLeft(masterKey, 3*(i+1)) XOR
  roundConstant(i)`. It only needs to make each round's subkey deterministic and
  visibly distinct from the raw key and from every other round's subkey, which it
  does — but related-key attacks are not a design goal here.
- **Block size (8 bytes) and round count (4-6) are small** relative to real
  ciphers (AES uses 16-byte blocks and 10-14 rounds), chosen for a demo where
  every byte/round needs to be legible on a projector, not for security margin.
- **No authentication.** This is confidentiality-only CBC, with no MAC/AEAD. A
  tampered ciphertext will usually (not always) be caught by PKCS#7 padding
  validation failing on decrypt, but that's an accident of padding, not a security
  guarantee — a real system would add a MAC.
- **Multiple rounds compound the avalanche effect**: each round re-applies both
  confusion and diffusion, and empirically (see the avalanche tests in
  `algorithm/cpp/test/cipher_test.cpp` and `algorithm/test/cipher.test.ts`) a single flipped plaintext or key bit changes roughly 40-50% of
  final ciphertext bits at the default 6 rounds — the intended, demonstrated
  property of a well-mixed block cipher.
- **A message starting with U+FEFF loses that character on decrypt.** Decryption
  turns the recovered bytes into text the way JavaScript's `TextDecoder` does,
  which drops one leading byte-order mark, so `decrypt(encrypt(m))` returns `m`
  without its first character when `m` begins with U+FEFF. This came from the
  original implementation and is kept unchanged. Every other UTF-8 string
  round-trips exactly.

# @cipher/algorithm

From-scratch symmetric block cipher (custom S-box, multi-round confusion/diffusion,
CBC mode, PKCS#7 padding) for a university assignment. No UI, no external crypto
libraries, no runtime dependencies. See [`SECURITY.md`](./SECURITY.md) for the
design writeup and [`../CLAUDE.md`](../CLAUDE.md) / [`../AGENTS.md`](../AGENTS.md)
for the locked public interface and repo-wide conventions.

## Usage

```bash
npm install          # from the repo root — sets up this workspace
npm run algorithm:test
npm run --workspace algorithm typecheck
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
src/
  constants.ts    block size, round bounds, ROTATE_BITS
  sbox.ts         hardcoded S-box + derived inverse S-box
  bytes.ts        byte/bit helpers (hex, XOR, rotation, bit-diff, random bytes)
  keySchedule.ts  master-key derivation + per-round subkey derivation
  blockCipher.ts  single-block encrypt/decrypt (with per-round trace)
  padding.ts      PKCS#7 pad/unpad
  cbc.ts          CBC-mode encrypt/decrypt (with per-block trace)
  index.ts        public API — see ../CLAUDE.md
  cli.ts          minimal CLI
scripts/
  generate-sbox.mjs  one-off S-box generator (not run at runtime)
test/
  units.test.ts   S-box, padding, byte/bit helpers, key schedule
  cipher.test.ts  block/CBC round-trips, error handling, avalanche effect
```

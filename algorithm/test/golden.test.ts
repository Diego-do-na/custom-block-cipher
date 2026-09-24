// Byte-for-byte parity, through the package entry point (C++ -> WASM -> src/index.ts,
// i.e. exactly what the demo calls), against test/vectors/golden.json: reference outputs
// captured from the original TypeScript implementation (see scripts/make-golden-vectors.ts).
// cpp/test/golden_test.cpp checks the same vectors against the native C++ build.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import * as cipher from '../src/index.js';

type Json = any;
const golden: Json = JSON.parse(readFileSync(new URL('./vectors/golden.json', import.meta.url), 'utf8'));

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const bytes = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, 'hex'));

/** Recursively turns every Uint8Array into hex, keeping key order, to match the golden encoding. */
function hexDeep(value: unknown): unknown {
  if (value instanceof Uint8Array) return hex(value);
  if (Array.isArray(value)) return value.map(hexDeep);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, hexDeep(v)]));
  }
  return value;
}

/** Deep equality *and* identical key order at every level (JSON.stringify is order-sensitive). */
function assertSameShape(actual: unknown, expected: unknown, message?: string) {
  const converted = hexDeep(actual);
  assert.deepStrictEqual(converted, expected, message);
  assert.equal(JSON.stringify(converted), JSON.stringify(expected), `field order differs: ${message ?? ''}`);
}

function num(v: number | string): number {
  return typeof v === 'number' ? v : v === '-0' ? -0 : Number(v);
}

function errorOf(fn: () => unknown): string | null {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof Error, 'errors must be plain Error instances, as before');
    return err.message;
  }
  return null;
}

const chunk = (b: Uint8Array) => Array.from({ length: b.length / 8 }, (_, j) => b.slice(j * 8, j * 8 + 8));

test('golden: constants, S-box and inverse S-box', () => {
  const { BLOCK_SIZE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS, ROTATE_BITS } = cipher;
  assert.deepStrictEqual({ BLOCK_SIZE, DEFAULT_ROUNDS, MIN_ROUNDS, MAX_ROUNDS, ROTATE_BITS }, golden.constants);
  assert.deepStrictEqual(cipher.SBOX, golden.sbox);
  assert.deepStrictEqual(cipher.INV_SBOX, golden.invSbox);
  assert.ok(Array.isArray(cipher.SBOX) && Array.isArray(cipher.INV_SBOX), 'S-boxes are plain arrays, as before');
});

test('golden: assertValidRounds accepts/rejects with identical messages', () => {
  for (const v of golden.assertValidRounds) {
    assert.equal(errorOf(() => cipher.assertValidRounds(num(v.rounds))), v.error, `rounds = ${v.rounds}`);
  }
});

test('golden: key schedule (master key folding + subkeys)', () => {
  for (const v of golden.masterKeys) assert.equal(hex(cipher.deriveMasterKeyBytes(v.key)), v.master, v.key);
  for (const v of golden.masterKeyErrors) assert.equal(errorOf(() => cipher.deriveMasterKeyBytes(v.key)), v.error);
  for (const v of golden.subkeys) assert.deepStrictEqual(cipher.deriveSubkeys(bytes(v.master), v.rounds).map(hex), v.subkeys);
});

test('golden: bit and byte rotation', () => {
  for (const v of golden.rotateBits) {
    assert.equal(hex(cipher.rotateBitsLeft(bytes(v.input), v.count)), v.left);
    assert.equal(hex(cipher.rotateBitsRight(bytes(v.input), v.count)), v.right);
  }
  for (const v of golden.rotateBytes) {
    assert.equal(hex(cipher.rotateBytesLeft(bytes(v.input), v.by)), v.left);
    assert.equal(hex(cipher.rotateBytesRight(bytes(v.input), v.by)), v.right);
  }
});

test('golden: byte helpers (xor, concat, hex, bitDiff)', () => {
  for (const v of golden.xor) {
    if ('error' in v) assert.equal(errorOf(() => cipher.xorBytes(bytes(v.a), bytes(v.b))), v.error);
    else assert.equal(hex(cipher.xorBytes(bytes(v.a), bytes(v.b))), v.out);
  }
  for (const v of golden.concat) assert.equal(hex(cipher.concatBytes(...v.parts.map(bytes))), v.out);
  for (const v of golden.hexToBytes) {
    if ('error' in v) assert.equal(errorOf(() => cipher.hexToBytes(v.hex)), v.error);
    else assert.equal(hex(cipher.hexToBytes(v.hex)), v.out);
  }
  for (const v of golden.bytesToHex) assert.equal(cipher.bytesToHex(Uint8Array.from(v.bytes)), v.hex);
  for (const v of golden.bitDiff) {
    if ('error' in v) {
      assert.equal(errorOf(() => cipher.bitDiff(bytes(v.a), bytes(v.b))), v.error);
      continue;
    }
    assertSameShape(cipher.bitDiff(bytes(v.a), bytes(v.b)), { diffBits: v.diffBits, totalBits: v.totalBits, diffMask: v.diffMask });
  }
});

test('golden: PKCS#7 pad/unpad', () => {
  for (const v of golden.pad) assert.equal(hex(cipher.pkcs7Pad(bytes(v.data), v.blockSize)), v.padded);
  for (const v of golden.unpad) {
    if ('error' in v) assert.equal(errorOf(() => cipher.pkcs7Unpad(bytes(v.data), v.blockSize)), v.error);
    else assert.equal(hex(cipher.pkcs7Unpad(bytes(v.data), v.blockSize)), v.out);
  }
});

test('golden: encryptBlock/decryptBlock full per-round traces (fields and field order)', () => {
  for (const v of golden.encryptBlock) {
    assertSameShape(cipher.encryptBlock(bytes(v.block), v.subkeys.map(bytes)), { output: v.output, trace: v.trace });
  }
  for (const v of golden.decryptBlock) {
    assertSameShape(cipher.decryptBlock(bytes(v.block), v.subkeys.map(bytes)), { output: v.output, trace: v.trace });
  }
  for (const v of golden.blockErrors) {
    const run = v.op === 'encryptBlock' ? cipher.encryptBlock : cipher.decryptBlock;
    assert.equal(errorOf(() => run(bytes(v.block), v.subkeys.map(bytes))), v.error);
  }
});

test('golden: encryptCbc/decryptCbc full per-block traces (fields and field order)', () => {
  for (const v of golden.encryptCbc) {
    const r = cipher.encryptCbc(v.plainBlocks.map(bytes), bytes(v.iv), v.subkeys.map(bytes));
    assertSameShape(r, { cipherBlocks: v.cipherBlocks, trace: v.trace });
  }
  for (const v of golden.decryptCbc) {
    const r = cipher.decryptCbc(v.cipherBlocks.map(bytes), bytes(v.iv), v.subkeys.map(bytes));
    assertSameShape(r, { plainBlocks: v.plainBlocks, trace: v.trace });
  }
});

test('golden: decryptWithTrace of TypeScript-produced ciphertext gives the same plaintext and trace', () => {
  for (const v of golden.messages) {
    const options = v.rounds === null ? {} : { rounds: v.rounds };
    const { plaintext, trace } = cipher.decryptWithTrace(v.result.combinedHex, v.key, options);
    assert.equal(plaintext, v.decrypted.plaintext, JSON.stringify(v.plaintext));
    assertSameShape(trace, v.decrypted.trace);
    assert.equal(cipher.decrypt(v.result.combinedHex, v.key, options), v.decrypted.plaintext);
  }
});

test('golden: encryptWithTrace matches the TypeScript output in everything but the random IV', () => {
  for (const v of golden.messages) {
    const options = v.rounds === null ? {} : { rounds: v.rounds };
    const { result, trace } = cipher.encryptWithTrace(v.plaintext, v.key, options);
    const et = v.encryptTrace;

    // IV-independent fields match exactly.
    assert.equal(trace.rounds, et.rounds);
    assert.equal(hex(trace.masterKeyBytes), et.masterKeyBytes);
    assert.deepStrictEqual(trace.subkeys.map(hex), et.subkeys);
    assert.equal(hex(trace.paddedPlainBytes), et.paddedPlainBytes);
    assert.deepStrictEqual(Object.keys(trace), Object.keys(et), 'EncryptTrace field order');
    assert.deepStrictEqual(Object.keys(result), Object.keys(v.result), 'EncryptResult field order');

    // With this run's IV, blocks are exactly what CBC produces; with the TypeScript run's IV,
    // CBC reproduces the TypeScript blocks and ciphertext byte-for-byte.
    assertSameShape(trace.blocks, hexDeep(cipher.encryptCbc(chunk(trace.paddedPlainBytes), trace.iv, trace.subkeys).trace));
    assert.equal(result.combinedHex, result.ivHex + result.ciphertextHex);
    assert.equal(result.ivHex, hex(trace.iv));
    const pinned = cipher.encryptCbc(chunk(bytes(et.paddedPlainBytes)), bytes(et.iv), trace.subkeys);
    assertSameShape(pinned.trace, et.blocks);
    assert.equal(et.iv + pinned.cipherBlocks.map(hex).join(''), v.result.combinedHex);

    // And the round trip holds (except for the documented leading-U+FEFF case).
    assert.equal(cipher.decrypt(result.combinedHex, v.key, options), v.decrypted.plaintext);
  }
});

test('golden: wrong-key decryption fails (or garbles) identically', () => {
  for (const v of golden.wrongKey) {
    const options = { rounds: v.rounds };
    if ('error' in v) {
      assert.equal(errorOf(() => cipher.decryptWithTrace(v.combinedHex, v.key, options)), v.error);
    } else {
      const { plaintext, trace } = cipher.decryptWithTrace(v.combinedHex, v.key, options);
      assert.equal(plaintext, v.plaintext);
      assertSameShape(trace, v.trace);
    }
  }
});

test('golden: high-level API errors (and their precedence) match', () => {
  for (const v of golden.apiErrors) {
    const options = v.rounds === null ? {} : { rounds: num(v.rounds) };
    const err = errorOf(() =>
      v.op === 'encrypt' ? cipher.encrypt(v.plaintext, v.key, options) : cipher.decrypt(v.combinedHex, v.key, options),
    );
    assert.equal(err, v.error, JSON.stringify(v));
  }
});

test('golden: avalanche bit counts with a fixed IV are identical', () => {
  for (const v of golden.avalanche) {
    const master = cipher.deriveMasterKeyBytes(v.key);
    const keys = cipher.deriveSubkeys(master, v.rounds);
    const padded = cipher.pkcs7Pad(cipher.textToBytes(v.plaintext), cipher.BLOCK_SIZE);
    const iv = bytes(v.iv);
    const base = cipher.concatBytes(...cipher.encryptCbc(chunk(padded), iv, keys).cipherBlocks);
    const flipTarget = (v.target === 'plaintext' ? padded : master).slice();
    flipTarget[v.byteIndex] ^= 1 << (7 - v.bitOffset);
    const flipped = v.target === 'plaintext'
      ? cipher.concatBytes(...cipher.encryptCbc(chunk(flipTarget), iv, keys).cipherBlocks)
      : cipher.concatBytes(...cipher.encryptCbc(chunk(padded), iv, cipher.deriveSubkeys(flipTarget, v.rounds)).cipherBlocks);
    const d = cipher.bitDiff(base, flipped);
    assert.equal(hex(base), v.baseCipher);
    assert.equal(hex(flipped), v.flippedCipher);
    assert.equal(d.diffBits, v.diffBits);
    assert.equal(d.totalBits, v.totalBits);
  }
});

test('golden: text <-> bytes conversions match TextEncoder/TextDecoder', () => {
  for (const v of golden.utf8Encode) {
    assert.equal(hex(cipher.textToBytes(String.fromCharCode(...v.units))), v.bytes);
  }
  for (const v of golden.utf8Decode) assert.equal(cipher.bytesToText(bytes(v.bytes)), v.text);
});

test('golden: decrypt() decodes arbitrary (even invalid) UTF-8 plaintext bytes exactly like the original', () => {
  // Encrypt each raw byte sequence directly (bypassing text encoding), then decrypt it
  // through the public API — which decodes on the C++ side — and compare with the text
  // the original TextDecoder produced for those bytes.
  const subkeys = cipher.deriveSubkeys(cipher.deriveMasterKeyBytes('utf8 key'), cipher.DEFAULT_ROUNDS);
  const iv = bytes('0011223344556677');
  for (const v of golden.utf8Decode) {
    const padded = cipher.pkcs7Pad(bytes(v.bytes), cipher.BLOCK_SIZE);
    const { cipherBlocks } = cipher.encryptCbc(chunk(padded), iv, subkeys);
    const combinedHex = hex(iv) + cipherBlocks.map(hex).join('');
    assert.equal(cipher.decrypt(combinedHex, 'utf8 key'), v.text, `bytes ${v.bytes}`);
  }
});

test('bridge: errors never corrupt the WASM module (many failures in a row, then a normal call)', () => {
  const { combinedHex } = cipher.encrypt('still works', 'key');
  for (let i = 0; i < 20000; i++) {
    assert.throws(() => cipher.decrypt('zz', 'key'));
    assert.throws(() => cipher.decrypt(combinedHex, 'wrong key'));
  }
  assert.equal(cipher.decrypt(combinedHex, 'key'), 'still works');
});

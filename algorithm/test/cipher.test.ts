import { test } from 'node:test';
import assert from 'node:assert/strict';

// These run against the package entry point — the C++ cipher compiled to WASM, through
// the exact binding layer the demo imports — rather than against the C++ directly
// (cpp/test/ ports these same cases to Catch2 for the native build).
import {
  encryptBlock,
  decryptBlock,
  deriveMasterKeyBytes,
  deriveSubkeys,
  encrypt,
  decrypt,
  encryptWithTrace,
  encryptCbc,
  pkcs7Pad,
  bitDiff,
  concatBytes,
  textToBytes,
  BLOCK_SIZE,
  MIN_ROUNDS,
  MAX_ROUNDS,
} from '../src/index.js';

test('encryptBlock/decryptBlock round-trip for arbitrary blocks and round counts', () => {
  const master = deriveMasterKeyBytes('block level key');
  for (let rounds = MIN_ROUNDS; rounds <= MAX_ROUNDS; rounds++) {
    const subkeys = deriveSubkeys(master, rounds);
    const block = Uint8Array.from({ length: BLOCK_SIZE }, (_, i) => (i * 37 + rounds) & 0xff);
    const { output: cipherBlock } = encryptBlock(block, subkeys);
    const { output: plainBlock } = decryptBlock(cipherBlock, subkeys);
    assert.deepEqual(plainBlock, block, `round-trip failed at rounds=${rounds}`);
  }
});

test('decrypt(encrypt(m, key)) === m for a range of message lengths', () => {
  const messages = [
    '',
    'a',
    'exactly8',
    'this message is definitely longer than one block',
    'unicode: café ☕ 日本語',
    'x'.repeat(100),
  ];

  for (const message of messages) {
    const { combinedHex } = encrypt(message, 'a reasonably good passphrase');
    const decrypted = decrypt(combinedHex, 'a reasonably good passphrase');
    assert.equal(decrypted, message, `round-trip failed for message: ${JSON.stringify(message)}`);
  }
});

test('decrypt(encrypt(m, key)) === m for a range of keys', () => {
  const keys = ['a', 'short', 'a much longer passphrase than one block worth of bytes', '密码'];
  for (const key of keys) {
    const { combinedHex } = encrypt('constant message', key);
    assert.equal(decrypt(combinedHex, key), 'constant message');
  }
});

test('encrypting the same message+key twice yields different ciphertext (random IV)', () => {
  const a = encrypt('same message', 'same key');
  const b = encrypt('same message', 'same key');
  assert.notEqual(a.combinedHex, b.combinedHex);
  assert.equal(decrypt(a.combinedHex, 'same key'), 'same message');
  assert.equal(decrypt(b.combinedHex, 'same key'), 'same message');
});

test('decrypting with the wrong key does not silently return the original plaintext', () => {
  const { combinedHex } = encrypt('a secret message', 'right key');
  // A wrong key almost always corrupts PKCS#7 padding, so this usually throws;
  // on the rare occasion padding happens to validate, it must not recover the message.
  try {
    assert.notEqual(decrypt(combinedHex, 'wrong key'), 'a secret message');
  } catch (err) {
    assert.match((err as Error).message, /padding/i);
  }
});

test('rejects an out-of-range round count', () => {
  assert.throws(() => encrypt('hi', 'key', { rounds: MIN_ROUNDS - 1 }));
  assert.throws(() => encrypt('hi', 'key', { rounds: MAX_ROUNDS + 1 }));
});

test('rejects malformed ciphertext hex', () => {
  assert.throws(() => decrypt('not-hex', 'key'));
  assert.throws(() => decrypt('ab', 'key')); // shorter than one IV block
});

test('avalanche effect: a single flipped plaintext bit changes a large share of ciphertext bits', () => {
  const key = 'avalanche test key';
  const message = 'The quick brown fox jumps over the lazy dog';

  const { result: base, trace: baseTrace } = encryptWithTrace(message, key);

  const flippedBytes = textToBytes(message).slice();
  flippedBytes[0] ^= 0b00000001; // flip the lowest bit of the first byte
  const flippedMessage = new TextDecoder().decode(flippedBytes);

  // Reuse the same IV as the base encryption so only the plaintext bit differs.
  const rounds = baseTrace.rounds;
  const { trace: flippedTrace } = encryptWithTrace(flippedMessage, key, { rounds });

  const baseCipher = concatBytes(...baseTrace.blocks.map((b) => b.cipherBlock));

  // Re-encrypt manually with the same IV/subkeys as base to isolate the plaintext-bit effect.
  const paddedFlipped = pkcs7Pad(flippedBytes, BLOCK_SIZE);
  const flippedBlocks = chunkBytes(paddedFlipped, BLOCK_SIZE);
  const { cipherBlocks: flippedCipherBlocks } = encryptCbc(flippedBlocks, baseTrace.iv, baseTrace.subkeys);
  const flippedCipher = concatBytes(...flippedCipherBlocks);

  const { diffBits, totalBits } = bitDiff(baseCipher, flippedCipher);
  const ratio = diffBits / totalBits;

  // A well-mixed cipher should land near 50%; for a small educational cipher we
  // just assert a strong, unmistakable avalanche rather than pin an exact number.
  assert.ok(ratio > 0.25, `expected a strong avalanche effect, got ${(ratio * 100).toFixed(1)}% bits changed`);
  void base;
});

// NEW in the C++ port (not in the original 22 tests): SECURITY.md says a flipped *key*
// bit also avalanches, which the original suite never exercised.
test('avalanche effect: a single flipped key bit changes a large share of ciphertext bits', () => {
  const key = 'avalanche test key';
  const message = 'The quick brown fox jumps over the lazy dog';

  const { trace: baseTrace } = encryptWithTrace(message, key);
  const baseCipher = concatBytes(...baseTrace.blocks.map((b) => b.cipherBlock));

  // Same IV and plaintext as base; only the lowest bit of the first master-key byte differs.
  const flippedMasterKey = baseTrace.masterKeyBytes.slice();
  flippedMasterKey[0] ^= 0b00000001;
  const flippedSubkeys = deriveSubkeys(flippedMasterKey, baseTrace.rounds);
  const plainBlocks = chunkBytes(baseTrace.paddedPlainBytes, BLOCK_SIZE);
  const { cipherBlocks } = encryptCbc(plainBlocks, baseTrace.iv, flippedSubkeys);
  const flippedCipher = concatBytes(...cipherBlocks);

  const { diffBits, totalBits } = bitDiff(baseCipher, flippedCipher);
  const ratio = diffBits / totalBits;

  assert.ok(ratio > 0.25, `expected a strong avalanche effect, got ${(ratio * 100).toFixed(1)}% bits changed`);
});

function chunkBytes(bytes: Uint8Array, size: number): Uint8Array[] {
  const blocks: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += size) blocks.push(bytes.slice(i, i + size));
  return blocks;
}

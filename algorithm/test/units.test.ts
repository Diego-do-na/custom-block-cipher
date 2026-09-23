import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SBOX, INV_SBOX } from '../src/sbox.js';
import { pkcs7Pad, pkcs7Unpad } from '../src/padding.js';
import { deriveMasterKeyBytes, deriveSubkeys } from '../src/keySchedule.js';
import { rotateBitsLeft, rotateBytesLeft, rotateBytesRight, xorBytes, bitDiff, bytesToHex, hexToBytes } from '../src/bytes.js';
import { BLOCK_SIZE } from '../src/constants.js';

test('SBOX is a permutation of 0..255', () => {
  const seen = new Set(SBOX);
  assert.equal(seen.size, 256);
  assert.equal(Math.min(...SBOX), 0);
  assert.equal(Math.max(...SBOX), 255);
});

test('INV_SBOX exactly inverts SBOX', () => {
  for (let i = 0; i < 256; i++) {
    assert.equal(INV_SBOX[SBOX[i]], i);
  }
});

test('pkcs7Pad/Unpad round-trips for every length in a block', () => {
  const blockSize = 8;
  for (let len = 0; len < 20; len++) {
    const data = new Uint8Array(len).map((_, i) => i & 0xff);
    const padded = pkcs7Pad(data, blockSize);
    assert.equal(padded.length % blockSize, 0);
    assert.ok(padded.length > data.length, 'always adds at least one byte of padding');
    const unpadded = pkcs7Unpad(padded, blockSize);
    assert.deepEqual(unpadded, data);
  }
});

test('pkcs7Unpad rejects malformed padding', () => {
  assert.throws(() => pkcs7Unpad(new Uint8Array([1, 2, 3, 0]), 8), /padded data length/i);
  assert.throws(() => pkcs7Unpad(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 0]), 8), /bad pad length/i);
  assert.throws(() => pkcs7Unpad(new Uint8Array([1, 2, 3, 4, 5, 2, 9, 2]), 8), /padding bytes do not match/i);
});

test('rotateBytesLeft/Right are inverses', () => {
  const bytes = Uint8Array.from([10, 20, 30, 40, 50]);
  assert.deepEqual(rotateBytesRight(rotateBytesLeft(bytes, 2), 2), bytes);
});

test('rotateBitsLeft by a full byte-array width is the identity', () => {
  const bytes = Uint8Array.from([1, 2, 3, 4]);
  assert.deepEqual(rotateBitsLeft(bytes, 32), bytes);
});

test('rotateBitsLeft actually mixes bits across byte boundaries', () => {
  const bytes = Uint8Array.from([0b10000000, 0b00000000]);
  assert.deepEqual(rotateBitsLeft(bytes, 1), Uint8Array.from([0b00000000, 0b00000001]));
});

test('xorBytes is its own inverse', () => {
  const a = Uint8Array.from([1, 2, 3]);
  const b = Uint8Array.from([9, 8, 7]);
  assert.deepEqual(xorBytes(xorBytes(a, b), b), a);
});

test('bitDiff counts differing bits correctly', () => {
  const a = Uint8Array.from([0b00000000]);
  const b = Uint8Array.from([0b00000011]);
  const { diffBits, totalBits } = bitDiff(a, b);
  assert.equal(diffBits, 2);
  assert.equal(totalBits, 8);
});

test('hex round-trip', () => {
  const bytes = Uint8Array.from([0, 1, 254, 255, 16]);
  assert.deepEqual(hexToBytes(bytesToHex(bytes)), bytes);
});

test('deriveMasterKeyBytes is deterministic and fills BLOCK_SIZE bytes', () => {
  const a = deriveMasterKeyBytes('correct horse battery staple');
  const b = deriveMasterKeyBytes('correct horse battery staple');
  assert.equal(a.length, BLOCK_SIZE);
  assert.deepEqual(a, b);
});

test('deriveMasterKeyBytes differs for different keys', () => {
  const a = deriveMasterKeyBytes('key-one');
  const b = deriveMasterKeyBytes('key-two');
  assert.notDeepEqual(a, b);
});

test('deriveSubkeys produces one visibly distinct subkey per round', () => {
  const master = deriveMasterKeyBytes('a shared secret');
  const subkeys = deriveSubkeys(master, 6);
  assert.equal(subkeys.length, 6);

  const hexes = subkeys.map(bytesToHex);
  assert.equal(new Set(hexes).size, 6, 'all subkeys should be distinct from each other');
  for (const hex of hexes) {
    assert.notEqual(hex, bytesToHex(master), 'subkey should differ from the raw master key');
  }
});

test('deriveSubkeys is deterministic for the same master key', () => {
  const master = deriveMasterKeyBytes('deterministic please');
  assert.deepEqual(deriveSubkeys(master, 5), deriveSubkeys(master, 5));
});

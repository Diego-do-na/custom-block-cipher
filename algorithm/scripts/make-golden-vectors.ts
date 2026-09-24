// One-off generator for algorithm/test/vectors/golden.json: reference outputs captured
// from the ORIGINAL TypeScript implementation of the cipher (commit a517dab), which the
// C++ port (native and WASM) must reproduce byte-for-byte.
//
// The TypeScript implementation no longer lives in this repo, so to regenerate, check
// out that commit alongside and point --ref at its algorithm/src directory:
//
//   git worktree add ../cipher-ts-ref a517dab
//   npx tsx algorithm/scripts/make-golden-vectors.ts \
//     --ref ../cipher-ts-ref/algorithm/src --out algorithm/test/vectors/golden.json
//
// Every "random" input below comes from a seeded PRNG, so the file is reproducible.

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const SOURCE_COMMIT = 'a517dab';
const SEED = 0x901d_e7ec;

function arg(name: string): string {
  const i = process.argv.indexOf(name);
  if (i === -1 || !process.argv[i + 1]) {
    throw new Error(`Usage: make-golden-vectors.ts --ref <ts algorithm/src dir> --out <golden.json>`);
  }
  return process.argv[i + 1];
}

const refDir = resolve(arg('--ref'));
const outPath = resolve(arg('--out'));
const ref: any = await import(pathToFileURL(resolve(refDir, 'index.ts')).href);

// --- helpers ---------------------------------------------------------------------------

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(SEED);
const randInt = (lo: number, hi: number) => lo + Math.floor(rand() * (hi - lo + 1));
const randBytes = (n: number) => Uint8Array.from({ length: n }, () => randInt(0, 255));

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const utf8Hex = (s: string): string => hex(new TextEncoder().encode(s));

/** JSON can't hold NaN/±Infinity/-0, so non-finite and negative-zero numbers are stored as strings. */
function num(n: number): number | string {
  if (Number.isNaN(n)) return 'NaN';
  if (n === Infinity) return 'Infinity';
  if (n === -Infinity) return '-Infinity';
  if (Object.is(n, -0)) return '-0';
  return n;
}

function capture<T>(fn: () => T): { ok: T } | { error: string } {
  try {
    return { ok: fn() };
  } catch (err) {
    return { error: (err as Error).message };
  }
}

function encRounds(trace: any[]) {
  return trace.map((r) => ({
    round: r.round,
    subkey: hex(r.subkey),
    input: hex(r.input),
    afterXor: hex(r.afterXor),
    afterSub: hex(r.afterSub),
    afterRotate: hex(r.afterRotate),
  }));
}

function decRounds(trace: any[]) {
  return trace.map((r) => ({
    round: r.round,
    subkey: hex(r.subkey),
    input: hex(r.input),
    afterUnrotate: hex(r.afterUnrotate),
    afterInvSub: hex(r.afterInvSub),
    afterXor: hex(r.afterXor),
  }));
}

function cbcEncTrace(trace: any[]) {
  return trace.map((b) => ({
    index: b.index,
    plainBlock: hex(b.plainBlock),
    previous: hex(b.previous),
    inputBlock: hex(b.inputBlock),
    rounds: encRounds(b.rounds),
    cipherBlock: hex(b.cipherBlock),
  }));
}

function cbcDecTrace(trace: any[]) {
  return trace.map((b) => ({
    index: b.index,
    cipherBlock: hex(b.cipherBlock),
    previous: hex(b.previous),
    rounds: decRounds(b.rounds),
    decryptedBlock: hex(b.decryptedBlock),
    plainBlock: hex(b.plainBlock),
  }));
}

function decryptTrace(t: any) {
  return {
    rounds: t.rounds,
    masterKeyBytes: hex(t.masterKeyBytes),
    subkeys: t.subkeys.map(hex),
    iv: hex(t.iv),
    blocks: cbcDecTrace(t.blocks),
    paddedPlainBytes: hex(t.paddedPlainBytes),
  };
}

function randomText(): string {
  const pools = ['abcdefghijklmnopqrstuvwxyz ', 'ABCXYZ0123456789!?.,', 'éüñç', '☕€∑', '日本語密码', '😀🔐'];
  const len = randInt(0, 40);
  let s = '';
  for (let i = 0; i < len; i++) {
    const pool = Array.from(pools[randInt(0, pools.length - 1)]);
    s += pool[randInt(0, pool.length - 1)];
  }
  return s;
}

// --- vectors ---------------------------------------------------------------------------

const constants = {
  BLOCK_SIZE: ref.BLOCK_SIZE,
  DEFAULT_ROUNDS: ref.DEFAULT_ROUNDS,
  MIN_ROUNDS: ref.MIN_ROUNDS,
  MAX_ROUNDS: ref.MAX_ROUNDS,
  ROTATE_BITS: ref.ROTATE_BITS,
};

const assertValidRounds = [4, 5, 6, 3, 7, 0, -1, -0, 4.5, 5.000001, 0.1, 1e-7, 123456789, 1e21, 1.5e300, NaN, Infinity, -Infinity].map(
  (r) => {
    const res = capture(() => ref.assertValidRounds(r));
    return { rounds: num(r), error: 'error' in res ? res.error : null };
  },
);

const keyStrings = [
  'a', 'short', 'exactly8', 'nine char', 'correct horse battery staple', 'a shared secret',
  'a much longer passphrase than one block worth of bytes', '密码', 'café ☕', '🔐🔐',
  'my secret key', 'avalanche test key', 'block level key', 'key-one', 'key-two', ' ', '\u0000',
  ...Array.from({ length: 20 }, randomText).filter((s) => s.length > 0),
];
const masterKeys = keyStrings.map((key) => ({ key, keyUtf8: utf8Hex(key), master: hex(ref.deriveMasterKeyBytes(key)) }));
const masterKeyErrors = [{ key: '', keyUtf8: '', error: (capture(() => ref.deriveMasterKeyBytes('')) as { error: string }).error }];

const subkeys: unknown[] = [];
for (let len = 0; len <= 16; len++) {
  const master = randBytes(len);
  for (let rounds = 0; rounds <= 8; rounds++) {
    subkeys.push({ master: hex(master), rounds, subkeys: ref.deriveSubkeys(master, rounds).map(hex) });
  }
}

const rotateBits: unknown[] = [];
const rotateBytes: unknown[] = [];
for (let len = 0; len <= 9; len++) {
  const data = randBytes(len);
  for (let count = -70; count <= 70; count++) {
    rotateBits.push({ input: hex(data), count, left: hex(ref.rotateBitsLeft(data, count)), right: hex(ref.rotateBitsRight(data, count)) });
  }
  if (len > 0) {
    for (let by = -12; by <= 12; by++) {
      rotateBytes.push({ input: hex(data), by, left: hex(ref.rotateBytesLeft(data, by)), right: hex(ref.rotateBytesRight(data, by)) });
    }
  }
}

const xor = [
  ...Array.from({ length: 20 }, () => {
    const n = randInt(0, 12);
    const a = randBytes(n);
    const b = randBytes(n);
    return { a: hex(a), b: hex(b), out: hex(ref.xorBytes(a, b)) };
  }),
  { a: '0102', b: '010203', error: (capture(() => ref.xorBytes(randBytes(2), randBytes(3))) as { error: string }).error },
];

const concat = [[], ['01'], ['', '0203', ''], ['aabb', 'cc', 'ddeeff']].map((parts) => ({
  parts,
  out: hex(ref.concatBytes(...parts.map((p) => Uint8Array.from(Buffer.from(p, 'hex'))))),
}));

const pad: unknown[] = [];
for (const blockSize of [1, 2, 3, 7, 8, 9, 16, 255, 256, 300]) {
  for (let len = 0; len <= 20; len++) {
    const data = randBytes(len);
    pad.push({ data: hex(data), blockSize, padded: hex(ref.pkcs7Pad(data, blockSize)) });
  }
}

const unpadInputs: Array<[string, number]> = [
  ['', 8], ['01020300', 8], ['0102030405060700', 8], ['0102030405020902', 8], ['0102030405060709', 8],
  ['0102030405060708', 8], ['0808080808080808', 8], ['0102030405060701', 8], ['0102030405060202', 8],
  ['01020304050603030303', 8], ['aabbccddeeff0102' + '0303030303030303', 8], ['01', 1], ['02', 1], ['0202', 2],
];
for (let i = 0; i < 40; i++) {
  const blockSize = [1, 2, 4, 8, 16][randInt(0, 4)];
  const data = randBytes(blockSize * randInt(0, 3));
  if (data.length > 0 && rand() < 0.5) data[data.length - 1] = randInt(0, blockSize + 1);
  unpadInputs.push([hex(data), blockSize]);
}
const unpad = unpadInputs.map(([data, blockSize]) => {
  const res = capture(() => ref.pkcs7Unpad(Uint8Array.from(Buffer.from(data, 'hex')), blockSize));
  return 'ok' in res ? { data, blockSize, out: hex(res.ok as Uint8Array) } : { data, blockSize, error: res.error };
});

const hexToBytes = ['', '00', 'ff', 'ABcd', '0123456789abcdefABCDEF', 'abc', 'zz', '0x12', ' 12', '12 ', 'é1', 'g0', '-1', '1-'].map((h) => {
  const res = capture(() => ref.hexToBytes(h));
  return 'ok' in res ? { hex: h, out: hex(res.ok as Uint8Array) } : { hex: h, error: res.error };
});
const bytesToHex = Array.from({ length: 10 }, () => {
  const b = randBytes(randInt(0, 10));
  return { bytes: Array.from(b), hex: ref.bytesToHex(b) };
});

const bitDiff = [
  ...Array.from({ length: 30 }, () => {
    const n = randInt(0, 16);
    const a = randBytes(n);
    const b = randBytes(n);
    const d = ref.bitDiff(a, b);
    return { a: hex(a), b: hex(b), diffBits: d.diffBits, totalBits: d.totalBits, diffMask: hex(d.diffMask) };
  }),
  { a: '00', b: '0000', error: (capture(() => ref.bitDiff(new Uint8Array(1), new Uint8Array(2))) as { error: string }).error },
];

const encryptBlock: unknown[] = [];
const decryptBlock: unknown[] = [];
for (let i = 0; i < 200; i++) {
  const rounds = randInt(0, 8);
  const keys = i % 2 === 0
    ? Array.from({ length: rounds }, () => randBytes(8))
    : ref.deriveSubkeys(randBytes(8), rounds);
  const block = randBytes(8);
  const enc = ref.encryptBlock(block, keys);
  encryptBlock.push({ block: hex(block), subkeys: keys.map(hex), output: hex(enc.output), trace: encRounds(enc.trace) });
  const dec = ref.decryptBlock(block, keys);
  decryptBlock.push({ block: hex(block), subkeys: keys.map(hex), output: hex(dec.output), trace: decRounds(dec.trace) });
}

const blockErrors = [
  { op: 'encryptBlock', block: '01020304050607', subkeys: [hex(randBytes(8))] },
  { op: 'decryptBlock', block: '010203040506070809', subkeys: [hex(randBytes(8))] },
  { op: 'encryptBlock', block: '0102030405060708', subkeys: ['01020304'] },
  { op: 'decryptBlock', block: '0102030405060708', subkeys: ['0102030405060708090a'] },
].map((c) => {
  const block = Uint8Array.from(Buffer.from(c.block, 'hex'));
  const keys = c.subkeys.map((k) => Uint8Array.from(Buffer.from(k, 'hex')));
  const res = capture(() => (c.op === 'encryptBlock' ? ref.encryptBlock(block, keys) : ref.decryptBlock(block, keys)));
  return { ...c, error: (res as { error: string }).error };
});

const encryptCbc: unknown[] = [];
const decryptCbc: unknown[] = [];
for (let i = 0; i < 60; i++) {
  const keys = ref.deriveSubkeys(randBytes(8), randInt(4, 6));
  const iv = randBytes(8);
  const blocks = Array.from({ length: randInt(0, 6) }, () => randBytes(8));
  const enc = ref.encryptCbc(blocks, iv, keys);
  encryptCbc.push({ plainBlocks: blocks.map(hex), iv: hex(iv), subkeys: keys.map(hex), cipherBlocks: enc.cipherBlocks.map(hex), trace: cbcEncTrace(enc.trace) });
  const dec = ref.decryptCbc(blocks, iv, keys);
  decryptCbc.push({ cipherBlocks: blocks.map(hex), iv: hex(iv), subkeys: keys.map(hex), plainBlocks: dec.plainBlocks.map(hex), trace: cbcDecTrace(dec.trace) });
}

// Full encrypt -> decrypt through the high-level API. The IV is random, so what's
// pinned is: the TS-produced ciphertext itself (the port must decrypt it to the same
// plaintext + trace), and every IV-independent part of the encrypt trace.
const fixedMessages = [
  '', 'a', 'exactly8', 'hello world', 'this message is definitely longer than one block',
  'unicode: café ☕ 日本語', 'x'.repeat(100), 'Meet me at midnight.', 'Attack at dawn, not dusk.', 'two blocks!',
  'The quick brown fox jumps over the lazy dog', '\uFEFFhi', 'a\uFEFFb', '\u0000\u0001\u0002',
];
const messages: unknown[] = [];
const allMessages = [...fixedMessages, ...Array.from({ length: 40 }, randomText)];
allMessages.forEach((plaintext, i) => {
  const key = keyStrings[i % keyStrings.length];
  const rounds = i % 4 === 3 ? null : [4, 5, 6][i % 3];
  const options = rounds === null ? {} : { rounds };
  const { result, trace } = ref.encryptWithTrace(plaintext, key, options);
  const decrypted = ref.decryptWithTrace(result.combinedHex, key, options);
  messages.push({
    plaintext,
    plaintextUtf8: utf8Hex(plaintext),
    key,
    keyUtf8: utf8Hex(key),
    rounds,
    result,
    encryptTrace: {
      rounds: trace.rounds,
      masterKeyBytes: hex(trace.masterKeyBytes),
      subkeys: trace.subkeys.map(hex),
      iv: hex(trace.iv),
      paddedPlainBytes: hex(trace.paddedPlainBytes),
      blocks: cbcEncTrace(trace.blocks),
    },
    decrypted: { plaintext: decrypted.plaintext, plaintextUtf8: utf8Hex(decrypted.plaintext), trace: decryptTrace(decrypted.trace) },
  });
});

// Decrypting with the wrong key: usually a padding error, occasionally "valid" padding
// that yields garbage text — which also exercises the UTF-8 replacement-char decoding.
const wrongKey: unknown[] = [];
for (let i = 0; i < 400; i++) {
  const plaintext = randomText();
  const key = `right key ${i}`;
  const wrong = `wrong key ${i}`;
  const rounds = [4, 5, 6][i % 3];
  const { combinedHex } = ref.encrypt(plaintext, key, { rounds });
  const res = capture(() => ref.decryptWithTrace(combinedHex, wrong, { rounds }));
  wrongKey.push(
    'ok' in res
      ? { combinedHex, key: wrong, keyUtf8: utf8Hex(wrong), rounds, plaintext: (res.ok as { plaintext: string }).plaintext, plaintextUtf8: utf8Hex((res.ok as { plaintext: string }).plaintext), trace: decryptTrace((res.ok as { trace: unknown }).trace) }
      : { combinedHex, key: wrong, keyUtf8: utf8Hex(wrong), rounds, error: res.error },
  );
}

const validCombined = ref.encrypt('hi', 'key').combinedHex;
const apiErrors = [
  { op: 'encrypt', plaintext: 'hi', key: 'key', rounds: 3 },
  { op: 'encrypt', plaintext: 'hi', key: 'key', rounds: 7 },
  { op: 'encrypt', plaintext: 'hi', key: 'key', rounds: 4.5 },
  { op: 'encrypt', plaintext: 'hi', key: '', rounds: 7 },
  { op: 'encrypt', plaintext: 'hi', key: '', rounds: null },
  { op: 'decrypt', combinedHex: 'zz', key: '', rounds: 7 },
  { op: 'decrypt', combinedHex: 'zz', key: '', rounds: null },
  { op: 'decrypt', combinedHex: 'not-hex', key: 'key', rounds: null },
  { op: 'decrypt', combinedHex: 'ab', key: '', rounds: null },
  { op: 'decrypt', combinedHex: '', key: 'key', rounds: null },
  { op: 'decrypt', combinedHex: validCombined.slice(0, 16), key: 'key', rounds: null },
  { op: 'decrypt', combinedHex: validCombined + 'aabbcc', key: 'key', rounds: null },
  { op: 'decrypt', combinedHex: validCombined, key: '', rounds: null },
  { op: 'decrypt', combinedHex: validCombined, key: 'key', rounds: NaN },
].map((c) => {
  const options = c.rounds === null ? {} : { rounds: c.rounds };
  const res = capture(() => (c.op === 'encrypt' ? ref.encrypt(c.plaintext, c.key, options) : ref.decrypt(c.combinedHex, c.key, options)));
  return { ...c, rounds: c.rounds === null ? null : num(c.rounds), keyUtf8: utf8Hex(c.key), plaintextUtf8: c.plaintext === undefined ? undefined : utf8Hex(c.plaintext), error: (res as { error: string }).error };
});

// Avalanche with a FIXED IV (the test suites use a random one), so the exact changed-bit
// counts are comparable across implementations. Mirrors the demo's AvalancheSection:
// flip one bit of the padded plaintext, or of the master key, and re-run encryptCbc.
const avalanche: unknown[] = [];
for (let i = 0; i < 40; i++) {
  const plaintext = i === 0 ? 'The quick brown fox jumps over the lazy dog' : randomText() || 'x';
  const key = i === 0 ? 'avalanche test key' : `avalanche key ${i}`;
  const rounds = [4, 5, 6][i % 3];
  const iv = randBytes(8);
  const target = i % 2 === 0 ? 'plaintext' : 'key';
  const master = ref.deriveMasterKeyBytes(key);
  const keys = ref.deriveSubkeys(master, rounds);
  const padded = ref.pkcs7Pad(ref.textToBytes(plaintext), 8);
  const chunk = (b: Uint8Array) => Array.from({ length: b.length / 8 }, (_, j) => b.slice(j * 8, j * 8 + 8));
  const base = ref.concatBytes(...ref.encryptCbc(chunk(padded), iv, keys).cipherBlocks);
  const flipTarget = target === 'plaintext' ? padded.slice() : master.slice();
  const byteIndex = randInt(0, flipTarget.length - 1);
  const bitOffset = randInt(0, 7);
  flipTarget[byteIndex] ^= 1 << (7 - bitOffset);
  const flipped = target === 'plaintext'
    ? ref.concatBytes(...ref.encryptCbc(chunk(flipTarget), iv, keys).cipherBlocks)
    : ref.concatBytes(...ref.encryptCbc(chunk(padded), iv, ref.deriveSubkeys(flipTarget, rounds)).cipherBlocks);
  const d = ref.bitDiff(base, flipped);
  avalanche.push({ plaintext, key, rounds, iv: hex(iv), target, byteIndex, bitOffset, baseCipher: hex(base), flippedCipher: hex(flipped), diffBits: d.diffBits, totalBits: d.totalBits });
}

// UTF-8 decoding (TextDecoder semantics: replacement chars + leading BOM stripped).
const utf8DecodeInputs = [
  '', 'efbbbf', 'efbbbf68', 'efbbbfefbbbf68', '68efbbbf', 'c080', 'c1bf', 'c2', 'e282', 'e282ac', 'eda080', 'edbfbf',
  'f4908080', 'f48fbfbf', 'f0908d88', 'f08f8080', 'f5', 'ff', 'fe', '80', 'bf80', 'e0a0', 'e080af', 'f09080', 'f0908041',
  'e2ac41', 'c341', '41c3', 'fc8080808080', 'efbfbd', '00',
  ...Array.from({ length: 800 }, () => {
    const b = randBytes(randInt(0, 12));
    for (let i = 0; i < b.length; i++) if (rand() < 0.4) b[i] = randInt(0x80, 0xff);
    return hex(b);
  }),
];
const utf8Decode = utf8DecodeInputs.map((h) => {
  const text = ref.bytesToText(Uint8Array.from(Buffer.from(h, 'hex')));
  return { bytes: h, text, textUtf8: utf8Hex(text) };
});

// Stored as UTF-16 code units: lone surrogates can't round-trip through strict JSON parsers.
const utf8Encode = ['', 'abc', 'caf\u00e9', '\u65e5\u672c\u8a9e', '\uD83D\uDE00', '\uFEFFx', 'a\uD800b', '\uDC00', '\uD83D', 'x\uD83D\uDE00y'].map((text) => ({
  units: Array.from({ length: text.length }, (_, i) => text.charCodeAt(i)),
  bytes: hex(ref.textToBytes(text)),
}));

const golden = {
  meta: {
    description: 'Reference outputs of the original TypeScript cipher implementation. The C++ port must match these byte-for-byte.',
    sourceCommit: SOURCE_COMMIT,
    generator: 'algorithm/scripts/make-golden-vectors.ts',
    seed: SEED,
    bytes: 'all byte arrays are lowercase hex strings',
    numbers: 'non-finite numbers and -0 are stored as the strings "NaN", "Infinity", "-Infinity", "-0"',
  },
  constants,
  sbox: Array.from(ref.SBOX),
  invSbox: Array.from(ref.INV_SBOX),
  assertValidRounds,
  masterKeys,
  masterKeyErrors,
  subkeys,
  rotateBits,
  rotateBytes,
  xor,
  concat,
  pad,
  unpad,
  hexToBytes,
  bytesToHex,
  bitDiff,
  encryptBlock,
  decryptBlock,
  blockErrors,
  encryptCbc,
  decryptCbc,
  messages,
  wrongKey,
  apiErrors,
  avalanche,
  utf8Decode,
  utf8Encode,
};

writeFileSync(outPath, JSON.stringify(golden) + '\n');
console.log(`Wrote ${outPath}`);

/** Byte-array helpers shared across the cipher and the demo's visualizers. */

export function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`Invalid hex string: "${hex}"`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new Error(`xorBytes: length mismatch (${a.length} vs ${b.length})`);
  }
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

/** Circular shift of a byte array's *positions* to the left, e.g. [1,2,3] -> [2,3,1]. */
export function rotateBytesLeft(bytes: Uint8Array, by = 1): Uint8Array {
  const n = bytes.length;
  const shift = ((by % n) + n) % n;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = bytes[(i + shift) % n];
  }
  return out;
}

/** Circular shift of a byte array's *positions* to the right — the inverse of rotateBytesLeft. */
export function rotateBytesRight(bytes: Uint8Array, by = 1): Uint8Array {
  return rotateBytesLeft(bytes, -by);
}

/**
 * Circular left rotation of the whole byte array treated as one big bit string.
 * Used by the key schedule (rotate_left(master_key, n)) — distinct from
 * rotateBytesLeft, which only shifts whole-byte positions.
 */
export function rotateBitsLeft(bytes: Uint8Array, bitCount: number): Uint8Array {
  const totalBits = bytes.length * 8;
  const shift = ((bitCount % totalBits) + totalBits) % totalBits;
  if (shift === 0) return bytes.slice();

  const byteShift = shift >> 3;
  const bitShift = shift & 7;
  const rotatedBytes = rotateBytesLeft(bytes, byteShift);

  if (bitShift === 0) return rotatedBytes;

  const n = rotatedBytes.length;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    const current = rotatedBytes[i];
    const next = rotatedBytes[(i + 1) % n];
    out[i] = ((current << bitShift) | (next >> (8 - bitShift))) & 0xff;
  }
  return out;
}

/** Circular right rotation of the whole byte array treated as one big bit string — the inverse of rotateBitsLeft. */
export function rotateBitsRight(bytes: Uint8Array, bitCount: number): Uint8Array {
  return rotateBitsLeft(bytes, -bitCount);
}

/** Number of differing bits between two equal-length byte arrays, plus a per-byte XOR diff mask. */
export function bitDiff(a: Uint8Array, b: Uint8Array): { diffBits: number; totalBits: number; diffMask: Uint8Array } {
  if (a.length !== b.length) {
    throw new Error(`bitDiff: length mismatch (${a.length} vs ${b.length})`);
  }
  const diffMask = xorBytes(a, b);
  let diffBits = 0;
  for (const byte of diffMask) {
    diffBits += popcount(byte);
  }
  return { diffBits, totalBits: a.length * 8, diffMask };
}

function popcount(byte: number): number {
  let count = 0;
  let n = byte;
  while (n) {
    count += n & 1;
    n >>= 1;
  }
  return count;
}

/** Cryptographically-irrelevant but uniformly random bytes, used for the (non-secret) IV. */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(out);
  } else {
    for (let i = 0; i < length; i++) {
      out[i] = Math.floor(Math.random() * 256);
    }
  }
  return out;
}

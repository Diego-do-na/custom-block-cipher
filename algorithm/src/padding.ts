import { concatBytes } from './bytes.js';

/**
 * PKCS#7 padding: pad with N bytes of value N, where N = bytes needed to reach the
 * next multiple of blockSize. If already a multiple, a full block of padding is added
 * (so padding is always present and always unambiguous to strip).
 */
export function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
  const padLength = blockSize - (data.length % blockSize);
  const padding = new Uint8Array(padLength).fill(padLength);
  return concatBytes(data, padding);
}

/** Strips and validates PKCS#7 padding, throwing if the padding is malformed. */
export function pkcs7Unpad(data: Uint8Array, blockSize: number): Uint8Array {
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new Error(`Padded data length must be a positive multiple of ${blockSize}, got ${data.length}`);
  }

  const padLength = data[data.length - 1];
  if (padLength < 1 || padLength > blockSize) {
    throw new Error(`Invalid PKCS#7 padding: bad pad length byte ${padLength}`);
  }

  for (let i = data.length - padLength; i < data.length; i++) {
    if (data[i] !== padLength) {
      throw new Error('Invalid PKCS#7 padding: padding bytes do not match.');
    }
  }

  return data.slice(0, data.length - padLength);
}

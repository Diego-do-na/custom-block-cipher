#!/usr/bin/env node
/**
 * Minimal CLI for exercising the cipher in isolation, decoupled from the demo app.
 *
 * Usage:
 *   npm run cli -- encrypt "<plaintext>" "<key>" [rounds]
 *   npm run cli -- decrypt "<combined-hex>" "<key>" [rounds]
 */
import { encrypt, decrypt } from './index.js';

function main(): void {
  const [command, text, key, roundsArg] = process.argv.slice(2);
  const rounds = roundsArg ? Number(roundsArg) : undefined;

  if (!command || !text || !key) {
    console.error('Usage: cli.ts <encrypt|decrypt> <text> <key> [rounds]');
    process.exitCode = 1;
    return;
  }

  if (command === 'encrypt') {
    const { ivHex, ciphertextHex, combinedHex } = encrypt(text, key, { rounds });
    console.log(`IV:         ${ivHex}`);
    console.log(`Ciphertext: ${ciphertextHex}`);
    console.log(`Combined:   ${combinedHex}`);
  } else if (command === 'decrypt') {
    const plaintext = decrypt(text, key, { rounds });
    console.log(`Plaintext: ${plaintext}`);
  } else {
    console.error(`Unknown command "${command}". Use "encrypt" or "decrypt".`);
    process.exitCode = 1;
  }
}

main();

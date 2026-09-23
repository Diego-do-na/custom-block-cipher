import { useState, type ReactNode } from 'react';
import {
  encryptWithTrace,
  encryptCbc,
  deriveSubkeys,
  bitDiff,
  bytesToHex,
  concatBytes,
  BLOCK_SIZE,
  DEFAULT_ROUNDS,
  MIN_ROUNDS,
  MAX_ROUNDS,
} from '@cipher/algorithm';
import { Panel } from '../shared/Panel';
import { Badge } from '../shared/Badge';
import { Button } from '../shared/Button';
import { BitGrid } from '../shared/BitGrid';
import { IconZap, IconKey, IconLock } from '../../icons/icons';

type FlipTarget = 'plaintext' | 'key';

interface ComparisonResult {
  baseCipher: Uint8Array;
  flippedCipher: Uint8Array;
  diffBits: number;
  totalBits: number;
}

function flipBit(bytes: Uint8Array, byteIndex: number, bitOffset: number): Uint8Array {
  const out = bytes.slice();
  out[byteIndex] ^= 1 << (7 - bitOffset);
  return out;
}

export function AvalancheSection() {
  const [plaintext, setPlaintext] = useState('Attack at dawn, not dusk.');
  const [key, setKey] = useState('correct horse battery staple');
  const [rounds, setRounds] = useState(DEFAULT_ROUNDS);
  const [target, setTarget] = useState<FlipTarget>('plaintext');
  const [byteIndex, setByteIndex] = useState(0);
  const [bitOffset, setBitOffset] = useState(0);
  const [result, setResult] = useState<ComparisonResult | null>(null);

  function compare() {
    const { trace } = encryptWithTrace(plaintext, key, { rounds });
    const baseCipher = concatBytes(...trace.blocks.map((b) => b.cipherBlock));

    let flippedCipher: Uint8Array;

    if (target === 'plaintext') {
      const flippedPadded = flipBit(trace.paddedPlainBytes, byteIndex, bitOffset);
      const flippedBlocks = chunk(flippedPadded, BLOCK_SIZE);
      const { cipherBlocks } = encryptCbc(flippedBlocks, trace.iv, trace.subkeys);
      flippedCipher = concatBytes(...cipherBlocks);
    } else {
      const flippedMasterKey = flipBit(trace.masterKeyBytes, byteIndex, bitOffset);
      const flippedSubkeys = deriveSubkeys(flippedMasterKey, rounds);
      const plainBlocks = chunk(trace.paddedPlainBytes, BLOCK_SIZE);
      const { cipherBlocks } = encryptCbc(plainBlocks, trace.iv, flippedSubkeys);
      flippedCipher = concatBytes(...cipherBlocks);
    }

    const { diffBits, totalBits } = bitDiff(baseCipher, flippedCipher);
    setResult({ baseCipher, flippedCipher, diffBits, totalBits });
  }

  const percent = result ? (100 * result.diffBits) / result.totalBits : 0;

  return (
    <div className="flex flex-col gap-6">
      <div className="max-w-3xl">
        <h2 className="font-display text-2xl font-semibold tracking-tight text-foreground">Avalanche effect</h2>
        <p className="mt-2 text-base text-muted-foreground">
          Flip a single bit in the plaintext or the key, re-encrypt with everything else identical (same IV, same
          subkeys unless the key is what changed), and compare. A well-mixed cipher turns one flipped bit into
          roughly half the output bits changing.
        </p>
      </div>

      <Panel title="Setup" icon={<IconZap className="size-5" />}>
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-end gap-4">
            <label className="block grow basis-64">
              <span className="mb-1.5 block font-display text-xs font-medium tracking-wide text-muted-foreground uppercase">Plaintext</span>
              <input
                value={plaintext}
                onChange={(e) => setPlaintext(e.target.value)}
                className="w-full rounded-lg bg-panel px-3 py-2 font-mono text-sm text-foreground ring-1 ring-inset ring-border focus:outline-2 focus:outline-offset-2 focus:outline-ring"
              />
            </label>
            <label className="block grow basis-64">
              <span className="mb-1.5 block font-display text-xs font-medium tracking-wide text-muted-foreground uppercase">Key</span>
              <input
                value={key}
                onChange={(e) => setKey(e.target.value)}
                className="w-full rounded-lg bg-panel px-3 py-2 font-mono text-sm text-foreground ring-1 ring-inset ring-border focus:outline-2 focus:outline-offset-2 focus:outline-ring"
              />
            </label>
            <label className="block">
              <span className="mb-1.5 block font-display text-xs font-medium tracking-wide text-muted-foreground uppercase">Rounds</span>
              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min={MIN_ROUNDS}
                  max={MAX_ROUNDS}
                  value={rounds}
                  onChange={(e) => setRounds(Number(e.target.value))}
                  className="h-2 w-28 cursor-pointer accent-diffusion"
                />
                <span className="font-mono text-sm text-foreground">{rounds}</span>
              </div>
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <div className="flex gap-1 rounded-lg bg-panel p-1 ring-1 ring-inset ring-border">
              <ToggleButton active={target === 'plaintext'} icon={<IconLock className="size-4" />} onClick={() => setTarget('plaintext')}>
                Flip plaintext bit
              </ToggleButton>
              <ToggleButton active={target === 'key'} icon={<IconKey className="size-4" />} onClick={() => setTarget('key')}>
                Flip key bit
              </ToggleButton>
            </div>

            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <span className="font-display text-xs font-medium tracking-wide uppercase">Bit to flip:</span>
              <span className="font-mono text-foreground">
                byte {byteIndex}, bit {7 - bitOffset}
              </span>
            </div>
          </div>

          <BitSelector byteIndex={byteIndex} bitOffset={bitOffset} onSelect={(b, o) => { setByteIndex(b); setBitOffset(o); }} />

          <div>
            <Button icon={<IconZap className="size-4" />} onClick={compare}>
              Compare ciphertexts
            </Button>
          </div>
        </div>
      </Panel>

      {result && (
        <Panel title="Result">
          <div className="flex flex-col gap-6">
            <div className="flex flex-wrap items-center gap-6">
              <div>
                <p className="font-display text-4xl font-semibold text-changed">{percent.toFixed(1)}%</p>
                <p className="text-sm text-muted-foreground">
                  {result.diffBits} of {result.totalBits} ciphertext bits changed
                </p>
              </div>
              <Badge tone={percent > 30 ? 'success' : 'danger'}>{percent > 30 ? 'strong avalanche' : 'weak avalanche'}</Badge>
            </div>

            <div>
              <p className="mb-2 font-display text-xs font-medium tracking-wide text-muted-foreground uppercase">
                Base ciphertext (top) vs. flipped-bit ciphertext (bottom) {'—'} changed bits highlighted
              </p>
              <div className="flex flex-col gap-3 overflow-x-auto rounded-lg bg-panel p-4 ring-1 ring-inset ring-border">
                <BitGrid bytes={result.baseCipher} />
                <div className="h-px bg-border" />
                <BitGrid bytes={result.flippedCipher} compareTo={result.baseCipher} />
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <HexRow label="Base ciphertext" hex={bytesToHex(result.baseCipher)} />
              <HexRow label="Flipped ciphertext" hex={bytesToHex(result.flippedCipher)} />
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}

function BitSelector({ byteIndex, bitOffset, onSelect }: { byteIndex: number; bitOffset: number; onSelect: (byteIndex: number, bitOffset: number) => void }) {
  return (
    <div className="flex flex-wrap gap-3">
      {Array.from({ length: BLOCK_SIZE }, (_, b) => (
        <div key={b} className="flex gap-0.5">
          {Array.from({ length: 8 }, (_, o) => {
            const active = b === byteIndex && o === bitOffset;
            return (
              <button
                key={o}
                type="button"
                onClick={() => onSelect(b, o)}
                aria-label={`Select byte ${b} bit ${7 - o}`}
                aria-pressed={active}
                className={`size-5 cursor-pointer rounded-sm ring-1 ring-inset transition-colors duration-150 ${
                  active ? 'bg-changed ring-changed' : 'bg-panel ring-border hover:bg-muted'
                }`}
              />
            );
          })}
        </div>
      ))}
    </div>
  );
}

function ToggleButton({ active, icon, children, onClick }: { active: boolean; icon: ReactNode; children: ReactNode; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex min-h-9 cursor-pointer items-center gap-2 rounded-md px-3 py-1.5 font-display text-sm font-medium tracking-wide transition-colors duration-200 ${
        active ? 'bg-diffusion text-diffusion-foreground' : 'text-muted-foreground hover:bg-muted hover:text-foreground'
      }`}
    >
      {icon}
      {children}
    </button>
  );
}

function HexRow({ label, hex }: { label: string; hex: string }) {
  return (
    <div className="rounded-lg bg-panel p-3 ring-1 ring-inset ring-border">
      <p className="font-display text-xs font-medium tracking-wide text-muted-foreground uppercase">{label}</p>
      <p className="mt-1 font-mono text-sm break-all text-diffusion">{hex}</p>
    </div>
  );
}

function chunk(bytes: Uint8Array, size: number): Uint8Array[] {
  const blocks: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += size) blocks.push(bytes.slice(i, i + size));
  return blocks;
}

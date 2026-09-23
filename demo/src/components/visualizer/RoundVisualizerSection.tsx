import { useMemo, useState } from 'react';
import {
  encryptWithTrace,
  bytesToHex,
  DEFAULT_ROUNDS,
  MIN_ROUNDS,
  MAX_ROUNDS,
  type EncryptTrace,
} from '@cipher/algorithm';
import { Panel } from '../shared/Panel';
import { Badge } from '../shared/Badge';
import { Button } from '../shared/Button';
import { ByteGrid } from '../shared/ByteGrid';
import { IconLayers, IconChevronLeft, IconChevronRight, IconRefresh, IconLink } from '../../icons/icons';

interface Step {
  title: string;
  bytes: Uint8Array;
  tone: 'neutral' | 'confusion' | 'diffusion';
  note?: string;
}

function buildSteps(trace: EncryptTrace, blockIndex: number): Step[] {
  const block = trace.blocks[blockIndex];
  const steps: Step[] = [
    {
      title: 'Block input',
      tone: 'neutral',
      bytes: block.inputBlock,
      note: `plainBlock ⊕ ${blockIndex === 0 ? 'IV' : `C[${blockIndex - 1}]`} (CBC chaining)`,
    },
  ];

  for (const r of block.rounds) {
    steps.push({
      title: `Round ${r.round + 1} — XOR subkey`,
      tone: 'confusion',
      bytes: r.afterXor,
      note: `subkey[${r.round}] = ${bytesToHex(r.subkey)}`,
    });
    steps.push({
      title: `Round ${r.round + 1} — S-box substitution`,
      tone: 'confusion',
      bytes: r.afterSub,
    });
    steps.push({
      title: `Round ${r.round + 1} — Rotate bits`,
      tone: 'diffusion',
      bytes: r.afterRotate,
    });
  }

  steps.push({ title: 'Ciphertext block', tone: 'neutral', bytes: block.cipherBlock });
  return steps;
}

export function RoundVisualizerSection() {
  const [plaintext, setPlaintext] = useState('two blocks!');
  const [key, setKey] = useState('correct horse battery staple');
  const [rounds, setRounds] = useState(DEFAULT_ROUNDS);
  const [trace, setTrace] = useState<EncryptTrace | null>(null);
  const [blockIndex, setBlockIndex] = useState(0);
  const [stepIndex, setStepIndex] = useState(0);

  function regenerate() {
    const { trace: newTrace } = encryptWithTrace(plaintext, key, { rounds });
    setTrace(newTrace);
    setBlockIndex(0);
    setStepIndex(0);
  }

  const steps = useMemo(() => (trace ? buildSteps(trace, blockIndex) : []), [trace, blockIndex]);
  const currentStep = steps[stepIndex];

  return (
    <div className="flex flex-col gap-6">
      <div className="max-w-3xl">
        <h2 className="font-display text-2xl font-semibold tracking-tight text-foreground">Round-by-round visualizer</h2>
        <p className="mt-2 text-base text-muted-foreground">
          Watch one block transform sub-step by sub-step, and see how CBC chains ciphertext from one block into the next.
        </p>
      </div>

      <Panel title="Message & key" icon={<IconLayers className="size-5" />}>
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
          <Button icon={<IconRefresh className="size-4" />} onClick={regenerate}>
            {trace ? 'Regenerate (new IV)' : 'Generate trace'}
          </Button>
        </div>
      </Panel>

      {trace && (
        <>
          <Panel title="CBC chain" icon={<IconLink className="size-5" />} description="Click a block to inspect its rounds below">
            <ChainDiagram trace={trace} selected={blockIndex} onSelect={(i) => { setBlockIndex(i); setStepIndex(0); }} />
          </Panel>

          <Panel
            title={`Block ${blockIndex} — round stepper`}
            description={`${steps.length} steps · ${rounds} rounds`}
          >
            <div className="flex flex-col gap-5">
              <div className="flex flex-wrap gap-1.5">
                {steps.map((step, i) => (
                  <button
                    key={step.title + i}
                    type="button"
                    onClick={() => setStepIndex(i)}
                    className={`cursor-pointer rounded-md px-2.5 py-1.5 font-display text-[11px] font-medium tracking-wide transition-colors duration-200 ${
                      i === stepIndex
                        ? 'bg-diffusion text-diffusion-foreground'
                        : 'bg-panel text-muted-foreground ring-1 ring-inset ring-border hover:text-foreground'
                    }`}
                  >
                    {step.title}
                  </button>
                ))}
              </div>

              {currentStep && (
                <div className="rounded-lg bg-panel p-4 ring-1 ring-inset ring-border">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Badge tone={currentStep.tone === 'neutral' ? 'neutral' : currentStep.tone}>
                        {currentStep.tone === 'neutral' ? 'state' : currentStep.tone}
                      </Badge>
                      <h4 className="font-display text-sm font-semibold text-foreground">{currentStep.title}</h4>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="ghost"
                        icon={<IconChevronLeft className="size-4" />}
                        disabled={stepIndex === 0}
                        onClick={() => setStepIndex((i) => Math.max(0, i - 1))}
                      >
                        Prev
                      </Button>
                      <Button
                        variant="ghost"
                        icon={<IconChevronRight className="size-4" />}
                        disabled={stepIndex === steps.length - 1}
                        onClick={() => setStepIndex((i) => Math.min(steps.length - 1, i + 1))}
                      >
                        Next
                      </Button>
                    </div>
                  </div>
                  {currentStep.note && <p className="mt-1 font-mono text-xs text-muted-foreground">{currentStep.note}</p>}
                  <div className="mt-4">
                    <ByteGrid bytes={currentStep.bytes} />
                  </div>
                </div>
              )}
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}

function ChainDiagram({ trace, selected, onSelect }: { trace: EncryptTrace; selected: number; onSelect: (i: number) => void }) {
  return (
    <div className="flex flex-wrap items-center gap-2 overflow-x-auto py-2">
      <ChainNode label="IV" hex={bytesToHex(trace.iv)} />
      {trace.blocks.map((block, i) => (
        <span key={i} className="flex items-center gap-2">
          <IconChevronRight className="size-5 shrink-0 text-muted-foreground" />
          <button type="button" onClick={() => onSelect(i)} className="cursor-pointer">
            <ChainNode label={`C[${i}]`} hex={bytesToHex(block.cipherBlock)} active={selected === i} sub={`P[${i}] ⊕ prev → ${trace.rounds} rounds`} />
          </button>
        </span>
      ))}
    </div>
  );
}

function ChainNode({ label, hex, sub, active }: { label: string; hex: string; sub?: string; active?: boolean }) {
  return (
    <div
      className={`flex min-w-32 flex-col items-center gap-1 rounded-lg px-3 py-2 text-center ring-1 ring-inset transition-colors duration-200 ${
        active ? 'bg-diffusion/15 ring-diffusion/50' : 'bg-panel ring-border hover:bg-muted'
      }`}
    >
      <span className="font-display text-xs font-semibold text-foreground">{label}</span>
      <span className="font-mono text-[11px] text-diffusion">{hex}</span>
      {sub && <span className="text-[10px] text-muted-foreground">{sub}</span>}
    </div>
  );
}

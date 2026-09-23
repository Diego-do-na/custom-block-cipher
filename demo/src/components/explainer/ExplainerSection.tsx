import type { ReactNode } from 'react';
import { Panel } from '../shared/Panel';
import { Badge } from '../shared/Badge';
import { IconChevronRight, IconKey, IconShuffle, IconRotate, IconLink, IconLock, IconEye, IconEyeOff } from '../../icons/icons';
import { DEFAULT_ROUNDS } from '@cipher/algorithm';

const TECHNIQUES = [
  {
    tone: 'confusion' as const,
    label: 'Confusion #1',
    title: 'XOR with a round subkey',
    icon: IconKey,
    body:
      'Every byte of the block is XORed with that round’s subkey. XOR is its own inverse (x ⊕ k ⊕ k = x), so decryption undoes it with the exact same subkey.',
  },
  {
    tone: 'confusion' as const,
    label: 'Confusion #2',
    title: 'S-box substitution',
    icon: IconShuffle,
    body:
      'Each byte is looked up in a fixed 256-entry table — a non-linear substitution, so an attacker can’t predict how the output changes from a simple formula on the input.',
  },
  {
    tone: 'diffusion' as const,
    label: 'Diffusion #1',
    title: 'Bit rotation',
    icon: IconRotate,
    body:
      'The block is rotated by a few bits — not a whole number of bytes — so bits spill across byte boundaries. Combined with the S-box in the next round, this is what lets a change in one byte spread into others.',
  },
  {
    tone: 'diffusion' as const,
    label: 'Diffusion #2',
    title: 'CBC chaining',
    icon: IconLink,
    body:
      'Each block is XORed with the previous block’s ciphertext before encryption. A change in block i cascades into every block after it — diffusion across the whole message, not just one block.',
  },
];

export function ExplainerSection() {
  return (
    <div className="flex flex-col gap-8">
      <div className="max-w-3xl">
        <h2 className="font-display text-2xl font-semibold tracking-tight text-foreground">How this cipher works</h2>
        <p className="mt-3 text-base leading-relaxed text-muted-foreground">
          This is a small, from-scratch symmetric block cipher built to demonstrate two foundational ideas behind real
          ciphers like AES: <span className="text-confusion">confusion</span> and{' '}
          <span className="text-diffusion">diffusion</span>. Confusion techniques obscure the relationship between key
          and output <em>within</em> a single byte. Diffusion techniques spread one byte&rsquo;s influence{' '}
          <em>across</em> the block, and across the whole message.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {TECHNIQUES.map((t) => (
          <Panel key={t.title} icon={<t.icon className="size-5" />} title={t.label}>
            <Badge tone={t.tone}>{t.tone}</Badge>
            <h3 className="mt-3 font-display text-base font-semibold text-foreground">{t.title}</h3>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{t.body}</p>
          </Panel>
        ))}
      </div>

      <Panel title="One round" description={`Repeated ${DEFAULT_ROUNDS} times by default, each round with a fresh subkey`}>
        <RoundDiagram />
      </Panel>

      <Panel title="CBC chaining across blocks" description="Diffusion #2 — spreads a change across the whole message">
        <CbcDiagram />
      </Panel>

      <Panel title="What's secret vs. public" icon={<IconLock className="size-5" />}>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <SecretRow icon={<IconEyeOff className="size-4" />} tone="secret" label="Master key" body="Never displayed or transmitted as if public. Everything else derives from it." />
          <SecretRow icon={<IconEye className="size-4" />} tone="public" label="IV" body="Random per message, sent alongside the ciphertext. Not secret — just needs to be unique per encryption." />
          <SecretRow icon={<IconEye className="size-4" />} tone="public" label="S-box" body="A fixed constant of the algorithm, identical for every encryption (Kerckhoffs's principle: security rests on the key, not on hiding the algorithm)." />
        </div>
      </Panel>
    </div>
  );
}

function SecretRow({ icon, tone, label, body }: { icon: ReactNode; tone: 'secret' | 'public'; label: string; body: string }) {
  return (
    <div className="rounded-lg bg-panel p-4 ring-1 ring-inset ring-border">
      <Badge tone={tone} icon={icon}>
        {tone}
      </Badge>
      <p className="mt-2 font-display text-sm font-semibold text-foreground">{label}</p>
      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{body}</p>
    </div>
  );
}

function FlowBox({ tone, children }: { tone: 'neutral' | 'confusion' | 'diffusion'; children: ReactNode }) {
  const toneClass =
    tone === 'confusion'
      ? 'bg-confusion/10 ring-confusion/40 text-confusion'
      : tone === 'diffusion'
        ? 'bg-diffusion/10 ring-diffusion/40 text-diffusion'
        : 'bg-panel ring-border text-foreground';
  return (
    <div className={`flex min-h-16 min-w-28 flex-col items-center justify-center rounded-lg px-3 py-2 text-center ring-1 ring-inset ${toneClass}`}>
      {children}
    </div>
  );
}

function Arrow() {
  return <IconChevronRight className="size-5 shrink-0 text-muted-foreground" />;
}

function RoundDiagram() {
  return (
    <div className="flex flex-wrap items-center gap-2 overflow-x-auto py-2">
      <FlowBox tone="neutral">
        <span className="font-mono text-xs">Block</span>
      </FlowBox>
      <Arrow />
      <FlowBox tone="confusion">
        <span className="font-display text-xs font-semibold">XOR</span>
        <span className="text-[11px] text-muted-foreground">subkey[i]</span>
      </FlowBox>
      <Arrow />
      <FlowBox tone="confusion">
        <span className="font-display text-xs font-semibold">S-Box</span>
        <span className="text-[11px] text-muted-foreground">substitute</span>
      </FlowBox>
      <Arrow />
      <FlowBox tone="diffusion">
        <span className="font-display text-xs font-semibold">Rotate</span>
        <span className="text-[11px] text-muted-foreground">bits left</span>
      </FlowBox>
      <Arrow />
      <FlowBox tone="neutral">
        <span className="font-mono text-xs">Next round</span>
      </FlowBox>
    </div>
  );
}

function CbcDiagram() {
  const blocks = [0, 1, 2];
  return (
    <div className="flex flex-wrap items-center gap-2 overflow-x-auto py-2">
      <FlowBox tone="neutral">
        <span className="font-mono text-xs">IV</span>
      </FlowBox>
      {blocks.map((i) => (
        <span key={i} className="flex items-center gap-2">
          <Arrow />
          <FlowBox tone="confusion">
            <span className="font-display text-xs font-semibold">XOR</span>
            <span className="text-[11px] text-muted-foreground">
              P[{i}] {'⊕'} prev
            </span>
          </FlowBox>
          <Arrow />
          <FlowBox tone="diffusion">
            <span className="font-display text-xs font-semibold">Rounds</span>
            <span className="text-[11px] text-muted-foreground">C[{i}]</span>
          </FlowBox>
        </span>
      ))}
    </div>
  );
}

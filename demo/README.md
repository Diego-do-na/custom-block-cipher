# demo

Interactive presentation app for the custom block cipher in
[`../algorithm`](../algorithm) — React + TypeScript + Vite + Tailwind CSS v4. See
[`../CLAUDE.md`](../CLAUDE.md) / [`../AGENTS.md`](../AGENTS.md) for the full
project overview and the algorithm's locked interface this app imports against.

## Usage

```bash
npm install       # from the repo root — sets up this workspace + @cipher/algorithm
npm run demo:dev    # http://localhost:5173
npm run demo:build
```

## Sections

- **How It Works** (`src/components/explainer`) — confusion/diffusion primer with
  boxes-and-arrows diagrams of one round and the CBC chain.
- **Live Demo** (`src/components/live`) — plaintext + key in, IV + ciphertext hex
  out, decrypt back, proving the round-trip live.
- **Round Visualizer** (`src/components/visualizer`) — a clickable stepper through
  every sub-step (XOR, S-box, rotate) of every round for a chosen block, plus a
  CBC chain diagram across all blocks of the message.
- **Avalanche Effect** (`src/components/avalanche`) — flip one bit (plaintext or
  key), re-encrypt with everything else held constant, and see the bit-level diff
  and percentage changed.

All four import directly from `@cipher/algorithm` — no cipher logic is
reimplemented in this app; see `src/components/*` for the exact functions used
(`encrypt`, `decrypt`, `encryptWithTrace`, `encryptCbc`, `deriveSubkeys`,
`bitDiff`, etc.).

## Design system

Chosen via the `ui-ux-pro-max` skill: Minimalism & Swiss Style, a dark
developer-tool color palette, and the "Developer Mono" font pairing (JetBrains
Mono for headings/hex/code, IBM Plex Sans for body text). Tokens live in
`src/index.css` (`@theme` block) — `background`/`foreground`/`card`/`panel`/
`muted`/`border` for structure, `accent` (green, success) / `destructive` (red,
error) for status, and `confusion` (violet) / `diffusion` (cyan) / `changed`
(amber) for technique-specific highlighting, used consistently across all four
sections. SVG icon set (no emoji) in `src/icons/icons.tsx`.

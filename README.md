# Custom Block Cipher

A university assignment: a from-scratch symmetric block cipher demonstrating
confusion and diffusion, plus an interactive live-presentation demo.

- [`/algorithm`](algorithm) — the cipher (pure TypeScript, zero runtime deps).
  Start with [`algorithm/SECURITY.md`](algorithm/SECURITY.md) for the design
  writeup.
- [`/demo`](demo) — the presentation app (React + Vite + Tailwind), importing
  `/algorithm` directly.

Full project context, the locked `/algorithm` interface, how to run everything,
and repo conventions: see [`CLAUDE.md`](CLAUDE.md) / [`AGENTS.md`](AGENTS.md)
(identical content, two names for different tools).

## Quick start

```bash
npm install
npm run algorithm:test   # 22 tests: correctness round-trips + avalanche effect
npm run demo:dev         # http://localhost:5173
```

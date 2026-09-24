# Custom Block Cipher

A university assignment: a from-scratch symmetric block cipher demonstrating
confusion and diffusion, plus an interactive live-presentation demo.

- [`/algorithm`](algorithm) — the cipher (C++20, zero runtime deps), compiled
  to WebAssembly for the demo. Start with
  [`algorithm/SECURITY.md`](algorithm/SECURITY.md) for the design writeup.
- [`/demo`](demo) — the presentation app (React + Vite + Tailwind), importing
  `/algorithm` directly.

Full project context, the locked `/algorithm` interface, how to run everything,
and repo conventions: see [`CLAUDE.md`](CLAUDE.md) / [`AGENTS.md`](AGENTS.md)
(identical content, two names for different tools).

## Prerequisites

- **Node.js 20.19+ or 22.12+** (required by Vite), with npm.
- **A C++20 compiler and `make`.** On macOS, install the Xcode Command Line Tools:
  `xcode-select --install`.
- **Emscripten 6.0.10**, which compiles the C++ cipher to WebAssembly.
  - macOS, with [Homebrew](https://brew.sh): `brew install emscripten`
  - Windows / Linux: install it with
    [emsdk](https://emscripten.org/docs/getting_started/downloads.html)
    (`./emsdk install 6.0.10 && ./emsdk activate 6.0.10`), then load its
    environment in your shell so `em++` is on your `PATH`.

Check with `node --version`, `c++ --version` and `em++ --version`.

## Quick start

```bash
git clone https://github.com/Diego-do-na/custom-block-cipher.git
cd custom-block-cipher
npm install

npm run algorithm:test   # C++ (Catch2) + WASM-binding tests: round-trips, avalanche, byte-for-byte parity
npm run demo:dev         # http://localhost:5173 (rebuilds the WASM module first)
```

The WebAssembly module isn't committed. `algorithm:test`, `demo:dev` and
`demo:build` rebuild it from the C++ source automatically. The very first build
is slower, because Emscripten compiles and caches its own system libraries once.

## Other commands

```bash
npm run demo:build             # production build of the demo (output in demo/dist)
npm run algorithm:typecheck    # typecheck the TypeScript binding layer
npm run algorithm:cli -- encrypt "hello world" "my secret key"
npm run algorithm:cli -- decrypt <combined-hex> "my secret key"
```

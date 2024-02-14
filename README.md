# qubic-crypto
[![build](https://github.com/computor-tools/qubic-crypto/actions/workflows/build.yml/badge.svg)](https://github.com/computor-tools/qubic-crypto/actions/workflows/build.yml)

Cryptographic functions used by Qubic protocol in WASM.

> [!CAUTION]
> Do not run in production yet, more testing is needed.

### To install dependencies and build:
This should pull and run emsdk from https://github.com/emscripten-core/emsdk

Tested on arch linux and ubuntu only, [check CI](https://github.com/computor-tools/qubic-crypto/actions). You'll need GNU Make.
```bash
bun run build
```

### Run test:
```bash
bun run test
```

This project was created using `bun init` in bun v1.0.20. [Bun](https://bun.sh) is a fast all-in-one JavaScript runtime.

# qubic-crypto
[![build](https://github.com/computor-tools/qubic-crypto/actions/workflows/build.yml/badge.svg)](https://github.com/computor-tools/qubic-crypto/actions/workflows/build.yml)

Cryptographic functions used by Qubic protocol in WASM.

> [!CAUTION]
> Do not run in production yet, more testing is needed.

## License
Come-from-Beyond's [**Anti-Military License**](LICENSE).

## Usage
### To install dependencies and build:
Build command should pull and run emsdk from https://github.com/emscripten-core/emsdk

Tested on arch linux and ubuntu only, [check CI](https://github.com/computor-tools/qubic-crypto/actions). You'll need GNU Make.
```bash
bun run build
```

Run test:
```bash
bun run test
```

### Instal with Bun from Github:
1. Add `qubic-crypto` to `trustedDependencies`. This allows to execute postinstall script.
```diff
   "name": "test",
   "module": "index.js",
   "type": "module",
+  "trustedDependencies": ["qubic-crypto"],
   "dependencies": {
```
2. Postinstall fetches dependencies (FourQlib, K12 & emsdk) from Github, executes GNU Make and emsdk scripts. Requires GNU Make to be already installed, [check CI](https://github.com/computor-tools/qubic-crypto/actions) for more info.
```bash
bun add --verbose github:computor-tools/qubic-crypto
```

3. Import
```js
import crypto from 'qubic-crypto';
```

### Function list
#### createPrivateKey
```js
const privateKey = await crypto.createPrivateKey(seed, index);
```

#### generatePublicKey
```js
const publicKey = await crypto.generatePublicKey(privateKey);
```

#### K12
```js
const digest = new Uint8Array(crypto.DIGEST_LENGTH);
await crypto.K12(message, digest, crypto.DIGEST_LENGTH);
```

#### sign
```js
const signature = await crypto.sign(privateKey, publicKey, digest);
```

#### verify
```js
await crypto.verify(publicKey, digest, signature);
```

#### generateCompressedPublicKey
```js
const compressedPublicKey = await crypto.generateCompressedPublicKey(privateKey);
```

#### compressedSecretAgreement
```js
const sharedSecret = await crypto.compressedSecretAgreement(privateKey, compressedPublicKey);
```

#### merkleRoot
```js
await crypto.merkleRoot(depth, index, data, siblings, root);
```

### Constants
- `crypto.SEED_LENGTH = 55`
- `crypto.PRIVATE_KEY_LENGTH = 32`
- `crypto.PUBLIC_KEY_LENGTH = 32`
- `crypto.SIGNATURE_LENGTH = 64`
- `crypto.SHARED_SECRET_LENGTH = 32`
- `crypto.DIGEST_LENGTH = 32`
- `crypto.NONCE_LENGTH = 32`

---

This project was created using `bun init` in bun v1.0.20. [Bun](https://bun.sh) is a fast all-in-one JavaScript runtime.

# @openforge-sh/liboqs

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-22+-green.svg)](https://nodejs.org/)

A JavaScript/TypeScript wrapper for [liboqs](https://github.com/open-quantum-safe/liboqs), providing access to post-quantum cryptographic algorithms for key encapsulation mechanisms (KEM) and digital signatures.

## Overview

This library provides WebAssembly bindings to liboqs, part of the [Open Quantum Safe](https://openquantumsafe.org/) project. It includes:

- Individual WASM modules per algorithm for optimal bundle sizes
- TypeScript definitions for complete type safety
- Support for both Node.js and browser environments
- SIMD-optimized builds for maximum performance
- Tree-shakable ES module exports to minimize bundle size
- Automatic memory management and secure cleanup

## Status

### ⚠️ Important Notice

**This library is meant for research, prototyping, and experimentation.** While the underlying liboqs library is well-maintained by the Open Quantum Safe project, both projects carry important caveats:

- Most post-quantum algorithms have not received the same level of scrutiny as traditional cryptography
- Algorithm support may change rapidly as research advances
- Some algorithms may prove insecure against classical or quantum computers
- This library has not received a formal security audit

**If you must use post-quantum cryptography in production environments**, use **hybrid approaches** that combine post-quantum algorithms with traditional algorithms (e.g., ML-KEM with X25519, ML-DSA with Ed25519). This provides defense-in-depth during the transition period.

For production deployments, follow guidance from NIST's [Post-Quantum Cryptography Standardization](https://csrc.nist.gov/Projects/post-quantum-cryptography) project.

### NIST Standardized Algorithms

The algorithms implementing NIST FIPS standards are:
- **ML-KEM** (FIPS 203, formerly Kyber): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **ML-DSA** (FIPS 204, formerly Dilithium): ML-DSA-44, ML-DSA-65, ML-DSA-87
- **SLH-DSA** (FIPS 205, formerly SPHINCS+): Multiple variants - currently exposed as `SPHINCS+-*` (name migration pending in liboqs)

These algorithm names are stable and will be maintained. If NIST updates implementation details, this library will track those changes.

**Note**: liboqs currently uses legacy `SPHINCS+` names for SLH-DSA, and we follow their naming. When liboqs adds `SLH-DSA` aliases to match FIPS 205 nomenclature, this library will expose them.

### Additional Algorithms

The library provides JavaScript wrappers for **97 algorithms** including experimental and alternative post-quantum schemes:

<details>
<summary>Key Encapsulation Mechanisms (32 algorithms)</summary>

- **Kyber** (legacy, use ML-KEM): `Kyber512`, `Kyber768`, `Kyber1024`
- **Classic McEliece**: 10 variants (`Classic-McEliece-348864` through `Classic-McEliece-8192128f`)
- **FrodoKEM**: 6 variants (AES and SHAKE, 640/976/1344-bit)
- **HQC**: `HQC-128`, `HQC-192`, `HQC-256`
- **NTRU**: 6 variants (HPS and HRSS families)
- **NTRU Prime**: `sntrup761`

**Note**: BIKE family is not supported due to WASM incompatibility (requires platform-specific optimizations).

</details>

<details>
<summary>Digital Signatures (65 algorithms)</summary>

- **Falcon**: `Falcon-512`, `Falcon-1024`, `Falcon-padded-512`, `Falcon-padded-1024`
- **SPHINCS+**: 12 variants (SHA2 and SHAKE, 128/192/256-bit security, f/s modes, simple variant only)
- **CROSS**: 18 variants (RSDP and RSDPG parameter sets with balanced/fast/small tradeoffs)
- **MAYO**: `MAYO-1`, `MAYO-2`, `MAYO-3`, `MAYO-5`
- **SNOVA**: 12 variants (various parameter sets)
- **UOV**: 12 variants (Ip, Is, III, V with different optimization levels)

</details>

See `algorithms.json` for the complete algorithm registry. All 97 algorithms have WASM modules, JavaScript wrappers, TypeScript definitions, and test coverage.

## Installation

This package works with all major JavaScript package managers:

```bash
# bun (recommended - fastest)
bun add @openforge-sh/liboqs

# npm
npm install @openforge-sh/liboqs

# pnpm
pnpm add @openforge-sh/liboqs

# yarn
yarn add @openforge-sh/liboqs

# deno (via npm: specifier - no install needed)
# See "Deno Usage" section below
```

This project uses **bun** by default for development, but all package managers are fully supported.

### Deno Usage

Deno works differently - it doesn't use package.json or require installation:

```typescript
// Import directly using npm: specifier
import { createMLKEM768 } from "npm:@openforge-sh/liboqs";

const kem = await createMLKEM768();
const { publicKey, secretKey } = await kem.generateKeyPair();
kem.destroy();
```

**Optional**: Create a `deno.json` for cleaner imports:
```json
{
  "imports": {
    "liboqs": "npm:@openforge-sh/liboqs"
  }
}
```

Then import like:
```typescript
import { createMLKEM768 } from "liboqs";
```

**Run with:**
```bash
deno run --allow-read --allow-env your-script.ts
```

Deno automatically caches npm packages on first run - no separate install step needed.

## Requirements

- **Node.js 22.0 or higher** (for WASM SIMD support)
- **Package Managers**: Bun 1.0+, npm 10+, pnpm 8+, yarn 4+ (for Node.js)
- **Deno 2.0+** (uses npm: specifier, no package manager needed)
- **Modern browsers** with WebAssembly support (Chrome 91+, Firefox 89+, Safari 16.4+, Edge 91+)

## Quick Start

For detailed examples and usage patterns, see the [API documentation](API_FINAL.md).

### Key Encapsulation (ML-KEM)

```javascript
import { createMLKEM768 } from '@openforge-sh/liboqs';

// Alice generates keypair
const alice = await createMLKEM768();
const { publicKey, secretKey } = await alice.generateKeyPair();

// Bob encapsulates shared secret
const bob = await createMLKEM768();
const { ciphertext, sharedSecret } = await bob.encapsulate(publicKey);

// Alice decapsulates
const aliceSecret = await alice.decapsulate(ciphertext, secretKey);

// Verify shared secrets match
console.log('Secrets match:', Buffer.compare(sharedSecret, aliceSecret) === 0);

// Cleanup
alice.destroy();
bob.destroy();
```

### Digital Signatures (ML-DSA)

```javascript
import { createMLDSA65 } from '@openforge-sh/liboqs';

const signer = await createMLDSA65();
const { publicKey, secretKey } = await signer.generateKeyPair();

const message = new TextEncoder().encode('Hello, quantum world!');
const signature = await signer.sign(message, secretKey);

const isValid = await signer.verify(message, signature, publicKey);
console.log('Valid:', isValid); // true

signer.destroy();
```

## Available Algorithms

### NIST Standardized (Recommended)

#### Key Encapsulation
- **ML-KEM-512** - NIST Level 1 (128-bit quantum security) - `createMLKEM512()`
- **ML-KEM-768** - NIST Level 3 (192-bit quantum security) - `createMLKEM768()`
- **ML-KEM-1024** - NIST Level 5 (256-bit quantum security) - `createMLKEM1024()`

#### Digital Signatures
- **ML-DSA-44** - NIST Level 2 (128-bit quantum security) - `createMLDSA44()`
- **ML-DSA-65** - NIST Level 3 (192-bit quantum security) - `createMLDSA65()`
- **ML-DSA-87** - NIST Level 5 (256-bit quantum security) - `createMLDSA87()`

### Algorithm Details

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext/Signature |
|-----------|----------------|------------|------------|----------------------|
| ML-KEM-512 | Level 1 (128-bit) | 800 B | 1,632 B | 768 B |
| ML-KEM-768 | Level 3 (192-bit) | 1,184 B | 2,400 B | 1,088 B |
| ML-KEM-1024 | Level 5 (256-bit) | 1,568 B | 3,168 B | 1,568 B |
| ML-DSA-44 | Level 2 (128-bit) | 1,312 B | 2,560 B | ~2,420 B |
| ML-DSA-65 | Level 3 (192-bit) | 1,952 B | 4,032 B | ~3,309 B |
| ML-DSA-87 | Level 5 (256-bit) | 2,592 B | 4,896 B | ~4,627 B |

## Bundle Size Optimization

Each algorithm is compiled separately into individual WASM modules, so you only bundle what you use:

```javascript
// Single algorithm (~80-160KB depending on algorithm complexity)
import { createMLKEM768 } from '@openforge-sh/liboqs';
const kem = await createMLKEM768();

// Multiple algorithms - each adds its own WASM module
import { createMLKEM768, createMLDSA65 } from '@openforge-sh/liboqs';
const kem = await createMLKEM768();
const sig = await createMLDSA65();
```

Tree-shaking ensures unused algorithms are never included in your bundle. WASM modules are lazy-loaded when you call the factory function.

## Package Structure

### Exports

```javascript
// Main entry - all 97 algorithm factory functions, classes, and metadata
import { createMLKEM768, MLKEM768, ML_KEM_768_INFO } from '@openforge-sh/liboqs';

// KEM-only exports (32 algorithms)
import {
  createMLKEM512,
  createClassicMcEliece348864,
  createFrodoKEM640AES
} from '@openforge-sh/liboqs/kem';

// Signature-only exports (65 algorithms)
import {
  createMLDSA44,
  createFalcon512,
  createSphincsSha2128fSimple
} from '@openforge-sh/liboqs/sig';

// Error classes only
import { LibOQSError, LibOQSInitError } from '@openforge-sh/liboqs/errors';
```

### File Structure

```
@openforge-sh/liboqs/
├── src/
│   ├── algorithms/
│   │   ├── kem/
│   │   │   ├── ml-kem/           # ML-KEM (3 variants)
│   │   │   ├── kyber/            # Legacy Kyber (3 variants)
│   │   │   ├── classic-mceliece/ # Classic McEliece (10 variants)
│   │   │   ├── frodokem/         # FrodoKEM (6 variants)
│   │   │   ├── hqc/              # HQC (3 variants)
│   │   │   └── ntru/             # NTRU + sntrup761 (7 variants)
│   │   └── sig/
│   │       ├── ml-dsa/           # ML-DSA (3 variants)
│   │       ├── falcon/           # Falcon (4 variants)
│   │       ├── sphincs/          # SPHINCS+ (12 variants)
│   │       ├── cross/            # CROSS (18 variants)
│   │       ├── mayo/             # MAYO (4 variants)
│   │       ├── snova/            # SNOVA (12 variants)
│   │       └── uov/              # UOV (12 variants)
│   ├── core/
│   │   └── errors.js             # Error classes
│   ├── types/                    # TypeScript definitions
│   ├── index.js                  # Main entry (all 97 algorithms)
│   ├── kem.js                    # KEM exports (32 algorithms)
│   └── sig.js                    # Signature exports (65 algorithms)
└── dist/                         # WASM modules (97 total, ~100-200KB each)
    ├── ml-kem-512.min.js
    ├── classic-mceliece-348864.min.js
    ├── ml-dsa-44.min.js
    ├── falcon-512.min.js
    ├── sphincs-sha2-128f-simple.min.js
    └── ... (and others)
```

## Architecture

The library is organized in layers:

1. **WASM Modules**: Emscripten-compiled liboqs binaries (one per algorithm)
2. **Low-level Bindings**: Direct WASM function calls (`_OQS_KEM_*`, `_OQS_SIG_*`)
3. **High-level Wrappers**: User-friendly classes (`MLKEM768`, `MLDSA65`)
4. **Public API**: Factory functions and exports

### Memory Management

**IMPORTANT**: Always call `destroy()` when finished with an algorithm instance. WASM memory is not garbage-collected by JavaScript.

#### Why This Matters

WebAssembly modules allocate native memory outside the JavaScript heap. When you create an algorithm instance, liboqs allocates C structures that JavaScript's garbage collector cannot reclaim. Without calling `destroy()`, this memory leaks permanently.

**Long-running applications** (servers, single-page apps, daemons) that don't call `destroy()` will experience:
- Increasing memory usage over time
- Eventually: allocation failures or crashes when the 256MB WASM heap limit is reached

**Short-lived scripts** are less affected since the OS reclaims all memory when the process exits.

#### Best Practices

```javascript
// Pattern 1: Simple cleanup
const kem = await createMLKEM768();
const { publicKey, secretKey } = await kem.generateKeyPair();
kem.destroy();

// Pattern 2: Error-safe cleanup (recommended)
const kem = await createMLKEM768();
try {
  const { publicKey, secretKey } = await kem.generateKeyPair();
  const { ciphertext, sharedSecret } = await kem.encapsulate(publicKey);
  // ... use results ...
} finally {
  kem.destroy(); // Always runs, even if errors occur
}

// Pattern 3: Multiple operations
const sig = await createMLDSA65();
try {
  const { publicKey, secretKey } = await sig.generateKeyPair();
  const message = new TextEncoder().encode('Hello!');
  const signature = await sig.sign(message, secretKey);
  const isValid = await sig.verify(message, signature, publicKey);
  return isValid;
} finally {
  sig.destroy();
}
```

#### Additional Notes

- Secret keys, shared secrets, and signatures are handled via WASM memory
- Keys and secrets are not automatically zeroed (limitation of JavaScript/WASM)
- Each algorithm instance must be destroyed individually
- After calling `destroy()`, the instance cannot be reused

### Thread Safety

- Individual algorithm instances are **not** thread-safe
- For concurrent operations, create separate instances per worker/thread
- WASM modules can be instantiated multiple times safely

## Security Considerations

1. **Use NIST Standardized Algorithms**: ML-KEM and ML-DSA are recommended for production
2. **Hybrid Cryptography**: We, as well as OQS, strongly recommend combining with traditional algorithms (X25519/Ed25519) during transition
3. **Key Storage**: Store secret keys securely, never in plain text or localStorage
4. **Stay Updated**: Monitor NIST guidance and update regularly
5. **Audit Your Deployment**: Consult cryptographic experts for production use
6. **Random Number Generation**: This library uses system entropy (Node.js `crypto.randomBytes()`, browser `crypto.getRandomValues()`)

### Reporting Security Issues

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy. Issues specific to the liboqs C library should be reported to the [liboqs project](https://github.com/open-quantum-safe/liboqs/security).

## Building from Source

### Prerequisites

- **Node.js 22+**
- **Emscripten** (latest stable release)
- **Git**
- **CMake 3.20+**
- **Python 3** (for Emscripten)
- **jq** (for JSON parsing in build.sh)

### Build Steps

```bash
# Clone repository
git clone https://github.com/openforge-sh/liboqs-node.git
cd liboqs-node

# Build all algorithms
./build.sh

# Build specific algorithm
./build.sh ml-kem-768

# Setup only (clone liboqs without building)
./build.sh --setup-only

# Clean build artifacts
./build.sh --clean
```

### Build System

The build system is **data-driven** using `algorithms.json`:

```json
{
  "kem": {
    "ml-kem": {
      "ML-KEM-768": {
        "slug": "ml-kem-768",
        "cmake_var": "ML_KEM_768",
        "security": 3,
        "standardized": true
      }
    }
  }
}
```

The `build.sh` script:
1. Parses `algorithms.json` with jq
2. Dynamically generates CMake flags to build single-algorithm WASM modules
3. Compiles with Emscripten optimizations (Closure compiler, WASM SIMD)
4. Outputs standalone `.min.js` files with embedded WASM

**No build script changes needed to add new algorithms** - just update the JSON registry.

### Adding New Algorithms

1. Add algorithm to `algorithms.json`
2. Run `./build.sh <algorithm-slug>`
3. Optionally create JavaScript wrapper following existing patterns
4. Export from `src/index.js` if wrapper was created

## Testing

The library includes comprehensive test coverage using Vitest:

```bash
# Run all tests (1295+ tests across 97 algorithms)
npm test

# Or use your preferred package manager
bun test
pnpm test
yarn test
```

Test coverage includes:
- **Algorithm correctness**: All algorithms tested for basic functionality
- **Round-trip verification**: KEM encapsulation/decapsulation, signature sign/verify
- **Key generation**: Validates key sizes match specifications
- **Cross-environment**: Node.js and browser (jsdom) compatibility
- **Error handling**: Validates proper error messages and types
- **Memory safety**: Ensures cleanup via destroy() methods
- **Edge cases**: Empty messages, invalid signatures, destroyed instances

## Contributing

Contributions are welcome! Please:

- **Tests must pass**: Run `bun run test` (or `npm run test`) before submitting
- **Follow existing code style**: Use ESM, async/await, JSDoc comments
- **Document public APIs**: Add comprehensive JSDoc for all exported functions and classes
- **Security first**: Consider security implications, especially for cryptographic operations
- **Consistency matters**: Follow established patterns in existing wrappers

For larger changes or new algorithms, open an issue first to discuss the approach.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Install dependencies: `bun install` (or `npm install`, `pnpm install`, etc.)
4. Make your changes (add tests if applicable)
5. Run tests: `bun run test` (or `npm run test`)
6. Build and test locally
7. Submit a pull request

### Package Manager Notes

```bash
# Using bun (recommended/default for contributors)
bun install
bun run test
bun run build

# Using npm
npm install
npm run test
npm run build

# Using pnpm
pnpm install
pnpm runtest
pnpm run build

# Using yarn
yarn install
yarn run test
yarn run build
```

Contributions that add new algorithm wrappers, improve documentation, add tests, or enhance the build system are especially appreciated.

## Documentation

- **[Security Policy](SECURITY.md)** - Vulnerability reporting and security guidance
- **[liboqs Documentation](https://github.com/open-quantum-safe/liboqs)** - Underlying C library

## License

MIT License - see [LICENSE.md](LICENSE.md) for details.

## Acknowledgments

- [Open Quantum Safe](https://openquantumsafe.org/) project for liboqs
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- The cryptographic research community
- Emscripten team for excellent WASM tooling

## Versioning

This library's version tracks the bundled liboqs version:
- `@openforge-sh/liboqs 0.14.0` includes `liboqs 0.14.0`

## Disclaimer

This library provides access to cryptographic algorithms believed to be quantum-resistant based on current research. The field of post-quantum cryptography is evolving. Algorithm support may change as research advances. Always consult with cryptographic experts for production deployments and follow NIST recommendations.

The liboqs project states: **"WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA."** This guidance applies to this JavaScript/WebAssembly wrapper as well.

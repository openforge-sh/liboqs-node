# @openforge-sh/liboqs

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-22+-green.svg)](https://nodejs.org/)

A JavaScript/TypeScript wrapper for [LibOQS](https://github.com/open-quantum-safe/liboqs), providing access to post-quantum cryptographic algorithms for key encapsulation mechanisms (KEM) and digital signatures.

## Overview

This library provides WebAssembly bindings to LibOQS, part of the [Open Quantum Safe](https://openquantumsafe.org/) project. It includes:

- Individual WASM modules per algorithm for optimal bundle sizes
- TypeScript definitions for complete type safety
- Support for Node.js and browser environments
- SIMD-optimized builds for maximum performance
- Tree-shakable ES module exports to minimize bundle size
- Automatic memory management and secure cleanup

## Status

### ⚠️ Important Notice

**This library is meant for research, prototyping, and experimentation.** While the underlying LibOQS library is well-maintained by the Open Quantum Safe project, both projects carry important caveats:

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
- **SLH-DSA** (FIPS 205, formerly SPHINCS+): 12 variants (SHA2 and SHAKE, 128/192/256-bit security, f/s modes)

These algorithm names are stable and will be maintained. If NIST updates implementation details, this library will track those changes as closely as possible.

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
- **SLH-DSA** (FIPS 205): 12 variants (SHA2 and SHAKE, 128/192/256-bit security, f/s modes)
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

✅ **Fully Supported** - Available through **npm** only due to package size limitations on JSR:

```typescript
// Alternative: Import from npm
import { createMLKEM768 } from "npm:@openforge-sh/liboqs";

const kem = await createMLKEM768();
const { publicKey, secretKey } = kem.generateKeyPair();
kem.destroy();
```

**How it works:** The library automatically detects the Deno runtime and loads optimized WASM modules built for deno compatibility (`ENVIRONMENT='web'` Emscripten build).

**Recommended Setup** - Create a `deno.json` for cleaner imports:
```json
{
  "imports": {
    "liboqs": "npm:@openforge-sh/liboqs@^0.14.0"
  }
}
```

Then import like:
```typescript
import { createMLKEM768 } from "liboqs";
```

**Using the CLI with Deno:**
```bash
# Run CLI directly (JSR)
deno run --allow-read npm:@openforge-sh/liboqs/cli kem keygen ml-kem-768

# Or from npm
deno run --allow-read npm:@openforge-sh/liboqs/cli kem keygen ml-kem-768
```

```json
# Or add to deno.json tasks:
{
  "tasks": {
    "liboqs": "deno run --allow-read npm:@openforge-sh/liboqs/cli"
  }
}
```
```bash
# Then run:
deno task liboqs list --kem
```

**Permissions:**
```bash
# Library usage (cryptographic operations only)
deno run --allow-read your-script.ts

# CLI usage (may need write for output files)
deno run --allow-read --allow-write npm:@openforge-sh/liboqs/cli kem keygen ml-kem-768 --output-dir ./keys
```

Deno automatically caches packages on first run - no separate install step needed.

## Requirements

- **Node.js 22.0 or higher** (for WASM SIMD support)
- **Package Managers**: Bun 1.0+, npm 10+, pnpm 8+, yarn 4+ (for Node.js)
- **Deno 2.0+** (available only through npm)
- **Modern browsers** with WebAssembly support (Chrome 91+, Firefox 89+, Edge 91+, Safari 16.4+ - Safari is untested)

## Quick Start

### Command Line Interface

The package includes a CLI for cryptographic operations without writing code:

```bash
# Generate ML-KEM-768 keypair
npx @openforge-sh/liboqs kem keygen ml-kem-768 --output-dir ./keys

# Encapsulate to create shared secret
npx @openforge-sh/liboqs kem encapsulate ml-kem-768 ./keys/public.key --format base64

# Sign a message
npx @openforge-sh/liboqs sig sign ml-dsa-65 message.txt ./keys/secret.key -o signature.sig

# Verify signature
npx @openforge-sh/liboqs sig verify ml-dsa-65 message.txt signature.sig ./keys/public.key

# List available algorithms
npx @openforge-sh/liboqs list --kem

# Get algorithm info
npx @openforge-sh/liboqs info ml-kem-768
```

**Works with all package managers:**
- `npx @openforge-sh/liboqs` (npm)
- `bunx @openforge-sh/liboqs` (bun)
- `pnpm dlx @openforge-sh/liboqs` (pnpm)
- `yarn dlx @openforge-sh/liboqs` (yarn)

**For full CLI documentation, run:**
```bash
npx @openforge-sh/liboqs --help
```

### Key Encapsulation (ML-KEM)

```javascript
import { createMLKEM768 } from '@openforge-sh/liboqs';

// Alice generates keypair
const alice = await createMLKEM768();
const { publicKey, secretKey } = alice.generateKeyPair();

// Bob encapsulates shared secret
const bob = await createMLKEM768();
const { ciphertext, sharedSecret } = bob.encapsulate(publicKey);

// Alice decapsulates
const aliceSecret = alice.decapsulate(ciphertext, secretKey);

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
const { publicKey, secretKey } = signer.generateKeyPair();

const message = new TextEncoder().encode('Hello, quantum world!');
const signature = signer.sign(message, secretKey);

const isValid = signer.verify(message, signature, publicKey);
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
- **SLH-DSA-SHA2-128f** - NIST Level 1 (128-bit quantum security, fast) - `createSLHDSASHA2128f()`
- **SLH-DSA-SHA2-128s** - NIST Level 1 (128-bit quantum security, small) - `createSLHDSASHA2128s()`
- **SLH-DSA-SHA2-192f** - NIST Level 3 (192-bit quantum security, fast) - `createSLHDSASHA2192f()`
- **SLH-DSA-SHA2-192s** - NIST Level 3 (192-bit quantum security, small) - `createSLHDSASHA2192s()`
- **SLH-DSA-SHA2-256f** - NIST Level 5 (256-bit quantum security, fast) - `createSLHDSASHA2256f()`
- **SLH-DSA-SHA2-256s** - NIST Level 5 (256-bit quantum security, small) - `createSLHDSASHA2256s()`
- **SLH-DSA-SHAKE-128f** - NIST Level 1 (128-bit quantum security, fast) - `createSLHDSASHAKE128f()`
- **SLH-DSA-SHAKE-128s** - NIST Level 1 (128-bit quantum security, small) - `createSLHDSASHAKE128s()`
- **SLH-DSA-SHAKE-192f** - NIST Level 3 (192-bit quantum security, fast) - `createSLHDSASHAKE192f()`
- **SLH-DSA-SHAKE-192s** - NIST Level 3 (192-bit quantum security, small) - `createSLHDSASHAKE192s()`
- **SLH-DSA-SHAKE-256f** - NIST Level 5 (256-bit quantum security, fast) - `createSLHDSASHAKE256f()`
- **SLH-DSA-SHAKE-256s** - NIST Level 5 (256-bit quantum security, small) - `createSLHDSASHAKE256s()`

### Algorithm Details

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext/Signature |
|-----------|----------------|------------|------------|----------------------|
| ML-KEM-512 | Level 1 (128-bit) | 800 B | 1,632 B | 768 B |
| ML-KEM-768 | Level 3 (192-bit) | 1,184 B | 2,400 B | 1,088 B |
| ML-KEM-1024 | Level 5 (256-bit) | 1,568 B | 3,168 B | 1,568 B |
| ML-DSA-44 | Level 2 (128-bit) | 1,312 B | 2,560 B | ~2,420 B |
| ML-DSA-65 | Level 3 (192-bit) | 1,952 B | 4,032 B | ~3,309 B |
| ML-DSA-87 | Level 5 (256-bit) | 2,592 B | 4,896 B | ~4,627 B |
| SLH-DSA-SHA2-128f | Level 1 (128-bit) | 32 B | 64 B | 17,088 B |
| SLH-DSA-SHA2-128s | Level 1 (128-bit) | 32 B | 64 B | 7,856 B |
| SLH-DSA-SHA2-192f | Level 3 (192-bit) | 48 B | 96 B | 35,664 B |
| SLH-DSA-SHA2-192s | Level 3 (192-bit) | 48 B | 96 B | 16,224 B |
| SLH-DSA-SHA2-256f | Level 5 (256-bit) | 64 B | 128 B | 49,856 B |
| SLH-DSA-SHA2-256s | Level 5 (256-bit) | 64 B | 128 B | 29,792 B |
| SLH-DSA-SHAKE-128f | Level 1 (128-bit) | 32 B | 64 B | 17,088 B |
| SLH-DSA-SHAKE-128s | Level 1 (128-bit) | 32 B | 64 B | 7,856 B |
| SLH-DSA-SHAKE-192f | Level 3 (192-bit) | 48 B | 96 B | 35,664 B |
| SLH-DSA-SHAKE-192s | Level 3 (192-bit) | 48 B | 96 B | 16,224 B |
| SLH-DSA-SHAKE-256f | Level 5 (256-bit) | 64 B | 128 B | 49,856 B |
| SLH-DSA-SHAKE-256s | Level 5 (256-bit) | 64 B | 128 B | 29,792 B |

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

Tree-shaking ensures unused algorithms are never included in your bundle. Each algorithm's WASM is embedded in its module and loaded when you import the factory function.

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
│   │       ├── slh-dsa/          # SLH-DSA (12 variants)
│   │       ├── cross/            # CROSS (18 variants)
│   │       ├── mayo/             # MAYO (4 variants)
│   │       ├── snova/            # SNOVA (12 variants)
│   │       └── uov/              # UOV (12 variants)
│   ├── cli/
│   │   ├── commands/             # CLI command implementations
│   │   │   ├── info.js           # Algorithm information
│   │   │   ├── kem.js            # KEM operations (keygen, encaps, decaps)
│   │   │   ├── sig.js            # Signature operations (keygen, sign, verify)
│   │   │   └── list.js           # List available algorithms
│   │   ├── algorithms.js         # Algorithm registry
│   │   ├── index.js              # CLI entry point
│   │   ├── io.js                 # File I/O utilities
│   │   └── parser.js             # Command parser
│   ├── core/
│   │   ├── errors.js             # Error classes
│   │   └── validation.js         # Input validation utilities
│   ├── types/                    # TypeScript definitions
│   │   ├── algorithms.d.ts
│   │   ├── errors.d.ts
│   │   └── index.d.ts
│   ├── index.js                  # Main entry (all 97 algorithms)
│   ├── kem.js                    # KEM exports (32 algorithms)
│   └── sig.js                    # Signature exports (65 algorithms)
├── bin/
│   └── cli.js                    # CLI executable entry point
├── tests/
│   ├── kem.test.ts
│   ├── sig.test.ts
│   ├── cli.test.ts
│   └── deno/                     # Deno-specific tests
│       ├── kem.test.ts
│       ├── sig.test.ts
│       └── cli.test.ts
├── dist/                         # WASM modules (97 × 2 = 194 files, ~100-500KB each)
│   ├── ml-kem-512.min.js         # Node.js/Browser module
│   ├── ml-kem-512.deno.js        # Deno module
│   ├── falcon-512.min.js
│   ├── falcon-512.deno.js
│   └── ... (and 190 others)
├── algorithms.json               # Algorithm registry and metadata
└── build.sh                      # WASM build script
```

## Architecture

The library is organized in layers:

1. **WASM Modules**: Emscripten-compiled LibOQS binaries (one per algorithm)
2. **Low-level Bindings**: Direct WASM function calls (`_OQS_KEM_*`, `_OQS_SIG_*`)
3. **High-level Wrappers**: User-friendly classes (`MLKEM768`, `MLDSA65`)
4. **Public API**: Factory functions and exports

### Memory Management

**IMPORTANT**: Always call `destroy()` when finished with an algorithm instance. WASM memory is not garbage-collected by JavaScript.

#### Why This Matters

WebAssembly modules allocate native memory outside the JavaScript heap. When you create an algorithm instance, LibOQS allocates C structures that JavaScript's garbage collector cannot reclaim. Without calling `destroy()`, this memory leaks permanently.

**Long-running applications** (servers, single-page apps, daemons) that don't call `destroy()` will experience:
- Increasing memory usage over time
- Eventually: allocation failures or crashes when the 256MB WASM heap limit is reached

**Short-lived scripts** are less affected since the OS reclaims all memory when the process exits.

#### Best Practices

```javascript
// Pattern 1: Simple cleanup
const kem = await createMLKEM768();
const { publicKey, secretKey } = kem.generateKeyPair();
kem.destroy();

// Pattern 2: Error-safe cleanup (recommended)
const kem = await createMLKEM768();
try {
  const { publicKey, secretKey } = kem.generateKeyPair();
  const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
  // ... use results ...
} finally {
  kem.destroy(); // Always runs, even if errors occur
}

// Pattern 3: Multiple operations
const sig = await createMLDSA65();
try {
  const { publicKey, secretKey } = sig.generateKeyPair();
  const message = new TextEncoder().encode('Hello!');
  const signature = sig.sign(message, secretKey);
  const isValid = sig.verify(message, signature, publicKey);
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

1. **Use NIST Standardized Algorithms**: ML-KEM, ML-DSA, and SLH-DSA are recommended for production
2. **Hybrid Cryptography**: We, as well as OQS, strongly recommend combining with traditional algorithms (X25519/Ed25519) during transition
3. **Key Storage**: Store secret keys securely, never in plain text or localStorage
4. **Stay Updated**: Monitor NIST guidance and update regularly
5. **Audit Your Deployment**: Consult cryptographic experts for production use
6. **Random Number Generation**: This library uses system entropy (Node.js `crypto.randomBytes()`, browser `crypto.getRandomValues()`)

### Reporting Security Issues

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy. Issues specific to the LibOQS C library should be reported to the [LibOQS project](https://github.com/open-quantum-safe/liboqs/security).

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

The library provides an **automated template generator** that creates algorithm wrapper files from `algorithms.json`:

#### Quick Start

```bash
# 1. Add algorithm metadata to algorithms.json
# 2. Fetch key sizes from existing file (if updating)
node scripts/fetch-key-sizes.js

# 3. Generate algorithm wrapper
node scripts/generate-algorithm.js <algorithm-slug>

# Or generate multiple algorithms at once
node scripts/generate-algorithm.js --all    # All algorithms
node scripts/generate-algorithm.js --kem    # All KEM algorithms
node scripts/generate-algorithm.js --sig    # All signature algorithms

# 4. Build WASM module
./build.sh <algorithm-slug>

# 5. Export from src/index.js, src/kem.js, or src/sig.js
```

#### Template System

All algorithm wrapper files follow a consistent pattern defined by the template generator (`scripts/generate-algorithm.js`). The templates automatically generate:

- **Documentation**: JSDoc comments with algorithm details, security levels, key sizes
- **Module loading**: Cross-runtime compatibility (Node.js, Deno, browsers)
- **Class structure**: Factory functions, wrapper classes, memory management
- **Validation**: Input validation for keys, ciphertexts, signatures
- **Type definitions**: Full TypeScript support via JSDoc

**Example**: Adding a new algorithm to `algorithms.json`:

```json
{
  "sig": {
    "slh-dsa": {
      "SLH-DSA-SHA2-128f": {
        "slug": "slh-dsa-sha2-128f",
        "cmake_var": "SLH_DSA_PURE_SHA2_128F",
        "security": 1,
        "standardized": true,
        "keySize": {
          "publicKey": 32,
          "secretKey": 64,
          "signature": 17088
        }
      }
    }
  }
}
```

Then generate the wrapper:

```bash
node scripts/generate-algorithm.js slh-dsa-sha2-128f
# ✓ Generated: src/algorithms/sig/slh-dsa/slh-dsa-sha2-128f.js
```

#### Key Size Management

The `fetch-key-sizes.js` script extracts key sizes from existing algorithm files and updates `algorithms.json`:

```bash
node scripts/fetch-key-sizes.js
# Scans src/algorithms/**/*.js for keySize data
# Updates algorithms.json with found key sizes
```

This is useful when:
- Updating key sizes after LibOQS version changes
- Ensuring consistency across the codebase
- Adding new algorithms

#### Manual Steps Required

After generating wrappers:

1. **Export in index files**: Add to `src/index.js`, `src/kem.js`, or `src/sig.js`
2. **Add tests**: Follow patterns in `tests/kem.test.ts` or `tests/sig.test.ts`
3. **Update TypeScript definitions**: If needed, update `src/types/algorithms.d.ts`
4. **Add additional algorithm information**: The script leaves a TODO section in JSDoc, for algorithm-specific information that's difficult to automate

The template system ensures all 97 algorithms maintain consistent APIs, documentation, and error handling patterns.

## Testing

The library includes comprehensive test coverage using Vitest:

```bash
# Run all tests (1295+ tests across 97 algorithms)
bun test

# Or use your preferred package manager
npm test
pnpm test
yarn test

# Or with Deno:
deno test --allow-read --allow-write --allow-run --allow-env --no-check tests/deno/
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

- **Tests must pass**: Run `bun run test` (or `npm run test`) and `deno test --allow-read --allow-write --allow-run --allow-env --no-check tests/deno/` before submitting
- **Follow existing code style**: Use ESM, async/await, JSDoc comments (if not using the generator script)
- **Document public APIs**: Add comprehensive JSDoc for all exported functions and classes (if not using the generator script)
- **Security first**: Consider security implications, especially for cryptographic operations
- **Consistency matters**: Follow established patterns in existing wrappers (if not using the generator script)

For larger changes, open an issue first to discuss the approach.

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
- **[LibOQS Documentation](https://github.com/open-quantum-safe/liboqs)** - Underlying C library

## License

MIT License - see [LICENSE.md](LICENSE.md) for details.

## Acknowledgments

- [Open Quantum Safe](https://openquantumsafe.org/) project for LibOQS
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- The cryptographic research community
- Emscripten team for excellent WASM tooling

## Versioning

This library's version tracks the bundled LibOQS version:
- `@openforge-sh/liboqs 0.14.0` includes `LibOQS 0.14.0`

## Disclaimer

This library provides access to cryptographic algorithms believed to be quantum-resistant based on current research. The field of post-quantum cryptography is evolving. Algorithm support may change as research advances. Always consult with cryptographic experts for production deployments and follow NIST recommendations.

The LibOQS project states: **"WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA."** This guidance applies to this JavaScript/WebAssembly wrapper as well.

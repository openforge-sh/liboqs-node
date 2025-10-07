#!/usr/bin/env node

/**
 * @fileoverview Algorithm file generator for LibOQS WASM wrapper
 * @description Generates individual algorithm implementation files from algorithms.json
 *
 * Usage:
 *   node scripts/generate-algorithm.js <slug>
 *   node scripts/generate-algorithm.js --all
 *   node scripts/generate-algorithm.js --kem
 *   node scripts/generate-algorithm.js --sig
 */

import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import process from "node:process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

// Load algorithms registry
const algorithmsPath = join(rootDir, 'algorithms.json');
const algorithms = JSON.parse(readFileSync(algorithmsPath, 'utf8'));

/**
 * Convert slug to PascalCase class name
 * @param {string} slug - Algorithm slug (e.g., "ml-kem-768")
 * @returns {string} PascalCase name (e.g., "MLKEM768")
 */
function slugToClassName(slug) {
  return slug
    .split('-')
    .map(part => part.toUpperCase())
    .join('');
}

/**
 * Convert slug to constant name
 * @param {string} slug - Algorithm slug (e.g., "ml-kem-768")
 * @returns {string} Constant name (e.g., "ML_KEM_768")
 */
function slugToConstantName(slug) {
  return slug.toUpperCase().replace(/-/g, '_');
}

/**
 * Generate KEM algorithm file
 */
function generateKEMFile(name, data) {
  const { slug, security, standardized, deprecated } = data;
  const className = slugToClassName(slug);
  const constantName = slugToConstantName(slug);
  const displayName = name;

  // Get key sizes from LibOQS documentation or defaults
  // These should be provided in algorithms.json or queried from LibOQS
  const keySizes = data.keySize || {
    publicKey: 'UNKNOWN',
    secretKey: 'UNKNOWN',
    ciphertext: 'UNKNOWN',
    sharedSecret: 32
  };

  const securityBits = security === 1 ? 128 : security === 3 ? 192 : security === 5 ? 256 : 'unknown';
  const deprecatedNote = deprecated ? '\n *\n * **DEPRECATED:** This algorithm is deprecated. Please use a standardized alternative.' : '';
  const standardizedNote = standardized ? ' (NIST standardized)' : '';

  return `/**
 * @fileoverview ${displayName} KEM algorithm implementation
 * @module algorithms/kem/${slug.split('-')[0]}/${slug}
 * @description
 * ${displayName} is a key encapsulation mechanism providing NIST security level ${security}.${deprecatedNote}
 *
 * TODO: Add algorithm-specific description, features, and characteristics
 *
 * Key features:
 * - Post-quantum cryptography
 * - Security Level ${security} (${securityBits}-bit classical, quantum-resistant)${standardizedNote}
 * - IND-CCA2 security
 *
 * @see {@link https://openquantumsafe.org/} - LibOQS documentation
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? \`../../../../dist/${slug}.deno.js\`
    : \`../../../../dist/${slug}.min.js\`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * ${constantName}_INFO algorithm constants and metadata
 * @type {{readonly name: '${displayName}', readonly identifier: '${displayName}', readonly type: 'kem', readonly securityLevel: ${security}, readonly standardized: ${standardized || false}, ${deprecated ? `readonly deprecated: true, ` : ''}readonly description: string, readonly keySize: {readonly publicKey: number, readonly secretKey: number, readonly ciphertext: number, readonly sharedSecret: number}}}
 */
export const ${constantName}_INFO = {
  name: '${displayName}',
  identifier: '${displayName}',
  type: 'kem',
  securityLevel: ${security},
  standardized: ${standardized || false},${deprecated ? `
  deprecated: true,` : ''}
  description: '${displayName} (${securityBits}-bit quantum security)${deprecated ? ' - DEPRECATED' : ''}',
  keySize: {
    publicKey: ${keySizes.publicKey},
    secretKey: ${keySizes.secretKey},
    ciphertext: ${keySizes.ciphertext},
    sharedSecret: ${keySizes.sharedSecret}
  }
};

/**
 * Factory function to create a ${displayName} KEM instance
 *
 * @async
 * @function create${className}
 * @returns {Promise<${className}>} Initialized ${displayName} instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { create${className} } from '@openforge-sh/liboqs';
 *
 * const kem = await create${className}();
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * kem.destroy();
 */
export async function create${className}() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = ${constantName}_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('${displayName}', 'Failed to create KEM instance');
  }

  return new ${className}(wasmModule, kemPtr);
}

/**
 * ${displayName} wrapper class providing high-level KEM operations
 *
 * This class wraps the low-level WASM module to provide a user-friendly
 * interface for ${displayName} operations with automatic memory management
 * and input validation.
 *
 * @class ${className}
 * @example
 * import { create${className} } from '@openforge-sh/liboqs';
 *
 * const kem = await create${className}();
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
 * kem.destroy();
 */
export class ${className} {
  /** @type {Object} @private */
  #wasmModule;
  /** @type {number} @private */
  #kemPtr;
  /** @type {boolean} @private */
  #destroyed = false;

  /**
   * @param {Object} wasmModule - Emscripten WASM module
   * @param {number} kemPtr - Pointer to KEM instance
   * @private
   */
  constructor(wasmModule, kemPtr) {
    this.#wasmModule = wasmModule;
    this.#kemPtr = kemPtr;
  }

  /**
   * Generate a new keypair for ${displayName}
   *
   * Generates a public/private keypair using the algorithm's internal
   * random number generator. The secret key must be kept confidential.
   *
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSOperationError} If keypair generation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const { publicKey, secretKey } = kem.generateKeyPair();
   * // publicKey: ${keySizes.publicKey} bytes
   * // secretKey: ${keySizes.secretKey} bytes (keep confidential!)
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKeyPtr = this.#wasmModule._malloc(${constantName}_INFO.keySize.publicKey);
    const secretKeyPtr = this.#wasmModule._malloc(${constantName}_INFO.keySize.secretKey);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('keypair', '${displayName}', \`Error code: \${result}\`);
      }

      const publicKey = new Uint8Array(${constantName}_INFO.keySize.publicKey);
      const secretKey = new Uint8Array(${constantName}_INFO.keySize.secretKey);

      publicKey.set(this.#wasmModule.HEAPU8.subarray(publicKeyPtr, publicKeyPtr + ${constantName}_INFO.keySize.publicKey));
      secretKey.set(this.#wasmModule.HEAPU8.subarray(secretKeyPtr, secretKeyPtr + ${constantName}_INFO.keySize.secretKey));

      return { publicKey, secretKey };

    } finally {
      this.#wasmModule._free(publicKeyPtr);
      this.#wasmModule._free(secretKeyPtr);
    }
  }

  /**
   * Encapsulate a shared secret using a public key
   *
   * Generates a random shared secret and encapsulates it using the
   * provided public key. The shared secret can be used for symmetric
   * encryption.
   *
   * @param {Uint8Array} publicKey - Recipient's public key (${keySizes.publicKey} bytes)
   * @returns {{ciphertext: Uint8Array, sharedSecret: Uint8Array}}
   * @throws {LibOQSValidationError} If public key is invalid
   * @throws {LibOQSOperationError} If encapsulation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const { ciphertext, sharedSecret } = kem.encapsulate(recipientPublicKey);
   * // ciphertext: ${keySizes.ciphertext} bytes (send to recipient)
   * // sharedSecret: ${keySizes.sharedSecret} bytes (use for symmetric encryption)
   */
  encapsulate(publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);

    const publicKeyPtr = this.#wasmModule._malloc(${constantName}_INFO.keySize.publicKey);
    const ciphertextPtr = this.#wasmModule._malloc(${constantName}_INFO.keySize.ciphertext);
    const sharedSecretPtr = this.#wasmModule._malloc(${constantName}_INFO.keySize.sharedSecret);

    try {
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_KEM_encaps(
        this.#kemPtr,
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('encaps', '${displayName}', \`Error code: \${result}\`);
      }

      const ciphertext = new Uint8Array(${constantName}_INFO.keySize.ciphertext);
      const sharedSecret = new Uint8Array(${constantName}_INFO.keySize.sharedSecret);

      ciphertext.set(this.#wasmModule.HEAPU8.subarray(ciphertextPtr, ciphertextPtr + ${constantName}_INFO.keySize.ciphertext));
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + ${constantName}_INFO.keySize.sharedSecret));

      return { ciphertext, sharedSecret };

    } finally {
      this.#wasmModule._free(publicKeyPtr);
      this.#wasmModule._free(ciphertextPtr);
      this.#wasmModule._free(sharedSecretPtr);
    }
  }

  /**
   * Decapsulate a shared secret using a secret key
   *
   * Recovers the shared secret from a ciphertext using the secret key.
   * The recovered shared secret will match the one generated during
   * encapsulation.
   *
   * @param {Uint8Array} ciphertext - Ciphertext received (${keySizes.ciphertext} bytes)
   * @param {Uint8Array} secretKey - Recipient's secret key (${keySizes.secretKey} bytes)
   * @returns {Uint8Array} Recovered shared secret (${keySizes.sharedSecret} bytes)
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If decapsulation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const sharedSecret = kem.decapsulate(ciphertext, mySecretKey);
   * // sharedSecret: ${keySizes.sharedSecret} bytes (matches sender's shared secret)
   */
  decapsulate(ciphertext, secretKey) {
    this.#checkDestroyed();
    this.#validateCiphertext(ciphertext);
    this.#validateSecretKey(secretKey);

    const ciphertextPtr = this.#wasmModule._malloc(${constantName}_INFO.keySize.ciphertext);
    const secretKeyPtr = this.#wasmModule._malloc(${constantName}_INFO.keySize.secretKey);
    const sharedSecretPtr = this.#wasmModule._malloc(${constantName}_INFO.keySize.sharedSecret);

    try {
      this.#wasmModule.HEAPU8.set(ciphertext, ciphertextPtr);
      this.#wasmModule.HEAPU8.set(secretKey, secretKeyPtr);

      const result = this.#wasmModule._OQS_KEM_decaps(
        this.#kemPtr,
        sharedSecretPtr,
        ciphertextPtr,
        secretKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('decaps', '${displayName}', \`Error code: \${result}\`);
      }

      const sharedSecret = new Uint8Array(${constantName}_INFO.keySize.sharedSecret);
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + ${constantName}_INFO.keySize.sharedSecret));

      return sharedSecret;

    } finally {
      this.#wasmModule._free(ciphertextPtr);
      this.#wasmModule._free(secretKeyPtr);
      this.#wasmModule._free(sharedSecretPtr);
    }
  }

  /**
   * Clean up resources and free WASM memory
   *
   * This method should be called when you're done using the instance
   * to free WASM memory. After calling destroy(), the instance cannot
   * be used for further operations.
   *
   * @example
   * const kem = await create${className}();
   * // ... use kem ...
   * kem.destroy();
   */
  destroy() {
    if (!this.#destroyed) {
      if (this.#kemPtr) {
        this.#wasmModule._OQS_KEM_free(this.#kemPtr);
        this.#kemPtr = null;
      }
      this.#destroyed = true;
    }
  }

  /**
   * Get algorithm information and constants
   * @returns {typeof ${constantName}_INFO} Algorithm metadata
   * @example
   * const info = kem.info;
   * console.log(info.keySize.publicKey); // ${keySizes.publicKey}
   */
  get info() {
    return ${constantName}_INFO;
  }

  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', '${displayName}');
    }
  }

  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== ${constantName}_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        \`Invalid public key: expected \${${constantName}_INFO.keySize.publicKey} bytes, got \${publicKey?.length ?? 'null'}\`,
        '${displayName}'
      );
    }
  }

  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== ${constantName}_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        \`Invalid secret key: expected \${${constantName}_INFO.keySize.secretKey} bytes, got \${secretKey?.length ?? 'null'}\`,
        '${displayName}'
      );
    }
  }

  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== ${constantName}_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        \`Invalid ciphertext: expected \${${constantName}_INFO.keySize.ciphertext} bytes, got \${ciphertext?.length ?? 'null'}\`,
        '${displayName}'
      );
    }
  }
}
`;
}

/**
 * Generate SIG algorithm file
 */
function generateSIGFile(name, data) {
  const { slug, security, standardized, deprecated } = data;
  const className = slugToClassName(slug);
  const constantName = slugToConstantName(slug);
  const displayName = name;

  // Get key sizes from LibOQS documentation or defaults
  const keySizes = data.keySize || {
    publicKey: 'UNKNOWN',
    secretKey: 'UNKNOWN',
    signature: 'UNKNOWN'
  };

  const securityBits = security === 1 ? 128 : security === 2 ? 160 : security === 3 ? 192 : security === 5 ? 256 : 'unknown';
  const deprecatedNote = deprecated ? '\n *\n * **DEPRECATED:** This algorithm is deprecated. Please use a standardized alternative.' : '';
  const standardizedNote = standardized ? ' (NIST standardized)' : '';

  return `/**
 * @fileoverview ${displayName} signature algorithm implementation
 * @module algorithms/sig/${slug.split('-')[0]}/${slug}
 * @description
 * ${displayName} is a digital signature algorithm providing NIST security level ${security}.${deprecatedNote}
 *
 * TODO: Add algorithm-specific description, features, and characteristics
 *
 * Key features:
 * - Post-quantum cryptography
 * - Security Level ${security} (${securityBits}-bit classical, quantum-resistant)${standardizedNote}
 * - Strong existential unforgeability under chosen message attack (SUF-CMA)
 *
 * @see {@link https://openquantumsafe.org/} - LibOQS documentation
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? \`../../../../dist/${slug}.deno.js\`
    : \`../../../../dist/${slug}.min.js\`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * ${constantName}_INFO algorithm constants and metadata
 * @type {{readonly name: '${displayName}', readonly identifier: '${displayName}', readonly type: 'sig', readonly securityLevel: ${security}, readonly standardized: ${standardized || false}, ${deprecated ? `readonly deprecated: true, ` : ''}readonly description: string, readonly keySize: {readonly publicKey: number, readonly secretKey: number, readonly signature: number}}}
 */
export const ${constantName}_INFO = {
  name: '${displayName}',
  identifier: '${displayName}',
  type: 'sig',
  securityLevel: ${security},
  standardized: ${standardized || false},${deprecated ? `
  deprecated: true,` : ''}
  description: '${displayName} signature (NIST Level ${security}, ${securityBits}-bit quantum security)${deprecated ? ' - DEPRECATED' : ''}',
  keySize: {
    publicKey: ${keySizes.publicKey},
    secretKey: ${keySizes.secretKey},
    signature: ${keySizes.signature}
  }
};

/**
 * Load and initialize ${displayName} module
 * @returns {Promise<${className}>} Initialized ${displayName} instance
 * @throws {LibOQSInitError} If initialization fails
 * @example
 * import { create${className} } from '@openforge-sh/liboqs';
 * const sig = await create${className}();
 */
export async function create${className}() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = ${constantName}_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);

  if (!sigPtr) {
    throw new LibOQSInitError('${displayName}', 'Failed to create SIG instance');
  }

  return new ${className}(wasmModule, sigPtr);
}

/**
 * ${displayName} digital signature wrapper class
 *
 * Provides high-level interface for ${displayName} digital signature operations.
 * Automatically manages WASM memory and validates inputs.
 *
 * @class ${className}
 * @example
 * const sig = await create${className}();
 * const { publicKey, secretKey } = sig.generateKeyPair();
 *
 * const message = new TextEncoder().encode('Hello, quantum world!');
 * const signature = sig.sign(message, secretKey);
 *
 * const isValid = sig.verify(message, signature, publicKey);
 * console.log('Valid:', isValid); // true
 *
 * sig.destroy();
 */
export class ${className} {
  #wasmModule;
  #sigPtr;
  #destroyed = false;

  /**
   * @param {Object} wasmModule - Emscripten WASM module
   * @param {number} sigPtr - Pointer to OQS_SIG structure
   * @private
   */
  constructor(wasmModule, sigPtr) {
    this.#wasmModule = wasmModule;
    this.#sigPtr = sigPtr;
  }

  /**
   * Generate a new ${displayName} keypair
   *
   * Creates a new public/private keypair for digital signatures.
   * The secret key must be kept confidential.
   *
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSOperationError} If key generation fails
   * @example
   * const { publicKey, secretKey } = sig.generateKeyPair();
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(${constantName}_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(${constantName}_INFO.keySize.secretKey);

    const pkPtr = this.#wasmModule._malloc(publicKey.length);
    const skPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, pkPtr, skPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', '${displayName}', 'Key generation failed');
      }

      publicKey.set(this.#wasmModule.HEAPU8.subarray(pkPtr, pkPtr + publicKey.length));
      secretKey.set(this.#wasmModule.HEAPU8.subarray(skPtr, skPtr + secretKey.length));

      return { publicKey, secretKey };
    } finally {
      this.#wasmModule._free(pkPtr);
      this.#wasmModule._free(skPtr);
    }
  }

  /**
   * Sign a message using the secret key
   *
   * Generates a digital signature for the provided message.
   * The signature can be verified using the corresponding public key.
   *
   * @param {Uint8Array} message - Message to sign (arbitrary length)
   * @param {Uint8Array} secretKey - Secret key for signing (${keySizes.secretKey} bytes)
   * @returns {Uint8Array} Digital signature (up to ${keySizes.signature} bytes)
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If signing fails
   * @example
   * const message = new TextEncoder().encode('Hello!');
   * const signature = sig.sign(message, secretKey);
   */
  sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateMessage(message);
    this.#validateSecretKey(secretKey);

    const signature = new Uint8Array(${constantName}_INFO.keySize.signature);
    const sigPtr = this.#wasmModule._malloc(signature.length);
    const sigLenPtr = this.#wasmModule._malloc(8); // size_t
    const msgPtr = this.#wasmModule._malloc(message.length);
    const skPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      this.#wasmModule.HEAPU8.set(message, msgPtr);
      this.#wasmModule.HEAPU8.set(secretKey, skPtr);
      this.#wasmModule.setValue(sigLenPtr, signature.length, 'i64');

      const result = this.#wasmModule._OQS_SIG_sign(
        this.#sigPtr,
        sigPtr,
        sigLenPtr,
        msgPtr,
        message.length,
        skPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('sign', '${displayName}', 'Signing failed');
      }

      const actualSigLen = this.#wasmModule.getValue(sigLenPtr, 'i32');
      const actualSignature = new Uint8Array(actualSigLen);
      actualSignature.set(this.#wasmModule.HEAPU8.subarray(sigPtr, sigPtr + actualSigLen));

      return actualSignature;
    } finally {
      this.#wasmModule._free(sigPtr);
      this.#wasmModule._free(sigLenPtr);
      this.#wasmModule._free(msgPtr);
      this.#wasmModule._free(skPtr);
    }
  }

  /**
   * Verify a signature against a message using the public key
   *
   * Verifies that the signature is valid for the given message and public key.
   *
   * @param {Uint8Array} message - Original message that was signed
   * @param {Uint8Array} signature - Signature to verify
   * @param {Uint8Array} publicKey - Public key for verification (${keySizes.publicKey} bytes)
   * @returns {boolean} True if signature is valid, false otherwise
   * @throws {LibOQSValidationError} If inputs are invalid
   * @example
   * const isValid = sig.verify(message, signature, publicKey);
   * if (isValid) {
   *   console.log('Signature is valid!');
   * }
   */
  verify(message, signature, publicKey) {
    this.#checkDestroyed();
    this.#validateMessage(message);
    this.#validateSignature(signature);
    this.#validatePublicKey(publicKey);

    const msgPtr = this.#wasmModule._malloc(message.length);
    const sigPtr = this.#wasmModule._malloc(signature.length);
    const pkPtr = this.#wasmModule._malloc(publicKey.length);

    try {
      this.#wasmModule.HEAPU8.set(message, msgPtr);
      this.#wasmModule.HEAPU8.set(signature, sigPtr);
      this.#wasmModule.HEAPU8.set(publicKey, pkPtr);

      const result = this.#wasmModule._OQS_SIG_verify(
        this.#sigPtr,
        msgPtr,
        message.length,
        sigPtr,
        signature.length,
        pkPtr
      );

      return result === 0;
    } finally {
      this.#wasmModule._free(msgPtr);
      this.#wasmModule._free(sigPtr);
      this.#wasmModule._free(pkPtr);
    }
  }

  /**
   * Clean up WASM resources
   *
   * Frees the native signature structure. The instance cannot be used after calling destroy().
   *
   * @example
   * sig.destroy();
   */
  destroy() {
    if (!this.#destroyed) {
      if (this.#sigPtr) {
        this.#wasmModule._OQS_SIG_free(this.#sigPtr);
        this.#sigPtr = null;
      }
      this.#destroyed = true;
    }
  }

  /**
   * Get algorithm information
   * @returns {typeof ${constantName}_INFO} Algorithm metadata
   */
  get info() {
    return ${constantName}_INFO;
  }

  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', '${displayName}');
    }
  }

  #validateMessage(message) {
    if (!ArrayBuffer.isView(message) || message.constructor.name !== 'Uint8Array') {
      throw new LibOQSValidationError(
        'Message must be Uint8Array',
        '${displayName}'
      );
    }
  }

  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== ${constantName}_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        \`Invalid public key: expected \${${constantName}_INFO.keySize.publicKey} bytes, got \${publicKey?.length ?? 'null'}\`,
        '${displayName}'
      );
    }
  }

  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== ${constantName}_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        \`Invalid secret key: expected \${${constantName}_INFO.keySize.secretKey} bytes, got \${secretKey?.length ?? 'null'}\`,
        '${displayName}'
      );
    }
  }

  #validateSignature(signature) {
    if (!isUint8Array(signature)) {
      throw new LibOQSValidationError(
        'Signature must be Uint8Array',
        '${displayName}'
      );
    }
    if (signature.length === 0 || signature.length > ${constantName}_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        \`Invalid signature length: expected up to \${${constantName}_INFO.keySize.signature} bytes, got \${signature.length}\`,
        '${displayName}'
      );
    }
  }
}
`;
}

/**
 * Find algorithm data by slug
 */
function findAlgorithm(slug) {
  for (const [type, families] of Object.entries(algorithms)) {
    for (const [family, algos] of Object.entries(families)) {
      for (const [name, data] of Object.entries(algos)) {
        if (data.slug === slug) {
          return { type, family, name, ...data };
        }
      }
    }
  }
  return null;
}

/**
 * Get all algorithms of a specific type
 */
function getAllAlgorithms(type = null) {
  const results = [];
  for (const [algType, families] of Object.entries(algorithms)) {
    if (type && algType !== type) continue;
    for (const [family, algos] of Object.entries(families)) {
      for (const [name, data] of Object.entries(algos)) {
        results.push({ type: algType, family, name, ...data });
      }
    }
  }
  return results;
}

/**
 * Generate a single algorithm file
 */
function generateAlgorithm(slug) {
  const algo = findAlgorithm(slug);

  if (!algo) {
    console.error(`Algorithm "${slug}" not found in algorithms.json`);
    process.exit(1);
  }

  const { type, family, name } = algo;
  const familyDir = family.replace(/_/g, '-');
  const outputPath = join(rootDir, 'src', 'algorithms', type, familyDir, `${slug}.js`);

  // Ensure directory exists
  mkdirSync(dirname(outputPath), { recursive: true });

  // Generate file content
  const content = type === 'kem'
    ? generateKEMFile(name, algo)
    : generateSIGFile(name, algo);

  // Write file
  writeFileSync(outputPath, content, 'utf8');
  console.log(`✓ Generated: ${outputPath}`);
}

/**
 * Main function
 */
function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log(`
Algorithm File Generator

Usage:
  node scripts/generate-algorithm.js <slug>     Generate specific algorithm
  node scripts/generate-algorithm.js --all      Generate all algorithms
  node scripts/generate-algorithm.js --kem      Generate all KEM algorithms
  node scripts/generate-algorithm.js --sig      Generate all SIG algorithms

Examples:
  node scripts/generate-algorithm.js ml-kem-768
  node scripts/generate-algorithm.js --all
`);
    process.exit(0);
  }

  const arg = args[0];

  if (arg === '--all') {
    const allAlgos = getAllAlgorithms();
    console.log(`Generating ${allAlgos.length} algorithm files...`);
    allAlgos.forEach(algo => generateAlgorithm(algo.slug));
    console.log(`\n✓ Generated ${allAlgos.length} algorithm files`);
  } else if (arg === '--kem') {
    const kemAlgos = getAllAlgorithms('kem');
    console.log(`Generating ${kemAlgos.length} KEM algorithm files...`);
    kemAlgos.forEach(algo => generateAlgorithm(algo.slug));
    console.log(`\n✓ Generated ${kemAlgos.length} KEM algorithm files`);
  } else if (arg === '--sig') {
    const sigAlgos = getAllAlgorithms('sig');
    console.log(`Generating ${sigAlgos.length} SIG algorithm files...`);
    sigAlgos.forEach(algo => generateAlgorithm(algo.slug));
    console.log(`\n✓ Generated ${sigAlgos.length} SIG algorithm files`);
  } else {
    generateAlgorithm(arg);
  }
}

main();

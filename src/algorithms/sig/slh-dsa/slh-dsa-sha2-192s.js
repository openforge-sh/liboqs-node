/**
 * @fileoverview SLH-DSA-SHA2-192s signature algorithm implementation
 * @module algorithms/sig/sphincs/slh-dsa-sha2-192s
 * @description
 * SLH-DSA-SHA2-192s is a stateless hash-based signature scheme providing NIST security level 3.
 * This variant uses SHA2 for hashing, is optimized for signature size, and uses simple mode.
 *
 * Key features:
 * - Stateless hash-based signatures
 * - Security Level 3 (192-bit classical, quantum-resistant)
 * - SHA2 hash function
 * - Small signature size
 * - FIPS 205 standardized
 *
 * @see {@link https://csrc.nist.gov/pubs/fips/205/final} - FIPS 205: SLH-DSA specification - SPHINCS+ specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/slh-dsa-sha2-192s.deno.js`
    : `../../../../dist/slh-dsa-sha2-192s.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * SLH-DSA-SHA2-192S-INFO algorithm constants and metadata
 * @type {{readonly name: 'SLH-DSA-SHA2-192s', readonly identifier: 'SLH_DSA_PURE_SHA2_192S', readonly type: 'sig', readonly securityLevel: 3, readonly standardized: true, readonly description: string, readonly keySize: {readonly publicKey: 48, readonly secretKey: 96, readonly signature: 16224}}}
 */
export const SLH_DSA_SHA2_192S_INFO = {
  name: 'SLH-DSA-SHA2-192s',
  identifier: 'SLH_DSA_PURE_SHA2_192S',
  type: 'sig',
  securityLevel: 3,
  standardized: true,
  description: 'SLH-DSA-SHA2-192s hash-based signature (NIST Level 3, 192-bit quantum security, SHA2, small, simple)',
  keySize: {
    publicKey: 48,
    secretKey: 96,
    signature: 16224
  }
};

/**
 * Factory function to create a SLH-DSA-SHA2-192s signature instance
 *
 * @async
 * @function createSlhDsaSha2192s
 * @returns {Promise<SlhDsaSha2192s>} Initialized SLH-DSA-SHA2-192s instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createSlhDsaSha2192s } from '@openforge-sh/liboqs';
 *
 * const sig = await createSlhDsaSha2192s();
 * const { publicKey, secretKey } = sig.generateKeyPair();
 * sig.destroy();
 */
export async function createSlhDsaSha2192s() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = SLH_DSA_SHA2_192S_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);

  if (!sigPtr) {
    throw new LibOQSInitError('SLH-DSA-SHA2-192s', 'Failed to create SIG instance');
  }

  return new SlhDsaSha2192s(wasmModule, sigPtr);
}

/**
 * SLH-DSA-SHA2-192s signature scheme wrapper class
 *
 * @class SlhDsaSha2192s
 * @description
 * High-level wrapper for SLH-DSA-SHA2-192s signature operations. Provides secure key generation,
 * signing, and verification with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const sig = await createSlhDsaSha2192s();
 *
 * // Generate keypair
 * const { publicKey, secretKey } = sig.generateKeyPair();
 *
 * // Sign message
 * const message = new TextEncoder().encode('Hello, world!');
 * const signature = sig.sign(message, secretKey);
 *
 * // Verify signature
 * const isValid = sig.verify(message, signature, publicKey);
 *
 * // Cleanup
 * sig.destroy();
 */
export class SlhDsaSha2192s {
  /** @type {Object} @private */ #wasmModule;
  /** @type {number} @private */ #sigPtr;
  /** @type {boolean} @private */ #destroyed = false;

  /**
   * @private
   * @constructor
   * @param {Object} wasmModule - Emscripten WASM module
   * @param {number} sigPtr - Pointer to OQS_SIG structure
   */
  constructor(wasmModule, sigPtr) {
    this.#wasmModule = wasmModule;
    this.#sigPtr = sigPtr;
  }

  /**
   * Generate a new SLH-DSA-SHA2-192s keypair
   *
   * @async
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = sig.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 48 bytes
   * console.log('Secret key:', secretKey.length);  // 96 bytes
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(SLH_DSA_SHA2_192S_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(SLH_DSA_SHA2_192S_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'SLH-DSA-SHA2-192s', 'Key generation failed');
      }

      publicKey.set(this.#wasmModule.HEAPU8.subarray(publicKeyPtr, publicKeyPtr + publicKey.length));
      secretKey.set(this.#wasmModule.HEAPU8.subarray(secretKeyPtr, secretKeyPtr + secretKey.length));

      return { publicKey, secretKey };
    } finally {
      this.#wasmModule._free(publicKeyPtr);
      this.#wasmModule._free(secretKeyPtr);
    }
  }

  /**
   * Sign a message using a secret key
   *
   * @async
   * @param {Uint8Array} message - Message to sign (any length)
   * @param {Uint8Array} secretKey - Secret key (96 bytes)
   * @returns {Uint8Array} Signature (16224 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If secret key size is invalid
   * @throws {LibOQSOperationError} If signing fails
   *
   * @example
   * const message = new TextEncoder().encode('Hello, world!');
   * const signature = sig.sign(message, secretKey);
   * console.log('Signature:', signature.length);  // 16224 bytes
   */
  sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateSecretKey(secretKey);

    const signatureMaxLen = SLH_DSA_SHA2_192S_INFO.keySize.signature;
    const signature = new Uint8Array(signatureMaxLen);

    const messagePtr = this.#wasmModule._malloc(message.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);
    const signaturePtr = this.#wasmModule._malloc(signatureMaxLen);
    const signatureLenPtr = this.#wasmModule._malloc(8);

    try {
      this.#wasmModule.HEAPU8.set(message, messagePtr);
      this.#wasmModule.HEAPU8.set(secretKey, secretKeyPtr);

      const result = this.#wasmModule._OQS_SIG_sign(
        this.#sigPtr,
        signaturePtr,
        signatureLenPtr,
        messagePtr,
        message.length,
        secretKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('sign', 'SLH-DSA-SHA2-192s', 'Signing failed');
      }

      const actualSignatureLen = this.#wasmModule.getValue(signatureLenPtr, 'i32');
      signature.set(this.#wasmModule.HEAPU8.subarray(signaturePtr, signaturePtr + actualSignatureLen));

      return signature.slice(0, actualSignatureLen);
    } finally {
      this.#wasmModule._free(messagePtr);
      this.#wasmModule._free(secretKeyPtr);
      this.#wasmModule._free(signaturePtr);
      this.#wasmModule._free(signatureLenPtr);
    }
  }

  /**
   * Verify a signature using a public key
   *
   * @async
   * @param {Uint8Array} message - Original message (any length)
   * @param {Uint8Array} signature - Signature to verify
   * @param {Uint8Array} publicKey - Public key (48 bytes)
   * @returns {boolean} True if signature is valid, false otherwise
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key or signature size is invalid
   *
   * @example
   * const isValid = sig.verify(message, signature, publicKey);
   * console.log('Signature valid:', isValid);
   */
  verify(message, signature, publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);
    this.#validateSignature(signature);

    const messagePtr = this.#wasmModule._malloc(message.length);
    const signaturePtr = this.#wasmModule._malloc(signature.length);
    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);

    try {
      this.#wasmModule.HEAPU8.set(message, messagePtr);
      this.#wasmModule.HEAPU8.set(signature, signaturePtr);
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_SIG_verify(
        this.#sigPtr,
        messagePtr,
        message.length,
        signaturePtr,
        signature.length,
        publicKeyPtr
      );

      return result === 0;
    } finally {
      this.#wasmModule._free(messagePtr);
      this.#wasmModule._free(signaturePtr);
      this.#wasmModule._free(publicKeyPtr);
    }
  }

  /**
   * Free WASM resources
   *
   * @description
   * Releases all WASM memory associated with this instance.
   * The instance cannot be used after calling destroy().
   *
   * @example
   * sig.destroy();
   * // sig is now unusable
   */
  destroy() {
    if (!this.#destroyed && this.#sigPtr) {
      this.#wasmModule._OQS_SIG_free(this.#sigPtr);
      this.#sigPtr = null;
      this.#destroyed = true;
    }
  }

  /**
   * Get algorithm information
   *
   * @readonly
   * @returns {typeof SLH_DSA_SHA2_192S_INFO} Algorithm metadata
   *
   * @example
   * console.log(sig.info.name);           // 'SLH-DSA-SHA2-192s'
   * console.log(sig.info.securityLevel);  // 3
   * console.log(sig.info.keySize);        // { publicKey: 48, secretKey: 96, signature: 16224 }
   */
  get info() {
    return SLH_DSA_SHA2_192S_INFO;
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'SLH-DSA-SHA2-192s');
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== SLH_DSA_SHA2_192S_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${SLH_DSA_SHA2_192S_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'SLH-DSA-SHA2-192s'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== SLH_DSA_SHA2_192S_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${SLH_DSA_SHA2_192S_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'SLH-DSA-SHA2-192s'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} signature
   * @throws {LibOQSValidationError} If signature size is invalid
   */
  #validateSignature(signature) {
    if (!isUint8Array(signature) || signature.length === 0 || signature.length > SLH_DSA_SHA2_192S_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        `Invalid signature: expected 0 < length <= ${SLH_DSA_SHA2_192S_INFO.keySize.signature} bytes, got ${signature?.length ?? 'null'}`,
        'SLH-DSA-SHA2-192s'
      );
    }
  }
}

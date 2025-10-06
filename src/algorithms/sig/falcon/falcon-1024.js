/**
 * @fileoverview Falcon-1024 signature algorithm implementation
 * @module algorithms/sig/falcon/falcon-1024
 * @description
 * Falcon-1024 is a lattice-based signature scheme providing NIST security level 5.
 * It offers compact signatures and fast verification, based on NTRU lattices and Fast Fourier sampling.
 *
 * Key features:
 * - Compact signatures (~1462 bytes average)
 * - Fast verification
 * - Security Level 5 (256-bit classical, quantum-resistant)
 * - Variable-length signatures
 *
 * @see {@link https://falcon-sign.info/} - Falcon specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';
import { VERSION } from '../../../index.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `https://cdn.openforge.sh/${VERSION}/falcon-1024.deno.js`
    : `https://cdn.openforge.sh/${VERSION}/falcon-1024.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * Algorithm metadata for Falcon-1024
 * @constant {Object} FALCON_1024_INFO
 * @property {string} name - Algorithm display name
 * @property {string} identifier - liboqs identifier string
 * @property {string} type - Algorithm type ('sig')
 * @property {number} securityLevel - NIST security level (5 = 256-bit)
 * @property {boolean} standardized - NIST standardization status
 * @property {string} description - Algorithm description
 * @property {Object} keySize - Key and signature sizes in bytes
 * @property {number} keySize.publicKey - Public key size (1793 bytes)
 * @property {number} keySize.secretKey - Secret key size (2305 bytes)
 * @property {number} keySize.signature - Maximum signature size (1462 bytes)
 */
export const FALCON_1024_INFO = {
  name: 'Falcon-1024',
  identifier: 'Falcon-1024',
  type: 'sig',
  securityLevel: 5,
  standardized: false,
  description: 'Falcon-1024 lattice-based signature (NIST Level 5, 256-bit quantum security)',
  keySize: {
    publicKey: 1793,
    secretKey: 2305,
    signature: 1462
  }
};

/**
 * Factory function to create a Falcon-1024 signature instance
 *
 * @async
 * @function createFalcon1024
 * @returns {Promise<Falcon1024>} Initialized Falcon-1024 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createFalcon1024 } from '@openforge-sh/liboqs';
 *
 * const sig = await createFalcon1024();
 * const { publicKey, secretKey } = sig.generateKeyPair();
 * sig.destroy();
 */
export async function createFalcon1024() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = FALCON_1024_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);
  if (!sigPtr) {
    throw new LibOQSInitError('Falcon-1024', 'Failed to create SIG instance');
  }

  return new Falcon1024(wasmModule, sigPtr);
}

/**
 * Falcon-1024 signature algorithm wrapper class
 *
 * @class Falcon1024
 * @description
 * High-level wrapper for Falcon-1024 signature operations. Provides secure key generation,
 * message signing, and signature verification with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const sig = await createFalcon1024();
 *
 * // Generate keypair
 * const { publicKey, secretKey } = sig.generateKeyPair();
 *
 * // Sign message
 * const message = new TextEncoder().encode('Hello, quantum world!');
 * const signature = sig.sign(message, secretKey);
 *
 * // Verify signature
 * const isValid = sig.verify(message, signature, publicKey);
 * console.log('Valid:', isValid); // true
 *
 * // Cleanup
 * sig.destroy();
 */
export class Falcon1024 {
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
   * Generate a new Falcon-1024 keypair
   *
   * @async
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = sig.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 1793 bytes
   * console.log('Secret key:', secretKey.length);  // 2305 bytes
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKeyPtr = this.#wasmModule._malloc(FALCON_1024_INFO.keySize.publicKey);
    const secretKeyPtr = this.#wasmModule._malloc(FALCON_1024_INFO.keySize.secretKey);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'Falcon-1024', 'Key generation failed');
      }

      const publicKey = new Uint8Array(
        this.#wasmModule.HEAPU8.buffer,
        publicKeyPtr,
        FALCON_1024_INFO.keySize.publicKey
      ).slice();

      const secretKey = new Uint8Array(
        this.#wasmModule.HEAPU8.buffer,
        secretKeyPtr,
        FALCON_1024_INFO.keySize.secretKey
      ).slice();

      return { publicKey, secretKey };
    } finally {
      this.#wasmModule._free(publicKeyPtr);
      this.#wasmModule._free(secretKeyPtr);
    }
  }

  /**
   * Sign a message with Falcon-1024
   *
   * @async
   * @param {Uint8Array} message - Message to sign (any length)
   * @param {Uint8Array} secretKey - Secret key (2305 bytes)
   * @returns {Uint8Array} Signature (variable length, max 1462 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If secret key size is invalid
   * @throws {LibOQSOperationError} If signing fails
   *
   * @example
   * const message = new TextEncoder().encode('Sign this message');
   * const signature = sig.sign(message, secretKey);
   * console.log('Signature length:', signature.length); // ~1462 bytes (variable)
   */
  sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateSecretKey(secretKey);

    const messagePtr = this.#wasmModule._malloc(message.length);
    const secretKeyPtr = this.#wasmModule._malloc(FALCON_1024_INFO.keySize.secretKey);
    const signaturePtr = this.#wasmModule._malloc(FALCON_1024_INFO.keySize.signature);
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
        throw new LibOQSOperationError('sign', 'Falcon-1024', 'Signature generation failed');
      }

      const signatureLen = this.#wasmModule.getValue(signatureLenPtr, 'i32');

      const signature = new Uint8Array(
        this.#wasmModule.HEAPU8.buffer,
        signaturePtr,
        signatureLen
      ).slice();

      return signature;
    } finally {
      this.#wasmModule._free(messagePtr);
      this.#wasmModule._free(secretKeyPtr);
      this.#wasmModule._free(signaturePtr);
      this.#wasmModule._free(signatureLenPtr);
    }
  }

  /**
   * Verify a Falcon-1024 signature
   *
   * @async
   * @param {Uint8Array} message - Original message
   * @param {Uint8Array} signature - Signature to verify
   * @param {Uint8Array} publicKey - Public key (1793 bytes)
   * @returns {boolean} True if signature is valid, false otherwise
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key or signature size is invalid
   *
   * @example
   * const isValid = sig.verify(message, signature, publicKey);
   * if (isValid) {
   *   console.log('Signature is valid!');
   * } else {
   *   console.log('Signature verification failed');
   * }
   */
  verify(message, signature, publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);
    this.#validateSignature(signature);

    const messagePtr = this.#wasmModule._malloc(message.length);
    const signaturePtr = this.#wasmModule._malloc(signature.length);
    const publicKeyPtr = this.#wasmModule._malloc(FALCON_1024_INFO.keySize.publicKey);

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
   * @returns {Object} Algorithm metadata
   *
   * @example
   * console.log(sig.info.name);           // 'Falcon-1024'
   * console.log(sig.info.securityLevel);  // 5
   * console.log(sig.info.keySize);        // { publicKey: 1793, secretKey: 2305, signature: 1462 }
   */
  get info() {
    return { ...FALCON_1024_INFO };
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'Falcon-1024');
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== FALCON_1024_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key size: expected ${FALCON_1024_INFO.keySize.publicKey} bytes, got ${publicKey.length}`,
        'Falcon-1024'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== FALCON_1024_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key size: expected ${FALCON_1024_INFO.keySize.secretKey} bytes, got ${secretKey.length}`,
        'Falcon-1024'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} signature
   * @throws {LibOQSValidationError} If signature size is invalid
   */
  #validateSignature(signature) {
    if (!isUint8Array(signature) || signature.length === 0 || signature.length > FALCON_1024_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        `Invalid signature size: expected 1-${FALCON_1024_INFO.keySize.signature} bytes, got ${signature.length}`,
        'Falcon-1024'
      );
    }
  }
}

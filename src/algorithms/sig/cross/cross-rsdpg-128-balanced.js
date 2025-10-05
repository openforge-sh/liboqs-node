/**
 * @fileoverview CROSS-rsdpg-128-balanced signature algorithm implementation
 * @module algorithms/sig/cross/cross-rsdpg-128-balanced
 * @description
 * CROSS-rsdpg-128-balanced is a code-based signature scheme providing NIST security level 1.
 * It offers balanced tradeoff between signature size and signing/verification speed.
 *
 * Key features:
 * - Balanced performance profile
 * - Security Level 1 (128-bit classical, quantum-resistant)
 * - Variable-length signatures
 * - Code-based cryptography (restricted syndrome decoding problem)
 *
 * @see {@link https://www.cross-crypto.com/} - CROSS specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import moduleFactory from '../../../../dist/cross-rsdpg-128-balanced.min.js';
import { isUint8Array } from '../../../core/validation.js';

/**
 * Algorithm metadata for CROSS-rsdpg-128-balanced
 * @constant {Object} CROSS_RSDPG_128_BALANCED_INFO
 * @property {string} name - Algorithm display name
 * @property {string} identifier - liboqs identifier string
 * @property {string} type - Algorithm type ('sig')
 * @property {number} securityLevel - NIST security level (1 = 128-bit)
 * @property {boolean} standardized - NIST standardization status
 * @property {string} description - Algorithm description
 * @property {Object} keySize - Key and signature sizes in bytes
 * @property {number} keySize.publicKey - Public key size (54 bytes)
 * @property {number} keySize.secretKey - Secret key size (32 bytes)
 * @property {number} keySize.signature - Maximum signature size (9120 bytes)
 */
export const CROSS_RSDPG_128_BALANCED_INFO = {
  name: 'CROSS-rsdpg-128-balanced',
  identifier: 'CROSS-rsdpg-128-balanced',
  type: 'sig',
  securityLevel: 1,
  standardized: false,
  description: 'CROSS-rsdpg-128-balanced code-based signature (NIST Level 1, 128-bit quantum security, balanced)',
  keySize: {
    publicKey: 54,
    secretKey: 32,
    signature: 9120
  }
};

/**
 * Factory function to create a CROSS-rsdpg-128-balanced signature instance
 *
 * @async
 * @function createCrossRsdpg128Balanced
 * @returns {Promise<CrossRsdpg128Balanced>} Initialized CROSS-rsdpg-128-balanced instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createCrossRsdpg128Balanced } from '@openforge-sh/liboqs';
 *
 * const sig = await createCrossRsdpg128Balanced();
 * const { publicKey, secretKey } = await sig.generateKeyPair();
 * sig.destroy();
 */
export async function createCrossRsdpg128Balanced() {
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = CROSS_RSDPG_128_BALANCED_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);

  if (!sigPtr) {
    throw new LibOQSInitError('CROSS-rsdpg-128-balanced', 'Failed to create SIG instance');
  }

  return new CrossRsdpg128Balanced(wasmModule, sigPtr);
}

/**
 * CROSS-rsdpg-128-balanced signature algorithm wrapper class
 *
 * @class CrossRsdpg128Balanced
 * @description
 * High-level wrapper for CROSS-rsdpg-128-balanced signature operations. Provides secure key generation,
 * message signing, and signature verification with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const sig = await createCrossRsdpg128Balanced(moduleFactory);
 *
 * // Generate keypair
 * const { publicKey, secretKey } = await sig.generateKeyPair();
 *
 * // Sign message
 * const message = new TextEncoder().encode('Hello, quantum world!');
 * const signature = await sig.sign(message, secretKey);
 *
 * // Verify signature
 * const isValid = await sig.verify(message, signature, publicKey);
 * console.log('Valid:', isValid); // true
 *
 * // Cleanup
 * sig.destroy();
 */
export class CrossRsdpg128Balanced {
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
   * Generate a new CROSS-rsdpg-128-balanced keypair
   *
   * @async
   * @returns {Promise<{publicKey: Uint8Array, secretKey: Uint8Array}>} Generated keypair
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = await sig.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 54 bytes
   * console.log('Secret key:', secretKey.length);  // 32 bytes
   */
  async generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(CROSS_RSDPG_128_BALANCED_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(CROSS_RSDPG_128_BALANCED_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'CROSS-rsdpg-128-balanced', 'Key generation failed');
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
   * Sign a message with CROSS-rsdpg-128-balanced
   *
   * @async
   * @param {Uint8Array} message - Message to sign (any length)
   * @param {Uint8Array} secretKey - Secret key (32 bytes)
   * @returns {Promise<Uint8Array>} Signature (variable length, max 9120 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If secret key size is invalid
   * @throws {LibOQSOperationError} If signing fails
   *
   * @example
   * const message = new TextEncoder().encode('Sign this message');
   * const signature = await sig.sign(message, secretKey);
   * console.log('Signature length:', signature.length);
   */
  async sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateMessage(message);
    this.#validateSecretKey(secretKey);

    const messagePtr = this.#wasmModule._malloc(message.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);
    const signaturePtr = this.#wasmModule._malloc(CROSS_RSDPG_128_BALANCED_INFO.keySize.signature);
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
        throw new LibOQSOperationError('sign', 'CROSS-rsdpg-128-balanced', 'Signature generation failed');
      }

      const signatureLen = this.#wasmModule.getValue(signatureLenPtr, 'i32');
      const signature = new Uint8Array(signatureLen);
      signature.set(this.#wasmModule.HEAPU8.subarray(signaturePtr, signaturePtr + signatureLen));

      return signature;
    } finally {
      this.#wasmModule._free(messagePtr);
      this.#wasmModule._free(secretKeyPtr);
      this.#wasmModule._free(signaturePtr);
      this.#wasmModule._free(signatureLenPtr);
    }
  }

  /**
   * Verify a CROSS-rsdpg-128-balanced signature
   *
   * @async
   * @param {Uint8Array} message - Original message
   * @param {Uint8Array} signature - Signature to verify
   * @param {Uint8Array} publicKey - Public key (54 bytes)
   * @returns {Promise<boolean>} True if signature is valid, false otherwise
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key or signature size is invalid
   *
   * @example
   * const isValid = await sig.verify(message, signature, publicKey);
   * if (isValid) {
   *   console.log('Signature is valid!');
   * } else {
   *   console.log('Signature verification failed');
   * }
   */
  async verify(message, signature, publicKey) {
    this.#checkDestroyed();
    this.#validateMessage(message);
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
   * @returns {Object} Algorithm metadata
   *
   * @example
   * console.log(sig.info.name);           // 'CROSS-rsdpg-128-balanced'
   * console.log(sig.info.securityLevel);  // 1
   * console.log(sig.info.keySize);        // { publicKey: 54, secretKey: 32, signature: 9120 }
   */
  get info() {
    return { ...CROSS_RSDPG_128_BALANCED_INFO };
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'CROSS-rsdpg-128-balanced');
    }
  }

  /**
   * @private
   * @param {Uint8Array} message
   * @throws {LibOQSValidationError} If message is invalid
   */
  #validateMessage(message) {
    if (!isUint8Array(message)) {
      throw new LibOQSValidationError(
        'Message must be Uint8Array',
        'CROSS-rsdpg-128-balanced'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== CROSS_RSDPG_128_BALANCED_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${CROSS_RSDPG_128_BALANCED_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'CROSS-rsdpg-128-balanced'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== CROSS_RSDPG_128_BALANCED_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${CROSS_RSDPG_128_BALANCED_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'CROSS-rsdpg-128-balanced'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} signature
   * @throws {LibOQSValidationError} If signature size is invalid
   */
  #validateSignature(signature) {
    if (!isUint8Array(signature)) {
      throw new LibOQSValidationError(
        'Signature must be Uint8Array',
        'CROSS-rsdpg-128-balanced'
      );
    }
    if (signature.length === 0 || signature.length > CROSS_RSDPG_128_BALANCED_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        `Invalid signature length: expected up to ${CROSS_RSDPG_128_BALANCED_INFO.keySize.signature} bytes, got ${signature.length}`,
        'CROSS-rsdpg-128-balanced'
      );
    }
  }
}

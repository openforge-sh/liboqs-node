/**
 * @fileoverview SPHINCS+-sha2-256s-simple signature algorithm implementation
 * @module algorithms/sig/sphincs/sphincs-sha2-256s-simple
 * @description
 * SPHINCS+-sha2-256s-simple is a stateless hash-based signature scheme providing NIST security level 5.
 * This variant uses SHA2 for hashing, is optimized for signature size, and uses simple mode.
 *
 * Key features:
 * - Stateless hash-based signatures
 * - Security Level 5 (256-bit classical, quantum-resistant)
 * - SHA2 hash function
 * - Small signature size
 * - Simple mode (faster)
 *
 * @see {@link https://sphincs.org/} - SPHINCS+ specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import moduleFactory from '../../../../dist/sphincs-sha2-256s-simple.min.js';
import { isUint8Array } from '../../../core/validation.js';

/**
 * Algorithm metadata for SPHINCS+-sha2-256s-simple
 * @constant {Object} SPHINCSPLUS_SHA2_256S_SIMPLE_INFO
 * @property {string} name - Algorithm display name
 * @property {string} identifier - liboqs identifier string
 * @property {string} type - Algorithm type ('sig')
 * @property {number} securityLevel - NIST security level (5 = 256-bit)
 * @property {boolean} standardized - NIST standardization status
 * @property {string} description - Algorithm description
 * @property {Object} keySize - Key and signature sizes in bytes
 * @property {number} keySize.publicKey - Public key size (64 bytes)
 * @property {number} keySize.secretKey - Secret key size (128 bytes)
 * @property {number} keySize.signature - Signature size (29792 bytes)
 */
export const SPHINCSPLUS_SHA2_256S_SIMPLE_INFO = {
  name: 'SPHINCS+-SHA2-256s-simple',
  identifier: 'SPHINCS+-SHA2-256s-simple',
  type: 'sig',
  securityLevel: 5,
  standardized: false,
  description: 'SPHINCS+-sha2-256s-simple hash-based signature (NIST Level 5, 256-bit quantum security, SHA2, small, simple)',
  keySize: {
    publicKey: 64,
    secretKey: 128,
    signature: 29792
  }
};

/**
 * Factory function to create a SPHINCS+-sha2-256s-simple signature instance
 *
 * @async
 * @function createSphincsSha2256sSimple
 * @returns {Promise<SphincsSha2256sSimple>} Initialized SPHINCS+-sha2-256s-simple instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createSphincsSha2256sSimple } from '@openforge-sh/liboqs';
 *
 * const sig = await createSphincsSha2256sSimple();
 * const { publicKey, secretKey } = await sig.generateKeyPair();
 * sig.destroy();
 */
export async function createSphincsSha2256sSimple() {
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = SPHINCSPLUS_SHA2_256S_SIMPLE_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);

  if (!sigPtr) {
    throw new LibOQSInitError('SPHINCS+-sha2-256s-simple', 'Failed to create SIG instance');
  }

  return new SphincsSha2256sSimple(wasmModule, sigPtr);
}

/**
 * SPHINCS+-sha2-256s-simple signature scheme wrapper class
 *
 * @class SphincsSha2256sSimple
 * @description
 * High-level wrapper for SPHINCS+-sha2-256s-simple signature operations. Provides secure key generation,
 * signing, and verification with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const sig = await createSphincsSha2256sSimple();
 *
 * // Generate keypair
 * const { publicKey, secretKey } = await sig.generateKeyPair();
 *
 * // Sign message
 * const message = new TextEncoder().encode('Hello, world!');
 * const signature = await sig.sign(message, secretKey);
 *
 * // Verify signature
 * const isValid = await sig.verify(message, signature, publicKey);
 *
 * // Cleanup
 * sig.destroy();
 */
export class SphincsSha2256sSimple {
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
   * Generate a new SPHINCS+-sha2-256s-simple keypair
   *
   * @async
   * @returns {Promise<{publicKey: Uint8Array, secretKey: Uint8Array}>} Generated keypair
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = await sig.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 64 bytes
   * console.log('Secret key:', secretKey.length);  // 128 bytes
   */
  async generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(SPHINCSPLUS_SHA2_256S_SIMPLE_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(SPHINCSPLUS_SHA2_256S_SIMPLE_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'SPHINCS+-sha2-256s-simple', 'Key generation failed');
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
   * @param {Uint8Array} secretKey - Secret key (128 bytes)
   * @returns {Promise<Uint8Array>} Signature (29792 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If secret key size is invalid
   * @throws {LibOQSOperationError} If signing fails
   *
   * @example
   * const message = new TextEncoder().encode('Hello, world!');
   * const signature = await sig.sign(message, secretKey);
   * console.log('Signature:', signature.length);  // 29792 bytes
   */
  async sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateSecretKey(secretKey);

    const signatureMaxLen = SPHINCSPLUS_SHA2_256S_SIMPLE_INFO.keySize.signature;
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
        throw new LibOQSOperationError('sign', 'SPHINCS+-sha2-256s-simple', 'Signing failed');
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
   * @param {Uint8Array} publicKey - Public key (64 bytes)
   * @returns {Promise<boolean>} True if signature is valid, false otherwise
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key or signature size is invalid
   *
   * @example
   * const isValid = await sig.verify(message, signature, publicKey);
   * console.log('Signature valid:', isValid);
   */
  async verify(message, signature, publicKey) {
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
   * @returns {Object} Algorithm metadata
   *
   * @example
   * console.log(sig.info.name);           // 'SPHINCS+-sha2-256s-simple'
   * console.log(sig.info.securityLevel);  // 5
   * console.log(sig.info.keySize);        // { publicKey: 64, secretKey: 128, signature: 29792 }
   */
  get info() {
    return { ...SPHINCSPLUS_SHA2_256S_SIMPLE_INFO };
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'SPHINCS+-sha2-256s-simple');
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== SPHINCSPLUS_SHA2_256S_SIMPLE_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${SPHINCSPLUS_SHA2_256S_SIMPLE_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'SPHINCS+-sha2-256s-simple'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== SPHINCSPLUS_SHA2_256S_SIMPLE_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${SPHINCSPLUS_SHA2_256S_SIMPLE_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'SPHINCS+-sha2-256s-simple'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} signature
   * @throws {LibOQSValidationError} If signature size is invalid
   */
  #validateSignature(signature) {
    if (!isUint8Array(signature) || signature.length === 0 || signature.length > SPHINCSPLUS_SHA2_256S_SIMPLE_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        `Invalid signature: expected 0 < length <= ${SPHINCSPLUS_SHA2_256S_SIMPLE_INFO.keySize.signature} bytes, got ${signature?.length ?? 'null'}`,
        'SPHINCS+-sha2-256s-simple'
      );
    }
  }
}

/**
 * @fileoverview OV-Ip signature algorithm implementation
 * @module algorithms/sig/uov/ov-ip
 * @description
 * OV-Ip is an Unbalanced Oil and Vinegar (UOV) signature scheme.
 * This variant uses uncompressed keys.
 *
 * Key features:
 * - Multivariate quadratic cryptography
 * - Security Level 1 (128-bit classical, quantum-resistant)
 * - Standard key sizes
 * - Compact signatures (128 bytes)
 *
 * @see {@link https://www.uovsig.org/} - UOV specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';
import moduleFactory from '../../../../dist/ov-ip.min.js';

/**
 * Algorithm metadata for OV-Ip
 * @constant {Object} OV_IP_INFO
 * @property {string} name - Algorithm display name
 * @property {string} identifier - liboqs identifier string
 * @property {string} type - Algorithm type ('sig')
 * @property {number} securityLevel - NIST security level (1 = 128-bit)
 * @property {boolean} standardized - NIST standardization status
 * @property {string} description - Algorithm description
 * @property {Object} keySize - Key and signature sizes in bytes
 * @property {number} keySize.publicKey - Public key size (278432 bytes)
 * @property {number} keySize.secretKey - Secret key size (237896 bytes)
 * @property {number} keySize.signature - Maximum signature size (128 bytes)
 */
export const OV_IP_INFO = {
  name: 'OV-Ip',
  identifier: 'OV-Ip',
  type: 'sig',
  securityLevel: 1,
  standardized: false,
  description: 'OV-Ip UOV signature scheme (NIST Level 1, 128-bit quantum security, uncompressed keys)',
  keySize: {
    publicKey: 278432,
    secretKey: 237896,
    signature: 128
  }
};

/**
 * Factory function to create a OV-Ip signature instance
 *
 * @async
 * @function createOVIp
 * @returns {Promise<OVIp>} Initialized OV-Ip instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createOVIp } from '@openforge-sh/liboqs';
 *
 * const sig = await createOVIp();
 * const { publicKey, secretKey } = await sig.generateKeyPair();
 * sig.destroy();
 */
export async function createOVIp() {
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = OV_IP_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);

  if (!sigPtr) {
    throw new LibOQSInitError('OV-Ip', 'Failed to create SIG instance');
  }

  return new OVIp(wasmModule, sigPtr);
}

/**
 * OV-Ip digital signature wrapper class
 *
 * @class OVIp
 * @description
 * High-level wrapper for OV-Ip signature operations. Provides secure key generation,
 * signing, and verification with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const sig = await createOVIp();
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
 *
 * // Cleanup
 * sig.destroy();
 */
export class OVIp {
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
   * Generate a new OV-Ip keypair
   *
   * @async
   * @returns {Promise<{publicKey: Uint8Array, secretKey: Uint8Array}>} Generated keypair
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = await sig.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 278432 bytes
   * console.log('Secret key:', secretKey.length);  // 237896 bytes
   */
  async generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(OV_IP_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(OV_IP_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'OV-Ip', 'Key generation failed');
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
   * Sign a message using the secret key
   *
   * @async
   * @param {Uint8Array} message - Message to sign (arbitrary length)
   * @param {Uint8Array} secretKey - Secret key for signing (237896 bytes)
   * @returns {Promise<Uint8Array>} Digital signature (up to 128 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If signing fails
   *
   * @example
   * const message = new TextEncoder().encode('Hello!');
   * const signature = await sig.sign(message, secretKey);
   * console.log('Signature:', signature.length); // 128 bytes
   */
  async sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateMessage(message);
    this.#validateSecretKey(secretKey);

    const signature = new Uint8Array(OV_IP_INFO.keySize.signature);
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
        throw new LibOQSOperationError('sign', 'OV-Ip', 'Signing failed');
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
   * @async
   * @param {Uint8Array} message - Original message that was signed
   * @param {Uint8Array} signature - Signature to verify
   * @param {Uint8Array} publicKey - Public key for verification (278432 bytes)
   * @returns {Promise<boolean>} True if signature is valid, false otherwise
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If inputs are invalid
   *
   * @example
   * const isValid = await sig.verify(message, signature, publicKey);
   * if (isValid) {
   *   console.log('Signature is valid!');
   * }
   */
  async verify(message, signature, publicKey) {
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
   * console.log(sig.info.name);           // 'OV-Ip'
   * console.log(sig.info.securityLevel);  // 1
   * console.log(sig.info.keySize);        // { publicKey: 278432, secretKey: 237896, signature: 128 }
   */
  get info() {
    return { ...OV_IP_INFO };
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'OV-Ip');
    }
  }

  /**
   * @private
   * @param {Uint8Array} message
   * @throws {LibOQSValidationError} If message is invalid
   */
  #validateMessage(message) {
    if (!ArrayBuffer.isView(message) || message.constructor.name !== 'Uint8Array') {
      throw new LibOQSValidationError(
        'Message must be Uint8Array',
        'OV-Ip'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== OV_IP_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${OV_IP_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'OV-Ip'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== OV_IP_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${OV_IP_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'OV-Ip'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} signature
   * @throws {LibOQSValidationError} If signature is invalid
   */
  #validateSignature(signature) {
    if (!isUint8Array(signature)) {
      throw new LibOQSValidationError(
        'Signature must be Uint8Array',
        'OV-Ip'
      );
    }
    if (signature.length === 0 || signature.length > OV_IP_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        `Invalid signature length: expected up to ${OV_IP_INFO.keySize.signature} bytes, got ${signature.length}`,
        'OV-Ip'
      );
    }
  }
}

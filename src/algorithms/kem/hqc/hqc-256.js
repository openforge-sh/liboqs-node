/**
 * @fileoverview HQC-256 KEM algorithm implementation
 * @module algorithms/kem/hqc/hqc-256
 * @description
 * HQC-256 is a code-based key encapsulation mechanism providing NIST security level 5.
 * It is based on the Hamming Quasi-Cyclic (HQC) code construction.
 *
 * Key features:
 * - Code-based cryptography (Hamming Quasi-Cyclic codes)
 * - Security Level 5 (256-bit classical, quantum-resistant)
 * - IND-CCA2 security
 * - Competitive performance
 *
 * @see {@link https://pqc-hqc.org/} - HQC specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import moduleFactory from '../../../../dist/hqc-256.min.js';
import { isUint8Array } from '../../../core/validation.js';

/**
 * Algorithm metadata for HQC-256
 * @constant {Object} HQC_256_INFO
 * @property {string} name - Algorithm display name
 * @property {string} identifier - liboqs identifier string
 * @property {string} type - Algorithm type ('kem')
 * @property {number} securityLevel - NIST security level (5 = 256-bit)
 * @property {boolean} standardized - NIST standardization status
 * @property {string} description - Algorithm description
 * @property {Object} keySize - Key and ciphertext sizes in bytes
 * @property {number} keySize.publicKey - Public key size (7245 bytes)
 * @property {number} keySize.secretKey - Secret key size (7317 bytes)
 * @property {number} keySize.ciphertext - Ciphertext size (14421 bytes)
 * @property {number} keySize.sharedSecret - Shared secret size (64 bytes)
 */
export const HQC_256_INFO = {
  name: 'HQC-256',
  identifier: 'HQC-256',
  type: 'kem',
  securityLevel: 5,
  standardized: false,
  description: 'HQC-256 code-based KEM (NIST Level 5, 256-bit quantum security)',
  keySize: {
    publicKey: 7245,
    secretKey: 7317,
    ciphertext: 14421,
    sharedSecret: 64
  }
};

/**
 * Factory function to create a HQC-256 KEM instance
 *
 * @async
 * @function createHQC256
 * @returns {Promise<HQC256>} Initialized HQC-256 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createHQC256 } from '@openforge-sh/liboqs-node';
 *
 * const kem = await createHQC256();
 * const { publicKey, secretKey } = await kem.generateKeyPair();
 * kem.destroy();
 */
export async function createHQC256() {
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = HQC_256_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('HQC-256', 'Failed to create KEM instance');
  }

  return new HQC256(wasmModule, kemPtr);
}

/**
 * HQC-256 key encapsulation mechanism wrapper class
 *
 * @class HQC256
 * @description
 * High-level wrapper for HQC-256 KEM operations. Provides secure key generation,
 * encapsulation, and decapsulation with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const kem = await createHQC256();
 *
 * // Generate keypair
 * const { publicKey, secretKey } = await kem.generateKeyPair();
 *
 * // Encapsulate
 * const { ciphertext, sharedSecret } = await kem.encapsulate(publicKey);
 *
 * // Decapsulate
 * const recoveredSecret = await kem.decapsulate(ciphertext, secretKey);
 *
 * // Cleanup
 * kem.destroy();
 */
export class HQC256 {
  /** @type {Object} @private */ #wasmModule;
  /** @type {number} @private */ #kemPtr;
  /** @type {boolean} @private */ #destroyed = false;

  /**
   * @private
   * @constructor
   * @param {Object} wasmModule - Emscripten WASM module
   * @param {number} kemPtr - Pointer to OQS_KEM structure
   */
  constructor(wasmModule, kemPtr) {
    this.#wasmModule = wasmModule;
    this.#kemPtr = kemPtr;
  }

  /**
   * Generate a new HQC-256 keypair
   *
   * @async
   * @returns {Promise<{publicKey: Uint8Array, secretKey: Uint8Array}>} Generated keypair
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = await kem.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 7245 bytes
   * console.log('Secret key:', secretKey.length);  // 7317 bytes
   */
  async generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(HQC_256_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(HQC_256_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'HQC-256', 'Key generation failed');
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
   * Encapsulate a shared secret using a public key
   *
   * @async
   * @param {Uint8Array} publicKey - Public key (7245 bytes)
   * @returns {Promise<{ciphertext: Uint8Array, sharedSecret: Uint8Array}>} Ciphertext and shared secret
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key size is invalid
   * @throws {LibOQSOperationError} If encapsulation fails
   *
   * @example
   * const { ciphertext, sharedSecret } = await kem.encapsulate(publicKey);
   * console.log('Ciphertext:', ciphertext.length);      // 14421 bytes
   * console.log('Shared secret:', sharedSecret.length); // 64 bytes
   */
  async encapsulate(publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);

    const ciphertext = new Uint8Array(HQC_256_INFO.keySize.ciphertext);
    const sharedSecret = new Uint8Array(HQC_256_INFO.keySize.sharedSecret);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const ciphertextPtr = this.#wasmModule._malloc(ciphertext.length);
    const sharedSecretPtr = this.#wasmModule._malloc(sharedSecret.length);

    try {
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_KEM_encaps(
        this.#kemPtr,
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('encapsulate', 'HQC-256', 'Encapsulation failed');
      }

      ciphertext.set(this.#wasmModule.HEAPU8.subarray(ciphertextPtr, ciphertextPtr + ciphertext.length));
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + sharedSecret.length));

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
   * @async
   * @param {Uint8Array} ciphertext - Ciphertext (14421 bytes)
   * @param {Uint8Array} secretKey - Secret key (7317 bytes)
   * @returns {Promise<Uint8Array>} Shared secret (64 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If ciphertext or secret key size is invalid
   * @throws {LibOQSOperationError} If decapsulation fails
   *
   * @example
   * const sharedSecret = await kem.decapsulate(ciphertext, secretKey);
   * console.log('Recovered secret:', sharedSecret.length); // 64 bytes
   */
  async decapsulate(ciphertext, secretKey) {
    this.#checkDestroyed();
    this.#validateCiphertext(ciphertext);
    this.#validateSecretKey(secretKey);

    const sharedSecret = new Uint8Array(HQC_256_INFO.keySize.sharedSecret);

    const ciphertextPtr = this.#wasmModule._malloc(ciphertext.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);
    const sharedSecretPtr = this.#wasmModule._malloc(sharedSecret.length);

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
        throw new LibOQSOperationError('decapsulate', 'HQC-256', 'Decapsulation failed');
      }

      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + sharedSecret.length));

      return sharedSecret;
    } finally {
      this.#wasmModule._free(ciphertextPtr);
      this.#wasmModule._free(secretKeyPtr);
      this.#wasmModule._free(sharedSecretPtr);
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
   * kem.destroy();
   * // kem is now unusable
   */
  destroy() {
    if (!this.#destroyed && this.#kemPtr) {
      this.#wasmModule._OQS_KEM_free(this.#kemPtr);
      this.#kemPtr = null;
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
   * console.log(kem.info.name);           // 'HQC-256'
   * console.log(kem.info.securityLevel);  // 5
   * console.log(kem.info.keySize);        // { publicKey: 7245, secretKey: 7317, ciphertext: 14421, sharedSecret: 64 }
   */
  get info() {
    return { ...HQC_256_INFO };
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'HQC-256');
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== HQC_256_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${HQC_256_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'HQC-256'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== HQC_256_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${HQC_256_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'HQC-256'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} ciphertext
   * @throws {LibOQSValidationError} If ciphertext size is invalid
   */
  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== HQC_256_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        `Invalid ciphertext: expected ${HQC_256_INFO.keySize.ciphertext} bytes, got ${ciphertext?.length ?? 'null'}`,
        'HQC-256'
      );
    }
  }
}

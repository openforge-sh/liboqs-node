/**
 * @fileoverview sntrup761 KEM algorithm implementation
 * @module algorithms/kem/ntru/sntrup761
 * @description
 * sntrup761 is a lattice-based key encapsulation mechanism from the Streamlined NTRU Prime family.
 * It provides post-quantum security based on the NTRU problem.
 * @deprecated This algorithm is deprecated. Consider using ML-KEM for new applications.
 *
 * Key features:
 * - Lattice-based cryptography (NTRU problem)
 * - Security Level 3 (192-bit classical, quantum-resistant)
 * - Streamlined design
 * - Compact ciphertext (1039 bytes)
 *
 * @see {@link https://ntru.org/} - NTRU specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import moduleFactory from '../../../../dist/sntrup761.min.js';
import { isUint8Array } from '../../../core/validation.js';

/**
 * Algorithm metadata for sntrup761
 * @constant {Object} SNTRUP761_INFO
 * @property {string} name - Algorithm display name
 * @property {string} identifier - liboqs identifier string
 * @property {string} type - Algorithm type ('kem')
 * @property {number} securityLevel - NIST security level (3 = 192-bit)
 * @property {boolean} standardized - NIST standardization status
 * @property {string} description - Algorithm description
 * @property {Object} keySize - Key and ciphertext sizes in bytes
 * @property {number} keySize.publicKey - Public key size (1158 bytes)
 * @property {number} keySize.secretKey - Secret key size (1763 bytes)
 * @property {number} keySize.ciphertext - Ciphertext size (1039 bytes)
 * @property {number} keySize.sharedSecret - Shared secret size (32 bytes)
 */
export const SNTRUP761_INFO = {
  name: 'sntrup761',
  identifier: 'sntrup761',
  type: 'kem',
  securityLevel: 3,
  standardized: false,
  description: 'sntrup761 Streamlined NTRU Prime (NIST Level 3, 192-bit quantum security)',
  keySize: {
    publicKey: 1158,
    secretKey: 1763,
    ciphertext: 1039,
    sharedSecret: 32
  }
};

/**
 * Factory function to create a sntrup761 KEM instance
 *
 * @async
 * @function createSntrup761
 * @returns {Promise<Sntrup761>} Initialized sntrup761 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createSntrup761 } from '@openforge-sh/liboqs-node';
 *
 * const kem = await createSntrup761();
 * const { publicKey, secretKey } = await kem.generateKeyPair();
 * kem.destroy();
 */
export async function createSntrup761() {
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = SNTRUP761_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('sntrup761', 'Failed to create KEM instance');
  }

  return new Sntrup761(wasmModule, kemPtr);
}

/**
 * sntrup761 key encapsulation mechanism wrapper class
 *
 * @class Sntrup761
 * @description
 * High-level wrapper for sntrup761 KEM operations. Provides secure key generation,
 * encapsulation, and decapsulation with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const kem = await createSntrup761();
 *
 * // Generate keypair
 * const { publicKey, secretKey } = await kem.generateKeyPair();
 *
 * // Encapsulate
 * const { ciphertext, sharedSecret: senderSecret } = await kem.encapsulate(publicKey);
 *
 * // Decapsulate
 * const receiverSecret = await kem.decapsulate(ciphertext, secretKey);
 *
 * // Cleanup
 * kem.destroy();
 */
export class Sntrup761 {
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
   * Generate a new sntrup761 keypair
   *
   * @async
   * @returns {Promise<{publicKey: Uint8Array, secretKey: Uint8Array}>} Generated keypair
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = await kem.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 1158 bytes
   * console.log('Secret key:', secretKey.length);  // 1763 bytes
   */
  async generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(SNTRUP761_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(SNTRUP761_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'sntrup761', 'Key generation failed');
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
   * Encapsulate a shared secret using the public key
   *
   * @async
   * @param {Uint8Array} publicKey - Public key for encapsulation (1158 bytes)
   * @returns {Promise<{ciphertext: Uint8Array, sharedSecret: Uint8Array}>} Ciphertext and shared secret
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key is invalid
   * @throws {LibOQSOperationError} If encapsulation fails
   *
   * @example
   * const { ciphertext, sharedSecret } = await kem.encapsulate(publicKey);
   * console.log('Ciphertext:', ciphertext.length);     // 1039 bytes
   * console.log('Shared secret:', sharedSecret.length); // 32 bytes
   */
  async encapsulate(publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);

    const ciphertext = new Uint8Array(SNTRUP761_INFO.keySize.ciphertext);
    const sharedSecret = new Uint8Array(SNTRUP761_INFO.keySize.sharedSecret);

    const ciphertextPtr = this.#wasmModule._malloc(ciphertext.length);
    const sharedSecretPtr = this.#wasmModule._malloc(sharedSecret.length);
    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);

    try {
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_KEM_encaps(
        this.#kemPtr,
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('encapsulate', 'sntrup761', 'Encapsulation failed');
      }

      ciphertext.set(this.#wasmModule.HEAPU8.subarray(ciphertextPtr, ciphertextPtr + ciphertext.length));
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + sharedSecret.length));

      return { ciphertext, sharedSecret };
    } finally {
      this.#wasmModule._free(ciphertextPtr);
      this.#wasmModule._free(sharedSecretPtr);
      this.#wasmModule._free(publicKeyPtr);
    }
  }

  /**
   * Decapsulate a shared secret using the secret key
   *
   * @async
   * @param {Uint8Array} ciphertext - Ciphertext to decapsulate (1039 bytes)
   * @param {Uint8Array} secretKey - Secret key for decapsulation (1763 bytes)
   * @returns {Promise<Uint8Array>} Shared secret (32 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If decapsulation fails
   *
   * @example
   * const sharedSecret = await kem.decapsulate(ciphertext, secretKey);
   * console.log('Shared secret:', sharedSecret.length); // 32 bytes
   */
  async decapsulate(ciphertext, secretKey) {
    this.#checkDestroyed();
    this.#validateCiphertext(ciphertext);
    this.#validateSecretKey(secretKey);

    const sharedSecret = new Uint8Array(SNTRUP761_INFO.keySize.sharedSecret);

    const sharedSecretPtr = this.#wasmModule._malloc(sharedSecret.length);
    const ciphertextPtr = this.#wasmModule._malloc(ciphertext.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

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
        throw new LibOQSOperationError('decapsulate', 'sntrup761', 'Decapsulation failed');
      }

      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + sharedSecret.length));

      return sharedSecret;
    } finally {
      this.#wasmModule._free(sharedSecretPtr);
      this.#wasmModule._free(ciphertextPtr);
      this.#wasmModule._free(secretKeyPtr);
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
   * console.log(kem.info.name);           // 'sntrup761'
   * console.log(kem.info.securityLevel);  // 3
   * console.log(kem.info.keySize);        // { publicKey: 1158, secretKey: 1763, ciphertext: 1039, sharedSecret: 32 }
   */
  get info() {
    return { ...SNTRUP761_INFO };
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'sntrup761');
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== SNTRUP761_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${SNTRUP761_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'sntrup761'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== SNTRUP761_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${SNTRUP761_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'sntrup761'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} ciphertext
   * @throws {LibOQSValidationError} If ciphertext size is invalid
   */
  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== SNTRUP761_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        `Invalid ciphertext: expected ${SNTRUP761_INFO.keySize.ciphertext} bytes, got ${ciphertext?.length ?? 'null'}`,
        'sntrup761'
      );
    }
  }
}

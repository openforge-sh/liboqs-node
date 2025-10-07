/**
 * @fileoverview NTRU-HPS-2048-677 KEM algorithm implementation
 * @module algorithms/kem/ntru/ntru-hps-2048-677
 * @description
 * NTRU-HPS-2048-677 is a lattice-based key encapsulation mechanism from the NTRU-HPS (Highest Performance Secure) family.
 * It provides post-quantum security based on the NTRU problem.
 *
 * Key features:
 * - Lattice-based cryptography (NTRU problem)
 * - Security Level 3 (192-bit classical, quantum-resistant)
 * - Optimized for performance
 * - Compact ciphertext (930 bytes)
 *
 * @see {@link https://ntru.org/} - NTRU specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/ntru-hps-2048-677.deno.js`
    : `../../../../dist/ntru-hps-2048-677.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * NTRU-HPS-2048-677-INFO algorithm constants and metadata
 * @type {{readonly name: 'NTRU-HPS-2048-677', readonly identifier: 'NTRU-HPS-2048-677', readonly type: 'kem', readonly securityLevel: 3, readonly standardized: false, readonly description: string, readonly keySize: {readonly publicKey: 930, readonly secretKey: 1234, readonly ciphertext: 930, readonly sharedSecret: 32}}}
 */
export const NTRU_HPS_2048_677_INFO = {
  name: 'NTRU-HPS-2048-677',
  identifier: 'NTRU-HPS-2048-677',
  type: 'kem',
  securityLevel: 3,
  standardized: false,
  description: 'NTRU-HPS-2048-677 NTRU-HPS (Highest Performance Secure) (NIST Level 3, 192-bit quantum security)',
  keySize: {
    publicKey: 930,
    secretKey: 1234,
    ciphertext: 930,
    sharedSecret: 32
  }
};

/**
 * Factory function to create a NTRU-HPS-2048-677 KEM instance
 *
 * @async
 * @function createNTRUHps2048677
 * @returns {Promise<NTRUHps2048677>} Initialized NTRU-HPS-2048-677 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createNTRUHps2048677 } from '@openforge-sh/liboqs';
 *
 * const kem = await createNTRUHps2048677();
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * kem.destroy();
 */
export async function createNTRUHps2048677() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = NTRU_HPS_2048_677_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('NTRU-HPS-2048-677', 'Failed to create KEM instance');
  }

  return new NTRUHps2048677(wasmModule, kemPtr);
}

/**
 * NTRU-HPS-2048-677 key encapsulation mechanism wrapper class
 *
 * @class NTRUHps2048677
 * @description
 * High-level wrapper for NTRU-HPS-2048-677 KEM operations. Provides secure key generation,
 * encapsulation, and decapsulation with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const kem = await createNTRUHps2048677();
 *
 * // Generate keypair
 * const { publicKey, secretKey } = kem.generateKeyPair();
 *
 * // Encapsulate
 * const { ciphertext, sharedSecret: senderSecret } = kem.encapsulate(publicKey);
 *
 * // Decapsulate
 * const receiverSecret = kem.decapsulate(ciphertext, secretKey);
 *
 * // Cleanup
 * kem.destroy();
 */
export class NTRUHps2048677 {
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
   * Generate a new NTRU-HPS-2048-677 keypair
   *
   * @async
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = kem.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 930 bytes
   * console.log('Secret key:', secretKey.length);  // 1234 bytes
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(NTRU_HPS_2048_677_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(NTRU_HPS_2048_677_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'NTRU-HPS-2048-677', 'Key generation failed');
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
   * @param {Uint8Array} publicKey - Public key for encapsulation (930 bytes)
   * @returns {{ciphertext: Uint8Array, sharedSecret: Uint8Array}}
   * @returns {Uint8Array} returns.sharedSecret - Shared secret Ciphertext and shared secret
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key is invalid
   * @throws {LibOQSOperationError} If encapsulation fails
   *
   * @example
   * const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
   * console.log('Ciphertext:', ciphertext.length);     // 930 bytes
   * console.log('Shared secret:', sharedSecret.length); // 32 bytes
   */
  encapsulate(publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);

    const ciphertext = new Uint8Array(NTRU_HPS_2048_677_INFO.keySize.ciphertext);
    const sharedSecret = new Uint8Array(NTRU_HPS_2048_677_INFO.keySize.sharedSecret);

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
        throw new LibOQSOperationError('encapsulate', 'NTRU-HPS-2048-677', 'Encapsulation failed');
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
   * @param {Uint8Array} ciphertext - Ciphertext to decapsulate (930 bytes)
   * @param {Uint8Array} secretKey - Secret key for decapsulation (1234 bytes)
   * @returns {Uint8Array} Shared secret (32 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If decapsulation fails
   *
   * @example
   * const sharedSecret = kem.decapsulate(ciphertext, secretKey);
   * console.log('Shared secret:', sharedSecret.length); // 32 bytes
   */
  decapsulate(ciphertext, secretKey) {
    this.#checkDestroyed();
    this.#validateCiphertext(ciphertext);
    this.#validateSecretKey(secretKey);

    const sharedSecret = new Uint8Array(NTRU_HPS_2048_677_INFO.keySize.sharedSecret);

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
        throw new LibOQSOperationError('decapsulate', 'NTRU-HPS-2048-677', 'Decapsulation failed');
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
   * @returns {typeof NTRU_HPS_2048_677_INFO} Algorithm metadata
   *
   * @example
   * console.log(kem.info.name);           // 'NTRU-HPS-2048-677'
   * console.log(kem.info.securityLevel);  // 3
   * console.log(kem.info.keySize);        // { publicKey: 930, secretKey: 1234, ciphertext: 930, sharedSecret: 32 }
   */
  get info() {
    return NTRU_HPS_2048_677_INFO;
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'NTRU-HPS-2048-677');
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== NTRU_HPS_2048_677_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${NTRU_HPS_2048_677_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'NTRU-HPS-2048-677'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== NTRU_HPS_2048_677_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${NTRU_HPS_2048_677_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'NTRU-HPS-2048-677'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} ciphertext
   * @throws {LibOQSValidationError} If ciphertext size is invalid
   */
  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== NTRU_HPS_2048_677_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        `Invalid ciphertext: expected ${NTRU_HPS_2048_677_INFO.keySize.ciphertext} bytes, got ${ciphertext?.length ?? 'null'}`,
        'NTRU-HPS-2048-677'
      );
    }
  }
}

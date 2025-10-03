/**
 * @fileoverview Classic-McEliece-6688128f KEM algorithm implementation
 * @module algorithms/kem/classic-mceliece/classic-mceliece-6688128f
 * @description
 * Classic-McEliece-6688128f is a code-based key encapsulation mechanism providing NIST security level 5.
 * It is based on the McEliece cryptosystem using binary Goppa codes.
 *
 * Key features:
 * - Code-based cryptography (Goppa codes)
 * - Security Level 5 (256-bit classical, quantum-resistant)
 * - Extremely conservative security margin
 * - IND-CCA2 security
 * - Very large public keys, small ciphertexts
 *
 * @see {@link https://classic.mceliece.org/} - Classic McEliece specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import moduleFactory from '../../../../dist/classic-mceliece-6688128f.min.js';
import { isUint8Array } from '../../../core/validation.js';

/**
 * Classic-McEliece-6688128f algorithm constants and metadata
 * @constant {Object} CLASSIC_MCELIECE_6688128F_INFO
 * @property {string} name - Algorithm display name
 * @property {string} identifier - liboqs identifier string
 * @property {string} type - Algorithm type ('kem')
 * @property {number} securityLevel - NIST security level (5 = 256-bit)
 * @property {boolean} standardized - NIST standardization status
 * @property {string} description - Algorithm description
 * @property {Object} keySize - Key and ciphertext sizes in bytes
 * @property {number} keySize.publicKey - Public key size (1044992 bytes)
 * @property {number} keySize.secretKey - Secret key size (13932 bytes)
 * @property {number} keySize.ciphertext - Ciphertext size (208 bytes)
 * @property {number} keySize.sharedSecret - Shared secret size (32 bytes)
 */
export const CLASSIC_MCELIECE_6688128F_INFO = {
  name: 'Classic-McEliece-6688128f',
  identifier: 'Classic-McEliece-6688128f',
  type: 'kem',
  securityLevel: 5,
  standardized: false,
  description: 'Classic McEliece 6688128f code-based KEM (NIST Level 5, 256-bit quantum security)',
  keySize: {
    publicKey: 1044992,
    secretKey: 13932,
    ciphertext: 208,
    sharedSecret: 32
  }
};

/**
 * Load and initialize Classic-McEliece-6688128f module
 * @returns {Promise<ClassicMcEliece6688128f>} Initialized Classic-McEliece-6688128f instance
 * @throws {LibOQSInitError} If initialization fails
 * @example
 * import { createClassicMcEliece6688128f } from '@openforge-sh/liboqs-node';
 * const kem = await createClassicMcEliece6688128f();
 */
export async function createClassicMcEliece6688128f() {

  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = CLASSIC_MCELIECE_6688128F_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('Classic-McEliece-6688128f', 'Failed to create KEM instance');
  }

  return new ClassicMcEliece6688128f(wasmModule, kemPtr);
}

/**
 * Classic-McEliece-6688128f wrapper class providing high-level KEM operations
 *
 * This class wraps the low-level WASM module to provide a user-friendly
 * interface for Classic-McEliece-6688128f operations with automatic memory management
 * and input validation.
 *
 * @class ClassicMcEliece6688128f
 * @example
 * import { createClassicMcEliece6688128f } from '@openforge-sh/liboqs-node';
 *
 * const kem = await createClassicMcEliece6688128f();
 * const { publicKey, secretKey } = await kem.generateKeyPair();
 * const { ciphertext, sharedSecret } = await kem.encapsulate(publicKey);
 * kem.destroy();
 */
export class ClassicMcEliece6688128f {
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
   * Generate a new keypair for Classic-McEliece-6688128f
   *
   * Generates a public/private keypair using the algorithm's internal
   * random number generator. The secret key must be kept confidential.
   *
   * @returns {Promise<{publicKey: Uint8Array, secretKey: Uint8Array}>} Generated keypair
   * @throws {LibOQSOperationError} If keypair generation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const { publicKey, secretKey } = await kem.generateKeyPair();
   * // publicKey: 1044992 bytes
   * // secretKey: 13932 bytes (keep confidential!)
   */
  async generateKeyPair() {
    this.#checkDestroyed();

    const publicKeyPtr = this.#wasmModule._malloc(CLASSIC_MCELIECE_6688128F_INFO.keySize.publicKey);
    const secretKeyPtr = this.#wasmModule._malloc(CLASSIC_MCELIECE_6688128F_INFO.keySize.secretKey);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('keypair', 'Classic-McEliece-6688128f', `Error code: ${result}`);
      }

      const publicKey = new Uint8Array(CLASSIC_MCELIECE_6688128F_INFO.keySize.publicKey);
      const secretKey = new Uint8Array(CLASSIC_MCELIECE_6688128F_INFO.keySize.secretKey);

      publicKey.set(this.#wasmModule.HEAPU8.subarray(publicKeyPtr, publicKeyPtr + CLASSIC_MCELIECE_6688128F_INFO.keySize.publicKey));
      secretKey.set(this.#wasmModule.HEAPU8.subarray(secretKeyPtr, secretKeyPtr + CLASSIC_MCELIECE_6688128F_INFO.keySize.secretKey));

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
   * @param {Uint8Array} publicKey - Recipient's public key (1044992 bytes)
   * @returns {Promise<{ciphertext: Uint8Array, sharedSecret: Uint8Array}>} Encapsulation result
   * @throws {LibOQSValidationError} If public key is invalid
   * @throws {LibOQSOperationError} If encapsulation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const { ciphertext, sharedSecret } = await kem.encapsulate(recipientPublicKey);
   * // ciphertext: 208 bytes (send to recipient)
   * // sharedSecret: 32 bytes (use for symmetric encryption)
   */
  async encapsulate(publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);

    const publicKeyPtr = this.#wasmModule._malloc(CLASSIC_MCELIECE_6688128F_INFO.keySize.publicKey);
    const ciphertextPtr = this.#wasmModule._malloc(CLASSIC_MCELIECE_6688128F_INFO.keySize.ciphertext);
    const sharedSecretPtr = this.#wasmModule._malloc(CLASSIC_MCELIECE_6688128F_INFO.keySize.sharedSecret);

    try {
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_KEM_encaps(
        this.#kemPtr,
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('encaps', 'Classic-McEliece-6688128f', `Error code: ${result}`);
      }

      const ciphertext = new Uint8Array(CLASSIC_MCELIECE_6688128F_INFO.keySize.ciphertext);
      const sharedSecret = new Uint8Array(CLASSIC_MCELIECE_6688128F_INFO.keySize.sharedSecret);

      ciphertext.set(this.#wasmModule.HEAPU8.subarray(ciphertextPtr, ciphertextPtr + CLASSIC_MCELIECE_6688128F_INFO.keySize.ciphertext));
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + CLASSIC_MCELIECE_6688128F_INFO.keySize.sharedSecret));

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
   * @param {Uint8Array} ciphertext - Ciphertext received (208 bytes)
   * @param {Uint8Array} secretKey - Recipient's secret key (13932 bytes)
   * @returns {Promise<Uint8Array>} Recovered shared secret (32 bytes)
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If decapsulation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const sharedSecret = await kem.decapsulate(ciphertext, mySecretKey);
   * // sharedSecret: 32 bytes (matches sender's shared secret)
   */
  async decapsulate(ciphertext, secretKey) {
    this.#checkDestroyed();
    this.#validateCiphertext(ciphertext);
    this.#validateSecretKey(secretKey);

    const ciphertextPtr = this.#wasmModule._malloc(CLASSIC_MCELIECE_6688128F_INFO.keySize.ciphertext);
    const secretKeyPtr = this.#wasmModule._malloc(CLASSIC_MCELIECE_6688128F_INFO.keySize.secretKey);
    const sharedSecretPtr = this.#wasmModule._malloc(CLASSIC_MCELIECE_6688128F_INFO.keySize.sharedSecret);

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
        throw new LibOQSOperationError('decaps', 'Classic-McEliece-6688128f', `Error code: ${result}`);
      }

      const sharedSecret = new Uint8Array(CLASSIC_MCELIECE_6688128F_INFO.keySize.sharedSecret);
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + CLASSIC_MCELIECE_6688128F_INFO.keySize.sharedSecret));

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
   * const kem = await createClassicMcEliece6688128f();
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
   * @returns {Object} Algorithm metadata (copy of CLASSIC_MCELIECE_6688128F_INFO)
   * @example
   * const info = kem.info;
   * console.log(info.keySize.publicKey); // 1044992
   */
  get info() {
    return { ...CLASSIC_MCELIECE_6688128F_INFO };
  }

  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'Classic-McEliece-6688128f');
    }
  }

  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== CLASSIC_MCELIECE_6688128F_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${CLASSIC_MCELIECE_6688128F_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'Classic-McEliece-6688128f'
      );
    }
  }

  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== CLASSIC_MCELIECE_6688128F_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${CLASSIC_MCELIECE_6688128F_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'Classic-McEliece-6688128f'
      );
    }
  }

  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== CLASSIC_MCELIECE_6688128F_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        `Invalid ciphertext: expected ${CLASSIC_MCELIECE_6688128F_INFO.keySize.ciphertext} bytes, got ${ciphertext?.length ?? 'null'}`,
        'Classic-McEliece-6688128f'
      );
    }
  }
}

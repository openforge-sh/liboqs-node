/**
 * @fileoverview Unit tests for KEM (Key Encapsulation Mechanism) algorithms
 * @description Tests all implemented KEM algorithms for basic functionality:
 * - Key pair generation
 * - Encapsulation
 * - Decapsulation
 * - Round-trip correctness
 */

import { describe, test, expect } from 'vitest';

/**
 * Helper to compare Uint8Array values across Node.js and browser environments
 */
function compareArrays(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return 1;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return 1;
  }
  return 0;
}

import {
  createMLKEM512,
  createMLKEM768,
  createMLKEM1024,
  ML_KEM_512_INFO,
  ML_KEM_768_INFO,
  ML_KEM_1024_INFO,
  createKyber512,
  createKyber768,
  createKyber1024,
  KYBER512_INFO,
  KYBER768_INFO,
  KYBER1024_INFO,
  createFrodoKEM640AES,
  createFrodoKEM640SHAKE,
  createFrodoKEM976AES,
  createFrodoKEM976SHAKE,
  createFrodoKEM1344AES,
  createFrodoKEM1344SHAKE,
  FRODOKEM_640_AES_INFO,
  FRODOKEM_640_SHAKE_INFO,
  FRODOKEM_976_AES_INFO,
  FRODOKEM_976_SHAKE_INFO,
  FRODOKEM_1344_AES_INFO,
  FRODOKEM_1344_SHAKE_INFO,
  createHQC128,
  createHQC192,
  createHQC256,
  HQC_128_INFO,
  HQC_192_INFO,
  HQC_256_INFO,
  createClassicMcEliece348864,
  createClassicMcEliece348864f,
  createClassicMcEliece460896,
  createClassicMcEliece460896f,
  createClassicMcEliece6688128,
  createClassicMcEliece6688128f,
  createClassicMcEliece6960119,
  createClassicMcEliece6960119f,
  createClassicMcEliece8192128,
  createClassicMcEliece8192128f,
  CLASSIC_MCELIECE_348864_INFO,
  CLASSIC_MCELIECE_348864F_INFO,
  CLASSIC_MCELIECE_460896_INFO,
  CLASSIC_MCELIECE_460896F_INFO,
  CLASSIC_MCELIECE_6688128_INFO,
  CLASSIC_MCELIECE_6688128F_INFO,
  CLASSIC_MCELIECE_6960119_INFO,
  CLASSIC_MCELIECE_6960119F_INFO,
  CLASSIC_MCELIECE_8192128_INFO,
  CLASSIC_MCELIECE_8192128F_INFO,
  createNTRUHps2048509,
  createNTRUHps2048677,
  createNTRUHps4096821,
  createNTRUHps40961229,
  createNTRUHrss701,
  createNTRUHrss1373,
  createSntrup761,
  NTRU_HPS_2048_509_INFO,
  NTRU_HPS_2048_677_INFO,
  NTRU_HPS_4096_821_INFO,
  NTRU_HPS_4096_1229_INFO,
  NTRU_HRSS_701_INFO,
  NTRU_HRSS_1373_INFO,
  SNTRUP761_INFO
} from '../src/index.js';
import type { KEMInstance, AlgorithmInfo } from '../src/types/algorithms.d.ts';

/**
 * Registry of all KEM algorithms to test
 * Add new algorithms here when implemented
 */
const kemAlgorithms: Array<{
  name: string;
  factory: () => Promise<KEMInstance>;
  info: AlgorithmInfo;
}> = [
    { name: 'ML-KEM-512', factory: createMLKEM512, info: ML_KEM_512_INFO },
    { name: 'ML-KEM-768', factory: createMLKEM768, info: ML_KEM_768_INFO },
    { name: 'ML-KEM-1024', factory: createMLKEM1024, info: ML_KEM_1024_INFO },
    { name: 'Kyber512', factory: createKyber512, info: KYBER512_INFO },
    { name: 'Kyber768', factory: createKyber768, info: KYBER768_INFO },
    { name: 'Kyber1024', factory: createKyber1024, info: KYBER1024_INFO },
    { name: 'FrodoKEM-640-AES', factory: createFrodoKEM640AES, info: FRODOKEM_640_AES_INFO },
    { name: 'FrodoKEM-640-SHAKE', factory: createFrodoKEM640SHAKE, info: FRODOKEM_640_SHAKE_INFO },
    { name: 'FrodoKEM-976-AES', factory: createFrodoKEM976AES, info: FRODOKEM_976_AES_INFO },
    { name: 'FrodoKEM-976-SHAKE', factory: createFrodoKEM976SHAKE, info: FRODOKEM_976_SHAKE_INFO },
    { name: 'FrodoKEM-1344-AES', factory: createFrodoKEM1344AES, info: FRODOKEM_1344_AES_INFO },
    { name: 'FrodoKEM-1344-SHAKE', factory: createFrodoKEM1344SHAKE, info: FRODOKEM_1344_SHAKE_INFO },
    { name: 'HQC-128', factory: createHQC128, info: HQC_128_INFO },
    { name: 'HQC-192', factory: createHQC192, info: HQC_192_INFO },
    { name: 'HQC-256', factory: createHQC256, info: HQC_256_INFO },
    { name: 'Classic-McEliece-348864', factory: createClassicMcEliece348864, info: CLASSIC_MCELIECE_348864_INFO },
    { name: 'Classic-McEliece-348864f', factory: createClassicMcEliece348864f, info: CLASSIC_MCELIECE_348864F_INFO },
    { name: 'Classic-McEliece-460896', factory: createClassicMcEliece460896, info: CLASSIC_MCELIECE_460896_INFO },
    { name: 'Classic-McEliece-460896f', factory: createClassicMcEliece460896f, info: CLASSIC_MCELIECE_460896F_INFO },
    { name: 'Classic-McEliece-6688128', factory: createClassicMcEliece6688128, info: CLASSIC_MCELIECE_6688128_INFO },
    { name: 'Classic-McEliece-6688128f', factory: createClassicMcEliece6688128f, info: CLASSIC_MCELIECE_6688128F_INFO },
    { name: 'Classic-McEliece-6960119', factory: createClassicMcEliece6960119, info: CLASSIC_MCELIECE_6960119_INFO },
    { name: 'Classic-McEliece-6960119f', factory: createClassicMcEliece6960119f, info: CLASSIC_MCELIECE_6960119F_INFO },
    { name: 'Classic-McEliece-8192128', factory: createClassicMcEliece8192128, info: CLASSIC_MCELIECE_8192128_INFO },
    { name: 'Classic-McEliece-8192128f', factory: createClassicMcEliece8192128f, info: CLASSIC_MCELIECE_8192128F_INFO },
    { name: 'NTRU-HPS-2048-509', factory: createNTRUHps2048509, info: NTRU_HPS_2048_509_INFO },
    { name: 'NTRU-HPS-2048-677', factory: createNTRUHps2048677, info: NTRU_HPS_2048_677_INFO },
    { name: 'NTRU-HPS-4096-821', factory: createNTRUHps4096821, info: NTRU_HPS_4096_821_INFO },
    { name: 'NTRU-HPS-4096-1229', factory: createNTRUHps40961229, info: NTRU_HPS_4096_1229_INFO },
    { name: 'NTRU-HRSS-701', factory: createNTRUHrss701, info: NTRU_HRSS_701_INFO },
    { name: 'NTRU-HRSS-1373', factory: createNTRUHrss1373, info: NTRU_HRSS_1373_INFO },
    { name: 'sntrup761', factory: createSntrup761, info: SNTRUP761_INFO }
  ];

describe('KEM Algorithms', () => {
  describe.each(kemAlgorithms)('$name', ({ name, factory, info }) => {
    test('should generate valid keypair', async () => {
      const kem = await factory();

      const { publicKey, secretKey } = kem.generateKeyPair();

      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(info.keySize.publicKey);
      expect(secretKey.length).toBe(info.keySize.secretKey);

      kem.destroy();
    });

    test('should encapsulate and produce ciphertext and shared secret', async () => {
      const kem = await factory();

      const { publicKey } = kem.generateKeyPair();
      const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);

      expect(ciphertext).toBeInstanceOf(Uint8Array);
      expect(sharedSecret).toBeInstanceOf(Uint8Array);
      expect(ciphertext.length).toBe(info.keySize.ciphertext);
      expect(sharedSecret.length).toBe(info.keySize.sharedSecret);

      kem.destroy();
    });

    test('should decapsulate and recover shared secret', async () => {
      const kem = await factory();

      const { publicKey, secretKey } = kem.generateKeyPair();
      const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
      const recoveredSecret = kem.decapsulate(ciphertext, secretKey);

      expect(recoveredSecret).toBeInstanceOf(Uint8Array);
      expect(recoveredSecret.length).toBe(info.keySize.sharedSecret);

      // Verify secrets match
      expect(compareArrays(sharedSecret, recoveredSecret)).toBe(0);

      kem.destroy();
    });

    test('should produce different keypairs on each generation', async () => {
      const kem = await factory();

      const keypair1 = kem.generateKeyPair();
      const keypair2 = kem.generateKeyPair();

      // Public keys should differ
      expect(compareArrays(keypair1.publicKey, keypair2.publicKey)).not.toBe(0);
      // Secret keys should differ
      expect(compareArrays(keypair1.secretKey, keypair2.secretKey)).not.toBe(0);

      kem.destroy();
    });

    test('should produce different shared secrets for different keypairs', async () => {
      const kem = await factory();

      const keypair1 = kem.generateKeyPair();
      const keypair2 = kem.generateKeyPair();

      const { sharedSecret: secret1 } = kem.encapsulate(keypair1.publicKey);
      const { sharedSecret: secret2 } = kem.encapsulate(keypair2.publicKey);

      expect(compareArrays(secret1, secret2)).not.toBe(0);

      kem.destroy();
    });

    test('should have correct algorithm info', async () => {
      const kem = await factory();
      const kemInfo = kem.info;

      expect(kemInfo.name).toBe(name);
      expect(kemInfo.identifier).toBe(info.identifier);
      expect(kemInfo.type).toBe('kem');
      expect(kemInfo.standardized).toBe(info.standardized);
      expect(kemInfo.keySize).toEqual(info.keySize);

      kem.destroy();
    });

    test('should throw error when using destroyed instance', async () => {
      const kem = await factory();
      kem.destroy();

      expect(() => kem.generateKeyPair()).toThrow(/destroyed/);
    });

    test('should throw error on invalid public key size', async () => {
      const kem = await factory();
      const invalidPublicKey = new Uint8Array(10); // Wrong size

      expect(() => kem.encapsulate(invalidPublicKey)).toThrow(/Invalid public key/);

      kem.destroy();
    });

    test('should throw error on invalid secret key size', async () => {
      const kem = await factory();
      const { publicKey } = kem.generateKeyPair();
      const { ciphertext } = kem.encapsulate(publicKey);
      const invalidSecretKey = new Uint8Array(10); // Wrong size

      expect(() => kem.decapsulate(ciphertext, invalidSecretKey)).toThrow(/Invalid secret key/);

      kem.destroy();
    });

    test('should throw error on invalid ciphertext size', async () => {
      const kem = await factory();
      const { secretKey } = kem.generateKeyPair();
      const invalidCiphertext = new Uint8Array(10); // Wrong size

      expect(() => kem.decapsulate(invalidCiphertext, secretKey)).toThrow(/Invalid ciphertext/);

      kem.destroy();
    });
  });
});

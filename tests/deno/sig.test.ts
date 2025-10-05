/// <reference lib="deno.ns" />

/**
 * @fileoverview Unit tests for SIG (Digital Signature) algorithms
 * @description Tests all implemented signature algorithms for basic functionality:
 * - Key pair generation
 * - Message signing
 * - Signature verification
 * - Invalid signature detection
 */

import { assertEquals, assertRejects, assertInstanceOf, assertNotEquals } from "@std/assert";

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
  createMLDSA44,
  createMLDSA65,
  createMLDSA87,
  ML_DSA_44_INFO,
  ML_DSA_65_INFO,
  ML_DSA_87_INFO,
  createFalcon512,
  createFalcon1024,
  createFalconPadded512,
  createFalconPadded1024,
  FALCON_512_INFO,
  FALCON_1024_INFO,
  FALCON_PADDED_512_INFO,
  FALCON_PADDED_1024_INFO,
  createMAYO1,
  createMAYO2,
  createMAYO3,
  createMAYO5,
  MAYO_1_INFO,
  MAYO_2_INFO,
  MAYO_3_INFO,
  MAYO_5_INFO,
  createOVIp,
  createOVIpPkc,
  createOVIpPkcSkc,
  createOVIs,
  createOVIsPkc,
  createOVIsPkcSkc,
  createOVIII,
  createOVIIIPkc,
  createOVIIIPkcSkc,
  createOVV,
  createOVVPkc,
  createOVVPkcSkc,
  OV_IP_INFO,
  OV_IP_PKC_INFO,
  OV_IP_PKC_SKC_INFO,
  OV_IS_INFO,
  OV_IS_PKC_INFO,
  OV_IS_PKC_SKC_INFO,
  OV_III_INFO,
  OV_III_PKC_INFO,
  OV_III_PKC_SKC_INFO,
  OV_V_INFO,
  OV_V_PKC_INFO,
  OV_V_PKC_SKC_INFO,
  createCrossRsdp128Balanced,
  createCrossRsdp128Fast,
  createCrossRsdp128Small,
  createCrossRsdp192Balanced,
  createCrossRsdp192Fast,
  createCrossRsdp192Small,
  createCrossRsdp256Balanced,
  createCrossRsdp256Fast,
  createCrossRsdp256Small,
  createCrossRsdpg128Balanced,
  createCrossRsdpg128Fast,
  createCrossRsdpg128Small,
  createCrossRsdpg192Balanced,
  createCrossRsdpg192Fast,
  createCrossRsdpg192Small,
  createCrossRsdpg256Balanced,
  createCrossRsdpg256Fast,
  createCrossRsdpg256Small,
  CROSS_RSDP_128_BALANCED_INFO,
  CROSS_RSDP_128_FAST_INFO,
  CROSS_RSDP_128_SMALL_INFO,
  CROSS_RSDP_192_BALANCED_INFO,
  CROSS_RSDP_192_FAST_INFO,
  CROSS_RSDP_192_SMALL_INFO,
  CROSS_RSDP_256_BALANCED_INFO,
  CROSS_RSDP_256_FAST_INFO,
  CROSS_RSDP_256_SMALL_INFO,
  CROSS_RSDPG_128_BALANCED_INFO,
  CROSS_RSDPG_128_FAST_INFO,
  CROSS_RSDPG_128_SMALL_INFO,
  CROSS_RSDPG_192_BALANCED_INFO,
  CROSS_RSDPG_192_FAST_INFO,
  CROSS_RSDPG_192_SMALL_INFO,
  CROSS_RSDPG_256_BALANCED_INFO,
  CROSS_RSDPG_256_FAST_INFO,
  CROSS_RSDPG_256_SMALL_INFO,
  createSphincsSha2128fSimple,
  createSphincsSha2128sSimple,
  createSphincsSha2192fSimple,
  createSphincsSha2192sSimple,
  createSphincsSha2256fSimple,
  createSphincsSha2256sSimple,
  createSphincsShake128fSimple,
  createSphincsShake128sSimple,
  createSphincsShake192fSimple,
  createSphincsShake192sSimple,
  createSphincsShake256fSimple,
  createSphincsShake256sSimple,
  SPHINCSPLUS_SHA2_128F_SIMPLE_INFO,
  SPHINCSPLUS_SHA2_128S_SIMPLE_INFO,
  SPHINCSPLUS_SHA2_192F_SIMPLE_INFO,
  SPHINCSPLUS_SHA2_192S_SIMPLE_INFO,
  SPHINCSPLUS_SHA2_256F_SIMPLE_INFO,
  SPHINCSPLUS_SHA2_256S_SIMPLE_INFO,
  SPHINCSPLUS_SHAKE_128F_SIMPLE_INFO,
  SPHINCSPLUS_SHAKE_128S_SIMPLE_INFO,
  SPHINCSPLUS_SHAKE_192F_SIMPLE_INFO,
  SPHINCSPLUS_SHAKE_192S_SIMPLE_INFO,
  SPHINCSPLUS_SHAKE_256F_SIMPLE_INFO,
  SPHINCSPLUS_SHAKE_256S_SIMPLE_INFO,
  createSnova2454,
  createSnova2454Esk,
  createSnova2454Shake,
  createSnova2454ShakeEsk,
  createSnova2455,
  createSnova2583,
  createSnova2965,
  createSnova37172,
  createSnova3784,
  createSnova49113,
  createSnova56252,
  createSnova60104,
  SNOVA_24_5_4_INFO,
  SNOVA_24_5_4_ESK_INFO,
  SNOVA_24_5_4_SHAKE_INFO,
  SNOVA_24_5_4_SHAKE_ESK_INFO,
  SNOVA_24_5_5_INFO,
  SNOVA_25_8_3_INFO,
  SNOVA_29_6_5_INFO,
  SNOVA_37_17_2_INFO,
  SNOVA_37_8_4_INFO,
  SNOVA_49_11_3_INFO,
  SNOVA_56_25_2_INFO,
  SNOVA_60_10_4_INFO
} from '../../src/index.js';

// Import WASM modules

/**
 * Registry of all signature algorithms to test
 * Add new algorithms here when implemented
 */
const sigAlgorithms: Array<{
  name: string;
  factory: () => Promise<any>;
  info: Readonly<Record<string, any>>;
}> = [
  {
    name: 'ML-DSA-44',
    factory: createMLDSA44,

    info: ML_DSA_44_INFO
  },
  {
    name: 'ML-DSA-65',
    factory: createMLDSA65,

    info: ML_DSA_65_INFO
  },
  {
    name: 'ML-DSA-87',
    factory: createMLDSA87,

    info: ML_DSA_87_INFO
  },
  {
    name: 'Falcon-512',
    factory: createFalcon512,

    info: FALCON_512_INFO
  },
  {
    name: 'Falcon-1024',
    factory: createFalcon1024,

    info: FALCON_1024_INFO
  },
  {
    name: 'Falcon-padded-512',
    factory: createFalconPadded512,

    info: FALCON_PADDED_512_INFO
  },
  {
    name: 'Falcon-padded-1024',
    factory: createFalconPadded1024,

    info: FALCON_PADDED_1024_INFO
  },
  {
    name: 'MAYO-1',
    factory: createMAYO1,
    info: MAYO_1_INFO
  },
  {
    name: 'MAYO-2',
    factory: createMAYO2,
    info: MAYO_2_INFO
  },
  {
    name: 'MAYO-3',
    factory: createMAYO3,
    info: MAYO_3_INFO
  },
  {
    name: 'MAYO-5',
    factory: createMAYO5,
    info: MAYO_5_INFO
  },
  {
    name: 'OV-Ip',
    factory: createOVIp,
    info: OV_IP_INFO
  },
  {
    name: 'OV-Ip-pkc',
    factory: createOVIpPkc,
    info: OV_IP_PKC_INFO
  },
  {
    name: 'OV-Ip-pkc-skc',
    factory: createOVIpPkcSkc,
    info: OV_IP_PKC_SKC_INFO
  },
  {
    name: 'OV-Is',
    factory: createOVIs,
    info: OV_IS_INFO
  },
  {
    name: 'OV-Is-pkc',
    factory: createOVIsPkc,
    info: OV_IS_PKC_INFO
  },
  {
    name: 'OV-Is-pkc-skc',
    factory: createOVIsPkcSkc,
    info: OV_IS_PKC_SKC_INFO
  },
  {
    name: 'OV-III',
    factory: createOVIII,
    info: OV_III_INFO
  },
  {
    name: 'OV-III-pkc',
    factory: createOVIIIPkc,
    info: OV_III_PKC_INFO
  },
  {
    name: 'OV-III-pkc-skc',
    factory: createOVIIIPkcSkc,
    info: OV_III_PKC_SKC_INFO
  },
  {
    name: 'OV-V',
    factory: createOVV,
    info: OV_V_INFO
  },
  {
    name: 'OV-V-pkc',
    factory: createOVVPkc,
    info: OV_V_PKC_INFO
  },
  {
    name: 'OV-V-pkc-skc',
    factory: createOVVPkcSkc,
    info: OV_V_PKC_SKC_INFO
  },
  {
    name: 'CROSS-rsdp-128-balanced',
    factory: createCrossRsdp128Balanced,

    info: CROSS_RSDP_128_BALANCED_INFO
  },
  {
    name: 'CROSS-rsdp-128-fast',
    factory: createCrossRsdp128Fast,

    info: CROSS_RSDP_128_FAST_INFO
  },
  {
    name: 'CROSS-rsdp-128-small',
    factory: createCrossRsdp128Small,

    info: CROSS_RSDP_128_SMALL_INFO
  },
  {
    name: 'CROSS-rsdp-192-balanced',
    factory: createCrossRsdp192Balanced,
    info: CROSS_RSDP_192_BALANCED_INFO
  },
  {
    name: 'CROSS-rsdp-192-fast',
    factory: createCrossRsdp192Fast,
    info: CROSS_RSDP_192_FAST_INFO
  },
  {
    name: 'CROSS-rsdp-192-small',
    factory: createCrossRsdp192Small,
    info: CROSS_RSDP_192_SMALL_INFO
  },
  {
    name: 'CROSS-rsdp-256-balanced',
    factory: createCrossRsdp256Balanced,
    info: CROSS_RSDP_256_BALANCED_INFO
  },
  {
    name: 'CROSS-rsdp-256-fast',
    factory: createCrossRsdp256Fast,
    info: CROSS_RSDP_256_FAST_INFO
  },
  {
    name: 'CROSS-rsdp-256-small',
    factory: createCrossRsdp256Small,
    info: CROSS_RSDP_256_SMALL_INFO
  },
  {
    name: 'CROSS-rsdpg-128-balanced',
    factory: createCrossRsdpg128Balanced,
    info: CROSS_RSDPG_128_BALANCED_INFO
  },
  {
    name: 'CROSS-rsdpg-128-fast',
    factory: createCrossRsdpg128Fast,
    info: CROSS_RSDPG_128_FAST_INFO
  },
  {
    name: 'CROSS-rsdpg-128-small',
    factory: createCrossRsdpg128Small,
    info: CROSS_RSDPG_128_SMALL_INFO
  },
  {
    name: 'CROSS-rsdpg-192-balanced',
    factory: createCrossRsdpg192Balanced,
    info: CROSS_RSDPG_192_BALANCED_INFO
  },
  {
    name: 'CROSS-rsdpg-192-fast',
    factory: createCrossRsdpg192Fast,
    info: CROSS_RSDPG_192_FAST_INFO
  },
  {
    name: 'CROSS-rsdpg-192-small',
    factory: createCrossRsdpg192Small,
    info: CROSS_RSDPG_192_SMALL_INFO
  },
  {
    name: 'CROSS-rsdpg-256-balanced',
    factory: createCrossRsdpg256Balanced,
    info: CROSS_RSDPG_256_BALANCED_INFO
  },
  {
    name: 'CROSS-rsdpg-256-fast',
    factory: createCrossRsdpg256Fast,
    info: CROSS_RSDPG_256_FAST_INFO
  },
  {
    name: 'CROSS-rsdpg-256-small',
    factory: createCrossRsdpg256Small,
    info: CROSS_RSDPG_256_SMALL_INFO
  },
  {
    name: 'SPHINCS+-SHA2-128f-simple',
    factory: createSphincsSha2128fSimple,
    info: SPHINCSPLUS_SHA2_128F_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHA2-128s-simple',
    factory: createSphincsSha2128sSimple,
    info: SPHINCSPLUS_SHA2_128S_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHA2-192f-simple',
    factory: createSphincsSha2192fSimple,
    info: SPHINCSPLUS_SHA2_192F_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHA2-192s-simple',
    factory: createSphincsSha2192sSimple,
    info: SPHINCSPLUS_SHA2_192S_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHA2-256f-simple',
    factory: createSphincsSha2256fSimple,
    info: SPHINCSPLUS_SHA2_256F_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHA2-256s-simple',
    factory: createSphincsSha2256sSimple,
    info: SPHINCSPLUS_SHA2_256S_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHAKE-128f-simple',
    factory: createSphincsShake128fSimple,
    info: SPHINCSPLUS_SHAKE_128F_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHAKE-128s-simple',
    factory: createSphincsShake128sSimple,
    info: SPHINCSPLUS_SHAKE_128S_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHAKE-192f-simple',
    factory: createSphincsShake192fSimple,
    info: SPHINCSPLUS_SHAKE_192F_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHAKE-192s-simple',
    factory: createSphincsShake192sSimple,
    info: SPHINCSPLUS_SHAKE_192S_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHAKE-256f-simple',
    factory: createSphincsShake256fSimple,
    info: SPHINCSPLUS_SHAKE_256F_SIMPLE_INFO
  },
  {
    name: 'SPHINCS+-SHAKE-256s-simple',
    factory: createSphincsShake256sSimple,
    info: SPHINCSPLUS_SHAKE_256S_SIMPLE_INFO
  },
  {
    name: 'SNOVA-24-5-4',
    factory: createSnova2454,
    info: SNOVA_24_5_4_INFO
  },
  {
    name: 'SNOVA-24-5-4-esk',
    factory: createSnova2454Esk,
    info: SNOVA_24_5_4_ESK_INFO
  },
  {
    name: 'SNOVA-24-5-4-SHAKE',
    factory: createSnova2454Shake,
    info: SNOVA_24_5_4_SHAKE_INFO
  },
  {
    name: 'SNOVA-24-5-4-SHAKE-esk',
    factory: createSnova2454ShakeEsk,
    info: SNOVA_24_5_4_SHAKE_ESK_INFO
  },
  {
    name: 'SNOVA-24-5-5',
    factory: createSnova2455,
    info: SNOVA_24_5_5_INFO
  },
  {
    name: 'SNOVA-25-8-3',
    factory: createSnova2583,
    info: SNOVA_25_8_3_INFO
  },
  {
    name: 'SNOVA-29-6-5',
    factory: createSnova2965,
    info: SNOVA_29_6_5_INFO
  },
  {
    name: 'SNOVA-37-17-2',
    factory: createSnova37172,
    info: SNOVA_37_17_2_INFO
  },
  {
    name: 'SNOVA-37-8-4',
    factory: createSnova3784,
    info: SNOVA_37_8_4_INFO
  },
  {
    name: 'SNOVA-49-11-3',
    factory: createSnova49113,
    info: SNOVA_49_11_3_INFO
  },
  {
    name: 'SNOVA-56-25-2',
    factory: createSnova56252,
    info: SNOVA_56_25_2_INFO
  },
  {
    name: 'SNOVA-60-10-4',
    factory: createSnova60104,
    info: SNOVA_60_10_4_INFO
  }
];

for (const { name, factory, info } of sigAlgorithms) {
  Deno.test(`${name} - should generate valid keypair`, async () => {
    const sig = await factory();

    const { publicKey, secretKey } = await sig.generateKeyPair();

    assertInstanceOf(publicKey, Uint8Array);
    assertInstanceOf(secretKey, Uint8Array);
    assertEquals(publicKey.length, info.keySize.publicKey);
    assertEquals(secretKey.length, info.keySize.secretKey);

    sig.destroy();
  });

  Deno.test(`${name} - should sign message and produce valid signature`, async () => {
    const sig = await factory();
    const { secretKey } = await sig.generateKeyPair();
    const message = new TextEncoder().encode('Test message for signing');

    const signature = await sig.sign(message, secretKey);

    assertInstanceOf(signature, Uint8Array);
    assertEquals(signature.length > 0, true);
    assertEquals(signature.length <= info.keySize.signature, true);

    sig.destroy();
  });

  Deno.test(`${name} - should verify valid signature`, async () => {
    const sig = await factory();
    const { publicKey, secretKey } = await sig.generateKeyPair();
    const message = new TextEncoder().encode('Test message');

    const signature = await sig.sign(message, secretKey);
    const isValid = await sig.verify(message, signature, publicKey);

    assertEquals(isValid, true);

    sig.destroy();
  });

  Deno.test(`${name} - should reject signature with wrong message`, async () => {
    const sig = await factory();
    const { publicKey, secretKey } = await sig.generateKeyPair();
    const message = new TextEncoder().encode('Original message');
    const wrongMessage = new TextEncoder().encode('Wrong message');

    const signature = await sig.sign(message, secretKey);
    const isValid = await sig.verify(wrongMessage, signature, publicKey);

    assertEquals(isValid, false);

    sig.destroy();
  });

  Deno.test(`${name} - should reject signature with wrong public key`, async () => {
    const sig = await factory();
    const keypair1 = await sig.generateKeyPair();
    const keypair2 = await sig.generateKeyPair();
    const message = new TextEncoder().encode('Test message');

    const signature = await sig.sign(message, keypair1.secretKey);
    const isValid = await sig.verify(message, signature, keypair2.publicKey);

    assertEquals(isValid, false);

    sig.destroy();
  });

  Deno.test(`${name} - should reject tampered signature`, async () => {
    const sig = await factory();
    const { publicKey, secretKey } = await sig.generateKeyPair();
    const message = new TextEncoder().encode('Test message');

    const signature = await sig.sign(message, secretKey);

    // Tamper with signature
    const tamperedSignature = new Uint8Array(signature);
    tamperedSignature[0] ^= 0xFF;

    const isValid = await sig.verify(message, tamperedSignature, publicKey);

    assertEquals(isValid, false);

    sig.destroy();
  });

  Deno.test(`${name} - should produce different signatures on each signing`, async () => {
    const sig = await factory();
    const { secretKey } = await sig.generateKeyPair();
    const message = new TextEncoder().encode('Test message');

    const signature1 = await sig.sign(message, secretKey);
    const signature2 = await sig.sign(message, secretKey);

    // ML-DSA is randomized, so signatures should differ
    assertNotEquals(compareArrays(signature1, signature2), 0);

    sig.destroy();
  });

  Deno.test(`${name} - should produce different keypairs on each generation`, async () => {
    const sig = await factory();

    const keypair1 = await sig.generateKeyPair();
    const keypair2 = await sig.generateKeyPair();

    // Public keys should differ
    assertNotEquals(compareArrays(keypair1.publicKey, keypair2.publicKey), 0);
    // Secret keys should differ
    assertNotEquals(compareArrays(keypair1.secretKey, keypair2.secretKey), 0);

    sig.destroy();
  });

  Deno.test(`${name} - should sign and verify empty message`, async () => {
    const sig = await factory();
    const { publicKey, secretKey } = await sig.generateKeyPair();
    const emptyMessage = new Uint8Array(0);

    const signature = await sig.sign(emptyMessage, secretKey);
    const isValid = await sig.verify(emptyMessage, signature, publicKey);

    assertEquals(isValid, true);

    sig.destroy();
  });

  Deno.test(`${name} - should sign and verify large message`, async () => {
    const sig = await factory();
    const { publicKey, secretKey } = await sig.generateKeyPair();
    // Create 1MB message
    const largeMessage = new Uint8Array(1024 * 1024).fill(42);

    const signature = await sig.sign(largeMessage, secretKey);
    const isValid = await sig.verify(largeMessage, signature, publicKey);

    assertEquals(isValid, true);

    sig.destroy();
  });

  Deno.test(`${name} - should have correct algorithm info`, async () => {
    const sig = await factory();
    const sigInfo = sig.info;

    assertEquals(sigInfo.name, name);
    assertEquals(sigInfo.identifier, info.identifier);
    assertEquals(sigInfo.type, 'sig');
    assertEquals(sigInfo.standardized, info.standardized);
    assertEquals(sigInfo.keySize, info.keySize);

    sig.destroy();
  });

  Deno.test(`${name} - should throw error when using destroyed instance`, async () => {
    const sig = await factory();
    sig.destroy();

    await assertRejects(
      async () => await sig.generateKeyPair(),
      Error,
      "destroyed"
    );
  });

  Deno.test(`${name} - should throw error on invalid public key size`, async () => {
    const sig = await factory();
    const { secretKey } = await sig.generateKeyPair();
    const message = new TextEncoder().encode('Test');
    const signature = await sig.sign(message, secretKey);
    const invalidPublicKey = new Uint8Array(10); // Wrong size

    await assertRejects(
      async () => await sig.verify(message, signature, invalidPublicKey),
      Error,
      "Invalid public key"
    );

    sig.destroy();
  });

  Deno.test(`${name} - should throw error on invalid secret key size`, async () => {
    const sig = await factory();
    const message = new TextEncoder().encode('Test');
    const invalidSecretKey = new Uint8Array(10); // Wrong size

    await assertRejects(
      async () => await sig.sign(message, invalidSecretKey),
      Error,
      "Invalid secret key"
    );

    sig.destroy();
  });

  Deno.test(`${name} - should throw error on invalid signature size`, async () => {
    const sig = await factory();
    const { publicKey } = await sig.generateKeyPair();
    const message = new TextEncoder().encode('Test');
    const invalidSignature = new Uint8Array(0); // Empty signature

    await assertRejects(
      async () => await sig.verify(message, invalidSignature, publicKey),
      Error,
      "Invalid signature"
    );

    sig.destroy();
  });
}

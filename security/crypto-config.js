/**
 * Yakmesh Cryptographic Configuration
 * 
 * Provides configurable security levels for post-quantum algorithms.
 * Supports NIST standardized algorithms from FIPS 203/204.
 * 
 * Security Levels:
 * - LEVEL_3: Default (ML-KEM-768, ML-DSA-65) - ~192-bit classical security
 * - LEVEL_5: Paranoid (ML-KEM-1024, ML-DSA-87) - ~256-bit classical security
 * 
 * @module security/crypto-config
 * @version 1.6.0
 * @license MIT
 */

import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

/**
 * NIST Security Level configurations
 */
export const SecurityLevel = {
  LEVEL_3: 3,  // ~192-bit classical security (default)
  LEVEL_5: 5,  // ~256-bit classical security (paranoid)
};

/**
 * Algorithm configurations by security level
 */
const CRYPTO_PROFILES = {
  [SecurityLevel.LEVEL_3]: {
    name: 'NIST Level 3',
    classicalBits: 192,
    quantumBits: 128,
    signature: {
      name: 'ML-DSA-65',
      algorithm: ml_dsa65,
      publicKeySize: 1952,
      secretKeySize: 4032,
      signatureSize: 3309,
    },
    kem: {
      name: 'ML-KEM-768',
      algorithm: ml_kem768,
      publicKeySize: 1184,
      secretKeySize: 2400,
      ciphertextSize: 1088,
      sharedSecretSize: 32,
    },
  },
  [SecurityLevel.LEVEL_5]: {
    name: 'NIST Level 5',
    classicalBits: 256,
    quantumBits: 192,
    signature: {
      name: 'ML-DSA-87',
      algorithm: ml_dsa87,
      publicKeySize: 2592,
      secretKeySize: 4896,
      signatureSize: 4627,
    },
    kem: {
      name: 'ML-KEM-1024',
      algorithm: ml_kem1024,
      publicKeySize: 1568,
      secretKeySize: 3168,
      ciphertextSize: 1568,
      sharedSecretSize: 32,
    },
  },
};

// Current active security level (can be changed at runtime)
let activeLevel = SecurityLevel.LEVEL_3;

/**
 * Set the active security level
 * @param {number} level - SecurityLevel.LEVEL_3 or SecurityLevel.LEVEL_5
 */
export function setSecurityLevel(level) {
  if (!CRYPTO_PROFILES[level]) {
    throw new Error(`Invalid security level: ${level}. Use SecurityLevel.LEVEL_3 or LEVEL_5`);
  }
  activeLevel = level;
  console.log(`🔐 Security level set to ${CRYPTO_PROFILES[level].name}`);
}

/**
 * Get the current security level
 * @returns {number} Current security level
 */
export function getSecurityLevel() {
  return activeLevel;
}

/**
 * Get the crypto profile for current or specified security level
 * @param {number} [level] - Optional security level (uses active if not specified)
 * @returns {Object} Crypto profile with signature and kem algorithms
 */
export function getCryptoProfile(level = activeLevel) {
  return CRYPTO_PROFILES[level];
}

/**
 * Get the signature algorithm for current security level
 * @param {number} [level] - Optional security level
 * @returns {Object} Signature algorithm instance (ml_dsa65 or ml_dsa87)
 */
export function getSignatureAlgorithm(level = activeLevel) {
  return CRYPTO_PROFILES[level].signature.algorithm;
}

/**
 * Get the KEM algorithm for current security level
 * @param {number} [level] - Optional security level  
 * @returns {Object} KEM algorithm instance (ml_kem768 or ml_kem1024)
 */
export function getKemAlgorithm(level = activeLevel) {
  return CRYPTO_PROFILES[level].kem.algorithm;
}

/**
 * Get signature algorithm name for current security level
 * @param {number} [level] - Optional security level
 * @returns {string} Algorithm name (e.g., 'ML-DSA-65')
 */
export function getSignatureName(level = activeLevel) {
  return CRYPTO_PROFILES[level].signature.name;
}

/**
 * Get KEM algorithm name for current security level
 * @param {number} [level] - Optional security level
 * @returns {string} Algorithm name (e.g., 'ML-KEM-768')
 */
export function getKemName(level = activeLevel) {
  return CRYPTO_PROFILES[level].kem.name;
}

/**
 * Generate a keypair using the current security level's signature algorithm
 * @param {Uint8Array} seed - 32-byte seed for deterministic generation
 * @param {number} [level] - Optional security level
 * @returns {Object} { publicKey, secretKey }
 */
export function generateSignatureKeyPair(seed, level = activeLevel) {
  const algo = CRYPTO_PROFILES[level].signature.algorithm;
  return algo.keygen(seed);
}

/**
 * Sign a message using the current security level's signature algorithm
 * @param {Uint8Array} message - Message to sign
 * @param {Uint8Array} secretKey - Secret key
 * @param {number} [level] - Optional security level
 * @returns {Uint8Array} Signature
 */
export function sign(message, secretKey, level = activeLevel) {
  const algo = CRYPTO_PROFILES[level].signature.algorithm;
  return algo.sign(message, secretKey);
}

/**
 * Verify a signature using the current security level's signature algorithm
 * @param {Uint8Array} signature - Signature to verify
 * @param {Uint8Array} message - Original message
 * @param {Uint8Array} publicKey - Public key
 * @param {number} [level] - Optional security level
 * @returns {boolean} True if valid
 */
export function verify(signature, message, publicKey, level = activeLevel) {
  const algo = CRYPTO_PROFILES[level].signature.algorithm;
  return algo.verify(signature, message, publicKey);
}

/**
 * Generate a KEM keypair using the current security level
 * @param {Uint8Array} seed - 64-byte seed for deterministic generation
 * @param {number} [level] - Optional security level
 * @returns {Object} { publicKey, secretKey }
 */
export function generateKemKeyPair(seed, level = activeLevel) {
  const algo = CRYPTO_PROFILES[level].kem.algorithm;
  return algo.keygen(seed);
}

/**
 * Encapsulate (create shared secret) using peer's public key
 * @param {Uint8Array} publicKey - Peer's public key
 * @param {number} [level] - Optional security level
 * @returns {Object} { ciphertext, sharedSecret }
 */
export function encapsulate(publicKey, level = activeLevel) {
  const algo = CRYPTO_PROFILES[level].kem.algorithm;
  // noble uses cipherText (camelCase), we normalize to ciphertext
  const { cipherText, sharedSecret } = algo.encapsulate(publicKey);
  return { ciphertext: cipherText, sharedSecret };
}

/**
 * Decapsulate (recover shared secret) using own secret key
 * @param {Uint8Array} ciphertext - Received ciphertext
 * @param {Uint8Array} secretKey - Own secret key
 * @param {number} [level] - Optional security level
 * @returns {Uint8Array} Shared secret
 */
export function decapsulate(ciphertext, secretKey, level = activeLevel) {
  const algo = CRYPTO_PROFILES[level].kem.algorithm;
  return algo.decapsulate(ciphertext, secretKey);
}

/**
 * Get human-readable summary of current crypto configuration
 * @returns {Object} Summary object
 */
export function getCryptoSummary() {
  const profile = CRYPTO_PROFILES[activeLevel];
  return {
    securityLevel: activeLevel,
    levelName: profile.name,
    classicalSecurity: `${profile.classicalBits}-bit`,
    quantumSecurity: `${profile.quantumBits}-bit`,
    signatureAlgorithm: profile.signature.name,
    kemAlgorithm: profile.kem.name,
    nistStandards: ['FIPS 203 (ML-KEM)', 'FIPS 204 (ML-DSA)'],
  };
}

export default {
  SecurityLevel,
  setSecurityLevel,
  getSecurityLevel,
  getCryptoProfile,
  getSignatureAlgorithm,
  getKemAlgorithm,
  getSignatureName,
  getKemName,
  generateSignatureKeyPair,
  sign,
  verify,
  generateKemKeyPair,
  encapsulate,
  decapsulate,
  getCryptoSummary,
};

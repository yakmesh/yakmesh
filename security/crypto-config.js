/**
 * Yakmesh Cryptographic Configuration
 * 
 * Provides configurable security levels for post-quantum algorithms.
 * Supports NIST standardized algorithms from FIPS 203/204/205.
 * 
 * Security Levels:
 * - LEVEL_3: Default (ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-192f) - ~192-bit classical security
 * - LEVEL_5: Paranoid (ML-KEM-1024, ML-DSA-87, SLH-DSA-SHA2-256f) - ~256-bit classical security
 * 
 * Signature Strategy:
 * - Primary: ML-DSA (lattice-based) - fast, compact signatures
 * - Backup: SLH-DSA (hash-based) - different cryptographic assumptions, defense-in-depth
 * 
 * @module security/crypto-config
 * @version 1.7.0
 * @license MIT
 */

import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { slh_dsa_sha2_192f, slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';

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
    backupSignature: {
      name: 'SLH-DSA-SHA2-192f',
      algorithm: slh_dsa_sha2_192f,
      publicKeySize: 48,
      secretKeySize: 96,
      signatureSize: 35664,
      type: 'hash-based',
      fips: '205',
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
    backupSignature: {
      name: 'SLH-DSA-SHA2-256f',
      algorithm: slh_dsa_sha2_256f,
      publicKeySize: 64,
      secretKeySize: 128,
      signatureSize: 49856,
      type: 'hash-based',
      fips: '205',
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
    backupSignatureAlgorithm: profile.backupSignature.name,
    kemAlgorithm: profile.kem.name,
    nistStandards: ['FIPS 203 (ML-KEM)', 'FIPS 204 (ML-DSA)', 'FIPS 205 (SLH-DSA)'],
  };
}

// =============================================================================
// SLH-DSA Backup Signature Functions (FIPS 205 - Hash-Based)
// =============================================================================

/**
 * Get the backup (SLH-DSA) signature algorithm for current security level
 * @param {number} [level] - Optional security level
 * @returns {Object} Backup signature algorithm instance
 */
export function getBackupSignatureAlgorithm(level = activeLevel) {
  return CRYPTO_PROFILES[level].backupSignature.algorithm;
}

/**
 * Get backup signature algorithm name for current security level
 * @param {number} [level] - Optional security level
 * @returns {string} Algorithm name (e.g., 'SLH-DSA-SHA2-192f')
 */
export function getBackupSignatureName(level = activeLevel) {
  return CRYPTO_PROFILES[level].backupSignature.name;
}

/**
 * Generate a backup (SLH-DSA) keypair using the current security level
 * Note: SLH-DSA keys are much smaller than ML-DSA, but signatures are larger
 * @param {number} [level] - Optional security level
 * @returns {Object} { publicKey, secretKey }
 */
export function generateBackupSignatureKeyPair(level = activeLevel) {
  const algo = CRYPTO_PROFILES[level].backupSignature.algorithm;
  return algo.keygen();
}

/**
 * Sign a message using SLH-DSA (backup/hash-based algorithm)
 * Note: SLH-DSA signing is slower (~100-160ms) but based on hash assumptions
 * @param {Uint8Array} message - Message to sign
 * @param {Uint8Array} secretKey - SLH-DSA secret key
 * @param {number} [level] - Optional security level
 * @returns {Uint8Array} Signature (larger than ML-DSA, ~35-50KB)
 */
export function signBackup(message, secretKey, level = activeLevel) {
  const algo = CRYPTO_PROFILES[level].backupSignature.algorithm;
  return algo.sign(message, secretKey);
}

/**
 * Verify a SLH-DSA backup signature
 * @param {Uint8Array} signature - Signature to verify
 * @param {Uint8Array} message - Original message
 * @param {Uint8Array} publicKey - SLH-DSA public key
 * @param {number} [level] - Optional security level
 * @returns {boolean} True if valid
 */
export function verifyBackup(signature, message, publicKey, level = activeLevel) {
  const algo = CRYPTO_PROFILES[level].backupSignature.algorithm;
  return algo.verify(signature, message, publicKey);
}

// =============================================================================
// Dual Signature Functions (Defense-in-Depth)
// =============================================================================

/**
 * Generate both ML-DSA (primary) and SLH-DSA (backup) keypairs
 * Use for maximum security: if lattice assumptions break, hash-based still holds
 * @param {Uint8Array} seed - 32-byte seed for ML-DSA (SLH-DSA uses random)
 * @param {number} [level] - Optional security level
 * @returns {Object} { primary: { publicKey, secretKey }, backup: { publicKey, secretKey } }
 */
export function generateDualSignatureKeyPairs(seed, level = activeLevel) {
  return {
    primary: generateSignatureKeyPair(seed, level),
    backup: generateBackupSignatureKeyPair(level),
  };
}

/**
 * Create a dual signature (both ML-DSA and SLH-DSA)
 * Provides defense-in-depth: attacker must break BOTH lattice AND hash assumptions
 * @param {Uint8Array} message - Message to sign
 * @param {Uint8Array} primarySecretKey - ML-DSA secret key
 * @param {Uint8Array} backupSecretKey - SLH-DSA secret key
 * @param {number} [level] - Optional security level
 * @returns {Object} { primary: Uint8Array, backup: Uint8Array, combined: Uint8Array }
 */
export function signDual(message, primarySecretKey, backupSecretKey, level = activeLevel) {
  const primarySig = sign(message, primarySecretKey, level);
  const backupSig = signBackup(message, backupSecretKey, level);
  
  // Combined signature: [4-byte primary length][primary sig][backup sig]
  const combined = new Uint8Array(4 + primarySig.length + backupSig.length);
  const view = new DataView(combined.buffer);
  view.setUint32(0, primarySig.length, false); // big-endian length prefix
  combined.set(primarySig, 4);
  combined.set(backupSig, 4 + primarySig.length);
  
  return { primary: primarySig, backup: backupSig, combined };
}

/**
 * Verify a dual signature (requires BOTH signatures to be valid)
 * @param {Object} signatures - { primary, backup } or { combined }
 * @param {Uint8Array} message - Original message
 * @param {Uint8Array} primaryPublicKey - ML-DSA public key
 * @param {Uint8Array} backupPublicKey - SLH-DSA public key
 * @param {number} [level] - Optional security level
 * @returns {Object} { valid: boolean, primaryValid: boolean, backupValid: boolean }
 */
export function verifyDual(signatures, message, primaryPublicKey, backupPublicKey, level = activeLevel) {
  let primarySig, backupSig;
  
  if (signatures.combined) {
    // Parse combined signature
    const view = new DataView(signatures.combined.buffer, signatures.combined.byteOffset);
    const primaryLen = view.getUint32(0, false);
    primarySig = signatures.combined.slice(4, 4 + primaryLen);
    backupSig = signatures.combined.slice(4 + primaryLen);
  } else {
    primarySig = signatures.primary;
    backupSig = signatures.backup;
  }
  
  const primaryValid = verify(primarySig, message, primaryPublicKey, level);
  const backupValid = verifyBackup(backupSig, message, backupPublicKey, level);
  
  return {
    valid: primaryValid && backupValid,
    primaryValid,
    backupValid,
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
  // SLH-DSA backup signatures (FIPS 205)
  getBackupSignatureAlgorithm,
  getBackupSignatureName,
  generateBackupSignatureKeyPair,
  signBackup,
  verifyBackup,
  // Dual signature (defense-in-depth)
  generateDualSignatureKeyPairs,
  signDual,
  verifyDual,
};

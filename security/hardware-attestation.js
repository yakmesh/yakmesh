/**
 * Hardware Attestation - Prove Real Silicon
 * 
 * Uses AES-NI timing characteristics to distinguish real hardware
 * from VMs, emulators, and bot farms. Real silicon has consistent,
 * fast AES operations. Emulation is slow and variable.
 * 
 * v2.4.1: Extended to detect VAES, GFNI, and future PQC accelerators:
 *   - AES-NI (128-bit): Industry baseline
 *   - VAES (256/512-bit): AVX-512 vectorized AES, 4x throughput
 *   - GFNI (512-bit): Universal Galois Field math acceleration
 *   - PQC-NI: Future NTT accelerators for post-quantum (2026-2027)
 * 
 * "If you can't prove your hardware, your word carries less weight."
 * 
 * @module security/hardware-attestation
 * @version 2.4.1
 */

import { createCipheriv, randomBytes } from 'crypto';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
// ACCEL: Hardware-accelerated crypto
import { sha3_256, mlDsa65Sign, mlDsa65Verify } from '../utils/accel.js';
import { createLogger } from '../utils/logger.js';
import os from 'os';

const log = createLogger('security:hardware');

/**
 * Hardware attestation thresholds
 * 
 * Based on empirical testing of real AES-NI hardware:
 * - Real AES-NI: ~2-5ms for 1MB, stddev < 0.5ms
 * - Software AES: ~20-50ms for 1MB, stddev > 5ms
 * - Emulated: ~100-500ms, highly variable
 */
export const HARDWARE_THRESHOLDS = {
  // AES-256-GCM 1MB encryption
  AES_1MB_MAX_MEAN_MS: 20,        // Real hardware < 10ms typically
  AES_1MB_MAX_STDDEV_MS: 2,       // Consistent timing
  AES_1MB_MIN_THROUGHPUT_MBPS: 500, // Minimum 500 MB/s
  
  // Timing consistency
  MAX_VARIANCE_RATIO: 0.2,        // stddev/mean < 20%
  
  // Challenge parameters
  CHALLENGE_DATA_SIZE: 1024 * 1024,  // 1MB
  CHALLENGE_ITERATIONS: 50,
  CHALLENGE_TIMEOUT_MS: 60000,       // 1 minute
};

/**
 * CPU Feature flags we care about
 * Extended for VAES, GFNI, and future PQC acceleration
 */
export const CPU_FEATURES = {
  // Baseline AES (128-bit)
  AES_NI: 'aes',           // AES hardware acceleration
  
  // Vectorized AES (256/512-bit) - AVX-512 extension
  VAES: 'vaes',            // Vector AES (4x throughput)
  AVX: 'avx',              // Advanced Vector Extensions
  AVX2: 'avx2',            // AVX2
  AVX512: 'avx512',        // AVX-512 (enables VAES)
  
  // Galois Field acceleration
  GFNI: 'gfni',            // Galois Field New Instructions (universal crypto)
  
  // Hardware RNG
  RDRAND: 'rdrand',        // Hardware RNG
  RDSEED: 'rdseed',        // Hardware seed RNG
  
  // Post-Quantum (future, 2026-2027)
  NTT_ACCEL: 'ntt',        // Number Theoretic Transform accelerator
  SHA3_NI: 'sha3ni',       // SHA-3/Keccak acceleration
};

/**
 * Crypto acceleration tiers
 * Higher tiers = stronger fingerprints and more trust
 */
export const CRYPTO_ACCELERATION_TIER = {
  NONE: 0,          // Software only - no hardware acceleration
  AES_NI: 1,        // Basic AES-NI (128-bit) - current baseline
  VAES_256: 2,      // VAES 256-bit (AVX2) - 2x throughput
  VAES_512: 3,      // VAES 512-bit (AVX-512) - 4x throughput
  GFNI: 4,          // GFNI (universal Galois Field) - most flexible
  PQC_READY: 5,     // Future: NTT + SHA-3 accelerators
};

/**
 * Tier names for display
 */
export const TIER_NAMES = {
  [CRYPTO_ACCELERATION_TIER.NONE]: 'Software',
  [CRYPTO_ACCELERATION_TIER.AES_NI]: 'AES-NI',
  [CRYPTO_ACCELERATION_TIER.VAES_256]: 'VAES-256',
  [CRYPTO_ACCELERATION_TIER.VAES_512]: 'VAES-512',
  [CRYPTO_ACCELERATION_TIER.GFNI]: 'GFNI',
  [CRYPTO_ACCELERATION_TIER.PQC_READY]: 'PQC-Ready',
};

/**
 * Detect CPU features
 * Uses Node.js crypto module which exposes OpenSSL's detection
 * Extended for VAES, GFNI, AVX-512, and PQC readiness
 */
export function detectCPUFeatures() {
  const cpus = os.cpus();
  const cpu = cpus[0] || {};
  const model = cpu.model || '';
  
  // Parse CPU flags from model string and system info
  const vendor = detectCPUVendor();
  const flags = detectCPUFlags(model, vendor);
  
  const features = {
    vendor,
    model,
    cores: cpus.length,
    speed: cpu.speed || 0,
    
    // Baseline AES-NI (set by timing test)
    hasAESNI: false,
    
    // Extended instruction sets
    hasVAES: flags.vaes,
    hasAVX: flags.avx,
    hasAVX2: flags.avx2,
    hasAVX512: flags.avx512,
    hasGFNI: flags.gfni,
    
    // Hardware RNG
    hasRDRAND: flags.rdrand,
    hasRDSEED: flags.rdseed,
    
    // Post-quantum readiness (future)
    hasNTTAccel: flags.ntt,
    hasSHA3NI: flags.sha3ni,
    
    // Hardware RNG via Web Crypto
    hasHardwareRNG: typeof crypto !== 'undefined' && 
                    typeof crypto.getRandomValues === 'function',
    
    // Crypto acceleration tier (updated after timing test)
    cryptoTier: CRYPTO_ACCELERATION_TIER.NONE,
    cryptoTierName: 'Unknown',
  };
  
  return features;
}

/**
 * Detect CPU flags from model string and vendor
 * This is heuristic-based since Node.js doesn't expose CPUID directly
 */
function detectCPUFlags(model, vendor) {
  const flags = {
    aes: false,
    vaes: false,
    avx: false,
    avx2: false,
    avx512: false,
    gfni: false,
    rdrand: false,
    rdseed: false,
    ntt: false,
    sha3ni: false,
  };
  
  const modelLower = model.toLowerCase();
  
  // Intel detection
  if (vendor === 'GenuineIntel') {
    // AES-NI: Westmere (2010) and later
    if (modelLower.match(/i[3579]|xeon|core/)) {
      flags.aes = true;
      flags.rdrand = true;
    }
    
    // AVX: Sandy Bridge (2011) and later
    if (modelLower.match(/2nd gen|3rd gen|4th gen|5th gen|6th gen|7th gen|8th gen|9th gen|10th gen|11th gen|12th gen|13th gen|14th gen/i) ||
        modelLower.match(/haswell|broadwell|skylake|coffee|comet|ice|tiger|alder|raptor|meteor/i)) {
      flags.avx = true;
      flags.avx2 = true;
    }
    
    // AVX-512 + VAES: Ice Lake (2019) and later
    if (modelLower.match(/ice lake|tiger lake|alder lake|raptor lake|meteor lake|sapphire rapids|emerald rapids/i) ||
        modelLower.match(/11th gen|12th gen|13th gen|14th gen/i)) {
      flags.avx512 = true;
      flags.vaes = true;
    }
    
    // GFNI: Ice Lake (2019) and later
    if (modelLower.match(/ice lake|tiger lake|sapphire rapids|emerald rapids/i) ||
        modelLower.match(/11th gen/i)) {
      flags.gfni = true;
    }
    
    // Sapphire Rapids has AMX (AI) which may help PQC
    if (modelLower.match(/sapphire rapids|emerald rapids/i)) {
      flags.rdseed = true;
    }
  }
  
  // AMD detection
  if (vendor === 'AuthenticAMD') {
    // AES-NI: Bulldozer (2011) and later, plus Ryzen
    if (modelLower.match(/ryzen|epyc|threadripper|bulldozer|piledriver|steamroller|excavator/i)) {
      flags.aes = true;
      flags.rdrand = true;
    }
    
    // AVX/AVX2: Ryzen (Zen) and later
    if (modelLower.match(/ryzen|epyc|threadripper/i)) {
      flags.avx = true;
      flags.avx2 = true;
    }
    
    // VAES + GFNI: Zen 3 (Ryzen 5000) and later
    if (modelLower.match(/5[0-9]{3}|7[0-9]{3}|9[0-9]{3}|zen 3|zen 4|zen 5/i) ||
        modelLower.match(/vermeer|cezanne|raphael|phoenix|granite ridge/i)) {
      flags.vaes = true;
      flags.gfni = true;
    }
    
    // AVX-512: Zen 4 (Ryzen 7000) and later
    if (modelLower.match(/7[0-9]{3}x?|9[0-9]{3}x?|zen 4|zen 5/i) ||
        modelLower.match(/raphael|phoenix|granite ridge/i)) {
      flags.avx512 = true;
    }
  }
  
  // Apple Silicon detection
  if (vendor === 'Apple') {
    // M1 and later have AES acceleration
    if (modelLower.match(/apple m[1-9]/i)) {
      flags.aes = true;
      flags.rdrand = true;
      // Apple has its own crypto acceleration, roughly equivalent to VAES
      flags.vaes = true;
    }
  }
  
  // ARM detection (generic)
  if (vendor === 'ARM') {
    // ARMv8 has AES acceleration
    if (modelLower.match(/cortex-a|neoverse|graviton/i)) {
      flags.aes = true;
    }
    // AWS Graviton 3+ has good crypto
    if (modelLower.match(/graviton[3-9]/i)) {
      flags.vaes = true; // Equivalent
    }
  }
  
  return flags;
}

/**
 * Detect CPU vendor from model string
 */
function detectCPUVendor() {
  const cpus = os.cpus();
  const model = cpus[0]?.model || '';
  
  if (model.includes('Intel')) return 'GenuineIntel';
  if (model.includes('AMD')) return 'AuthenticAMD';
  if (model.includes('Apple')) return 'Apple';
  if (model.includes('ARM')) return 'ARM';
  
  return 'Unknown';
}

/**
 * Measure AES-NI performance with multiple data sizes
 * VAES can be detected by measuring 4MB vs 1MB - vectorized is proportionally faster
 */
export async function measureAESPerformanceExtended(options = {}) {
  const results = {};
  
  // Standard 1MB test (baseline)
  results.standard = await measureAESPerformance({
    dataSize: 1024 * 1024,
    iterations: options.iterations || 30,
  });
  
  // 4MB test (VAES shines here with 4x vector width)
  results.large = await measureAESPerformance({
    dataSize: 4 * 1024 * 1024,
    iterations: options.iterations || 20,
  });
  
  // Calculate VAES indicator: if 4MB is ~4x throughput, likely VAES
  // Real VAES maintains or improves throughput on larger data
  const throughputRatio = results.large.throughputMBps / results.standard.throughputMBps;
  
  // VAES detection heuristics:
  // - Throughput > 2000 MB/s suggests VAES-256 or better
  // - Throughput > 4000 MB/s suggests VAES-512
  // - Consistent or improving throughput on larger data suggests vectorization
  const vaesIndicators = {
    highThroughput: results.standard.throughputMBps > 2000,
    veryHighThroughput: results.standard.throughputMBps > 4000,
    maintainsThroughput: throughputRatio > 0.9,
    throughputRatio,
  };
  
  results.vaesIndicators = vaesIndicators;
  results.likelyVAES = vaesIndicators.highThroughput && vaesIndicators.maintainsThroughput;
  results.likelyVAES512 = vaesIndicators.veryHighThroughput && vaesIndicators.maintainsThroughput;
  
  return results;
}

/**
 * Determine crypto acceleration tier based on detected features and timing
 */
export function determineCryptoTier(features, timing) {
  // Start with NONE
  let tier = CRYPTO_ACCELERATION_TIER.NONE;
  
  // Check for AES-NI via timing
  if (timing && timing.meanMs < 10 && timing.varianceRatio < 0.1) {
    tier = CRYPTO_ACCELERATION_TIER.AES_NI;
  }
  
  // Check for VAES via features or timing
  if (features.hasVAES || (timing && timing.throughputMBps > 2000)) {
    tier = CRYPTO_ACCELERATION_TIER.VAES_256;
  }
  
  // Check for VAES-512 via features or timing
  if ((features.hasVAES && features.hasAVX512) || (timing && timing.throughputMBps > 4000)) {
    tier = CRYPTO_ACCELERATION_TIER.VAES_512;
  }
  
  // Check for GFNI
  if (features.hasGFNI) {
    tier = CRYPTO_ACCELERATION_TIER.GFNI;
  }
  
  // Check for PQC readiness (future)
  if (features.hasNTTAccel && features.hasSHA3NI) {
    tier = CRYPTO_ACCELERATION_TIER.PQC_READY;
  }
  
  return {
    tier,
    tierName: TIER_NAMES[tier],
    description: getTierDescription(tier),
  };
}

/**
 * Get description for crypto tier
 */
function getTierDescription(tier) {
  switch (tier) {
    case CRYPTO_ACCELERATION_TIER.NONE:
      return 'No hardware crypto acceleration detected. Software-only AES.';
    case CRYPTO_ACCELERATION_TIER.AES_NI:
      return 'AES-NI (128-bit) detected. Standard hardware acceleration.';
    case CRYPTO_ACCELERATION_TIER.VAES_256:
      return 'VAES 256-bit detected. 2x throughput vs standard AES-NI.';
    case CRYPTO_ACCELERATION_TIER.VAES_512:
      return 'VAES 512-bit (AVX-512) detected. 4x throughput, strongest fingerprints.';
    case CRYPTO_ACCELERATION_TIER.GFNI:
      return 'GFNI detected. Universal Galois Field acceleration for flexible crypto.';
    case CRYPTO_ACCELERATION_TIER.PQC_READY:
      return 'PQC-Ready. NTT and SHA-3 accelerators for post-quantum algorithms.';
    default:
      return 'Unknown crypto acceleration tier.';
  }
}

/**
 * Measure AES-NI performance
 * Real hardware will have consistent, fast timing
 */
export async function measureAESPerformance(options = {}) {
  const dataSize = options.dataSize || HARDWARE_THRESHOLDS.CHALLENGE_DATA_SIZE;
  const iterations = options.iterations || HARDWARE_THRESHOLDS.CHALLENGE_ITERATIONS;
  
  const key = randomBytes(32);
  const iv = randomBytes(12); // GCM uses 12-byte IV
  const data = randomBytes(dataSize);
  
  const timings = [];
  
  for (let i = 0; i < iterations; i++) {
    const start = process.hrtime.bigint();
    
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
      cipher.update(data),
      cipher.final(),
    ]);
    cipher.getAuthTag(); // Must get auth tag for GCM
    
    const end = process.hrtime.bigint();
    const durationNs = Number(end - start);
    timings.push(durationNs);
  }
  
  // Calculate statistics
  const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
  const variance = timings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / timings.length;
  const stddev = Math.sqrt(variance);
  
  const meanMs = mean / 1_000_000;
  const stddevMs = stddev / 1_000_000;
  const throughputMBps = (dataSize / (mean / 1_000_000_000)) / (1024 * 1024);
  
  return {
    dataSize,
    iterations,
    meanNs: mean,
    stddevNs: stddev,
    meanMs,
    stddevMs,
    minMs: Math.min(...timings) / 1_000_000,
    maxMs: Math.max(...timings) / 1_000_000,
    throughputMBps,
    varianceRatio: stddevMs / meanMs,
  };
}

/**
 * Validate AES timing results against hardware thresholds
 */
export function validateAESTiming(timing) {
  const issues = [];
  
  if (timing.meanMs > HARDWARE_THRESHOLDS.AES_1MB_MAX_MEAN_MS) {
    issues.push(`Mean too slow: ${timing.meanMs.toFixed(2)}ms > ${HARDWARE_THRESHOLDS.AES_1MB_MAX_MEAN_MS}ms`);
  }
  
  if (timing.stddevMs > HARDWARE_THRESHOLDS.AES_1MB_MAX_STDDEV_MS) {
    issues.push(`Timing too variable: stddev ${timing.stddevMs.toFixed(2)}ms > ${HARDWARE_THRESHOLDS.AES_1MB_MAX_STDDEV_MS}ms`);
  }
  
  if (timing.throughputMBps < HARDWARE_THRESHOLDS.AES_1MB_MIN_THROUGHPUT_MBPS) {
    issues.push(`Throughput too low: ${timing.throughputMBps.toFixed(0)} MB/s < ${HARDWARE_THRESHOLDS.AES_1MB_MIN_THROUGHPUT_MBPS} MB/s`);
  }
  
  if (timing.varianceRatio > HARDWARE_THRESHOLDS.MAX_VARIANCE_RATIO) {
    issues.push(`Variance ratio too high: ${(timing.varianceRatio * 100).toFixed(1)}% > ${HARDWARE_THRESHOLDS.MAX_VARIANCE_RATIO * 100}%`);
  }
  
  return {
    valid: issues.length === 0,
    issues,
    hasAESNI: timing.meanMs < 10 && timing.varianceRatio < 0.1,
  };
}

/**
 * Hardware Attestation class
 * Creates and verifies hardware attestations
 */
export class HardwareAttestation {
  /**
   * Create a local hardware attestation
   * Proves this node is running on real hardware
   * Extended in v2.4.1 to detect VAES, GFNI, and crypto tier
   */
  static async createLocal(options = {}) {
    log.info('hardware-attestation', 'Creating local hardware attestation (v2.4.1)');
    
    const features = detectCPUFeatures();
    const timing = await measureAESPerformance();
    const validation = validateAESTiming(timing);
    
    // Update features based on timing test
    features.hasAESNI = validation.hasAESNI;
    
    // Extended detection for VAES/GFNI (optional, adds ~200ms)
    let extendedTiming = null;
    if (options.extended !== false) {
      extendedTiming = await measureAESPerformanceExtended({ iterations: 10 });
      
      // Update VAES detection from timing if not detected from CPU flags
      if (!features.hasVAES && extendedTiming.likelyVAES) {
        features.hasVAES = true;
      }
    }
    
    // Determine crypto acceleration tier
    const cryptoTierResult = determineCryptoTier(features, timing);
    features.cryptoTier = cryptoTierResult.tier;
    features.cryptoTierName = cryptoTierResult.tierName;
    
    const attestation = {
      version: '2.4.1',
      createdAt: Date.now(),
      cpu: features,
      timing: {
        meanMs: timing.meanMs,
        stddevMs: timing.stddevMs,
        throughputMBps: timing.throughputMBps,
        varianceRatio: timing.varianceRatio,
      },
      validation: {
        valid: validation.valid,
        hasAESNI: validation.hasAESNI,
        issues: validation.issues,
      },
      // v2.4.1 extended fields
      cryptoAcceleration: {
        tier: cryptoTierResult.tier,
        tierName: cryptoTierResult.tierName,
        description: cryptoTierResult.description,
        hasVAES: features.hasVAES,
        hasGFNI: features.hasGFNI,
        hasAVX512: features.hasAVX512,
        pqcReady: features.hasNTTAccel && features.hasSHA3NI,
      },
      extendedTiming: extendedTiming ? {
        standardThroughputMBps: extendedTiming.standard?.throughputMBps,
        largeThroughputMBps: extendedTiming.large?.throughputMBps,
        throughputRatio: extendedTiming.vaesIndicators?.throughputRatio,
        likelyVAES: extendedTiming.likelyVAES,
        likelyVAES512: extendedTiming.likelyVAES512,
      } : null,
    };
    
    log.info('hardware-attestation-complete', {
      hasAESNI: validation.hasAESNI,
      throughputMBps: timing.throughputMBps.toFixed(0),
      valid: validation.valid,
      cryptoTier: cryptoTierResult.tierName,
      hasVAES: features.hasVAES,
      hasGFNI: features.hasGFNI,
    });
    
    return attestation;
  }
  
  /**
   * Create a local hardware attestation (quick mode)
   * Skips extended timing tests for faster results
   */
  static async createLocalQuick() {
    return HardwareAttestation.createLocal({ extended: false });
  }
  
  /**
   * Create a challenge for another node to prove hardware
   */
  static createChallenge() {
    const nonce = randomBytes(32);
    const data = randomBytes(HARDWARE_THRESHOLDS.CHALLENGE_DATA_SIZE);
    
    return {
      version: '1.0',
      type: 'hardware-challenge',
      nonce: bytesToHex(nonce),
      dataHash: bytesToHex(sha3_256(data)),
      dataSize: HARDWARE_THRESHOLDS.CHALLENGE_DATA_SIZE,
      iterations: HARDWARE_THRESHOLDS.CHALLENGE_ITERATIONS,
      createdAt: Date.now(),
      expiresAt: Date.now() + HARDWARE_THRESHOLDS.CHALLENGE_TIMEOUT_MS,
      // Data sent separately or derived from nonce
      _data: data, // Not serialized, used locally
    };
  }
  
  /**
   * Respond to a hardware challenge
   */
  static async respondToChallenge(challenge, privateKey, dokoId) {
    if (Date.now() > challenge.expiresAt) {
      throw new Error('Challenge expired');
    }
    
    // Derive challenge data from nonce (deterministic)
    const nonce = hexToBytes(challenge.nonce);
    const data = deriveDataFromNonce(nonce, challenge.dataSize);
    
    // Verify data hash
    const dataHash = bytesToHex(sha3_256(data));
    if (dataHash !== challenge.dataHash) {
      throw new Error('Challenge data mismatch');
    }
    
    // Perform the timed operation
    const timing = await measureAESPerformance({
      dataSize: challenge.dataSize,
      iterations: challenge.iterations,
    });
    
    const features = detectCPUFeatures();
    features.hasAESNI = timing.meanMs < 10 && timing.varianceRatio < 0.1;
    
    const responseData = {
      version: '1.0',
      challengeNonce: challenge.nonce,
      responderId: dokoId,
      respondedAt: Date.now(),
      cpu: features,
      timing: {
        meanMs: timing.meanMs,
        stddevMs: timing.stddevMs,
        throughputMBps: timing.throughputMBps,
        varianceRatio: timing.varianceRatio,
      },
    };
    
    // Sign the response
    const responseBytes = new TextEncoder().encode(JSON.stringify(responseData));
    const signature = mlDsa65Sign(responseBytes, privateKey);
    
    return {
      ...responseData,
      signature: bytesToHex(signature),
    };
  }
  
  /**
   * Verify a challenge response
   */
  static verifyResponse(response, challenge, publicKey) {
    // Check timing
    if (response.respondedAt > challenge.expiresAt) {
      return { valid: false, reason: 'RESPONSE_TOO_LATE' };
    }
    
    // Check challenge nonce matches
    if (response.challengeNonce !== challenge.nonce) {
      return { valid: false, reason: 'NONCE_MISMATCH' };
    }
    
    // Verify signature
    const responseCopy = { ...response };
    delete responseCopy.signature;
    const responseBytes = new TextEncoder().encode(JSON.stringify(responseCopy));
    const signature = hexToBytes(response.signature);
    const pubKeyBytes = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    
    if (!mlDsa65Verify(signature, responseBytes, pubKeyBytes)) {
      return { valid: false, reason: 'INVALID_SIGNATURE' };
    }
    
    // Validate timing
    const timingValidation = validateAESTiming(response.timing);
    if (!timingValidation.valid) {
      return { 
        valid: false, 
        reason: 'TIMING_VALIDATION_FAILED',
        issues: timingValidation.issues,
      };
    }
    
    return {
      valid: true,
      hasAESNI: timingValidation.hasAESNI,
      throughputMBps: response.timing.throughputMBps,
    };
  }
  
  /**
   * Verify a standalone attestation
   */
  static verify(attestation) {
    if (!attestation || !attestation.timing) {
      return { valid: false, reason: 'MISSING_DATA' };
    }
    
    // Check age (attestations expire after 24 hours)
    const age = Date.now() - attestation.createdAt;
    if (age > 24 * 60 * 60 * 1000) {
      return { valid: false, reason: 'ATTESTATION_EXPIRED' };
    }
    
    // Validate timing
    return validateAESTiming(attestation.timing);
  }
}

/**
 * Derive challenge data from nonce (deterministic)
 * Both challenger and responder can generate same data
 */
function deriveDataFromNonce(nonce, size) {
  const chunks = [];
  let counter = 0;
  
  while (chunks.reduce((sum, c) => sum + c.length, 0) < size) {
    const input = new Uint8Array([...nonce, ...numberToBytes(counter++)]);
    chunks.push(sha3_256(input));
  }
  
  return Buffer.concat(chunks).slice(0, size);
}

function numberToBytes(n) {
  const bytes = new Uint8Array(4);
  bytes[0] = (n >> 24) & 0xff;
  bytes[1] = (n >> 16) & 0xff;
  bytes[2] = (n >> 8) & 0xff;
  bytes[3] = n & 0xff;
  return bytes;
}

/**
 * Get a summary of this machine's crypto capabilities
 * Useful for CLI display and debugging
 */
export async function getCryptoCapabilitySummary() {
  const features = detectCPUFeatures();
  const timing = await measureAESPerformance({ iterations: 20 });
  const validation = validateAESTiming(timing);
  features.hasAESNI = validation.hasAESNI;
  
  const tierResult = determineCryptoTier(features, timing);
  
  return {
    cpu: {
      vendor: features.vendor,
      model: features.model,
      cores: features.cores,
    },
    capabilities: {
      aesNI: features.hasAESNI,
      vaes: features.hasVAES,
      avx512: features.hasAVX512,
      gfni: features.hasGFNI,
      pqcReady: features.hasNTTAccel && features.hasSHA3NI,
    },
    performance: {
      throughputMBps: Math.round(timing.throughputMBps),
      meanMs: timing.meanMs.toFixed(2),
      varianceRatio: (timing.varianceRatio * 100).toFixed(1) + '%',
    },
    tier: tierResult,
    recommendation: getTierRecommendation(tierResult.tier),
  };
}

/**
 * Get upgrade recommendations for crypto tier
 */
function getTierRecommendation(tier) {
  switch (tier) {
    case CRYPTO_ACCELERATION_TIER.NONE:
      return 'Consider upgrading to hardware with AES-NI (any modern Intel/AMD CPU).';
    case CRYPTO_ACCELERATION_TIER.AES_NI:
      return 'Solid baseline. Consider Zen 4+ or Intel 11th gen+ for VAES.';
    case CRYPTO_ACCELERATION_TIER.VAES_256:
      return 'Good crypto acceleration. AVX-512 would give 4x vectorization.';
    case CRYPTO_ACCELERATION_TIER.VAES_512:
      return 'Excellent. Full VAES-512 provides strongest attestation fingerprints.';
    case CRYPTO_ACCELERATION_TIER.GFNI:
      return 'Top-tier current hardware with universal crypto acceleration.';
    case CRYPTO_ACCELERATION_TIER.PQC_READY:
      return 'Future-proof! PQC accelerators ready for post-quantum era.';
    default:
      return 'Unknown tier.';
  }
}

export default HardwareAttestation;
